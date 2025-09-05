/// Flutter OffMesh Prototype — full main.dart
/// BLE chat + file transfer with ACK/retry (research prototype)
///
/// Restored full file-transfer path, improved UI, and robust handlers.
/// This file is large by design (detailed comments + functionality).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_reactive_ble/flutter_reactive_ble.dart';
import 'package:flutter_ble_peripheral/flutter_ble_peripheral.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart' as perms;
import 'package:file_picker/file_picker.dart';
import 'package:path/path.dart' as p;

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const OffMeshApp());
}

class OffMeshApp extends StatefulWidget {
  const OffMeshApp({Key? key}) : super(key: key);
  @override
  State<OffMeshApp> createState() => _OffMeshAppState();
}

// -----------------------------------------------------------------------------
// IMPORTANT NOTES
// - This is a research / test-only prototype. It does NOT provide encryption
//   or authentication for messages. Do not use in production.
// - Make sure AndroidManifest contains the Bluetooth and storage permissions
//   (compile-time). At runtime we also request permissions.
// - Some plugin APIs change between versions; advertising call is wrapped in
//   try/catch to avoid hard crashes when method signatures differ.
// -----------------------------------------------------------------------------

class _OffMeshAppState extends State<OffMeshApp> {
  // --- BLE & UUIDs
  final flutterReactiveBle = FlutterReactiveBle();
  final peripheral = FlutterBlePeripheral();

  // example service/characteristic UUIDs (change for your setup if needed)
  final Uuid _serviceUuid = Uuid.parse('12345678-1234-5678-1234-56789abcdef0');
  final Uuid _charInbox = Uuid.parse('12345678-1234-5678-1234-56789abcdef1');
  final Uuid _charOutbox = Uuid.parse('12345678-1234-5678-1234-56789abcdef2');
  final Uuid _charInfo = Uuid.parse('12345678-1234-5678-1234-56789abcdef3');

  // secure storage for node identity
  final storage = const FlutterSecureStorage();
  SimpleKeyPair? myKeypair;
  String? myNodeHex; // short public id (hex prefix)

  // peers / subscriptions
  final Map<String, DiscoveredDevice> _peers = {};
  final Map<String, StreamSubscription<List<int>>> _outboxSubs = {};

  // pending acks for reliable send
  final Map<int, Completer<bool>> _pendingAcks = {};

  // incoming files map: baseFileId -> FileState
  final Map<int, _FileState> _incomingFiles = {};

  // outgoing file tracking
  final Map<int, _OutgoingFileState> _outgoingFiles = {};

  // constants
  static const int maxTtl = 5;
  static const int typeChat = 1;
  static const int typeFileMeta = 2;
  static const int typeFileChunk = 3;
  static const int typeAck = 4;

  final List<String> _logs = [];
  final TextEditingController _msgCtrl = TextEditingController();

  int? get myNodeId =>
      myNodeHex != null ? int.tryParse(myNodeHex!, radix: 16) : null;

  @override
  void initState() {
    super.initState();
    _initAll();
  }

  Future<void> _initAll() async {
    _log('Initializing OffMesh...');

    try {
      final ok = await _requestBlePermissions();
      if (!ok) {
        _log('Permissions not granted. BLE will not start.');
        return;
      }
    } catch (e) {
      _log('Permission request failed: $e');
    }

    await _loadOrCreateKeypair();

    if (myNodeHex == null) {
      _log('❌ Failed to load/create node identity');
      return;
    }

    try {
      await _startAdvertising();
    } catch (e) {
      _log('Start advertising failed: $e');
    }

    try {
      _startScan();
    } catch (e) {
      _log('Start scan failed: $e');
    }

    setState(() {});
  }

  // ---------- Permissions ----------------------------------------------------
  Future<bool> _requestBlePermissions() async {
    try {
      final statuses = await [
        perms.Permission.bluetoothScan,
        perms.Permission.bluetoothConnect,
        perms.Permission.bluetoothAdvertise,
        perms.Permission.location, // older Android
        perms.Permission.storage,
      ].request();

      final scanStatus = statuses[perms.Permission.bluetoothScan];
      final connectStatus = statuses[perms.Permission.bluetoothConnect];

      bool ok =
          (scanStatus == perms.PermissionStatus.granted ||
              scanStatus == perms.PermissionStatus.limited) &&
          (connectStatus == perms.PermissionStatus.granted ||
              connectStatus == perms.PermissionStatus.limited);

      final loc = statuses[perms.Permission.location];
      if ((Platform.isAndroid) && loc != perms.PermissionStatus.granted) {
        _log(
          'Warning: location permission not granted; scans on older Android may fail.',
        );
      }

      _log(
        'Permissions: ${statuses.map((k, v) => MapEntry(k.toString(), v.toString()))}',
      );
      return ok;
    } catch (e) {
      _log('Permission request exception: $e');
      return false;
    }
  }

  // ---------- Identity (keypair) -------------------------------------------
  Future<void> _loadOrCreateKeypair() async {
    try {
      final pubHex = await storage.read(key: 'pub');
      final privHex = await storage.read(key: 'priv');

      if (pubHex != null && privHex != null) {
        myKeypair = SimpleKeyPairData(
          Uint8List.fromList(_hexToBytes(privHex)),
          publicKey: SimplePublicKey(
            Uint8List.fromList(_hexToBytes(pubHex)),
            type: KeyPairType.ed25519,
          ),
          type: KeyPairType.ed25519,
        );
        myNodeHex = pubHex.substring(0, 8).toUpperCase();
        _log('🔑 Loaded node $myNodeHex');
        return;
      }

      // create new
      final algorithm = Ed25519();
      final kp = await algorithm.newKeyPair();
      final pub = await kp.extractPublicKey();
      final priv = await kp.extractPrivateKeyBytes();
      final pubHexNew = _bytesToHex(pub.bytes);
      final privHexNew = _bytesToHex(priv);
      await storage.write(key: 'pub', value: pubHexNew);
      await storage.write(key: 'priv', value: privHexNew);
      myKeypair = kp;
      myNodeHex = pubHexNew.substring(0, 8).toUpperCase();
      _log('🔑 Generated node $myNodeHex');
    } catch (e) {
      _log('Keypair error: $e');
    }
  }

  // ---------- Advertising & Scanning ---------------------------------------
  Future<void> _startAdvertising() async {
    if (myNodeHex == null) return;
    try {
      final advertiseSettings = AdvertiseSettings(
        advertiseMode: AdvertiseMode.advertiseModeLowLatency,
        txPowerLevel: AdvertiseTxPower.advertiseTxPowerHigh,
        connectable: true,
        timeout: 0,
      );

      final advertiseData = AdvertiseData(
        includeDeviceName: true,
        serviceUuid: _serviceUuid.toString(),
        manufacturerId: 0x02AC,
        manufacturerData: Uint8List.fromList(_hexToBytes(myNodeHex!)),
      );

      // some versions expose a different API; we wrap in try/catch
      await peripheral.start(
        advertiseData: advertiseData,
        advertiseSettings: advertiseSettings,
      );

      _log('📡 Advertising as $myNodeHex');
    } catch (e) {
      _log('Advertise start failed (plugin mismatch or runtime error): $e');
    }
  }

  void _startScan() {
    _log('🔎 Scanning...');
    try {
      flutterReactiveBle
          .scanForDevices(withServices: [_serviceUuid])
          .listen(
            (d) {
              try {
                if (!_peers.containsKey(d.id)) {
                  _peers[d.id] = d;
                  _log('Discovered ${d.name.isEmpty ? d.id : d.name}');
                  _connect(d);
                }
              } catch (e) {
                _log('Scan device handling error: $e');
              }
            },
            onError: (e) {
              _log('Scan stream error: $e');
            },
          );
    } catch (e) {
      _log('Start scan failed: $e');
    }
  }

  Future<void> _connect(DiscoveredDevice d) async {
    try {
      final stream = flutterReactiveBle.connectToDevice(
        id: d.id,
        connectionTimeout: const Duration(seconds: 10),
      );

      stream.listen((state) async {
        try {
          if (state.connectionState == DeviceConnectionState.connected) {
            _log('🔗 Connected to ${d.name.isEmpty ? d.id : d.name}');
            _subscribeOutbox(d.id);
          } else if (state.connectionState ==
              DeviceConnectionState.disconnected) {
            _log('🔌 Disconnected ${d.id}');
            _outboxSubs[d.id]?.cancel();
            _outboxSubs.remove(d.id);
            _peers.remove(d.id);
          }
        } catch (e) {
          _log('Connect state handler error: $e');
        }
      }, onError: (e) => _log('Connection stream error ${d.id}: $e'));
    } catch (e) {
      _log('Connect failed ${d.id}: $e');
    }
  }

  void _subscribeOutbox(String deviceId) {
    try {
      final q = QualifiedCharacteristic(
        serviceId: _serviceUuid,
        characteristicId: _charOutbox,
        deviceId: deviceId,
      );
      final sub = flutterReactiveBle.subscribeToCharacteristic(q).listen((
        data,
      ) {
        try {
          _onOutboxNotify(deviceId, data);
        } catch (e) {
          _log('Outbox notify parse error: $e');
        }
      }, onError: (e) => _log('Outbox subscription error $deviceId: $e'));
      _outboxSubs[deviceId] = sub;
    } catch (e) {
      _log('Subscribe failed $deviceId: $e');
    }
  }

  void _onOutboxNotify(String deviceId, List<int> data) {
    try {
      final pkt = Packet.fromBytes(data);
      _handlePacket(deviceId, pkt);
    } catch (e) {
      _log('Failed to parse packet from $deviceId: $e');
    }
  }

  // ---------- Packet handling ----------------------------------------------
  void _handlePacket(String fromDeviceId, Packet pkt) {
    try {
      if (_seen(pkt.pktId)) return;

      // send ACK back to sender only
      if (pkt.type != typeAck && myNodeId != null) {
        final ack = Packet(
          typeAck,
          myNodeId!,
          pkt.srcId,
          pkt.pktId,
          Uint8List(0),
          maxTtl,
        );
        _sendPacketRawToDevice(fromDeviceId, ack.toBytes());
      }

      switch (pkt.type) {
        case typeChat:
          final msg = utf8.decode(pkt.payload);
          _log(
            '💬 [${pkt.srcId.toRadixString(16).padLeft(8, "0").toUpperCase()}] $msg',
          );
          _completePending(pkt.pktId, true);
          break;

        case typeFileMeta:
          _handleIncomingFileMeta(pkt);
          break;

        case typeFileChunk:
          _handleIncomingFileChunk(pkt);
          break;

        case typeAck:
          _completePending(pkt.pktId, true);
          break;

        default:
          _log('Unknown pkt type ${pkt.type}');
      }
    } catch (e) {
      _log('Handle packet error: $e');
    }
  }

  void _handleIncomingFileMeta(Packet pkt) {
    try {
      final payload = pkt.payload;
      if (payload.length < 4) {
        _log('FileMeta: payload too short');
        return;
      }
      final baseId = _u32From(payload, 0);
      final rest = utf8.decode(payload.sublist(4));
      final parts = rest.split('|');
      final name = parts.isNotEmpty ? parts[0] : 'unknown';
      final total = parts.length > 1 ? int.tryParse(parts[1]) ?? 0 : 0;
      final size = parts.length > 2 ? int.tryParse(parts[2]) ?? 0 : 0;

      final fs = _FileState.full(name, total, size);
      _incomingFiles[baseId] = fs;
      _log(
        '📁 Incoming file meta: $name (chunks=$total, bytes=$size) id=$baseId',
      );
    } catch (e) {
      _log('FileMeta handling error: $e');
    }
  }

  void _handleIncomingFileChunk(Packet pkt) {
    try {
      final payload = pkt.payload;
      if (payload.length < 6) {
        _log('FileChunk: payload too short');
        return;
      }
      final baseId = _u32From(payload, 0);
      final idx = _u16From(Uint8List.fromList(payload), 4);
      final data = payload.sublist(6);
      final fs = _incomingFiles[baseId];
      if (fs == null) {
        _log('FileChunk for unknown id $baseId (idx=$idx)');
        return;
      }
      fs.addChunk(idx, Uint8List.fromList(data));
      _log(
        '▶ Received chunk $idx for ${fs.name} (${fs.receivedCount}/${fs.total ?? -1})',
      );
      if (fs.isComplete) {
        _saveIncomingFile(baseId, fs);
        _incomingFiles.remove(baseId);
      }
    } catch (e) {
      _log('FileChunk handling error: $e');
    }
  }

  final Set<int> _seenPktIds = {};
  bool _seen(int pktId) {
    try {
      if (_seenPktIds.contains(pktId)) return true;
      _seenPktIds.add(pktId);
      if (_seenPktIds.length > 10000) _seenPktIds.clear();
      return false;
    } catch (e) {
      _log('Seen check error: $e');
      return false;
    }
  }

  void _completePending(int pktId, bool ok) {
    try {
      final c = _pendingAcks.remove(pktId);
      if (c != null && !c.isCompleted) c.complete(ok);
    } catch (e) {
      _log('Complete pending error: $e');
    }
  }

  Future<void> _saveIncomingFile(int baseId, _FileState fs) async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final f = File('${dir.path}/${fs.name}');
      final bytes = fs.assemble();
      await f.writeAsBytes(bytes);
      _log('✅ Incoming file saved: ${fs.name} -> ${f.path}');
    } catch (e) {
      _log('Save incoming file failed: $e');
    }
  }

  // ---------- Low-level send -----------------------------------------------
  Future<void> _sendPacketRawToDevice(String deviceId, List<int> bytes) async {
    try {
      final q = QualifiedCharacteristic(
        serviceId: _serviceUuid,
        characteristicId: _charInbox,
        deviceId: deviceId,
      );
      await flutterReactiveBle.writeCharacteristicWithResponse(
        q,
        value: Uint8List.fromList(bytes),
      );
      _log('TX -> $deviceId (${bytes.length} bytes)');
    } catch (e) {
      _log('Write fail -> $deviceId: $e');
    }
  }

  // Broadcast reliable send: we send to all connected peers and wait for any ACK
  Future<void> _sendReliable(
    int dstId,
    int pktId,
    int type,
    Uint8List payload, {
    int retries = 4,
    Duration timeout = const Duration(seconds: 2),
  }) async {
    try {
      if (myNodeId == null) {
        _log('Node id not ready');
        return;
      }
      final pkt = Packet(type, myNodeId!, dstId, pktId, payload, maxTtl);
      final bytes = pkt.toBytes();

      final completer = Completer<bool>();
      _pendingAcks[pktId] = completer;
      int attempt = 0;

      while (attempt < retries && !completer.isCompleted) {
        attempt++;
        for (final entry in _peers.entries) {
          try {
            await _sendPacketRawToDevice(entry.key, bytes);
          } catch (e) {
            _log('Send to ${entry.key} failed: $e');
          }
        }
        try {
          await completer.future.timeout(timeout);
          break;
        } on TimeoutException {
          _log('⏳ Retry pkt $pktId (attempt $attempt)');
        } catch (e) {
          _log('Error waiting ack: $e');
        }
      }

      if (!completer.isCompleted) {
        _pendingAcks.remove(pktId);
        _log('❌ No ACK for $pktId after $attempt attempts');
      } else {
        _log('✅ ACK for $pktId');
      }
    } catch (e) {
      _log('Send reliable error: $e');
    }
  }

  // ---------- Chat send ---------------------------------------------------
  void _sendChat(String text) {
    try {
      final pktId = DateTime.now().millisecondsSinceEpoch & 0x7FFFFFFF;
      _sendReliable(
        0xFFFF,
        pktId,
        typeChat,
        Uint8List.fromList(utf8.encode(text)),
      );
      _log('➡️ Me: $text');
    } catch (e) {
      _log('Send chat error: $e');
    }
  }

  // ---------- File send (full path restored) -------------------------------
  /// Choose a file and send using file meta + chunked payloads.
  Future<void> _pickAndSendFile() async {
    try {
      final result = await FilePicker.platform.pickFiles();
      if (result == null || result.files.isEmpty) return;
      final picked = result.files.first;
      final path = picked.path;
      if (path == null) return;

      final f = File(path);
      final bytes = await f.readAsBytes();
      final name = p.basename(path);
      await _sendFileBytes(name, bytes);
    } catch (e) {
      _log('File pick/send error: $e');
    }
  }

  Future<void> _sendFileBytes(String name, Uint8List bytes) async {
    try {
      // choose chunk size small enough to fit typical BLE MTU
      const int chunkSize = 512; // prototype
      final totalChunks = (bytes.length / chunkSize).ceil();
      final baseId = _random32();

      // register outgoing file for progress UI
      final ofs = _OutgoingFileState(name, bytes.length, totalChunks);
      _outgoingFiles[baseId] = ofs;

      // create meta payload: [u32 baseId] + utf8('name|chunks|size')
      final metaText = '$name|$totalChunks|${bytes.length}';
      final metaPayload = BytesBuilder();
      metaPayload.add(_u32(baseId));
      metaPayload.add(utf8.encode(metaText));

      final metaPktId = baseId ^ 0xA5A50000;
      await _sendReliable(
        0xFFFF,
        metaPktId,
        typeFileMeta,
        metaPayload.takeBytes(),
      );

      // send chunks
      for (int i = 0; i < totalChunks; i++) {
        final off = i * chunkSize;
        final end = min(off + chunkSize, bytes.length);
        final chunk = bytes.sublist(off, end);
        final chunkPayload = BytesBuilder();
        chunkPayload.add(_u32(baseId)); // identify which file
        chunkPayload.add(_u16(i)); // chunk index
        chunkPayload.add(chunk);
        final pktId = baseId ^ (i & 0xFFFF);

        // update UI state
        ofs.sentChunks = i + 1;
        setState(() {});

        await _sendReliable(
          0xFFFF,
          pktId,
          typeFileChunk,
          chunkPayload.takeBytes(),
        );

        // mark chunk ack progress inside outgoing state if ack arrived
        if (_pendingAcks[pktId] == null) {
          // ack already completed
          ofs.ackedChunks++;
        }
      }

      _log('📤 File send finished (meta+chunks): $name');
      _outgoingFiles.remove(baseId);
    } catch (e) {
      _log('Send file error: $e');
    }
  }

  // ---------- Utility & helpers -------------------------------------------
  void _log(String m) {
    try {
      setState(() {
        _logs.insert(0, '${DateTime.now().toIso8601String()}  $m');
        if (_logs.length > 2000) _logs.removeRange(2000, _logs.length);
      });
    } catch (_) {}
  }

  @override
  void dispose() {
    try {
      for (final s in _outboxSubs.values) {
        s.cancel();
      }
      peripheral.stop();
    } catch (_) {}
    super.dispose();
  }

  // ---------- UI ----------------------------------------------------------
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0D0D0D),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1A1A1A),
          elevation: 4,
          titleTextStyle: TextStyle(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            color: Colors.white,
            fontFamily: 'monospace',
          ),
        ),
      ),
      home: Scaffold(
        appBar: AppBar(
          title: Row(
            children: [
              const Icon(Icons.memory, color: Colors.greenAccent, size: 20),
              const SizedBox(width: 8),
              Text('OffMesh Node ${myNodeHex ?? "?"}'),
            ],
          ),
          actions: [
            IconButton(
              icon: const Icon(Icons.attach_file, color: Colors.greenAccent),
              tooltip: 'Send file',
              onPressed: _pickAndSendFile,
            ),
            IconButton(
              icon: const Icon(Icons.refresh, color: Colors.greenAccent),
              tooltip: 'Rescan Devices',
              onPressed: _startScan,
            ),
          ],
        ),
        body: Column(
          children: [
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: const BoxDecoration(
                  gradient: LinearGradient(
                    colors: [Color(0xFF0D0D0D), Color(0xFF1A1A1A)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: ListView.builder(
                  reverse: true,
                  itemCount: _logs.length,
                  itemBuilder: (_, i) {
                    final text = _logs[i];
                    final isMe = text.contains('➡️ Me:');
                    final isSystem =
                        text.contains('📡') ||
                        text.contains('🔎') ||
                        text.contains('🔗') ||
                        text.contains('🔌') ||
                        text.contains('❌') ||
                        text.contains('✅') ||
                        text.contains('⏳') ||
                        text.contains('Warning') ||
                        text.contains('📁') ||
                        text.contains('TX ->');

                    if (isSystem) {
                      return Container(
                        margin: const EdgeInsets.symmetric(vertical: 4),
                        child: Text(
                          text,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            color: Colors.white70,
                          ),
                        ),
                      );
                    }

                    return Align(
                      alignment: isMe
                          ? Alignment.centerRight
                          : Alignment.centerLeft,
                      child: Container(
                        margin: const EdgeInsets.symmetric(vertical: 6),
                        padding: const EdgeInsets.symmetric(
                          vertical: 10,
                          horizontal: 14,
                        ),
                        constraints: const BoxConstraints(maxWidth: 320),
                        decoration: BoxDecoration(
                          color: isMe
                              ? Colors.greenAccent.withOpacity(0.14)
                              : Colors.white.withOpacity(0.04),
                          borderRadius: BorderRadius.circular(14),
                          border: Border.all(
                            color: isMe
                                ? Colors.greenAccent.withOpacity(0.45)
                                : Colors.white24,
                            width: 1,
                          ),
                        ),
                        child: Text(
                          text,
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 13,
                            color: isMe ? Colors.greenAccent : Colors.white,
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ),
            ),

            // outgoing/incoming file progress small area
            if (_outgoingFiles.isNotEmpty || _incomingFiles.isNotEmpty)
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 6,
                ),
                color: const Color(0xFF111111),
                child: Column(
                  children: [
                    for (final e in _outgoingFiles.entries)
                      _buildOutgoingProgress(e.key, e.value),
                    for (final e in _incomingFiles.entries)
                      _buildIncomingProgress(e.key, e.value),
                  ],
                ),
              ),

            // input box
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: const BoxDecoration(
                color: Color(0xFF1A1A1A),
                border: Border(
                  top: BorderSide(color: Colors.white24, width: 0.5),
                ),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _msgCtrl,
                      style: const TextStyle(color: Colors.white),
                      cursorColor: Colors.greenAccent,
                      decoration: InputDecoration(
                        hintText: 'Type message...',
                        hintStyle: const TextStyle(color: Colors.white38),
                        filled: true,
                        fillColor: Colors.black,
                        contentPadding: const EdgeInsets.symmetric(
                          vertical: 10,
                          horizontal: 12,
                        ),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10),
                          borderSide: const BorderSide(color: Colors.white24),
                        ),
                        focusedBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10),
                          borderSide: const BorderSide(
                            color: Colors.greenAccent,
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  GestureDetector(
                    onTap: () {
                      final txt = _msgCtrl.text.trim();
                      if (txt.isNotEmpty) {
                        _msgCtrl.clear();
                        _sendChat(txt);
                      }
                    },
                    child: Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.greenAccent,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: const Icon(Icons.send, color: Colors.black),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildOutgoingProgress(int id, _OutgoingFileState ofs) {
    final pct = ofs.totalChunks > 0 ? ofs.ackedChunks / ofs.totalChunks : 0.0;
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '${ofs.name} (upload) — ${ofs.ackedChunks}/${ofs.totalChunks}',
                ),
                const SizedBox(height: 4),
                LinearProgressIndicator(value: pct),
              ],
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
            icon: const Icon(Icons.cancel, color: Colors.redAccent),
            onPressed: () {
              // cancelling not implemented in prototype; just remove UI
              setState(() => _outgoingFiles.remove(id));
            },
          ),
        ],
      ),
    );
  }

  Widget _buildIncomingProgress(int id, _FileState fs) {
    final pct = (fs.total != null && fs.total! > 0)
        ? (fs.receivedCount / (fs.total ?? 1))
        : (fs.receivedCount > 0 ? 0.5 : 0.0);
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '${fs.name} (download) — ${fs.receivedCount}/${fs.total ?? "?"}',
                ),
                const SizedBox(height: 4),
                LinearProgressIndicator(value: pct),
              ],
            ),
          ),
          const SizedBox(width: 8),
        ],
      ),
    );
  }

  // ---------- Byte helpers -------------------------------------------------
  List<int> _hexToBytes(String hex) {
    try {
      final clean = hex.replaceAll(RegExp('[^0-9A-Fa-f]'), '');
      final out = <int>[];
      for (var i = 0; i < clean.length; i += 2) {
        out.add(int.parse(clean.substring(i, i + 2), radix: 16));
      }
      return out;
    } catch (e) {
      _log('hexToBytes error: $e');
      return [];
    }
  }

  String _bytesToHex(List<int> bytes) {
    try {
      return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    } catch (e) {
      _log('bytesToHex error: $e');
      return '';
    }
  }

  List<int> _u16(int v) => [(v >> 8) & 0xFF, v & 0xFF];
  List<int> _u32(int v) => [
    (v >> 24) & 0xFF,
    (v >> 16) & 0xFF,
    (v >> 8) & 0xFF,
    v & 0xFF,
  ];

  int _u16From(Uint8List d, int off) => (d[off] << 8) | d[off + 1];
  int _u32From(List<int> d, int off) =>
      (d[off] << 24) | (d[off + 1] << 16) | (d[off + 2] << 8) | d[off + 3];

  int _random32() {
    final rnd = Random.secure();
    return rnd.nextInt(0x7FFFFFFF);
  }

  static int _u16FromStatic(Uint8List d, int off) => (d[off] << 8) | d[off + 1];
}

// ---------------------------------------------------------------------------
// Helper classes: File state, Packet format, outgoing tracking
// ---------------------------------------------------------------------------

class _FileState {
  final String name;
  final int? total; // number of chunks
  final int? bytesTotal; // total bytes
  final List<Uint8List?> _chunks;
  int receivedCount = 0;

  _FileState(this.name, this.total)
    : _chunks = List<Uint8List?>.filled(total ?? 0, null),
      bytesTotal = null;

  _FileState.full(this.name, this.total, this.bytesTotal)
    : _chunks = List<Uint8List?>.filled(total ?? 0, null);

  void addChunk(int idx, Uint8List data) {
    if (idx < 0 || (total != null && idx >= total!)) return;
    if (_chunks[idx] == null) {
      _chunks[idx] = data;
      receivedCount++;
    }
  }

  bool get isComplete => (total != null) && receivedCount >= (total ?? 0);

  Uint8List assemble() {
    final out = BytesBuilder();
    for (var c in _chunks) {
      if (c != null) out.add(c);
    }
    return out.takeBytes();
  }
}

class _OutgoingFileState {
  final String name;
  final int totalBytes;
  final int totalChunks;
  int sentChunks = 0;
  int ackedChunks = 0;

  _OutgoingFileState(this.name, this.totalBytes, this.totalChunks);
}

/// Packet layout and helpers
class Packet {
  final int type; // 1 byte
  final int srcId; // 2 bytes
  final int dstId; // 2 bytes
  final int pktId; // 2 bytes (prototype limited)
  final Uint8List payload; // up to 65535 in this format
  final int ttl; // 1 byte

  Packet(this.type, this.srcId, this.dstId, this.pktId, this.payload, this.ttl);

  List<int> toBytes() {
    final b = BytesBuilder();
    b.addByte(type & 0xFF);
    b.addByte(ttl & 0xFF);
    b.add(_u16Static(srcId));
    b.add(_u16Static(dstId));
    b.add(_u16Static(pktId));
    b.add(_u16Static(payload.length));
    b.add(payload);
    return b.takeBytes();
  }

  static Packet fromBytes(List<int> data) {
    final d = Uint8List.fromList(data);
    if (d.length < 10) throw FormatException('Packet too short');
    final type = d[0];
    final ttl = d[1];
    final src = _u16FromStatic(d, 2);
    final dst = _u16FromStatic(d, 4);
    final pktId = _u16FromStatic(d, 6);
    final len = _u16FromStatic(d, 8);
    if (d.length < 10 + len) throw FormatException('Truncated payload');
    final payload = Uint8List.fromList(d.sublist(10, 10 + len));
    return Packet(type, src, dst, pktId, payload, ttl);
  }

  static List<int> _u16Static(int v) => [(v >> 8) & 0xFF, v & 0xFF];
  static int _u16FromStatic(Uint8List d, int off) => (d[off] << 8) | d[off + 1];
}
