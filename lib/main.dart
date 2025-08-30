/// Flutter OffMesh Prototype — robust main.dart
/// BLE chat + file transfer with ACK/retry (controlled dev environment)
///
/// Notes:
/// - Requires flutter_reactive_ble, flutter_ble_peripheral,
///   cryptography, flutter_secure_storage, path_provider, permission_handler
/// - Ensure AndroidManifest contains Bluetooth permissions (see earlier message)
/// - This is a prototype/demo: no encryption/auth is performed on packets.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_reactive_ble/flutter_reactive_ble.dart';
import 'package:flutter_ble_peripheral/flutter_ble_peripheral.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart' as perms;

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const OffMeshApp());
}

class OffMeshApp extends StatefulWidget {
  const OffMeshApp({Key? key}) : super(key: key);
  @override
  State<OffMeshApp> createState() => _OffMeshAppState();
}

class _OffMeshAppState extends State<OffMeshApp> {
  // --- BLE & UUIDs
  final flutterReactiveBle = FlutterReactiveBle();
  final peripheral = FlutterBlePeripheral();

  // Use reactive_ble's Uuid type (these are example UUIDs)
  final Uuid _serviceUuid = Uuid.parse('12345678-1234-5678-1234-56789abcdef0');
  final Uuid _charInbox = Uuid.parse('12345678-1234-5678-1234-56789abcdef1');
  final Uuid _charOutbox = Uuid.parse('12345678-1234-5678-1234-56789abcdef2');
  final Uuid _charInfo = Uuid.parse('12345678-1234-5678-1234-56789abcdef3');

  final storage = const FlutterSecureStorage();
  SimpleKeyPair? myKeypair;
  String? myNodeHex; // nullable until created/loaded

  final Map<String, DiscoveredDevice> _peers = {};
  final Map<String, StreamSubscription<List<int>>> _outboxSubs = {};
  final Map<int, Completer<bool>> _pendingAcks = {};
  final Map<int, _FileState> _incomingFiles = {};

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
    // 1) request necessary BLE & storage permissions
    try {
      final ok = await _requestBlePermissions();
      if (!ok) {
        _log('Permissions not granted. BLE will not start.');
        return;
      }
    } catch (e) {
      _log('Permission request failed: $e');
      // continue — permission request failing should not crash; scanning will fail later
    }

    // 2) load or create the persistent keypair / node id
    await _loadOrCreateKeypair();

    if (myNodeHex == null) {
      _log('❌ Failed to load or create node identity');
      return;
    }

    // 3) safe start advertising & scanning
    try {
      await _startAdvertising();
    } catch (e) {
      _log("Start advertising failed: $e");
    }

    try {
      _startScan();
    } catch (e) {
      _log("Start scan failed: $e");
    }

    setState(() {});
  }

  /// Request BLE & storage related permissions.
  /// Returns true if required permissions look granted enough to proceed.
  Future<bool> _requestBlePermissions() async {
    try {
      // Request the newest Bluetooth permissions (Android 12+). permission_handler
      // exposes them as Permission.bluetoothScan/connect/advertise.
      final statuses = await [
        perms.Permission.bluetoothScan,
        perms.Permission.bluetoothConnect,
        perms.Permission.bluetoothAdvertise,
        perms.Permission.location, // for older Android scans
        perms.Permission.storage,
      ].request();

      // Check at least bluetoothScan and bluetoothConnect are granted (or limited).
      final scanStatus = statuses[perms.Permission.bluetoothScan];
      final connectStatus = statuses[perms.Permission.bluetoothConnect];

      bool ok =
          (scanStatus == perms.PermissionStatus.granted ||
              scanStatus == perms.PermissionStatus.limited) &&
          (connectStatus == perms.PermissionStatus.granted ||
              connectStatus == perms.PermissionStatus.limited);

      // If location is required on older Android, require it too.
      final loc = statuses[perms.Permission.location];
      if ((Platform.isAndroid) && loc != perms.PermissionStatus.granted) {
        // on older Android scanning may require location; log but allow to continue
        _log(
          'Warning: location permission not granted; scans on older Android may fail.',
        );
      }

      _log(
        'Permissions result: ${statuses.map((k, v) => MapEntry(k.toString(), v.toString()))}',
      );
      return ok;
    } catch (e) {
      _log('Permission request exception: $e');
      return false;
    }
  }

  Future<void> _loadOrCreateKeypair() async {
    try {
      final pubHex = await storage.read(key: 'pub');
      final privHex = await storage.read(key: 'priv');

      if (pubHex != null && privHex != null) {
        // reconstruct simple keypair from saved hex (prototype only)
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

      // else create
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
        // serviceUuid and manufacturer fields depend on plugin version
        serviceUuid: _serviceUuid.toString(),
        manufacturerId: 0x02AC,
        manufacturerData: Uint8List.fromList(_hexToBytes(myNodeHex!)),
      );

      // Many plugin versions expose start({advertiseData, advertiseSettings})
      // If your plugin has a different signature, adjust accordingly.
      await peripheral.start(
        advertiseData: advertiseData,
        advertiseSettings: advertiseSettings,
      );

      _log('📡 Advertising as $myNodeHex');
    } catch (e) {
      // If the method signature differs on your plugin version, this will catch it.
      _log('Advertise start failed (plugin mismatch or runtime error): $e');
    }
  }

  void _startScan() {
    _log('🔎 Scanning...');
    try {
      // scanForDevices returns a stream of DiscoveredDevice
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
              // Many runtime errors here are permission or platform issues; we log them.
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

  void _handlePacket(String fromDeviceId, Packet pkt) {
    try {
      if (_seen(pkt.pktId)) return;

      // send ACK back to the sender only (simple prototype)
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
          final parts = utf8.decode(pkt.payload).split('|');
          final name = parts.isNotEmpty ? parts[0] : 'unknown';
          final size = parts.length > 1 ? int.tryParse(parts[1]) ?? 0 : 0;
          _incomingFiles[pkt.pktId] = _FileState(name, size);
          _log('📁 Incoming $name ($size bytes)');
          break;

        case typeFileChunk:
          final fs = _incomingFiles[pkt.pktId];
          if (fs != null) {
            fs.received.add(pkt.payload);
            _log(
              '▶ Chunk for ${fs.name}: ${fs.received.length}/${fs.total ?? -1}',
            );
            if (fs.total != null && fs.received.length >= fs.total!) {
              _saveFile(fs);
              _incomingFiles.remove(pkt.pktId);
            }
          }
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

  Future<void> _saveFile(_FileState fs) async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final f = File('${dir.path}/${fs.name}');
      await f.writeAsBytes(fs.received.takeBytes());
      _log('✅ File saved: ${fs.name} -> ${f.path}');
    } catch (e) {
      _log('Save file failed: $e');
    }
  }

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

  /// Reliable send: broadcast to all connected peers in prototype.
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
        // broadcast to all connected peers in prototype mode
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

  void _log(String m) {
    try {
      setState(() {
        _logs.insert(0, '${DateTime.now().toIso8601String()}  $m');
        if (_logs.length > 1000) _logs.removeRange(1000, _logs.length);
      });
    } catch (_) {
      // ignore UI update errors
    }
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
              Text("OffMesh Node ${myNodeHex ?? "?"}"),
            ],
          ),
          actions: [
            IconButton(
              icon: const Icon(Icons.refresh, color: Colors.greenAccent),
              tooltip: "Rescan Devices",
              onPressed: _startScan,
            ),
          ],
        ),
        body: Column(
          children: [
            // chat/log area
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
                    final isMe = text.contains("➡️ Me:");
                    final isSystem =
                        text.contains("📡") ||
                        text.contains("🔎") ||
                        text.contains("🔗") ||
                        text.contains("🔌") ||
                        text.contains("❌") ||
                        text.contains("✅") ||
                        text.contains("⏳") ||
                        text.contains("Warning");

                    // system logs get monospace label style
                    if (isSystem) {
                      return Container(
                        margin: const EdgeInsets.symmetric(vertical: 2),
                        child: Text(
                          text,
                          style: const TextStyle(
                            fontFamily: "monospace",
                            fontSize: 12,
                            color: Colors.white70,
                          ),
                        ),
                      );
                    }

                    // chat bubbles
                    return Align(
                      alignment: isMe
                          ? Alignment.centerRight
                          : Alignment.centerLeft,
                      child: Container(
                        margin: const EdgeInsets.symmetric(vertical: 4),
                        padding: const EdgeInsets.symmetric(
                          vertical: 8,
                          horizontal: 12,
                        ),
                        constraints: const BoxConstraints(maxWidth: 280),
                        decoration: BoxDecoration(
                          color: isMe
                              ? Colors.greenAccent.withOpacity(0.15)
                              : Colors.white.withOpacity(0.05),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: isMe
                                ? Colors.greenAccent.withOpacity(0.4)
                                : Colors.white24,
                            width: 1,
                          ),
                        ),
                        child: Text(
                          text,
                          style: TextStyle(
                            fontFamily: "monospace",
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

  /// Convert hex -> bytes (safe)
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

  /// Convert bytes -> hex (safe)
  String _bytesToHex(List<int> bytes) {
    try {
      return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    } catch (e) {
      _log('bytesToHex error: $e');
      return '';
    }
  }
}

// ------------ helpers ------------

class _FileState {
  final String name;
  final int? total;
  final BytesBuilder received = BytesBuilder();
  _FileState(this.name, this.total);
}

/// Packet layout:
/// [type:1][ttl:1][src:2][dst:2][pktId:2][len:2][payload:len]
class Packet {
  final int type;
  final int srcId;
  final int dstId;
  final int pktId;
  final Uint8List payload;
  final int ttl;

  Packet(this.type, this.srcId, this.dstId, this.pktId, this.payload, this.ttl);

  List<int> toBytes() {
    final b = BytesBuilder();
    b.addByte(type & 0xFF);
    b.addByte(ttl & 0xFF);
    b.add(_u16(srcId));
    b.add(_u16(dstId));
    b.add(_u16(pktId));
    b.add(_u16(payload.length));
    b.add(payload);
    return b.takeBytes();
  }

  static Packet fromBytes(List<int> data) {
    final d = Uint8List.fromList(data);
    if (d.length < 10) throw FormatException('Packet too short');
    final type = d[0];
    final ttl = d[1];
    final src = _u16From(d, 2);
    final dst = _u16From(d, 4);
    final pktId = _u16From(d, 6);
    final len = _u16From(d, 8);
    if (d.length < 10 + len) throw FormatException('Truncated payload');
    final payload = Uint8List.fromList(d.sublist(10, 10 + len));
    return Packet(type, src, dst, pktId, payload, ttl);
  }

  static List<int> _u16(int v) => [(v >> 8) & 0xFF, v & 0xFF];
  static int _u16From(Uint8List d, int off) => (d[off] << 8) | d[off + 1];
}
