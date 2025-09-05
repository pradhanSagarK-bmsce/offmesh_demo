/// Flutter OffMesh Prototype — main.dart (full)
/// BLE chat + multi-hop file transfer + optional E2E encryption + UI tabs
///
/// Features added/implemented:
/// - Chat with ACK/retry and per-packet reliable send
/// - Full file transfer (meta + chunked payloads) with progress UI
/// - Multi-hop forwarding (TTL) to relay packets
/// - Optional end-to-end encryption toggle using X25519 -> AES-GCM
/// - Key-exchange packet type (ephemeral X25519 public keys)
/// - Logs tab (all system/logs) and Chat tab (clean chat view)
/// - Node Stats tab: battery (battery_plus), uptime, peers list
/// - Robust try/catch and defensive handling across the code
/// - Uses flutter_reactive_ble, flutter_ble_peripheral, cryptography,
///   flutter_secure_storage, path_provider, permission_handler, file_picker,
///   battery_plus
///
/// IMPORTANT: This is research/test prototype code. Do NOT use in production
/// without proper security review. The encryption is included as an optional
/// feature but the authentication and trust model is simplistic.
///
/// Make sure AndroidManifest has the required Bluetooth + storage permissions.
/// Also add required plugin setup for Android 12+ if targeting newer SDKs.
/// Flutter OffMesh Prototype — main.dart (full)
/// BLE chat + multi-hop file transfer + optional E2E encryption + UI tabs
///
/// This file is a research prototype. Do NOT use in production without review.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:battery_plus/battery_plus.dart';
import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_ble_peripheral/flutter_ble_peripheral.dart';
import 'package:flutter_reactive_ble/flutter_reactive_ble.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
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
  // BLE & peripheral
  final flutterReactiveBle = FlutterReactiveBle();
  final peripheral = FlutterBlePeripheral();

  // UUIDs (example)
  final Uuid _serviceUuid = Uuid.parse('12345678-1234-5678-1234-56789abcdef0');
  final Uuid _charInbox = Uuid.parse('12345678-1234-5678-1234-56789abcdef1');
  final Uuid _charOutbox = Uuid.parse('12345678-1234-5678-1234-56789abcdef2');
  final Uuid _charInfo = Uuid.parse('12345678-1234-5678-1234-56789abcdef3');

  // storage & identity
  final storage = const FlutterSecureStorage();
  SimpleKeyPair? myKeypair; // Ed25519 identity
  String? myNodeHex; // short public id (hex prefix)

  // ephemeral X25519 keypair (for key exchange)
  SimpleKeyPair? _ephemeralKeypair; // X25519
  SimplePublicKey? _ephemeralPublic; // our ephemeral public

  // per-peer derived secret keys (map by deviceId)
  final Map<String, SecretKey> _peerSecrets = {};

  // peers/subscriptions
  final Map<String, DiscoveredDevice> _peers = {};
  final Map<String, StreamSubscription<List<int>>> _outboxSubs = {};
  final Map<String, StreamSubscription<ConnectionStateUpdate>> _connSubs = {};

  // pending ACKs and file state
  final Map<int, Completer<bool>> _pendingAcks = {};
  final Map<int, _FileState> _incomingFiles = {};
  final Map<int, _OutgoingFileState> _outgoingFiles = {};

  // constants
  static const int maxTtl = 5;
  static const int typeChat = 1;
  static const int typeFileMeta = 2;
  static const int typeFileChunk = 3;
  static const int typeAck = 4;
  static const int typeKeyExchange = 5;

  // UI / state
  final List<String> _logs = [];
  final List<String> _chatMessages = [];
  final TextEditingController _msgCtrl = TextEditingController();
  int _selectedTabIndex = 0; // 0=Chat,1=Logs,2=Stats
  bool _encryptionEnabled = false;
  bool _autoExchangeKeys = true;

  // battery & uptime
  final Battery _battery = Battery();
  int _batteryLevel = -1;
  StreamSubscription<BatteryState>? _batteryStateSub;
  DateTime _startTime = DateTime.now();

  int? get myNodeId =>
      myNodeHex != null ? int.tryParse(myNodeHex!, radix: 16) : null;

  @override
  void initState() {
    super.initState();
    _initAll();
    _startBatteryMonitor();
  }

  Future<void> _startBatteryMonitor() async {
    try {
      _updateBattery();
      _batteryStateSub = _battery.onBatteryStateChanged.listen((
        BatteryState state,
      ) {
        // update level periodically
        _updateBattery();
      });
    } catch (e) {
      _log('Battery monitor start error: $e');
    }
  }

  Future<void> _updateBattery() async {
    try {
      final lvl = await _battery.batteryLevel;
      setState(() => _batteryLevel = lvl);
    } catch (e) {
      _log('Battery read error: $e');
    }
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

    // create ephemeral keypair for X25519 (we can rotate later)
    await _createEphemeralKeys();

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

  Future<void> _createEphemeralKeys() async {
    try {
      final alg = X25519();
      final kp = await alg.newKeyPair();
      final pub = await kp.extractPublicKey();
      _ephemeralKeypair = kp;
      _ephemeralPublic = pub;
      _log('🔐 Ephemeral key created for key-exchange');
    } catch (e) {
      _log('Ephemeral key create error: $e');
    }
  }

  // ---------------- permissions ---------------------------------------------
  Future<bool> _requestBlePermissions() async {
    try {
      final statuses = await [
        perms.Permission.bluetoothScan,
        perms.Permission.bluetoothConnect,
        perms.Permission.bluetoothAdvertise,
        perms.Permission.location,
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

  // ---------------- identity (secure storage) --------------------------------
  Future<void> _loadOrCreateKeypair() async {
    try {
      final pubHex = await storage.read(key: 'pub');
      final privHex = await storage.read(key: 'priv');

      if (pubHex != null && privHex != null) {
        // reconstruct identity (prototype)
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

      // else create new Ed25519 keypair for identity (stored in secure storage)
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

  // ---------------- advertising & scanning ----------------------------------
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
      final stream = flutterReactiveBle.scanForDevices(
        withServices: [_serviceUuid],
      );
      stream.listen(
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

      final sub = stream.listen((state) async {
        try {
          if (state.connectionState == DeviceConnectionState.connected) {
            _log('🔗 Connected to ${d.name.isEmpty ? d.id : d.name}');
            _subscribeOutbox(d.id);
            // send our ephemeral public key optionally
            if (_autoExchangeKeys && _ephemeralPublic != null) {
              await _sendKeyExchange(d.id, _ephemeralPublic!.bytes);
            }
          } else if (state.connectionState ==
              DeviceConnectionState.disconnected) {
            _log('🔌 Disconnected ${d.id}');
            try {
              _outboxSubs[d.id]?.cancel();
            } catch (_) {}
            _outboxSubs.remove(d.id);
            _peers.remove(d.id);
            // remove peer secret
            _peerSecrets.remove(d.id);
          }
        } catch (e) {
          _log('Connect state handler error: $e');
        }
      }, onError: (e) => _log('Connection stream error ${d.id}: $e'));

      // keep reference to cancel if needed
      _connSubs[d.id] = sub;
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
      ) async {
        try {
          await _onOutboxNotify(deviceId, data);
        } catch (e) {
          _log('Outbox notify parse error: $e');
        }
      }, onError: (e) => _log('Outbox subscription error $deviceId: $e'));
      _outboxSubs[deviceId] = sub;
    } catch (e) {
      _log('Subscribe failed $deviceId: $e');
    }
  }

  Future<void> _onOutboxNotify(String deviceId, List<int> data) async {
    try {
      final pkt = Packet.fromBytes(data);
      await _handlePacket(deviceId, pkt);
    } catch (e) {
      _log('Failed to parse packet from $deviceId: $e');
    }
  }

  // ---------------- packet handling & routing -------------------------------
  Future<void> _handlePacket(String fromDeviceId, Packet pkt) async {
    try {
      if (_seen(pkt.pktId)) return;

      // If encryption enabled and we have a secret for this peer, attempt to decrypt payload
      Uint8List effectivePayload = pkt.payload;
      if (_encryptionEnabled && _peerSecrets.containsKey(fromDeviceId)) {
        try {
          final decrypted = await _decryptPayloadAsync(
            fromDeviceId,
            pkt.payload,
          );
          if (decrypted != null) {
            effectivePayload = decrypted;
          } else {
            _log('⚠️ Decrypt failed for pkt ${pkt.pktId} from $fromDeviceId');
          }
        } catch (e) {
          _log('Decrypt exception: $e');
        }
      }

      // send ACK back to sender only (for reliability)
      if (pkt.type != typeAck && myNodeId != null) {
        final ack = Packet(
          typeAck,
          myNodeId!,
          pkt.srcId,
          pkt.pktId,
          Uint8List(0),
          maxTtl,
        );
        await _sendPacketRawToDevice(fromDeviceId, ack.toBytes());
      }

      // routing: if packet dest is not me and TTL > 1, forward (multi-hop)
      if (pkt.dstId != 0xFFFF &&
          myNodeId != null &&
          pkt.dstId != myNodeId &&
          pkt.ttl > 1) {
        // forward by decrementing ttl and broadcasting to peers (except the one we got it from)
        final fwd = Packet(
          pkt.type,
          pkt.srcId,
          pkt.dstId,
          pkt.pktId,
          pkt.payload,
          pkt.ttl - 1,
        );
        _log('↪️ Forwarding pkt ${pkt.pktId} (ttl->${pkt.ttl - 1}) to peers');
        _broadcastExcept(fromDeviceId, fwd.toBytes());
        // continue handling locally if destined to wildcard (we still process)
      }

      switch (pkt.type) {
        case typeChat:
          final msg = utf8.decode(effectivePayload);
          final display =
              '💬 [${pkt.srcId.toRadixString(16).padLeft(8, "0").toUpperCase()}] $msg';
          _log(display, addToChat: true);
          _completePending(pkt.pktId, true);
          break;

        case typeFileMeta:
          _handleIncomingFileMetaWithPayload(pkt, effectivePayload);
          break;

        case typeFileChunk:
          _handleIncomingFileChunkWithPayload(pkt, effectivePayload);
          break;

        case typeAck:
          _completePending(pkt.pktId, true);
          break;

        case typeKeyExchange:
          await _handleKeyExchangePacket(fromDeviceId, pkt, effectivePayload);
          break;

        default:
          _log('Unknown pkt type ${pkt.type}');
      }
    } catch (e) {
      _log('Handle packet error: $e');
    }
  }

  // forward to all peers except excludedDeviceId
  void _broadcastExcept(String? excludedDeviceId, List<int> bytes) {
    try {
      for (final entry in _peers.entries) {
        final deviceId = entry.key;
        if (excludedDeviceId != null && deviceId == excludedDeviceId) continue;
        _sendPacketRawToDevice(deviceId, bytes);
      }
    } catch (e) {
      _log('Broadcast error: $e');
    }
  }

  void _handleIncomingFileMetaWithPayload(Packet pkt, Uint8List payload) {
    try {
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

  void _handleIncomingFileChunkWithPayload(Packet pkt, Uint8List payload) {
    try {
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

  // ---------------- Key exchange & encryption helpers -----------------------
  Future<void> _sendKeyExchange(
    String deviceId,
    List<int> ourPublicBytes,
  ) async {
    try {
      final pktId = DateTime.now().millisecondsSinceEpoch & 0x7FFFFFFF;
      final payload = BytesBuilder();
      // payload: publen(2) + pubbytes
      payload.add(_u16(ourPublicBytes.length));
      payload.add(ourPublicBytes);
      final pkt = Packet(
        typeKeyExchange,
        myNodeId ?? 0x0000,
        0xFFFF,
        pktId,
        Uint8List.fromList(payload.takeBytes()),
        maxTtl,
      );
      await _sendPacketRawToDevice(deviceId, pkt.toBytes());
      _log('🔁 Sent key-exchange to $deviceId (pkt $pktId)');
    } catch (e) {
      _log('Send key-exchange error: $e');
    }
  }

  Future<void> _handleKeyExchangePacket(
    String fromDeviceId,
    Packet pkt,
    Uint8List payload,
  ) async {
    try {
      if (payload.length < 2) {
        _log('KeyExchange: payload too short');
        return;
      }
      final pubLen = _u16From(Uint8List.fromList(payload), 0);
      if (payload.length < 2 + pubLen) {
        _log('KeyExchange: truncated payload');
        return;
      }
      final peerPub = payload.sublist(2, 2 + pubLen);

      // compute shared secret using our ephemeral keypair
      if (_ephemeralKeypair == null) {
        await _createEphemeralKeys();
        if (_ephemeralKeypair == null) {
          _log('No ephemeral key to compute shared secret');
          return;
        }
      }

      try {
        final alg = X25519();
        final shared = await alg.sharedSecretKey(
          keyPair: _ephemeralKeypair!,
          remotePublicKey: SimplePublicKey(
            Uint8List.fromList(peerPub),
            type: KeyPairType.x25519,
          ),
        );

        // store secret for this peer
        _peerSecrets[fromDeviceId] = shared;
        _log('🔐 Derived shared secret with $fromDeviceId');

        // optionally send our public key back if we didn't initiate
        if (_autoExchangeKeys && _ephemeralPublic != null) {
          await _sendKeyExchange(fromDeviceId, _ephemeralPublic!.bytes);
        }
      } catch (e) {
        _log('Key exchange compute error: $e');
      }
    } catch (e) {
      _log('Handle key-exchange error: $e');
    }
  }

  // Encrypt: produce bytes: nonce(12) + macLen(2) + mac + ciphertext
  Future<Uint8List?> _encryptPayloadAsync(
    String deviceId,
    Uint8List plain,
  ) async {
    try {
      final secret = _peerSecrets[deviceId];
      if (secret == null) return null;
      final aes = AesGcm.with256bits();
      final nonce = _randomBytes(12);
      final secretBox = await aes.encrypt(
        plain,
        secretKey: secret,
        nonce: nonce,
      );
      final macBytes = secretBox.mac.bytes;
      final out = BytesBuilder();
      out.add(nonce); // 12 bytes
      out.add(_u16(macBytes.length)); // mac length (2 bytes)
      out.add(macBytes); // MAC
      out.add(secretBox.cipherText); // cipher text
      return Uint8List.fromList(out.takeBytes());
    } catch (e) {
      _log('Encrypt error: $e');
      return null;
    }
  }

  // Decrypt counterpart to above format:
  // payload layout: nonce(12) + macLen(2) + mac + cipherText
  Future<Uint8List?> _decryptPayloadAsync(
    String deviceId,
    Uint8List payload,
  ) async {
    try {
      final secret = _peerSecrets[deviceId];
      if (secret == null) return null;
      if (payload.length < 14) return null; // nonce(12) + macLen(2) minimal
      final nonce = payload.sublist(0, 12);
      final macLen = _u16From(Uint8List.fromList(payload), 12);
      final macStart = 14;
      final macEnd = macStart + macLen;
      if (payload.length < macEnd) return null;
      final macBytes = payload.sublist(macStart, macEnd);
      final cipher = payload.sublist(macEnd);
      final secretBox = SecretBox(cipher, nonce: nonce, mac: Mac(macBytes));
      final aes = AesGcm.with256bits();
      final clear = await aes.decrypt(secretBox, secretKey: secret);
      return Uint8List.fromList(clear);
    } catch (e) {
      _log('Decrypt async error: $e');
      return null;
    }
  }

  // ---------------- low-level send ------------------------------------------
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

      final completer = Completer<bool>();
      _pendingAcks[pktId] = completer;
      int attempt = 0;

      while (attempt < retries && !completer.isCompleted) {
        attempt++;

        // send per-peer, possibly encrypted per-peer
        for (final entry in _peers.entries) {
          final deviceId = entry.key;
          try {
            List<int> bytesToSend;
            if (_encryptionEnabled && _peerSecrets.containsKey(deviceId)) {
              // encrypt for that peer
              final encrypted = await _encryptPayloadAsync(deviceId, payload);
              if (encrypted != null) {
                final pktEnc = Packet(
                  type,
                  myNodeId!,
                  dstId,
                  pktId,
                  encrypted,
                  maxTtl,
                );
                bytesToSend = pktEnc.toBytes();
              } else {
                // fallback plaintext
                final pktPlain = Packet(
                  type,
                  myNodeId!,
                  dstId,
                  pktId,
                  payload,
                  maxTtl,
                );
                bytesToSend = pktPlain.toBytes();
              }
            } else {
              final pktPlain = Packet(
                type,
                myNodeId!,
                dstId,
                pktId,
                payload,
                maxTtl,
              );
              bytesToSend = pktPlain.toBytes();
            }

            await _sendPacketRawToDevice(deviceId, bytesToSend);
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

  // ---------------- chat & file sending ------------------------------------
  void _sendChat(String text) async {
    try {
      final pktId = DateTime.now().millisecondsSinceEpoch & 0x7FFFFFFF;
      final bytes = Uint8List.fromList(utf8.encode(text));
      await _sendReliable(0xFFFF, pktId, typeChat, bytes);
      _log('➡️ Me: $text', addToChat: true);
    } catch (e) {
      _log('Send chat error: $e');
    }
  }

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
      const int chunkSize = 512;
      final totalChunks = (bytes.length / chunkSize).ceil();
      final baseId = _random32();
      final ofs = _OutgoingFileState(name, bytes.length, totalChunks);
      _outgoingFiles[baseId] = ofs;

      // meta payload
      final metaText = '$name|$totalChunks|${bytes.length}';
      final metaPayload = BytesBuilder();
      metaPayload.add(_u32(baseId));
      metaPayload.add(utf8.encode(metaText));
      final metaPktId = baseId ^ 0xA5A50000;
      await _sendReliable(
        0xFFFF,
        metaPktId,
        typeFileMeta,
        Uint8List.fromList(metaPayload.takeBytes()),
      );

      // chunks
      for (int i = 0; i < totalChunks; i++) {
        final off = i * chunkSize;
        final end = min(off + chunkSize, bytes.length);
        final chunk = bytes.sublist(off, end);
        final chunkPayload = BytesBuilder();
        chunkPayload.add(_u32(baseId));
        chunkPayload.add(_u16(i));
        chunkPayload.add(chunk);
        final pktId = baseId ^ (i & 0xFFFF);

        ofs.sentChunks = i + 1;
        setState(() {});

        await _sendReliable(
          0xFFFF,
          pktId,
          typeFileChunk,
          Uint8List.fromList(chunkPayload.takeBytes()),
        );

        // if ack arrived earlier it's removed; we check _pendingAcks
        if (!_pendingAcks.containsKey(pktId)) {
          ofs.ackedChunks++;
        }
        setState(() {});
      }

      _log('📤 File send finished (meta+chunks): $name');
      _outgoingFiles.remove(baseId);
    } catch (e) {
      _log('Send file error: $e');
    }
  }

  // ---------------- incoming file save -------------------------------------
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

  // ---------------- helpers & utilities ------------------------------------
  void _log(String m, {bool addToChat = false}) {
    try {
      final ts = '${DateTime.now().toIso8601String()}  $m';
      setState(() {
        _logs.insert(0, ts);
        if (_logs.length > 3000) _logs.removeRange(3000, _logs.length);
        if (addToChat) {
          _chatMessages.insert(0, ts);
          if (_chatMessages.length > 2000)
            _chatMessages.removeRange(2000, _chatMessages.length);
        } else {
          // if message is chat prefixed with 💬 or ➡️ Me: also add to _chatMessages
          if (m.startsWith('💬') || m.startsWith('➡️ Me:')) {
            _chatMessages.insert(0, ts);
            if (_chatMessages.length > 2000)
              _chatMessages.removeRange(2000, _chatMessages.length);
          }
        }
      });
    } catch (_) {}
  }

  final Set<int> _seenPktIds = {};
  bool _seen(int pktId) {
    try {
      if (_seenPktIds.contains(pktId)) return true;
      _seenPktIds.add(pktId);
      if (_seenPktIds.length > 20000) _seenPktIds.clear();
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

  // local parsers
  int _u16From(Uint8List d, int off) => (d[off] << 8) | d[off + 1];
  int _u32From(List<int> d, int off) =>
      (d[off] << 24) | (d[off + 1] << 16) | (d[off + 2] << 8) | d[off + 3];

  int _random32() {
    final rnd = Random.secure();
    return rnd.nextInt(0x7FFFFFFF);
  }

  Uint8List _randomBytes(int n) {
    final rnd = Random.secure();
    final out = Uint8List(n);
    for (int i = 0; i < n; i++) out[i] = rnd.nextInt(256);
    return out;
  }

  @override
  void dispose() {
    try {
      for (final s in _outboxSubs.values) s.cancel();
      for (final s in _connSubs.values) s.cancel();
      _batteryStateSub?.cancel();
      peripheral.stop();
    } catch (_) {}
    super.dispose();
  }

  // ---------------- UI -----------------------------------------------------
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
            // Tab selector
            _buildTabBar(),

            // Tab content
            Expanded(
              child: IndexedStack(
                index: _selectedTabIndex,
                children: [_buildChatTab(), _buildLogsTab(), _buildStatsTab()],
              ),
            ),

            // Input row (only visible on chat tab)
            if (_selectedTabIndex == 0) _buildInputRow(),
          ],
        ),
      ),
    );
  }

  Widget _buildTabBar() {
    return Container(
      color: const Color(0xFF111111),
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          _tabButton(Icons.chat_bubble, 'Chat', 0),
          _tabButton(Icons.list_alt, 'Logs', 1),
          _tabButton(Icons.info_outline, 'Node Stats', 2),
        ],
      ),
    );
  }

  Widget _tabButton(IconData icon, String label, int idx) {
    final active = _selectedTabIndex == idx;
    return GestureDetector(
      onTap: () => setState(() => _selectedTabIndex = idx),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: active ? Colors.greenAccent : Colors.white70),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              color: active ? Colors.greenAccent : Colors.white70,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildChatTab() {
    return Container(
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
        itemCount: _chatMessages.length,
        itemBuilder: (_, i) {
          final text = _chatMessages[i];
          final isMe = text.contains('➡️ Me:');
          return Align(
            alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
            child: Container(
              margin: const EdgeInsets.symmetric(vertical: 6),
              padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 14),
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
    );
  }

  Widget _buildLogsTab() {
    return Container(
      padding: const EdgeInsets.all(12),
      color: const Color(0xFF0B0B0B),
      child: ListView.builder(
        reverse: true,
        itemCount: _logs.length,
        itemBuilder: (_, i) {
          final text = _logs[i];
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
        },
      ),
    );
  }

  Widget _buildStatsTab() {
    final uptime = DateTime.now().difference(_startTime);
    return Container(
      padding: const EdgeInsets.all(12),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _statRow('Node ID', myNodeHex ?? '?'),
            _statRow('Peers discovered', _peers.length.toString()),
            _statRow('Connected subs', _outboxSubs.length.toString()),
            _statRow(
              'Battery',
              _batteryLevel >= 0 ? '$_batteryLevel%' : 'Unknown',
            ),
            _statRow('Uptime', _formatDuration(uptime)),
            const SizedBox(height: 12),
            Row(
              children: [
                const Text(
                  'Encryption:',
                  style: TextStyle(fontFamily: 'monospace'),
                ),
                const SizedBox(width: 8),
                Switch(
                  value: _encryptionEnabled,
                  onChanged: (v) => setState(() => _encryptionEnabled = v),
                ),
                const SizedBox(width: 12),
                const Text(
                  'Auto key-exchange:',
                  style: TextStyle(fontFamily: 'monospace'),
                ),
                const SizedBox(width: 8),
                Switch(
                  value: _autoExchangeKeys,
                  onChanged: (v) => setState(() => _autoExchangeKeys = v),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              'Peer secrets (derived):',
              style: TextStyle(
                fontFamily: 'monospace',
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 6),
            for (final e in _peerSecrets.entries)
              Text(
                '${e.key} — secret: ${e.value.hashCode.toRadixString(16)}',
                style: const TextStyle(fontFamily: 'monospace'),
              ),
            const SizedBox(height: 12),
            const Text(
              'Discovered devices:',
              style: TextStyle(
                fontFamily: 'monospace',
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 6),
            for (final e in _peers.entries)
              Text(
                '${e.key} — ${e.value.name.isEmpty ? "<no name>" : e.value.name}',
                style: const TextStyle(fontFamily: 'monospace'),
              ),
          ],
        ),
      ),
    );
  }

  Widget _statRow(String k, String v) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            k,
            style: const TextStyle(
              fontFamily: 'monospace',
              color: Colors.white70,
            ),
          ),
          Text(
            v,
            style: const TextStyle(
              fontFamily: 'monospace',
              color: Colors.greenAccent,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInputRow() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A1A),
        border: Border(top: BorderSide(color: Colors.white24, width: 0.5)),
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
                  borderSide: const BorderSide(color: Colors.greenAccent),
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
    );
  }

  String _formatDuration(Duration d) {
    final h = d.inHours;
    final m = d.inMinutes.remainder(60);
    final s = d.inSeconds.remainder(60);
    return '${h}h ${m}m ${s}s';
  }
}

// ---------------------------------------------------------------------------
// Helper classes
// ---------------------------------------------------------------------------

class _FileState {
  final String name;
  final int? total; // number of chunks
  final int? bytesTotal;
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
