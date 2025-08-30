
# 📄 OffMesh Demo – SRS & Implementation Report

## 1. Introduction

### 1.1 Purpose

The **OffMesh Demo** is a Flutter-based application that enables **peer-to-peer Bluetooth Low Energy (BLE) communication**. It is designed as a **decentralized chat and file transfer system** where devices act as independent nodes.

The system provides:

* Persistent **Node ID** for identity.
* BLE **scanning, advertising, and connecting**.
* **Reliable chat + file transfer** using ACK/Retry.
* A **dark-themed terminal-like UI** with chat bubbles and system logs.

---

## 2. System Requirements

### 2.1 Functional Requirements

1. Generate and store a **unique Node ID** per device.
2. **Advertise** the node over BLE for discovery.
3. **Scan** for nearby nodes.
4. **Connect** to discovered devices.
5. Support **text chat** between nodes.
6. Support **file transfer** with progress tracking.
7. Provide **system logs** of all BLE events.
8. Maintain a **chat-like UI** with:

   * Chat bubbles for user/device messages.
   * Monospace logs for system events.
   * Input bar for typing and sending messages.

### 2.2 Non-Functional Requirements

* **Reliability**: Retransmission mechanism for failed packets.
* **Security**: Persistent Node IDs stored securely using `flutter_secure_storage`.
* **Scalability**: Multiple peers can connect and relay messages.
* **Usability**: Dark UI with clear distinction between chat and logs.

### 2.3 Hardware/Software Requirements

* **Platform**: Android 8.0+
* **Language**: Dart (Flutter)
* **Dependencies**:

  * `flutter_reactive_ble` – BLE communication.
  * `flutter_ble_peripheral` – BLE advertising.
  * `flutter_secure_storage` – Persistent ID.
  * `cryptography` – Encryption (optional future).
  * `path_provider` – File storage.
  * `uuid` – Unique service IDs.

---

## 3. System Design

### 3.1 Architecture

```
 ┌─────────────┐
 │   Node A    │
 │ (Advertise) │
 └─────┬───────┘
       │ BLE
 ┌─────▼───────┐
 │   Node B    │
 │   (Scan)    │
 └─────────────┘
```

* Nodes advertise services + scan simultaneously.
* When a peer is discovered, connection is established.
* Messages/files are exchanged with **ACK/Retry**.
* Logs track every event.

---

## 4. Implementation Details

### 4.1 Main UI (Code you shared)

* Built with **`MaterialApp`** in dark mode.
* AppBar shows **Node ID** and a **refresh button** for scanning.
* Body:

  * **ListView** for displaying chat messages & logs.
  * **TextField + Send button** for input.

### 4.2 Functions

#### `_startScan()`

* Starts BLE scanning.
* Logs discovered devices.
* Updates UI when new peers are found.

#### `_startAdvertise()`

* Starts BLE advertising with unique Node ID.
* Allows other nodes to discover this device.

#### `_connectToDevice(device)`

* Attempts to connect to a discovered BLE device.
* On success: initializes message channel.
* Logs connection state (✅ Connected / ❌ Failed).

#### `_sendChat(String msg)`

* Takes input message, wraps with metadata (Node ID).
* Sends message via BLE write characteristic.
* Adds to local `_logs` as `➡️ Me:`.

#### `_onMessageReceived(String msg, fromNode)`

* Triggered when peer sends data.
* Checks if it’s:

  * **Chat** → Display as bubble.
  * **System** → Display as monospace log.
* Logs `🔗 Message received`.

#### `_sendFile(File file)`

* Splits file into BLE packet chunks.
* Sends sequentially with **ACK for each packet**.
* Retries if no ACK received in timeout.
* Logs transfer progress (`⏳ 25%`, `✅ Complete`).

#### `_generateNodeId()`

* Generates a random hex ID on first launch.
* Stores securely in `flutter_secure_storage`.
* Retrieved on future launches (persistent identity).

---

## 5. UI/UX Features

* **Dark theme** (background `#0D0D0D`).
* **Neon green accents** for identity.
* **Chat bubbles**:

  * Green (Me).
  * Gray (Peers).
* **System logs**:

  * Monospace font.
  * Subdued white color.
* **AppBar**:

  * Shows `OffMesh Node <ID>`.
  * Refresh button to rescan peers.
* **Bottom Input Bar**:

  * Rounded text field with hint.
  * Glowing green Send button.

---

## 6. What Has Been Implemented ✅

* ✅ **Persistent Node ID** generation & storage.
* ✅ **BLE scanning & advertising**.
* ✅ **Connection management** (connect/disconnect).
* ✅ **Chat messaging** between nodes.
* ✅ **ACK/Retry mechanism** for reliable transfer.
* ✅ **File transfer support** (chunked).
* ✅ **UI** with chat bubbles + logs + input field.
* ✅ **System logs** for BLE events.

---

## 7. Future Improvements 🚀

* 🔒 End-to-end encryption (using `cryptography`).
* 📡 Multi-hop mesh routing (relay messages through peers).
* 📂 File sharing UI (progress bar per file).
* 🖥️ Separate **tabs** for Chat vs Console Logs.
* 📊 Node statistics (battery, uptime, peers connected).

---

