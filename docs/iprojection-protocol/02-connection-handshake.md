# 02 — Connection & handshake

> Confidence tags as in doc 01: **[V]** read from code/rodata, **[I]** inferred, **[?]** unresolved.
> Source of truth is the native library ([`apk/decompile/libengine_arm64/c/`](../apk/decompile/libengine_arm64/c));
> Ghidra address = ELF vaddr + `0x100000`. Nothing here has been validated on hardware.

## 1. Big picture

A "session" with a projector uses **three** TCP connections plus a UDP/TCP keep-alive:

```
client                                                   projector
  │  TCP  3620  ECON control channel (EEMP0100 messages)    │   session start/stop, active list, U2U, WebRTC SDP …
  │  TCP  3621  PCON picture connection  ("EPRD0600")       │   screen rectangles (JPEG/RAW/…)  → doc 04
  │  TCP  3621  PCON audio connection    (optional)         │   PCM audio                       → doc 04
  │  UDP 3620 (or TCP 3620) keep-alive, ECON cmd 10         │   every 1 s (UDP) / 5 s (TCP), timeout 10 s
  │  TCP  3629  ESC/VP.net (stand-alone, short-lived)       │   remote control + power status  → doc 03
```

Up to **4 projectors** can be connected at once (`Define.CONNECT_MAX_NUM = 4`); the app sends the same bitmap to all.
Alternatively, on Android 10+ with an H.264-capable device and a projector that reports WebRTC support
(`D_PjInfo.isSupportedWebRTC`, single projector only) the picture is carried by **WebRTC**; the ECON channel then only
carries SDP (see doc 04 §6).

## 2. Java-side call sequence

```
ConnectionControler.tryConnect(list)                         ui/engine_wrapper/ConnectionControler.java
  ├─ if a QR/NFC "linkage" search is active: keyword := "QUICKCON" (isSupportConnectionIdentifier) | "2270"
  ├─ if PJ busy (Status==2)  → confirmation dialog;  if D_PjInfo.isNeededPjKeyword → keyword dialog
  └─ callConnect() → Pj.connect(list) → PjConnector.connect()
        Engine.SetEncryption(pref)      = NEngSetParameter(3, 0|1)       1 = AES
        Engine.SetProjectorLogUpload()  = NEngSetParameter(25, 0|1)
        Engine.SetBandWidth(eBandWidth) = NEngSetParameter(22, ordinal)  {noControl,4M,2M,1M,512K,256K,7M,15M,25M}
        Engine.SetAudioTransfer()       = NEngSetParameter(5, 0|1)
        (optional) pre-connect fixed-IP search to refresh D_PjInfo      (needed: native engine keys everything by ProjectorID)
        Pj.doConnect():
          Engine.ChangeProtocol(JPEG|WebRTC)    = NEngChangeProtocol(bool)
          for each PJ: D_ConnectPjInfo{ProjectorID, PrjKeyWord, nBPP=32, bCompulsionResolution=true, bNotBreak, nMPPControlMode}
          Engine.GetSendImageBufferSize(list,int[2])  → native returns the (W,H) bitmap size to render for these PJs
          Engine.Connect(list, listener, userName)    = NEngConnectProjector(ArrayList<D_ConnectPjInfo>, String userName)
JNI callback:  EngineJni.CallBackResult(kind, projectorId, code) → OnPjEventListener.onConnectRet(kind, id, code)
```

`userName` is only non-null for moderator / multi-PC projection (MPP) sessions.

Result codes delivered to `onConnectRet` ([Engine.java](../apk/sources/com/epson/iprojection/engine/Engine.java), [ErrCodeDemuxer.java](../apk/sources/com/epson/iprojection/ui/engine_wrapper/utils/ErrCodeDemuxer.java)):

| code | meaning | | code | meaning |
|---|---|---|---|---|
| `0` | connected | | `-401` | cannot connect to projector |
| `2` | connected, show projector-selection UI | | `-402` | **illegal projector keyword** |
| `-405` / `-419` | NP / MPP version mismatch | | `-403` | projector powered off |
| `-415` | MPP max users reached | | `-404` | interrupted by another user |
| `-416` | mirror/combination not allowed | | `-406` / `-421` | network error / no response |
| `-424` | terminated by other user | | `-438` | disconnected by admin (moderator) |
| `-450` | keep-alive timeout | | `-441` | wrong ESC/VP.net web password (see doc 03) |

## 3. Wire-level connection sequence (native)

```
1. TCP connect  client(NIC ip : ephemeral)  →  <pj-ip>:3620           CEconProjectionClientNetwork::ConnectTCP  (timeout 10 s)
2. ECON 0x101  REQ_START_SESSION  (client → PJ)                         CEconProjectionClientNSC10::SendEconConnect
3. ECON 0x102  started_session   (PJ → client)    | 0x103 reject_start_session(nErrCategory, nErrCause)
4. start keep-alive (UDP 1 s or TCP 5 s, ECON cmd 10)                   CKeepAlive::Exec
5. ECON 0x110  require_connect_picture_control (PJ → client)  ⇒ client opens PCON 3621 picture (+audio) sockets
6. client streams EPRD0600 picture data (doc 04)
7. teardown: 0x106 TERMINATE_SESSION / 0x104 DROP_SESSION  →  0x107 / 0x105 ack
```

Legacy (non-NSC10) projectors use ids `0x04`/`0x12` instead of `0x101` (`CEconProjectionClientNSC::SendEconConnect`).

### 3.1 `0x101` REQ_START_SESSION  **[V] structure / [I] field meaning**

Built by `CEasyCommand::MakeReqConnect` + `AddRecord` + `AddExtParam*` (see doc 01 §3 for the container).

```
ECON header   "EEMP0100" | client-ip(4) | 0x00000101 | payload-len
payload body (0x30 bytes, offsets from payload start; LE unless noted):
  +0x00  u8   record count = 1
  +0x01  u8   extension present = 1
  +0x04  u8   connect type: 0 normal NP; 1 any other non-zero MPP mode; 2 when nMPPControlMode==1 (collaboration, old);
              3 when nMPPControlMode==3 (moderator entry ⇒ secure MPP params with RSA + HMAC)  (CEasyCommand::MakeReqConnect)
  +0x05  u8[8]   8-byte value taken from the caller (client random / FCN key seed) [I]
  +0x0D  u32  IPv4 slot  (projector-side address field #1)                                      [I]
  +0x11  u32  IPv4 slot  (projector-side address field #2)                                      [I]
  +0x15  u8   feature flags: bit0 pause/resume, bit1 audio sending, bit3 projector flag 0x1b76 [I]
  +0x16  u8   value/1000 of a client setting (bandwidth/throughput class)                         [I]
  +0x17  u8   flag byte                                                                           [I]
  +0x18  u16  max picture width  (LE)         ← GetMinimumSettingImageWidth / client resolution
  +0x1A  u16  max picture height (LE)
  +0x1C  pixel format, RFB-style (13 B):  bpp, depth, bigEndian=0, trueColour=1,
           redMax u16 LE, greenMax u16 LE, blueMax u16 LE, three shift bytes, pad
           32/24 bpp → 20 20 00 01  FF 00 FF 00 FF 00  00 08 10 00 …
           16 bpp    → 10 10 00 01  1F 00 3F 00 1F 00  0B 05 00 00 …   (RGB565)
           (the shift-byte order here is not the same as in the PCON screen-format command, doc 04 §4.2 — keep both as observed)
  +0x2C  u8, +0x2D u8   two flag bytes from the connect parameter block                           [I]
  record[0] (26 B)   projector unique id / MAC[6] | ASCII name[16] | u32 projector IPv4
  extension TLVs (id u32 | len u32 | value):
     0x05 UserID            (own attender id)        0x04 PJ list (also used for the mirror-projector list)
     0x06/0x07/0x08 user lists (active / reserve / all)   0x1B octet string   0x1C HasControlPad   0x21 Invoice
     0x11 DynamicClientResolution, 0x0E ClientResolution(u8), 0x12 ResolutionMultiUser(u8)
     0x0F MaxUserNum(u32)   0x0D MPPVersion(u32)     0x25 MPPControlMode(u32 + user id)
     0x26 DeliveryParameter / SharedInformation       0x13 FCN params (pen/mouse/touch back-channel, device list)
     0x2A SecureMPPParams   → nested 0x2B (PEM public key) + 0x2C (32-byte HMAC signature)  (only when connect type 3)
     0x2D TransmitterInfo(u32, =1 for Chrome/transmitter) 0x2E WebRTCParameter(u8 0|1)       0x30 ServerOS(u32 os + 8 B app version)
```

`ServerOS`: `4` = Android transmitter (modes 3/4), `6` = Android, `7` = ChromeOS (`IsChromeOSOnJava`).
The client's `name` field is `my_wcstombs(userName, max 16+NUL)`.

### 3.2 `0x102` started_session (success response)  **[V]**

Handled in `CEconProjectionClientNSC10::AnalyzeEconData` (`case 0x102`). Relevant content:

* body byte `+4` → `ProjectorID`-session partition/slot (`this+0x9c`), byte `+5` bit 3 → capability flag (`this+0x18788`).
* ext **UserID (0x05)** = *your* attender/user id assigned by the projector (stored with `CUserInfoList::UpdateUserIDMySelf`) —
  this 32-bit value later becomes the **PCON authentication id** (see §4.1).
* ext **PJ list**, **FirstUser**, **MPPControlMode**, **DeliveryParameter** `(u32 deliveryEnabled, u32 …)` and **EncParams**
  (`ECON_FCN_ENC_PARAMS`: `type` 1/2/3 + 8-byte key seed) → `CProjectorNetwork::SetEncryptInfo` (see §6).
* ext **Password** / **SharedPinCode** → moderator password material (converted by `CModeratorPasswordConverter`).
* After this, keep-alive starts (`e_KeepAlive_UDP`, `e_KeepAlive_TCP` or `e_KeepAlive_TCP_duplex` depending on the PJ's
  `isSupportBiDirectionalTCPKeepAlive`/`UniDirectionalTCPConnect` capability).

`0x103` carries `nErrCategory`/`nErrCause` which `ErrCodeDemuxer`/`MsgGetterUtils` turn into the Java codes above
(`-402` = wrong keyword).

### 3.3 Server-initiated and other ECON ids  **[V]**

Client → projector (from `CEasyCommand::MakeHeader(id,…)` call sites, list in
[`econ_command_ids_sent.txt`](../apk/decompile/libengine_arm64/econ_command_ids_sent.txt)):

| id | function | purpose |
|---|---|---|
| `0x01` / `0x02` | `SendEconSearch` | broadcast / unicast search (doc 01) |
| `0x0A` | `CKeepAlive::Exec` | keep-alive (header only) |
| `0x11` | `CProjectorManagerNetwork::SendBreakIntoInfo` | "interrupt" info |
| `0x13` | `SendReqMovie` | request movie (legacy) |
| `0x17` | `SendVSFControl` | video-stream control (legacy) |
| `0x1C` | `SendUpdateClientResolution` | change client resolution |
| `0x22` | `SendStartFwdPenData` | start pen/mouse/touch forwarding (FCN) |
| `0x2B` | display keyword | show keyword on PJ (doc 01 §7) |
| `0x101` | `SendEconConnect` | **start session** |
| `0x104` | `DropSessionProjector` | drop session |
| `0x106` | `TerminateSessionProjector` | terminate (end of session for all) |
| `0x108` | `UpdateActiveList` | which clients are displayed (MPP) |
| `0x10B` | `UpdateMirrorActiveList` | mirror list |
| `0x10F` | `GetUserList` | request user list |
| `0x112` / `0x115` | `RequestModeration` / `ReleaseModeration` | moderator take / release |
| `0x116` | `U2UCommandSub` | user-to-user commands: key emulation, NW standby ON, screen lock, thumbnails (§5) |
| `0x11C` / `0x11D` | `SendControlDeliveryCommand` / `SendGetDeliveryDataCommand` | file/image delivery |
| `0x120` | `SendUpdateServerRandomCommand` | encryption nonce update |
| `0x121` | `SendRequestProjctorLogsCommand` | request projector logs |
| `0x125` | `SendWebRTCOfferSDP` | WebRTC offer (doc 04 §6) |
| `0x127` | `SendPlayStateData` | WebRTC play-state control (one-byte value; mapping from API argument is in doc 04 §6) |
| `0x129` | `SendChangeProtocol` | WebRTC protocol-change control (one-byte boolean; doc 04 §6) |

Projector → client (from the `switch` in `AnalyzeEconData`): `0x102` started, `0x103` rejected, `0x105/0x107/0x118`
dropped/terminated/reject-terminate, `0x109/0x10A` accept/reject active list, `0x10C/0x10D` accept/reject mirror list,
`0x10E` user list, **`0x110` require PCON picture connection**, `0x111` disconnect PCON, `0x113/0x114` require-accept /
reject moderation, `0x117` MPP control mode, `0x11E/0x11F` update_client_random, `0x122/0x123` projector logs,
`0x124` require WebRTC connection (`width`, `height`, `partition`), `0x126` answer SDP, `0x128` disconnect WebRTC
(`0x11B`, `0x11C` exist in the switch but were not decoded),
plus legacy ids `0x06,0x07,0x08,0x16 (server control: pause/restart),0x18,0x1B,0x1D,0x1E,0x20,0x23`.
`0x16` "server control" carries `command` 0/3 = restart, 1 = pause, and `partition`.

## 4. PCON connections (port 3621)

Triggered by projector command `0x110`: `CEconProjectionClientNetwork::StartPCon → StartPConPicture / StartPConAudio`.

```
socket(AF_INET, SOCK_STREAM); SetPConClientSockOptions; bind(NIC-ip : 0); connect(<pj-ip>:3621)
send IDENTIFIER (36 bytes)  — CPictureControlCommandHelper::CreateIdentifier2          [V]
   0x00  "EPRD0600"                       (8)   rodata @0xd3fd0
   0x08  client IPv4, network order       (4)
   0x0C  00 00 00 00                      (4)
   0x10  0x00000010                       (u32 LE, length of the 16-byte block below)
   0x14  D0 00 00 00                      (4)   identify opcode 0xD0
   0x18  auth-id                          (4)   = your UserID from 0x102 (CUserInfoList), else the NIC IPv4 as u32;
                                               on the wire byte-swapped (big-endian) – the caller builds it with 4 byte-shifts [I]
   0x1C  type                             (1)   0 = picture socket, 1 = audio socket
   0x1D  param                            (1)
   0x1E  00 00 00 00 00 00                (6)
```

Then the picture / audio payload follows on the same socket (doc 04). Receive/handshake of the projector side on 3621
is not parsed by the client (no read after identify) **[I]**; failure shows up as an ECON `0x111`/keep-alive timeout.

## 5. Authentication / PIN ("projector keyword")

* A projector may require a keyword: `D_PjInfo.isNeededPjKeyword` (search reply cmd 3 flag, doc 01 §5). The user can make the
  projector display it (`ECON 0x2B`, doc 01 §7). Max length 16 (`ECON_KEYWORD_MAXLEN`).
* Java passes it as `D_ConnectPjInfo.PrjKeyWord`; JNI converts the `String` to a wide-char array in the native
  `_NSCENGINE_CONNECTPROJLIST` entry (0x4C bytes per PJ, keyword = `wchar_t[16]`), then to ASCII
  (`CProjectorNetwork+0x7BB`, `my_wcstombs`, 0x11 bytes) inside `CProjectorNetwork::ConnectProjector(keyword, …, bool audio,
  bool quick, int mpp-mode)` ([CProjectorNetwork.c](../apk/decompile/libengine_arm64/c/CProjectorNetwork.c), `ProjectorNetwork.cpp:0x87`).
  The user-supplied keyword is kept only when `quick == false` and the MPP mode is not 3/4 (or the encryption type is 3 and the PJ flag
  `+0x92e` is set); otherwise the built-in keyword is substituted: **`"2270"`** or **`"QUICKCON"`**
  (`*(projectorInfo+0x1b8b)` ≈ `isSupportConnectionIdentifier` selects QUICKCON) **[V]**.
* The keyword is **not** transmitted as clear text in the 0x101 body that I could decode. It is used as: (a) the key for the
  AES-EPCTR encoder (`Encrypt::createAESEPCTREncoder(0xDC67E11472D3CA0B, keyword, len)`) and (b) the HMAC-SHA256 key for the
  secure-MPP signature **[I]**. The projector validates it implicitly and answers `0x103` (→ `-402`) on mismatch.
  How the AES-EPCTR key is derived exactly from keyword/EncParams was not completely reconstructed.
* Moderator ("MPP" mode 3/4) uses a different secret: `NEngSetMPPControlMode(mode, passwordBytes)`; the password
  is hashed into `SecureMPPParams` (§3.1) — RSA-2048 key pair + HMAC-SHA256 (§6).

## 6. Encryption primitives (all implemented in Java, called back from native)

[`CipherUtils.java`](../apk/sources/com/epson/iprojection/common/utils/CipherUtils.java) (native uses JNI static calls
`encrypt`, `decrypt`, `encryptAESEPCTR`, `getPrivateAndPublicKey`, `getSignature`, `decryptRSA`):

| function | algorithm |
|---|---|
| `encrypt` / `decrypt(buf,len,key)` | `AES/ECB/NoPadding` (picture "AES" mode, type 1) |
| `encryptAESEPCTR(buf,len,key,j,j2,j3,counter[])` | custom CTR: keystream block = `AES-ECB(key, [ (j3 XOR j) (8 B BE) ‖ (counter BE 8 B  XOR  j2 BE 8 B) ])`, counter++ per 16-byte block; XOR with data |
| `getPrivateAndPublicKey()` | RSA-2048, returns PKCS#8 PEM private key + SubjectPublicKeyInfo PEM public key (PEM with `\r\n`, 64-col MIME base64) |
| `getSignature(key,data)` | **HMAC-SHA256** (key = keyword/password, data = public key PEM) → 32 bytes sent as TLV `0x2C` |
| `decryptRSA(buf,len,privPem)` | `RSA/ECB/OAEPWithSHA-1AndMGF1Padding` – decrypts the **DEK** returned by the projector |

Encryption is optional and user-controlled (`conPJ_PROJECTION_WITH_ENCRYPT_TAG` → `NEngSetParameter(3, 1)`); it is
off unless enabled / enforced by the projector via `EncParams` in `0x102` (`type 0` = none, `1` AES, `3` AES-EPCTR; type 2 unused).
`Encrypt::copyPNKey/CreatePNEnckeys` contain built-in key material in `libengine.so` (`CPNKEY`), so a compatible client has
to reproduce those routines (decompiled in [`Encrypt.c`](../apk/decompile/libengine_arm64/c/Encrypt.c)).
**A first headless client can simply keep encryption disabled** (`SetEncryption(false)`) unless the projector enforces it.

## 7. Keep-alive and teardown **[V]**

* `CKeepAlive` thread: sends an ECON **header-only** message with id **10** every `m_nKeepAliveIntervalUDP = 1000 ms` (UDP to
  `<pj>:3620`) or `m_nKeepAliveIntervalTCP = 5000 ms` (over the ECON TCP socket). Any received id-10 updates the "last
  received" time; if `now > last + 10000 ms` (20000 for MPP / `KEEPALIVE_TIMEOUT_MDLHI4`) the engine raises error `-450`
  (`ERROR_DISCONNECT_TIMEOUT`) and tears down.
* Teardown: `NEngDisconnectProjector(id, terminateSession)` → `0x104` (drop only me) or `0x106` (terminate session);
  sockets 3620/3621 closed; the PJ answers `0x105/0x107`.
* Reconnect logic: `Pj.shouldReconnect()` retries (`resetReconnect`) up to a counter when a connect fails with a generic error.

## 8. QR/NFC fast path

When a connection is started from a scanned QR/NFC tag the app additionally (a) joins the projector's Wi-Fi with
`WifiNetworkSpecifier`/`WifiConfiguration` (`WifiConnector`, `WiFiChangingState`), (b) binds the process to that network
(`bindProcessToNetwork`), and (c) uses the built-in keyword (`QUICKCON`/`2270`) — see doc 01 §8.

## 9. Open items

* Complete bit-exact semantic of the `0x101` body bytes `+0x05…+0x2D` (confirm by capturing one session).
* Key derivation of the AES-EPCTR data key (`CAESEPCTREncoder_Android`, `Encrypt::*`, `CProjectorNSC10::GetTK/GetRS/GetRC`).
* Whether the projector sends any bytes on the PCON sockets (identify acknowledgement).
