# 05 — Architecture summary & roadmap for a headless client

## 1. What the app is made of

| Layer | Where | Notes |
|---|---|---|
| UI / app logic (Kotlin+Java, names largely preserved) | `apk/sources/com/epson/iprojection/ui/**` | Activities for PJ selection, remote, mirroring, moderator, whiteboard, … |
| Engine wrapper (Java) | `ui/engine_wrapper/` — [`Pj`](../apk/sources/com/epson/iprojection/ui/engine_wrapper/Pj.java) (118 KB, singleton façade), [`PjFinder`](../apk/sources/com/epson/iprojection/ui/engine_wrapper/PjFinder.java), [`ConnectionControler`](../apk/sources/com/epson/iprojection/ui/engine_wrapper/ConnectionControler.java), `ImageSender`, `PjCyclicSearchThreadForRegisted`, `PjStatusOfRegistedUpdateThread` | state machine (`StateMachine.ConnectState`), search/connect orchestration, status polling |
| JNI bridge | [`engine/Engine.java`](../apk/sources/com/epson/iprojection/engine/Engine.java) → [`engine/jni/EngineJni.java`](../apk/sources/com/epson/iprojection/engine/jni/EngineJni.java) (`System.loadLibrary("c++_shared"); loadLibrary("engine")`) | 50 `native` methods `NEng*`, callbacks `CallBack*`, `Notify*` |
| **Protocol engine (C++)** | `apk/resources/lib/{arm64-v8a,armeabi-v7a,x86_64}/libengine.so` (2.2 MB, **symbols not stripped**, 5 250 dynamic symbols, build path `…/1090-iProRD/android/app/src/main/cpp/Engine/…`) | ECON, PCON, ESC/VP.net, JPEG/RAW encoding, AES, keep-alive. The primary source for wire behavior; app-side orchestration and WebRTC/FCN details also matter. |
| Crypto helpers | [`common/utils/CipherUtils.java`](../apk/sources/com/epson/iprojection/common/utils/CipherUtils.java), [`engine/common/HashCreator.java`](../apk/sources/com/epson/iprojection/engine/common/HashCreator.java) | called **from native** through JNI |
| WebRTC | `service/webrtc/**`, `org/webrtc/**`, `lib/*/libjingle_peerconnection_so.so` (arm64, armv7 only) | single-projector mirroring path |
| Chrome-extension bridge | `com/epson/iprojection/mirroring_for_chrome/**`, `com/epson/webserver_module/**` (AndroidAsync HTTP + Java-WebSocket servers) | ChromeOS only: the Android app exposes HTTP + 3 WebSockets (text / image / audio) on ports `EServerPort.PORT_MIN…` to the Epson Chrome extension; **not** a projector protocol |
| Third-party | Firebase/Analytics (`http://www.google-analytics.com/collect` posts from `CHttpCommunicationMgr`), Adobe PDF (`libAPC.so`, `libMPS.so` = PDF rendering for "Documents"), Google Play services | irrelevant for protocol work |

`AndroidManifest.xml`: package `com.epson.iprojection`, v4.2.0 (136), minSdk 29 / targetSdk 35; permissions include `INTERNET`, `ACCESS_WIFI_STATE`,
`CHANGE_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`, `CHANGE_NETWORK_STATE`, `FOREGROUND_SERVICE_MEDIA_PROJECTION`, `RECORD_AUDIO`, `NFC`, `CAMERA`.

## 2. Native library map (libengine.so)

Class index with addresses: [`libengine_arm64/symbols_by_class.txt`](../apk/decompile/libengine_arm64/symbols_by_class.txt); decompiled C per class:
[`libengine_arm64/c/`](../apk/decompile/libengine_arm64/c) (6 393 functions, 165 files). Ghidra address = ELF vaddr + `0x100000`.

| Responsibility | C++ classes | Doc |
|---|---|---|
| JNI entry points, callbacks to Java | `JNI.c` (`Java_…EngineJni_NEng*`), `CEngine` | this |
| NIC/Wi-Fi enumeration | `CNICManager`, `CNICManagerAndroid`, `CNetworkManager` (search thread `Run`), `CIPAddress` | 01 |
| Discovery | `CEconSearchManager`, `CEconClient`, `CEconSearchTcpThread`, `CEconServer`, `CEconDisplayKeywordTcpThread` | 01 |
| ECON message codec | `CEasyCommand` (header, records, ext TLVs), `EconExtParam`, `CEconExtParam`, `CUserInfoList` | 01, 02 |
| Capability model | `Capability`, `CapabilityList`, `Cap*` (15 TLV types) | 01 §6 |
| Session / connection | `CProjectorManager[NSC10|Network]`, `CProjector[NSC10|Network]`, `CEconProjectionClient[NSC|NSC10|Network]`, `CKeepAlive`, `ClientResolutionManager` | 02 |
| ESC/VP.net | `CEscVpNet` | 03 |
| Picture pipeline | `CDisplay[Android|Manager]`, `CPictureController[NSC]`, `CPictureData`, `CPictureEncoder`, `CPRect*`, `CPImageColorChecker`, `CPictureControlCommand[Helper|AudioHelper]`, `CPerformanceInfo`, `CQualityController`, libjpeg-turbo 2.0.5 | 04 |
| Audio | `CAudioController[Android]`, `CPictureControlCommandAudioHelper` | 04 |
| Encryption | `Encrypt`, `CAESEncoder[_Android]`, `CAESEPCTREncoder[_Android]`, `CProjectorNetwork::SetEncryptInfo` | 02 §6 |
| FCN (pen/mouse/touch back-channel) | `CFCNClient`, `IFCNClient`, `CFCNTranslater[Android]` | not covered |
| Moderator / multi-PC (MPP), delivery, thumbnails | `CUserInfoList`, `CapMultiPC`, `CProjectorManagerNSC10::*Moderation*`, `*Delivery*`, `U2UCommand*` | 02 |
| Misc | `CProjectorLogManager` (projector logs → HTTP/GA), `CHttpCommunicationMgr`, `CRaccoonDongle` (USB-dongle transport variant), `CPerformanceRecorder` | – |

Sockets are wrapped by `CENPSocketWrapping` → `CENPSocketNormal|Android|DongleEcon|DonglePconImage|DonglePconAudio` (same API, BSD sockets or a USB "Raccoon dongle" tunnel).
`CToolAndroid::Sleep/GetTickCount` time helpers.

### Native → Java calls (JNI upcalls the engine needs)
`CipherUtils.{encrypt,decrypt,encryptAESEPCTR,getPrivateAndPublicKey,getSignature,decryptRSA}`, `HashCreator.CreateHashForSecuredEscvp`,
`WebRTCEntrance.{createOfferSDP,answerSdp,start,stop}`, `ThumbnailCapturerEntrance`, `HttpUtils` (analytics), `ChromeOSUtils`/`IPAddress` (virtual IP for ChromeOS),
`EngineJni.CallBack*` (connect result, MPP events, screen lock, delivery, resend request, image-proc time…).

## 3. JNI API (what the Java layer can ask the engine)

```
Init/Destroy      NEngInitialize(this, bool, String)  NEngDestory
Discovery         NEngStartSearchPj  NEngEndSearchPj  NEngGetSearchStatus  NEngAddSearchProjector  NEngDeleteSearchProjector
                  NEngDeleteProjectorInfo  NEngRequestDisplayKeyword
Session           NEngConnectProjector(list,user)  NEngDisconnectProjector(id,terminate)  NEngGetProjectorStatus
                  NEngGetSendImageBufferSize  NEngGetResolution  NEngSetResolution  NEngIsAlivePj  NEngIsPlay
Parameters        NEngSetParameter / GetParameter  (3 encrypt, 5 audio, 22 bandwidth, 24 proc-time interval, 25 log upload)
                  NEngChangeProtocol(JPEG|WebRTC)
Picture           NEngSendImage(Bitmap, Rect[], ResRect)  NEngUpdateThumbnail  NEngClearThumbnail  NEngRequestThumbnail  NEngStopThumbnail
                  NEngSetProjectionMode  NEngProjectionMyself
Control (ESC/VP)  NEngCtlChangeSource/AVMute/Freeze/VolumeUP/VolumeDown/DispQRCode
                  NEngSendEscvpCommand[WithIp]  NEngSendEscvp(ip,cmd,password)  NEngSendAndReceiveEscvpCommandWithIp
                  NEngSendU2UCommandKeyEmulation  NEngSendU2UCommandNWStandbyON
Moderator/MPP     NEngSetMPPControlMode  NEngControlMPPOtherUser  NEngDisconnectMPPOtherUser  NEngUpdateMPPLayout
                  NEngRequestScreenLock  NEngIsRequestedScreenLock  NEngSetAllowModeratorMonitering
Delivery          NEngRequestDelivery[WhitePaper]  NEngChangeDeliveryMethod  NEngSetDeliveryParmission
```

## 4. End-to-end flow (what a headless client must reproduce)

```
 ┌── presence/power (no session) ────────────────────────────────────────────────────────────────┐
 │ ESC/VP.net 3629:  "PWR?" (open) or secured query (SEL=2)   → 01 on / 04,09 standby / else offline │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘
 ┌── discovery (optional) ───────────────────────────────────────────────────────────────────────┐
 │ UDP bcast "EEMP0100" cmd 1  →  replies cmd 3 (+cmd 0x15 capability)  on UDP/TCP 3620            │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘
 ┌── projection ─────────────────────────────────────────────────────────────────────────────────┐
 │ TCP 3620: 0x101 REQ_START_SESSION  → 0x102 (user-id, enc-params)                                │
 │ keep-alive id 10 every 1 s (UDP) / 5 s (TCP)                                                    │
 │ PJ: 0x110  → client: TCP 3621 identifier (type 0)  [+ audio socket type 1]                      │
 │ stream: "EPRD0600" + rect list (Tight-style JPEG rects)  — or WebRTC (0x124/0x125/0x126)        │
 │ end: 0x106/0x104                                                                                │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 5. Roadmap for a Python / Go / Node client

Language choice: **Python (asyncio)** for fastest iteration and packet-level experimentation (`struct`, `hashlib`), **Go** for the final
long-running fleet manager (cheap goroutine-per-projector, static binary). The protocol work is identical; keep a protocol spec/test-vector package that both can use.

### Phase 0 — ground truth (1–2 days, required)
1. Capture the *official app* against a real projector with Wireshark (phone → Wi-Fi AP mirror/port-mirror or PCAPdroid): search, connect, mirror 30 s, disconnect, plus `PWR ON/OFF`, source change.
2. Diff the captures with the byte layouts in docs 01–04; fix every **[I]/[?]** item (list at the end of each doc). Store captures as test vectors.
3. Optional dynamic aid: a Frida script hooking `EngineJni.NEng*`, `CEscVpNet::SendESCVPCommandSub*`, and `send()` in `libengine.so` to dump plaintext before encryption.

### Phase 1 — status & control MVP (smallest useful product; **no ECON needed**)
* `escvp` module: open / digest / secured-query (doc 03 §7). Unit tests with the lengths 34/34/52/34 and the SHA-256 test vector.
* Inventory file (YAML): `name, ip, esc/vp password, web-remote password`. Async task per projector: poll `PWR?` every 5 s (timeout 3 s), expose state via MQTT/HTTP/Prometheus.
* Commands: `PWR ON/OFF`, `SOURCE …`, `MUTE ON/OFF`, `KEY xx`, `VOL`, network-standby wake (`SCOMPORT` + `SPOWER ON`), batch fan-out with per-device retry.
* Fallback web-remote (HTTP Digest, doc 03 §5) for settings the ESC/VP vocabulary does not cover.

### Phase 2 — discovery
* UDP broadcast search per NIC (`EEMP0100` cmd 1), bind UDP 3620 (`SO_REUSEADDR`), parse cmd 3 / 0x15 into `{name, mac, ip, status, flags, capabilities}`; unicast search (cmd 2) over UDP and TCP for static lists; periodic re-search every 5 s like the app.
* Parse the capability TLVs (doc 01 §6) — decode `CapProjectorFunction` bits from the decompiled getters.
* QR/NFC linkage decoder (doc 01 §8) for zero-touch onboarding (the XOR-`0xE5` scheme is trivial to implement).

### Phase 3 — session + keep-alive (no picture yet)
* ECON codec (`EEMP0100` container, records, TLVs) as a reusable library (round-trip tests against captures).
* `0x101/0x102/0x103`, keep-alive thread, `0x106` teardown, reconnect policy; map `0x103` categories to errors; keyword handling (+ `0x2B` show-keyword; built-in `QUICKCON` / `2270` fall-back).
* Multi-projector: one session object per PJ (max 4 per client in the original — a custom client can try more).

### Phase 4 — picture streaming
* PCON picture socket (identifier + `EPRD0600` rect packets, doc 04 §4/§7). Start with full-screen JPEG at the projector's native/negotiated size, no encryption, then add dirty-rectangle updates, resends and adaptive quality (`MinImageQuality…MaxImageQuality`, bandwidth cap sleep).
* Screen source on a headless host: `mss`/PipeWire/DXGI/X11 grab → JPEG (libjpeg-turbo / `turbojpeg`). Multi-projector = the same JPEG bytes to every socket (the original passes one bitmap to the engine for all selected projectors).
* Audio: PCM 22 050 Hz mono 16-bit on the audio socket (`C9 len32 data`).

### Phase 5 — optional hardening / extras
* Encryption (AES / AES-EPCTR; doc 02 §6) — only if a projector enforces it. Implement from `Encrypt.c`, `CAESEPCTREncoder*.c` and `CipherUtils.java`; validate with captures.
* Secure moderator mode (RSA-2048 + HMAC), MPP/moderator, thumbnails, delivery, FCN (pen/touch) — each is an independent extension of the ECON codec.
* WebRTC path (H.264) via `aiortc` / `pion`: SDP munging `ep=receiver-ip-addr`, `ep=codec` (doc 04 §6); only valuable for a single high-quality screen.

### Fallback strategy
If a feature needs the undocumented crypto or FCN details, run the original `libengine.so` (arm64) under an Android emulator/AVD with a small harness APK (copy `EngineJni` + `Engine` + the Java crypto helpers, drive `NEng*` directly). This gives a bit-exact reference peer while the pure-protocol client matures.

### Architecture sketch

```
inventory.yaml ─► Supervisor (asyncio / goroutines)
                    ├─ PowerMonitor   (ESC/VP.net, 5 s)           ──► state bus (MQTT / REST / metrics)
                    ├─ Discovery      (EEMP0100 UDP/TCP 3620)     ──► inventory updates
                    ├─ CommandRouter  (open | digest | secured | web-remote)
                    └─ Projection[n]  (ECON session + keep-alive ─► PCON picture/audio sender ◄─ ScreenCapture)
```

## 6. Practical notes & cautions

* **Interoperability / authorisation.** This analysis supports talking to projectors you own or manage; check Epson's licence terms for the app and device firmware before shipping a client.
  Do not test on production devices without a rollback plan — a wrong ECON `0x101` can disconnect an active presenter.
* **Default web-remote credentials** (`EPSONREMOTE:guest`, `EPSONWEB:admin`, `EPSONMOBILE:`) and the built-in connect keywords (`QUICKCON`, `2270`) are compiled into the client; for a fleet, set non-default passwords and keep them in a secret store.
  ESC/VP.net *open* mode is unauthenticated by design — keep the projector VLAN isolated.
* ESC/VP and ECON are plain TCP/UDP (encryption of the picture is optional). Do not expose 3620/3621/3629 beyond the management network.
* The engine assumes a single NIC chosen at start (`CNICManager`); a multi-homed headless host must bind sockets explicitly to the right interface.

## 7. Index of generated artifacts

| Path | Content |
|---|---|
| [`docs/01…05`](.) | this documentation |
| [`apk/decompile/README.md`](../apk/decompile/README.md) | how the native decompile was produced / how to regenerate |
| [`apk/decompile/libengine_arm64/c/`](../apk/decompile/libengine_arm64/c) | Ghidra decompiled C/C++, one file per class |
| [`…/function_index.txt`](../apk/decompile/libengine_arm64/function_index.txt) | `file:line address Class::method` for all 6 393 functions |
| [`…/symbols_by_class.txt`](../apk/decompile/libengine_arm64/symbols_by_class.txt) | exported symbols grouped by class (vaddr, size, mangled name) |
| [`…/rodata_strings.txt`](../apk/decompile/libengine_arm64/rodata_strings.txt) | read-only strings (log tags, command strings, JNI names) |
| [`…/econ_command_ids_sent.txt`](../apk/decompile/libengine_arm64/econ_command_ids_sent.txt) | ECON command id ↔ sending function |
| [`apk/decompile/tools/`](../apk/decompile/tools) | `elfdump.py`, `symgroups.py`, `a64dis.py`, `cmdids.py`, `cmdnames.py`, `DecompileEngine2.java` (Ghidra headless script) |
