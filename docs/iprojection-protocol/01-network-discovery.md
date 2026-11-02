# 01 — Network discovery

Target: Epson iProjection for Android `com.epson.iprojection` v4.2.0 (versionCode 136).

> **Method / confidence.** The discovery code lives almost entirely in the native library
> `libengine.so` (not in Java). It was decompiled with Ghidra 12.2; output is in
> [`apk/decompile/libengine_arm64/c/`](../apk/decompile/libengine_arm64/c). Everything below was derived by
> static analysis only — **nothing was replayed against a real projector**. Fields are tagged
> **[V]** (value read directly from code/rodata), **[I]** (inferred from structure) or **[?]** (not resolved).
> Ghidra addresses in the `.c` files are `ELF vaddr + 0x100000`.

## 1. Summary

| Mechanism | Transport | Port | Direction | Used for |
|---|---|---|---|---|
| **ECON broadcast search** | UDP, limited to the NIC's subnet broadcast address | **3620** | client → `<subnet-broadcast>:3620` | Auto search ("find all projectors") |
| **ECON unicast search (UDP)** | UDP | 3620 | client → `<pj-ip>:3620` | Fixed/registered IPs, manual IP entry |
| **ECON unicast search (TCP)** | TCP | 3620 | client ⇄ `<pj-ip>:3620` | Same list as above; one thread per IP; returns the capability blob |
| **ECON reply listener** | UDP server bound to the NIC IP | 3620 | projector → client | Receives the UDP replies |
| **Display-keyword request** | TCP | 3620 | client → `<pj-ip>:3620` | Ask a projector to show its connection keyword on screen |
| **QR / NFC "linkage data"** | out-of-band | – | camera / NFC | Gives IP/MAC/SSID/Wi-Fi password without any network search |
| **Status poll of known PJs** | TCP (ESC/VP.net) | 3629 | client → `<pj-ip>:3629` | `PWR?` every 5 s (see doc 03) |

No SSDP/UPnP/mDNS/IP-multicast is used: zero hits for `239.*`, `224.*`, `M-SEARCH`, `ssdp`, `mdns`, `NsdManager`,
`MulticastSocket`. The Android manifest only requests `CHANGE_WIFI_MULTICAST_STATE`, and the multicast lock is
taken only on ChromeOS ([ChromeOSUtils.java](../apk/sources/com/epson/iprojection/common/utils/ChromeOSUtils.java)).

Constants (from [`Define.java`](../apk/sources/com/epson/iprojection/engine/common/Define.java), confirmed in native code):

```
ECON_PORTNUMBER  = 3620 (0x0E24)   // ECON discovery + session control   [V]
PCON_PORTNUMBER  = 3621 (0x0E25)   // picture / audio data connections   [V]
ESCVP_PORTNUMBER = 3629 (0x0E2D)   // ESC/VP.net remote control          [V]
CONNECTION_TIMEOUT = 10000 ms; ESCVP_CONNECT_TIMEOUT = 1000 ms; ESCVP_RECV_TIMEOUT = 3000 ms
ECON_UNIQINFO_LENGTH = 6   (projector MAC address used as unique id)
ECON_STR_PRJ_ANME_SIZE = 32, ECON_KEYWORD_MAXLEN = 16, CONNECT_MAX_NUM = 4
KEEPALIVE: UDP 1000 ms, TCP 5000 ms, timeout 10000 ms (20000 ms for moderator/MPP)
USE_CHARSET = "Shift_JIS"
```

## 2. Java → native call chain

```
PjFinder / Pj (ui/engine_wrapper)                 -- search orchestration, 5 s cyclic re-search
  → Engine.StartSearchPj / AddSearchProjector     (engine/Engine.java)
    → EngineJni.NEngStartSearchPj(0)              (engine/jni/EngineJni.java; System.loadLibrary("engine"))
      → CNetworkManager::StartSearchProjector → CNetworkManager::Run (search thread)
        → CNetworkManager::SearchBroadcast / SearchFixed
          → CEconSearchManager::SearchEx(bBroadcastUDP, bUnicastUDP, bUnicastTCP, …)
            → CEconSearchManager::SendSearchCmd → CEconClient::SendEconSearch / SendEconSearchTCP
```

Results come back through JNI callbacks `EngineJni.NotifyUpdatePjInfo(D_PjInfo)`, `NotifyUpdateProjectorList()`,
`NotifySearchEnd(int)` and are delivered to `OnFindPjListener` ([`D_PjInfo.java`](../apk/sources/com/epson/iprojection/engine/common/D_PjInfo.java)
is the shape of one discovered projector).

* **Auto search** = broadcast. **Manual search** = `NEngAddSearchProjector(D_AddFixedSearchInfo{prjName, ipAddress[4], uniqInfo[6]})`
  adds an address to the *fixed IP list* (`CEconSearchManager::CreateFixedSearchIPList`) which is searched by unicast.
* `PjCyclicSearchThreadForRegisted` re-runs `manualSearch` (registered IPs) + `autoSearch` every 5 s while idle.
* NIC selection (`CNICManager`, `CNICManagerAndroid`) enumerates interfaces with `ioctl(SIOCGIFCONF)` and
  `SIOCGIFNETMASK`; preference order `chromeOS-NIC` > `wlan1` > `wlan0` > `lan0` > `eth1` > `eth0`
  ([`NICManagerAndroid.java`](../apk/sources/com/epson/iprojection/engine/test/NICManagerAndroid.java)).
  The broadcast address is stored in `CEconClient+0x4b8` and used as the destination of the broadcast search **[I]**
  (computed from IP/netmask of the selected NIC).

## 3. ECON packet format ("EEMP0100")

All ECON traffic (UDP search, TCP session control) shares one container. Reconstructed from
`CEasyCommand::MakeHeader`, `CEasyCommand::GetCreateCmdData`, `CEasyCommand::AnalysisHeader`,
`CEasyCommand::ParseReceivedCommand` ([CEasyCommand.c](../apk/decompile/libengine_arm64/c/CEasyCommand.c)).

```
offset size  field
0x00   8     magic = "EEMP0100"                              [V]  (rodata @ vaddr 0xd4368; parser checks 0x504d4545 'EEMP' + 0x3130 '01')
0x08   4     sender IPv4 (client NIC address, network order) [V/I] (CIPAddress::GetHostAddress)
0x0C   4     command id, uint32 little-endian                [V]
0x10   4     payload length, uint32 little-endian            [V]
0x14   …     payload (length bytes)
```

Payload (only present when the command carries data; header-only commands have length 0):

```
+0x00  1     record count (N)
+0x01  1     "has extension" flag
+0x02  2     reserved / command-specific
+0x04  …     command-specific body (fixed 0x30-byte block in total: bytes 0x00..0x2F)
0x30   N×26  records: MAC[6] | name[16] (ASCII, NUL padded) | status uint32 LE      [V]  (CEasyCommand::AddRecord, new 0x1a)
…      4+…   extension section: uint32 total length, then TLVs (see doc 02 §3.1)    [V]
```

Total = `0x14 + 0x30 + N*0x1A + ext`; `GetCreateCmdData` writes exactly this. Receive path limits one message to
`0xC33C` payload bytes (`CEconSearchTcpThread::ReceiveEconData`).

## 4. Search request

**Broadcast search** (`CEconClient::SendEconSearch(true,…)`): command id **1**, header only.
**Unicast search** (`SendEconSearch(false,…)`, and the TCP variant `CEconSearchTcpThread::Search`): command id **2**, header only.

Both are exactly 20 bytes (no payload):

```
45 45 4D 50 30 31 30 30   "EEMP0100"
C0 A8 01 32               sender IP, e.g. 192.168.1.50
01 00 00 00               command 1 = broadcast search (2 = unicast search)
00 00 00 00               payload length 0
```

Socket details **[V]** (`CEconClient::SendUDP`, `CEconSearchTcpThread::Search`):

* UDP: `socket(AF_INET, SOCK_DGRAM)`, `SO_BROADCAST=1`, `SO_REUSEADDR=1`, `sendto(<broadcast or pj-ip>:3620)`. The source port is **not bound** (ephemeral) for the *sending* socket.
* UDP listener: `CEconServer` (`CNetworkManager::CreateEconServer`) opens a UDP socket bound to the **NIC IP : 3620** with
  `SO_REUSEADDR`, `SO_RCVTIMEO` and receives replies there. ⇒ a headless client must bind **UDP 3620** on the chosen NIC
  to see the answers. **[I]** (the reply is sent to the source address; whether the projector replies to the source port or
  to 3620 was not resolved — binding the sender socket to 3620 with `SO_REUSEADDR` and also reading from it covers both).
* TCP unicast: one `CEconSearchTcpThread` per fixed IP. Non-blocking `connect(<pj-ip>:3620)` (up to 100 `select()` retries),
  sends the 20-byte header (cmd 2), then reads a 20-byte header + `length` bytes and feeds it to
  `CEconClient::AnalysisEconSearchData`. The overall search ends when every expected projector has answered
  (`CheckRecvEnd`), after the poll budget, or on cancel.
* `SearchEx` waits in 100 ms steps; default `PJCheckCount` = value at `CEconSearchManager+0x754`, forced to 10 for modes 3/4.
  Between unicast sends it sleeps 30 ms every 8 addresses (`CToolAndroid::Sleep(0x1e)`).

## 5. Search responses

`CEconClient::AnalysisEconSearchData` ([CEconClient.c](../apk/decompile/libengine_arm64/c/CEconClient.c)) accepts only
messages whose `"EEMP0100"` header parses, that arrive on the NIC the search was started from (it compares the receiving thread's NIC address with its own) and are not command ids 1/10 (own search echoes / keep-alive, ignored). It handles:

| Reply cmd | Meaning | Content |
|---|---|---|
| **3** | *Projector info* | record[0] = projector **MAC[6]**, name; body: `+4` name[32] (`PrjName`), `+0x24` usage-status byte (maps to `e_proj_status_*`: 1 free, 2 NP in use, 3 busy/not interruptible, 4/5/6/7 MPP states, …), `+0x25`/`+0x26` flags (e.g. keyword required); ext TLVs: `MaxUserNum` (0x0F), `CurrentUserNum` (0x10), `DynamicClientResolution` (0x11), `PJList`/ids (0x04) |
| **0x15 (21)** | *Capability response* | record[0] = MAC, 6+16 bytes name, `uint32`, followed by a **0x400-byte capability blob** (see §6) |
| **0x11 (17)** | *Break-into / not-break IP list* | list of IPs that are "interruption prohibited" → `NOT_BREAK_IP` list |

The projector is keyed by `uniqInfo` = **MAC[6]**; `IPAddr` is the UDP/TCP source address. Update logic:
`CEconClient::ClientinfoToEconInfo`, `UpdateCpability`, `AddCapability`.

`D_PjInfo.Status` values ([`Define.java`](../apk/sources/com/epson/iprojection/engine/common/Define.java)):

```
0 not found  1 not in use  2 in use (NP)  3 in use, interruption prohibited
4 in use (MPC)  5 MPC mirroring  6 MPC full  7 MPC mirroring full  8 in use by other app  9 searching  10 not connected
```

## 6. Capability blob (0x400 bytes)

TLV list parsed by `Capability::Capability(uchar*, int)` / `CapBase::parse`
([Capability.c](../apk/decompile/libengine_arm64/c/Capability.c), [CapBase.c](../apk/decompile/libengine_arm64/c/CapBase.c)):

```
type : uint8
len  : uint8           if type in 1..8
       uint16 (LE)     otherwise (type 0, 9..14)          [V]
```

| type | class | meaning |
|---|---|---|
| 0 | `CapAllCapability` | container |
| 1 | `CapClientIdentifier` | |
| 2 | `CapIMFirmwareVersion` | firmware version string |
| 3 | `CapPanelResolution` | `panelResolution=%04dx%04d` |
| 4 | `CapSupportFramebufferResolution` | |
| 5 | `CapSupportRectEncoding` | JPEG, RAW16/24/32, ZLIB, LZO, EIC, RAWEX, LZOEX, JPEGEX, JPEGALIGNED, RAWEXALIGNED, `MaxRectDataSize` |
| 6 | `CapSupportMovieEncoding` | (movie send, WMV9…) |
| 7 | `CapSupportAudioEncoding` | frequency / quantize / channel |
| 8 | `CapProjectorFunction` | feature bits: `isSupportAES`, `isSupportAESEPCTR`, `isSupportDES`, `isSupportRectWithHeader`, `isSupportPauseAndResume`, `isSupportRetryConnection`, `isSupportDynamicResolutionChange`, `isSupportDisplayKeyword`, `isSupportConnectionIdentifier`, `isSupportWebRemote`, `isSupportSPRemote`, `isSupportWhiteboardSharing`, `isSupportUniDirectionalTCPConnect`, `isSupportBiDirectionalTCPKeepAlive`, `isSupportPicConAuth`, `isSupportPinCodeWithMultiPC`, `isSupportQRConnect`, `isNotSupportNP`… (bit positions: see `CapProjectorFunction::is*` getters) |
| 9 | `CapMovieSendingFormat` | |
| 10 | `CapMultiPC` | MPP (multi-PC projection / moderator) versions, max users, delivery, thumbnail |
| 11 | `CapClientResolution` | client resolution ids |
| 12 | `CapForwardCoordinatesviaNetwork` | FCN (pen/mouse/touch back-channel) versions and AES support |
| 13 | `CapPoolData` | |
| 14 | `CapProjectorExtendedFunction` | |

Byte 6 of the blob is the **platform id** (`Capability::getPlatform`). Java-side feature flags in `D_PjInfo`
(`isSupportedSecuredEscvp`, `isSupportedWebRTC`, `bSupportedMPP`, `isNeededPjKeyword`, `isSupportDisplayKeyword`, …) are
filled from these bits through `NotifyUpdatePjInfo`.

## 7. Display-keyword request

`NEngRequestDisplayKeyword(id)` → `CEconClient::SendEconDisplayKeyword` → `CEconDisplayKeywordTcpThread::SendCommand`:
TCP connect to `<pj-ip>:3620`, send an **ECON header only, command id 0x2B (43)**. The projector then overlays its
connection keyword/QR on the screen (requires `isSupportDisplayKeyword`).

## 8. QR code / NFC ("linkage data") — zero-network discovery

[`LinkageDataCommonDecoder`](../apk/sources/com/epson/iprojection/linkagedata/decoder/LinkageDataCommonDecoder.java),
`QRDecoderV0/V1/V2`, `NFCDecoderV0`. The projector's QR code (or NFC tag) carries IP, MAC and Wi-Fi settings.

```
raw QR bytes r[] / NFC bytes n[]  →  decoded bytes b[]  (LinkageDataCommonDecoder.getContentData*)
  QR : b[i-1] = ((r[i] & 0x0F) << 4 | (r[i+1] >> 4 & 0x0F)) ^ 0xE5     for i = 1 .. len-2      (nibble-shifted + XOR key 229)
  NFC: b[i]   = n[i] ^ 0xE5
checks on b[]: b[0] = total length (≤ array length);  b[b[0]-1] == 0x80 (check code)
b[1]  : high nibble = format version (QR: 0, 1, 2; NFC: 0);  low nibble = connect flags
          bit0 = 0 → easy-connect, bit1 = 1 → WPA2-PSK-AES, bit2 = 0 → auto SSID, bit3 must be 0
b[2]  : wire flags: bit0 wired available, bit1 wireless available, bit2 = 0 → prefer wireless
          (V2: bits 3..7 = type: 0 projector connect, 1 whiteboard)
then  : IPv4 wired[4] (if available) · IPv4 wireless[4] (if available) ·
        QR V0/V1: projector name (len ≤ 6, 1 length byte) OR MAC[6] (length byte has bit7 set, followed by MAC);
        QR V2 and NFC V0: MAC[6] ·
        Wi-Fi passphrase (1 length byte ≤ 63; only if easy-connect + WPA2) ·
        SSID (1 length byte ≤ 32; QR V0/V1 only when easy-connect, QR V2/NFC V0 always)
```

NFC V0 appends one projector-status byte after these fields: bit 0 = projector powered on, bit 1 = NFC auto-power-on,
bit 2 = wireless configured, bit 3 = wireless powered on, bit 4 = wireless authentication fixed, and bit 5 = wireless
authentication succeeded. QR V2 and NFC V0 both decode the projector identity as MAC[6]; only QR V0/V1 use the
name-or-MAC marker.

When a linkage search is active `ConnectionControler.tryConnectSub` sets the projector keyword to the built-in
constants **`"QUICKCON"`** (projectors that report `isSupportConnectionIdentifier`) or **`"2270"`** (older ones)
([CommonDefine.java](../apk/sources/com/epson/iprojection/common/CommonDefine.java): `SECRET_PJ_KEYWORD_NEW`, `SECRET_PJ_KEYWORD`).
This lets a scanned QR bypass the keyword prompt.

## 9. Reproducing discovery (headless)

```python
import socket, struct
def econ(cmd, ip4, payload=b""):
    return b"EEMP0100" + ip4 + struct.pack("<II", cmd, len(payload)) + payload

nic_ip, bcast = "192.168.1.50", "192.168.1.255"
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
rx.bind((nic_ip, 3620)); rx.settimeout(0.5)
rx.sendto(econ(1, socket.inet_aton(nic_ip)), (bcast, 3620))   # 20 bytes
# read replies: expect b"EEMP0100", cmd 3 (info) and cmd 0x15 (capability) per projector
```

For per-IP checks open `TCP <ip>:3620`, send `econ(2, nic_ip)` and read `20 + len` bytes. A cheaper liveness/power check that
needs no ECON at all is ESC/VP `PWR?` (doc 03).

## 10. Open items

* Exact byte offsets of the reply-3 body (`PrjName` at +4, status at +0x24..0x26) come from `ClientinfoToEconInfo`; the
  meaning of every flag bit is not fully resolved.
* Whether replies target UDP port 3620 or the sender's ephemeral port (see §4).
* Bit positions inside `CapProjectorFunction` (derive from `CapProjectorFunction::is*` / `set*`).
