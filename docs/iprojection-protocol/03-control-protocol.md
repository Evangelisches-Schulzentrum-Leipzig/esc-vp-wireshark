# 03 — Control protocol (power, input, volume, status, …)

> Confidence tags: **[V]** read from code, **[I]** inferred, **[?]** unresolved. Static analysis only.

## 1. Short answer

The app does **not** use a proprietary wrapper for projector control. It uses **standard ESC/VP.net on TCP 3629**
(the documented Epson ESC/VP21 command language carried inside the ESC/VP.net framing), in three flavours, plus two
non-ESC/VP channels:

| # | Channel | Port | When the app uses it | Implemented in |
|---|---|---|---|---|
| A | **ESC/VP.net "open"** (no password) | TCP 3629 | non-secured projectors; fire-and-forget remote keys, power, source, volume, freeze, mute | `CEscVpNet::SendESCVPCommandSub*` |
| B | **ESC/VP.net "digest"** (password, SHA-256 challenge/response) | TCP 3629 | projectors that report `isSupportedSecuredEscvp` (Web-control-password protected) – `PWR ON/OFF`, `SPOWER ON`, `SCOMPORT`, … | `CEscVpNet::SendESCVPDigestCommandSub*`, `HashCreator.java` |
| C | **ESC/VP.net "secured query"** (v0x20, type 2) | TCP 3629 | read-only polling of `SNO?` (serial) and `PWR?` (power state) on secured projectors | `CEscVpNet::SendESCVPSecuredCommandSub*` |
| D | **ECON U2U commands** over the running session | TCP 3620 (ECON `0x116`) | secured projector *while connected*: key emulation, network-standby-ON, screen lock | `CEconProjectionClientNSC10::U2UCommand*` |
| E | **Projector Web Remote** (HTTP, Digest auth) | TCP 80 | "Remote" tab: opens the PJ's own web UI in a WebView | `ui/activities/remote/*` |

Everything for A–C is available **without connecting a projection session**, which is what a headless fleet manager needs.

## 2. ESC/VP.net framing (A, B, C)  **[V]**

Reconstructed byte-exactly from `CEscVpNet::*_SendRequest / _Receive / _Hash` (decompiled in
[CEscVpNet.c](../apk/decompile/libengine_arm64/c/CEscVpNet.c)). Header = 16 bytes:

```
0..9   "ESC/VP.net"
10     version   0x10 (open)  /  0x20 (digest, secured)
11     type      0x03 = connect/auth    0x02 = secured query
12..13 0x0000
14     status    0x00 in requests;  0x20 OK, 'A'(0x41) auth required, 'U'(0x55) unsupported, … in responses
15     number of following header blocks (each 18 bytes: id, attribute, 16 data bytes)
```

TCP timeouts in the app: connect 1000 ms (non-blocking), receive 3000 ms (`ESCVP_CONNECT_TIMEOUT`, `ESCVP_RECV_TIMEOUT`).
The PJ IP is the projector address (`projector+0x5E8`); the socket is bound to the selected NIC if known.

### A. Open mode (version 0x10)

Request (34 bytes), response (16 bytes):

```
"ESC/VP.net" 10 03 00 00 00 01 | 01 01 | "ELPCSPOPN" + 7×00
                  └ 1 header     └ id 0x01 (password), attr 0x01 (plain) + 16-byte field
                                    — the app always sends the literal ASCII "ELPCSPOPN" here
response OK :  "ESC/VP.net" 10 03 00 00 20 00      (byte14 == 0x20, byte15 == 0, else "Header Error")
```

Then the **command is sent as ASCII + `\r`** (max 31 chars; `SendESCVPCommandSub_SendRCCommand`: `strcpy(buf, cmd); buf[len] = '\r'`).
`SendEscvpCommand(WithIp)` closes the socket after sending (no response read). `SendAndReceiveEscvpCommandWithIp` additionally reads
up to 32 bytes and Java (`Pj.sendAndReceiveEscvpCommandWithIp`) takes the text up to `"\r:"`, e.g. `PWR?` → `PWR=01`.

### B. Digest mode (version 0x20, type 3) — password-protected projectors

```
step 1  C→P  "ESC/VP.net" 20 03 00 00 00 01 | 01 03 | 16×00                       (34 B)   "give me a challenge"
        P→C  34 B, byte14: 0x41 'A' → auth required, challenge = bytes 18..33 (16 B nonce)
                             0x20     → no auth needed (app still hashes with empty password)
                             0x55 'U' → not supported → app falls back to open mode (A)
step 2  C→P  "ESC/VP.net" 20 03 00 00 00 02 | 01 04 | H[0:16] | 01 05 | H[16:32]  (52 B)
        where  nonceHex = lowercase hex of the 16-byte nonce (32 chars, "%02x" per byte)
               H = SHA256( hex(SHA256("ESC/VP.net:" + password)) + ":" + nonceHex )       ← HashCreator.CreateHashForSecuredEscvp
        P→C  16/34 B with byte14 == 0x20 → authenticated (otherwise app returns -441 "wrong web password")
step 3  C→P  "<command>\r"
```

Java reference: [`HashCreator.java`](../apk/sources/com/epson/iprojection/engine/common/HashCreator.java) (native calls it through JNI as
`CreateHashForSecuredEscvpOnJava`). `sendDigestEscvp(cmd, ip, password)` returns `-441` on wrong password; `DigestEscvpSendingState`
first tries the password stored for that PJ, then the "apply to all" password, then prompts.

### C. Secured query (version 0x20, type 2) — SNO? / PWR?

```
C→P  "ESC/VP.net" 20 02 00 00 00 01 | 06 SEL | 16×00        SEL: 01 = "SNO?" (serial number), 02 = "PWR?" (power status), 00 = other
P→C  34 B: [10]=0x20 [11]=0x02 [14]=0x20 [15]=0x01 | id attr | 16-byte ASCII value (NUL padded)
```

No password, no challenge: this is why the app can poll registered *secured* projectors every 5 s
(`PjStatusOfRegistedUpdateThread`). Only the two literal strings `SNO?` and `PWR?` are recognised by the client; other values leave `SEL=0`.

## 3. Command strings used by the app (ESC/VP21 vocabulary)  **[V]**

Java constants ([`Pj.java`](../apk/sources/com/epson/iprojection/ui/engine_wrapper/Pj.java) L104-122) and native
(`CEscVpNet.c`, rodata):

| purpose | string sent (+ `\r`) | notes |
|---|---|---|
| power on / off (batch UI) | `PWR ON`, `PWR OFF` | `FragmentPjControlBatch` |
| power key toggle | `KEY 01` | `ESCVP_COMMAND_POWER` |
| A/V mute on/off | `MUTE ON`, `MUTE OFF` (batch) · `KEY 3E` (native `SendAVMute`) | |
| freeze | `KEY 47` | |
| volume up / down | `KEY 56` / `KEY 57` | |
| source: computer / video / LAN | PC: `KEY 67` (gen 0) · `KEY 10` (gen 1-2) · `SOURCE F1` (gen ≥ 3)<br>Video: `KEY 4F` · `KEY 11` · `SOURCE F2`<br>LAN: `KEY 8A` (gen < 9) · `SOURCE 53` (gen ≥ 9) | "gen" = projector generation field at `projector+0x8C8` **[I]** (older models use remote-key codes, newer ones the `SOURCE` command) |
| display QR code | `QRDISPSWITCH 00` | |
| menu / esc / enter | `KEY 3C` / `KEY 3D` / `KEY 49` | remote-pad keys |
| cursor / pointer | `KEY 58` up, `59` down, `5A` left, `5B` right, `5C` right-up, `5D` left-up, `5E` right-down, `5F` left-down, `KEY 50` pointer | `ESCVP_COMMAND_MVPT_*` |
| zoom | `KEY 28` / `KEY 29` | |
| **network standby ON** | `SPOWER ON` (`SPOWER OFF`) | needs "Network Standby" and a COM-port selection first |
| select serial/communication port | `SCOMPORT 01` (wired) / `SCOMPORT 02` (wireless) | sent after `SPOWER ON` when the user wakes a PJ from standby (`EscvpUtils.sendSecureEscvpOfNetworkStandbyOnAndScomport`) |
| power state | `PWR?` → `PWR=01` lamp on, `PWR=04`/`PWR=09` standby (`ConnectPjInfo.eStatus.normal/standby`), anything else → unavailable | polled every 5 s |
| serial number | `SNO?` → `SNO=<serial>` | `CustomDimensionForAllEvent` |
| diagnostic (native only, via U2U logs) | `LOGINFO? 03 00`, `LOGINFO? 05 00`, `LUMLEVEL?`, `LUMINANCE?`, `LUMCONST?`, `MENUINFO? 0B`, `SMTEMPERRLOG?`, `IMSETTIME?` | used by `CProjectorLogManager` for projector logs |

The client can transmit other ESC/VP21 command strings (for example `LAMP?`, `ERR?`, `SOURCE?`, `VOL`, `LUMINANCE`, `MSEL`…),
but the APK does not establish that every projector accepts them or that their behavior is uniform. Check the target
projector's command documentation and model support; the app's native send path limits a command to 31 characters.

Mapping of the native `NEngCtl*` JNI calls (they require a *connected* session and use the PJ the engine already tracks):
`NEngCtlChangeSource(id, 0|1|2)` → PC / Video / LAN · `NEngCtlAVMute` · `NEngCtlFreeze` · `NEngCtlVolumeUP/Down` · `NEngCtlDispQRCode`.

## 4. ECON U2U commands (channel D)  **[V]/[I]**

For a **secured projector with an active session** `Pj.pjcontrol_spoweron` and the remote-pad use ECON command **`0x116`**
(`CEasyCommand::MakeU2UCommand`, `CEconProjectionClientNSC10::U2UCommandSub`) instead of ESC/VP:

```
U2U_COMMAND_PARAM { u8 target (0x10); i32 kind; i32 args[...] }
kind  6       key emulation       (arg = key code; JNI NEngSendU2UCommandKeyEmulation copies "KEY xx" string, max 0x7F chars)
kind  7       network standby ON  (NEngSendU2UCommandNWStandbyON)
kind -1       free format, sub-kinds 1/2/5/6 (screen lock request, status, thumbnail control)
kind -2/-3    status notifications (U2UCommandNotifyStatus)
```

The wire layout is the same ECON container (doc 01 §3): body bytes `+4` target, `+8` kind, `+0x0C…` arguments; the projector's reply
is dispatched in `AnalyzeEconData case 0x116` (error classes `-5,-2,-3,-1`). Details of the arguments for every `kind` were
not fully reconstructed **[?]** — capture one `PWR`/`KEY` U2U command to confirm.

## 5. Web Remote (channel E)  **[V]**

`AuthInfo` ([source](../apk/sources/com/epson/iprojection/ui/activities/remote/AuthInfo.java)) builds the URL and default credentials that the app
tries first; HTTP **Digest** (RFC 2617, MD5) is implemented in `HttpDigestAuth.java`:

| remote type | URL | user | default password |
|---|---|---|---|
| Web Remote (business) | `http://<ip>/webremote/index.html` | `EPSONREMOTE` | `guest` |
| Smart Remote | `http://<ip>/mobile/index.html?EPSON=Projector` | `EPSONMOBILE` | *(empty)* |
| Signage | `http://<ip>/webremote/index.html` | `EPSONWEB` | `admin` |

These are the factory defaults compiled into the client; the real password may have been changed on the device. Timeouts 10 s.

## 6. Which channel does the app pick?  (`commandsend/state/StartState.java`)

```
if PJ.isSupportedSecure:
    if (escvp-only requested) or (not connected): DigestEscvpSendingState   (B)  [password: PJ's saved → "apply all" → prompt]
    else (connected)                              U2USendingState            (D)
else:
    OpenEscvpSendingState                                                     (A)
status poll of a registered PJ:  C when isSupportedSecuredEscvp else A ("PWR?")
```

Error returns from the engine: `-441` wrong ESC/VP.net password, `-430` send ESC/VP error, `-4xx` network errors (doc 02 §2).

## 7. Reference implementation (headless)

```python
import socket, hashlib

def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise ConnectionError("closed")
        buf += c
    return buf

def escvp_open(ip, cmd, read_reply=False, timeout=3):
    s = socket.create_connection((ip, 3629), timeout=timeout)
    s.sendall(b"ESC/VP.net" + bytes([0x10,0x03,0,0,0,1, 0x01,0x01]) + b"ELPCSPOPN".ljust(16, b"\0"))
    h = _recv_exact(s, 16)
    assert h[:10] == b"ESC/VP.net" and h[10] == 0x10 and h[11] == 0x03 and h[14] == 0x20, h.hex()
    s.sendall(cmd.encode() + b"\r")
    out = b""
    if read_reply:
        s.settimeout(timeout); out = s.recv(64)
    s.close(); return out.decode(errors="replace").split("\r:")[0] if read_reply else None

def escvp_digest(ip, cmd, password, timeout=3):
    s = socket.create_connection((ip, 3629), timeout=timeout)
    s.sendall(b"ESC/VP.net" + bytes([0x20,0x03,0,0,0,1, 0x01,0x03]) + b"\0"*16)
    r = _recv_exact(s, 34)
    st = r[14]
    if st == 0x55:                       # not supported -> use open mode
        s.close(); return escvp_open(ip, cmd, True, timeout)
    nonce = r[18:34] if st == 0x41 else b"\0"*16
    pw = password if st == 0x41 else ""
    h1 = hashlib.sha256(("ESC/VP.net:" + pw).encode()).hexdigest()
    h  = hashlib.sha256((h1 + ":" + nonce.hex()).encode()).digest()
    s.sendall(b"ESC/VP.net" + bytes([0x20,0x03,0,0,0,2, 0x01,0x04]) + h[:16] + bytes([0x01,0x05]) + h[16:])
    ok = _recv_exact(s, 16)
    if ok[14] != 0x20: raise PermissionError("wrong ESC/VP.net password (-441)")
    s.sendall(cmd.encode() + b"\r"); s.close()

def escvp_secured_query(ip, what="PWR?", timeout=3):
    sel = {"SNO?": 1, "PWR?": 2}[what]
    s = socket.create_connection((ip, 3629), timeout=timeout)
    s.sendall(b"ESC/VP.net" + bytes([0x20,0x02,0,0,0,1, 0x06, sel]) + b"\0"*16)
    r = _recv_exact(s, 34); s.close()
    assert r[10] == 0x20 and r[11] == 0x02 and r[14] == 0x20
    return r[18:34].split(b"\0")[0].decode()
```

The packet builders above were checked against the decompiled constants (lengths 34 / 34 / 52 / 34 bytes); they have **not** been run against a
projector. `PWR=01` is lamp on, `PWR=04`/`09` standby (network standby) — map anything else to *unavailable/offline*.

## 8. Notes for automation

* A projector in network standby is tracked by the app through `PWR?` polling of *registered* IPs (not through ECON search) **[I]** → use ESC/VP (3629) for presence/power of known projectors.
* **Batch control** of many projectors = iterate over IPs, one short TCP connection per command (the app does exactly this, one thread per PJ).
* Respect the 3 s receive timeout; some PJs close the socket right after the command.
* Standard ESC/VP21 replies `ERR` on a refused command (e.g. `PWR ON` while cooling) — the app never reads it for fire-and-forget commands; do read the reply (`read_reply=True`) if you need success feedback **[I]**.
