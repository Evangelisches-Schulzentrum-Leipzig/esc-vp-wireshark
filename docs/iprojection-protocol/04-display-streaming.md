# 04 — Display / audio streaming

> Confidence tags: **[V]** read from code/rodata, **[I]** inferred, **[?]** unresolved. Static analysis only; not replayed on hardware.

## 1. Two transports

| Transport | When | Carries |
|---|---|---|
| **JPEG/RAW "EPRD0600" stream** (default; `ProtocolType.JPEG`) | all projectors; always used for multi-projector (> 1 PJ), ChromeOS, Huawei devices, devices without H.264, projectors without WebRTC | rectangles of the screen, encoded by the native engine, over a dedicated **TCP 3621** connection |
| **WebRTC** (`ProtocolType.WebRTC`) | exactly one projector with `D_PjInfo.isSupportedWebRTC`, Android device with usable H.264 encoder, not Huawei/ChromeOS (`WebRTCUtils.shouldUseWebRTC`) | H.264 video + optional audio via Google WebRTC (`libjingle_peerconnection_so.so`), signalling/control = ECON `0x124`–`0x129` (see §6) |

Switch: `Engine.ChangeProtocol(ProtocolType)` → `NEngChangeProtocol(bool)` → ECON `SendChangeProtocol`.

## 2. Capture on Android (Java)

```
MirroringService (foreground, FOREGROUND_SERVICE_MEDIA_PROJECTION)         service/mirroring/*
  MirroringPresenterJPEG → MirroringJpegImageReader (extends MirroringJpeg)
     MediaProjection.createVirtualDisplay("Capturing Display", W, H, dpi, flags=16 (AUTO_MIRROR),
                                          ImageReader.newInstance(W, H, PixelFormat 1 = RGBA_8888, maxImages 5))
     onImageAvailable → Bitmap (reused) → Pj.sendMirroringImage(bitmap)
        → ImageSender.sendImageWithConvertingBitmapConfig → draws centred into the engine-sized buffer bitmap
        → Engine.SendImage(bitmap, Rect[] dirty (may be null), ResRect)  → EngineJni.NEngSendImage(Bitmap, Rect[], ResRect)
  MirroringJpegAudio: AudioPlaybackCapture AudioRecord, 22050 Hz, mono, PCM-16 (or 8-bit) → Pj.addAudioData(byte[])
```

* `W×H` come from `NEngGetSendImageBufferSize(ids[], int[2])` (returns the common projection size for the selected projectors;
  `Pj.getPjResWidth/Height`). The app letterboxes the device screen into a bitmap of exactly that size.
* A "wait" bitmap (black + icon, bottom-right with 32-px margin) is sent when mirroring is paused (`ImageSender.sendWaitImage`);
  it is re-sent after 60 s (`DELAY_SEND_TIME`).
* Native may call back `CallBackRequestResendImage(mode)` (projector asked for a refresh) → Java re-sends `m_pTempImageFull`.
* Moderator mode: `NEngUpdateThumbnail(bitmap, rects)` / `NEngRequestThumbnail`, `NEngProjectionMyself`, `NEngSetProjectionMode(1|2|4)`
  (1 = full, 2 = wait/thumbnail only, 4 = …).
* Tunables (`NEngSetParameter(id, value)`): `3` encryption, `5` audio on/off, `22` bandwidth, `24` image-proc-time callback interval, `25` projector-log upload.
  Bandwidth enum → target throughput table in `libengine.so` (bytes/s): `eNoControl` (none), `e4M` 524 288, `e2M` 262 144, `e1M` 131 072,
  `e512K` 65 536, `e256K` 32 768, `e7M` 917 504, `e15M` 1 966 080, `e25M` 3 276 800 (`CPerformanceInfo::GetBandwidthControl`, table @ vaddr `0xD5030`).

## 3. Native pipeline (libengine.so)

```
NEngSendImage(Bitmap, Rect[], ResRect)                         JNI.c
  CDisplayAndroid / CDisplayManager      Bitmap → DIB (CDIB), dirty rects (CPRect/CPRectAdjuster/CPRangeAdjuster)
  CPictureController::SendPictureData
    CPictureData::UpdateDIBAndRect / UpdateRectList / OptimizeRectList / AlignRectList / ScanlinizeRectList
    CPictureData::DecideEncodeType  (CPImageColorChecker::isNaturalImage decides JPEG vs lossless "flat" encodings,
                                     threshold = JPEG quality setting; CheckSmoothImage)
    CPictureData::DoEncoding        JPEG (libjpeg-turbo 2.0.5, CDisplay::BitmapToJpeg) | RAW/RAWEX | ZLIB/LZO/EIC/… per capability
  CPictureControlCommand::SendPictureCommand → CPictureControlCommandHelper::CreateCommandWithEncoder
        MakeCommandHeader ("EPRD0600") → MakeCommandData (rect headers + chunk data) → Encrypt (AES/EPCTR, optional)
  CEconProjectionClientNetwork::SendPconPictureData(buf,len)   plain blocking send() on the PCON picture socket
```

Quality / rate control lives in `CPerformanceInfo` (reads an optional `./PerformanceSetting` file; settings `JPEGQuality`,
`MinImageQuality`, `MaxImageQuality`, `StartImageQuality`, `MinFps`, `MaxFps`, `CaptureInterval`, `SendPicInterval`,
`ResendInterval`, `DividRectSize`, `SmoothThreshold`, `ResizeFullScreen`, `OptimizeSending`, `PriorQuality`, `WaitSendInterval`,
`ReSendDuringBandwidthControl`) and `CQualityController` / `CQualityLevelChecker` (adaptive quality from measured throughput).
When a bandwidth cap is set, `MakeCommandData` sleeps after each chunk so that `bytes/s ≤ cap`:
`sleep_ms = 1e6 / (cap / (dataLen + headerLen + 0x200)) − procTime_µs, /1000` **[V]**.

## 4. PCON picture socket — framing  **[V]** (`CPictureControlCommandHelper.c`, `CEconProjectionClientNetwork.c`)

Opened after ECON `0x110` (doc 02 §4): `connect(<pj>:3621)`, send the 36-byte **identifier** (type 0), then stream commands.

### 4.1 Stream command header (20 bytes) — `MakeCommandHeader`

```
0x00  "EPRD0600"                 8   magic (rodata @ 0xD3FD0)
0x08  client IPv4, network order 4
0x0C  00 00 00 00                4
0x10  payload length             4   **big-endian**: bytes after this header (rect data incl. headers and padding)
```

### 4.2 Screen-format command (`CreateScreenFormatCommandWithEncoder`) — sent when the format/resolution is (re)negotiated **[I]**

20-byte header with payload length `0x18` (`0x2E` with a work-area block), payload:

```
C8 00 00 00                opcode 0xC8
WW WW  HH HH               width, height (u16 big-endian)
pixel format (16 B):  bpp,bpp,00,01,  redMax u16 LE, greenMax u16 LE,  blueMax u16 LE,  redShift, greenShift, blueShift, 00 …
     32/24 bpp: 20 20 00 01 | FF 00 | FF 00 | FF 00 | 10 08 00        (R16 G8 B0)
     16 bpp   : 10 10 00 01 | 1F 00 | 3F 00 | 1F 00 | 0B 05 00        (RGB565)
[work area: 6 × u16 BE when present, opcode byte 0xCC instead of 0xC8]
```

### 4.3 Rectangle update command — `MakeCommandData`

```
header (20 B, §4.1)
u16 0x0000 | u16 nRects (big-endian)                       4 B
repeat nRects:
   rect header            (type-dependent, below)
   rect data              chunk.size bytes
```

Chunk types (`CEncodeChunk::type`, 0…6; mapped from capability encoding ids by `CPictureData::ConvertCapEncodeType`:
`0x0000→1, 0x0100→2, 0x0200/0x0707/0x0D07→3, 0x0006→4, 0x0C07/0x0E07→5, 0x0B07→6`):

* **Tight-style header (types 0, 5, 6) — 16 bytes** (`MakeTightHeader`):

  ```
  left u16 BE | top u16 BE | width u16 BE | height u16 BE | 00 00 00 07 | ctl | len0 len1 len2
  ctl  : 0x90 for type 0 (JPEG),  0xC0 type 5,  0xB0 type 6     (0xC0/0xB0 not decoded)
  len* : (L & 0x7F)|0x80,  ((L>>7) & 0x7F)|0x80,  (L>>14) & 0xFF        (L = following chunk-data length)
  ```
  The `00 00 00 07` is a 32-bit big-endian "encoding id 7" (Tight), i.e. the stream is **Tight-inspired**.
  Type 0's chunk data is a baseline JPEG file (libjpeg-turbo); the payload formats for types 5 and 6 remain unresolved.
* **Raw-style header (types 1, 2) — 12 bytes** (`MakeRawHeader`): `left,top,width,height (u16 BE) | 00 00 00 00` then raw pixels (bpp per screen format; lossless "flat" modes `RAW16/RAW32/RAWEX…`).
* **Ex header (type 3) — 0x1C bytes (+ padding to the cipher block size when encrypted)** (`MakeExHeader`): `left,top,width,height BE | 00 00 00 07 | flag 0xD0 (0x70 when encoder present) | fmt 0x18/0x10 | pad | 0x1F? | len u32 BE`; used for "EX"/aligned encodings (`JPEGEX`, `RAWEX`, `LZOEX`, `*ALIGNED`). Exact field meaning **[?]**.

If encryption is active the whole payload after the 20-byte header is padded to the cipher block size with pad-bytes whose value equals the pad length
(`Encrypt`: `memset(buf+len, padLen, padLen)`), then encrypted in place (`AES/ECB` type 1, `AES-EPCTR` type 3; doc 02 §6) — block size comes from `CEncoder::blockSize()` (16).

The projector sends no per-frame ACK that the client waits for; flow control is TCP back-pressure plus the optional bandwidth cap above.
After a TCP error `errno 0x68` (ECONNRESET) is mapped to engine error `1`; other `send()` failures to `0xC`.

## 5. PCON audio socket  **[V]**

Second TCP connection to `<pj>:3621`, identifier byte `type = 1` (doc 02 §4), only if the projector reports audio support
(`isSupportedAudio`, `isSupportedAudioFrequency_22050`, `isSupportedAudioChannel_Monaural`, `isSupportedAudioQuantize_16bit`) and `NEngSetParameter(5,1)`.

```
chunk := C9 | len u32 LE | data[len]          (CPictureControlCommandAudioHelper::MakeCommandHeader: 0xC9 + 4-byte length)
data  := PCM, default 22 050 Hz, mono, 16-bit LE (8-bit when the projector lacks 16-bit);  encrypted/padded like pictures if encryption is on
```

The audio format negotiated in ECON `0x101` is a byte `freqCode | (16bit ? 2 : 0) | (stereo ? 1 : 0)`:
`11025→0x00, 12000→0x04, 16000→0x08, 22050→0x0C, 24000→0x10, 30000→0x14, 44100→0x18, 48000→0x1C` (`SendEconConnect`).
`CallBackPjAudioParameter(int)` returns the projector's required audio buffer size to Java (`Pj.getPjAudioBufferSize`).

## 6. WebRTC mode  **[V]/[I]**

```
PJ → client  ECON 0x124 "require_connect_webrtc":   body: width u16 @+4, height u16 @+6, partition u32 @+8
client:      WebRTCEntrance.createOfferSDP(width, height, bandWidth(kbps), pjIp, partition, audioEnabled)   (Java, org.webrtc)
             sdp += "ep=receiver-ip-addr:<pjIp>\n" + "ep=codec:H264\n"                               WebRTCUtils.addCustomSDP*
client → PJ  ECON 0x125:  body u32 = bandwidth;  ext TLV 0x1B (OctetString) = the SDP text (≤ 50 000 B)
PJ → client  ECON 0x126:  ext 0x1B = answer SDP     → WebRTCEntrance.answerSdp(sdp)
PJ → client  ECON 0x128: disconnect WebRTC
client → PJ  ECON 0x127: play-state byte (`SendPlayStateData`): API argument 2 → byte 1, 4 → byte 2, otherwise → byte 3
client → PJ  ECON 0x129: protocol-change byte (`SendChangeProtocol`): boolean value 0 or 1
```

Bandwidth target for WebRTC in kbit/s, `CPerformanceInfo::GetBandwidthControlForWebRTC(partition)` **[V]** (partition = number of users sharing the projector screen: default/1, 2, 4):

| setting | default | partition 2 | partition 4 |
|---|---|---|---|
| no control | 20 480 | 7 090 | 3 540 |
| 25M | 12 800 | 7 090 | 3 540 |
| 15M | 7 168 | 4 270 | 2 130 |
| 7M | 5 376 | 3 370 | 1 680 |
| 4M | 3 072 | 2 220 | 1 110 |
| 2M | 1 350 | 1 024 | 512 |
| 1M / 512K | 512 | 512 | 512 |
| 256K | 256 | 256 | 256 |
Local video is created from the same `VirtualDisplay` frames via `WebRTCVideoFrameConverter` (`service/webrtc/*`); on Android ≥ 14 the capture crop/scale is `CropAndScaleInfo` (`WebRTCWrapperAndroid14orMore`).
No STUN/TURN: `RTCConfiguration(new ArrayList())` — host candidates only, same LAN.

## 7. Minimal headless picture sender (sketch)

```python
import socket, struct, io
from PIL import Image                                 # any JPEG encoder will do

def pcon_connect(pj_ip, nic_ip, auth_id_be: bytes, kind=0):   # kind 0 = picture
    s = socket.socket(); s.bind((nic_ip, 0)); s.connect((pj_ip, 3621))
    ident = b"EPRD0600" + socket.inet_aton(nic_ip) + b"\0\0\0\0" + struct.pack("<I", 0x10) \
          + struct.pack("<I", 0xD0) + auth_id_be + bytes([kind, 0]) + b"\0"*6          # 36 bytes
    s.sendall(ident); return s

def send_jpeg_rect(s, nic_ip, x, y, w, h, jpeg: bytes):
    L = len(jpeg)
    rect = struct.pack(">HHHH", x, y, w, h) + b"\0\0\0\x07" + bytes([0x90, (L & 0x7F) | 0x80, ((L >> 7) & 0x7F) | 0x80, (L >> 14) & 0xFF]) + jpeg
    payload = b"\0\0" + struct.pack(">H", 1) + rect
    s.sendall(b"EPRD0600" + socket.inet_aton(nic_ip) + b"\0\0\0\0" + struct.pack(">I", len(payload)) + payload)

def push_frame(s, nic_ip, img: Image.Image, quality=75):
    buf = io.BytesIO(); img.convert("RGB").save(buf, "JPEG", quality=quality)
    send_jpeg_rect(s, nic_ip, 0, 0, img.width, img.height, buf.getvalue())
```

Preconditions: an ECON session is established (doc 02), the projector has sent `0x110`, `img` has exactly the engine-negotiated size
(`GetSendImageBufferSize` equivalent: use the CapPanelResolution / client resolution from the capability blob, doc 01 §6), and encryption is off.
The identifier fields and the Tight control byte are taken from the decompiled code; **verify against a packet capture before relying on them**
(especially `auth_id` byte order and whether a screen-format command (§4.2) must precede the first frame).

## 8. Open items

* Screen-format command trigger/ordering; exact `Ex` header; payload formats for chunk types 5/6 and meaning of control bytes `0xC0`/`0xB0`.
* Whether the projector answers on the PCON sockets (identify ack).
* Full AES-EPCTR key schedule (doc 02 §6).
* WebRTC `PlayState` (`SendPlayStateData`) body and `0x127/0x129` bodies.
