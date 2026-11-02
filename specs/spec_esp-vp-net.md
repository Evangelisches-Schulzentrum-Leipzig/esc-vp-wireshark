# ESC/VP.net Protocol Specification

**Scope:** binary ESC/VP.net framing, connection setup, and authentication for projector control on port 3629. The
ASCII command language carried after a successful connection is specified separately in
[spec_esp-vp21.md](spec_esp-vp21.md).

This independent, community-maintained specification describes ESC/VP.net packet formats and session behavior.
Protocol details are based on the Epson reference and the
[iProjection control-protocol notes](../docs/iprojection-protocol/03-control-protocol.md); unspecified or
inferred behavior is identified as such.

## 1. Overview

ESC/VP.net is the binary control/session protocol. It negotiates a connection and, for TCP sessions, carries
ESC/VP21 ASCII commands over the same connection. TCP control sessions use port **3629**. The documented
session-less HELLO exchange also uses UDP port **3629**.

Two version values are relevant:

| Wire version | Label used here | Summary |
|---|---|---|
| `0x10` | V1 (1.0) | Plain-password CONNECT, followed by an ESC/VP21 command session. |
| `0x20` | V2 (2.0) | Challenge-based digest authentication. |

The original reference describes the version octet as a packed value whose high nibble is the major version and
low nibble is the minor version: `0x10` is version 1.0 and `0x20` is version 2.0. Support is firmware-dependent;
acceptance of one version does not prove support for the other.

## 2. Common packet format

Every ESC/VP.net control packet starts with a 16-byte common header. Optional fixed-size headers follow it.

| Offset | Size | Field | Request value / interpretation |
|---:|---:|---|---|
| 0 | 10 | Signature | ASCII `ESC/VP.net` |
| 10 | 1 | Protocol version | `0x10` or `0x20` |
| 11 | 1 | Message type | `0` NULL, `1` HELLO, `2` PASSWORD, `3` CONNECT |
| 12 | 2 | Reserved / sequence-number field | Big-endian `0x0000` |
| 14 | 1 | Status | `0x00` in a request; response status in a reply |
| 15 | 1 | Header count | Number of 18-byte headers immediately following |

Each optional header is 18 bytes:

| Relative offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Header identifier |
| 1 | 1 | Attribute |
| 2 | 16 | Header information / value |

For a packet containing only the common header and these fixed-size headers, its length is
`16 + (18 * header_count)` bytes. On TCP, read exactly the declared header bytes before parsing the next protocol
data; a TCP read is not guaranteed to match a packet boundary.

### 2.1 Message types

| Type | Name | Use |
|---:|---|---|
| `0x00` | NULL | Reserved / no operation. |
| `0x01` | HELLO | Session-less discovery or capability exchange. V1 UDP HELLO is documented; V2 HELLO is not established by the evidence here. |
| `0x02` | PASSWORD | Password-presence check, password confirmation, or password change flow. It is not the normal command-session setup. |
| `0x03` | CONNECT | Starts an ESC/VP21 session. In V2, this type is also used for the digest challenge flow. |

### 2.2 Response status values

The status byte is at offset 14:

| Status | Name | Meaning |
|---:|---|---|
| `0x20` | OK | Request accepted / operation succeeded. |
| `0x40` | Bad Request | Malformed packet, unsupported header, or invalid field. |
| `0x41` | Unauthorized | Password is required; in V2 challenge flow this accompanies the challenge. |
| `0x43` | Forbidden | Password/authentication rejected. |
| `0x45` | Request Not Allowed | Message type is not allowed in the current transport/mode. |
| `0x53` | Service Unavailable | Projector is busy or unavailable. |
| `0x55` | Version Not Supported | Requested protocol version is unsupported. |

After a rejected TCP request, the projector commonly closes the connection after sending the response. A client
should treat EOF/reset as transport termination, not as a successful response.

## 3. Header identifiers and attributes

| ID | Name | Attributes / interpretation |
|---:|---|---|
| `0x01` | Password | Attribute `0x00`: no password; `0x01`: plain US-ASCII. V2 challenge/proof attributes are detailed in Section 7. |
| `0x02` | New password | Password-change header. The legacy reference identifies attributes `0x00` (none) and `0x01` (plain US-ASCII). |
| `0x03` | Projector name | Attribute `0x00`: no name; `0x01`: US-ASCII; `0x02`: Shift-JIS (reserved); `0x03`: EUC-JP (reserved). |
| `0x04` | IM-Type / model type | Attribute identifies a projector family; information bytes are normally zero-filled. See values below. |
| `0x05` | Projector command type | Attribute `0x16`: ESC/VP Level 6 (reserved); `0x21`: ESC/VP21 v1.0. |

Each header's information field is exactly 16 bytes. Text fields are normally NUL-padded. The newer V2 attributes
are described in the authentication section; unrelated attribute values should be treated as unknown, not guessed.

The legacy reference assigns these values to the IM-Type header's attribute:

| Attribute | Meaning |
|---:|---|
| `0x0C` | Type D |
| `0x10`-`0x15` | Reserved |
| `0x16`-`0x19` | Type A (`0x17`-`0x19` are also marked reserved in the reference) |
| `0x20` | Initial EMP/PL-735 model |
| `0x21` | Type C / Type E |
| `0x22` | Type F |
| `0x23` | Type G |
| `0x24`-`0x29` | Reserved |
| `0x30` | Type B |
| `0x31`-`0x39` | Reserved |
| `0x40` | Type H |
| `0x41` | Type I |
| `0x42` | Type J |
| `0x43`-`0x49` | Reserved |
| `0x50` | Type K |
| `0x51`-`0x59` | Reserved |

## 4. Transport and session lifecycle

### 4.1 UDP HELLO

The discovery request is a V1 HELLO packet (`version=0x10`, `type=0x01`, `status=0`, no headers) sent to the
broadcast address on UDP port 3629. A successful response may include projector-name, IM-Type, and
projector-command-type headers.

### 4.2 TCP CONNECT

For command control, connect to TCP port 3629 and exchange ESC/VP.net packets. A successful CONNECT response
(`status=0x20`) leaves the TCP connection open; ESC/VP21 command bytes then travel directly over that connection.
The connection ends when either endpoint closes it. PASSWORD checks and failed CONNECT attempts are separate
transactions and normally end after their response.

## 5. V1 (version `0x10`) password and CONNECT flow

V1 places a 16-byte plain password value in a Password header. The password is therefore visible to a passive
observer on the local network; this protocol layer does not provide TLS.

### 5.1 PASSWORD message (type `0x02`)

A PASSWORD request checks whether a password is configured or confirms a password. It does **not** establish the
long-lived ESC/VP21 command session. The projector sends a response and then closes the TCP connection.

Password-presence check (no headers):

```text
"ESC/VP.net" 10 02 00 00 00 00
```

The response status is `0x20` if no password is configured, or `0x41` if one is configured.

Password confirmation:

```text
"ESC/VP.net" 10 02 00 00 00 01 | 01 01 | "AbCdEfGhIjk" + NUL padding to 16 bytes
```

The response is `0x20` for a correct password or `0x43` for an incorrect password. A configured password omitted
from the request produces `0x41`. If no password is configured, a supplied password is ignored. A New-Password
header (`id=0x02`) is defined for password-change operations; the complete change procedure is not specified here.
These PASSWORD replies have no headers and use the same common response shape:

```text
"ESC/VP.net" 10 02 00 00 <status> 00
```

`<status>` is `0x20` (accepted), `0x41` (password required), `0x43` (incorrect password), or `0x53` (busy), as
applicable.

### 5.2 CONNECT message (type `0x03`)

CONNECT without a password header is:

```text
"ESC/VP.net" 10 03 00 00 00 00
```

It succeeds when no password is configured. For a password-protected projector, include one Password header:

```text
offset 0..15:  "ESC/VP.net" 10 03 00 00 00 01
offset 16..33: 01 01 <16-byte password field>
```

The fields are `version=0x10`, `type=0x03`, reserved=`0`, request status=`0`, header count=`1`, header ID=`0x01`,
and attribute=`0x01`. The legacy reference specifies a printable US-ASCII password. A shorter value is
NUL-padded in the fixed 16-byte field. Behavior for values longer than 16 bytes is implementation-dependent.

Successful CONNECT response:

```text
"ESC/VP.net" 10 03 00 00 20 00
```

This 16-byte response (`status=0x20`, no headers) starts the bidirectional ESC/VP21 session. The TCP connection
remains open until either endpoint closes it; ESC/VP21 commands are sent directly over the stream.
CONNECT failure replies use the same 16-byte shape with `type=0x03` and no headers:

```text
"ESC/VP.net" 10 03 00 00 <status> 00
```

The status is `0x41` when a configured password is missing, `0x43` for an incorrect password, and `0x53` when
the projector is busy or cannot start a session. Unlike an accepted CONNECT, each failure response is followed
by TCP connection closure.

| Response status | Result |
|---:|---|
| `0x20` | CONNECT accepted; keep the TCP session open and send ESC/VP21 commands. |
| `0x41` | Password required but omitted. |
| `0x43` | Supplied password is incorrect. |
| `0x53` | Projector is busy or cannot start a new ESC/VP21 session. |

If a password is supplied when none is configured, the legacy reference says it is ignored. Authentication
failures and busy responses close the TCP connection after the response.

## 6. V1 validation and transport-specific errors

The original reference describes V1 as accepting version `0x10`. V2 behavior is covered separately below; older
projectors may reject a version `0x20` request with `0x55`.

| Condition | Response / behavior |
|---|---|
| Invalid signature, type outside `0..3`, nonzero request status/reserved field, invalid header ID/attribute, or other malformed V1 request | `0x40` Bad Request. In TCP session mode, close the connection after the response. |
| Unsupported version | `0x55` Version Not Supported; in TCP mode, close the connection. |
| UDP request type is not HELLO (`0x01`) | `0x45` Request Not Allowed. |
| TCP request type is neither PASSWORD (`0x02`) nor CONNECT (`0x03`) | `0x45` Request Not Allowed, then close the connection. |
| HELLO contains headers | `0x40` Bad Request. |
| PASSWORD uses a header other than Password/New-Password, or the password is blank, non-printable, or outside US-ASCII | `0x40` Bad Request, then close the connection. |
| PASSWORD omits a configured password | `0x41` Unauthorized, then close the connection. |
| PASSWORD includes an incorrect configured password | `0x43` Forbidden, then close the connection. |
| Projector is busy while processing PASSWORD or CONNECT | `0x53` Service Unavailable, then close the connection. |
| CONNECT omits a configured password | `0x41` Unauthorized, then close the connection. |
| CONNECT includes an incorrect configured password | `0x43` Forbidden, then close the connection. |
| CONNECT cannot start another ESC/VP21 session | `0x53` Service Unavailable, then close the connection. |

The legacy reference also states that a password supplied when no password is set is ignored. Exact validation and
connection-close behavior can vary by projector firmware; the table records the documented V1 behavior.

## 7. V2 (version `0x20`) digest authentication

V2 uses a challenge and a SHA-256 response. It is a proprietary ESC/VP.net digest scheme, not HTTP Digest.
The password is not sent as a plain-text field in this exchange.

### 7.1 Challenge request

The V2 CONNECT challenge request is 34 bytes:

```text
"ESC/VP.net" 20 03 00 00 00 01 | 01 03 | 16 zero bytes
```

This is `version=0x20`, `type=0x03`, one Password header (`id=0x01`, `attribute=0x03`) whose 16-byte value is
zero-filled.

The challenge response uses version `0x20`, type `0x03`, and status `0x41`; its 16-byte nonce occupies packet
offsets 18-33. A `0x55` status indicates that V2 is unsupported.

### 7.2 Digest calculation and proof

Let `password` be the configured password and `nonce` the 16 raw challenge bytes:

```text
nonceHex = lowercase hexadecimal encoding of nonce
passwordHashHex = lowercase hex(SHA256(UTF8("ESC/VP.net:" + password)))
digest = SHA256(ASCII(passwordHashHex + ":" + nonceHex))
```

`digest` is 32 raw bytes. The proof carries it in two 16-byte Password headers:

| Header | ID | Attribute | Information |
|---|---:|---:|---|
| First digest half | `0x01` | `0x04` | `digest[0..15]` |
| Second digest half | `0x01` | `0x05` | `digest[16..31]` |

The proof packet is 52 bytes: the 16-byte common header (`type=0x03`, request status `0`, header count `2`) plus
two 18-byte headers. A response status of `0x20` indicates that authentication succeeded; a non-OK response is
an authentication or request failure. After successful authentication, send ESC/VP21 command bytes on the same
TCP connection.

## 8. Session conformance

A receiver MUST parse the complete 16-byte common header before interpreting its status. If the header count is
nonzero, the receiver MUST also read the declared 18-byte headers before processing their contents.

After a V2 challenge response with status `0x41`, the client MUST read the complete challenge, compute the
SHA-256 proof, and send both digest headers. A rejected TCP request terminates that session; a subsequent
connection uses a new TCP socket. Status `0x55` indicates that the requested version is unsupported.

After a successful CONNECT response (`status=0x20`), ESC/VP21 command lines are ASCII and end with carriage
return (`0x0D`). Responses end with `0x0D 0x3A`. TCP does not preserve message boundaries, so receivers MUST
buffer data through the complete response terminator.

## 9. Security and compatibility notes

* V1 sends a plain password in a fixed-width field. Use it only on a trusted network.
* V2's challenge-response avoids sending the password as clear text, but does not encrypt subsequent commands or
  replace transport-layer protection.
* Version support is projector/firmware-dependent. Status `0x55` identifies an unsupported version, not an
  authentication failure.
* See [spec_esp-vp21.md](spec_esp-vp21.md) for command grammar and common command values.

## 10. References

* Epson ESC/VP.net reference PDF, Revision F: [../docs/1050273.pdf](../docs/1050273.pdf) ([source link](https://ia601808.us.archive.org/8/items/manualzz-id-1050273/1050273.pdf)).
* iProjection reverse-engineering notes: [03-control-protocol.md](../docs/iprojection-protocol/03-control-protocol.md).
