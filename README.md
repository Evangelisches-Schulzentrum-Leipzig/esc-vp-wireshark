# ESC/VP.net Wireshark Dissector

A Wireshark Lua dissector plugin for the **Epson ESC/VP.net** projector control protocol, including full **ESC/VP21** command session decoding.

## Features

- **ESC/VP.net handshake dissection** — decodes the 16-byte binary common header (signature, version, message type, status, headers)
- **Variable header parsing** — Password, New-Password, Projector-Name, IM-Type, and Projector-Command-Type with per-type attribute decoding
- **ESC/VP21 ASCII session parsing** — recognizes Set commands (`PWR ON`), Get queries (`SOURCE?`), query responses (`LAMP=3000`), ACK (`:`) and ERR
- **Parameter value decoding** — translates raw values into human-readable descriptions for 27 commands (power state, input source, aspect ratio, color mode, lamp hours, etc.)
- **Expert info** — warnings on error status codes, errors on malformed/truncated packets
- Registers on **TCP and UDP port 3629**

## Supported Protocols

| Protocol | Version | Transport | Description |
|----------|---------|-----------|-------------|
| ESC/VP.net | 1.0 (`0x10`) | TCP/UDP 3629 | Binary handshake: HELLO, PASSWORD, CONNECT |
| ESC/VP21 | 1.0 | TCP (post-CONNECT) | ASCII command session (Set, Get, Response) |

## Installation

Copy `espvpnet.lua` into your Wireshark personal plugins directory:

| OS | Path |
|----|------|
| Windows | `%APPDATA%\Wireshark\plugins\` |
| Linux | `~/.local/lib/wireshark/plugins/` |
| macOS | `~/.local/lib/wireshark/plugins/` |

Restart Wireshark or reload Lua plugins (**Ctrl+Shift+L** / **Analyze > Reload Lua Plugins**).

## Display Filter Examples

```
escvpnet                          -- All ESC/VP.net traffic
escvpnet.type == 3                -- CONNECT messages only
escvpnet.status == 0x43           -- Forbidden (wrong password) responses
escvpnet.vp21.command == "PWR"    -- Power commands/queries
escvpnet.vp21.decoded             -- Packets with decoded parameter values
escvpnet.header.im_type           -- Packets containing IM-Type headers
```

## Documentation

Protocol specification summaries are in [`specs/`](specs/) and reference PDFs in [`docs/`](docs/).

## Disclaimer

This dissector plugin was written entirely by AI (GitHub Copilot / Claude). The protocol specification documents in [`specs/`](specs/) were mostly laid out and structured by a human; the detailed content was subsequently expanded and completed with AI assistance.

Every change to the code and specification has been verified both against the protocol specification and for correct functionality in Wireshark using a real network capture of ESC/VP.net traffic.

## License

[Open Software License v3.0](LICENSE.txt)
