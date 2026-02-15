# meshbot-udp

**PLEASE NOTE: THIS IS WORK IN PROGRESS AND MOSTLY BROKEN**

A bot parsing, crafting and sending Meshtastic packets via UDP multicast.

## How it works

The bot joins a UDP multicast group (default `224.0.0.69:4403`) and listens for
incoming Meshtastic `MeshPacket` protobufs. Each received packet goes through:

1. **Deduplication** — packet IDs are cached to discard duplicates
2. **Decryption** — AES-128-CTR using the configured key, with an IV built from
   the packet ID and sender address
3. **Decoding** — the inner `Data` protobuf is decoded to determine the meshtastic specific port number
4. **Dispatch** — a `MsgDispatcher` routes the message to handler chains registered
   per `PortNum` (TextMessage, NodeInfo, Position, Routing, Traceroute)

Handlers can return `Continue` to pass the message to the next handler in the chain,
or `Finished` to stop processing.

The bot also periodically broadcasts its own `NodeInfo` (including its public key)
to the multicast group and responds to `!ping` text messages with `pong!`.

### PKI-encrypted direct messages

The bot supports Meshtastic 2.5+ PKI-encrypted private messaging. An X25519
keypair is generated on first run and persisted in the config file. To send a
PKI-encrypted direct message, `send_private_msg()` looks up the recipient's
public key from the node database, performs X25519 ECDH key agreement, derives
an AES-256 key via SHA-256, and encrypts the payload with AES-256-CCM
(8-byte auth tag). The resulting `MeshPacket` is marked `pki_encrypted = true`
with the sender's public key attached.

## Configuration

CLI options (run with `--help`):

| Flag               | Default                     | Description                     |
|--------------------|-----------------------------|---------------------------------|
| `-i`               | `10.0.0.1`                  | Local interface address to bind |
| `-m`               | `224.0.0.69`                | Multicast group address         |
| `-p`               | `4403`                      | UDP port                        |
| `-c`               | `$HOME/meshbot/config.json` | Config file path                |
| `-n`               | `$HOME/meshbot/nodedb.json` | Node database path              |
| `-v` / `-d` / `-t` | off                         | Verbosity: info / debug / trace |

The config file (`config.json`) is auto-created on first run with a random MAC,
node ID, and X25519 keypair. It controls the AES key, hop limit, nodeinfo
broadcast interval, and a UDP source whitelist. Paths support shell expansion
(`$HOME`, `~`, env vars).

The node database (`nodedb.json`) persists discovered mesh nodes and is updated
on disk and in memory whenever a `NodeInfo` message is received.

## Building

```
cargo build                    # debug
cargo build --release          # release (fat LTO)
cargo build --profile minsize  # minimal size (stripped, abort on panic)
```

Regenerate protobuf Rust types from the `src/protobufs/` git submodule:

```
cargo build --features gen
```

## Cross-building

Asus RT-AX59U (arm64, OpenWrt):

```
cross build --release --target aarch64-unknown-linux-musl
```

Asus RT-AX53U (mips, OpenWrt):

```
cross +nightly build -Z build-std --release --target mipsel-unknown-linux-musl
```
