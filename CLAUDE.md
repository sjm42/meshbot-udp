# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Meshtastic mesh networking bot that parses, crafts, and sends Meshtastic protocol packets via UDP multicast. It joins a multicast group, receives encrypted Meshtastic `MeshPacket` protobufs, decrypts them with AES-128-CTR, and dispatches decoded payloads to handlers based on `PortNum`.

## Build Commands

```bash
cargo build                    # debug build
cargo build --release          # release build (fat LTO)
cargo build --profile minsize  # minimal size release (stripped, abort on panic)
cargo clippy                   # lint
cargo fmt                      # format (80 char width, crate-grouped imports)
```

Regenerate protobuf Rust code from the `src/protobufs/` git submodule:
```bash
cargo build --features gen
```

Cross-compile for embedded targets:
```bash
cross build --release --target aarch64-unknown-linux-musl
cross +nightly build -Z build-std --release --target mipsel-unknown-linux-musl
```

## Architecture

**Single binary** (`src/bin/meshbot_udp.rs`): Runs the main UDP multicast receive loop. Binds to a local interface, joins a multicast group, deduplicates packets via `packet_cache`, decrypts payloads, and dispatches to `MsgDispatcher`.

**Library modules** (`src/lib.rs` re-exports everything):
- `config.rs` — `CliOpts` (clap CLI args) and `MyConfig` (JSON config from `$HOME/meshbot/config.json`). Config auto-generates with random MAC/node ID and X25519 keypair on first run.
- `state.rs` — `MyState` holds runtime state: config, UDP sockets, node database (`RwLock<NodeDb>`), packet dedup cache, and RNG. Shared via `Arc<MyState>`.
- `mesh.rs` — Core protocol logic:
  - `MsgDispatcher` — Maps `PortNum` variants to chains of async handler functions. Handlers return `HandlerStatus::Continue` or `HandlerStatus::Finished` to control chain execution.
  - `decrypt_payload()` — AES-128-CTR decryption using packet ID + sender as IV.
  - `encrypt_payload_pki()` — PKI encryption: X25519 ECDH key agreement, SHA-256 key derivation, AES-256-CCM authenticated encryption (8-byte tag, 8-byte nonce). Returns `[ciphertext || tag || extra_nonce]`.
  - `send_text_msg()` / `send_nodeinfo()` / `send_private_msg()` — Outbound packet construction and transmission. `send_private_msg` sends PKI-encrypted direct messages using the recipient's public key from the node database.
  - Handlers for: TextMessage, NodeInfo (updates persistent node DB), Position, Routing, Traceroute.

**Protobuf types** (`src/generated/meshtastic.rs`): Auto-generated from `src/protobufs/` (Meshtastic upstream protobuf definitions as a git submodule). Included via `include!()` macro. Do not edit directly — regenerate with `--features gen`.

## Runtime Configuration

- CLI defaults: interface `10.0.0.1`, multicast `224.0.0.69`, port `4403`
- Config file: `$HOME/meshbot/config.json` (auto-created with defaults if missing)
- Node database: `$HOME/meshbot/nodedb.json` (persisted on every nodeinfo update)
- Paths support shell expansion (`$HOME`, `~`, env vars)

## Code Conventions

- Rust edition 2024, stable toolchain
- Uses nightly-style let-chains (`if let Ok(x) = ... && condition`)
- All source files end with `// EOF` comment
- `rustfmt.toml`: max_width=80, imports_granularity="Crate", group_imports="StdExternalCrate"
