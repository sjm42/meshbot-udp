# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2024 crate named `meshbot_udp`. `src/lib.rs` re-exports the main
modules:

- `src/config.rs` handles CLI and JSON configuration.
- `src/state.rs` owns runtime state, node database persistence, and packet cache state.
- `src/mesh.rs` contains packet encryption, decryption, dispatch, and send helpers.
- `src/bin/meshbot_udp.rs` is the UDP multicast bot executable.
- `src/protobufs/` contains Meshtastic protobuf inputs and package metadata.
- `src/generated/` contains generated Rust protobuf code; do not edit it directly.

There is no dedicated `tests/` tree yet. Add unit tests near the module they
exercise, or integration tests under `tests/` for binary/API behavior.

## Build, Test, and Development Commands

- `cargo build` builds the debug binary and library.
- `cargo build --release` builds with release LTO settings from `Cargo.toml`.
- `cargo build --profile minsize` builds a stripped, smaller release profile.
- `cargo run -- --help` shows CLI options for multicast, config paths, and verbosity.
- `cargo test` runs the test suite.
- `cargo fmt` applies repository formatting rules.
- `cargo clippy --all-targets --all-features` checks common Rust issues.
- `cargo build --features gen` regenerates protobuf Rust types from `src/protobufs/`.

## Coding Style & Naming Conventions

Use stable Rust from `rust-toolchain.toml`. Formatting is controlled by
`rustfmt.toml`: 100-column width, crate-granular imports, grouped std/external/crate
imports, and compressed function parameter layout. Use Rust naming conventions:
`snake_case` for functions/modules, `CamelCase` for types, and `SCREAMING_SNAKE_CASE`
for constants. Keep generated protobuf code out of manual edits; update source
`.proto` files and rebuild with `--features gen`.

## Testing Guidelines

Prefer deterministic tests for packet parsing, encryption/decryption, config path
expansion, whitelist behavior, and dispatcher flow. Name tests after observable
behavior, for example `decrypt_payload_rejects_bad_mac`. Run `cargo test` before
submitting changes.

## Commit & Pull Request Guidelines

Recent history uses short, imperative commit subjects such as `cargo update`.
Keep subjects concise and scoped, for example `fix whitelist matching` or
`regenerate protobuf bindings`. Pull requests should describe behavior changes,
list validation commands run, and mention config or network defaults affected.
Include logs or packet examples for multicast or protocol changes when useful.

## Security & Configuration Tips

Runtime config and node database files default under `$HOME/meshbot/`. Do not
commit generated secrets, local node IDs, private keys, or real deployment
whitelists. Treat multicast test captures as potentially sensitive mesh traffic.
