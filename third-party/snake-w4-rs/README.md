# snake-w4-rs

## Description

A simple snake game cartridge written in [rust](https://www.rust-lang.org/) for [WASM-4](https://wasm4.org/),<br>
a low-level fantasy game console for building small games with [WebAssembly](https://webassembly.org/).

## Develop

## Requirements

- [rust toolchain](https://www.rust-lang.org/tools/install)
- wasm32-unknown-unknown target: `rustup target add wasm32-unknown-unknown`
- [wasm4](https://wasm4.org/docs/getting-started/setup)

#### Release build

```bash
cargo build --release
```

### Run locally

```bash
w4 run target/wasm32-unknown-unknown/release/snake_w4_rs.wasm
```

## License

[MIT](./LICENSE)

