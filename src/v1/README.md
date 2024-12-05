The zkEngine is an (NIVC) zkWASM implementation based on the [Nebula](https://eprint.iacr.org/2024/1605) proving scheme.
It aims to be memory efficient and highly portable for constrained enviroments. With these traits it can be used for
local verifiable compute and privacy on a large array of devices.

The zkEngine is the backend for the [NovaNet](https://novanet.xyz) incentive and prover network. 

## Usage: as Rust dependency

### Cargo

```toml
[dependencies]
zk-engine = { git = "https://github.com/ICME-Lab/zkEngine_dev", branch= "main" }
```