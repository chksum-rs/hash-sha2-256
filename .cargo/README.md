# chksum-hash-sha2-256

[![GitHub](https://img.shields.io/badge/github-chksum--rs%2Fhash--sha2--256-24292e?style=flat-square&logo=github "GitHub")](https://github.com/chksum-rs/hash-sha2-256)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash-sha2-256/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash-sha2-256/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash-sha2-256?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash-sha2-256/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash-sha2-256/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash-sha2-256/0.0.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash-sha2-256/0.0.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash-sha2-256?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash-sha2-256/blob/master/LICENSE)

An implementation of SHA-2 256 hash algorithm for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash-sha2-256 = "0.0.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash-sha2-256
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash_sha2_256 as sha2_256;

let digest = sha2_256::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
);
```

Use the `default` function to create a hash instance for stream digest calculation.

```rust
use chksum_hash_sha2_256 as sha2_256;

let digest = sha2_256::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "62e84f4c96b9f9d30465b33f13710e479854762157c9dfa88ed89a01999fff2a"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash-sha2-256/).

## License

This crate is licensed under the MIT License.
