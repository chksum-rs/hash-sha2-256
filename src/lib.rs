//! This crate provides an implementation of the SHA-2 256 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-hash-sha2-256 = "0.0.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-hash-sha2-256
//! ```     
//!
//! # Batch Processing
//!
//! The digest of known-size data can be calculated with the [`hash`] function.
//!
//! ```rust
//! use chksum_hash_sha2_256 as sha2_256;
//!
//! let digest = sha2_256::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! ```
//!
//! # Stream Processing
//!
//! The digest of data streams can be calculated chunk-by-chunk with a consumer created by calling the [`default`] function.
//!
//! ```rust
//! // Import all necessary items
//! # use std::io;
//! # use std::path::PathBuf;
//! use std::fs::File;
//! use std::io::Read;
//!
//! use chksum_hash_sha2_256 as sha2_256;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! // Create a hash instance
//! let mut hash = sha2_256::default();
//!
//! // Open a file and create a buffer for incoming data
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//!
//! // Iterate chunk by chunk
//! while let Ok(count) = file.read(&mut buffer) {
//!     // EOF reached, exit loop
//!     if count == 0 {
//!         break;
//!     }
//!
//!     // Update the hash with data
//!     hash.update(&buffer[..count]);
//! }
//!
//! // Calculate the digest
//! let digest = hash.digest();
//! // Cast the digest to hex and compare
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Internal Buffering
//!
//! An internal buffer is utilized due to the unknown size of data chunks.
//!
//! The size of this buffer is at least as large as one hash block of data processed at a time.
//!
//! To mitigate buffering-related performance issues, ensure the length of processed chunks is a multiple of the block size.
//!
//! # Input Type
//!
//! Anything that implements `AsRef<[u8]>` can be passed as input.
//!
//! ```rust
//! use chksum_hash_sha2_256 as sha2_256;
//!
//! let digest = sha2_256::default()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "61466aaea66ab788a5f507ecd6061292c95e18fb9e144eab023a899aa96b59cb"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>`, digests can be chained to calculate hash of a hash digest.
//!
//! ```rust
//! use chksum_hash_sha2_256 as sha2_256;
//!
//! let digest = sha2_256::hash(b"example data");
//! let digest = sha2_256::hash(digest);
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "3290ecdd193eddf06676521ba0cf802dff85d3be5b2cf4725b79800af6626102"
//! );
//! ```
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]

pub mod block;
pub mod digest;
pub mod state;

use chksum_hash_core as core;

use crate::block::Block;
#[doc(inline)]
pub use crate::block::LENGTH_BYTES as BLOCK_LENGTH_BYTES;
#[doc(inline)]
pub use crate::digest::{Digest, LENGTH_BYTES as DIGEST_LENGTH_BYTES};
#[doc(inline)]
pub use crate::state::State;

/// Creates a new hash.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_256 as sha2_256;
///
/// let digest = sha2_256::new().digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
///
/// let digest = sha2_256::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[must_use]
pub fn new() -> Update {
    Update::new()
}

/// Creates a default hash.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_256 as sha2_256;
///
/// let digest = sha2_256::default().digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
///
/// let digest = sha2_256::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[must_use]
pub fn default() -> Update {
    core::default()
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_256 as sha2_256;
///
/// let digest = sha2_256::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
pub fn hash(data: impl AsRef<[u8]>) -> Digest {
    core::hash::<Update>(data)
}

/// A hash state containing an internal buffer that can handle an unknown amount of input data.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_256 as sha2_256;
///
/// // Create a new hash instance
/// let mut hash = sha2_256::Update::new();
///
/// // Fill with data
/// hash.update("data");
///
/// // Finalize and create a digest
/// let digest = hash.finalize().digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
///
/// // Reset to default values
/// hash.reset();
///
/// // Produce a hash digest using internal finalization
/// let digest = hash.digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct Update {
    state: State,
    unprocessed: Vec<u8>,
    processed: usize,
}

impl Update {
    /// Creates a new hash.
    #[must_use]
    pub fn new() -> Self {
        let state = state::new();
        let unprocessed = Vec::with_capacity(BLOCK_LENGTH_BYTES);
        let processed = 0;
        Self {
            state,
            unprocessed,
            processed,
        }
    }

    /// Updates the internal state with an input data.
    ///
    /// # Performance issues
    ///
    /// To achieve maximum performance, the length of incoming data parts should be a multiple of the block length.
    ///
    /// In any other case, an internal buffer is used, which can cause a speed decrease in performance.
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        let data = data.as_ref();

        // The `chunks_exact` method doesn't drain original vector so it needs to be handled manually
        for _ in 0..(self.unprocessed.len() / BLOCK_LENGTH_BYTES) {
            let block = {
                let chunk = self.unprocessed.drain(..BLOCK_LENGTH_BYTES);
                let chunk = chunk.as_slice();
                Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into()
            };
            self.state = self.state.update(block);
            self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
        }

        if self.unprocessed.is_empty() {
            // Internal buffer is empty, incoming data can be processed without buffering.
            let mut chunks = data.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                self.state = self.state.update(block);
                self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            if !remainder.is_empty() {
                self.unprocessed.extend(remainder);
            }
        } else if (self.unprocessed.len() + data.len()) < BLOCK_LENGTH_BYTES {
            // Not enough data even for one block.
            self.unprocessed.extend(data);
        } else {
            // Create the first block from the buffer, create the second (and every other) block from incoming data.
            let unprocessed = self.unprocessed.len() % BLOCK_LENGTH_BYTES;
            let missing = BLOCK_LENGTH_BYTES - unprocessed;
            let (fillment, data) = data.split_at(missing);
            let block = {
                let mut block = [0u8; BLOCK_LENGTH_BYTES];
                let (first_part, second_part) = block.split_at_mut(self.unprocessed.len());
                first_part.copy_from_slice(self.unprocessed.drain(..self.unprocessed.len()).as_slice());
                second_part[..missing].copy_from_slice(fillment);
                block
            };
            let mut chunks = block.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                self.state = self.state.update(block);
                self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            assert!(remainder.is_empty(), "chunks remainder must be empty");

            let mut chunks = data.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                self.state = self.state.update(block);
                self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            self.unprocessed.extend(remainder);
        }

        self
    }

    /// Applies padding and produces the finalized state.
    #[must_use]
    pub fn finalize(&self) -> Finalize {
        let mut state = self.state;
        let mut processed = self.processed;
        let unprocessed = {
            let mut chunks = self.unprocessed.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                state = state.update(block);
                processed = processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            chunks.remainder()
        };

        let length = {
            let length = unprocessed.len().wrapping_add(processed) as u64;
            let length = length.wrapping_mul(8); // convert byte-length into bits-length
            length.to_be_bytes()
        };

        if (unprocessed.len() + 1 + length.len()) <= BLOCK_LENGTH_BYTES {
            let padding = {
                let mut padding = [0u8; BLOCK_LENGTH_BYTES];
                padding[..unprocessed.len()].copy_from_slice(&unprocessed[..unprocessed.len()]);
                padding[unprocessed.len()] = 0x80;
                padding[(BLOCK_LENGTH_BYTES - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = {
                let block = &padding[..];
                Block::try_from(block)
                    .expect("padding length must exact size as block")
                    .into()
            };
            state = state.update(block);
        } else {
            let padding = {
                let mut padding = [0u8; BLOCK_LENGTH_BYTES * 2];
                padding[..unprocessed.len()].copy_from_slice(&unprocessed[..unprocessed.len()]);
                padding[unprocessed.len()] = 0x80;
                padding[(BLOCK_LENGTH_BYTES * 2 - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = {
                let block = &padding[..BLOCK_LENGTH_BYTES];
                Block::try_from(block)
                    .expect("padding length must exact size as block")
                    .into()
            };
            state = state.update(block);

            let block = {
                let block = &padding[BLOCK_LENGTH_BYTES..];
                Block::try_from(block)
                    .expect("padding length must exact size as block")
                    .into()
            };
            state = state.update(block);
        }

        Finalize { state }
    }

    /// Resets the internal state to default values.
    pub fn reset(&mut self) -> &mut Self {
        self.state = self.state.reset();
        self.unprocessed.clear();
        self.processed = 0;
        self
    }

    /// Produces the hash digest using internal finalization.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.finalize().digest()
    }
}

impl core::Update for Update {
    type Digest = Digest;
    type Finalize = Finalize;

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data);
    }

    fn finalize(&self) -> Self::Finalize {
        self.finalize()
    }

    fn reset(&mut self) {
        self.reset();
    }
}

impl Default for Update {
    fn default() -> Self {
        Self::new()
    }
}

/// A finalized hash state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finalize {
    state: State,
}

impl Finalize {
    /// Creates and returns the hash digest.
    #[must_use]
    #[rustfmt::skip]
    pub fn digest(&self) -> Digest {
        let State { a, b, c, d, e, f, g, h } = self.state;
        let [a, b, c, d, e, f, g, h] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
            f.to_be_bytes(),
            g.to_be_bytes(),
            h.to_be_bytes(),
        ];
        Digest::new([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
            f[0], f[1], f[2], f[3],
            g[0], g[1], g[2], g[3],
            h[0], h[1], h[2], h[3],
        ])
    }

    /// Resets the hash state to the in-progress state.
    #[must_use]
    pub fn reset(&self) -> Update {
        Update::new()
    }
}

impl core::Finalize for Finalize {
    type Digest = Digest;
    type Update = Update;

    fn digest(&self) -> Self::Digest {
        self.digest()
    }

    fn reset(&self) -> Self::Update {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let digest = default().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = new().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn reset() {
        let digest = new().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = new().update("data").finalize().reset().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hello_world() {
        let digest = new().update("Hello World").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        );

        let digest = new()
            .update("Hello")
            .update(" ")
            .update("World")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        );
    }

    #[test]
    fn rust_book() {
        let phrase = "Welcome to The Rust Programming Language, an introductory book about Rust. The Rust programming \
                      language helps you write faster, more reliable software. High-level ergonomics and low-level \
                      control are often at odds in programming language design; Rust challenges that conflict. \
                      Through balancing powerful technical capacity and a great developer experience, Rust gives you \
                      the option to control low-level details (such as memory usage) without all the hassle \
                      traditionally associated with such control.";

        let digest = hash(phrase).to_hex_lowercase();
        assert_eq!(
            digest,
            "b2de5395f39bf32376693a9cdccc13da1d705d0eb9e9ec8c566a91f604fcc942"
        );
    }

    #[test]
    fn zeroes() {
        let data = vec![0u8; 64];

        let digest = new().update(&data[..60]).digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "5dcc1b5872dd9ff1c234501f1fefda01f664164e1583c3e1bb3dbea47588ab31"
        );

        let digest = new()
            .update(&data[..60])
            .update(&data[60..])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        );
    }
}
