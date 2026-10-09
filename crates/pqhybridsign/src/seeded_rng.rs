// SPDX-License-Identifier: AGPL-3.0-or-later
//! A deterministic RNG seeded from 32 bytes and expanded by SHA-512 over a
//! counter, shared by the components that need reproducible randomness.
//!
//! FN-DSA has no all-zero deterministic mode the way ML-DSA-44's `rnd`
//! does: its key generation and signing both draw an unbounded amount of
//! randomness from an RNG. schnorrkel draws its Schnorr nonce the same way.
//! Seeding this expander from a value derived from the secret key (see each
//! component's `sign_deterministic`) or, for `Falcon512::derive`, from the
//! HKDF-expanded component seed reproduces the same output for the same
//! input while keeping the seed itself secret.
//!
//! `rand_core::block::BlockRng` owns the output buffer and the read index.
//! It hands out whole `u32` words, so a draw that is not a multiple of four
//! bytes discards the rest of its last word. Every caller draws a multiple
//! of four: fn-dsa takes 40 bytes for a signature seed and 32 for a keygen
//! seed, schnorrkel takes 32 for a nonce witness. The unit tests pin those
//! widths against SHA-512 computed directly.

use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One SHA-512 digest as the sixteen little-endian words `BlockRng` reads.
///
/// `BlockRng` keeps its results buffer private, so this type carries the
/// drop-time wipe: when the `BlockRng` drops, so does this, and the words
/// it held, which seed a signature, are zeroed.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct Block([u32; 16]);

impl AsRef<[u32]> for Block {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl AsMut<[u32]> for Block {
    fn as_mut(&mut self) -> &mut [u32] {
        &mut self.0
    }
}

/// The block generator: `SHA-512(state || counter_be)` for each counter.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Sha512Counter {
    state: [u8; 32],
    counter: u64,
}

impl BlockRngCore for Sha512Counter {
    type Item = u32;
    type Results = Block;

    fn generate(&mut self, results: &mut Block) {
        let mut hasher = Sha512::new();
        hasher.update(self.state);
        hasher.update(self.counter.to_be_bytes());
        let mut digest = hasher.finalize();
        for (word, bytes) in results.0.iter_mut().zip(digest.as_chunks::<4>().0) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        digest.zeroize();
        self.counter += 1;
    }
}

impl CryptoRng for Sha512Counter {}

/// A deterministic RNG seeded from a 32-byte value.
///
/// Draw a multiple of four bytes per call. See the module documentation.
pub(crate) struct SeededRng(BlockRng<Sha512Counter>);

impl SeededRng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self(BlockRng::new(Sha512Counter {
            state: seed,
            counter: 0,
        }))
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for SeededRng {}

#[cfg(test)]
mod tests {
    use super::*;

    /// One SHA-512 digest of `seed || counter` as a big-endian `u64`, the
    /// block the expander hands out for that counter.
    fn block(seed: &[u8; 32], counter: u64) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let mut out = [0u8; 64];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// The stream is pinned because every FN-DSA key derived from a seed,
    /// every deterministic FN-DSA signature and every deterministic sr25519
    /// signature depends on it. The draw widths are the ones the callers
    /// use: fn-dsa takes 40 bytes for a signature seed and 32 for a keygen
    /// seed, schnorrkel takes 32 for a nonce witness.
    #[test]
    fn the_stream_is_sha512_over_the_seed_and_a_big_endian_counter() {
        let seed = [7u8; 32];
        let mut rng = SeededRng::new(seed);
        let mut first = [0u8; 40];
        let mut second = [0u8; 24];
        let mut third = [0u8; 64];
        rng.fill_bytes(&mut first);
        rng.fill_bytes(&mut second);
        rng.fill_bytes(&mut third);

        let expected = block(&seed, 0);
        assert_eq!(first, expected[..40]);
        assert_eq!(second, expected[40..]);
        assert_eq!(third, block(&seed, 1));
    }

    /// Two 32-byte draws, the schnorrkel width, read one block in order.
    #[test]
    fn two_thirty_two_byte_draws_read_one_block_in_order() {
        let seed = [9u8; 32];
        let mut rng = SeededRng::new(seed);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        let expected = block(&seed, 0);
        assert_eq!(a, expected[..32]);
        assert_eq!(b, expected[32..]);
    }

    #[test]
    fn different_seeds_give_different_streams() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        SeededRng::new([1u8; 32]).fill_bytes(&mut a);
        SeededRng::new([2u8; 32]).fill_bytes(&mut b);
        assert_ne!(a, b);
    }
}
