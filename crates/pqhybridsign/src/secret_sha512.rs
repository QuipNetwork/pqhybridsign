//! SHA-512 buffering for secret input. The compression backend may use its own
//! temporaries; inspect it along with the final linked binary for each target.

use sha2::{compress512, digest::generic_array::GenericArray};
use zeroize::{Zeroize, ZeroizeOnDrop};

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretSha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    used: usize,
    len: u128,
}

impl SecretSha512 {
    pub(crate) fn new() -> Self {
        Self {
            state: IV,
            buffer: [0; 128],
            used: 0,
            len: 0,
        }
    }

    fn compress(&mut self) {
        compress512(
            &mut self.state,
            core::slice::from_ref(GenericArray::from_slice(&self.buffer)),
        );
        self.buffer.zeroize();
        self.used = 0;
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u128);
        while !input.is_empty() {
            let n = core::cmp::min(128 - self.used, input.len());
            self.buffer[self.used..self.used + n].copy_from_slice(&input[..n]);
            self.used += n;
            input = &input[n..];
            if self.used == 128 {
                self.compress();
            }
        }
    }

    pub(crate) fn finalize_into(&mut self, out: &mut [u8; 64]) {
        let bits = self.len.wrapping_mul(8);
        self.buffer[self.used] = 0x80;
        self.used += 1;
        if self.used > 112 {
            self.compress();
        }
        self.buffer[112..].copy_from_slice(&bits.to_be_bytes());
        self.compress();
        for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha512};

    #[test]
    fn matches_sha512_at_block_and_padding_boundaries() {
        for len in [
            0, 1, 31, 64, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 1025,
        ] {
            let mut storage = [0u8; 1025];
            for (n, byte) in storage.iter_mut().enumerate() {
                *byte = n.wrapping_mul(37) as u8;
            }
            let data = &storage[..len];
            for chunk_size in [1, 17, 127, 128, 257] {
                let mut h = SecretSha512::new();
                for chunk in data.chunks(chunk_size) {
                    h.update(chunk);
                }
                let mut out = [0; 64];
                h.finalize_into(&mut out);
                assert_eq!(
                    &out[..],
                    &Sha512::digest(data)[..],
                    "len={len}, chunk={chunk_size}"
                );
                assert_eq!(h.buffer, [0; 128]);
                assert_eq!(h.state, [0; 8]);
            }
        }
    }
}
