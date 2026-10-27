// Inline favicons — images a page embeds as `data:` URIs
//
// The favicon scanner decodes them (`favicon_search::InlineImage`); this
// module decides how one is saved in `inline_favicons.json`: under the
// SHA-256 of its bytes, with Shodan's hash of it, its media type and the
// image itself in base64.
//
// ## Two hashes, two jobs
//
// The SHA-256 identifies the image: a cryptographic hash, so two different
// images never share one in practice, and a fixed standard that every tool
// computes the same way (`sha256sum`, Python's `hashlib`), in any year.
// Shodan's hash (`mmh3`) is only there to look the image up on Shodan: a
// 32-bit MurmurHash3, fast but easy to collide on purpose.
//
// ## Why not `std::hash::DefaultHasher`
//
// `DefaultHasher` is the hash `HashMap` uses, and its documentation leaves
// the algorithm unspecified on purpose. It is SipHash-1-3 today, but a
// later Rust release may change it, and a key saved in a file would then
// no longer match the one computed for the same image. Its 64 bits also
// make a collision as likely as not past about five billion distinct
// images (the birthday bound). A saved identifier needs a hash defined by
// a standard, not by a library version.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact::{ArtifactEntry, Sighting};
use crate::favicon_search::InlineImage;

// ---------------------------------------------------------------------------
// How an inline favicon is saved
// ---------------------------------------------------------------------------

/// One inline favicon, as `inline_favicons.json` saves it under the
/// SHA-256 of its bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineFavicon {
    /// Shodan's favicon hash of the image, to search Shodan with
    /// (`http.favicon.hash:<mmh3>`).
    pub mmh3: i32,
    /// The media type declared by the first page it was seen on.
    pub media_type: String,
    /// The image, in base64.
    pub data: String,
    /// The pages it was seen on.
    pub sightings: Vec<Sighting>,
}

/// The results of the `inline-favicon` kind: each image, keyed by the
/// SHA-256 of its bytes in hex.
pub type InlineFavicons = HashMap<String, InlineFavicon>;

impl InlineFavicon {
    /// `image`, not seen on any page yet.
    pub fn new(image: &InlineImage) -> Self {
        Self {
            mmh3: shodan_mmh3(&image.bytes),
            media_type: image.media_type.clone(),
            data: base64_encode(&image.bytes),
            sightings: Vec::new(),
        }
    }
}

impl ArtifactEntry for InlineFavicon {
    fn sightings_mut(&mut self) -> &mut Vec<Sighting> {
        &mut self.sightings
    }
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

/// The key an image is saved under in `InlineFavicons`: the SHA-256 of
/// its bytes, in lower-case hex.
///
/// ## The `Digest` trait
///
/// `sha2` is one of the RustCrypto hash crates (`sha1`, `sha3`, `blake2`,
/// ...), which all implement the `Digest` trait of the `digest` crate:
/// `Sha256::digest(bytes)` here would read `Sha3_256::digest(bytes)` with
/// `sha3`. Its result is a fixed-size array of 32 bytes; written in hex,
/// two digits per byte, it is the usual 64-character form.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(2 * digest.len());
    for byte in digest.iter() {
        // `fmt::Write` lets `write!` append to a `String`, which cannot
        // fail.
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Shodan's favicon hash of `bytes`, the number its `http.favicon.hash`
/// filter takes.
///
/// Shodan computes it in Python as `mmh3.hash(codecs.encode(data,
/// "base64"))`: MurmurHash3 (x86, 32 bits, seed 0) of the image's base64
/// *with its line breaks* (`base64_lines`), returned as a signed 32-bit
/// number. Any other base64 layout gives another hash.
fn shodan_mmh3(bytes: &[u8]) -> i32 {
    // `cast_signed` reads the same 32 bits as an `i32`, as Python's
    // `mmh3.hash` does: hashes from 2³¹ up come out negative.
    murmur3_x86_32(base64_lines(bytes).as_bytes(), 0).cast_signed()
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

/// The base64 encoding of `bytes` (RFC 4648: standard alphabet, `=`
/// padding), on one line.
///
/// Every group of 3 bytes (24 bits) becomes 4 characters of 6 bits each. A
/// last group of 1 or 2 bytes is completed with zero bits, and each missing
/// character is written `=`. Hand-written like the decoder in
/// `favicon_search`, rather than pulled in with the `base64` crate.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // `div_ceil` rounds up: a last, shorter group still takes 4 characters.
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        // The group's bytes side by side in one 24-bit number, first byte
        // highest; a missing byte stays zero.
        let mut bits: u32 = 0;
        for (i, &byte) in group.iter().enumerate() {
            bits |= u32::from(byte) << (16 - 8 * i);
        }
        // One character per 6 bits holding data: 2, 3 or 4 of them.
        for i in 0..=group.len() {
            let index = (bits >> (18 - 6 * i)) & 0x3f;
            encoded.push(char::from(ALPHABET[index as usize]));
        }
        for _ in group.len()..3 {
            encoded.push('=');
        }
    }
    encoded
}

/// `bytes` in base64 as Python's `codecs.encode(bytes, "base64")` writes
/// it: lines of 76 characters, each one ended by `\n`, the last included.
///
/// Python encodes 57 bytes per line. 57 is a multiple of 3, so only the
/// last line can hold padding, and cutting the one-line encoding every 76
/// characters gives the same lines.
fn base64_lines(bytes: &[u8]) -> String {
    let encoded = base64_encode(bytes);
    let mut lines = String::with_capacity(encoded.len() + encoded.len().div_ceil(76));
    // Base64 is ASCII: every byte is a whole character.
    for line in encoded.as_bytes().chunks(76) {
        lines.extend(line.iter().map(|&byte| char::from(byte)));
        lines.push('\n');
    }
    lines
}

// ---------------------------------------------------------------------------
// MurmurHash3
// ---------------------------------------------------------------------------

/// MurmurHash3, its 32-bit variant for x86 (`MurmurHash3_x86_32` in Austin
/// Appleby's reference code), of `data` with `seed`.
///
/// MurmurHash3 is fast but not cryptographic: anyone can build two inputs
/// with the same hash. That is fine for a search key, which is all Shodan
/// uses it for; the SHA-256 is what identifies an image here.
///
/// ## Wrapping arithmetic
///
/// The algorithm multiplies and adds modulo 2³², letting results overflow.
/// Rust's `*` and `+` panic on overflow in debug builds, so the code asks
/// for it explicitly: `wrapping_mul` and `wrapping_add` keep the low 32
/// bits, as C's unsigned arithmetic does. `rotate_left` is the circular
/// shift the reference writes `(x << r) | (x >> (32 - r))`.
fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    // Mixes one 4-byte block, or the tail, before it joins the hash.
    let scramble = |k: u32| k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);

    let mut hash = seed;
    // `chunks_exact` yields whole 4-byte blocks only; the 0 to 3 bytes left
    // over are its `remainder`. `&mut blocks` iterates without consuming
    // `blocks`, so the remainder can still be asked for after the loop.
    let mut blocks = data.chunks_exact(4);
    for block in &mut blocks {
        // Little-endian, as the reference reads a block on x86.
        let k = u32::from_le_bytes(block.try_into().expect("a block is 4 bytes"));
        hash ^= scramble(k);
        hash = hash
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64);
    }

    let tail = blocks.remainder();
    if !tail.is_empty() {
        let mut k: u32 = 0;
        for (i, &byte) in tail.iter().enumerate() {
            k |= u32::from(byte) << (8 * i);
        }
        hash ^= scramble(k);
    }

    // Finalization (`fmix32`): fold in the length, then let every input bit
    // affect every output bit. The reference's length is a 32-bit `int`
    // too.
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^= hash >> 16;
    hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_matches_rfc_4648() {
        // The test vectors of RFC 4648, section 10.
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in vectors {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
        }
    }

    #[test]
    fn base64_lines_wrap_like_python() {
        // Python's `codecs.encode(bytes(range(60)), "base64")`.
        let python =
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\nOTo7\n";
        let bytes: Vec<u8> = (0..60).collect();
        assert_eq!(base64_lines(&bytes), python);
        // No line at all, not even a lone newline.
        assert_eq!(base64_lines(b""), "");
    }

    #[test]
    fn murmur3_matches_reference_vectors() {
        // Published test vectors of the reference MurmurHash3_x86_32: the
        // empty input, a tail of 1 to 3 bytes, one and several blocks.
        let vectors: [(&str, u32, u32); 8] = [
            ("", 0, 0x0000_0000),
            ("", 1, 0x514E_28B7),
            ("a", 0x9747_B28C, 0x7FA0_9EA6),
            ("ab", 0x9747_B28C, 0x7487_5592),
            ("abc", 0x9747_B28C, 0xC84A_62DD),
            ("abcd", 0x9747_B28C, 0xF047_8627),
            ("Hello, world!", 0x9747_B28C, 0x2488_4CBA),
            (
                "The quick brown fox jumps over the lazy dog",
                0x9747_B28C,
                0x2FA8_26CD,
            ),
        ];
        for (input, seed, expected) in vectors {
            assert_eq!(
                murmur3_x86_32(input.as_bytes(), seed),
                expected,
                "{input:?} with seed {seed:#x}"
            );
        }
    }

    #[test]
    fn murmur3_read_as_signed_matches_python_mmh3() {
        // `mmh3.hash("foo")`, from the README of Python's `mmh3`.
        assert_eq!(murmur3_x86_32(b"foo", 0).cast_signed(), -156_908_512);
    }

    #[test]
    fn shodan_mmh3_hashes_python_style_base64() {
        // Python: `mmh3.hash(codecs.encode(bytes(range(60)), "base64"))`.
        let bytes: Vec<u8> = (0..60).collect();
        assert_eq!(shodan_mmh3(&bytes), -609_915_622);
    }

    #[test]
    fn sha256_hex_matches_fips_180_2() {
        // The "abc" example of FIPS 180-2, appendix B.1.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
