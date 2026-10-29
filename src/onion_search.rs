// Onion address search strategies — ripgrep-inspired optimization layers
//
// Two strategies for extracting .onion addresses from raw byte slices:
//
// 1. `search_regex_bytes` — uses `regex::bytes::Regex` to search &[u8] directly.
//    This is the same regex engine as before, but skips the UTF-8 conversion
//    (`String::from_utf8_lossy`) that allocated a new String for every record.
//    ripgrep uses `regex::bytes` exclusively — it never converts input to &str.
//
// 2. `search_memchr` — the core ripgrep technique: no regex at all.
//    Uses `memchr::memmem` (SIMD-accelerated) to jump to each `.o` and `.O`,
//    the start of ".onion" in any case, then validates surrounding bytes
//    with a hand-rolled checker.
//    This is dramatically faster because:
//    - memmem scans 16–32 bytes per CPU cycle using SIMD (SSE2/AVX2/NEON)
//    - `.o` and `.O` are uncommon in web content, and most of them (`.org`,
//      `.open`) fail the validator's first comparison
//    - No NFA/DFA state tracking — just literal comparison + byte checks
//
// Both functions keep only what `checked_address` accepts (a v3 address's
// checksum and version are verified there), return the addresses found
// lowercase, in order, duplicates included, and produce identical results.
// This lets you benchmark the technique itself in isolation. Recording
// *where* each address was seen is the caller's job
// (`extractor::OnionExtractor`).

use memchr::memmem;
use regex::bytes::Regex;
use sha3::{Digest, Sha3_256};

/// The .onion pattern: 16 (v2) or 56 (v3) base32 characters, then `.onion`,
/// all in any case.
///
/// `(?-u:\b)` is an ASCII word boundary: only `[0-9A-Za-z_]` count as word
/// characters, exactly like `is_word_boundary_byte` in the memchr engine.
/// A plain `\b` is Unicode-aware, so it treats `é` as a word character and
/// rejects `café3g2upl4pq6kufc4m.onion`, which the memchr engine accepts.
///
/// Every letter lists both cases (`[a-zA-Z2-7]`, `[oO]`) instead of using
/// the `(?i)` flag: `(?i)` together with a Unicode `\b` once made this
/// search over 1000x slower, and explicit classes stay plain ASCII, like
/// the memchr engine's byte checks.
pub const ONION_PATTERN: &str =
    r"(?-u:\b)([a-zA-Z2-7]{16}|[a-zA-Z2-7]{56})\.[oO][nN][iI][oO][nN](?-u:\b)";

// ---------------------------------------------------------------------------
// The check both strategies apply to every match
// ---------------------------------------------------------------------------

/// The suffix every address ends with, as it is returned: lowercase.
const SUFFIX: &[u8] = b".onion";

/// What a v3 checksum hashes in front of the public key and the version.
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// The version every 56-character (v3) address encodes.
const V3_VERSION: u8 = 3;

/// The address `matched` spells, lowercase, if it is a valid onion address;
/// `None` otherwise.
///
/// `matched` is what `ONION_PATTERN` matches: 16 or 56 base32 characters,
/// then `.onion`, in any case. It is valid if its label (the part before
/// `.onion`) has:
/// - 16 characters: a v2 address, which carries no checksum. Tor dropped v2
///   in 2021, so these are history, not live services.
/// - 56 characters: a v3 address. Its base32 decodes to 35 bytes,
///   `public key (32) || checksum (2) || version (1)`; the version must be
///   3, and the checksum the first 2 bytes of
///   `SHA3-256(".onion checksum" || public key || version)`.
///
/// Both strategies keep only what passes this check, and so does the
/// `baseline` example: they agree on which addresses count and on how they
/// are written, since the returned string becomes the Artifact's key.
///
/// The name follows `u32::checked_add` and friends: `checked_` says the
/// result is an `Option`, `None` instead of a wrong value.
pub fn checked_address(matched: &[u8]) -> Option<String> {
    let label_len = matched.len().checked_sub(SUFFIX.len())?;
    let (label, suffix) = matched.split_at(label_len);
    let valid = suffix.eq_ignore_ascii_case(SUFFIX)
        && match label.len() {
            16 => label.iter().all(|&c| base32_value(c).is_some()),
            56 => is_valid_v3(label),
            _ => false,
        };
    // A valid address is plain ASCII, so no byte is lost converting it.
    valid.then(|| String::from_utf8_lossy(matched).to_ascii_lowercase())
}

/// Whether a 56-character label encodes version 3 and a checksum matching
/// its public key.
fn is_valid_v3(label: &[u8]) -> bool {
    let Some(decoded) = decode_base32::<35>(label) else {
        return false;
    };
    let public_key = &decoded[..32];
    let checksum = &decoded[32..34];
    let version = decoded[34];
    if version != V3_VERSION {
        return false;
    }
    // `Digest` is the trait every RustCrypto hash implements (see
    // `inline_favicon::sha256_hex`); `chain_update` feeds the parts in
    // order without first copying them into one buffer.
    let digest = Sha3_256::new()
        .chain_update(CHECKSUM_PREFIX)
        .chain_update(public_key)
        .chain_update([version])
        .finalize();
    digest[..2] == *checksum
}

/// The value (0-31) of one base32 character, in either case. The alphabet
/// is RFC 4648's: `a` to `z` are 0-25, `2` to `7` are 26-31.
fn base32_value(c: u8) -> Option<u8> {
    match c.to_ascii_lowercase() {
        c @ b'a'..=b'z' => Some(c - b'a'),
        c @ b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Decode base32 text into exactly `N` bytes, or `None` if a character
/// isn't base32 or the text doesn't hold exactly `N` bytes (no padding).
///
/// Each character carries 5 bits; they queue up in `bits`, and every time
/// 8 are waiting, the oldest 8 go out as one byte. 56 characters are 280
/// bits: exactly 35 bytes.
///
/// `N` is a *const generic*: a value fixed at compile time rather than a
/// type, so the result is a plain array on the stack (`[u8; 35]`), with no
/// heap allocation.
fn decode_base32<const N: usize>(text: &[u8]) -> Option<[u8; N]> {
    if text.len() * 5 != N * 8 {
        return None;
    }
    let mut bytes = [0; N];
    let mut written = 0;
    // The bits decoded but not yet written out, in the low `pending` bits:
    // at most 7 left over plus 5 new ones, so a `u16` is enough.
    let mut bits: u16 = 0;
    let mut pending: u32 = 0;
    for &c in text {
        bits = (bits << 5) | u16::from(base32_value(c)?);
        pending += 5;
        if pending >= 8 {
            pending -= 8;
            bytes[written] = (bits >> pending) as u8;
            written += 1;
            bits &= (1 << pending) - 1;
        }
    }
    Some(bytes)
}

// ---------------------------------------------------------------------------
// Strategy A: regex::bytes — same regex, no UTF-8 conversion
// ---------------------------------------------------------------------------

/// Search a byte slice for .onion addresses using `regex::bytes::Regex`.
///
/// The `regex` crate has two modules most people don't know about:
/// - `regex::Regex` — searches `&str` (requires valid UTF-8)
/// - `regex::bytes::Regex` — searches `&[u8]` (arbitrary bytes)
///
/// ripgrep uses `regex::bytes` exclusively because real-world files contain
/// invalid UTF-8 (binary data, mixed encodings). By searching `&[u8]`
/// directly, we skip the `String::from_utf8_lossy()` allocation that
/// the baseline (`examples/baseline.rs`) makes for every record body.
pub fn search_regex_bytes(body: &[u8], onion_re: &Regex) -> Vec<String> {
    onion_re
        .find_iter(body)
        // Only the matched bytes (22 or 62 bytes) are converted to a String,
        // not the ENTIRE body (potentially hundreds of KB). `filter_map`
        // drops the matches `checked_address` turns down.
        .filter_map(|m| checked_address(m.as_bytes()))
        .collect()
}

// ---------------------------------------------------------------------------
// Strategy B: memchr — SIMD literal search + hand-rolled validation
// ---------------------------------------------------------------------------

/// Check if a byte is a valid character in an .onion address.
///
/// Onion addresses use base32 encoding: letters a-z plus digits 2-7, here
/// in either case. (Not 0-1, 8-9 — those aren't in the base32 alphabet.)
///
/// `#[inline(always)]` tells the compiler to inline this function at every
/// call site. For tiny predicate functions called in hot loops, this avoids
/// function-call overhead (push/pop registers, jump). The compiler can then
/// optimize the inlined code within the loop context — e.g., keeping the
/// byte in a register instead of passing it on the stack.
#[inline(always)]
fn is_onion_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'2'..=b'7')
}

/// Check if a byte represents a word boundary (not an alphanumeric or underscore).
///
/// This replicates the `\b` (word boundary) semantics from our regex pattern.
/// In regex, `\b` matches the position between a word character and a non-word
/// character. A word character is `[a-zA-Z0-9_]`.
///
/// We use this to verify that the .onion address isn't embedded inside a
/// longer word — e.g., "xxxx.onions" should NOT match because 's' follows.
#[inline(always)]
fn is_word_boundary_byte(b: u8) -> bool {
    !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
}

/// The searchers `search_memchr` jumps with: one `memmem::Finder` for `.o`,
/// one for `.O`.
///
/// ## Why two short needles
///
/// `memmem` compares bytes exactly, so one `.onion` needle misses `.ONION`
/// and `.Onion`. The `.` is the only byte the same in every spelling, but
/// web pages are full of them (URLs, sentences, CSS): one byte in 34 over
/// 1 GB of a real WARC Archive, and stopping at each one is slow. `.o` and
/// `.O` are rare enough for memmem to skip most of the body; the six bytes
/// from each are then compared to `.onion` with `eq_ignore_ascii_case`. Over
/// that same 1 GB, the two scans took half the time of one scan for all 32
/// spellings of `.onion` at once (Teddy, the SIMD multi-pattern search of
/// the `aho-corasick` crate), and a fifth of the time of stopping at each `.`.
///
/// Building a `Finder` analyses its needle; the caller builds one
/// `SuffixFinder` and reuses it for every record.
pub struct SuffixFinder {
    lower: memmem::Finder<'static>,
    upper: memmem::Finder<'static>,
}

impl SuffixFinder {
    pub fn new() -> Self {
        Self {
            lower: memmem::Finder::new(b".o"),
            upper: memmem::Finder::new(b".O"),
        }
    }

    /// Positions of every `.o` and `.O` in `body`, in increasing order.
    ///
    /// Each `Finder` yields its own positions in order, and the two are
    /// merged like the halves in merge sort: `peek` looks at the next
    /// position of each without taking it, and the smaller one is taken.
    /// A plain `chain` (every `.o`, then every `.O`) would return addresses
    /// out of the order they appear in, which the regex engine keeps.
    ///
    /// The returned iterator borrows both `self` and `body`: since edition
    /// 2024, `impl Trait` in return position captures every lifetime in
    /// scope without a `+ 'a` bound.
    fn candidates(&self, body: &[u8]) -> impl Iterator<Item = usize> {
        let mut lower = self.lower.find_iter(body).peekable();
        let mut upper = self.upper.find_iter(body).peekable();
        std::iter::from_fn(move || match (lower.peek(), upper.peek()) {
            (Some(l), Some(u)) if u < l => upper.next(),
            (Some(_), _) => lower.next(),
            (None, _) => upper.next(),
        })
    }
}

impl Default for SuffixFinder {
    fn default() -> Self {
        Self::new()
    }
}

/// Search a byte slice for .onion addresses using `memchr::memmem`.
///
/// ## The ripgrep algorithm, applied
///
/// ripgrep's key insight: most regex patterns contain literal substrings.
/// Before running the expensive regex engine, ripgrep uses SIMD-accelerated
/// literal search to find potential match positions, then validates only
/// those positions with the full pattern.
///
/// Our pattern ends in the literal ".onion", in any case. Instead of
/// running the regex on every byte of the body, we:
///
/// 1. Use `SuffixFinder` to jump directly to each `.o` or `.O`
///    (memmem scans 16-32 bytes per cycle via SIMD)
/// 2. At each hit, validate the surrounding bytes with simple comparisons
///
/// For a typical web page body (50-500 KB), ".onion" appears 0-2 times, and
/// the other `.o` (`.org`, `.open`) fail at their second letter. The
/// SIMD scan processes the entire body in microseconds, and the validator
/// only runs at those positions. Compare this to the regex engine which
/// must track NFA states for every byte.
pub fn search_memchr(body: &[u8], finder: &SuffixFinder) -> Vec<String> {
    let mut found = Vec::new();

    // Phase 1: SIMD scan — jump to each `.o` or `.O`.
    // `memmem::Finder` uses the Two-Way algorithm with SIMD acceleration.
    // On x86_64, it uses SSE2 (16 bytes/cycle) or AVX2 (32 bytes/cycle).
    // On ARM, it uses NEON. This is the same engine ripgrep uses.
    for dot_pos in finder.candidates(body) {
        // Phase 2: Validate the suffix — from the '.', the bytes must spell
        // ".onion" in any case. `get` returns `None` past the end of the body.
        let addr_end = dot_pos + SUFFIX.len();
        let is_suffix = body
            .get(dot_pos..addr_end)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(SUFFIX));
        if !is_suffix {
            continue;
        }

        // Phase 3: Validate backward — count consecutive onion chars before '.'
        //
        // We scan backward from the byte before '.' and count how many
        // consecutive [a-zA-Z2-7] characters there are. For a valid .onion
        // address, this count must be exactly 16 (v2) or 56 (v3).
        let mut prefix_len = 0;
        let prefix_start = dot_pos; // first byte to check is dot_pos - 1
        while prefix_len < prefix_start && is_onion_char(body[prefix_start - 1 - prefix_len]) {
            prefix_len += 1;
        }

        // Check if the prefix length matches v2 (16) or v3 (56).
        let valid_length = prefix_len == 16 || prefix_len == 56;

        // Phase 4: Validate boundaries — check word boundaries on both sides.
        //
        // The byte before the address (or start of input) must be a word boundary.
        // The byte after ".onion" (or end of input) must be a word boundary.
        let addr_start = prefix_start - prefix_len;

        let left_boundary = addr_start == 0 || is_word_boundary_byte(body[addr_start - 1]);
        let right_boundary = addr_end >= body.len() || is_word_boundary_byte(body[addr_end]);

        if valid_length && left_boundary && right_boundary {
            // Phase 5: Check and extract — only convert the matched bytes
            // to a String, once `checked_address` accepts them (a v3
            // checksum and version).
            //
            // We convert just the 22 bytes (v2) or 62 bytes (v3) of the
            // address, not the entire body. This is a tiny allocation
            // that only happens when we actually find an onion address.
            if let Some(address) = checked_address(&body[addr_start..addr_end]) {
                found.push(address);
            }
        }
    }

    found
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regex() -> Regex {
        Regex::new(ONION_PATTERN).unwrap()
    }

    fn make_finder() -> SuffixFinder {
        SuffixFinder::new()
    }

    /// Run both engines on `body`, assert they agree, return what they found.
    fn search_both(body: &[u8]) -> Vec<String> {
        let regex_found = search_regex_bytes(body, &make_regex());
        let memchr_found = search_memchr(body, &make_finder());
        assert_eq!(
            regex_found,
            memchr_found,
            "Strategies disagree on input: {:?}",
            String::from_utf8_lossy(body)
        );
        regex_found
    }

    // -- v2 (16-char) addresses --

    #[test]
    fn detects_v2_onion_address() {
        let found = search_both(b"visit http://abcdefghijklmnop.onion for info");
        assert_eq!(found, ["abcdefghijklmnop.onion"]);
    }

    // -- v3 (56-char) addresses --

    /// A valid v3 address built from a made-up public key: its first 51
    /// characters (255 of the key's 256 bits) spell the base32 alphabet,
    /// the last five hold the key's last bit, the checksum and version 3.
    const V3: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrsa3iad.onion";

    #[test]
    fn detects_v3_onion_address() {
        let found = search_both(format!("link: {V3} is here").as_bytes());
        assert_eq!(found, [V3]);
    }

    #[test]
    fn v3_address_with_wrong_checksum_is_rejected() {
        // V3 with its first character changed: the key no longer matches
        // the checksum.
        let found =
            search_both(b"link: bbcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrsa3iad.onion");
        assert!(found.is_empty());
    }

    #[test]
    fn v3_address_of_another_version_is_rejected() {
        // V3's key with version 4, and the checksum computed for version 4:
        // only the version is wrong.
        let found =
            search_both(b"link: abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrsie4ie.onion");
        assert!(found.is_empty());
    }

    // -- Case: any case is found, every address returned lowercase --

    #[test]
    fn uppercase_address_is_found_lowercase() {
        let found =
            search_both(b"see ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSA3IAD.ONION now");
        assert_eq!(found, [V3]);
    }

    #[test]
    fn mixed_case_address_is_found_lowercase() {
        let found =
            search_both(b"see AbCdEfGhIjKlMnOpQrStUvWxYz234567aBcDeFgHiJkLmNoPqRsA3iAd.onion now");
        assert_eq!(found, [V3]);
    }

    #[test]
    fn suffix_in_any_case_is_found() {
        let found = search_both(
            b"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrsa3iad.Onion, \
              abcdefghijklmnop.oNIoN",
        );
        assert_eq!(found, [V3, "abcdefghijklmnop.onion"]);
    }

    // -- Word boundary tests --

    #[test]
    fn no_match_when_no_word_boundary() {
        let found = search_both(b"visit abcdefghijklmnop.onions for info");
        assert!(found.is_empty(), "Should not match with trailing 's'");
    }

    #[test]
    fn no_match_with_wrong_prefix_length() {
        assert!(search_both(b"visit abcdefghij.onion for info").is_empty());
    }

    #[test]
    fn no_match_with_invalid_chars_in_prefix() {
        assert!(search_both(b"visit abcdefgh89klmnop.onion for info").is_empty());
    }

    #[test]
    fn non_ascii_letter_before_address_is_a_boundary() {
        // `é` is two bytes (0xC3 0xA9), neither an ASCII word character.
        let found = search_both("café3g2upl4pq6kufc4m.onion".as_bytes());
        assert_eq!(found, ["3g2upl4pq6kufc4m.onion"]);
    }

    // -- Multiple matches --

    #[test]
    fn addresses_in_any_case_come_out_in_page_order() {
        let found = search_both(
            b"qrstuvwxyzabcdef.ONION, then abcdefghijklmnop.onion, then qrstuvwxyzabcdef.Onion",
        );
        assert_eq!(
            found,
            [
                "qrstuvwxyzabcdef.onion",
                "abcdefghijklmnop.onion",
                "qrstuvwxyzabcdef.onion"
            ]
        );
    }

    #[test]
    fn finds_multiple_addresses() {
        let found =
            search_both(b"first: abcdefghijklmnop.onion second: qrstuvwxyzabcdef.onion done");
        assert_eq!(found, ["abcdefghijklmnop.onion", "qrstuvwxyzabcdef.onion"]);
    }

    #[test]
    fn repeated_address_is_returned_each_time() {
        let found = search_both(b"abcdefghijklmnop.onion and again abcdefghijklmnop.onion");
        assert_eq!(found, ["abcdefghijklmnop.onion", "abcdefghijklmnop.onion"]);
    }

    // -- Edge cases --

    #[test]
    fn address_at_start_of_input() {
        assert_eq!(
            search_both(b"abcdefghijklmnop.onion is at the start").len(),
            1
        );
    }

    #[test]
    fn address_at_end_of_input() {
        assert_eq!(search_both(b"ends with abcdefghijklmnop.onion").len(), 1);
    }

    #[test]
    fn no_false_positive_from_opinion() {
        assert!(search_both(b"in my opinion this is fine").is_empty());
    }

    #[test]
    fn empty_body() {
        assert!(search_both(b"").is_empty());
    }

    // -- Cross-validation: both strategies always agree --

    #[test]
    fn strategies_agree_on_mixed_content() {
        let inputs: Vec<&[u8]> = vec![
            b"nothing here",
            b"abcdefghijklmnop.onion",
            b"http://abcdefghijklmnop.onion/path?q=1",
            b"<a href=\"abcdefghijklmnop.onion\">link</a>",
            b"abcdefghijklmnop.onion and qrstuvwxyzabcdef.onion",
            b"not_an_onion: abcdefgh.onion (too short)",
            b"abcdefghijklmnop.onions (has trailing s)",
            b"\x00\xff binary abcdefghijklmnop.onion data \x80\x90",
            // Any case, in the key and in the suffix.
            b"ABCDEFGHIJKLMNOP.ONION and AbCdEfGhIjKlMnOp.oNiOn",
            b"ABCDEFGHIJKLMNOP.ONIONS (has trailing S)",
            b"ends in a cut suffix: abcdefghijklmnop.ONIO",
            b"example.org, example.Org, example.Onion.org, .o, .O, .",
            b"abcdefghijklmnop.onion.ONION",
            // v3 addresses that fail the check, in any case.
            b"BBCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSA3IAD.ONION",
            b"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        ];

        for input in inputs {
            search_both(input);
        }
    }
}
