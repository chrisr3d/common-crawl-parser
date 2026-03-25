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
//    Uses `memchr::memmem` (SIMD-accelerated) to find the literal ".onion",
//    then validates surrounding bytes with a hand-rolled checker.
//    This is dramatically faster because:
//    - memmem scans 16–32 bytes per CPU cycle using SIMD (SSE2/AVX2/NEON)
//    - ".onion" is rare in web content, so the validator rarely runs
//    - No NFA/DFA state tracking — just literal comparison + byte checks
//
// Both functions have the same signature and produce identical results.
// This lets you benchmark the technique itself in isolation.

use std::collections::HashSet;

use memchr::memmem;
use regex::bytes::Regex;

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
/// the baseline strategy makes for every record body.
pub fn search_regex_bytes(body: &[u8], onion_re: &Regex, results: &mut HashSet<String>) {
    for m in onion_re.find_iter(body) {
        // Only the matched bytes (22 or 62 bytes) are converted to a String.
        // Compare this to the baseline which converts the ENTIRE body
        // (potentially hundreds of KB) to a String via from_utf8_lossy.
        let matched = String::from_utf8_lossy(m.as_bytes()).to_lowercase();
        results.insert(matched);
    }
}

// ---------------------------------------------------------------------------
// Strategy B: memchr — SIMD literal search + hand-rolled validation
// ---------------------------------------------------------------------------

/// Check if a byte is a valid character in an .onion address.
///
/// Onion addresses use base32 encoding: lowercase letters a-z plus digits 2-7.
/// (Not 0-1, 8-9 — those aren't in the base32 alphabet.)
///
/// `#[inline(always)]` tells the compiler to inline this function at every
/// call site. For tiny predicate functions called in hot loops, this avoids
/// function-call overhead (push/pop registers, jump). The compiler can then
/// optimize the inlined code within the loop context — e.g., keeping the
/// byte in a register instead of passing it on the stack.
#[inline(always)]
fn is_onion_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'2'..=b'7')
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

/// Search a byte slice for .onion addresses using `memchr::memmem`.
///
/// ## The ripgrep algorithm, applied
///
/// ripgrep's key insight: most regex patterns contain literal substrings.
/// Before running the expensive regex engine, ripgrep uses SIMD-accelerated
/// literal search to find potential match positions, then validates only
/// those positions with the full pattern.
///
/// Our pattern `\b[a-z2-7]{16,56}\.onion\b` has the literal ".onion".
/// Instead of running the regex on every byte of the body, we:
///
/// 1. Use `memmem::Finder` to jump directly to each ".onion" occurrence
///    (scanning 16-32 bytes per cycle via SIMD)
/// 2. At each hit, validate the surrounding bytes with simple comparisons
///
/// For a typical web page body (50-500 KB), ".onion" appears 0-2 times.
/// The SIMD scan processes the entire body in microseconds, and the
/// validator only runs at those 0-2 positions. Compare this to the regex
/// engine which must track NFA states for every byte.
pub fn search_memchr(body: &[u8], finder: &memmem::Finder<'_>, results: &mut HashSet<String>) {
    let needle_len = 6; // ".onion".len()
    let mut search_start = 0;

    while search_start < body.len() {
        // Phase 1: SIMD scan — find the next ".onion" literal.
        // `memmem::Finder` uses the Two-Way algorithm with SIMD acceleration.
        // On x86_64, it uses SSE2 (16 bytes/cycle) or AVX2 (32 bytes/cycle).
        // On ARM, it uses NEON. This is the same engine ripgrep uses.
        let haystack = &body[search_start..];
        let Some(relative_pos) = finder.find(haystack) else {
            break; // No more ".onion" in the remaining data
        };
        let dot_pos = search_start + relative_pos; // absolute position of '.'

        // Phase 2: Validate backward — count consecutive onion chars before '.'
        //
        // We scan backward from the byte before '.' and count how many
        // consecutive [a-z2-7] characters there are. For a valid .onion
        // address, this count must be exactly 16 (v2) or 56 (v3).
        let mut prefix_len = 0;
        let prefix_start = dot_pos; // first byte to check is dot_pos - 1
        while prefix_len < prefix_start && is_onion_char(body[prefix_start - 1 - prefix_len]) {
            prefix_len += 1;
        }

        // Check if the prefix length matches v2 (16) or v3 (56).
        let valid_length = prefix_len == 16 || prefix_len == 56;

        // Phase 3: Validate boundaries — check word boundaries on both sides.
        //
        // The byte before the address (or start of input) must be a word boundary.
        // The byte after ".onion" (or end of input) must be a word boundary.
        let addr_start = prefix_start - prefix_len;
        let addr_end = dot_pos + needle_len;

        let left_boundary = addr_start == 0 || is_word_boundary_byte(body[addr_start - 1]);
        let right_boundary = addr_end >= body.len() || is_word_boundary_byte(body[addr_end]);

        if valid_length && left_boundary && right_boundary {
            // Phase 4: Extract — only convert the matched bytes to a String.
            //
            // We convert just the 22 bytes (v2) or 62 bytes (v3) of the
            // address, not the entire body. This is a tiny allocation
            // that only happens when we actually find an onion address.
            let address_bytes = &body[addr_start..addr_end];
            // Since we validated that prefix chars are [a-z2-7] and suffix is
            // ".onion", we know this is valid ASCII — from_utf8 won't fail.
            // We still lowercase for consistency (the prefix is already lowercase,
            // but being explicit about it is clearer).
            if let Ok(s) = std::str::from_utf8(address_bytes) {
                results.insert(s.to_lowercase());
            }
        }

        // Advance past this ".onion" to find the next one.
        search_start = dot_pos + needle_len;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regex() -> Regex {
        Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b").unwrap()
    }

    fn make_finder() -> memmem::Finder<'static> {
        memmem::Finder::new(b".onion")
    }

    // -- v2 (16-char) addresses --

    #[test]
    fn detects_v2_onion_address() {
        let body = b"visit http://abcdefghijklmnop.onion for info";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert_eq!(regex_results, memchr_results);
        assert!(regex_results.contains("abcdefghijklmnop.onion"));
    }

    // -- v3 (56-char) addresses --

    #[test]
    fn detects_v3_onion_address() {
        // 56 chars of [a-z2-7]
        let v3 = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";
        assert_eq!(v3.len(), 56);
        let body = format!("link: {}.onion is here", v3);
        let body = body.as_bytes();

        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert_eq!(regex_results, memchr_results);
        assert_eq!(regex_results.len(), 1);
    }

    // -- Word boundary tests --

    #[test]
    fn no_match_when_no_word_boundary() {
        // ".onion" embedded in a longer word — right boundary fails
        let body = b"visit abcdefghijklmnop.onions for info";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert!(regex_results.is_empty(), "Should not match with trailing 's'");
        assert_eq!(regex_results, memchr_results);
    }

    #[test]
    fn no_match_with_wrong_prefix_length() {
        // Only 10 chars before .onion — not 16 or 56
        let body = b"visit abcdefghij.onion for info";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert!(regex_results.is_empty());
        assert_eq!(regex_results, memchr_results);
    }

    #[test]
    fn no_match_with_invalid_chars_in_prefix() {
        // Has '8' and '9' which are not in [a-z2-7]
        let body = b"visit abcdefgh89klmnop.onion for info";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert!(regex_results.is_empty());
        assert_eq!(regex_results, memchr_results);
    }

    // -- Multiple matches --

    #[test]
    fn finds_multiple_addresses() {
        let body = b"first: abcdefghijklmnop.onion second: qrstuvwxyzabcdef.onion done";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert_eq!(regex_results.len(), 2);
        assert_eq!(regex_results, memchr_results);
    }

    // -- Edge cases --

    #[test]
    fn address_at_start_of_input() {
        let body = b"abcdefghijklmnop.onion is at the start";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert_eq!(regex_results.len(), 1);
        assert_eq!(regex_results, memchr_results);
    }

    #[test]
    fn address_at_end_of_input() {
        let body = b"ends with abcdefghijklmnop.onion";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert_eq!(regex_results.len(), 1);
        assert_eq!(regex_results, memchr_results);
    }

    #[test]
    fn no_false_positive_from_opinion() {
        // "opinion" contains "onion" but not ".onion"
        let body = b"in my opinion this is fine";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert!(regex_results.is_empty());
        assert_eq!(regex_results, memchr_results);
    }

    #[test]
    fn empty_body() {
        let body = b"";
        let re = make_regex();
        let finder = make_finder();

        let mut regex_results = HashSet::new();
        let mut memchr_results = HashSet::new();
        search_regex_bytes(body, &re, &mut regex_results);
        search_memchr(body, &finder, &mut memchr_results);

        assert!(regex_results.is_empty());
        assert_eq!(regex_results, memchr_results);
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
        ];

        let re = make_regex();
        let finder = make_finder();

        for input in inputs {
            let mut regex_results = HashSet::new();
            let mut memchr_results = HashSet::new();
            search_regex_bytes(input, &re, &mut regex_results);
            search_memchr(input, &finder, &mut memchr_results);
            assert_eq!(regex_results, memchr_results,
                "Strategies disagree on input: {:?}", String::from_utf8_lossy(input));
        }
    }
}
