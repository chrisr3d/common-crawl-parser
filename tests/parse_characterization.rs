// Characterization tests for the public parse functions in `src/lib.rs`.
//
// A characterization test pins what the code does *today*, right or wrong,
// so that a refactor can prove it changed behaviour only where intended.
// Issue 03 replaces the six `parse_warc*` functions with one
// `parse_archive`; these tests are the yardstick for that change.
//
// The fixture is a hand-built Archive (see `fixture_archive`), small enough
// that every expected Artifact can be written out below.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::{
    Sighting, Snapshot, WarcBuilder, assert_all_agree, http_response, parse_with_every_function,
    write_archive,
};
use onion_crawler::parse_warc_memchr;

/// File name of the fixture Archive. Every Sighting records it.
const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

// Onion addresses, each placed in the fixture to exercise one case.

/// v3 (56 chars), only in page A's `Onion-Location` HTTP header.
const HEADER_V3: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
/// v3, in page A's HTML body.
const BODY_V3: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
/// v2 (16 chars), twice in page A's body and once in page B's.
const BODY_V2: &str = "3g2upl4pq6kufc4m.onion";
/// v3 address in uppercase, in page A's body. The `.onion` suffix stays
/// lowercase so the memchr engine finds it and has to reject the address.
const UPPERCASE_V3: &str = "BBCNEWSD73HKZNO2INI43T4GBLXVYCYAC5AW4GNV7T2RCCIJH7745UQD.onion";
/// v2, only inside `request` and `metadata` records.
const NON_RESPONSE_V2: &str = "expyuzz4wqqyqhjn.onion";
/// v3, in page C, a `text/plain` response.
const PLAIN_TEXT_V3: &str = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion";

/// Page A: HTML with three favicon tags and most of the onions.
const PAGE_A: &str = "https://example.com/blog/post.html";
const DATE_A: &str = "2025-01-01T00:00:01Z";
/// Page B: HTML with an inline `data:` favicon.
const PAGE_B: &str = "https://example.org/";
const DATE_B: &str = "2025-01-01T00:00:02Z";
/// Page C: plain text that merely *contains* favicon markup.
const PAGE_C: &str = "https://example.net/notes.txt";
const DATE_C: &str = "2025-01-01T00:00:03Z";

/// The 8-byte PNG signature, base64-encoded as `iVBORw0KGgo=`.
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Build the fixture Archive: three pages, each preceded by its `request`
/// and followed by its `metadata` record, the way Common Crawl orders them.
fn fixture_archive() -> Vec<u8> {
    let page_a = format!(
        r#"<!DOCTYPE html>
<html><head>
<title>Post</title>
<link rel="icon" href="relative.png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="msapplication-TileImage" content="https://cdn.example.com/tile.png">
</head><body>
<p>Search privately at {BODY_V3}.</p>
<p>Old mirror: http://{BODY_V2}/ (also written {BODY_V2}).</p>
<p>News: {UPPERCASE_V3}</p>
</body></html>"#
    );
    let page_b = format!(
        r#"<html><head>
<link rel="shortcut icon" href="data:image/png;base64,iVBORw0KGgo=">
</head><body>Mirror list: {BODY_V2}</body></html>"#
    );
    let page_c = format!(
        r#"Paste this into your page: <link rel="icon" href="/not-a-favicon.png">
Contact: {PLAIN_TEXT_V3}
"#
    );

    WarcBuilder::new()
        .warcinfo(
            "2025-01-01T00:00:00Z",
            "isPartOf: CC-MAIN-2025-01\r\noperator: Common Crawl Admin\r\n",
        )
        .request(
            PAGE_A,
            DATE_A,
            &format!(
                "GET /blog/post.html HTTP/1.1\r\nHost: example.com\r\nReferer: http://{NON_RESPONSE_V2}/\r\n\r\n"
            ),
        )
        .response(
            PAGE_A,
            DATE_A,
            &http_response(
                &[
                    ("Content-Type", "text/html; charset=utf-8"),
                    (
                        "Onion-Location",
                        &format!("http://{HEADER_V3}/blog/post.html"),
                    ),
                ],
                &page_a,
            ),
        )
        .metadata(
            PAGE_A,
            DATE_A,
            &format!("fetchTimeMs: 120\r\nnote: {NON_RESPONSE_V2}\r\n"),
        )
        .request(
            PAGE_B,
            DATE_B,
            "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
        )
        .response(
            PAGE_B,
            DATE_B,
            &http_response(&[("Content-Type", "text/html")], &page_b),
        )
        .metadata(PAGE_B, DATE_B, "fetchTimeMs: 80\r\n")
        .request(
            PAGE_C,
            DATE_C,
            "GET /notes.txt HTTP/1.1\r\nHost: example.net\r\n\r\n",
        )
        .response(
            PAGE_C,
            DATE_C,
            &http_response(&[("Content-Type", "text/plain")], &page_c),
        )
        .metadata(PAGE_C, DATE_C, "fetchTimeMs: 95\r\n")
        .finish()
}

/// What the parse functions extract from `fixture_archive` today.
fn expected_snapshot() -> Snapshot {
    let on_a = || vec![Sighting::new(PAGE_A, DATE_A, ARCHIVE_NAME)];
    let on_b = || vec![Sighting::new(PAGE_B, DATE_B, ARCHIVE_NAME)];
    let on_c = || vec![Sighting::new(PAGE_C, DATE_C, ARCHIVE_NAME)];
    let string_keys = |pairs: Vec<(&str, Vec<Sighting>)>| {
        pairs
            .into_iter()
            .map(|(key, sightings)| (key.to_string(), sightings))
            .collect::<BTreeMap<_, _>>()
    };

    Snapshot {
        // Not extracted:
        // - UPPERCASE_V3: both onion engines match lowercase only.
        // - NON_RESPONSE_V2: only `response` records are searched.
        onions: string_keys(vec![
            // The whole HTTP response is searched, headers included.
            (HEADER_V3, on_a()),
            (BODY_V3, on_a()),
            // Twice on page A but one Sighting per page; then page B.
            (BODY_V2, [on_a(), on_b()].concat()),
            // Onion search ignores `Content-Type`.
            (PLAIN_TEXT_V3, on_c()),
        ]),
        // Nothing from page C: favicons are only searched in HTML responses.
        favicon_urls: string_keys(vec![
            // `relative.png` resolved against the page's directory.
            ("https://example.com/blog/relative.png", on_a()),
            ("https://example.com/apple-touch-icon.png", on_a()),
            ("https://cdn.example.com/tile.png", on_a()),
            // Root guess added for every HTML page (dropped in issue 03, ADR-0003).
            ("https://example.com/favicon.ico", on_a()),
            ("https://example.org/favicon.ico", on_b()),
        ]),
        inline_favicons: BTreeMap::from([(PNG_SIGNATURE.to_vec(), on_b())]),
    }
}

#[test]
fn fixture_yields_pinned_artifacts() {
    let path = write_archive(
        "fixture_yields_pinned_artifacts",
        ARCHIVE_NAME,
        &fixture_archive(),
    );
    let snapshot = Snapshot::from(parse_warc_memchr(&path).unwrap());
    assert_eq!(snapshot, expected_snapshot());
}

#[test]
fn every_parse_function_agrees_on_fixture() {
    let path = write_archive(
        "every_parse_function_agrees_on_fixture",
        ARCHIVE_NAME,
        &fixture_archive(),
    );
    assert_all_agree(&parse_with_every_function(&path));
}

/// Environment variable naming a real downloaded `.warc.gz` Archive.
const REAL_ARCHIVE_VAR: &str = "REAL_WARC_ARCHIVE";

/// Cross-check the parse functions on a real Archive. No pinned values:
/// the fixture can't contain every oddity of the open web, but a real
/// Archive does, and all six functions must still agree on it.
///
/// `#[ignore]` keeps it out of a plain `cargo test`; run it with
///
/// ```text
/// REAL_WARC_ARCHIVE=download/CC-NEWS-...warc.gz cargo test --release -- --ignored --nocapture
/// ```
///
/// It parses the Archive six times, reads it fully into RAM for the
/// in-memory variants, and the `mmap` strategy decompresses it to a `.warc`
/// file next to the Archive (several GB, removed afterwards).
#[test]
#[ignore = "slow: parses a real Archive six times; set REAL_WARC_ARCHIVE"]
fn every_parse_function_agrees_on_real_archive() {
    // `var_os` returns `None` when unset, without failing on non-UTF-8 paths.
    let Some(path) = std::env::var_os(REAL_ARCHIVE_VAR) else {
        eprintln!("skipped: set {REAL_ARCHIVE_VAR} to a downloaded .warc.gz Archive");
        return;
    };
    assert_all_agree(&parse_with_every_function(Path::new(&path)));
}
