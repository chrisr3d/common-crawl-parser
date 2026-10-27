// Characterization tests for `parse_archive`.
//
// A characterization test pins what the code does *today*, right or wrong,
// so that a refactor can prove it changed behaviour only where intended.
// Issue 02 pinned the six `parse_warc*` functions this way; issue 03
// replaced them with one `parse_archive`, and the expected values below
// changed only where that issue said they would.
//
// The fixture is a hand-built Archive (see `fixture_archive`), small enough
// that every expected Artifact can be written out below.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;
use std::path::Path;

use cc_extract::{Format, OnionEngine, Shard, Sighting, Transport};
use common::{
    Snapshot, WarcBuilder, assert_all_agree, http_response, parse, parse_with_every_combination,
    write_archive,
};

/// File name of the fixture Archive.
const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// The fixture's Shard. Every Sighting records it.
fn shard() -> Shard {
    Shard::from_archive_name(ARCHIVE_NAME)
}

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
/// v2 in page B's body, directly after the non-ASCII letter `é` with no
/// space. `é`'s two UTF-8 bytes are not ASCII word characters, so both
/// engines must see a word boundary before the address.
const NON_ASCII_NEIGHBOUR_V2: &str = "msydqstlz2kzerdg.onion";

/// Page A: HTML with three favicon tags and most of the onions.
const PAGE_A: &str = "https://example.com/blog/post.html";
const DATE_A: &str = "2025-01-01T00:00:01Z";
/// Page B: HTML with an inline `data:` favicon only.
const PAGE_B: &str = "https://example.org/";
const DATE_B: &str = "2025-01-01T00:00:02Z";
/// Page C: plain text that merely *contains* favicon markup.
const PAGE_C: &str = "https://example.net/notes.txt";
const DATE_C: &str = "2025-01-01T00:00:03Z";

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
    // The `data:` URI holds the 8-byte PNG signature, base64-encoded.
    let page_b = format!(
        r#"<html><head>
<link rel="shortcut icon" href="data:image/png;base64,iVBORw0KGgo=">
</head><body>Mirror list: {BODY_V2}
<p>Notre café{NON_ASCII_NEIGHBOUR_V2}</p></body></html>"#
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

/// What `parse_archive` extracts from `fixture_archive`.
fn expected_snapshot() -> Snapshot {
    let seen_on = |page_url: &str, date: &str| Sighting {
        page_url: page_url.to_string(),
        date: date.to_string(),
        shard: shard(),
    };
    let on_a = || vec![seen_on(PAGE_A, DATE_A)];
    let on_b = || vec![seen_on(PAGE_B, DATE_B)];
    let on_c = || vec![seen_on(PAGE_C, DATE_C)];
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
            // ASCII word boundaries: `é` before the address is a boundary.
            (NON_ASCII_NEIGHBOUR_V2, on_b()),
            // Onion search ignores `Content-Type`.
            (PLAIN_TEXT_V3, on_c()),
        ]),
        // Only favicons a page declares: no root `/favicon.ico` guess
        // (ADR-0003). Nothing from page B: its inline `data:` favicon is
        // an `inline-favicon` Artifact, not a URL. Nothing from page C:
        // favicons are only searched in HTML responses.
        favicon_urls: string_keys(vec![
            // `relative.png` resolved against the page's directory.
            ("https://example.com/blog/relative.png", on_a()),
            ("https://example.com/apple-touch-icon.png", on_a()),
            ("https://cdn.example.com/tile.png", on_a()),
        ]),
    }
}

#[test]
fn fixture_yields_pinned_artifacts() {
    let path = write_archive(
        "fixture_yields_pinned_artifacts",
        ARCHIVE_NAME,
        &fixture_archive(),
    );
    let snapshot = parse(
        Transport::Disk(path),
        Format::Warc,
        &shard(),
        OnionEngine::Memchr,
    );
    assert_eq!(snapshot, expected_snapshot());
}

#[test]
fn every_transport_and_engine_agrees_on_fixture() {
    let path = write_archive(
        "every_transport_and_engine_agrees_on_fixture",
        ARCHIVE_NAME,
        &fixture_archive(),
    );
    assert_all_agree(&parse_with_every_combination(&path));
}

/// Environment variable naming a real downloaded `.warc.gz` Archive.
const REAL_ARCHIVE_VAR: &str = "REAL_WARC_ARCHIVE";

/// Cross-check every Transport and onion engine on a real Archive. No
/// pinned values: the fixture can't contain every oddity of the open web,
/// but a real Archive does, and all combinations must still agree on it.
///
/// `#[ignore]` keeps it out of a plain `cargo test`; run it with
///
/// ```text
/// REAL_WARC_ARCHIVE=download/CC-NEWS-...warc.gz cargo test --release -- --ignored --nocapture
/// ```
///
/// It parses the Archive six times, reads it fully into RAM for the
/// `Memory` Transport, and the `Mmap` Transport decompresses it to a `.warc`
/// file next to the Archive (several GB, removed afterwards).
#[test]
#[ignore = "slow: parses a real Archive six times; set REAL_WARC_ARCHIVE"]
fn every_transport_and_engine_agrees_on_real_archive() {
    // `var_os` returns `None` when unset, without failing on non-UTF-8 paths.
    let Some(path) = std::env::var_os(REAL_ARCHIVE_VAR) else {
        eprintln!("skipped: set {REAL_ARCHIVE_VAR} to a downloaded .warc.gz Archive");
        return;
    };
    assert_all_agree(&parse_with_every_combination(Path::new(&path)));
}
