// Tests for reading WET Archives.
//
// A WET Archive holds one `warcinfo` record, then one `conversion` record
// per HTML page: the page's visible text, as `text/plain`. Each
// `conversion` record's `WARC-Target-URI` is the page URL and its
// `WARC-Date` the crawl time. WET alone misses most onions (they sit in
// HTTP headers and attribute values, which WET drops), so no Plan reads
// WET by itself; these tests parse a WET Archive directly through
// `parse_archive`.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;

use cc_extract::{Format, OnionEngine, Shard, Sighting, Transport};
use common::{
    Snapshot, WarcBuilder, assert_all_agree, parse, parse_with_every_combination, write_archive,
};

/// File name of the fixture Archive.
const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wet.gz";

/// The fixture's Shard. Every Sighting records it.
fn shard() -> Shard {
    Shard::from_archive_name(ARCHIVE_NAME)
}

/// v3, twice in page A's text.
const TEXT_V3: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
/// v2, in page B's text.
const TEXT_V2: &str = "3g2upl4pq6kufc4m.onion";
/// v2, only in the `warcinfo` record.
const WARCINFO_V2: &str = "expyuzz4wqqyqhjn.onion";

/// Page A: an onion written out in the page.
const PAGE_A: &str = "https://example.com/blog/post.html";
const DATE_A: &str = "2025-01-01T00:00:01Z";
/// Page B: an onion, and favicon markup shown as text.
const PAGE_B: &str = "https://example.org/howto.html";
const DATE_B: &str = "2025-01-01T00:00:02Z";

/// Build the fixture Archive: the `warcinfo` record, then one `conversion`
/// record per page.
fn fixture_archive() -> Vec<u8> {
    let text_a =
        format!("Post\nSearch privately at {TEXT_V3}.\nOr type {TEXT_V3} in Tor Browser.\n");
    let text_b = format!(
        "How to add a favicon\nWrite <link rel=\"icon\" href=\"/favicon.png\"> in the head.\nMirror: {TEXT_V2}\n"
    );

    WarcBuilder::new()
        .warcinfo(
            "2025-01-01T00:00:00Z",
            &format!("isPartOf: CC-MAIN-2025-01\r\ndescription: mirror at {WARCINFO_V2}\r\n"),
        )
        .conversion(PAGE_A, DATE_A, &text_a)
        .conversion(PAGE_B, DATE_B, &text_b)
        .finish()
}

/// What `parse_archive` extracts from `fixture_archive`.
fn expected_snapshot() -> Snapshot {
    let seen_on = |page_url: &str, date: &str| Sighting {
        page_url: page_url.to_string(),
        date: date.to_string(),
        shard: shard(),
    };

    Snapshot {
        // Not extracted: WARCINFO_V2, the `warcinfo` record is not a page.
        onions: BTreeMap::from([
            // Twice on page A but one Sighting per page.
            (TEXT_V3.to_string(), vec![seen_on(PAGE_A, DATE_A)]),
            (TEXT_V2.to_string(), vec![seen_on(PAGE_B, DATE_B)]),
        ]),
        // WET has no markup, only text: the `<link>` on page B is words on
        // the page, not a declared favicon.
        favicon_urls: BTreeMap::new(),
    }
}

#[test]
fn onions_in_visible_text_are_found() {
    let path = write_archive(
        "onions_in_visible_text_are_found",
        ARCHIVE_NAME,
        &fixture_archive(),
    );
    let snapshot = parse(
        Transport::Disk(path),
        Format::Wet,
        &shard(),
        OnionEngine::Memchr,
    );
    assert_eq!(snapshot, expected_snapshot());
}

#[test]
fn every_transport_and_engine_agrees_on_wet_fixture() {
    let path = write_archive(
        "every_transport_and_engine_agrees_on_wet_fixture",
        ARCHIVE_NAME,
        &fixture_archive(),
    );
    let results = parse_with_every_combination(&path);
    // Agreeing on nothing would pass too, so check the reference found the
    // fixture's onions.
    assert_eq!(results[0].1, expected_snapshot());
    assert_all_agree(&results);
}
