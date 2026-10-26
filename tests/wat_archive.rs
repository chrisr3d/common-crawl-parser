// Tests for reading WAT Archives.
//
// A WAT Archive holds one `warcinfo` record, then one `metadata` record per
// record of the matching WARC Archive: three per page (made from its
// `request`, `response` and `metadata` records). Each is a JSON document
// that ia-web-commons wrote about that WARC record: its WARC headers, its
// HTTP headers and, for an HTML page, the page's `<link>` and `<meta>` tags
// and its links. Only the records made from a `response` describe a page.
//
// The record's own `WARC-Date` is when the WAT was generated; the crawl
// date is inside the JSON (`Envelope.WARC-Header-Metadata.WARC-Date`). The
// fixtures use a later WAT date, so a Sighting dated with it is caught.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;

use cc_extract::{Format, OnionEngine, Shard, Sighting, Transport};
use common::{
    Snapshot, WarcBuilder, assert_all_agree, http_response, parse, parse_together,
    parse_with_every_combination, wat_json, wat_request_json, wat_response_json, write_archive,
    write_archives,
};
use serde_json::json;

/// File names of the fixture Shard's Archives, one per Format.
const WARC_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";
const WAT_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wat.gz";
const WET_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wet.gz";

/// The fixture's Shard. Every Sighting records it.
fn shard() -> Shard {
    Shard::from_archive_name(WAT_NAME)
}

/// When the WAT Archive was generated: the outer `WARC-Date` of its
/// records, days after the crawl.
const WAT_DATE: &str = "2025-01-09T00:00:00Z";

// Onion addresses, each placed where one Format keeps it.

/// v3, in page A's `Onion-Location` HTTP header: WAT `Headers`.
const HEADER_V3: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
/// v3, in page A's `<meta http-equiv="onion-location">`: WAT `Head.Metas`.
const META_V3: &str = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion";
/// v2, in the `href` of a link on page A: WAT `Links[].url`.
const HREF_V2: &str = "3g2upl4pq6kufc4m.onion";
/// v3, the text of a link on page A: WAT `Links[].text`, and WET.
const ANCHOR_V3: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
/// v2, in page A's text outside any link: WET only.
const TEXT_V2: &str = "msydqstlz2kzerdg.onion";
/// v2, only in page A's `request` record, which is not a page.
const REQUEST_V2: &str = "expyuzz4wqqyqhjn.onion";

/// Page A: most onions, a relative favicon and a tile image (its `name`
/// in lower case: values compare case-insensitively).
const PAGE_A: &str = "https://example.com/blog/post.html";
const DATE_A: &str = "2025-01-01T00:00:01Z";
/// Page B: an inline `data:` favicon and a protocol-relative one (its
/// `rel` capitalised).
const PAGE_B: &str = "https://example.org/";
const DATE_B: &str = "2025-01-01T00:00:02Z";
/// Page C, in the single-record WAT Archives of the last tests: deep
/// enough that a relative URL resolves differently against a `<base>`.
const PAGE_C: &str = "https://example.net/docs/page.html";
const DATE_C: &str = "2025-01-01T00:00:03Z";

/// The same two pages as a WARC, a WAT and a WET Archive, written the way
/// Common Crawl derives WAT and WET from WARC.
fn fixture_archives() -> Vec<(&'static str, Vec<u8>)> {
    let page_a_headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        (
            "Onion-Location",
            &format!("http://{HEADER_V3}/blog/post.html"),
        ),
    ];
    let page_a_html = format!(
        r#"<!DOCTYPE html>
<html><head>
<title>Post</title>
<link rel="icon" href="favicon.png">
<link rel="stylesheet" href="/style.css">
<meta name="msapplication-tileimage" content="/tile.png">
<meta http-equiv="onion-location" content="http://{META_V3}/">
</head><body>
<p>Mirror: <a href="http://{HREF_V2}/">our mirror</a>, or <a href="/tor">{ANCHOR_V3}</a>.</p>
<p>Chat at <b>{TEXT_V2}</b></p>
</body></html>"#
    );
    // What ia-web-commons keeps of page A: the `<head>` tags with their
    // attributes, every link with its text, but no other text.
    let page_a_html_metadata = json!({
        "Head": {
            "Title": "Post",
            "Link": [
                {"path": "LINK@/href", "url": "favicon.png", "rel": "icon"},
                {"path": "LINK@/href", "url": "/style.css", "rel": "stylesheet"},
            ],
            "Metas": [
                {"name": "msapplication-tileimage", "content": "/tile.png"},
                {"http-equiv": "onion-location", "content": format!("http://{META_V3}/")},
            ],
        },
        "Links": [
            {"path": "A@/href", "url": format!("http://{HREF_V2}/"), "text": "our mirror"},
            {"path": "A@/href", "url": "/tor", "text": ANCHOR_V3},
        ],
    });
    let page_a_text = format!("Post\nMirror: our mirror, or {ANCHOR_V3}.\nChat at {TEXT_V2}\n");
    let page_a_request_headers = [
        ("Host", "example.com"),
        ("Referer", &format!("http://{REQUEST_V2}/")),
    ];
    let page_a_request = format!(
        "GET /blog/post.html HTTP/1.1\r\nHost: example.com\r\nReferer: http://{REQUEST_V2}/\r\n\r\n"
    );

    let page_b_headers = [("Content-Type", "text/html")];
    let page_b_html = r#"<html><head>
<link rel="Shortcut Icon" href="data:image/png;base64,iVBORw0KGgo=">
<link rel="Apple-Touch-Icon" href="//cdn.example.org/touch.png">
</head><body><p>Hello</p></body></html>"#;
    // ia-web-commons cuts every `data:` URL after its first comma
    // (`trimDataUrl`): the inline image is gone.
    let page_b_html_metadata = json!({
        "Head": {
            "Link": [
                {"path": "LINK@/href", "url": "data:image/png;base64,", "rel": "Shortcut Icon"},
                {"path": "LINK@/href", "url": "//cdn.example.org/touch.png", "rel": "Apple-Touch-Icon"},
            ],
        },
        "Links": [],
    });

    let warcinfo = "isPartOf: CC-MAIN-2025-01\r\n";
    let crawler_notes = "fetchTimeMs: 12\r\n";

    let warc = WarcBuilder::new()
        .warcinfo("2025-01-01T00:00:00Z", warcinfo)
        .request(PAGE_A, DATE_A, &page_a_request)
        .response(
            PAGE_A,
            DATE_A,
            &http_response(&page_a_headers, &page_a_html),
        )
        .metadata(PAGE_A, DATE_A, crawler_notes)
        .response(PAGE_B, DATE_B, &http_response(&page_b_headers, page_b_html))
        .finish();

    let wat = WarcBuilder::new()
        .warcinfo(WAT_DATE, warcinfo)
        .wat_metadata(
            PAGE_A,
            WAT_DATE,
            &wat_request_json(PAGE_A, DATE_A, &page_a_request_headers),
        )
        .wat_metadata(
            PAGE_A,
            WAT_DATE,
            &wat_response_json(PAGE_A, DATE_A, &page_a_headers, Some(page_a_html_metadata)),
        )
        .wat_metadata(
            PAGE_A,
            WAT_DATE,
            &wat_json(
                "metadata",
                PAGE_A,
                DATE_A,
                json!({"Actual-Content-Type": "application/warc-fields"}),
            ),
        )
        .wat_metadata(
            PAGE_B,
            WAT_DATE,
            &wat_response_json(PAGE_B, DATE_B, &page_b_headers, Some(page_b_html_metadata)),
        )
        .finish();

    let wet = WarcBuilder::new()
        .warcinfo(WAT_DATE, warcinfo)
        .conversion(PAGE_A, DATE_A, &page_a_text)
        .conversion(PAGE_B, DATE_B, "Hello\n")
        .finish();

    vec![(WARC_NAME, warc), (WAT_NAME, wat), (WET_NAME, wet)]
}

/// What every page of the fixture holds, as found in its WARC Archive.
fn expected_snapshot() -> Snapshot {
    let on_a = || vec![seen_on(PAGE_A, DATE_A)];
    Snapshot {
        // Not extracted: REQUEST_V2, the `request` record is not a page.
        onions: BTreeMap::from([
            (HEADER_V3.to_string(), on_a()),
            (META_V3.to_string(), on_a()),
            (HREF_V2.to_string(), on_a()),
            (ANCHOR_V3.to_string(), on_a()),
            (TEXT_V2.to_string(), on_a()),
        ]),
        // Not extracted: page B's inline `data:` favicon (no Artifact kind
        // keeps it yet, and WAT has cut it anyway).
        favicon_urls: BTreeMap::from([
            ("https://example.com/blog/favicon.png".to_string(), on_a()),
            ("https://example.com/tile.png".to_string(), on_a()),
            (
                "https://cdn.example.org/touch.png".to_string(),
                vec![seen_on(PAGE_B, DATE_B)],
            ),
        ]),
    }
}

/// What the fixture's WAT Archive alone holds: everything but the onion
/// in plain text.
fn wat_alone_snapshot() -> Snapshot {
    let mut expected = expected_snapshot();
    expected.onions.remove(TEXT_V2);
    expected
}

/// A Sighting of the fixture's Shard.
fn seen_on(page_url: &str, date: &str) -> Sighting {
    Sighting {
        page_url: page_url.to_string(),
        date: date.to_string(),
        shard: shard(),
    }
}

/// ADR-0001: `onion` accepts WAT + WET instead of WARC, `favicon` WAT.
/// The Plan for both reads WAT and WET; the favicon extractor finds nothing
/// in WET, so handing it WET too changes nothing.
#[test]
fn wat_and_wet_together_find_what_warc_finds() {
    let [warc, wat, wet] = write_archives(
        "wat_and_wet_together_find_what_warc_finds",
        &fixture_archives(),
    )
    .try_into()
    .unwrap();

    let from_warc = parse(
        Transport::Disk(warc),
        Format::Warc,
        &shard(),
        OnionEngine::Memchr,
    );
    let from_wat_and_wet = parse_together(
        vec![
            (Transport::Disk(wat), Format::Wat),
            (Transport::Disk(wet), Format::Wet),
        ],
        &shard(),
        OnionEngine::Memchr,
    );

    assert_eq!(from_warc, expected_snapshot());
    assert_eq!(from_wat_and_wet, expected_snapshot());
}

/// What WAT keeps of a page: HTTP headers, `<head>` tags and links (URLs
/// and texts), not the rest of its text. That is why `onion` needs WET as
/// well.
#[test]
fn wat_alone_misses_only_onions_in_plain_text() {
    let [_, wat, _] = write_archives(
        "wat_alone_misses_only_onions_in_plain_text",
        &fixture_archives(),
    )
    .try_into()
    .unwrap();

    let from_wat = parse(
        Transport::Disk(wat),
        Format::Wat,
        &shard(),
        OnionEngine::Memchr,
    );

    assert_eq!(from_wat, wat_alone_snapshot());
}

#[test]
fn every_transport_and_engine_agrees_on_wat_fixture() {
    let [_, wat, _] = write_archives(
        "every_transport_and_engine_agrees_on_wat_fixture",
        &fixture_archives(),
    )
    .try_into()
    .unwrap();

    let results = parse_with_every_combination(&wat);
    // Agreeing on nothing would pass too, so check the reference found the
    // fixture's Artifacts.
    assert_eq!(results[0].1, wat_alone_snapshot());
    assert_all_agree(&results);
}

/// Parse a WAT Archive made of `records`, page C's WAT records' JSON.
fn parse_page_c(test_name: &str, records: &[&str]) -> Snapshot {
    let archive = records
        .iter()
        .fold(WarcBuilder::new(), |builder, json| {
            builder.wat_metadata(PAGE_C, WAT_DATE, json)
        })
        .finish();
    let path = write_archive(test_name, WAT_NAME, &archive);
    parse(
        Transport::Disk(path),
        Format::Wat,
        &shard(),
        OnionEngine::Memchr,
    )
}

/// Relative URLs resolve against `<base href>` when the page has one,
/// itself relative to the page here.
#[test]
fn favicons_resolve_against_the_head_base() {
    let json = wat_response_json(
        PAGE_C,
        DATE_C,
        &[("Content-Type", "text/html")],
        Some(json!({
            "Head": {
                "Base": "/static/",
                "Link": [{"path": "LINK@/href", "url": "icons/fav.png", "rel": "icon"}],
            },
        })),
    );

    let snapshot = parse_page_c("favicons_resolve_against_the_head_base", &[&json]);

    assert_eq!(
        snapshot.favicon_urls,
        BTreeMap::from([(
            "https://example.net/static/icons/fav.png".to_string(),
            vec![seen_on(PAGE_C, DATE_C)]
        )])
    );
}

/// JSON may escape any `/` as `\/`. Such strings can't be borrowed from the
/// record and are decoded into new ones, but read the same.
#[test]
fn escaped_json_strings_are_read() {
    let json = wat_response_json(
        PAGE_C,
        DATE_C,
        &[
            ("Content-Type", "text/html"),
            (
                "Onion-Location",
                &format!("http://{HEADER_V3}/docs/page.html"),
            ),
        ],
        Some(json!({
            "Head": {"Link": [{"path": "LINK@/href", "url": "/icons/fav.png", "rel": "icon"}]},
        })),
    )
    .replace('/', "\\/");

    let snapshot = parse_page_c("escaped_json_strings_are_read", &[&json]);

    let on_c = || vec![seen_on(PAGE_C, DATE_C)];
    assert_eq!(
        snapshot,
        Snapshot {
            onions: BTreeMap::from([(HEADER_V3.to_string(), on_c())]),
            favicon_urls: BTreeMap::from([(
                "https://example.net/icons/fav.png".to_string(),
                on_c()
            )]),
        }
    );
}

/// A record whose JSON can't be read has no crawl date to give a
/// Sighting: it is skipped, and the records after it are still read.
#[test]
fn records_with_invalid_json_are_skipped() {
    let page_with = |onion: &str| {
        wat_response_json(
            PAGE_C,
            DATE_C,
            &[("Onion-Location", &format!("http://{onion}/"))],
            None,
        )
    };
    let broken = page_with(META_V3);
    // Without its last `}`, the JSON is cut short.
    let broken = &broken[..broken.len() - 1];

    let snapshot = parse_page_c(
        "records_with_invalid_json_are_skipped",
        &[broken, &page_with(HEADER_V3)],
    );

    assert_eq!(
        snapshot.onions,
        BTreeMap::from([(HEADER_V3.to_string(), vec![seen_on(PAGE_C, DATE_C)])])
    );
}
