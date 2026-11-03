// Records written otherwise than Common Crawl writes them, read the same on
// every Transport.
//
// Common Crawl ends every line of a record's headers with `\r\n`, writes
// them in ASCII, and follows each body with `\r\n\r\n`. A damaged or
// foreign Archive may not. The streaming parser (disk, memory) and the
// slice parser (mmap) then follow the same rules: header lines are bytes,
// whatever their encoding; a record starts at the first line beginning
// `WARC/` after the previous body; its headers end at the first line of
// only whitespace.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;

use cc_extract::{Format, OnionEngine, Shard};
use common::{gzip_member, http_response, on_every_transport, parse};

const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// The onion address every page of these tests holds.
const ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

/// A `response` record whose block is an HTML page holding `ONION`: its
/// `headers`, then a `Content-Length` and the blank line, each line ended
/// by `eol`, then the block and `\r\n\r\n`.
fn response(headers: &[&[u8]], eol: &[u8]) -> Vec<u8> {
    let block = http_response(&[("Content-Type", "text/html")], &format!("<p>{ONION}</p>"));
    let content_length = format!("Content-Length: {}", block.len());
    let mut record = Vec::new();
    for line in headers
        .iter()
        .copied()
        .chain([content_length.as_bytes(), b""])
    {
        record.extend_from_slice(line);
        record.extend_from_slice(eol);
    }
    record.extend(block);
    record.extend_from_slice(b"\r\n\r\n");
    record
}

/// The header lines of a `response` record for the page at `page_url`.
fn headers_for(page_url: &str) -> [Vec<u8>; 4] {
    [
        b"WARC/1.0".to_vec(),
        b"WARC-Type: response".to_vec(),
        b"WARC-Date: 2025-01-01T00:00:01Z".to_vec(),
        format!("WARC-Target-URI: {page_url}").into_bytes(),
    ]
}

/// A `response` record for the page at `page_url`, written as Common Crawl
/// writes one.
fn usual_response(page_url: &str) -> Vec<u8> {
    let headers = headers_for(page_url);
    response(&headers.each_ref().map(Vec::as_slice), b"\r\n")
}

/// Parse `bytes` as a WARC Archive on every Transport, and assert that
/// each sees `ONION` on the pages `page_urls`, in this order, and finds
/// nothing else.
fn assert_onion_seen_on(test_name: &str, bytes: &[u8], page_urls: &[&str]) {
    let shard = Shard::from_archive_name(ARCHIVE_NAME);
    let expected = BTreeMap::from([(
        ONION.to_string(),
        page_urls
            .iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>(),
    )]);
    for (transport_name, transport) in on_every_transport(test_name, ARCHIVE_NAME, bytes) {
        let snapshot = parse(transport, Format::Warc, &shard, OnionEngine::Memchr);
        let seen: BTreeMap<String, Vec<String>> = snapshot
            .onions
            .into_iter()
            .map(|(onion, sightings)| {
                let urls = sightings.into_iter().map(|s| s.page_url).collect();
                (onion, urls)
            })
            .collect();
        assert_eq!(seen, expected, "on {transport_name}");
        assert!(
            snapshot.favicon_urls.is_empty(),
            "on {transport_name}: {:?}",
            snapshot.favicon_urls
        );
    }
}

/// A header line of multi-byte characters is passed over: header names
/// are compared as bytes, never cutting a character in two.
#[test]
fn a_header_of_multibyte_characters_is_passed_over() {
    let headers = headers_for("https://example.com/");
    let mut lines = headers.each_ref().map(Vec::as_slice).to_vec();
    // `é` is two bytes: byte 10, the length of `WARC-Type:`, falls inside
    // the fourth.
    lines.push("X: ééééééé".as_bytes());
    let bytes = gzip_member(&response(&lines, b"\r\n"));

    assert_onion_seen_on(
        "a_header_of_multibyte_characters",
        &bytes,
        &["https://example.com/"],
    );
}

/// A header value that isn't UTF-8 is read as text all the same, each
/// byte that can't be read replaced by `�` (U+FFFD).
#[test]
fn a_header_value_not_in_utf8_is_read_with_replacements() {
    let lines: [&[u8]; 4] = [
        b"WARC/1.0",
        b"WARC-Type: response",
        b"WARC-Date: 2025-01-01T00:00:01Z",
        // `\xe9` is `é` in Latin-1, a byte UTF-8 never has on its own.
        b"WARC-Target-URI: https://example.com/caf\xe9",
    ];
    let bytes = gzip_member(&response(&lines, b"\r\n"));

    assert_onion_seen_on(
        "a_header_value_not_in_utf8",
        &bytes,
        &["https://example.com/caf\u{FFFD}"],
    );
}

/// Lines ended by a bare `\n`, the blank line ending the headers included,
/// are read as lines ended by `\r\n` are: so is the record after them.
#[test]
fn lines_ended_by_a_bare_newline_are_read() {
    let headers = headers_for("https://example.com/");
    let bare_newlines = response(&headers.each_ref().map(Vec::as_slice), b"\n");
    let bytes = [
        gzip_member(&bare_newlines),
        gzip_member(&usual_response("https://example.org/")),
    ]
    .concat();

    assert_onion_seen_on(
        "lines_ended_by_a_bare_newline",
        &bytes,
        &["https://example.com/", "https://example.org/"],
    );
}

/// A record starts at a line beginning `WARC/`, not at a `WARC/` inside a
/// line: such a line and those after it are passed over up to the next
/// record.
#[test]
fn warc_inside_a_line_starts_no_record() {
    let inside_a_line = [b"junk ".as_slice(), &usual_response("https://example.net/")].concat();
    let bytes = [
        usual_response("https://example.com/"),
        inside_a_line,
        usual_response("https://example.org/"),
    ]
    .map(|record| gzip_member(&record))
    .concat();

    assert_onion_seen_on(
        "warc_inside_a_line",
        &bytes,
        &["https://example.com/", "https://example.org/"],
    );
}

/// A record may follow the previous body at once, without the blank lines
/// Common Crawl writes between them: the next record is looked for from
/// the end of the body.
#[test]
fn a_record_right_after_the_previous_body_is_read() {
    let first = usual_response("https://example.com/");
    let without_blank_lines = first.strip_suffix(b"\r\n\r\n").unwrap();
    let bytes = [
        gzip_member(without_blank_lines),
        gzip_member(&usual_response("https://example.org/")),
    ]
    .concat();

    assert_onion_seen_on(
        "a_record_right_after_the_previous_body",
        &bytes,
        &["https://example.com/", "https://example.org/"],
    );
}
