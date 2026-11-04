// WARC responses read as Common Crawl and browsers read them: which ones
// are HTML pages, and in which charset.
//
// Common Crawl detects the type of each response from its bytes, and writes
// it in the record's `WARC-Identified-Payload-Type` header. A response is
// an HTML page when that type or the HTTP `Content-Type` the server sent
// says so: the first catches pages a server labels wrong or not at all,
// the second pages a browser renders though what precedes their HTML (an
// XML declaration, `<?php` text) makes Common Crawl identify another type.
// Each page is then read in its charset, as a browser decides it: UTF-16
// pages give their favicons and onions, pages in legacy charsets their
// non-ASCII favicon URLs. These tests build Archives of such pages and read
// them on every Transport, with both onion engines.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;

use cc_extract::{
    ArtifactKind, Extractor, FaviconExtractor, Findings, Format, InlineFaviconExtractor,
    OnionEngine, OnionExtractor, Shard, parse_archive,
};
use common::{WarcBuilder, http_response, on_every_transport};

const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";
const DATE: &str = "2025-01-01T00:00:01Z";

/// SHA-256 of `hello`, the inline favicon of `FAVICON_PAGE`.
const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

/// An HTML page declaring the favicon `/i.png` and an inline favicon, the
/// bytes `hello` in base64.
const FAVICON_PAGE: &str = r#"<html><head>
<link rel="icon" href="/i.png">
<link rel="apple-touch-icon" href="data:image/png;base64,aGVsbG8=">
</head></html>"#;

/// What one Archive gives, for each Artifact kind: each Artifact with the
/// URLs of the Pages it was seen on.
#[derive(Debug, PartialEq, Eq, Default)]
struct Found {
    onions: BTreeMap<String, Vec<String>>,
    favicons: BTreeMap<String, Vec<String>>,
    inline_favicons: BTreeMap<String, Vec<String>>,
}

/// Parse the WARC `archive` with the three extractors, on every Transport
/// and with both onion engines; assert that all six runs agree, and return
/// what they found.
fn found_in(test_name: &str, archive: &[u8]) -> Found {
    let shard = Shard::from_archive_name(ARCHIVE_NAME);
    let mut runs = Vec::new();
    for engine in [OnionEngine::Memchr, OnionEngine::Regex] {
        for (transport_name, transport) in on_every_transport(test_name, ARCHIVE_NAME, archive) {
            let mut extractors: Vec<Box<dyn Extractor>> = vec![
                Box::new(OnionExtractor::new(engine)),
                Box::new(FaviconExtractor::new()),
                Box::new(InlineFaviconExtractor::new()),
            ];
            parse_archive(transport, Format::Warc, &shard, &mut extractors)
                .unwrap_or_else(|e| panic!("{transport_name}: parse failed: {e}"));
            let mut found = Found::default();
            for extractor in extractors {
                let kind = extractor.kind();
                match extractor.into_findings() {
                    Findings::Sightings(sightings) => {
                        let into = match kind {
                            ArtifactKind::Onion => &mut found.onions,
                            ArtifactKind::Favicon => &mut found.favicons,
                            ArtifactKind::InlineFavicon => unreachable!("{kind} finds images"),
                        };
                        *into = sightings
                            .into_iter()
                            .map(|(artifact, sightings)| {
                                let urls = sightings.into_iter().map(|s| s.page_url);
                                (artifact, urls.collect())
                            })
                            .collect();
                    }
                    Findings::InlineFavicons(favicons) => {
                        found.inline_favicons = favicons
                            .into_iter()
                            .map(|(sha256, favicon)| {
                                let urls = favicon.sightings.into_iter().map(|s| s.page_url);
                                (sha256, urls.collect())
                            })
                            .collect();
                    }
                }
            }
            runs.push((format!("{transport_name}/{engine:?}"), found));
        }
    }
    let (reference_name, reference) = runs.remove(0);
    for (name, found) in &runs {
        assert_eq!(found, &reference, "{name} differs from {reference_name}");
    }
    reference
}

/// `page_urls` as the list `Found` gives for an Artifact seen on them.
fn pages(page_urls: &[&str]) -> Vec<String> {
    page_urls.iter().map(|url| url.to_string()).collect()
}

#[test]
fn a_response_is_html_when_either_type_says_so() {
    // Each case: the `WARC-Identified-Payload-Type`, if any, the HTTP
    // `Content-Type` headers, and whether the page is read as HTML.
    let cases: [(Option<&str>, &[&str], bool); 13] = [
        // Identified as HTML: read, whatever the server sent.
        (Some("text/html"), &[], true),
        (Some("text/html"), &["charset=utf-8"], true),
        (Some("text/html"), &["text/plain"], true),
        (
            Some("application/xhtml+xml"),
            &["application/octet-stream", "text/html"],
            true,
        ),
        // Identified as another type, but sent as HTML: read.
        (Some("application/xml"), &["text/html; charset=utf-8"], true),
        (Some("text/x-php"), &["text/html"], true),
        (Some("text/plain"), &["application/xhtml+xml"], true),
        // Neither says HTML: not read.
        (Some("application/xml"), &[], false),
        (Some("text/plain"), &["text/plain"], false),
        (Some("application/octet-stream"), &["charset=utf-8"], false),
        // Not identified: the `Content-Type` decides.
        (None, &["text/html; charset=utf-8"], true),
        (None, &["application/xhtml+xml"], true),
        (None, &["text/plain"], false),
    ];

    let mut archive = WarcBuilder::new();
    let mut html_pages = Vec::new();
    for (i, (identified, content_types, is_html)) in cases.iter().enumerate() {
        let page_url = format!("https://example.net/{i}/");
        let warc_headers: Vec<(&str, &str)> = identified
            .iter()
            .map(|identified| ("WARC-Identified-Payload-Type", *identified))
            .collect();
        let http_headers: Vec<(&str, &str)> = content_types
            .iter()
            .map(|content_type| ("Content-Type", *content_type))
            .collect();
        archive = archive.response_with(
            &page_url,
            DATE,
            &warc_headers,
            &http_response(&http_headers, FAVICON_PAGE),
        );
        if *is_html {
            html_pages.push(page_url);
        }
    }

    let found = found_in(
        "a_response_is_html_when_either_type_says_so",
        &archive.finish(),
    );
    let html_pages: Vec<&str> = html_pages.iter().map(String::as_str).collect();
    assert_eq!(
        found.favicons,
        BTreeMap::from([("https://example.net/i.png".to_string(), pages(&html_pages))])
    );
    assert_eq!(
        found.inline_favicons,
        BTreeMap::from([(HELLO_SHA256.to_string(), pages(&html_pages))])
    );
}

/// An onion address, written in `ONION_PAGE`.
const ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

/// `FAVICON_PAGE` with `ONION` in its text.
fn onion_page() -> String {
    FAVICON_PAGE.replace(
        "</head>",
        &format!("</head><body><p>Mirror: {ONION}</p></body>"),
    )
}

/// `text` in UTF-16, little endian, without a byte-order mark.
fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `text` in UTF-16, big endian, without a byte-order mark.
fn utf16be(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

#[test]
fn a_utf16_page_gives_what_the_same_page_in_utf8_gives() {
    let page = onion_page();
    let little_endian_bom = [&[0xFF, 0xFE][..], &utf16le(&page)].concat();
    let big_endian_bom = [&[0xFE, 0xFF][..], &utf16be(&page)].concat();
    let xml_page = format!(r#"<?xml version="1.0"?>{page}"#);
    // Each case: the page URL, its `Content-Type` and its body.
    let cases: [(&str, &str, Vec<u8>); 9] = [
        (
            "https://example.net/utf-8/",
            "text/html",
            page.clone().into_bytes(),
        ),
        // By byte-order mark, which wins over the HTTP charset.
        (
            "https://example.net/le-bom/",
            "text/html",
            little_endian_bom.clone(),
        ),
        ("https://example.net/be-bom/", "text/html", big_endian_bom),
        (
            "https://example.net/bom-over-http/",
            "text/html; charset=utf-8",
            little_endian_bom,
        ),
        // By HTTP charset; `utf-16` alone is little endian.
        (
            "https://example.net/le/",
            "text/html; charset=utf-16le",
            utf16le(&page),
        ),
        (
            "https://example.net/be/",
            "text/html; charset=UTF-16BE",
            utf16be(&page),
        ),
        (
            "https://example.net/utf-16/",
            "text/html; charset=\"utf-16\"",
            utf16le(&page),
        ),
        // Undeclared, but an XML declaration's first bytes, `<?x`, show the
        // byte order.
        (
            "https://example.net/xml-le/",
            "text/html",
            utf16le(&xml_page),
        ),
        (
            "https://example.net/xml-be/",
            "text/html",
            utf16be(&xml_page),
        ),
    ];

    let mut archive = WarcBuilder::new();
    for (page_url, content_type, body) in &cases {
        archive = archive.response(
            page_url,
            DATE,
            &http_response(&[("Content-Type", content_type)], body),
        );
    }
    let found = found_in(
        "a_utf16_page_gives_what_the_same_page_in_utf8_gives",
        &archive.finish(),
    );

    let every_page = pages(&cases.each_ref().map(|(page_url, _, _)| *page_url));
    assert_eq!(
        found,
        Found {
            onions: BTreeMap::from([(ONION.to_string(), every_page.clone())]),
            favicons: BTreeMap::from([(
                "https://example.net/i.png".to_string(),
                every_page.clone()
            )]),
            inline_favicons: BTreeMap::from([(HELLO_SHA256.to_string(), every_page)]),
        }
    );
}

/// An HTML page in any charset declaring the favicon `href`, given as
/// bytes in that charset, and the inline favicon of `FAVICON_PAGE`.
fn page_with_favicon(href: &[u8]) -> Vec<u8> {
    [
        &b"<html><head><link rel=\"icon\" href=\""[..],
        href,
        b"\"><link rel=\"icon\" href=\"data:image/png;base64,aGVsbG8=\"></head></html>",
    ]
    .concat()
}

#[test]
fn a_legacy_charset_page_gives_its_non_ascii_favicon_urls() {
    // `café`: `caf\xe9` in windows-1252; `日本`: `\x93\xfa\x96{` in
    // Shift_JIS, `\xe6\x97\xa5\xe6\x9c\xac` in UTF-8. A browser
    // percent-encodes the path from UTF-8, the query from the page's
    // charset, where `{` needs no escape.
    let cafe = "https://example.net/caf%C3%A9.png?q=caf%E9";
    let nihon = "https://example.net/%E6%97%A5%E6%9C%AC.png?q=%93%FA%96{";
    let cafe_in_utf8 = "https://example.net/caf%C3%A9.png?q=caf%C3%A9";
    // Each case: the page URL, its `Content-Type`, the favicon's `href` as
    // the page writes it, and the URL a browser requests.
    let cases: [(&str, &str, &[u8], &str); 5] = [
        // `ISO-8859-1` and `latin1` are labels of windows-1252.
        (
            "https://example.net/latin1/",
            "text/html; charset=ISO-8859-1",
            b"/caf\xe9.png?q=caf\xe9",
            cafe,
        ),
        (
            "https://example.net/shift_jis/",
            "text/html;charset=Shift_JIS",
            b"/\x93\xfa\x96{.png?q=\x93\xfa\x96{",
            nihon,
        ),
        // An entity is decoded once the charset made the value text.
        (
            "https://example.net/entity/",
            "text/html; charset=windows-1252",
            b"/caf&#233;.png?q=caf&#xE9;",
            cafe,
        ),
        // Undeclared: windows-1252 unless the page reads as UTF-8.
        (
            "https://example.net/undeclared-latin1/",
            "text/html",
            b"/caf\xe9.png?q=caf\xe9",
            cafe,
        ),
        (
            "https://example.net/undeclared-utf-8/",
            "text/html",
            "/café.png?q=café".as_bytes(),
            cafe_in_utf8,
        ),
    ];

    let mut archive = WarcBuilder::new();
    let mut expected: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (page_url, content_type, href, favicon) in cases {
        archive = archive.response(
            page_url,
            DATE,
            &http_response(&[("Content-Type", content_type)], &page_with_favicon(href)),
        );
        expected
            .entry(favicon.to_string())
            .or_default()
            .push(page_url.to_string());
    }
    let found = found_in(
        "a_legacy_charset_page_gives_its_non_ascii_favicon_urls",
        &archive.finish(),
    );

    assert_eq!(found.favicons, expected);
    let every_page = pages(&cases.map(|(page_url, ..)| page_url));
    assert_eq!(
        found.inline_favicons,
        BTreeMap::from([(HELLO_SHA256.to_string(), every_page)])
    );
}

#[test]
fn a_meta_tag_declares_the_page_charset() {
    // `мир` is `\xec\xe8\xf0` in windows-1251. `◆` is `\x1b$B"!\x1b(B` in
    // ISO-2022-JP: its bytes hold a `"`, so such a page must be decoded
    // before its markup is read.
    let cases: [(&str, Vec<u8>, &str); 2] = [
        (
            "https://example.net/windows-1251/",
            [
                &b"<meta charset=\"windows-1251\">"[..],
                &page_with_favicon(b"/\xec\xe8\xf0.png?q=\xec\xe8\xf0"),
            ]
            .concat(),
            "https://example.net/%D0%BC%D0%B8%D1%80.png?q=%EC%E8%F0",
        ),
        (
            "https://example.net/iso-2022-jp/",
            [
                &b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-2022-JP\">"[..],
                &page_with_favicon(b"/\x1b$B\"!\x1b(B.png?q=\x1b$B\"!\x1b(B"),
            ]
            .concat(),
            "https://example.net/%E2%97%86.png?q=%1B$B%22!%1B(B",
        ),
    ];

    let mut archive = WarcBuilder::new();
    for (page_url, body, _) in &cases {
        archive = archive.response(
            page_url,
            DATE,
            &http_response(&[("Content-Type", "text/html")], body),
        );
    }
    let found = found_in("a_meta_tag_declares_the_page_charset", &archive.finish());

    let expected = cases
        .iter()
        .map(|(page_url, _, favicon)| (favicon.to_string(), pages(&[page_url])))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(found.favicons, expected);
    let every_page = pages(&cases.each_ref().map(|(page_url, ..)| *page_url));
    assert_eq!(
        found.inline_favicons,
        BTreeMap::from([(HELLO_SHA256.to_string(), every_page)])
    );
}
