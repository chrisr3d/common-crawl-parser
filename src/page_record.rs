// Page records — one crawled page, as every extractor sees it
//
// The record parsers in `warc_parser` produce different types: the streaming
// parser owns its bytes (`WarcRecord`), the mmap parser borrows them from
// the mapped file (`WarcSlice`). `parse_archive` turns either into a
// `PageRecord` that *borrows* the same bytes, so extractors work on one
// type without anything being copied.
//
// One variant per Format. A WAT record is JSON: it is parsed here, once,
// into `WatMetadata`, and every extractor reads the parsed fields.

use std::borrow::Cow;
use std::sync::LazyLock;

use memchr::memmem;
use serde::Deserialize;

/// One crawled page read from an Archive.
///
/// ## Lifetimes: `PageRecord<'a>`
///
/// A `PageRecord` holds references (`&'a str`, `&'a [u8]`), not owned data.
/// The lifetime parameter `'a` names how long the borrowed bytes live, and
/// the compiler checks that no `PageRecord` outlives them. In the parsing
/// loop, `'a` is one iteration: the record borrows the current
/// `WarcRecord`'s buffers (or a region of the mmap) and is gone before the
/// next record is read.
///
/// ## Exhaustive `match`
///
/// Extractors `match` on the record's variant without a `_` catch-all arm.
/// When a variant is added, every such `match` stops compiling until it
/// says what to do with that Format's records, so no extractor can silently
/// ignore a new Format.
pub enum PageRecord<'a> {
    /// A WARC `response` record.
    Warc(WarcResponse<'a>),
    /// A WAT `metadata` record made from a WARC `response` record.
    Wat(WatMetadata<'a>),
    /// A WET `conversion` record.
    Wet(WetConversion<'a>),
}

impl<'a> PageRecord<'a> {
    /// URL of the crawled page.
    pub fn page_url(&self) -> &'a str {
        match self {
            PageRecord::Warc(response) => response.page_url,
            PageRecord::Wat(metadata) => metadata.page_url,
            PageRecord::Wet(conversion) => conversion.page_url,
        }
    }

    /// When the page was crawled.
    ///
    /// Borrowed from `self`, not for `'a` like `page_url`: a WAT date is a
    /// `Cow` that may own its string (see `WatMetadata`), and an owned
    /// string lives only as long as the record holding it.
    pub fn date(&self) -> &str {
        match self {
            PageRecord::Warc(response) => response.date,
            PageRecord::Wat(metadata) => &metadata.date,
            PageRecord::Wet(conversion) => conversion.date,
        }
    }
}

/// A WARC `response` record: page URL, crawl date and the full HTTP response.
pub struct WarcResponse<'a> {
    /// The `WARC-Target-URI` header.
    pub page_url: &'a str,
    /// The `WARC-Date` header.
    pub date: &'a str,
    /// The complete HTTP response: status line, headers, blank line, body.
    pub http_response: &'a [u8],
}

impl<'a> WarcResponse<'a> {
    /// The HTTP body, if the response declares an HTML `Content-Type`.
    ///
    /// `None` for other content types and for malformed responses with no
    /// blank line between headers and body.
    pub fn html_body(&self) -> Option<&'a [u8]> {
        let (http_headers, http_body) = split_http_response(self.http_response)?;
        is_html_content(http_headers).then_some(http_body)
    }
}

/// A WET `conversion` record: page URL, crawl date and the page's visible
/// text.
///
/// Common Crawl writes one per HTML page of the matching WARC Archive,
/// copying that response's `WARC-Target-URI` and `WARC-Date`, so both are
/// the page's, as in a `WarcResponse`.
pub struct WetConversion<'a> {
    /// The `WARC-Target-URI` header.
    pub page_url: &'a str,
    /// The `WARC-Date` header.
    pub date: &'a str,
    /// The text nodes of the HTML page, without markup, HTTP headers or
    /// attribute values. Bytes, like `WarcResponse::http_response`: the
    /// extractors search bytes.
    pub text: &'a [u8],
}

/// A WAT `metadata` record made from a WARC `response` record: page URL,
/// crawl date, the record's JSON, and the `<head>` tags ia-web-commons
/// parsed from the page.
pub struct WatMetadata<'a> {
    /// The `WARC-Target-URI` header, the same as the response's.
    pub page_url: &'a str,
    /// `Envelope.WARC-Header-Metadata.WARC-Date`, the response's own
    /// `WARC-Date`. The WAT record's `WARC-Date` is when the WAT was
    /// generated, not when the page was crawled.
    pub date: Cow<'a, str>,
    /// The whole JSON document, as bytes: onions are searched in it
    /// directly, wherever they sit (HTTP headers, link URLs and texts,
    /// `<meta>` contents).
    pub json: &'a [u8],
    /// `Envelope.Payload-Metadata.HTTP-Response-Metadata.HTML-Metadata.Head`;
    /// `None` when the response is not an HTML page.
    pub head: Option<Head<'a>>,
}

/// Finds `"WARC-Type":"response"`, which only the JSON of records made
/// from a `response` contains (Common Crawl writes it without whitespace).
///
/// ## `LazyLock`: a `static` built on first use
///
/// A `static` must be built at compile time, and `Finder::new` can't be
/// (it inspects the needle at runtime to choose a search algorithm).
/// `LazyLock` runs the closure the first time the value is used, then
/// keeps the result for the rest of the program; it is thread-safe, so
/// parse tasks on several threads share one `Finder`.
static RESPONSE_TYPE: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(br#""WARC-Type":"response""#));

impl<'a> WatMetadata<'a> {
    /// Read one WAT record's JSON. `None` when it was made from another
    /// WARC record type (a `request`, the WARC's own `metadata`) or is not
    /// valid JSON.
    ///
    /// Two thirds of a WAT's records are not made from a `response`; a
    /// SIMD search for `"WARC-Type":"response"` drops them without parsing
    /// their JSON. A record it does match is still checked once parsed, so
    /// the same text elsewhere in a record can't let it through.
    pub fn parse(page_url: &'a str, json: &'a [u8]) -> Option<Self> {
        RESPONSE_TYPE.find(json)?;
        let record: WatJson<'a> = serde_json::from_slice(json).ok()?;
        let envelope = record.envelope;
        if envelope.warc_header.warc_type != "response" {
            return None;
        }
        // Each level is optional: a non-HTML response has no
        // `HTML-Metadata`, an HTML page without `<head>` tags no `Head`.
        let head = envelope
            .payload
            .and_then(|payload| payload.http_response)
            .and_then(|response| response.html)
            .and_then(|html| html.head);
        Some(WatMetadata {
            page_url,
            date: envelope.warc_header.date,
            json,
            head,
        })
    }
}

// ---------------------------------------------------------------------------
// WAT JSON
// ---------------------------------------------------------------------------
//
// ## Partial deserialization
//
// A WAT record describing an HTML page is a few kilobytes of JSON, most of
// it the page's links (`HTML-Metadata.Links`). The structs below declare
// only the path down to `Head` and the fields read there. `serde` skips
// every key a struct doesn't declare: it still checks that the skipped
// value is valid JSON, but builds no value from it, so the large `Links`
// array costs a scan, not a `Vec` of links. (`#[serde(deny_unknown_fields)]`
// would turn the skipping into an error.)
//
// `#[serde(rename = "...")]` maps the JSON keys, such as
// `WARC-Header-Metadata`, which are not valid Rust names.
//
// ## Borrowing from the input: `&'a` and `Cow<'a, str>`
//
// `serde_json::from_slice` can hand out strings that point into the input
// bytes instead of copying them: the struct's lifetime `'a` ties it to
// those bytes, so it can't outlive the record. A JSON string with an
// escape (`\/`, `\u00e9`) is not stored as-is in the input, though, and
// has to be decoded into a new `String`. `Cow<'a, str>` (*clone on write*)
// holds either: `Cow::Borrowed(&'a str)` for the usual unescaped string,
// `Cow::Owned(String)` for an escaped one. A plain `&'a str` field would
// make the whole record fail to parse on the first escape.
//
// `#[serde(borrow)]` asks for the borrowing. Without it, `Cow` fields
// always deserialize as `Owned`; and on a struct field whose type has a
// lifetime (`Envelope<'a>`), it passes the borrow down.
//
// The borrowing only works on a `Cow<'a, str>` field itself, not inside an
// `Option`: `Option<Cow<'a, str>>` always allocates. Optional strings below
// are therefore plain `Cow`s with `#[serde(default)]`: a missing key reads
// as `""` (`Cow::default()`, an empty `String`, which allocates nothing),
// and an empty string never matches a favicon `rel`.

/// One WAT record: only `Envelope` is read.
#[derive(Deserialize)]
struct WatJson<'a> {
    #[serde(rename = "Envelope", borrow)]
    envelope: Envelope<'a>,
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "WARC-Header-Metadata", borrow)]
    warc_header: WarcHeaderMetadata<'a>,
    #[serde(rename = "Payload-Metadata", borrow)]
    payload: Option<PayloadMetadata<'a>>,
}

/// The WARC headers of the record the WAT record was made from.
#[derive(Deserialize)]
struct WarcHeaderMetadata<'a> {
    #[serde(rename = "WARC-Type", borrow)]
    warc_type: Cow<'a, str>,
    #[serde(rename = "WARC-Date", borrow)]
    date: Cow<'a, str>,
}

#[derive(Deserialize)]
struct PayloadMetadata<'a> {
    #[serde(rename = "HTTP-Response-Metadata", borrow)]
    http_response: Option<HttpResponseMetadata<'a>>,
}

#[derive(Deserialize)]
struct HttpResponseMetadata<'a> {
    #[serde(rename = "HTML-Metadata", borrow)]
    html: Option<HtmlMetadata<'a>>,
}

#[derive(Deserialize)]
struct HtmlMetadata<'a> {
    #[serde(rename = "Head", borrow)]
    head: Option<Head<'a>>,
}

/// The `<head>` of an HTML page, as ia-web-commons lists it in a WAT
/// record. Attribute names are lower-cased (`rel`, `url`), values are kept
/// as written in the page, so they must still be compared
/// case-insensitively.
#[derive(Deserialize)]
pub struct Head<'a> {
    /// `<base href>`, as written; `""` when the page has none.
    #[serde(rename = "Base", borrow, default)]
    pub base: Cow<'a, str>,
    /// The `<link>` tags.
    #[serde(rename = "Link", borrow, default)]
    pub links: Vec<Link<'a>>,
    /// The `<meta>` tags.
    #[serde(rename = "Metas", borrow, default)]
    pub metas: Vec<Meta<'a>>,
}

/// One `<link>` tag.
#[derive(Deserialize)]
pub struct Link<'a> {
    /// The `rel` attribute, such as `icon`; `""` when absent.
    #[serde(borrow, default)]
    pub rel: Cow<'a, str>,
    /// The `href` attribute, as written (often relative); `""` when absent.
    #[serde(borrow, default)]
    pub url: Cow<'a, str>,
}

/// One `<meta>` tag.
#[derive(Deserialize)]
pub struct Meta<'a> {
    /// The `name` attribute, such as `msapplication-TileImage`; `""` when
    /// absent (an `http-equiv` or `property` tag).
    #[serde(borrow, default)]
    pub name: Cow<'a, str>,
    /// The `content` attribute; `""` when absent.
    #[serde(borrow, default)]
    pub content: Cow<'a, str>,
}

// ---------------------------------------------------------------------------
// HTTP Response Helpers
// ---------------------------------------------------------------------------

/// Split a WARC response body into HTTP headers and HTTP body.
///
/// WARC "response" records contain the full HTTP response:
/// ```text
/// HTTP/1.1 200 OK\r\n
/// Content-Type: text/html\r\n
/// \r\n
/// <html>...</html>
/// ```
///
/// We need the HTTP body (the HTML) for favicon extraction, and the
/// HTTP headers to check Content-Type. Returns `None` if no `\r\n\r\n`
/// separator is found (malformed response).
fn split_http_response(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = memmem::find(data, b"\r\n\r\n")?;
    Some((&data[..separator], &data[separator + 4..]))
}

/// Check if HTTP headers indicate an HTML content type.
///
/// Looks for `Content-Type:` header containing `text/html` or `application/xhtml`.
/// Case-insensitive to handle the variety of web servers in the wild.
fn is_html_content(http_headers: &[u8]) -> bool {
    // Search for "content-type:" case-insensitively by scanning lines.
    for line in http_headers.split(|&b| b == b'\n') {
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.len() > 13 && trimmed[..13].eq_ignore_ascii_case(b"content-type:") {
            let value = &trimmed[13..];
            // Check for text/html or application/xhtml anywhere in the value
            // (it may include charset, e.g. "text/html; charset=utf-8").
            let lower: Vec<u8> = value.iter().map(|b| b.to_ascii_lowercase()).collect();
            // The window size comes from the needle itself: a hand-counted
            // `windows(16)` for the 17-byte "application/xhtml" never
            // matched, so XHTML pages were skipped.
            let contains = |needle: &[u8]| lower.windows(needle.len()).any(|w| w == needle);
            return contains(b"text/html") || contains(b"application/xhtml");
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `html_body()` of a response with this `Content-Type` and body `<p>`.
    fn html_body_for(content_type: &str) -> Option<Vec<u8>> {
        let http_response = format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n<p>");
        let response = WarcResponse {
            page_url: "https://example.com/",
            date: "2025-01-01T00:00:00Z",
            http_response: http_response.as_bytes(),
        };
        response.html_body().map(<[u8]>::to_vec)
    }

    #[test]
    fn html_and_xhtml_responses_have_an_html_body() {
        assert_eq!(
            html_body_for("text/html; charset=utf-8").as_deref(),
            Some(&b"<p>"[..])
        );
        assert_eq!(
            html_body_for("application/xhtml+xml").as_deref(),
            Some(&b"<p>"[..])
        );
    }

    #[test]
    fn other_responses_have_no_html_body() {
        assert_eq!(html_body_for("text/plain"), None);
    }
}
