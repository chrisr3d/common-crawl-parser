// Favicon extraction — fast byte-level scanning without an HTML parser
//
// Extracts favicon URLs and inline base64-encoded favicons from HTML content.
// Mirrors the logic of AIL Framework's `extract_favicon_from_html()` but
// uses `memchr::memmem` (SIMD) to locate `<link` and `<meta` tags, then
// hand-parses attributes from the tag bytes. No DOM tree, no allocations
// for non-matching tags.
//
// ## What we look for
//
// 1. `<link rel="icon" href="...">` — standard favicon
// 2. `<link rel="shortcut icon" href="...">` — legacy IE format
// 3. `<link rel="mask-icon" href="...">` — Safari pinned tabs
// 4. `<link rel="apple-touch-icon" href="...">` — iOS Safari
// 5. `<meta name="msapplication-TileImage" content="...">` — Edge/IE
// 6. Inline `data:` URIs in any of the above → decoded as base64 favicons
//
// Unlike AIL, we don't add a guessed `{scheme}://{domain}/favicon.ico` for
// every page: only favicons a page declares are recorded. A guessed URL
// was never checked to exist, and one per page would swell the results.
//
// Relative URLs resolve as a browser resolves them: against the page's
// first `<base href>`, itself resolved against the page URL, else against
// the page URL (the HTML standard's "document base URL").
//
// WAT records need no scanning: ia-web-commons has already listed the
// page's `<link>` and `<meta>` tags and its `<base href>`, and
// `favicons_in_head` applies the same `rel` and `name` rules to that list
// and resolves against that `<base href>` the same way.
//
// ## Why not use an HTML parsing crate?
//
// Full HTML parsers (`scraper`, `html5ever`, `kuchikiki`) build a DOM tree
// for every page — expensive when we only care about 1-2 tags. Real-world
// WARC bodies are often malformed (truncated, mixed encodings, embedded
// binary), which can cause parser panics or infinite loops. Byte scanning
// with memchr is robust against malformed input and processes non-matching
// pages in microseconds (just the SIMD scan, no allocations).

use std::borrow::Cow;
use std::cell::OnceCell;

use memchr::memmem;

use crate::page_record::Head;

/// A favicon reference found in an HTML page.
///
/// Each entry is either a URL pointing to the favicon, or inline base64
/// data (a `data:` URI that contains the favicon bytes directly).
#[derive(Debug, Clone)]
pub struct FaviconRef {
    /// The favicon URL (absolute or relative) or `data:` URI.
    pub url: String,
    /// If the href was a `data:` URI, this holds the decoded favicon bytes.
    /// `None` for regular URL references.
    pub inline_data: Option<Vec<u8>>,
}

/// A favicon embedded in the page as a base64 `data:` URI, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineImage {
    /// The media type the URI declares, without parameters and in lower
    /// case: `image/png` for `data:image/png;base64,...`. Empty if the URI
    /// declares none.
    pub media_type: String,
    /// The image itself.
    pub bytes: Vec<u8>,
}

/// Result of scanning one HTML page for favicon references.
#[derive(Debug, Default)]
pub struct FaviconResult {
    /// Favicon URLs found in `<link>` / `<meta>` tags (resolved to absolute).
    pub urls: Vec<String>,
    /// Inline favicons decoded from base64 `data:` URIs.
    pub inline_favicons: Vec<InlineImage>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Extract favicon references from an HTML byte slice.
///
/// `page_url` is the WARC-Target-URI of the page — used to resolve relative
/// favicon URLs into absolute ones, through the page's `<base href>` if it
/// has one.
///
/// ## How it works
///
/// We scan the body twice:
/// 1. For `<link ` tags — check if `rel=` matches a favicon-related value,
///    then extract the `href=` attribute.
/// 2. For `<meta ` tags — check if `name="msapplication-TileImage"`, then
///    extract the `content=` attribute.
///
/// Both scans use `memmem::Finder` (SIMD) to jump directly to candidate
/// tags, then parse only those few bytes. On a typical 100 KB page with
/// zero favicon tags, this completes in ~5 μs.
///
/// The `<base>` tag is only looked for once a favicon URL is found (see
/// `DocumentBase`): a page without favicons pays no third scan.
pub fn extract_favicons(body: &[u8], page_url: &str) -> FaviconResult {
    let mut result = FaviconResult::default();
    let base = DocumentBase::new(body, page_url);

    // --- Scan <link> tags for favicon rel values ---
    let link_finder = memmem::Finder::new(b"<link ");
    // Also catch uppercase/mixed case: <LINK, <Link, etc.
    // We do a case-insensitive scan by checking both finders.
    let link_finder_upper = memmem::Finder::new(b"<LINK ");

    scan_link_tags(body, &link_finder, &base, &mut result);
    scan_link_tags(body, &link_finder_upper, &base, &mut result);

    // --- Scan <meta> tags for msapplication-TileImage ---
    let meta_finder = memmem::Finder::new(b"<meta ");
    let meta_finder_upper = memmem::Finder::new(b"<META ");

    scan_meta_tags(body, &meta_finder, &base, &mut result);
    scan_meta_tags(body, &meta_finder_upper, &base, &mut result);

    result
}

/// The favicon URLs declared in a WAT record's `<head>`, resolved to
/// absolute URLs against the page's `<base href>` if it has one, else
/// against `page_url`.
///
/// The `<link>` tags whose `rel` is a favicon value give their `url`, the
/// `msapplication-TileImage` `<meta>` tags their `content`, as in the HTML
/// scanner. With several `<base>` tags, ia-web-commons probably keeps the
/// last one where the HTML scanner keeps the first; rare, and not copied
/// there. `data:` URLs are skipped: WAT cuts every one after its first comma
/// (`trimDataUrl` in ia-web-commons), so the inline image is gone, and the
/// stub left is no URL to fetch.
pub fn favicons_in_head(head: &Head<'_>, page_url: &str) -> Vec<String> {
    let base = document_base_url(page_url, &head.base);
    let link_urls = head
        .links
        .iter()
        .filter(|link| is_favicon_rel(link.rel.as_bytes()))
        .map(|link| &link.url);
    let meta_urls = head
        .metas
        .iter()
        .filter(|meta| is_tile_image_name(meta.name.as_bytes()))
        .map(|meta| &meta.content);

    let mut urls = Vec::new();
    for value in link_urls.chain(meta_urls) {
        let value = value.trim();
        if value.is_empty() || value.starts_with("data:") {
            continue;
        }
        push_resolved(&mut urls, &base, value);
    }
    urls
}

// ---------------------------------------------------------------------------
// Tag scanners
// ---------------------------------------------------------------------------

/// Favicon-related `rel` attribute values (case-insensitive).
///
/// These match what AIL Framework looks for in BeautifulSoup:
/// - `icon` — standard HTML5 favicon
/// - `shortcut icon` — legacy IE (technically "shortcut" is non-standard
///   but widely used and still present in the wild)
/// - `mask-icon` — Safari pinned tab SVG icons
/// - `apple-touch-icon` — iOS home screen icons
const FAVICON_REL_VALUES: &[&[u8]] =
    &[b"icon", b"shortcut icon", b"mask-icon", b"apple-touch-icon"];

/// Whether a `<link>`'s `rel` declares a favicon.
fn is_favicon_rel(rel: &[u8]) -> bool {
    FAVICON_REL_VALUES
        .iter()
        .any(|expected| rel.eq_ignore_ascii_case(expected))
}

/// Whether a `<meta>`'s `name` declares a Windows tile image.
fn is_tile_image_name(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"msapplication-TileImage")
}

/// Scan for `<link` tags with favicon rel values, extract their href.
fn scan_link_tags(
    body: &[u8],
    finder: &memmem::Finder<'_>,
    base: &DocumentBase<'_>,
    result: &mut FaviconResult,
) {
    let mut pos = 0;
    while pos < body.len() {
        let Some(offset) = finder.find(&body[pos..]) else {
            break;
        };
        let tag_start = pos + offset;

        // Find the end of this tag (closing `>`).
        let tag_end = match find_tag_end(body, tag_start) {
            Some(end) => end,
            None => break, // Truncated — no closing `>`
        };

        let tag_bytes = &body[tag_start..tag_end];

        // Check if `rel="..."` matches a favicon value.
        if let Some(rel_value) = extract_attribute(tag_bytes, b"rel")
            && is_favicon_rel(rel_value)
            && let Some(href) = extract_attribute(tag_bytes, b"href")
        {
            process_favicon_value(href, base, result);
        }

        pos = tag_end;
    }
}

/// Scan for `<meta name="msapplication-TileImage" content="...">` tags.
fn scan_meta_tags(
    body: &[u8],
    finder: &memmem::Finder<'_>,
    base: &DocumentBase<'_>,
    result: &mut FaviconResult,
) {
    let mut pos = 0;
    while pos < body.len() {
        let Some(offset) = finder.find(&body[pos..]) else {
            break;
        };
        let tag_start = pos + offset;

        let tag_end = match find_tag_end(body, tag_start) {
            Some(end) => end,
            None => break,
        };

        let tag_bytes = &body[tag_start..tag_end];

        // Check name="msapplication-TileImage"
        if let Some(name_value) = extract_attribute(tag_bytes, b"name")
            && is_tile_image_name(name_value)
            && let Some(content) = extract_attribute(tag_bytes, b"content")
        {
            process_favicon_value(content, base, result);
        }

        pos = tag_end;
    }
}

/// The `href` of the page's first `<base>` tag that has one.
///
/// Like `<link>` and `<meta>`, `<base>` is looked for in lower and upper
/// case. If a page has both, the one that comes first wins.
fn first_base_href(body: &[u8]) -> Option<&[u8]> {
    let lower = first_base_href_found_by(body, &memmem::Finder::new(b"<base "));
    let upper = first_base_href_found_by(body, &memmem::Finder::new(b"<BASE "));
    // Each is `Some((tag_start, href))` if found: keep the earlier one.
    [lower, upper]
        .into_iter()
        .flatten()
        .min_by_key(|&(tag_start, _)| tag_start)
        .map(|(_, href)| href)
}

/// The first `<base>` tag with an `href` that `finder` finds: where it
/// starts, and its `href`.
fn first_base_href_found_by<'a>(
    body: &'a [u8],
    finder: &memmem::Finder<'_>,
) -> Option<(usize, &'a [u8])> {
    let mut pos = 0;
    while pos < body.len() {
        let tag_start = pos + finder.find(&body[pos..])?;
        // `None` if truncated — no closing `>`
        let tag_end = find_tag_end(body, tag_start)?;

        // A `<base>` may only set a `target`: the next one may have an `href`.
        if let Some(href) = extract_attribute(&body[tag_start..tag_end], b"href") {
            return Some((tag_start, href));
        }

        pos = tag_end;
    }
    None
}

// ---------------------------------------------------------------------------
// Attribute extraction — hand-rolled, zero-allocation for non-matches
// ---------------------------------------------------------------------------

/// Find the closing `>` of an HTML tag, respecting quoted attribute values.
///
/// A naive search for `>` would break on attributes like `data-x="a>b"`.
/// We track whether we're inside single or double quotes to skip `>`
/// characters that appear inside attribute values.
fn find_tag_end(body: &[u8], tag_start: usize) -> Option<usize> {
    let mut i = tag_start;
    let mut in_double_quote = false;
    let mut in_single_quote = false;

    // Cap search at 4 KB from tag start — no real HTML tag is longer.
    // Prevents runaway scanning on malformed input.
    let limit = (tag_start + 4096).min(body.len());

    while i < limit {
        match body[i] {
            b'"' if !in_single_quote => in_double_quote = !in_double_quote,
            b'\'' if !in_double_quote => in_single_quote = !in_single_quote,
            b'>' if !in_double_quote && !in_single_quote => return Some(i + 1),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Extract the value of an HTML attribute from a tag's bytes.
///
/// Handles both quoted (`attr="value"`, `attr='value'`) and unquoted
/// (`attr=value`) forms. Case-insensitive attribute name matching.
///
/// Returns the raw bytes of the attribute value (without quotes).
/// Returns `None` if the attribute isn't present in the tag.
fn extract_attribute<'a>(tag: &'a [u8], attr_name: &[u8]) -> Option<&'a [u8]> {
    // Build the search pattern: attribute name followed by `=`.
    // We search case-insensitively by scanning for the `=` sign and
    // checking if the preceding bytes match the attribute name.
    let mut pos = 0;

    while pos + attr_name.len() < tag.len() {
        // Find the next `=` sign.
        let eq_pos = match memchr::memchr(b'=', &tag[pos..]) {
            Some(offset) => pos + offset,
            None => return None,
        };

        // Check if the bytes before `=` end with the attribute name.
        // There may be whitespace between the name and `=`.
        let before_eq = &tag[pos..eq_pos];
        let trimmed = trim_end_ascii(before_eq);

        if trimmed.len() >= attr_name.len() {
            let name_start = trimmed.len() - attr_name.len();
            let candidate = &trimmed[name_start..];

            // Verify the attribute name matches (case-insensitive) and
            // is preceded by whitespace or tag start (not part of another
            // attribute name like "data-href" matching "href").
            if candidate.eq_ignore_ascii_case(attr_name)
                && (name_start == 0 || trimmed[name_start - 1].is_ascii_whitespace())
            {
                // Extract the value after `=`.
                let value_start = eq_pos + 1;
                return extract_quoted_or_bare_value(tag, value_start);
            }
        }

        pos = eq_pos + 1;
    }

    None
}

/// Extract a value after an `=` sign — handles `"quoted"`, `'quoted'`,
/// and `bare` (terminated by whitespace or `>`).
fn extract_quoted_or_bare_value(tag: &[u8], start: usize) -> Option<&[u8]> {
    let mut i = start;

    // Skip whitespace after `=`.
    while i < tag.len() && tag[i].is_ascii_whitespace() {
        i += 1;
    }

    if i >= tag.len() {
        return None;
    }

    match tag[i] {
        // Quoted value — find matching closing quote.
        quote @ (b'"' | b'\'') => {
            let value_start = i + 1;
            let value_end = memchr::memchr(quote, &tag[value_start..])?;
            Some(&tag[value_start..value_start + value_end])
        }
        // Unquoted value — terminated by whitespace, `>`, or `/`.
        _ => {
            let value_start = i;
            let mut value_end = value_start;
            while value_end < tag.len()
                && !tag[value_end].is_ascii_whitespace()
                && tag[value_end] != b'>'
                && tag[value_end] != b'/'
            {
                value_end += 1;
            }
            if value_end > value_start {
                Some(&tag[value_start..value_end])
            } else {
                None
            }
        }
    }
}

/// Trim trailing ASCII whitespace from a byte slice.
fn trim_end_ascii(s: &[u8]) -> &[u8] {
    let end = s
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1);
    &s[..end]
}

// ---------------------------------------------------------------------------
// Favicon value processing — URL resolution and data: URI decoding
// ---------------------------------------------------------------------------

/// Process a favicon attribute value — either a URL or an inline `data:` URI.
///
/// As in AIL, a value is one of two kinds:
/// - `data:` URIs → decode the base64 payload, store as inline favicon
/// - Everything else → resolve to absolute URL against the page's base URL
///   (`DocumentBase`)
fn process_favicon_value(value: &[u8], base: &DocumentBase<'_>, result: &mut FaviconResult) {
    // Convert to string — favicon URLs should be valid UTF-8 (they're in
    // HTML attributes). If not, skip this value.
    let value_str = match std::str::from_utf8(value) {
        Ok(s) => s.trim(),
        Err(_) => return,
    };

    if value_str.is_empty() {
        return;
    }

    if let Some(data_uri) = value_str.strip_prefix("data:") {
        if let Some(image) = decode_inline_image(data_uri) {
            result.inline_favicons.push(image);
        }
    } else {
        // Regular URL — resolve relative to the page's base URL.
        push_resolved(&mut result.urls, base.url(), value_str);
    }
}

/// Decode what follows `data:` in a `data:[<mediatype>][;base64],<data>`
/// URI; `None` unless the data is base64 and decodes to some bytes.
///
/// A URI without `;base64` holds percent-encoded text, such as
/// `data:image/svg+xml,<svg…>`: it is not decoded, even when its text
/// happens to read as base64.
fn decode_inline_image(data_uri: &str) -> Option<InlineImage> {
    let (header, data) = data_uri.split_once(',')?;
    // `;base64` comes last: `image/svg+xml;charset=utf-8;base64`.
    let (media_type, encoding) = header.rsplit_once(';')?;
    if !encoding.trim().eq_ignore_ascii_case("base64") {
        return None;
    }
    // Parameters such as `;charset=utf-8` follow the type itself, and
    // `IMAGE/PNG` is the same type as `image/png`.
    let media_type = media_type
        .split_once(';')
        .map_or(media_type, |(media_type, _parameters)| media_type)
        .trim()
        .to_ascii_lowercase();

    // Strip whitespace (AIL does `''.join(data.split())`)
    let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64_decode(&cleaned).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(InlineImage { media_type, bytes })
}

/// The URL a page's relative favicon URLs resolve against, found on first
/// use.
///
/// ## `OnceCell`: computing a value on first use, through `&self`
///
/// Finding the `<base>` tag costs a scan of the page, wasted on the many
/// pages that declare no favicon. So the scanners get this struct instead
/// of the URL, and `url()` scans the first time it is called only. The
/// scanners hold a shared reference (`&DocumentBase`), yet the first call
/// must store its result: `OnceCell` allows exactly that, being written
/// once through `&self` (*interior mutability*), then read ever after.
///
/// `std::cell::LazyCell` would also do it, holding the closure to run
/// instead of `body` and `page_url`. But a closure's type has no name, so
/// every function taking a `LazyCell` would need a generic parameter for
/// it. Unlike `LazyLock`, neither type can be shared between threads, and
/// neither needs to: a page is scanned on one thread.
struct DocumentBase<'a> {
    body: &'a [u8],
    page_url: &'a str,
    url: OnceCell<Cow<'a, str>>,
}

impl<'a> DocumentBase<'a> {
    fn new(body: &'a [u8], page_url: &'a str) -> Self {
        Self {
            body,
            page_url,
            url: OnceCell::new(),
        }
    }

    /// The page's base URL, looking for its `<base>` the first time only.
    fn url(&self) -> &str {
        self.url.get_or_init(|| {
            // A `<base href>` that isn't UTF-8 is ignored, as a favicon URL
            // that isn't would be.
            let base_href = first_base_href(self.body)
                .and_then(|href| std::str::from_utf8(href).ok())
                .unwrap_or("");
            document_base_url(self.page_url, base_href)
        })
    }
}

/// A page's base URL: its `<base href>` (`""` when it has none), itself
/// resolved against `page_url`, else `page_url`.
///
/// ## `Cow` for a value computed only sometimes
///
/// Most pages have no `<base>`, and the base is then `page_url` itself.
/// `Cow::Borrowed(page_url)` uses it without copying; only a page with a
/// `<base>` pays for building a new `String` (`Cow::Owned`). Both deref to
/// `&str`, so the code using it doesn't care which one it got.
fn document_base_url<'a>(page_url: &'a str, base_href: &str) -> Cow<'a, str> {
    match base_href.trim() {
        "" => Cow::Borrowed(page_url),
        // `<base href>` may itself be relative to the page.
        base_href => Cow::Owned(resolve_url(page_url, base_href)),
    }
}

/// Resolve `url` against `base` and append it, unless the page already
/// declared the same favicon.
fn push_resolved(urls: &mut Vec<String>, base: &str, url: &str) {
    let absolute = resolve_url(base, url);
    if !urls.contains(&absolute) {
        urls.push(absolute);
    }
}

/// Minimal base64 decoder — handles standard base64 (RFC 4648).
///
/// We avoid pulling in the `base64` crate for this single use case.
/// This implementation handles standard and URL-safe alphabets, ignores
/// padding, and rejects invalid characters.
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Lookup table: ASCII byte → 6-bit value (255 = invalid).
    const DECODE_TABLE: [u8; 256] = {
        let mut table = [255u8; 256];
        let mut i = 0u8;
        // A-Z → 0-25
        while i < 26 {
            table[(b'A' + i) as usize] = i;
            i += 1;
        }
        i = 0;
        // a-z → 26-51
        while i < 26 {
            table[(b'a' + i) as usize] = 26 + i;
            i += 1;
        }
        i = 0;
        // 0-9 → 52-61
        while i < 10 {
            table[(b'0' + i) as usize] = 52 + i;
            i += 1;
        }
        // +, / (standard) and -, _ (URL-safe)
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table[b'-' as usize] = 62;
        table[b'_' as usize] = 63;
        table
    };

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits_collected: u8 = 0;

    for &b in bytes {
        if b == b'=' {
            break; // Padding — stop here
        }
        let value = DECODE_TABLE[b as usize];
        if value == 255 {
            return Err(()); // Invalid character
        }
        buffer = (buffer << 6) | value as u32;
        bits_collected += 6;
        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }

    Ok(output)
}

/// Resolve a potentially relative URL against a base page URL.
///
/// Handles the common cases without pulling in the `url` crate:
/// - Already absolute (`http://...`, `https://...`) → return as-is
/// - Protocol-relative (`//cdn.example.com/...`) → prepend scheme
/// - Root-relative (`/icons/favicon.png`) → prepend scheme + host
/// - Relative (`images/favicon.png`) → prepend scheme + host + path base
fn resolve_url(base_url: &str, relative: &str) -> String {
    // Already absolute
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return relative.to_string();
    }

    // Parse the base URL to extract scheme and host.
    let (scheme, after_scheme) = match base_url.split_once("://") {
        Some((s, rest)) => (s, rest),
        None => return relative.to_string(), // Can't resolve without scheme
    };

    // Extract host (everything up to the first `/` after scheme).
    let (host, path) = match after_scheme.find('/') {
        Some(pos) => (&after_scheme[..pos], &after_scheme[pos..]),
        None => (after_scheme, "/"),
    };

    let origin = format!("{scheme}://{host}");

    if relative.starts_with("//") {
        // Protocol-relative
        format!("{scheme}:{relative}")
    } else if relative.starts_with('/') {
        // Root-relative
        format!("{origin}{relative}")
    } else {
        // Relative — resolve against the directory of the current path.
        let base_dir = match path.rfind('/') {
            Some(pos) => &path[..=pos],
            None => "/",
        };
        format!("{origin}{base_dir}{relative}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_link_icon() {
        let html = br#"<html><head><link rel="icon" href="/favicon.png"></head></html>"#;
        let result = extract_favicons(html, "https://example.com/page");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/favicon.png")
        );
    }

    #[test]
    fn shortcut_icon() {
        let html = br#"<link rel="shortcut icon" href="/icons/fav.ico">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/icons/fav.ico")
        );
    }

    #[test]
    fn apple_touch_icon() {
        let html = br#"<link rel="apple-touch-icon" href="/apple-icon.png">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/apple-icon.png")
        );
    }

    #[test]
    fn mask_icon() {
        let html = br#"<link rel="mask-icon" href="/safari-pinned.svg">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/safari-pinned.svg")
        );
    }

    #[test]
    fn msapplication_tile_image() {
        let html = br#"<meta name="msapplication-TileImage" content="/icons/tile.png">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/icons/tile.png")
        );
    }

    #[test]
    fn no_root_favicon_guess_without_tags() {
        let html = b"<html><head><title>No icons</title></head></html>";
        let result = extract_favicons(html, "https://example.com/page/deep");
        assert!(
            result.urls.is_empty(),
            "only declared favicons are recorded"
        );
    }

    #[test]
    fn declared_root_favicon_is_kept() {
        let html = br#"<link rel="icon" href="/favicon.ico">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert_eq!(result.urls, ["https://example.com/favicon.ico"]);
    }

    fn inline_image(media_type: &str, bytes: &[u8]) -> InlineImage {
        InlineImage {
            media_type: media_type.to_string(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn inline_data_uri_decoded_with_its_media_type() {
        // "hello" in base64 = "aGVsbG8="
        let html = br#"<link rel="icon" href="data:image/png;base64,aGVsbG8=">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert_eq!(
            result.inline_favicons,
            [inline_image("image/png", b"hello")]
        );
        assert!(result.urls.is_empty());
    }

    #[test]
    fn inline_media_type_without_parameters_in_lower_case() {
        // "<svg/>" in base64 = "PHN2Zy8+"
        // With spaces after the `;`s, as some pages write it.
        let html =
            br#"<link rel="icon" href="data:Image/SVG+XML; charset=utf-8; base64,PHN2Zy8+">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert_eq!(
            result.inline_favicons,
            [inline_image("image/svg+xml", b"<svg/>")]
        );
    }

    #[test]
    fn data_uri_not_in_base64_is_dropped() {
        // Percent-encoded data, even when it happens to read as base64.
        let html = br#"<link rel="icon" href="data:image/svg+xml,abcd">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(result.inline_favicons.is_empty());
        assert!(result.urls.is_empty());
    }

    #[test]
    fn absolute_url_left_as_is() {
        let html = br#"<link rel="icon" href="https://cdn.other.com/favicon.png">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://cdn.other.com/favicon.png")
        );
    }

    #[test]
    fn protocol_relative_url() {
        let html = br#"<link rel="icon" href="//cdn.example.com/fav.ico">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://cdn.example.com/fav.ico")
        );
    }

    #[test]
    fn relative_url_resolved() {
        let html = br#"<link rel="icon" href="images/fav.png">"#;
        let result = extract_favicons(html, "https://example.com/blog/post");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/blog/images/fav.png")
        );
    }

    #[test]
    fn relative_url_resolved_against_relative_base() {
        let html = br#"<base href="/static/"><link rel="icon" href="icons/fav.png">"#;
        let result = extract_favicons(html, "https://example.net/docs/page.html");
        assert_eq!(result.urls, ["https://example.net/static/icons/fav.png"]);
    }

    #[test]
    fn urls_resolved_against_absolute_base() {
        let html = br#"
            <BASE HREF="https://cdn.example.org/assets/">
            <link rel="icon" href="fav.png">
            <link rel="apple-touch-icon" href="/touch.png">
        "#;
        let result = extract_favicons(html, "https://example.net/docs/page.html");
        assert_eq!(
            result.urls,
            [
                "https://cdn.example.org/assets/fav.png",
                "https://cdn.example.org/touch.png"
            ]
        );
    }

    #[test]
    fn first_base_with_an_href_wins() {
        // In both case orders: neither finder may win just by being lower
        // or upper case.
        let pages: [&[u8]; 2] = [
            br#"
            <base target="_blank">
            <base href="/first/">
            <BASE HREF="/second/">
            <link rel="icon" href="fav.png">
            "#,
            br#"
            <BASE TARGET="_blank">
            <BASE HREF="/first/">
            <base href="/second/">
            <link rel="icon" href="fav.png">
            "#,
        ];
        for html in pages {
            let result = extract_favicons(html, "https://example.net/docs/page.html");
            assert_eq!(result.urls, ["https://example.net/first/fav.png"]);
        }
    }

    #[test]
    fn single_quoted_attributes() {
        let html = br#"<link rel='icon' href='/favicon.png'>"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(
            result
                .urls
                .iter()
                .any(|u| u == "https://example.com/favicon.png")
        );
    }

    #[test]
    fn multiple_favicons_all_extracted() {
        let html = br#"
            <link rel="icon" href="/icon1.png">
            <link rel="apple-touch-icon" href="/icon2.png">
            <meta name="msapplication-TileImage" content="/icon3.png">
        "#;
        let result = extract_favicons(html, "https://example.com/");
        assert_eq!(result.urls.len(), 3);
        assert!(result.urls.iter().any(|u| u.ends_with("icon1.png")));
        assert!(result.urls.iter().any(|u| u.ends_with("icon2.png")));
        assert!(result.urls.iter().any(|u| u.ends_with("icon3.png")));
    }

    #[test]
    fn non_favicon_link_tags_ignored() {
        let html = br#"
            <link rel="stylesheet" href="/style.css">
            <link rel="canonical" href="https://example.com/">
        "#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(result.urls.is_empty());
    }

    #[test]
    fn empty_body() {
        let result = extract_favicons(b"", "https://example.com/");
        assert!(result.urls.is_empty());
    }

    #[test]
    fn case_insensitive_rel() {
        let html = br#"<LINK REL="ICON" HREF="/fav.png">"#;
        let result = extract_favicons(html, "https://example.com/");
        assert!(result.urls.iter().any(|u| u.ends_with("fav.png")));
    }

    // -- URL resolution tests --

    #[test]
    fn resolve_absolute() {
        assert_eq!(
            resolve_url("https://a.com/x", "https://b.com/y"),
            "https://b.com/y"
        );
    }

    #[test]
    fn resolve_root_relative() {
        assert_eq!(
            resolve_url("https://a.com/dir/page", "/img/fav.ico"),
            "https://a.com/img/fav.ico"
        );
    }

    #[test]
    fn resolve_relative() {
        assert_eq!(
            resolve_url("https://a.com/dir/page", "img/fav.ico"),
            "https://a.com/dir/img/fav.ico"
        );
    }

    #[test]
    fn resolve_protocol_relative() {
        assert_eq!(
            resolve_url("https://a.com/x", "//cdn.a.com/fav.ico"),
            "https://cdn.a.com/fav.ico"
        );
    }

    // -- Base64 decoder tests --

    #[test]
    fn base64_decode_basic() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello"); // No padding
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    #[test]
    fn base64_decode_url_safe() {
        // URL-safe variants: - instead of +, _ instead of /
        let standard = base64_decode("ab+c/d==").unwrap();
        let url_safe = base64_decode("ab-c_d==").unwrap();
        assert_eq!(standard, url_safe);
    }
}
