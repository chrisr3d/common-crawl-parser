// Favicon extraction — one forward pass over the bytes, no HTML parser
//
// Extracts favicon URLs and inline base64-encoded favicons from HTML content.
// Mirrors the logic of AIL Framework's `extract_favicon_from_html()`, but
// reads the page in one pass: `memchr` jumps from one `<` to the next, and
// only the few tags that matter are read attribute by attribute. No DOM
// tree, no allocations for non-matching tags.
//
// ## What we look for
//
// 1. `<link rel="icon" href="...">` — standard favicon; `shortcut icon` and
//    `alternate icon` too, as `rel` is a list of tokens
// 2. `<link rel="mask-icon" href="...">` — Safari pinned tabs
// 3. `<link rel="apple-touch-icon" href="...">` and
//    `apple-touch-icon-precomposed` — iOS Safari
// 4. `<meta name="msapplication-TileImage" content="...">` — Edge/IE
// 5. Inline `data:` URIs in any of the above → decoded as base64 favicons
//
// Unlike AIL, we don't add a guessed `{scheme}://{domain}/favicon.ico` for
// every page: only favicons a page declares are recorded. A guessed URL
// was never checked to exist, and one per page would swell the results.
//
// ## Reading tags as a browser does
//
// A favicon is what a browser would load, so the page is read by the HTML
// standard's tokenizer rules, as far as these tags need: tag names in any
// case, attributes in any order and spacing, quoted or not, entities such
// as `&amp;` decoded in their values; nothing read inside comments or
// `<script>`, `<style>`, `<title>` and the other elements holding text
// only. URLs resolve with the `url` crate, by the URL standard browsers
// follow: against the page's first `<base href>`, itself resolved against
// the page URL, else against the page URL (the HTML standard's "document
// base URL").
//
// WAT records need no scanning: ia-web-commons has already parsed the page
// and listed its `<link>` and `<meta>` tags and its `<base href>`, entities
// decoded, comments and scripts left out. `favicons_in_head` applies the
// same `rel` and `name` rules to that list and resolves against that
// `<base href>` the same way.
//
// ## Why not use an HTML parsing crate?
//
// Of the parsers that follow the HTML standard, `html5ever` (behind
// `scraper`) needs the page as UTF-8, which many WARC bodies are not, and
// allocates for every token of every page, to keep 1-2 tags; `lol_html`
// streams, but is a large dependency for this. The scanner looks at each
// `<` once and reads only `<link>`, `<meta>`, `<base>`, comments and the
// text-only elements: the rest of the page costs one `memchr` jump per tag.
// Where it still reads differently from a browser (see `scan_page`),
// comparing its favicons with WAT's over the same pages shows it.

use std::borrow::Cow;

use memchr::memmem;
use url::Url;

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
/// One pass over the page (`scan_page`) collects the favicon values of its
/// `<link>` and `<meta>` tags, in page order, and its first `<base href>`;
/// then each value is either decoded as an inline image or resolved into an
/// absolute URL.
pub fn extract_favicons(body: &[u8], page_url: &str) -> FaviconResult {
    let tags = scan_page(body);
    let mut result = FaviconResult::default();
    if tags.favicon_values.is_empty() {
        return result;
    }

    // A `<base href>` that isn't UTF-8 is ignored, as a favicon URL that
    // isn't would be.
    let base_href = tags
        .base_href
        .as_deref()
        .and_then(|href| std::str::from_utf8(href).ok());
    let base = document_base(page_url, base_href);
    for value in &tags.favicon_values {
        process_favicon_value(value, base.as_ref(), &mut result);
    }
    result
}

/// The favicon URLs declared in a WAT record's `<head>`, resolved to
/// absolute URLs against the page's `<base href>` if it has one, else
/// against `page_url`.
///
/// The `<link>` tags whose `rel` holds a favicon token give their `url`,
/// the `msapplication-TileImage` `<meta>` tags their `content`, as in the
/// HTML scanner. Nothing is decoded or skipped: ia-web-commons has decoded
/// the values and left out comments and scripts. With several `<base>`
/// tags, ia-web-commons probably keeps the last one where the HTML scanner
/// keeps the first; rare, and not copied there. `data:` URLs are skipped: WAT cuts every one after its first comma
/// (`trimDataUrl` in ia-web-commons), so the inline image is gone, and the
/// stub left is no URL to fetch.
pub fn favicons_in_head(head: &Head<'_>, page_url: &str) -> Vec<String> {
    // `""`: the page has no `<base href>`.
    let base_href = Some(head.base.as_ref()).filter(|href| !href.is_empty());
    let base = document_base(page_url, base_href);
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
        let value = value.trim_ascii();
        if value.is_empty() || strip_data_scheme(value).is_some() {
            continue;
        }
        push_resolved(&mut urls, base.as_ref(), value);
    }
    urls
}

// ---------------------------------------------------------------------------
// Favicon rules and the page scan
// ---------------------------------------------------------------------------

/// The `rel` tokens that declare a favicon (case-insensitive).
///
/// HTML reads `rel` as a list of tokens separated by whitespace, so `icon`
/// also covers `shortcut icon` (legacy IE; "shortcut" means nothing to a
/// browser but is still common) and `alternate icon`.
/// - `icon` — standard HTML5 favicon
/// - `apple-touch-icon` — iOS home screen icons
/// - `apple-touch-icon-precomposed` — the same, already finished: iOS 6
///   and older added a gloss to the others
/// - `mask-icon` — Safari pinned tab SVG icons
const FAVICON_REL_TOKENS: &[&[u8]] = &[
    b"icon",
    b"apple-touch-icon",
    b"apple-touch-icon-precomposed",
    b"mask-icon",
];

/// Whether a `<link>`'s `rel` declares a favicon: whether any of its
/// tokens is one of `FAVICON_REL_TOKENS`.
fn is_favicon_rel(rel: &[u8]) -> bool {
    rel.split(u8::is_ascii_whitespace).any(|token| {
        FAVICON_REL_TOKENS
            .iter()
            .any(|expected| token.eq_ignore_ascii_case(expected))
    })
}

/// Whether a `<meta>`'s `name` declares a Windows tile image.
fn is_tile_image_name(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"msapplication-TileImage")
}

/// What one pass over a page finds, borrowed from the page unless an
/// entity had to be decoded.
#[derive(Default)]
struct PageTags<'a> {
    /// The `href` of each favicon `<link>` and the `content` of each
    /// `msapplication-TileImage` `<meta>`, in page order.
    favicon_values: Vec<Cow<'a, [u8]>>,
    /// The `href` of the first `<base>` that has one.
    base_href: Option<Cow<'a, [u8]>>,
}

/// Read a page as a browser's HTML tokenizer does, as far as favicons
/// need: `memchr` jumps from one `<` to the next. The `<link>`, `<meta>`
/// and `<base>` start tags are read attribute by attribute; comments and
/// the text of raw-text elements (`Element::RawText`) are skipped to their
/// end. The pass resumes after each, so it stays linear however long a tag
/// (a large inline favicon) or comment is.
///
/// Any other start tag is passed over at its `<`, its attributes unread:
/// a `<link>` written inside one of its quoted values
/// (`<div data-html='<link …>'>`) is read, where a browser sees text. End
/// tags are passed over the same way, and the tokenizer's special case for
/// `<!--` inside a script is not followed.
fn scan_page(page: &[u8]) -> PageTags<'_> {
    let mut tags = PageTags::default();
    let mut pos = 0;
    while let Some(offset) = memchr::memchr(b'<', &page[pos..]) {
        // `None`: the page ends inside something read to its end.
        let Some(next) = read_markup(page, pos + offset, &mut tags) else {
            break;
        };
        pos = next;
    }
    tags
}

/// Read the markup starting at the `<` at `open` into `tags`: where the
/// scan resumes, or `None` if the page ends inside what is read here: a
/// tag, which a browser drops, or a comment or raw-text element, the rest
/// of the page being its text.
fn read_markup<'a>(page: &'a [u8], open: usize, tags: &mut PageTags<'a>) -> Option<usize> {
    let after = open + 1;
    match page.get(after) {
        // A start tag is `<` then a letter.
        Some(b) if b.is_ascii_alphabetic() => read_start_tag(page, after, tags),
        Some(b'!') if page[after..].starts_with(b"!--") => comment_end(page, after + 3),
        // An end tag holds nothing to read.
        Some(b'/') if page.get(after + 1).is_some_and(u8::is_ascii_alphabetic) => Some(after + 1),
        // `<![CDATA[…`, `<?php …`, `</ …`: a *bogus comment* to HTML,
        // which ends at the first `>`, even one closing a tag written
        // inside it. `<!DOCTYPE …>` has its own tokenizer states, but ends
        // at its first `>` all the same.
        Some(b'!' | b'?' | b'/') => {
            memchr::memchr(b'>', &page[after..]).map(|offset| after + offset + 1)
        }
        // A `<` in text.
        _ => Some(after),
    }
}

/// Read the start tag whose name starts at `name_start` into `tags`, as
/// `read_markup`.
fn read_start_tag<'a>(page: &'a [u8], name_start: usize, tags: &mut PageTags<'a>) -> Option<usize> {
    // The name runs to whitespace, `/` or `>`. One longer than any name in
    // `ELEMENTS` is none of them, and is not read to its end.
    let Some(name_len) = page[name_start..]
        .iter()
        .take(LONGEST_ELEMENT_NAME + 1)
        .position(|&b| ends_tag_name(b))
    else {
        return Some(name_start);
    };
    let name_end = name_start + name_len;
    let Some(element) = Element::named(&page[name_start..name_end]) else {
        return Some(name_start);
    };

    match element {
        Element::Link => {
            let StartTag {
                values: [rel, href],
                end,
            } = read_attributes(page, name_end, [b"rel", b"href"])?;
            if let (Some(rel), Some(href)) = (rel, href)
                && is_favicon_rel(&rel)
            {
                tags.favicon_values.push(href);
            }
            Some(end)
        }
        Element::Meta => {
            let StartTag {
                values: [name, content],
                end,
            } = read_attributes(page, name_end, [b"name", b"content"])?;
            if let (Some(name), Some(content)) = (name, content)
                && is_tile_image_name(&name)
            {
                tags.favicon_values.push(content);
            }
            Some(end)
        }
        Element::Base => {
            let StartTag {
                values: [href],
                end,
            } = read_attributes(page, name_end, [b"href"])?;
            // A `<base>` may only set a `target`: the next one may have an
            // `href`.
            if tags.base_href.is_none() {
                tags.base_href = href;
            }
            Some(end)
        }
        Element::RawText => {
            let StartTag { values: [], end } = read_attributes(page, name_end, [])?;
            raw_text_end(page, end, &page[name_start..name_end])
        }
    }
}

/// Where the comment whose `<!--` ends at `from` ends, just past its
/// `-->` (or `--!>`, which HTML accepts too); `None` if the page ends
/// first.
fn comment_end(page: &[u8], from: usize) -> Option<usize> {
    // `<!-->` and `<!--->` are empty comments.
    for empty_end in [&b">"[..], b"->"] {
        if page[from..].starts_with(empty_end) {
            return Some(from + empty_end.len());
        }
    }
    let mut pos = from;
    loop {
        let dashes = pos + memmem::find(&page[pos..], b"--")?;
        let after_dashes = &page[dashes + 2..];
        if after_dashes.starts_with(b">") {
            return Some(dashes + 3);
        }
        if after_dashes.starts_with(b"!>") {
            return Some(dashes + 4);
        }
        // Not the end: `--` alone, or the first two of `--->`.
        pos = dashes + 1;
    }
}

/// Where the text of a raw-text element, from `from` on, ends: at its end
/// tag, `</` then its `name` in any case, then whitespace, `/` or `>`.
/// The scan resumes just past that name. `None` if the page ends first.
fn raw_text_end(page: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut pos = from;
    loop {
        let name_start = pos + memmem::find(&page[pos..], b"</")? + 2;
        let name_end = name_start + name.len();
        if page
            .get(name_start..name_end)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
            && page.get(name_end).is_some_and(|&b| ends_tag_name(b))
        {
            return Some(name_end);
        }
        pos = name_start;
    }
}

/// The elements whose start tags the scanner reads.
#[derive(Clone, Copy)]
enum Element {
    Link,
    Meta,
    Base,
    /// An element holding text up to its end tag, never tags: a `<link>`
    /// written in a script or a `<title>` is no `<link>` to a browser.
    RawText,
}

/// Each `Element` with its name.
///
/// The raw-text ones are HTML's *raw text* elements (`script`, `style`,
/// `xmp`, `iframe`, `noembed`, `noframes`) and *escapable raw text*
/// elements (`title`, `textarea`, whose entities are decoded, which
/// changes nothing here). `noscript` and `template` hold markup, read as
/// any other.
const ELEMENTS: &[(&[u8], Element)] = &[
    (b"link", Element::Link),
    (b"meta", Element::Meta),
    (b"base", Element::Base),
    (b"script", Element::RawText),
    (b"style", Element::RawText),
    (b"xmp", Element::RawText),
    (b"iframe", Element::RawText),
    (b"noembed", Element::RawText),
    (b"noframes", Element::RawText),
    (b"title", Element::RawText),
    (b"textarea", Element::RawText),
];

/// The length of the longest name in `ELEMENTS`, worked out at compile
/// time (a `const` block may loop with `while`, not with `for`).
const LONGEST_ELEMENT_NAME: usize = {
    let mut longest = 0;
    let mut i = 0;
    while i < ELEMENTS.len() {
        if ELEMENTS[i].0.len() > longest {
            longest = ELEMENTS[i].0.len();
        }
        i += 1;
    }
    longest
};

impl Element {
    /// The element called `name`, in any case.
    fn named(name: &[u8]) -> Option<Self> {
        ELEMENTS
            .iter()
            .find(|(element_name, _)| name.eq_ignore_ascii_case(element_name))
            .map(|&(_, element)| element)
    }
}

/// Whether `b` ends a tag name: whitespace, `/` or `>`.
fn ends_tag_name(b: u8) -> bool {
    b.is_ascii_whitespace() || b == b'/' || b == b'>'
}

// ---------------------------------------------------------------------------
// Attributes — read as HTML's tokenizer reads them
// ---------------------------------------------------------------------------

/// A start tag read to its end, keeping the values of `N` attributes.
struct StartTag<'a, const N: usize> {
    /// Each value, its entities decoded; `None` if the tag has no such
    /// attribute.
    values: [Option<Cow<'a, [u8]>>; N],
    /// Just past the tag's `>`.
    end: usize,
}

/// Read the attributes of a start tag, from `from`, just after its name,
/// to the `>` that ends it, keeping the value of each attribute named in
/// `names` (in any case; the first one if repeated, as HTML ignores the
/// others).
///
/// `None` if the page ends inside the tag: a browser drops such a tag.
///
/// ## `N` attributes, checked at compile time
///
/// `N` is a const generic: `read_attributes(page, from, [b"rel", b"href"])`
/// returns a `StartTag<'_, 2>`, which the caller destructures with an
/// array pattern (`StartTag { values: [rel, href], end }`). A pattern with
/// the wrong number of names doesn't compile.
fn read_attributes<'a, const N: usize>(
    page: &'a [u8],
    from: usize,
    names: [&[u8]; N],
) -> Option<StartTag<'a, N>> {
    // `[None; N]` repeats a `Copy` value, which `Option<&[u8]>` is and
    // `Option<Cow<[u8]>>` isn't: the values are kept as slices of the page,
    // and decoded once the tag is read, with the array's `map`.
    let mut values = [None; N];
    let mut attributes = Attributes {
        page,
        pos: from,
        end: None,
    };
    // `&mut attributes` lends the iterator to the loop instead of moving it
    // in (`&mut I` is an iterator too), so its `end` can be read after.
    for (name, value) in &mut attributes {
        if let Some(i) = names.iter().position(|n| name.eq_ignore_ascii_case(n)) {
            values[i] = values[i].or(Some(value));
        }
    }
    Some(StartTag {
        values: values.map(|value| value.map(decode_entities)),
        end: attributes.end?,
    })
}

/// The attributes of one start tag, read one by one.
///
/// HTML's tokenizer is a state machine reading one character at a time;
/// this follows its states for attributes:
/// - a name runs to whitespace, `/`, `>` or `=`; quotes are part of it, so
///   the stray quote of `crossorigin"` opens nothing;
/// - only an `=` (whitespace allowed around it) gives the name a value: a
///   quoted one runs to the same quote, `>` included; an unquoted one to
///   whitespace or `>`, `/` included;
/// - whitespace and `/` separate attributes, yet a name may also follow a
///   closing quote directly (`rel="icon"href="…"`);
/// - the first `>` outside a quoted value ends the tag, however far.
struct Attributes<'a> {
    page: &'a [u8],
    /// Where the next attribute is looked for.
    pos: usize,
    /// Once the iterator is done: just past the tag's `>`, or `None` if the
    /// page ended inside the tag.
    end: Option<usize>,
}

impl<'a> Iterator for Attributes<'a> {
    /// An attribute's name and value, as written; `""` without a value.
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let page = self.page;
        loop {
            match *page.get(self.pos)? {
                b'>' => {
                    self.end = Some(self.pos + 1);
                    return None;
                }
                b'/' => self.pos += 1,
                b if b.is_ascii_whitespace() => self.pos += 1,
                _ => break,
            }
        }

        // The first character is part of the name whatever it is, even an
        // `=` (`<link =x>` has an attribute `=x`).
        let name_start = self.pos;
        let name_end = skip_while(page, name_start + 1, |b| {
            !(b.is_ascii_whitespace() || matches!(b, b'/' | b'>' | b'='))
        });
        let name = &page[name_start..name_end];

        let equals = skip_while(page, name_end, |b| b.is_ascii_whitespace());
        if page.get(equals) != Some(&b'=') {
            self.pos = equals;
            return Some((name, b""));
        }
        let value_start = skip_while(page, equals + 1, |b| b.is_ascii_whitespace());
        match *page.get(value_start)? {
            quote @ (b'"' | b'\'') => {
                let value_start = value_start + 1;
                let value_end = value_start + memchr::memchr(quote, &page[value_start..])?;
                self.pos = value_end + 1;
                Some((name, &page[value_start..value_end]))
            }
            // `rel=>`: no value, and the `>` ends the tag.
            b'>' => {
                self.pos = value_start;
                Some((name, b""))
            }
            _ => {
                let value_end =
                    skip_while(page, value_start, |b| !b.is_ascii_whitespace() && b != b'>');
                self.pos = value_end;
                Some((name, &page[value_start..value_end]))
            }
        }
    }
}

/// The first position from `from` on whose byte fails `keep_going`;
/// `page.len()` if there is none.
fn skip_while(page: &[u8], from: usize, keep_going: impl Fn(u8) -> bool) -> usize {
    page[from..]
        .iter()
        .position(|&b| !keep_going(b))
        .map_or(page.len(), |offset| from + offset)
}

// ---------------------------------------------------------------------------
// Character references (entities)
// ---------------------------------------------------------------------------

/// `value` with its character references decoded, as a browser decodes an
/// attribute value, for those a URL holds in practice:
/// - numeric ones, decimal (`&#38;`) or hex (`&#x26;`), the closing `;`
///   optional;
/// - the named `&amp;`, `&lt;`, `&gt;`, `&quot;` and `&apos;`.
///
/// Any other `&` is kept as written, `&copy;` included: HTML names over
/// 2,000 characters, and URLs hardly ever hold one. Nor are the numbers
/// 128 to 159 mapped to Windows-1252 characters as HTML does.
///
/// Borrowed, without copying, when the value holds no `&`: nearly always.
fn decode_entities(value: &[u8]) -> Cow<'_, [u8]> {
    let Some(first_amp) = memchr::memchr(b'&', value) else {
        return Cow::Borrowed(value);
    };
    let mut decoded = Vec::with_capacity(value.len());
    let mut pos = 0;
    let mut amp = Some(first_amp);
    while let Some(at) = amp {
        decoded.extend_from_slice(&value[pos..at]);
        pos = match character_reference(&value[at + 1..]) {
            Some((character, len)) => {
                decoded.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
                at + 1 + len
            }
            None => {
                decoded.push(b'&');
                at + 1
            }
        };
        amp = memchr::memchr(b'&', &value[pos..]).map(|offset| pos + offset);
    }
    decoded.extend_from_slice(&value[pos..]);
    Cow::Owned(decoded)
}

/// The named character references `decode_entities` decodes.
const NAMED_REFERENCES: &[(&[u8], char)] = &[
    (b"amp;", '&'),
    (b"lt;", '<'),
    (b"gt;", '>'),
    (b"quot;", '"'),
    (b"apos;", '\''),
];

/// The character a reference written just after an `&` stands for, and
/// the length of the reference, its `;` included; `None` if `text` starts
/// with no reference `decode_entities` decodes.
fn character_reference(text: &[u8]) -> Option<(char, usize)> {
    let Some(number) = text.strip_prefix(b"#") else {
        return NAMED_REFERENCES
            .iter()
            .find(|(name, _)| text.starts_with(name))
            .map(|&(name, character)| (character, name.len()));
    };
    let (prefix_len, radix) = match number.first() {
        Some(b'x' | b'X') => (1, 16),
        _ => (0, 10),
    };
    let digits: Vec<u32> = number[prefix_len..]
        .iter()
        .map_while(|&b| char::from(b).to_digit(radix))
        .collect();
    if digits.is_empty() {
        return None;
    }
    // Saturating: a number too large for a `u32` is past Unicode's last
    // code point too.
    let code = digits.iter().fold(0u32, |code, &digit| {
        code.saturating_mul(radix).saturating_add(digit)
    });
    // Zero, a surrogate or past Unicode's last code point: HTML reads
    // U+FFFD, the replacement character.
    let character = char::from_u32(code)
        .filter(|&character| character != '\0')
        .unwrap_or(char::REPLACEMENT_CHARACTER);
    let end = 1 + prefix_len + digits.len();
    let len = if text.get(end) == Some(&b';') {
        end + 1
    } else {
        end
    };
    Some((character, len))
}

// ---------------------------------------------------------------------------
// Favicon value processing — URL resolution and data: URI decoding
// ---------------------------------------------------------------------------

/// Process a favicon attribute value — either a URL or an inline `data:` URI.
///
/// As in AIL, a value is one of two kinds:
/// - `data:` URIs → decode the base64 payload, store as inline favicon
/// - Everything else → resolve to absolute URL against the page's base URL
///   (`document_base`)
fn process_favicon_value(value: &[u8], base: Option<&Url>, result: &mut FaviconResult) {
    // Convert to string — favicon URLs should be valid UTF-8 (they're in
    // HTML attributes). If not, skip this value.
    let Ok(value) = std::str::from_utf8(value) else {
        return;
    };
    // HTML strips ASCII whitespace around a URL, and fetches nothing for
    // an empty one.
    let value = value.trim_ascii();
    if value.is_empty() {
        return;
    }

    if let Some(data_uri) = strip_data_scheme(value) {
        if let Some(image) = decode_inline_image(data_uri) {
            result.inline_favicons.push(image);
        }
    } else {
        push_resolved(&mut result.urls, base, value);
    }
}

/// What follows the scheme of a `data:` URI (`data:`, `DATA:`: a scheme
/// is case-insensitive); `None` for any other value.
fn strip_data_scheme(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_at_checked("data:".len())?;
    scheme.eq_ignore_ascii_case("data:").then_some(rest)
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

/// The URL a page's favicon values resolve against, the HTML standard's
/// "document base URL": its first `<base href>` resolved against the page
/// URL, else the page URL. A `<base href>` that is no URL leaves the page
/// URL, as in a browser. `None` if the page URL is no URL either: then
/// only absolute values resolve.
fn document_base(page_url: &str, base_href: Option<&str>) -> Option<Url> {
    let page = Url::parse(page_url).ok();
    match base_href {
        Some(href) => resolve(page.as_ref(), href).or(page),
        None => page,
    }
}

/// `value` resolved against `base` as a browser resolves it; `None` if it
/// is no URL.
///
/// ## The `url` crate: URLs as browsers read them
///
/// The WHATWG URL standard is what browsers implement, and `url` follows
/// it: `../` and `./` segments removed, `?v=2` resolved against the whole
/// base path, scheme and host in any case (and written lowercase), `\`
/// read as `/`, spaces percent-encoded, the default port dropped. Each
/// of these is a rule a hand-written resolver gets wrong sooner or later.
/// `Url::options().base_url(base).parse(value)` is `base.join(value)`, also
/// for a base that may be missing.
fn resolve(base: Option<&Url>, value: &str) -> Option<Url> {
    Url::options().base_url(base).parse(value).ok()
}

/// Resolve `value` against `base` and append it, unless it is no URL or
/// the page already declared the same favicon. It is written as `url`
/// serializes it, which is what a browser requests.
fn push_resolved(urls: &mut Vec<String>, base: Option<&Url>, value: &str) {
    let Some(url) = resolve(base, value) else {
        return;
    };
    let url = String::from(url);
    if !urls.contains(&url) {
        urls.push(url);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page_record::{Link, Meta};

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
        // In both case orders: the first `<base>` with an `href` wins, in
        // whichever case it is written.
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

    // -- WARC and WAT: the same favicons from the same page --

    /// The page the WARC / WAT comparisons below are crawled from.
    const PAGE: &str = "https://example.net/dir/page";

    /// The WAT `Head` ia-web-commons lists for a page holding these
    /// `<link>` tags, given as `(rel, href)`, and no `<base>`.
    fn head_with_links<'a>(links: &[(&'a str, &'a str)]) -> Head<'a> {
        Head {
            base: Cow::Borrowed(""),
            links: links
                .iter()
                .map(|&(rel, url)| Link {
                    rel: rel.into(),
                    url: url.into(),
                })
                .collect(),
            metas: Vec::new(),
        }
    }

    /// Assert that the WARC scanner finds `expected` in `html`, and
    /// `favicons_in_head` the same in `head`, the WAT form of that page.
    fn assert_warc_and_wat(html: &str, head: &Head<'_>, page_url: &str, expected: &[&str]) {
        assert_eq!(
            extract_favicons(html.as_bytes(), page_url).urls,
            expected,
            "WARC: {html:?}"
        );
        assert_eq!(
            favicons_in_head(head, page_url),
            expected,
            "WAT, for {html:?}"
        );
    }

    #[test]
    fn tag_names_in_any_case_followed_by_any_whitespace() {
        let head = head_with_links(&[("icon", "/i.png")]);
        for html in [
            r#"<Link rel="icon" href="/i.png">"#,
            "<link\nrel=\"icon\" href=\"/i.png\">",
            "<LINK\r\n\tREL=\"icon\"\nHREF=\"/i.png\">",
            r#"<link/rel="icon" href="/i.png">"#,
        ] {
            assert_warc_and_wat(html, &head, PAGE, &["https://example.net/i.png"]);
        }
    }

    #[test]
    fn rel_is_a_list_of_tokens_in_any_case() {
        for rel in [
            "Icon",
            "alternate icon",
            "  shortcut\ticon ",
            "apple-touch-icon-precomposed",
            "MASK-ICON",
        ] {
            let html = format!(r#"<link rel="{rel}" href="/i.png">"#);
            let head = head_with_links(&[(rel, "/i.png")]);
            assert_warc_and_wat(&html, &head, PAGE, &["https://example.net/i.png"]);
        }
    }

    #[test]
    fn rel_tokens_that_are_not_favicons() {
        for rel in ["fluid-icon", "icons", "shortcut", "preload stylesheet"] {
            let html = format!(r#"<link rel="{rel}" href="/i.png">"#);
            let head = head_with_links(&[(rel, "/i.png")]);
            assert_warc_and_wat(&html, &head, PAGE, &[]);
        }
    }

    #[test]
    fn urls_resolved_as_a_browser_resolves_them() {
        for (page_url, href, expected) in [
            (PAGE, "../up.png", "https://example.net/up.png"),
            (PAGE, "./fav.png", "https://example.net/dir/fav.png"),
            (PAGE, "/a/./b/../fav.png", "https://example.net/a/fav.png"),
            // Scheme and host in any case; the host is written lowercase.
            (
                PAGE,
                "HTTPS://CDN.Example/i.png",
                "https://cdn.example/i.png",
            ),
            (
                PAGE,
                "ftp://files.example/i.png",
                "ftp://files.example/i.png",
            ),
            // A query alone keeps the page's path.
            (PAGE, "?v=2", "https://example.net/dir/page?v=2"),
            // A `/` in the page's query is no path separator.
            (
                "https://example.net/dir/page?next=/x/y",
                "fav.png",
                "https://example.net/dir/fav.png",
            ),
            // Backslashes are slashes, spaces are percent-encoded, the
            // default port is dropped.
            (PAGE, r"\\cdn.example\i.png", "https://cdn.example/i.png"),
            (PAGE, "/my icon.png", "https://example.net/my%20icon.png"),
            (
                PAGE,
                "https://example.net:443/i.png",
                "https://example.net/i.png",
            ),
        ] {
            let html = format!(r#"<link rel="icon" href="{href}">"#);
            let head = head_with_links(&[("icon", href)]);
            assert_warc_and_wat(&html, &head, page_url, &[expected]);
        }
    }

    #[test]
    fn values_that_are_no_url_are_dropped() {
        for href in ["https://", "http://exa mple.net/i.png"] {
            let html = format!(r#"<link rel="icon" href="{href}">"#);
            let head = head_with_links(&[("icon", href)]);
            assert_warc_and_wat(&html, &head, PAGE, &[]);
        }
    }

    /// A `data:` URI holding `size` bytes of base64 (`AAAA` decodes to
    /// three zero bytes).
    fn large_data_uri(size: usize) -> String {
        format!("data:image/png;base64,{}", "AAAA".repeat(size / 4))
    }

    #[test]
    fn a_tag_of_any_length_hides_nothing_after_it() {
        let data_uri = large_data_uri(5 * 1024);
        let html = format!(
            r#"<link rel="icon" href="{data_uri}"><link rel="apple-touch-icon" href="/touch.png">"#
        );
        // WAT cuts the `data:` URI after its first comma.
        let head = head_with_links(&[
            ("icon", "data:image/png;base64,"),
            ("apple-touch-icon", "/touch.png"),
        ]);
        assert_warc_and_wat(&html, &head, PAGE, &["https://example.net/touch.png"]);

        let inline = extract_favicons(html.as_bytes(), PAGE).inline_favicons;
        assert_eq!(inline, [inline_image("image/png", &[0; 5 * 1024 / 4 * 3])]);
    }

    // -- WARC against the WAT `Head` of the same page, where ia-web-commons
    // has decoded the entities and dropped the comments and scripts --

    #[test]
    fn entities_decoded_in_values() {
        for (href, decoded, expected) in [
            (
                "/i.png?a=1&#038;b=2",
                "/i.png?a=1&b=2",
                "https://example.net/i.png?a=1&b=2",
            ),
            (
                "/i.png?a=1&amp;b=2",
                "/i.png?a=1&b=2",
                "https://example.net/i.png?a=1&b=2",
            ),
            (
                "&#x2F;&#x2F;cdn.example&#x2F;i.png",
                "//cdn.example/i.png",
                "https://cdn.example/i.png",
            ),
            (
                "/i.png?v&#X3D;2&#47;3",
                "/i.png?v=2/3",
                "https://example.net/i.png?v=2/3",
            ),
            // The `;` of a numeric reference is optional.
            (
                "/i.png?a=1&#38b=2&#x26z=3",
                "/i.png?a=1&b=2&z=3",
                "https://example.net/i.png?a=1&b=2&z=3",
            ),
        ] {
            let html = format!(r#"<link rel="icon" href="{href}">"#);
            let head = head_with_links(&[("icon", decoded)]);
            assert_warc_and_wat(&html, &head, PAGE, &[expected]);
        }
    }

    #[test]
    fn entities_decoded_in_rel_meta_and_base() {
        let html = r#"
            <base href="&#x2F;static&#x2F;">
            <link rel="shortcut&#32;ic&#111;n" href="fav.png">
            <meta name="msapplication&#45;TileImage" content="tile.png?a=1&amp;b=2">
        "#;
        let head = Head {
            base: Cow::Borrowed("/static/"),
            links: vec![Link {
                rel: "shortcut icon".into(),
                url: "fav.png".into(),
            }],
            metas: vec![Meta {
                name: "msapplication-TileImage".into(),
                content: "tile.png?a=1&b=2".into(),
            }],
        };
        assert_warc_and_wat(
            html,
            &head,
            PAGE,
            &[
                "https://example.net/static/fav.png",
                "https://example.net/static/tile.png?a=1&b=2",
            ],
        );
    }

    #[test]
    fn attributes_read_as_html_reads_them() {
        let head = head_with_links(&[("icon", "/i.png")]);
        for html in [
            // An unquoted value runs to whitespace or `>`, `/` included.
            "<link rel=icon href=/i.png>",
            "<link rel=icon href=/i.png />",
            "<link href=/i.png rel=icon>",
            // No whitespace needed after a quoted value.
            r#"<link rel="icon"href="/i.png">"#,
            // Whitespace allowed around `=`; `>` inside quotes ends nothing.
            r#"<link title="a > b" rel = 'icon' href= "/i.png">"#,
            // A repeated attribute is ignored.
            r#"<link rel="icon" href="/i.png" href="/other.png">"#,
        ] {
            assert_warc_and_wat(html, &head, PAGE, &["https://example.net/i.png"]);
        }

        let html = "<link rel=icon href=https://cdn.example/i.png>";
        let head = head_with_links(&[("icon", "https://cdn.example/i.png")]);
        assert_warc_and_wat(html, &head, PAGE, &["https://cdn.example/i.png"]);
    }

    #[test]
    fn a_stray_quote_in_an_earlier_tag_hides_nothing() {
        let html = r#"<link rel=preload crossorigin"><link rel="icon" href="/i.png">"#;
        let head = head_with_links(&[("preload", ""), ("icon", "/i.png")]);
        assert_warc_and_wat(html, &head, PAGE, &["https://example.net/i.png"]);
    }

    #[test]
    fn tags_in_comments_and_scripts_are_not_read() {
        let head = head_with_links(&[("icon", "/i.png")]);
        for html in [
            r#"<!-- <link rel="icon" href="/old.png"> --><link rel="icon" href="/i.png">"#,
            // `--!>` ends a comment too; `<!-->` is an empty one.
            r#"<!-- <link rel="icon" href="/old.png"> --!><!--><link rel="icon" href="/i.png">"#,
            r#"<script>document.write('<link rel="icon" href="/js.png">');</script>
               <link rel="icon" href="/i.png">"#,
            r#"<SCRIPT type="text/javascript">var t = "<link rel=icon href=/js.png>";</Script >
               <link rel="icon" href="/i.png">"#,
            // A `<base>` in a comment sets nothing.
            r#"<!--<base href="/elsewhere/">--><link rel="icon" href="/i.png">"#,
            // `<?`, `<!` and `</` without a letter open a *bogus* comment,
            // which ends at the first `>`: the end of the `<link>` here. A
            // `<!DOCTYPE>` ends at its `>` too.
            r#"<?php }); <link rel="icon" href="/php.png"><link rel="icon" href="/i.png">"#,
            r#"<![CDATA[ <link rel="icon" href="/cdata.png"> ]]><link rel="icon" href="/i.png">"#,
            r#"</ <link rel="icon" href="/slash.png"><link rel="icon" href="/i.png">"#,
            r#"<!DOCTYPE html><link rel="icon" href="/i.png">"#,
        ] {
            assert_warc_and_wat(html, &head, PAGE, &["https://example.net/i.png"]);
        }
    }

    #[test]
    fn tags_in_text_only_elements_are_not_read() {
        let head = head_with_links(&[("icon", "/i.png")]);
        for element in ["textarea", "title", "style", "iframe", "TITLE"] {
            let html = format!(
                r#"<{element}><link rel="icon" href="/hidden.png"></{element}>
                   <link rel="icon" href="/i.png">"#
            );
            assert_warc_and_wat(&html, &head, PAGE, &["https://example.net/i.png"]);
        }
        // `</title` only ends a `<title>` followed by whitespace, `/` or `>`.
        let html = r#"<title></titles><link rel="icon" href="/hidden.png"></title >
                      <link rel="icon" href="/i.png">"#;
        assert_warc_and_wat(html, &head, PAGE, &["https://example.net/i.png"]);
    }

    #[test]
    fn tags_in_noscript_are_read() {
        let html = r#"<noscript><link rel="icon" href="/i.png"></noscript>"#;
        let head = head_with_links(&[("icon", "/i.png")]);
        assert_warc_and_wat(html, &head, PAGE, &["https://example.net/i.png"]);
    }

    // -- WARC only --

    /// The favicon URLs the WARC scanner finds in `html`, crawled at `PAGE`.
    fn warc_favicons(html: &str) -> Vec<String> {
        extract_favicons(html.as_bytes(), PAGE).urls
    }

    #[test]
    fn other_named_references_kept_invalid_numbers_replaced() {
        // Named references other than the five are left as written, as
        // is an `&` starting none.
        assert_eq!(
            warc_favicons(r#"<link rel="icon" href="/&copy;.png?a&b=&#;&#xZ">"#),
            ["https://example.net/&copy;.png?a&b=&#;&#xZ"]
        );
        // Zero and numbers past Unicode read as U+FFFD, percent-encoded.
        assert_eq!(
            warc_favicons(r#"<link rel="icon" href="/&#0;&#x110000;.png">"#),
            ["https://example.net/%EF%BF%BD%EF%BF%BD.png"]
        );
    }

    #[test]
    fn a_100_kb_inline_favicon_is_found() {
        let data_uri = large_data_uri(100 * 1024);
        let html = format!(
            r#"<link rel="icon" href="{data_uri}"><link rel="mask-icon" href="/mask.svg">"#
        );
        let result = extract_favicons(html.as_bytes(), PAGE);
        assert_eq!(
            result.inline_favicons,
            [inline_image("image/png", &[0; 100 * 1024 / 4 * 3])]
        );
        assert_eq!(result.urls, ["https://example.net/mask.svg"]);
    }

    #[test]
    fn a_tag_still_open_at_the_end_of_the_page_is_dropped() {
        for html in [
            r#"<link rel="icon" href="/i.png"><link rel="apple-touch-icon" href="/t.png""#,
            r#"<link rel="icon" href="/i.png"><link rel="apple-touch-icon" href="/t.png"#,
            r#"<link rel="icon" href="/i.png"><link rel=apple-touch-icon href=/t.png"#,
            // A comment or script left open hides the rest of the page.
            r#"<link rel="icon" href="/i.png"><!-- <link rel="mask-icon" href="/m.svg">"#,
            r#"<link rel="icon" href="/i.png"><script><link rel="mask-icon" href="/m.svg">"#,
        ] {
            assert_eq!(warc_favicons(html), ["https://example.net/i.png"]);
        }
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
