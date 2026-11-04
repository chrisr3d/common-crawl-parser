// Charsets — which encoding a browser reads a response's bytes in
//
// Bytes are text only in a charset. Browsers decide which one by the HTML
// standard's *encoding sniffing*, and so does this module, for each WARC
// response:
//   1. a byte-order mark at the start of the body (UTF-8, UTF-16LE or
//      UTF-16BE), which wins over anything the server says;
//   2. the `charset` parameter of the HTTP `Content-Type`;
//   3. the first bytes of an XML declaration in UTF-16, `<?x` as
//      `<\0?\0x\0` or `\0<\0?\0x`, which show the byte order;
//   4. for an HTML page, a `<meta charset>` (or its older form, `<meta
//      http-equiv="Content-Type" content="...; charset=...">`) in its first
//      1024 bytes, which the HTML standard's *prescan* reads before parsing
//      the page (`meta_charset`), else the `encoding` of an XML declaration
//      opening them (`<?xml version="1.0" encoding="...">`);
//   5. else none is declared (`Charset::Undeclared`).
//
// A charset is named by a *label* (`latin1`, `utf8`, `x-sjis`, ...), which
// the WHATWG Encoding Standard maps to one of its encodings: `latin1` is
// windows-1252, as in every browser. `encoding_rs`, Firefox's implementation
// of that standard, maps the labels and decodes the bytes.
//
// Nearly every charset writes ASCII as ASCII bytes, and no other character
// with them (`Encoding::is_ascii_compatible`): in those, markup and onion
// addresses are found without decoding anything. The exceptions are UTF-16,
// whose ASCII is no ASCII bytes; ISO-2022-JP, whose other characters are
// written with ASCII bytes too; and the *replacement* encoding that labels
// of charsets browsers refuse to read map to, which decodes to nothing.

use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE, WINDOWS_1252, X_USER_DEFINED};
use memchr::{memchr, memmem};

use crate::favicon_search::Attributes;
use crate::warc_parser::header_value;

/// The charset a response is read in.
///
/// ## `&'static Encoding`
///
/// `encoding_rs` defines each encoding once, as a `static`: a charset is a
/// reference to it, copied freely, and two are the same encoding exactly
/// when they point to the same one (`==` compares the addresses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// Named by a byte-order mark, the HTTP `charset` or a `<meta>` tag.
    Declared(&'static Encoding),
    /// Named nowhere: `encoding` decides from the bytes.
    Undeclared,
}

impl Charset {
    /// The charset a browser reads a response in, and the response's body
    /// without its byte-order mark: by the mark, else by the HTTP `charset`
    /// among `http_headers`, else by the first bytes of a UTF-16 XML
    /// declaration. (A browser reads the last in an HTML page's prescan,
    /// and XML's own rules in an XML document; no other response starts
    /// with them.)
    pub fn of_response<'a>(http_headers: &[u8], body: &'a [u8]) -> (Charset, &'a [u8]) {
        // `for_bom` returns the encoding and the length of its mark.
        if let Some((encoding, bom_length)) = Encoding::for_bom(body) {
            return (Charset::Declared(encoding), &body[bom_length..]);
        }
        let declared = http_charset(http_headers).or_else(|| utf16_xml_declaration(body));
        (
            declared.map_or(Charset::Undeclared, Charset::Declared),
            body,
        )
    }

    /// The charset a browser reads an HTML page in, and its body without
    /// its byte-order mark: as `of_response`, else by a `<meta>` tag or an
    /// XML declaration near the top of the page.
    pub fn of_html_page<'a>(http_headers: &[u8], body: &'a [u8]) -> (Charset, &'a [u8]) {
        match Charset::of_response(http_headers, body) {
            (Charset::Undeclared, body) => {
                let charset = prescan(body).map_or(Charset::Undeclared, Charset::Declared);
                (charset, body)
            }
            declared => declared,
        }
    }

    /// Whether this is UTF-16, little or big endian: the one charset whose
    /// ASCII text is no ASCII bytes, `a` written `a\0` or `\0a`.
    pub fn is_utf16(self) -> bool {
        self == Charset::Declared(UTF_16LE) || self == Charset::Declared(UTF_16BE)
    }

    /// The encoding of `body` in this charset: the declared one, else
    /// UTF-8 unless `body` holds bytes beyond ASCII and UTF-8 reads none of
    /// them, windows-1252 then.
    ///
    /// ## The default of an undeclared page
    ///
    /// The HTML standard leaves it to the browser: one guessing from the
    /// bytes, as Chrome does, reads a page in UTF-8 when its bytes are, and
    /// windows-1252 is the fallback of browsers in most of the world. Bytes
    /// beyond ASCII that line up as UTF-8 characters are hardly anything
    /// else, so a page holding any is read as UTF-8, a stray byte UTF-8
    /// can't read elsewhere notwithstanding (or a character cut short at the
    /// end, where Common Crawl's size limit cut the page). A page holding
    /// only bytes UTF-8 can't read is read as Latin-1, which most
    /// undeclared ones are.
    ///
    /// ## `utf8_chunks`
    ///
    /// `<[u8]>::utf8_chunks` cuts bytes into chunks, each a run of valid
    /// UTF-8 (`valid()`, a `&str`) followed by the bytes, maybe none, that
    /// are not (`invalid()`): a page is read once, and no error stops it.
    pub fn encoding(self, body: &[u8]) -> &'static Encoding {
        match self {
            Charset::Declared(encoding) => encoding,
            Charset::Undeclared
                if body.is_ascii() || body.utf8_chunks().any(|chunk| !chunk.valid().is_ascii()) =>
            {
                UTF_8
            }
            Charset::Undeclared => WINDOWS_1252,
        }
    }
}

/// The encoding the `charset` parameter of the last HTTP `Content-Type`
/// naming a type gives, if its label is one: `text/html;
/// charset="Shift_JIS"` gives Shift_JIS. A value naming no type, such as
/// `charset=utf-8` alone, counts for nothing, as in a browser, and so does
/// an unknown label.
fn http_charset(http_headers: &[u8]) -> Option<&'static Encoding> {
    let content_type = http_headers
        .split(|&b| b == b'\n')
        .filter_map(|line| header_value(line, b"Content-Type:"))
        .filter(|value| names_a_type(value))
        // The last one, looked for from the end: `split` yields its parts
        // from either end (`DoubleEndedIterator`), and so do the filters.
        .next_back()?;
    let label = content_type
        .split(|&b| b == b';')
        .skip(1)
        .find_map(|parameter| {
            let (name, value) = parameter.split_at(parameter.iter().position(|&b| b == b'=')?);
            name.trim_ascii()
                .eq_ignore_ascii_case(b"charset")
                .then(|| unquoted(value[1..].trim_ascii()))
        })?;
    // `for_label` ignores case and the whitespace around the label.
    Encoding::for_label(label)
}

/// Whether a `Content-Type` value starts with a type, `type/subtype`,
/// before its parameters. `*/*`, which a browser passes over, is none.
fn names_a_type(value: &[u8]) -> bool {
    let essence = value.split(|&b| b == b';').next().unwrap_or_default();
    let Some(slash) = essence.iter().position(|&b| b == b'/') else {
        return false;
    };
    let (main, sub) = (
        essence[..slash].trim_ascii(),
        essence[slash + 1..].trim_ascii(),
    );
    !main.is_empty() && !sub.is_empty() && !sub.contains(&b'/') && (main, sub) != (b"*", b"*")
}

/// A parameter's `value` as HTTP reads it: in double quotes, what they
/// enclose, any text after the closing one ignored; else the value itself.
fn unquoted(value: &[u8]) -> &[u8] {
    match value.strip_prefix(b"\"") {
        Some(quoted) => &quoted[..memchr(b'"', quoted).unwrap_or(quoted.len())],
        None => value,
    }
}

/// UTF-16LE or UTF-16BE if `body` starts with `<?x` in that encoding, the
/// start of an XML declaration: the HTML standard's prescan checks these
/// six bytes first (`<?x`, not `<?xml`, for historical reasons).
fn utf16_xml_declaration(body: &[u8]) -> Option<&'static Encoding> {
    if body.starts_with(b"<\0?\0x\0") {
        Some(UTF_16LE)
    } else if body.starts_with(b"\0<\0?\0x") {
        Some(UTF_16BE)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The `<meta>` prescan
// ---------------------------------------------------------------------------

/// How many bytes of a page the prescan reads, as the HTML standard says.
const PRESCAN_LENGTH: usize = 1024;

/// The charset the HTML standard's prescan finds in the first
/// `PRESCAN_LENGTH` bytes of `page`: a `<meta>` tag's, else that of an XML
/// declaration opening them. `None` if neither declares one.
///
/// The prescan reads the bytes before their charset is known, so it reads
/// only tags, attributes and quotes, the same bytes in every charset it can
/// find. A page read so is no UTF-16 page: UTF-16 declared there reads as
/// UTF-8.
fn prescan(page: &[u8]) -> Option<&'static Encoding> {
    let page = &page[..page.len().min(PRESCAN_LENGTH)];
    meta_charset(page).or_else(|| xml_declaration_encoding(page))
}

/// The charset the first `<meta>` tag of `page` declaring one it knows
/// gives, comments and the attributes of other tags, a quoted `>` included,
/// passed over. `x-user-defined` reads as windows-1252.
fn meta_charset(page: &[u8]) -> Option<&'static Encoding> {
    // Past the end of the bytes, the prescan gives up: `?` returns `None`
    // wherever a construct is still open there.
    let mut pos = 0;
    while let Some(offset) = memchr(b'<', &page[pos..]) {
        let open = pos + offset;
        let rest = &page[open..];
        let at = |i: usize| rest.get(i).copied();
        pos = if rest.starts_with(b"<!--") {
            // Up to the first `-->`, whose dashes may be those of `<!--`.
            open + 2 + memmem::find(&rest[2..], b"-->")? + 3
        } else if rest
            .get(..5)
            .is_some_and(|name| name.eq_ignore_ascii_case(b"<meta"))
            && at(5).is_some_and(|b| b.is_ascii_whitespace() || b == b'/')
        {
            let (charset, end) = read_meta(page, open + 5)?;
            if charset.is_some() {
                return charset;
            }
            end
        } else if at(1).is_some_and(|b| b.is_ascii_alphabetic())
            || (at(1) == Some(b'/') && at(2).is_some_and(|b| b.is_ascii_alphabetic()))
        {
            // Any other tag: its name runs to whitespace or `>`, then its
            // attributes are read to the `>` ending it.
            let name_end = open
                + rest
                    .iter()
                    .position(|&b| b.is_ascii_whitespace() || b == b'>')?;
            let mut attributes = Attributes::new(page, name_end);
            // Read every attribute, dropping each, to reach the tag's end.
            attributes.by_ref().for_each(drop);
            attributes.end()?
        } else if matches!(at(1), Some(b'!' | b'/' | b'?')) {
            open + memchr(b'>', rest)? + 1
        } else {
            open + 1
        };
    }
    None
}

/// Read the attributes of a `<meta>` tag, from `from`, just after its
/// name, to its end: the charset it declares, if any, and where the
/// prescan resumes. `None` if the page ends inside the tag.
///
/// A tag declares a charset by its `charset` attribute, or by its
/// `content` when its `http-equiv` is `Content-Type`. Of an attribute
/// given twice, the first counts.
fn read_meta(page: &[u8], from: usize) -> Option<(Option<&'static Encoding>, usize)> {
    let mut names_seen: Vec<&[u8]> = Vec::new();
    let mut is_content_type = false;
    // Whether the charset came from `content`, which then needs
    // `http-equiv`; `None` until an attribute gave one.
    let mut from_content = None;
    // `None` until an attribute named a charset, `Some(None)` if it named
    // none the prescan knows: then a later `content` changes nothing.
    let mut charset: Option<Option<&'static Encoding>> = None;

    let mut attributes = Attributes::new(page, from);
    for (name, value) in &mut attributes {
        if names_seen
            .iter()
            .any(|seen| seen.eq_ignore_ascii_case(name))
        {
            continue;
        }
        names_seen.push(name);
        if name.eq_ignore_ascii_case(b"http-equiv") {
            is_content_type |= value.eq_ignore_ascii_case(b"content-type");
        } else if name.eq_ignore_ascii_case(b"content") {
            if charset.is_none()
                && let Some(encoding) = charset_in_content(value)
            {
                charset = Some(Some(encoding));
                from_content = Some(true);
            }
        } else if name.eq_ignore_ascii_case(b"charset") {
            charset = Some(Encoding::for_label(value));
            from_content = Some(false);
        }
    }
    let end = attributes.end()?;

    let declared = match from_content {
        Some(true) if !is_content_type => None,
        Some(_) => charset.flatten(),
        None => None,
    };
    let declared = declared.map(|encoding| match not_utf16(encoding) {
        encoding if encoding == X_USER_DEFINED => WINDOWS_1252,
        encoding => encoding,
    });
    Some((declared, end))
}

/// The charset the `content` of a `<meta http-equiv="Content-Type">`
/// names, as the HTML standard reads it: the first `charset=` followed by a
/// label, quoted or running to whitespace or `;`.
fn charset_in_content(content: &[u8]) -> Option<&'static Encoding> {
    const CHARSET: &[u8] = b"charset";
    let skip_whitespace = |from: usize| {
        from + content[from..]
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count()
    };
    let mut pos = 0;
    loop {
        let found = content[pos..]
            .windows(CHARSET.len())
            .position(|word| word.eq_ignore_ascii_case(CHARSET))?;
        let after_word = skip_whitespace(pos + found + CHARSET.len());
        if content.get(after_word) != Some(&b'=') {
            // `charset` not followed by `=`: look further.
            pos = after_word;
            continue;
        }
        let value_start = skip_whitespace(after_word + 1);
        let value = &content[value_start..];
        let label = match *value.first()? {
            // A quote left open names nothing.
            quote @ (b'"' | b'\'') => &value[1..1 + memchr(quote, &value[1..])?],
            _ => {
                let end = value
                    .iter()
                    .position(|&b| b.is_ascii_whitespace() || b == b';')
                    .unwrap_or(value.len());
                &value[..end]
            }
        };
        return Encoding::for_label(label);
    }
}

/// The encoding an XML declaration opening `page` names, `<?xml
/// version="1.0" encoding="ISO-8859-1"?>`, as the HTML standard reads it:
/// the first `encoding` before the declaration's `>`, then `=`, then a
/// label in quotes. Whitespace (here any byte up to 0x20) may surround the
/// `=`; a label holding any is none.
fn xml_declaration_encoding(page: &[u8]) -> Option<&'static Encoding> {
    const WORD: &[u8] = b"encoding";
    if !page.starts_with(b"<?xml") {
        return None;
    }
    let declaration = &page[..memchr(b'>', page)?];
    let skip_whitespace =
        |from: usize| from + page[from..].iter().take_while(|&&b| b <= 0x20).count();
    let equals = skip_whitespace(memmem::find(declaration, WORD)? + WORD.len());
    if page.get(equals) != Some(&b'=') {
        return None;
    }
    let quote_at = skip_whitespace(equals + 1);
    let quote = *page.get(quote_at).filter(|&&b| b == b'"' || b == b'\'')?;
    let label = &page[quote_at + 1..];
    let label = &label[..memchr(quote, label)?];
    if label.iter().any(|&b| b <= 0x20) {
        return None;
    }
    Encoding::for_label(label).map(not_utf16)
}

/// `encoding`, unless it is UTF-16: a charset declared in bytes read as
/// ASCII can't be that one, and UTF-8 is read instead.
fn not_utf16(encoding: &'static Encoding) -> &'static Encoding {
    if encoding == UTF_16LE || encoding == UTF_16BE {
        UTF_8
    } else {
        encoding
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use encoding_rs::{ISO_8859_2, ISO_8859_5, KOI8_R, SHIFT_JIS, WINDOWS_1251};

    /// The charset of an HTML page sent with this `Content-Type`, if any.
    fn html_charset(content_type: Option<&str>, body: &[u8]) -> Charset {
        let headers = content_type.map_or(String::new(), |value| {
            format!("HTTP/1.1 200 OK\r\nContent-Type: {value}")
        });
        Charset::of_html_page(headers.as_bytes(), body).0
    }

    /// The charset of an HTML page sent without a `Content-Type`.
    fn charset_of_page(body: &str) -> Charset {
        html_charset(None, body.as_bytes())
    }

    #[test]
    fn a_meta_tag_declares_the_charset() {
        for (body, encoding) in [
            (r#"<meta charset="Shift_JIS">"#, SHIFT_JIS),
            ("<META CHARSET=koi8-r>", KOI8_R),
            (
                r#"<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">"#,
                WINDOWS_1251,
            ),
            (
                r#"<meta content='text/html; charset="koi8-r"' http-equiv=content-type>"#,
                KOI8_R,
            ),
            // `latin1` is a label of windows-1252.
            (
                "<!DOCTYPE html><html><head><meta charset=latin1>",
                WINDOWS_1252,
            ),
        ] {
            assert_eq!(charset_of_page(body), Charset::Declared(encoding), "{body}");
        }
    }

    #[test]
    fn a_meta_tag_counts_only_as_html_reads_it() {
        for (body, expected) in [
            // `content` declares a charset only with `http-equiv`.
            (
                r#"<meta content="text/html; charset=koi8-r">"#,
                Charset::Undeclared,
            ),
            // Nothing is read in a comment or a quoted value.
            (
                r#"<!-- <meta charset="koi8-r"> --><meta charset="iso-8859-2">"#,
                Charset::Declared(ISO_8859_2),
            ),
            (
                r#"<div title="a > <meta charset=koi8-r>"><meta charset="iso-8859-5">"#,
                Charset::Declared(ISO_8859_5),
            ),
            // An unknown label passes to the next tag; of an attribute
            // given twice, the first counts.
            (
                r#"<meta charset="bogus"><meta charset="koi8-r" charset="iso-8859-2">"#,
                Charset::Declared(KOI8_R),
            ),
            // A page that can be read as ASCII is no UTF-16 page.
            (r#"<meta charset="utf-16le">"#, Charset::Declared(UTF_8)),
            (
                r#"<meta charset="x-user-defined">"#,
                Charset::Declared(WINDOWS_1252),
            ),
        ] {
            assert_eq!(charset_of_page(body), expected, "{body}");
        }
    }

    #[test]
    fn an_xml_declaration_opening_the_page_counts_after_meta_tags() {
        for (body, expected) in [
            (
                r#"<?xml version="1.0" encoding="ISO-8859-2"?><html>"#,
                Charset::Declared(ISO_8859_2),
            ),
            (
                "<?xml version='1.0' encoding = 'koi8-r' ?><meta charset=iso-8859-5>",
                Charset::Declared(ISO_8859_5),
            ),
            (
                r#"<?xml version="1.0" encoding="UTF-16"?>"#,
                Charset::Declared(UTF_8),
            ),
            // Only at the very start, and before the declaration's `>`.
            (r#" <?xml encoding="koi8-r"?>"#, Charset::Undeclared),
            (
                r#"<?xml version="1.0"?><p encoding="koi8-r">"#,
                Charset::Undeclared,
            ),
        ] {
            assert_eq!(charset_of_page(body), expected, "{body}");
        }
    }

    #[test]
    fn a_utf16_xml_declaration_shows_its_byte_order() {
        let little_endian = b"<\0?\0x\0m\0l\0";
        let big_endian = b"\0<\0?\0x\0m\0l";
        assert_eq!(
            Charset::of_response(b"", little_endian).0,
            Charset::Declared(UTF_16LE)
        );
        assert_eq!(
            Charset::of_response(b"", big_endian).0,
            Charset::Declared(UTF_16BE)
        );
        // The HTTP charset comes first.
        let http = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8";
        assert_eq!(
            Charset::of_response(http, little_endian).0,
            Charset::Declared(UTF_8)
        );
    }

    #[test]
    fn an_undeclared_page_is_utf8_unless_only_another_charset_reads_it() {
        let utf8 = "café".as_bytes();
        for (body, expected) in [
            (&b"plain ASCII"[..], UTF_8),
            (utf8, UTF_8),
            // A stray byte UTF-8 can't read leaves a UTF-8 page UTF-8.
            (&[utf8, b" \xff"].concat(), UTF_8),
            // `caf\xe9` is `café` in windows-1252, nothing in UTF-8.
            (b"caf\xe9", WINDOWS_1252),
        ] {
            assert_eq!(Charset::Undeclared.encoding(body), expected, "{body:?}");
        }
    }

    #[test]
    fn only_the_first_1024_bytes_are_read() {
        let late = format!("{}<meta charset=koi8-r>", " ".repeat(1024));
        assert_eq!(charset_of_page(&late), Charset::Undeclared);
        let early = format!("{}<meta charset=koi8-r>", " ".repeat(1000));
        assert_eq!(charset_of_page(&early), Charset::Declared(KOI8_R));
    }

    #[test]
    fn the_byte_order_mark_then_http_win_over_a_meta_tag() {
        let page = b"<meta charset=koi8-r>";
        let http = Some("text/html; charset=iso-8859-2");
        assert_eq!(html_charset(http, page), Charset::Declared(ISO_8859_2));
        let with_bom = [&b"\xEF\xBB\xBF"[..], page].concat();
        assert_eq!(html_charset(http, &with_bom), Charset::Declared(UTF_8));
        // A `charset` without a type, or an unknown one, declares nothing.
        for http in ["charset=iso-8859-2", "text/html; charset=bogus"] {
            assert_eq!(html_charset(Some(http), page), Charset::Declared(KOI8_R));
        }
        // Text after a quoted value is ignored, and `*/*` names no type.
        let headers = b"HTTP/1.1 200 OK\r\n\
            Content-Type: text/html; charset=\"iso-8859-2\"junk; q=1\r\n\
            Content-Type: */*; charset=iso-8859-5";
        assert_eq!(
            Charset::of_html_page(headers, page).0,
            Charset::Declared(ISO_8859_2)
        );
    }
}
