# Research: can WAT or WET replace WARC for this parser?

Date: 2026-09-08. Crawl used for measurements: CC-MAIN-2026-34 (August 2026).
Code state: branch `favicon-extraction`, commit 86298b8.

Names below are those of that commit, kept as measured. The binary is now
`cc-extract`; the `memchr` and `bytes` strategies are `--onion-engine memchr`
and `regex`, the `mmap` strategy `-t mmap`, and stream mode (`-m`) is
`-t memory`. The `parse_warc_*` functions became one `parse_archive`, and the
WAT + WET reading this document recommends is the default Plan on CC-MAIN
(`documentation/FEATURES.md`).

## 1. Question and TL;DR

Common Crawl publishes every crawl segment three times: the raw `WARC`, the
`WAT` metadata extract, and the `WET` plain-text extract. This parser downloads
the WARC (about 0.9 GB per file, 100,000 files per crawl) and pulls out two
things: `.onion` addresses (`src/onion_search.rs`) and favicon references, both
as URLs and as inline `data:` URIs (`src/favicon_search.rs`). The question is
whether the much smaller WAT or WET files contain enough to do the same job,
what exactly would be lost, and whether the size saving is worth it.

**Recommendation.**

- For **`.onion` addresses**, WAT is a good substitute and WAT+WET together are
  an excellent one. Across five segments (106,439 pages, 4.67 GB of WARC), WAT
  alone recovered 35 of 38 unique onions (92.1 %) and 92 of 104 individual
  matches (88.5 %) from 16.2 % of the bytes. WAT and WET together recovered
  38 of 38 unique onions from 23.0 % of the bytes. WET alone is not enough
  (13 of 38, 34.2 %), because 53 % of all matches live in HTTP response headers
  (`Onion-Location`, `Content-Security-Policy`), which WET drops entirely.
- For **favicon URLs**, WAT is sufficient: 86,120 of the 86,231 HTML pages with
  a favicon `<link rel=...>` in the WARC (99.9 %) have the corresponding entry in
  the WAT `Head.Link` array, with the `rel` attribute preserved, and the
  `msapplication-TileImage` meta tag is preserved too (31,861 vs 31,896).
- For **inline `data:` favicons**, WAT is useless by construction: the WAT
  generator truncates every `data:` URL at its comma, so only the media type
  survives (`data:image/png;base64,`) and the payload is gone. WET contains no
  markup at all. If inline favicons matter, the WARC is required. In the sample
  they are rare: 65 of 20,822 HTML pages (0.3 %) in the primary segment carried
  a non-empty inline favicon.
- The **size saving is real and worth it if inline favicons can be dropped**:
  the pipeline is download-bound on this machine by a factor of 3 to 5
  (14.8 to 24.6 s to download a WARC versus 5.1 s to parse it), and crawl-wide
  the WARC set is 84.78 TiB against 13.92 TiB for WAT and 5.84 TiB for WET.
- **Caveat on completeness.** WAT and WET deterministically drop some places an
  onion can hide: inline `<script>` bodies, HTML comments, non-HTML payloads
  (JavaScript, JSON, CSS, PDF, plain text) and request records. None of the 104
  matches in the sample lived in any of those places, but the sample is small
  (38 unique onions). A periodic WARC spot-check is advisable if the goal is
  exhaustive discovery. **Measured since (section 4.7):** over 99 Shards, WAT
  + WET missed 7 of 215 distinct onions (3.3 %) and 21 of 1,470 Sightings
  (1.4 %), all in inline scripts, attributes WAT does not keep and HTML
  comments; for favicon URLs, WAT turned out more accurate than the WARC
  scanner.
- **Blocking bug.** The current `WarcRecordIter` in `src/warc_parser.rs` crashes
  with a stack overflow on any WAT or WET file (it recurses once per skipped
  non-`response` record; WAT files contain 63,523 consecutive `metadata`
  records). It must be converted to a loop before either format can be fed to
  the parser. Details in section 5.

## 2. Format comparison

All three formats are WARC-format containers (section 3). The measured numbers
below are for one segment file, `CC-MAIN-20260807101845-20260807131845-00000`
in segment `1786091384908.68` of CC-MAIN-2026-34, downloaded on 2026-09-08
(`download.log` in the scratchpad, `curl -w` timing, single sequential
download each). Sizes are exact bytes; MB means 10^6 bytes.

| | WARC (`.warc.gz`) | WAT (`.warc.wat.gz`) | WET (`.warc.wet.gz`) |
|---|---|---|---|
| Content | Raw HTTP request and response (headers plus full body), plus crawler metadata per page | JSON per source record: WARC headers, HTTP headers, and for HTML the head (`Title`, `Base`, `Link`, `Metas`, `Scripts`) and all outgoing links | Plain text extracted from the HTML body, one record per HTML page |
| WARC record types (measured) | 1 `warcinfo`, 21,174 `request`, 21,174 `response`, 21,174 `metadata` | 1 `warcinfo`, 63,523 `metadata` (one per WARC record, including the WARC's own `warcinfo`) | 1 `warcinfo`, 20,614 `conversion` |
| Payload `Content-Type` of the data records | `application/http; msgtype=response` | `application/json` | `text/plain` |
| Compressed size | 909,108,907 B (909.1 MB) | 151,385,264 B (151.4 MB, 16.7 %) | 63,890,507 B (63.9 MB, 7.0 %) |
| Decompressed size (`gzcat \| wc -c`) | 3,953,539,145 B (3.95 GB) | 683,136,743 B (683 MB, 17.3 %) | 176,867,503 B (177 MB, 4.5 %) |
| Download wall time (this connection) | 14.8 s at 61.4 MB/s | 4.5 s at 33.6 MB/s | 2.5 s at 25.6 MB/s |
| `gzcat > /dev/null` (single core, M3 Max) | 3.38 s | 0.70 s | 0.30 s |
| `.onion` matches, total / unique | 22 / 9 | 22 / 9 | 4 / 2 |

Across the five segments measured (section 4) the ratios were stable:
compressed WAT is 16.2 % of WARC and WET 6.8 %; decompressed WAT is 17.0 % and
WET 4.4 %. These match the crawl-wide figures published by Common Crawl for
CC-MAIN-2026-34: 84.78 TiB of WARC, 13.92 TiB of WAT (16.4 %) and 5.84 TiB of
WET (6.9 %), 100,000 files each, for 2.14 billion pages and 360 TiB of
uncompressed content
([crawl index page](https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-34/index.html),
[announcement](https://commoncrawl.org/blog/august-2026-crawl-archive-now-available)).
For comparison, a 2015 mailing-list estimate put WET at about one tenth and
WAT at about one third of the WARC volume
([common-crawl group thread](https://groups.google.com/g/common-crawl/c/5Jx9uIfYMqA));
the WAT ratio has clearly shrunk since then.

The file-name suffixes `.warc.gz`, `.warc.wat.gz` and `.warc.wet.gz` are the
ones Common Crawl documents on its
[Get Started page](https://commoncrawl.org/get-started) and the ones present in
the local `warc.paths.gz`, `wat.paths.gz` and `wet.paths.gz` files
(`gzcat wat.paths.gz | head -1` gives
`crawl-data/CC-MAIN-2026-34/segments/1786091384908.68/wat/CC-MAIN-20260807101845-20260807131845-00000.warc.wat.gz`).
The WARC 1.1 specification itself only recommends `.warc.gz` for compressed
WARC files; `.wat` and `.wet` are Common Crawl / Internet Archive conventions,
not part of the ISO standard
([WARC 1.1, Annex B file naming](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/)).

## 3. What each format captures, relative to this parser's targets

### 3.1 The container: all three are WARC files

The WARC 1.1 standard defines eight record types: `warcinfo`, `response`,
`resource`, `request`, `metadata`, `revisit`, `conversion` and `continuation`
([WARC 1.1 section 5.5](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/)).
A `response` record "should contain a complete scheme-specific response,
including network protocol information, where possible" (section 6.3). A
`metadata` record "contains content created in order to further describe,
explain, or accompany a harvested resource, in ways not covered by other record
types" (section 6.6). A `conversion` record "shall contain an alternative
version of another record's content that was created as the result of an
archival process" (section 6.8). The `WARC-Refers-To` field "contains the
WARC-Record-ID of a single record for which the present record holds additional
content" (section 5.11).

The measured record-type counts in section 2 confirm the mapping: WAT files
consist of `metadata` records and WET files of `conversion` records, each
carrying a `WARC-Refers-To` pointing at the original WARC record and a
`WARC-Target-URI` equal to the page URL. Sample headers from the downloaded
files (`head -c 6000 ... | grep '^WARC'`):

```text
WARC/1.0                                            WARC/1.0
WARC-Type: metadata                                 WARC-Type: conversion
WARC-Target-URI: http://022okbj.com/tjlogan-...     WARC-Target-URI: http://022okbj.com/tjlogan-...
WARC-Date: 2026-08-12T07:29:27Z                     WARC-Date: 2026-08-07T11:43:24Z
WARC-Refers-To: <urn:uuid:019fdc08-fe83-7e82-...>   WARC-Refers-To: <urn:uuid:019fdc08-fe83-7e82-...>
Content-Type: application/json                      WARC-Identified-Content-Language: zho
Content-Length: 1476                                Content-Type: text/plain
```

Note the dates: the WAT record's own `WARC-Date` is the WAT generation time
(12 August), not the crawl time. The crawl time is preserved inside the JSON at
`Envelope.WARC-Header-Metadata.WARC-Date` (`2026-08-07T11:43:24Z` for the record
above). The WET record keeps the crawl time in its outer header. This matters
for `OnionSource.date`.

### 3.2 WARC: what the parser reads today

Common Crawl describes WARC as "the raw data from the crawl, providing a direct
mapping to the crawl process", storing the HTTP response headers, the response
body, the request, and crawl-process metadata
([Get Started](https://commoncrawl.org/get-started)). The parser only reads
`response` records (`src/warc_parser.rs`, `is_response` check), runs the onion
search over the whole record body, HTTP headers included
(`src/lib.rs`, `parse_warc_memchr`), and runs favicon extraction on the HTTP
body when the `Content-Type` is HTML (`extract_favicons_from_record` in
`src/lib.rs`). Everything an onion or favicon could be embedded in is available.

### 3.3 WAT: JSON produced by ia-web-commons

Common Crawl says WAT files "contain important metadata about the records stored
in the WARC format", serialized as JSON with whitespace stripped, and that for
HTML this includes the HTTP response headers, the page links with their link
types, the page title and the meta tags
([Get Started](https://commoncrawl.org/get-started)). The blog post on formats
says WAT "files contain parsed data from the HTTP response headers, links
extracted from HTML pages, and other metadata"
([Web archiving file formats explained](https://commoncrawl.org/blog/web-archiving-file-formats-explained)).

The generator is the Internet Archive's `webarchive-commons`, maintained by
Common Crawl as
[commoncrawl/ia-web-commons](https://github.com/commoncrawl/ia-web-commons).
The JSON key names are string constants in
[`ResourceConstants.java`](https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/resource/ResourceConstants.java):
`"Envelope"`, `"Payload-Metadata"`, `"HTTP-Response-Metadata"`, `"Headers"`,
`"WARC-Header-Metadata"`, `"HTML-Metadata"`, `"Head"`, `"Base"`, `"Title"`,
`"Metas"`, `"Link"`, `"Scripts"`, `"Links"`, `"Text"`. In
[`HTMLMetaData.java`](https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/resource/html/HTMLMetaData.java),
`addLink()` appends to `Head.Link`, `addMeta()` to `Head.Metas`, `addScript()`
to `Head.Scripts`, and `addHref()` to the top-level `Links`; `setTextExtract()`
stores the `Text` field that later becomes the WET payload.

Which HTML elements become links is defined in
[`ExtractingParseObserver.java`](https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/resource/html/ExtractingParseObserver.java).
Its extractor table covers `A` (href, plus target, alt, title, rel, hreflang,
type), `AREA` (href, rel), `APPLET`/`OBJECT` (codebase, data), `BASE`, `EMBED`,
`FRAME`, `IFRAME` (src), `FORM` (action, target, method), `IMG` (src, alt,
title, longdesc), `INPUT` (src, formaction), `LINK`, `SCRIPT` (src, type),
`VIDEO` (src, poster), plus the global attributes `background`, `data-href` and
`data-uri`, and URLs found inside inline `<style>` CSS. The relevant parts for
this parser, quoted from the source:

```java
private static class LinkTagExtractor implements TagExtractor {
    public void extract(HTMLMetaData data, TagNode node, ExtractingParseObserver obs) {
        ArrayList<String> l = getAttrListUrl(node,"href","rel","type","hreflang");
        if(l != null) { data.addLink(l); }
    }
}
private static class MetaTagExtractor implements TagExtractor {
    public void extract(HTMLMetaData data, TagNode node, ExtractingParseObserver obs) {
        ArrayList<String> l = getAttrList(node,"name","rel","content","http-equiv","property");
        if(l != null) { if (l.size() == 2) { return; } data.addMeta(l); }
    }
}
```

So `rel` **is** kept for `Head.Link` entries (the parser needs it to recognise
`icon`, `shortcut icon`, `mask-icon`, `apple-touch-icon`), and `name` plus
`content` are kept for meta tags (needed for `msapplication-TileImage`). The
same file also shows what is **not** extracted: `handleScriptNode` is a `TODO`
that does nothing, `handleRemarkNode` (HTML comments) is a no-op, anchor text is
capped at `MAX_TEXT_LEN = 128` characters, and every URL goes through
`trimDataUrl`, which cuts a `data:` URL at its first comma (or at 128
characters):

```java
public static String trimDataUrl(String url) {
    if (url.startsWith("data:")) {
        int posComma = url.indexOf(',', 5);
        if (posComma == -1) { if (url.length() > 128) return url.substring(0, 128); return url; }
        else if (posComma > 128) return url.substring(0, 128);
        else if (posComma == 6) return "data:,";
        else if (posComma > 6) return url.substring(0, posComma + 1);
    }
    return url;
}
```

This is the deterministic reason inline favicons cannot be recovered from WAT.

`WATExtractorOutput.java` writes one `metadata` record with
`Content-Type: application/json` for every source record, including `request`,
`response`, `metadata` and `warcinfo`
([source](https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/extract/WATExtractorOutput.java));
this is why the WAT has exactly 3 x 21,174 + 1 records. Only the record derived
from the `response` carries `HTTP-Response-Metadata` and `HTML-Metadata`.
Common Crawl's own reference consumer,
[`cc-pyspark/wat_extract_links.py`](https://raw.githubusercontent.com/commoncrawl/cc-pyspark/main/wat_extract_links.py),
navigates
`record['Envelope']['Payload-Metadata']['HTTP-Response-Metadata']['HTML-Metadata']`,
reads `Head.Link`, `Head.Metas`, `Head.Scripts`, `Head.Base` and `Links`, and
skips records whose `Envelope.WARC-Header-Metadata.WARC-Type` is not
`response`.

A real record from the downloaded WAT (pretty-printed and truncated) shows the
shape, including the HTTP headers and a favicon `Link` entry with `rel`:

```json
{"Container": {"Filename": "CC-MAIN-20260807101845-20260807131845-00000.warc.gz", "Offset": "126176", ...},
 "Envelope": {
  "Format": "WARC/1.0",
  "WARC-Header-Metadata": {"WARC-Type": "response", "WARC-Date": "2026-08-07T11:13:49Z",
                           "WARC-Target-URI": "http://272ku.com/272ku-movie/ribenyouma/2162614.html", ...},
  "Payload-Metadata": {
   "Actual-Content-Type": "application/http; msgtype=response",
   "HTTP-Response-Metadata": {
    "Response-Message": {"Status": "200", "Version": "HTTP/1.1", "Reason": "OK"},
    "Headers": {"Content-Type": "text/html", "Server": "cloudflare", ...},
    "HTML-Metadata": {
     "Head": {
      "Title": "...",
      "Metas": [{"name": "HTML@/lang", "content": "en"}, {"content": "IE=edge,chrome=1", "http-equiv": "X-UA-Compatible"}, ...],
      "Link": [{"path": "LINK@/href", "url": "/favicon.ico", "rel": "icon", "type": "image/x-icon"},
               {"path": "LINK@/href", "url": "/okle/css/app.css", "rel": "stylesheet"}, ...],
      "Scripts": [{"path": "SCRIPT@/src", "url": "https://g.alicdn.com/.../aliplayer-h5-min.js", "type": "text/javascript"}, ...]},
     "Links": [{"path": "DIV@/data-href", "url": "/"}, {"path": "FORM@/action", "url": "/e/search/index.php", "method": "post"},
               {"path": "A@/href", "url": "javascript:translatePage();", "text": "繁体中文"}, ...]}}}}}
```

Relative to this parser's targets, WAT therefore keeps: the full HTTP response
header map (so `Onion-Location` and `Content-Security-Policy` values survive),
every `href`/`src`/`action` URL in the document, the anchor text of every link
(up to 128 characters), `<meta>` `content` values, `<link>` entries with `rel`,
and the page title. It drops: all text that is not anchor text or title, inline
script bodies, comments, attribute values other than the ones listed, `data:`
URL payloads, and everything about non-HTML responses except their HTTP
headers.

### 3.4 WET: plain text of HTML pages only

Common Crawl states that WET files "only contain extracted plaintext" and
consist of "WARC metadata followed by plaintext content"
([Get Started](https://commoncrawl.org/get-started)); the formats blog post adds
that they contain "only the body text of web pages, extracted from the HTML and
excluding any HTML code, images, or other media"
([formats explained](https://commoncrawl.org/blog/web-archiving-file-formats-explained)).
In the generator,
[`WETExtractorOutput.java`](https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/extract/WETExtractorOutput.java)
processes only source records whose type is `response`, takes the text from
`Envelope.Payload-Metadata.HTTP-Response-Metadata.HTML-Metadata.Text`, and
writes it as a `conversion` record, copying `WARC-Target-URI`, `WARC-Date` and
the source record id (as `WARC-Refers-To`) and, when present,
`WARC-Identified-Content-Language`. The `Text` field is filled by
`handleTextNode` in `ExtractingParseObserver.java`, which appends each HTML
text node (with entities decoded and whitespace normalised) to a
`textExtract` buffer; script and style contents are handled by separate
handlers and are not appended.

Empirically (script in section 4.4), the primary segment's WET has 20,614
`conversion` records for 21,174 responses: 20,610 of them are for `text/html`
responses, plus one each for `text/plain`, `application/json`,
`application/xhtml+xml` and a response without `Content-Type`. None of the
191 PDF, 35 Atom, 17 XML or 21 of the 22 `text/plain` responses have a WET
record, and 211 `text/html` responses have none either (presumably pages whose
text extraction produced nothing). Relative to this parser's targets, WET keeps
only onions that appear as visible text in an HTML page. It has no HTTP
headers, no attribute values (`href`, `content`), no markup, and therefore no
favicon information of any kind.

## 4. Empirical results

### 4.1 Method

Five `(WARC, WAT, WET)` triples from CC-MAIN-2026-34 were downloaded, one
"primary" segment kept on disk and four more chosen by taking lines 20001,
40001, 60001 and 80001 of `wat.paths.gz` (different segments and crawl days)
and streamed through the analysis without keeping decompressed copies. The
`warc.paths.gz` in the repository is for CC-MAIN-2026-12, so it was not used;
the WARC path was derived from the WAT path by substituting `/wat/` with
`/warc/` and `.warc.wat.gz` with `.warc.gz`, and all URLs returned HTTP 200.

Onion matching was reproduced three ways and cross-checked:

- `LC_ALL=C grep -aoE '\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b'`, the regex from
  `src/lib.rs` (`parse_warc_bytes`) in the C locale so `\b` has ASCII
  semantics, as `is_word_boundary_byte` in `src/onion_search.rs` does.
- `rg -a -o -N -I` with the same pattern; ripgrep uses the same Rust `regex`
  crate the `bytes` strategy uses.
- A Python re-implementation of `search_memchr` (find `.onion`, count the run
  of `[a-z2-7]` before it, require exactly 16 or 56, require non-word bytes on
  both sides) applied record by record so each match can be attributed to a
  WARC record type and a position inside the record
  (`analyze_warc.py`, `analyze_wat.py`, `aggregate.py` in the scratchpad, paths
  in section 7).
- The real binary, `target/release/onion-crawler <one-line paths file> -l 1 -j 1
  --output-dir <scratchpad dir>`, with the downloaded file symlinked into
  `download/` so the "Already downloaded" branch was taken. `output/` in the
  repository was never touched (the CLI has `--output-dir`).

All three counting methods agreed on every file (for the primary WARC:
grep 22/9, rg 22/9, Python 22/9). The real parser reported 9 unique onions with
13 `(url, archive)` source entries for the primary WARC in both the `memchr`
and `bytes` strategies (22 matches collapse to 13 because the same onion often
appears several times on one page), so the grep counts are a faithful proxy
for the extractor.

### 4.2 Onion counts and set differences

| Segment (paths-file line) | WARC MB | WAT MB | WET MB | WARC total/unique | WAT total/unique | WET total/unique | unique in WARC not WAT | unique in WARC not WET |
|---|---|---|---|---|---|---|---|---|
| seg 00000 (line 1) | 909.1 | 151.4 | 63.9 | 22 / 9 | 22 / 9 | 4 / 2 | 0 | 7 |
| line 20001 | 911.6 | 151.3 | 62.4 | 22 / 16 | 20 / 14 | 9 / 9 | 2 | 7 |
| line 40001 | 973.7 | 153.0 | 64.4 | 23 / 11 | 19 / 9 | 4 / 2 | 2 | 9 |
| line 60001 | 938.2 | 149.5 | 63.0 | 12 / 8 | 8 / 5 | 4 / 3 | 3 | 5 |
| line 80001 | 941.4 | 153.5 | 65.1 | 25 / 18 | 23 / 16 | 11 / 10 | 2 | 8 |
| **Total** | **4,674.1** | **758.6 (16.2 %)** | **318.8 (6.8 %)** | **104 / 38** | **92 / 35** | **32 / 13** | **3** | **25** |

Nothing was found in WAT or WET that was absent from the WARC (WAT minus WARC =
0, WET minus WARC = 0), and nothing in the WARC was absent from the union of
WAT and WET (WARC minus (WAT or WET) = 0). Stated as loss: WAT alone loses
3 of 38 unique onions (7.9 %) and 12 of 104 matches (11.5 %); WET alone loses
25 of 38 unique (65.8 %) and 72 of 104 matches (69 %); WAT plus WET loses
nothing in this sample. Record counts across the five segments: 319,322 WARC
records (106,439 responses, of which 104,584 HTML), 319,327 WAT records,
103,682 WET conversion records. The full per-segment output is in
`extra/*.summary.json` and the aggregate in the output of `aggregate.py`.

### 4.3 Where the onions live, and which format keeps them

Attribution of all 104 WARC matches (Python record-level pass; every match was
in a `response` record, none in `request` or WARC `metadata` records):

| Location in the WARC response record | Matches | Kept by WAT? | Kept by WET? |
|---|---|---|---|
| HTTP response header (`Onion-Location` 49, `Content-Security-Policy` 6) | 55 (52.9 %) | yes, `HTTP-Response-Metadata.Headers.*` | no |
| Visible text inside an `<a>` element | 20 (19.2 %) | yes, `HTML-Metadata.Links[].text` | yes |
| Visible text not inside an `<a>` (`<b>`, `<strong>`, `<div>`) | 12 (11.5 %) | **no** | yes |
| `<a href="...">` attribute | 11 (10.6 %) | yes, `HTML-Metadata.Links[].url` | no |
| `<meta http-equiv="onion-location" content="...">` | 6 (5.8 %) | yes, `HTML-Metadata.Head.Metas[].content` | no |
| Inline `<script>`, HTML comment, `<style>`, non-HTML payload, request record | 0 | no | no |

The WAT-side attribution agrees exactly: 49 matches under
`Headers.onion-location` / `Onion-Location` / `Onion-location` (the header name
is kept with the server's capitalisation, so a case-insensitive key lookup is
needed), 6 under `Headers.content-security-policy`, 20 under `Links[].text`,
11 under `Links[].url`, 6 under `Head.Metas[].content`; 92 in total.

The dominance of `Onion-Location` is expected: it is the Tor Project's
mechanism for a clearnet HTTPS site to advertise its onion mirror, either as
an HTTP header (`Onion-Location: http://<address>.onion/...`) or as
`<meta http-equiv="onion-location" content="...">`, and it "must be a valid
URL with http: or https: protocol and a .onion hostname"
([Tor Project, Onion-Location](https://community.torproject.org/onion-services/advanced/onion-location/)).
In the sample it is used by voanews.com, svoboda.org, krymr.com, taz.de,
soylentnews.org and mirror.b10c.me. Sample contexts from the primary WARC
(`analyze_warc.py`, context trimmed):

```text
http-response-header | voanews5aitmne6gs2btok… | https://amharic.voanews.com/a/... | onion-location: https://amharic.voanews5aitmne6gs2btokcacixclgfl43cv27sirgbauyyjylwpdtqd.onion/a/...
http-response-header | 7rmath4ro2of2a42.onion  | https://soylentnews.org/comments.pl?... | ...src 'self' https://soylentnews.org http://7rmath4ro2of2a42.onion https://checkout.stripe.com; frame-src ...
attribute meta@content | soylentqarvi3ikkzpp7fn… | https://soylentnews.org/comments.pl?... | <meta http-equiv="onion-location" content="http://soylentqarvi3ikkzpp7fn4m5pxeeonbv6kr4akgkczqethjfhmalhid.onion" />
attribute a@href     | ossplanetnyou5xifr6liw… | https://e04.us/almalinux/?C=S&O=D | <li>Aliases: <a href="http://mirror.ossplanetnyou5xifr6liw5vhzwc2g2fmmlohza25wwgnnaw65ytfsad.onion">http://mirror.ossplanet…
```

The three onions WAT misses are all plain visible text that is not a link, and
all three are recovered by WET:

```text
line20001 | visible-text | wlchatc3pjwpli5r.onion | https://www.wikileaks.org/plusd/cables/1975USUNN04807_b.html
   ctx: ...use our secured webchat available at <b>http://wlchatc3pjwpli5r.onion</b></p>
line20001 | visible-text | ibfckmpsmylhbfovflajicjgldsqpc75k5w454irzwlh7qifgglncbad.onion | https://www.wikileaks.org/plusd/cables/...
   ctx: <div class="onion-url">http://ibfckmpsmylhbfovflajicjgldsqpc75k5w454irzwlh7qifgglncbad.onion </div>
line60001 | visible-text | keybase5wmilwokqirssclfnsqrjdsi7jdir5wy7y7iu3tanwmtp6oid.onion | https://keybase.io/kevinclev
   ctx: Available within Tor at <strong>http://keybase5wmilwokqirssclfnsqrjdsi7jdir5wy7y7iu3tanwmtp6oid.onion</strong>
```

Conversely, everything WET misses is either an HTTP header (55), an `href`
(11) or a `<meta content>` (6); WET's four matches in the primary segment are
the plain-text renderings of the `e04.us` mirror list and the
`magazconstruction.com` comment, as expected.

### 4.4 Favicons

Counts across the five segments (WARC side: HTML responses whose body contains
a `<link>` whose `rel` is one of the four values in
`favicon_search::FAVICON_REL_VALUES`; WAT side: response-derived records whose
`Head.Link` array has an entry with such a `rel`):

| | WARC | WAT |
|---|---|---|
| HTML pages / records with HTML-Metadata | 104,584 | 103,841 |
| Pages with a favicon-`rel` `<link>` / `Head.Link` entry | 86,231 | 86,120 (99.9 %) |
| Pages with `<meta name="msapplication-TileImage">` / `Head.Metas` entry | 31,896 | 31,861 (99.9 %) |
| Favicon hrefs that are `data:` URIs | 1,478 | 1,528 (all truncated, see below) |
| `Head.Link` entries in total / with a `rel` key | | 2,419,742 / 2,402,366 (99.3 %) |

`rel` values in the WAT `Head.Link` array for the primary segment, most common
first: `alternate` 204,576, `stylesheet` 204,524, `icon` 25,789, `preload`
24,640, `dns-prefetch` 19,024, `apple-touch-icon` 17,299, `canonical` 15,036,
`preconnect` 12,418, `modulepreload` 10,783, `shortcut icon` 6,770. The favicon
`url` values are stored as written in the page (`/favicon.ico`,
`favicon.ico`, absolute URLs), so the existing `resolve_url` logic in
`src/favicon_search.rs` is still needed, with `Envelope.WARC-Header-Metadata.WARC-Target-URI`
(or the outer `WARC-Target-URI`, which is identical) as the base and `Head.Base`
when present. Sample entries with `grep -aoE '"Link":\[[^]]{0,1500}\]' ... | grep -i icon`:

```json
{"path":"LINK@/href","url":"/favicon.ico","rel":"icon","type":"image/x-icon"}
{"path":"LINK@/href","url":"http://301pixel.eu/wp-content/uploads/2020/10/cropped-jl-180x180.png","rel":"apple-touch-icon"}
{"path":"LINK@/href","url":"favicon.png","rel":"apple-touch-icon"}
```

Inline favicons are the one target WAT cannot serve. In the primary WARC,
198 favicon `href`s start with `data:`; 129 of them are the empty placeholder
`data:,` (which `favicon_search::process_favicon_value` already discards
because the base64 payload is empty), leaving 65 pages with a real inline icon
(payload up to 3,924 characters; prefixes `data:image/png;base64,` 22,
`data:;base64,` 17, `data:image/svg+xml,` 10, `data:image/x-icon;base64,` 10,
`data:image/svg+xml;base64,` 5). In the WAT, the 208 favicon `Head.Link`
entries whose `url` starts with `data:` take only 10 distinct values, the
longest is 37 characters, and not one has anything after the comma: the values
are `data:,`, `data:image/png;base64,`, `data:;base64,`, `data:image/svg+xml,`
and so on, exactly what `trimDataUrl` (section 3.3) produces. The raw counts of
the string `data:image` tell the same story: 62,236 occurrences in the WARC,
44,109 in the WAT (all truncated stubs), 56 in the WET (text that happened to
contain the literal).

### 4.5 The parser on WAT and WET files today

Running the actual binary on the WAT and WET files (paths file with one line,
`-l 1 -j 1`, `--output-dir` in the scratchpad) crashes immediately with the
default `memchr` strategy and with `bytes`:

```text
[CC-MAIN-20260807101845-20260807131845-00000.warc.wat.gz] Parsing (memchr)...
thread 'tokio-rt-worker' (725702) has overflowed its stack
fatal runtime error: stack overflow, aborting
```

The `mmap` strategy, whose `WarcSliceIter` skips non-response records with
`continue` inside a `loop`, runs to completion and reports 0 onions and 0
favicons for both files (2.2 s for the WAT, 1.0 s for the WET), which is the
expected behaviour of a parser that only looks at `response` records. The
difference is `src/warc_parser.rs:164`, where `WarcRecordIter::next` skips a
non-response record with `return self.next();`. The comment above it says the
tail recursion "is fine — Rust will optimize it"; Rust does not guarantee
tail-call elimination, and with 63,523 consecutive `metadata` records (WAT) or
20,614 consecutive `conversion` records (WET) the recursion exhausts the
thread's stack. Real WARC files never trigger it because record types
alternate.

### 4.6 Timing floors

On the test machine (Apple M3 Max, 16 cores), single-threaded:

| | WARC | WAT | WET |
|---|---|---|---|
| Download (measured, 5 segments) | 14.8 to 24.6 s (39 to 61 MB/s) | 1.5 to 4.5 s | 0.7 to 2.5 s |
| `gzcat > /dev/null` | 3.38 s | 0.70 s | 0.30 s |
| `rg -c <onion regex>` over the decompressed bytes | 0.34 s | 0.08 s | 0.02 s |
| `gzcat \| rg -c` (streaming) | 3.66 s | 0.79 s | 0.32 s |
| `onion-crawler` parse phase (`memchr`, includes favicon scan) | 5.1 s | crash (see 4.5) | crash (see 4.5) |

`documentation/PROGRESS.md` records that timing was added to the pipeline but
contains no measured throughput numbers, so the figures above are the only
ones available. They show the local pipeline is download-bound by roughly 3x
to 5x, and that even the parse phase is dominated by gzip decompression (3.4 s
of the 5.1 s), not by the onion or favicon scan.

### 4.7 At scale: 99 Shards, `cc-extract` against itself

Added 2026-10-29. The five segments above held 38 onions, too few to size a
loss. This run measures it with the binary itself, over 100 Shards.

**Method.**

- **Sample:** 100 Shards of CC-MAIN-2026-34, one per segment (every
  1,000th line of `wat.paths.gz`), so they spread over the crawl's days.
- **Two runs of `cc-extract`** over the same paths file, same machine,
  `-t memory`, default `-j`, default kinds (`onion,favicon`), each into its
  own `--output-dir`:
  - `--formats warc`;
  - the default Plan, WAT + WET.
- **One Shard failed** in the WARC run (its error message was not kept), so
  both runs are compared over the 99 Shards each one marked done in
  `processed.log`.
- **Comparison:** sets of `(Artifact, page_url, shard)` Sightings from
  `onions.json` and `favicons.json`.
- **Where each difference lives:** for every onion Sighting one run found and
  the other did not, the page's WARC `response`, WAT `metadata` and WET
  `conversion` records were read back from that Shard's three Archives (the
  Archives streamed, only those pages' records kept), and every occurrence of
  the address located. For favicons, 60 differing pages were sampled the same
  way: 15 from each group in the favicon section below, all from 4 Shards.

**Time.** Wall clock 23 min 25 s for WARC, 6 min 54 s for WAT + WET (3.4x).
Per Shard, as `cc-extract` reports it with jobs running side by side:

| | WARC | WAT + WET |
|---|---|---|
| Download | 208.5 s | 53.6 s |
| Parse | 6.3 s | 4.3 s |

Both runs are download-bound. Parsing WAT + WET is only a third faster than
WARC for a quarter of the bytes: decompression shrinks with the bytes (3.4 s
against 1.0 s in 4.6), but WAT's JSON is decoded record by record, which costs
more per byte than WARC's byte scan, and WAT has as many records as the WARC.

**Onions.**

| | WARC | WAT + WET | Both | Only WARC | Only WAT + WET |
|---|---|---|---|---|---|
| Distinct onions | 215 | 209 | 208 | 7 (3.3 %) | 1 |
| Sightings | 1,470 | 1,450 | 1,449 | 21 (1.4 %) | 1 |

Every one of the 21 Sightings only WARC found sits where WAT and WET keep
nothing; in each, neither the WAT nor the WET record of the page holds the
address:

| Where on the page | Sightings | Onions (site) |
|---|---|---|
| Inline JavaScript | 11 | `nnmclub2vv…4id.onion` (nnmclub.to, 10: a footer link written by a script), `gfonxmohva…fyd.onion` (i2p.net) |
| JSON inside `<script>` | 7 | `xhamsteropoffvdm.onion` (xhamster, 5: a site configuration listing its own domains), `facebookcorewwwi.onion` (addons.mozilla.org, `application/json` state), `silkroad6ownowfk.onion` (reason.com, JSON-LD) |
| An attribute WAT does not keep | 2 | `5dk6evicej…oqd.onion` (cheeserobot.org, `<input value="…@….onion:9735">`), `marvamxeq4…rad.onion` (solucionesmarva.com, `<button data-tor-url="…">`, and an inline script) |
| HTML comment | 1 | `jthnx5wyvjvzsxtu.onion` (9ch.net, a commented-out link; WAT + WET found this address on other pages) |

None came from a JSON escape in WAT, a truncated record, a non-HTML payload or
a request record. The one Sighting only WAT + WET found is the page URL itself
(a web gateway host `<address>.onion.ly`): WAT repeats the WARC headers, while
WARC is searched in the HTTP response only.

So the 0 of 38 lost in section 4.2 does not hold at scale: the default Plan
loses 3.3 % of distinct onions, by construction, and nothing in this parser
can win them back from WAT or WET. Several of the lost addresses are a site's
own Tor mirror (nnmclub, xhamster, i2p, solucionesmarva), which sites tend to
put in scripts and buttons rather than in plain links.

**Favicons.**

| | WARC | WAT | Both | Only WARC | Only WAT |
|---|---|---|---|---|---|
| Distinct favicons | 3,205,879 | 3,222,509 | 3,120,722 | 85,157 | 101,787 |
| Sightings | 4,858,279 | 4,895,999 | 4,741,057 (97.6 % of WARC) | 117,222 | 154,942 |
| Pages with a favicon | 1,671,605 | 1,682,222 | 1,669,262 | 2,343 | 12,960 |

Most differences are the same favicon, written differently by the two sides,
and WAT's form is the right one:

- **HTML entities.** 94,204 of the 117,222 Sightings only WARC found (80 %)
  hold an HTML entity the WARC scanner left undecoded, where WAT, as a browser
  does, decoded it: `…?fit=32%2C32&#038;ssl=1` against `…?fit=32%2C32&ssl=1`.
  The most frequent are `&#038;` (WordPress), `&amp;`, `&#x2F;` (a path
  written `&#x2F;&#x2F;cdn…` then resolves as a relative one), `&#x3D;` and
  `&#47;`.
- **Unquoted values cut at `/`.** 2,512 end in `/https:` or `/http:`: the
  scanner ends an unquoted value at the first `/`, so
  `href=https://cdn.example/favicon.ico` gives `https:`, resolved against the
  page. HTML ends an unquoted value only at whitespace or `>`.

The 60 sampled pages, by group (a page can show more than one cause):

| Group | Pages | Cause |
|---|---|---|
| Favicons only WAT found, on pages where WARC found none | 15 | WARC scanner: unquoted value cut at `/` (9), newline after `<link` (6), no space between attributes (2), entity in `rel` (1) |
| Favicons only WAT found, on pages where WARC found others | 15 | WARC scanner: an earlier `<link>` without a closing `>` within 4 KB, counting quotes, stops the scan (11); no space between attributes (1); newline after `<link` (1); unexplained (2) |
| Favicons only WARC found, on pages where WAT found none | 15 | WARC scanner false positive, the tag inside an HTML comment (6) or a `<script>` (2); WAT's parser did not list well-formed icon tags (6, cause not determined; on 4 of them WAT's `Head` holds no `Link`, `Meta` or `Title` at all); WAT record without `HTML-Metadata` (1) |
| Favicons only WARC found, on pages where WAT found others | 15 | WARC scanner false positive, the tag inside an HTML comment (14); unexplained (1) |

So for favicon URLs, WAT is today the more accurate of the two. The WARC
scanner misses tags a browser reads and reads tags a browser ignores; WAT
misses the icon tags of a few pages its own parser fails on.

**Recommendation on the default Plan.** The data does not settle it alone:
it weighs 3.3 % of distinct onions, mostly sites' own mirrors, against about
4 times the bytes (3.4 times the wall clock on this machine, less where the
link is faster). Two points hold either way:

- The WARC favicon scanner's defects above are worth fixing first. If onions
  move to WARC, the cheapest Plan serving `onion,favicon` is WARC alone, and
  favicons would then come from the scanner that is less accurate today.
- Keeping WAT + WET as the default stays sound for favicons; a run that wants
  every onion it can get passes `--formats warc`.

## 5. Implementation implications

**Fix the recursion first.** Replace the `return self.next();` at
`src/warc_parser.rs:164` with a `loop { ... continue; }` around the record
parse, mirroring `WarcSliceIter`. This is a prerequisite for feeding any WAT or
WET file to the streaming strategies and is a latent robustness bug for WARC
files too (a long run of `revisit` or `metadata` records would also trigger it).
Add a test with a few thousand consecutive non-response records.

**Record selection.** The iterator currently accepts only
`WARC-Type: response`. For WAT it needs to accept `metadata` records with
`Content-Type: application/json`; for WET, `conversion` records with
`Content-Type: text/plain`. Selecting by file-name suffix (`.warc.wat.gz`,
`.warc.wet.gz`, `.warc.gz`) is the simplest way to decide which record type a
given archive should yield, and keeps a plain WARC's own `metadata` records
(crawler info such as `fetchTimeMs`) excluded as today.

**Onion extraction from WAT needs no JSON parser.** Because onion addresses
consist only of `[a-z2-7]` and `.`, they are never escaped in JSON, and they
are delimited by `"`, `/`, `:` or space, all of which are non-word bytes, so
`search_memchr` over the raw JSON record body produces exactly the same
matches as over the WARC record (22 = 22 in the primary segment, 92 matches
attributed to the expected JSON paths across five segments). Two details
change: the WAT has three records per page, so the request- and
metadata-derived records should be skipped cheaply (they are small; a
`memmem` for `"HTTP-Response-Metadata"` or `"WARC-Type":"response"` in the
body suffices, or simply let the `(url, archive)` de-duplication absorb them),
and `OnionSource.date` must come from `Envelope.WARC-Header-Metadata.WARC-Date`
inside the JSON rather than from the record's own `WARC-Date`, which is the WAT
generation time. `WARC-Target-URI` can be taken from the record header as now.

**Onion extraction from WET** works unchanged apart from record selection: the
outer `WARC-Target-URI` and `WARC-Date` are the page URL and crawl date.

**Favicon URLs from WAT require structured access.** The `Head.Link` array
must be read for entries whose `rel` is a favicon value and whose `url` is
taken, and `Head.Metas` for `name` = `msapplication-TileImage`. Options are a
real JSON parse with `serde_json` (`RawValue` or a `Deserialize` struct for
`Envelope.Payload-Metadata.HTTP-Response-Metadata.HTML-Metadata.Head` only,
ignoring the large `Links` array), or a targeted byte scan for `"rel":"icon"`
and friends followed by hand-parsing the enclosing `{...}` object, in the same
spirit as `scan_link_tags`. Relative URLs still need `resolve_url` against the
page URL (and `Head.Base` if present). The root `favicon.ico` fallback is
unaffected. Note that WAT normalises attribute names to lower case in the JSON
keys (`rel`, `url`, `type`) but keeps the original casing of the values, so the
existing `eq_ignore_ascii_case` comparison should stay.

**Inline favicons cannot come from WAT or WET.** If they remain a requirement,
one option is a hybrid: process WAT+WET for onions and favicon URLs, and
process the WARC only for a sample of segments to collect inline favicons; the
`Container.Offset` field in each WAT record gives the byte offset of the
corresponding record inside the compressed WARC, so individual records can be
fetched with an HTTP `Range` request without downloading the whole file
(`"Container": {"Filename": ..., "Offset": "126176", "Gzip-Metadata": {"Deflate-Length": "7003", ...}}`).

**Expected speedup.** Download volume per page drops to 16.2 % (WAT) or 23.0 %
(WAT+WET) of the WARC; decompression work drops in the same proportion
(3.38 s to 0.70 + 0.30 s per segment). Since the pipeline is download-bound
locally and the `-j` concurrency is already capped by CPU and RAM, the
end-to-end throughput gain for a full crawl should be close to the byte
reduction, roughly 4x to 6x, before any per-record savings. Crawl-wide this is
the difference between 84.78 TiB and 19.76 TiB (WAT+WET) or 13.92 TiB (WAT
only). Stream mode (`-m`) benefits most, since a WAT+WET pair per segment is
about 215 MB in memory instead of 900 MB.

**Reporting.** `records_scanned` semantics change (WAT yields three records per
page), and the `processed.log` file name scheme must distinguish the three
archive kinds so a WAT and its WARC are not confused as "already processed".

## 6. Open questions

- **Sample size.** 38 unique onions across 106,439 pages is a thin basis for a
  loss percentage. The qualitative result (WAT keeps headers, links, link text
  and meta content; WET keeps visible text; together they covered everything
  seen) is deterministic from the generator source, but the frequency of
  onions in inline scripts, comments and non-HTML payloads (JavaScript bundles,
  JSON APIs, PDFs) in the full crawl is unknown. A larger run over, say, 100
  WARC segments with the record-level attribution script would settle it.
  Settled by section 4.7: 3.3 % of distinct onions lost over 99 Shards.
- **Anchor-text truncation.** WAT caps `Links[].text` at 128 characters. A v3
  address (62 characters) inside a long link text could be cut. Not observed
  in the sample, but not excluded.
- **Header-name casing.** WAT stores HTTP header names as sent
  (`onion-location`, `Onion-Location`, `Onion-location` all occurred). A
  byte-level scan is unaffected; a JSON-key lookup must be case-insensitive.
- **Stability of the WAT schema.** The JSON layout is defined by
  `ia-web-commons` constants and has been stable for years, but Common Crawl
  could change extraction details (for example `trimDataUrl`) without notice.
- **211 HTML pages without a WET record.** Their cause was not investigated;
  if they are pages the HTML parser rejected, they are also likely to lack
  `HTML-Metadata` in the WAT (103,841 WAT records with HTML-Metadata versus
  104,584 HTML responses), which would be a small, systematic blind spot for
  both derived formats.
- **Rate limits.** Whether `data.commoncrawl.org` throttles differently for
  WAT/WET than for WARC was not tested; download speeds in the sample varied
  between 26 and 102 MB/s regardless of format.

## 7. Sources

Primary documentation:

- Common Crawl, "Get Started" (format overview, suffixes, WAT/WET descriptions):
  https://commoncrawl.org/get-started
- Common Crawl blog, "Web archiving file formats explained":
  https://commoncrawl.org/blog/web-archiving-file-formats-explained
- Common Crawl blog, "August 2026 crawl archive now available" (2.14 billion
  pages, 360 TiB, per-format TiB):
  https://commoncrawl.org/blog/august-2026-crawl-archive-now-available
- Common Crawl, CC-MAIN-2026-34 index page (file counts and sizes per format):
  https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-34/index.html
- IIPC, WARC 1.1 specification (record types 5.5, 6.3, 6.6, 6.8;
  WARC-Refers-To 5.11; Content-Length 5.2; Annex B file naming):
  https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/
- commoncrawl/ia-web-commons, `ExtractingParseObserver.java` (link extractor
  table, `LinkTagExtractor`, `MetaTagExtractor`, `trimDataUrl`, `MAX_TEXT_LEN`,
  `handleScriptNode`, `handleRemarkNode`, `handleTextNode`):
  https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/resource/html/ExtractingParseObserver.java
- commoncrawl/ia-web-commons, `ResourceConstants.java` (JSON key names):
  https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/resource/ResourceConstants.java
- commoncrawl/ia-web-commons, `HTMLMetaData.java` (which method fills which key):
  https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/resource/html/HTMLMetaData.java
- commoncrawl/ia-web-commons, `WETExtractorOutput.java` (conversion records,
  text source, response-only):
  https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/extract/WETExtractorOutput.java
- commoncrawl/ia-web-commons, `WATExtractorOutput.java` (metadata records for
  every source record):
  https://raw.githubusercontent.com/commoncrawl/ia-web-commons/master/src/main/java/org/archive/extract/WATExtractorOutput.java
- commoncrawl/cc-pyspark, `wat_extract_links.py` (reference WAT consumer):
  https://raw.githubusercontent.com/commoncrawl/cc-pyspark/main/wat_extract_links.py
- Tor Project, "Onion-Location":
  https://community.torproject.org/onion-services/advanced/onion-location/

Secondary:

- common-crawl Google Group, "The size of warc, wet, wat files" (2015
  estimates): https://groups.google.com/g/common-crawl/c/5Jx9uIfYMqA

Not reachable: the Internet Archive's "WAT Overview and Technical Details" wiki
page (`webarchive.jira.com/wiki/spaces/Iresearch/pages/13467719/...`) now
redirects to an Atlassian login, and the `ia-web-commons` README does not
describe WAT or WET; the Java sources above were used instead.

Data and scripts used, kept in the session scratchpad
(`/private/tmp/claude-501/-Users-chrisr3d-Francis-PMF-common-crawl-parser/c8702a04-c688-44ea-b345-61e30522743f/scratchpad/cc/`):

- `CC-MAIN-20260807101845-20260807131845-00000.warc.gz`, `.warc.wat.gz`,
  `.warc.wet.gz` (compressed primary triple, 1.12 GB) and the decompressed
  `.warc.wat` and `.warc.wet`; the 3.95 GB decompressed `.warc` was deleted to
  free disk space (regenerate with `gzcat`).
- `download.log`, `decompress.log`; `paths.warc`, `paths.wat`, `paths.wet`
  (one-line paths files for the parser runs); `out_warc/`, `out_warc_bytes/`,
  `out_wat_mmap/`, `out_wet_mmap/` (parser output directories).
- `analyze_warc.py`, `analyze_wat.py`, `aggregate.py`; per-segment results in
  `extra/` (`*.summary.json`, `*.matches.jsonl`, `*.onions.{warc,wat,wet}.txt`,
  `batch.log` with download timings for the four extra segments). The four
  extra compressed triples were deleted after processing.

Local code referenced: `src/onion_search.rs` (`search_memchr`,
`is_word_boundary_byte`), `src/favicon_search.rs` (`FAVICON_REL_VALUES`,
`process_favicon_value`, `resolve_url`), `src/warc_parser.rs` (line 164),
`src/lib.rs` (`parse_warc_memchr`, `extract_favicons_from_record`),
`src/main.rs` (`--output-dir`).
