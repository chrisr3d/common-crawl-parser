# Features

What `cc-extract` (v2.0.0) does today, feature by feature. `README.md` covers
building and running, `PROGRESS.md` covers the Rust concepts behind each step.
This file covers behaviour: what each feature reads, what it writes, and where it
stops short. Terms (Shard, Archive, Format, Artifact kind, Sighting, Plan) are
defined in `GLOSSARY.md`.

## At a glance

One run takes a Common Crawl paths file, works out which Shards still need which
of the requested Artifact kinds, downloads for each kind the Archives that find
the most of it, and writes what it finds to a kvrocks store (see section 9):

- `onion`: every `.onion` address found, with the pages it appeared on.
- `favicon`: every favicon URL an HTML page declares, with the pages that
  declare it.
- `inline-favicon`: every favicon image a page embeds as a base64 `data:` URI,
  identified by its SHA-256, with its media type, its SHA-1, MD5 and Shodan
  hash, and the pages that embed it; with `--save-images`, the image itself, on
  disk.

`-e` / `--extract` picks the kinds (default `onion,favicon`). All requested kinds
are extracted in the same pass over each Archive.

```text
paths file ──▶ schedule the Slice's Shards (offset, limit; skip the kinds done or given up)
           ──▶ plan each Shard's Formats (per kind, those finding the most)
           ──▶ download its Archives (to disk or to memory) ┐ up to --jobs Shards
           ──▶ parse them on the blocking thread pool       ┘ in flight at once
           ──▶ per kind done, one Shard at a time: write its Sightings to the
               store, then mark the (Shard, kind) pair done there
```

## 1. Input: the paths file

The positional argument is a paths file as Common Crawl publishes it
(`warc.paths.gz`, `wat.paths.gz` or `wet.paths.gz` for a Crawl): one Archive path
per line, relative to `https://data.commoncrawl.org/`. Plain text and gzip are
both accepted; gzip is detected by the `.gz` extension. Blank lines are ignored.
A file that can't be read to its end, such as a `.gz` cut short by an
interrupted download, stops the run with exit 1 before anything is scheduled.

Any of the three files will do: they list the same Shards, and the paths of a
Shard's other Archives are derived from the line by swapping the Format's
directory and suffix:

```text
crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/wat/CC-MAIN-…-00000.warc.wat.gz
crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/warc/CC-MAIN-…-00000.warc.gz
```

The Dataset is read from the path's prefix: `crawl-data/CC-MAIN-<crawl>/` or
`crawl-data/CC-NEWS/`. A line in neither is reported and skipped.

Shards are selected in this order:

1. The Slice: `--offset N` drops the first N paths, and `--limit M` keeps the
   M paths after them (default: all the rest). Blank lines don't count. No
   path after the Slice is read.
2. Every path of the Slice is considered. A Shard whose every requested kind
   is already marked done for it in the store is skipped. Otherwise it is
   scheduled for the missing kinds only, less those given up (section 9).
   A line that can't be used is reported and skipped, still counting toward
   `--limit`.

Running the same command again covers the same Slice: after exit 3, it
retries the Slice's undone pairs, and once they are all done it schedules
nothing. To go on to the next paths, move `--offset`.

## 2. Artifact kinds, Format requirements and Plans

Code: `src/artifact.rs` (requirements), `src/plan.rs` (planner),
`src/format.rs` (Formats and Datasets).

Each kind accepts some combinations of Formats (its Format requirement),
listed from the one that finds the most to the one that finds the least:

| Artifact kind | Accepted combinations, finding the most first | Default |
|---|---|---|
| `onion` | WARC, then WAT + WET | on |
| `favicon` | WARC, then WAT | on |
| `inline-favicon` | WARC | off |

For each Shard, every kind still to do for it reads the first of its
combinations made of Formats the Shard's Dataset publishes. The Shard's Plan
is what the kinds read together, and only those Archives are downloaded.
CC-MAIN publishes all three Formats and CC-NEWS WARC only, so by default every
kind reads WARC on both (~1 GB per Shard).

The order rests on what each combination found over 100 Shards of
CC-MAIN-2026-34 (`RESEARCH-warc-wat-wet.md`, sections 4.7 and 4.8). WARC
finds every onion WAT + WET find, and more: about 2 % of live onions sit
where only WARC keeps them (inline scripts, attribute values, comments). For
favicon URLs, WAT adds 309 Sightings to WARC's 5.08 million, nearly all its
own misreadings, and misses 3,564 of WARC's (see Known limitations). The
size of the Archives chooses nothing: WAT + WET is
about a quarter of WARC's download (~240 MB per Shard), one option away
(`--formats wat,wet`). The estimated sizes (WARC ~1 GB, WAT ~170 MB, WET
~70 MB) only budget RAM for `-t memory` (section 8).

`--formats warc,wat,wet` forces the Formats a run may download for every
Shard. It is rejected at startup if they can't serve a requested kind
(`cannot extract favicon from wet: it needs warc or wat`), and when a Shard is
planned if its Dataset doesn't publish one of them. The same rule applies
inside them: each kind reads the first of its combinations made of forced
Formats, and a forced Format no kind reads is not downloaded.

| `--formats` | `onion` reads | `favicon` reads | `inline-favicon` reads |
|---|---|---|---|
| none (default) | WARC | WARC | WARC |
| `wat,wet` | WAT + WET (~240 MB) | WAT (~170 MB) | rejected |
| `warc,wat` | WARC | WARC: WAT is not downloaded | WARC |
| `wat` | rejected | WAT | rejected |

A kind reading several Archives gets the union of what each one gave: Sightings
are not joined record by record. A (Shard, kind) pair is done only when every
Archive that kind reads has been downloaded and parsed: inside `--formats
wat,wet`, a failed WET Archive leaves `onion` undone but still lets `favicon`
finish from WAT.

A kind whose combination reads a given-up Archive (section 9) reads instead
its next combination avoiding every given-up Archive of the Shard, inside the
forced Formats if any: less data beats none. It is left out, given up, only
when no combination is left. With the WARC given up, `onion` reads WAT + WET,
`favicon` WAT, and `inline-favicon` is given up; with the WET given up too,
`onion` is given up as well. Since the Plan depends on the kinds still to do
and on the Shard's given-up Archives, two Shards of one run can have
different Plans.

## 3. Download

Each Archive is fetched over HTTPS with `reqwest` (rustls, no OpenSSL). One HTTP
client is shared by all jobs so connections are reused. Progress is printed every
10 MB. A Shard's Archives are downloaded one after the other; Shards download
concurrently.

Where the bytes go depends on the Transport (`-t` / `--transport`, see the next
section):

- **`disk` and `mmap` (default `disk`).** The Archive is streamed to
  `download/<file name>.<process id>.part`, under the current directory, and
  renamed to `download/<file name>` once the body is complete. When the server
  sent a `Content-Length`, the byte count must match it, or the download fails.
  If `download/<file name>` already exists, the download is skipped and the
  existing file is parsed: only a complete Archive ever gets that name, so a
  download cut short (a network error, a killed process) is fetched again on the
  next run. `-d` / `--delete` removes each Archive of the Shard once it has
  parsed.

  A failed download removes its `.part` file; a killed process leaves it behind.
  No run reads a `.part` file, so it is safe to delete once no run uses that
  `download/`. The process id in the name keeps processes on one machine that
  share a `download/` from writing into the same file when they reach the same
  Shard. Process ids are unique per machine only: processes on several nodes
  sharing a `download/` over a network filesystem could still collide (the
  SLURM example uses `-t memory`, which writes nothing there).
- **`memory`.** The Archive is collected into a `Vec<u8>` (pre-sized from
  `Content-Length`) and handed to the parser without touching the disk.

A download that stops receiving data fails, on every Transport. Connecting may
take 30 s, and the response headers must arrive within 60 s of the request,
connecting included; then each chunk of the body must arrive within 60 s of
the one before. When nothing arrives for that long, the download fails like
any other, with
`Download error: no data received for 60 s`: on `disk` and `mmap` its `.part`
file is removed, so nothing appears at the Archive's name; the kinds reading
that Archive are left undone, the run carries on with the other Shards and
exits with 3, and the next run downloads the Archive again, a timeout never
counting toward giving it up (section 9). The wait starts
over with each chunk, so a slow download that keeps receiving data is never
cut, however long it takes in all. A connection whose peer is gone is already
failed by TCP keepalive (on in `reqwest`: a probe after 15 s idle, then every
15 s, 3 unanswered in a row fail it, about a minute in all); the 60 s read
timeout catches a peer that still answers the probes but sends nothing. The
bound is fixed, with no option to change it.

## 4. Reading records

Code: `src/warc_parser.rs` (records), `src/page_record.rs` (pages), `parse_archive`
in `src/lib.rs`.

All three Formats are multi-member gzip files of WARC records, decompressed with
`flate2` (`zlib-ng` backend). Each Format keeps its pages in one record type,
and the parser reads only that one, skipping the bodies of the others without
allocating for them:

| Format | Record read | What a page record gives the extractors |
|---|---|---|
| WARC | `response` | The record block, i.e. the whole HTTP response (status line, headers, body), with `WARC-Target-URI`, `WARC-Date` and `WARC-Identified-Payload-Type` |
| WAT | `metadata` | The record's JSON, and the `<base>`, `<link>` and `<meta>` tags ia-web-commons listed from the page's `<head>` |
| WET | `conversion` | The page's visible text, with `WARC-Target-URI` and `WARC-Date` |

A WAT Archive has three `metadata` records per page, made from the WARC
`request`, `response` and `metadata` records. Only those made from a `response`
are read: a SIMD search for `"WARC-Type":"response"` drops the others before any
JSON is parsed. The JSON is then parsed once, into structs borrowing from the
record, declaring only what is read. A WAT record's own `WARC-Date` is when the
WAT was generated, so the crawl date comes from the JSON
(`Envelope.WARC-Header-Metadata.WARC-Date`). A record whose JSON can't be read is
skipped.

**Which WARC responses are HTML pages.** Common Crawl's own check, the one that
picks the pages its WAT and WET Archives read as HTML: the type it identified
from the response's bytes, in the record's `WARC-Identified-Payload-Type`, is
`text/html` or `application/xhtml+xml` (in any case). CC-MAIN writes that
header, CC-NEWS doesn't: a record without one is an HTML page when its HTTP
`Content-Type` contains `text/html` or `application/xhtml`. A server's
`Content-Type` is often missing or wrong (`charset=utf-8` alone, `text/plain`,
a first `application/octet-stream`), and a type identified as anything else
(`text/plain`, `application/xml`) is no HTML page, whatever the server said.

**Charsets.** Each WARC response is read in the charset a browser reads it in,
by the HTML standard's encoding sniffing (`src/charset.rs`):

1. a byte-order mark at the start of the body (UTF-8, UTF-16LE, UTF-16BE),
   which wins over the rest;
2. the `charset` parameter of the last HTTP `Content-Type` naming a type
   (`text/html; charset=Shift_JIS`); one naming no type (`charset=utf-8` alone,
   `*/*`) or an unknown charset counts for nothing;
3. the first bytes of an XML declaration in UTF-16 (`<?x` as `<\0?\0x\0` or
   `\0<\0?\0x`), which show the byte order;
4. for an HTML page, the first `<meta charset="…">`, or `<meta
   http-equiv="Content-Type" content="…; charset=…">`, in its first 1024 bytes,
   comments and the attributes of other tags passed over (the standard's
   *prescan*), else the `encoding` of an XML declaration opening the page
   (`<?xml version="1.0" encoding="ISO-8859-1"?>`). UTF-16 declared in either
   reads as UTF-8, since it could be read as ASCII; `x-user-defined` in a
   `<meta>` as windows-1252;
5. else UTF-8, unless the page holds bytes beyond ASCII and UTF-8 reads none
   of them: windows-1252 then. Browsers guessing from the bytes read UTF-8
   pages as UTF-8, and fall back on windows-1252 in most of the world. A page
   holding one UTF-8 character beyond ASCII is read as UTF-8, a stray byte
   elsewhere (or a last character cut short by Common Crawl's size limit)
   notwithstanding. The page is read through for this only when a favicon
   value isn't ASCII, its entities decoded.

Every charset of the WHATWG Encoding Standard is read, by any of its labels
(`latin1` and `iso-8859-1` are windows-1252, as in browsers), with
`encoding_rs`, Firefox's implementation of that standard. A charset writing
ASCII as ASCII bytes and no other character with them, every one but UTF-16 and
ISO-2022-JP, costs nothing more: the page is searched as bytes, and only the
favicon values found are decoded. A UTF-16 or ISO-2022-JP page is decoded whole
first. A charset browsers refuse to read (`iso-2022-kr`, `hz-gb-2312`: the
standard's *replacement* encoding) gives nothing, as in a browser.

The Transport decides how the compressed bytes reach the parser. All three give
the same results:

| Transport | Technique |
|---|---|
| `disk` (default) | Stream-decompress `download/<file name>` (`WarcRecordIter` over a file) |
| `memory` | Stream-decompress the downloaded `Vec<u8>` (`WarcRecordIter` over a `Cursor`) |
| `mmap` | Decompress to a copy next to the Archive (3 to 5 GB for a WARC) that no other process can open, memory-map it and read records as slices into it (`WarcSliceIter`) |

The mmap copy is created as `<file name>.<process id>.mmap` and that name is
removed at once, before anything is written to it. The process keeps the file
open and mapped; the kernel frees its space once the process closes it, after a
successful parse, an error, or a kill. So the copy never shows in `download/`,
processes parsing the same Archive each have their own, and a killed process
leaves nothing behind. While the parse runs, its 3 to 5 GB still take disk
space: `df` counts them, `ls` and `du` don't see them. On NFS the client keeps
the copy as a hidden `.nfsXXXX` file in `download/` (`ls -a` shows it) and
removes it once it is closed, after a kill too (only a crash of the node leaves
one); Lustre and GPFS keep such files on their servers. Windows can't remove an open file: there the copy keeps its
name until the parse ends, and a killed process leaves it behind.

Both record parsers, streaming (`disk`, `memory`) and slice (`mmap`), follow
the same rules, so every Transport reads an Archive alike, one written
otherwise than Common Crawl writes them too:

- Lines are read as bytes, each ended by `\n`. A record starts at the first
  line beginning `WARC/` after the end of the previous body: the lines before
  it are passed over, and a `WARC/` inside a line starts nothing. Its headers
  end at the first line of only whitespace, `\r\n` or a bare `\n`.
- Header names are compared ignoring case, and a header given twice keeps its
  last value. `WARC-Target-URI` and `WARC-Date` are read as UTF-8, any byte
  that isn't replaced by `�`: a header in another encoding never fails the
  record.
- A record's `Content-Length` must be ASCII digits, whitespace around them
  allowed, few enough for the machine's word size. A record without one, or
  with any other value (`12a3`, `-5`, empty, 2^64 or more), fails the
  Archive whatever its type, as its body can't be told from the records after
  it: `a record has no Content-Length`, `a record's Content-Length is not a
  byte count: "12a3"`.

The data may end only between two records. The gzip stream can end cleanly
with the last record unfinished: data ending inside a record, in its headers or
before the end of its body (read or passed over, whatever the record's type),
fails the Archive on every Transport, with the same message, `the Archive ends
inside a record`. Otherwise the rest of the Archive would be dropped without a
word and its pair marked done. A body is read as far as the data goes, never
reserved at the length its header declares (8 MiB at most up front, above
any real record): a `Content-Length` larger than any memory fails that way
too, rather than taking the process down. A body running into the next record
is not detected.

## 5. Onion extraction

Code: `src/onion_search.rs`, `OnionExtractor` in `src/extractor.rs`.

**What matches.** A run of exactly 16 or 56 characters from the base32 alphabet
(`a-z`, `2-7`), followed by `.onion`, with a word boundary on both sides, in any
case: the characters and the suffix (`.ONION`, `.Onion`). This is the regex
`\b([a-zA-Z2-7]{16}|[a-zA-Z2-7]{56})\.[oO][nN][iI][oO][nN]\b`, each letter
listing both cases: the `(?i)` flag, with `\b`, once made it over 1000x slower.
Then:

- 56 characters are a v3 address, which carries its own check: its base32
  decodes to a 32-byte public key, a 2-byte checksum and a version byte. It is
  kept only if the version is 3 and the checksum is the first 2 bytes of
  `SHA3-256(".onion checksum" || public key || version)`; any other is dropped
  silently, like text that doesn't match. Over 99 Shards of CC-MAIN-2026-34,
  all 203 v3 addresses found passed.
- 16 characters are a v2 address, kept without a check: there is no checksum
  to verify. Tor dropped v2 in 2021, so these are history, not live services.

Every address is recorded lowercase, whatever its case on the page:
`ABC…XYZ.ONION` and `abc…xyz.onion` are one Artifact.

`--onion-engine` picks the search; both find the same addresses, and unit tests
check that they agree:

| Engine | Technique |
|---|---|
| `memchr` (default) | Jump to each `.o` and `.O` with SIMD `memmem`, compare the rest of `.onion` ignoring case, count base32 characters backwards, check the boundaries |
| `regex` | The regex above, with `regex::bytes` on the raw bytes |

Both engines, and `examples/baseline.rs`, then apply the same check and
lowercasing (`onion_search::checked_address`), so they count the same onions.

**Where it looks.** Every page record, whatever its content type:

- WARC: the page URL (`WARC-Target-URI`), then the whole HTTP response: HTML,
  JavaScript, JSON, plain text, and the HTTP headers. Headers matter: in the
  sample measured in `RESEARCH-warc-wat-wet.md`, 53 % of matches came from
  `Onion-Location` and `Content-Security-Policy` headers. The URL holds the
  address of a page read through a Tor web gateway (`<address>.onion.ly/…`).
  A response in UTF-16, by its byte-order mark, HTTP charset or the first
  bytes of an XML declaration (section 4), whatever its type, is searched
  decoded as well: UTF-16 is the one charset
  whose bytes hide the ASCII text they hold (`a\0b\0…`), as WET's text, decoded
  by Common Crawl, shows. Its bytes are still searched, for its headers and
  for a body declared UTF-16 but written in ASCII. Every other response is
  searched as bytes alone, which show its addresses as they are.
- WAT: the raw JSON bytes, which repeat the WARC headers (the page URL among
  them) and the HTTP headers, and hold the page's links, link texts and
  `<meta>` contents. An address is made of ASCII letters, digits and `.`,
  which JSON never escapes, so it is found as in WARC.
- WET: the page's text.

Together, WAT and WET hold most places an onion is found: over 100 Shards they
found 209 of the 216 distinct onions WARC found, and none it missed.
[Known limitations](#known-limitations) lists where the rest were.

**What it records.** For each address, in lowercase, one Sighting per distinct
`(page_url, shard)` pair: the Page it was seen on, in the address's set
`onion:<address>` (keys in section 9). The Page holds:

```text
page_url  https://example.com/2020/10/04/post
date      2025-01-01T00:00:01Z
shard     CC-MAIN-20250101000000-20250101010101-00000
```

`date` is when the page was crawled, in every Format. The same page crawled in
two Shards yields two Sightings. Several mentions on one page (its URL
included), or in both its WAT and WET records, yield one.

## 6. Favicon extraction

Code: `src/favicon_search.rs` (scanning), `FaviconExtractor` in
`src/extractor.rs`. The rules mirror AIL Framework's
`extract_favicon_from_html()`, but a WARC page is read in one pass over its
bytes, by HTML's own rules for the few tags that matter, instead of building a
DOM.

**Which pages.**

- WARC: `response` records that are HTML pages, identified so by Common Crawl
  (else by their `Content-Type`, section 4). The body is scanned for tags, in
  its charset.
- WAT: records with an HTML `<head>` listed by ia-web-commons. Its list of
  `<link>` and `<meta>` tags is checked with the same rules; nothing is scanned.
- WET: none; the text keeps no markup.

Favicon extraction is independent of onion extraction: it runs on every HTML
page, not only on pages that mention an onion.

**What it looks for.**

| Tag | Attribute matched | Value taken |
|---|---|---|
| `<link>` | a `rel` token equal to `icon`, `apple-touch-icon`, `apple-touch-icon-precomposed` or `mask-icon` (case-insensitive) | `href` |
| `<meta>` | `name="msapplication-TileImage"` (case-insensitive) | `content` |

As in HTML, `rel` is a list of tokens separated by whitespace: `shortcut icon`
and `alternate icon` are favicons through their `icon` token. `fluid-icon` is
not a favicon.

**How a WARC page is read.** `memchr` jumps from one `<` to the next, and the
`<link>`, `<meta>` and `<base>` tags are read as a browser reads them:

- tag names in any case, followed by any whitespace (a newline or a tab too),
  `/` or `>`;
- attributes in any order, double-quoted, single-quoted or bare. A bare value
  runs to whitespace or `>`, `/` included (`href=https://cdn.example/i.png`,
  `href=/i.png`). A quoted value needs no whitespace after it
  (`rel="icon"href="…"`). A quote opens a value only after `=`, so a stray one
  (`<link rel=preload crossorigin">`) hides nothing. Of a repeated attribute,
  the first counts;
- a tag ends at the first `>` outside a quoted value, however long the tag (an
  inline image of any size). A tag still open at the end of the page is
  dropped, as a browser drops it;
- values are read in the page's charset (section 4), then their entities are
  decoded: numeric ones, decimal (`&#38;`) or hex (`&#x26;`), the closing `;`
  optional, and `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`. Any other named one
  (`&copy;`) is kept as written. A byte not valid in the charset reads as `�`
  (U+FFFD), as in a browser;
- nothing is read inside HTML comments (`<!-- … -->`, closed by `--->` or
  `--!>` too), nor inside `<script>`, `<style>`, `<title>`, `<textarea>`,
  `<iframe>`, `<xmp>`, `<noembed>` and `<noframes>`, up to their end tag: a
  browser reads their contents as text. `<?php …`, `<![CDATA[ …` and `</`
  without a letter after it are *bogus comments* to HTML, which end at the
  first `>`, even one closing a tag written inside them; `<!DOCTYPE …>` ends at
  its first `>` too. `<noscript>` and `<template>` are read as any markup. A comment or one
  of these elements left open hides the rest of the page.

Any other tag is passed over at its `<` without reading its attributes (see
Known limitations). One pass reads each part of the page once, so the scan
stays linear however large a tag or comment.

In WAT, the token rule and the URL resolution below are the same; nothing is
decoded or skipped, since ia-web-commons has already decoded the values and
lists no tag from comments or scripts.

**URL resolution.** Each value is resolved with the `url` crate, by the URL
standard browsers follow: against the page's `<base href>` (itself resolved
against the page URL) when it has one, else against the page URL
(`WARC-Target-URI`). In WARC the first `<base>` with an `href` counts, wherever
it is on the page; in WAT it is ia-web-commons' `Head.Base`. A `<base href>`
that is no URL leaves the page URL, as in a browser.

- `https://cdn.example/fav.png` is kept as is, `HTTPS://CDN.Example/fav.png`
  written `https://cdn.example/fav.png`;
- `//cdn.example/fav.png` gets the base's scheme;
- `/icons/fav.png` gets the base's scheme and host;
- `fav.png` and `../fav.png` are resolved against the base's directory, `.`
  and `..` segments removed; a `/` in the base's query or fragment is no
  directory;
- `?v=2` keeps the base's whole path;
- backslashes read as `/`, spaces are percent-encoded, a default port
  (`:443`) is dropped;
- a path is percent-encoded from UTF-8, a query from the page's charset, as
  browsers do for `http`, `https`, `ftp` and `file` URLs: `/café.png?q=café` on
  a windows-1252 page is `/caf%C3%A9.png?q=caf%E9`. A character the charset
  lacks, which only an entity can bring in (`&#20013;` on a windows-1252 page),
  is written as that reference, percent-encoded: `%26%2320013%3B`. A UTF-16
  page encodes its queries in UTF-8. WAT's values come decoded, their page's
  charset unknown: their queries are encoded from UTF-8.

A value that is no URL (`https://`) is dropped, an empty one skipped. URLs are
recorded as `url` writes them, which is what a browser requests.

**No root guess.** Unlike AIL, no `{scheme}://{host}/favicon.ico` is added for
pages that declare nothing: only declared favicons are recorded. A guessed URL
was never checked to exist, and with one per HTML page such guesses made up
nearly a third of the favicon URLs recorded.

**`data:` values** (the scheme in any case) are not favicon URLs. In WARC,
base64 ones are handed to the `inline-favicon` kind (next section); in WAT they
are skipped, since ia-web-commons cuts every `data:` URL after its first comma.

**What it records.** Each absolute favicon URL with its Sightings, in
`favicon:<url>`, deduplicated on `(page_url, shard)`, as for onions.

## 7. Inline favicons

Code: `src/inline_favicon.rs`, `InlineFaviconExtractor` in `src/extractor.rs`.

Requested with `-e inline-favicon` (not in the default list). Only WARC holds
the images, so asking for this kind makes the Shard's Plan WARC, and the other
kinds read that WARC too.

The `<link>` and `<meta>` values of section 6 that are `data:` URIs marked
`;base64` are decoded. A percent-encoded URI (`data:image/svg+xml,<svg…>`) is
dropped, even when its text happens to read as base64. Each image is recorded
under the SHA-256 of its bytes, in lowercase hex, so the same image on many
pages, or written with other line breaks, is one Artifact: its Sightings in
`inline-favicon:<sha256>`, and its description in the hash `image:<sha256>`:

```text
media_type  image/png
mmh3        1932519735
sha1        7679eec1d792d130b56cc3a3d9c55a750600ac64
md5         340680474585d738bda590f1675a0f46
```

- `mmh3`: Shodan's favicon hash, the number its `http.favicon.hash:` filter
  takes: MurmurHash3 x86_32 (seed 0) of the base64 as Python's
  `codecs.encode(data, "base64")` writes it (a newline every 76 characters and
  at the end), read as a signed 32-bit number.
- `sha1`, `md5`: the SHA-1 and MD5 of the image's bytes, in lowercase hex.
- `media_type`: as the first Page written declares it, from the `data:` header,
  without parameters, in lower case
  (`data:Image/SVG+XML;charset=utf-8;base64,` gives `image/svg+xml`); empty if
  the URI declares none.

**Four hashes, one key.** The SHA-256 identifies the image: two different
images never share one in practice, and every tool computes it the same way.
The other three are other common ways to identify an image, so it can be
looked up by whichever one is at hand. None of them can be the key. `mmh3` has 32 bits: among
a million distinct images, about 116 pairs share one (the birthday bound), and
an image can be built to have any chosen value. MD5 and SHA-1 can be made to
collide on purpose too. All three are computed during the crawl: the bytes are
dropped once hashed, so a hash left out could only be added by crawling again.

**Found from any hash.** Each of the three leads back to the images having it:
the sets `mmh3:<value>` (signed decimal, as in `image:<sha256>`), `sha1:<hex>`
and `md5:<hex>` hold their SHA-256s. A set can list several images; for `mmh3`,
that is expected.

```sh
redis-cli -s /tmp/kvrocks.sock SMEMBERS mmh3:1932519735  # the images with that Shodan hash
redis-cli -s /tmp/kvrocks.sock HGETALL image:<sha256>    # one image's hashes and media type
```

**Saving the images.** The store holds no image bytes. Without
`--save-images`, they are dropped once hashed. With `--save-images <dir>`, each
image of a Shard is written to `<dir>/<first two hex digits of its
SHA-256>/<SHA-256>`, such as `images/49/49e1dad4…c00d`:

- No extension: the media type is in the store, as the first Page declared it,
  rightly or not. The first two hex digits spread the images over 256
  subdirectories, as a directory of millions of files is slow to list.
- Each file is written under a temporary name in its subdirectory
  (`<sha256>.<process id>.part`), then renamed to its own: a killed run leaves
  at most a `.part` file, never part of an image under an image's name. So a
  file already at an image's path is that image, and is left as it is.
  Directories are created as needed.
- A (Shard, `inline-favicon`) pair's images are all on disk before its writes to
  the store, so before it is marked done. One that can't be written (a
  directory not writable, a regular file where a subdirectory should be) leaves
  the pair undone, with a message naming its path, and the run exits with 3.
- Given without `inline-favicon` requested, the option is accepted, and a line
  at start-up says no image will be saved.

A pair done without `--save-images` keeps no image: a later run with the option
skips it, done, and saves only the images of the pairs it extracts. An image
written before SHA-1 and MD5 were computed has neither, nor any index entry,
until a pair extracted later finds it again and adds them; nothing redoes the
pairs already done (see section 9, resuming).

## 8. Concurrency and resource guards

Each Shard is processed in a Tokio task of its own, up to `jobs` at once, and
results are consumed as soon as any one finishes. Downloads are async; parsing
runs under `spawn_blocking` so it doesn't stall downloads. Results are written
to the store one Shard at a time on the main task, so no locks are needed.
While a Shard is written, the Shards in flight go on downloading and parsing;
the next one starts once the main task takes a result. A slow store (one
server shared by many writers) holds finished Shards back, at most `jobs` of
them, and slows the crawl down: it doesn't fail the downloads in flight,
however long a write takes.

The number of jobs (default: one per logical CPU core) is capped in two steps:

1. At most 2x the number of logical CPU cores.
2. With `--transport memory` only, at most `memory / largest Plan`, where the
   largest Plan is the biggest estimated size among the scheduled Shards'
   Plans (~1 GB for WARC, the default; ~240 MB for `--formats wat,wet`), and
   the memory the smaller
   of the available RAM and `--max-memory` (in GB of 2^30 bytes, fractions
   allowed). RAM is read from `sysctl` on macOS or `/proc/meminfo` on Linux
   (`MemAvailable`); on other platforms `--max-memory` alone caps, and
   without it this cap is skipped. Never fewer than one job.

Each cap prints a warning when it lowers the requested value, the memory one
saying whether the available RAM or `--max-memory` lowered it. Every process
reads the available RAM of the whole machine: several processes sharing one
each see all of it, so each needs `--max-memory` set to its share (the
machine's RAM divided by the number of processes). Without `--transport
memory`, `--max-memory` is accepted, and a start-up line says it has no
effect.

## 9. The results store

Results and done marks go to a [kvrocks](https://kvrocks.apache.org/) store:
the Redis protocol, its data kept on disk (RocksDB) rather than in RAM. No
results file is written: nothing goes under the working directory but
`download/`, the mmap Transport's temporary file and, if asked to go there, the
images `--save-images` writes (section 7).

**Reaching it.** `--kvrocks` names a Unix socket (default `/tmp/kvrocks.sock`)
or gives a `redis://host:port` URL. A socket reaches a store on the same
machine without the network stack. TCP is there for a store that has no socket
to offer: kvrocks has no macOS build that runs well, and in Docker Desktop a
container's socket, though visible on the Mac, can't be connected to from
there; its published port can. If the store needs a password, it comes from
`CC_EXTRACT_KVROCKS_PASSWORD` and is sent with `AUTH` (in kvrocks, the password
chooses the namespace); a URL holding one is refused, since options show in
`ps` and in shell history. The store is reached and checked after the
arguments and the paths file are read, before anything is downloaded: a store
that can't be reached stops the run with exit status 1, naming it. A
connection lost during the run (a network fault, the store restarted) is
opened again: the write that finds it gone fails, leaving its pair undone
(exit 3, section 11), and the next one connects anew.

**Keys.** Kinds are named as on the command line:

| Key | Type | Content |
|---|---|---|
| `page:<id>` | hash | `page_url`, `date`, `shard` of one Page |
| `<kind>:<artifact>` | set | ids of the Pages the Artifact was seen on |
| `page:<id>:<kind>` | set | the Page's Artifacts of that kind |
| `artifacts:<kind>` | set | every Artifact of the kind |
| `image:<sha256>` | hash | `media_type` (declared by the first Page written), `mmh3` (signed decimal), `sha1`, `md5` (lowercase hex) |
| `mmh3:<value>`, `sha1:<hex>`, `md5:<hex>` | set | SHA-256s of the inline favicons with that hash |
| `processed` | set | `<shard> <kind>`, one per done pair |
| `failures` | set | `<archive> <run>`, one per failure counted on an Archive |
| `failures:<archive>` | hash | `<run>`: the error message of each run that counted a failure on the Archive |

`<artifact>` is the onion address, the favicon URL, or the inline favicon's
SHA-256. A Page's `<id>` is the first 16 bytes of the SHA-256 of
`"<shard> <page_url>"`, in lowercase hex: computed from the Page alone, so a
Shard written again gives the same keys, and each set lists 32 characters per
Page rather than its URL. One Sighting is one Page in an Artifact's set: the
same page crawled in two Shards is two Pages, two Sightings. The forward sets
link the kinds seen on one Page: from an onion to the inline favicons of the
Pages naming it, then to their `mmh3`, and through `mmh3:<value>` to every
other image sharing it. No image bytes are written to the store (section 7).

In the failure records, `<archive>` is an Archive's file name
(`CC-MAIN-…-00001.warc.wet.gz`) and `<run>` a run's start time since the Unix
epoch, to the nanosecond, and process id: `1735689600.000000500-4242`. Two runs
never share one on a machine, and as good as never across machines whose
stores are combined.

**Only adding.** Every write is a `SADD` or an `HSETNX` (set a hash field only
if absent): nothing written is ever removed or changed, so the first `date` or
`media_type` written is the one kept, and writing the same Shard again changes
nothing. Two stores combine by union, failure records included.

**Writing one Shard.** For each kind whose Archives all parsed, the Shard's
Sightings are written in pipelined batches (many commands sent before the
replies are read), then, once every write is acknowledged, `<shard> <kind>` is
added to `processed`. A Shard costs its own writes only, whatever the store
already holds (a Shard's favicons are about 51,000 Sightings, 200,000
commands). The run's results are never held in RAM: only one Shard's at a
time.

**Mark after writes.** The order is the guarantee: a run killed, or a
connection lost, between the writes and the mark leaves the pair undone, never
marked with Sightings missing. The next run extracts the pair again and writes
the same members and fields, which changes nothing. A transaction
(`MULTI`/`EXEC`) is not used: kvrocks runs `EXEC` under a lock that stops
every other client, for 200,000 commands. A write that fails leaves its pair
undone too, like a failed download or parse: the run goes on with the other
kinds and Shards, and exits with 3.

**Resuming.** At start-up, the members of `processed` say which pairs are done;
a member without a kind this version knows is ignored, its pairs done again. A
later run with more kinds extracts only the new ones for the Shards already
done. A Shard whose download or parse failed is not marked for the kinds
reading the Archive that failed, and is retried on the next run; once the
Archive is given up, on the kinds' next combination (below).

**Given-up Archives.** Some failures come back on every run: they are counted
against the Archive, at most once per run.

- Counted: a download answered with an HTTP 4xx status other than 408 and 429
  (a 404 on a derived WAT or WET path), and a parse error from the Archive's
  bytes (not gzip, a gzip member damaged or cut short, data ending inside a
  record, a `Content-Length` missing or malformed), on any Transport. An
  Archive corrupt in `download/` counts too: it is parsed again, not
  downloaded again. Its message ends with where in the compressed Archive it
  broke, `(at byte X of Y)` (see Known limitations). A panic while parsing an
  Archive, a bug its bytes trigger, counts too, as `the parser panicked:
  <message>`: it fails that Archive alone, the Shard's other Archives parsed
  as usual.
- Not counted: timeouts (the 60 s without data included), connection errors,
  5xx, 408 and 429, a body cut short of its `Content-Length` (a download
  error), local I/O errors (a file in `download/` that can't be opened, a disk
  full writing a download or the mmap copy), store writes and image saves.

Each counted failure is one record, written to both keys above with writes
that only add: the run's message in `failures:<archive>` under `<run>`, then
`<archive> <run>` in `failures`. A failure counts only when both keys hold
it, so a record half-written by a killed run counts nothing. At start-up the
records are read in two round trips: `failures`, then the hashes of the
Archives it lists, sent together.

After 3 runs counted a failure on it (fixed, with no option), the Archive is
given up and no longer downloaded. Each pair reading it is planned on its next
combination avoiding the Shard's given-up Archives, and is given up only when
none is left: such a pair is not scheduled (section 2). A pair done on its
next combination is marked done as usual, the record staying in the store:
done wins over any record. The run that gives an Archive up says so at that
Shard, and gives up there the kinds with no combination left; the others are
left undone for the next run, which reads their next combination (exit 3). At
start-up, a line gives the number of given-up Archives in the Slice (those
leaving out a requested kind not yet done), and the summary lists each with
the kinds it leaves undone and its last error.

To retry, delete the records: the Archive is scheduled again, its count
started over. An Archive corrupt in `download/` is parsed again as it is: remove
the file there too, so it is downloaded again.

```sh
redis-cli -s /tmp/kvrocks.sock DEL failures:<archive file name>   # one Archive
redis-cli -s /tmp/kvrocks.sock DEL failures                       # every Archive
```

Deleting `failures:<archive>` leaves the Archive's members in `failures`
with no message to match, and deleting `failures` leaves each Archive's
hash with no member listing it: either way nothing counts, and a later
failure counts from one. The hashes left behind are ignored.

A done mark doesn't say which matching rules extracted the pair, so a change to
the rules (such as onions found in any case and v3 checksums verified, or
favicon tags read as HTML reads them) applies to the Shards extracted from then
on: the pairs already done keep what the older rules found, and nothing redoes
them. Results under one set of rules take a fresh store, or a namespace of
their own.

The summary at the end reports processed, skipped, failed and given-up Shards,
each Shard of the Slice in one of them: skipped (every requested kind done
before the run), failed (a kind left undone that a later run may do, by a
failed download, parse, store write or image save), given up (only given-up
kinds left undone), processed (the others). Then the Artifacts new to the store
per kind (those `SADD` added to `artifacts:<kind>`), the total per kind (that
set's size), average download and parse time per processed Shard, and the
given-up Archives. Each Shard's log also gives the time its writes took, and
with `--save-images` how many new images it saved. The exit status tells
whether any Shard failed, or only given-up pairs are left (see section 11).

## 10. HPC batch mode

For runs over a whole Crawl (about 100,000 Shards) on a cluster,
`--offset` and `--limit` give each process its own Slice of the paths file.
Running a process's command again covers its Slice only: after exit 3 it
retries the undone pairs left there, and an Archive failing the same way on
every run is given up after 3, so a script re-running on exit 3 comes to an
end (exit 0, or 4 with given-up pairs left). With `--transport memory`, each
process caps its jobs at its own share of the machine's RAM with
`--max-memory`.

Several processes share one store: each writes its own Shards, and the
writes only add. On one machine they reach it over its socket; across several
nodes, over TCP (`--kvrocks redis://host:port`), the store running outside
the job on a host every compute node can connect to. It outlives the job:
re-runs resume from it, and the results are read from it. A node is one more
client: Slices don't overlap, and runs are told apart by their start time and
process id, so several machines writing at once leave the same store as one
would. The traffic, password included, is not encrypted: keep the store on a
trusted network.

One server's write rate bounds the whole Crawl. With one writer (kvrocks in
Docker, over TCP), a Shard's favicons (about 51,000 Sightings) took about
1.5 s to write: about 150,000 s, 42 hours of writing, over 100,000 Shards.
Writers in parallel go faster only as far as the server keeps up. Each Shard
logs its `Store time`; a slow store slows the crawl without failing downloads
(section 8), and a dropped connection fails only the write that finds it
gone (section 9).

`examples/slurm/crawl.sh` is an array of 10 tasks, each one a whole node, each
running 20 processes over 500 paths with `--transport memory`, each given the
node's RAM divided by 20 with `--max-memory`, all writing to one store over
TCP. With more than one array task it refuses a socket path, which only its
own machine can reach.

## 11. CLI reference

| Flag | Default | Effect |
|---|---|---|
| `<INPUT>` | | Paths file (WARC, WAT or WET), plain or `.gz`. Required. |
| `-l`, `--limit N` | all | Cover the N paths after the offset, the Slice: Shards done skipped, none after it read |
| `-o`, `--offset N` | 0 | Skip the first N paths |
| `-j`, `--jobs N` | CPU cores | Shards in flight at once (capped, see section 8) |
| `-d`, `--delete` | off | Delete each Shard's Archives from `download/` once parsed (not with `-t memory`) |
| `-e`, `--extract K,...` | `onion,favicon` | Artifact kinds: `onion`, `favicon`, `inline-favicon` |
| `--formats F,...` | per kind, those finding the most (WARC) | Force the Formats a run may download: `warc`, `wat`, `wet` (section 2) |
| `-t`, `--transport T` | `disk` | `disk`, `memory` or `mmap` |
| `--max-memory GB` | available RAM | With `-t memory`, the most RAM the process's downloads may hold, in GB of 2^30 bytes (section 8) |
| `--onion-engine E` | `memchr` | `memchr` or `regex` |
| `--kvrocks SOCKET\|URL` | `/tmp/kvrocks.sock` | The store: a Unix socket path, or `redis://host:port` |
| `--save-images DIR` | off | Write each inline favicon image to `DIR/<first two hex digits of its SHA-256>/<SHA-256>` (section 7) |

The store's password, if it needs one, is read from the
`CC_EXTRACT_KVROCKS_PASSWORD` environment variable, never from an option.

The exit status (listed by `--help` too) tells a script whether to run the same
command again:

| Code | Meaning | Run again? |
|---|---|---|
| 0 | Every Shard of the Slice done for every requested kind | No need |
| 1 | Stopped early, such as on a missing or unreadable paths file, an unreachable store, an `--offset` past the end, or a Plan no Shard can meet | Once the cause is fixed |
| 2 | Invalid option or value (`clap`'s code for usage errors) | Once the command is fixed |
| 3 | Ran to the end with some Shards left with kinds a run may still do: a failed download, parse, store write or image save | Yes, the same command |
| 4 | Ran to the end with nothing left to retry, but some pairs of the Slice given up, by this run or an earlier one: each combination they may read (inside `--formats`) reads an Archive that failed the same way on 3 runs | Only once the given-up Archives' records are deleted, or with `--formats` letting in another combination (section 9) |

Early stops come before anything is downloaded or written. Shards that fail
don't stop the run: the others go on, and the run exits with 3 at the end. 3
wins over 4: a run with both retryable and given-up pairs left exits with 3.
Paths file lines the run can't use (not a Common Crawl path, or one whose other
Formats' paths can't be derived) are reported and skipped: they are no Shard
to retry, and leave the exit status at 0.

## Known limitations

Behaviour that is surprising or incomplete today, roughly in order of impact.

- **WAT + WET (`--formats wat,wet`, or a given-up WARC) miss some onions
  WARC finds.** Over 100 Shards of CC-MAIN-2026-34, they missed 7 of the 216
  distinct onions WARC found (3.2 %) and 21 of its 1,486 Sightings (1.4 %),
  and found none WARC missed. Every one they missed sat where
  WAT and WET keep nothing: inline scripts, JSON inside `<script>`,
  attributes WAT doesn't keep (`<input value>`, `data-*`) and HTML comments.
  Several were a site's own Tor mirror. The bodies of non-HTML responses
  (JavaScript, JSON, CSS, PDF, plain text) are dropped too. In WAT, an address
  right after a JSON escape of a control character (`\n`, `\t`) is missed, the
  escape's last letter reading as part of it. WARC, the default, finds them
  all, for about 4 times the download (`RESEARCH-warc-wat-wet.md`, sections
  4.7 and 4.8).
- **Favicons differ slightly between WARC and WAT.** Over 100 Shards of
  CC-MAIN-2026-34 they share 99.93 % of WARC's Sightings; 3,564 are found
  only in WARC, 309 only in WAT. What differs, from a sample of the pages:
  - ia-web-commons' parser misreads comments HTML closes at `--->` or `--!>`,
    or written with runs of dashes (`<!-----`), and leaves out the tags after
    them; it lists no `<link>` after a `<noscript>` in the head, decodes some
    pages in the wrong charset (`×` written `Ã—`), and keeps the *last*
    `<base>` of a page, where HTML (and the scanner) use the first. WARC
    finds those favicons.
  - It also lists tags HTML doesn't read: written right after a quoted value
    or a tag left without its `>` (`href="…"<link rel="icon" …>`), which
    HTML reads as attributes of the tag before, or inside a comment "closed"
    by `-- >`, or inside a `<title>` or `<iframe>` not closed.

  Details in `RESEARCH-warc-wat-wet.md`, sections 4.7 and 4.8.
- **Pages Common Crawl types as something else are not scanned.** Its HTML
  check goes by the type it detected from the bytes, not the server's
  `Content-Type`, so a page sent as `text/html`, which a browser renders,
  but detected as `application/xml` (opening with an XML declaration) or
  `text/x-php` (opening with `<?php` text) is not scanned for favicons or
  inline favicons. Over 100 Shards, 369 favicon Sightings on 121 pages; WAT
  lists none of them either, being made by the same check.
- **TCP to the store is not encrypted.** A Unix socket reaches a store on the
  same machine; over TCP (several nodes, section 10) the traffic, password
  included, goes in the clear: keep the store on a trusted network.
- **Onion Sightings keep no context.** The store records which page mentioned
  the address, not where on the page or in what role (link, header, plain
  text).
- **The WARC favicon scanner reads only the tags it needs.**
  - Start tags other than `<link>`, `<meta>`, `<base>` and the text-only
    elements are passed over at their `<`, their attributes unread. Markup
    written inside one of their quoted values is read as if it were the
    page's: a `<link>` there (`<div data-html='<link …>'>`) is taken for a
    favicon, and a `<!--`, `<script` or `<title` there starts a skip that can
    hide the favicons after it. A browser sees text in both cases.
  - `<noscript>` is read as markup, as a browser without scripts reads it. An
    `<iframe … />` inside one, never closed by `</iframe>`, then hides the rest
    of the page, where a browser running scripts reads the `<noscript>` as text
    and finds the favicons after it.
  - Of the named entities, only `&amp;`, `&lt;`, `&gt;`, `&quot;` and `&apos;`
    are decoded, and numeric ones from 128 to 159 are not mapped to
    Windows-1252 characters as HTML maps them.
  - A page sent as `application/xhtml+xml` is read as HTML, its charset
    from a `<meta>` too: a browser reads it as XML, whose charset only an XML
    declaration gives, UTF-8 by default.
- **One bad record drops the Archive.** A read or decompression error aborts
  the Archive, dropping everything found in it; the kinds reading it are left
  undone, and after 3 runs failing on it the Archive is given up (section 9).
  The error gives its position in the Archive, `(at byte X of Y)`: X
  compressed bytes read when it came, Y the compressed size. X runs past the
  fault by up to the rest of its gzip member (whose checksum is checked at
  its end) and 32 KiB (the decoder reads ahead); a record cut at the end of
  the data gives X = Y. So does, on `mmap` alone, a malformed record further
  in: the copy is decompressed whole before any record is read. The log line, `failures:<archive>` and the summary's
  given-up list show it, so a run tells whether damaged Archives break at
  their start or further in, where reading on from the next gzip member
  would keep the records on either side of the fault.
- **A download is cut only when no data comes at all.** A server sending a
  few bytes now and then, each within 60 s, keeps a download going however
  slow it is: there is no minimum speed.
