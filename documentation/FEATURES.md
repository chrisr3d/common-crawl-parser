# Features

What `cc-extract` (v2.0.0) does today, feature by feature. `README.md` covers
building and running, `PROGRESS.md` covers the Rust concepts behind each step.
This file covers behaviour: what each feature reads, what it writes, and where it
stops short. Terms (Shard, Archive, Format, Artifact kind, Sighting, Plan) are
defined in `GLOSSARY.md`.

## At a glance

One run takes a Common Crawl paths file, works out which Shards still need which
of the requested Artifact kinds, downloads the cheapest Archives that serve them,
and maintains one result file per kind:

- `onions.json`: every `.onion` address found, with the pages it appeared on.
- `favicons.json`: every favicon URL an HTML page declares, with the pages that
  declare it.
- `inline_favicons.json`: every favicon image a page embeds as a base64 `data:`
  URI, keyed by its SHA-256, with its Shodan hash and the pages that embed it.

`-e` / `--extract` picks the kinds (default `onion,favicon`). All requested kinds
are extracted in the same pass over each Archive.

```text
paths file ──▶ schedule Shards (offset, skip the kinds done, limit)
           ──▶ plan each Shard's Formats (cheapest serving every kind)
           ──▶ download its Archives (to disk or to memory) ┐ up to --jobs Shards
           ──▶ parse them on the blocking thread pool       ┘ in flight at once
           ──▶ merge into the result maps, one Shard at a time
           ──▶ per kind done: rewrite its JSON file, then append to processed.log
```

A second mode, `merge`, combines result directories produced by separate runs
(see [HPC batch mode](#10-hpc-batch-mode)).

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

1. `--offset N` drops the first N paths.
2. A Shard whose every requested kind is already listed for it in
   `processed.log` is skipped. Otherwise it is scheduled for the missing kinds
   only.
3. `--limit N` stops once N Shards are scheduled. Skipped Shards don't count
   toward the limit.

## 2. Artifact kinds, Format requirements and Plans

Code: `src/artifact.rs` (requirements), `src/plan.rs` (planner),
`src/format.rs` (Formats and Datasets).

Each kind accepts some combinations of Formats (its Format requirement):

| Artifact kind | Accepted combinations | Default |
|---|---|---|
| `onion` | WARC, or WAT + WET | on |
| `favicon` | WARC, or WAT | on |
| `inline-favicon` | WARC | off |

A Shard's Plan is the cheapest combination of Formats, among those its Dataset
publishes, that contains an accepted combination for every kind still to do
for it. Cost is the estimated Archive size: WARC ~1 GB, WAT ~170 MB,
WET ~70 MB. Inside the Plan, each kind reads the cheapest of its own accepted
combinations:

| Kinds to do | Plan on CC-MAIN | Who reads what |
|---|---|---|
| `onion` + `favicon` | WAT + WET (~240 MB) | `onion` both, `favicon` WAT |
| `onion` | WAT + WET | `onion` both |
| `favicon` | WAT (~170 MB) | `favicon` WAT |
| anything with `inline-favicon` | WARC (~1 GB) | every kind WARC |

CC-MAIN publishes all three Formats; CC-NEWS publishes WARC only, so its Plan
is always WARC. Since the
Plan depends on the kinds still to do, two Shards of one run can have different
Plans.

`--formats warc,wat,wet` forces the Formats downloaded for every Shard. It is
rejected at startup if they can't serve a requested kind
(`cannot extract favicon from wet: it needs warc or wat`), and when a Shard is
planned if its Dataset doesn't publish one of them. Each kind still reads the
cheapest combination it accepts among the forced Formats, and a forced Format
no kind reads is not downloaded.

A kind reading several Archives gets the union of what each one gave: Sightings
are not joined record by record. A (Shard, kind) pair is done only when every
Archive that kind reads has been downloaded and parsed; a failed
WET Archive leaves `onion` undone but still lets `favicon` finish from WAT.

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
exits with 3, and the next run downloads the Archive again. The wait starts
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
| WARC | `response` | The record block, i.e. the whole HTTP response (status line, headers, body), with `WARC-Target-URI` and `WARC-Date` |
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

- WARC: the whole HTTP response: HTML, JavaScript, JSON, plain text, and the HTTP
  headers. Headers matter: in the sample measured in
  `RESEARCH-warc-wat-wet.md`, 53 % of matches came from `Onion-Location` and
  `Content-Security-Policy` headers.
- WAT: the raw JSON bytes, which repeat the HTTP headers and hold the page's
  links, link texts and `<meta>` contents. An address is made of ASCII letters,
  digits and `.`, which JSON never escapes, so it is found as in WARC.
- WET: the page's text.

Together, WAT and WET hold most places an onion is found: over 99 Shards they
found 208 of the 215 distinct onions WARC found.
[Known limitations](#known-limitations) lists where the rest were.

**What it records.** For each address, one Sighting per distinct
`(page_url, shard)` pair:

```json
{
  "exampleexampleexampleexampleexampleexampleexampleexkokad.onion": [
    {
      "page_url": "https://example.com/2020/10/04/post",
      "date": "2025-01-01T00:00:01Z",
      "shard": "CC-MAIN-20250101000000-20250101010101-00000"
    }
  ]
}
```

`date` is when the page was crawled, in every Format. The same page crawled in
two Shards yields two Sightings. Several mentions on one page, or in both its
WAT and WET records, yield one.

## 6. Favicon extraction

Code: `src/favicon_search.rs` (scanning), `FaviconExtractor` in
`src/extractor.rs`. The rules mirror AIL Framework's
`extract_favicon_from_html()`, but a WARC page is read in one pass over its
bytes, by HTML's own rules for the few tags that matter, instead of building a
DOM.

**Which pages.**

- WARC: `response` records whose HTTP `Content-Type` contains `text/html` or
  `application/xhtml`. The body is scanned for tags.
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
- entities are decoded in values: numeric ones, decimal (`&#38;`) or hex
  (`&#x26;`), the closing `;` optional, and `&amp;`, `&lt;`, `&gt;`, `&quot;`,
  `&apos;`. Any other named one (`&copy;`) is kept as written;
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
  (`:443`) is dropped.

A value that is no URL (`https://`) is dropped, an empty one skipped. URLs are
recorded as `url` writes them, which is what a browser requests.

**No root guess.** Unlike AIL, no `{scheme}://{host}/favicon.ico` is added for
pages that declare nothing: only declared favicons are recorded. A guessed URL
was never checked to exist, and with one per HTML page such guesses made up
nearly a third of the URLs in `favicons.json`.

**`data:` values** (the scheme in any case) are not favicon URLs. In WARC,
base64 ones are handed to the `inline-favicon` kind (next section); in WAT they
are skipped, since ia-web-commons cuts every `data:` URL after its first comma.

**What it records.** `favicons.json` maps each absolute favicon URL to its
Sightings, deduplicated on `(page_url, shard)`, as for onions.

## 7. Inline favicons

Code: `src/inline_favicon.rs`, `InlineFaviconExtractor` in `src/extractor.rs`.

Requested with `-e inline-favicon` (not in the default list). Only WARC holds
the images, so asking for this kind makes the Shard's Plan WARC, and the other
kinds read that WARC too.

The `<link>` and `<meta>` values of section 6 that are `data:` URIs marked
`;base64` are decoded. A percent-encoded URI (`data:image/svg+xml,<svg…>`) is
dropped, even when its text happens to read as base64. Each image is saved
under the SHA-256 of its bytes, in hex, so the same image on many pages, or
written with other line breaks, is one entry:

```json
{
  "49e1dad481e94dfab7c9573a9a81d56aa2ca629fe15a3f7a910aa4f47601c00d": {
    "mmh3": 1932519735,
    "media_type": "image/png",
    "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ...",
    "sightings": [{ "page_url": "...", "date": "...", "shard": "..." }]
  }
}
```

- `mmh3`: Shodan's favicon hash, the number its `http.favicon.hash:` filter
  takes: MurmurHash3 x86_32 (seed 0) of the base64 as Python's
  `codecs.encode(data, "base64")` writes it (a newline every 76 characters and
  at the end), read as a signed 32-bit number.
- `media_type`: from the `data:` header, without parameters, in lower case
  (`data:Image/SVG+XML;charset=utf-8;base64,` gives `image/svg+xml`); empty if
  the URI declares none.
- `data`: the image, in base64 without line breaks.

## 8. Concurrency and resource guards

Shards are processed through `buffer_unordered(jobs)`: up to `jobs` Shards are
in flight, and results are consumed as soon as any one finishes. Downloads are
async; parsing runs under `spawn_blocking` so it doesn't stall downloads.
Results are merged one Shard at a time on the main task, so no locks are
needed.

The number of jobs (default: one per logical CPU core) is capped in two steps:

1. At most 2x the number of logical CPU cores.
2. With `--transport memory` only, at most `available RAM / largest Plan`,
   where the largest Plan is the biggest estimated size among the scheduled
   Shards' Plans (~240 MB for WAT + WET, ~1 GB for WARC). RAM is read from
   `sysctl` on macOS or `/proc/meminfo` on Linux; on other platforms this cap is
   skipped.

Each cap prints a warning when it lowers the requested value.

## 9. State, resume and output files

Everything is written under `--output-dir` (default `output/`):

| File | Content | Written |
|---|---|---|
| `processed.log` | One `<shard> <kind>` line per done pair | Appended after the kind's file is saved |
| `onions.json` | Onion address → Sightings | Fully rewritten after each Shard that finished `onion`, and once more at the end |
| `favicons.json` | Favicon URL → Sightings | Same, for `favicon` |
| `inline_favicons.json` | Image SHA-256 → hashes, image and Sightings | Same, for `inline-favicon` |

Only the requested kinds' files are loaded at start-up and saved: `-e onion`
never touches `favicons.json`. New results are merged into the loaded ones, so
successive runs accumulate. A results file that can't be loaded (corrupt, or
written in the old `url` / `archive` shape) stops the run before anything is
written, rather than being overwritten.

A results file is never written in place: the new JSON goes to
`<file>.tmp` in the same directory, then `rename` puts it in place in one
step (atomic within one filesystem). A run killed during a save leaves the
previous file whole, and maybe a `<file>.tmp` that nothing loads and the next
save replaces. This guards against a killed process, not a power cut or a node
crash: nothing is forced to disk with `fsync`. `processed.log` needs no such
care: it is appended one short line at a time, and a line cut off by a kill
names no known kind, so it is ignored and its pair redone.

A kind's file is saved before its `<shard> <kind>` line is appended, so a crash
in between leaves the pair undone and the next run extracts it again;
deduplication makes that redo change nothing. A later run with more kinds
extracts only the new ones for the Shards already done. A Shard whose download
or parse failed is not marked for the kinds reading the failed Archive, nor for
a kind whose file failed to save, and is retried on the next run. Lines
`processed.log` can't read (such as bare Archive names, written before kinds
were tracked) are ignored, so those Shards are processed again.

A `<shard> <kind>` line doesn't say which matching rules extracted the pair, so
a change to the rules (such as onions found in any case and v3 checksums
verified, or favicon tags read as HTML reads them) applies to the Shards
extracted from then on: the pairs already done keep what the older rules found,
and nothing redoes them. Results under one set of rules take a fresh
`--output-dir`. Favicon URLs are keys written by the `url` crate since its
rules came in (host in lowercase, `..` removed, entities decoded): a file
merged across that change can hold one favicon under two keys, its old
spelling and its new one.

The summary at the end reports processed, skipped and failed Shards (a Shard
left with any kind undone, by a failed download, parse or save), new and total
Artifacts per kind, and average download and parse time per Shard. The exit
status tells whether any Shard failed (see section 11).

## 10. HPC batch mode

For runs over a whole Crawl (about 100,000 Shards) on a cluster:

- `--offset` and `--limit` give each process its own slice of the paths file.
- `--output-dir` gives each process its own state and result files, so
  processes never write to the same file.
- `cc-extract merge <DIR>... [-o OUT]` merges every kind whose results file is
  in at least one directory, deduplicates as above, and writes the merged files
  to `OUT` (default `output/`). A file that can't be loaded is reported and
  skipped. For an inline favicon, the first media type seen wins.
  `processed.log` files are not merged.

Two example scripts run this on SLURM. They hold `<...>` placeholders for the
account, partition and paths, to be replaced first:

- `examples/slurm/crawl.sh`: an array of 10 tasks, each one a whole node
  (`--exclusive`), each running 20 processes over 500 paths (`--transport
  memory`, the node's cores shared out as `--jobs`), so 100,000 paths in total.
  Output goes to `<output root>/<task>/<process>/`.
  Its report tells processes that finished with Shards to retry (exit 3) from
  those that stopped early (any other non-zero exit). It exits with 0 either
  way, so `afterok` starts the merge on the results so far.
- `examples/slurm/merge.sh`: merges every `<output root>/<task>/<process>/`
  directory into `<output root>`. Meant to run after the crawl job, with
  `--dependency=afterok`.

## 11. CLI reference

| Flag | Default | Effect |
|---|---|---|
| `<INPUT>` | | Paths file (WARC, WAT or WET), plain or `.gz`. Required unless using `merge`. |
| `-l`, `--limit N` | all | Process at most N Shards this run, not counting Shards already done for every requested kind |
| `-o`, `--offset N` | 0 | Skip the first N paths |
| `-j`, `--jobs N` | CPU cores | Shards in flight at once (capped, see section 8) |
| `-d`, `--delete` | off | Delete each Shard's Archives from `download/` once parsed (not with `-t memory`) |
| `-e`, `--extract K,...` | `onion,favicon` | Artifact kinds: `onion`, `favicon`, `inline-favicon` |
| `--formats F,...` | the Plan | Force the Formats downloaded: `warc`, `wat`, `wet` |
| `-t`, `--transport T` | `disk` | `disk`, `memory` or `mmap` |
| `--onion-engine E` | `memchr` | `memchr` or `regex` |
| `--output-dir DIR` | `output` | Where state and results are read and written |
| `merge DIR... [-o OUT]` | | Merge result directories into `OUT` (default `output`) |

The exit status (listed by `--help` too) tells a script whether to run the same
command again:

| Code | Meaning | Run again? |
|---|---|---|
| 0 | Every Shard taken on done for every requested kind | No need |
| 1 | Stopped early, such as on a missing or unreadable paths or results file, an `--offset` past the end, or a Plan no Shard can meet | Once the cause is fixed |
| 2 | Invalid option or value (`clap`'s code for usage errors) | Once the command is fixed |
| 3 | Ran to the end with some Shards left with kinds undone: a failed download, parse or save | Yes, the same command |

Early stops come before anything is downloaded or written. Shards that fail
don't stop the run: the others go on, and the run exits with 3 at the end.
Paths file lines the run can't use (not a Common Crawl path, or one whose other
Formats' paths can't be derived) are reported and skipped: they are no Shard
to retry, and leave the exit status at 0.
`merge` exits with 0, or 1 when it has nothing to merge or can't save.

## Known limitations

Behaviour that is surprising or incomplete today, roughly in order of impact.

- **WAT + WET miss some onions WARC finds.** Over 99 Shards of
  CC-MAIN-2026-34, the default Plan missed 7 of the 215 distinct onions WARC
  found (3.3 %) and 21 of its 1,470 Sightings (1.4 %). Every one sat where
  WAT and WET keep nothing: inline scripts, JSON inside `<script>`,
  attributes WAT doesn't keep (`<input value>`, `data-*`) and HTML comments.
  Several were a site's own Tor mirror. The bodies of non-HTML responses
  (JavaScript, JSON, CSS, PDF, plain text) are dropped too. In WAT, an address
  right after a JSON escape of a control character (`\n`, `\t`) is missed, the
  escape's last letter reading as part of it; one in the page URL itself is
  found, since the JSON repeats the WARC headers (WARC only searches the HTTP
  response). `--formats warc` finds them all, for about 4 times the download
  (`RESEARCH-warc-wat-wet.md`, section 4.7).
- **Favicons differ slightly between WARC and WAT.** Over 99 Shards of
  CC-MAIN-2026-34 they share 99.9 % of WARC's Sightings; 3,880 are found only
  in WARC, 1,109 only in WAT. What still differs, from a sample of the pages:
  - WARC only scans responses whose `Content-Type` says HTML, as bytes:
    ia-web-commons also reads pages sent without that header (none,
    `charset=utf-8` alone, `text/plain`) and pages in UTF-16. A URL value that
    isn't UTF-8 (on a Latin-1 page) is dropped in WARC.
  - ia-web-commons' parser misreads comments HTML closes at `--->` or `--!>`,
    or written with runs of dashes (`<!-----`), and leaves out the tags after
    them; it fails on a few pages altogether, and keeps the *last* `<base>`
    of a page, where HTML (and the scanner) use the first. WARC finds those
    favicons.
  - It also lists a tag written right after a quoted value
    (`href="…"<link rel="icon" …>`), which HTML reads as attributes of the
    tag before.

  Details in `RESEARCH-warc-wat-wet.md`, section 4.7.
- **Results files are rewritten whole after every Shard.** A large
  `favicons.json` makes each save slower as the run goes on, on the one task
  that merges results.
- **`--limit` counts Shards to do, not paths.** Re-running a slice with the same
  `--offset` and `--limit` after some of its Shards are done goes on past the
  slice's end, into the next process's paths. `merge` deduplicates, so this
  costs time, not correctness.
- **The RAM guard sees the whole machine.** Each process divides the free RAM by
  its largest Plan on its own, so several processes on one node can together
  schedule more in-memory Shards than fit.
- **Onion Sightings keep no context.** The output records which page mentioned
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
- **One bad record drops the Archive.** A read or decompression error aborts
  the Archive, dropping everything found in it; the kinds reading it are left
  undone and retried on the next run.
- **A download is cut only when no data comes at all.** A server sending a
  few bytes now and then, each within 60 s, keeps a download going however
  slow it is: there is no minimum speed.
