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
for it (ADR-0001). Cost is the estimated Archive size: WARC ~1 GB, WAT ~170 MB,
WET ~70 MB. Inside the Plan, each kind reads the cheapest of its own accepted
combinations:

| Kinds to do | Plan on CC-MAIN | Who reads what |
|---|---|---|
| `onion` + `favicon` | WAT + WET (~240 MB) | `onion` both, `favicon` WAT |
| `onion` | WAT + WET | `onion` both |
| `favicon` | WAT (~170 MB) | `favicon` WAT |
| anything with `inline-favicon` | WARC (~1 GB) | every kind WARC |

CC-MAIN publishes all three Formats; CC-NEWS is taken to publish WARC only, so
its Plan is always WARC (see [Known limitations](#known-limitations)). Since the
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
Archive that kind reads has been downloaded and parsed (ADR-0002); a failed
WET Archive leaves `onion` undone but still lets `favicon` finish from WAT.

## 3. Download

Each Archive is fetched over HTTPS with `reqwest` (rustls, no OpenSSL). One HTTP
client is shared by all jobs so connections are reused. Progress is printed every
10 MB. A Shard's Archives are downloaded one after the other; Shards download
concurrently.

Where the bytes go depends on the Transport (`-t` / `--transport`, see the next
section):

- **`disk` and `mmap` (default `disk`).** The Archive is streamed to
  `download/<file name>`, under the current directory. If that file already
  exists, the download is skipped and the existing file is parsed. `-d` /
  `--delete` removes each Archive of the Shard once it has parsed.
- **`memory`.** The Archive is collected into a `Vec<u8>` (pre-sized from
  `Content-Length`) and handed to the parser without touching the disk.

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
| `mmap` | Decompress to a temporary file next to the Archive (3 to 5 GB for a WARC), memory-map it and read records as slices into it (`WarcSliceIter`); the file is deleted afterwards, unless decompressing it failed |

## 5. Onion extraction

Code: `src/onion_search.rs`, `OnionExtractor` in `src/extractor.rs`.

**What matches.** A run of exactly 16 (v2) or 56 (v3) characters from the base32
alphabet `[a-z2-7]`, followed by `.onion`, with a word boundary on both sides.
This is the regex `\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b`.

`--onion-engine` picks the search; both find the same addresses, and unit tests
check that they agree:

| Engine | Technique |
|---|---|
| `memchr` (default) | Jump to each `.onion` literal with SIMD `memmem`, count base32 characters backwards, check the boundaries |
| `regex` | The regex above, with `regex::bytes` on the raw bytes |

**Where it looks.** Every page record, whatever its content type:

- WARC: the whole HTTP response: HTML, JavaScript, JSON, plain text, and the HTTP
  headers. Headers matter: in the sample measured in
  `RESEARCH-warc-wat-wet.md`, 53 % of matches came from `Onion-Location` and
  `Content-Security-Policy` headers.
- WAT: the raw JSON bytes, which repeat the HTTP headers and hold the page's
  links, link texts and `<meta>` contents. An address is made of `[a-z2-7.]`,
  which JSON never escapes, so it is found as in WARC.
- WET: the page's text.

Together, WAT and WET hold the places an onion was found in the research
sample; [Known limitations](#known-limitations) lists the places they don't.

**What it records.** For each address, one Sighting per distinct
`(page_url, shard)` pair:

```json
{
  "exampleexampleexampleexampleexampleexampleexampleexample.onion": [
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
`extract_favicon_from_html()`, but WARC pages are scanned as bytes with
`memchr` instead of building a DOM.

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
| `<link>` | `rel` equal to `icon`, `shortcut icon`, `mask-icon` or `apple-touch-icon` (case-insensitive) | `href` |
| `<meta>` | `name="msapplication-TileImage"` (case-insensitive) | `content` |

In WARC, attribute values may be double-quoted, single-quoted or bare, in any
order inside the tag. A `>` inside a quoted value does not end the tag. Each
tag name (`<link `, `<LINK `, `<meta `, `<META `) is scanned for separately; if
one of its tags doesn't close within 4 KB, that scan treats the page as
truncated and stops there, while the others carry on.

**URL resolution.** Each value is turned into an absolute URL as a browser
would: against the page's `<base href>` (itself resolved against the page URL)
when it has one, else against the page URL (`WARC-Target-URI`). In WARC the
first `<base>` with an `href` counts, and it is only looked for once the page
declares a favicon; in WAT it is ia-web-commons' `Head.Base`.

- `https://cdn.example/fav.png` is kept as is;
- `//cdn.example/fav.png` gets the base's scheme;
- `/icons/fav.png` gets the base's scheme and host;
- `fav.png` is resolved against the base's directory.

**No root guess.** Unlike AIL, no `{scheme}://{host}/favicon.ico` is added for
pages that declare nothing: only declared favicons are recorded (ADR-0003).

**`data:` values** are not favicon URLs. In WARC, base64 ones are handed to the
`inline-favicon` kind (next section); in WAT they are skipped, since
ia-web-commons cuts every `data:` URL after its first comma.

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

A kind's file is saved before its `<shard> <kind>` line is appended, so a crash
in between leaves the pair undone and the next run extracts it again;
deduplication makes that redo change nothing. A later run with more kinds
extracts only the new ones for the Shards already done. A Shard whose download
or parse failed is not marked for the kinds reading the failed Archive, and is
retried on the next run. Lines `processed.log` can't read (such as bare Archive
names, written before kinds were tracked) are ignored, so those Shards are
processed again.

The summary at the end reports processed, skipped and failed Shards, new and
total Artifacts per kind, and average download and parse time per Shard.

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

## Known limitations

Behaviour that is surprising or incomplete today, roughly in order of impact.

- **WAT + WET don't see everything WARC does.** They drop some places an onion
  can hide: inline `<script>` bodies, HTML comments, `<style>`, the bodies of
  non-HTML responses (JavaScript, JSON, CSS, PDF, plain text) and request
  records. None of the matches in the research sample lived there, but the
  sample holds 38 onions. In WAT, an address right after a JSON escape (`\n`,
  `\u2003`) is missed, the escape's last character reading as part of it, and
  one in the page URL itself is found, since the JSON repeats the WARC
  headers (WARC only searches the HTTP response). For favicons, ia-web-commons
  reads the `<head>` with its own parser, so the two Formats can differ where
  the byte scanner is narrower (below), and it probably keeps the *last*
  `<base>` of a page where the scanner keeps the first. `--formats warc` runs a
  WARC spot-check.
- **Results files are rewritten whole after every Shard.** A large
  `favicons.json` makes each save slower as the run goes on, on the one task
  that merges results.
- **Interrupted downloads are reused as if complete.** With the `disk` and
  `mmap` Transports, a partial `download/<file>` left by a failed or killed
  download counts as "already downloaded" on the next run. The truncated
  Archive then fails to parse (or yields partial results) on every retry,
  until the file is deleted by hand.
- **`--limit` counts Shards to do, not paths.** Re-running a slice with the same
  `--offset` and `--limit` after some of its Shards are done goes on past the
  slice's end, into the next process's paths. `merge` deduplicates, so this
  costs time, not correctness.
- **Failed Shards don't change the exit status.** A run exits with 0 even when
  Shards failed (they are counted in the summary and retried next run); it
  exits with 1 only when it stops early, such as on an unreadable results file
  or an `--offset` past the end of the paths file.
- **The RAM guard sees the whole machine.** Each process divides the free RAM by
  its largest Plan on its own, so several processes on one node can together
  schedule more in-memory Shards than fit.
- **CC-NEWS's Formats are unverified.** That CC-NEWS publishes WARC only was
  written from memory, commoncrawl.org being unreachable at the time. If it
  publishes WAT or WET too, its Plans are more expensive than they need to be.
- **Onion matching is by shape only.**
  - Case-sensitive. An address written in uppercase (`ABCD...XYZ.ONION`) is
    missed. Making the pattern case-insensitive with `(?i)` slowed the regex by
    over 1000x (see `PROGRESS.md`, Performance Fixes).
  - A v3 address carries a checksum and a version byte; neither is verified, so
    any 56-character base32 run in front of `.onion` is accepted.
  - v2 addresses (16 characters) are still matched although Tor dropped them in
    2021. They are useful as history, not as live services.
  - No context is kept: the output records which page mentioned the address,
    not where on the page or in what role (link, header, plain text).
- **Favicon tag matching in WARC is narrower than HTML.**
  - Only `<link ` and `<LINK ` are found (likewise `<meta `, `<base `), so mixed
    case (`<Link`) and a newline or tab right after the tag name are missed.
  - `rel` must equal one of the four values exactly, which misses
    `apple-touch-icon-precomposed`, `alternate icon`, and `icon` with extra
    spaces.
  - `../` segments are not normalised.
  - A `<link>` or `<meta>` tag that doesn't close within 4 KB stops the scan
    for that tag name (such as `<link `) in the rest of the page. Large inline
    `data:` favicons can hit this.
- **One bad record drops the Archive.** A read or decompression error aborts
  the Archive, dropping everything found in it; the kinds reading it are left
  undone and retried on the next run.
