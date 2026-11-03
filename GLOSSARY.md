# Common Crawl extraction

Pulls small, typed pieces of information (such as `.onion` addresses and favicons) out of Common Crawl's published web archives, reading each part of a Crawl once for every Artifact kind requested.

## Language

### Common Crawl data

**Dataset**:
One Common Crawl collection with its own set of available Formats: `CC-MAIN` (general web crawls, WARC + WAT + WET) or `CC-NEWS` (news articles, WARC only).

**Crawl**:
One release of the `CC-MAIN` Dataset, identified like `CC-MAIN-2026-34`.

**Segment**:
Common Crawl's own grouping of files inside a Crawl (100 per Crawl, 1,000 files each per Format), identified like `1786091384908.68`.
_Avoid_: using it for a single file

**Shard**:
One file-level part of a Dataset, identified like `CC-MAIN-20260807101845-20260807131845-00000` or `CC-NEWS-20251001064107-04363`, published as one Archive per Format the Dataset offers.
_Avoid_: segment, WARC file, archive

**Format**:
One of the three forms Common Crawl publishes the same pages in: WARC (raw HTTP responses), WAT (JSON metadata extracted from them), WET (plain text extracted from them).
_Avoid_: archive type, input type, file type

**Archive**:
One downloadable Common Crawl file: one Shard in one Format.
_Avoid_: WARC (when any Format is meant), segment

**Record**:
One entry of an Archive, with its own headers and body. One Page spans several Records of a WARC (its request, response and metadata); each Format reads one type of Record and passes over the rest.
_Avoid_: entry, item; record for a Page

### Extraction

**Artifact kind**:
A category of information that can be requested: `onion` (`.onion` address), `favicon` (favicon URL), `inline-favicon` (favicon image embedded in the page as a `data:` URI).
_Avoid_: data point, feature, target, observable

**Artifact**:
One value of an Artifact kind found in a crawled page, such as one `.onion` address, one favicon URL, or one inline favicon image (identified by the SHA-256 of its bytes).
_Avoid_: match, result

**Page**:
One URL crawled in one Shard, with the date it was crawled; the same URL in another Shard is another Page.
_Avoid_: item, document, record

**Sighting**:
One occurrence of an Artifact: the Page it was seen on, which gives when that Page was crawled and the Shard it came from.
_Avoid_: source, occurrence

**Format requirement**:
The Format combinations able to serve an Artifact kind; for example `onion` is served by WARC alone or by WAT and WET together.
_Avoid_: mapping, minimum format

**Plan**:
The Formats read for one Shard: the cheapest combination, among those its Dataset offers, that meets the Format requirement of every requested Artifact kind.
_Avoid_: strategy

### Running

**Slice**:
A contiguous range of a paths file's lines, given to one run; running the same command again covers the same lines.
_Avoid_: range, chunk, partition (and slice for a Shard)

**Given-up Archive**:
An Archive that failed to download or parse, for a reason that repeats (such as a 404, bytes corrupt at the source, or a bug its bytes trigger), on enough runs that no Plan reading it is scheduled again.
_Avoid_: hopeless Shard, dead Archive, failed Archive
