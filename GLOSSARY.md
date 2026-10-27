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
One file-level slice of a Dataset, identified like `CC-MAIN-20260807101845-20260807131845-00000` or `CC-NEWS-20251001064107-04363`, published as one Archive per Format the Dataset offers.
_Avoid_: segment, WARC file, archive

**Format**:
One of the three forms Common Crawl publishes the same pages in: WARC (raw HTTP responses), WAT (JSON metadata extracted from them), WET (plain text extracted from them).
_Avoid_: archive type, input type, file type

**Archive**:
One downloadable Common Crawl file: one Shard in one Format.
_Avoid_: WARC (when any Format is meant), segment

### Extraction

**Artifact kind**:
A category of information that can be requested: `onion` (`.onion` address), `favicon` (favicon URL), `inline-favicon` (favicon image embedded in the page as a `data:` URI).
_Avoid_: data point, feature, target, observable

**Artifact**:
One value of an Artifact kind found in a crawled page, such as one `.onion` address or one favicon URL.
_Avoid_: match, result

**Sighting**:
One occurrence of an Artifact: the page it was seen on, when that page was crawled, and the Shard it came from.
_Avoid_: source, occurrence

**Format requirement**:
The Format combinations able to serve an Artifact kind; for example `onion` is served by WARC alone or by WAT and WET together.
_Avoid_: mapping, minimum format

**Plan**:
The Formats read for one Shard: the cheapest combination, among those its Dataset offers, that meets the Format requirement of every requested Artifact kind.
_Avoid_: strategy
