// Artifact kinds, Shards and Sightings — the vocabulary extractors speak
//
// An Artifact is one value found in a crawled page (one `.onion` address,
// one favicon URL). A Sighting records where and when it was seen: the page,
// the crawl date, and the Shard the page was read from. Every Artifact kind
// keeps its results the same way, a map from each Artifact to its
// Sightings (`Sightings`).
//
// The helpers at the bottom are the only place that decides when two
// Sightings are "the same": extraction, the per-Archive merge in `main` and
// the `merge` subcommand all go through them.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::page_record::PageRecord;

// ---------------------------------------------------------------------------
// Artifact kinds
// ---------------------------------------------------------------------------

/// A category of information that can be extracted from the crawl.
///
/// The behaviour of each kind lives in its `Extractor`; this enum only
/// names it. It derives `Copy` because it is a plain tag (one byte), and
/// `Eq` + `Hash` as the Rust API guidelines recommend for public value
/// types, so callers can put kinds in sets or use them as map keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// `.onion` addresses.
    Onion,
    /// Favicon URLs that HTML pages declare.
    Favicon,
}

/// `Display` gives the user-facing name, used in progress output.
impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ArtifactKind::Onion => "onion",
            ArtifactKind::Favicon => "favicon",
        })
    }
}

// ---------------------------------------------------------------------------
// Shards
// ---------------------------------------------------------------------------

/// One file-level slice of a Dataset, such as
/// `CC-MAIN-20260305070756-20260305100756-00000`.
///
/// Common Crawl publishes each Shard as one Archive per Format
/// (`<shard>.warc.gz`, later `.warc.wat.gz` and `.warc.wet.gz`), so the
/// Shard is what those Archives have in common.
///
/// ## The newtype pattern
///
/// `Shard` is a tuple struct wrapping a single `String`. At runtime it *is*
/// a `String` (same size, no overhead), but the compiler treats it as its
/// own type: an Archive file name can't be passed where a Shard is expected
/// by mistake, and the only way to build one from a file name is
/// `from_archive_name`, which strips the Format suffix. `serde` serializes a
/// newtype as its inner value, so in JSON a Shard is a plain string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Shard(String);

impl Shard {
    /// The Shard an Archive belongs to: its file name without the Format
    /// suffix (`X.warc.gz` → `X`). A name without that suffix is kept whole.
    pub fn from_archive_name(archive_name: &str) -> Self {
        let id = archive_name
            .strip_suffix(".warc.gz")
            .unwrap_or(archive_name);
        Shard(id.to_string())
    }
}

impl fmt::Display for Shard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Sightings
// ---------------------------------------------------------------------------

/// One occurrence of an Artifact: the page it was seen on, when that page
/// was crawled, and the Shard it came from.
///
/// `Serialize` / `Deserialize` define the JSON shape of `onions.json` and
/// `favicons.json`: `{"page_url": ..., "date": ..., "shard": ...}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sighting {
    /// URL of the crawled page (`WARC-Target-URI`).
    pub page_url: String,
    /// When the page was crawled (`WARC-Date`).
    pub date: String,
    /// The Shard the page was read from.
    pub shard: Shard,
}

impl Sighting {
    /// A Sighting on the page `record` came from.
    pub fn new(record: &PageRecord<'_>, shard: &Shard) -> Self {
        Self {
            page_url: record.page_url().to_string(),
            date: record.date().to_string(),
            shard: shard.clone(),
        }
    }
}

/// The results of one Artifact kind: each Artifact mapped to the pages it
/// was seen on.
pub type Sightings = HashMap<String, Vec<Sighting>>;

/// Record that every Artifact in `found` was seen on `record`'s page.
///
/// Builds the `Sighting` only when something was found: most pages contain
/// no Artifact of a given kind, and those pages then cost no allocation.
pub fn add_sightings(
    sightings: &mut Sightings,
    found: Vec<String>,
    record: &PageRecord<'_>,
    shard: &Shard,
) {
    if found.is_empty() {
        return;
    }
    let sighting = Sighting::new(record, shard);
    for artifact in found {
        push_unless_seen(sightings.entry(artifact).or_default(), sighting.clone());
    }
}

/// Merge the Sightings in `from` into `into`, skipping pages already listed.
pub fn merge_sightings(into: &mut Sightings, from: Sightings) {
    for (artifact, list) in from {
        let existing = into.entry(artifact).or_default();
        for sighting in list {
            push_unless_seen(existing, sighting);
        }
    }
}

/// Append `sighting` unless the same page of the same Shard is already
/// listed.
///
/// Sightings are deduplicated on `(page_url, shard)`: an Artifact found
/// twice on one page is one Sighting, but the same page crawled again in
/// another Shard is a second one.
fn push_unless_seen(list: &mut Vec<Sighting>, sighting: Sighting) {
    let seen = list
        .iter()
        .any(|s| s.page_url == sighting.page_url && s.shard == sighting.shard);
    if !seen {
        list.push(sighting);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sighting(page_url: &str, archive_name: &str) -> Sighting {
        Sighting {
            page_url: page_url.to_string(),
            date: "2025-01-01T00:00:00Z".to_string(),
            shard: Shard::from_archive_name(archive_name),
        }
    }

    #[test]
    fn sighting_json_has_page_url_date_and_shard() {
        let json = serde_json::to_value(sighting(
            "https://example.com/",
            "CC-MAIN-20250101000000-20250101010101-00000.warc.gz",
        ))
        .unwrap();

        assert_eq!(
            json,
            serde_json::json!({
                "page_url": "https://example.com/",
                "date": "2025-01-01T00:00:00Z",
                "shard": "CC-MAIN-20250101000000-20250101010101-00000",
            })
        );
    }

    #[test]
    fn merge_keeps_one_sighting_per_page_and_shard() {
        let page = "https://example.com/";
        let mut merged = Sightings::new();
        merged.insert(
            "a.onion".to_string(),
            vec![sighting(page, "shard-1.warc.gz")],
        );

        let mut more = Sightings::new();
        more.insert(
            "a.onion".to_string(),
            vec![
                // Same page, same Shard: already listed.
                sighting(page, "shard-1.warc.gz"),
                // Same page, crawled again in another Shard: kept.
                sighting(page, "shard-2.warc.gz"),
            ],
        );
        merge_sightings(&mut merged, more);

        assert_eq!(
            merged["a.onion"],
            [
                sighting(page, "shard-1.warc.gz"),
                sighting(page, "shard-2.warc.gz")
            ]
        );
    }
}
