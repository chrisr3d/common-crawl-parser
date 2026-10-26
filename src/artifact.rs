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
use std::str::FromStr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::format::Format;
use crate::page_record::PageRecord;
use crate::plan::FormatRequirement;

// ---------------------------------------------------------------------------
// Artifact kinds
// ---------------------------------------------------------------------------

/// A category of information that can be extracted from the crawl.
///
/// The behaviour of each kind lives in its `Extractor`; this enum names it
/// and holds the facts that don't depend on any page: its name and its
/// output file. It derives `Copy` because it is a plain tag (one byte), and
/// `Eq` + `Hash` as the Rust API guidelines recommend for public value
/// types, so callers can put kinds in sets or use them as map keys. `Ord`
/// (declaration order) lets a `BTreeMap` keyed by kind list them the same
/// way every run.
///
/// ## `clap::ValueEnum`: one name per kind
///
/// The derive turns each variant into a CLI value, kebab-cased (`Onion` →
/// `onion`, a future `InlineFavicon` → `inline-favicon`), so `--extract`
/// parses kinds without hand-written code. `Display` and `FromStr` below
/// reuse those names, so the CLI, progress output and `processed.log` all
/// spell a kind the same way and can't drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ValueEnum)]
pub enum ArtifactKind {
    /// .onion addresses
    Onion,
    /// Favicon URLs that HTML pages declare
    Favicon,
}

impl ArtifactKind {
    /// Every kind, in declaration order. `value_variants` comes from the
    /// `ValueEnum` derive, so a new variant is listed without editing this.
    pub fn all() -> &'static [ArtifactKind] {
        Self::value_variants()
    }

    /// Name of the JSON file this kind's Sightings are saved in.
    pub fn output_filename(self) -> &'static str {
        match self {
            ArtifactKind::Onion => "onions.json",
            ArtifactKind::Favicon => "favicons.json",
        }
    }

    /// The Format combinations this kind can be extracted from (ADR-0001),
    /// among which the planner chooses (`plan`).
    ///
    /// ## A static table as a `match`
    ///
    /// The table could be a `HashMap` built at startup, but then a new kind
    /// without an entry would only fail when looked up, at runtime. A
    /// `match` on `self` must cover every variant, so a new kind without a
    /// requirement doesn't compile. The slices are written inline:
    /// `&[&[Format::Warc]]` is built from constants only, so the compiler
    /// stores it once in the binary (*constant promotion*) and the
    /// reference lives for `'static`.
    pub fn format_requirement(self) -> FormatRequirement {
        match self {
            // Only WARC can be read so far. Once the WET and WAT readers
            // exist, `onion` also accepts WAT + WET and `favicon` WAT
            // (ADR-0001).
            ArtifactKind::Onion => &[&[Format::Warc]],
            ArtifactKind::Favicon => &[&[Format::Warc]],
        }
    }
}

/// `Display` gives the CLI name, used in progress output and
/// `processed.log`.
impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `to_possible_value` returns `None` only for variants marked
        // `#[value(skip)]`, and none is.
        let value = self.to_possible_value().expect("every kind has a CLI name");
        f.write_str(value.get_name())
    }
}

/// Parse a CLI name back into a kind, so `"onion".parse::<ArtifactKind>()`
/// works outside `clap` too (reading `processed.log`).
impl FromStr for ArtifactKind {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        // Both traits define a `from_str`; the fully qualified
        // `<Self as ValueEnum>::` says which one is meant. `false`: names
        // are case-sensitive, as on the command line.
        <Self as ValueEnum>::from_str(name, false)
    }
}

// ---------------------------------------------------------------------------
// Shards
// ---------------------------------------------------------------------------

/// One file-level slice of a Dataset, such as
/// `CC-MAIN-20260305070756-20260305100756-00000`.
///
/// Common Crawl publishes each Shard as one Archive per Format
/// (`<shard>.warc.gz`, `<shard>.warc.wat.gz`, `<shard>.warc.wet.gz`), so
/// the Shard is what those Archives have in common.
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
    /// suffix (`X.warc.gz`, `X.warc.wat.gz` or `X.warc.wet.gz` → `X`). A
    /// name without one of these suffixes is kept whole.
    pub fn from_archive_name(archive_name: &str) -> Self {
        // `find_map` returns the first `Some` the closure gives: the name
        // stripped of the first suffix it ends with.
        let id = Format::all()
            .iter()
            .find_map(|format| archive_name.strip_suffix(format.suffix()))
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
