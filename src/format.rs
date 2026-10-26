// Formats and Datasets — what Common Crawl publishes, and where
//
// Common Crawl publishes each Shard of a Crawl in up to three Formats: WARC
// (the raw HTTP responses), WAT (JSON metadata extracted from them) and WET
// (their visible text). A Dataset decides which of the three exist, and
// the planner (`plan`) only chooses among those.

use std::fmt;

use clap::ValueEnum;

use crate::artifact::Shard;

// ---------------------------------------------------------------------------
// Formats
// ---------------------------------------------------------------------------

/// One of the forms Common Crawl publishes the same pages in.
///
/// `ValueEnum` lets `--formats` parse it (`warc`, `wat`, `wet`), as for
/// `ArtifactKind`; the variants' doc comments become the values' help text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ValueEnum)]
pub enum Format {
    /// Raw HTTP responses, headers and body (~1 GB per Shard)
    Warc,
    /// JSON metadata extracted from each response (~170 MB per Shard)
    Wat,
    /// Plain text extracted from each HTML page (~70 MB per Shard)
    Wet,
}

/// One megabyte, counted as 1024 × 1024 bytes as in the progress output;
/// the unit of `Format::estimated_size`.
const MB: u64 = 1_048_576;

impl Format {
    /// Every Format, in declaration order.
    pub fn all() -> &'static [Format] {
        Self::value_variants()
    }

    /// End of the file name of this Format's Archives.
    pub fn suffix(self) -> &'static str {
        match self {
            Format::Warc => ".warc.gz",
            Format::Wat => ".warc.wat.gz",
            Format::Wet => ".warc.wet.gz",
        }
    }

    /// Name of the directory holding this Format's Archives, the last one
    /// in their path (`…/segments/<segment>/wat/<archive>`).
    pub fn directory(self) -> &'static str {
        match self {
            Format::Warc => "warc",
            Format::Wat => "wat",
            Format::Wet => "wet",
        }
    }

    /// Typical size of one Archive in this Format: the cost the planner
    /// minimizes, and what the RAM guard of `--transport memory` expects
    /// one download to hold.
    pub fn estimated_size(self) -> u64 {
        match self {
            Format::Warc => 1024 * MB,
            Format::Wat => 170 * MB,
            Format::Wet => 70 * MB,
        }
    }

    /// The Format of an Archive, from the suffix of its file name.
    pub fn from_archive_name(archive_name: &str) -> Option<Format> {
        Self::all()
            .iter()
            .copied()
            .find(|format| archive_name.ends_with(format.suffix()))
    }

    /// This Format's bit in a `FormatSet`.
    ///
    /// `as u8` turns a fieldless variant into its discriminant, its
    /// position in the declaration (`Warc` 0, `Wat` 1, `Wet` 2), so each
    /// Format gets a bit of its own: `0b001`, `0b010`, `0b100`.
    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// `Display` gives the CLI name (`warc`), as for `ArtifactKind`.
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self
            .to_possible_value()
            .expect("every Format has a CLI name");
        f.write_str(value.get_name())
    }
}

// ---------------------------------------------------------------------------
// Sets of Formats
// ---------------------------------------------------------------------------

/// A set of Formats: a Plan, or one combination a kind accepts.
///
/// ## Bitmasks
///
/// Each Format owns one bit of a `u8` (`Format::bit`), and a set is the OR
/// of its members' bits: WAT + WET is `0b010 | 0b100 = 0b110`. Set
/// operations then become single integer operations:
///
/// - union: `a | b`
/// - "every member of `a` is in `b`": no bit of `a` is outside `b`, so
///   `a & !b == 0`
///
/// and the subsets of a set are numbers no larger than the set itself
/// (`subsets`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FormatSet(u8);

impl FormatSet {
    /// No Format at all.
    pub const EMPTY: FormatSet = FormatSet(0);

    /// The set of `formats`.
    pub fn of(formats: &[Format]) -> FormatSet {
        formats.iter().copied().collect()
    }

    pub fn contains(self, format: Format) -> bool {
        self.0 & format.bit() != 0
    }

    /// Whether every Format of `self` is also in `other`.
    pub fn is_subset_of(self, other: FormatSet) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn union(self, other: FormatSet) -> FormatSet {
        FormatSet(self.0 | other.0)
    }

    /// The Formats in the set, in declaration order.
    ///
    /// `move` copies `self` (a `Copy` byte) into the closure: the iterator
    /// can outlive this call, so it can't borrow a local.
    pub fn iter(self) -> impl Iterator<Item = Format> {
        Format::all()
            .iter()
            .copied()
            .filter(move |&format| self.contains(format))
    }

    /// The total estimated size of one Archive per Format in the set.
    pub fn estimated_size(self) -> u64 {
        self.iter().map(Format::estimated_size).sum()
    }

    /// Every non-empty subset of this set.
    ///
    /// ## Enumerating subsets with a bitmask
    ///
    /// A subset only clears bits, so its value is at most the set's own;
    /// counting from 1 (the smallest non-empty set) up to the set's value
    /// visits every subset, plus numbers that have a bit the set lacks,
    /// which `is_subset_of` drops. With three Formats that is at most
    /// seven numbers, so trying them all costs nothing.
    pub fn subsets(self) -> impl Iterator<Item = FormatSet> {
        (1..=self.0)
            .map(FormatSet)
            .filter(move |subset| subset.is_subset_of(self))
    }
}

/// `collect()` into a `FormatSet`, such as the Formats of a list of
/// Archives: `archives.iter().map(ArchivePath::format).collect()`.
///
/// `FromIterator` is the trait `collect` builds its result through, so
/// implementing it makes `FormatSet` a valid target, like `Vec` or `HashSet`.
impl FromIterator<Format> for FormatSet {
    fn from_iter<I: IntoIterator<Item = Format>>(formats: I) -> Self {
        FormatSet(
            formats
                .into_iter()
                .fold(0, |bits, format| bits | format.bit()),
        )
    }
}

/// `wat,wet`: the Formats as written for `--formats`.
impl fmt::Display for FormatSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.iter().map(|format| format.to_string()).collect();
        f.write_str(&names.join(","))
    }
}

// ---------------------------------------------------------------------------
// Datasets
// ---------------------------------------------------------------------------

/// One Common Crawl collection, with its own set of Formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dataset {
    /// General web crawls, one Crawl per release (`CC-MAIN-2025-01`).
    CcMain,
    /// News articles, published continuously.
    CcNews,
}

impl Dataset {
    /// The Dataset an Archive path belongs to, from its first directories:
    /// `crawl-data/CC-MAIN-<crawl>/…` or `crawl-data/CC-NEWS/…`.
    pub fn from_uri(uri: &str) -> Option<Dataset> {
        if uri.starts_with("crawl-data/CC-MAIN-") {
            Some(Dataset::CcMain)
        } else if uri.starts_with("crawl-data/CC-NEWS/") {
            Some(Dataset::CcNews)
        } else {
            None
        }
    }

    /// The Formats this Dataset publishes every Shard in.
    pub fn available_formats(self) -> FormatSet {
        match self {
            Dataset::CcMain => FormatSet::of(&[Format::Warc, Format::Wat, Format::Wet]),
            // Unverified: written from memory, commoncrawl.org was not
            // reachable to check that CC-NEWS publishes no WAT or WET.
            Dataset::CcNews => FormatSet::of(&[Format::Warc]),
        }
    }
}

/// `CC-MAIN` / `CC-NEWS`, as in the Archive paths.
impl fmt::Display for Dataset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Dataset::CcMain => "CC-MAIN",
            Dataset::CcNews => "CC-NEWS",
        })
    }
}

// ---------------------------------------------------------------------------
// Archive paths
// ---------------------------------------------------------------------------

/// Where one Archive is on Common Crawl's server: one line of a paths file,
/// such as
/// `crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/wat/CC-MAIN-20250101000000-20250101010101-00000.warc.wat.gz`.
///
/// The Archives of one Shard in the other Formats sit at the same path with
/// another last directory and suffix (`…/warc/….warc.gz`,
/// `…/wet/….warc.wet.gz`), so any paths file locates all three
/// (`in_format`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivePath {
    uri: String,
    dataset: Dataset,
    format: Format,
}

impl ArchivePath {
    /// Read one paths file line; fails when its Dataset or Format is unknown.
    pub fn parse(uri: &str) -> Result<ArchivePath, String> {
        let dataset = Dataset::from_uri(uri).ok_or(
            "not in a known Dataset (crawl-data/CC-MAIN-<crawl>/… or crawl-data/CC-NEWS/…)",
        )?;
        let format = Format::from_archive_name(file_name(uri)).ok_or(
            "not a known Format (file name ending in .warc.gz, .warc.wat.gz or .warc.wet.gz)",
        )?;
        Ok(ArchivePath {
            uri: uri.to_string(),
            dataset,
            format,
        })
    }

    /// The path relative to Common Crawl's base URL, as in the paths file.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The last component of the path, such as `<shard>.warc.wat.gz`.
    pub fn file_name(&self) -> &str {
        file_name(&self.uri)
    }

    pub fn dataset(&self) -> Dataset {
        self.dataset
    }

    pub fn format(&self) -> Format {
        self.format
    }

    /// The Shard this Archive is one Format of.
    pub fn shard(&self) -> Shard {
        Shard::from_archive_name(self.file_name())
    }

    /// The same Shard's Archive in `format`: the last directory and the
    /// suffix swapped for `format`'s. `None` when the path doesn't end in
    /// `/<directory>/<shard><suffix>` for its own Format, as CC-NEWS paths
    /// don't (they have no other Format to point to).
    pub fn in_format(&self, format: Format) -> Option<ArchivePath> {
        if format == self.format {
            return Some(self.clone());
        }
        let (directory, file_name) = self.uri.rsplit_once('/')?;
        let parent = directory.strip_suffix(self.format.directory())?;
        // `parent` must end where a directory ends: `…/wat`, not `…/xwat`.
        if !parent.ends_with('/') {
            return None;
        }
        let shard = file_name.strip_suffix(self.format.suffix())?;
        Some(ArchivePath {
            uri: format!("{parent}{}/{shard}{}", format.directory(), format.suffix()),
            dataset: self.dataset,
            format,
        })
    }
}

/// The last component of a `/`-separated path.
///
/// `rsplit` always yields at least one piece (the whole string when there
/// is no `/`), so `next()` can't return `None` here.
fn file_name(uri: &str) -> &str {
    uri.rsplit('/').next().unwrap_or(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use Format::{Warc, Wat, Wet};

    // Made-up paths in the shape Common Crawl publishes; any Crawl, segment
    // and Shard would do.
    const WARC_PATH: &str = "crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/warc/\
                             CC-MAIN-20250101000000-20250101010101-00000.warc.gz";
    const WAT_PATH: &str = "crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/wat/\
                            CC-MAIN-20250101000000-20250101010101-00000.warc.wat.gz";
    const WET_PATH: &str = "crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/wet/\
                            CC-MAIN-20250101000000-20250101010101-00000.warc.wet.gz";
    const NEWS_PATH: &str = "crawl-data/CC-NEWS/2025/01/CC-NEWS-20250101000000-00000.warc.gz";

    #[test]
    fn any_format_path_derives_the_others() {
        let paths = [(Warc, WARC_PATH), (Wat, WAT_PATH), (Wet, WET_PATH)];
        for (_, from) in paths {
            let archive = ArchivePath::parse(from).unwrap();
            for (format, expected) in paths {
                assert_eq!(
                    archive.in_format(format).unwrap().uri(),
                    expected,
                    "from {from}"
                );
            }
        }
    }

    #[test]
    fn every_format_names_the_same_shard() {
        for (path, format) in [(WARC_PATH, Warc), (WAT_PATH, Wat), (WET_PATH, Wet)] {
            let archive = ArchivePath::parse(path).unwrap();
            assert_eq!(archive.format(), format);
            assert_eq!(archive.dataset(), Dataset::CcMain);
            assert_eq!(
                archive.shard().to_string(),
                "CC-MAIN-20250101000000-20250101010101-00000"
            );
        }
    }

    #[test]
    fn cc_news_paths_are_parsed() {
        let archive = ArchivePath::parse(NEWS_PATH).unwrap();
        assert_eq!(archive.dataset(), Dataset::CcNews);
        assert_eq!(archive.format(), Warc);
        assert_eq!(archive.shard().to_string(), "CC-NEWS-20250101000000-00000");
        assert_eq!(archive.in_format(Warc).unwrap().uri(), NEWS_PATH);
    }

    #[test]
    fn paths_outside_known_datasets_or_formats_are_rejected() {
        assert!(ArchivePath::parse("crawl-data/CC-OTHER/2025/01/X-00000.warc.gz").is_err());
        assert!(
            ArchivePath::parse("crawl-data/CC-MAIN-2025-01/segments/1.00/arc/X-00000.arc.gz")
                .is_err()
        );
    }
}
