// Extractors — one per Artifact kind
//
// `parse_archive` reads every record of an Archive once and hands each one
// to every extractor in a list of `Box<dyn Extractor>`. It never looks at
// which kinds are in the list, so adding an Artifact kind means writing one
// more `impl Extractor`, without touching the parsing loop.

use clap::ValueEnum;
use regex::bytes::Regex;

use crate::artifact::{
    ArtifactEntry, ArtifactKind, Findings, Shard, Sighting, Sightings, add_sightings,
};
use crate::inline_favicon::{InlineFavicon, InlineFavicons, sha256_hex};
use crate::onion_search::SuffixFinder;
use crate::page_record::PageRecord;
use crate::{favicon_search, onion_search};

/// Finds the Artifacts of one kind in the pages of one Shard.
///
/// ## Trait objects: `Box<dyn Extractor>`
///
/// `OnionExtractor` and `FaviconExtractor` are different types with
/// different sizes, so they can't sit side by side in a `Vec` directly.
/// `Box<dyn Extractor>` puts each one on the heap behind a *fat pointer*:
/// a pointer to the data plus a pointer to a *vtable*, a table of function
/// pointers for this trait's methods, one table per implementing type. Calling `extractor.extract(..)`
/// looks the method up in that table at runtime (*dynamic dispatch*).
///
/// The alternative, generics (`fn parse_archive<E: Extractor>(..)`), would
/// compile one copy of the loop per extractor type and could only hold
/// *one* type per list. Here the set of kinds is chosen at runtime, so
/// dynamic dispatch is the right tool; its cost (one indirect call per
/// record per extractor) is nothing next to gzip decompression.
pub trait Extractor {
    /// The Artifact kind this extractor finds.
    fn kind(&self) -> ArtifactKind;

    /// Look for Artifacts in one page and record where they were seen.
    fn extract(&mut self, record: &PageRecord<'_>, shard: &Shard);

    /// Number of distinct Artifacts found so far, for progress output.
    fn artifact_count(&self) -> usize;

    /// Hand over everything found, consuming the extractor.
    ///
    /// `self: Box<Self>` lets the method take ownership through the box.
    /// A plain `self` would need the concrete type's size, which a
    /// `dyn Extractor` doesn't have, so it couldn't be called on a trait
    /// object.
    fn into_findings(self: Box<Self>) -> Findings;
}

// ---------------------------------------------------------------------------
// Onion addresses
// ---------------------------------------------------------------------------

/// Which search the onion extractor runs. Both find the same addresses.
///
/// `ValueEnum` lets `--onion-engine` parse it, like `ArtifactKind`; the
/// variants' doc comments become the values' help text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OnionEngine {
    /// SIMD memmem search for ".onion", then hand-written validation
    Memchr,
    /// Regular expression (regex::bytes) over the raw bytes
    Regex,
}

/// Finds `.onion` addresses anywhere in a page: the page URL and the whole
/// HTTP response of a WARC record, the JSON of a WAT record, the text of a
/// WET record.
pub struct OnionExtractor {
    search: OnionSearch,
    sightings: Sightings,
}

/// An `OnionEngine`, ready to run: the `SuffixFinder` or `Regex` is built
/// once per extractor, not once per record.
///
/// An enum is as large as its largest variant, and Clippy warns when one
/// variant dwarfs the others (two `Finder`s here, against a `Regex` that is
/// a handle to shared state): each value of the enum wastes the difference.
/// `#[expect]` silences the warning, with the reason, and itself warns if
/// the lint ever stops firing, where `#[allow]` would stay silently.
#[expect(
    clippy::large_enum_variant,
    reason = "one value per extractor, already on the heap in a Box<dyn Extractor>"
)]
enum OnionSearch {
    Memchr(SuffixFinder),
    Regex(Regex),
}

impl OnionExtractor {
    pub fn new(engine: OnionEngine) -> Self {
        let search = match engine {
            OnionEngine::Memchr => OnionSearch::Memchr(SuffixFinder::new()),
            OnionEngine::Regex => OnionSearch::Regex(
                Regex::new(onion_search::ONION_PATTERN).expect("ONION_PATTERN is a valid regex"),
            ),
        };
        Self {
            search,
            sightings: Sightings::new(),
        }
    }
}

impl Extractor for OnionExtractor {
    fn kind(&self) -> ArtifactKind {
        ArtifactKind::Onion
    }

    fn extract(&mut self, record: &PageRecord<'_>, shard: &Shard) {
        // One closure runs the engine on any bytes: each arm below only
        // names what it searches, the WARC one twice.
        let search = |haystack: &[u8]| match &self.search {
            OnionSearch::Memchr(finder) => onion_search::search_memchr(haystack, finder),
            OnionSearch::Regex(re) => onion_search::search_regex_bytes(haystack, re),
        };
        let found = match record {
            // The page URL, then the whole response, HTTP headers
            // included: about half of the onions found sit in headers
            // such as `Onion-Location`. The URL holds the address of a
            // page read through a Tor gateway (`<address>.onion.ly`); an
            // address in both the URL and the response is still one
            // Sighting (`add_sightings`).
            PageRecord::Warc(response) => {
                let mut found = search(response.page_url.as_bytes());
                found.extend(search(response.http_response));
                found
            }
            // The raw JSON, searched like the HTTP response: an address is
            // made of `[a-zA-Z2-7.]` only, which ia-web-commons doesn't
            // escape, and the bytes around it (`"`, `/`, `:`, space) are
            // word boundaries, so the addresses WAT kept are found as in
            // the WARC record, the page URL's included (the JSON repeats
            // the WARC headers). Two differences: onions only in the
            // page's plain text are gone (WET has them), and one right
            // after an escape such as `\n` or `\u2003` is missed, the
            // escape's last character reading as part of the address.
            PageRecord::Wat(metadata) => search(metadata.json),
            // Only the onions written out as text on the page.
            PageRecord::Wet(conversion) => search(conversion.text),
        };
        add_sightings(&mut self.sightings, found, record, shard);
    }

    fn artifact_count(&self) -> usize {
        self.sightings.len()
    }

    fn into_findings(self: Box<Self>) -> Findings {
        Findings::Sightings(self.sightings)
    }
}

// ---------------------------------------------------------------------------
// Favicon URLs
// ---------------------------------------------------------------------------

/// Finds the favicon URLs that HTML pages declare.
#[derive(Default)]
pub struct FaviconExtractor {
    sightings: Sightings,
}

impl FaviconExtractor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Extractor for FaviconExtractor {
    fn kind(&self) -> ArtifactKind {
        ArtifactKind::Favicon
    }

    fn extract(&mut self, record: &PageRecord<'_>, shard: &Shard) {
        let found = match record {
            // The scanner also decodes inline `data:` favicons: those are
            // the `inline-favicon` kind's (`InlineFaviconExtractor`).
            PageRecord::Warc(response) => response
                .html_body()
                .map(|html| favicon_search::extract_favicons(html, response.page_url).urls),
            // ia-web-commons already parsed the page's `<head>`.
            PageRecord::Wat(metadata) => metadata
                .head
                .as_ref()
                .map(|head| favicon_search::favicons_in_head(head, metadata.page_url)),
            // WET keeps only the page's text: no `<link>` or `<meta>` tag
            // survives, so there is nothing to find.
            PageRecord::Wet(_) => None,
        };
        // `None` (not an HTML page) finds nothing, like an empty list.
        add_sightings(
            &mut self.sightings,
            found.unwrap_or_default(),
            record,
            shard,
        );
    }

    fn artifact_count(&self) -> usize {
        self.sightings.len()
    }

    fn into_findings(self: Box<Self>) -> Findings {
        Findings::Sightings(self.sightings)
    }
}

// ---------------------------------------------------------------------------
// Inline favicons
// ---------------------------------------------------------------------------

/// Finds the favicon images that HTML pages embed as base64 `data:` URIs,
/// each one kept under the SHA-256 of its bytes.
#[derive(Default)]
pub struct InlineFaviconExtractor {
    favicons: InlineFavicons,
}

impl InlineFaviconExtractor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Extractor for InlineFaviconExtractor {
    fn kind(&self) -> ArtifactKind {
        ArtifactKind::InlineFavicon
    }

    fn extract(&mut self, record: &PageRecord<'_>, shard: &Shard) {
        // Only WARC keeps the images (`ArtifactKind::format_requirement`).
        let PageRecord::Warc(response) = record else {
            return;
        };
        let Some(html) = response.html_body() else {
            return;
        };
        // The same scan as the favicon extractor's, which keeps the URLs:
        // with both kinds requested, a page is scanned twice, a few
        // microseconds next to its decompression.
        let images = favicon_search::extract_favicons(html, response.page_url).inline_favicons;
        if images.is_empty() {
            return;
        }

        let sighting = Sighting::new(record, shard);
        for image in images {
            self.favicons
                .entry(sha256_hex(&image.bytes))
                // The other hashes are computed the first time an image is
                // seen only. The key is an owned `String`, so its borrow of
                // `image` has ended: the closure can move `image` into the
                // new entry.
                .or_insert_with(|| InlineFavicon::new(image))
                .add_sighting(sighting.clone());
        }
    }

    fn artifact_count(&self) -> usize {
        self.favicons.len()
    }

    fn into_findings(self: Box<Self>) -> Findings {
        Findings::InlineFavicons(self.favicons)
    }
}
