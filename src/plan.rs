// The planner — which Formats to read for one Shard (ADR-0001)
//
// Each Artifact kind accepts some Format combinations, its Format
// requirement (`ArtifactKind::format_requirement`). The Plan for a Shard is
// the cheapest set of Formats, among those its Dataset publishes, that
// contains an accepted combination of every requested kind. Each kind then
// reads the cheapest of its own combinations inside the Plan: with `onion`
// (WARC, or WAT + WET) and `favicon` (WARC, or WAT), the Plan is WAT + WET,
// `onion` reads both and `favicon` reads WAT only.
//
// The cost of a set is the estimated size of its Archives
// (`Format::estimated_size`), what a Shard costs to download.

use std::error::Error;
use std::fmt;

use crate::artifact::ArtifactKind;
use crate::format::{Dataset, Format, FormatSet};

// ---------------------------------------------------------------------------
// Format requirements and the planner
// ---------------------------------------------------------------------------

/// The Format combinations that can serve one Artifact kind; any one of
/// them is enough. `&[&[Format::Warc], &[Format::Wat, Format::Wet]]` reads
/// "WARC, or WAT and WET together".
pub type FormatRequirement = &'static [&'static [Format]];

/// The cheapest of `requirement`'s combinations made only of Formats in
/// `inside`; `None` when none of them fits.
///
/// ## `Iterator::min_by_key`
///
/// `min_by_key` returns the item whose key is smallest, `None` for an empty
/// iterator, so "no combination fits" needs no separate check. The key is
/// computed by a closure (here the estimated size), so the items themselves
/// need no `Ord`.
pub fn cheapest_fit(requirement: FormatRequirement, inside: FormatSet) -> Option<FormatSet> {
    requirement
        .iter()
        .map(|combination| FormatSet::of(combination))
        .filter(|combination| combination.is_subset_of(inside))
        .min_by_key(|combination| combination.estimated_size())
}

/// The cheapest subset of `available` that contains an accepted
/// combination of every requirement; `None` when even all of `available`
/// can't serve one of them.
///
/// Every non-empty subset is tried (`FormatSet::subsets`): with three
/// Formats there are seven, so a cleverer search would gain nothing.
pub fn cheapest_plan(
    available: FormatSet,
    requirements: &[FormatRequirement],
) -> Option<FormatSet> {
    available
        .subsets()
        .filter(|&plan| {
            requirements
                .iter()
                .all(|&requirement| cheapest_fit(requirement, plan).is_some())
        })
        .min_by_key(|plan| plan.estimated_size())
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/// What one Shard reads: for each requested kind, the Formats its
/// extractor reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    reads: Vec<(ArtifactKind, FormatSet)>,
}

impl Plan {
    /// Plan a Shard of `dataset` for `kinds`: the cheapest Formats the
    /// Dataset publishes, or the `forced` ones (`--formats`).
    pub fn new(
        dataset: Dataset,
        kinds: &[ArtifactKind],
        forced: Option<FormatSet>,
    ) -> Result<Plan, PlanError> {
        let available = dataset.available_formats();
        let formats = match forced {
            Some(forced) => {
                if let Some(format) = forced.iter().find(|&format| !available.contains(format)) {
                    return Err(PlanError::Unavailable { dataset, format });
                }
                forced
            }
            None => {
                let requirements: Vec<FormatRequirement> =
                    kinds.iter().map(|kind| kind.format_requirement()).collect();
                // `None` only when some kind can't be served even by every
                // Format the Dataset publishes: `within` then names it.
                cheapest_plan(available, &requirements).unwrap_or(available)
            }
        };
        Plan::within(formats, kinds)
    }

    /// Each of `kinds` reading the cheapest of its combinations inside
    /// `formats`; fails on the first kind none of them fits.
    ///
    /// ## Collecting into a `Result`
    ///
    /// The closure returns a `Result` per kind. `collect` into
    /// `Result<Vec<_>, _>` stops at the first `Err` and returns it,
    /// otherwise gives `Ok` with every value: the loop, the early return
    /// and the `Vec` all in one call.
    pub fn within(formats: FormatSet, kinds: &[ArtifactKind]) -> Result<Plan, PlanError> {
        let reads = kinds
            .iter()
            .map(
                |&kind| match cheapest_fit(kind.format_requirement(), formats) {
                    Some(reads) => Ok((kind, reads)),
                    None => Err(PlanError::Unserved { kind, formats }),
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Plan { reads })
    }

    /// The Formats whose Archives are downloaded: those some kind reads.
    /// A forced Format that no kind reads is left out, as downloading it
    /// would be wasted.
    pub fn formats(&self) -> FormatSet {
        self.reads
            .iter()
            .fold(FormatSet::EMPTY, |all, &(_, reads)| all.union(reads))
    }

    /// The planned kinds, in the order requested.
    pub fn kinds(&self) -> Vec<ArtifactKind> {
        self.reads.iter().map(|&(kind, _)| kind).collect()
    }

    /// The kinds that read `format`: the extractors an Archive in that
    /// Format is handed to.
    pub fn kinds_reading(&self, format: Format) -> Vec<ArtifactKind> {
        self.reads
            .iter()
            .filter(|(_, reads)| reads.contains(format))
            .map(|&(kind, _)| kind)
            .collect()
    }

    /// Split the kinds into those done once the Archives of `parsed` have
    /// parsed, and the others: a kind is done only if every Format it reads
    /// is in `parsed` (ADR-0002).
    ///
    /// `Iterator::partition` sends each item to the first collection when
    /// the closure returns `true`, to the second otherwise.
    pub fn split_done(&self, parsed: FormatSet) -> (Vec<ArtifactKind>, Vec<ArtifactKind>) {
        let (done, undone): (Vec<_>, Vec<_>) = self
            .reads
            .iter()
            .partition(|(_, reads)| reads.is_subset_of(parsed));
        let kinds = |pairs: Vec<&(ArtifactKind, FormatSet)>| -> Vec<ArtifactKind> {
            pairs.into_iter().map(|&(kind, _)| kind).collect()
        };
        (kinds(done), kinds(undone))
    }
}

/// Why a Shard can't be planned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// A forced Format the Shard's Dataset doesn't publish.
    Unavailable { dataset: Dataset, format: Format },
    /// A kind none of whose accepted combinations fits inside `formats`.
    Unserved {
        kind: ArtifactKind,
        formats: FormatSet,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Unavailable { dataset, format } => {
                write!(f, "{dataset} does not publish {format} Archives")
            }
            PlanError::Unserved { kind, formats } => {
                let needs: Vec<String> = kind
                    .format_requirement()
                    .iter()
                    .map(|combination| FormatSet::of(combination).to_string())
                    .collect();
                write!(
                    f,
                    "cannot extract {kind} from {formats}: it needs {}",
                    needs.join(" or ")
                )
            }
        }
    }
}

/// An empty `impl` is enough: `Error` only requires `Debug` and `Display`,
/// and it is what lets `?` turn a `PlanError` into a `Box<dyn Error>`.
impl Error for PlanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Dataset;
    use Format::{Warc, Wat, Wet};

    // Requirement tables as ADR-0001 describes them. The real table
    // (`ArtifactKind::format_requirement`) only lists WARC until the WAT and
    // WET readers exist, so the planner is tested against these.
    const ONION: FormatRequirement = &[&[Warc], &[Wat, Wet]];
    const FAVICON: FormatRequirement = &[&[Warc], &[Wat]];
    const INLINE_FAVICON: FormatRequirement = &[&[Warc]];

    fn cc_main() -> FormatSet {
        Dataset::CcMain.available_formats()
    }

    #[test]
    fn onion_and_favicon_plan_wat_and_wet() {
        assert_eq!(
            cheapest_plan(cc_main(), &[ONION, FAVICON]),
            Some(FormatSet::of(&[Wat, Wet]))
        );
    }

    #[test]
    fn favicon_alone_plans_wat() {
        assert_eq!(
            cheapest_plan(cc_main(), &[FAVICON]),
            Some(FormatSet::of(&[Wat]))
        );
    }

    #[test]
    fn inline_favicon_plans_warc_whatever_comes_with_it() {
        for others in [&[][..], &[ONION], &[FAVICON], &[ONION, FAVICON]] {
            let requirements = [others, &[INLINE_FAVICON]].concat();
            assert_eq!(
                cheapest_plan(cc_main(), &requirements),
                Some(FormatSet::of(&[Warc])),
                "with {} other kind(s)",
                others.len()
            );
        }
    }

    #[test]
    fn cc_news_plans_warc() {
        assert_eq!(
            cheapest_plan(Dataset::CcNews.available_formats(), &[ONION, FAVICON]),
            Some(FormatSet::of(&[Warc]))
        );
    }

    #[test]
    fn each_kind_reads_its_cheapest_combination_inside_the_plan() {
        let wat_wet = FormatSet::of(&[Wat, Wet]);
        assert_eq!(cheapest_fit(ONION, wat_wet), Some(wat_wet));
        assert_eq!(cheapest_fit(FAVICON, wat_wet), Some(FormatSet::of(&[Wat])));

        // Inside a Plan of every Format, WAT + WET is cheaper than WARC.
        assert_eq!(cheapest_fit(ONION, cc_main()), Some(wat_wet));
    }

    #[test]
    fn no_combination_fits_outside_the_plan() {
        assert_eq!(cheapest_fit(FAVICON, FormatSet::of(&[Wet])), None);
    }

    // `Plan::new` and `Plan::within` use the real requirement table.

    #[test]
    fn forced_formats_must_serve_every_kind() {
        let wet = FormatSet::of(&[Wet]);
        assert_eq!(
            Plan::new(Dataset::CcMain, &[ArtifactKind::Favicon], Some(wet)),
            Err(PlanError::Unserved {
                kind: ArtifactKind::Favicon,
                formats: wet
            })
        );
    }

    #[test]
    fn wet_alone_cannot_serve_onion() {
        // WET drops HTTP headers and attribute values, where most onions
        // are: it serves `onion` only together with WAT (ADR-0001).
        let wet = FormatSet::of(&[Wet]);
        assert_eq!(
            Plan::new(Dataset::CcMain, &[ArtifactKind::Onion], Some(wet)),
            Err(PlanError::Unserved {
                kind: ArtifactKind::Onion,
                formats: wet
            })
        );
    }

    #[test]
    fn forced_formats_must_be_published_by_the_dataset() {
        assert_eq!(
            Plan::new(
                Dataset::CcNews,
                &[ArtifactKind::Onion],
                Some(FormatSet::of(&[Warc, Wat]))
            ),
            Err(PlanError::Unavailable {
                dataset: Dataset::CcNews,
                format: Wat
            })
        );
    }

    #[test]
    fn forced_formats_no_kind_reads_are_not_downloaded() {
        let plan = Plan::new(
            Dataset::CcMain,
            &[ArtifactKind::Onion],
            Some(FormatSet::of(&[Warc, Wat])),
        )
        .unwrap();
        assert_eq!(plan.formats(), FormatSet::of(&[Warc]));
    }

    #[test]
    fn a_kind_is_done_only_once_every_format_it_reads_parsed() {
        let kinds = [ArtifactKind::Onion, ArtifactKind::Favicon];
        let plan = Plan::new(Dataset::CcMain, &kinds, None).unwrap();

        assert_eq!(plan.split_done(FormatSet::EMPTY), (vec![], kinds.to_vec()));
        assert_eq!(plan.split_done(plan.formats()), (kinds.to_vec(), vec![]));
    }
}
