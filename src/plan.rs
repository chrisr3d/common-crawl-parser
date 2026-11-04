// The planner — which Formats to read for one Shard
//
// Each Artifact kind accepts some Format combinations, its Format
// requirement (`ArtifactKind::format_requirement`), listed from the one
// that finds the most to the one that finds the least. For each Shard,
// every requested kind reads the first of them made of Formats its Dataset
// publishes (of the forced ones, with `--formats`), and the Plan is what
// the kinds read together: with `onion` (WARC, then WAT + WET) and
// `favicon` (WARC, then WAT) on CC-MAIN, both read WARC.
//
// What a kind finds decides, not what its Archives cost to download: the
// size estimates (`Format::estimated_size`) only budget RAM. A kind whose
// Archive is given up reads its next combination avoiding it, and is left
// out only when none is left (`Plan::avoiding`).

use std::error::Error;
use std::fmt;

use crate::artifact::ArtifactKind;
use crate::format::{Dataset, Format, FormatSet};

// ---------------------------------------------------------------------------
// Format requirements
// ---------------------------------------------------------------------------

/// The Format combinations that can serve one Artifact kind, from the one
/// that finds the most to the one that finds the least; any one of them is
/// enough. `&[&[Format::Warc], &[Format::Wat, Format::Wet]]` reads "WARC,
/// or else WAT and WET together".
pub type FormatRequirement = &'static [&'static [Format]];

/// `requirement`'s combinations made only of Formats in `inside`, in its
/// order, as sets.
///
/// ## Lazy iterators
///
/// Nothing is built when this returns: each combination is turned into a
/// set and checked only when the caller asks for the next one, so a caller
/// stopping at the first (`first_fit`) never looks at the others.
fn combinations_inside(
    requirement: FormatRequirement,
    inside: FormatSet,
) -> impl Iterator<Item = FormatSet> {
    requirement
        .iter()
        .map(|combination| FormatSet::of(combination))
        .filter(move |combination| combination.is_subset_of(inside))
}

/// The first of `requirement`'s combinations made only of Formats in
/// `inside`, the one finding the most; `None` when none of them fits.
///
/// `Iterator::next` gives the first item, `None` from an empty iterator,
/// so "no combination fits" needs no separate check.
pub fn first_fit(requirement: FormatRequirement, inside: FormatSet) -> Option<FormatSet> {
    combinations_inside(requirement, inside).next()
}

/// The Formats a Shard of `dataset` may read: the `forced` ones
/// (`--formats`), if the Dataset publishes each of them, else every Format
/// it publishes.
fn allowed_formats(dataset: Dataset, forced: Option<FormatSet>) -> Result<FormatSet, PlanError> {
    let available = dataset.available_formats();
    let Some(forced) = forced else {
        return Ok(available);
    };
    match forced.iter().find(|&format| !available.contains(format)) {
        Some(format) => Err(PlanError::Unavailable { dataset, format }),
        None => Ok(forced),
    }
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/// The kinds `Plan::avoiding` left out, each with the avoided Formats that
/// stand in its way.
pub type LeftOut = Vec<(ArtifactKind, FormatSet)>;

/// What one Shard reads: for each requested kind, the Formats its
/// extractor reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    reads: Vec<(ArtifactKind, FormatSet)>,
}

impl Plan {
    /// Plan a Shard of `dataset` for `kinds`: each reads the first of its
    /// combinations among the Formats the Dataset publishes, or among the
    /// `forced` ones (`--formats`).
    pub fn new(
        dataset: Dataset,
        kinds: &[ArtifactKind],
        forced: Option<FormatSet>,
    ) -> Result<Plan, PlanError> {
        Plan::within(allowed_formats(dataset, forced)?, kinds)
    }

    /// Plan `kinds` as `new` does, around the `avoided` Formats (such as
    /// one whose Archive was given up): each kind reads the first of its
    /// combinations that reads none of them, and is left out when none is
    /// left. Less data beats none: with WARC avoided, `onion` reads WAT +
    /// WET, `favicon` WAT, and `inline-favicon` is left out.
    ///
    /// Returns the Plan of the kinds left, `None` when none is, and each
    /// kind left out with the avoided Formats its combinations read, those
    /// standing in its way. Fails as `new` does,
    /// whatever is avoided: a kind no combination can serve is a
    /// configuration error, not a given-up Archive.
    pub fn avoiding(
        dataset: Dataset,
        kinds: &[ArtifactKind],
        forced: Option<FormatSet>,
        avoided: FormatSet,
    ) -> Result<(Option<Plan>, LeftOut), PlanError> {
        let formats = allowed_formats(dataset, forced)?;
        // Only the check matters here: every kind must be served when
        // nothing is avoided. The Plan it builds is dropped.
        Plan::within(formats, kinds)?;

        let mut reads = Vec::new();
        let mut left_out = Vec::new();
        for &kind in kinds {
            let requirement = kind.format_requirement();
            match first_fit(requirement, formats.difference(avoided)) {
                Some(read) => reads.push((kind, read)),
                None => {
                    let in_the_way = combinations_inside(requirement, formats)
                        .fold(FormatSet::EMPTY, |all, combination| {
                            all.union(combination.intersection(avoided))
                        });
                    left_out.push((kind, in_the_way));
                }
            }
        }
        // `bool::then_some` turns `true` into `Some(value)`, `false` into
        // `None`.
        let plan = (!reads.is_empty()).then_some(Plan { reads });
        Ok((plan, left_out))
    }

    /// Each of `kinds` reading the first of its combinations inside
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
                |&kind| match first_fit(kind.format_requirement(), formats) {
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
    /// is in `parsed`.
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
    use ArtifactKind::{Favicon, InlineFavicon, Onion};
    use Format::{Warc, Wat, Wet};

    // The real requirement tables.
    const ONION: FormatRequirement = Onion.format_requirement();
    const FAVICON: FormatRequirement = Favicon.format_requirement();

    fn set(formats: &[Format]) -> FormatSet {
        FormatSet::of(formats)
    }

    /// What each of `plan`'s kinds reads, in the order requested.
    fn reads(plan: &Plan) -> Vec<(ArtifactKind, FormatSet)> {
        plan.kinds()
            .into_iter()
            .map(|kind| {
                let read = Format::all()
                    .iter()
                    .copied()
                    .filter(|&format| plan.kinds_reading(format).contains(&kind))
                    .collect();
                (kind, read)
            })
            .collect()
    }

    #[test]
    fn each_kind_reads_its_first_combination_inside_the_formats() {
        let wat_wet = set(&[Wat, Wet]);
        assert_eq!(
            first_fit(ONION, Dataset::CcMain.available_formats()),
            Some(set(&[Warc]))
        );
        assert_eq!(first_fit(ONION, wat_wet), Some(wat_wet));
        assert_eq!(first_fit(FAVICON, wat_wet), Some(set(&[Wat])));
    }

    #[test]
    fn no_combination_fits_outside_the_formats() {
        assert_eq!(first_fit(FAVICON, set(&[Wet])), None);
    }

    // `Plan::new` and `Plan::avoiding` use the real requirement table.

    #[test]
    fn every_kind_reads_warc_on_cc_main() {
        for kinds in [
            &[Onion][..],
            &[Favicon],
            &[Onion, Favicon],
            &[Onion, Favicon, InlineFavicon],
        ] {
            let plan = Plan::new(Dataset::CcMain, kinds, None).unwrap();
            assert_eq!(plan.formats(), set(&[Warc]), "{kinds:?}");
            assert_eq!(plan.kinds_reading(Warc), kinds, "{kinds:?}");
        }
    }

    #[test]
    fn every_kind_reads_warc_on_cc_news() {
        let kinds = [Onion, Favicon, InlineFavicon];
        let plan = Plan::new(Dataset::CcNews, &kinds, None).unwrap();
        assert_eq!(plan.formats(), set(&[Warc]));
        assert_eq!(plan.kinds_reading(Warc), kinds);
    }

    #[test]
    fn forced_wat_and_wet_serve_onion_from_both_and_favicon_from_wat() {
        let plan = Plan::new(Dataset::CcMain, &[Onion, Favicon], Some(set(&[Wat, Wet]))).unwrap();
        assert_eq!(
            reads(&plan),
            [(Onion, set(&[Wat, Wet])), (Favicon, set(&[Wat]))]
        );
    }

    #[test]
    fn forced_formats_no_kind_reads_are_not_downloaded() {
        // Inside WARC + WAT, `favicon` and `onion` read WARC first: no
        // kind reads WAT.
        let plan = Plan::new(Dataset::CcMain, &[Onion, Favicon], Some(set(&[Warc, Wat]))).unwrap();
        assert_eq!(
            reads(&plan),
            [(Onion, set(&[Warc])), (Favicon, set(&[Warc]))]
        );
        assert_eq!(plan.formats(), set(&[Warc]));
    }

    #[test]
    fn forced_formats_must_serve_every_kind() {
        let wet = set(&[Wet]);
        assert_eq!(
            Plan::new(Dataset::CcMain, &[Favicon], Some(wet)),
            Err(PlanError::Unserved {
                kind: Favicon,
                formats: wet
            })
        );
    }

    #[test]
    fn wet_alone_cannot_serve_onion() {
        // WET drops HTTP headers and attribute values, where most onions
        // are: it serves `onion` only together with WAT.
        let wet = set(&[Wet]);
        assert_eq!(
            Plan::new(Dataset::CcMain, &[Onion], Some(wet)),
            Err(PlanError::Unserved {
                kind: Onion,
                formats: wet
            })
        );
    }

    #[test]
    fn forced_formats_must_be_published_by_the_dataset() {
        assert_eq!(
            Plan::new(Dataset::CcNews, &[Onion], Some(set(&[Warc, Wat]))),
            Err(PlanError::Unavailable {
                dataset: Dataset::CcNews,
                format: Wat
            })
        );
    }

    #[test]
    fn around_an_avoided_warc_each_kind_falls_back_on_its_next_combination() {
        let kinds = [Onion, Favicon, InlineFavicon];

        let (plan, left_out) = Plan::avoiding(Dataset::CcMain, &kinds, None, set(&[Warc])).unwrap();

        assert_eq!(
            reads(&plan.unwrap()),
            [(Onion, set(&[Wat, Wet])), (Favicon, set(&[Wat]))]
        );
        // No other combination serves `inline-favicon`.
        assert_eq!(left_out, [(InlineFavicon, set(&[Warc]))]);
    }

    #[test]
    fn a_kind_is_left_out_when_every_combination_reads_an_avoided_format() {
        let kinds = [Onion, Favicon];

        let (plan, left_out) =
            Plan::avoiding(Dataset::CcMain, &kinds, None, set(&[Warc, Wet])).unwrap();

        assert_eq!(reads(&plan.unwrap()), [(Favicon, set(&[Wat]))]);
        // Each avoided Format stands in the way of one combination.
        assert_eq!(left_out, [(Onion, set(&[Warc, Wet]))]);
    }

    #[test]
    fn forced_formats_fall_back_inside_themselves() {
        // WAT + WET is not inside WARC + WAT: `onion` has nothing left.
        let (plan, left_out) = Plan::avoiding(
            Dataset::CcMain,
            &[Onion, Favicon],
            Some(set(&[Warc, Wat])),
            set(&[Warc]),
        )
        .unwrap();

        assert_eq!(reads(&plan.unwrap()), [(Favicon, set(&[Wat]))]);
        assert_eq!(left_out, [(Onion, set(&[Warc]))]);
    }

    #[test]
    fn no_plan_when_every_kind_is_left_out() {
        assert_eq!(
            Plan::avoiding(Dataset::CcNews, &[Onion, Favicon], None, set(&[Warc])),
            Ok((None, vec![(Onion, set(&[Warc])), (Favicon, set(&[Warc]))]))
        );
    }

    #[test]
    fn an_avoided_format_no_kind_reads_changes_nothing() {
        let kinds = [Onion, Favicon];
        for avoided in [FormatSet::EMPTY, set(&[Wet])] {
            assert_eq!(
                Plan::avoiding(Dataset::CcMain, &kinds, None, avoided),
                Ok((
                    Some(Plan::new(Dataset::CcMain, &kinds, None).unwrap()),
                    vec![]
                )),
                "{avoided}"
            );
        }
    }

    #[test]
    fn avoiding_fails_as_new_does_on_formats_serving_no_combination() {
        let wet = set(&[Wet]);
        assert_eq!(
            Plan::avoiding(Dataset::CcMain, &[Favicon], Some(wet), set(&[Warc])),
            Err(PlanError::Unserved {
                kind: Favicon,
                formats: wet
            })
        );
    }

    #[test]
    fn a_kind_is_done_only_once_every_format_it_reads_parsed() {
        let kinds = [Onion, Favicon];
        let plan = Plan::new(Dataset::CcMain, &kinds, Some(set(&[Wat, Wet]))).unwrap();

        assert_eq!(plan.split_done(FormatSet::EMPTY), (vec![], kinds.to_vec()));
        assert_eq!(plan.split_done(set(&[Wat])), (vec![Favicon], vec![Onion]));
        assert_eq!(plan.split_done(plan.formats()), (kinds.to_vec(), vec![]));
    }
}
