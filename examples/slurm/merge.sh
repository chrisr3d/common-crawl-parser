#!/bin/bash
#
# merge.sh — merge the results of every crawl.sh process into one directory
#
# An example to adapt: replace every <...> placeholder for your cluster, with
# the same BINARY and OUTPUT_ROOT as in crawl.sh.
#
# Submit after crawl.sh:
#   JOB=$(sbatch --parsable examples/slurm/crawl.sh)
#   sbatch --dependency=afterok:${JOB} examples/slurm/merge.sh
#
# `cc-extract merge` merges every Artifact kind whose results file is in at
# least one directory (onions.json, favicons.json, inline_favicons.json),
# deduplicating Sightings on (page_url, shard). It holds the merged results
# in memory: raise --mem if it runs out. processed.log files are not merged;
# they stay in each process's directory, where a re-run of crawl.sh reads
# them.
#SBATCH --job-name=cc-extract-merge
#SBATCH --account=<account>
#SBATCH --partition=<partition>
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:30:00
#SBATCH --output=logs/merge.out
#SBATCH --error=logs/merge.err

BINARY="<path to common-crawl-parser>/target/release/cc-extract"
OUTPUT_ROOT="<path to output directory>"

echo "=== Merging results ==="

# crawl.sh writes to ${OUTPUT_ROOT}/<array task>/<process>/. `nullglob`
# makes the pattern expand to nothing, rather than to itself, when no
# directory matches.
shopt -s nullglob
DIRS=("${OUTPUT_ROOT}"/*/*/)

echo "Found ${#DIRS[@]} result directories"
if [ "${#DIRS[@]}" -eq 0 ]; then
    echo "Nothing to merge under ${OUTPUT_ROOT}"
    exit 1
fi

# The merged files go to ${OUTPUT_ROOT} itself, next to the array task
# directories, so a second merge doesn't read them back in.
if ! "${BINARY}" merge "${DIRS[@]}" --output-dir "${OUTPUT_ROOT}"; then
    echo "=== Merge failed ==="
    exit 1
fi

echo ""
echo "=== Merge complete: results in ${OUTPUT_ROOT} ==="
