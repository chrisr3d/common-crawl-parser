#!/bin/bash
#
# crawl.sh — SLURM array job running cc-extract over a Crawl
#
# NOT WORKING WITH THE KVROCKS STORE YET. Every process writes its results to
# the store named by --kvrocks, and runs across several nodes are not
# supported: nothing yet decides whether the nodes write to one store over
# the network or each to its own, copied together afterwards. Kept as a
# starting point until then.
#
# An example to adapt: replace every <...> placeholder for your cluster and
# check the values under "Configuration" before submitting.
#
# Two levels of parallelism:
#   - Level 1: SLURM array tasks, one node each, PATHS_PER_TASK paths each
#   - Level 2: within each array task, PROCESSES_PER_NODE independent
#     cc-extract processes, each with its own non-overlapping slice of the
#     paths file (--offset / --limit)
#
# With the values below, 10 array tasks cover 100,000 paths, about one CC-MAIN
# Crawl:
#   - Array task 0 covers paths     0 -  9,999
#   - Process 0.0  covers paths     0 -    499
#   - Process 0.1  covers paths   500 -    999
#   - ...
#   - Process 9.19 covers paths 99,500 - 99,999
#
# Why several processes per node rather than one with --jobs <all cores>:
# a process writes each Shard's results to the store on one thread.
# Separate processes share that work out.
#
# Submit:          sbatch examples/slurm/crawl.sh
# Re-run one task: sbatch --array=3 examples/slurm/crawl.sh
#
# This script exits with 0 even when some of its processes left Shards to
# retry or stopped early (see the end). Re-run those tasks (once the cause of
# an early stop is fixed).
#
# A re-run resumes: each process reads the done (Shard, kind) pairs from the
# store and skips them. Done Shards don't count toward --limit, though, so a
# process whose slice is partly done goes on into the next process's slice.
# The store's writes only add, so the overlap costs time, not correctness.
#SBATCH --job-name=cc-extract
#SBATCH --account=<account>
#SBATCH --partition=<partition>
#SBATCH --array=0-9
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --exclusive
#SBATCH --mem=0
#SBATCH --time=06:00:00
#SBATCH --output=logs/crawl_%a.out
#SBATCH --error=logs/crawl_%a.err

# sbatch opens the --output / --error files above before the script runs,
# relative to the directory it was submitted from: create logs/ there first.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# The binary, built beforehand with `cargo build --release`.
BINARY="<path to common-crawl-parser>/target/release/cc-extract"

# A Crawl's warc.paths.gz, wat.paths.gz or wet.paths.gz: any of them lists
# the same Shards. Which Formats are downloaded is decided per Shard, from
# EXTRACT (see --formats in `cc-extract --help` to force them).
PATHS_FILE="<path to wat.paths.gz>"

# The store every process writes to: a Unix socket path, or a
# redis://host:port URL. Its password, if it needs one, goes in the
# CC_EXTRACT_KVROCKS_PASSWORD environment variable.
KVROCKS="<socket path or redis://host:port of the kvrocks store>"

# Artifact kinds to extract. The default, onion,favicon, reads WAT + WET on
# CC-MAIN (~240 MB per Shard); adding inline-favicon makes every kind read
# WARC instead (~1 GB per Shard).
EXTRACT="onion,favicon"

# Level 1: how many paths each array task is responsible for
PATHS_PER_TASK=10000

# Level 2: how many processes to launch within each array task's node
PROCESSES_PER_NODE=20

# Derived: each process covers this many paths
PATHS_PER_PROCESS=$((PATHS_PER_TASK / PROCESSES_PER_NODE))

# Each process gets this many CPU cores for its internal --jobs.
# `--exclusive` gives the array task the whole node; SLURM_CPUS_ON_NODE
# is how many cores that is.
CPUS="${SLURM_CPUS_ON_NODE:-$(nproc)}"
JOBS_PER_PROCESS=$((CPUS / PROCESSES_PER_NODE))
if [ "${JOBS_PER_PROCESS}" -lt 1 ]; then
    JOBS_PER_PROCESS=1
fi

# With --transport memory, each job holds its Shard's Archives in RAM
# (~240 MB for WAT + WET, ~1 GB for WARC). Every process caps its jobs by
# the node's free RAM, not by its share of it, so check that
# PROCESSES_PER_NODE x JOBS_PER_PROCESS Shards fit in the node's memory.

# Base offset for this array task
TASK_OFFSET=$((SLURM_ARRAY_TASK_ID * PATHS_PER_TASK))

echo "=== Array task ${SLURM_ARRAY_TASK_ID} ==="
echo "Node: $(hostname), CPUs: ${CPUS}"
echo "Task offset: ${TASK_OFFSET}, paths per task: ${PATHS_PER_TASK}"
echo "Processes: ${PROCESSES_PER_NODE}, paths per process: ${PATHS_PER_PROCESS}, jobs per process: ${JOBS_PER_PROCESS}"
echo ""

# ---------------------------------------------------------------------------
# Launch the processes in parallel
# ---------------------------------------------------------------------------
# Each process runs in the background (&) with its own offset and limit.
# `wait` below blocks until all of them finish.
#
# --transport memory parses each Archive from RAM, so nothing is written to
# download/ (the disk Transports would write it under the current directory).
# ---------------------------------------------------------------------------
PIDS=()

for i in $(seq 0 $((PROCESSES_PER_NODE - 1))); do
    OFFSET=$((TASK_OFFSET + i * PATHS_PER_PROCESS))

    echo "  Starting process ${i}: offset=${OFFSET}, limit=${PATHS_PER_PROCESS}, jobs=${JOBS_PER_PROCESS}"

    "${BINARY}" "${PATHS_FILE}" \
        --extract "${EXTRACT}" \
        --offset "${OFFSET}" \
        --limit "${PATHS_PER_PROCESS}" \
        --jobs "${JOBS_PER_PROCESS}" \
        --transport memory \
        --kvrocks "${KVROCKS}" &

    PIDS+=($!)
done

echo ""
echo "All ${PROCESSES_PER_NODE} processes launched, waiting..."
echo ""

# ---------------------------------------------------------------------------
# Wait for every process and collect exit codes
# ---------------------------------------------------------------------------
# A process exits with:
#   0     every Shard of its slice done for every kind in EXTRACT
#   3     it ran to the end, but some Shards failed (download, parse or
#         store write): they are not marked done in the store, and running
#         the same command again retries them
#   other it stopped early, such as on an unreachable store or an
#         --offset past the end of the paths file (1), on invalid arguments
#         (2), or killed by a signal (128 + its number): fix the cause first
# ---------------------------------------------------------------------------
TO_RETRY=0
STOPPED=0
for j in "${!PIDS[@]}"; do
    wait "${PIDS[$j]}"
    EXIT_CODE=$?
    case "${EXIT_CODE}" in
        0) ;;
        3)
            echo "  Process ${j} finished with Shards to retry"
            TO_RETRY=$((TO_RETRY + 1))
            ;;
        *)
            echo "  Process ${j} stopped early with exit code ${EXIT_CODE}"
            STOPPED=$((STOPPED + 1))
            ;;
    esac
done

echo ""
echo "=== Array task ${SLURM_ARRAY_TASK_ID} finished: $((PROCESSES_PER_NODE - TO_RETRY - STOPPED))/${PROCESSES_PER_NODE} processes done, ${TO_RETRY} with Shards to retry, ${STOPPED} stopped early ==="
