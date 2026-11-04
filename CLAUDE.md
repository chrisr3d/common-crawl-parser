# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Rust learning project (crate `cc-extract`): extracts Artifacts (`.onion` addresses, favicon URLs, inline favicon images) from Common Crawl archives (WARC, WAT, WET) into a kvrocks store. Edition 2024 (rustc 1.91+). `cargo run -- --help` lists every option and exit status.

## Conventions

- Teaching code: idiomatic Rust, with comments explaining the Rust concepts as well as the code. Every module opens with a header comment giving its role; keep it true when the module changes.
- Name things with the capitalised terms of `GLOSSARY.md` (Shard, Archive, Slice, Plan, Sighting...), in code, comments and docs alike.
- A behaviour change is followed by a doc commit updating `README.md` (building, running), `documentation/FEATURES.md` (behaviour), `documentation/PROGRESS.md` (journal: what changed, Rust concepts introduced) and `GLOSSARY.md` (new terms). This file changes only when a rule in it does.
- The `///` comments on `Config` (`src/main.rs`) are the `-h` text, which README's Usage section shows verbatim: change both together (`tests/cli_help.rs` fails otherwise).
- `examples/slurm/crawl.sh` stays setup-neutral: `<...>` placeholders for account, partition, paths and store, no cluster-specific values.

## Running and testing

- `cargo run` needs a paths file and a reachable kvrocks (default socket `/tmp/kvrocks.sock`, or `--kvrocks redis://host:port`); an unreachable store exits 1 before any download.
- `cargo test` needs no store: library tests use `MemoryStore`; the end-to-end tests (`tests/crawl_cli.rs`) skip.
- `CC_EXTRACT_TEST_KVROCKS=redis://127.0.0.1:16666 cargo test` also runs the end-to-end tests, one at a time, against that store. They `FLUSHDB` it: point it at a throwaway instance only.
- `cargo run --release --example baseline -- <archive.warc.gz>` runs the original `warc`-crate parser, the benchmark for the custom one.

## Design rules

Parsing separates three independent choices: Transport (how bytes arrive: disk, memory, mmap), Format (how records are read: WARC, WAT, WET), Artifact kind (what is extracted). Per Shard, the planner (`src/plan.rs`) gives each requested kind the first Formats of its Format requirement the Shard offers, those finding the most. Keep the three independent:

- One parsing loop (`parse_archive`, `src/lib.rs`) serves every Transport and Format, and never names a kind: kind-specific work lives in the extractors (`src/extractor.rs`).
- Every Transport and `--onion-engine` combination gives identical results (`tests/parse_characterization.rs` cross-checks them).
- The store is the only output (keys in the header of `src/store.rs`). Writes only add (`SADD`, `HSETNX`), so redoing a Shard is harmless. `save_then_mark` is the only way to mark a (Shard, kind) pair done, once all its writes and `--save-images` files succeeded; any failure leaves the pair undone. A done mark wins over any failure record.
- Nothing is written under the working directory but `download/`, the mmap copy and the `--save-images` directory. Temporary files are `TempFile` guards, removed however their function ends; downloads and images are written as `<name>.<pid>.part` and renamed once complete, so no partial file ever has the final name.

## Agent skills

### Issue tracker

Issues live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.
