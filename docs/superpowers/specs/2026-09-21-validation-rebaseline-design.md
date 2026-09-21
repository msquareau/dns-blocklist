# Validation Re-baseline — Design

**Date:** 2026-09-21
**Status:** approved, not yet implemented
**Scope:** validation only. No source URL changes. No category changes. No SDBL v3 format changes.

## 1. The problem

The daily `Build & Release` run failed on 2026-09-21 (run `35560856379`). One source breached one
floor. Every other check passed.

```
HaGeZi Light — upstream: 65681, parsed: 65681 (+0 / 0.0%) — FAIL
  (parsed 65681 below min_parsed_entries 75000)
ERROR: 1 source(s) failed validation (0 download, 1 parse), strict-mode threshold is 0.
```

The parse was correct. The upstream header declared 65,681 entries. The parser produced 65,681
entries. Only the hand-written floor of 75,000 was stale.

This is the second such failure in four months. Commit `3c70dfc` (2026-06-08) lowered the same
three Light floors after the same kind of upstream trim.

| Date | Light entries | Floor at the time |
|---|---:|---:|
| before June 2026 | ~130,000 | 130,000 |
| 2026-06-08 | 94,925 | lowered to 75,000 |
| 2026-09-20 | 82,665 | 75,000 |
| 2026-09-21 | 65,681 | breach |

An absolute floor that a maintainer must lower after each upstream trim is a treadmill. It converts
a routine upstream event into a total publish outage.

### 1.1 Two further gaps found during the audit

**The upstream-count check is silently off for 10 of 29 sources.**
`parser::extract_expected_entry_count` walks the leading comment block. It returns `None` at the
first line that starts with neither `#` nor `!`. Every adblock file opens with `[Adblock Plus]`, so
the walk stops on line 1.

The headers are present. `adblock/nsfw.txt` carries `! Number of entries: 73470`, and the parser
produced exactly 73,470. The report still printed `upstream: <none>`.

All 9 adblock sources are affected: Fake/Phishing, NSFW, Gambling, Anti-Piracy, Social Media,
DoH/VPN/Proxy Bypass, Dynamic DNS, URL Shorteners, Pop-up Ads.

A tenth source, Block List Project Drugs, declares `# Entries: 26,029`. The extractor looks for
`Number of entries:` only, and it cannot parse the thousands separator.

**Twenty-three of 29 sources carry no artifact-side floor.** Only the six largest HaGeZi lists set
`minTrieEntries`. For the other 23, a category emptied by a builder defect passes Layer 3 without a
word, unless a canary happens to cover it.

Together these mean 10 sources have no upstream comparison and no floor. The only remaining guard is
`parsed == 0`. A source truncated to a single domain ships.

## 2. Prior art

`alpaca-blocklists-builder` solved the same problem first. Its design
(`docs/superpowers/specs/2026-09-17-source-health-and-backfill-design.md`) removed the absolute
parse floor and replaced the shrink signal with a relative check. This design ports that model.

Three decisions carry over:

1. The absolute parse floor is deleted, not lowered.
2. The remaining absolute floor reads the finished artifact, so it guards against a builder defect
   rather than an upstream trim. Each floor is re-baselined to one third of its measured count.
3. The shrink signal becomes relative to the previous run, and it is never fatal.

Its stated ladder:

> 1. A fall below 60% stays silent. That is normal growth or an upstream cleanup.
> 2. A fall of 60% to 67% records a degraded entry, and the run still publishes.
> 3. A fall past 67% breaches the floor and fails the run.

The 2026-09-21 Light trim is a 20.5% fall against the previous run. Under this model it stays
silent and the artifact ships.

## 3. Severity model

`--strict` and `--best-effort` set severity globally today. This design makes severity a property of
each guard, fixed here and not at the command line.

A run ends in one of three states.

| Status | Meaning | Exit code | Publishes |
|---|---|---:|---|
| `ok` | every guard passed | 0 | yes |
| `degraded` | the artifact is sound, but something needs a person to look at it | 0 | yes |
| `failed` | the artifact is unsound or a source produced no usable bytes | 1 | no |

### 3.1 Guard table

| Guard | Layer | Severity |
|---|---|---|
| HTTP status not 2xx after retries | 1 | failed |
| Body below `minSizeBytes` | 1 | failed |
| `Content-Type` rejected | 1 | failed |
| Smell test finds no parseable domain in the first 30 lines | 1 | failed |
| Parsed below 90% of the declared count | 2 | failed |
| Parsed is 0 and no count was declared | 2 | failed |
| Parsed fell more than `maxParsedDropRatio` against the previous run | 2 | **degraded** |
| Canary bitmap incomplete | 3 | failed |
| Round-trip mismatch | 3 | failed |
| Per-bit count below `minTrieEntries` | 3 | failed |

Every row except the drop check keeps the severity that `--strict` gives it today. No guard becomes
more permissive.

### 3.2 The two flags

Both flags keep parsing. Each prints one deprecation line and changes nothing:

```
warning: --strict is deprecated and ignored; severity is now fixed per guard.
```

A script that another person already wrote keeps working. `release.yml` drops the flag from its
invocation in this change.

## 4. Layer 2 — delete the floor, add the drop check

### 4.1 Remove `minParsedEntries`

Delete `min_parsed_entries` from `config::SourceEntry` and from all six config entries that set it.

`ValidationError::BelowFloor` stays. It serves two cases today, and only the first one goes: the
`min_parsed_entries` breach, and the `parsed == 0` case that reports `min: 1`. The second case
remains fatal.

Keep both remaining Layer 2 guards fatal:
- parsed below 90% of a declared count;
- parsed equal to 0 when nothing was declared.

### 4.2 The `build` block

`blocklist-sources.json` gains a top-level block:

```json
"build": {
  "maxParsedDropRatio": 0.6
}
```

`config::BuildSettings` deserializes it with a serde default of `0.6`, so a config without the block
still loads.

### 4.3 The baseline

A new module `src/counts.rs` owns the file `build/cache/source-counts.json`, a
`BTreeMap<String, usize>` keyed by `displayName`.

```rust
/// A missing or unreadable baseline reads as empty on purpose. The baseline
/// exists to raise a warning. It must never fail a build of its own accord.
pub fn read(path: &Path) -> BTreeMap<String, usize>;

/// A write error prints a warning and returns. It never aborts the run.
pub fn write(path: &Path, counts: &BTreeMap<String, usize>);
```

Both directions fail open. The first run after this change finds no baseline, raises nothing, and
writes one.

### 4.4 The check

```rust
pub fn check_parse_drop(
    source: &SourceEntry,
    parsed: usize,
    previous: Option<usize>,
    max_drop_ratio: f64,
) -> Option<ValidationError>;
```

It returns `ValidationError::ParsedDrop { source, parsed, previous, fell }` when
`1.0 - (parsed / previous) > max_drop_ratio`. It returns `None` when `previous` is absent or 0.

The caller records the error as degraded. The run continues and publishes.

The baseline is rewritten from this run's counts at the end of every run that reaches compilation.
One fall therefore reports exactly once, and the new count becomes the next run's normal.

## 5. Layer 2 — fix the header extractor

Three changes to `parser::extract_expected_entry_count`:

1. **Allow a bracket preamble.** A line that starts with `[` is skipped when it is the first
   non-empty line. The walk then continues. Any later bracket line still ends the header block.
2. **Accept a second key.** Match `Entries:` as well as `Number of entries:`.
3. **Strip thousands separators.** Remove `,` and `_` before the integer parse.

The walk must still stop at the first real content line. A domain list whose first entry is a bare
domain must not be scanned to its end.

This restores the 90% upstream comparison for 10 sources. It is the largest single coverage gain in
this change.

## 6. Layer 3 — re-baseline and extend the floors

### 6.1 The rule

For `minSizeBytes` and `minTrieEntries` alike:

1. Take a clean measured run.
2. The proposed value is one third of the measured value, truncated to two significant figures.
3. **A floor never rises.** Where the current value is lower, the current value stays.
4. A list under 50 entries gets `1`. Total emptiness is the only fault a floor can detect at that
   size. The same applies to a body under 150 bytes.

### 6.2 What the floors now mean

Both fields get re-documented. Neither detects an upstream trim any more.

`minSizeBytes` rejects a truncated or empty download before the parse. `minTrieEntries` reads the
finished binary, so it catches a builder defect that empties a category after a clean parse. That
fault is covered by no other guard, which is the only reason the field survives.

An operator reading a `minTrieEntries` breach should suspect the compiler, not the upstream. A fall
of more than 67% is far beyond any upstream consolidation.

### 6.3 The measured values

From a local `--best-effort` run on 2026-09-21, SHA256
`f32627d82294974785f06e0bc2dab4e888b4dc790bbbee643eb09938313f9a27`. Per-bit trie counts equal parsed
counts for every source, so no source contains a duplicate domain.

| Source | Body bytes | `minSizeBytes` now | new | Trie entries | `minTrieEntries` now | new |
|---|---:|---:|---:|---:|---:|---:|
| HaGeZi Light | 1,510,491 | 1,500,000 | 500,000 | 65,681 | 75,000 | 21,000 |
| HaGeZi Multi | 18,521,853 | 6,500,000 | 6,100,000 | 546,182 | 260,000 | 180,000 |
| HaGeZi Pro | 20,665,670 | 10,000,000 | 6,800,000 | 637,867 | 360,000 | 210,000 |
| HaGeZi Pro++ | 21,840,102 | 11,500,000 | 7,200,000 | 687,148 | 420,000 | 220,000 |
| HaGeZi Ultimate | 22,927,470 | 13,500,000 | 7,600,000 | 740,241 | 520,000 | 240,000 |
| HaGeZi Threat Intelligence | 49,843,478 | 16,500,000 | 16,000,000 | 2,825,039 | 900,000 | 900,000 |
| HaGeZi NRD (7 days) | 58,496,264 | — | 19,000,000 | 3,621,561 | — | 1,200,000 |
| HaGeZi DGA (7 days) | 14,201,894 | — | 4,700,000 | 606,152 | — | 200,000 |
| HaGeZi Fake/Phishing | 348,790 | — | 110,000 | 17,254 | — | 5,700 |
| HaGeZi NSFW | 1,360,077 | — | 450,000 | 73,470 | — | 24,000 |
| HaGeZi Gambling | 10,570,950 | — | 3,500,000 | 524,913 | — | 170,000 |
| HaGeZi Anti-Piracy | 1,155,497 | — | 380,000 | 51,557 | — | 17,000 |
| HaGeZi Social Media | 17,175 | — | 5,700 | 900 | — | 300 |
| HaGeZi Apple Tracking | 3,739 | — | 1,200 | 114 | — | 38 |
| HaGeZi Amazon Tracking | 26,631 | — | 8,800 | 716 | — | 230 |
| HaGeZi Microsoft Tracking | 25,591 | — | 8,500 | 748 | — | 240 |
| HaGeZi Samsung Tracking | 8,173 | — | 2,700 | 268 | — | 89 |
| HaGeZi Xiaomi Tracking | 12,391 | — | 4,100 | 469 | — | 150 |
| HaGeZi Huawei Tracking | 6,847 | — | 2,200 | 169 | — | 56 |
| HaGeZi LG Tracking | 44,926 | — | 14,000 | 1,962 | — | 650 |
| HaGeZi Roku Tracking | 4,694 | — | 1,500 | 162 | — | 54 |
| HaGeZi TikTok | 13,240 | — | 4,400 | 438 | — | 140 |
| HaGeZi TikTok Extended | 19,186 | — | 6,300 | 616 | — | 200 |
| HaGeZi DoH/VPN/Proxy Bypass | 342,240 | — | 110,000 | 16,448 | — | 5,400 |
| HaGeZi DoH Only | 68,212 | — | 22,000 | 3,750 | — | 1,200 |
| HaGeZi Dynamic DNS | 24,941 | — | 8,300 | 1,539 | — | 510 |
| HaGeZi URL Shorteners | 140,880 | — | 46,000 | 9,965 | — | 3,300 |
| HaGeZi Pop-up Ads | 1,021,239 | — | 340,000 | 50,569 | — | 16,000 |
| Block List Project Drugs | 491,184 | — | 160,000 | 26,029 | — | 8,600 |

Threat Intelligence keeps its current `minTrieEntries` of 900,000. One third of its measured count
is 940,000, and a floor never rises.

The implementation must re-derive this table from its own measured run rather than copy these
numbers forward. Upstream counts move daily.

## 7. Reporting

The console and `validation-report.txt` both gain:

- a `Status: ok | degraded | failed` line;
- a `=== Degraded ===` section that lists each degraded entry with its reason;
- the per-source line keeps its shape, and a degraded source is tagged `DEGRADED` rather than
  `WARN`.

The process exit code follows the status.

## 8. Workflow

`.github/workflows/release.yml`:

1. Restore `build/cache` with `actions/cache/restore@v5`, key `sources-v1-${{ github.run_id }}`,
   restore key `sources-v1-`.
2. Drop `--strict` from the compiler invocation.
3. Save `build/cache` with `actions/cache/save@v5` after the run, under `if: always()`.

The save runs whatever the outcome. This is safe because the compiler writes the baseline only on a
run that reaches compilation. A failed run leaves the restored file untouched, so the save rewrites
the same bytes.

A degraded run publishes as before. GitHub evicts a cache after 7 days without a read. That reads as
no baseline, which raises nothing and fails nothing.

## 9. Testing

Inline unit tests in `src/validator.rs`, `src/parser.rs` and `src/counts.rs`:

- an adblock header behind an `[Adblock Plus]` preamble returns the count;
- `# Entries: 26,029` returns 26029;
- a header walk stops at the first content line;
- a drop past the ratio produces a degraded error, not a fatal one;
- a drop under the ratio produces nothing;
- an absent or zero previous count produces nothing;
- an unreadable baseline file reads as an empty map.

`tests/validation_test.rs` extends the issue-#20 suite with:

- a source whose parse falls 70% against a baseline, asserted to leave the exit code at 0;
- a `minTrieEntries` breach, asserted to abort;
- a canary mismatch, asserted to abort, which the suite already covers;
- an assertion that every source in the shipped `blocklist-sources.json` sets both floors.

## 10. Non-goals

These stay out of this change, and they should not drift in.

- **No source URL change, no category change, no SDBL v3 format change.**
- **No mirror tier and no byte cache.** `alpaca-blocklists-builder` can treat "no bytes anywhere" as
  fatal because it holds four URL tiers and a last-good cache behind each source. This repo has one
  URL per source and no cache. A dead upstream still fails the daily run here, exactly as it does
  today. That gap is real and it is larger than this change.
- **No object-store cache.** The baseline is small and it belongs beside the run that writes it.

## 11. Accepted cost

A category that quietly halves no longer fails the run. The drop check covers that shape for a
source's parse count. A fall in the finished artifact with no matching fall in the parse count would
pass unseen between 33% and 100%.

The current floors convert routine upstream events into total publish outages. That is the worse
failure.

## 12. Deferred

`canary-domains.json` carries 2 canaries for 29 categories. A canary is the only guard that proves a
category resolves to the right bits, so the coverage is thin. Extending it needs a separate pass:
each canary must name a domain that upstream will still carry in a year, and a rolling window such
as NRD or DGA can carry no canary at all. That work is out of scope here.
