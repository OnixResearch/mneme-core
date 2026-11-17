# Entity-seeded recall

Can bounded expansion from explicitly selected entities improve retrieval of
connected evidence at the same reader and context budget?
([mneme-core#7](https://github.com/OnixResearch/mneme-core/issues/7))

**Answer.** Expansion reaches connected evidence that lexical recall misses.
It does not yet help a reader. Its rows are structured candidates, not the
claims and excerpts a reader quotes and cites. At a fixed budget they push out
the citable candidates that rest on the same evidence. The profile ships
opt-in, as a versioned structured request. Default recall, fusion and
benchmark claims are unchanged.

## The profile

`mneme_recall::expansion::Profile` takes:

- host-selected seed entities, at most 16;
- allowlisted relation types, at most 8, each 1 to 128 bytes with no control
  characters;
- a hop bound from 1 to 4;
- an optional undirected walk;
- an output: reached entities, or admitted claims about them;
- an order: by distance or by record identity;
- a row bound and the Datalog work, time, row, support and recursion limits.

A profile that breaks a bound is refused before any rule is built. That
includes a recursion depth below `hops + 2`, which could not finish the walk.

The profile compiles to the versioned bundle `mneme-entity-seeded-expansion`
version 1. Structured recall evaluates it through the existing path: the same
scope, access, pinned revision and valid-time instant as any structured
request. The rules are:

```text
seed(s)            :- entity(s, type, label)            one rule per seed
reached(0, x)      :- seed(x)
edge(x, y)         :- relation(t, x, y)                  one rule per allowed type t
                                                         (plus relation(t, y, x) when undirected)
reached(k, y)      :- reached(k - 1, x), edge(x, y)      one rule per hop k = 1..hops
nearest(d, x)      :- reached(k, x), d = min(k)
expanded(...)      :- nearest(d, x) [, assertion(x, predicate, value, a)]
```

Each hop is its own rule, so the hop bound limits distance; the recursion limit
does not. The `min` aggregate leaves one row per entity at its shortest
distance, however many paths or cycles reach it. A distance-ordered row starts
with the integer distance, so structured ranking places nearer rows first. A
record-ordered row starts with the record identity, so distance has no effect.

## What the profile guarantees

Each guarantee is checked by a test in `crates/mneme-recall/tests/recall.rs`.

| Guarantee | Test |
|---|---|
| Admitted claims within the hop bound are returned. Claims beyond it are not, nor are proposed ones. Coverage is complete, and work and profile identity appear in the mode report. | `seeded_expansion_returns_admitted_claims_within_its_hop_bound` |
| Cycles and shortcuts give each entity one row, at its shortest distance. | `expansion_reaches_each_entity_once_at_its_shortest_distance_despite_cycles` |
| Only allowed relation types are followed, against their direction only when asked. A relation into another scope is never followed. | `expansion_follows_only_allowed_relations_between_visible_entities` |
| A missing seed and an unreadable seed give identical, empty results. An unreadable seed beside a readable one adds nothing. | `missing_and_unreadable_seeds_expand_identically_to_nothing` |
| A hub beyond the row limit is partial and never exhaustive, so it cannot establish absence. A request that refuses partial results gets none. | `a_hub_beyond_the_row_limit_is_partial_and_never_exhaustive` |
| A second path to a claim adds no row. The row shares the claim's evidence root, so only one candidate on that root counts as independent support. | `a_second_path_to_a_claim_adds_no_row_and_no_independent_support` |
| The profile's order decides whether nearer claims rank first. | `the_profile_order_decides_whether_nearer_claims_rank_first` |
| Every bound is refused before rules are built. | `expansion_bounds_are_refused_before_any_rule_is_built` |

Datalog work was not reported before this change. The structured mode report
now carries `structured_work`, the work units its build and query spent; the
agent API returns it as `structured-work`.

## Measured comparison

`cargo run --release -p mneme-recall --example entity_seeded_comparison` builds
a synthetic workspace of 32 services connected by `depends` relations. Each
service has one accepted, sourced claim of the form "The cedar service keeps
its events in Kafka." Each claim names only its own service.

For each service, the example asks "Which stores do the dependencies of the
cedar service use?" The gold evidence is the sources of the claims about
services one or two hops away: 164 sources over 32 questions.

All conditions share every request budget:

- lexical recall alone;
- lexical recall plus the profile (seed = the service, `depends`, two hops,
  claims), ordered by record;
- the same, ordered by distance.

Two measures are kept apart:

- **Evidence reached**: gold sources among any packed candidate's ancestry
  roots, whatever the candidate's kind.
- **Citable evidence**: gold sources among packed claim and excerpt candidates,
  the kinds a reader quotes and cites.

Measured on 2026-11-17 on the development host, engine `264bed4` plus this
change, release build, load average about 8. Retrieval figures are
deterministic. Times are means over the 32 questions.

| Budget (items, bytes) | Condition | Evidence reached | Citable evidence | Packed expansion rows | Packed bytes | Structured work | Time (µs) |
|---|---|---:|---:|---:|---:|---:|---:|
| (8, 4096) | lexical | 0.189 (31/164) | 0.189 (31/164) | 0.00 | 514 | 0 | 7,290 |
| (8, 4096) | + expansion, record order | 0.848 (139/164) | 0.000 (0/164) | 4.34 | 900 | 3,509 | 14,527 |
| (8, 4096) | + expansion, distance order | 0.817 (134/164) | 0.000 (0/164) | 4.19 | 886 | 3,509 | 13,913 |
| (4, 1024) | lexical | 0.073 (12/164) | 0.073 (12/164) | 0.00 | 232 | 0 | 7,213 |
| (4, 1024) | + expansion, record order | 0.390 (64/164) | 0.000 (0/164) | 2.00 | 407 | 3,509 | 13,684 |
| (4, 1024) | + expansion, distance order | 0.390 (64/164) | 0.000 (0/164) | 2.00 | 408 | 3,509 | 13,118 |

What the table shows:

- **Reach.** Expansion finds four to five times more of the connected evidence
  than lexical recall. Here lexical recall finds such evidence only through
  words every claim shares.
- **Citation.** Citable evidence falls to zero. Fusion gives the expansion rows
  about half of the packed items. Independence ordering then demotes every
  lexical claim and excerpt that rests on the same evidence as a row, placing
  it behind that row as a non-independent duplicate. The rows themselves cannot
  be quoted. A reader that cites only claims and excerpts is therefore worse
  off than with lexical recall alone.
- **Order.** Distance order does not help in this fixture. The seed's own
  claim, at distance zero and not part of the gold evidence, takes a slot first.
- **Cost.** About 3,500 Datalog work units and 6 ms per request on this host.

This is a retrieval comparison over a synthetic graph. It is not a reader
result and says nothing about answer quality. The comparative reader study
(answer-blind comparison and oracle-evidence diagnostic) belongs to
[Memory Lab #4](https://github.com/OnixResearch/memory-lab/issues/4), which can
run this profile unchanged.

## Decision

**Keep the profile opt-in and do not adopt it for reader-facing recall.**
Nothing in default retrieval, fusion weights or benchmark reporting changes.

The missing contract is specific: **an expansion row must reach the reader as
the candidates it names**. Expansion found the claim at distance two, but
recall has no way to say "this claim, which lexical ranking also knows,
deserves a better position". It adds a separate structured row instead. The
proposed seam:

- A structured request names one column as a record identity.
- Recall maps each row's named record to that record's existing indexed claim
  and excerpt candidates, under the same index eligibility, scope and
  lifecycle rules.
- Fusion then ranks those candidates with the structured rank as one more
  input. No parallel row is created.
- A row whose record has no eligible candidate stays a structured row, as now.

Two further gaps would have to close before adoption:

- Structured mode ignores `include_disputed` and `include_hypothetical`: the
  claim extent is always accepted and decision-backed.
- `relation` records carry no lifecycle or valid time, so an expansion follows
  every visible relation at every instant.

Reopen adoption when the seam exists, the comparison above shows citable
evidence above lexical recall at the same budget, and the Memory Lab reader
comparison agrees.
