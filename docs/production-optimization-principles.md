# TALUS Production Optimization Principles

This document is the live optimization reference for TALUS production work.
`IMPLEMENTATION_PLAN.md` remains the only task checklist. This file explains
which optimizations are safe, which shortcuts are forbidden, and how to make DKG,
preprocessing, and strict signing usable without weakening the security model.

## Production Constraint

The only production signing mode is strict no-rejected-z leakage:

```text
- consume a BCC-certified token batch before response work;
- keep all rejected candidate z/h/pass/failure material private;
- privately check candidate validity;
- privately select one valid candidate;
- open only selected ctilde, z, and h;
- run final FIPS 204 verification before returning the signature.
```

The old paper-fast shape is not a production optimization. It is a dev/research
shortcut unless a separate leakage proof is produced and reviewed.

Forbidden production "optimizations":

```text
- clear partial z_i messages;
- rejected aggregate z exposure;
- reveal-on-failure after challenge;
- public A*s1_i or public A*nonce commitments;
- public `A*s1` or `A*nonce` helper material in any form that reveals the
  secret by linear algebra;
- candidate retry where failed candidate material is visible;
- scalar-per-coefficient release transport;
- caller-supplied runtime evidence or proof stubs.
```

Reference security documents:

```text
docs/no-rejected-z-leakage.md
docs/no-public-a-secret-linear-images.md
```

## Current Performance Reality

The live strict-signing release test now completes and passes:

```text
cargo test -p talus-mpc --features production-release-checks \
  strict_session_release_uses_live_vector_mpc_artifact_source -- --ignored --nocapture

observed debug/in-memory unit-harness time: about 186 seconds for ML-DSA-65
```

This is not acceptable as production signing latency. It proves the release
strict path can execute and satisfy evidence gates; it does not prove the
execution strategy is production-performance ready.

The slow test is strict signing, not DKG. Focused DKG/vector reducer tests are
fast after the vector reducer work:

```text
production_vector_runtime_computes_private_bit_sum_leq_threshold: ~0.07s
production_vector_runtime_computes_preprocessing_cef_bcc_threshold_phase: ~0.08s
```

Current profiled ML-DSA-65 debug/in-memory unit-harness snapshot:

```text
hint_canonical_decomposition: ~59.1s, 283 rounds, 789,504 mul lanes
hint_highbits_checks:         ~46.5s, 140 rounds, 430,080 mul lanes
hint_weight_check:            ~26.7s,  71 rounds,   6,170 mul lanes
z_canonical_decomposition:    ~14.5s, 283 rounds, 657,920 mul lanes
z_bound_checks:               ~11.5s,  97 rounds, 248,320 mul lanes
z_bound_all:                  ~10.8s,  77 rounds,   5,166 mul lanes
runtime_certificate:           ~2.6s, log/evidence scan only
selected opening/product work: ~1.6s to ~1.7s per small phase
```

Interpretation:

```text
- canonical decomposition and private comparison/highbits circuits dominate;
- selected-only opening is not the main cost;
- log/evidence scanning is visible but secondary;
- moving canonical masks/material into preprocessing and batching by phase are
  the highest-impact next optimizations.
```

## Why Dev/Scaffold Was Fast

Dev/scaffold tests often did less cryptographic work:

```text
- prebuilt selected-opening artifacts;
- local/clear candidate values;
- synthetic or already-shaped runtime evidence;
- local boolean pass/fail decisions;
- simplified token material;
- fewer lanes;
- no full private canonical decomposition;
- no durable wire-log replay for every checked opening;
- no private selected-only opening over live MPC handles.
```

Those tests are useful for API and invariant checks, but they are not comparable
to the strict live vector MPC test.

## Optimization Rule

Production performance must scale with:

```text
circuit depth
+ chunk count
+ token batch count
```

not with:

```text
coefficient count * bit count * candidate count * per-phase driver overhead
```

The right optimization is not to remove checks. The right optimization is to
execute the same checks as wide vector layers with precomputed certified material.

## Highest-Impact Optimization Paths

### 1. Batch Strict Signing By Phase

Current live strict signing still walks much of the private circuit candidate by
candidate:

```text
candidate 0:
  z prep -> z decomposition -> z bound -> hint -> hint weight
candidate 1:
  z prep -> z decomposition -> z bound -> hint -> hint weight
...
selection -> selected opening
```

Production target:

```text
all candidates:
  prepare all z shares
  decompose all z lanes
  run all z-bound comparisons layer-by-layer
  compute all hint approximations
  decompose all hint lanes
  run all hint/highbits checks layer-by-layer
  run all hint-weight checks layer-by-layer
  combine all valid bits
  private priority selection
  selected-only opening
```

Expected effect:

```text
rounds: approximately circuit depth, not candidate_count * circuit depth
messages: fewer larger vector messages
durable log writes: fewer phase records with more lanes per record
```

Code references:

```text
talus-mpc/src/online.rs:
  ProductionStrictLiveVectorMpcArtifactSource
  strict_prepare_runtime_z_share
  StrictRuntimeZBoundCheckState
  StrictRuntimeHintBitsCheckState
  StrictRuntimeHintWeightCheckState
  StrictRuntimePrioritySelectionState
  strict_drive_selected_* / strict_collect_selected_*
```

Completion condition:

```text
strict signing counters show batched layer execution;
round count does not multiply by candidate count except for necessary selection layers;
no rejected candidate material is opened or logged.
```

### 2. Move Canonical Masks Into Certified Preprocessing

Strict signing pays heavily for private canonical bit decomposition of:

```text
z
hint/highbits intermediate r
```

For strict production, do not optimize by removing online hint/highbits or
hint-weight checks unless a separate proof shows they cannot fail or that any
failure remains safely hidden. The approved optimization is to make the online
hint relation cheaper:

```text
preprocessing/key state:
  [w]    = [A*y]      // token-local, secret-shared and certified
  [As1]  = [A*s1]     // long-term, secret-shared and certified

online:
  [r] = [w] + c*[As1] - c*t1*2^d

not:
  [r] = A*[z] - c*t1*2^d
```

`[As1]` and `[w]` must remain secret-shared. They are not public commitments and
must never become public exact A-images.

The decomposition protocol needs certified random masks. These masks can be
generated and certified before online signing, as long as each mask is:

```text
- transcript-bound to its future use class;
- one-time use;
- crash-safe consumed;
- never reused after a failed or aborted signing attempt;
- not linked to public challenge-dependent values until consumed.
```

Production target:

```text
preprocessing token contains:
  certified nonce y shares
  certified secret-shared [w] = [A*y]
  BCC/CEF certificate
  certified canonical-mask inventory for strict z/hint checks
  durable one-time-use mask ids

long-term key state contains:
  certified secret-shared [As1] = [A*s1]

online signing consumes:
  token batch
  mask batch
  [w] token handles
  [As1] key handles
  then performs masked openings/checks with already-certified masks
```

Expected effect:

```text
online signing loses large random-mask certification and repeated A*z cost;
online work becomes mostly challenge-dependent arithmetic, comparisons,
selection, and selected opening.
```

Code references:

```text
talus-dkg/src/power2round.rs:
  CertifiedPower2RoundMaskBatch
  ProductionCanonicalBitDecompositionState

talus-mpc/src/local.rs:
  CertifiedToken
  PreprocessingSession
  TokenPool / FileTokenInventory
```

Completion condition:

```text
strict signing consumes certified decomposition masks from token/preprocessing
inventory;
online path does not generate/certify fresh canonical masks per candidate;
reuse after crash fails closed.
```

### 3. Separate Online-Critical Checks From Token-Certification Checks

Some correctness conditions are token properties and should be certified before
the challenge:

```text
- nonce distribution / boundedness;
- masked-broadcast consistency;
- CarryCompare/CEF correctness;
- BCC admission;
- w1 token material binding.
```

Some conditions are challenge-dependent and must remain online:

```text
- z = y + c*s1;
- z norm bound;
- h derived from selected response;
- hint weight;
- final FIPS verify.
```

Optimization principle:

```text
do not recompute token-only facts during online signing;
do not move challenge-dependent rejection checks into preprocessing unless a
proof shows rejected-z leakage remains impossible.
```

Completion condition:

```text
CertifiedToken carries enough preprocessing runtime evidence that strict signing
does not rerun token certification circuits online, while still privately
checking all challenge-dependent predicates before selected opening. In
particular, z-bound and hint-weight remain private online checks unless a
reviewed proof removes them.
```

### 4. Use Layer Schedulers, Not Hand-Written Per-Step Loops

The current live test drives many state machines in small Rust loops. That is
correct but expensive in debug/in-memory testing.

Production target:

```text
VectorCircuitScheduler:
  enqueue all gates for one layer
  send one vector private-message batch per receiver
  collect one vector batch per phase label
  update all dependent handles
  persist one compact phase cursor
```

The scheduler must preserve transcript labels, replay protection, and reliable
broadcast semantics.

Expected effect:

```text
less Rust loop overhead;
fewer log records;
fewer message envelopes;
better batching on real transports.
```

Code references:

```text
talus-dkg/src/power2round.rs:
  ProductionVectorPrimeFieldMpcRuntime
  PrimeFieldMpcWireMessageRecord
  PrimeFieldMpcCounters
```

Completion condition:

```text
runtime counters show fewer phase records for the same lane count;
all release gates still derive evidence from durable logs;
restart/resume still works from phase cursors.
```

### 5. Aggregate Durable Logs Without Losing Auditability

The unit harness writes and replays durable wire records very frequently. Durable
evidence is mandatory, but the representation can be more compact.

Safe improvements:

```text
- batch multiple vector lanes into one canonical wire payload;
- batch same-layer per-receiver directed shares;
- persist compact cursor summaries plus transcript hash;
- keep full public audit hash chain;
- keep enough raw records for external audit where required.
```

Unsafe improvements:

```text
- caller-supplied counters;
- caller-supplied transcript hashes;
- dropping phase labels from evidence;
- accepting evidence that cannot be replayed from durable logs.
```

Completion condition:

```text
durable_log_bytes fall substantially in benchmark runs;
release gates still reject forged/replayed/missing phase records.
```

### 6. Tune Token Batch Size K

Strict signing consumes a fixed batch of BCC-certified tokens to avoid rejected-z
leakage. Larger K improves probability of at least one valid candidate but
multiplies private online checks.

Production policy should be empirical:

```text
measure per-token validity probability after BCC/CEF certification;
choose K per suite/security profile;
keep K as small as the leakage/failure target allows;
document no-valid batch probability.
```

Possible direction:

```text
stronger preprocessing certification -> higher token pass probability -> smaller K
```

Completion condition:

```text
ML-DSA-44/65/87 benchmark reports show chosen K, no-valid probability model,
and measured online cost.
```

### 7. Precompute IT-MPC Randomness And Multiplication Material

The selected protocol avoids OT/SPDZ/MASCOT for v1, but honest-majority IT-MPC
still benefits from preprocessing:

```text
- random bit vectors;
- canonical mask vectors;
- multiplication/degree-reduction helper sharings;
- comparison helper material;
- threshold-sum helper material.
```

Rules:

```text
- every precomputed item is transcript-bound;
- every item has a durable one-time-use id;
- all items are consumed before use;
- crash after consumption never rolls back to fresh;
- no item contains public exact A*secret material.
```

Completion condition:

```text
online strict signing uses precomputed certified material for all eligible
randomness-heavy subprotocols.
```

### 8. Optimize IT-VSS And DKG Independently

DKG is allowed to be heavier than signing, but it cannot be scalar-per-coefficient.

IT-VSS target:

```text
one vector/chunk sharing per dealer/vector;
vector IC tags;
vector audit/discard;
vector polynomial consistency;
chunked memory limits;
public durable replay verifier.
```

Bounded sampler target:

```text
share full s1/s2 residue vectors;
batch bitness and range checks;
batch sum-mod-m circuits;
avoid scalar VSS per coefficient.
```

Power2Round target is already mostly in the right shape:

```text
certified masks;
masked C vector opening;
vector comparisons;
vector canonical checks;
vector add-4095;
vector t1 opening.
```

Completion condition:

```text
DKG counters scale with vector/chunk count and circuit depth;
no production DKG release path accepts scalar-per-coefficient IT-VSS/MPC logs.
```

## Measurement Plan

Each benchmark or release performance test should report:

```text
suite
party count n
threshold T
token batch size K
coefficient lanes
rounds
private messages
broadcasts
wire bytes
durable log bytes
vector lanes
multiplication layers
opened lanes
checked lanes
wall-clock time
build profile
transport type
```

A local debug unit test is allowed to be slow if it is explicitly marked
ignored/dev. A release performance gate must use release-mode execution and
production-shaped batching.

## Priority Order

Implement optimizations in this order:

```text
1. Add instrumentation that breaks strict signing time down by phase.
2. Batch strict signing by phase across all candidates.
3. Move strict canonical masks into preprocessing token inventory.
4. Add a vector circuit scheduler for repeated layer driving/collection.
5. Compact durable logs while preserving replayability.
6. Tune token batch size K with measured pass probabilities.
7. Add ML-DSA-44/65/87 release-mode performance envelopes.
8. Only then revisit deeper algebraic optimizations.
```

This order keeps the current secure proof shape intact while attacking the main
latency sources.

## Optimization Backlog

This backlog is intentionally concrete. It names speed work that is allowed
under the strict production security model.

### Strict Signing

```text
[x] Add live-runtime phase profiling.
[ ] Batch by phase across candidates/chunks instead of candidate-by-candidate.
[ ] Move z/hint canonical masks into preprocessing token inventory.
[ ] Precompute/store certified secret-shared [w] = [A*y] in each token.
[ ] Precompute/store certified secret-shared [As1] = [A*s1] in key state.
[ ] Compute online hint relation as [r] = [w] + c*[As1] - c*t1*2^d.
[ ] Avoid online recomputation of token-only BCC/CEF facts, but keep
    challenge-dependent z-bound and hint-weight private checks unless separately
    proven unnecessary.
[ ] Add a vector circuit scheduler for repeated comparison/decomposition layers.
[ ] Specialize z-bound as a centered range check instead of a generic
    decomposition plus two full comparisons where proof-compatible.
[ ] Specialize hint/highbits checks around the precomputed [w]/[As1] relation so
    online signing does not redo token admission logic or full A*z.
[ ] Replace current hint-weight reduction with a shallower tree/popcount
    threshold circuit.
[ ] Do not implement y-margin z-bound shortcuts as production unless separately
    proven and reviewed.
[ ] Keep selected-only opening and final FIPS verification unchanged.
[ ] Add release-mode ML-DSA-44/65/87 signing performance gates.
```

### Preprocessing

```text
[ ] Certify token batches, not one token at a time.
[ ] Store certified secret-shared [w] = [A*y] with each token.
[ ] Precompute canonical decomposition masks for strict signing.
[ ] Precompute safe random-bit/comparison helper material.
[ ] Batch masked-broadcast commit/open vectors.
[ ] Batch CarryCompare lanes.
[ ] Batch CEF/BCC admission lanes.
[ ] Persist one-time-use ids for every precomputed helper.
[ ] Tune token batch size K from measured BCC-certified pass probability.
```

### Vector IT-MPC Runtime

```text
[ ] Add a layer scheduler that enqueues all gates for the current circuit layer.
[ ] Aggregate same-layer private messages by receiver.
[ ] Aggregate same-layer reliable broadcasts.
[ ] Compact phase cursors without losing replayability.
[ ] Compact durable wire logs while retaining transcript hashes and release
    verification.
[ ] Add CPU parallelism inside independent vector/chunk arithmetic with
    deterministic transcript order.
[ ] Add release-build benchmark mode separate from debug unit tests.
```

### DKG / IT-VSS / Bounded Sampler

```text
[ ] Keep IT-VSS at vector/chunk granularity, never scalar-per-coefficient.
[ ] Add final chunk-size and memory-limit policy per ML-DSA suite.
[ ] Batch bounded-sampler bitness/range/sum-mod-m checks.
[ ] Ensure DKG counters scale with vector/chunk count and circuit depth.
[ ] Keep Power2Round in the state-owned vector path and remove legacy helper-only
    release callers.
```

### Measurement And Gates

```text
[ ] Record phase timing/counter breakdowns for strict signing in release mode.
[ ] Record preprocessing token-batch fill timing/counters.
[ ] Record DKG setup timing/counters.
[ ] Add no-scalarized-release regression tests for every production path.
[ ] Define acceptable local baseline envelopes for ML-DSA-44 first.
[ ] Scale envelopes for ML-DSA-65 and ML-DSA-87 after ML-DSA-44 is stable.
```

## Current Open Optimization Questions

These require implementation data, not speculation:

```text
- Which strict signing phase dominates the 186s debug run?
- How much time is spent in Rust loop overhead vs vector MPC operations?
- How much durable-log volume can be compacted without losing replay gates?
- What is the real BCC-certified token pass probability by suite?
- What token batch size K is needed for target no-valid probability?
- Which mask/check material can be safely precomputed without challenge
  dependence?
```

Do not claim production performance readiness until these are answered with
counters and release-mode measurements.
