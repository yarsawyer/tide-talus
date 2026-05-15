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
  strict_full_pipeline_release_benchmark_harness_mldsa65_live_runtime -- --ignored --nocapture

observed debug/in-memory unit-harness strict-online time: about 51.7 seconds
for ML-DSA-65 after fused canonical decomposition, prefix public
comparisons, and prefix canonical-recovery subtraction.
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

Current profiled ML-DSA-65 debug/in-memory unit-harness snapshot after
prefix canonical recovery and specialized canonical `< q`:

```text
fused z+hint canonical decomp:  ~5.1s,  20 rounds, 1,774,080 mul lanes
fused z-bound/highbits checks:  ~3.4s,   6 rounds,   501,248 mul lanes
fused validity / hint-weight:  ~28.8s,  59 rounds,     9,162 mul lanes
selection/opening:             ~12.5s,   9 rounds,     5,636 mul lanes
hint_approx_precomputed:        ~0.7s, no MPC rounds
total strict online:           ~50.4s,  94 rounds, 6.97 MB wire bytes
```

Current profiled ML-DSA-65 debug/in-memory unit-harness snapshot with a
two-token strict candidate batch:

```text
token batch size:                2
fused all-candidate decomp:  ~10.0s,  20 rounds, 3,548,160 mul lanes
fused all-candidate bounds:   ~6.8s,   6 rounds, 1,002,496 mul lanes
fused validity / hint-weight:~47.6s,  49 rounds,    18,428 mul lanes
selection:                    ~8.5s,   4 rounds,         8 mul lanes
selected opening:            ~13.8s,   4 rounds,     5,632 mul lanes
total strict online:      ~90-100s,   83 rounds, 13.87 MB wire bytes
```

The selected-opening wall-clock time is noisy in the debug/in-memory harness,
but the stable counters changed in the intended direction after affine
one-hot selection:

```text
selected-open vector_mul_lanes:   11,264 -> 5,632
selected-open wire bytes:         52,448 -> 35,552
selected-open durable log bytes: 104,976 -> 71,184
```

The hint-validity threshold now adds deterministic public-zero padding to hit a
better carry-save/ripple reducer shape. The padding does not change the private
predicate because it adds only public false bits, but it reduced the ML-DSA-65
K=2 live profile:

```text
HintCheck rounds:          59 -> 49
total online rounds:       93 -> 83
LAN 0.5ms RTT estimate: 46.5ms -> 41.5ms
```

Release-mode in-memory harness snapshot for the same ML-DSA-65 K=2 live path:

```text
preprocessing:                 ~120ms
strict online:                ~2.59s, 83 rounds, 13.87 MB wire bytes
final FIPS verify:              <1ms

ZDecomp:                       589ms, 20 rounds
ZBound:                        246ms,  6 rounds
HintCheck:                    1249ms, 49 rounds
Selection:                     199ms,  4 rounds
SelectedOpen:                  279ms,  4 rounds

LAN RTT estimate only:
  0.2ms RTT -> 16.6ms
  0.5ms RTT -> 41.5ms
  1.0ms RTT -> 83.0ms
```

Interpretation: the old ~90s number was a debug-build harness artifact. The
optimized Rust release path is already seconds, not minutes. It is still not
the final real-network product benchmark because this run uses in-memory
transport and durable-log simulation, but it is the correct baseline for code
execution speed.

Interpretation:

```text
- canonical decomposition and private comparison/highbits circuits dominate;
- the optimized `[w] + c*[As1] - c*t1*2^d` hint approximation removes online
  `A*z` from the supplied-handle path, but does not remove the private hint
  decomposition/highbits/weight checks;
- strict online no longer repeats bitness checks for `R_bits` derived from
  preprocessing-certified masks; it still keeps canonical range/equality checks;
- z and hint canonical decomposition now share one fused runtime state; z-bound
  and highbits interval comparisons also share one packed comparison schedule;
- z-bound all-coefficient aggregation uses a packed private OR tree over
  violation bits instead of counting every violation with a threshold-sum
  circuit;
- final private validity now fuses z-bound failures, hint bits, and BCC token
  admission into one private threshold tree. A z-bound failure or missing BCC
  admission is encoded as `omega + 1` failure units, so one such failure
  invalidates the candidate without a separate pass-bit AND state;
- strict candidate batching now keeps all candidates inside the same runtime
  states for canonical decomposition, z-bound/highbits comparisons, fused
  validity, and selected z/h products. With the selected-opening helper/fusion
  patch plus public-zero threshold padding, the two-token live harness reports
  83 online rounds, so marginal candidate cost is mostly vector width and
  selected-candidate bookkeeping rather than another full set of MPC rounds;
- selected-opening helper material is now a first-class one-time-use helper
  inventory alongside comparison and threshold helpers. Release signing
  consumes the token-bound selected-opening helper id before online private
  checks begin, and release token logs bind the helper hash. The selected
  `z` and `h` openings share one packed selected-product/opening path
  (`selected_z_h_opening_chunks`) instead of separate selected-z and
  selected-h paths. The selected-product circuit also uses the affine one-hot
  form `value_0 + sum_{j>0} selected_j * (value_j - value_0)`, so a two-token
  batch multiplies one delta vector instead of both candidate vectors. This is
  the current production-shaped boundary for moving selected-opening
  multiplication work into preprocessing; a future triple-backed runtime may
  replace the checked online product layer, but it must keep the same
  one-time-use helper and selected-only opening contract;
- hint-validity threshold padding is allowed only with public-zero inputs. It
  is a scheduler optimization for the carry-save/ripple reducer shape, not a
  semantic shortcut: z-bound failures and hint bits remain private, and the
  threshold predicate is unchanged;
- public comparisons now use log-depth prefix `(generate,equal)` reduction,
  which applies to z-bound, highbits intervals, threshold checks, and
  canonical `< q` checks;
- masked canonical recovery now uses prefix-borrow subtraction for
  `R = C + q*wrap - A`, which removes the 24-bit sequential borrow chain and
  drops ZDecomp from the old 133-round profile to 20 rounds;
- canonical `< q` now uses the ML-DSA special form `q = 2^23 - 8191`: a
  23-bit value is invalid iff high bits 13..22 are all one and low bits 0..12
  are nonzero. This reduces ZDecomp wire/lane volume, but does not reduce
  online round count because it replaces one log-depth comparator with a
  same-depth specialized reduction;
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

Core preprocessing rule:

```text
Move into preprocessing everything that is independent of the online
message/challenge and can be transcript-bound, certified, stored, and consumed
exactly once.

Keep online and private every check that depends on the challenge or selected
message, unless a separate reviewed proof shows the check cannot fail or that
its failure is safely hidden.

Never make preprocessing an excuse to publish exact A-images, rejected z,
candidate pass bits, masks, comparison witnesses, or failure reasons.
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

Strict online canonical decomposition follows the same rule. The preprocessing
path certifies z/hint canonical mask bits and binds them to one-time token
inventory. Online signing recovers `R_bits` through checked MPC arithmetic from
those certified mask bits and public masked openings, then keeps the
challenge-dependent canonical range and equality checks. It does not repeat a
separate online bitness proof for those derived `R_bits`. Power2Round remains
different: it is a standalone release circuit and still keeps its own
state-owned bitness assertions.

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
  comparison helper material where one-time-use-safe
  threshold-check helper material where one-time-use-safe
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
  StrictSigningCanonicalMaskInventory
  StrictSigningCanonicalMaskProvenance
  PreprocessingSession
  TokenPool / FileTokenInventory
```

Completion condition:

```text
token/certificate-bound mask handles exist, strict signing consumes them,
release gates reject anonymous or cross-token mask inventories, and in-memory /
file-backed one-time-use logs reject replay after reopen. Final distributed
random mask generation still needs to be produced by preprocessing.
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

Current progress:

```text
Done:
  compact canonical Fq vector wire lanes to 24-bit little-endian encoding
  while retaining legacy i32 replay compatibility.

  persist same-layer prime-field MPC wire records through a batched log API.
  File-backed logs encode grouped records with compact same-scope/same-direction
  prefixes and replay them as the original canonical wire records.

  expose default-preserving app transport batch hooks for private sends and
  reliable broadcasts. Replay uses those hooks for locally sent message groups;
  production adapters can override them to coalesce frames.

  deduplicate identical consecutive phase cursors in:
    DKG setup cursor logs
    prime-field MPC / Power2Round cursor logs
    preprocessing release cursor logs

  keep file-backed replay/corrupt-log tests for the compact cursor behavior.

Still open:
  route more online send paths through explicit same-layer batch APIs rather
  than only replay/adapter hooks;
  derive benchmark reports from actual grouped file-log sizes, not only
  conservative per-record counter estimates;
  add release benchmark reports that quantify total log-byte reduction.
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

Current implementation:

```text
talus-core::TokenPassProbabilityEstimate records observed attempts/passes.
talus-core::ProductionBatchSizingPolicy derives K from:
  target no-valid probability
  observed pass probability
  suite release minimum/recommended batch size

talus-mpc::PreprocessingTokenBatchFillReport converts preprocessing fill
attempt/certified-token counts into the pass-probability estimate without
exposing per-token pass bits or failure reasons.

talus-mpc::BccCertifiedTokenBatch can construct strict batches from this
empirical sizing decision. TokenPool can remove/consume whole token batches as
one fail-closed operation, rather than making strict signing select tokens one
at a time.

talus-mpc::PreprocessingReleaseBatchDriver owns a group of release
preprocessing drivers as one scheduler unit. It drives all active token
drivers, lets the application route the resulting vector-MPC traffic once per
batch step, collects all active drivers, aggregates counters, and emits the
batch fill report. It can now also start, drive, collect, and finish a fused
private preprocessing batch, so the release scheduler no longer has to run
CarryCompare/CEF/BCC as separate per-token private circuits.

Strict-signing canonical mask generation now has a fused batch path:
`start_strict_signing_canonical_mask_batch_generation` runs one larger vector
mask-generation/canonicality circuit for multiple token members, and
`finish_strict_signing_canonical_mask_batch_generation` slices private
token-bound inventories from that one runtime transcript. Release token
certification can consume those fused inventories instead of requiring one
strict-mask circuit per token.

The private CarryCompare/CEF/BCC runtime now also has a fused batch primitive
that concatenates token statements into one wider vector circuit. The completed
fused state can be promoted back into per-token release certificates through
`certify_preprocessing_token_release_validated_with_fused_private_batch_strict_inventory_and_nonce_share`.
Each resulting token keeps its normal per-token certificate and token binding,
but the CarryCompare/CEF/BCC proof transcripts are derived from the shared
fused runtime evidence instead of requiring one private circuit per token.
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
ignored/dev. Release-mode measurements are used first as best-shape baselines
and regression signals, not as final product-acceptance thresholds. Do not
invent a maximum wall-clock target before the secure production-shaped path has
been measured and the bottleneck phases are understood.

## Priority Order

Implement optimizations in this order:

```text
1. Add instrumentation that breaks strict signing time down by phase.
2. Batch strict signing by phase across all candidates.
3. Move strict canonical masks into preprocessing token inventory.
4. Add a vector circuit scheduler for repeated layer driving/collection.
5. Compact durable logs while preserving replayability.
6. Tune token batch size K with measured pass probabilities.
7. Add ML-DSA-44/65/87 release-mode best-shape baseline reports and
   regression counters.
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
[x] Add optimized live-runtime hint relation consumer:
    [r] = [w] + c*[As1] - c*t1*2^d.
    The live strict source uses this path when certified [w] and [As1] handles
    are supplied, avoiding online A*z in that path.
[x] Gate release-capable strict signing so missing [w]/[As1] handles reject
    under production-release-checks instead of falling back to online A*z.
[x] Bind z/hint canonical mask inventory into the preprocessing token and
    runtime certificate; release-capable token batches reject missing mask
    inventory.
[x] Bind strict mask inventory to preprocessing provenance and reject anonymous
    or cross-token mask replay in release-capable batches.
[x] Add strict mask inventory ids plus in-memory/file-backed one-time-use logs;
    `StrictSigningSession::finish_with_mask_use_log` persists mask consumption
    before private runtime work starts.
[x] Add strict comparison/threshold helper inventory and one-time-use logs.
    Release tokens now carry token-bound helper provenance for comparison and
    threshold-check material, the public token-batch log binds the helper
    inventory hashes, release admission rejects missing or cross-token helper
    material, and strict signing consumes helper ids before private online
    checks start. The online circuit still evaluates the challenge-dependent
    z-bound, hint/highbits, hint-weight, validity, and selection predicates
    privately; what moved into preprocessing is the reusable helper inventory
    boundary, certification binding, and replay prevention.
[~] Batch by phase across candidates/chunks instead of candidate-by-candidate.
[~] Pack strict-signing canonical-mask random-bit and XOR-fold layers.
    The preprocessing release driver now generates each 23-bit canonical mask
    target as a packed runtime payload instead of 23 independent random-bit
    vector phases, folds XOR layers as packed bit matrices, and batches the
    z/hint canonical `mask < q` comparison plus `assert_lt_q` threshold check.
    The `assert_lt_q` step now uses a specialized all-ones assertion
    (`lt_q - 1 == 0`) instead of the generic bit-sum equality circuit.
    This reduced the focused two-party debug in-memory release-batch test from
    roughly 93-99s to about 46-55s. Remaining work is batching/compressing the
    comparison internals, threshold internals, token-chunk, and transport/log
    layers. The vector runtime now exposes a durable phase profile from the
    local wire log so optimization work can see, per kind/phase, record counts,
    private/broadcast split, vector lanes, max lanes per wire record, wire
    bytes, and durable log bytes. Release-driver gates now reject payloads that
    exceed the suite chunk policy.
    The comparison circuit now avoids the redundant
    `comparison AND candidate` multiplication because `candidate = eq AND
    condition` is disjoint from the already-true comparison bit; the OR update
    is a local addition. Release-driver regression gates now cap comparison and
    CarryCompare profile records/labels. A follow-up comparator batching pass
    packs `candidate = eq AND condition` and `eq_next = eq AND eq_condition`
    into one multiplication layer per bit. On the focused release-driver
    profile this reduced:
    `ComparisonToPublicCheck records=68 labels=34 -> records=46 labels=23`,
    and `PreprocessingCarryCompare records=76 labels=38 -> records=38
    labels=19`.
    Prime-field MPC vector wire payloads now compact canonical Fq lanes into
    24-bit little-endian values with a versioned vector-length marker. The
    decoder still accepts old `i32` vectors for replay, but new release-runtime
    records use the compact format. On the focused release-driver profile this
    reduced:
    `ComparisonToPublicCheck wire_bytes=773312 -> 581824`,
    `RandomBitShare wire_bytes=518784 -> 389248`,
    `PreprocessingCarryCompare wire_bytes=473024 -> 356288`,
    `PreprocessingCefBcc wire_bytes=87296 -> 65792`, and
    `PreprocessingMaskedBroadcast wire_bytes=49792 -> 37504`.
[x] Generate z/hint canonical masks inside production preprocessing.
    Token storage, provenance binding, replay rejection, strict-signing
    consumption/use logging, and the app-driven random-bit/XOR/range-
    certification state machine exist. A strict-material release constructor
    consumes the completed mask state and binds it into the preprocessing
    runtime certificate. Release constructors/tests that do not provide this
    material now reject instead of silently attaching the old test placeholder.
    Remaining performance work is batching this across token chunks.
[x] Precompute/store certified secret-shared [w] = [A*y] in each token.
    Token storage, certificate binding, strict-signing consumption, and release
    constructor derivation are done. The release constructor derives the handle
    from the private distributed nonce/runtime [y] handle. The older
    opened-material derivation is test/scaffold-only and not exported by the
    normal production API.
[x] Exercise full-shape ML-DSA-44/65/87 release-token preprocessing with
    runtime-generated [w], strict masks, and vector runtime certificates.
    This is correctness coverage, not a latency target yet.
[x] Precompute/store certified secret-shared [As1] = [A*s1] in key state.
    DKG key packages now store private encoded [As1] K-vector shares. Release
    package-set gates recompute [As1] from the local s1 share and rho and reject
    mismatches. Strict signing release builds construct runtime key-state from
    the DKG package handle; direct from-s1 [As1] derivation remains outside
    production-release-checks.
[x] Compute online hint relation as [r] = [w] + c*[As1] - c*t1*2^d
    when those certified handles are present.
[ ] Avoid online recomputation of token-only BCC/CEF facts, but keep
    challenge-dependent z-bound and hint-weight private checks unless separately
    proven unnecessary.
[~] Add a vector circuit scheduler for repeated comparison/decomposition layers.
    First live strict-signing scheduler pass is in place: all candidate
    responses are prepared before checks, and z/hint canonical decomposition
    now drives the same mask/open/recover/check layer across every candidate
    before advancing; hint interval/highbits checks are batched across
    candidates, and final validity uses one fused private threshold tree.
    Z-bound no longer runs separate lower and
    upper comparison states: it packs `z < gamma` and `z < q-gamma+1` into one
    less-than comparison and derives `z > q-gamma` by private NOT. Hint
    highbits does the same for each target interval: it packs `r < lower+1`
    and `r < upper` into one less-than state, derives `r > lower` by private
    NOT, and reuses the single `gt_lower AND lt_upper` product both for the
    ordinary interval and the wrap-around interval. The strict live source now
    runs z-bound and hint/highbits checks over bounded vector chunks, then
    privately aggregates per-chunk pass bits before candidate selection.
    Hint-weight now computes private chunk counts, combines those private count
    bits, and checks the total against `omega` without opening partial counts
    or per-chunk failures. Z-bound all-true reductions and non-chunked
    threshold reductions transpose candidate vectors into one threshold circuit
    with candidates as vector lanes, instead of running one threshold state per
    candidate. Private priority selection now drives the selected-bit product
    and prefix-update product in one packed vector MPC layer per candidate.
    Selected z/h product driving and selected openings now run over bounded
    chunks while still opening only the selected candidate material. Selected
    opening has a dedicated token-bound helper inventory, and release signing
    consumes that helper id together with comparison and threshold helpers
    before online private checks begin. The selected `z` and `h` products are
    packed into one `selected_z_h_opening_chunks` path, so selected work shares
    one `selected_products_batch` profile stage and the focused
    profile-contract test rejects the old split `selected_z_product` /
    `selected_h_product` phase names. The release-capable live source enforces this batched
    scheduler profile under `production-release-checks` before it returns a
    selected-opening artifact. The gate also rejects scalar counters, missing
    or duplicate batch phases, excess round counts, and inflated wire/log byte
    counts. Remaining scheduler work is suite-specific wall-clock/throughput
    envelopes.
[ ] Specialize z-bound as a centered range check instead of a generic
    decomposition plus two full comparisons where proof-compatible.
[ ] Specialize hint/highbits checks around the precomputed [w]/[As1] relation so
    online signing does not redo token admission logic or full A*z.
[x] Replace per-candidate hint-weight reduction with a packed threshold circuit.
[x] Replace z-bound all-coefficient pass aggregation with a packed private OR
    tree over violation bits.
[x] Fuse z-bound, hint-weight, and BCC-admission validity aggregation.
    The release path now feeds z-failure bits, hint bits, and public
    BCC-admission failure into one private threshold tree. Z/BCC failures are
    weighted as `omega + 1`, so no separate `z_bound_all_batch` or
    `valid_bit_batch` phase is needed. The live ML-DSA-65 harness now reports
    94 strict online rounds instead of the prior 96-round fused-comparator
    profile.
[x] Replace MSB-to-LSB public comparisons with a log-depth prefix comparator.
[x] Replace sequential masked canonical recovery with prefix-borrow
    subtraction. `R = C + q*wrap - A` now runs as one packed init layer, five
    prefix borrow layers, and one packed diff layer for the 24-bit recovery
    path.
[x] Specialize canonical `R < q` using `q = 2^23 - 8191`.
    The release runtime now checks canonicality as
    `!(high_10_bits_all_one && low_13_bits_nonzero)` instead of using a
    generic 23-bit public comparator. This reduces strict online ZDecomp
    vector lanes and wire bytes. It does not change round count.
[~] Specialize gamma1/gamma2 centered interval checks beyond the current fused
    comparator schedule. A first z-bound specialization using the power-of-two
    `gamma1` structure and `q = 2^23 - 8191` complement bounds was implemented
    and measured, but it is not used on the release path because it increased
    online round count from 96 to 112. It saved a small amount of wire bytes
    while making the latency shape worse, so the fused generic-prefix
    comparator remains the release path. Further gamma/highbits specialization
    must reduce depth, not just lane count.
[ ] Do not implement y-margin z-bound shortcuts as production unless separately
    proven and reviewed.
[x] Keep selected-only opening and final FIPS verification unchanged.
[~] Add release-mode ML-DSA-44/65/87 signing baseline/regression gates.
    Batched scheduler shape and first counter/round/log envelopes are
    release-gated. Suite-specific wall-clock/throughput baseline reports
    now have a report type for strict signing; filling real all-suite report
    fixtures remains open. Reports should guide optimization, not freeze
    arbitrary product targets.
```

### Preprocessing

```text
[x] Certify token batches, not one token at a time.
    Release token-batch logs, batch pool admission, and batch pool consumption
    exist. `PreprocessingReleaseBatchDriver` now owns large batch scheduling
    and fill reporting. Strict-signing canonical-mask generation has a fused
    multi-token vector circuit that splits token-bound inventories from one
    runtime transcript. CarryCompare/CEF/BCC also has a fused private runtime
    primitive (`start_private_circuit_batch_from_envelopes`) that executes
    multiple token statements as one wider vector circuit, and fused private
    proof state can now be promoted into the normal per-token release
    certificate format.
[x] Store certified secret-shared [w] = [A*y] with each token.
    Token storage, certificate binding, strict-signing consumption, and release
    constructor derivation are done. The remaining hardening work is direct
    derivation from distributed nonce/runtime [y] handles, not the token field
    or strict-signing consumer path.
[~] Precompute canonical decomposition masks for strict signing.
    Token-bound storage/provenance validation, production runtime generation,
    certificate binding, and one-time-use persistence are implemented.
    Remaining performance work is batching/chunking large token batches and
    compacting the helper-material transcript.
[~] Precompute safe random-bit/comparison helper material.
    Strict canonical masks are generated in preprocessing and consumed once.
    Comparison/threshold helper inventory is now token-bound,
    certificate-bound, file-log-bound, and consumed once across restart.
    Remaining work is deeper helper material generation for concrete
    multiplication/checking subprotocols if the reviewed runtime adopts
    preprocessed triples or equivalent helper handles.
[ ] Batch masked-broadcast commit/open vectors.
[ ] Batch CarryCompare lanes.
[ ] Batch CEF/BCC admission lanes.
[~] Persist one-time-use ids for every precomputed helper.
    Strict canonical-mask ids and strict comparison/threshold helper ids have
    file-backed one-time-use logs. Remaining work is adding the same durable
    identity discipline to any future concrete preprocessed triple/helper
    handles introduced below those inventories.
[x] Tune token batch size K from measured BCC-certified pass probability.
    The policy and strict-batch constructors are implemented. Remaining
    all-suite benchmark reports must provide the measured probabilities used by
    deployment profiles.
```

### Vector IT-MPC Runtime

```text
[ ] Add a layer scheduler that enqueues all gates for the current circuit layer.
[~] Aggregate same-layer private messages by receiver.
    Durable accepted-message logs are grouped; app transport batch-send APIs
    exist and replay uses them; broader online send-path batching remains open.
[~] Aggregate same-layer reliable broadcasts.
    Durable accepted-message logs are grouped; app transport batch-send APIs
    exist and replay uses them; broader online broadcast-path batching remains
    open.
[x] Compact phase cursors without losing replayability.
[~] Compact durable wire logs while retaining transcript hashes and release
    verification.
[ ] Add CPU parallelism inside independent vector/chunk arithmetic with
    deterministic transcript order.
[ ] Add release-build benchmark mode separate from debug unit tests.
```

### DKG / IT-VSS / Bounded Sampler

```text
[ ] Keep IT-VSS at vector/chunk granularity, never scalar-per-coefficient.
[x] Add final chunk-size and memory-limit policy per ML-DSA suite.
    The shared policy lives in `talus-core::ProductionBatchSizingPolicy`; the
    vector MPC phase profile now records `max_record_lanes`, and the focused
    release-driver path gates durable records against the selected suite
    policy. Remaining work is using that policy to split very large future
    multi-token batches automatically while keeping chunks vector-sized.
[ ] Batch bounded-sampler bitness/range/sum-mod-m checks.
[ ] Ensure DKG counters scale with vector/chunk count and circuit depth.
[ ] Keep Power2Round in the state-owned vector path and remove legacy helper-only
    release callers.
```

### Measurement And Gates

```text
[~] Record phase timing/counter breakdowns for strict signing in release mode.
    `StrictSigningFullPipelineBenchmarkReport` now aggregates strict live-vector
    runtime phases into:
      response_prep, z_decomp, z_bound, hint_decomp, hint_check, selection,
      selected_open, final_verify.
    It also records LAN-like RTT estimates, strict/preprocessing bytes, durable
    log bytes, token pass probability, batch size K, party count, threshold,
    and final verifier result. The default regression tests use synthetic
    matrix fixtures for ML-DSA-44/65/87 and 3/2, 5/3, 7/4. An ignored
    ML-DSA-65 live-runtime harness runs `StrictSigningSession` with
    release-valid tokens and production vector runtime evidence.
[x] Record preprocessing token-batch fill timing/counters.
[ ] Record DKG setup timing/counters.
[ ] Add no-scalarized-release regression tests for every production path.
[x] Define ML-DSA-44 best-shape preprocessing baseline report first.
[x] Scale preprocessing baseline reports for ML-DSA-65 and ML-DSA-87 after
    ML-DSA-44 is stable.
```

Current representative release-mode preprocessing best-shape reports use two
BCC-certified token attempts, one local in-memory production vector runtime,
fused CarryCompare/CEF/BCC, fused strict-mask generation, typed token logs, and
`--release --features production-release-checks`. Wall-clock timings are
machine/load dependent; records, lanes, and bytes are the stable regression
signals.

```text
ML-DSA-44:
  setup: 10 ms
  fused private CarryCompare/CEF/BCC: 23 ms
  fused strict masks: 56 ms
  certificate/log: 12 ms
  records: 72
  private/broadcast records: 70 / 2
  vector lanes: 569,344
  wire bytes: 1,719,552
  durable log bytes: 3,439,824
  chunk policy: ok
  scalarized release profile: no
  top bottlenecks:
    RandomBitShare: 1,131,816 durable bytes
    specialized strict-mask MulDegreeReductionShare: 1,087,284 durable bytes
    PreprocessingCarryCompare: 896,616 durable bytes

ML-DSA-65:
  setup: 15 ms
  fused private CarryCompare/CEF/BCC: 41 ms
  fused strict masks: 114 ms
  certificate/log: 27 ms
  records: 76
  private/broadcast records: 74 / 2
  vector lanes: 819,200
  wire bytes: 2,469,760
  durable log bytes: 4,940,280
  chunk policy: ok
  scalarized release profile: no
  top bottlenecks:
    RandomBitShare: 1,556,412 durable bytes
    specialized strict-mask MulDegreeReductionShare: 1,492,788 durable bytes
    PreprocessingCarryCompare: 1,413,372 durable bytes

ML-DSA-87:
  setup: 15 ms
  fused private CarryCompare/CEF/BCC: 51 ms
  fused strict masks: 120 ms
  certificate/log: 26 ms
  records: 78
  private/broadcast records: 76 / 2
  vector lanes: 1,107,968
  wire bytes: 3,336,384
  durable log bytes: 6,673,548
  chunk policy: ok
  scalarized release profile: no
  top bottlenecks:
    RandomBitShare: 2,122,320 durable bytes
    specialized strict-mask MulDegreeReductionShare: 2,033,460 durable bytes
    PreprocessingCarryCompare: 1,880,316 durable bytes
```

Interpretation:

```text
The current preprocessing path is vectorized and fast in local release mode.
Strict-mask generic public comparison is no longer the dominant phase: the
canonical `mask < q` check uses the ML-DSA special form
`!(high_10_bits_all_one && low_13_bits_any_one)`, which replaces the old
23-step generic comparator with reduction layers and one final AND. The
dominant work is now random-bit generation, the specialized strict-mask
reduction multiplications, and CarryCompare. ML-DSA-65/87 strict-mask random-bit
generation is split into bounded runtime chunks, so every release report
satisfies the current per-record lane envelope.
```

## Current Open Optimization Questions

These require implementation data, not speculation:

```text
- Which strict signing phase dominates after precomputed hint approximation?
  Current answer: hint canonical decomposition, hint/highbits checks, and
  hint-weight remain dominant.
- How much time is spent in Rust loop overhead vs vector MPC operations?
- How much durable-log volume can be compacted without losing replay gates?
- What is the real BCC-certified token pass probability by suite?
- What token batch size K is needed for target no-valid probability?
- Which mask/check material can be safely precomputed without challenge
  dependence?
```

Do not claim production performance readiness until these are answered with
counters and release-mode measurements. Until then, optimize for the best known
secure execution shape and use measurements to find the next bottleneck.
