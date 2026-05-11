# TALUS Production Implementation Plan

This is the single live implementation plan for the TALUS workspace.

If another document has an old checklist that disagrees with this file, this
file wins. Historical roadmap/checklist documents live under `docs/archive/`.
Reference documents may explain protocol choices, security rationale, or
performance principles, but they must not be treated as independent task lists.

## Documentation Policy

Live task tracking:

```text
IMPLEMENTATION_PLAN.md
```

Reference documents:

```text
docs/it-vss-rabin-ben-or.md
docs/no-public-a-secret-linear-images.md
docs/no-rejected-z-leakage.md
talus.md
SECURITY.md
talus-dkg/ARCHITECTURE.md
```

Archived historical checklists:

```text
docs/archive/IMPLEMENTATION_PLAN-history.md
docs/archive/production-grade-roadmap.md
docs/archive/dkg-production-completion-plan.md
docs/archive/dkg-production-performance.md
docs/archive/preprocessing-bcc-performance.md
docs/archive/optimization-principles.md
docs/archive/original-talus-attack-tests.md
docs/archive/no-duplication-architecture-audit.md
```

When work changes implementation status, update this file first. Update a
reference document only if the security rule or protocol rationale itself
changed.

## Production Definition

The only production profile is:

```text
Strict PQ honest-majority TALUS-MPC
```

Production means:

```text
- ML-DSA operational party identities.
- ML-KEM-established private-channel evidence.
- Equivocation-resistant reliable broadcast evidence.
- Honest-majority shape: n >= 2f + 1, T = f + 1, n >= 2T - 1.
- Dealerless native DKG using batched/vector IT-VSS.
- Standard ML-DSA public key pk = (rho, t1).
- DKG retains only s1 shares; never s2, t, t0, low bits, or witnesses.
- No public exact A-image of secret material.
- BCC-certified preprocessing tokens only.
- No reveal-on-failure after challenge.
- No rejected-z leakage.
- Returned signatures verify with the standard FIPS 204 ML-DSA verifier.
```

Everything else is test, dev, research, or attack-demo code. It must be gated
behind `cfg(test)`, explicit non-production features, or dev modules. Normal
crate users must not be able to select it.

## Completed Baseline

These pieces exist and should not be reimplemented from scratch.

### Workspace And Security Guardrails

- [x] Cargo workspace exists for `talus-core`, `talus-mpc-core`, `talus-dkg`,
  `talus-mpc`, `talus-wire`, and `talus-tests`.
- [x] `fips204` is the ML-DSA compatibility dependency.
- [x] Tidecoin crate dependencies have been removed from TALUS.
- [x] `production-release-checks` rejects incompatible insecure/dev features
  such as paper-fast signing and scaffold DKG features.
- [x] `cargo check --workspace --features production-release-checks` passes.

### FIPS 204 / TALUS Arithmetic

- [x] FIPS-sized `Poly`/`PolyVec` adapter exists for ML-DSA arithmetic needed
  by TALUS.
- [x] FIPS-compatible public-key decode, `w1Encode`, `mu`, `ctilde`,
  `SampleInBall`, `ExpandA`, NTT/inverse NTT, `A*z`, and signature encoding
  helpers exist.
- [x] BCC, hint, decomposition, CEF, and boundary helpers exist.
- [x] CEF uses the approved formula:
  ```text
  w1 = (sum_Htilde + floor(B / alpha) - kappa + delta) mod m
  ```
- [x] Boundary tests prove `- delta` is wrong.

### Public A-Secret Ban

- [x] Public `A*s1_i` is removed from normal DKG production structs.
- [x] Normal preprocessing no longer exposes public exact `A*nonce`.
- [x] Public-linear-image partial verifier code is test/dev gated.
- [x] Attack tests exist proving public `A*x` can recover secrets for ML-DSA
  parameter shapes.
- [x] Source/API scans reject known public exact `A*secret` artifacts on
  release paths.

Reference: `docs/no-public-a-secret-linear-images.md`.

### Strict Signing Boundary

Canonical code:

```text
talus-mpc/src/online.rs: StrictSigningSession
talus-mpc/src/online.rs: ProductionStrictSigningBackend
talus-mpc/src/online.rs: ProductionVectorResponsePreparationBackend
talus-mpc/src/online.rs: ProductionVectorResponseBoundCheckBackend
talus-mpc/src/online.rs: ProductionVectorHintCheckBackend
talus-mpc/src/online.rs: ProductionVectorPrivateSelectionBackend
talus-mpc/src/online.rs: ProductionVectorSelectedOpeningBackend
```

Status:

- [x] Strict signing consumes the token batch before private backend execution.
- [x] Clear partial signature wire payloads are not normal production APIs.
- [x] `CommitmentBackedPartialVerifier` and public-linear-image blame are
  test/dev gated.
- [x] Strict selected-opening boundary exists and returns only selected
  signature material/evidence.
- [x] Distributed runtime boundary rejects strict MPC wire messages unless an
  explicit runtime is installed.

Reference: `docs/no-rejected-z-leakage.md`.

### Native DKG Boundaries

Canonical code:

```text
talus-dkg/src/lib.rs: NativeDkgSession
talus-dkg/src/lib.rs: ProductionNativeDkgAssemblyOutput
talus-dkg/src/lib.rs: ProductionNativeDkgAssemblyOutput::new
talus-dkg/src/power2round.rs: ProductionPower2RoundOutput
```

Status:

- [x] `NativeDkgSession` exists as the user-facing DKG session facade.
- [x] Production output has a production constructor.
- [x] Scaffold conversion is `cfg(test)` only.
- [x] Release gates reject scaffold setup, simulator Power2Round, missing setup
  evidence, explicit blockers, and inconsistent package sets.
- [x] DKG key packages can be imported into the TALUS signing share provider
  without reintroducing `s2`, `t`, or `t0`.

### Vector IT-VSS

Canonical code:

```text
talus-dkg/src/it_vss.rs: ProductionInformationCheckingVssBackend
talus-dkg/src/it_vss.rs: ProductionItVssPublicPrecommitment
talus-dkg/src/it_vss.rs: ProductionItVssPublicCoinShare
talus-dkg/src/it_vss.rs: ProductionItVssAuditRecord
talus-dkg/src/it_vss.rs: ProductionItVssConsistencyRecord
talus-dkg/src/it_vss.rs: ProductionItVssCounters
```

Status:

- [x] Production vector information-checking backend exists in normal builds.
- [x] Vector-domain Shamir sharing exists.
- [x] Audited and retained IC tag material is separated.
- [x] Retained receiver tags are receiver-private in current backend tests.
- [x] Public precommitment and public coin artifacts exist.
- [x] Vector polynomial consistency records exist.
- [x] Release/performance counters exist.
- [x] Bounded sampler has production-backend vector tests.

Reference: `docs/it-vss-rabin-ben-or.md`.

### Vector Prime-Field MPC / Power2Round Boundaries

Canonical code:

```text
talus-dkg/src/power2round.rs: ShareVec
talus-dkg/src/power2round.rs: BitShareVec
talus-dkg/src/power2round.rs: PrimeFieldMpcCounters
talus-dkg/src/power2round.rs: PrimeFieldMpcWireMessageRecord
talus-dkg/src/power2round.rs: ProductionPower2RoundPerPartyDriver
talus-wire/src/lib.rs: DkgPrimeFieldMpcPayload
```

Status:

- [x] Vector share containers exist.
- [x] Prime-field MPC counters exist.
- [x] Durable wire-log vectorization checks reject scalarized logs.
- [x] Canonical wire payload for vector/scalar DKG prime-field MPC exists.
- [x] Typed Power2Round driver phases exist.
- [x] Certified precomputed Power2Round mask batches and crash-safe mask-use
  logs exist.
- [x] Vector Power2Round phase helpers exist for masked opening, wrap
  comparison, canonical-bit recovery, canonical checks, add-4095, and `t1`
  opening.
- [x] `ProductionPower2RoundOutput` validates `t1` evidence against context.

### Nonce Preprocessing Boundaries

Canonical code:

```text
talus-mpc/src/local.rs: PreprocessingSession
talus-mpc/src/local.rs: DistributedNonceShare
talus-mpc/src/local.rs: MaskedBroadcastConsistencyVerifier
talus-mpc/src/local.rs: ProductMaskedBroadcastConsistencyVerifier
talus-mpc/src/local.rs: CertifiedToken
talus-mpc/src/local.rs: TokenPool
talus-mpc/src/local.rs: FileSessionRegistry
```

Status:

- [x] Production-facing `PreprocessingSession` API exists.
- [x] Masked-broadcast commit/open validation exists.
- [x] Normal `DistributedNonceShare` has no public exact `A*nonce`.
- [x] Distributed nonce generation core exists.
- [x] Product verifier boundary exists.
- [x] `CertifiedToken` carries policy/evidence.
- [x] `TokenPool` rejects uncertified and duplicate tokens.
- [x] File-backed session-id persistence prevents preprocessing session reuse.
- [x] CEF and BCC admission run in one vector pass with the approved
  `+ delta` correction.

### Transport Boundary

Status:

- [x] TALUS crates do not implement sockets/TCP/QUIC/libp2p.
- [x] `talus-wire` owns canonical wire encodings and context validation.
- [x] App-facing transport traits and PQ binding evidence exist.
- [x] Deterministic conformance tests cover ML-KEM-768 session binding,
  ML-DSA-65 identity binding, wrong identity/session/suite, duplicate/replay,
  incomplete broadcast views, and equivocation.

## Do Not Redo

Do not start new parallel implementations for these.

- `PreprocessingSession`.
- Masked-broadcast commit/open validation.
- `CertifiedToken` and pre-challenge certification policy/evidence.
- CEF `+ delta` arithmetic.
- Public `A*secret` attack tests and release scans.
- `ProductionStrictSigningBackend` trait stack.
- `ProductionInformationCheckingVssBackend` vector backend.
- `ProductionPower2RoundOutput` and typed Power2Round driver phases.
- `ProductionNativeDkgAssemblyOutput::new`.

If a current implementation is incomplete, replace internals behind the
existing boundary. Do not add another boundary with the same responsibility.

## Execution Queue

The queue below is ordered for implementation. Complete a phase before using
later phases as production evidence.

### Phase 1: Documentation And API Discipline

Goal: keep one live plan and one normal production API surface.

Status: **complete for the API/documentation discipline scope**. This phase
does not mean the cryptographic protocol is production-complete; it means the
normal crate surface and live documentation no longer present test/dev paper
paths as production options.

- [x] Update `talus-dkg/ARCHITECTURE.md` so archived docs are marked
  historical and this file is the live checklist.
- [x] Add crate-level rustdoc stating that normal builds expose only the strict
  production profile.
- [x] Add feature-graph scans proving normal workspace dependencies do not
  enable `paper-fast-dev` or `scaffold-dev`; those remain explicit opt-ins for
  test/dev builds only.
- [x] Add or tighten source/API scans proving normal builds do not expose:
  ```text
  TestPaperFastExperimental
  TestLocalSimulation
  CommitmentBackedPartialVerifier
  PartialSignaturePayload
  public A*s1_i
  public A*nonce
  reveal-on-failure APIs
  ```
- [x] Keep all paper-compatible attack helpers under test/dev modules only.

Completion gate:

- [x] `rg -n "\- \[ \]" docs -g '*.md'` has no live unchecked checklist outside
  `IMPLEMENTATION_PLAN.md` except archived files under `docs/archive/`.
- [x] `cargo test -p talus-tests production_api_scan -- --nocapture` passes.

### Phase 2: Finish Vector IT-VSS In The App Driver

Goal: make `ProductionInformationCheckingVssBackend` usable as the normal DKG
vector-sharing path, not only backend/helper tests.

Status: **complete for the app-driver/release-flow boundary**. This phase
closes the durable vector IT-VSS setup flow: precommitment, post-precommitment
public coins, final public metadata, private delivery, verification, complaint
collection, complaint resolution, and accepted-sharing certification.

Not part of Phase 2: proving that every later DKG/signing circuit is fully
vectorized and within production performance targets. That remains Phase 9.
Not part of Phase 2: final external cryptographic review and operational
hardening. That remains Phase 12.

- [x] Drive public precommitment -> public coin -> final metadata through
  `NativeDkgSession` for every S1/S2 vector IT-VSS batch.
- [x] Persist phase cursors for every vector IT-VSS phase:
  ```text
  public precommitment
  public coin share
  private delivery
  local verification
  complaint broadcast
  complaint resolution
  accepted sharing certification
  ```
- [x] Release gate proves every final S1/S2 vector IT-VSS commitment has the
  required public precommitment and complete post-commitment public-coin shares.
- [x] Release gate proves durable log order for every final S1/S2 vector
  IT-VSS sharing:
  ```text
  public precommitment -> public coin shares -> final public commitment
  ```
- [x] Resume each phase from durable logs without live in-memory queues.
- [x] Reject incomplete vector IT-VSS phase-cursor logs in release context after
  restart.
- [x] Reject aborted vector IT-VSS sessions after restart.
- [x] Add final chunk sizing and memory limits for ML-DSA-44/65/87.
- [x] Add adversarial tests:
  ```text
  retained tag exposure attempt
  malformed vector length
  wrong vector domain
  bad label hash
  duplicate batch private delivery
  wrong receiver in batch
  mixed dealer batches
  outside-label complaint
  aborted session cannot become accepted
  ```
- [x] Remove/gate remaining scaffold artifact helpers from release-capable DKG
  assembly internals.

Completion gates:

- [x] Production release context requires batched/vector IT-VSS public flow.
- [x] No scalar-per-coefficient IT-VSS artifact can satisfy release gates.
- [x] Retained receiver tags never appear in public artifacts/logs.
- [x] Public beta/share-point reveal is unavailable in v1 production.

Implementation note:

- The current `ProductionInformationCheckingVssBackend` is the normal-build
  vector IT-VSS backend for DKG setup. It is vector/chunk shaped and rejects
  scalar-per-coefficient release labels. Remaining performance proof work is
  tracked in Phase 9, not here.

### Phase 3: Finish Production Vector Prime-Field IT-MPC Runtime

Goal: provide the release-capable vector MPC runtime used by Power2Round,
preprocessing BCC/CEF, and strict signing checks.

Status: **not complete**. The vector containers, phase drivers, durable wire
records, counters, and release gates exist. However the actual final
app-driven vector IT-MPC runtime is not complete for all consumers. The trait
still has scalarizing compatibility defaults for tests, and production paths
must continue moving toward one concrete app-driven vector runtime with durable
counter evidence.

Completed groundwork:

- [x] Add vector operation boundaries:
  ```text
  open_many_checked
  assert_zero_vec
  assert_bit_vec
  random_bit_vec
  multiplication layers
  comparison to public constants
  equality to public constants
  bit sums and threshold checks
  secret one-hot selection
  ```
- [x] Add public scalar multiplication as a local vector operation boundary.
- [x] Add durable wire-message logs and phase cursors for prime-field MPC
  transport-shaped execution.
- [x] Add counters:
  ```text
  rounds
  private messages
  broadcasts
  wire bytes
  durable log bytes
  vector lanes
  multiplication layers
  wall-clock time
  ```
- [x] Add release gates rejecting scalar durable wire-log evidence.
- [x] Add backend-counter release gate so production wrappers cannot accept
  scalarized/no-counter backend execution.
- [x] Add durable runtime evidence derived from prime-field MPC wire logs, with
  coverage bits for:
  ```text
  vector openings
  vector assert-zero
  vector bitness
  vector random bits
  vector multiplication layers
  comparisons
  equality checks
  bit-sum / threshold checks
  private one-hot selection
  ```
- [x] Add readiness derivation from durable runtime evidence so Phase 3
  readiness no longer has to be caller-asserted as raw booleans.
- [x] Add normal-build typed vector runtime phases for generic bit-sum /
  threshold checks and private one-hot selection checks, so strict signing and
  preprocessing can use the same prime-field MPC transport surface as
  Power2Round.
- [x] Add `ProductionVectorPrimeFieldMpcRuntime`, a normal-build vector-only
  app-driven runtime wrapper for:
  ```text
  open_many_checked
  assert_zero_vec
  assert_bit_vec
  random_bit_vec
  mul_vec by circuit layer
  comparison-to-public
  equality-to-public
  bit sums / threshold checks
  private one-hot selection
  ```
- [x] Add generic normal-build vector phases for assert-bit,
  comparison-to-public, and equality-to-public so later consumers do not need
  to reuse Power2Round-specific phase names.
- [x] Add release evidence and malicious/runtime tests for the vector-only
  runtime wrapper:
  ```text
  full Phase 3 operation coverage
  durable vector logs/counters/evidence
  wrong phase rejection
  duplicate/equivocated vector message rejection
  no scalar durable evidence accepted
  ```
- [x] Add API/source guard tests proving the production vector runtime exposes
  vector-only methods and does not implement the scalarizing compatibility
  backend trait.
- [x] Add restart/resume tests for the production vector runtime:
  ```text
  sent vector phases replay from durable logs
  accepted vector phases recover from durable logs
  replay does not regenerate durable records
  ```
- [x] Add delay/reorder/duplicate/equivocation tests over every generic Phase 3
  vector operation family.
- [x] Add negative runtime-evidence tests:
  ```text
  missing random-bit evidence fails full Phase 3 gate
  missing private-selection evidence fails full Phase 3 gate
  missing assert-bit/comparison/equality evidence fails full Phase 3 gate
  Power2Round-only evidence cannot satisfy full Phase 3 readiness
  ```
- [x] Add Phase 3 runtime-core performance envelope assertions for the fixed
  test circuit:
  ```text
  vector lanes > 0
  private messages > 0
  broadcasts > 0
  wire/durable bytes > 0
  scalar operations = 0
  bounded round count
  ```
- [x] Thread Power2Round-specific durable vector IT-MPC runtime evidence into
  `PublicKeyAssemblyCertificate`.
- [x] Make release DKG certificate validation reject `ProductionItMpc`
  Power2Round certificates that lack durable vector runtime evidence.
- [x] Add normal-build production secret handle types:
  ```text
  ProductionShareVec
  ProductionBitShareVec
  ProductionShareVectorId
  ```
  The handles are transcript-bound, local-party scoped, redacted from `Debug`,
  zeroized on drop, and are not scalar-compatible `ItMpcPrimeFieldBackend`
  shares.
- [x] Add app-supplied entropy boundary for production vector Shamir
  degree-reduction:
  ```text
  ProductionVectorItMpcEntropy
  ```
  The crate does not provide a production RNG here; embeddings must provide
  transcript-bound entropy.
- [x] Add runtime-owned local vector operations over production handles:
  ```text
  public_const_share_vec
  add_share_vec
  sub_share_vec
  mul_public_const_share_vec
  bit_not_vec
  ```
- [x] Add app-driven vector Shamir multiplication / degree reduction over
  production handles:
  ```text
  drive_mul_vec_degree_reduction
  collect_mul_vec_degree_reduction
  ```
  Tests reconstruct the result from transport-delivered Shamir shares and prove
  durable vector evidence is emitted.
- [x] Add production-handle checked opening and zero assertion helpers:
  ```text
  drive_open_share_vec
  collect_open_share_vec
  drive_assert_zero_share_vec
  collect_assert_zero_share_vec
  ```
  Failed zero checks return a generic canonicality failure and do not expose raw
  failed values.
- [x] Add first production-handle bit-circuit operations:
  ```text
  drive_bit_and_vec / collect_bit_and_vec
  bit_xor_from_and_vec
  bit_or_from_and_vec
  ```
  Tests cover private AND/OR/XOR over Shamir-shared bit vectors through the
  app-driven runtime.
- [x] Add production-handle bitness check primitives:
  ```text
  drive_assert_bit_product_vec
  collect_assert_bit_product_vec
  drive_assert_zero_share_vec
  collect_assert_zero_share_vec
  ```
  The runtime computes `b * (b - 1)` through vector Shamir degree reduction and
  then checks the product is zero through the durable checked-opening/assertion
  path.
- [x] Add first production-handle private-selection support:
  ```text
  one_hot_sum_minus_one
  drive_selection_product_vec
  collect_selection_product_vec
  sum_share_vecs
  ```
  Tests prove one-hot selection bits are checked, selected products are computed
  through the app-driven runtime, and the selected vector reconstructs to the
  expected value.
- [x] Add first production-handle public equality / bit-sum check phases:
  ```text
  drive_equality_to_public_share_vec
  collect_equality_to_public_share_vec
  drive_bit_sum_equals_public_vec
  collect_bit_sum_equals_public_vec
  ```
  These emit durable equality/threshold-check evidence and return generic
  canonicality failure on bad residuals without exposing failed raw values.
- [x] Add production random-bit contribution generation over
  `ProductionBitShareVec`:
  ```text
  drive_random_bit_contribution_vec
  collect_random_bit_contribution_vec
  ```
  Every party privately contributes a random bit vector, Shamir-shares it to
  all receivers through the app transport, and callers combine dealer
  contributions with private XOR rounds. Tests prove the combined bit vector
  reconstructs correctly and emits random-bit plus multiplication evidence.
- [x] Fix production vector Shamir resharing so each lane uses one polynomial
  evaluated at every receiver. This applies to both multiplication
  degree-reduction and random-bit contributions.
- [x] Add handle-level private public-comparison driver state:
  ```text
  ProductionPublicComparisonVecState
  start_lt_public_vec
  start_gt_public_vec
  drive_public_comparison_vec_step
  collect_public_comparison_vec_step
  ```
  The comparison advances through app-driven vector multiplication layers and
  never opens input bits or comparison results. Tests cover private `[x < C]`
  and `[x > C]` over Shamir-shared bit vectors.
- [x] Add release-certificate wrapper targets for Phase 3 consumer evidence:
  ```text
  PreprocessingVectorRuntimeCertificate
  StrictSigningVectorRuntimeCertificate
  ```
  Both apply the full durable vector runtime release gate to
  `ProductionVectorItMpcRuntimeEvidence`.
- [x] Keep the broader Phase 3 runtime-readiness gate separate from the
  Power2Round-only gate: Power2Round evidence must cover its private vector
  circuit, while full Phase 3 readiness must also cover random-bit generation
  and private one-hot selection used by preprocessing/signing.
- [x] Add adversarial/negative tests for existing transport-shaped pieces:
  ```text
  bad checked opening
  bad bitness
  wrong comparison bit
  wrong selection bit
  replayed vector phase
  duplicate gate label
  insufficient preprocessing
  scalarized wire log
  ```

Remaining production tasks:

- [ ] Finish full `<= threshold` circuits over private bit sums. The runtime now
  has private `<` and `>` against public constants and bit-sum residual checks,
  but production hint-weight / threshold checks still need a binary
  adder/decomposition layer for arbitrary private bit sums.
- [ ] Adapt production consumers to use `ProductionVectorPrimeFieldMpcRuntime`
  instead of the older Power2Round-specific phase driver or local/in-process
  trait backends.
- [ ] Remove production dependence on local/in-process Shamir substrates.
  Local and in-process backends may remain only as test/dev modules.
- [ ] Wire the finished vector runtime into all production consumers:
  ```text
  Power2Round
  preprocessing masked-broadcast certification
  CarryCompare / CEF / BCC
  strict response checks
  private selection
  selected opening
  ```
- [ ] Persist durable logs for every production opened value and checked
  opening produced by the final runtime, not only by test-shaped drivers.
- [ ] Thread durable runtime evidence into production certificates/release
  context for preprocessing and strict signing. Power2Round certificates now
  carry runtime evidence, but the other Phase 3 consumers still need equivalent
  release-bound evidence.
- [ ] Replace phase-ordering-only Power2Round driver logs with final runtime
  evidence where appropriate. Current driver logs prove restartable phase
  ordering and selected openings; they do not by themselves prove all internal
  vector runtime operations.
- [ ] Add ML-DSA-44/65/87 performance envelopes with maximum rounds, messages,
  bytes, lanes, and wall-clock budgets.
- [ ] Add malicious tests against the final runtime, not only helper/runtime
  boundaries:
  ```text
  bad checked opening
  bad bitness
  wrong comparison bit
  wrong selection bit
  replayed vector phase
  duplicate gate label
  insufficient preprocessing
  scalarized wire log
  ```

Completion gates:

- [ ] The final runtime supports Power2Round, private BCC/CEF, strict response
  checks, and private selection without scalar compatibility defaults.
- [ ] No scalar-per-coefficient transport path is reachable in production.
- [ ] Failed checks reveal no raw secret-dependent values.
- [ ] Counters meet ML-DSA-44/65/87 baseline envelopes.
- [ ] `cargo check --workspace --features production-release-checks` passes
  with Phase 3 release gates active.

Phase 3 implementation notes:

```text
- Vector Power2Round/prime-field circuit helpers compile in normal builds;
  only local/scaffold backend implementations remain test/dev gated.
- ItMpcPrimeFieldBackend exposes batched bitness checks through
  assert_bit_vec, in addition to open_vec_checked, assert_zero_vec,
  random_bit_vec, mul_vec, and local public-constant multiplication.
- Trait default vector methods remain scalarizing compatibility defaults for
  tests and non-release experiments. Release-capable wrappers now require
  backend counters proving vector execution.
- Durable prime-field MPC wire logs now derive release counters for rounds,
  private messages, broadcasts, canonical wire bytes, durable log bytes,
  vector lanes, and multiplication layers.
- ProductionItMpcReadiness now requires vector runtime operations, durable
  wire logs, release counters, no scalarized execution, and local public
  constant multiplication before a backend may claim ProductionItMpc.
- Public DKG certificates now include optional Power2Round runtime evidence.
  Release gates require it for `ProductionItMpc` certificates; scaffold and
  correctness tests may omit it, but those outputs cannot become release-valid.
```

### Phase 4: Finish Production Power2Round

Goal: compute DKG public `t1` through the production vector IT-MPC runtime.

Status: **partially complete**. The vector Power2Round circuit, typed output
boundary, certified-mask flow, release evidence, and all-suite parity tests are
implemented. Phase 4 is not fully complete until Phase 3 supplies the final
app-driven vector IT-MPC runtime and Phase 9 proves the execution is
non-scalarized and within the production performance envelope.

Completed:

- [x] Drive the full vector Power2Round phase set through the typed runtime
  boundary:
  ```text
  certified mask precompute
  open C = t + A_mask
  wrap compare A_mask > C
  recover canonical R bits
  bitness checks
  R < q checks
  R == t mod q checks
  add 4095
  open only t1 bits
  certify ProductionPower2RoundOutput
  ```
- [x] Ensure `t`, `t0`, lower bits, masks, failed diffs, and witnesses never
  appear in public output, logs, errors, or debug output.
- [x] Add all-suite parity tests against FIPS `Power2Round` for ML-DSA-44,
  ML-DSA-65, and ML-DSA-87.
- [x] Add typed phase-order and resume tests for the Power2Round driver.
- [x] Add release gates rejecting simulator/dev Power2Round evidence.
- [x] Add release gates rejecting Power2Round backends that cannot provide
  vector runtime counters.
- [x] Add a normal-build Power2Round certification boundary on
  `ProductionVectorPrimeFieldMpcRuntime`:
  ```text
  phase-ordering t1 logs alone -> rejected
  durable vector IT-MPC runtime evidence -> required
  output.runtime_evidence -> attached only after release gate validation
  ```

Remaining production tasks:

- [x] Re-run the Power2Round output certification boundary over the Phase 3
  app-driven vector IT-MPC runtime wrapper rather than accepting raw
  phase-ordering logs.
- [x] Move the generic `ItMpcPrimeFieldBackend` Power2Round wrapper out of
  normal production builds:
  ```text
  ProductionItMpcPower2RoundBackend -> cfg(test) / scaffold-dev only
  power2round_t1_vec_with_certified_mask -> cfg(test) / scaffold-dev only
  finish_with_power2round_backend -> cfg(test) / scaffold-dev only
  normal production assembly -> consumes ProductionPower2RoundOutput
  ```
- [x] Move all release-capable Power2Round phase driving onto
  `ProductionVectorPrimeFieldMpcRuntime`:
  ```text
  open masked C
  wrap compare
  canonical subtractor
  canonical bitness/range/equality checks
  add 4095
  open t1 high bits
  certify output with runtime evidence
  ```
  The mutable lower-level runtime escape hatch is test/scaffold-dev only, and
  release-boundary tests now drive the private Power2Round phase set through
  the production runtime facade.
- [ ] Finish runtime-owned Power2Round arithmetic/value generation from
  `[t]` and certified masks inside the final vector runtime. The current
  app-driven runtime owns transport, cursors, durable logs, vector phase
  evidence, and release certification. Runtime-owned circuit state now derives
  the masked opening `C = t + A_mask` from local `[t]` and certified mask
  shares instead of accepting a caller-computed masked vector. Production
  closure still requires the runtime to own the nonlinear bit-circuit state and
  derive wrap comparison, canonical `R`, bitness/range/equality checks,
  add-4095, and `t1` openings from shared inputs rather than accepting
  backend-private or caller-computed phase material.
- [x] Add file-backed restart/resume tests for every Power2Round phase cursor:
  ```text
  masks generated
  masked C opened
  canonical R recovered
  4095 added
  t1 bits opened
  evidence certified
  ```
- [ ] Add durable-log release evidence proving the final runtime opened only
  masked `C` values and `t1` high bits.
- [ ] Add performance gates showing Power2Round round count follows vector
  circuit depth, not coefficient count, for ML-DSA-44/65/87.
- [ ] Add malicious/adversarial tests against the final runtime:
  ```text
  malformed certified mask
  replayed mask id
  wrong masked opening
  forged wrap comparison
  forged canonical R bit
  noncanonical R + q witness
  forged add-4095 carry
  wrong t1 opened bit
  duplicate phase label
  ```

Completion gates:

- [x] Release-capable `ProductionPower2RoundOutput` requires app-driven
  production vector IT-MPC runtime evidence at certification time.
- [ ] The full private Power2Round circuit execution uses only the final
  app-driven production vector IT-MPC runtime. Transport-phase execution is on
  the production runtime facade; runtime-owned arithmetic/state generation is
  still open.
- [x] Scalar/local Power2Round harnesses are test/dev only.
- [x] No `t`, `t0`, low bits, masks, or witnesses are serialized.
- [x] Durable runtime evidence proves no scalar-per-coefficient Power2Round
  release path was used.
- [ ] ML-DSA-44/65/87 Power2Round performance counters satisfy Phase 9
  baseline envelopes.

Phase 4 implementation notes:

```text
- ProductionItMpcPower2RoundBackend and
  power2round_t1_vec_with_certified_mask are now test/dev harnesses because
  they are generic over ItMpcPrimeFieldBackend, which still includes
  local-compatible substrates. They are cfg(test)/scaffold-dev only.
- Normal production assembly consumes an already-certified
  ProductionPower2RoundOutput. Release-capable output must include durable
  app-driven vector IT-MPC runtime evidence.
- All-suite tests compare the production vector output path against the clear
  FIPS reference for ML-DSA-44/65/87, while release gates still reject clear,
  local, in-process, networked, and transport-backed simulator evidence.
- The remaining Phase 4 gap is the real app-driven private circuit execution:
  the production runtime must eventually compute every Power2Round operation
  directly instead of attaching release evidence around test/dev backend-private
  circuit execution.
```

### Phase 5: Finish Native DKG Assembly

Goal: one normal DKG path produces release-valid ML-DSA key packages.

- [x] Wire:
  ```text
  production bounded sampler
  -> production vector IT-VSS
  -> production vector Power2Round
  -> ProductionNativeDkgAssemblyOutput
  ```
- [x] Compute shared:
  ```text
  [t] = A*[s1] + [s2]
  ```
- [x] Consume `s2` into temporary `SharedT` during public-key assembly.
- [x] Open only `t1` through typed `ProductionPower2RoundOutput` carrying
  durable vector runtime evidence.
- [x] Store only:
  ```text
  rho
  t1
  pk = (rho, t1)
  local s1 share
  DKG certificate
  ```
- [x] Remove remaining release-capable scaffold residue/certificate reliance
  from assembly internals.
- [x] Add same-run party/package agreement tests:
  ```text
  rho
  t1
  public key
  certificate
  accepted dealer set
  rejected dealer set
  ```
- [x] Add no-secret-output tests for packages, debug output, and
  serialized artifacts.
- [x] Add all-suite DKG assembly agreement tests for ML-DSA-44/65/87.

Completion gates:

- [x] Full release-valid native DKG assembly succeeds for ML-DSA-44/65/87.
- [x] Release validator accepts exactly one production output path.
- [x] Any scaffold/simulator artifact in DKG output fails validation.

Phase 5 implementation notes:

```text
- assemble_logged_native_dkg_production_from_logs is the normal production
  assembly helper. It recovers certified production setup logs and consumes a
  typed ProductionPower2RoundOutput that the application produced through the
  app-driven vector runtime evidence boundary.
- assemble_logged_native_dkg_production_with_power2round_backend and
  NativeDkgSession::finish_with_power2round_backend are cfg(test)/scaffold-dev
  only. They remain for correctness tests while Phase 4 migrates the full
  private circuit to the final app-driven runtime.
- Native DKG assembly tests no longer derive t1 with ClearSimPower2RoundBackend;
  they use the production vector Power2Round wrapper and assert release-valid
  packages contain no s2, t, t0, SharedT, or simulator evidence.
- production_native_dkg_assembly_all_suites_release_valid covers ML-DSA-44,
  ML-DSA-65, and ML-DSA-87 with production Power2Round evidence and
  ProductionNativeDkgAssemblyOutput::new. The app-driver log test still runs
  the full transport-shaped batch path for ML-DSA-44 because it is intentionally
  heavier.
```

### Phase 6: Finish Production Preprocessing Tokens

Goal: fill a durable pool of BCC-certified tokens without trusted dealer
material or post-challenge leakage.

- [x] Replace the production-facing nonce-generation boundary with an
  app-driven session facade:
  ```text
  DistributedNonceGenerationSession::start
  handle_private
  handle_broadcast
  next_outbound
  finish -> DistributedNonceGenerationLocalOutput
  ```
  The facade emits typed receiver-private IT-VSS deliveries and reliable
  broadcast artifacts; each party finishes with only its local nonce share and
  public evidence. The older `generate_distributed_nonce_shares` helper remains
  an all-party integration harness for tests.
- [x] Batch/counter model and all-suite token-batch gate exist:
  ```text
  token batch
  coefficient lanes
  signer lanes
  vector/chunk labels
  ```
- [x] Product masked-broadcast consistency verifier rejects clear audit witnesses
  and requires transcript-bound private-certification proof bytes.
- [x] Remove local aggregate `A*y` witness dependence from production CEF/BCC
  token admission. The distributed nonce adapter no longer fills
  `ay_contribution`, and CEF/BCC certification uses opened masked-broadcast
  high/low material plus certified mask/carry data.
- [x] Certify:
  ```text
  masked-broadcast consistency
  CarryCompare kappa bits
  CEF delta correction bits
  w1
  BCC admission
  ```
- [x] Add durable token inventory state model:
  ```text
  Fresh -> Reserved -> Consumed -> Erased
  ```
- [x] Reject duplicate session ids and corrupt file-backed session/counter logs.
- [x] Add preprocessing counters and release threshold gate for vector lanes,
  masked broadcasts, CarryCompare lanes, CEF correction lanes, and BCC lanes.
- [x] Add all-suite token-batch tests.
- [x] Add app-driven nonce-generation routing test covering private delivery,
  public precommitment, public coin, public commitment, local finish, and
  evidence agreement across parties.

Completion gates:

- [x] Token cannot enter strict pool unless BCC-certified by production
  evidence.
- [x] No preprocessing release path needs local aggregate nonce witnesses.
- [x] Failed BCC is pre-challenge and reveals no nonce material, low bits,
  boundary distances, masks, or failure positions.
- [x] Token pool/inventory rejects reuse; file-backed session and counter logs
  survive restart and reject corrupt logs.

Phase 6 review/backend-selection follow-up:

```text
- Replace deterministic masked-broadcast proof hash stubs with the final
  reviewed private-certification transcript once that backend is selected.
```

Phase 6 implementation note: production parties must not receive
`DistributedNonceGenerationOutput` because that type contains every party's
nonce share and exists only for local integration tests. The production-facing
session returns `DistributedNonceGenerationLocalOutput`.

### Phase 7: Finish Strict Production Signing

Goal: produce only final valid ML-DSA signatures, with no rejected-z leakage.

- [x] Normal API exposes a single canonical strict production backend builder:
  ```text
  strict_production_signing_backend(...)
  StrictProductionSigningBackend<SP>
  ```
  Distributed runtimes must adapt the same component stack and must not grow a
  duplicate response/check/select/open implementation.
- [x] Replace clear partial-signature transport with production vector
  component handles. Candidate handles are opaque in public/debug surfaces and
  are consumed phase-by-phase by the canonical backend stack.
- [x] Compute privately for every token:
  ```text
  [z_j] = [y_j] + c_j * [s1]
  ```
- [x] Privately check:
  ```text
  z bound
  r = A*z - c*t1*2^d
  HighBits(r) vs w1
  hint weight <= omega
  valid_j
  ```
- [x] Select the lowest public-priority valid candidate without opening
  `valid_j` or failure reasons.
- [x] Open only selected:
  ```text
  ctilde*
  z*
  h*
  ```
- [x] Run independent FIPS 204 verification before returning.
- [x] On no-valid or failed final verify, return generic failure and keep all
  participating tokens consumed.
- [x] Add malicious coordinator/session-driver tests:
  ```text
  wrong challenge
  forked signer set
  token reuse attempt
  rejected-z collection attempt
  detailed failure reason request
  replayed strict MPC message
  ```

Completion gates:

- [x] No `z_i`, unselected aggregate `z`, candidate hints, validity bits, or
  failure reasons appear in public output, wire messages, durable logs, errors,
  or telemetry.
- [x] Every returned signature passes standard FIPS 204 verification.
- [x] Crash after token consumption cannot restore tokens.

Phase 7 implementation note: the canonical strict signing stack is production
API shape and no-rejected-z discipline. Cross-party vector IT-MPC transport
optimization and proof/backend review continue in Phase 9 and Phase 12; callers
must not implement a second signing algorithm in a distributed runtime.

### Phase 8: Transport And Persistence Hardening

Goal: make app-supplied transport and durable-state requirements testable.

- [x] Update transport docs and rustdoc to say the crate supplies interfaces,
  not sockets.
- [x] Add embeddable conformance tests for downstream transport adapters:
  ```text
  ML-KEM session evidence present and context-bound
  ML-DSA identity evidence present and context-bound
  authenticated private delivery
  reliable broadcast same-message-or-abort
  replay rejection
  duplicate rejection
  equivocation detection
  ```
- [x] Finish durable stores for:
  ```text
  DKG message log
  DKG phase cursor log
  IT-VSS phase cursor log
  Power2Round phase cursor log
  preprocessing token inventory
  strict signing token-use log
  mask-use log
  ```
- [x] Add corrupt/truncated/rollback log tests.
- [x] Add delayed/reordered/replayed delivery tests across DKG, preprocessing,
  Power2Round, and strict signing.

Completion gates:

- [x] Production cannot start without matching transport evidence.
- [x] Restart resumes only from persisted cursors and accepted logs.
- [x] Incomplete/aborted sessions cannot become accepted.
- [x] Reused token/mask/preprocessing ids fail closed.

Phase 8 implementation note: `talus-wire` remains an interface and canonical
encoding crate, not a socket implementation. Existing tests cover ML-KEM-768
session binding, ML-DSA-65 identity binding, authenticated private delivery,
duplicate/replay rejection, wrong-context rejection, and same-message-or-abort
reliable broadcast. `talus-dkg` owns file-backed DKG/Power2Round message logs,
phase cursor logs, IT-VSS cursor release gates, and Power2Round mask-use logs.
`talus-mpc` now adds `FileTokenInventory`, so preprocessing token reservation,
consumption, erasure, corrupt-log rejection, and rollback rejection are durable
across restart.

### Phase 9: Cross-System Vectorization And Optimization

Goal: make DKG, preprocessing, BCC/CEF, and strict signing usable in real
deployments by ensuring cost follows batches/chunks and circuit depth, not
scalar coefficient loops.

Status: **not complete**. The shared counter/evidence groundwork is complete,
but full production performance is not proven until the remaining release paths
consume those counters as hard gates and the end-to-end performance tests run
over the real production flow.

Completed in the Phase 9 groundwork pass:

- [x] Define production batch/chunk sizing policy for each suite:
  ```text
  ML-DSA-44
  ML-DSA-65
  ML-DSA-87
  ```
- [x] Add one shared performance counter model across DKG, IT-VSS, IT-MPC,
  preprocessing, and strict signing:
  ```text
  rounds
  private messages
  broadcasts
  wire bytes
  durable log bytes
  vector lanes
  multiplication layers
  opened lanes
  checked lanes
  token batch size
  wall-clock time
  ```
- [x] Add adapters from existing subsystem counters into the shared performance
  model:
  ```text
  talus-dkg/src/it_vss.rs:
    ProductionItVssCounters -> TalusPerformanceCounters

  talus-dkg/src/power2round.rs:
    PrimeFieldMpcCounters -> TalusPerformanceCounters

  talus-mpc/src/local.rs:
    PreprocessingCertificationCounters -> TalusPerformanceCounters

  talus-mpc/src/online.rs:
    StrictSigningEvidence -> TalusPerformanceCounters
  ```
- [x] Existing scalarized prime-field MPC wire-log checks reject scalar payload
  evidence on release paths.

Remaining Phase 9 implementation tasks:

- [ ] Finish proving/vectorizing IT-VSS at the chunk/vector level:
  ```text
  one vector commitment per dealer/vector/chunk
  vector IC tags
  vector audit/discard
  vector polynomial consistency
  vector complaint resolution
  no scalar-per-coefficient release path
  ```
  Code references:
  ```text
  talus-dkg/src/it_vss.rs: ProductionInformationCheckingVssBackend
  talus-dkg/src/it_vss.rs: ProductionItVssCounters
  talus-dkg/src/lib.rs: drive_share_small_residue_vector_batches_it_vss
  ```
- [ ] Finish proving/vectorizing bounded sampler:
  ```text
  full s1/s2 residue vectors
  batched bitness checks
  batched range checks
  batched sum-mod-m circuits
  batched transcript labels
  ```
  Code references:
  ```text
  talus-dkg/src/lib.rs: sample_verified_small_polyvec
  talus-dkg/src/lib.rs: it_vss_share_small_residue_vector_batches
  ```
- [ ] Finish proving/vectorizing Power2Round execution:
  ```text
  precomputed certified mask batches
  open all masked C lanes together
  compare all A_mask > C lanes together
  recover/certify all canonical R bits by bit column
  add 4095 by bit column
  open all t1 lanes together
  ```
  Code references:
  ```text
  talus-dkg/src/power2round.rs: ProductionPower2RoundDriver
  talus-dkg/src/power2round.rs: PrimeFieldMpcCounters
  talus-dkg/src/power2round.rs: ensure_prime_field_mpc_wire_log_vectorized_for_release
  ```
- [ ] Finish proving/vectorizing preprocessing token generation:
  ```text
  token batches
  coefficient lanes
  signer lanes
  masked-broadcast commit/open vectors
  CarryCompare lanes
  CEF correction lanes
  BCC admission lanes
  ```
  Code references:
  ```text
  talus-mpc/src/local.rs: PreprocessingSession
  talus-mpc/src/local.rs: PreprocessingCertificationCounters
  talus-mpc/src/local.rs: DistributedNonceGenerationSession
  ```
- [ ] Finish proving/vectorizing strict signing checks:
  ```text
  candidate-token batch
  z response lanes
  z-bound predicate lanes
  hint/highbits lanes
  hint-weight lanes
  private selection lanes
  selected opening only
  ```
  Code references:
  ```text
  talus-mpc/src/online.rs: ProductionStrictSigningBackend
  talus-mpc/src/online.rs: StrictResponseCheckCounters
  talus-mpc/src/online.rs: StrictSigningDistributedRuntime
  ```
- [ ] Precompute reusable certified material where safe:
  ```text
  Power2Round canonical masks
  preprocessing nonce-mask material
  IT-MPC random bits
  multiplication/checking preprocessing
  ```
  Each precomputed item must have a durable one-time-use log and a transcript
  binding. Reuse after crash must fail closed.
- [ ] Remove or ignore slow scalar stress tests from default production
  performance runs:
  ```text
  scalar-per-coefficient Power2Round
  scalar-per-coefficient VSS
  paper-compat/test-only signing harnesses
  ```
- [ ] Add performance envelopes for ML-DSA-44 baseline and suite-scaled
  envelopes for ML-DSA-65/87:
  ```text
  max rounds
  max messages
  max bytes
  max durable bytes
  max wall-clock time on local in-memory transport
  no scalarized release counters
  ```
- [ ] Add regression tests/bench-smoke jobs that fail when a release path
  accidentally loops through scalar transport phases.

Completion gates:

- [ ] DKG round count scales with circuit phases/chunks, not coefficient count.
- [ ] Preprocessing token-batch fill scales with token chunks and vector lanes,
  not individual scalar checks.
- [ ] Strict signing opens only selected signature material and reports vector
  counters for private checks.
- [ ] Release counters prove vector/chunk execution for every production path.
- [ ] ML-DSA-44 baseline stays within the agreed performance envelope.
- [ ] Slow scalar correctness stress tests are marked as dev/ignored or kept out
  of production performance gates.

Phase 9 groundwork note: `talus-core::performance` now provides the shared
`ProductionBatchSizingPolicy`, `TalusPerformanceCounters`, and smoke
`TalusPerformanceEnvelope`. `talus-dkg` adapts `ProductionItVssCounters` and
`PrimeFieldMpcCounters` into that shared model; `talus-mpc` adapts
preprocessing certification counters and strict-signing evidence. This is
instrumentation and release-evidence plumbing only. It must not be read as proof
that every production path is fully optimized end-to-end.

### Phase 10: Release Gates, Scans, And Performance Gates

Goal: production-invalid builds and artifacts fail automatically.

- [ ] Consolidate release validation so production DKG/signing output can only
  pass through one narrow release-valid path.
- [ ] Complete forbidden field scans across serialized release outputs:
  ```text
  s2
  t
  t0
  low bits
  mask witnesses
  retained receiver tags
  private setup payloads
  rejected z
  detailed failure reason
  ```
- [ ] Extend scans to final preprocessing token-batch logs and final app-driven
  IT-MPC logs.
- [ ] Add performance regression jobs for ML-DSA-44 baseline:
  ```text
  DKG setup
  Power2Round
  preprocessing batch fill
  strict signing with prepared tokens
  restart/resume
  ```
- [ ] Add CI jobs:
  ```text
  cargo fmt --check
  cargo clippy --workspace --all-targets
  cargo test --workspace
  cargo check --workspace --features production-release-checks
  release-gate tests
  source/API scans
  performance smoke tests
  ```

Completion gates:

- [ ] Any simulator/scaffold/test backend in normal build fails release checks.
- [ ] Any public exact `A*secret` image fails release checks.
- [ ] Any rejected-z leakage path fails release checks.
- [ ] Counters prove vectorized execution, not scalar-per-coefficient
  execution.

### Phase 11: End-To-End Production Tests

Goal: prove the whole production path.

- [ ] ML-DSA-44:
  ```text
  DKG -> preprocessing -> strict signing -> FIPS verify
  ```
- [ ] ML-DSA-65:
  ```text
  DKG -> preprocessing -> strict signing -> FIPS verify
  ```
- [ ] ML-DSA-87:
  ```text
  DKG -> preprocessing -> strict signing -> FIPS verify
  ```
- [ ] Malicious DKG tests:
  ```text
  bad VSS private delivery
  bad public coin
  bad Power2Round phase
  restart mid-phase
  corrupt/truncated log
  ```
- [ ] Malicious preprocessing tests:
  ```text
  bad masked broadcast
  wrong CEF correction
  BCC failure
  token reuse
  rollback
  ```
- [ ] Malicious signing tests:
  ```text
  wrong challenge
  bad token batch
  no valid token batch
  rejected-z collection attempt
  failed final verifier
  ```

Completion gates:

- [ ] All suites produce standard-verifiable signatures.
- [ ] No invalid signature is returned.
- [ ] No rejected candidate material is exposed.
- [ ] No public exact `A*secret` appears in logs, artifacts, or public output.
- [ ] Performance counters are within the agreed target envelope.

### Phase 12: Cryptographic Review Package

Goal: make external cryptographic review efficient after the implementation is
complete.

- [ ] Protocol spec for final vector IT-VSS.
- [ ] Protocol spec for final vector IT-MPC.
- [ ] Protocol spec for private BCC/CEF and strict signing.
- [ ] Final masked-broadcast private-certification backend selection; replace
  deterministic proof-hash stubs with the reviewed transcript/proof artifact.
- [ ] Protocol spec for bounded sampler and DKG assembly.
- [ ] Source map from every protocol step to code.
- [ ] Public/private transcript field inventory.
- [ ] Persistence and crash-safety inventory.
- [ ] Zeroization and one-time-material inventory.
- [ ] Security claims and non-claims:
  ```text
  security with abort
  honest majority only
  no fairness claim
  no paper-fast rejected-z claim
  signatures are standard-verifiable, not distribution-identical unless later proven
  ```
- [ ] Test matrix and coverage summary.
- [ ] Performance report.

Completion gates:

- [ ] Reviewer can trace every public artifact to a protocol step.
- [ ] Reviewer can trace every secret value to storage, use, and erasure rules.
- [ ] Every release gate has a documented security reason.
- [ ] Every deviation from the TALUS paper is documented and justified.

## Next Workable Slice

Start here:

1. Finish the remaining Phase 9 vectorization and performance-gate tasks.
2. Phase 10 release gates, scans, and performance gates.
3. Phase 11 end-to-end system tests.
4. Phase 12 cryptographic review package.

Do not return to older archived checklists unless you need historical context.
Implement against this file.
