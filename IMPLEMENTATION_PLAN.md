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
docs/production-optimization-principles.md
docs/threshold-scheme-evaluation.md
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

## External Scheme Evaluation Track

Canonical document:

```text
docs/threshold-scheme-evaluation.md
```

This track evaluates external threshold ML-DSA schemes that may inform future
backend choices. It is not a replacement for the current production plan until
its completion gates pass.

Tracked candidates:

```text
Track A:
  Mithril / ePrint 2026/013

Track B:
  Quorus / ePrint 2025/1163
```

Current status:

```text
[ ] Mithril paper review complete.
[ ] Mithril Go implementation inspected and tested for N=3..6.
[ ] Rust threshold-ml-dsa crate provenance inspected.
[ ] Mithril signatures verified with an independent FIPS 204 verifier.
[ ] Mithril DKG/key-import and malicious/fail-closed behavior assessed.

[x] Quorus paper review complete.
[x] Quorus honest-majority production model extracted.
[~] Quorus round count and WAN latency evaluated.
[ ] Quorus implementation availability checked.
[x] Quorus compared against the current IT-VSS/IT-MPC direction at design level.
```

Current Quorus conclusion:

```text
Quorus should be treated as a separate QuorusProfile, not merged into TALUS
strict signing. It keeps the external FIPS ML-DSA public key shape pk=(rho,t1),
but the threshold protocol opens full t and stores protocol-public t0. It uses
shares [s] and [e], Quorus preprocessing, and private RejSamp instead of TALUS
BCC/CEF and s1-only signing.

This makes Quorus a strong candidate for the no-TEE honest-majority production
path, but adopting it is an architectural pivot. It requires a separate
prototype and tests, not partial grafting onto the current TALUS BCC/CEF path.
```

Decision rule:

```text
No external scheme may replace the current production path based on paper,
README, crate, or benchmark claims alone. A candidate must pass independent
FIPS 204 verification tests, malicious/fail-closed tests, dependency/provenance
review, and transport/DKG fit analysis before it can become a prototype backend.
```

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

Status: **complete for the Phase 2 boundary**. The normal-build vector IT-VSS
backend and app-driver flow include vector Shamir sharing, vector IC tag
material, retained-tag privacy, precommitment, post-precommitment public coins,
final public metadata, first-class public audit/discard artifacts, first-class
public vector-consistency artifacts, private delivery, local verification,
complaint collection, complaint resolution artifacts, restart cursors, durable
public replay, malformed transcript rejection, conservative no-false-blame
dispute handling, and release gates.

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
  public audit/discard records
  public vector consistency records
  final public metadata
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
  public precommitment
    -> public coin shares
    -> final public commitment
    -> public audit/discard records
    -> public vector consistency records
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
- [x] Implement vector IC tag types and checks:
  ```text
  holder-side y vectors
  audited receiver-side (b, c_vec)
  retained receiver-private (b, c_vec)
  retained-tag Debug redaction
  retained-tag public serialization unavailable
  ```
- [x] Implement vector Shamir sharing and directed private deliveries in
  `ProductionInformationCheckingVssBackend`.
- [x] Implement public-coin share/transcript derivation after precommitment.
- [x] Implement local private-delivery verification and hash-bound complaint
  evidence.
- [x] Implement release counters proving vector/chunk execution shape.

Recently closed Phase 2 tasks:

- [x] Make public audit/discard a first-class app-driver round:
  ```text
  audited receiver tags are broadcast/opened only for audit
  audited tags are explicitly discarded
  retained receiver tags remain receiver-private forever
  all observers can verify audit records from durable logs
  ```
- [x] Make vector polynomial consistency a first-class independently
  verifiable transcript:
  ```text
  public coins derive challenge bits after precommitment
  dealer/public transcript exposes the masked polynomial evaluations needed for
    verification
  every holder check is reproducible from durable logs
  metadata hashes alone are insufficient for release
  ```
- [x] Extend release gates so accepted S1/S2 vector IT-VSS artifacts require:
  ```text
  public precommitment
  complete public coin transcript
  independently persisted audit/discard transcript
  independently persisted consistency transcript
  valid complaint-resolution artifact
  vector counters
  ```
- [x] Add negative tests proving metadata-hash-only IT-VSS artifacts cannot
  satisfy release gates.

Closed Phase 2 completion tasks:

- [x] Add a public durable-log replay verifier for vector IT-VSS:
  ```text
  input:
    DkgConfig
    durable DKG wire log

  replay:
    expected S1/S2 vector IT-VSS labels
    public precommitments
    post-commitment public coin shares
    final public commitments
    public audit/discard records
    public vector consistency records
    complaints and complaint-resolution artifact

  output:
    accepted dealer set
    rejected dealer set
    replay transcript hash / evidence

  completion:
    replay reaches the same accepted/rejected dealer set as the persisted
    resolution, and malformed public transcript shape/order is rejected before
    any setup artifact is accepted. Hash-level forged audit/consistency
    rejection is covered by the following closed Phase 2 tasks.
  ```
- [x] Strengthen public audit/discard validation:
  ```text
  done:
    carry the opened audited receiver-side tag bytes in the durable public
      audit artifact
    verify audited_receiver_tag_hash against replayable opened audited tag
      material
    verify the opened audit material encodes the same holder, receiver, and
      tag index as the public audit record
    reject wrong dealer/holder/receiver/label combinations
    reject duplicate audit records
    reject retained receiver tags or retained-tag markers in public audit
      material
    reject missing audit records
    reject unbalanced extra audit tag indices by requiring each S1/S2
      dealer/label tuple to use contiguous tag indices with the same count for
      every holder/receiver pair

    bind the exact expected audit tag count to the accepted public metadata
      hash for each production IT-VSS commitment

  completion:
    forged public audit records cannot satisfy release validation or third-party
    replay.
  ```
- [x] Strengthen vector polynomial consistency validation:
  ```text
  done:
    carry the opened masked evaluation vector bytes in the durable public
      consistency artifact
    verify masked_eval_hash against replayable public consistency material
    verify the masked-eval material encodes the same dealer, holder, label,
      round, and challenge bit as the public consistency record
    verify challenge_bit against the post-commitment public coin transcript
    reject wrong dealer/holder/label combinations
    reject duplicate consistency records
    reject missing consistency records
    reject unbalanced extra consistency rounds by requiring each S1/S2
      dealer/label tuple to use contiguous round indices with the same count
      for every holder

    bind the exact expected consistency round count to the accepted public
      metadata hash for each production IT-VSS commitment

  completion:
    forged consistency masked evaluations, wrong public coins, missing rounds,
    and replayed public coins cannot satisfy release validation or third-party
    replay.
  ```
- [x] Add Phase 2 adversarial tests:
  ```text
  forged public audit hash [done]
  retained receiver tag disguised as public audit material [done]
  wrong audited-tag holder/receiver/tag-index encoding [done]
  forged vector consistency hash [done]
  wrong public coin challenge bit [done]
  missing consistency round [done]
  extra consistency round [done]
  uniform extra audit tag count rejected by metadata [done]
  uniform extra consistency round count rejected by metadata [done]
  replayed public coin transcript [done]
  duplicate audit/consistency record [done]
  ambiguous complaint evidence [done]

  completion:
    every malformed case fails closed with no accepted setup artifact.
  ```
- [x] Wire conservative vector IT-VSS dispute policy:
  ```text
  done:
    production vector IT-VSS does not turn hash-only complaint evidence into
      rejected dealers
    non-empty production complaint sets validate public shape, then return
      ItVssAbortNoBlame
    duplicate complaint keys are rejected as ambiguous public evidence
    malformed audit transcript -> abort/reject
    malformed consistency transcript -> abort/reject
    no public beta/share-point reveal

  completion:
    vector/public audit and consistency disputes cannot falsely blame the
    dealer when the evidence is not public and attributable; tests prove false
    dealer blame is not emitted.
  ```
- [x] Update Phase 2 gates and docs after implementation:
  ```text
  mark durable replay verifier complete
  mark forged audit/consistency rejection complete
  document AbortNoBlame/blame policy as implemented in vector replay
  keep external cryptographic review tracked in Phase 12, not as a Phase 2
    implementation blocker
  ```

Completion gates:

- [x] Production release context requires the full batched/vector IT-VSS public
  flow, including independently persisted audit/discard and consistency
  transcripts.
- [x] No scalar-per-coefficient IT-VSS artifact can satisfy release gates.
- [x] Retained receiver tags never appear in public artifacts/logs.
- [x] Public beta/share-point reveal is unavailable in v1 production.
- [x] Accepted vector IT-VSS sharing certificates cannot be produced from
  metadata hashes alone.
- [x] A third-party observer can replay durable public IT-VSS logs and reach the
  same accepted/rejected dealer set with malformed audit/consistency rejection
  coverage.

Implementation note:

- The current `ProductionInformationCheckingVssBackend` is the normal-build
  vector IT-VSS backend for DKG setup. It is vector/chunk shaped and rejects
  scalar-per-coefficient release labels. It now emits replayable public
  audit/discard and vector-consistency artifacts through `DkgItVssArtifact`
  wire payloads. Remaining performance proof work is tracked in Phase 9, not
  here.

### Phase 3: Finish Production Vector Prime-Field IT-MPC Runtime

Goal: provide the release-capable vector MPC runtime used by Power2Round,
preprocessing BCC/CEF, and strict signing checks.

Status: **partially complete, with the core runtime surface largely in place**.
The vector containers, app-driven runtime phases, production handle types,
durable wire records, counters, readiness evidence, and release gates exist.
The remaining Phase 3 risk is no longer the absence of basic vector operations;
it is consumer migration and all-suite/performance closure. Power2Round already
carries durable app-driven vector runtime evidence, and preprocessing now
carries durable vector runtime evidence for the current release
token-certification path. Strict signing still needs the finished
runtime-owned response-check consumer path; all-suite and performance gates
remain open until the full DKG, preprocessing, and signing pipeline runs
through release evidence.

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

- [x] Add private bit-sum / `<= public threshold` runtime surface for
  production handles. This exists in the vector runtime and is now a consumer
  integration issue, not a missing primitive.
- [x] Add explicit preprocessing phase markers to durable vector IT-MPC
  evidence:
  ```text
  PreprocessingMaskedBroadcast
  PreprocessingCarryCompare
  PreprocessingCefBcc
  ```
  `ProductionVectorItMpcRuntimeCoverage` now records these separately from
  generic open/assert-zero/mul coverage, so release evidence can prove
  preprocessing-specific runtime execution instead of only "some vector runtime
  happened".
- [x] Add a preprocessing-tagged CarryCompare comparison circuit entry point:
  ```text
  start_preprocessing_carry_compare_gt_public_lanes_vec
  ```
  It reuses the existing private vector comparison circuit but records
  multiplication layers under `PreprocessingCarryCompare`, not the generic
  comparison phase. Tests reconstruct expected carry bits and verify durable
  preprocessing CarryCompare coverage.
- [x] Add a preprocessing-tagged CEF/BCC threshold circuit entry point:
  ```text
  start_preprocessing_cef_bcc_bit_sum_leq_public_vec
  ```
  It reuses the existing private vector bit-sum / `<= public threshold`
  circuit but records its multiplication and comparison layers under
  `PreprocessingCefBcc`. Durable coverage now treats this phase as both
  preprocessing CEF/BCC evidence and threshold-check evidence. Tests
  reconstruct expected threshold predicates and verify no scalar gate use.
- [ ] Adapt every release-capable production consumer to use
  `ProductionVectorPrimeFieldMpcRuntime` evidence rather than local/in-process
  trait backends or subsystem-specific proof stubs. Current status:
  ```text
  Power2Round -> migrated to durable app-driven vector runtime evidence
  preprocessing -> migrated for the current release preprocessing path
  strict signing -> not fully migrated; see Phase 7
  ```
- [ ] Remove production dependence on local/in-process Shamir substrates for
  preprocessing and strict signing. Local and in-process backends may remain
  only as test/dev modules.
- [ ] Wire the finished vector runtime into all production consumers:
  ```text
  Power2Round -> done for release evidence and state-owned t1 opening
  preprocessing masked-broadcast certification -> done for current release path
  CarryCompare / CEF / BCC -> done for current release path
  strict response checks -> Phase 7 blocker
  private selection -> runtime primitive exists; Phase 7 consumer blocker
  selected opening -> runtime primitive exists; Phase 7 consumer blocker
  ```
- [ ] Persist durable logs for every production opened value and checked
  opening produced by the final runtime, not only by test-shaped drivers.
- [ ] Thread durable runtime evidence into production certificates/release
  context for strict signing. Preprocessing release tokens now carry runtime
  evidence for masked-broadcast, CarryCompare, and CEF/BCC; strict signing
  still needs its runtime-owned response-check path.
- [x] Replace phase-ordering-only Power2Round release certification with final
  runtime evidence. Power2Round restart cursors still exist for resumability,
  but release-capable `ProductionPower2RoundOutput` requires durable vector
  runtime evidence and state-owned nonlinear markers.
- [x] Add preprocessing ML-DSA-44/65/87 best-shape performance reports with
  measured records, private/broadcast split, bytes, durable bytes, lanes,
  wall-clock time, and no-scalarized-release counters.
  Current representative release-mode results:
  ```text
  ML-DSA-44: 72 records, 70 private / 2 broadcast, 569,344 lanes,
             1,719,552 wire bytes, 3,439,824 durable log bytes,
             setup/private/masks/cert = 10/23/56/12 ms,
             chunk_policy_ok=true, no_scalarized_release_profile=true.

  ML-DSA-65: 76 records, 74 private / 2 broadcast, 819,200 lanes,
             2,469,760 wire bytes, 4,940,280 durable log bytes,
             setup/private/masks/cert = 18/41/114/27 ms,
             chunk_policy_ok=true, no_scalarized_release_profile=true.

  ML-DSA-87: 78 records, 76 private / 2 broadcast, 1,107,968 lanes,
             3,336,384 wire bytes, 6,673,548 durable log bytes,
             setup/private/masks/cert = 15/51/120/26 ms,
             chunk_policy_ok=true, no_scalarized_release_profile=true.
  ```
  The strict-mask generic `< q` comparison has been replaced with the ML-DSA
  special-form predicate `!(high_10_bits_all_one && low_13_bits_any_one)`,
  reducing the strict-mask comparison circuit from 23 generic comparison
  layers to reduction layers plus one final AND. The current bottlenecks are
  now `RandomBitShare`, specialized strict-mask `MulDegreeReductionShare`, and
  preprocessing `CarryCompare`. ML-DSA-65/87 strict-mask random-bit phases are
  chunked under the production per-record lane policy.
  Strict signing and DKG best-shape reports remain separate open tasks.
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
  checks, and private selection without scalar compatibility defaults. The
  runtime support is in place for the core operations, but private BCC/CEF and
  strict-signing consumer flows have not yet been migrated end-to-end.
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

Status: **complete for the release boundary and consumer migration scope**.
The vector Power2Round circuit, typed output boundary, certified-mask flow,
state-owned nonlinear runtime markers, release evidence, restart cursors, and
all-suite parity/performance tests are implemented. Remaining work is
optimization and cleanup: slow full-lane stress paths stay out of default test
runs, and legacy helper-only drivers may be deleted or further isolated once
adversarial/dev tests no longer reference them.

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
- [x] Finish runtime-owned Power2Round arithmetic/value generation from
  `[t]` and certified masks inside the final vector runtime. The current
  app-driven runtime owns transport, cursors, durable logs, vector phase
  evidence, and release certification.
  Current runtime-owned state now derives:
  - [x] masked opening `C = t + A_mask`;
  - [x] lane-wise private wrap comparison `[A_mask > C]`;
  - [x] canonical `R` bits through the private subtractor from `C`, wrap, and
    mask bits;
  - [x] private `R < q` comparison state from recovered `R_bits`;
  - [x] equality residual `sum_j 2^j R_j == [t] mod q` from recovered
    `R_bits`;
  - [x] `S_bits = R_bits + 4095` through a runtime-owned ripple adder;
  - [x] selected `t1` high-bit openings from state-owned `S_bits`.
  - [x] state-owned bitness product/zero-check APIs for recovered `R_bits`
    with focused runtime tests.
  - [x] release certification now requires durable state-owned nonlinear
    runtime markers, so caller-supplied nonlinear phase vectors alone cannot
    satisfy `ProductionPower2RoundOutput` certification.
- [x] Add file-backed restart/resume tests for every Power2Round phase cursor:
  ```text
  masks generated
  masked C opened
  canonical R recovered
  4095 added
  t1 bits opened
  evidence certified
  ```
- [x] Add durable-log release evidence proving the final runtime opened only
  masked `C` values and `t1` high bits.
- [x] Add performance gates showing Power2Round round count follows vector
  circuit depth, not coefficient count, for ML-DSA-44/65/87.
- [x] Add malicious/adversarial tests against the final runtime:
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
  Current coverage:
  - [x] forged canonical/subtractor residual is rejected before certification.
  - [x] inconsistent masked-opening Shamir shares are rejected before storing
    opened `C`.
  - [x] non-bit `t1` opening is rejected before certification.
  - [x] malformed certified mask / wrong mask binding.
  - [x] replayed mask id.
  - [x] wrong masked opening share.
  - [x] forged wrap comparison.
  - [x] forged canonical `R` bit / noncanonical `R + q` witness.
  - [x] forged add-4095 carry.
  - [x] duplicate phase label.

Completion gates:

- [x] Release-capable `ProductionPower2RoundOutput` requires app-driven
  production vector IT-MPC runtime evidence at certification time.
- [x] The full private Power2Round circuit execution uses only the final
  app-driven production vector IT-MPC runtime. Runtime-owned nonlinear state
  generation and release markers are in place. Release-boundary and
  all-suite performance callers now open `t1` through state-owned `S_bits`;
  old helper-heavy phase drivers remain only as negative/dev scaffolding.
- [x] Scalar/local Power2Round harnesses are test/dev only.
- [x] No `t`, `t0`, low bits, masks, or witnesses are serialized.
- [x] Durable runtime evidence proves no scalar-per-coefficient Power2Round
  release path was used.
- [x] ML-DSA-44/65/87 Power2Round performance counters satisfy Phase 9
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
- Phase 4's former app-driven private-circuit gap is closed for the release
  boundary: state-owned masked opening, wrap comparison, canonical R recovery,
  bitness, range/equality, add-4095, t1 opening, and release marker checks now
  exist. Release-boundary tests and all-suite performance gates now use the
  state-owned t1-opening path. Remaining cleanup is deleting or moving the
  legacy helper-only phase drivers once no adversarial/dev tests reference
  them.
```

### Phase 5: Finish Native DKG Assembly

Goal: one normal DKG path produces release-valid ML-DSA key packages.

Status: **complete for the native DKG assembly boundary**. The normal
production assembly entry point, typed `ProductionNativeDkgAssemblyOutput::new`,
package release gates, no-secret-output shape, scaffold/dev gating, setup-bound
Power2Round output, production public-output commitments, and release-context
finalization helper are in place.

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
- [x] Replace placeholder `scaffold_party_commitment` public output fields with
  real production artifacts recovered from DKG setup logs:
  ```text
  pairwise_seed_commitments
  vss_commitments / IT-VSS public commitment summaries
  ```
- [x] Bind `ProductionPower2RoundOutput` to the recovered setup transcript, not
  only to config/rho/t1:
  ```text
  setup transcript hash
  sampler_s1_hash
  sampler_s2_hash
  IT-VSS public artifact hash
  IT-VSS resolution hash
  SharedT/input-origin hash or equivalent runtime input certificate
  ```
  This prevents a valid `t1` output for the same config/rho from being attached
  to unrelated recovered setup logs.
  - [x] Production setup recovery now replays the durable public vector IT-VSS
    log before native DKG assembly accepts setup artifacts. Metadata-hash-only
    IT-VSS logs are rejected at the assembly recovery boundary, not only by a
    standalone release scanner.
  - [x] `ProductionPower2RoundOutput` now carries an explicit setup-input
    binding hash, and `PublicKeyAssemblyCertificate` retains that binding.
    Release-valid native DKG assembly rejects missing or mismatched bindings.
  - [x] Add negative tests for mismatched `ProductionPower2RoundOutput`
    setup-input bindings at the release-valid assembly boundary.
- [x] Make `NativeDkgSession::finish` validate the full release context or
  expose a single release-finalization helper that composes:
  ```text
  ProductionNativeDkgAssemblyOutput
  durable setup log
  cursor log
  coordinator readiness
  PQ transport evidence
  ```
  `ensure_production_native_dkg_output_context_allowed_for_release` already
  exists, but Phase 5 is not complete until the normal user-facing finish path
  makes this hard to skip.
  `NativeDkgSession::finish_release_validated` now provides this composed
  release boundary.
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
- [x] Strengthen all-suite tests so the release-valid path uses durable
  app-driven Power2Round runtime evidence from the actual setup-derived
  `SharedT`, rather than synthetic runtime evidence injected around a local
  helper.
- [x] Make the broad ML-DSA-44 app-driver DKG assembly test satisfy the current
  release gate with durable production vector Power2Round runtime evidence.
  The test now uses the setup-derived `SharedT` to compute the expected `t1`
  coefficients, then passes a `ProductionPower2RoundOutput` certified through
  the app-driven vector runtime evidence boundary into production assembly.
  Remaining work above is stricter setup/input binding, not the missing
  runtime-evidence gate.

Completion gates:

- [ ] Full release-valid native DKG assembly succeeds for ML-DSA-44/65/87 with
  durable setup logs, real production public artifacts, and
  setup-bound Power2Round evidence.
- [x] Release validator accepts exactly one production output path.
- [x] Any scaffold/simulator artifact in DKG output fails validation.
- [ ] Public output contains no scaffold placeholder commitments.
- [ ] A `ProductionPower2RoundOutput` from another setup transcript, sampler
  transcript, or IT-VSS artifact set is rejected.
- [ ] Normal finalization cannot skip durable context validation.

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
  ProductionNativeDkgAssemblyOutput::new, but it currently uses synthetic setup
  hashes and injected runtime evidence. Treat it as a package/release-gate shape
  test, not proof of full setup-bound production DKG execution. The app-driver
  log test runs the full transport-shaped batch path for ML-DSA-44 and now
  passes the production assembly gate with durable vector Power2Round runtime
  evidence. It still derives expected `t1` from a setup-derived local reference
  and then certifies the opened `t1` through the app-driven vector runtime; the
  remaining Phase 5 task is to bind that runtime certificate directly to the
  setup transcript and `SharedT` input origin.
```

### Phase 6: Finish Production Preprocessing Tokens

Goal: fill a durable pool of BCC-certified tokens without trusted dealer
material or post-challenge leakage.

Status: **partially complete for the current release path, pending
automatic production token material generation, all-suite/performance closure,
and external review**. The production-facing
session/API shape, token-inventory lifecycle, counters, duplicate-session
protection, no local aggregate `A*y` witness rule, and BCC-token admission
surface exist. Release-capable token construction now drives masked-broadcast
relation certification, CarryCompare, CEF correction, and BCC admission through
`ProductionVectorPrimeFieldMpcRuntime` and attaches durable
`PreprocessingVectorRuntimeCertificate` evidence to the actual `CertifiedToken`
output. Legacy hash-only masked-broadcast proof stubs are rejected, and
release evidence must prove the statement-bound preprocessing phases and
private vector circuits ran for the concrete token session/transcript.
Remaining Phase 6 work is no longer a missing certification backend, missing
strict-mask release boundary, caller-supplied `[w]` handle, or coarse
file-backed release-preprocessing cursor. It is all-suite throughput/performance
gates, larger adversarial coverage, final multi-party runtime scheduling, and
review-driven hardening.
There is now a normal-build
`ProductionPreprocessingCertificationRuntime` adapter over
`ProductionVectorPrimeFieldMpcRuntime`; it refuses non-release vector runtime
evidence and derives typed preprocessing stage proof transcripts from the
durable runtime evidence. This closes the ad hoc proof-construction API
surface. The adapter also has an app-driven
`StrictSigningCanonicalMaskGenerationState` for z/hint canonical masks: it
drives random-bit contribution collection, private XOR folding across dealers,
mask-value derivation, private `mask < q` comparison, and a public threshold
assertion. Release-capable token construction now rejects callers that only
attach preprocessing runtime evidence without strict-signing runtime material.
A product-shaped constructor exists for callers that have already driven the
private preprocessing state, strict-mask state, and distributed nonce share:
`certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share`.
It derives the token `[w] = [A*y]` handle from the private distributed
nonce/runtime `[y]` handle, then binds runtime-generated strict masks and `[w]`
into the same `PreprocessingVectorRuntimeCertificate`. The older
opened-material `[w]` adapter is test/scaffold-only and is not exported by the
normal production API.
The release-check suite now also exercises full ML-DSA-44/65/87 token shapes
through this runtime-generated strict-material path.

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
- [x] Make masked-broadcast consistency proof bytes opaque in the normal API.
  Callers can inspect proof bytes for wire transport, but cannot fabricate
  them through public struct fields.
- [x] Replace legacy opaque/hash-only masked-broadcast proof bytes with a typed
  runtime-transcript-bound proof envelope:
  ```text
  proof domain
  statement hash
  runtime transcript binding
  coefficient lane count
  signer count
  ```
  The verifier rejects the old `TMBCC1` hash-only proof shape. The stronger
  backend now also drives a private vector relation proof
  `sum(masked_broadcast_relation_violations) <= 0` under the
  `PreprocessingMaskedBroadcast` phase before token certification can finish.
- [x] Remove local aggregate `A*y` witness dependence from production CEF/BCC
  token admission. The distributed nonce adapter no longer fills
  `ay_contribution`, and CEF/BCC certification uses opened masked-broadcast
  high/low material plus certified mask/carry data.
- [x] Certify the artifact shape for:
  ```text
  masked-broadcast consistency
  CarryCompare kappa bits
  CEF delta correction bits
  w1
  BCC admission
  ```
- [x] Move the remaining certification from local/hash-shaped helpers to
  `ProductionVectorPrimeFieldMpcRuntime` handles:
  ```text
  masked-broadcast relation-violation handles -> done; release certification
    now requires a preprocessing-tagged vector threshold proof
    sum(violations) <= 0 before masked-broadcast output can finish
  CarryCompare rho-sum bit handles -> done for the runtime-private state
    boundary
  CarryCompare runtime output -> boundary added; release certification now
    requires a completed runtime-owned CarryCompare output stored by
    `finish_and_attach_private_circuit_state_for_statement`
  CEF correction lanes -> done for the runtime-private state boundary and
    driven through a separate preprocessing CEF threshold circuit; correction
    bits are bound into private material hashes and are not mixed into the BCC
    `sum(violation_bits) <= 0` admission gate
  BCC violation-bit handles -> done for the runtime-private state boundary;
    full private BCC predicate/certificate output boundary added
  masked-broadcast runtime output -> done; release certification now
    requires a runtime-owned masked-broadcast output with signer count,
    coefficient count, aggregate masked-broadcast runtime transcript, and
    runtime-private material-state hash, and the output cannot be finished
    unless the runtime-owned relation proof is complete
  CEF/BCC runtime output + token-admission bit -> boundary added; release
    certification now requires a completed runtime-owned CEF/BCC output with
    `token_admitted = true`
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

- [x] Token cannot enter a release-validated strict pool unless BCC-certified by
  durable production vector runtime evidence attached to the token.
- [x] No preprocessing release path needs local aggregate nonce witnesses.
- [x] Failed BCC is pre-challenge and reveals no nonce material, low bits,
  boundary distances, masks, or failure positions.
- [x] Token pool/inventory rejects reuse; file-backed session and counter logs
  survive restart and reject corrupt logs.
- [x] `CertifiedToken` release validation rejects missing
  `PreprocessingVectorRuntimeCertificate`.
- [x] `CertifiedToken` release validation rejects detached runtime evidence
  whose certificate binding was produced for a different token.
- [x] `CertifiedToken` release validation requires the attached runtime
  certificate transcript hash to match the aggregate preprocessing runtime
  transcript recorded in the token evidence:
  ```text
  masked-broadcast proof transcript
  CarryCompare runtime transcript
  CEF/BCC runtime transcript
  ```
- [x] `CertifiedToken` release validation rejects runtime evidence whose vector
  counters are too small for the token's signer/coefficient lanes.
- [x] Add a release-oriented token certification entry point that consumes
  app/runtime-produced masked-broadcast envelopes plus durable runtime
  evidence:
  ```text
  certify_preprocessing_token_release_validated_with_runtime
  ```
  This is the entry point the final private vector IT-MPC preprocessing runtime
  should use once it produces the masked-broadcast / CarryCompare / CEF / BCC
  transcripts directly.
- [x] Require the release-oriented envelope entry point to consume an explicit
  preprocessing runtime transcript/proof bundle:
  ```text
  masked-broadcast aggregate runtime transcript
  typed CarryCompare stage runtime proof
  typed CEF/BCC stage runtime proof
  ```
  It rejects a bundle whose masked-broadcast aggregate does not match the
  typed envelope proofs, rejects tampered CarryCompare/BCC stage proof bytes,
  and release runtime evidence must hash the full decoded transcript bundle.
- [x] Add the production-facing preprocessing certification runtime boundary:
  ```text
  PreprocessingCertificationRuntime::certify_preprocessing
  PreprocessingCertificationRuntimeStatement
  certify_preprocessing_token_release_validated_with_runtime
  ```
  This boundary hands the runtime the recomputed public statement for
  CarryCompare/BCC proof production and rejects runtime proofs that bind to a
  different stage statement.
- [x] Add the normal-build adapter that binds preprocessing runtime proof
  production to the app-driven vector IT-MPC runtime:
  ```text
  ProductionPreprocessingCertificationRuntime
  ProductionVectorPrimeFieldMpcRuntime
  ```
  The adapter requires `ensure_release_ready()` on the durable runtime
  evidence, derives CarryCompare and CEF/BCC proof transcript hashes from the
  runtime wire transcript, and returns aggregate preprocessing runtime
  evidence. Remaining work: the underlying private preprocessing circuits must
  still execute through this runtime before the adapter is called.
- [x] Add runtime-adapter phase drivers for the preprocessing statement:
  ```text
  ProductionPreprocessingCertificationRuntime::drive_statement_phases
  ProductionPreprocessingCertificationRuntime::collect_statement_phases
  ```
  These methods emit/collect the durable preprocessing phase markers for
  masked-broadcast consistency, CarryCompare, and CEF/BCC under labels bound to
  the preprocessing session and transcript. They are phase integration points;
  the private arithmetic inside those phases is still the remaining Phase 6
  cryptographic implementation.
- [x] Require statement-specific preprocessing phase cursors before the normal
  runtime adapter can certify. `ProductionPreprocessingCertificationRuntime`
  now rejects generic release-ready runtime evidence unless the cursor log
  contains collected `PreprocessingMaskedBroadcast`, `PreprocessingCarryCompare`,
  and `PreprocessingCefBcc` phases under the exact statement labels. This still
  does not finish the private CEF/BCC circuit, but it prevents unrelated runtime
  evidence from being reused for a different preprocessing statement.
- [x] Require the durable wire log to contain the exact preprocessing statement
  marker vectors before the normal runtime adapter can certify. Phase cursors
  prove the round reached `Collected`; the wire-marker gate additionally proves
  every expected sender committed the statement-bound marker lanes for:
  ```text
  PreprocessingMaskedBroadcast
  PreprocessingCarryCompare
  PreprocessingCefBcc
  ```
  This rejects unrelated or forged phase values even if a cursor with the
  correct label exists. It is still a statement-binding hardening layer, not
  the final private CarryCompare/CEF/BCC circuit.
- [x] Require private preprocessing circuit layers in the durable vector runtime
  log before the normal runtime adapter can certify. Marker broadcasts alone now
  fail the release gate unless the same durable runtime transcript also contains
  vector multiplication/degree-reduction layers for:
  ```text
  PreprocessingCarryCompare
  PreprocessingCefBcc
  ```
  The gate is statement-label specific: CarryCompare layers must sit under
  `carry_compare_private/rho_gt_t`, and CEF/BCC threshold layers must sit under
  `cef_bcc_private/bcc_sum_leq`. Tests drive the existing private vector
  comparison and bit-sum threshold circuits through those preprocessing labels
  and prove marker-only or unrelated private layers are rejected. Remaining
  work is to feed these circuits with the real masked-broadcast/rho/low-bit/BCC
  predicate handles from preprocessing, instead of test-constructed secret
  bits.
- [x] Bind the preprocessing runtime statement and stage proof transcripts to
  those private circuit root labels. The statement now carries the expected
  CarryCompare and CEF/BCC private-circuit label hashes, certification rejects
  mutated label roots, and stage transcript hashes change if the private
  circuit roots change. This prevents a valid public evidence hash from being
  certified under the wrong private circuit entry point.
- [x] Bind preprocessing runtime statements to the public side of the real
  private circuit inputs:
  ```text
  CarryCompare public input hash:
    signer set
    coefficient count
    alpha
    public masked-low sums
    public t = masked_low_sum mod alpha

  CEF/BCC public input hash:
    signer set
    coefficient count
    alpha / high modulus / gamma2
    public masked-high sums
    public masked-low sums
    public t values
  ```
  These hashes intentionally exclude private rho/mask values. Stage transcript
  hashes and marker lanes now bind to these public-input hashes, so the private
  circuit cannot be certified against a different public masked-broadcast
  aggregate.
- [x] Add a typed private preprocessing circuit input boundary:
  ```text
  PreprocessingPrivateCircuitHandles
  ```
  The normal public boundary carries runtime-owned private bit handles, not
  caller-supplied proof hashes. It carries no public secret rho/mask values, and
  the wrapped handle debug output redacts local lanes. Internally the adapter
  derives `PreprocessingPrivateCircuitInputs` after it has recomputed the
  statement, binding handle graph hashes to the statement's coefficient count,
  public circuit input hashes, and private circuit label roots. The production
  preprocessing runtime adapter now requires this handle bundle before it can
  certify and rejects mismatched statement hashes.
- [x] Remove public arbitrary private-hash construction for
  preprocessing private circuit bindings. `PreprocessingPrivateCircuitInputs`
  is now an internal binding object, not a crate-root/normal API export. Normal
  callers pass `PreprocessingPrivateCircuitHandles`, and the adapter derives
  the internal handle graph hash from transcript-bound handle IDs, lane counts,
  holders, and interpolation points. Tests prove empty and short/wrong-lane
  runtime handles reject.
- [x] Add a runtime-owned preprocessing private-circuit driver:
  ```text
  PreprocessingPrivateCircuitDriverState
  ProductionPreprocessingCertificationRuntime::start_private_circuit_handles
  ProductionPreprocessingCertificationRuntime::drive_private_circuit_handles_step
  ProductionPreprocessingCertificationRuntime::collect_private_circuit_handles_step
  ProductionPreprocessingCertificationRuntime::finish_private_circuit_handles
  ```
  The driver runs the preprocessing-tagged masked-broadcast relation threshold
  circuit, CarryCompare comparison circuit, CEF correction threshold circuit,
  and BCC threshold circuit through `ProductionVectorPrimeFieldMpcRuntime`,
  then finishes into `PreprocessingPrivateCircuitHandles`. Focused tests prove
  the driver starts only from statement-sized runtime bit handles and cannot
  finish before the runtime-owned circuits are complete.
- [x] Add a preprocessing-material start path for those private circuits:
  ```text
  ProductionPreprocessingCertificationRuntime::
    start_private_circuit_handles_from_preprocessing_material
  ```
  This path derives CarryCompare public thresholds from the opened
  masked-broadcast low sums and fixes CEF/BCC admission to
  `sum(private_bcc_violation_bits) <= 0`; callers no longer choose these public
  thresholds. It also verifies that the opened broadcast material matches the
  statement public-input hashes before starting the runtime circuits.
- [x] Require exact statement-derived labels for preprocessing private material
  handles:
  ```text
  PreprocessingPrivateMaterialHandles
  masked_broadcast_private/relation_violation_bits/party_i
  carry_compare_private/rho_sum_bits/bit_i
  cef_bcc_private/bcc_violation_bits/violation
  ```
  The raw threshold-based circuit start is now internal to the adapter. Normal
  callers pass one typed material bundle, not loose rho/BCC slices, and the
  bundle has no public constructor. The temporary adapter bridge
  `private_material_handles_from_runtime_bits` is cfg(test)/`scaffold-dev` only
  and is rejected with `production-release-checks`; it validates wrong labels,
  wrong lane counts, wrong rho bit widths, and any BCC input shape other than
  one violation-bit vector over all coefficients.
- [x] Add a normal-build adapter-owned preprocessing material derivation path:
  ```text
  PreprocessingPrivateMaterialState
  ProductionPreprocessingCertificationRuntime::
    derive_private_material_state_from_opened_preprocessing
  ProductionPreprocessingCertificationRuntime::
    derive_private_material_handles_from_opened_preprocessing
  ProductionPreprocessingCertificationRuntime::
    start_private_circuit_handles_from_envelopes
  ProductionPreprocessingCertificationRuntime::
    start_private_circuit_handles_from_state
  ProductionPreprocessingCertificationRuntime::
    finish_and_attach_private_circuit_state
  ```
  The adapter now recomputes the statement public-input hashes from opened
  masked broadcasts, derives statement-labeled masked-broadcast relation
  violation bits,
  rho-sum bit handles, and BCC violation-bit handles internally, wraps them in
  `PreprocessingPrivateMaterialState` with source `RuntimePrivateMpc`, and
  feeds that state into the same private circuit driver. Normal production code
  can start private preprocessing circuits directly from release envelopes,
  drive/collect the app-transport rounds, finish the state-owned driver, attach
  its completed handles to the runtime adapter, and then call the release token
  constructor.
  It no longer needs the scaffold bridge that accepts caller-provided runtime
  bit handles. Raw handle attachment and the builder-like
  `with_private_circuit_handles` hook are cfg(test)/`scaffold-dev` only.
  The state now records its source as either `OpenedMaterialDerived` or
  `RuntimePrivateMpc`; `production-release-checks` rejects the transitional
  `OpenedMaterialDerived` source before private circuit start and accepts only
  `RuntimePrivateMpc`. `start_private_circuit_handles_from_envelopes` now uses
  the adapter-owned `RuntimePrivateMpc` material source; the explicit
  `derive_private_material_state_from_opened_preprocessing` helper remains only
  as a transitional normal-build helper and cannot satisfy release-check builds.
  The final
  `derive_private_material_state_from_runtime_private_mpc` boundary now
  consumes statement-labeled runtime MPC handles for masked-broadcast
  relation-violation bits, CarryCompare rho-sum bits, CEF correction bits, and
  BCC violation bits, hashes the private source handles into the state, redacts
  private lanes, and feeds the same private circuit driver. Masked-broadcast relation
  handles are now generated by
  `start_preprocessing_masked_broadcast_consistency_vec`, which verifies the
  opened broadcasts against the statement's per-signer runtime bindings and
  emits statement-labeled private violation handles. The raw runtime-private state
  input constructor/type is no longer exported from the normal crate API;
  release callers use the adapter-owned helper that generates relation handles
  internally. CarryCompare rho-sum bit handles are now generated by
  `start_preprocessing_carry_compare_rho_sum_bits_vec`, which derives the
  secret bit lanes from statement-bound opened broadcasts and emits exactly
  labeled `carry_compare_private/rho_sum_bits/bit_i` handles. CEF correction
  handles are now generated by `start_preprocessing_cef_correction_bits_vec`,
  which derives statement-bound `delta` lanes and drives them through a
  separate runtime threshold coverage circuit under
  `cef_bcc_private/cef_correction_sum_leq`. BCC violation handles are now
  generated by `start_preprocessing_bcc_violation_bits_vec`, which derives the
  boundary predicate lanes from statement-bound opened broadcasts and emits the exact
  `cef_bcc_private/bcc_violation_bits/violation` handle. Normal release callers
  no longer supply any private preprocessing material handles. Masked-broadcast
  runtime output is now a distinct boundary:
  `finish_runtime_masked_broadcast_output` requires statement-bound
  runtime-private material state, validates every masked-broadcast proof
  binding, and refuses unfinished masked-broadcast relation threshold state;
  `certify_preprocessing` rejects adapters that have not stored that output.
  CarryCompare runtime output
  is also a distinct boundary:
  `finish_runtime_carry_compare_output` requires a completed runtime-owned
  comparison state and durable vector runtime transcript, and
  `certify_preprocessing` rejects adapters that have not stored that output.
  CEF/BCC runtime output is also distinct now:
  `finish_runtime_cef_bcc_output` requires a completed runtime-owned threshold
  state, binds `w1_hash`, `bcc_evidence_hash`, the CarryCompare evidence hash,
  and `token_admitted = true`, and `certify_preprocessing` rejects adapters
  that have not stored that output via
  `finish_and_attach_private_circuit_state_for_statement`.
- [x] Narrow the normal release-token API to the crate-owned production runtime
  adapter. `certify_preprocessing_token_release_validated_with_runtime` no
  longer accepts arbitrary downstream `PreprocessingCertificationRuntime`
  implementations, and the trait is no longer re-exported from the normal crate
  API. Tests that need malformed proof bundles use internal helpers only.
- [x] Add a release-token constructor that consumes a finished state-owned
  preprocessing private-circuit driver:
  ```text
  certify_preprocessing_token_release_validated_with_finished_runtime_driver
  ```
  It derives the runtime statement from the durable masked-broadcast envelopes,
  calls `finish_and_attach_private_circuit_state_for_statement`, and only then
  delegates to `certify_preprocessing_token_release_validated_with_runtime`.
  Tests prove an unfinished private runtime driver cannot emit a release-valid
  token.
- [x] Add an all-party runtime-driven preprocessing release test:
  ```text
  distributed nonce generation
    -> nonce-share-derived PartyPreprocessInput values
    -> masked-broadcast envelopes
    -> runtime-owned private material handles
    -> app-driven CarryCompare / CEF-correction / BCC vector circuits
    -> finished runtime driver state
    -> release-valid CertifiedToken for every party
  ```
  The test runs through `ProductionVectorPrimeFieldMpcRuntime` with in-memory
  app transport under `scaffold-dev`, routes runtime messages between all
  parties, and verifies that each party emits the same release-certified token
  public material. This includes the stronger masked-broadcast private
  relation proof before CarryCompare/CEF/BCC and closes the vertical
  token-construction gap for the current driver.
- [x] Add Phase 6 preprocessing hardening tests:
  ```text
  replayed masked broadcast -> reject
  wrong transcript -> reject
  wrong signer set -> reject before envelope creation/certification
  reused nonce/token id -> inventory transition rejects
  crash/restart before and after release token certification -> file inventory
    stays fresh/reserved/consumed and blocks reuse
  forged CEF-correction runtime output -> reject
  forged BCC admission output -> reject
  forged runtime-owned masked-broadcast / CarryCompare / CEF-BCC outputs
    -> reject
  ```
  The masked-broadcast proof backend now uses runtime-owned relation
  violation handles plus a preprocessing-tagged vector threshold proof, so the
  previous statement/hash-only proof gap is closed for the release path.
- [x] Add explicit runtime-owned preprocessing output objects:
  ```text
  RuntimeCarryCompareOutput
  RuntimeCefBccOutput
  PreprocessingCertificationRuntimeOutputs
  ```
  Stage proofs now carry the runtime's claimed masked-broadcast output,
  CarryCompare evidence hash, CEF/BCC evidence hash, `w1` output hash, runtime
  transcript hashes, and token admission bit. Release token certification
  rejects forged runtime-owned outputs even when the stage proof envelopes
  themselves decode. Tests cover forged masked-broadcast output, forged
  CarryCompare output, forged CEF/BCC `w1` output, mismatched runtime
  transcript hash, and a runtime output that does not admit the token.
- [x] Remove lower-level release constructors that attach runtime evidence or
  typed proof bytes directly from the normal public API. They remain internal
  verifier helpers for tests and for the runtime-owned constructor, but normal
  callers see the production boundary:
  ```text
  certify_preprocessing_token_release_validated_with_runtime
  ```
- [x] Remove the normal-build `PreprocessingSession::finish_release_validated`
  shortcut. App-driven preprocessing sessions can finish local pre-challenge
  certification, but release-capable token construction must go through
  `certify_preprocessing_token_release_validated_with_runtime`, which consumes
  runtime proof handles and durable vector runtime evidence.
- [x] Keep the low-level typed stage-proof constructor internal to the crate.
  Normal callers can pass a preprocessing certification runtime boundary, but
  they do not get a public helper for assembling CarryCompare/BCC proof bytes
  directly.
- [x] Make preprocessing runtime proof handles opaque in the normal API. The
  stage proof bytes and the CarryCompare/BCC proof bundle fields are
  read-only, constructor-less public handles; normal callers cannot fabricate
  release-capable proof bytes by filling public struct fields.
- [x] Make preprocessing runtime certificates opaque in the normal API. Runtime
  evidence and token-binding hashes are exposed through read-only accessors,
  not public mutable fields.
- [x] Bind preprocessing runtime certificates to the complete durable runtime
  evidence surface, not just the transcript hash and a few lane counters:
  ```text
  all runtime counters
  all vector-operation coverage bits
  preprocessing-specific coverage bits
  preprocessing stage transcript hashes
  token counters and public evidence hashes
  ```
  Mutating runtime counters or coverage after certificate creation invalidates
  token release validation.
- [x] Make `production-release-checks` treat release validity as the token
  certification condition. In release-check builds, `CertifiedToken::is_certified`
  now requires `ensure_certified_token_release_valid`, so a token with a
  detached or mismatched runtime certificate cannot enter even the generic
  certified-token pool path.
- [x] Strengthen preprocessing runtime counter coverage so release validation
  distinguishes:
  ```text
  masked-broadcast lanes = signer_count * coeff_count
  certification lanes = CarryCompare + CEF correction + BCC
  ```
  Runtime evidence must contain enough vector opening lanes for masked
  broadcasts and enough vector mul/assert/random/local-public lanes for the
  certification stages.
- [x] Add preprocessing-specific durable runtime phase markers:
  ```text
  PreprocessingMaskedBroadcast
  PreprocessingCarryCompare
  PreprocessingCefBcc
  ```
  Runtime evidence now carries explicit coverage bits for these phases, and
  tests prove the app-driven vector runtime records them without scalar
  openings/checks.
- [x] Add a production-shaped masked-broadcast envelope constructor that binds
  an externally produced runtime transcript hash:
  ```text
  prepare_masked_broadcast_envelope_with_runtime_transcript
  ```
  This helper is now crate-private. It remains an internal verifier/test
  primitive, but normal callers cannot build production envelopes by supplying
  arbitrary transcript hashes.
- [x] Add a runtime-evidence-owned masked-broadcast envelope constructor and
  release binding check:
  ```text
  prepare_masked_broadcast_envelope_with_vector_runtime_evidence
  MaskedBroadcastRuntimeBinding
  ProductionPreprocessingCertificationRuntime validation
  ```
  The production runtime adapter now rejects per-envelope masked-broadcast
  proof transcripts that are not bound to the statement/runtime path and now
  emits private masked-broadcast relation handles from statement/broadcast
  validation. The final release path proves zero relation violations inside
  the vector runtime before token certification can finish.
- [x] Preprocessing counters prove vector/chunk execution for ML-DSA-44/65/87
  token batches.

Phase 6 remaining work after the stronger masked-broadcast backend:

```text
- Broader adversarial tests around malformed relation-bit handles,
  replayed relation circuit labels, and cross-session masked-broadcast
  relation-state reuse are now covered by focused runtime-private state tests.
- Add explicit throughput/latency thresholds for the full all-suite
  preprocessing path. Full-shape ML-DSA-44/65/87 release-token correctness
  coverage exists, but it is not yet a performance gate.
- A typed public release-token batch log scanner now exists for release-valid
  `CertifiedToken` batches. It binds ordered token ids, signer-set hash, public
  `w1` hash, certified `[w]` handle identity, strict mask provenance, runtime
  transcript, token binding, and certificate hash, and a text guard rejects
  private-material markers such as nonce shares, raw masks, rejected `z`, low
  bits, witnesses, and pass/valid bits. `TokenPool` now has a release batch
  admission API that replays this typed log before reserving inventory state,
  so tampered logs leave tokens fresh/unreserved. Strict release signing also
  has a `BccCertifiedTokenBatch::new_release_validated_with_log` constructor
  that rejects forged token-binding/certificate metadata before online use.
  The older `BccCertifiedTokenBatch::new_release_validated` constructor is now
  crate-internal and documented as a lower-level validator used only after log
  replay or by negative tests. The in-memory typed-log constructor is also
  crate-internal now. Public release setup uses the file-backed path. The
  file-backed log has append/read/replay support, rejects truncated/corrupt
  records, duplicate token indexes, and private marker text, and `TokenPool`
  can admit a batch directly from the replayed file log. The strict signing
  release facade exposes `start_release_validated_with_file_log`, which
  constructs the release batch only after replaying that durable file log, and
  release session tests now exercise this file-backed setup path. Remaining
  work is to make the final normal token-batch persistence backend use this
  path everywhere once token batching is promoted beyond integration tests.
- Make the final multi-party preprocessing driver own transport routing and
  token-pool admission across all parties. Per-party runtime scheduling is now
  owned by `PreprocessingReleaseDriver`: after the preprocessing transcript is
  complete it drives private preprocessing circuits, strict mask generation,
  coarse cursor persistence, release-token certification, and optional typed
  token-log append. The in-memory scaffold batch path now starts one
  `PreprocessingSession` per nonce share, routes commit/open, starts one
  release driver per party, routes vector-MPC messages, certifies all tokens,
  and appends one typed token-batch log. Applications still own actual network
  delivery between parties and final token-pool admission policy.
```

- [x] Add direct strict-signing `[w]` derivation from distributed nonce/runtime
  `[y]` handles:
  ```text
  DistributedNonceShare.y_share
    -> runtime weighted nonce share handle [lambda_i * y_i]
    -> public-linear runtime A transform
    -> strict-signing precomputed [w] handle
  ```
  The release-token constructor
  `certify_preprocessing_token_release_validated_with_finished_runtime_driver_strict_material_and_nonce_share`
  now binds this path into the same runtime certificate used by preprocessing
  CarryCompare/CEF/BCC and strict mask material. Tests open the derived handle
  only in test mode to prove it equals `A*y`, reject wrong-label nonce handles,
  reject nonce shares that do not match the committed/opened preprocessing
  transcript, and the all-suite release-token fixture now uses the nonce-share
  path for full-shape tokens. The older opened-preprocessing derivation is
  gated to test/scaffold code and is not part of the normal production release
  token API.
- [x] Promote nonce-share-derived token finalization into the app-facing
  preprocessing session surface:
  ```text
  PreprocessingSession::finish_with_release_runtime(...)
  PreprocessingSession::finish_with_release_runtime_and_cursor_store(...)
  ```
  This consumes the completed preprocessing transcript, a runtime-owned
  private preprocessing driver state, runtime-generated strict mask state, and
  local distributed nonce share, then emits a release-certified token through
  the nonce-derived `[w]` constructor. The focused release-check test proves
  the session facade produces a release-valid token with nonce-derived `[w]`
  and does not require callers to invoke the low-level constructor directly.
- [x] Add release-preprocessing coarse cursor persistence:
  ```text
  PreprocessingReleaseSessionCursorStore
  PreprocessingReleaseSessionCursorMemoryStore
  FilePreprocessingReleaseSessionCursorStore
  ```
  The file log replays strict text records, rejects corrupt/truncated cursor
  lines, and records the final token-binding hash once a release-certified
  token exists. Focused release-check tests prove the session facade persists
  the expected phase progression, file reopen recovers the latest certified
  cursor, cross-session cursor lookup does not replay stale state, and
  premature driver finalization persists an aborted cursor.
- [x] Add a release preprocessing driver:
  ```text
  PreprocessingSession::into_release_driver(...)
  PreprocessingReleaseDriver::drive_runtime_step(...)
  PreprocessingReleaseDriver::collect_runtime_step(...)
  PreprocessingReleaseDriver::finish(...)
  PreprocessingReleaseDriver::finish_and_append_token_log(...)
  ```
  The driver owns private preprocessing runtime scheduling, strict-mask
  generation, coarse cursor updates, release-token certification, and typed
  token-log append for one party. The focused release-check test proves the
  driver emits a release-certified token, advances through transcript/private/
  strict-mask/certified cursors, and writes a replayable public token log.
- [x] Apply the release driver to the in-memory multi-party nonce-share batch
  path:
  ```text
  distributed nonce shares
    -> one PreprocessingSession per signer
    -> routed commit/open transcript
    -> one PreprocessingReleaseDriver per signer
    -> routed vector-MPC runtime rounds
    -> release-certified token batch
    -> single typed release-token batch log
  ```
  The focused two-party scaffold test passes and proves the batch path no
  longer manually calls `start_private_circuit_handles_from_envelopes` or
  strict-mask generation. The strict-mask runtime now packs all 23 random-bit
  vectors for one mask target into one runtime payload, packs XOR-fold layers
  across all mask bits, and runs one combined z/hint canonical `mask < q`
  comparison plus one packed `assert_lt_q` all-ones assertion. This reduced the
  focused debug in-memory two-party test from roughly 93-99 seconds to about
  46-55 seconds. The release-driver test now asserts vector random-bit,
  comparison, and threshold coverage with no scalar fallback. The vector
  runtime also exposes a durable-log phase profile with per-phase record counts,
  private/broadcast split, vector lanes, maximum lanes per wire record, wire
  bytes, and durable log bytes; the release-driver test uses this profile to
  prove strict-mask random-bit phases remain packed, every payload respects the
  suite chunk policy, and the remaining comparison/log hot spots are
  measurable.
  The public-comparison circuit now also avoids a redundant private
  `comparison AND candidate` multiplication: after `candidate = eq AND
  condition`, `comparison` and `candidate` are disjoint by construction, so the
  OR update is a local addition. Focused release-driver gates now cap
  comparison and CarryCompare profile records/labels so these circuits cannot
  silently regress to per-bit scalarized scheduling. A follow-up comparator pass
  then packed `candidate = eq AND condition` and
  `eq_next = eq AND eq_condition` into one multiplication layer per bit; focused
  profile counts dropped from
  `ComparisonToPublicCheck records=68 labels=34` to `records=46 labels=23`,
  and `PreprocessingCarryCompare records=76 labels=38` to `records=38
  labels=19`.
  Prime-field MPC vector wire payloads now use a backward-compatible compact
  lane encoding: canonical Fq lanes are emitted as 24-bit little-endian values
  behind a version marker, while the decoder still accepts the old `i32` vector
  format for replay. On the focused release-driver profile this reduced the
  dominant wire/log byte counts without changing lanes or circuit checks:
  `ComparisonToPublicCheck wire_bytes=773312 -> 581824`,
  `RandomBitShare wire_bytes=518784 -> 389248`,
  `PreprocessingCarryCompare wire_bytes=473024 -> 356288`,
  `PreprocessingCefBcc wire_bytes=87296 -> 65792`, and
  `PreprocessingMaskedBroadcast wire_bytes=49792 -> 37504`. The release-driver
  test now gates the dominant vector phases to ensure their wire bytes remain
  below legacy 4-byte-per-lane encoding.
  Phase-cursor logs now also deduplicate identical consecutive cursor records
  for DKG setup, prime-field MPC/Power2Round, and preprocessing release
  sessions. File-backed cursor replay tests prove duplicate cursor writes are
  compacted without losing restart state or corrupt-log rejection.
  Prime-field MPC wire logs now expose batched persistence for same-layer
  records. File-backed logs write grouped durable records with compact
  same-scope/same-direction prefixes and replay them back into the exact
  canonical per-message records used by release verification. Existing
  per-record replay remains backward-compatible. `talus-wire` also exposes
  default-preserving private-send and reliable-broadcast batch hooks, and
  prime-field MPC restart replay uses those hooks when resending grouped local
  messages. Wider online send-path batching remains a scheduler/transport
  optimization, not a cryptographic change.
  Token-batch sizing is now empirical instead of hard-coded:
  `talus-core::TokenPassProbabilityEstimate` records observed token
  attempts/passes, `ProductionBatchSizingPolicy` derives the recommended strict
  signing batch size for a target no-valid probability, and
  `PreprocessingTokenBatchFillReport` converts preprocessing fill counts into
  that estimate without exposing per-token failures. `BccCertifiedTokenBatch`
  can enforce the resulting decision. `TokenPool` can also take and consume a
  whole certified token batch as one fail-closed operation.
  `PreprocessingReleaseBatchDriver` now owns a set of release preprocessing
  drivers as one scheduler unit: drive active token drivers, route once, collect
  active token drivers, aggregate counters, and emit a public fill report.
  It also has a fused private-runtime scheduler:
  `start_fused_private_runtime`, `drive_fused_private_runtime_step`,
  `collect_fused_private_runtime_step`, and
  `finish_fused_private_and_append_token_log` drive one wider
  CarryCompare/CEF/BCC circuit for the token batch and then emit normal
  per-token release certificates/log entries. This closes ad hoc one-token
  caller orchestration. Strict-signing canonical masks now have a fused
  multi-token generation path:
  `start_strict_signing_canonical_mask_batch_generation` creates one larger
  vector mask/canonicality circuit, and
  `finish_strict_signing_canonical_mask_batch_generation` slices token-bound
  inventories from that one runtime transcript. CarryCompare/CEF/BCC now has a
  fused private runtime primitive:
  `start_private_circuit_batch_from_envelopes` concatenates token statements
  into one wider private relation/CarryCompare/CEF/BCC vector circuit.
  Fused batch private proof state now promotes back into the normal per-token
  release certificate format through
  `certify_preprocessing_token_release_validated_with_fused_private_batch_strict_inventory_and_nonce_share`,
  so token certificates remain token-bound while sharing the fused private
  CarryCompare/CEF/BCC runtime evidence. Remaining work is all-suite
  measurement of pass probabilities and deeper low-level circuit/log
  optimization.
  The remaining work is deeper performance/scheduler optimization of
  comparison/threshold internals, token chunks, and transport/log overhead
  rather than orchestration correctness.
- [x] Harden the batch-driver persistence boundary:
  ```text
  driver token batch
    -> typed file-backed release-token log
    -> log replay
    -> local TokenPool + FileTokenInventory reservation
  ```
  The focused scaffold test now also proves wrong log order, duplicate log
  entries, and tampered certificate hashes fail closed before token-pool
  admission. The positive pool-admission assertion uses the local party token
  and a single-entry durable log because all party-local outputs from one
  preprocessing round intentionally share the same preprocessing session id;
  each production party owns its own local token pool.

Phase 6 implementation note: production parties must not receive
`DistributedNonceGenerationOutput` because that type contains every party's
nonce share and exists only for local integration tests. The production-facing
session returns `DistributedNonceGenerationLocalOutput`.

### Phase 7: Finish Strict Production Signing

Goal: produce only final valid ML-DSA signatures, with no rejected-z leakage.

Status: **partially complete**. The canonical strict no-rejected-z component
stack, token-consumption discipline, selected-opening boundary, FIPS verify
gate, and malicious coordinator tests exist. The remaining production gap is
that the normal strict session still needs a distributed/vector IT-MPC adapter
over `ProductionVectorPrimeFieldMpcRuntime`; local/direct component runtimes
must remain test/dev substrates and must not be the release-capable execution
path.

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
- [x] Add the runtime candidate handle and response-preparation primitive:
  ```text
  [z_j] = [y_j] + c_j * [s1]
  ```
  Code references:
  ```text
  talus-mpc/src/online.rs: StrictRuntimeCandidateHandle
  talus-mpc/src/online.rs: strict_prepare_runtime_z_share
  talus-dkg/src/power2round.rs: ProductionVectorPrimeFieldMpcRuntime::mul_public_challenge_polyvec_share_vec
  ```
- [x] Add generic runtime canonical-bit-decomposition wrapper for arbitrary
  `ProductionShareVec` values, reusing the Power2Round mask/open/recover/check
  pattern instead of a signing-specific duplicate.
  Code references:
  ```text
  talus-dkg/src/power2round.rs: ProductionCanonicalBitDecompositionState
  ```
- [x] Add runtime-owned state objects for strict private checks:
  ```text
  z-bound comparison state
  r = A*z - c*t1*2^d helper
  HighBits(r) vs w1 interval state
  hint-weight <= omega state
  valid-bit combiner
  private priority-selection state
  selected z/h opening helpers
  ```
  Code references:
  ```text
  talus-mpc/src/online.rs: StrictRuntimeZBoundCheckState
  talus-mpc/src/online.rs: strict_runtime_hint_approx_share
  talus-mpc/src/online.rs: StrictRuntimeHintBitsCheckState
  talus-mpc/src/online.rs: StrictRuntimeHintWeightCheckState
  talus-mpc/src/online.rs: StrictRuntimeAllBitsTrueState
  talus-mpc/src/online.rs: StrictRuntimeValidBitState
  talus-mpc/src/online.rs: StrictRuntimePrioritySelectionState
  talus-mpc/src/online.rs: strict_drive_selected_* / strict_collect_selected_*
  talus-mpc/src/online.rs: strict_build_selected_signature_output
  ```
- [x] Add the selected-opening artifact handoff from the distributed runtime
  to strict session finishing. This boundary accepts only selected public
  material plus durable vector-runtime evidence and rejects artifacts whose
  request hash, token ordering, selected priority, or selected challenge seed
  do not match the consumed batch.
  Code references:
  ```text
  talus-mpc/src/online.rs: StrictRuntimeSelectedOpeningArtifact
  talus-mpc/src/online.rs: ProductionStrictRuntimeSelectedOpeningBackend
  talus-mpc/src/online.rs: strict_runtime_selected_opening_backend_accepts_bound_artifact_only
  talus-mpc/src/online.rs: strict_runtime_selected_opening_backend_rejects_unbound_artifacts
  ```
- [x] Tighten the strict-signing release gate so generic/local component-stack
  output cannot satisfy release mode merely by attaching durable runtime
  evidence. Release-valid selected output now requires a
  `StrictSigningVectorRuntimeCertificate` sourced from the selected-opening
  artifact handoff. `StrictSigningSession::start_release_validated` accepts
  only `ProductionStrictRuntimeSelectedOpeningArtifactBackend`, which obtains
  the artifact from an owned `StrictRuntimeSelectedOpeningArtifactSource` after
  token consumption instead of accepting a manually supplied artifact at the
  session boundary.
  Code references:
  ```text
  talus-mpc/src/online.rs: StrictSigningRuntimeCertificateSource
  talus-mpc/src/online.rs: StrictSigningVectorRuntimeCertificate::is_selected_opening_artifact_bound
  talus-mpc/src/online.rs: StrictRuntimeSelectedOpeningArtifactSource
  talus-mpc/src/online.rs: ProductionStrictRuntimeSelectedOpeningArtifactBackend
  talus-mpc/src/online.rs: ProductionStrictVectorMpcArtifactSource
  talus-mpc/src/online.rs: strict_session_release_rejects_generic_runtime_evidence_wrapper
  talus-mpc/src/online.rs: strict_session_release_accepts_selected_opening_artifact_backend
  ```
- [ ] Finish the release-capable distributed adapter that drives those runtime
  states through the app-driven message loop end-to-end. The runtime-owned
  primitives and selected-opening artifact boundary exist, but the normal
  strict release session still needs the orchestrator that produces that
  artifact by sequencing:
  ```text
  canonical z/r decomposition
  z-bound coefficient failure bits
  hint-bit derivation
  fused hint-weight / z-bound / BCC-admission validity threshold
  private priority selection
  selected z/h opening
  final signature encoding
  ```
- [x] Run independent FIPS 204 verification before returning.
- [x] On no-valid or failed final verify, return generic failure and keep all
  participating tokens consumed.
- [x] Under `production-release-checks`, strict signing rejects preprocessing
  batches that lack release-valid `PreprocessingVectorRuntimeCertificate`
  evidence before any token is durably consumed or any private signing backend
  runs. This prevents local/hash-shaped preprocessing tokens from reaching the
  release signing path even if a caller bypasses `new_release_validated`.
- [x] Make strict-signing runtime certificates opaque in the normal API.
  Durable runtime evidence is available through read-only accessors, not public
  mutable fields.
- [x] Add malicious coordinator/session-driver tests:
  ```text
  wrong challenge
  forked signer set
  token reuse attempt
  rejected-z collection attempt
  detailed failure reason request
  replayed strict MPC message
  ```
- [ ] Implement the release-capable distributed adapter from
  `ProductionStrictSigningBackend` components to
  `ProductionVectorPrimeFieldMpcRuntime` handles:
  ```text
  response preparation: primitive done, adapter orchestration open
  z-bound checks: comparison state done, aggregate all-coeff pass-bit orchestration open
  hint/highbits checks: interval state done, full adapter orchestration open
  hint-weight threshold checks: state done, adapter orchestration open
  private valid-bit combination: state done, adapter orchestration open
  private priority selection: state done, adapter orchestration open
  selected opening only: helpers and artifact boundary done, adapter
  orchestration open
  ```
- [x] Add `ProductionStrictSigningVectorMpcRuntimeBackend`, a release-boundary
  adapter that attaches `StrictSigningVectorRuntimeCertificate` only after
  durable Phase 3 vector runtime evidence passes the full release gate. This
  blocks local component-stack output from satisfying release mode without
  runtime evidence, but does not replace the remaining runtime-owned
  response/check/select/open implementation above.
- [x] Make `StrictSigningSession` reject release execution unless selected
  output carries a durable strict-signing vector runtime certificate. The
  session facade can still run direct/local component stacks in dev/test, but
  under `production-release-checks` they fail closed unless wrapped by the
  runtime-evidence adapter.
- [x] Add a narrow `StrictSigningSession::start_release_validated` constructor
  whose backend type is `ProductionStrictSigningVectorMpcRuntimeBackend<_>`, so
  release-oriented callers can enter through a typed runtime-certificate
  boundary instead of the local/direct component stack.
- [x] Attach durable `StrictSigningVectorRuntimeCertificate` evidence to final
  strict-signing selected output when the release adapter is supplied with
  passing vector runtime evidence.

Completion gates:

- [x] No `z_i`, unselected aggregate `z`, candidate hints, validity bits, or
  failure reasons appear in public output, wire messages, durable logs, errors,
  or telemetry.
- [x] Every returned signature passes standard FIPS 204 verification.
- [x] Crash after token consumption cannot restore tokens.
- [x] Release strict signing rejects missing durable preprocessing vector
  runtime evidence before token consumption.
- [x] Release strict signing rejects missing durable strict-signing vector
  runtime certificate on selected output.
- [x] Release strict signing has no reachable local/direct signing backend that
  can return a release-valid signature. Local/direct and generic
  runtime-evidence wrappers may still be constructed in dev/test, but under
  `production-release-checks` they fail unless the selected output is bound
  through `ProductionStrictRuntimeSelectedOpeningBackend`.

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
and the live strict-signing vector runtime path now passes its release-evidence
test, but the full all-lane ML-DSA-65 debug/in-memory unit harness remains far
too slow to represent production performance. Full production performance is not
proven until the remaining release paths consume counters as hard gates and the
end-to-end performance tests run over optimized production-shaped batching.

Optimization reference:

```text
docs/production-optimization-principles.md
```

Current dependency split:

```text
Power2Round:
  migrated to durable app-driven vector runtime evidence; remaining work is
  performance-envelope maintenance and helper cleanup.

Preprocessing:
  blocked on Phase 6 runtime-backed masked-broadcast / CarryCompare / CEF / BCC
  certification before performance can be claimed.

Strict signing:
  correctness/evidence path passes through the live vector runtime, including
  selected-only opening. Performance remains open: the current ignored all-lane
  ML-DSA-65 debug/in-memory harness is too slow and must be replaced by
  phase-batched, precomputed-mask, release-mode performance gates before
  production latency can be claimed.
```

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
- [x] Add strict-signing live-runtime profiling:
  ```text
  per-phase elapsed milliseconds
  per-phase PrimeFieldMpcCounters deltas
  z response prep
  z canonical decomposition
  z-bound checks
  hint canonical decomposition
  hint/highbits checks
  hint weight
  private selection
  selected-only opening
  ```
  The ignored live ML-DSA-65 strict test prints the profile under
  `--nocapture`. Current measured bottlenecks are hint canonical decomposition,
  hint/highbits checks, hint weight, z canonical decomposition, and z-bound
  checks. The detailed snapshot is in
  `docs/production-optimization-principles.md`.

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
- [x] Finish proving/vectorizing Power2Round release execution:
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
  token batches: scheduler, logs, pool consumption, empirical sizing, and
    fused strict-mask generation exist
  coefficient lanes
  signer lanes
  masked-broadcast commit/open vectors
  CarryCompare lanes: fused private runtime primitive exists and promotes into
    per-token release certificates
  CEF correction lanes: fused private runtime primitive exists and promotes into
    per-token release certificates
  BCC admission lanes: fused private runtime primitive exists and promotes into
    per-token release certificates
  durable PreprocessingVectorRuntimeCertificate on each release token
  remaining work: all-suite pass-rate/performance measurement and deeper
    phase batching of comparison/threshold internals
  ```
  Code references:
  ```text
  talus-mpc/src/local.rs: PreprocessingSession
  talus-mpc/src/local.rs: PreprocessingCertificationCounters
  talus-mpc/src/local.rs: DistributedNonceGenerationSession
  talus-mpc/src/local.rs: PreprocessingReleaseBatchDriver
  talus-mpc/src/local.rs: StrictSigningCanonicalMaskBatchMember
  talus-mpc/src/local.rs: PreprocessingPrivateCircuitBatchMember
  talus-mpc/src/local.rs: PreprocessingReleaseBatchDriver::start_fused_private_runtime
  talus-mpc/src/local.rs: PreprocessingReleaseBatchDriver::finish_fused_private_and_append_token_log
  talus-mpc/src/local.rs: certify_preprocessing_token_release_validated_with_fused_private_batch_strict_inventory_and_nonce_share
  ```
- [ ] Finish proving/vectorizing strict signing checks:
  ```text
  candidate-token batch: production metadata exists
  z response lanes: live runtime path exists
  z-bound predicate lanes: live runtime path exists
  hint/highbits lanes: live runtime path exists
  hint-weight lanes: live runtime path exists
  private selection lanes: live runtime path exists and emits PrivateSelectionCheck evidence
  selected opening only: live runtime path exists and opens selected material only
  durable StrictSigningVectorRuntimeCertificate on each release signature: live path passes
  remaining work: phase-batch the live runtime and move eligible masks/material into preprocessing
  ```
  Code references:
  ```text
  talus-mpc/src/online.rs: ProductionStrictSigningBackend
  talus-mpc/src/online.rs: StrictResponseCheckCounters
  talus-mpc/src/online.rs: StrictSigningDistributedRuntime
  talus-mpc/src/online.rs: ProductionStrictLiveVectorMpcArtifactSource
  ```
  Optimization backlog:
  ```text
  [x] profile strict live runtime by phase
  [x] consume optional certified [w] = [A*y] and [As1] = [A*s1] runtime
      handles in the live strict source
  [x] require those [w]/[As1] handles under production-release-checks so
      release-capable strict signing cannot fall back to online A*z
  [x] bind strict z/hint canonical mask inventory into `CertifiedToken` and
      preprocessing runtime certificates; release-capable batches reject tokens
      missing this inventory, anonymous mask inventories, and cross-token mask
      replays
  [x] add strict signing mask inventory ids and in-memory/file-backed
      one-time-use logs; release signing can persist mask consumption before
      private runtime work starts, and reuse after reopen is rejected
  [x] add strict comparison/threshold helper inventory ids and one-time-use
      logs; release tokens now bind helper provenance into the preprocessing
      runtime certificate and typed token-batch log, release admission rejects
      missing or cross-token helper material, and strict signing consumes the
      helper ids before private online response checks start
  [x] add strict selected-opening helper inventory ids and one-time-use logs;
      release tokens now bind selected-opening multiplication-helper
      provenance into the preprocessing runtime certificate and typed
      token-batch log, release admission rejects missing selected-opening
      helper material, and strict signing consumes the helper id before private
      online response checks start
  [~] phase-batch all candidates/chunks
      First live-source passes are implemented: response preparation now
      prepares every candidate before private checks; z and hint canonical
      decomposition are fused into one `[z || r]` decomposition state per
      candidate and that state runs through a shared batch scheduler across
      all candidates. Z-bound and hint interval/highbits comparisons are also
      fused into one packed comparison schedule before their private
      predicates split back into z-bound pass bits and hint bits. Valid-bit
      combination is batched across candidates. Z-bound no longer runs separate lower and
      upper comparison states: it packs `z < gamma` and `z < q-gamma+1` into
      one less-than comparison and derives `z > q-gamma` by private NOT. Hint
      highbits now packs `r < lower+1` and `r < upper` into one less-than
      state, derives `r > lower` by private NOT, and reuses the single
      `gt_lower AND lt_upper` product for both normal and wrap-around
      intervals. The live source now runs z-bound and hint/highbits checks over
      bounded vector chunks, then privately aggregates per-chunk pass bits
      before candidate selection. Hint-weight now computes private chunk
      counts, combines those private count bits, and checks the total against
      `omega` without opening partial counts or chunk failures. Z-bound
      all-true reductions and non-chunked threshold reductions transpose
      candidate vectors into one threshold circuit with candidates as vector
      lanes, rather than one threshold state per candidate. Private priority
      selection packs the selected-bit product and prefix-update product into
      one vector MPC layer per candidate. Selected `z` and selected `h`
      product driving and opening now run over bounded chunks while still
      opening only selected material; both are packed into one
      `selected_z_h_opening_chunks` selected-opening path backed by the
      selected-opening helper inventory. Selected-product computation uses
      affine one-hot selection, `value_0 + sum_{j>0} selected_j *
      (value_j - value_0)`, so a two-token batch multiplies one delta vector
      instead of both candidate vectors. The focused regression
      `strict_selected_share_opening_uses_affine_one_hot_products` proves this
      shape. Selected work shares one selected-products profile stage instead
      of separate z/h product stages, and a focused profile-contract
      regression rejects the old
      split/per-candidate phase names. The release-capable live source now
      enforces this batched scheduler profile under `production-release-checks`
      before returning a selected-opening artifact, so obsolete phase names,
      scalar gates, duplicate/missing batch phases, excess round counts, and
      inflated wire/log byte counts cannot satisfy release checks. Remaining
      work is suite-specific wall-clock/throughput baselines that exercise the
      optimized scheduler without the slow debug all-lane harness.
  [x] optimize fused validity threshold reducer shape with public-zero padding.
      The strict live path now pads the private hint/z-validity threshold with
      deterministic public false bits when that improves the carry-save/ripple
      reducer schedule. This does not change the predicate: z-bound failures
      and hint bits remain private, and only zero-valued public inputs are
      added. The focused regression
      `strict_fused_validity_rejects_z_failure_after_hint_threshold` proves a
      z-bound failure still rejects even when hint weight is valid.
  [x] generate strict z/hint canonical masks inside production preprocessing
      (token storage, provenance binding, certificate binding, replay
      rejection, strict-signing consumption, durable mask-use logs, and the
      app-driven random-bit/XOR/range-certification state machine are done;
      a strict-material release constructor consumes that state; release
      constructors/tests without this material now reject instead of silently
      attaching the test placeholder)
  [x] precompute/store certified secret-shared [w] = [A*y] in each token
      (token storage, certificate binding, strict-signing consumption, and
      release constructor derivation are done; final direct derivation from
      distributed nonce/runtime [y] handles remains a later backend-hardening
      task)
  [x] add full-shape ML-DSA-44/65/87 release-token tests for
      runtime-generated [w], strict masks, and runtime certificate binding
  [x] precompute/store certified secret-shared [As1] = [A*s1] in key state
      (DKG key packages now carry private encoded [As1] K-vector shares;
      release package-set gates recompute [As1] from the retained s1 share and
      rho and reject tampering; strict signing release builds construct
      key-state from the DKG package handle, and the ad hoc from-s1 derivation
      constructor is not compiled under production-release-checks)
  [x] compute online hint relation as [r] = [w] + c*[As1] - c*t1*2^d
      when certified handles are supplied
  [x] avoid redundant online bitness proof for strict-signing derived
      canonical `R_bits`
      Strict signing consumes preprocessing-certified z/hint canonical mask
      bits and derives `R_bits` by checked MPC arithmetic from those masks and
      public masked openings. The online path still proves canonical range and
      equality for z and hint intermediates, but it no longer repeats a
      standalone bitness assertion for the derived bits. Power2Round is not
      changed by this optimization; it remains a standalone circuit with
      state-owned bitness/range/equality checks.
  [ ] avoid online recomputation of token-only BCC/CEF facts without removing
      private z-bound or hint-weight checks
      Production optimization rule: move only message/challenge-independent
      material into preprocessing, require transcript-bound certification and
      one-time-use logs for every helper, and keep challenge-dependent
      z-bound/hint-weight/selection checks online and private unless a
      separate reviewed proof permits otherwise.
  [x] add vector circuit scheduler
  [~] specialize z-bound and hint/highbits circuits where proof-compatible
      (z-bound and hint interval comparisons are packed; remaining work is
      suite-specific wall-clock proof and any future algebraic shortcuts)
  [x] replace per-candidate hint-weight reduction with a packed threshold
      circuit
  [x] replace z-bound all-coefficient pass aggregation with a packed private
      OR tree over violation bits
  [x] fuse z-bound, hint-weight, and BCC-admission validity aggregation
      into one private threshold tree. Z-bound failures and missing BCC
      admission are encoded as `omega + 1` failure units, so one such failure
      invalidates the candidate without separate `z_bound_all_batch` and
      `valid_bit_batch` reductions. The live ML-DSA-65 strict harness now
      reports 94 online rounds instead of the prior 96-round profile.
  [x] batch strict online execution across token candidates. The release live
      harness now runs a two-token batch through one all-candidate canonical
      decomposition state, one all-candidate z-bound/highbits comparison
      state, one fused validity threshold, and packed selected z/h products.
      After selected-opening helper/fusion work, the measured ML-DSA-65 K=2
      profile was 93 online rounds. The affine selected-opening patch reduced
      selected-open multiplication lanes from 11,264 to 5,632 and selected-open
      wire/log bytes from about 52.4KB/105KB to 35.6KB/71KB. The public-zero
      threshold-padding patch then reduced `HintCheck` from 59 to 49 rounds and
      the total K=2 online profile to 83 rounds, proving extra candidates
      mostly widen vectors instead of duplicating the full MPC round schedule.
  [x] replace MSB-to-LSB public comparisons with a log-depth prefix comparator
  [x] replace sequential masked canonical recovery with prefix-borrow
      subtraction for `R = C + q*wrap - A`; the ML-DSA-65 live debug harness
      now reports ZDecomp at 20 rounds instead of the old 133-round profile
  [x] specialize canonical `R < q` with the ML-DSA identity
      `q = 2^23 - 8191`; release runtime checks
      `!(high_10_bits_all_one && low_13_bits_nonzero)` instead of a generic
      23-bit comparator. This reduces ZDecomp vector lanes/wire bytes while
      preserving the 20-round canonical-decomposition schedule.
  [~] specialize gamma1/gamma2 centered interval checks beyond the current
      fused comparator schedule. A first z-bound specialization using the
      power-of-two `gamma1` structure and `q = 2^23 - 8191` complement bounds
      was implemented and measured, but it increased online round count from
      96 to 112. The release path stays on the fused generic-prefix comparator
      until a specialization reduces depth rather than only moving lanes/bytes.
  [ ] do not implement y-margin z-bound shortcuts as production without a
      separate proof/review
  [~] add release-mode ML-DSA-44/65/87 signing performance gates
      (batched scheduler shape and first counter/round/log envelopes are
      release-gated; strict signing now has a full-pipeline benchmark report
      type with per-slot timing, LAN-like RTT estimates, all-suite/3-5-7 party
      matrix coverage, scalar-fallback gates, and an ignored live-runtime
      ML-DSA-65 harness. Remaining work is replacing synthetic matrix fixtures
      with real all-suite release runs and tuning envelopes from those runs.)
  ```
- [ ] Precompute reusable certified material where safe:
  ```text
  Power2Round canonical masks
  strict signing z/hint canonical masks (storage/provenance binding, replay
    rejection, and one-time-use logs done; production random generation still
    open)
  strict signing comparison/threshold helper inventory (token binding,
    file-backed release-log binding, cross-token rejection, and one-time-use
    consumption across restart are done; concrete preprocessed
    triple/helper-handle generation remains a runtime hardening task if
    adopted)
  token-local secret-shared [w] = [A*y]
  key-state secret-shared [As1] = [A*s1]
  preprocessing nonce-mask material
  IT-MPC random bits
  multiplication/checking preprocessing
  ```
  Rule: each precomputed item must be challenge-independent, transcript-bound,
  certified, and consumed exactly once. Do not precompute by publishing exact
  `A*secret` images or by exposing rejected-z material, pass bits, masks,
  witnesses, or failure reasons.
  Each precomputed item must have a durable one-time-use log and a transcript
  binding. Reuse after crash must fail closed.
- [ ] Remove or ignore slow scalar stress tests from default production
  performance runs:
  ```text
  scalar-per-coefficient Power2Round
  scalar-per-coefficient VSS
  paper-compat/test-only signing harnesses
  ```
- [x] Add preprocessing best-shape performance baseline reports for ML-DSA-44
  and suite-scaled reports for ML-DSA-65/87:
  ```text
  measured rounds
  measured messages
  measured bytes
  measured durable bytes
  measured wall-clock time on local in-memory transport
  no scalarized release counters
  ```
  These reports are regression/bottleneck tools, not final product acceptance
  thresholds. The project optimizes for the best known secure execution shape
  first, then uses release-mode data to decide the next bottleneck.
  Strict signing and DKG reports remain open under their phase-specific
  performance tasks.
- [ ] Add regression tests/bench-smoke jobs that fail when a release path
  accidentally loops through scalar transport phases.

Completion gates:

- [ ] DKG round count scales with circuit phases/chunks, not coefficient count.
- [ ] Preprocessing token-batch fill scales with token chunks and vector lanes,
  not individual scalar checks.
- [ ] Strict signing opens only selected signature material and reports vector
  counters for private checks.
- [ ] Release counters prove vector/chunk execution for every production path.
- [x] ML-DSA-44 preprocessing baseline report exists and proves no scalarized
  release profile; later regression gates may be tightened from measured data.
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
  bad masked broadcast [done for replay/wrong transcript/wrong signer set]
  wrong CEF correction [done for forged runtime output]
  BCC failure / forged admission [done for runtime admission false]
  token reuse [done for in-memory and file inventory]
  rollback [partially done: file inventory restart guards token reuse; broader
    preprocessing phase-log rollback remains open]
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
- [ ] Performance counters prove the production path is vectorized/chunked and
  provide regression baselines for future optimization.

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
