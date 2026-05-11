# TALUS Production-Grade Roadmap

This is the actionable plan for reaching a production-grade TALUS-MPC system.
It consolidates the release rules from:

```text
docs/no-public-a-secret-linear-images.md
docs/no-rejected-z-leakage.md
docs/it-vss-rabin-ben-or.md
docs/dkg-production-completion-plan.md
docs/dkg-production-performance.md
docs/preprocessing-bcc-performance.md
docs/optimization-principles.md
docs/original-talus-attack-tests.md
docs/no-duplication-architecture-audit.md
```

Production grade means:

```text
- end-to-end post-quantum setup and transport;
- dealerless honest-majority DKG;
- no public exact A-image of secret material;
- no rejected-z leakage;
- no reveal-on-failure after challenge;
- no scaffold/test backends on release paths;
- standard FIPS 204 ML-DSA verification accepts every returned signature.
```

Architecture discipline:

```text
There is one production implementation path per protocol layer. Dev, attack,
and scalar correctness paths are allowed only as tests/dev fixtures and must
not become alternate production APIs.
```

The code-reference audit and cleanup checklist for preventing duplicate
cryptographic implementations is tracked in
`docs/no-duplication-architecture-audit.md`.

## Phase 0: Lock The Single Production Profile

Goal: make the single production profile impossible to confuse with test,
development, research, or paper-compatibility profiles.

Tasks:

- [ ] Add an explicit release-policy type that accepts exactly one production
  value. Test/dev profiles may exist only under test/dev gates and must not be
  selectable by normal users:
  ```rust
  enum SigningExecutionProfile {
      StrictPqHmProduction,
      #[cfg(any(test, feature = "paper-fast-dev"))]
      TestPaperFastExperimental,
      #[cfg(test)]
      TestLocalSimulation,
  }
  ```
- [ ] Add release policy that accepts only `StrictPqHmProduction`.
- [ ] Gate `TestPaperFastExperimental` behind an explicit non-production
  feature or `cfg(test)`.
- [ ] Gate `TestLocalSimulation` and local witness paths under `cfg(test)` or
  `scaffold-dev`.
- [ ] Document in crate-level rustdoc that there is only one production profile.
- [x] Remove the ambiguous public `talus_mpc::local` preprocessing module.
  Current status: the implementation module is private, normal callers use
  crate-root production exports or `talus_mpc::preprocessing`, and clear-audit
  helpers remain gated under `dev_backends`.
- [ ] Add tests proving the production profile rejects:
  ```text
  clear z_i transport
  candidate tokens
  public A*s1_i verifier
  reveal-on-failure
  scaffold/dev backends
  ```

Completion gates:

- [ ] Normal crate users cannot select a scaffold/test/research profile.
- [ ] Release checks fail if `TestPaperFastExperimental` or
  `TestLocalSimulation` is reachable from production APIs.
- [ ] `cargo doc` normal build presents strict production APIs first.

## Phase 1: Remove Public Exact A-Images

Goal: no release path publishes or depends on exact `A*secret` values.

Tasks:

- [x] Gate `CommitmentBackedPartialVerifier` as test/research only.
- [x] Gate or remove production visibility of `PolynomialPartialCommitment`
  fields:
  ```text
  ay_commitment
  as1_commitment
  ```
  Current status: these paper-compatible online symbols compile only under
  `cfg(test)` or the explicit non-default `paper-fast-dev` feature.
- [x] Remove `as1_commitments` from release-valid DKG public outputs, or mark
  the field scaffold-only and unavailable to production validators.
  Current status: `As1Commitment`, `DkgCommitPayload.as1_commitment`,
  `DkgPublicOutput.as1_commitments`, and `CommitmentSet::As1` are absent from
  the normal `talus-dkg` production structs and transcript code.
- [x] Add attack tests:
  ```text
  recover x from A*x for ML-DSA-44/65/87 when NTT slices are full rank
  recover s1_i from public A*s1_i in a test fixture
  recover nonce-polynomial coefficients from public A*a_h,k in a test fixture
  ```
- [x] Add release scanners for:
  ```text
  A*s1_i
  as1_commitment
  A*nonce
  Phi = A*secret
  CommitmentBackedPartialVerifier
  PublicAs1Share
  ```
- [ ] Add source comments on any remaining occurrence explaining why it is
  test-only or a forbidden paper-compatibility artifact.

Completion gates:

- [x] Production DKG public output contains no public `A*s1_i`.
- [x] Production nonce preprocessing contains no public `A*nonce` polynomial
  coefficient.
  Current status: public `DistributedNonceShare.ay_commitment` and clear
  masked-broadcast audit helpers compile only under `cfg(test)` or
  `paper-fast-dev`; normal preprocessing exposes only nonce hashes, masked
  broadcasts, and private/local witness inputs.
- [ ] Production online signing contains no public-linear-image blame verifier.
- [ ] Any public exact `A*secret` image in release artifacts fails CI.

## Phase 2: Strict No-Rejected-Z Signing

Goal: rejected `z_i`, aggregate `z`, hints, validity bits, and failure reasons
never become public.

Tasks:

- [x] Define strict signing API:
  ```rust
  sign_strict_no_rejected_z(...)
  ```
  Current status: `talus-mpc` exposes `StrictSignRequest`,
  `BccCertifiedTokenBatch`, `ConsumedBccCertifiedTokenBatch`,
  `StrictPrivateSigningBackend`, and `sign_strict_no_rejected_z`. The wrapper
  validates the request against a certified batch, durably consumes every token
  before the backend receives the batch, runs final verification, and exposes
  no clear partial-response API.
- [x] Add strict signing app-driver facade:
  ```rust
  StrictSigningSession::start(...)
  StrictSigningSession::handle_private(...)
  StrictSigningSession::handle_broadcast(...)
  StrictSigningSession::next_outbound(...)
  StrictSigningSession::finish(...)
  ```
  Current status: the facade owns request, certified batch, consumed-token
  store, private backend, verifier, and counters. It accepts and queues only
  the production `StrictSignMpc` wire domain, rejects legacy partial-signature
  traffic and malformed context/sender/receiver bindings, and makes
  success/failure terminal after `finish`.
- [x] Add strict signing phase cursor persistence:
  ```rust
  StrictSigningSessionStore
  StrictSigningSessionCursor
  FileStrictSigningSessionStore
  ```
  Current status: the cursor records deterministic session id, request hash,
  fixed token ids, coarse phase, optional runtime slot, accepted strict MPC
  message hashes, outbound strict MPC message hashes, strict MPC wire
  transcript hash, and selected signature hash after success. Tests cover
  start/finish cursor updates, strict MPC wire routing persistence, and
  file-backed reopen after consumed-token failure. A finished/failed cursor
  blocks starting the same strict signing session again.
- [x] Add strict signing runtime trait and per-slot cursor updates:
  ```rust
  StrictSigningDistributedRuntime
  StrictSigningRuntime
  StrictSigningRuntimeObserver
  StrictSigningRuntimeSlot
  ```
  Current status: `StrictSigningDistributedRuntime` is the app-message runtime
  boundary for slot-driven strict MPC payloads. `StrictSigningSession`
  validates strict MPC wire messages, delegates decoded payloads to the
  runtime, queues runtime-generated outbound messages, persists per-slot phase,
  sender set, outbound count, transcript hash, and completion state, requires
  all expected signers before completion, and rejects duplicate senders, wrong
  phases, incomplete completion, and replay after restart.
  `ProductionStrictSigningBackend`
  implements the local private-computation runtime and reports every runtime
  slot before execution. Tests prove persistence records response preparation,
  response-bound checks, hint checks, private selection, and selected opening.
  The default direct-component session adapter is now
  `DirectStrictSigningComponentRuntime`; it rejects strict MPC wire traffic
  rather than acting as a silent no-op runtime. A session that should process
  distributed strict MPC messages must install an explicit
  `StrictSigningDistributedRuntime`. Source scans reject response-preparation,
  bound-check, hint-check, selection, and selected-opening cryptographic logic
  inside the distributed runtime boundary so that this layer cannot become a
  second strict-signing algorithm.
- [x] Add strict signing production wire domain:
  ```text
  RoundId::StrictSignMpc
  PayloadKind::StrictSignMpc
  StrictSignMpcPayload
  ```
  Current status: `talus-wire` exposes typed strict MPC slots and an opaque
  backend payload. `talus-mpc` maps `StrictSigningRuntimeSlot` to those wire
  slots. Tests prove strict sessions accept only strict MPC messages bound to
  the session id/signing set/suite/sender/receiver, reject malformed or replayed
  messages, queue outbound private/broadcast strict MPC messages, persist
  accepted/outbound wire message hashes, persist completed runtime slots, and
  preserve accepted-message replay protection across cursor-store restart.
- [x] Define strict signing phase driver:
  ```text
  consume tokens -> derive challenges -> compute private responses ->
  private checks -> private selection -> selected opening -> final verify
  ```
  Current status: `StrictSigningPhaseDriver` enforces this order and rejects
  out-of-order openings/checks.
- [x] Define strict private response-check phase driver:
  ```text
  candidate metadata -> shared responses -> response bounds -> hints ->
  private pass bits -> priority selection -> selected opening
  ```
  Current status: `StrictResponseCheckPhaseDriver` enforces the inner circuit
  order and produces the coarse response-check counters recorded in strict
  evidence.
- [x] Define public random-priority candidate selection.
  Current status: `strict_candidate_priority` derives a request/token-bound
  public priority for every candidate. Strict backends use the lowest-priority
  valid candidate rather than the first valid candidate, avoiding first-failure
  leakage from the selected opening.
- [x] Add strict token-batch type:
  ```text
  BccCertifiedTokenBatch
  ```
- [x] Consume every token in the batch durably before:
  ```text
  challenge derivation
  z_i computation
  private response checks
  any response-related network message
  ```
- [ ] Implement crash/restart test:
  ```text
  crash after token consumption, before output -> all tokens remain consumed
  ```
- [ ] Replace clear partial `z_i` transport in the production profile with private IT-MPC
  response computation:
  ```text
  [z_j] = [y_j] + c_j*[s1]
  ```
  Current status: `LocalStrictPolynomialSigningBackend` is available only in
  the dev/test module. It executes the strict batch flow without clear partial
  transport and selects a locally valid final-signature candidate through the
  `StrictPrivateSigningBackend` trait. It is a circuit harness, not the
  production distributed IT-MPC backend. The trait now returns
  `StrictSelectedSignature` with `StrictSigningEvidence`, a public evidence
  envelope limited to token count, coarse response-check counters, selected
  public priority, selected signature hash, and backend transcript hash. The
  strict wrapper rejects evidence whose counters do not match the consumed
  batch shape.
  Current update: `ProductionVectorResponsePreparationBackend` now prepares
  vector responses from provided private polynomial `y` and `s1` shares and
  returns only opaque candidate handles. Candidate handles are consumed and
  returned by each private-check phase, removing the previous hidden shared
  local-state handoff between phase objects. Focused strict-flow tests no
  longer require `LocalStrictPolynomialSigningBackend` for the production trait
  stack.
- [ ] Implement private `z` norm predicate:
  ```text
  |z_j|_infty < gamma1 - beta
  ```
  Current status: `StrictResponseBoundCheckBackend` defines the production
  boundary for this predicate. It returns only public shape evidence; the dev
  implementation keeps per-candidate predicate results inside the gated dev
  module.
  Current update: `ProductionVectorResponseBoundCheckBackend` evaluates this
  predicate over vector candidate handles and stores the result inside opaque
  backend state.
- [ ] Implement private hint computation:
  ```text
  r_j = A*z_j - c_j*t1*2^d
  h_j = HighBits(r_j) != w1_j
  wt(h_j) <= omega
  ```
  Current status: `StrictHintCheckBackend` defines the production boundary for
  private HighBits/hint and hint-weight checks. It returns only public shape
  evidence; the dev implementation keeps per-candidate predicate results
  inside the gated dev module.
  Current update: `ProductionVectorHintCheckBackend` computes `A*z`,
  `A*z - c*t1*2^d`, the TALUS hint, and FIPS signature encoding for each
  candidate while keeping candidate results in opaque backend state.
- [ ] Keep these values secret for unselected candidates:
  ```text
  z_j
  h_j
  z_bound_ok_j
  hint_ok_j
  valid_j
  failure reason
  ```
- [ ] Implement random-priority private selection among valid candidates.
  Current status: `StrictPrivateSelectionBackend` defines the production
  boundary for private pass-bit combination and priority selection. It returns
  only the selected candidate and public selection evidence; unselected pass
  bits stay backend-private.
  Current update: `ProductionVectorPrivateSelectionBackend` selects the
  lowest-priority candidate whose vector bound and hint checks passed, exposing
  only selected-priority evidence.
- [ ] Open only selected:
  ```text
  ctilde*
  z*
  h*
  ```
  Current status: `StrictSelectedOpeningBackend` defines the production
  boundary for selected-only opening. It receives one selected candidate handle
  from the private selector and returns only selected-opening evidence: token
  count, selected priority, and selected signature hash. The local dev backend
  now uses this boundary, and tests prove the opener does not receive or reveal
  unselected candidates.
  Current update: `ProductionVectorSelectedOpeningBackend` opens only the
  selected vector candidate signature bytes. Debug/source-scan tests prove
  unselected candidate internals are not exposed.
- [ ] Replace dev local strict backend with production trait stack.
  Current status: `ProductionStrictSigningBackend` is the normal production
  composition entry point. It wires:
  ```text
  StrictResponsePreparationBackend
  StrictResponseBoundCheckBackend
  StrictHintCheckBackend
  StrictPrivateSelectionBackend
  StrictSelectedOpeningBackend
  ```
  through the strict response-check phase driver and emits
  `StrictSigningEvidence`. The concrete distributed vector IT-MPC
  transport/runtime remains pending, but the production-facing vector backend
  stack is now executable without the dev local strict backend.
- [ ] Return `GenericBatchFailure` with no candidate material if no valid
  candidate exists.
- [ ] Run final FIPS 204 verification before output.
- [ ] Add tests forcing:
  ```text
  z-bound failure
  hint-weight failure
  final verifier failure
  no-valid batch
  malicious coordinator collecting rejected z
  ```
  Current status: tests cover the strict phase order and a local strict backend
  path that signs without clear partial transport.

Completion gates:

- [x] Strict production emits no clear `PartialSignature.z_share`.
- [x] Strict production emits no `talus-wire::PartialSignaturePayload`.
  Current status: `PartialSignature`, `PolynomialPartialSignature`, and
  the clear partial wire payload compile only under `cfg(test)` or the explicit
  non-default `paper-fast-dev` feature, and are reachable through explicit
  `dev_backends` modules rather than the normal crate-root production API.
- [x] All tokens are consumed before private signing backend execution.
- [ ] Rejected candidates open no `z`, `z_i`, `h`, validity bits, or failure
  reasons.
- [ ] Final public output is either a valid FIPS signature or generic failure.
- [ ] All participating tokens remain consumed after failure or crash.

## Phase 3: Production Nonce Preprocessing

Goal: generate, certify, persist, and consume nonce tokens without trusted
dealer material or post-challenge leakage.

Current code status:

- [x] `PreprocessingSession` exists as the production-facing session facade.
  Code: `talus-mpc/src/local.rs:82` (`PreprocessingSessionOptions`) and
  `talus-mpc/src/local.rs:125` (`PreprocessingSession`). It implements:
  ```text
  start
  handle_private
  handle_broadcast
  next_outbound
  finish -> CertifiedToken
  ```
  Current limitation: the implemented preprocessing session is broadcast-only
  for certification messages; `handle_private` rejects private messages because
  nonce generation is not yet app-driven through per-party private delivery.
- [x] Masked-broadcast commit/open exists over typed preprocessing broadcasts.
  Code: `talus-mpc/src/local.rs:1615` (`prepare_masked_broadcast_envelope`)
  and `talus-mpc/src/local.rs:1752` (`open_broadcasts`). It checks transcript
  binding, commitment salt, duplicate parties, and opened masked-vector shape.
- [x] Normal preprocessing no longer exposes public exact `A*nonce`
  commitments. `DistributedNonceShare` at `talus-mpc/src/local.rs:471`
  retains a zeroizing local `y_share` plus nonce/randomness commitments, not a
  public `A*y` verifier image.
- [x] A product verifier boundary exists. Code:
  `talus-mpc/src/local.rs:691` (`MaskedBroadcastConsistencyVerifier`) and
  `talus-mpc/src/local.rs:719`
  (`ProductMaskedBroadcastConsistencyVerifier`).
- [x] Pre-challenge token evidence and policy gates exist. Code:
  `talus-mpc/src/local.rs:825` (`PreChallengeCertificationEvidence`),
  `talus-mpc/src/local.rs:908` (`CertifiedToken`), and
  `talus-mpc/src/local.rs:982` (`TokenPool`). Token-pool admission rejects
  uncertified candidates and duplicate session ids.
- [x] Session-id persistence exists. Code: `talus-mpc/src/local.rs:1088`
  (`FileSessionRegistry`) prevents preprocessing session-id reuse after reopen.
- [x] CEF arithmetic and BCC token admission exist in one vector pass across
  the opened masked broadcasts. Code: `talus-mpc/src/local.rs:1815`
  (`certify_vector_carry_compare_and_cef`). The CEF formula uses the approved
  correction:
  ```text
  w1 = (sum_Htilde + floor(B / alpha) - kappa + delta) mod m
  ```
- [x] Distributed nonce generation core exists. Code:
  `talus-mpc/src/local.rs:513` (`generate_distributed_nonce_shares`) and
  `talus-mpc/src/local.rs:609` (`party_preprocess_input_from_distributed_nonce_share`).
  It returns local nonce shares plus public evidence and feeds the same
  preprocessing input path.

What is still not production-complete:

- [ ] Replace in-process nonce-generation orchestration with an app-driven
  preprocessing nonce session. The current `generate_distributed_nonce_shares`
  hashes local entropy/session/dealer labels and certifies residues locally; it
  is not yet a per-party transport phase using production IT-VSS private
  deliveries.
- [ ] Replace deterministic masked-broadcast consistency certificates with the
  final private certification backend. Current code recomputes and hashes a
  public statement in `talus-mpc/src/local.rs:2020`
  (`production_masked_broadcast_consistency_proof`) and verifies it in
  `talus-mpc/src/local.rs:1784`. That is a production-shaped boundary and a
  useful regression gate, not a final distributed proof.
- [ ] Replace local CEF/BCC witness evidence with production vector IT-MPC
  evidence. `certify_vector_carry_compare_and_cef` currently validates with
  local aggregate witnesses; release must use the vector IT-MPC backend for
  CarryCompare, CEF correction bits, and BCC admission.
- [ ] Add durable token-pool persistence. `TokenPool` is in-memory; strict
  signing has consumed-token persistence, but preprocessing token inventory
  still needs a durable `Fresh -> Reserved -> Consumed -> Erased` store.
- [ ] Implement token-batch/chunk execution for preprocessing. Current token
  certification is vectorized across coefficients/signers for one session, but
  the release target is token-batched or chunked preprocessing with counters.
- [ ] Add all-suite end-to-end tests:
  ```text
  production DKG -> production preprocessing token batch ->
  strict no-rejected-z signing -> standard FIPS verifier
  ```

Do not redo:

- `PreprocessingSession` facade.
- Masked-broadcast commit/open validation.
- CEF `+ delta` formula and boundary tests.
- `CertifiedToken` evidence/policy admission.
- Session-id persistence.
- Removal/gating of public exact `A*nonce` images.

Completion gates:

- [x] Token cannot enter strict pool unless BCC-certified under the current
  certification policy/evidence gate.
- [x] Failed BCC is pre-challenge and retryable in the current certification
  flow.
- [x] Normal preprocessing exposes no public exact `A*nonce` commitment.
- [x] Token admission requires no-post-challenge-reveal policy evidence.
- [ ] No release-capable preprocessing path needs local clear aggregate
  witnesses for masked-broadcast, CEF, CarryCompare, or BCC certification.
- [ ] Nonce generation is app-driven through production IT-VSS/IT-MPC, not
  local orchestration.
- [ ] Token pool logs contain no nonce shares, low bits, masks, or rejected
  response material.
- [ ] Preprocessing counters prove messages/rounds scale with token
  batches/chunks and circuit layers, not coefficient count.
- [ ] End-to-end preprocessing can fill a token batch for ML-DSA-44 within the
  agreed performance envelope.

## Phase 4: Production Vector IT-VSS

Goal: implement the selected Rabin-Ben-Or-style VSS backend at production scale.

Current code status:

- [x] Production vector information-checking backend exists in normal builds.
  Code: `talus-dkg/src/it_vss.rs:1951`
  (`ProductionInformationCheckingVssBackend`). It Shamir-shares vector-domain
  secrets and rejects scalar-per-coefficient labels on the production path.
- [x] Public precommitment and app-broadcast public coin artifacts exist.
  Code: `talus-dkg/src/it_vss.rs:1221`
  (`ProductionItVssPublicPrecommitment`) and
  `talus-dkg/src/it_vss.rs:2510`
  (`production_it_vss_public_coin_share`).
- [x] The backend can consume public coin transcripts before final metadata.
  Code: `talus-dkg/src/it_vss.rs:2000`
  (`with_public_coin_transcripts`) and `talus-dkg/src/it_vss.rs:2302`
  (`finalize_prepared_secret`).
- [x] Audited and retained IC tag material is separated. Code:
  `talus-dkg/src/it_vss.rs:2940` (`ProductionItVssAuditRecord`) and the
  private delivery encodings around `talus-dkg/src/it_vss.rs:2840`.
  Audited tags may be opened/discarded; retained receiver tags remain private.
- [x] Vector polynomial consistency records exist and are bound into metadata.
  Code: `talus-dkg/src/it_vss.rs:2964`
  (`ProductionItVssConsistencyRecord`) and
  `talus-dkg/src/it_vss.rs:3152`
  (`production_it_vss_consistency_records`).
- [x] Release/performance counters exist. Code:
  `talus-dkg/src/it_vss.rs:3235` (`ProductionItVssCounters`) and
  `talus-dkg/src/it_vss.rs:3416`
  (`ensure_production_it_vss_counters_allowed_for_release`).
- [x] Bounded sampler has production-backend vector tests through
  `ProductionInformationCheckingVssBackend`.

What is still not production-complete:

- [ ] Drive public precommitment -> public coin -> final metadata through the
  normal app-facing DKG driver for every production VSS batch, not only through
  backend tests and helper wiring.
- [ ] Finish phase-cursor persistence/restart for every vector IT-VSS phase in
  the normal DKG driver.
- [ ] Add final chunk sizing and memory limits for ML-DSA-44/65/87 vector
  batches.
- [ ] Expand adversarial tests:
  ```text
  wrong retained tag privacy
  malformed vector length
  wrong vector domain
  bad label hash
  duplicate batch private delivery
  wrong receiver in batch
  mixed dealer batches
  aborted session cannot become accepted
  ```
- [ ] Remove or gate remaining scaffold artifact helpers from release-capable
  assembly once the app-driven path is the only normal DKG path.

Completion gates:

- [x] Production backend identity and vector sharing path exist.
- [x] Retained receiver tags never appear in public artifacts in current
  production vector backend tests.
- [ ] Public beta/share-point reveal is unavailable in v1 production.
- [ ] Restart cannot turn incomplete or aborted VSS into accepted sharing.
- [ ] Counters meet agreed scale limits for ML-DSA-44 baseline.

## Phase 5: Production Vector Prime-Field IT-MPC

Goal: provide the production MPC backend used by Power2Round, BCC, response
checks, hint computation, and selection.

Current code status:

- [x] Vector share containers exist. Code: `talus-dkg/src/power2round.rs:391`
  (`ShareVec`) and `talus-dkg/src/power2round.rs:439` (`BitShareVec`).
- [x] Prime-field MPC counters and release checks exist. Code:
  `talus-dkg/src/power2round.rs:487` (`PrimeFieldMpcCounters`) and
  `talus-dkg/src/power2round.rs:531`
  (`ensure_prime_field_mpc_counters_vectorized_for_release`).
- [x] Durable wire-log vectorization checks exist. Code:
  `talus-dkg/src/power2round.rs:1010`
  (`PrimeFieldMpcWireMessageRecord`) and
  `talus-dkg/src/power2round.rs:574`
  (`ensure_prime_field_mpc_wire_log_vectorized_for_release`). The release gate
  rejects scalarized prime-field MPC wire logs.
- [x] Canonical wire payload for DKG prime-field MPC exists. Code:
  `talus-wire/src/lib.rs:425` (`DkgPrimeFieldMpcPayload`).

What is still not production-complete:

- [ ] Finish the app-driven batched runtime for these vector operations:
  ```text
  open_many_checked
  assert_zero
  assert_bit
  random_bit
  multiplication layers
  comparison to public constants
  equality to public constants
  bit sums and threshold checks
  secret one-hot selection
  ```
- [ ] Replace remaining local/simulator substrates behind production-named
  Power2Round/signing/preprocessing paths with the app-driven vector runtime.
- [ ] Use public scalar multiplication as local operation everywhere on the
  release path.
- [ ] Add durable logs for opened values and checked openings in every runtime
  phase that releases public values.
- [ ] Add full round/message/byte/time counters. Current counters prove
  vectorized lanes but do not yet provide the full product performance budget.
- [ ] Add malicious tests:
  ```text
  bad MAC/check openings
  bad bitness
  wrong comparison bit
  wrong selection bit
  replayed vector phase
  duplicate gate label
  insufficient preprocessing
  ```

Completion gates:

- [ ] MPC backend supports Power2Round, private BCC, strict signing response
  checks, and private selection.
- [ ] No scalar-per-coefficient transport path is reachable in production.
- [ ] Failed checks reveal no raw secret-dependent values.
- [ ] Counters meet agreed performance envelope.

## Phase 6: Production DKG Assembly

Goal: derive standard ML-DSA public keys and party key packages without leaking
`s2`, `t`, `t0`, low bits, or exact `A*secret` images.

Current code status:

- [x] User-facing native DKG session exists. Code:
  `talus-dkg/src/lib.rs:6487` (`NativeDkgSession`).
- [x] Production output has a production constructor. Code:
  `talus-dkg/src/lib.rs:4011` (`ProductionNativeDkgAssemblyOutput`) and
  `talus-dkg/src/lib.rs:4020` (`ProductionNativeDkgAssemblyOutput::new`).
  Scaffold conversion is `cfg(test)` only.
- [x] Release gates validate key packages and reject scaffold/simulator/blocker
  artifacts. Code is tracked in the DKG release-gate section of
  `IMPLEMENTATION_PLAN.md`.
- [x] DKG key packages import into the TALUS signing share provider without
  reintroducing `s2`, `t`, or `t0`.
- [x] Power2Round production driver phases exist. Code:
  `talus-dkg/src/power2round.rs:6567`
  (`ProductionPower2RoundDriverPhase`) and
  `talus-dkg/src/power2round.rs:6594`
  (`ProductionPower2RoundPerPartyDriver`).

What is still not production-complete:

- [ ] Wire production sampler -> production IT-VSS -> production Power2Round
  through one normal release path.
- [ ] Compute shared:
  ```text
  [t] = A*[s1] + [s2]
  ```
- [ ] Consume and erase `s2`.
- [ ] Run vectorized private Power2Round through the final production
  app-driven IT-MPC runtime.
- [ ] Open only `t1`.
- [ ] Produce:
  ```text
  pk = (rho, t1)
  DkgKeyPackage { s1 share only }
  ProductionNativeDkgAssemblyOutput
  ```
- [x] Remove/gate scaffold wrappers from production output construction.
- [ ] Remove remaining release-capable scaffold residue/certificate reliance
  from assembly internals.
- [ ] Add all-party agreement tests:
  ```text
  rho
  t1
  public key
  certificate
  accepted set
  ```
- [ ] Add no-secret-output tests:
  ```text
  no s2
  no t
  no t0
  no low bits
  no mask witnesses
  no A*s1_i
  ```

Completion gates:

- [ ] Full DKG succeeds for ML-DSA-44/65/87.
- [ ] Standard ML-DSA verifier accepts signatures under generated public keys.
- [ ] Release validator has exactly one production output path.
- [ ] Any scaffold artifact in release output fails validation.

## Phase 7: Transport And Persistence

Goal: keep sockets outside the crate while enforcing exact app-supplied
transport and durable-state contracts.

Current code status:

- [x] The crate does not implement sockets/TCP/QUIC/libp2p. It owns protocol
  state machines, wire encodings, context validation, and deterministic test
  transports; embedding software supplies the concrete network.
- [x] App-facing transport traits and PQ binding evidence exist in `talus-wire`:
  ```text
  authenticated private delivery
  equivocation-resistant broadcast
  ML-KEM session evidence
  ML-DSA identity evidence
  ```
- [x] Reliable-broadcast contract exists:
  same sender message to all honest observers or equivocation/abort.
- [x] Deterministic conformance tests cover ML-KEM-768 session binding,
  ML-DSA-65 operational identity binding, wrong identity/session/suite,
  duplicate/replayed private messages, incomplete broadcast views, and
  equivocation.

What is still not production-complete:

- [ ] Add embeddable conformance-test harnesses that downstream applications
  can run against their concrete transport adapter.
- [ ] Finish durable stores for:
  ```text
  durable message log
  phase cursor log
  token-use log
  mask-use log
  ```
- [ ] Add full restart/adversarial tests for:
  ```text
  delayed delivery
  reordered delivery
  duplicate delivery
  replay
  equivocation
  restart mid-phase
  corrupted/truncated logs
  rollback attempts
  ```
- [ ] Add durable phase cursors for:
  ```text
  vector IT-VSS
  vector Power2Round
  preprocessing
  strict signing batches
  ```

Completion gates:

- [ ] Production cannot start without matching transport evidence.
- [ ] Restart resumes only from persisted phase cursor and accepted logs.
- [ ] Incomplete/aborted sessions cannot become accepted.
- [ ] Reused token/mask/preprocessing ids fail closed.

## Phase 8: Release Gates And CI

Goal: production-invalid configurations fail automatically.

Current code status:

- [x] Normal-build API/source scans exist for paper-fast and rejected-z
  symbols.
- [x] Release gates reject `paper-fast-dev` with
  `production-release-checks`.
- [x] DKG key-package release gates reject scaffold setup, simulator
  Power2Round, missing setup evidence, explicit blockers, inconsistent public
  material, and package-set disagreement.
- [x] Durable prime-field MPC wire-log release gates reject scalarized logs.
- [x] Production preprocessing source/API scans reject public exact `A*nonce`
  and clear partial verifier artifacts in normal APIs.

Still required:

- [ ] Consolidate release checks so production assembly/signing can only return
  release-valid outputs through one narrow path.
- [ ] Complete forbidden field scans across serialized release outputs:
  ```text
  s2
  t
  t0
  low bits
  mask witnesses
  retained receiver tags
  private setup payloads
  ```
- [x] Forbidden exact `A*secret` scans exist for the known dangerous symbols:
  ```text
  A*s1_i
  as1_commitment
  A*nonce
  Phi = A*secret
  CommitmentBackedPartialVerifier
  ```
- [x] Rejected-`z` leakage scans exist for the normal API surface:
  ```text
  PartialSignature.z_share
  PolynomialPartialSignature.z_share transport
  talus-wire PartialSignaturePayload as production transport
  CandidateTokenPool
  TestPaperFastExperimental
  detailed candidate failure reasons
  ```
- [x] Feature scan rejects insecure paper-fast feature combinations in release
  builds.
- [ ] Extend scans to final preprocessing token-batch logs and final app-driven
  IT-MPC logs once those logs are complete.
- [ ] Performance regression jobs for ML-DSA-44 baseline.
- [ ] CI jobs:
  ```text
  cargo check --workspace
  cargo test
  cargo clippy --workspace --all-targets
  doc tests
  release-gate tests
  API scan
  forbidden payload scan
  performance baseline
  ```

Completion gates:

- [ ] A production-invalid package set cannot pass any release validator.
- [ ] A production-valid package set passes exactly one narrow release path.
- [ ] Any simulator/scaffold/test backend in normal build fails CI.
- [ ] Any public exact `A*secret` image fails CI.
- [ ] Any rejected-`z` leakage path fails CI.

## Phase 9: End-To-End Production Tests

Goal: demonstrate the whole production path.

Tasks:

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
  bad VSS
  bad sampler input
  bad Power2Round share
  equivocation
  replay
  crash/restart
  ```
- [ ] Malicious preprocessing tests:
  ```text
  bad masked broadcast
  bad CarryCompare/CEF witness
  BCC failure
  token reuse
  crash/restart
  ```
- [ ] Malicious signing tests:
  ```text
  bad request
  no valid token batch
  failed private z-bound
  failed private hint weight
  final verify failure
  coordinator tries to collect rejected z
  ```

Completion gates:

- [ ] All suites produce standard-verifiable signatures.
- [ ] No invalid signature is returned.
- [ ] No rejected candidate material is exposed.
- [ ] No public exact `A*secret` appears in logs, artifacts, or public output.
- [ ] Performance counters are within agreed target envelope.

## Phase 10: Cryptographic Review Package

Goal: give reviewers a complete, traceable system.

Tasks:

- [ ] Protocol spec for final vector IT-VSS.
- [ ] Protocol spec for final vector IT-MPC.
- [ ] Protocol spec for private BCC and strict signing.
- [ ] Protocol spec for DKG bounded sampler.
- [ ] Source map from every protocol step to code.
- [ ] Public/private transcript field inventory.
- [ ] Persistence and crash-safety inventory.
- [ ] Zeroization and one-time-material inventory.
- [ ] Security claims and non-claims:
  ```text
  honest majority
  static malicious
  security with abort
  no fairness
  no guaranteed output delivery
  no signature indistinguishability claim unless separately implemented
  ```
- [ ] Test matrix and coverage summary.
- [ ] Performance report.

Completion gates:

- [ ] Reviewer can trace every public artifact to a protocol step.
- [ ] Reviewer can trace every secret value to storage, use, and erasure rules.
- [ ] Every release gate has a documented security reason.
- [ ] Every deviation from the TALUS paper is documented and justified.

## Security Findings Workstream

This section tracks the hardening tasks that came from the external
GPT-5.5-Pro review and our follow-up analysis. These are not optional cleanup
items; they are production blockers.

### Public `A*secret` Finding

Problem:

```text
For ML-DSA shapes with k >= l, public exact A*x is usually invertible in the
NTT/CRT representation. Therefore public A*s1_i, public A*nonce coefficients,
and Feldman-style Phi = A*secret are not hiding.
```

Tasks:

- [x] Remove public `A*s1_i` from release-valid DKG public output.
- [x] Remove public `A*nonce` / `Phi = A*secret` from release-valid
  preprocessing.
- [x] Gate `CommitmentBackedPartialVerifier` and public-linear-image online
  blame as test/research only.
- [x] Add attack tests recovering `x` from `A*x` for ML-DSA-44/65/87 where
  NTT slices are full-rank.
- [x] Add attack tests recovering `s1_i` from public `A*s1_i` and nonce
  polynomial coefficients from public `Phi = A*x`.
- [x] Add release scanners rejecting `A*s1_i`, `as1_commitment`, `A*nonce`,
  `Phi = A*secret`, and `CommitmentBackedPartialVerifier` on release paths.
  Current status: the online public-linear-image verifier is now absent from
  normal builds; DKG `as1_commitment` artifacts were removed from normal
  `talus-dkg` production structs and transcript code; preprocessing no
  longer exposes `DistributedNonceShare.ay_commitment` in the normal local API;
  clear masked-broadcast audit helpers moved to the gated `local_dev` module.
  `talus-tests` now has a cross-crate production-source scan covering the
  production MPC, DKG, wire, and DKG-signing helper boundaries. The workspace
  feature graph no longer pulls
  `paper-fast-dev` into production checks: paper-compatible integration and
  attack harnesses in `talus-tests` require the explicit `paper-fast-dev`
  feature, and `cargo check --workspace --features production-release-checks`
  passes without compiling insecure dev modules.
- [x] Add rejected-`z` leakage scanners for clear partial `z_i` transport,
  paper-fast retry helpers, partial-signature payload codecs, and production
  exports of partial-signature signer/assembler APIs.
- [x] Update public-output and wire-message docs so no exact public
  `A*secret` image appears in production artifacts.
  Current status: DKG wire/internal `as1` docs now mark it scaffold/test-only;
  normal production wire payloads omit the field.
  `talus-mpc` and `talus-wire` also reject
  `production-release-checks + paper-fast-dev` at compile time.

Completion gates:

- [x] Production DKG has no public exact `A*s1_i`.
- [x] Production preprocessing has no public exact `A*nonce`.
- [ ] Production signing has no public-linear-image blame verifier.
- [x] Attack tests demonstrate why the public `A*secret` paper-compatible path
  is forbidden.

### Rejected-`z` Leakage Finding

Problem:

```text
Ordinary ML-DSA destroys rejected z candidates internally. A threshold scheme
must not expose rejected z_i, aggregate z, hints, validity bits, or detailed
failure reasons.
```

Tasks:

- [x] Implement strict signing as the only production signing API boundary.
- [x] Consume token batches durably before challenge/response work.
- [ ] Replace clear partial `z_i` transport with private IT-MPC response
  computation.
- [ ] Privately compute z-bound, hint-weight, and validity predicates.
- [ ] Privately select one valid candidate by random priority.
- [ ] Open only selected `ctilde`, `z`, and `h`.
- [ ] Return only a valid FIPS signature or generic failure.
- [x] Add paper-compatible-path attack tests proving rejected `z` samples can be
  collected if clear partials are used.
- [x] Add strict-signing tests proving rejected `z` samples cannot be collected
  from normal production APIs and wire domains.
- [x] Add release scanners rejecting clear partial `z_i`, candidate-token
  verifier retry, detailed candidate failure reasons, and paper-fast paths.

Completion gates:

- [ ] No rejected candidate material appears in public output, wire messages,
  durable logs, errors, or telemetry.
- [ ] Crash after token consumption cannot reuse tokens.
- [ ] Final verification failure consumes material and releases no signature.

### Reveal-On-Failure Finding

Problem:

```text
After z_i = y_i + c*s1_i exists, revealing enough nonce material to recover y_i
leaks c*s1_i = z_i - y_i.
```

Tasks:

- [x] Require token-admission evidence that post-challenge reveal-on-failure is
  disabled.
- [ ] Disable post-challenge reveal-on-failure in every production API.
- [ ] Keep reveal diagnostics only in offline/pre-challenge or explicit
  test/research forensic paths.
- [ ] Use pre-challenge masked-broadcast consistency, CarryCompare, and BCC
  certification instead of post-challenge nonce reveal.
- [ ] If final verification fails, consume material and return generic failure
  without nonce/session reveal.

Completion gates:

- [ ] No production path reveals honest nonce material after challenge.
- [ ] Forensic reveal paths cannot be reached from normal release APIs.

### Coordinator/Driver Finding

Problem:

```text
The protocol may have a proposal leader/session driver for ergonomics, but no
trusted coordinator. A malicious driver must be unable to choose challenges,
fork transcripts, collect rejected z, force token reuse, or create inconsistent
party views.
```

Tasks:

- [ ] Rename or document coordinator-shaped code as non-trusted session driver
  or app-driver where possible.
- [ ] Ensure every party independently derives/verifies challenge, signer set,
  token state, transcript, and final signature.
- [ ] Add tests for malicious driver behavior:
  ```text
  wrong challenge
  forked signer set
  delayed/replayed messages
  token reuse attempt
  rejected-z collection attempt
  equivocated broadcast
  ```

Completion gates:

- [ ] No production API grants trusted authority to a coordinator.
- [ ] A bad driver can only cause abort/generic failure, not leakage or invalid
  signature output.

### Dependency Boundary Finding

Problem:

```text
TALUS should depend directly on fips204 and ml-kem. Tidecoin consensus-wrapper
compatibility is downstream integration, not a TALUS crate dependency.
```

Tasks:

- [x] Remove `tidecoin-consensus-core` from TALUS dependencies.
- [x] Remove the `tidecoin-local` feature.
- [x] Remove in-crate Tidecoin consensus parity test.
- [x] Use direct `fips204` verification tests in TALUS.
- [ ] Keep any future Tidecoin wrapper parity in downstream integration tests.

Completion gates:

- [x] `cargo tree` shows no Tidecoin crates.
- [x] `cargo check --workspace --all-features` passes without Tidecoin.

## Critical Path

The shortest path to production is:

1. Gate current clear partial/signing and public-linear-image verifier as
   test/research only.
2. Add release scanners for public `A*secret` and rejected-`z` leakage.
3. Finish production vector IT-VSS.
4. Finish production vector prime-field IT-MPC.
5. Finish vectorized private Power2Round and private BCC.
6. Implement strict private batch signing.
7. Wire production DKG -> preprocessing -> strict signing.
8. Run all-suite end-to-end tests.
9. Produce cryptographic review package.
