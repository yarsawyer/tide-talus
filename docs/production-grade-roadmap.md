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

## Phase 0: Lock The Single Production Profile

Goal: make the single production profile impossible to confuse with test,
development, research, or paper-compatibility profiles.

Tasks:

- [ ] Add an explicit profile/release-policy type:
  ```rust
  enum SigningExecutionProfile {
  StrictPqHmProduction
  TestPaperFastExperimental
  TestLocalSimulation
  }
  ```
- [ ] Add release policy that accepts only `StrictPqHmProduction`.
- [ ] Gate `TestPaperFastExperimental` behind an explicit non-production
  feature or `cfg(test)`.
- [ ] Gate `TestLocalSimulation` and local witness paths under `cfg(test)` or
  `scaffold-dev`.
- [ ] Document in crate-level rustdoc that there is only one production profile.
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

- [ ] Gate `CommitmentBackedPartialVerifier` as test/research only.
- [ ] Gate or remove production visibility of `PolynomialPartialCommitment`
  fields:
  ```text
  ay_commitment
  as1_commitment
  ```
- [ ] Remove `as1_commitments` from release-valid DKG public outputs, or mark
  the field scaffold-only and unavailable to production validators.
- [ ] Add attack tests:
  ```text
  recover x from A*x for ML-DSA-44/65/87 when NTT slices are full rank
  recover s1_i from public A*s1_i in a test fixture
  recover nonce-polynomial coefficients from public A*a_h,k in a test fixture
  ```
- [ ] Add release scanners for:
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

- [ ] Production DKG public output contains no public `A*s1_i`.
- [ ] Production nonce preprocessing contains no public `A*nonce` polynomial
  coefficient.
- [ ] Production online signing contains no public-linear-image blame verifier.
- [ ] Any public exact `A*secret` image in release artifacts fails CI.

## Phase 2: Strict No-Rejected-Z Signing

Goal: rejected `z_i`, aggregate `z`, hints, validity bits, and failure reasons
never become public.

Tasks:

- [ ] Define strict signing API:
  ```rust
  sign_strict_no_rejected_z(...)
  ```
- [ ] Add strict token-batch type:
  ```text
  BccCertifiedTokenBatch
  ```
- [ ] Consume every token in the batch durably before:
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
- [ ] Implement private `z` norm predicate:
  ```text
  |z_j|_infty < gamma1 - beta
  ```
- [ ] Implement private hint computation:
  ```text
  r_j = A*z_j - c_j*t1*2^d
  h_j = HighBits(r_j) != w1_j
  wt(h_j) <= omega
  ```
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
- [ ] Open only selected:
  ```text
  ctilde*
  z*
  h*
  ```
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

Completion gates:

- [ ] Strict production emits no clear `PartialSignature.z_share`.
- [ ] Strict production emits no `talus-wire::PartialSignaturePayload`.
- [ ] Rejected candidates open no `z`, `z_i`, `h`, validity bits, or failure
  reasons.
- [ ] Final public output is either a valid FIPS signature or generic failure.
- [ ] All participating tokens remain consumed after failure or crash.

## Phase 3: Production Nonce Preprocessing

Goal: generate, certify, persist, and consume nonce tokens without trusted
dealer material or post-challenge leakage.

Tasks:

- [ ] Implement production `PreprocessingSession` as the only normal API:
  ```text
  start
  handle_private
  handle_broadcast
  next_outbound
  finish -> CertifiedToken
  ```
- [ ] Generate nonce shares using production IT-VSS/IT-MPC only.
- [ ] Remove release-capable test-provided `y_shares`.
- [ ] Implement token-batch/chunk execution; no scalar-per-coefficient
  preprocessing loops on release paths.
- [ ] Implement masked-broadcast commit/open over app transport.
- [ ] Implement private masked-broadcast consistency certification.
- [ ] Implement vectorized CarryCompare + CEF certification.
- [ ] Decide production default:
  ```text
  strict BCC-certified token pool
  ```
- [ ] Implement private BCC certification or equivalent strict-token admission.
- [ ] If a paper-fast candidate-token path remains, gate it as test/research
  only and mark rejected-z leakage as unproven.
- [ ] Add token persistence:
  ```text
  Fresh -> Reserved -> Consumed -> Erased
  ```
- [ ] Prevent token reuse across crashes and rollback.

Completion gates:

- [ ] Token cannot enter strict pool unless BCC-certified.
- [ ] Failed BCC is pre-challenge and retryable.
- [ ] No nonce material is revealed after challenge.
- [ ] Token pool logs contain no nonce shares, low bits, masks, or rejected
  response material.
- [ ] Preprocessing counters prove messages/rounds scale with token
  batches/chunks and circuit layers, not coefficient count.
- [ ] End-to-end preprocessing can fill a token batch for ML-DSA-44 within the
  agreed performance envelope.

## Phase 4: Production Vector IT-VSS

Goal: implement the selected Rabin-Ben-Or-style VSS backend at production scale.

Tasks:

- [ ] Replace remaining deterministic/hash-binding artifact helpers with the
  final information-checking protocol.
- [ ] Implement vector polynomial sharing for whole `s1`, `s2`, and nonce
  vector batches.
- [ ] Implement salted private-payload commitments.
- [ ] Implement audited/retained IC tags:
  ```text
  audited tags may be opened and discarded
  retained tags remain receiver-private forever
  ```
- [ ] Implement public precommitment -> public coin -> final commitment order.
- [ ] Implement vector polynomial consistency rounds with public coins.
- [ ] Implement conservative abort/no-false-blame policy.
- [ ] Implement chunking and memory limits.
- [ ] Add counters:
  ```text
  rounds
  private messages
  broadcasts
  bytes
  time
  ```
- [ ] Implement persistence/restart for every IT-VSS phase.
- [ ] Add adversarial tests:
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

Completion gates:

- [ ] Production DKG uses batched/vector IT-VSS, not scalar-per-coefficient VSS.
- [ ] Retained receiver tags never appear in public artifacts.
- [ ] Public beta/share-point reveal is unavailable in v1 production.
- [ ] Restart cannot turn incomplete or aborted VSS into accepted sharing.
- [ ] Counters meet agreed scale limits for ML-DSA-44 baseline.

## Phase 5: Production Vector Prime-Field IT-MPC

Goal: provide the production MPC backend used by Power2Round, BCC, response
checks, hint computation, and selection.

Tasks:

- [ ] Implement `ShareVec` and `BitShareVec` as release-capable vector types.
- [ ] Implement batched:
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
- [ ] Use public scalar multiplication as local operation.
- [ ] Add durable logs for opened values and checked openings.
- [ ] Add counters for rounds/messages/bytes/time.
- [ ] Add release gate rejecting scalarized per-coefficient execution.
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

Tasks:

- [ ] Wire production sampler -> production IT-VSS -> production Power2Round.
- [ ] Compute shared:
  ```text
  [t] = A*[s1] + [s2]
  ```
- [ ] Consume and erase `s2`.
- [ ] Run vectorized private Power2Round.
- [ ] Open only `t1`.
- [ ] Produce:
  ```text
  pk = (rho, t1)
  DkgKeyPackage { s1 share only }
  ProductionNativeDkgAssemblyOutput
  ```
- [ ] Remove/gate scaffold wrappers from production assembly.
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

Tasks:

- [ ] Finalize app-facing transport adapter traits for:
  ```text
  authenticated private delivery
  equivocation-resistant broadcast
  ML-KEM session evidence
  ML-DSA identity evidence
  durable message log
  phase cursor log
  token-use log
  mask-use log
  ```
- [ ] Add conformance tests embedders can run against their transport.
- [ ] Add tests for:
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

Tasks:

- [ ] Normal-build public API scan.
- [ ] Forbidden field scan:
  ```text
  s2
  t
  t0
  low bits
  mask witnesses
  retained receiver tags
  private setup payloads
  ```
- [ ] Forbidden exact `A*secret` scan:
  ```text
  A*s1_i
  as1_commitment
  A*nonce
  Phi = A*secret
  CommitmentBackedPartialVerifier
  ```
- [ ] Rejected-`z` leakage scan:
  ```text
  PartialSignature.z_share
  PolynomialPartialSignature.z_share transport
  talus-wire PartialSignaturePayload as production transport
  CandidateTokenPool
  TestPaperFastExperimental
  detailed candidate failure reasons
  ```
- [ ] Feature scan rejecting insecure/dev/test features in release builds.
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
