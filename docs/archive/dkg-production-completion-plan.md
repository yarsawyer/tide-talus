# TALUS Native DKG Production Completion Plan

This document is the production checklist for full native TALUS DKG.

It intentionally separates:

- completed correctness/test scaffolding
- production boundaries that already exist
- missing production implementation work
- completeness gates that must pass before release

The goal is a production-only library API. Test harnesses may exist under
`cfg(test)`, but normal users should not select scaffold or simulator paths.

The complete cross-component roadmap is tracked in
`docs/production-grade-roadmap.md`. This DKG plan remains the DKG-focused view;
the roadmap adds strict online signing, no-rejected-`z` leakage, no public
`A*secret` images, release gates, and review-package tasks.
The production performance shape for preprocessing, CEF, CarryCompare, and BCC
is tracked in `docs/preprocessing-bcc-performance.md`.

## Production Definition

Full production DKG means:

```text
dealerless honest-majority native DKG
post-quantum authenticated transport context
batched/vector Rabin-Ben-Or-style IT-VSS
batched/vector prime-field IT-MPC Power2Round
standard ML-DSA public key pk = (rho, t1)
retained secret material: s1 share only
no s2/t/t0/low-bit/mask witness leakage
no public exact A-image of secret material
durable crash-safe logs and restart cursors
release-valid DkgKeyPackage set
```

Required deployment shape:

```text
n >= 2f + 1
T = f + 1
n >= 2T - 1
```

Security model:

```text
information-theoretic VSS/MPC core with abort
ML-KEM private-channel establishment evidence
ML-DSA operational party identity evidence
equivocation-resistant reliable broadcast evidence
SHAKE/cSHAKE/KMAC/TupleHash transcript binding
```

## Current Status Summary

- [x] Production-only crate direction documented.
- [x] Test/scaffold Power2Round and IT-VSS helpers are named as test helpers and
  gated out of normal builds where they depend on simulator substrate.
- [x] Release gates reject scaffold setup, simulator Power2Round, private setup
  payload leakage, incomplete cursors, and missing transport/readiness evidence.
- [x] Release validation has a narrow typed-output entry point:
  `ProductionNativeDkgAssemblyOutput::ensure_context_allowed_for_release`.
- [x] Batched/vector IT-VSS artifact and app-driver test paths exist.
- [x] Scalar and vector IT-VSS correctness paths exist for tests.
- [x] Scalar private Power2Round circuit logic exists for correctness tests.
- [ ] Full production Rabin-Ben-Or-style IT-VSS backend is implemented.
- [ ] Full production vectorized IT-MPC Power2Round backend is implemented.
- [ ] Production DKG path is fast enough for real use.
- [ ] Production transport conformance is tested against embedding-app
  adapters, not only in-memory transport.
- [ ] End-to-end production DKG generates release-valid packages without
  scaffold artifacts.
- [ ] Release paths contain no public `A*s1_i`, `A*nonce` coefficient, or
  `Phi = A*secret` artifacts.

## Phase 1: Production API Surface

Goal: normal crate users see one production DKG API. Test harnesses remain
available only to tests.

Tasks:

- [x] Remove public `talus-dkg/test-dealer` feature.
- [x] Gate clear/test-dealer helpers under `cfg(test)`.
- [x] Gate in-memory native DKG scaffold coordinator under `cfg(test)`.
- [x] Rename test Power2Round wrappers so they do not start with
  `Production...`.
- [x] Rename incomplete IT-VSS artifact helpers so they do not start with
  `Production...`.
- [x] Add `ProductionNativeDkgAssemblyOutput` as the release-valid output type.
- [x] Move remaining large Power2Round test/scaffold helpers into dedicated
  `testing`/`dev_backends` modules under `cfg(test)`.
- [x] Ensure rustdoc for normal builds does not advertise scaffold coordinator
  paths.
- [ ] Move remaining non-Power2Round setup scaffold helpers into dedicated
  `testing` modules under `cfg(test)` where they are not part of the production
  assembly candidate boundary.
- [ ] Add a CI scan that fails on new normal-build `Scaffold`, `Simulator`,
  `TestHarness`, or `InMemory...Coordinator` exports.

Completeness gate:

- [ ] `cargo doc -p talus-dkg --no-deps` normal build shows production
  boundaries only.
- [ ] Public API scan confirms no simulator/test backend is exported in normal
  builds.
- [ ] Release output can only be represented by `ProductionNativeDkgAssemblyOutput`.

## Phase 2: Fast Batched/Vector IT-VSS

Goal: implement the selected Rabin-Ben-Or-style IT-VSS protocol in a form that
is both production-secure and usable.

Production IT-VSS must not be scalar-per-coefficient.

Tasks:

- [x] Pin Rabin-Ben-Or-style source and v1 policy in
  `docs/it-vss-rabin-ben-or.md`.
- [x] Define audited and retained IC tag types with receiver-private retained
  tags.
- [x] Define vector IC tags authenticating `F_q^M`.
- [x] Add batched/vector IT-VSS labels and reject scalar-per-coefficient DKG
  release labels.
- [x] Add app-driver batch public/private delivery tests.
- [x] Add delayed/restart/complaint tests for batched vector delivery.
- [x] Add a normal-build `ProductionInformationCheckingVssBackend` that
  Shamir-shares whole vectors over `F_q` and emits receiver-private retained IC
  material for every holder/receiver pair.
- [x] Add tests proving production IT-VSS vector deliveries verify, tampered
  private deliveries produce hash-only complaints, scalar-per-coefficient
  labels are rejected, and bounded-sampler `s1`/`s2` vector batches can flow
  through the production IT-VSS backend.
- [x] Add explicit audited-vs-retained production tag encodings, derive public
  audit/discard records only from audited tags, and bind the audit transcript
  into production public commitment metadata.
- [ ] Replace test hash/tag artifact helper with a real Rabin-Ben-Or vector
  IT-VSS backend.
- [x] Implement dealer vector polynomial generation for whole-vector `S1`/`S2`
  labels in the normal-build production IT-VSS backend.
- [ ] Implement bounded-size chunking for large deployments.
- [ ] Implement private holder payloads with salted private commitments.
- [x] Implement receiver-private retained `(b, c_vec)` tag delivery in directed
  private delivery payloads.
- [x] Implement public audit opening only for audited tags, with audited tags
  discarded forever.
- [x] Implement explicit vector polynomial consistency transcript material:
  private `gamma_{r,i}` mask evaluations, public masked-evaluation records, and
  metadata binding for every holder/round.
- [x] Replace deterministic challenge derivation in the production backend with
  label-bound public-coin transcripts.
- [x] Add IT-VSS public-coin share wire artifacts and app-driver broadcast /
  collection helpers for embedding transports.
- [x] Split the app-driver production flow into a fully enforced
  public-precommitment -> public-coin -> final-metadata sequence for native DKG
  vector labels.
  Current status: `DkgItVssArtifactPayload::PublicPrecommitment` binds the
  prepared directed deliveries before public coins exist. The app-driver now
  has durable broadcast/collect helpers for public precommitments and public
  coins, then finalizes metadata only after the label-bound public-coin
  transcript is collected. Tests drive precommitment broadcast, public-coin
  collection, final public metadata broadcast, private delivery, and receiver
  verification through the application driver/log path.
- [ ] Implement conservative abort policy:
  `Blame(party)` only with objective public evidence, otherwise `AbortNoBlame`.
- [ ] Implement robust vector reconstruction/opening where required, without
  revealing retained receiver-side tags.
- [x] Add first chunk sizing and private-delivery memory limits to production
  IT-VSS security parameters.
- [ ] Implement multi-chunk splitting for deployments that exceed the configured
  per-chunk lane/byte limits.
- [ ] Add chunk sizing and memory limits:
  one vector if practical, otherwise bounded chunks that are still much larger
  than one coefficient.
- [x] Add first IT-VSS performance counters:
  vector sharings, vector lanes, directed deliveries, audited/retained tag
  vectors, audited/retained tag lanes, and consistency rounds.
- [ ] Extend IT-VSS performance counters:
  vector count, chunk count, IC tag count, consistency rounds, private bytes,
  public audit/consistency records, broadcast bytes, durable log records,
  elapsed time.
  Current status: private-delivery bytes and public audit/consistency record
  counts are tracked; broadcast bytes, durable log record counts, chunk counts,
  and measured elapsed time are still pending.
- [x] Add release gate rejecting scalar-per-coefficient IT-VSS artifacts in
  production logs.

Completeness gate:

- [ ] One dealer's `s1` contribution is shared as one vector or a small bounded
  number of chunks, never one sharing per coefficient.
- [ ] One dealer's `s2` contribution is shared as one vector or a small bounded
  number of chunks, never one sharing per coefficient.
- [ ] Retained receiver-side tags never appear in public payloads, logs, debug
  output, or serializable public artifacts.
- [ ] Malformed vectors, wrong domains, wrong labels, duplicate deliveries,
  mixed-dealer batches, outside-label complaints, and replayed messages abort
  or reject without certification.
- [ ] Restart from every IT-VSS phase cursor either resumes safely or remains
  incomplete; aborted sessions cannot become accepted.
  Current status: cursors now distinguish public precommitment, public coin,
  final commitment, private delivery, verification, complaint, resolution, and
  certification phases. Full crash/restart coverage for every vector IT-VSS
  cursor remains pending.
- [ ] Performance test proves message/round count scales with vector/chunk count
  and consistency rounds, not coefficient count.

## Phase 3: Bounded Secret Sampler Over Production IT-VSS

Goal: generate ML-DSA `s1` and `s2` secret shares with exact distribution and
without a trusted dealer.

Sampling rule:

```text
m = 2*eta + 1
each party contributes u_i in Z_m
r = sum_i u_i mod m
x = r - eta in [-eta, eta]
```

Tasks:

- [x] Exact modulo sampler design is documented.
- [x] Test sampler validates bounds, label binding, and no single-dealer control.
- [x] Vector-domain sampler IT-VSS artifact path exists in tests.
- [x] Bounded-sampler `s1`/`s2` vector batches can be shared and verified
  through `ProductionInformationCheckingVssBackend` without using the
  deterministic scaffold backend.
- [ ] Wire sampler to production vector IT-VSS backend only.
- [ ] Remove release dependency on raw/scaffold residue broadcasts.
- [ ] Add production chunked sampler opening/certification flow.
- [ ] Ensure malformed bounded residues produce abort/blame before any key
  package can be created.
- [ ] Ensure rushing resistance through commit/broadcast ordering and transcript
  binding.

Completeness gate:

- [ ] For ML-DSA-44, ML-DSA-65, and ML-DSA-87, generated `s1`/`s2` shares
  reconstruct in tests to values strictly inside `[-eta, eta]`.
- [ ] Exhaustive/symbolic tests prove exact uniformity for `m=5` and `m=9`.
- [ ] At least one honest contribution makes the final residue uniform for any
  fixed adversarial contributions.
- [ ] No production path accepts a single dealer sampled seed or public
  `ExpandS` seed for private `s1`/`s2`.

## Phase 4: Vectorized Prime-Field IT-MPC Backend

Goal: provide the production MPC backend used by DKG `Power2Round`.

The production backend must be vectorized. Scalar-per-coefficient transport
Power2Round is a correctness stress test only.

Tasks:

- [x] Scalar `ItMpcPrimeFieldBackend` boundary and scalar Power2Round circuit
  logic exist for tests.
- [x] Transport state-machine and per-party phase-driver boundaries exist.
- [x] Define `ShareVec` and `BitShareVec` backend types.
- [x] Add vector local add/sub and public-scalar multiplication.
- [x] Add vector multiplication, opening, assert-zero, and random-bit backend
  hooks.
- [x] Add vector transcript labels and gate ids.
- [x] Add canonical vector wire payloads and state-machine collectors for
  directed and reliable-broadcast prime-field MPC rounds.
- [x] Add networked Shamir test-backend vector message emission for vector
  operations.
- [x] Add wire-log-derived release counters and reject scalar prime-field MPC
  payload logs in release-context checks.
- [ ] Replace test-backend vector hooks with a production optimized batched
  Shamir/IT-MPC implementation.
- [ ] Add real production batched `open_many_checked`.
- [ ] Add production batched `assert_zero`.
- [ ] Add production batched `assert_bit`.
- [ ] Add production vector random-bit generation/preprocessing.
- [ ] Add MPC counters:
  rounds, gates, private messages, broadcasts, bytes, logs, elapsed time.
- [ ] Add malicious/adversarial vector MPC tests:
  bad share, missing party, duplicate sender, replayed gate, wrong label,
  wrong phase, malformed vector length, equivocation.

Completeness gate:

- [ ] For ML-DSA-44/65/87, full vector MPC operations run with round count tied
  to circuit depth, not coefficient count.
- [ ] Public constants use local operations, not MPC multiplication.
- [ ] Batched openings produce one phase per vector opening group, not one phase
  per scalar bit.
- [ ] All vector checks fail closed without opening raw failed differences.

## Phase 5: Production Vectorized Power2Round

Goal: compute `t1 = Power2Round([A*s1+s2]).high` without opening `t`, `t0`,
low bits, or witnesses.

Tasks:

- [x] Scalar reference and scalar private circuit tests exist.
- [x] Test harness verifies boundary coefficients and noncanonical `r+q`
  witness rejection.
- [x] Add unchecked/certified/consumed type-state wrappers for canonical mask
  batches.
- [x] Add one-time mask-use log contract and in-memory test implementation.
- [x] Implement persistent production mask-use logs for crash-safe reuse
  prevention.
- [x] Implement precomputed/certified canonical masks over the vector backend
  boundary: value, 23 bits, bitness, `< q`, transcript binding, and use-log
  consumption.
- [x] Wire precomputed/certified masks into the production per-party
  Power2Round driver phases.
- [ ] Drive masked-opening and canonical-bit recovery phases through the
  per-party application transport runtime.
  - [x] Vector masked-opening broadcast send/collect/recover path uses the
    per-party prime-field MPC runtime and durable wire logs.
  - [x] Vector masked-opening arithmetic helper validates consumed mask
    type-state, computes `[C] = [t] + [A_mask]`, and opens under the canonical
    `open_masked_c` transcript child.
  - [x] Vector wrap-comparison broadcast send/collect/recover path uses the
    per-party prime-field MPC runtime and durable wire logs.
  - [x] Vector wrap-comparison arithmetic helper validates consumed mask
    type-state, rejects noncanonical `C`, and computes `[A_mask > C]` under the
    canonical `a_gt_c` transcript child.
  - [x] Vector subtractor broadcast send/collect/recover path uses the
    per-party prime-field MPC runtime and durable wire logs.
  - [x] Vector canonical `R` bit recovery helper validates consumed mask
    type-state, computes `R = C + q*wrap - A_mask`, and uses the canonical
    `recover_r_bits` transcript child.
  - [x] Named vector certification helpers enforce recovered `R` bitness,
    `R < q`, and `sum 2^j R_j == t mod q`.
  - [x] Vector canonical range-check and equality-check broadcast
    send/collect/recover paths use the per-party prime-field MPC runtime and
    durable wire logs.
  - [x] Named vector add-4095 helper and `t1` high-bit opening helper use the
    canonical `add_4095` and `open_t1_bits` transcript paths.
  - [x] Vector add-4095 and `T1BitOpening` broadcast send/collect/recover paths
    use the per-party prime-field MPC runtime and durable wire logs.
  - [x] Driver requires typed masked-opening lane evidence and typed
    canonical-bit-recovery lane evidence.
  - [x] Driver requires typed add-round-constant lane evidence, packed public
    `t1`, and matching `Power2RoundEvidence` before completion.
  - [x] Cursored runtime can recover accepted add-4095 and `t1` bit-opening
    vector phases from durable wire logs, advance the production driver, pack
    `PublicT1`, and certify matching evidence after restart.
  - [x] Cursored runtime can recover accepted masked opening, wrap comparison,
    subtractor, canonical range, canonical equality, add-4095, and `t1`
    vector phases from durable wire logs and advance the production driver.
  - [x] `R` bitness-check runtime phase is represented explicitly instead of
    only inside the local vector circuit helper.
- [x] Implement vector masked opening `C = t + A_mask`.
- [x] Implement vector `A_mask > C` comparison.
- [x] Implement vector subtractor to recover canonical `R` bits.
- [x] Implement batched `R` bitness checks.
- [x] Implement batched `R < q` checks.
- [x] Implement batched `sum 2^j R_j == t mod q` checks.
- [x] Implement vector add-4095 ripple adder.
- [x] Open only bits `13..22` for every coefficient.
- [x] Pack public `t1` and emit `Power2RoundEvidence`.
- [ ] Zeroize masks, `R` bits, low bits, `t`, `s2`, and temporaries.
- [ ] Add release gate rejecting any backend that opens lower bits, `t`, `t0`,
  or uses scalar-per-coefficient transport in production.

Completeness gate:

- [ ] Full ML-DSA-44/65/87 vectorized Power2Round output matches FIPS reference
  for randomized test vectors.
- [ ] No public/durable log contains `t`, `t0`, low bits, mask bits, mask shares,
  failed check values, or bit-decomposition witnesses.
- [ ] Round/message counters match batched design expectations.
- [ ] Scalar full-vector Power2Round test is marked slow/ignored or moved to a
  benchmark/stress profile.

## Phase 6: Public Key Assembly

Goal: assemble `pk = (rho, t1)` and key packages retaining only `s1` shares.

Tasks:

- [x] `assemble_shared_t` consumes `s2` and creates temporary `SharedT`.
- [x] `DkgKeyPackage` excludes `s2`, `t`, `t0`, low bits, and simulator
  material.
- [x] `ProductionNativeDkgAssemblyOutput` wraps release-valid output only.
- [ ] Wire production sampler + production IT-VSS + vectorized Power2Round into
  one normal-build DKG path.
- [ ] Make scaffold assembly unavailable to normal users.
- [ ] Add public-key compatibility checks against the FIPS ML-DSA verifier
  expectations.
- [ ] Add multi-party agreement checks: all honest parties derive the same
  `rho`, `t1`, public key, setup certificate, and signer set.

Completeness gate:

- [ ] Production DKG emits a `DkgKeyPackage` for every accepted party.
- [ ] All packages agree on public material and certificate.
- [ ] Each package contains the correct local `s1` share and no forbidden
  material.
- [ ] Standard ML-DSA verification accepts later TALUS signatures using the DKG
  public key.

## Phase 7: Application Transport Contract

Goal: the crate stays transport-agnostic while enforcing exact production
transport requirements.

Tasks:

- [x] Transport traits exist for authenticated private delivery and
  equivocation-resistant broadcast.
- [x] Transport evidence types exist for ML-KEM, ML-DSA, and reliable broadcast.
- [x] In-memory conformance tests exist.
- [ ] Add app-facing adapter trait examples for production integrators.
- [ ] Add conformance test suite that embedders can run against their transport.
- [ ] Test ML-KEM session binding in every private DKG context.
- [ ] Test ML-DSA identity binding in every broadcast/private message context.
- [ ] Test reliable broadcast semantics:
  same sender message to all honest observers or equivocation/abort.
- [ ] Test delayed delivery, reordered delivery, duplicate delivery, replay,
  wrong context, and restart with persisted messages.
- [ ] Add byte counters per transport phase.

Completeness gate:

- [ ] Production DKG cannot start without transport evidence matching suite,
  epoch, party set, threshold, and transcript.
- [ ] Wrong ML-KEM session evidence is rejected.
- [ ] Wrong ML-DSA identity evidence is rejected.
- [ ] Broadcast equivocation is detected or aborts before certification.
- [ ] Private delivery authentication failure cannot create accepted VSS/MPC
  state.

## Phase 8: Persistence, Restart, and Reuse Prevention

Goal: crashes cannot cause share/key/session reuse or turn incomplete state into
accepted production output.

Tasks:

- [x] Setup cursors and release checks exist.
- [x] Transcript store rejects committed epoch reuse.
- [x] Some restart and delayed-delivery tests exist.
- [ ] Define production persistence trait boundaries for:
  setup cursors, wire logs, private state hashes, public artifacts, output
  packages, consumed one-time material.
- [ ] Persist vector IT-VSS phase cursors and private-state hashes.
- [ ] Persist vector Power2Round phase cursors and mask-consumption state.
- [ ] Persist one-time mask/preprocessing identifiers and reject reuse.
- [ ] Add crash tests at every DKG phase boundary.
- [ ] Add rollback tests: old log snapshots cannot overwrite newer accepted
  state.
- [ ] Add corruption tests for truncated, reordered, or malformed log records.

Completeness gate:

- [ ] Restart after any sent/waiting/collected phase resumes safely or remains
  incomplete.
- [ ] Aborted or incomplete sessions cannot produce `ProductionNativeDkgAssemblyOutput`.
- [ ] One-time masks and preprocessing material cannot be reused after crash.
- [ ] Accepted epoch cannot be recomputed with different public material.

## Phase 9: Release Gates and CI

Goal: production-invalid configurations are impossible to accidentally ship.

Tasks:

- [x] Release gates exist for certificates, packages, logs, cursors, and
  readiness.
- [x] Test substrates do not emit production Power2Round identity in normal
  builds.
- [x] Centralize typed-output release checks behind
  `ensure_production_native_dkg_output_context_allowed_for_release`.
- [x] Add normal-build public API scan.
- [ ] Add forbidden-field scan for `s2`, `t`, `t0`, low bits, mask witnesses,
  retained receiver tags, and private setup payloads.
- [x] Add forbidden public-linear-image scan for `A*s1_i`,
  `as1_commitment`, `A*nonce` coefficients, `Phi = A*secret`, and
  `CommitmentBackedPartialVerifier` on release paths.
- [x] Add rejected-`z` leakage scan for clear partial `z_i` transport,
  candidate-token verifier retry, exposed candidate hints, exposed validity
  bits, and detailed private-check failure reasons on release paths.
- [ ] Add feature scan to reject insecure/dev/test features in release builds.
- [ ] Add performance regression test with max rounds/messages/bytes for
  ML-DSA-44 baseline.
- [ ] Add CI jobs:
  `cargo check --workspace`, `cargo test`, `cargo clippy --workspace
  --all-targets`, release-gate tests, doc tests, API scan, forbidden payload scan.

Completeness gate:

- [ ] A production-invalid package set cannot pass any release validator.
- [ ] A production-valid package set must pass exactly one narrow release path.
- [ ] Any simulator/scaffold/test backend in normal build fails CI.
- [ ] Any retained receiver-side tag in public artifacts fails CI.
- [ ] Any public exact `A*secret` image in production artifacts fails CI.
- [ ] Any public-linear-image online blame verifier in release builds fails CI.
- [ ] Any clear rejected-`z` path in release builds fails CI.

## Phase 10: End-to-End Production DKG and Signing

Goal: prove native DKG output works with TALUS signing and standard ML-DSA
verification.

Tasks:

- [ ] Run full production DKG for ML-DSA-44.
- [ ] Run full production DKG for ML-DSA-65.
- [ ] Run full production DKG for ML-DSA-87.
- [ ] Import each party's `s1` share into TALUS signing provider.
- [x] Generate preprocessing tokens without public exact `A*nonce` commitments
  in the normal API.
  Current status: `talus-mpc` has `PreprocessingSession`,
  `DistributedNonceShare`, masked-broadcast commit/open, certification
  evidence, and `CertifiedToken`/`TokenPool` admission gates. The current nonce
  generator is still in-process orchestration, not the final app-driven
  production IT-VSS/IT-MPC phase.
- [ ] Generate preprocessing tokens through app-driven token-batched/vectorized
  nonce, CEF, CarryCompare, and BCC certification, not scalar-per-coefficient
  loops or local aggregate witnesses.
- [ ] Replace current deterministic masked-broadcast proof hashes/local
  recomputation with final private production certification evidence.
- [ ] Replace current local CEF/BCC witness evidence with production vector
  IT-MPC evidence.
- [ ] Persist preprocessing token inventory durably and reject token reuse after
  restart/rollback.
- [ ] Run strict TALUS online signing with no rejected-`z` leakage.
- [ ] Consume a fixed token batch before response work.
- [ ] Privately check response norm and hint weight.
- [ ] Open only selected valid `ctilde`, `z`, and `h`.
- [ ] Verify final signature with standard FIPS ML-DSA verifier.
- [ ] Test malicious setup failures do not leak forbidden material.
- [ ] Test final verify failure consumes one-time material and releases no
  signature.
- [ ] Test rejected candidates do not expose `z_i`, aggregate `z`, hints,
  validity bits, token failure reasons, or selected-index failure patterns.
- [ ] Record performance counters for DKG, preprocessing, and signing.

Completeness gate:

- [ ] For each suite, DKG -> TALUS signing -> standard verification passes.
- [ ] Malicious tests produce abort/blame/no output, never invalid accepted
  keys.
- [ ] DKG performance is within the agreed target envelope.
- [ ] No test/scaffold feature or backend is required by the end-to-end
  production test.
- [ ] `docs/no-rejected-z-leakage.md` is reflected in release-gate tests and
  strict signing tests.

## Phase 11: Cryptographic Review Package

Goal: make external review efficient after implementation is complete.

Review is not a blocker to implementing the full product path, but the review
package must be ready before release.

Tasks:

- [ ] Write protocol spec for final vector IT-VSS implementation.
- [ ] Write protocol spec for final vector IT-MPC Power2Round implementation.
- [ ] Map each protocol step to source files/functions.
- [ ] Document exact security claims and non-claims:
  abort security, no fairness, no guaranteed output delivery.
- [ ] Document all failure/blame paths.
- [ ] Document all persisted public/private state.
- [ ] Document all zeroization and one-time-material rules.
- [ ] Provide test matrix and coverage summary.
- [ ] Provide performance counter reports.

Completeness gate:

- [ ] A cryptographer can trace every production transcript field to a protocol
  step and source location.
- [ ] Every release gate has a documented security reason.
- [ ] Every known non-production/test helper is listed and gated.
- [ ] `docs/no-public-a-secret-linear-images.md` is reflected in release-gate
  tests and in the public API scan.
- [ ] `docs/no-rejected-z-leakage.md` is reflected in release-gate tests and
  strict online signing tests.

## Critical Path Order

Recommended implementation order:

1. Gate current clear partial/signing and public-linear-image verifier as
   test/research only.
2. Add release scanners for public `A*secret` and rejected-`z` leakage.
3. Move remaining test/scaffold helpers into test/dev modules.
4. Implement production vector IT-VSS backend with chunking and counters.
5. Wire bounded sampler exclusively to production vector IT-VSS.
6. Implement `ShareVec` / `BitShareVec` prime-field MPC backend.
7. Implement vectorized Power2Round with precomputed masks.
8. Implement token-batched/vectorized preprocessing, private BCC, and strict
   no-rejected-`z` signing.
9. Wire production DKG assembly to `ProductionNativeDkgAssemblyOutput`.
10. Add transport adapter conformance suite.
11. Add persistence/restart/reuse prevention for vector IT-VSS, Power2Round,
    preprocessing, and strict signing batches.
12. Run end-to-end DKG -> TALUS signing -> FIPS verification.
13. Build review package and performance report.

## Production Release Is Not Complete Until

- [x] No scalar-per-coefficient IT-VSS artifacts are accepted by release-context
  setup-log gates.
- [x] Scalarized Power2Round/prime-field MPC counters are rejected by release
  gates.
- [ ] No scaffold/test backend is exported or selectable in normal builds.
- [ ] No release-valid artifact can be produced from in-memory simulator state.
- [ ] No forbidden secret material appears in output, public logs, errors, or
  debug output.
- [ ] All transport evidence is PQ-safe and bound to the DKG transcript.
- [ ] Crash/restart and rollback tests pass.
- [ ] End-to-end production DKG and TALUS signing pass for all target suites.
- [ ] Performance counters show usable DKG execution time and bounded message
  volume.
