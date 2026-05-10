# TALUS-MPC Implementation Plan

This plan converts `talus.md` into executable milestones for a Rust workspace. The immediate goal is a correct, testable implementation path, not a production claim before the MPC, DKG, persistence, and proof obligations are closed.

## Implementation Readiness

We can start implementation immediately for Milestones 0 through 4:

- workspace scaffold and crate boundaries
- `fips204` dependency wiring plus a TALUS adapter for the internal ML-DSA hooks that threshold signing needs
- TALUS BCC, public hint, and CEF identities
- GF(2^128), authenticated shares, checked openings, Boolean gates, and generic CarryCompare

Milestones 5 through 9 need product decisions before they can be called complete:

- production triple provider design and security proof target
- reviewed PQ key-share provisioning and native honest-majority IT-DKG/VSS design
- pre-challenge masked-broadcast and CarryCompare certification
- durable storage and crash-consistent token consumption
- transport/equivocation model and deployment assumptions

The cross-component production completion checklist is now
`docs/production-grade-roadmap.md`. It is the actionable roadmap for the final
system and includes the two hard rules that supersede paper-compatible
shortcuts:

```text
no public exact A-image of secret material
no rejected-z leakage in production signing
```

Approved v1 production architecture:

- honest-majority PQ TALUS-MPC
- `N >= 2T - 1` for `T >= 3`
- ML-KEM-established private channels
- ML-DSA authenticated party identities and broadcast messages
- SHAKE/KMAC transcript binding and key derivation
- information-theoretic MPC/VSS preprocessing over PQ-authenticated channels
- reviewed PQ key-share provisioning as an initial operational setup profile
- native honest-majority IT-DKG/VSS as a mandatory product component
- bounded ML-DSA secret sampling as the review-critical DKG subprotocol
- no Ring-LPN/PCG, PQ-OT/MASCOT, or LWE/RLWE FHE-SPDZ in v1 production
- no classical Pedersen/DH/AKE in production

## Authority Boundaries

The TALUS paper is authoritative for the TALUS-specific signing mechanics. Follow these exactly unless a later reviewed erratum says otherwise:

- standard FIPS 204 ML-DSA signature format and final verifier compatibility
- BCC condition, boundary handling, retry semantics, and final verification gate
- CEF masked-broadcast arithmetic, including `+ delta`
- TALUS-MPC honest-majority shape: `N >= 2T - 1` for `T >= 3`; `T = 2` handled separately

The paper is not production-complete for our target where it uses abstract, classical, semi-honest, or future-work components. These must be replaced or reviewed before release:

- classical Pedersen DKG or finite-field/EC DH/AKE
- public exact lattice images of secrets, including `A*s1_i`, `A*nonce` coefficients, and Feldman-style `Phi = A*secret`
- online `z_i` verification/blame based on public `A*s1_i`
- paper reveal-on-failure blame semantics after `z_i` has been sent
- pairwise seed setup unless instantiated with PQ-secure authenticated key establishment or reviewed provisioning
- unauthenticated PRF-derived triples where malicious privacy requires authenticated Beaver triples
- concrete durable storage, crash recovery, rollback protection, and transport
- adaptive security beyond the paper's erasure assumptions

Product requirements that are stricter than the paper:

- end-to-end post-quantum setup: no EC/finite-field Pedersen, no ECDH/DH, no classical-only PKI for production security
- reviewed PQ key-share provisioning is acceptable as an initial setup profile, but native honest-majority IT-DKG/VSS remains mandatory
- plain Shamir DKG is insufficient unless the bounded ML-DSA s1/s2 sampling subprotocol is reviewed
- any ZK or cut-and-choose masked-broadcast proof is optional hardening, not the paper-mandated path
- no public exact `A*secret` images in production; see `docs/no-public-a-secret-linear-images.md`
- no per-party public-linear-image blame after challenge in v1 production
- no rejected-`z` leakage in production; see `docs/no-rejected-z-leakage.md`
- post-challenge reveal-on-failure is disabled by default; after `z_i = y_i + c*s1_i` is broadcast, revealing enough honest nonce material to reconstruct `y_i` is a long-term-share leakage surface unless separately proven and reviewed

## IT-DKG/VSS Source Bundle

Use a curated source bundle, not a generic "read about VSS" path.

Protocol foundations:

- Shamir 1979, "How to Share a Secret": base polynomial sharing, evaluation points, reconstruction, and Lagrange coefficients.
- BGW 1988, "Completeness Theorems for Non-Cryptographic Fault-Tolerant Distributed Computation": arithmetic-circuit MPC over Shamir shares; local addition, multiplication degree growth, degree reduction, and robust opening threshold intuition.
- Rabin-Ben-Or 1989, "Verifiable Secret Sharing and Multiparty Protocols with Honest Majority": the primary source for our PQ product DKG/VSS direction: broadcast plus pairwise private channels, honest majority, unconditional secrecy, and information-checking style verification without discrete-log commitments.
- Cramer-Damgaard-Nielsen, "Secure Multiparty Computation and Secret Sharing": book-level source for information-theoretic MPC, LSSS abstractions, VSS, robust opening, and multiplication.
- Cramer-Damgaard-Maurer 2000, "General Secure Multi-Party Computation from any Linear Secret-Sharing Scheme": abstraction source for LSSS-based MPC and VSS traits.
- Chida et al. 2018/2023, "Fast Large-Scale Honest-Majority MPC for Malicious Adversaries": main modern source for malicious honest-majority arithmetic MPC with abort, Shamir and replicated-sharing instantiations, and check-zero/malicious-detection patterns.

Reference implementations to inspect only:

- MP-SPDZ: inspect malicious honest-majority Shamir / Rep3 / PS / SY protocol structure, tests, circuit/runtime split, and benchmarks. Do not import as an unreviewed production dependency.
- Cicada: inspect active-adversary API shape and honest-majority security-with-abort tests.
- MPyC: inspect passive Shamir arithmetic, PRSS mechanics, interpolation, and finite-field sanity tests. Do not use as a malicious-security source.
- FRESCO: inspect protocol-suite and builder/test architecture.
- SCALE-MAMBA: inspect preprocessing/runtime separation and mature MPC system organization.

PQ infrastructure sources:

- NIST FIPS 203 ML-KEM for pairwise private channel establishment.
- NIST FIPS 204 ML-DSA for operational party identities, authenticated broadcast, and final signature compatibility.
- NIST SP 800-185 cSHAKE/KMAC/TupleHash for domain-separated transcript hashing, PRFs, and tuple-safe consensus encodings.

Do not include SLH-DSA in the v1 operational identity design. The approved identity scheme is ML-DSA.

Broadcast sources:

- Dolev-Strong authenticated Byzantine agreement is the synchronous signed-broadcast reference shape.
- Bracha/Toueg-style asynchronous reliable broadcast changes threshold/network assumptions and must not be introduced without reworking the product threshold model.

Implementation reading order:

1. Shamir: implement field arithmetic, sharing, interpolation, and Lagrange coefficients.
2. Rabin-Ben-Or: implement IT-VSS assumptions, broadcast/private-channel split, complaints, and information checking.
3. BGW: implement arithmetic-circuit MPC shape, multiplication, degree reduction, and robust open.
4. Cramer-Damgaard-Nielsen and Cramer-Damgaard-Maurer: shape generic LSSS/VSS/MPC traits instead of ad-hoc polynomial-only code.
5. Chida et al.: implement malicious honest-majority checking with abort for arithmetic circuits and preprocessing certification.
6. MP-SPDZ, Cicada, MPyC, FRESCO, and SCALE-MAMBA: inspect engineering patterns and tests only.
7. NIST FIPS 203, FIPS 204, and SP 800-185: implement PQ channels, authentication, and transcript binding.

Implementation warning:

- Generic Shamir DKG only samples arbitrary field secrets. TALUS needs bounded ML-DSA secrets: `s1`/`s2` coefficients in `[-eta, eta]`. The bounded distributed sampler is the hard DKG subproblem and must be reviewed separately.
- Do not replace Rabin-Ben-Or style IT-VSS with Feldman or Pedersen for production. Feldman/Pedersen are discrete-log based and are not compatible with the approved end-to-end PQ product profile.
- Do not use classical MASCOT/SPDZ/DH/ECDH/OT paths as the v1 production backend.
- Rust Shamir/VSS crates may be inspected for API and test ideas, but must not be used as production DKG/VSS/MPC dependencies.

Pinned product instantiation:

- `docs/it-vss-rabin-ben-or.md` is the implementation target for `ProductionInformationCheckingVssBackend`.
- v1 operational identities are ML-DSA only.
- The VSS/MPC core is information-theoretic assuming authenticated private channels and reliable broadcast; the overall product still depends on PQ infrastructure for channel establishment, identity authentication, and transcript binding.
- Audited information-checking tags may be opened only for audit and then discarded.
- Retained receiver-side information-checking tags are receiver-private forever: they must not be broadcast, sent to the holder, logged in public artifacts, or exposed through public serialization.
- Retained-tag replacement and public `beta_i` share-point reveal are not part of v1.
- Unresolved IC or polynomial-consistency disputes abort the VSS instance. Blame is emitted only when public evidence objectively identifies a party; otherwise use `AbortNoBlame`.
- Scalar IT-VSS is the first correctness/adversarial-test target. Production DKG must use batched/vector IT-VSS, not scalar-per-coefficient VSS.
- Production Power2Round must also be vectorized. The scalar per-coefficient
  Power2Round harness is only a correctness stress test; the production backend
  must batch across all coefficients, all openings, all checks, and all
  multiplications per circuit layer. See `docs/dkg-production-performance.md`.
- Production nonce preprocessing, CEF, CarryCompare, and BCC certification must
  also be token-batched/vectorized. Strict tokens are produced in batches or
  bounded chunks; messages and rounds must scale with token batches/chunks and
  circuit layers, not scalar coefficient loops. See
  `docs/preprocessing-bcc-performance.md`.
- Cross-component performance rules and follow-up benchmark/counter tasks are
  tracked in `docs/optimization-principles.md`.
- The full production DKG completion checklist, including IT-VSS performance,
  vectorized Power2Round, transport, persistence, release gates, end-to-end
  signing, and cryptographic review package, is tracked in
  `docs/dkg-production-completion-plan.md`.
  Current update: `talus-dkg` now has the first pinned IC-tag primitive types: canonical `ItVssFq`, holder-side `y` tags, `AuditedReceiverTag`, and `RetainedReceiverTag`. Audited tags have a public audit-phase encoder and carry a discard marker. Retained receiver tags keep `(b,c)` private, expose only holder/receiver/index accessors, verify through `verify_private`, and redact `(b,c)` in `Debug`; there is intentionally no public retained-tag encoder. Tests cover correct IC verification, modified value/y rejection, zero multiplier rejection, noncanonical field-element rejection, audited public encoding, and retained-tag redaction/no-public-encoding shape.
  Current update 2: `talus-dkg` now has a scalar IT-VSS state-machine skeleton for the pinned Rabin-Ben-Or instantiation. `ScalarItVssContext` binds suite, epoch, dealer, DKG config hash, party-set hash, threshold `f`, and sharing label hash. `ScalarItVssStateMachine` enforces ordered phases (`Context`, `PrivatePayload`, `IcAudit`, `PolynomialConsistency`, `Accepted`), rejects duplicate phase message keys, validates sender/receiver party ids, and exposes terminal failure classification through `ScalarItVssFailure`. Conservative aborts use `AbortNoBlame` with a transcript hash, while `BlameDealer` and `BlameParty` require nonzero public evidence hashes. Tests cover ordered completion, out-of-order rejection, duplicate replay rejection, unknown sender/receiver rejection, label/config binding, terminal abort behavior, and objective-blame evidence requirements.
  Current update 3: `talus-dkg` now implements the scalar IT-VSS honest path for correctness testing. `scalar_it_vss_deal_honest_path` builds degree-`f` Shamir scalar shares from caller-provided coefficients, evaluates caller-provided mask polynomials, derives deterministic test IC tag material, creates salted private-payload commitments, splits audited and retained IC tags, derives post-commitment polynomial-consistency challenges, and publishes `H_r(x) = G_r(x) + e_r F(x)` rounds. `accept_scalar_it_vss_honest_deal` validates public/private payload commitments, verifies audited IC tags, checks polynomial consistency, and emits `AcceptedScalarItVssSharing`. This remains a deterministic scalar correctness path and not the production randomness source or batched DKG backend. Tests cover honest acceptance, commitment binding, tampered audit-tag rejection, tampered polynomial-consistency rejection, and malformed polynomial/mask shapes.
  Current update 4: scalar IT-VSS reconstruction/opening is implemented for the correctness path. `scalar_it_vss_reconstruction_shares` builds public holder broadcasts containing `beta_i` plus retained holder-side `y` tags. `reconstruct_scalar_it_vss_opening` verifies each holder point against receiver-private retained `(b,c)` tags, accepts a point only when at least threshold `T=f+1` receivers approve it, reconstructs `F(0)` from accepted points, checks all threshold-sized accepted subsets agree on the same secret, and emits a transcript-bound `ScalarItVssReconstructionOutput`. Tests cover honest opening, excluding one forged holder while still reconstructing, aborting when too many holder values or retained `y` tags are forged, missing private payloads, and private-payload commitment tampering.
  Current update 5: scalar adversarial hardening now rejects duplicate holder reconstruction broadcasts, missing or duplicated retained tag indices per receiver, retained tags bound to the wrong holder, unknown receivers, and public payloads that contain the retained-receiver-tag forbidden marker. False IC disputes use `AbortNoBlame` and do not create dealer blame unless objective public evidence is provided. Release scanning now includes `ensure_public_payload_excludes_retained_receiver_tags` so retained receiver-side `(b,c)` material cannot enter public artifacts unnoticed.
  Current update 6: scalar IT-VSS persistence/restart scaffolding is in place. `ScalarItVssCursor`, `ScalarItVssCursorState`, `ScalarItVssPrivateStateRecord`, and `ScalarItVssPersistenceLog` record phase status, terminal failures, accepted state, local private-payload hashes, and retained receiver-tag state hashes without making private material public. `ScalarItVssStateMachine::persist_cursor` stores restart cursors, `persist_scalar_it_vss_private_state` stores private-state hashes, and `ensure_scalar_it_vss_restart_allows_accepted` rejects empty, incomplete, wrong-context, bad-private-state, and aborted sessions before they can be treated as accepted. Tests cover complete accepted restart, incomplete restart rejection, aborted restart rejection, wrong-context rejection, and bad private-state hash rejection.
  Current update 7: IT-VSS v1 release policy gates are now explicit. `ItVssV1ReleasePolicy` permits only the batched/vector production DKG mode, forbids public `beta_i` share-point reveal, and forbids public retained receiver-side IC tag artifacts. `ensure_production_it_vss_readiness` enforces this policy before a backend can claim `ProductionInformationChecking`, and `ensure_scalar_it_vss_release_state_allows_accepted` wraps restart validation for scalar correctness sessions so incomplete or aborted persisted state cannot become accepted release evidence. Tests cover scalar-per-coefficient DKG rejection, public beta reveal rejection, retained-tag-public-mode rejection, and release-state rejection of incomplete/aborted scalar sessions.
  Current update 8: batched/vector IC tag primitives are now implemented. `ItVssVectorHolderSideTag`, `AuditedVectorReceiverTag`, and `RetainedVectorReceiverTag` authenticate an entire `F_q^M` vector with one hidden scalar multiplier through `c_vec = beta_vec + b*y_vec`. Audited vector receiver tags have a public audit-phase encoder and are discarded; retained vector receiver tags keep `b` and `c_vec` receiver-private, redact them in `Debug`, and have no public encoder. Tests cover whole-vector verification, mutation rejection, length mismatch rejection, public audited encoding, and retained-vector redaction/privacy shape.
  Current update 9: the vector IT-VSS honest-path deal/accept flow is implemented. `vector_it_vss_deal_honest_path` evaluates vector Shamir polynomials, creates vector mask shares, builds salted private-payload commitments, derives audited and retained vector IC tags for every holder/receiver pair, and publishes vector polynomial-consistency rounds. `accept_vector_it_vss_honest_deal` verifies commitments, audited vector tags, vector polynomial consistency, party/point binding, and transcript binding before emitting `AcceptedVectorItVssSharing`. Tests cover honest vector acceptance, commitment binding, audited-tag tampering, commitment tampering, consistency tampering, and malformed vector shapes.
  Current update 10: vector IT-VSS reconstruction/opening is implemented for the correctness path. `vector_it_vss_reconstruction_shares` broadcasts holder vector points plus retained holder-side `y_vec` tags, and `reconstruct_vector_it_vss_opening` verifies each holder point through receiver-private retained vector `(b,c_vec)` tags. A holder vector point is accepted only with threshold receiver approvals; each coordinate is reconstructed at zero from the accepted Shamir points, and every threshold-sized accepted subset must agree coordinatewise. Tests cover honest vector opening, one forged holder being excluded, too many forged holders aborting, and malformed vector-share lengths being rejected.
  Current update 11: vector IT-VSS openings now feed the bounded sampler correctness path. `VerifiedSmallResidueInput::from_vector_it_vss_opening` accepts a whole-vector IT-VSS sharing (`index = None`), checks the vector domain/party set/transcript hash, verifies the reconstruction transcript, checks each opened residue is in `Z_m`, and emits per-coordinate verified sampler inputs with vector IT-VSS certificate provenance. Tests run full ML-DSA-44 `s1` vector openings from all dealers into `sample_verified_small_polyvec`, reconstruct sampled coefficients from threshold shares, and reject wrong vector-domain labels or out-of-range residues.
  Current update 12: logged/native certified sampling now expects whole-vector sampler IT-VSS artifacts. `sample_logged_small_polyvec_from_certified_log` verifies each coefficient's residue contribution against a vector-domain commitment (`ItVssSharingLabel` with `index = None`) instead of a per-coefficient commitment. The scaffold artifact generator now mints one sampler IT-VSS public commitment per dealer per secret vector by encoding the full residue vector, and the all-vector phase-log resolver expects S1/S2 vector-domain keys. The older per-coefficient artifact adapter remains test-only for the single-coefficient phase-driver test.
  Current update 13: the sampler IT-VSS phase driver now has a vector-domain path. `it_vss_share_small_residue_vector_contribution` and `drive_share_small_residue_vector_it_vss` share a dealer's full `s1`/`s2` residue vector under one vector-domain IT-VSS commitment, send directed private deliveries, verify receiver deliveries, persist the vector-domain resolution, and feed `sample_logged_small_polyvec_from_certified_log`. The durable DKG private-share replay key now includes an IT-VSS delivery `label_hash` when present, so replay/resume does not collapse multiple IT-VSS private deliveries to the same receiver across `s1`, `s2`, or future vector labels.
  Current update 14: `InMemoryNativeDkgScaffoldCoordinator` now drives the scaffold native DKG setup end-to-end over one in-memory runtime per party. It sequences raw bounded-sampler residue rounds, vector-domain sampler IT-VSS public/private phases, sampler IT-VSS complaint resolution, scalar VSS setup logs, certified `s1`/`s2` sampling, and public-key assembly through the existing logged phase drivers. Scalar VSS verification now ignores non-scalar private-share payloads in the shared DKG `VssShare` transport phase, allowing sampler IT-VSS private deliveries and scalar VSS private shares to coexist in the same durable setup log without mis-decoding each other.
  Current update 15: native DKG coordinator release readiness is now explicit. `NativeDkgCoordinatorKind`, `ProductionNativeDkgCoordinatorReadiness`, and `ensure_production_native_dkg_coordinator_readiness` require an application-supplied transport scheduler, production information-theoretic setup backend, production information-checking IT-VSS, production IT-MPC Power2Round, ML-KEM private channels, ML-DSA operational identities, reliable-broadcast conformance, durable restart policy, and no scaffold backends. External cryptographic review is tracked as post-implementation audit metadata, not as a readiness gate. The in-memory scaffold coordinator now fails release readiness with `InsecureNativeDkgCoordinator` instead of being implicitly distinguishable only by certificate blockers.
  Current update 16: the native DKG setup scheduler boundary is now explicit. `NativeDkgApplicationSetupDriver` is implemented for `CursoredLoggedDkgTransportPartyRuntime<T,L,C>` where the embedding application supplies `AuthenticatedP2pTransport + EquivocationResistantBroadcast`, a durable `DkgWireMessageLog`, and a durable `DkgSetupPhaseCursorLog`. The trait exposes resumable typed setup phases for raw bounded-sampler residues, vector-domain sampler IT-VSS public/private delivery and verification, scalar VSS commit/share phases, complaints, and explicit IT-VSS subphase cursors. This keeps sockets, retries, routing, and production persistence outside the crate while making the native DKG phase contract concrete.
  Current update 17: native DKG setup has an application-driver conformance test that reaches assembly without using `InMemoryNativeDkgScaffoldCoordinator`. The test drives raw `s1/s2` sampler residues, vector-domain sampler IT-VSS public/private phases, scalar VSS commit/share phases, sampler artifact persistence, certified sampling, and public-key assembly through helper functions typed only against `NativeDkgApplicationSetupDriver`, then validates the assembled public output and key-package set from the receiver's durable logs.
  Current update 18: scaffold coordinator separation is explicit in the API. `InMemoryNativeDkgScaffoldCoordinator` now advertises `COORDINATOR_KIND = InMemoryScaffold`, `PRODUCTION_ALLOWED = false`, and a `production_readiness_profile()` that intentionally uses scaffold backend ids. `NativeDkgCoordinatorReleaseProfile` lets coordinator implementations expose their release claim and run `ensure_allowed_for_production_release`; the in-memory coordinator fails with `InsecureNativeDkgCoordinator`. This makes the scaffold-vs-product split visible at the type/API level, not just in docs.
  Current update 19: transport and scheduler hardening now covers the product-facing boundaries. `talus-wire` exposes `NativeDkgTransportEvidence`, `MlKemChannelSessionEvidence`, `MlDsaOperationalIdentityEvidence`, `ReliableBroadcastEvidence`, and `NativeDkgApplicationTransportEvidenceProvider`; these reuse `PqTransportSessionBinding` for wire contexts while retaining a full evidence hash that includes reliable-broadcast conformance. Native DKG app-driver tests now cover delayed bounded-sampler broadcasts, delayed vector IT-VSS private deliveries, restart from waiting vector IT-VSS cursors, and complaint collection before/after completion. Vector IT-VSS hardening rejects retained-tag public leakage, wrong label/domain hashes, malformed retained-y vector lengths, and missing retained tags. `ensure_native_dkg_assembly_output_allowed_for_release` gates complete assembly outputs and rejects scaffold assembly material.
  Current update 20: native DKG release gating now has a composed product-facing context check. `ensure_native_dkg_release_context_allowed_for_release` validates the DKG key-package set, production coordinator/backend readiness, completed setup cursors, setup artifact logs matching the package certificate, forbidden private setup payload absence, and `NativeDkgTransportEvidence` binding to the same suite, transcript, and party set. Tests cover the valid production-shaped context plus incomplete cursors, wrong transport transcript binding, missing scaffold-free readiness, and private setup payload leakage.
  Current update 21: batched/vector IT-VSS now has an explicit facade instead of relying only on repeated single-sharing calls. `ItVssBatchedSecret`, `ItVssBatchedDealerOutput`, `ensure_it_vss_batched_vector_label`, and `it_vss_share_batched_vector_secrets` enforce whole-vector `s1`/`s2` labels (`index = None`) and reject scalar-per-coefficient or non-DKG-vector labels before transport messages are emitted. `it_vss_share_small_residue_vector_batches` shares one dealer's `s1`/`s2` bounded-sampler residue vectors with exactly one public commitment per vector-domain sharing. Tests cover valid S1/S2 vector batches, scalar-label rejection, auxiliary-domain rejection, duplicate label rejection, wrong dealer rejection, and malformed vector length rejection.
  Current update 22: the native application setup driver now has an end-to-end S1/S2 batched IT-VSS phase. `drive_share_small_residue_vector_batches_it_vss` emits one reliable-broadcast artifact carrying both vector commitments for the dealer and one private-delivery batch per receiver, while preserving per-vector artifact counts in the setup cursor. `persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs` recovers batched public commitments and private deliveries from durable logs, verifies the local receiver's vector deliveries through the IT-VSS backend, merges matching complaint broadcasts, resolves complaints, and persists the resolution. Tests tamper one dealer's S1 delivery inside a private batch and verify that the resolver rejects that dealer's whole batch while certifying the remaining S1/S2 vector commitments.
  Current update 23: batched IT-VSS private-delivery collection now waits for distinct sender parties rather than flattened inner deliveries. This prevents an S1/S2 batch from one sender from satisfying a round that still lacks the other sender's private message. Tests cover delayed batched public commitments, restart from the waiting public-artifact cursor, delayed batched private deliveries, restart from the waiting private-delivery cursor, and complaint resolution from recovered durable logs without using queued transport messages.
  Current update 24: the batched IT-VSS hardening pass is complete. Batch verification now has a full complaint lifecycle test: generated complaints are broadcast through the app-driver path, complaint delivery is delayed, restart resumes from the complaint-wait cursor, and resolution is recovered from durable logs. The batch resolver now rejects valid IT-VSS complaint evidence whose label is outside the expected S1/S2 vector batch instead of silently ignoring it. Adversarial tests cover duplicate inner deliveries, wrong receiver, mixed-dealer batches, wrong label hashes, and outside-label complaints. Release scanning now has batch-private-payload coverage, and `InMemoryNativeDkgScaffoldCoordinator` uses the S1/S2 batch vector IT-VSS driver instead of separate S1 then S2 vector phases.
  Current update 25: prime-field MPC transport now has a vector wire shape for batched Power2Round phases. `DkgPrimeFieldMpcPayload` carries either one scalar `value` or a non-empty `values` vector, scalar collectors reject vector payloads, and vector collectors reject scalar/empty payloads and malformed lane lengths. `TransportPrimeFieldMpcStateMachine` can send and collect directed and reliable-broadcast vector rounds, while `InMemoryPrimeFieldMpcNetwork` records vector messages separately from scalar messages and rejects vector replays. The networked Shamir prime-field backend now emits one vector message per sender/receiver/round for `mul_vec`, `assert_zero_vec`, `open_vec_checked`, and `random_bit_vec` instead of scalar lane messages. Tests cover vector wire roundtrips, vector replay rejection, reliable-broadcast vector collection, networked vector batch labels, and the prime-field Power2Round boundary suite.
  Current update 26: Power2Round mask batches now have an explicit type-state boundary. `UncheckedPower2RoundMaskBatch` can only be used after `certify_power2round_mask_batch` verifies boolean mask bits, `A < q`, and `A == sum 2^j bits[j] mod q` under the expected transcript label. `CertifiedPower2RoundMaskBatch` can be converted into `ConsumedPower2RoundMaskBatch` only through a `Power2RoundMaskUseLog`, and `InMemoryPower2RoundMaskUseLog` rejects reused mask batch ids. Vector canonical bit decomposition now consumes a certified mask batch before opening `C = r + A`. Tests cover transcript-bound mask ids, redacted debug output, one-time consumption, wrong-label rejection, non-boolean mask-bit rejection, and bad mask-value rejection.
  Current update 27: Power2Round mask consumption now has a file-backed crash-safe log. `FilePower2RoundMaskUseLog` persists only `(lane_count, label_hash)` mask-batch ids, never mask values or bits, and rejects duplicate consumed ids on reopen. Malformed log lines fail closed with `Power2RoundMaskUseLogCorrupt`. Tests cover reopen persistence, duplicate append/reuse rejection, corrupt log rejection, and in-memory reuse rejection.
  Current update 28: precomputed Power2Round mask batches now have a production-shaped API. `precompute_certified_power2round_mask_batch` generates and certifies a full vector mask batch under the intended `Power2Round/.../mask` label without marking it consumed. `canonical_bit_decompose_mod_q_vec_with_certified_mask` accepts only a certified batch whose id matches the decomposition label and lane count, then consumes it through the caller-supplied `Power2RoundMaskUseLog` immediately before opening `C = r + A`. Tests prove precompute leaves the durable use log empty, the decomposition step records the consumed id, restart observes the consumed id, reuse is rejected, and wrong decomposition labels fail before consumption.
  Current update 29: the per-party Power2Round driver skeleton now requires a certified precomputed mask batch for the first phase. `ProductionPower2RoundPerPartyDriver::accept_precomputed_masks` records the mask batch id and advances from `GenerateCanonicalMasks` to `OpenMaskedValues`; calling the generic phase acceptor for `GenerateCanonicalMasks` fails with `Power2RoundCertifiedMaskRequired`. `resume_after_precomputed_masks` restores the driver directly at the masked-opening phase from a persisted mask id. Tests cover phase ordering, certified-mask requirement, mask-id recording, and restart-style resume after mask precompute.
  Current update 30: vector masked openings are now driven through the per-party prime-field MPC runtime. `TransportPrimeFieldMpcPartyRuntime` and its cursored wrapper expose vector broadcast send/collect phases backed by durable wire logs, and `collect_broadcast_phase_vec_from_wire_log` can recover accepted vector openings after restart. `ProductionPower2RoundPerPartyDriver` no longer treats `OpenMaskedValues` or `RecoverCanonicalBits` as generic phase markers: masked openings must be accepted with a nonzero lane count matching the certified mask batch, canonical-bit recovery must match the opened lane count, and later phases fail until canonical-bit recovery is recorded. Tests cover delayed vector broadcast collection, durable recovery from accepted vector wire logs, typed masked-opening lane validation, typed canonical-bit-recovery lane validation, and resume after precomputed masks.
  Current update 31: the vector masked-opening computation is now a named Power2Round operation. `open_power2round_masked_c_vec` takes `[t]` lanes plus a consumed certified mask batch, validates lane shape against the consumed mask id, computes `[C] = [t] + [A_mask]`, and opens the vector under the canonical `open_masked_c` transcript child. The transport runtime also exposes `drive_power2round_masked_c_vec` and `drive_collect_power2round_masked_c_vec`, so callers no longer manually assemble the `Power2RoundMaskedOpenC` phase constants. Tests cover the arithmetic, transcript label, delayed collection, and durable recovery path.
  Current update 32: vector wrap comparison is now a named Power2Round operation. `power2round_wrap_compare_vec` validates the opened `C` vector against the consumed mask batch, rejects noncanonical opened values, and computes secret wrap bits `[A_mask > C]` under the canonical `a_gt_c` transcript child. The transport runtime also exposes `drive_power2round_wrap_compare_vec` and `drive_collect_power2round_wrap_compare_vec` for reliable-broadcast vector payloads. Tests cover comparison truth values, malformed lane counts, noncanonical `C`, delayed vector collection, and durable recovery from accepted wrap-comparison wire logs.
  Current update 33: vector canonical `R` bit recovery is now a named Power2Round operation. `power2round_recover_canonical_r_bits_vec` validates opened `C` values and consumed mask shape, then computes `R = C + q*wrap - A_mask` with the vector subtractor under the canonical `recover_r_bits` transcript child. The runtime exposes vector subtractor send/collect helpers for each subtractor bit, backed by reliable-broadcast vector payloads and durable wire-log recovery. Tests cover recovered bit recombination against expected `R`, malformed wrap length rejection, wrong `C` lane count rejection, delayed subtractor collection, and durable subtractor recovery.
  Current update 34: post-recovery canonical checks are now named Power2Round operations. `power2round_assert_r_bits_boolean_vec`, `power2round_assert_r_lt_q_vec`, `power2round_assert_r_bits_equal_t_vec`, and `power2round_certify_canonical_r_bits_vec` certify the recovered `R` bits before any high bits are opened. Vector reliable-broadcast runtime helpers now exist for `R < q` and `sum 2^j R_j == t mod q` check phases. Tests cover valid certification plus non-bit witness rejection, `R >= q` rejection, equality failure rejection, delayed canonical-check collection, and durable range-check recovery from wire logs.
  Current update 35: add-4095 and public `t1` opening now have named Power2Round vector operations and runtime phases. `power2round_add_4095_vec` wraps the vector ripple adder under the canonical `add_4095` transcript child, and `power2round_open_t1_bits_vec` opens only bits 13..22 under the canonical `open_t1_bits` path. The runtime exposes vector send/collect/recover helpers for add-4095 carry/share phases and `T1BitOpening` phases. Tests cover FIPS boundary parity, delayed add-4095 and `t1` bit vector collection, and durable recovery of those vector wire records.
  Current update 36: the vector Power2Round path now has a single packed-public-output boundary. `power2round_public_t1_from_coeffs` packs opened high-bit coefficients into `PublicT1`, and `power2round_certify_public_t1_evidence` emits transcript-bound `Power2RoundEvidence` from those packed bytes. `ProductionPower2RoundPerPartyDriver` now requires typed add-round-constant lane output, typed opened `PublicT1`, and matching public evidence before it can complete; generic phase acceptance for `AddRoundConstant`, `OpenT1Bits`, or `CertifyEvidence` now fails closed. Tests cover packing/evidence hash binding and final driver phase enforcement.
  Current update 37: the cursored Power2Round runtime now stitches the final vector phases into the production driver. `drive_collect_power2round_masked_c_vec_and_advance`, `drive_collect_power2round_add4095_all_vec_and_advance`, and `drive_collect_power2round_t1_bits_and_certify` collect live transport messages or recover accepted vector records from durable wire logs, then advance the typed driver. The `t1` path reconstructs opened high-bit vectors, packs `PublicT1`, emits `ProductionItMpc` evidence, and completes the driver after restart without regenerating phase material. Tests drive add-4095 and `t1` bit phases through the cursored runtime, rebuild from accepted logs, and certify the same public output.
  Current update 38: the cursored Power2Round runtime now stitches the earlier canonical-recovery phase set into the same typed driver. `drive_collect_power2round_canonical_recovery_all_vec_and_advance` requires accepted/recovered wrap-comparison, all 24 subtractor bit phases, canonical `R < q`, and equality-check vector records with a consistent lane count before advancing `RecoverCanonicalBits`. The production vector-driver test now drives masked opening, wrap comparison, subtractor, canonical range/equality, add-4095, and `t1` bit phases through cursored transport logs and certifies the final output from recovered durable records.
  Current update 39: canonical `R` bitness now has an explicit vector runtime phase instead of living only inside the local helper. `PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck` has stable wire encoding, state-machine broadcast/collect helpers, cursored runtime helpers, durable log recovery, and participation in `drive_collect_power2round_canonical_recovery_all_vec_and_advance`. Tests cover delayed/recovered bitness vector broadcasts and the full production vector-driver path now requires wrap comparison, subtractor phases, bitness checks, range checks, and equality checks before `RecoverCanonicalBits` can advance.
  Current update 40: production public-key assembly now has a typed Power2Round output boundary. `ProductionPower2RoundOutput` can only be constructed from `ProductionItMpc` evidence whose transcript hash, `rho` hash, party-set hash, suite, epoch, and `t1` hash match the DKG assembly label and packed `PublicT1`. `drive_collect_power2round_t1_bits_and_certify` now returns this typed output instead of a raw `(PublicT1, Power2RoundEvidence)` tuple. `assemble_public_output_from_production_power2round` accepts only the typed output, while the generic scaffold assembly path also verifies backend evidence against the public `t1`. Release gates now reject key packages whose Power2Round evidence does not match the actual package `rho/t1/config`, preventing simulator output from being relabeled as production by mutating the backend id.
  Current update 41: the logged native DKG production assembly entry point no longer accepts a generic `MpcPower2RoundBackend`. `assemble_logged_native_dkg_production_from_logs` now requires a pre-certified `ProductionPower2RoundOutput` produced by the per-party Power2Round driver, then combines it with recovered production IT-VSS setup logs and release-valid setup certificates. The old generic backend route remains only on scaffold/test assembly wrappers. A regression test drives application setup logs, creates typed production Power2Round evidence, and verifies that the production assembly function returns `ProductionNativeDkgAssemblyOutput` without accepting a backend parameter.
  Current update 42: the generic scaffold assembly APIs are now quarantined from normal builds. `assemble_public_output_scaffold`, `assemble_logged_native_dkg_scaffold_from_logs`, and `assemble_logged_native_dkg_with_production_it_vss_from_logs` are hidden behind `cfg(test)` or the explicit `scaffold-dev` feature and marked `doc(hidden)`. Normal crate users only see the production assembly route that consumes `ProductionPower2RoundOutput`. A source-level regression test asserts the production entry point does not mention `MpcPower2RoundBackend` in its signature and that all scaffold assembly entry points remain gated.
  Current update 43: simulator/dev Power2Round backends now have an explicit `dev_backends` namespace behind `cfg(test)` or the `scaffold-dev` feature. Direct simulator backend types (`LocalPrimeFieldMpcBackend`, Shamir simulators, transport-backed simulators, clear simulator, and test wrappers) are marked `doc(hidden)`, so production-facing docs/API emphasize the typed production assembly route rather than local correctness harnesses. The API regression test now checks both scaffold assembly gating and dev-backend quarantine markers.
  Current update 44: the Power2Round split is now physical, not only a namespace veneer, for the deterministic local prime-field simulator. `LocalPrimeFieldMpcBackend` and its `ItMpcPrimeFieldBackend` implementation moved into `power2round/dev_backends.rs` under `cfg(test)`, while the production `power2round.rs` module keeps the protocol types, wire phases, vector operations, and typed production assembly boundary. Normal workspace and `scaffold-dev` checks now build without simulator dead-code warnings, and regression tests cover the local vector backend plus API quarantine.
  Current update 45: the in-process Shamir Power2Round simulator has also moved physically into `power2round/dev_backends.rs` under `cfg(test)`. The production module no longer owns its struct or `ItMpcPrimeFieldBackend` implementation; tests import it through the dev-backend namespace. The API quarantine test now verifies that only the remaining network/transport simulator bodies are still in the parent module, while local and in-process simulator bodies live in the dev module.
  Current update 46: production Power2Round label hashing is now decoupled from the networked simulator type. Runtime and tests use the neutral `power2round_label_hash`, and the networked Shamir simulator plus its in-memory network transcript/message structs moved into `power2round/dev_backends.rs` under `cfg(test)`. Release hardening also now includes `ensure_prime_field_mpc_counters_vectorized_for_release`, which rejects scalarized MPC counters, and `ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release`, which rejects scalar-per-coefficient or outside-domain IT-VSS public artifacts in production release context checks.
  Current update 47: the Power2Round dev split and production output validator are tighter. The transport-backed Shamir simulator now lives in `power2round/dev_backends.rs`, the removed runtime-coordinated Shamir simulator is no longer exported from the parent module, and simulator-only Shamir helper functions are `cfg(test)` so normal builds stay warning-free. Scaffold small-residue certificate bundles are test-only, scaffold assembly outputs are hidden from rustdoc, and `ProductionNativeDkgAssemblyOutput::ensure_context_allowed_for_release` plus `ensure_production_native_dkg_output_context_allowed_for_release` provide the narrow product-facing release validator for typed production outputs.

## Review Notes From `talus.md`

- The document is implementation-oriented and has a sensible order: `fips204` reuse/adapters first, TALUS arithmetic second, MPC backend third, then local protocol, signing, malicious tests, and productionization.
- Do not rewrite standard ML-DSA from scratch. Use `fips204` for standard keygen/sign/verify/encoding behavior, and expose/fork/vendor only the narrow internals TALUS needs.
- The initial implementation should avoid networking and full DKG. Start with deterministic, in-process protocols and test transports.
- The final signature verification gate is non-negotiable: no API may return a signature unless the standard `fips204` verifier path accepts it outside the TALUS assembly code.
- The CEF formula is inconsistent in the document. Section 6 says `... - c - delta`, while Section 11.6 says `... - c + delta`. Treat this as a spec erratum: implement `+ delta` only, and add boundary tests that fail if `delta` is subtracted.
- Do not name the CEF carry bit `c` in code, because ML-DSA already uses `c` for the challenge polynomial. Use `kappa`, `rho_carry`, or `mask_carry`; the plan uses `kappa`.
- TALUS-MPC cannot offline-check BCC without reconstructing `Ay`. Implementation should model this as retry/verify-failure behavior for MPC signing, while still implementing `bcc_holds` for tests, local oracle flows, and theorem checks.
- `trusted-dealer-test` should exist only behind a test-only feature and should be excluded from release builds by CI.

## Information Needed

These are the decisions that affect implementation shape:

- Minimum supported Rust version and edition policy.
- Whether crates should be publishable independently or kept as private workspace crates.
- Preferred ML-DSA implementation: depend directly on `fips204` and ACVP-shaped vectors. TALUS-owned ML-DSA code should be limited to adapters and missing internal hooks. Tidecoin consensus-wrapper compatibility belongs in downstream integration tests, not in the TALUS crate dependency graph.
- Supported API surface for the first release: library only, CLI, or daemon/service.
- Target runtime for async protocol APIs: runtime-agnostic traits, Tokio, or sync-first deterministic engine.
- Persistence backend for session counters and consumed tokens: file, SQLite, sled/redb, or caller-provided trait.
- Transport threat model: authenticated channels supplied by caller, built-in TLS/noise, or test transport only for now.
- Production malicious-MPC path: honest-majority IT-MPC/VSS preprocessing over PQ-authenticated channels.
- Masked-broadcast failure path: certify consistency before challenge; post-challenge final-verify failure consumes the token and reveals no honest nonce material by default.
- DKG path: reviewed PQ key-share provisioning as an initial setup profile, native honest-majority IT-DKG/VSS mandatory; classical Pedersen/DH is test/research-only.
- Initial `(N, T)` deployment envelope and whether to enforce `N >= 2T - 1` for `T >= 3` at config validation.
- Compliance target: ACVP-compatible hooks only, or planned formal validation support.

## Release Blockers

These are release blockers, not future improvements:

- [ ] Reviewed PQ key-share provisioning profile is implemented and transcript-bound.
- [ ] Native honest-majority IT-DKG/VSS is implemented.
- [ ] Bounded ML-DSA s1/s2 distributed sampling is reviewed.
- [ ] Production triple provider uses honest-majority IT-MPC/VSS certified authenticated triples; trusted-dealer triples are unavailable in release builds.
- [ ] Masked-broadcast consistency and CarryCompare are certified before challenge.
- [ ] No release path publishes or depends on exact `A*secret` images (`A*s1_i`, `A*nonce` coefficients, or `Phi = A*secret`).
- [ ] `CommitmentBackedPartialVerifier` and any public-linear-image blame path are gated to tests or explicit insecure paper-compatibility builds.
- [ ] Strict production signing exposes no rejected `z_i`, aggregate `z`, hints, validity bits, or failure reasons.
- [ ] Current clear partial-signature adapters are gated as local/test or explicit research/paper-compatibility builds, not production.
- [ ] Post-challenge reveal-on-failure is disabled by default; any forensic test path has separate proof and review.
- [ ] Token and session persistence prevents nonce/session reuse across crashes.
- [ ] Transport provides authenticated P2P channels and equivocation-resistant broadcast.

## CEF Spec Erratum

Use this formula as the implementation source of truth for one coefficient:

```text
alpha = 2 * gamma2
m = (q - 1) / alpha

Htilde_i = H_i + maskH_i mod m
btilde_i = b_i + rho_i

B = sum_i btilde_i
t = B mod alpha
R = sum_i rho_i

kappa = [R > t]
delta = [R < t - gamma2 + kappa * alpha]

w1 = (sum_i Htilde_i + floor(B / alpha) - kappa + delta) mod m
```

The correction term is `+ delta`. Any occurrence of `- delta` is a spec bug.

Reference implementation for one coefficient:

```rust
fn cef_w1_coeff<P: MlDsaParams>(
    masked_highs: &[u32],
    masked_lows: &[u32],
    rhos: &[u32],
) -> u32 {
    let alpha = P::ALPHA as u64;
    let gamma2 = P::GAMMA2 as i64;
    let m = P::HIGH_MOD as u64;

    let sum_h = masked_highs.iter().map(|&x| x as u64).sum::<u64>() % m;
    let b = masked_lows.iter().map(|&x| x as u64).sum::<u64>();
    let r = rhos.iter().map(|&x| x as u64).sum::<u64>();
    let t = b % alpha;

    let kappa = u64::from(r > t);
    let delta_threshold = t as i64 - gamma2 + (kappa as i64) * (alpha as i64);
    let delta = u64::from((r as i64) < delta_threshold);

    ((sum_h + (b / alpha) + delta + m - kappa) % m) as u32
}
```

## Milestone 0: Workspace And Guardrails

Checklist:

- [x] Create Cargo workspace with `talus-core`, `talus-mpc-core`, `talus-dkg`, `talus-mpc`, `talus-wire`, `talus-tests`, and `talus-bench`.
- [x] Add workspace lint policy: deny unsafe by default, deny missing docs later, deny accidental debug formatting for secret types where practical.
- [x] Add features: `std`, `alloc`, `serde-wire`, `test-dealer`, `bench`, and `fips204-adapter`.
- [ ] Add CI scripts for `cargo fmt`, `cargo clippy`, `cargo test`, feature matrix, and release feature guard.
- [x] Add `SECURITY.md` with explicit non-production status until Milestone 9.

Verification:

- [x] TALUS package `cargo fmt --check`
- [x] `cargo clippy --workspace --all-targets --all-features`
- [x] `cargo test --workspace`
- [x] `cargo test --workspace --all-features`
- [x] Release build fails if `test-dealer` is enabled.

## Milestone 1: `talus-core` fips204 Adapter

Implementation steps:

- [x] Define `MlDsaParams` and suites `MlDsa44`, `MlDsa65`, `MlDsa87`.
- [x] Add `fips204` as the standard ML-DSA dependency.
- [x] Decide the internal-hook strategy: use a narrow vendored adapter copied from `fips204` internals with attribution and parity tests.
- [ ] Expose or adapt `Coeff`, `Poly`, `PolyVecL`, `PolyVecK`, and `MatrixA` only to the extent needed for TALUS `A*y`, `A*z`, BCC, hints, and CEF tests.
  Current status: a FIPS-sized `Poly`/`PolyVec` adapter is present for coefficient-wise arithmetic, sparse challenge multiplication in `Z_q[x]/(x^256+1)`, infinity norm, `z` bound checks, public-key `t1` decoding, `t1*2^d`, `c*t1*2^d`, `ExpandA`, NTT/inverse NTT, NTT-backed `A*z`, and `w'_approx = A*z - c*t1*2^d`. Typed `PolyVecL`/`PolyVecK` wrappers remain pending.
- [ ] Reuse `fips204` modular reduction, centering, NTT, hashing, encoding, and matrix/vector code where possible; avoid a clean-room arithmetic backend.
- [x] Expose/adapt FIPS `Power2Round`, `Decompose`, `HighBits`, `LowBits`, `MakeHint`, and `UseHint`.
- [x] Implement unsigned TALUS decomposition: `high_bits_unsigned` and `low_bits_unsigned`.
- [ ] Reuse/expose FIPS encodings, `ExpandA`, challenge hash, `SampleInBall`, `mu`, public `r`, and verifier from `fips204` where possible.
  Current status: FIPS Algorithm 23 public-key decode, Algorithm 28 `w1Encode`, SHAKE256 `mu`, SHAKE256 variable-length `ctilde`, Algorithm 29 `SampleInBall`, Algorithm 32 `ExpandA`, FIPS NTT/inverse NTT, NTT-backed `A*z`, and Algorithm 26-compatible signature encoding are implemented in the narrow adapter.
- [ ] Add independent oracle cross-checks against `fips204` and ACVP-shaped vectors where APIs expose enough internals.
  Current status: direct `fips204` public API tests are present; ACVP-shaped vector hooks remain pending.

Verification:

- [x] Adapter code is traceable to `fips204` or explicitly marked TALUS-specific.
- [x] Parameter constants match FIPS 204 for all three suites.
- [x] `fips204_adapter_matches_upstream_verify_all_params`.
- [x] `fips204_adapter_matches_upstream_signature_encoding_all_params`.
- [x] `fips204_verifier_wrapper_uses_public_key`.
- [ ] `poly_mul_ntt_matches_schoolbook_for_random_inputs` for any local/vendored arithmetic.
- [ ] `ntt_inverse_ntt_roundtrip` for any local/vendored NTT.
- [x] Sparse challenge multiplication handles identity and negacyclic boundary shifts.
- [x] `z_bound_holds` enforces the strict `gamma1 - beta` signing bound.
- [x] Public key lengths match FIPS parameters and public-key decode extracts `rho`/`t1`.
- [x] `public_approx_from_az` subtracts `c*t1*2^d` from supplied `A*z`.
- [x] `ntt_inverse_ntt_roundtrip`.
- [x] NTT-backed `A*z` matches schoolbook multiplication for representative expanded matrices.
- [x] `decompose_reconstructs_mod_q`.
- [x] `decompose_special_q_minus_one_boundary_case`.
- [x] `use_hint_matches_fips`.
- [x] FIPS `w1Encode` output lengths match all three suites.
- [x] `ctilde` length is `lambda / 4` for ML-DSA-44/65/87, and `SampleInBall` returns exactly `tau` nonzero coefficients in `{-1, 1}`.
- [ ] ACVP-compatible `keyGen`, `sigGen`, and `sigVer` hooks compile and parse vector-shaped JSON.
- [ ] Valid signatures verify internally and directly with `fips204`.
  Current status: `fips204` direct verification and a reusable `Fips204Verifier` helper pass; final emitted TALUS signatures remain pending.

## Milestone 2: TALUS Arithmetic, BCC, Hints, And CEF

Implementation steps:

- [x] Implement coefficient/slice-level `bcc_holds`.
- [x] Implement coefficient/slice-level public TALUS hint computation from `r` and `w1`.
- [x] Lift BCC and hint helpers to typed `PolyVec` inputs.
- [x] Implement coefficient-level clear CEF reconstruction.
- [x] Implement coefficient-level masked CEF reconstruction using public carry and correction bits.
- [ ] Lift CEF reconstruction to vector/polynomial types once the fips204 adapter exposes them.
- [x] Implement clear helpers for `kappa = [sum rho > t]` and `delta = [sum rho < t - gamma2 + kappa * alpha]`.
- [x] Use the CEF formula `sum(Htilde) + floor(B / alpha) - kappa + delta mod HIGH_MOD`.
  Current code asserts the TALUS precondition `sum(rho_i) < alpha`; Milestone 4 must enforce this with authenticated range checks before release.

Verification:

- [x] `bcc_safety_representative_ml_dsa_44`.
- [x] `bcc_safety_representative_ml_dsa_65`.
- [x] `bcc_safety_representative_ml_dsa_87`.
- [x] `hint_public_identity_representative`.
- [x] `cef_identity_clear_representative`.
- [x] `cef_identity_masked_representative`.
- [ ] `cef_identity_boundary_q_minus_one`.
- [x] Boundary test: `bsum = gamma2 + 1`, `R = 0`, so `kappa = 0`, `delta = 1`, and expected high part increments by one.
- [x] Boundary test: `bsum = alpha - 500`, `R = 1000`, so `kappa = 1`, `delta = 1`, and expected high part increments by one after carry correction.
- [x] Boundary test: `bsum = gamma2`, `R = 0`, so `delta = 0`, catching strict-boundary off-by-one errors.
- [x] Boundary test: `bsum = alpha - 1`, `R = 0`, so direct signed low part is `-1` and expected high part increments by one.
- [x] Tests prove `- delta` fails at selected boundary vectors.
- [ ] Monte Carlo BCC rates are close to documented theory.

## Milestone 3: `talus-mpc-core`

Implementation steps:

- [x] Implement `Gf128` over `x^128 + x^7 + x^2 + x + 1`.
- [x] Implement authenticated share types, MAC key shares, and local share arithmetic.
- [x] Implement `open_checked` and `open_many_checked`.
- [x] Implement authenticated Beaver multiplication.
- [x] Implement `AuthBit`, XOR, NOT, AND, half adders, full adders, and public constants.
- [x] Add test-only trusted dealer for authenticated shares and triples.
- [x] Add triple-use tracking.

Verification:

- [x] GF(2^128) field laws and known vectors.
- [x] `open_checked_valid`.
- [x] Bad value share and bad MAC share fail before output is used.
- [x] Beaver multiplication matches clear multiplication.
- [x] AND/XOR/NOT truth tables.
- [x] Triple reuse is rejected.

## Milestone 4: CarryCompare

Implementation steps:

- [x] Implement authenticated `AuthU19`.
- [x] Implement bitness checks.
- [x] Implement range checks against `floor(alpha / |S|)`.
- [x] Implement constant-topology `sum_u19`.
- [x] Implement `gt_public` and `lt_public`.
- [x] Implement `carry_compare<P>`.
- [x] Batch openings and MAC checks so `kappa` and `delta` are not released until checks pass.

Verification:

- [x] Exhaustive comparator tests for reduced widths.
- [x] Random U19 comparison tests.
- [x] CarryCompare matches clear computation for all parameter sets and representative `(N, T)`.
- [x] Invalid bit, out-of-range rho, bad triple, and MAC failure abort before `kappa` or `delta` is made available.

## Milestone 5: Local In-Process TALUS-MPC Preprocessing

Implementation steps:

- [x] Implement deterministic in-process party harness.
- [x] Implement session IDs, transcript binding, and uniqueness checks.
- [x] Implement nonce share generation with test-only dealer or local VSS harness.
  Current status: coefficient-vector local harness stores zeroizing local `y_share` material and nonce commitments; product VSS remains a release blocker.
- [x] Implement pairwise high masks.
- [x] Implement rho derivation and authenticated input binding.
- [x] Implement simultaneous commit/open broadcast for masked messages.
- [x] Add optional masked-broadcast consistency hardening hook.
  Current status: `talus-mpc` exposes `MaskedBroadcastConsistencyVerifier`, public statement/proof containers, a clear deterministic verifier for local audit openings, a product ZK verifier placeholder that returns a typed blocker, and `CutAndChooseAuditPlan` for separating audited openings from certifiable token candidates. This is optional product hardening, not the TALUS paper's required path. The paper path is reveal-on-failure blame after final verification failure.
- [ ] Implement production pre-challenge masked-broadcast consistency certification.
- [ ] Implement production pre-challenge private CarryCompare certification.
- [ ] Disable post-challenge reveal-on-failure by default; any forensic test path requires separate proof and review.
- [x] Implement token certification object.

Verification:

- [x] Certified token contains `w1`, signer set, session ID, nonce commitments, transcript hash, and zeroizable `y_share`.
- [x] Duplicate, replayed, or equivocated messages fail certification.
- [x] Mismatched clear masked-broadcast openings fail consistency verification before token certification.
- [x] Optional hardening ZK proof backend returns a typed blocked error until reviewed implementation exists.
- [ ] Final verification failure consumes the token, releases no signature, and reveals no honest nonce material.
- [x] Token cannot enter pool without certification.
- [x] Session ID reuse is fatal.

## Milestone 6: Online Signing

Implementation steps:

- [x] Implement `SignRequest` validation.
- [x] Implement challenge computation from `tr`, `M'`, `mu`, and encoded `w1`.
  Current status: challenge computation now uses FIPS-compatible SHAKE256 `mu`, Algorithm 28 `w1Encode`, variable-length `ctilde = H(mu || w1Encode(w1), lambda/4)`, and exposes `ctilde` as bytes rather than assuming ML-DSA-44's 32-byte length.
- [x] Implement local/test partial `z_i = y_i + c * s1_i`.
  Current status: typed polynomial helpers compute clear `z_i` from FIPS `ctilde`, local `y_i`, and `s1_i`; the online layer validates session/signer/challenge binding for typed partials, and `sign_polynomial_with_token` now drives token consumption, typed share lookup, partial computation, aggregation, FIPS candidate encoding via `A*z`, and the final verifier gate. This is not the strict production no-rejected-`z` signing backend because rejected clear partials can exist in the adapter/coordinator path.
- [x] Persist token consumption before sending `z_i`.
- [ ] Replace clear partial `z_i` transport with strict private MPC response checks for production.
- [ ] Gate `CommitmentBackedPartialVerifier` and public-linear-image blame as test/research only.
- [ ] Implement strict private batch selection so only selected valid `ctilde/z/h` opens.
- [x] Aggregate `z` with Lagrange coefficients.
  Current status: additive-share aggregation remains available for deterministic local tests. `talus-core` now exposes Lagrange coefficients at zero and Lagrange-weighted `PolyVec` aggregation over the ML-DSA modulus; `talus-mpc` exposes `assemble_polynomial_response_lagrange` and a `PolynomialAggregation::LagrangeAtZero` mode for typed online signing. Product key-share generation still has to provide shares at the matching public interpolation points.
- [x] Check `z` norm, compute public hint, enforce hint weight, encode signature.
  Current status: strict `z` norm checking, typed public TALUS hint computation, `omega` enforcement, and FIPS Algorithm 26-compatible signature candidate encoding are implemented. The resulting candidate is still not returned without the independent verifier gate.
- [x] Run independent final FIPS verification before returning.
  Current status: verifier is an injected `FinalVerifier` trait, and `FipsFinalVerifier<P>` verifies final signature bytes with the upstream `fips204` public verifier. Requests using externally supplied `mu` are rejected by this verifier because they cannot be independently checked against the original FIPS message path.
- [x] Implement retry policy and observability counters.
  Current status: retry exists for both the byte-oriented adapter shell and the typed polynomial signing entrypoint.

Verification:

- [ ] Honest end-to-end signing for all parameter sets.
- [x] Single attempt may fail without output.
- [ ] Multi-attempt signing succeeds at expected rates.
- [x] Local/test wrong `z_i` returns `Blame(i)`.
- [ ] Production wrong-response handling uses non-revealing checks; no public `A*s1_i` blame.
- [x] Commitment-backed partial verification accepts matching `A*y_i`/`A*s1_i` commitments and blames altered `z_i` in the local/paper-compatible test path.
- [x] Commitment-backed partial verification rejects missing commitments and malformed commitment vector lengths.
- [x] Typed polynomial partials with wrong session/signer/challenge binding return `Blame(i)`.
- [x] Aggregated typed `z` at the strict `gamma1 - beta` boundary is rejected.
- [x] Lagrange aggregation reconstructs typed polynomial partials at zero and rejects duplicate interpolation points.
- [x] Signature candidate encoding rejects hint weight over `omega`.
- [x] Final verify failure consumes token and retries without blame.
- [x] Consumed token cannot sign again.
- [x] `FipsFinalVerifier` accepts valid upstream FIPS signatures and rejects modified signatures.
- [x] Typed polynomial signing consumes a certified token, fetches per-party `y_i`/`s1_i` shares, emits a FIPS-shaped candidate, and returns only after the injected final verifier accepts it.
- [x] Missing or misbound typed online shares fail after token consumption and before any signature output.

## Milestone 7: Malicious Tests, Persistence, And Side Channels

Implementation steps:

- [x] Add malicious party simulators for preprocessing, MPC, wire, and online signing.
  Current status: `talus-tests` now contains deterministic adversarial simulators for wire, preprocessing, online signing, and MPC-core. Wire cases cover bad magic/version fields, unknown suite/round/payload kind, payload length mismatch, cross-session and cross-suite replay, wrong keygen transcript, unknown sender, duplicate sender, dropped sender, wrong round, malformed commit payloads, malformed sign-request flags, mismatched masked-open vectors, and trailing payload bytes. Preprocessing cases cover empty signer sets, duplicate party inputs, coefficient-count mismatch, invalid high/low values, replayed session ids, equivocated masked highs, mutated commitment salts, wrong transcript hashes with valid commitments, duplicate opened parties, and uncertified token-pool candidates. Online cases cover wrong request session, wrong signer set, wrong token transcript hash, wrong partial session/challenge binding, final verifier rejection, consumed-token reuse, and retry exhaustion after final-verifier failures. MPC-core cases cover bad MAC openings, bad input MACs, bad Beaver triple `c` MAC shares, MAC-valid but relation-invalid triple candidates, reused triples, non-bit authenticated inputs, and insufficient triple supply.
- [x] Add crash/restart tests around counters and consumed-token persistence.
  Current status: online signing uses a `TokenConsumptionStore` trait instead of a concrete in-memory store. `ConsumedTokenStore` remains the deterministic in-memory implementation, and `FileConsumedTokenStore` is a `std` file-backed log for crash/reopen tests. Signing checks consumed state before taking a token, persists consumption before partial work, and tests prove a restored token is blocked after reopening the store. Preprocessing now has matching `SessionStore` and `SessionCounterStore` traits, plus `FileSessionRegistry` and `FileSessionCounter` crash/reopen test backends.
- [x] Add secret type audit for `Debug`, cloning, serialization, and zeroization.
  Current status: manual redacted `Debug` implementations cover authenticated value/MAC shares, MAC-key shares, Beaver triple shares, authenticated bits/integers, preprocessing inputs/tokens, typed online signing shares, and service adapter structs. Focused tests assert that secret fields print as `<redacted>`. Clone/serialization review remains a production hardening item for persistent key-share types once those land.
- [x] Add deterministic property-style mutation loops for canonical encodings, CEF boundaries, signature payload lengths, and signer-set permutations.
  Current status: `talus-tests` exposes `run_deterministic_property_cases`, covering CEF boundary identities across ML-DSA-44/65/87, canonical wire message encode/decode/re-encode, trailing-byte rejection for payload codecs, FIPS signature payload lengths for all suites, and signer-set permutation canonical hashing.
- [ ] Add proptest fuzzing for canonical encodings and network reorder/drop/duplicate cases.
- [ ] Add Miri, Loom, and dudect targets where practical.

Verification:

- [ ] All malicious cases from `talus.md` map to token rejection, blame, retry exhaustion, or safe retry.
- [x] Wire adversarial cases map to deterministic decode/context/batch-validation failures.
- [x] Preprocessing adversarial cases map to `PreprocessError`, token rejection, or no certified token.
- [x] Online adversarial cases map to validation failure, `Blame(i)`, consumed token without output, or retry exhaustion.
- [x] MPC adversarial cases map to checked-opening failure, Beaver failure, product-open failure, or carry failure before returning opened values or carry bits.
- [x] Deterministic property cases pass for CEF boundaries, canonical wire encodings, signature payload lengths, and signer-set permutations.
- [ ] No invalid signature is returned in adversarial tests.
- [ ] No honest nonce material is revealed after challenge.
- [x] Reopened consumed-token persistence blocks restored token reuse.
- [x] Reopened session registry persistence blocks reused preprocessing session IDs.
- [x] Reopened session counter persistence continues from the durably advanced counter.
- [ ] Persistent counter races cannot reuse a session ID.

## Milestone 8: Production Protocol Components

Implementation steps:

- [x] Add initial `talus-wire` canonical message envelope and typed payload codecs.
  Current status: `talus-wire` now encodes and decodes fixed-width little-endian envelopes with protocol version, suite, keygen transcript hash, session id, round id, sender party id, signing-set hash, payload kind/domain, and payload length. It includes typed payload codecs for preprocessing commits, masked-broadcast opens, signing requests, partial signatures, final signatures, and DKG commit/share/complaint/finalize payloads, plus context validation, duplicate-sender checks, canonical signing-set hashing, and order-stable round transcript hashing.
- [x] Add protocol-facing triple provider abstraction.
  Current status: `talus-mpc-core` exposes `UncheckedBeaverTripleShare` and `CertifiedBeaverTripleShare` type-state separation. Multiplication, Boolean gates, CarryCompare, and `TripleProvider` consume only certified triple bundles in circuit order. The redacted `InMemoryTripleProvider` is for deterministic tests and adapter wiring. A test-only certification helper rejects MAC-valid but relation-invalid `c = a*b + delta` candidates; production relation certification/generation remains blocked. `talus-tests` exercises MPC circuits through the provider shape for triple supply and provider-exhaustion failures. No production triple-generation backend is implemented yet.
- [ ] Implement production honest-majority IT-MPC/VSS triple provider.
- [ ] Implement reviewed PQ key-share provisioning mode.
  Current status: `talus-dkg` now exposes `ProvisionedKeyShare` and `import_provisioned_key_shares` for explicit reviewed setup packages. The importer requires exactly one package per configured party, identical transcript-bound public output, nonzero ceremony transcript hash, suite-correct public-key and `t1` lengths, complete `A*s1_i` and pairwise seed commitment party sets, owner-bound secret packages, non-empty secret-share fields, and canonical typed `s1_share` bytes for the configured suite/party/interpolation point. The external reviewed provisioning ceremony and PQ channel/authentication implementation remain pending; this is not a silent trusted-dealer path.
- [ ] Implement native honest-majority IT-DKG/VSS with bounded ML-DSA sampling.
  Current status: `talus-dkg` now has the validated DKG state-machine scaffold: `DkgConfig`, `DkgSuite`, `KeygenEpoch`, `KeygenTranscriptHash`, public output containers, redacted secret-share containers, typed commit/share/complaint/finalize payloads, a deterministic `DkgLocalStateMachine` runner, bounded-sampler/VSS/pairwise-seed/transcript-store traits, transcript binding checks, explicit Shamir interpolation-point helpers tied to configured party ids, scalar Shamir helpers over the ML-DSA field (`evaluate_shamir_polynomial`, `share_scalar_with_polynomial`, `reconstruct_scalar_at_zero`), typed scalar IT-VSS share/complaint structures, canonical scalar complaint-evidence encoding/decoding, and a `ScalarItVssBackend` trait shape. `InProcessScalarItVssBackend` implements the first production-shaped local scalar VSS path: public checks, directed private shares, delivery bindings, canonical complaint evidence, verified-share complaint generation, accepted/rejected dealer resolution, and accepted-dealer scalar share combination without exposing a clear combined secret. `InProcessDistributedSmallSampler` implements the exact bounded-secret distribution simulator: each party contributes `u_i in Z_m`, `m = 2*eta + 1`; inputs are checked for bitness/range/party set/transcript label; the output residue is `sum_i u_i mod m`; and the sampled coefficient is shared as `x = r - eta mod q`. Sampled `s1` now converts to canonical `DkgSecretShare.s1_share` packages, while sampled `s2` is consumed as temporary DKG material when assembling shared `t = A*s1+s2`. `MpcPower2RoundBackend` now defines the production boundary for the non-linear public-key assembly step: input is consumed `SharedT`, output is `PublicT1` plus transcript-bound public evidence, and forbidden outputs are `t`, `t0`, `s2`, lower bits, bit-decomposition witnesses, and simulator private material. `ClearSimPower2RoundBackend`, gated by `insecure-clear-sim-power2round` or `cfg(test)`, reconstructs `t` only inside the in-process simulator, runs exact FIPS `Power2Round` coefficientwise, zeroizes `t0` temporaries, emits `InsecureClearSimulator` evidence, and produces a transcript-bound `DkgPublicOutput`; production release gates reject this backend. `DkgKeyPackage` now carries `rho`, `t1`, `public_key`, certificate, and a dedicated `DkgS1SecretShare` only, so packages do not contain `s2`, `t`, `t0`, low bits, or clear simulator material. `talus-wire` now has canonical `DkgSmallResiduePayload` encoding for bounded sampler residue inputs. `InformationCheckingVssBackend` marks the production hook for Rabin-Ben-Or-style private-channel checks. `InMemoryDkgTranscriptStore` and `FileDkgTranscriptStore` persist accepted epochs and reject reuse/corrupt logs. Tests cover valid and tampered scalar VSS deals, exhaustive sampler uniformity for `m=5` and `m=9`, all-suite bounds/shapes, no single-dealer control, malformed/equivocated/rushing sampler inputs, sampled `s1` package conversion, public-output assembly shape, FIPS `Power2Round` boundary coefficients, clear simulator parity, package exclusion of `s2/t/t0`, release rejection of the insecure backend, wire residue payloads, and durable transcript-store restart behavior. The scalar VSS, small sampler, and public-key assembly backends are still not final production IT-VSS/MPC because they are local simulators/hash-binding/scaffold checks rather than full information-checking tags, private MPC, and production `Power2Round` over PQ-authenticated channels. `talus-mpc` decodes imported `DkgSecretShare.s1_share` bytes into the online `PolyVec` shape through `polyvec_from_dkg_s1_share` and `DkgBackedPolynomialShareProvider`. `ProductionDkg::start` now enters the first commit phase, while `ProductionDkg::start_with_readiness` requires the product coordinator/readiness claim before starting. Native DKG release remains blocked until honest-majority IT-VSS, authenticated share delivery, equivocation-resistant broadcast, production complaint resolution, private MPC `Power2Round(t)`, and final public-key assembly are complete.
  Current update: `ItMpcPrimeFieldBackend` now defines the Fq arithmetic/bit backend needed for private DKG `Power2Round` without reusing the GF(2^128) TALUS carry layer. `ProductionItMpcPower2RoundBackend` implements the coefficient protocol against that trait: random canonical 23-bit mask, masked opening `C = r + A mod q`, secret wrap/subtractor recovery of canonical `R` bits, boolean/range/equality checks including `R < q`, add-4095 ripple adder, and opening only bits `13..22` as `t1`. `LocalPrimeFieldMpcBackend` is a deterministic in-process backend used for tests and full-vector parity; it is not the reviewed distributed Shamir/IT-MPC backend. Additional tests cover prime-field coefficient boundaries, noncanonical `r+q` witness rejection, non-boolean bit rejection, full-vector parity across ML-DSA-44/65/87, and no lower-bit/t0 openings. Native DKG remains blocked until the `ItMpcPrimeFieldBackend` trait is backed by reviewed distributed honest-majority IT-MPC over PQ-authenticated channels.
  Current update 2: `InProcessShamirPrimeFieldMpcBackend` now carries real per-party Shamir shares through the Fq `Power2Round` circuit and records multiplication/open labels. It implements add/sub locally on shares and multiplication/opening with local reconstruct-and-reshare for deterministic tests. This validates the distributed data model and transcript discipline, but it is still not the networked Shamir/IT-MPC backend. Simulator substrates now emit distinct `LocalPrimeFieldSimulator` or `InProcessShamirSimulator` evidence and are rejected by release gates; only a complete transport-backed backend may emit `ProductionItMpc`. Additional tests cover in-process Shamir coefficient boundaries and assert that no lower-bit or `t0` openings occur.
  Current update 3: `NetworkedShamirPrimeFieldMpcBackend` now adds a round-shaped in-memory network simulator for task-1 prime-field MPC. It records directed messages for random-bit sharing and BGW-style multiplication degree reduction, records broadcast messages for checked openings and assert-zero checks, rejects replayed `(sender, receiver, kind, label)` messages, and emits `NetworkedShamirSimulator` evidence. Tests cover networked Shamir `Power2Round` boundary coefficients, round-message recording, replay rejection, no lower-bit/`t0` openings, and release-gate rejection of the networked simulator. This is still not final production MPC: concrete PQ-authenticated transport, durable round logs, reviewed broadcast/blame behavior, and external security review remain required before any backend may emit `ProductionItMpc`.
  Current update 4: `TransportPrimeFieldMpcStateMachine` now defines the local-party transport-backed DKG private-MPC boundary. It builds canonical `DkgPrimeFieldMpcPayload` messages, sends directed field values through `AuthenticatedP2pTransport`, sends broadcast field values through `EquivocationResistantBroadcast`, validates suite/session/party-set context on collection, rejects replayed gate labels, records accepted public round metadata, and persists that metadata through `PrimeFieldMpcRoundLog` without logging masks, low bits, `t`, `t0`, `s2`, or failed-check raw values. `DkgPrimeFieldMpcPayload` now carries both a round kind and a typed phase, and the state machine exposes typed helpers for random-bit shares, multiplication degree-reduction shares, checked-opening shares, assert-zero shares, and public `t1` bit openings. `FilePrimeFieldMpcRoundLog` persists only public accepted-round metadata and rejects corrupt/replayed logs. `ProductionItMpcReadiness` gates `ProductionItMpc` on implemented per-party Power2Round, PQ-authenticated transport, durable round log, and implemented blame/abort policy; external review is audit metadata only. Tests cover directed send/collect, typed phase mismatch, wrong receiver, wrong label hash, equivocation-checked broadcast collection, broadcast equivocation rejection, wrong-suite context rejection, duplicate sender replay rejection, durable public round logging, corrupt-log rejection, and release/readiness-gate rejection of simulator backends.
  Current update 5: The transport-backed state machine now has semantic per-coefficient `Power2Round` phase helpers for mask-bit generation, mask range check, masked opening `C`, wrap comparison, subtractor/borrow recovery, canonical `R < q`, equality check, add-4095 carry/share propagation, and public `t1` bit openings. `PrimeFieldMpcRoundLog` now also persists per-coefficient completion markers, and `FilePrimeFieldMpcRoundLog` survives reopen with both accepted-round and completed-coefficient entries. `TransportBackedPower2RoundBackend` is present as the release-blocked backend skeleton and exposes the intended backend identity boundary, but `power2round_t1` deliberately returns `BlockedPendingReview` until the full coefficient arithmetic is driven by real per-party send/receive phases. Tests cover semantic coefficient phase helpers, coefficient completion replay rejection, file-backed coefficient completion persistence, and release rejection of the skeleton backend. This is still not the final production `Power2Round` backend: the all-parties simulator still has to be fully split into real per-party arithmetic execution before any backend may emit `ProductionItMpc`.
  Current update 6: `TransportBackedShamirPrimeFieldMpcBackend` now runs multiplication degree reduction, checked openings, assert-zero checks, random-bit contribution sharing, coefficient `Power2Round`, and vector-level `MpcPower2RoundBackend` wiring through `TransportPrimeFieldMpcStateMachine` and canonical `talus-wire` prime-field MPC payloads. It emits `TransportBackedShamirSimulator` evidence and release gates reject it. Tests cover transport-backed Shamir coefficient boundary cases, required multiplication/open/assert-zero/random-bit/t1-opening phases, no lower-bit or `t0` openings, and release rejection of the new simulator identity. This closes the in-crate end-to-end transport-shaped simulator path, but not production MPC: it still uses an all-parties in-process scheduler and test transport, so the remaining product work is to split the scheduler into real single-party execution over application-supplied PQ-authenticated transports with durable message logs, reviewed blame rules, and external review before allowing `ProductionItMpc`.
  Current update 7: `TransportPrimeFieldMpcPartyRuntime` now wraps one local-party transport state machine plus a local durable wire-message log, so callers can drive real single-party phases: send this party's multiplication/random-bit/open/assert-zero messages, collect peer messages, replay already-sent messages after restart, and recover already accepted values from the durable log without re-querying the transport. `PrimeFieldMpcWireMessageLog` records exact canonical sent/accepted wire messages separately from the public metadata log because wire records may contain private MPC shares. `InMemoryPrimeFieldMpcWireMessageLog` and `FilePrimeFieldMpcWireMessageLog` reject conflicting replay keys, are idempotent for identical canonical messages, survive reopen, replay sent messages without regenerating masks/shares/random bits, and recover accepted directed values from the log. Tests cover logged send replay with a deliberately different regenerated value, runtime restart/replay, file-backed wire-log reopen, corrupt wire-log rejection, and accepted-value recovery without network access. The remaining production split is now narrower: the `TransportBackedShamirPrimeFieldMpcBackend` still schedules all parties internally, so vector `Power2Round` must be refactored to coordinate multiple `TransportPrimeFieldMpcPartyRuntime` instances over application-supplied PQ-authenticated transports before a backend may claim `ProductionItMpc`.
  Current update 8: `RuntimeCoordinatedTransportShamirPrimeFieldMpcBackend` now coordinates one `TransportPrimeFieldMpcPartyRuntime` per DKG party and drives coefficient `Power2Round` through the per-party runtime send/collect APIs instead of injecting every party into one state machine. The in-crate coordinator routes only messages originated by each runtime's local party, which avoids re-routing injected peer traffic, and each runtime maintains its own durable wire-message log. The backend covers random-bit contribution sharing, BGW-style multiplication degree reduction, checked openings, assert-zero checks, and public `t1` bit openings through canonical `talus-wire` prime-field MPC payloads. It emits `RuntimeCoordinatedTransportShamirSimulator` evidence and release gates reject it. Tests cover runtime-coordinated coefficient boundary cases, wire-record generation, accepted-round metadata, and the no-lower-bit/no-`t0` opening rule. Production remains blocked until this scheduler is replaced by application-supplied ML-KEM/ML-DSA-authenticated transport adapters, durable delivery/retry policy, and implemented blame/abort behavior.
  Current update 9: `talus-wire` now exposes `PqTransportSessionBinding`, a canonical session-binding object for application-supplied transport adapters. It derives the TALUS wire session id from suite, keygen transcript hash, canonical party set, ML-KEM channel/session transcript hash, and ML-DSA identity-authentication transcript hash, then produces the `ExpectedContext` used by message validation. `TransportPrimeFieldMpcStateMachine::new_with_expected_context` accepts that externally supplied context, validates it against the DKG config, and writes the adapter session id into outgoing DKG prime-field MPC wire headers. Tests cover deterministic ML-KEM-768 encapsulation/decapsulation, ML-DSA-65 identity signing/verification, duplicate party rejection, wrong identity/session/suite rejection, and DKG state-machine use of the PQ-bound session id. Production still needs a real application transport adapter, retry/delivery policy, deployment key management, and reliable-broadcast proof/review.
  Current update 10: `TransportPrimeFieldMpcPartyRuntime` now exposes a single-party phase-driver API through `PrimeFieldMpcPhaseDriverStatus` and `drive_send_directed_phase`, `drive_broadcast_phase`, `drive_collect_directed_phase`, and `drive_collect_broadcast_phase`. The driver reports explicit sent/waiting/collected states without owning sockets or scheduling peer parties. Waiting states are returned for incomplete private delivery and incomplete broadcast views; malformed, duplicate, wrong-context, and equivocated messages remain hard errors. The test harness now drives phases by routing messages between independent party runtimes instead of injecting all parties into one state machine, and covers delayed private delivery, reordered private delivery, duplicate private delivery, broadcast missing-view waits, broadcast equivocation, sent-message replay after restart, and accepted-value recovery from the durable wire log. This replaces the coordinator for phase-level transport tests, while full vector `Power2Round` still needs to move from deterministic in-crate scheduling to the application-supplied transport adapter.
  Current performance note: private `Power2Round` must not remain scalarized for production DKG. The scalar per-coefficient transport path is a correctness stress path only. For ML-DSA-44, `t` has 1024 coefficients; the current scalar private bit circuit performs hundreds of MPC multiplications/checks per coefficient and routes millions of in-memory delivery/log records when run full-vector through the transport harness. Production DKG must add vectorized IT-MPC primitives (`ShareVec`, `BitShareVec`, batched openings, batched zero checks, and multiplication-by-layer scheduling) so `Power2Round([t]) -> t1` scales by circuit depth over vector payloads, not by `depth * coefficient_count` scalar transport phases. Full-vector scalar transport tests must be slow/ignored/benchmark-only; default tests should use coefficient-level transport conformance plus fast vector parity.
  Current update 11: `PrimeFieldMpcPhaseCursor`, `PrimeFieldMpcPhaseCursorLog`, `InMemoryPrimeFieldMpcPhaseCursorLog`, and `FilePrimeFieldMpcPhaseCursorLog` now persist the current prime-field MPC subphase cursor separately from sent/accepted wire messages. `CursoredTransportPrimeFieldMpcPartyRuntime` wires cursor persistence into every send/collect driver call and replays sent messages on resume while exposing the latest waiting/collected cursor to the embedding scheduler. `TransportBackedPower2RoundBackend` has been changed from a passive skeleton into a release-blocked per-party driver boundary: it can be converted into a cursor-aware runtime, and the all-at-once `MpcPower2RoundBackend` method now returns a precise `Power2RoundRequiresSinglePartyDriver` error instead of pretending a single party can synchronously return global `t1`. `DkgTransportStateMachine` and `DkgTransportPartyRuntime` now apply the same driver shape to native DKG setup phases: bounded `Z_m` residue broadcasts, VSS public-check broadcasts, VSS directed share delivery, and VSS complaint broadcasts over canonical `talus-wire` DKG payloads. Tests cover cursor resume, sampler/VSS driver routing, sparse directed VSS delivery, complaint broadcast collection, and the per-party Power2Round driver boundary. This still is not reviewed production IT-DKG/VSS: the driver carries protocol messages, but Rabin-Ben-Or-style information checking, production complaint resolution, real application transport integration, and external review remain release blockers.
  Current update 12: DKG setup phases now have their own durable wire-message log because commit/share/complaint/small-residue messages have different logical replay keys from prime-field MPC messages. `DkgWireMessageLog`, `InMemoryDkgWireMessageLog`, and `FileDkgWireMessageLog` persist exact sent/accepted canonical `WireMessage` bytes, make identical replay idempotent, and reject changed bytes for the same logical DKG message. `LoggedDkgTransportPartyRuntime` logs bounded-sampler and VSS setup messages, replays sent messages after restart without regenerating payloads, logs accepted small-residue, VSS commit, VSS share, and VSS complaint rounds, and recovers those accepted rounds from the log without transport. The bounded sampler now has logged helpers that collect or recover `SmallResidueContribution` rounds before calling `InProcessDistributedSmallSampler`, and scalar VSS now has logged adapters that encode/decode in-process public checks and directed private shares through DKG commit/share payloads, verify logged receiver shares, emit complaint payloads, broadcast complaint rounds, and recover all of those phases from logs. Tests cover replaying exact sent bytes after a changed local payload, restart replay, logged bounded-sampler collection/recovery, logged scalar VSS public-check/share verification, complaint broadcast/recovery, accepted-share recovery, file reopen, and corrupt-log rejection.
  Current update 13: Native DKG setup now has explicit phase-continuation cursors. `DkgSetupPhaseCursor`, `DkgSetupPhaseCursorLog`, `InMemoryDkgSetupPhaseCursorLog`, `FileDkgSetupPhaseCursorLog`, and `CursoredLoggedDkgTransportPartyRuntime` persist whether the local party sent, is waiting for, or collected small-residue, VSS commit, VSS share, and VSS complaint phases; small-residue cursors include vector/coefficient context. The full bounded sampler can now assemble an entire `s1`/`s2` vector from recovered logged coefficient rounds through `sample_logged_small_polyvec_from_log`, so restart does not resample or regenerate accepted residues. Scalar VSS logging now supports vector/polynomial material: one DKG commit can carry multiple in-process scalar public checks, one directed DKG share can carry a vector of private scalar shares, logged verification checks all receiver shares against the corresponding public checks, and accepted vector deals combine coefficientwise. Tests cover cursor resume, file cursor reopen/corruption, full logged `s1` recovery, vector scalar-VSS verification, and coefficientwise vector combination.
  Current update 14: `assemble_logged_native_dkg_scaffold_from_logs` now drives the native DKG assembly flow from durable logged setup state: it recovers full logged `s1` and `s2` bounded-sampler vectors, recovers and verifies logged vector VSS commits/shares/complaints, resolves accepted/rejected dealers, assembles temporary `t = A*s1+s2`, runs the selected `MpcPower2RoundBackend`, builds `pk = (rho,t1)`, produces per-party `DkgKeyPackage` outputs that retain only `s1`, and emits a `PublicKeyAssemblyCertificate` with a `DkgSetupTranscriptCertificate`. The setup certificate records sampler, VSS commit, VSS share, complaint, accepted-dealer, rejected-dealer, setup-backend, and release-blocker evidence. This is intentionally still scaffold-backed: the certificate marks missing production IT-VSS, production IT-MPC, and transport conformance as release blockers until production backends replace the in-process sampler/VSS/MPC substrates. Tests cover output binding, package shape, setup certificate contents, release blockers, and absence of retained `s2/t/t0` material in packages.
  Current update 15: Native DKG setup now has a restart/resume integration test that persists accepted small-residue wire logs and setup cursors, reconstructs a receiver runtime from those logs, resumes from the collected coefficient cursor, completes the remaining bounded-sampler/VSS setup phases, and assembles key packages from recovered logs. `talus-mpc` now accepts native `DkgKeyPackage` values directly through `DkgBackedPolynomialShareProvider::from_key_packages`, converting retained `s1` package material into the existing polynomial signing share provider without reintroducing `s2/t/t0`. The online signing test consumes a certified token and signs through the polynomial TALUS path using native DKG key packages. Final verifier behavior in that test remains scaffold-level (`AcceptVerifier`) because production-valid FIPS signatures still require production-certified preprocessing (`w1`, nonce shares, BCC/CarryCompare) and the reviewed DKG/MPC backends.
  Current update 16: DKG complaint handling now has an explicit vector policy through `resolve_in_process_scalar_vss_vector_complaints`: duplicate complaint tuples are rejected, complaint payload fields must match the embedded evidence, the evidence must bind to one public check in the dealer's vector, any valid coefficient complaint rejects the dealer's whole vector contribution, and the resolver aborts if accepted dealers fall below threshold. Logged native DKG assembly now uses that resolver instead of trusting complaint senders directly, and `DkgSetupTranscriptCertificate` preserves the accepted public complaint evidence payloads alongside transcript hashes and accepted/rejected dealer sets. Release gating is now certificate-level through `ensure_dkg_certificate_allowed_for_release`: production packages must carry `ProductionItMpc` Power2Round evidence, must include a setup certificate, must use `ProductionInformationTheoretic` setup, and must have no release blockers. Tests cover valid vector complaint rejection, duplicate complaints, tampered complaint evidence, insufficient accepted dealers, missing setup certificates, scaffold setup rejection, explicit blocker rejection, simulator Power2Round rejection, and the all-clear production-shaped certificate case.
  Current update 17: Native DKG public-output assembly now separates accepted contribution dealers from the final configured signing party set. `apply_logged_vss_commitments_to_public_output` validates the accepted dealer subset and filters only VSS contribution commitments to that subset; AS1 commitments and pairwise-seed commitments remain present for every configured signing party because those commitments bind retained signer shares and setup material, not accepted dealer contribution status. A regression test covers a rejected contribution dealer with threshold still satisfied and asserts that public output keeps all signing-party AS1/pairwise commitments while excluding the rejected dealer's VSS contribution commitments.
  Current update 18: Logged native DKG now has a complaint-positive integration test. The test drives full logged `s1`/`s2` bounded-sampler setup, broadcasts vector VSS commits, tampers dealer 2's directed VSS vector share for every receiver, verifies the resulting complaint evidence from each receiver's durable log, broadcasts and recovers the complaint round, assembles from logs, and asserts dealer 2 is rejected while threshold still holds. It also checks that the setup certificate preserves public complaint evidence and complaint hash, the public output keeps full signing-party AS1/pairwise commitments while filtering rejected VSS contributions, and key-package debug output still excludes `s2/t/t0` material.
  Current update 19: Release gating now reaches DKG key-package boundaries. `ensure_dkg_key_package_allowed_for_release` validates one package's production certificate and public-key/rho/t1 consistency. `ensure_dkg_key_package_set_allowed_for_release` validates a full package set: exact party coverage, reconstructed config, production-acceptable certificates, shared public material, shared certificate, owner-bound retained `s1` share encoding, and no scaffold/simulator/blocker states. Tests cover missing setup, simulator Power2Round, scaffold setup, explicit blockers, internally inconsistent public material, package-set public-material disagreement, certificate disagreement, empty package sets, single-package release acceptance, and the all-clear production-shaped package set.
  Current update 20: The production IT-VSS boundary is now concrete instead of only a note. `ItVssSharingLabel` binds each sharing to config hash, dealer, domain, optional coefficient/gate index, and a stable label hash. `ItVssInformationTag`, `ItVssPublicCommitment`, `ItVssPrivateShareDelivery`, `ItVssDealerOutput`, `VerifiedItVssSharingCertificate`, and `ItVssComplaintResolution` model the Rabin-Ben-Or-style information-checking artifacts for private share delivery, complaint creation, complaint resolution, and verified sharing certificates without using Feldman/Pedersen commitments. `ProductionItVssBackend` defines the production trait for share creation, private delivery verification, complaint construction, and complaint resolution. `ProductionInformationCheckingVssBackend` now implements that method boundary with the production backend identity, transcript-bound private delivery checks, hash-only public complaint evidence, and complaint-resolution certificates; separate release readiness still requires implemented IT-VSS, PQ private channels, equivocation-resistant broadcast, and implemented complaint resolution. Tests cover domain/dealer transcript binding, unknown dealer rejection, redacted private tag/share debug output, valid delivery verification, tamper complaint construction, and production certificate resolution.
  Current update 21: The bounded ML-DSA sampler now has a verified-input core. `VerifiedSmallResidueInput` carries dealer, sampler label, eta, residue, and verification provenance (`InProcessScaffold` or future IT-VSS certificate binding). `sum_verified_small_residues_mod`, `sample_verified_small_coeff`, and `sample_verified_small_polyvec` are the core sampler APIs; raw `SmallResidueContribution` inputs are now adapted through `verified_small_residue_inputs_from_scaffold_contributions` before sampling. Tests assert the verified path matches the scaffold path and rejects unverified or zero-certificate inputs.
  Current update 22: The complaint-positive logged DKG integration now includes restart recovery. After collecting and logging valid VSS complaints, the receiver runtime is rebuilt from its durable DKG wire log and setup cursor log, resumes at the collected complaint phase, recovers complaint evidence from logs only, and assembles from the restored runtime. This proves complaint evidence survives restart without live network state.
  Current update 23: `talus-dkg` now exposes a `production-release-checks` feature. Its feature-gated test exercises the package-level release gate against a clean production-shaped package set and verifies scaffold setup, simulator Power2Round, missing setup evidence, and explicit blockers are rejected.
  Current update 24: IT-VSS public artifacts now have canonical hash functions: `hash_it_vss_public_commitment`, `hash_verified_it_vss_sharing_certificate`, and `hash_it_vss_complaint_resolution`. The verified bounded-sampler path now has `VerifiedSmallResidueInput::from_verified_it_vss_certificate`, which binds a sampler input to a production `VerifiedItVssSharingCertificate` only when the DKG config hash, sampler vector/index, IT-VSS sharing label, dealer, backend id, accepted receiver set, and certificate hash are all valid. Tests cover commitment-hash sensitivity, receiver-order-insensitive certificate hashes, complaint-resolution hash stability, successful sampler-input construction, wrong-domain rejection, scaffold-backend rejection, and incomplete receiver-set rejection.
  Current update 25: `validate_it_vss_complaint_resolution` now checks the public shape of production IT-VSS complaint-resolution artifacts before they can feed bounded sampling or DKG assembly. It enforces config validity, accepted-dealer threshold, known and duplicate-free accepted/rejected sets, accepted/rejected disjointness, production IT-VSS backend ids, unique verified certificates, complaint-hash binding, complete accepted receiver sets, matching public commitments, no certificates for non-accepted dealers, and at least one certificate for every accepted dealer. Tests cover the valid resolution path plus too few accepted dealers, accepted/rejected overlap, duplicate certificates, complaint-hash mismatch, missing public commitment, missing certificate, and scaffold-backend rejection.
  Current update 26: The IT-VSS public-artifact validator is now wired into the native DKG scaffold path. Logged vector VSS resolution is converted into production-shaped `ItVssPublicCommitment`, `VerifiedItVssSharingCertificate`, and `ItVssComplaintResolution` artifacts, then validated before accepted/rejected dealers are used for public-output assembly. Logged bounded-sampler residue rounds are also adapted into certificate-backed `VerifiedSmallResidueInput` values through `scaffold_it_vss_certified_small_residue_inputs`, so the logged sampler path now exercises the same verified-input core that production IT-VSS certificates must feed. `ProductionItVssComplaintPhase` and `PRODUCTION_IT_VSS_COMPLAINT_PHASES` document the resolver skeleton: public commitments, private delivery, local verification, complaint broadcast, complaint resolution, and accepted-sharing certification. Additional tests cover scaffold IT-VSS vector-resolution conversion, certificate-backed sampler parity, ordered resolver phases, duplicate public commitments, incomplete receiver sets, and unexpected certificates for rejected/non-accepted dealers.
  Current update 27: IT-VSS public artifacts are now first-class durable setup records. `talus-wire` defines canonical `DkgItVssArtifactPayload` encodings for public commitments and complaint resolutions, including verified sharing certificates and public complaint records. `LoggedDkgTransportPartyRuntime` can persist and recover these artifacts through the DKG wire-message log under a dedicated `ItVssArtifact` phase. Scaffold-generated artifacts now use the explicit `InProcessHashBindingScaffold` backend id instead of pretending to be reviewed production IT-VSS, while setup certificates record IT-VSS artifact hashes and backend id. Release gates reject any production-shaped package whose setup certificate still carries a scaffold IT-VSS backend. The first concrete information-checking complaint evidence shape is also defined with public hashes only: dealer, receiver, tagger, label hash, expected tag hash, received-share hash, and transcript hash. Tests cover artifact wire round-trips, durable artifact persistence/recovery, scaffold backend release rejection, information-checking evidence validation, and logged assembly with persisted artifacts.
  Current update 28: IT-VSS artifact production is now separated from public-key assembly. `persist_logged_scaffold_it_vss_artifacts_from_logs` resolves logged scaffold VSS complaints and persists IT-VSS public artifacts before assembly; `assemble_logged_native_dkg_scaffold_from_logs` now only recovers and validates those artifacts, and rejects mismatches against the logged complaint decision. `DeterministicInformationCheckingVssBackend` exercises the production IT-VSS trait shape with private per-tagger tags, delivery verification, public hash-only complaint evidence, complaint construction, and accepted-dealer certificate resolution. `ensure_it_vss_artifact_log_allowed_for_release` scans encoded setup artifacts and rejects scaffold backend ids even if certificate blockers are manually edited. File-backed DKG wire-log tests now prove IT-VSS artifacts survive reopen/recovery.
  Current update 29: The deterministic IT-VSS backend is now wired through the same logged/cursored phase-driver shape as the rest of native setup. `LoggedDkgTransportPartyRuntime` can broadcast IT-VSS public commitments, send directed IT-VSS private deliveries via the DKG private-share payload, collect/recover both phases from durable logs, and persist only the resolution artifact when public commitments already came from the phase driver. Information-checking complaint evidence now includes a public delivery-transcript hash, and `validate_it_vss_complaints_against_private_deliveries` binds complaints to both the persisted public commitment and the exact accepted directed delivery without exposing raw shares or tags. Native logged assembly has negative tests for missing artifacts, missing/tampered public artifacts, and disagreement between persisted IT-VSS artifacts and the logged scalar-VSS complaint decision. Release checking is stricter through `ensure_dkg_setup_log_matches_certificate_for_release`, which scans encoded setup artifacts, rejects scaffold backend ids, recomputes IT-VSS public-artifact and resolution hashes from the durable log, and compares them with the setup certificate before accepting a production-shaped package.
  Current update 30: Logged native DKG assembly now requires bounded-sampler residue inputs to be backed by previously persisted IT-VSS public artifacts. `sample_logged_small_polyvec_from_certified_log` recovers sampler residue rounds from the durable log, checks matching IT-VSS public commitments for every dealer/vector/coefficient label, and then feeds only certificate-shaped `VerifiedSmallResidueInput` values into the sampler core; it no longer mints sampler verification artifacts during assembly. `persist_logged_scaffold_it_vss_artifacts_from_logs` now persists sampler public commitments for both `s1` and `s2` before adding scalar-VSS public artifacts and the complaint-resolution artifact. `ProductionItVssComplaintStateMachine` models the ordered public-commitment, private-delivery, verify, complaint, resolve, and certify phases, and setup cursors can now record the exact IT-VSS subphase. Release artifact scanning now rejects private setup payloads (`DkgShare`, directed private records, raw IT-VSS private deliveries, and scalar-VSS private-share encodings) so release bundles cannot accidentally contain `s2`, private delivery tags, or setup share material.
  Current update 31: Bounded-sampler residue artifact creation now goes through the `ProductionItVssBackend` trait boundary instead of hand-minting scaffold hashes. `it_vss_share_small_residue_contribution` encodes one residue contribution as transcript-bound IT-VSS secret material and asks the selected backend to emit the public commitment plus directed private deliveries; both the deterministic in-process backend and `ProductionInformationCheckingVssBackend` now exercise this path in tests, with production release still gated by `ProductionItVssReadiness`. `verify_it_vss_private_deliveries_for_receiver` is the per-party private-delivery verification phase: it checks accepted directed deliveries against persisted public commitments through the backend and emits only public hash-bound complaints. `ensure_logged_dkg_setup_matches_certificate` recomputes sampler, VSS commit/share, complaint, IT-VSS public-artifact, and IT-VSS resolution hashes from the local durable setup log and compares them with the assembly certificate. `ProductionPower2RoundPerPartyDriver` now records the ordered production driver phases for canonical masks, masked openings, canonical-bit recovery, add-4095, high-bit opening, and evidence certification; `TransportBackedPower2RoundBackend::begin_production_driver` exposes this skeleton, but the private circuit still remains a release blocker until fully driven by production per-party transport.
  Current update 49: `ProductionInformationCheckingVssBackend` is now a normal-build vector Shamir/information-checking backend instead of only an artifact identity. It Shamir-shares one whole vector-domain secret over `F_q`, emits receiver-private retained IC material for every holder/receiver pair, verifies directed private deliveries without opening unrelated shares, rejects scalar-per-coefficient labels, and produces hash-only public complaints. The bounded-sampler `s1`/`s2` vector batch path now has a production-backend test proving full-vector private deliveries verify through `ProductionInformationCheckingVssBackend`. The remaining IT-VSS production gaps are now narrower and explicit: public audit/discard tags, post-commitment vector polynomial consistency challenges, chunk sizing/counters, and final app-transport/persistence integration.
  Current update 50: Prime-field MPC release checks can now derive vector/scalar execution counters directly from durable `DkgPrimeFieldMpc` wire-message records. `ensure_prime_field_mpc_wire_log_vectorized_for_release` rejects scalar payload logs and accepts vector payload logs, so release validation can fail scalarized Power2Round/MPC execution from persisted transport evidence rather than trusting in-memory counters alone.
  Current update 51: Production vector IT-VSS now separates audited and retained tag encodings. `ProductionInformationCheckingVssBackend` emits audited holder/receiver tag material separately from receiver-private retained tags, derives public `ProductionItVssAuditRecord` entries only from audited receiver-side tags, binds the audit/discard transcript into the public commitment metadata, and verifies both audited and retained self-checks during private delivery validation. `ProductionItVssCounters` and `ensure_production_it_vss_counters_allowed_for_release` add first release/performance gates for vector sharings, vector lanes, directed deliveries, audited/retained tag vectors, audited/retained tag lanes, and consistency rounds. Tests now assert public audit-record counts, counter release acceptance, missing-audit release rejection, and bounded-sampler vector batches through the production IT-VSS backend with audited/discarded tags.
  Current update 52: Production vector IT-VSS now carries explicit vector-polynomial consistency material. For each consistency round the backend samples a private mask polynomial, sends each holder its private `gamma_{r,i}` mask evaluation, derives public masked-evaluation records `gamma_{r,i} + e_r beta_i`, binds those records into the public metadata hash, and rejects tampered gamma material during private delivery verification. Tests assert public consistency-record counts for dealer and bounded-sampler vector batches and verify gamma tampering fails. The remaining consistency hardening is to replace deterministic challenge derivation with the final post-commitment public-coin challenge flow through the application broadcast driver.
  Current update 32: The bounded-sampler IT-VSS path now has a single-call per-party driver for residue sharing: `drive_share_small_residue_it_vss` creates the backend sharing, broadcasts the public commitment, sends directed private deliveries to peers, and persists IT-VSS subphase cursors. `drive_verify_it_vss_private_deliveries` collects the local receiver's private deliveries, verifies them through the backend, broadcasts public complaints for invalid deliveries, and records verify/complaint cursors. `ProductionItVssReadiness` and `ensure_production_it_vss_readiness` now gate the production IT-VSS backend identity on implemented information checking, PQ private channels, equivocation-resistant broadcast, and implemented complaint-resolution policy; external review is audit metadata only. `DkgSetupRestartDecision`, `classify_dkg_setup_restart`, and `ensure_dkg_setup_cursors_complete_for_release` define release behavior for incomplete setup cursors after restart. `talus-mpc` now attaches a `PreChallengeCertificationPolicy` to certified preprocessing tokens, rejects token-pool admission when any required masked-broadcast, CarryCompare, BCC, persistence, or no-post-challenge-reveal condition is absent, and exposes `ensure_pre_challenge_certification_policy` as the product token-admission gate.
  Current update 33: Logged sampler IT-VSS artifact persistence can now be driven entirely from phase logs. `persist_logged_sampler_it_vss_artifacts_for_labels_from_phase_logs` selects expected sampler public commitments from accepted IT-VSS public-commitment broadcasts, verifies the local receiver's directed private deliveries through the backend, merges matching public complaint broadcasts, resolves complaints, and persists only the complaint-resolution artifact. `persist_logged_sampler_it_vss_artifacts_from_phase_logs` applies the same path to every `s1` and `s2` coefficient. This keeps the old scaffold artifact helper available for legacy tests, but the production-shaped sampler path no longer has to mint commitments from raw residue rounds during assembly. `talus-mpc` now has typed pre-challenge certification evidence: masked-broadcast consistency, CarryCompare, BCC, token persistence, and no-post-challenge-reveal policy evidence. `CertifiedToken` carries the evidence bundle plus the derived policy, and `is_certified`/token-pool admission require the evidence to match the token session and policy.
- [ ] Implement refresh/resharing.
- [x] Implement production transport abstraction and authenticated channels.
  Current status: `talus-wire` exposes runtime-agnostic `AuthenticatedP2pTransport` and `EquivocationResistantBroadcast` traits, plus an `InMemoryTransport` test bus and `PqTransportSessionBinding` for binding application-supplied ML-KEM/ML-DSA transport authentication into `ExpectedContext`. The crate intentionally does not choose or implement TCP, QUIC, libp2p, TLS, Noise, async runtime, retry policy, socket ownership, or deployment identity. TALUS crates own canonical `WireMessage` encodings, typed payloads, protocol state machines, transcript validation, and deterministic test transports; embedding software supplies the concrete networking stack, ML-KEM channel/session establishment, ML-DSA operational identity authentication, durable message logs, retransmission, and deployment key management. Protocol unit tests may use `InMemoryTransport` to model an already authenticated channel, but production transport-adapter integration tests must exercise real ML-KEM session establishment and ML-DSA party identity authentication, including rejection of wrong party keys, wrong session/context binding, downgraded suites, replayed messages, sender/header mismatches, and equivocated broadcasts. The current test harness performs deterministic ML-KEM-768 encapsulation/decapsulation and ML-DSA-65 identity signing/verification, derives a PQ-bound session id, passes it into the DKG prime-field MPC state machine, and rejects wrong identity, wrong session context, downgraded suite, and duplicate parties. The test bus validates channel sender identity against wire headers, rejects unknown parties, collects directed private rounds, collects observer broadcast views, rejects incomplete broadcast views, and detects cross-observer equivocation. Application-supplied concrete transport adapter wiring, durable message logs, retransmission, identity/key management, and reliable-broadcast proof review remain pending.
  Current update: `talus-wire` now defines `SynchronousBroadcastContract` as the product reliable-broadcast contract for embedding applications: for each `(session, round, sender)`, honest observers must deliver identical canonical `WireMessage` bytes or the adapter must report equivocation/abort; incomplete views are not progress. Conformance tests cover identical honest views, equivocation, and missing delivery.
  Current update 2: The transport tests now include an explicit application-provided PQ adapter harness rather than only direct `InMemoryTransport` calls. The harness binds an ML-KEM-768 session transcript and ML-DSA-65 operational identity transcript into `PqTransportSessionBinding`, implements the TALUS transport traits by delegating to the test bus, rejects wrong expected contexts, detects duplicate/replayed private messages, and exercises the synchronous broadcast contract's equivocation path. This still is a deterministic harness, not a shipped TCP/QUIC/libp2p transport implementation.
- [ ] Implement pre-challenge masked-broadcast and CarryCompare certification.
  Current status: optional verifier hooks and deterministic clear-audit scaffolding exist. The approved production path requires pre-challenge consistency certification and private CarryCompare certification before token admission. Post-challenge final verification failure must consume the token and reveal no honest nonce material by default. ZK, cut-and-choose, or reveal-on-failure forensic paths remain optional hardening/diagnostic test paths requiring separate proof and review.
- [ ] Add protocol versioning and upgrade/compatibility checks.

Verification:

- [ ] External review of triple provider and DKG proofs.
- [x] DKG scaffold rejects invalid party sets, duplicate/unsorted parties, invalid threshold, insufficient `N >= 2T - 1` deployment shape, transcript-binding mismatch, duplicate/missing DKG round senders, malformed directed share topology, duplicate complaints, final-output disagreement, and production start before review.
- [ ] Cross-node integration tests with network delay, reorder, duplicate, and equivocation.
  Current status: deterministic in-memory transport tests cover sender/header mismatch, unknown parties, incomplete broadcast views, and equivocation. Real cross-node tests remain pending until a concrete transport backend exists.
- [ ] Refresh then sign.
- [ ] Different signing sets.
- [ ] Long-running token pool and crash recovery tests.

## Milestone 9: Audit Package And Release Gate

Implementation steps:

- [ ] Write threat model.
- [ ] Write protocol spec matching code.
- [ ] Generate test vectors.
- [ ] Publish benchmarks and communication accounting.
- [ ] Publish private Power2Round batching benchmarks and reject scalar
      per-coefficient transport execution as a production DKG mode.
- [ ] Document known limitations.
- [ ] Freeze dependency versions and audit dependency tree.

Verification:

- [x] Release build has no `test-dealer`.
- [ ] Release build has no unreviewed `unsafe`.
- [ ] Secret types do not expose `Debug` or consensus-critical serde maps.
- [ ] All non-negotiable rules from `talus.md` are covered by tests or static checks.
- [ ] Independent verifier accepts every emitted signature in all release-gate tests.

## First Implementation Slice

Start with Milestone 0 and the `fips204` adapter subset of Milestone 1:

- [x] Create workspace and crate skeletons.
- [x] Implement `MlDsaParams` and suites.
- [x] Add the pinned `fips204` dependency.
- [x] Add direct `fips204` verification test harness.
- [x] Decide whether to patch/fork `fips204` or vendor a narrow adapter for internals currently marked `pub(crate)`: chosen narrow vendored adapter.
- [x] Expose/adapt FIPS `Decompose`, `HighBits`, `LowBits`, `UseHint` from `fips204` internals.
- [x] Implement TALUS unsigned decomposition.
- [x] Add boundary and parameter tests.

This slice is small enough to complete before committing to broader MPC implementation, and it directly attacks the highest-risk arithmetic edge case without rewriting standard ML-DSA.

## Source References Checked

## Current DKG Production Update

- [x] Production vector IT-VSS consistency challenges now require a
  label-bound public coin transcript instead of deterministic fallback
  derivation. Missing public coins abort production sharing.
- [x] `talus-wire` carries `DkgItVssArtifactPayload::PublicCoinShare`, and the
  DKG app-driver/runtime can broadcast and collect public-coin shares through
  the same durable IT-VSS artifact path.
- [x] `sampler_vector_it_vss_sharing_labels` exposes the native sampler
  whole-vector IT-VSS labels for application schedulers, and tests now drive
  app-broadcast public coins before production vector sharing.
- [x] Production IT-VSS security params now include first chunk/memory limits,
  and counters include private-delivery bytes plus public audit/consistency
  record counts.
- [x] The app-driver phase split for production vector IT-VSS is now explicit:
  prepared directed deliveries are bound by public precommitments, public coins
  are collected only after those precommitments are fixed, and final public
  metadata is derived from the public-coin transcript. Tests drive
  precommitment broadcast, public-coin collection, final metadata broadcast,
  private delivery, durable log recovery, and receiver verification.
- [ ] Remaining production work: finish vectorized production IT-MPC, wire final
  sampler -> IT-VSS -> Power2Round -> release-valid DKG output, and run
  all-suite DKG -> TALUS signing verifier tests.

- `talus.md` in this repository.
- Direct TALUS ML-DSA dependency: `fips204 = 0.4.6` with `ml-dsa-44`, `ml-dsa-65`, and `ml-dsa-87`.
- Local Cargo source for `fips204`: `~/.cargo/registry/src/.../fips204-0.4.6/src`, whose relevant internal modules are currently `pub(crate)`.
- FIPS 204 PDF from NIST: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- ACVP ML-DSA draft: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html
- TALUS paper PDF from arXiv: https://arxiv.org/pdf/2603.22109
