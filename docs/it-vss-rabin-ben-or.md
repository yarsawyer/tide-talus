# TALUS IT-VSS Rabin-Ben-Or Instantiation

This document pins the v1 production target for native TALUS IT-DKG/VSS.
It is intentionally conservative: the first reviewed implementation favors
security with abort over liveness recovery that reveals additional secret-share
material.

## Sources

Primary VSS source:

- Rabin and Ben-Or 1989, "Verifiable Secret Sharing and Multiparty Protocols
  with Honest Majority": https://doi.org/10.1145/73007.73014
  - Project summary page:
    https://cris.huji.ac.il/en/publications/verifiable-secret-sharing-and-multiparty-protocols-with-honest-ma/
  - The source model is broadcast plus pairwise private channels, honest
    majority, unconditional secrecy, and information checking without
    computational intractability assumptions.

Base sharing:

- Shamir 1979, "How to Share a Secret": degree-f polynomial sharing,
  nonzero evaluation points, and interpolation at zero.

Modern MPC follow-on:

- Chida et al., "Fast Large-Scale Honest-Majority MPC for Malicious
  Adversaries": https://eprint.iacr.org/2018/570
  - Use for the later malicious honest-majority arithmetic MPC layer with
    abort. Do not use it to replace the VSS source.

PQ infrastructure:

- NIST FIPS 204 ML-DSA:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST SP 800-185 cSHAKE/KMAC/TupleHash:
  https://csrc.nist.gov/pubs/sp/800/185/final

Reference code may be inspected only for engineering patterns:

- MP-SPDZ
- Cicada
- MPyC

These are not production dependencies for TALUS IT-VSS.

## Security Model

Parties:

```text
P_1, ..., P_n
```

Maximum corrupted parties:

```text
f
```

Required:

```text
n >= 2f + 1
```

TALUS signing threshold:

```text
T = f + 1
n >= 2T - 1
```

Sharing degree:

```text
f
```

Reconstruction threshold:

```text
f + 1
```

Network model:

```text
synchronous or partially synchronous rounds
authenticated private pairwise channels
equivocation-resistant broadcast
```

Security claim:

```text
VSS/MPC core:
  information-theoretic secrecy and malicious security with abort,
  assuming authenticated private channels and reliable broadcast

Whole product:
  post-quantum authenticated transport and transcript binding:
    ML-DSA party identities
    ML-KEM-derived private channels
    SHAKE/cSHAKE/KMAC/TupleHash domain separation
```

No fairness or guaranteed output-delivery claim is made for v1.

## Non-Negotiable V1 Rules

```text
1. Operational party identities are ML-DSA only.

2. No Feldman, Pedersen, DH, ECDH, RSA, ECDSA, Ed25519, or
   discrete-log commitments in the production VSS/DKG path.

3. Audited IC tags may be opened only for audit, and audited tags are
   discarded forever.

4. Retained receiver-side IC tags are private to the receiver forever.

5. Retained receiver-side IC tags are never broadcast.

6. Retained receiver-side IC tags are never sent to the holder.

7. Retained-tag replacement is not implemented in v1.

8. No public beta_i reveal in v1.

9. No public share-point reveal for liveness in v1.

10. Unresolved IC or polynomial-consistency disputes abort the VSS instance.

11. Blame is emitted only when public evidence identifies the deviating party.

12. Otherwise the failure is AbortNoBlame.

13. Scalar IT-VSS is implemented first for correctness and adversarial tests.

14. Production DKG must use batched/vector IT-VSS, not scalar-per-coefficient
    VSS.

15. All messages are transcript-bound with suite, epoch, VSS session, dealer,
    party set, vector/chunk label, round, and purpose.

16. No accepted VSS output may be created from an aborted or incomplete session.
```

## Field

Use the ML-DSA field:

```text
q = 8_380_417
F_q = integers modulo q
```

Evaluation points:

```text
alpha_i = i in F_q for party index i = 1..n
```

Require:

```text
n < q
alpha_i != 0
all alpha_i distinct
```

## Security Parameters

Because q is about 23 bits, one information-checking tag is not enough.
Use repeated independent tags.

Default scalar-test parameters:

```rust
pub struct ItVssSecurityParams {
    pub max_corruptions: usize,          // f
    pub ic_retained_tags: usize,         // default 8
    pub ic_audit_tags: usize,            // default 8
    pub poly_consistency_rounds: usize,  // default 192
}
```

The retained-tag soundness target is approximately:

```text
(q - 1)^(-8) < 2^-128
```

The polynomial consistency target is:

```text
2^-192
```

These constants are conservative defaults. Any change is a security-review
decision.

## Information-Checking Tag Primitive

Roles:

```text
D   = dealer
INT = holder/intermediary
R   = receiver/verifier
```

For one value s held by INT and later verified by R:

```text
D samples b in F_q^* and y in F_q.
D computes c = s + b*y mod q.
D privately sends (s, y) to INT.
D privately sends (b, c) to R.
Later INT sends (s', y') to R.
R accepts iff c == s' + b*y' mod q.
```

The holder must never learn retained (b, c). If the holder learns retained
(b, c), it can forge any s' by computing y' = (c - s') / b.

For production soundness, repeat the tag independently:

```text
ic_retained_tags retained verifier-private tags
ic_audit_tags audited tags
```

Audited tags may be opened for validation because they are immediately
discarded and cannot later authenticate reconstruction.

## Type-Level Separation

The implementation must keep audited and retained tags separate.

```rust
pub struct AuditedReceiverTag {
    pub holder: PartyId,
    pub receiver: PartyId,
    pub tag_index: u16,
    pub b: Fq,
    pub c: Fq,
    pub discard_after_audit: DiscardAfterAudit,
}

pub struct RetainedReceiverTag {
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    b: Fq,
    c: Fq,
    visibility: ReceiverPrivateOnly,
}
```

Rules:

```text
AuditedReceiverTag:
  public serialization allowed only in the audit phase
  cannot be moved into reconstruction state

RetainedReceiverTag:
  receiver-private serialization only
  no public wire encoding
  no Debug with secret values
  no broadcast payload conversion
```

Release gates must reject any public artifact that carries retained
receiver-side tags.

## Scalar IT-VSS Protocol

Scalar IT-VSS shares one value:

```text
s in F_q
```

The scalar protocol is the first implementation target because it is small
enough for exhaustive adversarial tests. It is not the production-scale DKG
path for all ML-DSA coefficients.

### Phase 0: Context

All parties agree on:

```text
suite
epoch
VSS session id
dealer
party set
threshold f
scalar label
evaluation points
security parameters
```

Reject any message whose canonical context does not match.

### Phase 1: Dealer Polynomial Sharing

Dealer chooses a random degree-f polynomial:

```text
F(x) = s + a_1*x + ... + a_f*x^f
```

For each party P_i:

```text
beta_i = F(alpha_i)
```

Dealer also chooses random degree-f mask polynomials:

```text
G_r(x), r = 1..poly_consistency_rounds
gamma_{r,i} = G_r(alpha_i)
```

### Phase 2: Private Payloads

For each holder P_i, dealer privately sends:

```text
beta_i
gamma_{1,i}, ..., gamma_{R,i}
holder-side y tags for beta_i to each receiver P_j
payload_salt_i
```

For each receiver P_j, dealer privately sends receiver-side IC tags:

```text
audited receiver tags (b, c)
retained receiver tags (b, c)
```

Dealer broadcasts only salted commitments to private payloads:

```text
C_i = TupleHash(
  "TALUS-VSS-private-payload-commit",
  session_id,
  dealer,
  receiver_i,
  payload_salt_i,
  canonical_private_payload_i
)
```

Do not broadcast unsalted hashes of beta_i or other low-entropy field values.
Since q is about 2^23, unsalted public hashes of private field elements are
brute-forceable.

### Phase 3: IC Audit

For each holder/receiver pair (P_i, P_j):

```text
P_i selects ic_audit_tags audit indices.
P_i broadcasts the audit request.
P_j broadcasts only the requested audited (b, c) tags.
P_i checks c == beta_i + b*y mod q for every audited tag.
Audited tags are discarded.
```

If any audit fails:

```text
AbortVss or AbortNoBlame unless public evidence identifies a party.
```

V1 does not implement retained-tag replacement.

### Phase 4: Polynomial Consistency

After private payloads and IC audits are fixed, parties generate public
challenge bits:

```text
e_r in {0, 1}
```

Challenges must be generated after private-payload commitments and audit
messages are transcript-bound. Use commit-open public coins or a reviewed
equivocation-resistant broadcast coin protocol. If a party refuses to open,
the VSS instance aborts.

For each round r, dealer broadcasts coefficients of:

```text
H_r(x) = G_r(x) + e_r*F(x)
```

Each party checks:

```text
H_r(alpha_i) == gamma_{r,i} + e_r*beta_i mod q
```

If a check fails and there is no public evidence that identifies one party:

```text
AbortNoBlame
```

V1 does not reveal beta_i or private payloads to recover liveness.

### Phase 5: Accepted Output

If IC audit and polynomial consistency pass, output:

```text
AcceptedVssSharing
```

The accepted sharing contains:

```text
dealer id
degree f
field q
evaluation points
own private beta_i
holder-side retained y tags
receiver-side retained (b,c) tags for other holders
transcript hash
public evidence
```

It must not contain:

```text
dealer secret s
F coefficients
G_r coefficients after consistency proof
audited tags after discard
private payloads for other parties
unopened coin salts
public beta_i reveal material
```

## Reconstruction / Opening

To reconstruct the scalar, each holder broadcasts:

```text
beta_i
retained holder-side y tags for each receiver
```

Each receiver verifies:

```text
c == beta_i + b*y mod q
```

using its receiver-private retained tags.

A point is accepted if at least f + 1 parties accept it. With at most f
corrupted parties, f + 1 acceptances imply at least one honest verifier
accepted the retained IC relation, except with retained-tag forgery
probability.

Then reconstruct the unique degree-f polynomial from accepted points and
return:

```text
s = F(0)
```

If there are fewer than f + 1 accepted points or reconstruction is ambiguous:

```text
AbortNoBlame
```

Never guess among multiple compatible secrets.

## Batched / Vector IT-VSS

Production DKG must not use scalar-per-coefficient VSS at ML-DSA scale.
After scalar tests pass, implement batched/vector VSS.

For vector share:

```text
beta_i in F_q^M
```

Use vector IC tags:

```text
b in F_q^*
y in F_q^M
c = beta_i + b*y mod q
```

Holder receives y privately. Receiver receives (b, c) privately. During
reconstruction, receiver accepts iff:

```text
c == beta_i' + b*y' mod q
```

where equality is componentwise over F_q^M.

Repeat independently for the retained-tag soundness target.

Polynomial consistency lifts to vector polynomials:

```text
F(x) in F_q^M[x]
G_r(x) in F_q^M[x]
H_r(x) = G_r(x) + e_r*F(x)
```

Party P_i checks:

```text
H_r(alpha_i) == gamma_{r,i} + e_r*beta_i
```

componentwise.

Current implementation status:

```text
ItVssVectorHolderSideTag:
  holder-private y_vec

AuditedVectorReceiverTag:
  receiver-side b and c_vec
  public audit-phase encoding
  discard after audit

RetainedVectorReceiverTag:
  receiver-private b and c_vec
  no public encoder
  Debug redacts b and c_vec

Implemented check:
  c_vec = beta_vec + b*y_vec

Vector honest-path deal/accept:
  dealer evaluates vector Shamir F(x) at each alpha_i
  dealer evaluates vector masks G_r(x) at each alpha_i
  private payloads contain beta_vec, gamma_vec shares, y_vec tags, retained tags
  public commitments are salted hashes of private payloads
  public consistency rounds open H_r(x)=G_r(x)+e_rF(x)
  accept verifies commitments, audited tags, consistency equations, and transcript hash

Batched/vector production facade:
  ItVssBatchedSecret is one whole-vector sharing request
  ItVssBatchedDealerOutput is the combined public/private dealer output
  ensure_it_vss_batched_vector_label requires MldsaS1 or MldsaS2 with index=None
  scalar-per-coefficient labels are rejected before messages are emitted
  SmallResidue and PrimeFieldMpcAux labels are rejected for DKG vector batches
  it_vss_share_small_residue_vector_batches emits one commitment per dealer/vector

Vector reconstruction/opening:
  holder broadcasts beta_vec and retained holder-side y_vec tags
  receiver verifies retained private c_vec = beta_vec + b*y_vec tags
  holder point is accepted only with threshold receiver approvals
  opening reconstructs each coordinate at zero from accepted Shamir points
  ambiguous coordinate reconstruction aborts

Bounded sampler adapter:
  accepted vector sharing must use the whole-vector domain with index=None
  reconstructed vector length must match the ML-DSA secret-vector shape
  every opened coordinate must be a valid residue in Z_m
  adapter emits one VerifiedSmallResidueInput per coordinate
  sample_verified_small_polyvec consumes the per-coordinate verified inputs

Logged native DKG artifact expectation:
  certified s1/s2 sampling expects one vector-domain sampler commitment per dealer
  the vector-domain sampler phase driver shares a dealer's full s1/s2 residue vector
  the batched vector phase driver shares a dealer's s1 and s2 vectors in one
  app-driver call, broadcasts one batch artifact, and sends one private
  delivery batch per receiver
  directed private deliveries are replay-keyed by IT-VSS label_hash when present
  batch private deliveries are hashed as a batch for replay while preserving
  each inner vector label for verification and complaint generation
  collection waits for distinct dealer/sender private messages, not the number
  of flattened inner vector deliveries, so one S1/S2 batch cannot complete a
  round by itself
  the batch resolver recovers public commitments/private deliveries from
  durable logs, verifies local receiver deliveries, merges matching public
  complaints, and rejects a dealer's batch if any vector delivery is invalid
  complaint broadcasts use the same app-driver/restart path: a party can
  broadcast generated complaints, wait for delayed reliable-broadcast delivery,
  resume from the complaint cursor, and resolve only from durable logs
  consistency challenge coins are public IT-VSS artifacts: applications first
  broadcast one `ItVssPublicPrecommitment` per prepared vector sharing to bind
  the directed deliveries before any challenge coins exist, then broadcast one
  `ProductionItVssPublicCoinShare` per `(party,label_hash)`, collect all shares
  through reliable broadcast, assemble a `ProductionItVssPublicCoinTranscript`,
  and finalize the vector metadata only after that transcript is available
  production vector metadata refuses to use deterministic fallback challenge
  derivation; a missing public-coin transcript aborts sharing
  `sampler_vector_it_vss_sharing_labels` exposes the exact whole-vector labels
  that embedding schedulers must use for these public-coin rounds, and
  app-driver tests cover broadcasting and collecting the public-coin transcript
  before production vector sharing
  resolver inputs are strict: duplicate inner deliveries, wrong receivers,
  mixed dealers, wrong label hashes, and valid IT-VSS complaint evidence for a
  label outside the expected S1/S2 vector batch abort rather than producing a
  certificate
  the in-memory scaffold coordinator sequences raw residues, vector sampler
  IT-VSS, scalar VSS setup logs, certified sampling, and assembly through the
  same logged transport phases
  production coordinator readiness rejects the in-memory scaffold coordinator
  and requires application-supplied transport with ML-KEM private channels,
  ML-DSA operational identities, reliable-broadcast conformance, production
  IT-VSS, production IT-MPC Power2Round, durable restart policy, and external
  review
  NativeDkgApplicationSetupDriver is the concrete app-facing scheduler
  contract: applications provide transport plus durable wire/cursor logs, and
  the crate provides typed resumable phases for bounded-sampler, vector IT-VSS,
  scalar VSS, complaint, and restart handling
  app-driver conformance tests now assemble a native DKG scaffold output from
  durable logs after driving sampler residues, vector IT-VSS, scalar VSS, and
  artifact persistence through the scheduler trait rather than the in-memory
  coordinator
  app-driver delay/restart tests now cover delayed bounded-sampler broadcasts,
  delayed vector IT-VSS private deliveries, restart from a waiting vector
  IT-VSS cursor, and complaint collection before and after all broadcasts
  arrive
  talus-wire exposes NativeDkgTransportEvidence as the application-facing
  evidence bundle for ML-KEM channel/session establishment, ML-DSA operational
  party identity authentication, and reliable-broadcast conformance; the
  provider trait derives the TALUS ExpectedContext while retaining a full
  transport evidence hash for audit
  vector IT-VSS hardening rejects retained-tag public leakage, malformed
  retained-y vector lengths, wrong vector domain/label hashes, missing retained
  tags, and aborted or inconsistent material before reconstruction can produce
  an opened vector
  complete native DKG assembly outputs must pass
  ensure_native_dkg_assembly_output_allowed_for_release; scaffold assembly
  remains release-blocked by certificate/backend checks
  release candidates should use
  ensure_native_dkg_release_context_allowed_for_release as the composed guard:
  it validates package/certificate release readiness, setup artifact log
  agreement, completed setup cursors, application transport evidence binding,
  and absence of private setup payloads in public release logs
  InMemoryNativeDkgScaffoldCoordinator has an explicit non-release profile and
  fails NativeDkgCoordinatorReleaseProfile::ensure_allowed_for_production_release
  with InsecureNativeDkgCoordinator
  per-coefficient sampler commitments are not the production-shaped polyvec path
  coefficient-level commitments remain only for narrow phase-driver tests
```

The bounded ML-DSA sampler consumes vector/batched IT-VSS outputs for residue
bits and coefficients. The scalar backend remains a correctness and adversarial
test target, not the final production-scale DKG path.

## Failure and Blame Policy

Use structured failures:

```rust
pub enum VssFailure {
    AbortNoBlame { reason: AbortReason },
    BlameDealer { dealer: PartyId, evidence: PublicEvidence },
    BlameParty { party: PartyId, evidence: PublicEvidence },
}
```

Rules:

```text
objective public evidence identifies a party:
  emit BlameDealer or BlameParty

conflict exists but private material would be required to attribute it:
  AbortNoBlame

unresolved IC dispute:
  AbortNoBlame unless public evidence identifies a party

unresolved polynomial-consistency dispute:
  AbortNoBlame unless public evidence identifies a party

equivocation in broadcast:
  BlameParty with broadcast evidence

malformed or replayed public message:
  BlameParty when the signed/enveloped sender is clear, otherwise AbortNoBlame
```

False blame is worse than abort. V1 must not claim identifiable blame unless
the evidence is public, transcript-bound, and independently verifiable.

## Transport Requirements

The crate does not own TCP sockets or a network stack. Embedding software
provides transport through traits.

Required semantics:

```text
private channel:
  authenticated P2P delivery
  receiver identity binding
  sender identity binding
  session/round/label binding
  replay rejection
  ML-KEM-derived confidentiality for production

broadcast:
  same sender message to every honest observer or abort/equivocation evidence
  ML-DSA signature over canonical wire messages
  suite/session/round/label binding
  replay rejection
```

Test transports may be in-memory only, but conformance tests must exercise:

```text
ML-KEM channel/session establishment binding
ML-DSA operational party identity authentication
equivocation-resistant broadcast behavior
```

## Persistence

Persist:

```text
session id
dealer
scalar/vector label
round cursor
broadcast messages
private payload commitments
own private payload
own retained holder-side y tags
own retained receiver-side (b,c) tags
complaints
abort/blame status
accepted status
transcript hash
```

Do not persist in public logs:

```text
retained receiver-side tags
dealer polynomial coefficients after share phase
mask polynomial coefficients after consistency proof
audited tags after discard
raw private payloads for other parties
private beta_i values
```

An incomplete or aborted session must remain non-accepted after restart.
Restart may resume from a persisted phase cursor only if the transcript can be
replayed and validated exactly.

## Rust Mapping

Existing production boundary:

```rust
pub trait ProductionItVssBackend {
    fn backend_id(&self) -> ItVssBackendId;
    fn share_secret<P: MlDsaParams>(...) -> Result<ItVssDealerOutput, DkgError>;
    fn verify_private_delivery<P: MlDsaParams>(...) -> Result<(), DkgError>;
    fn complaint_for_invalid_delivery<P: MlDsaParams>(...) -> Result<DkgComplaintPayload, DkgError>;
    fn resolve_complaints<P: MlDsaParams>(...) -> Result<ItVssComplaintResolution, DkgError>;
}
```

Implementation sequence:

```text
1. Add IC tag primitive types with audited/retained separation. [partial]
2. Add scalar IT-VSS context and phase state machine. [test coverage]
3. Add scalar honest-path tests. [done]
4. Add scalar adversarial tests. [partial]
5. Add reconstruction/opening tests. [pending]
6. Add persistence/restart tests. [partial through app-driver/log tests]
7. Add vector/batched IT-VSS design types. [done]
8. Add normal-build vector Shamir/information-checking backend. [done]
9. Wire vector/batched IT-VSS into bounded sampler. [partial]
10. Add public audit/discard records for audited tags only. [done]
11. Add vector polynomial consistency mask/private-gamma and public masked
    evaluation records. [done]
12. Replace deterministic challenge derivation with application-broadcast
    post-commitment public coins. [pending]
```

`ProductionInformationCheckingVssBackend` may implement the crate's
production-method boundary. Its current normal-build implementation performs
whole-vector Shamir sharing over `F_q`, emits receiver-private retained
information-checking material, emits separate audited tag material, derives
public audit/discard records only from audited tags, verifies directed private
deliveries, and produces hash-only public complaints. Release selection remains
gated by `ProductionItVssReadiness` until post-commitment vector polynomial
public-coin challenges, persistence, PQ transport evidence, and
complaint-resolution policy requirements in this document are satisfied.
External cryptographic review is tracked after implementation as audit
metadata; it is not a prerequisite for building or exercising the
production-shaped backend.

## Mandatory Tests

Information-checking primitive:

```text
ic_tag_accepts_correct_value
ic_tag_rejects_modified_value
ic_tag_rejects_modified_y
ic_tag_receiver_learns_no_value_in_exhaustive_small_model
ic_multi_tag_all_required
retained_tag_has_no_public_serialization
audited_tag_cannot_enter_reconstruction_state
```

Scalar VSS honest path:

```text
vss_scalar_honest_dealer_accepts
vss_scalar_reconstructs_original_secret
vss_scalar_all_honest_shares_lie_on_degree_f_poly
vss_scalar_private_payload_commitments_verify
vss_scalar_transcript_hash_stable
```

Adversarial dealer/party behavior:

```text
dealer_sends_missing_private_payload
dealer_sends_bad_payload_commitment
dealer_sends_bad_ic_tag_to_receiver
dealer_sends_inconsistent_beta_values
dealer_sends_inconsistent_gamma_values
dealer_fails_polynomial_consistency
dealer_equivocates_broadcast
receiver_broadcasts_wrong_audit_tag
holder_falsely_complains_after_valid_tag_aborts_without_false_blame
holder_sends_wrong_beta_on_reconstruction
holder_sends_wrong_y_on_reconstruction
party_replays_old_vss_message
party_uses_wrong_scalar_label
party_uses_wrong_epoch
party_uses_wrong_dealer
```

Polynomial consistency:

```text
poly_consistency_accepts_degree_f
poly_consistency_rejects_degree_f_plus_1_beta
poly_consistency_rejects_wrong_gamma
poly_consistency_challenge_generated_after_commitments
poly_consistency_replay_challenge_rejected
```

Reconstruction:

```text
reconstruct_with_all_honest_points
reconstruct_with_f_missing_points
reconstruct_rejects_forged_holder_value
reconstruct_rejects_ambiguous_points
reconstruct_requires_f_plus_1_accepted_points
```

Crash/restart:

```text
restart_after_private_send
restart_during_ic_audit
restart_after_abort_cannot_accept
restart_after_accept_preserves_transcript_hash
```

Release profile:

```text
production rejects Feldman/Pedersen backend
production rejects scalar-per-coefficient DKG mode
production rejects public retained receiver-side tag artifacts
production rejects beta_i public reveal mode
production rejects unsalted public private-share hash
production rejects accepted VSS from aborted session
production rejects Debug output with retained tag values
```

Implemented release gates:

```text
ItVssV1ReleasePolicy:
  allowed DKG mode: BatchedVector
  forbidden DKG mode: ScalarPerCoefficient
  public beta_i reveal: forbidden
  retained receiver-side tag public artifacts: forbidden

ProductionInformationChecking readiness must enforce this policy before a
backend can claim release readiness.

Scalar correctness sessions must pass restart validation before their evidence
can be treated as accepted:
  accepted cursor required
  private-state hashes required
  incomplete sessions rejected
  aborted sessions rejected
```

## Release Blockers

Native production IT-DKG/VSS remains blocked until:

```text
1. Scalar IT-VSS passes the adversarial suite.
2. Batched/vector IT-VSS is implemented and tested.
3. Retained receiver-side tags have no public serialization path.
4. Public beta_i reveal is absent from v1 release builds.
5. AbortNoBlame vs blame evidence policy is implemented.
6. Durable phase cursors and restart validation are complete.
7. App-provided ML-KEM/ML-DSA transport conformance tests pass.
8. External cryptographic/security review approves the backend.
```
