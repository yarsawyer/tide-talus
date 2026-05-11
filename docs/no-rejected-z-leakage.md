# No Rejected-Z Leakage In Production Signing

This is a security rationale/reference document. The live implementation
checklist is `../IMPLEMENTATION_PLAN.md`.

This document records a production security rule for TALUS-MPC online signing:

```text
Rejected candidate z values must never become public.
```

The rule applies to:

```text
z_i = y_i + c*s1_i
aggregate z
candidate hints h
validity bits
failure reasons
failed token identifiers exposed through public telemetry
```

The only `z` value that may be opened in production is the `z` inside a final
FIPS 204 ML-DSA signature that has passed independent verification.

## Why This Matters

ML-DSA/Dilithium response generation has the form:

```text
z = y + c*s1
```

Ordinary ML-DSA rejection sampling destroys rejected candidates internally.
Rejected `z` values are not output. Exposing rejected or unfiltered `z` values
creates samples from the wrong distribution and can leak information about
`s1`.

Threshold signing makes this more delicate. If a coordinator or observer sees
per-party values:

```text
z_i = y_i + c*s1_i
```

for failed attempts, then the failed online transcript can carry key-share
information. Even predicates that look nonce-only before `z` is known can become
secret-dependent after `z` is exposed, because:

```text
y = z - c*s1
```

Therefore, a candidate-token path that sends clear `z_i` before knowing whether
the final attempt is valid requires a separate reviewed leakage proof. Until
that proof exists, it is not the full-malicious-privacy production profile.

## Hard Production Rules

Strict production signing must enforce:

```text
1. Consume each token durably before any challenge, z_i, z, hint, or response
   computation.

2. Do not send clear z_i values.

3. Do not expose aggregate z for rejected candidates.

4. Do not expose candidate hint bits or hint weight for rejected candidates.

5. Do not expose per-token validity bits or detailed failure reasons.

6. Open only the selected valid signature material.

7. Run independent FIPS 204 verification before returning a signature.

8. If no valid candidate is selected, return a generic failure with no z/h/reason
   output and keep all participating tokens consumed.
```

Crash rule:

```text
If a process crashes after token consumption and before signature output, the
token remains consumed forever after restart.
```

Invalid challenge/request rule:

```text
If a request reaches the point where the token must be bound to the signing
session, the token is consumed or quarantined. It must never be reused for a
different challenge.
```

## Production Profile And Test Profiles

There is exactly one production profile:

```rust
StrictPqHmProduction
```

It is the only profile allowed behind release-valid APIs:

```text
- BCC-certified tokens only.
- Fixed token batch consumed before response work.
- z_j values are computed privately in IT-MPC.
- z-bound, hint-weight, and validity checks are private.
- selection among valid candidates is private/random-priority based.
- only selected ctilde, z, and h are opened.
- no clear partial z_i transport.
- no public A*s1_i verifier.
- no reveal-on-failure.
```

All other execution shapes are test, development, research, or attack-demo
profiles. They are not production profiles and must not be selectable by normal
crate users.

If code needs explicit profile names for release gates or tests, the normal
build must expose only the production value. Test/dev values must be gated so
normal crate users cannot select them:

```rust
pub enum SigningExecutionProfile {
    StrictPqHmProduction,
    #[cfg(any(test, feature = "paper-fast-dev"))]
    TestPaperFastExperimental,
    #[cfg(test)]
    TestLocalSimulation,
}
```

Release policy must accept only:

```text
StrictPqHmProduction
```

### TestPaperFastExperimental

Paper-compatible candidate-token test profile:

```text
- candidate tokens allowed.
- clear z_i may be sent before final verification is known.
- verifier retry may consume failed attempts.
- rejected-z leakage remains under analysis.
- not a production full-malicious-privacy profile.
```

This profile may exist only behind an explicit non-production feature or
`cfg(test)`. It is for paper-compatibility experiments and leakage analysis, not
for production.

### TestLocalSimulation

Local test and correctness harnesses:

```text
- may use clear z_i values.
- may use local witnesses.
- may use scaffold partial verifiers.
- never production.
```

## Strict Private Batch Signing Shape

The preferred production construction is:

```text
1. Take a fixed batch of K BCC-certified tokens.
2. Durably consume all K tokens before challenge or response computation.
3. Derive ctilde_j locally for every token from message/context and w1_j.
4. Compute [z_j] = [y_j] + c_j*[s1] privately.
5. Privately check:
     z_bound_ok_j
     hint_ok_j
     valid_j
6. Do not open valid_j or failure reasons.
7. Select one valid candidate with random-priority one-hot selection.
8. Open only selected ctilde*, z*, and h*.
9. Verify final ML-DSA signature before output.
10. If no valid candidate exists, return GenericBatchFailure and open nothing.
```

All tokens in the batch remain consumed, including unselected tokens.

Preprocessing token lifecycle is monotonic:

```text
Fresh -> Reserved -> Consumed -> Erased
```

The code-level `TokenInventory` gate enforces this state order for certified
preprocessing tokens, and `FileTokenInventory` persists the same transitions
across restart. Its log rejects corrupt records and rollback attempts such as
`Consumed -> Reserved`. The strict online consumed-token store is still the
final durable guard immediately before response computation; inventory
consumption does not replace that online guard.

## Current Code Status

The current local online adapter is not the production profile.

It correctly consumes tokens before partial response computation, but it still
has clear partial response types:

```text
PartialSignature { z_share: Vec<u8> }
PolynomialPartialSignature { z_share: PolyVec }
talus-wire PartialSignaturePayload { z_share: Vec<u8> }
```

Current code rule:

```text
These clear partial-response types and payload codecs are not present in normal
production builds. They compile only under cfg(test) or the explicit
paper-fast-dev feature used for attack demonstrations and legacy regression
tests.
```

Strict production API status:

```text
StrictSignRequest:
  production request without per-token clear partial response state.

BccCertifiedTokenBatch:
  accepts only pre-challenge certified tokens with one signer set.

sign_strict_no_rejected_z:
  durably consumes every token in the batch before the private backend receives
  any token material, then runs the final verifier before returning output.

StrictSigningSession:
  production-facing app-driver facade for strict signing. It owns the request,
  certified token batch, consumed-token store, private backend, verifier, and
  counters. It exposes `start`, `handle_private`, `handle_broadcast`,
  `next_outbound`, `finish`, and `into_parts` so applications can use the same
  driver shape as DKG/preprocessing. It accepts only `StrictSignMpc` wire
  messages bound to the strict signing session id, signing set, suite, sender,
  receiver, and typed runtime slot; legacy partial-signature traffic is
  rejected. It can queue strict MPC private/broadcast messages through
  `next_outbound`, but the payload is opaque backend data rather than a clear
  partial response. `finish` is terminal: success stores one final signature,
  and failure after consumption leaves the session failed with the consumed
  token state intact.

StrictSigningSessionStore / StrictSigningSessionCursor:
  durable phase cursor for strict signing. The cursor records the deterministic
  strict signing session id, request hash, fixed token ids, coarse phase
  (`Started`, `TokensConsumed`, `Finished`, `Failed`), optional runtime slot,
  accepted strict MPC message hashes, outbound strict MPC message hashes, the
  strict MPC wire transcript hash, and final signature hash after success.
  `FileStrictSigningSessionStore` is an append-only `std` implementation used
  for crash/reopen tests. A failed or finished cursor blocks starting the same
  strict session again.

StrictSignMpcPayload:
  production wire domain for strict private MPC runtime messages. It carries a
  typed runtime slot, slot-local phase, receiver id, label hash, transcript
  hash, and opaque backend bytes. It has no first-class fields for partial
  responses, candidate pass bits, rejected material, or failure reasons.

StrictSigningDistributedRuntime:
  slot-driven distributed runtime boundary. `StrictSigningSession` validates
  the wire envelope and decoded `StrictSignMpcPayload`, then calls the runtime
  with the opaque backend payload. The runtime may return strict MPC outbound
  messages and may mark one runtime slot complete. The session persists
  accepted message hashes, outbound message hashes, the wire transcript hash,
  and per-slot progress: phase, accepted senders, outbound count, slot
  transcript hash, and completion bit. A slot may complete only after every
  signer has contributed for the slot's phase. Duplicate senders, wrong phases,
  incomplete completion, and replays after cursor-store restart are rejected.

StrictSigningRuntimeSlot:
  named phase slots for the future distributed vector IT-MPC runtime:
  response preparation, response-bound checks, hint checks, private selection,
  and selected opening.

StrictSigningRuntime / StrictSigningRuntimeObserver:
  single production runtime boundary for strict private signing after token
  consumption. `ProductionStrictSigningBackend` implements this runtime and
  reports each runtime slot to the observer before executing it. The session
  wires the observer to `StrictSigningSessionStore`, so cursor persistence now
  records every private runtime slot instead of only a coarse backend call.

StrictPrivateSigningBackend:
  production boundary for the still-pending private response-check circuit.
  It returns a StrictSelectedSignature, not raw candidate internals.

StrictSelectedSignature / StrictSigningEvidence:
  public selected-output envelope. Evidence contains only token count,
  coarse response-check counters, selected public priority, selected signature
  hash, and backend transcript hash. It must not contain rejected z values,
  per-token validity bits, failure reasons, low bits, masks, or private
  witnesses. The strict wrapper rejects backend evidence whose counters do not
  match the consumed batch shape.

StrictCandidateMetadata:
  public per-token metadata derived from certified tokens and request data:
  session id, token transcript hash, public priority, mu, ctilde, and encoded
  w1 hash. It intentionally excludes response shares, aggregate z, hints,
  private validity bits, failure details, and witnesses.

LocalStrictPolynomialSigningBackend:
  dev/test-only harness that follows the strict backend boundary without clear
  partial transport. It locally evaluates candidate response checks and final
  signature construction so the strict flow is executable before the
  distributed IT-MPC backend lands.

StrictSigningPhaseDriver:
  enforces the required order:
    consume token batch
    derive challenges
    compute private responses
    evaluate private checks
    select private candidate
    open selected candidate
    final verify

StrictResponseCheckPhaseDriver:
  enforces the inner private circuit order:
    derive public candidate metadata
    compute shared responses
    check response bounds privately
    check hints privately
    combine private pass bits
    select by priority
    open selected output only
  The driver is used by the dev strict backend now and defines the phase order
  the production vector IT-MPC backend must follow.

StrictResponseBoundCheckBackend:
  production boundary for the first private predicate. It checks response
  bounds for every candidate while keeping per-candidate predicate bits inside
  the backend. The only returned public artifact is shape evidence: token
  count and response coefficient count. The dev implementation stores local
  predicate results only inside the gated dev module.

StrictHintCheckBackend:
  production boundary for private HighBits/hint and hint-weight checks. It
  keeps per-candidate predicate bits inside the backend and returns only shape
  evidence: token count and hint coefficient count. The dev implementation
  computes the check locally only inside the gated dev module.

StrictPrivateSelectionBackend:
  production boundary for combining private predicate bits and selecting the
  lowest-priority valid candidate. It returns only the selected candidate and
  public selection evidence. Unselected pass bits and failure reasons remain
  backend-private.

StrictSelectedOpeningBackend:
  production boundary for the selected-opening step. It receives exactly one
  selected candidate handle from the private selection backend and opens only
  the selected final signature material. It returns public selected-opening
  evidence: token count, selected priority, and selected signature hash. It
  must not receive or inspect the full candidate batch.

ProductionStrictSigningBackend:
  production-facing composition point for the strict trait stack. It wires
  private response preparation, response-bound checks, hint checks, private
  selection, and selected-only opening through one normal API entry point.
  Normal callers should construct it through:
    strict_production_signing_backend(...)
    StrictProductionSigningBackend<SP>
  so distributed runtimes and app drivers do not accidentally grow a second
  response/check/select/open implementation.

ProductionVectorResponsePreparationBackend:
  production-facing vector response preparation over provided private `y` and
  `s1` polynomial shares. It computes each candidate response as
  `[z_j] = [y_j] + c_j*[s1]`, aggregates by the configured Shamir/Lagrange
  signer set, and returns only opaque vector candidate handles. The handles
  are passed by value through the bound-check, hint-check, selection, and
  selected-opening phases. The normal production path does not use hidden
  shared local state such as `Rc<RefCell>` to move candidate internals between
  phase objects.

ProductionVectorResponseBoundCheckBackend:
  vector response-bound checker. It evaluates the strict ML-DSA response
  bound for every candidate and stores the predicate result inside the opaque
  backend state.

ProductionVectorHintCheckBackend:
  vector hint/highbits checker. It computes `A*z - c*t1*2^d`, derives the
  candidate hint, enforces hint encoding/weight through the FIPS encoder, and
  stores only the selected-output candidate bytes inside private backend state.

ProductionVectorPrivateSelectionBackend:
  combines the private bound/hint predicate state and selects the
  lowest-priority valid candidate. It exposes only selected priority evidence.

ProductionVectorSelectedOpeningBackend:
  opens only the selected candidate signature bytes. It does not receive the
  full candidate batch.

Remaining cryptographic backend work:
  the current strict vector backend is the normal production API shape and
  avoids paper-fast partial transport. It has explicit typed phase handoffs
  and selected-only opening. Cross-party vector IT-MPC transport optimization
  and proof/backend review continue under the implementation plan; any
  distributed runtime must adapt the same strict component stack rather than
  adding a separate scalarized response-check path.

strict_candidate_priority:
  production-visible public priority derivation used after private validity
  checks. Backends select the lowest-priority valid candidate instead of the
  first valid candidate, so the selected opening does not reveal that earlier
  batch entries failed.
```

Paper-fast and clear partial-signature mechanisms remain acceptable only for
test/scaffold/paper-compatibility paths.

## Release Gates

Release checks must fail if a production path enables or exports:

```text
clear PartialSignature.z_share
clear PolynomialPartialSignature.z_share transport
talus-wire PartialSignaturePayload as production signing transport
CandidateTokenPool
TestPaperFastExperimental
CommitmentBackedPartialVerifier
public A*s1_i partial verification
reveal-on-failure after challenge
token consumption after z computation
detailed failure reason after private candidate checks
```

Release checks must also prove:

```text
token consumption is durable before z computation
crash after consumption cannot restore a token
failed final verification returns no signature
rejected candidate z/h/validity bits are not logged or serialized
```

## Test Plan

Required tests:

```text
token_consumed_before_z:
  simulate crash after consumption and before output;
  restart;
  assert token cannot be reused and no z was persisted.

strict_profile_rejects_clear_partial_transport:
  assert strict production cannot use PartialSignaturePayload or clear z_i.

rejected_candidate_no_output:
  force z-bound, hint-weight, and final-verify failures;
  assert no rejected z/h/validity/failure detail is opened.

no_valid_batch_generic_failure:
  force all candidates invalid;
  assert GenericBatchFailure, all tokens consumed, no candidate material opened.

release_scan_for_rejected_z_leakage:
  production build fails on clear z_i transport, candidate-token verifier retry,
  CommitmentBackedPartialVerifier, or TestPaperFastExperimental.
```
