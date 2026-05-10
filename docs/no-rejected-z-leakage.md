# No Rejected-Z Leakage In Production Signing

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

If code needs explicit profile names for release gates or tests, use names that
make this distinction impossible to miss:

```rust
pub enum SigningExecutionProfile {
    StrictPqHmProduction,
    TestPaperFastExperimental,
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

## Current Code Status

The current local online adapter is not the production profile.

It correctly consumes tokens before partial response computation, but it still
has clear partial response types:

```text
PartialSignature { z_share: Vec<u8> }
PolynomialPartialSignature { z_share: PolyVec }
talus-wire PartialSignaturePayload { z_share: Vec<u8> }
```

These are acceptable only for test/scaffold/paper-compatibility paths until a
strict private MPC signing backend replaces them for production.

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
