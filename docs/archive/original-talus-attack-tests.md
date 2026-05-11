# Original TALUS Paper Attack Tests

This document tracks tests that intentionally demonstrate why selected
paper-compatible TALUS-MPC mechanisms are not production-safe.

These are not production features. They are attack demonstrations and regression
tests for release gates.

## Public `A*secret` Recovery

The TALUS paper uses exact public matrix images such as:

```text
A*s1_i
Phi = A*nonce_polynomial_coefficient
```

as Feldman-style public commitments.

For ML-DSA parameter shapes, this is not hiding. Under NTT/CRT, `A*x` becomes
256 linear systems over `F_q`. For full-column-rank slices, ordinary Gaussian
elimination recovers `x`.

Implemented tests:

```text
talus-core/tests/public_a_secret_attack.rs
```

Coverage:

- recover arbitrary `x` from public `A*x` for ML-DSA-44
- recover arbitrary `x` from public `A*x` for ML-DSA-65
- recover arbitrary `x` from public `A*x` for ML-DSA-87
- recover a signer `s1_i` share from public `A*s1_i`
- recover a nonce polynomial coefficient from public `Phi = A*x`

Production implication:

```text
No public A*s1_i.
No public A*nonce coefficient.
No public Phi = A*secret.
No production CommitmentBackedPartialVerifier.
```

Implementation status:

```text
CommitmentBackedPartialVerifier:
  compiled only for cfg(test) or explicit paper-fast-dev builds and exported
  through talus_mpc::dev_backends, not the normal production API.

PolynomialPartialCommitment / public A*y_i,A*s1_i online verifier material:
  compiled only for cfg(test) or explicit paper-fast-dev builds and exported
  through talus_mpc::dev_backends, not the normal production API.

PartialSignature / PolynomialPartialSignature / talus-wire PartialSignaturePayload:
  compiled only for cfg(test) or explicit paper-fast-dev builds. Clear partial
  signing helpers are available only from explicit dev_backends modules.

Workspace feature graph:
  production-release checks do not enable paper-fast-dev transitively.
  Paper-compatible attack and legacy integration tests in talus-tests require
  `--features paper-fast-dev`; normal and production-release workspace checks
  compile without the clear partial or public-linear-image dev modules.
```

## Rejected-`z` Leakage

The paper-fast online shape can expose:

```text
z_i = y_i + c*s1_i
```

before ordinary ML-DSA rejection/final verification has accepted the candidate.
Ordinary ML-DSA destroys rejected `z` internally. A threshold implementation
must preserve that discipline.

Required attack/regression tests:

- malicious driver tries to collect rejected clear `z_i` [done for
  paper-compatible path]
- malicious driver tries to collect rejected aggregate `z` [done for
  paper-compatible path]
- forced z-bound failure demonstrates rejected clear `z` already exists in the
  paper-compatible path [done]
- forced hint-weight failure opens no candidate material
- forced final-verifier failure consumes tokens and opens no rejected material
- no-valid token batch returns generic failure only
- logs/errors/telemetry contain no rejected `z`, hint bits, validity bits, or
  detailed candidate failure reasons

Production implication:

```text
Strict signing opens only selected valid ctilde, z, and h.
Rejected candidates remain private.
```

## Reveal-On-Failure Leakage

After `z_i = y_i + c*s1_i` exists, revealing enough nonce material to recover
`y_i` leaks:

```text
c*s1_i = z_i - y_i
```

Required attack/regression tests:

- post-challenge nonce reveal path is unreachable from production APIs [partial:
  token admission requires `post_challenge_reveal_disabled = true`]
- final verification failure consumes token material and reveals no nonce data
- forensic reveal helpers are test/research only
- release scanners reject reveal-after-challenge hooks

Production implication:

```text
No post-challenge reveal-on-failure in production.
```

## Completion Gates

- [x] Public `A*x` recovery tests exist for all ML-DSA suites.
- [x] Public `A*s1_i` recovery test exists.
- [x] Public nonce-commitment recovery test exists.
- [x] Rejected-`z` leakage attack simulations exist for the paper-compatible
  clear path.
- [x] Reveal-on-failure token-admission regression test exists.
- [ ] Strict signing no-rejected-`z` leakage simulations exist.
- [ ] Release scanners reject every production path that depends on the broken
  paper-compatible mechanisms.
