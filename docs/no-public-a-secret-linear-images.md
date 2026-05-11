# No Public Exact A-Images Of Secrets

This is a security rationale/reference document. The live implementation
checklist is `../IMPLEMENTATION_PLAN.md`.

This document records a production security rule for TALUS-MPC:

```text
Do not publish an exact ML-DSA matrix image A*x for any secret x.
```

This includes:

```text
forbidden:
  A*s1_i
  A*nonce_share_i
  A*nonce_polynomial_coefficient
  Phi = A*secret_coefficient_vector
  any public "Feldman-style" lattice commitment of the form A*x
```

The rule applies to DKG, nonce preprocessing, online partial verification,
blame protocols, logs, public certificates, and release-valid key packages.

## Reason

ML-DSA public keys have the noisy form:

```text
t = A*s1 + s2
```

The unknown `s2` term is essential. It is the noise term that makes recovering
`s1` a lattice problem.

A public exact image has no noise:

```text
V = A*x
```

For ML-DSA parameter sets, `A` maps `R_q^l -> R_q^k` with `k >= l`. Under the
CRT/NTT representation, this becomes 256 independent linear systems over
`F_q`. For ML-DSA-65 and ML-DSA-87, each slice is tall. With overwhelming
probability it has full column rank, so `x` can be recovered by ordinary
Gaussian elimination. No MLWE solver or bounded-domain search is needed.

For ML-DSA-44, the slices are square. They are invertible except with small
probability; even singular slices leak most coordinates.

Therefore:

```text
A*x is binding because A is usually injective.
A*x is not hiding for the same reason.
```

## Consequences

Public `A*s1_i` is a threshold-key compromise surface. If every party publishes
`A*s1_i`, observers can recover Shamir shares `s1_i` with high probability. Any
threshold number of recovered shares reconstructs the aggregate `s1`.

Public nonce polynomial commitments of the form `A*a_h,k` are also unsafe. They
can reveal nonce-polynomial coefficients. If nonce shares become recoverable,
then an online transcript containing

```text
z_i = y_i + c*s1_i
```

can leak `c*s1_i`; when `c` is invertible in `R_q`, this recovers `s1_i`.

## Production Policy

The production profile is:

```text
No public exact A-image of any secret value.
No public A*s1_i.
No public A*nonce polynomial coefficient.
No production Feldman-style lattice commitment Phi = A*x.
No production partial verifier based on A*z_i = A*y_i + c*A*s1_i.
```

`CommitmentBackedPartialVerifier` and any paper-compatible public-linear-image
partial verifier are allowed only as test, attack-demonstration, or explicit
insecure paper-compatibility code. They must not be reachable from a release
path.

## Online Blame Policy

The v1 production policy is:

```text
No per-party public-linear-image blame after challenge.
```

After the challenge and `z_i` response phase:

```text
- consume the token before or atomically with producing z_i;
- never reveal honest nonce material;
- run independent FIPS verification before output;
- if verification fails, return no signature and retry with a fresh token;
- blame only when non-revealing public evidence objectively identifies a party.
```

If future production requires per-party online blame, it must use a reviewed
non-revealing mechanism, such as:

```text
- IT-MPC/authenticated-share relation checks;
- information-checking proofs bound to the relation;
- hiding PQ commitments with reviewed zero-knowledge proofs.
```

It must not use public exact linear images.

## Required Tests And Release Gates

Add and maintain tests that demonstrate the danger:

```text
attack test:
  for each ML-DSA suite, compute V = A*x and recover x by NTT-coordinate
  linear solving whenever A has full column rank.

release gate:
  production fails if any public artifact contains or requires:
    A*s1_i
    A*nonce_polynomial_coefficient
    Phi = A*secret
    CommitmentBackedPartialVerifier
    public-linear-image online blame
```

The implementation should also keep source/API scans for:

```text
as1_commitment
CommitmentBackedPartialVerifier
Feldman
Phi = A*
A*s1_i
```

Any allowed occurrence must be test-only, dev-only, or documented as a forbidden
paper-compatibility artifact.

Current DKG status:

```text
As1Commitment:
  removed from normal DKG production structs.

DkgCommitPayload.as1_commitment:
  removed from normal DKG commit payload.

DkgPublicOutput.as1_commitments:
  removed from normal DKG public output.

production-release-checks + scaffold-dev:
  compile-time error.

talus-mpc/talus-wire production-release-checks + paper-fast-dev:
  compile-time error.

DistributedNonceShare.ay_commitment:
  cfg(test) or paper-fast-dev only.

MaskedBroadcastClearAudit / ClearMaskedBroadcastConsistencyVerifier:
  cfg(test) or paper-fast-dev only.

CutAndChooseAuditPlan:
  cfg(test) or paper-fast-dev only.
```
