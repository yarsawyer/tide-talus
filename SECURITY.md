# Security Status

This repository is not production-ready.

The approved v1 production profile is honest-majority, end-to-end
post-quantum TALUS-MPC:

- ML-KEM-established private channels
- ML-DSA authenticated identities and broadcast messages
- SHAKE/KMAC transcript binding
- information-theoretic MPC/VSS preprocessing over PQ-authenticated channels
- reviewed PQ key-share provisioning as an initial operational setup profile
- native honest-majority IT-DKG/VSS as a mandatory product component

TALUS-MPC requires release-blocking review of PQ key-share provisioning,
native honest-majority IT-DKG/VSS, bounded ML-DSA s1/s2 distributed sampling,
honest-majority IT-MPC/VSS authenticated triple generation, pre-challenge
masked-broadcast and CarryCompare certification, crash-safe nonce persistence,
and authenticated/equivocation-resistant transport before any production release.

Plain Shamir DKG is not sufficient by itself. ML-DSA key material is bounded,
so the DKG must include a reviewed distributed sampler for `s1`/`s2`
coefficients in the ML-DSA bounds.

The native DKG/VSS source bundle is intentionally narrow: Shamir for polynomial
sharing, Rabin-Ben-Or for information-theoretic VSS with honest majority, BGW
for arithmetic MPC, Cramer-Damgaard-Nielsen and Cramer-Damgaard-Maurer for
LSSS abstractions, and Chida et al. for malicious honest-majority MPC with
abort. MP-SPDZ, Cicada, MPyC, FRESCO, and SCALE-MAMBA are inspection references
only, not production dependencies.

Do not use Feldman/Pedersen/DH/ECDH/classical OT-based setup as production
security sources. Do not use SLH-DSA for v1 operational identities; the
approved identity scheme is ML-DSA.

Do not publish exact ML-DSA matrix images of secret material. Public values of
the form `A*x` are not hiding for ML-DSA shapes when `x` is a secret vector.
This forbids public `A*s1_i`, public `A*nonce` or `A*nonce-polynomial`
coefficients, and Feldman-style lattice commitments `Phi = A*secret` in
production. See `docs/no-public-a-secret-linear-images.md`.

Post-challenge reveal-on-failure is disabled by default. After online
`z_i = y_i + c*s1_i` shares are sent, revealing honest nonce material is a
long-term-share leakage surface unless separately proven safe and externally
reviewed. Production final-verification failure must consume the token, return
no signature, and reveal no honest nonce/session material.

The v1 production online policy is no per-party public-linear-image blame after
challenge. `CommitmentBackedPartialVerifier`-style checks based on
`A*z_i = A*y_i + c*A*s1_i` are test/insecure-paper-compatibility mechanisms only and
must not be reachable from release-valid signing paths.

Production signing must also prevent rejected-`z` leakage. Token consumption
must be durably persisted before any `z_i` or aggregate `z` computation, and a
release-valid signing path must not expose clear partial `z_i`, rejected
aggregate `z`, candidate hints, validity bits, or detailed failure reasons.
Only the selected final signature candidate may be opened, and only after
independent FIPS 204 verification accepts it. The current clear partial
signature adapters are local/test/research paths, not the strict
production signing backend. See `docs/no-rejected-z-leakage.md`.

The initial implementation intentionally starts with local arithmetic,
`fips204` adapter work, and deterministic in-process tests only.
