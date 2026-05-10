# Security Status

This repository is not production-ready.

The approved v1 production profile is honest-majority, end-to-end
post-quantum TALUS-MPC:

- ML-KEM-established private channels
- ML-DSA authenticated identities and broadcast messages
- SHAKE/KMAC transcript binding
- information-theoretic MPC/VSS preprocessing over PQ-authenticated channels
- reviewed PQ key-share provisioning as an initial operational setup mode
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

Post-challenge reveal-on-failure is disabled by default. After online
`z_i = y_i + c*s1_i` shares are sent, revealing honest nonce material is a
long-term-share leakage surface unless separately proven safe and externally
reviewed. Production final-verification failure must consume the token, return
no signature, and reveal no honest nonce/session material.

The initial implementation intentionally starts with local arithmetic,
`fips204` adapter work, and deterministic in-process tests only.
