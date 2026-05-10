# TALUS-MPC product implementation plan

## 0. Product target and security target

Build a Rust implementation that produces **standard FIPS 204 ML-DSA signatures** verifiable by an unmodified ML-DSA verifier. The implementation target is **TALUS-MPC**, not TALUS-TEE. TALUS-MPC computes the ML-DSA commitment high bits (w_1 = \mathrm{HighBits}(Ay)) without reconstructing the full nonce product (Ay), then performs one online broadcast round per signing attempt. TALUS-MPC cannot pre-check BCC offline, so each online attempt succeeds with probability roughly (p_\text{BCC}), about **31.7% for ML-DSA-65**, and the signing API must support retries. ([arXiv][1])

## 0.1 Approved v1 architecture

The approved production architecture is:

```text
Profile:
  honest-majority PQ TALUS-MPC

Deployment shape:
  N >= 2T - 1 for T >= 3

Channels:
  ML-KEM-established private channels
  ML-DSA authenticated party identities and broadcast messages
  SHAKE/KMAC transcript binding and key derivation

Preprocessing:
  information-theoretic MPC/VSS over PQ-authenticated channels
  certified authenticated triples before use
  masked-broadcast consistency checked before challenge
  CarryCompare privately certified before token admission
  BCC privately certified before token admission if feasible

Setup:
  reviewed PQ key-share provisioning is an initial operational mode
  native honest-majority IT-DKG/VSS is mandatory
  bounded ML-DSA secret sampling is the review-critical DKG subproblem

Out of scope for v1 production:
  Ring-LPN/PCG
  PQ-OT/MASCOT
  LWE/RLWE FHE-SPDZ
  classical Pedersen/DH/AKE
```

## 0.2 Authority boundaries

Treat the TALUS paper as authoritative where it gives the concrete TALUS construction
and proof. Do not weaken or casually modify these parts:

```text
- FIPS 204 signature compatibility and final verifier behavior
- BCC boundary checks and retry/failure semantics
- CEF masked-broadcast arithmetic, including the +delta correction
- TALUS-MPC honest-majority shape: N >= 2T - 1 for T >= 3
- one-round online signing with z_i broadcasts
- online blame using public A*s1_i commitments
- paper reveal-on-failure blame semantics as a diagnostic construction
```

Do not treat paper placeholders, classical setup references, or future-work notes as
production-complete for Tidecoin. These require stricter product design:

```text
- classical Pedersen DKG/VSS
- finite-field/EC DH or classical-only AKE
- unauthenticated PRF-derived triples for full malicious privacy
- concrete persistence, rollback protection, transport, and deployment identity
- adaptive security beyond the paper's erasure assumptions
```

Product rule: final Tidecoin TALUS must be end-to-end post-quantum. Classical
Pedersen/DH-style setup is allowed only as test/research scaffolding, never as a
production security dependency. Reviewed PQ key-share provisioning is allowed as
an initial operational setup mode, but it is not a substitute for implementing
native honest-majority IT-DKG/VSS.

Product rule: post-challenge reveal-on-failure is not a production default. Once
online `z_i = y_i + c*s1_i` shares have been sent, revealing enough honest nonce
material to reconstruct `y_i` creates a long-term-share leakage surface unless a
separate proof and external review say otherwise. Production behavior after
final verification failure is to consume the token, return no signature, and not
reveal honest nonce/session material. Reveal-on-failure is reserved for
offline/pre-challenge diagnostics or a separately reviewed forensic mode.

The implementation must support:

```text
Parameter sets:
  ML-DSA-44
  ML-DSA-65
  ML-DSA-87

Adversary:
  static malicious corruption of up to T−1 parties

Privacy target:
  full malicious privacy for the TALUS-MPC carry-computation layer

Abort target:
  identifiable abort whenever a malicious deviation is detectable

Compatibility:
  output signatures verify with standard FIPS 204 ML-DSA verification

Language:
  Rust, no unsafe by default

Release rule:
  never return a signature unless independent FIPS 204 verification accepts it
```

For (T \ge 3), keep the TALUS paper’s honest-majority deployment condition (N \ge 2T - 1) unless you intentionally replace the paper’s CSCP with a different actively secure dishonest-majority MPC backend and redo the proof. The TALUS paper states this honest-majority requirement for its MPC carry computation, while treating (T=2) separately. ([arXiv][1])

## 1. Workspace layout

Codex should create a Cargo workspace with these crates:

```text
talus-core/
  fips204-backed ML-DSA adapters, parameter metadata, TALUS-required
  decomposition hooks, BCC, CEF math, and any narrow internal helpers
  that fips204 does not expose publicly.

talus-mpc-core/
  malicious-secure MPC backend:
  GF(2^128), authenticated shares, MAC checks, Beaver triples,
  Boolean circuits, comparison circuits, range checks, batch checks.

talus-dkg/
  threshold key generation, Shamir sharing, VSS commitments,
  pairwise seed establishment, refresh.

talus-mpc/
  TALUS-MPC protocol state machines:
  keygen, preprocessing, CarryCompare, online signing, blame.

talus-wire/
  canonical message encodings, versioned protocol messages,
  transcript binding, network abstraction traits.

talus-tests/
  integration tests, adversarial tests, Monte Carlo tests,
  cross-verification against the standard fips204/Tidecoin verifier path.

talus-bench/
  Criterion benchmarks and communication accounting.
```

Suggested dependency policy:

```text
Allowed:
  fips204, pinned to the Tidecoin-tested version unless intentionally upgraded
  zeroize
  subtle
  rand_core
  rand_chacha
  sha3
  serde only behind explicit wire-format feature
  postcard or bincode only if canonical encoding is enforced
  criterion for benches
  proptest for tests

Avoid:
  unsafe
  panic-based protocol control flow
  implicit serde encodings for consensus-critical data
  non-canonical integer encodings
  non-domain-separated hash calls
```

Use the existing pure-Rust `fips204` implementation as the baseline for standard ML-DSA behavior. Do **not** reimplement FIPS 204 key generation, normal signing, verification, public key/signature encoding, or ACVP-compatible behavior from scratch when the crate already provides it. ([Docs.rs][2])

A black-box `sign()` API is still insufficient for TALUS-MPC because TALUS needs internal access to (A), (z), (w_1), `HighBits`, `LowBits`, `UseHint`, challenge expansion, and signature encoding. The implementation rule is:

```text
Reuse fips204 first.
Expose or wrap fips204 internals when needed.
Only implement TALUS-specific math and protocol logic directly.
Do not clean-room rewrite standard ML-DSA internals from the paper unless fips204 cannot reasonably be adapted.
```

The local Tidecoin production reference is the ML-DSA integration in:

```text
../rust-tidecoin/tidecoin/Cargo.toml
../rust-tidecoin/tidecoin/src/crypto/pq.rs
../rust-tidecoin/consensus-core/src/pq.rs
```

That code currently uses `fips204 = 0.4` with `ml-dsa-44`, `ml-dsa-65`, and `ml-dsa-87` features. TALUS should use this local Tidecoin path as the preferred verifier/signature-size/reference oracle in tests, including the consensus-core verifier facade.

The upstream `fips204` crate has useful internal modules for high/low bits, NTT, encodings, hashing, and ML-DSA signing flow, but many of these are `pub(crate)` in the published crate.

Decision: use the narrow vendored adapter path for now.

```text
Chosen path:
  vendor a narrow talus-core adapter copied from fips204 internals,
  with source attribution, minimal edits, and parity tests against fips204.

Deferred path:
  add a minimal fips204 extension/fork exposing only the TALUS-required hooks.

Last resort:
  implement the missing helper directly from FIPS 204 only when the helper
  is small, isolated, and covered by boundary/vector tests.
```

The goal is to avoid reinventing FIPS 204 while still exposing the internal values TALUS needs for threshold signing.

## 2. Global constants and parameter trait

Codex should define one parameter trait and three concrete suites.

```rust
pub trait MlDsaParams: Clone + Copy + 'static {
    const NAME: &'static str;

    const N: usize = 256;
    const Q: i32 = 8_380_417;
    const D: usize = 13;

    const K: usize;
    const L: usize;

    const ETA: i32;
    const TAU: usize;
    const LAMBDA: usize;
    const BETA: i32;
    const GAMMA1: i32;
    const GAMMA2: i32;
    const OMEGA: usize;
    const CTILDE_LEN: usize = Self::LAMBDA / 4;

    const ALPHA: i32 = 2 * Self::GAMMA2;

    // Number of HighBits buckets.
    // ML-DSA-44: 44
    // ML-DSA-65/87: 16
    const HIGH_MOD: i32 = (Self::Q - 1) / Self::ALPHA;

    // Use 19 bits for all α values; ML-DSA-44 fits in 18 bits,
    // ML-DSA-65/87 fit just under 2^19.
    const ALPHA_BITS: usize = 19;
}
```

Parameter values:

```text
ML-DSA-44:
  k = 4
  l = 4
  η = 2
  τ = 39
  λ = 128
  ctilde_len = 32
  β = 78
  γ1 = 2^17
  γ2 = (q−1)/88 = 95_232
  α = 190_464
  HIGH_MOD = 44
  ω = 80

ML-DSA-65:
  k = 6
  l = 5
  η = 4
  τ = 49
  λ = 192
  ctilde_len = 48
  β = 196
  γ1 = 2^19
  γ2 = (q−1)/32 = 261_888
  α = 523_776
  HIGH_MOD = 16
  ω = 55

ML-DSA-87:
  k = 8
  l = 7
  η = 2
  τ = 60
  λ = 256
  ctilde_len = 64
  β = 120
  γ1 = 2^19
  γ2 = (q−1)/32 = 261_888
  α = 523_776
  HIGH_MOD = 16
  ω = 75
```

FIPS 204 is the source of truth for ML-DSA algorithms, parameter sets, signature encoding, key encoding, context handling, pre-hash variants, and verification behavior. The implementation should include ACVP-compatible test hooks for FIPS 204 `keyGen`, `sigGen`, and `sigVer`, since NIST’s ACVP ML-DSA schema covers those modes. ([NIST][3])

## 3. `talus-core`: fips204-backed ML-DSA adapters

`talus-core` should not be a clean-room replacement for `fips204`. It should provide a stable TALUS-facing API over `fips204` and only fill gaps for threshold signing.

Reuse policy:

```text
Use fips204 directly for:
  - public and private key encoding/decoding when possible
  - standard key generation and standard signing test vectors
  - standard verification
  - signature encoding checks
  - ACVP-compatible behavior

Use local Tidecoin wrappers for:
  - product signature-size constants
  - production verification behavior
  - consensus verifier cross-checks

Expose/fork/vendor fips204 internals for:
  - HighBits/LowBits/UseHint
  - w1 encoding
  - ExpandA
  - SampleInBall
  - challenge transcript hashing
  - matrix/vector arithmetic needed to compute A*y and A*z

Implement directly in TALUS only:
  - unsigned low/high decomposition for CEF
  - BCC checks
  - public TALUS hint identity
  - CEF reconstruction formulas
```

### 3.1 Ring arithmetic

Prefer `fips204`'s existing NTT, polynomial, and matrix/vector code via a minimal extension/fork or narrow vendored adapter. Do not independently hand-write a full ML-DSA arithmetic backend unless the `fips204` reuse path is blocked and the implementation is covered by parity tests.

Implement:

```text
R_q = Z_q[X] / (X^256 + 1)

Types:
  Coeff
  Poly
  PolyVecL<P>
  PolyVecK<P>
  MatrixA<P>
```

Required operations:

```rust
impl Poly {
    fn zero() -> Self;
    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn neg(&self) -> Self;
    fn scalar_mul_small(&self, c: i32) -> Self;
    fn mul_ntt(&self, rhs: &Self) -> Self;
    fn reduce_q(&mut self);
    fn center_coeffs(&self) -> [i32; 256];
    fn norm_inf(&self) -> i32;
}
```

Tests:

```text
fips204_adapter_matches_upstream_verify_all_params
fips204_adapter_matches_upstream_signature_encoding_all_params
poly_add_sub_roundtrip
poly_mul_ntt_matches_schoolbook_for_random_inputs
ntt_inverse_ntt_roundtrip
coeff_centering_range_is_correct
all_coefficients_reduced_mod_q
```

### 3.2 FIPS helper functions

Expose these through a `fips204` extension/fork or a narrow adapter copied from the `fips204` implementation first. Implement them directly only as a last resort.

```rust
fn power2round(r: Coeff) -> (i32, i32);
fn decompose<P: MlDsaParams>(r: Coeff) -> (i32 /* high */, i32 /* low signed */);
fn high_bits<P: MlDsaParams>(r: Coeff) -> i32;
fn low_bits_signed<P: MlDsaParams>(r: Coeff) -> i32;
fn make_hint<P: MlDsaParams>(...);
fn use_hint<P: MlDsaParams>(h: bool, r: Coeff) -> i32;
```

Also implement TALUS-specific unsigned decomposition:

```rust
fn low_bits_unsigned<P: MlDsaParams>(r: Coeff) -> u32 {
    // return b in [0, α)
}

fn high_bits_unsigned<P: MlDsaParams>(r: Coeff) -> u32 {
    // return H in [0, HIGH_MOD)
}
```

The signed FIPS `LowBits` is for BCC and hint logic. The unsigned low part is for the carry-elimination masked broadcast.

Tests:

```text
decompose_reconstructs_mod_q
high_bits_range
low_bits_signed_range
low_bits_unsigned_range
use_hint_matches_fips
use_hint_public_talus_hint_identity
decompose_special_q_minus_one_boundary_case
```

Do **not** handwave `Decompose`. The (q \equiv 1 \pmod \alpha) boundary case is exactly where TALUS needs the correction bit (\delta).

## 4. ML-DSA signing math needed by TALUS

Expose these public computations by reusing `fips204` internals where possible. TALUS should not duplicate standard ML-DSA hashing, expansion, or encoding code unless `fips204` cannot be adapted.

```rust
fn expand_a<P: MlDsaParams>(rho: &[u8; 32]) -> MatrixA<P>;

fn challenge_hash<P: MlDsaParams>(
    mu: &[u8; 64],
    w1_encoded: &[u8],
) -> ChallengeBytes;

fn sample_in_ball<P: MlDsaParams>(ctilde: &ChallengeBytes) -> ChallengePoly;

fn compute_mu(pk_bytes: &[u8], msg: &[u8], ctx: &[u8]) -> [u8; 64];

fn compute_public_r<P: MlDsaParams>(
    a: &MatrixA<P>,
    z: &PolyVecL<P>,
    c: &ChallengePoly,
    t1: &PolyVecK<P>,
) -> PolyVecK<P> {
    // r = A z − c * t1 * 2^d mod q
}
```

Important FIPS hash rule:

```text
tr = H(pk, 64)
mu = H(tr || M', 64)
ctilde = H(mu || w1Encode(w1))
c = SampleInBall(ctilde)
```

Do not hash `pk || m || w1` directly. The TALUS paper notes this exact pitfall in the implementation discussion, and FIPS 204 defines the required ML-DSA signing and verification algorithms. ([arXiv][1])

## 5. BCC implementation

For a nonce commitment:

[
w = A\hat y
]

compute:

[
(w_1, r_0) = \mathrm{Decompose}(w, 2\gamma_2)
]

The Boundary Clearance Condition is:

[
\mathrm{BCC}(w) \iff \forall j:\ |r_{0,j}| < \gamma_2 - \beta
]

where:

[
\beta = \tau \eta
]

The TALUS safety theorem says that when BCC holds, subtracting (c s_2) cannot cross a rounding boundary:

[
\mathrm{HighBits}(w - c s_2, 2\gamma_2)
=======================================

# \mathrm{HighBits}(w, 2\gamma_2)

w_1
]

Therefore the final hint can be computed from public values using:

[
r = A z - c t_1 2^d
]

[
h_j = 1[
\mathrm{HighBits}(r_j, 2\gamma_2) \ne (w_1)_j
]
]

and must satisfy:

[
\mathrm{UseHint}(h_j, r_j, 2\gamma_2) = (w_1)_j
]

The paper gives the BCC safety theorem and the approximate ML-DSA-65 pass probability (p_\text{BCC} \approx 31.7%). ([arXiv][1])

Codex should implement:

```rust
fn bcc_holds<P: MlDsaParams>(w: &PolyVecK<P>) -> bool;

fn compute_talus_hint<P: MlDsaParams>(
    r: &PolyVecK<P>,
    w1: &HighBitsVec<P>,
) -> HintVec<P> {
    h_j = high_bits(r_j) != w1_j
}
```

Tests:

```text
bcc_safety_random_ml_dsa_44
bcc_safety_random_ml_dsa_65
bcc_safety_random_ml_dsa_87

For random w satisfying BCC:
  for random challenge c with τ nonzero coefficients
  for random s2 with ||s2||∞ ≤ η
  assert HighBits(w − c*s2) == HighBits(w)

hint_public_identity:
  given valid TALUS transcript under BCC
  r = A*z − c*t1*2^d
  h_j = HighBits(r_j) != w1_j
  assert UseHint(h_j, r_j) == w1_j

bcc_rate_monte_carlo:
  ML-DSA-44 expected around 0.43
  ML-DSA-65 expected around 0.317
  ML-DSA-87 expected around 0.39
```

The theoretical approximation is:

[
p_\text{BCC}
\approx
\left(1 - \frac{\beta}{\gamma_2}\right)^{kn}
]

because there are (k \cdot 256) coefficients.

## 6. Core TALUS-MPC carry-elimination formulas

For each preprocessing session, each signer (i \in S) samples an additive nonce piece:

[
\hat y_i \in R_q^\ell
]

The aggregate nonce is:

[
\hat y = \sum_{i \in S} \hat y_i
]

Each signer computes:

[
w_i = A \hat y_i
]

For every coefficient (j), decompose (w_{i,j}) into:

[
H_{i,j} \in \mathbb Z_m
]

[
b_{i,j} \in [0, \alpha)
]

where:

[
\alpha = 2\gamma_2
]

[
m = \frac{q-1}{\alpha}
]

So:

```text
m = 44 for ML-DSA-44
m = 16 for ML-DSA-65
m = 16 for ML-DSA-87
```

Each signer masks the high part and low part.

High mask:

[
\mathrm{maskH}_i \in \mathbb Z_m
]

with:

[
\sum_i \mathrm{maskH}_i \equiv 0 \pmod m
]

Low mask:

[
\rho_i \in [0, \lfloor \alpha / |S| \rfloor)
]

Broadcast coefficientwise:

[
\widetilde H_i = H_i + \mathrm{maskH}_i \pmod m
]

[
\widetilde b_i = b_i + \rho_i
]

Let:

[
B = \sum_i \widetilde b_i
]

[
t = B \bmod \alpha
]

The secure carry-comparison computes the low-mask carry bit. Do **not** name this bit `c` in code, because ML-DSA already uses `c` for the challenge polynomial. Use `kappa`, `rho_carry`, or `mask_carry`.

[
\kappa = [\sum_i \rho_i > t]
]

and the FIPS boundary correction:

[
\delta = [\sum_i \rho_i < t - \gamma_2 + \kappa\alpha]
]

Then the aggregate high bits are:

[
w_1 =
\left(
\sum_i \widetilde H_i
+
\left\lfloor \frac{B}{\alpha} \right\rfloor
-
\kappa
+
\delta
\right)
\bmod m
]

The correction term is `+\delta`. Any occurrence of `-\delta` in this document or implementation notes is a specification bug. Intuitively, when `\delta = 1`, the unsigned low part is in the upper half and FIPS signed decomposition rewrites it by subtracting `\alpha`; the high part must therefore increase by one.

This is coefficientwise over all (k \cdot 256) coefficients. The TALUS paper presents this masked-broadcast/CarryCompare structure for TALUS-MPC, including the formula for computing (w_1) locally after CSCP outputs the carry and correction bits. ([arXiv][1])

Codex should implement this as a pure function first:

```rust
fn cef_reconstruct_w1_from_clear_pieces<P: MlDsaParams>(
    pieces: &[PolyVecK<P>],
) -> HighBitsVec<P>;
```

Then as the masked protocol:

```rust
fn cef_reconstruct_w1_masked<P: MlDsaParams>(
    masked_highs: &[MaskedHigh<P>],
    masked_lows: &[MaskedLow<P>],
    kappa_bits: &[bool],
    correction_bits: &[bool],
) -> HighBitsVec<P>;
```

Tests:

```text
cef_identity_clear_random
cef_identity_masked_random
cef_identity_all_params
cef_identity_boundary_q_minus_one
cef_identity_for_all_small_exhaustive_coefficients_when_possible
cef_delta_boundary_no_low_mask_carry
cef_delta_boundary_with_low_mask_carry
cef_delta_exact_boundary
cef_delta_upper_boundary
```

For every test:

```text
direct = HighBits(sum_i w_i)
protocol = masked formula above
assert_eq!(direct, protocol)
```

Mandatory deterministic boundary cases:

```text
1. bsum = gamma2 + 1, R = 0
   kappa = 0, delta = 1
   expected high part increments by one

2. bsum = alpha - 500, R = 1000
   kappa = 1, delta = 1
   expected high part increments by one after low-mask carry correction

3. bsum = gamma2, R = 0
   delta = 0
   catches strict-boundary off-by-one errors

4. bsum = alpha - 1, R = 0
   signed low part is -1
   expected high part increments by one
```

The test suite must fail if `delta` is subtracted.

## 7. Malicious-secure MPC backend

The paper’s PRF-derived Beaver triples are not enough for your target. Replace them with authenticated triples. SPDZ-style MPC authenticates secret values using a global MAC key and multiplication triples, allowing malicious deviations to be detected. The original SPDZ work describes authenticating secret values with a global MAC key and using Beaver triples in preprocessing. ([University of Bristol][4])

### 7.1 Field choice

Use:

```text
F = GF(2^128)
```

Boolean bits are embedded as field elements (0) and (1). XOR is field addition. AND is field multiplication.

Required type:

```rust
#[derive(Clone, Copy, Zeroize)]
pub struct Gf128(u128);
```

Implement with a fixed irreducible polynomial, for example:

[
x^{128} + x^7 + x^2 + x + 1
]

Required operations:

```rust
impl Gf128 {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(self, rhs: Self) -> Self; // XOR
    fn mul(self, rhs: Self) -> Self;
    fn square(self) -> Self;
    fn inv(self) -> Option<Self>;
    fn from_bit(bit: bool) -> Self;
    fn is_zero_ct(self) -> Choice;
}
```

Tests:

```text
gf_add_commutative
gf_mul_commutative
gf_distributive
gf_inverse_nonzero
gf_square_consistency
gf_mul_matches_known_vectors
```

### 7.2 Authenticated share format

For each secret value (x \in F), party (i) holds:

[
x_i
]

[
\gamma_{x,i}
]

and also a share (\alpha_i) of the global MAC key (\alpha).

Invariant:

[
x = \sum_i x_i
]

[
\sum_i \gamma_{x,i} = \alpha x
]

Rust types:

```rust
pub struct AuthShare {
    pub value_share: Gf128,
    pub mac_share: Gf128,
}

pub struct MacKeyShare {
    pub alpha_i: Gf128,
}

pub struct AuthValue {
    pub shares: Vec<AuthShare>,
}
```

Never expose `AuthValue` in product APIs. Protocol parties only hold their own `AuthShare`.

### 7.3 Opening with MAC check

To open authenticated value (\langle x \rangle):

1. Each party broadcasts (x_i).
2. Everyone reconstructs:

[
x = \sum_i x_i
]

3. Each party broadcasts:

[
\sigma_i = \gamma_{x,i} - \alpha_i x
]

4. Check:

[
\sum_i \sigma_i = 0
]

If not, abort and blame.

Rust API:

```rust
fn open_checked(
    ctx: &mut MpcContext,
    x: AuthShare,
    label: GateLabel,
) -> Result<Gf128, MpcError>;
```

For product security, Codex should **not** defer all MAC checks to the end if an opened value will influence later public branching or output. Use round-batched MAC checks:

```rust
fn open_many_checked(
    ctx: &mut MpcContext,
    xs: &[AuthShare],
    label: RoundLabel,
) -> Result<Vec<Gf128>, MpcError>;
```

### 7.4 Authenticated multiplication

Given authenticated shares:

[
\langle x \rangle,\quad \langle y \rangle
]

and authenticated Beaver triple:

[
\langle a \rangle,\quad \langle b \rangle,\quad \langle c \rangle
]

where:

[
c = ab
]

compute:

[
d = x - a
]

[
e = y - b
]

Open (d,e) with MAC checks.

Then:

[
\langle xy \rangle
==================

\langle c \rangle

* d\langle b \rangle
* e\langle a \rangle
* de
  ]

Rust:

```rust
fn mul_authenticated(
    ctx: &mut MpcContext,
    x: AuthShare,
    y: AuthShare,
    triple: AuthTriple,
    label: GateLabel,
) -> Result<AuthShare, MpcError>;
```

Boolean AND:

```rust
fn and(
    ctx: &mut MpcContext,
    x: AuthBit,
    y: AuthBit,
    label: GateLabel,
) -> Result<AuthBit, MpcError>;
```

Boolean XOR:

```rust
fn xor(x: AuthBit, y: AuthBit) -> AuthBit {
    x + y
}
```

Boolean NOT:

```rust
fn not(x: AuthBit) -> AuthBit {
    x + public_one()
}
```

### 7.5 Triple generation

Do not implement product triples as:

```text
PRF(seed, gate_id)
```

without authentication and sacrifice.

Instead expose a protocol-facing provider interface first:

```rust
pub trait TripleProvider {
    fn take_triple_bundle(
        &mut self,
    ) -> Result<Vec<CertifiedBeaverTripleShare>, TripleProviderError>;

    fn take_triple_bundles(
        &mut self,
        count: usize,
    ) -> Result<Vec<Vec<CertifiedBeaverTripleShare>>, TripleProviderError>;
}
```

Current implementation status:

```text
Implemented:
  - TripleProvider trait in talus-mpc-core
  - UncheckedBeaverTripleShare and CertifiedBeaverTripleShare type separation
  - multiplication and CarryCompare consume only certified triple bundles
  - InMemoryTripleProvider for deterministic tests and adapter wiring
  - test-only relation certification helper for trusted-dealer scaffolding
  - provider exhaustion errors
  - redacted Debug for the in-memory provider
  - integration harness exercises MPC circuits through the provider shape
  - MAC-valid but relation-invalid c = a*b + delta candidates fail certification

Not implemented:
  - production authenticated triple generation
  - malicious-secure sacrifice/checking backend
  - persistent triple inventory
```

Production backend selection for v1:

```text
1. honest-majority information-theoretic MPC preprocessing
   Approved v1 path. Requires PQ-authenticated private channels and broadcast.

2. LPN/Ring-LPN PCG or silent VOLE-style preprocessing
   Deferred. Not part of v1 production.

3. PQ-OT/MASCOT-style preprocessing
   Deferred. Not part of v1 production.

4. LWE/RLWE FHE-SPDZ preprocessing
   Deferred. Not part of v1 production.
```

Implementation rule:

```text
No release build may enable trusted-dealer-test.
No production path may silently use an unauthenticated or dealer-generated triple source.
No multiplication or circuit API may accept unchecked triples.
```

Triple tests:

```text
valid_triples_pass_sacrifice
invalid_c_ab_relation_fails
flipped_triple_mac_fails
wrong_party_opening_is_blamed
triple_reuse_is_rejected
```

## 8. Boolean circuits for CarryCompare

The TALUS paper’s CarryCompare securely computes the low-mask carry bit:

[
\kappa = [\sum_i \rho_i > t]
]

and the correction bit:

[
\delta = [\sum_i \rho_i < t - \gamma_2 + \kappa\alpha]
]

The paper describes CSCP as a carry-safe comparison protocol using Boolean shares and Beaver triples, with a CSA reduction and prefix comparison. ([arXiv][1])

For Codex, implement a correct generic Boolean circuit first. Optimize later.

### 8.1 Authenticated bit input

Each party (i) inputs bits of (\rho_i):

[
\rho_i = \sum_{b=0}^{18} \rho_{i,b}2^b
]

Every bit must be authenticated.

```rust
pub struct AuthBit(AuthShare);
pub struct AuthU19 {
    bits_le: [AuthBit; 19],
}
```

Input checks:

```text
bitness:
  x * (x − 1) = 0

range:
  ρ_i < floor(α / |S|)

consistency:
  same ρ_i is used for:
    - masked low broadcast
    - CarryCompare input
    - blame transcript
```

Bitness test in GF(2^128):

```text
For bit x, valid iff x*x = x.
```

Range check:

```text
less_than_public(ρ_i, R)
where R = floor(α / |S|)
```

### 8.2 Adders

Implement half adder:

[
s = a \oplus b
]

[
c = a \land b
]

Full adder:

[
s = a \oplus b \oplus c_\text{in}
]

[
c_\text{out} = (a \land b) \oplus (c_\text{in} \land (a \oplus b))
]

Rust:

```rust
fn half_adder(a: AuthBit, b: AuthBit) -> (AuthBit, AuthBit);

fn full_adder(
    ctx: &mut MpcContext,
    a: AuthBit,
    b: AuthBit,
    carry: AuthBit,
) -> Result<(AuthBit, AuthBit), MpcError>;
```

### 8.3 Sum circuit

Compute:

[
\rho_\Sigma = \sum_i \rho_i
]

Because each:

[
\rho_i < \lfloor \alpha / |S| \rfloor
]

we have:

[
\rho_\Sigma < \alpha
]

so 19 bits are enough.

Generic implementation:

```rust
fn sum_u19(
    ctx: &mut MpcContext,
    values: &[AuthU19],
) -> Result<AuthU19, MpcError>;
```

Use constant circuit topology. No secret-dependent loops.

### 8.4 Compare secret value to public threshold

Implement:

```rust
fn gt_public(
    ctx: &mut MpcContext,
    x: &AuthU19,
    t: u32,
) -> Result<AuthBit, MpcError>;

fn lt_public(
    ctx: &mut MpcContext,
    x: &AuthU19,
    t: i64,
) -> Result<AuthBit, MpcError>;
```

For (x > t), scan from MSB to LSB:

```text
eq = 1
gt = 0

for b in (0..19).rev():
    xb = x[b]
    tb = public_bit(t, b)

    if tb == 0:
        gt = gt OR (eq AND xb)

    eq = eq AND NOT(xb XOR tb)
```

Implement OR as:

[
a \lor b = a \oplus b \oplus (a \land b)
]

For signed threshold in `lt_public`:

```text
if t <= 0:
  return public false

if t >= α:
  return public true

else:
  return x < t
```

### 8.5 CarryCompare function

```rust
fn carry_compare<P: MlDsaParams>(
    ctx: &mut MpcContext,
    rho_inputs: &[AuthU19],
    public_t: u32,
) -> Result<(AuthBit /* kappa */, AuthBit /* delta */), MpcError> {
    let rho_sum = sum_u19(ctx, rho_inputs)?;

    let kappa = gt_public(ctx, &rho_sum, public_t)?;

    // Need both branches because kappa is secret/authenticated.
    // delta0 = [sum < t − γ2]
    // delta1 = [sum < t − γ2 + α]
    let delta0 = lt_public(ctx, &rho_sum, public_t as i64 - P::GAMMA2 as i64)?;
    let delta1 = lt_public(ctx, &rho_sum, public_t as i64 - P::GAMMA2 as i64 + P::ALPHA as i64)?;

    // delta = kappa ? delta1 : delta0
    // kappa ? a : b = b XOR (kappa AND (a XOR b))
    let diff = xor(delta1, delta0);
    let selected = xor(delta0, and(ctx, kappa, diff)?);

    Ok((kappa, selected))
}
```

Then open (\kappa) and (\delta) only after:

```text
all opened multiplication masks in the current round pass MAC checks
all triple-sacrifice checks pass
all range checks pass
all bitness checks pass
```

## 9. Preventing malicious probing beyond Beaver triples

Authenticated triples close the specific Beaver-deviation hole, but product-grade malicious privacy also requires that malicious parties cannot use malformed preprocessing messages as an oracle.

Codex must implement these additional protections:

### 9.1 Rushing-resistant broadcast

All Round 1 preprocessing broadcasts must be simultaneous.

Use:

```text
commit phase:
  broadcast H(message || salt)

open phase:
  broadcast message || salt
  verify hash
```

or a reliable broadcast primitive with equivocation detection.

This prevents a corrupted party from waiting to see honest masked broadcasts before choosing its own (\widetilde H_i,\widetilde b_i).

### 9.2 Certified preprocessing tokens

A preprocessing token may enter the signing pool only after it is certified.

Certification requires:

```text
- all MPC MAC checks passed
- all authenticated triple checks passed
- all ρ bitness checks passed
- all ρ range checks passed
- all broadcast commitments opened consistently
- all VSS share commitments verified
- all masked-broadcast consistency checks passed
```

### 9.3 Masked-broadcast consistency

For each party (i), the following must be bound to the same transcript:

```text
nonce polynomial commitment Φ_i
nonce constant term yhat_i
w_i = A*yhat_i
H_i = HighBitsUnsigned(w_i)
b_i = LowBitsUnsigned(w_i)
maskH_i
ρ_i
Htilde_i = H_i + maskH_i mod HIGH_MOD
btilde_i = b_i + ρ_i
```

The TALUS paper does not require an up-front ZK proof for this statement.
It describes reveal-on-failure blame:

```text
Trigger:
  online z_i checks pass, but final FIPS ML-DSA verification fails

Then reveal only per-session material:
  yhat_h
  nonce polynomial openings
  rho_h
  per-session keys K_hj,tau

Then recompute:
  A*yhat_h
  H_h and b_h
  maskH_h and rho_h
  Htilde_h and btilde_h
  CSCP/CarryCompare transcript and generated triples

Then identify the malformed masked broadcast or first inconsistent CSCP gate.

Never reveal long-term pairwise seeds s_hj.
```

Production policy is stricter than the paper here. Post-challenge
reveal-on-failure is disabled by default because `z_i = y_i + c*s1_i` has
already been broadcast, and revealing enough nonce material to reconstruct
`y_i` exposes `c*s1_i = z_i - y_i`. Instead, production must certify
masked-broadcast consistency before challenge, using the approved
honest-majority IT-MPC/VSS preprocessing path. After challenge, blame is limited
to non-revealing `z_i` commitment checks. If final FIPS verification fails, the
token is consumed, no signature is released, and honest nonce/session material
is not revealed.

ZK proofs or cut-and-choose audits are optional product hardening, not the
TALUS paper's required consistency mechanism. If added later, they must be
post-quantum and reviewed before being used for production security claims.

Current implementation status:

```text
Implemented in talus-mpc:
  - MaskedBroadcastConsistencyVerifier trait
  - MaskedBroadcastConsistencyStatement and proof container
  - ClearMaskedBroadcastConsistencyVerifier for deterministic local audits
  - ProductZkMaskedBroadcastVerifier optional-hardening placeholder that returns a typed blocker
  - CutAndChooseAuditPlan for separating audited openings from certifiable tokens

Not implemented as product cryptography yet:
  - pre-challenge IT-MPC/VSS masked-broadcast consistency certification
  - pre-challenge private CarryCompare certification before token admission
  - optional pre-challenge/private BCC certification, if feasible
  - reviewed forensic reveal mode, if we decide to support one
  - reviewed optional ZK proof statement/backend, if we decide to add one
  - reviewed optional cut-and-choose parameter selection, if we decide to add one
  - integration with production PQ setup commitments
```

## 10. Key generation

The TALUS-MPC paper uses a DKG-style setup for (s_1), public-key assembly,
public matrix commitments (A s_{1,i}), and pairwise PRF seeds. It also states
the public key is (pk=(\rho_A,t_1)). ([arXiv][1])

### 10.1 State

Each party stores:

```rust
pub struct PartyKeyPackage<P: MlDsaParams> {
    pub suite: SuiteId,
    pub party_id: PartyId,
    pub n_parties: usize,
    pub threshold_t: usize,

    pub rho_a: [u8; 32],
    pub public_key: PublicKey<P>,
    pub t1: PolyVecK<P>,

    // Secret.
    pub s1_share: ShamirShare<PolyVecL<P>>,

    // Public commitments.
    pub a_s1_share_commitments: BTreeMap<PartyId, PolyVecK<P>>,

    // Pairwise seeds for preprocessing and masks.
    pub pairwise_seeds: BTreeMap<PartyId, PairwiseSeed>,

    // Authenticated MPC MAC key share.
    pub mac_key_share: MacKeyShare,

    // Persistent uniqueness.
    pub epoch: u64,
    pub next_session_counter: PersistentCounter,

    // Transcript hash of keygen.
    pub keygen_transcript_hash: [u8; 32],
}
```

### 10.2 DKG requirements

Codex must implement native DKG. The approved shape is honest-majority
information-theoretic DKG/VSS over PQ-authenticated private channels and
ML-DSA-authenticated broadcast. Reviewed PQ key-share provisioning is allowed as
an initial operational mode for running MPC before native DKG is complete, but
it must be explicit and transcript-bound; it must not become a silent trusted
dealer path.

Curated source bundle:

```text
Protocol foundations:
  - Shamir 1979 for polynomial sharing and reconstruction
  - Rabin-Ben-Or 1989 for IT-VSS with honest majority, broadcast, and
    pairwise private channels
  - BGW 1988 for arithmetic-circuit MPC over Shamir shares
  - Cramer-Damgaard-Nielsen and Cramer-Damgaard-Maurer for LSSS/VSS/MPC
    abstractions
  - Chida et al. 2018/2023 for malicious honest-majority arithmetic MPC
    with abort
```

Reference code to inspect only:

```text
  - MP-SPDZ malicious honest-majority Shamir / Rep3 / PS / SY
  - Cicada active-adversary honest-majority APIs/tests
  - MPyC passive Shamir arithmetic and interpolation tests
  - FRESCO protocol-suite and builder architecture
  - SCALE-MAMBA preprocessing/runtime separation

These are not production dependencies without separate audit and
PQ-composition review.
```

PQ infrastructure sources:

```text
  - NIST FIPS 203 ML-KEM for private channels
  - NIST FIPS 204 ML-DSA for party identities, authenticated broadcast,
    and final signature compatibility
  - NIST SP 800-185 cSHAKE/KMAC/TupleHash for transcript binding and PRFs

Do not use SLH-DSA in v1 operational identities. The approved identity scheme
is ML-DSA.
```

Codex should implement DKG with:

```text
- ML-KEM-established confidential authenticated P2P channels
- ML-DSA-authenticated broadcast with equivocation detection
- information-theoretic VSS commitments/checks
- public ML-DSA matrix commitments A*s for later z-share verification
- complaint handling
- resharing / refresh
- bounded ML-DSA secret sampling for s1/s2
```

Current implementation status:

```text
Implemented scaffold in talus-dkg:
  - validated DkgConfig with sorted party set, threshold checks, and optional
    N >= 2T - 1 deployment-shape enforcement
  - DkgSuite, KeygenEpoch, and KeygenTranscriptHash
  - public output containers for pk, rho, t1, VSS commitments, A*s1_i
    commitments, and pairwise seed commitments
  - secret-share container with redacted Debug
  - traits for bounded secret sampling, VSS, pairwise seed exchange, and
    durable transcript storage
  - typed commit/share/complaint/finalize round payloads
  - deterministic DkgLocalStateMachine that validates exact sender sets,
    directed share topology, duplicate complaints, unanimous final output,
    and public-output transcript binding
  - explicit ProvisionedKeyShare importer for reviewed PQ key-share packages
    with exact party-set, transcript, length, commitment-set, and owner checks
  - explicit Shamir interpolation-point helpers tied to configured party ids
  - scalar Shamir helpers over the ML-DSA field for evaluation, sharing, and
    reconstruction at zero
  - typed scalar IT-VSS share/complaint structures and ScalarItVssBackend
    trait shape
  - canonical scalar complaint-evidence encoding/decoding
  - InProcessScalarItVssBackend implements the first production-shaped local
    scalar VSS path: public checks, directed private shares, delivery bindings,
    canonical complaint evidence, verified-share complaint generation,
    accepted/rejected dealer resolution, and accepted-dealer scalar share
    combination without exposing a clear combined secret
  - the in-process scalar VSS backend is not final production IT-VSS yet:
    it uses hash bindings, not reviewed Rabin-Ben-Or-style information-checking
    tags over PQ-authenticated private channels
  - InProcessDistributedSmallSampler implements the exact bounded-secret
    distribution simulator: every party contributes u_i in Z_m where
    m = 2*eta + 1, inputs are checked for bitness/range/party set/transcript
    label, the sampler computes r = sum_i u_i mod m, and shares
    x = r - eta mod q
  - bounded-sampler tests cover exhaustive uniformity for m=5 and m=9 under
    fixed corrupted contributions, all-suite output bounds, no single-dealer
    control, malformed residue/bit/label/duplicate/missing inputs, s1/s2 vector
    shapes, and transcript binding across vector/coefficient labels
  - the distributed small sampler is still a simulator until wired to reviewed
    IT-VSS/MPC over PQ-authenticated private channels
  - sampled s1 now converts into canonical DkgSecretShare.s1_share packages;
    sampled s2 remains temporary DKG material for public-key assembly and is
    consumed when building shared t = A*s1+s2
  - MpcPower2RoundBackend defines the production boundary for the non-linear
    private Power2Round step: input is consumed SharedT, output is public t1
    plus transcript-bound public evidence, and forbidden outputs are t, t0, s2,
    lower bits, bit-decomposition witnesses, and simulator private material
  - ClearSimPower2RoundBackend, gated by insecure-clear-sim-power2round or
    cfg(test), reconstructs t only inside the in-process simulator, runs exact
    FIPS Power2Round coefficientwise, zeroizes t0 temporaries, emits evidence
    with backend_id = InsecureClearSimulator, and builds transcript-bound
    DkgPublicOutput; this is not production cryptography
  - ItMpcPrimeFieldBackend defines the Fq arithmetic/bit backend needed for
    private DKG Power2Round without using the GF(2^128) TALUS carry layer
  - ProductionItMpcPower2RoundBackend now implements the coefficient protocol
    against that Fq backend: random canonical 23-bit mask, masked opening
    C = r + A mod q, secret wrap/subtractor recovery of canonical R bits,
    boolean/range/equality checks, add-4095 ripple adder, and opening only
    bits 13..22 as t1
  - LocalPrimeFieldMpcBackend is a deterministic in-process backend for tests;
    it emits LocalPrimeFieldSimulator evidence and is rejected by release gates
  - InProcessShamirPrimeFieldMpcBackend carries real per-party Shamir shares
    through the Fq Power2Round circuit and records multiplication/open labels;
    multiplication/opening use local reconstruct-and-reshare in tests, so this
    is a distributed data-model simulator, emits InProcessShamirSimulator
    evidence, and is rejected by release gates
  - NetworkedShamirPrimeFieldMpcBackend is the next simulator substrate for
    task-1 private MPC: it records explicit directed in-memory round messages
    for random-bit sharing and BGW-style multiplication degree reduction, and
    broadcast messages for checked openings and assert-zero checks; it emits
    NetworkedShamirSimulator evidence and is rejected by release gates
  - TransportPrimeFieldMpcStateMachine is the local-party transport-backed MPC
    boundary: it builds canonical DKG prime-field MPC wire messages, sends
    directed values through AuthenticatedP2pTransport, sends broadcast values
    through EquivocationResistantBroadcast, validates suite/session/party-set
    context on collection, rejects replayed labels, and persists public
    accepted-round metadata through PrimeFieldMpcRoundLog
  - TransportPrimeFieldMpcPartyRuntime is the resumable single-party runtime
    wrapper: it owns one local-party state machine plus a local durable wire log,
    sends only that party's own MPC messages, collects peer messages, replays
    locally sent messages after restart, and recovers already accepted values
    from the wire log without re-querying the transport
  - PrimeFieldMpcPhaseDriverStatus and the runtime `drive_*_phase` methods
    expose the single-party phase-driver boundary: a node can send one local
    directed/broadcast phase, report what it is waiting for, collect a delivered
    phase, or recover accepted values from its durable wire log without the
    crate scheduling other parties
  - PrimeFieldMpcWireMessageLog records exact canonical sent and accepted wire
    messages for crash recovery; unlike PrimeFieldMpcRoundLog, this log can
    contain private share payloads and must be treated as local secret DKG state
  - InMemoryPrimeFieldMpcWireMessageLog and FilePrimeFieldMpcWireMessageLog
    provide test/durable implementations; the file log is idempotent for the
    same canonical message, rejects conflicting replay keys, survives reopen,
    replays sent messages without regenerating masks/shares/random bits, and
    recovers accepted messages after restart
  - DkgPrimeFieldMpcPayload carries both a round kind and typed phase; the
    transport-backed state machine exposes typed helpers for random-bit shares,
    multiplication degree-reduction shares, checked-opening shares,
    assert-zero shares, and public t1 bit openings
  - the transport-backed state machine also exposes semantic per-coefficient
    Power2Round phase helpers for mask bits, mask range checks, masked C
    openings, wrap comparison, subtractor recovery, canonical R<q checks,
    equality checks, add-4095 propagation, and t1 bit openings
  - FilePrimeFieldMpcRoundLog persists only public accepted-round metadata and
    per-coefficient completion markers, and rejects corrupt/replayed logs
  - TransportBackedShamirPrimeFieldMpcBackend now drives the same Shamir
    multiplication, checked opening/assert-zero, random-bit generation, and
    coefficient Power2Round circuit through canonical talus-wire payloads and
    TransportPrimeFieldMpcStateMachine collection phases; it emits
    TransportBackedShamirSimulator evidence and remains release-blocked because
    it still uses an in-process all-parties scheduler and test transport
  - RuntimeCoordinatedTransportShamirPrimeFieldMpcBackend is the next
    transport split: it owns one TransportPrimeFieldMpcPartyRuntime per party,
    routes only locally originated canonical wire messages between runtimes,
    drives random-bit sharing, BGW-style multiplication degree reduction,
    checked openings, assert-zero checks, and coefficient Power2Round through
    the per-party send/collect APIs, and records each runtime's durable wire
    log; it emits RuntimeCoordinatedTransportShamirSimulator evidence and is
    release-blocked because the coordinator and transports are still
    deterministic in-crate test infrastructure rather than application-supplied
    PQ-authenticated networking
  - PrimeFieldMpcPhaseCursor and the in-memory/file phase cursor logs persist
    the current single-party MPC subphase separately from sent/accepted wire
    messages, so a restarted application can resume at the precise waiting or
    collected phase
  - CursoredTransportPrimeFieldMpcPartyRuntime wires cursor persistence into
    prime-field MPC send/collect driver calls and replays sent messages on
    resume without regenerating masks, shares, or openings
  - TransportBackedPower2RoundBackend is now the release-blocked single-party
    driver boundary; it can be converted into a cursor-aware runtime, and its
    all-at-once power2round_t1 method returns
    Power2RoundRequiresSinglePartyDriver because one party cannot synchronously
    return global t1 without application-delivered rounds
  - DkgTransportStateMachine and DkgTransportPartyRuntime apply the same
    transport-driver pattern to bounded Z_m sampler and VSS setup phases:
    small-residue broadcasts, VSS public-check broadcasts, directed VSS share
    delivery, and complaint broadcasts
  - DkgWireMessageLog, InMemoryDkgWireMessageLog, FileDkgWireMessageLog, and
    LoggedDkgTransportPartyRuntime persist exact sent/accepted DKG setup wire
    messages for bounded-sampler and VSS phases; identical replay is
    idempotent, changed bytes for the same logical DKG message are rejected,
    and accepted bounded-sampler, VSS commit, VSS share, and VSS complaint
    rounds can be recovered from the local log
  - logged bounded-sampler helpers collect or recover replayed
    SmallResidueContribution rounds and feed them into
    InProcessDistributedSmallSampler, so sampled coefficients are derived from
    exact durable wire messages rather than regenerated local structs
  - logged scalar-VSS adapters encode in-process scalar public checks into DKG
    commit payloads and directed private shares into DKG share payloads,
    collect/recover those payloads from the wire log, verify receiver shares,
    emit complaint payloads, and collect/recover complaint broadcasts; this is
    still scaffold VSS because the in-process checks are hash bindings rather
    than full information-checking tags
  - DkgSetupPhaseCursor, DkgSetupPhaseCursorLog,
    InMemoryDkgSetupPhaseCursorLog, FileDkgSetupPhaseCursorLog, and
    CursoredLoggedDkgTransportPartyRuntime persist DKG setup continuation
    state separately from wire messages, so a restarted application can tell
    whether the local party last sent, waited for, or collected a bounded
    sampler/VSS setup phase; bounded-sampler cursors include vector and
    coefficient context
  - sample_logged_small_polyvec_from_log assembles full s1/s2 vectors from
    recovered accepted small-residue coefficient rounds, avoiding residue
    regeneration after restart
  - scalar-VSS logged adapters now support vector/polynomial material: DKG
    commits can carry multiple in-process scalar public checks, directed DKG
    shares can carry vectors of private scalar shares, receiver verification
    checks the whole vector, and accepted vector deals combine coefficientwise
  - assemble_logged_native_dkg_scaffold_from_logs drives native DKG assembly
    from durable logged setup state: recovered logged s1/s2 bounded-sampler
    vectors, logged vector VSS verification, formal accepted/rejected dealer
    resolution from validated complaint evidence, temporary t = A*s1+s2
    assembly, Power2Round t1 opening, pk = (rho,t1), per-party DkgKeyPackage
    output, and erasure of temporary s2/t material through the existing
    consumed SharedT path
  - resolve_in_process_scalar_vss_vector_complaints is the current formal
    scaffold complaint policy: duplicate complaint tuples are rejected, embedded
    evidence must match the complainant/dealer/receiver fields and one public
    check in the dealer's vector, any valid complaint rejects the dealer's
    entire vector contribution, and DKG aborts if accepted dealers fall below
    threshold
  - native DKG public-output assembly now separates the final signing party set
    from the accepted contribution dealer set: AS1 and pairwise-seed
    commitments remain present for every configured signing party, while VSS
    contribution commitments are filtered to the accepted dealer subset after
    complaint resolution
  - logged native DKG setup now has a complaint-positive integration path: a
    tampered VSS vector share produces valid self-authored complaints, the
    complaints are broadcast and recovered from durable logs, assembly rejects
    the bad contribution dealer while threshold still holds, and the setup
    certificate preserves the public complaint evidence
  - PublicKeyAssemblyCertificate can now carry a DkgSetupTranscriptCertificate
    with setup backend identity, sampler/VSS/complaint transcript hashes,
    accepted complaint evidence payloads, accepted/rejected dealer sets, and
    explicit release blockers; scaffold native DKG certificates mark
    ProductionItVss, ProductionItMpc, and TransportConformance as blockers
  - ensure_dkg_certificate_allowed_for_release is now certificate-level, not
    Power2Round-only: release packages must use ProductionItMpc evidence, must
    include a setup certificate, must use ProductionInformationTheoretic setup,
    and must carry no remaining release blockers
  - ensure_dkg_key_package_allowed_for_release and
    ensure_dkg_key_package_set_allowed_for_release apply the release gate at
    package boundaries: they check production certificate acceptability,
    public-key/rho/t1 consistency, package-set public material agreement,
    package-set certificate agreement, exact party coverage, and retained s1
    share encoding
  - the production IT-VSS boundary is now explicit: ItVssSharingLabel,
    ItVssInformationTag, ItVssPublicCommitment, ItVssPrivateShareDelivery,
    ItVssDealerOutput, VerifiedItVssSharingCertificate, ItVssComplaintResolution,
    and ProductionItVssBackend model the Rabin-Ben-Or-style
    information-checking path for private share delivery, complaint creation,
    complaint resolution, and verified sharing certificates; the
    ProductionInformationCheckingVssBackend now implements this method boundary
    with production backend identity, transcript-bound private delivery checks,
    hash-only public complaint evidence, and production certificate resolution,
    while release use remains gated by ProductionItVssReadiness; external
    review is tracked as post-implementation audit metadata, not as an
    implementation blocker
  - the exact bounded sampler now has a verified-input core:
    VerifiedSmallResidueInput carries dealer, sampler label, eta, residue, and
    verification provenance; sum_verified_small_residues_mod and
    sample_verified_small_coeff are the core path, while raw
    SmallResidueContribution inputs are adapted through the in-process scaffold
    verifier for tests and logged setup
  - IT-VSS artifacts now have canonical hash functions for public commitments,
    verified sharing certificates, and complaint-resolution results; bounded
    sampler inputs can be built from a VerifiedItVssSharingCertificate only
    when the IT-VSS sharing label matches the sampler vector/index, the dealer
    and production backend match, every configured receiver is accepted, and
    the certificate hash is nonzero
  - IT-VSS complaint-resolution public shape is now validated before use:
    accepted dealers must meet threshold, accepted/rejected dealer sets must be
    disjoint and known, verified certificates must be unique, production-backend
    only, complaint-hash bound, receiver-set complete, and backed by matching
    public commitments; accepted dealers without certificates and certificates
    for non-accepted dealers are rejected
  - logged native DKG assembly now routes scaffold VSS resolution through
    production-shaped IT-VSS public commitments, verified sharing certificates,
    and validate_it_vss_complaint_resolution before accepted/rejected dealers
    are used; logged bounded-sampler residue rounds are also adapted into
    certificate-backed VerifiedSmallResidueInput values before sampling
  - IT-VSS public artifacts now have canonical wire encodings and durable setup
    log persistence/recovery for public commitments and complaint-resolution
    certificates; scaffold-derived artifacts are explicitly marked with
    InProcessHashBindingScaffold, and release gates reject any setup certificate
    whose IT-VSS backend is not ProductionInformationChecking
  - IT-VSS artifact persistence is now a resolution-phase responsibility:
    persist_logged_scaffold_it_vss_artifacts_from_logs resolves and stores
    public artifacts before assembly, while assembly only recovers and validates
    those artifacts from the durable setup log
  - deterministic IT-VSS now has the same logged/cursored phase-driver surface
    as bounded sampling and scalar VSS: public commitments are broadcast under
    the IT-VSS artifact phase, directed private deliveries are encoded through
    the DKG private-share payload and recovered from the durable wire log, and
    complaint-resolution artifacts can be persisted without duplicating public
    commitments already accepted through the driver
  - information-checking complaint evidence now also binds to the exact
    directed private-delivery transcript hash; validation checks the persisted
    public commitment, the accepted private delivery, received-share hash, and
    complaint transcript before a complaint can drive dealer rejection, without
    revealing raw shares or tags
  - logged native DKG assembly has negative tests for missing IT-VSS artifacts,
    missing/tampered public artifacts, and disagreement between persisted
    IT-VSS artifacts and the logged scalar-VSS complaint decision
  - logged native DKG assembly now requires bounded-sampler residue inputs to
    have matching IT-VSS public artifacts already persisted in the setup log;
    sample_logged_small_polyvec_from_certified_log recovers residue rounds and
    public artifacts from durable logs, then feeds certificate-shaped
    VerifiedSmallResidueInput values into the sampler instead of minting
    sampler verification evidence during assembly
  - persist_logged_scaffold_it_vss_artifacts_from_logs now writes sampler
    public commitments for both s1 and s2 before writing scalar-VSS public
    artifacts and the complaint-resolution artifact
  - ProductionItVssComplaintStateMachine records the ordered IT-VSS resolver
    flow, and setup phase cursors can now persist the exact IT-VSS subphase for
    restart/resume
  - release checking now includes full setup-log matching:
    ensure_dkg_setup_log_matches_certificate_for_release scans encoded
    IT-VSS artifacts, rejects scaffold backend ids, recomputes public-artifact
    and complaint-resolution hashes from the durable log, and compares them
    with the setup certificate
  - release artifact scanning rejects DKG private-share payloads, directed
    private setup records, raw IT-VSS private deliveries, and scalar-VSS
    private-share encodings so public release bundles cannot accidentally carry
    s2/t/t0-adjacent setup secrets or private information-checking tags
  - bounded-sampler residue artifact creation now calls the IT-VSS backend
    boundary: it_vss_share_small_residue_contribution encodes one residue as a
    transcript-bound IT-VSS secret, then asks ProductionItVssBackend to produce
    the public commitment and directed private deliveries; both the
    deterministic backend and ProductionInformationCheckingVssBackend exercise
    this in tests, with release use still gated by ProductionItVssReadiness
  - verify_it_vss_private_deliveries_for_receiver is the per-party private
    delivery verification phase; it verifies accepted directed deliveries
    against public commitments through the backend and emits only public,
    hash-bound complaint payloads for failures
  - ensure_logged_dkg_setup_matches_certificate recomputes sampler, VSS
    commit/share, complaint, IT-VSS public-artifact, and IT-VSS resolution
    hashes from the local durable setup log and compares them with the public
    assembly certificate
  - ProductionPower2RoundPerPartyDriver records the ordered production driver
    phases for canonical masks, masked openings, canonical-bit recovery,
    add-4095, high-bit opening, and evidence certification; this is a scheduler
    boundary, not the complete private Power2Round circuit
  - bounded-sampler IT-VSS has a per-party driver path:
    drive_share_small_residue_it_vss creates the backend sharing, broadcasts
    its public commitment, sends directed private deliveries to peers, and logs
    IT-VSS subphase cursors; drive_verify_it_vss_private_deliveries collects
    the receiver's private deliveries, verifies them through the backend, and
    broadcasts public complaints for invalid deliveries
  - ProductionItVssReadiness gates the production IT-VSS backend identity on
    implemented information checking, PQ private channels, equivocation-
    resistant broadcast, and implemented complaint-resolution policy; external
    review is audit metadata only
  - DkgSetupRestartDecision and ensure_dkg_setup_cursors_complete_for_release
    define the setup restart/release policy: incomplete sent/waiting setup
    state can resume but cannot produce a release package
  - CertifiedToken now carries PreChallengeCertificationPolicy; token-pool
    admission rejects tokens unless masked-broadcast consistency,
    CarryCompare certification, BCC certification, persistent session storage,
    and no-post-challenge nonce reveal policy are all present
  - logged sampler IT-VSS artifacts can now be persisted from phase logs:
    persist_logged_sampler_it_vss_artifacts_for_labels_from_phase_logs selects
    accepted public commitments, verifies local directed private deliveries,
    merges matching public complaints, resolves them, and persists only the
    complaint-resolution artifact; persist_logged_sampler_it_vss_artifacts_from_phase_logs
    applies this to every s1 and s2 coefficient
  - CertifiedToken also carries typed PreChallengeCertificationEvidence for
    masked-broadcast consistency, CarryCompare, BCC, token persistence, and
    no-post-challenge-reveal policy; token certification now requires evidence
    to match the session and derived policy, not just boolean flags
  - deterministic information-checking test backend now exercises the
    production IT-VSS method shape: share_secret emits private deliveries with
    per-tagger private tags, verify_private_delivery rejects tampered shares or
    tags, complaint_for_invalid_delivery emits public hash-only evidence, and
    resolve_complaints produces scaffold-marked certificates for accepted
    dealers
  - the production IT-VSS complaint resolver phase skeleton is explicit:
    broadcast public commitments, deliver private shares/tags, verify private
    deliveries, broadcast complaints, resolve complaints, and certify accepted
    sharings; the current adapter exercises this shape but remains a scaffold
    until reviewed Rabin-Ben-Or information checking replaces it
  - the first information-checking complaint evidence model is explicit:
    public evidence carries dealer/receiver/tagger ids, label hash, expected tag
    hash, received-share hash, delivery-transcript hash, and transcript hash
    only; it must not contain raw shares, raw tags, long-term seeds, or
    unrelated receiver material
  - the complaint-positive logged DKG integration now restarts the receiver
    after complaint collection, rebuilds from durable wire logs and setup
    cursors, recovers complaint evidence from logs only, and assembles packages
    from the restored runtime
  - talus-dkg exposes a production-release-checks feature with a release-gate
    test that exercises clean production-shaped packages and rejects scaffold
    setup, simulator Power2Round, missing setup, and explicit blockers
  - native DKG setup has a restart/resume integration test that restores a
    receiver from accepted wire logs and setup cursors, resumes after an
    already-collected bounded-sampler coefficient, completes setup, and
    assembles key packages from recovered logs
  - talus-mpc DkgBackedPolynomialShareProvider can now be constructed directly
    from native DkgKeyPackage values, importing only retained s1 material into
    polynomial online signing while keeping s2/t/t0 absent
  - the current key-package signing integration uses the scaffold final
    verifier path; a standard FIPS verifier test with DKG-derived signatures
    remains blocked on production-certified preprocessing w1/nonce material,
    BCC/CarryCompare certification, and production DKG/MPC backends
  - ProductionItMpcReadiness gates the ProductionItMpc backend identity on
    per-party Power2Round, PQ-authenticated transport, durable round logs,
    and implemented blame/abort policy; external review is audit metadata only
  - DkgKeyPackage carries rho, t1, public_key, certificate, and a dedicated
    DkgS1SecretShare only; it does not contain s2, t, t0, low bits, or clear
    simulator material
  - InformationCheckingVssBackend marks the production hook for reviewed
    Rabin-Ben-Or-style private-channel information checks
  - docs/it-vss-rabin-ben-or.md now pins the v1 IT-VSS instantiation for
    ProductionInformationCheckingVssBackend: ML-DSA-only operational
    identities, no Feldman/Pedersen/DH path, audited IC tags opened only for
    audit and discarded, retained receiver-side IC tags kept receiver-private
    forever, no retained-tag replacement, no public beta_i reveal, conservative
    AbortNoBlame when disputes lack objective public evidence, scalar IT-VSS
    first for correctness tests, and batched/vector IT-VSS required before
    production DKG scale
  - talus-dkg now has the first concrete Rabin-Ben-Or IC-tag primitive types:
    canonical ItVssFq field elements, holder-side y tags, audited receiver tags
    with public audit-phase encoding, and retained receiver tags whose b/c
    values are private, redacted, and have no public encoder; tests enforce
    correct verification, mutation rejection, zero/noncanonical rejection, and
    audited-vs-retained separation
  - talus-dkg also has the scalar IT-VSS state-machine skeleton for this
    pinned instantiation: ScalarItVssContext binds suite/epoch/dealer/config
    hash/party-set hash/threshold f/label hash, ScalarItVssStateMachine enforces
    Context -> PrivatePayload -> IcAudit -> PolynomialConsistency -> Accepted,
    rejects duplicate phase message keys and unknown parties, and classifies
    terminal failures as AbortNoBlame or objective BlameDealer/BlameParty only
    when nonzero public evidence hashes exist
  - talus-dkg now implements the scalar IT-VSS honest path for correctness
    testing: caller-provided degree-f Shamir and mask polynomials are evaluated
    over F_q, private payloads carry beta_i/gamma_i plus audited and retained IC
    tags, public commitments are salted, consistency challenges are derived
    after commitments, H_r(x)=G_r(x)+e_rF(x) is checked, and accepted scalar
    sharing evidence is emitted; this is still deterministic scalar validation,
    not the production randomness source or batched/vector DKG backend
  - scalar IT-VSS reconstruction/opening is now implemented for the correctness
    path: holders broadcast beta_i and retained holder-side y tags, receivers
    verify using receiver-private retained b/c tags, points need threshold
    receiver approvals, one bad holder can be excluded, too many bad holders
    abort, all threshold-sized accepted subsets must reconstruct the same
    secret, and the output carries a reconstruction transcript hash
  - scalar adversarial hardening rejects duplicate reconstruction broadcasts,
    missing or duplicated retained tag indices, retained tags bound to the wrong
    holder, and public payloads carrying retained receiver-side tag markers;
    false IC disputes now remain AbortNoBlame unless objective public evidence
    supports blame
  - scalar IT-VSS persistence/restart scaffolding now records phase cursors,
    terminal failures, accepted state, local private-payload hashes, and
    retained receiver-tag state hashes; restart acceptance rejects incomplete,
    aborted, wrong-context, and bad-private-state logs before any scalar sharing
    can be treated as accepted
  - IT-VSS v1 release policy is now a typed gate: ProductionInformationChecking
    readiness rejects scalar-per-coefficient DKG mode, public beta_i reveal, and
    any mode that allows retained receiver-side IC tags in public artifacts;
    scalar IT-VSS release-state validation also rejects incomplete or aborted
    restart logs before accepted evidence can be used
  - batched/vector IC tags are now represented directly: one hidden scalar
    multiplier authenticates a whole F_q vector as c_vec=beta_vec+b*y_vec,
    audited vector receiver tags have public audit encoding, and retained
    vector receiver tags keep b/c_vec private, redacted, and unavailable to
    public encoders
  - vector IT-VSS now has a deterministic honest-path deal/accept flow:
    vector Shamir shares, vector mask shares, salted private-payload
    commitments, audited/retained vector IC tags, vector polynomial-consistency
    rounds, and accepted vector evidence are all checked before acceptance
  - vector IT-VSS reconstruction/opening is implemented for the correctness
    path: holders broadcast vector beta_i plus retained y_vec tags, receivers
    verify with receiver-private retained b/c_vec tags, threshold-approved holder
    points are reconstructed coordinatewise, forged holders are excluded, and
    too many forged holders abort
  - accepted vector IT-VSS openings now adapt into the bounded sampler:
    VerifiedSmallResidueInput::from_vector_it_vss_opening checks whole-vector
    domain binding, reconstruction transcript binding, party set, vector length,
    and Z_m residue range, then emits per-coordinate verified inputs consumed by
    sample_verified_small_polyvec
  - logged/native certified sampling now expects whole-vector sampler IT-VSS
    artifacts rather than per-coefficient sampler artifacts:
    sample_logged_small_polyvec_from_certified_log uses vector-domain
    commitments, and the scaffold artifact generator emits one sampler
    commitment per dealer per s1/s2 vector
  - the sampler IT-VSS phase driver now has a vector-domain path:
    drive_share_small_residue_vector_it_vss creates one vector-domain
    commitment per dealer/vector, sends directed private deliveries, and the
    durable private-share replay key includes the IT-VSS label_hash so s1/s2
    deliveries to the same receiver cannot be replay-collapsed
  - InMemoryNativeDkgScaffoldCoordinator drives the scaffold native DKG setup
    sequence end-to-end over crate transport interfaces:
    raw sampler residues, vector-domain sampler IT-VSS, scalar VSS setup logs,
    certified s1/s2 sampling, and public-key assembly
  - native DKG coordinator release readiness is explicit:
    ProductionNativeDkgCoordinatorReadiness requires an application-supplied
    transport scheduler, ML-KEM private channels, ML-DSA operational identities,
    reliable-broadcast conformance, production IT-VSS, production IT-MPC
    Power2Round, durable restart policy, and no scaffold backends
  - NativeDkgApplicationSetupDriver is the application-owned setup scheduler
    boundary:
    embedding software supplies authenticated transport and durable wire/cursor
    logs, while the crate exposes typed resumable phases for bounded-sampler
    residues, vector-domain sampler IT-VSS, scalar VSS setup, complaints, and
    resume cursors
  - native DKG app-driver conformance reaches scaffold assembly without using
    the in-memory coordinator:
    tests drive sampler residues, vector IT-VSS, scalar VSS, artifact
    persistence, certified sampling, and public-key assembly through
    NativeDkgApplicationSetupDriver-typed helpers
  - the in-memory scaffold coordinator advertises a non-release profile:
    COORDINATOR_KIND is InMemoryScaffold, PRODUCTION_ALLOWED is false, and
    NativeDkgCoordinatorReleaseProfile rejects it with InsecureNativeDkgCoordinator
  - Native DKG transport evidence is an app-facing skeleton, not a networking
    stack:
    applications provide ML-KEM channel/session evidence, ML-DSA operational
    identity evidence, and reliable-broadcast evidence; TALUS derives the
    existing PQ session binding and expected wire context from those hashes
  - app-driver restart/delay coverage now includes delayed sampler broadcast,
    delayed vector IT-VSS private delivery, restart from a waiting vector IT-VSS
    cursor, and complaint collection before/after all broadcasts arrive
  - vector IT-VSS hardening rejects retained-tag public leakage, wrong
    label/domain hashes, malformed retained-y vector lengths, and missing
    retained tags
  - ensure_native_dkg_assembly_output_allowed_for_release gates complete
    assembly outputs and rejects scaffold output material
  - ensure_native_dkg_release_context_allowed_for_release is the composed
    product-facing native DKG release guard: it requires package/certificate
    release acceptance, setup artifact logs matching the certificate, completed
    setup cursors, production coordinator/backend readiness, no private setup
    payloads in release logs, and NativeDkgTransportEvidence bound to the same
    ML-DSA suite, keygen transcript, and party set
  - batched/vector IT-VSS has an explicit facade:
    ItVssBatchedSecret, ItVssBatchedDealerOutput,
    ensure_it_vss_batched_vector_label, and
    it_vss_share_batched_vector_secrets require whole-vector s1/s2 labels
    with index=None and reject scalar-per-coefficient or auxiliary-domain
    labels; it_vss_share_small_residue_vector_batches emits one public
    commitment per dealer/vector for the bounded sampler path
  - the app-driver path can now drive the S1/S2 vector batch end-to-end:
    drive_share_small_residue_vector_batches_it_vss broadcasts one batched
    commitment artifact per dealer, sends one private-delivery batch per
    receiver, and persists the IT-VSS subphase cursor; the batch resolver
    recovers artifacts from durable logs, verifies local vector deliveries,
    merges public complaints, and rejects a dealer's whole S1/S2 batch when
    any vector delivery is invalid
  - batched private-delivery collection counts distinct sender parties rather
    than flattened inner vector deliveries, so a single S1/S2 delivery batch
    cannot advance a round that is still missing another sender; restart tests
    cover waiting public-artifact and private-delivery cursors plus log-only
    batch resolution after restart
  - batch IT-VSS complaint handling now covers the full app-driver lifecycle:
    generated complaints are broadcast, delayed complaint delivery produces a
    wait cursor, restart resumes from that cursor, and resolution is recovered
    from logs; adversarial tests reject duplicate inner deliveries, wrong
    receiver batches, mixed-dealer batches, wrong label hashes, and IT-VSS
    complaints whose labels are outside the expected S1/S2 vector batch
  - release scans include batch private-delivery payloads, and the in-memory
    native DKG scaffold coordinator now uses the same S1/S2 batch vector
    IT-VSS driver rather than sequencing S1 and S2 as separate vector phases
  - scalar VSS log verification filters the shared VssShare phase to scalar
    private-share payloads, so sampler IT-VSS private deliveries can coexist in
    the same durable setup log
  - talus-wire encodes/decodes DkgSmallResiduePayload for bounded sampler
    residue inputs
  - talus-wire encodes/decodes DkgPrimeFieldMpcPayload for DKG private-MPC
    subprotocol messages
  - InMemoryDkgTranscriptStore and FileDkgTranscriptStore persist accepted DKG
    epochs and reject epoch reuse or corrupt durable logs
  - new adversarial DKG tests cover equivocated sampler inputs, rushing/wrong
    transcript labels, malformed small residues, public-output shape failures,
    and durable transcript-store restart behavior
  - Power2Round tests cover exact FIPS boundary coefficients, prime-field MPC
    coefficient boundaries, in-process Shamir coefficient boundaries,
    networked Shamir coefficient boundaries and round-message recording,
    transport-backed Shamir coefficient boundaries over canonical wire phases,
    runtime-coordinated multi-party runtime coefficient boundaries,
    single-party phase-driver wait/collect behavior under delayed private
    delivery, reordered private delivery, duplicate private delivery, broadcast
    missing-view waits, broadcast equivocation, sent-message replay after
    restart, and accepted-value recovery after restart,
    replayed prime-field MPC message-label rejection,
    transport-backed prime-field MPC directed/broadcast round collection,
    resumable single-party runtime replay,
    durable wire-message logging/reopen/replay/accepted-value recovery,
    typed phase mismatch, wrong receiver, wrong label hash, context/replay
    rejection, broadcast equivocation rejection, durable public accepted-round
    logging, per-coefficient completion logging, corrupt-log rejection,
    release-blocked backend skeleton behavior, and production readiness gating,
    noncanonical r+q witness rejection, non-boolean bit rejection, full-vector
    parity across ML-DSA-44/65/87, clear simulator parity with reconstructed t,
    package exclusion of s2/t/t0 material, and a release guard rejecting the
    insecure simulator backend
  - test-only clear Shamir VSS dealing/verification helpers for deterministic
    invalid-share, round-verification, complaint-payload, and complaint-resolution
    tests
  - test-only scalar DKG combination that sums accepted dealer contributions
    and rejects transcripts below threshold after complaints
  - test-only bounded-vector scaffolding that validates ML-DSA s1/s2 shape,
    enforces input coefficients in [-eta, eta], and rejects naive combined
    outputs outside [-eta, eta]
  - canonical local BoundedSecretVectorShare encoding/decoding for typed
    DkgSecretShare.s1_share bytes, with suite, party, point, length, and
    field-value checks
  - ProvisionedKeyShare import validates canonical typed s1_share bytes for
    the configured suite and owner party
  - test-only provisioning package construction connects bounded-vector DKG
    output to importable ProvisionedKeyShare packages
  - test-only end-to-end DKG harness covers config, bounded-vector deals,
    complaint-style dealer rejection, accepted dealer set, encoded
    DkgSecretShare packages, and ProvisionedKeyShare import
  - talus-mpc decodes imported DkgSecretShare.s1_share bytes into the existing
    online PolyVec shape through polyvec_from_dkg_s1_share and
    DkgBackedPolynomialShareProvider
  - online tests cover DKG s1 shape mapping, party binding, session binding,
    and typed signing through the DKG-backed share provider
  - ProductionDkg::start enters the first commit phase; product callers that
    need readiness enforcement use ProductionDkg::start_with_readiness, which
    requires the application-supplied coordinator/readiness claim before start

Not implemented as production cryptography yet:
  - PQ key-share provisioning ceremony and concrete PQ channel/auth
    implementation around imported packages
  - native honest-majority IT-DKG/VSS
  - malicious-secure bounded distributed sampler for ML-DSA s1/s2
  - IT-VSS backend and complaint resolution
  - networked Shamir/IT-MPC implementation of ItMpcPrimeFieldBackend
    over concrete PQ-authenticated transport and implemented blame rules; the
    runtime-coordinated simulator and single-party phase-driver tests now split
    Power2Round-style phases across per-party runtimes and durable wire logs,
    but the full vector Power2Round backend still uses deterministic in-crate
    scheduling rather than the embedding application's ML-KEM/ML-DSA
    authenticated transport adapter, retry policy, and reliable broadcast
    implementation
  - vectorized/batched private Power2Round execution: the current scalar
    per-coefficient transport path is a correctness stress path, not the
    production execution model
  - encrypted share delivery over authenticated PQ-safe P2P
  - equivocation-resistant broadcast integration
  - refresh/resharing
```

### DKG Power2Round performance requirement

Production native DKG must not execute private `Power2Round` as thousands of
independent scalar mini-protocols.

For ML-DSA-44:

```text
t has k * 256 = 4 * 256 = 1024 coefficients
```

The current scalar transport correctness path runs the full private bit circuit
per coefficient. One coefficient performs roughly:

```text
~487 MPC multiplications
~23 random-bit sharing phases
~64 checked openings / assert-zero broadcasts
```

For a 3-party Shamir transport harness, this is on the order of:

```text
~4,500-4,700 private deliveries per coefficient
~200 protocol broadcast messages per coefficient
~5,000 in-memory delivery/log records per coefficient
```

Running that for all ML-DSA-44 coefficients reaches millions of delivery/log
operations in debug tests. Over a real network, the worse problem is sequential
round structure: scalarizing the circuit makes the cost scale by both circuit
depth and coefficient count. That is not an acceptable production DKG shape.

The production backend must use vectorized IT-MPC primitives:

```text
ShareVec       = vector of field shares across all coefficients
BitShareVec    = vector of secret bits across all coefficients
open_many      = one batched opening for many shares
assert_zero_many = one batched check transcript for many zero checks
mul_many_by_layer = one round per multiplication layer, not per scalar gate
```

Private `Power2Round([t]) -> t1` must batch across coefficients:

```text
1. generate/certify random canonical masks for all coefficients together
2. open all masked C values together
3. compute A > C comparisons by bit layer across all coefficients
4. recover canonical R bits by subtractor layer across all coefficients
5. batch R < q and R == t mod q checks
6. add 4095 by ripple layer across all coefficients
7. open only all t1 high bits together
```

The target cost model is:

```text
bad scalarized shape:
  rounds * coefficients

required batched shape:
  rounds over vector payloads
```

Full-vector scalar transport tests must be marked slow/ignored or benchmark
only. Default tests should keep coefficient-level transport conformance,
release-gate checks, and fast vector parity tests that do not route millions of
scalar messages.

Before production release, add counters and benchmarks for:

```text
MPC multiplication gates
MPC multiplication layers
private deliveries
broadcast messages
opened values
wire bytes
durable log bytes
wall-clock time under LAN/WAN latency profiles
```

Selected product design direction:

```text
Use reviewed PQ key-share provisioning as an initial setup mode.
Implement native honest-majority IT-DKG/VSS as a mandatory product component.

Every accepted keygen transcript must also publish public ML-DSA matrix A*s1_i
commitments for later partial z_i verification and pairwise seed commitments
for preprocessing/triple derivation.

Plain Shamir DKG is not sufficient by itself because ML-DSA key material must be
bounded: s1/s2 coefficients must be in [-eta, eta]. The bounded distributed
sampler is the review-critical DKG subprotocol.

Classical Pedersen DKG/VSS and classical DH/AKE are test/research-only and
must not be production security dependencies.
```

This is a release blocker, not a cleanup task. The crate may expose the
state-machine shape and test hooks now, but production key generation must keep
returning a typed blocked error until reviewed PQ key-share provisioning and
native IT-DKG/VSS semantics, complaint handling, bounded sampling, and proof
obligations are complete.

The generated secret must satisfy:

[
|s_1|_\infty \le \eta
]

Use two setup modes:

```text
1. dealer-test mode:
   only for tests and differential testing

2. product setup mode:
   reviewed PQ key-share provisioning as an initial mode
   native honest-majority IT-DKG/VSS as a mandatory product component
```

Do not silently replace DKG with a trusted dealer in production. If the product
uses key-share provisioning before DKG is complete, the ceremony and transcript
binding must be explicit, reviewed, post-quantum secure, and produce the same
PartyKeyPackage/public transcript shape as native DKG.

### 10.3 Public key assembly

Parties compute:

[
t = A s_1 + s_2
]

[
(t_1,t_0) = \mathrm{Power2Round}(t,d)
]

[
pk = (\rho_A,t_1)
]

Implementation boundary:

```text
SharedT:
  temporary Shamir/IT-MPC shares of t = A*s1+s2
  consumed by MpcPower2RoundBackend
  no Debug secret material
  no production serialization
  zeroized on drop

MpcPower2RoundBackend:
  input: consumed SharedT
  output: PublicT1 plus public Power2RoundEvidence
  forbidden output: t, t0, s2, lower bits, bit-decomposition witnesses,
                    simulator transcript material

ClearSimPower2RoundBackend:
  allowed only behind insecure-clear-sim-power2round or cfg(test)
  reconstructs t in process
  runs exact FIPS Power2Round coefficientwise
  returns t1 and public evidence
  zeroizes t0 temporaries
  must be rejected by production release gates

ProductionItMpcPower2RoundBackend:
  implemented against the ItMpcPrimeFieldBackend trait
  production-complete only after the backend is a reviewed distributed
  Shamir/IT-MPC implementation over PQ-authenticated channels
```

The implemented circuit performs canonical private bit decomposition of every
coefficient `r in Z_q`, enforces boolean bits, enforces the represented integer
is `< q`, adds the FIPS rounding constant `4095`, opens only high bits
`13..22` of `r + 4095`, and erases lower-bit witnesses. The `< q` check is
mandatory because `2^23 - q = 8191`; without canonical range checking, an
alternate representation `r + q` could produce the wrong high bits.

TALUS-MPC online signing does not need (s_2) or (t_0), because BCC allows the hint to be computed from public values when the nonce is good. The paper’s key generation discussion notes using (A s_{1,i}) commitments for public-key assembly and later blame attribution. ([arXiv][1])

## 11. Preprocessing protocol

### 11.1 Inputs

```text
KeyPackage for each party
signing set S, |S| = T
session id τ
parameter set P
```

### 11.2 Session ID

Generate:

```text
τ = keygen_transcript_hash || epoch || monotonic_counter || 128-bit random salt
```

Rules:

```text
- τ must be globally unique
- τ must be persisted before use
- τ must survive process restart
- τ must be bound into every PRF, every MAC check, every message, every transcript
- reuse of τ is a fatal error
```

The TALUS paper explicitly warns that reusing the preprocessing session identifier is equivalent to reusing PRF-derived masks/triples and breaks security. ([arXiv][1])

The current implementation exposes this as `SessionStore` and
`SessionCounterStore`. `SessionRegistry` and `SessionCounter` are deterministic
in-memory implementations for local harnesses; `FileSessionRegistry` and
`FileSessionCounter` are `std` file-backed crash/reopen test backends. A
production deployment still needs an atomic storage and locking model for
multi-process or multi-threaded session allocation.

### 11.3 Nonce DKG

Each party (h \in S):

1. Samples nonce constant term:

[
\hat y_h
]

2. Samples degree-((T-1)) Shamir polynomial:

[
g_h(X) = \hat y_h + a_{h,1}X + \cdots + a_{h,T-1}X^{T-1}
]

3. Sends (g_h(i)) privately to party (i).

4. Broadcasts commitments:

[
\Phi_{h,k} = A a_{h,k}
]

Each party (i) verifies received share:

[
A g_h(i)
========

\sum_{k=0}^{T-1} i^k \Phi_{h,k}
]

Party (i)’s aggregate nonce share:

[
\hat y_i^\text{share} = \sum_{h \in S} g_h(i)
]

The aggregate nonce is:

[
\hat y = \sum_{h \in S} \hat y_h
]

### 11.4 Mask derivation

For high masks:

For each pair (a<b), derive:

[
r_{ab} = \mathrm{PRF}(K_{ab,\tau}, "maskH" || coefficient) \bmod m
]

Then:

[
\mathrm{maskH}*i =
\sum*{j>i} r_{ij}
-----------------

\sum_{j<i} r_{ji}
\pmod m
]

This guarantees:

[
\sum_i \mathrm{maskH}_i \equiv 0 \pmod m
]

For low masks:

[
\rho_i \in [0, \lfloor \alpha / |S| \rfloor)
]

Use transcript-bound deterministic derivation plus local randomness:

```text
rho_seed_i = H(
  "TALUS rho" ||
  τ ||
  party_id ||
  all pairwise PRF outputs ||
  local randomness commitment
)

ρ_i = rho_seed_i mod floor(α / |S|)
```

Then feed the bit decomposition of (\rho_i) into the authenticated MPC input protocol.

### 11.5 Masked broadcast

Each party (h) computes:

[
w_h = A\hat y_h
]

[
H_h = \mathrm{HighBitsUnsigned}(w_h)
]

[
b_h = \mathrm{LowBitsUnsigned}(w_h)
]

Broadcast:

[
\widetilde H_h = H_h + \mathrm{maskH}_h \pmod m
]

[
\widetilde b_h = b_h + \rho_h
]

Also broadcast:

```text
- nonce VSS commitments Φ_h
- masked-broadcast commitment/proof
- authenticated input commitment for ρ_h bits
- transcript hash
```

### 11.6 CarryCompare

For each coefficient (j):

Public:

[
B_j = \sum_h \widetilde b_{h,j}
]

[
t_j = B_j \bmod \alpha
]

MPC private inputs:

[
\rho_{h,j}
]

Authenticated MPC computes and opens:

[
\kappa_j = [\sum_h \rho_{h,j} > t_j]
]

[
\delta_j = [\sum_h \rho_{h,j} < t_j - \gamma_2 + \kappa_j\alpha]
]

Then everyone computes:

[
(w_1)_j =
\left(
\sum_h \widetilde H_{h,j}
+
\left\lfloor \frac{B_j}{\alpha} \right\rfloor
-
\kappa_j
+
\delta_j
\right)
\bmod m
]

Store:

```rust
pub struct PreprocessedToken<P: MlDsaParams> {
    pub session_id: SessionId,
    pub signing_set: Vec<PartyId>,
    pub w1: HighBitsVec<P>,
    pub y_share: PolyVecL<P>,
    pub nonce_commitments: NonceCommitments<P>,
    pub preprocessing_transcript_hash: [u8; 32],
    pub certification: CertificationProof,
    consumed: bool,
}
```

A token is allowed into the pool only if certified.

## 12. Online signing protocol

The online protocol consumes one certified token.

### 12.1 Sign request

Assembler broadcasts:

```text
SignRequest {
  protocol_version
  suite
  session_id
  signing_set
  message or external_mu
  context
  token_transcript_hash
}
```

Every party verifies:

```text
- token exists
- token is certified
- token is unused
- signing set matches
- message/context encoding is canonical
- session id matches
```

### 12.2 Challenge

Compute:

[
\mu = H(tr || M', 64)
]

[
\widetilde c = H(\mu || \mathrm{EncodeW1}(w_1))
]

[
c = \mathrm{SampleInBall}(\widetilde c)
]

### 12.3 Partial response

Each party (i) computes:

[
z_i = \hat y_i^\text{share} + c \cdot s_{1,i}
]

The implementation must persist token consumption before requesting or releasing
online partials, so a crash or final-verification failure cannot reuse the same
nonce token. Then it zeroizes local nonce-share material as soon as the typed
partial has been computed.

```text
- reject immediately if durable consumed-token state already contains session_id
- mark token consumed
- persist consumed state
- compute typed partial z_i from y_i and s1_i
- zeroize nonce share y_i
```

The current implementation exposes this durability boundary as
`TokenConsumptionStore`. `ConsumedTokenStore` is the deterministic in-memory
implementation for local harnesses, and `FileConsumedTokenStore` is a `std`
append-only log used by crash/reopen tests. A production deployment still needs
to choose the durable storage backend and locking model.

Party sends:

```text
PartialSignature {
  session_id
  party_id
  z_i
  transcript_hash
}
```

### 12.4 Partial response verification

The assembler checks each (z_i) using public commitments.

Expected:

[
A z_i
=====

A \hat y_i^\text{share}
+
c \cdot A s_{1,i}
]

From nonce commitments:

[
A \hat y_i^\text{share}
=======================

\sum_{h \in S}
\sum_{k=0}^{T-1}
i^k \Phi_{h,k}
]

From keygen commitments:

[
A s_{1,i}
]

If:

[
A z_i \ne A \hat y_i^\text{share} + c A s_{1,i}
]

then output:

```text
Blame(i)
```

and do not continue.

The current implementation exposes this as an injected
`PolynomialPartialVerifier` on the typed online signing path. The
commitment-backed verifier derives `A` from the FIPS public-key seed, computes
`A*z_i`, checks it against public `A*y_i` and `A*s1_i` commitments, and returns
`Blame(i)` before aggregation if the identity fails. A no-op verifier exists only
for scaffolding tests that intentionally do not model public commitments.

### 12.5 Aggregate response

Compute Lagrange coefficients for signer set (S):

[
\lambda_i = \prod_{j \in S, j \ne i} \frac{0-j}{i-j} \pmod q
]

Aggregate:

[
z = \sum_{i \in S} \lambda_i z_i
]

The current implementation has a deterministic in-process typed entrypoint
(`sign_polynomial_with_token`) that consumes a certified token, obtains each
party's typed `(y_i, s1_i)` share, computes typed partials, aggregates them,
derives `A*z` from the FIPS public-key seed, computes TALUS public hints, encodes
a FIPS-shaped candidate, and returns it only after the injected independent
verifier accepts it. Both additive aggregation for local tests and
Lagrange-at-zero aggregation for Shamir-style shares are implemented. Product
key-share generation still has to guarantee that its public interpolation points
match the online aggregation mode.

Check:

[
|z|_\infty < \gamma_1 - \beta
]

If this fails, consume token and retry with a new token. Do not output anything derived from this attempt.

### 12.6 Hint

Compute public:

[
r = A z - c t_1 2^d
]

Compute:

[
h_j =
1[
\mathrm{HighBits}(r_j,2\gamma_2) \ne (w_1)_j
]
]

Check:

[
\mathrm{wt}(h) \le \omega
]

Encode:

[
\sigma = (\widetilde c, z, h)
]

### 12.7 Final verification gate

Before returning:

```rust
assert!(ml_dsa_verify(pk, message, context, sigma));
```

If verification fails:

```text
- do not return sigma
- consume token
- retry if max_attempts not reached
- otherwise return RetryExhausted
```

Never release invalid signatures. The TALUS paper emphasizes that final signatures are standard FIPS 204 signatures and that TALUS relies on verification of the assembled signature before output. ([arXiv][1])

## 13. Retry policy

For ML-DSA-65:

[
p_\text{BCC} \approx 0.317
]

Probability of at least one success in (K) attempts:

[
p_K = 1 - (1-p_\text{BCC})^K
]

Suggested defaults:

```text
K = 13:
  success probability ≈ 99.3% for ML-DSA-65

K = 19:
  success probability ≈ 99.9% for ML-DSA-65
```

API:

```rust
pub enum SignOutcome<P: MlDsaParams> {
    Signature(Signature<P>),
    RetryExhausted { attempts: usize },
    Blame(PartyId),
}
```

Do not hide retries from observability. The API may loop internally, but logs and metrics should report:

```text
attempts_used
tokens_consumed
bcc_or_verify_failures
malicious_blames
retry_exhaustions
```

Do not log secrets, shares, nonces, challenges, or raw (z_i).

## 14. Blame protocol

Blame must be split into **offline blame** and **online blame**.

### 14.1 Offline blame

Offline blame happens before a token enters the signing pool.

Detect:

```text
- invalid VSS share
- malformed Round 1 broadcast
- failed MAC check
- failed triple sacrifice
- invalid ρ bitness
- invalid ρ range
- inconsistent masked-broadcast proof
- equivocation in broadcast
```

Offline blame may reveal preprocessing-only data because no challenge has been issued and no (z_i) has been sent. Still, reveal only the minimum needed to identify the deviator.

### 14.2 Online blame

Online blame must not reveal honest nonce material.

Online blame handles:

```text
- missing partial response
- malformed partial response
- z_i inconsistent with commitments
- replayed session
- wrong signing set
```

Blame condition:

[
A z_i \ne A \hat y_i^\text{share} + c A s_{1,i}
]

Return:

```text
Blame(i)
```

Do not reveal (\hat y_i), aggregate (\hat y), or secret shares after challenge computation.

### 14.3 Verify failure after valid z checks

If all (z_i) commitment checks pass but final FIPS verification fails:

```text
- treat as BCC/rejection failure
- consume token
- retry
- no blame
- no nonce reveal
```

This is important. Revealing nonce material after (z_i = y_i + c s_{1,i}) has been sent can expose key material.

## 15. Message and transcript design

Every message must include:

```text
protocol_version
suite_id
parameter_set
keygen_transcript_hash
session_id
round_id
sender_party_id
signing_set_hash
payload
payload_length
domain_separator
```

Transcript hash:

```text
TH_0 = H("TALUS-MPC transcript v1" || suite || pk)
TH_{r+1} = H(TH_r || canonical_round_messages)
```

Rules:

```text
- all hashes domain-separated
- all messages canonical
- all integer encodings fixed-width little-endian or big-endian, but one only
- no serde maps for consensus-critical ordering unless sorted
- reject duplicate party messages
- reject unknown party IDs
- reject messages from outside signing set
- reject cross-suite replay
```

Current implementation status: `talus-wire` provides a fixed-width canonical
little-endian envelope carrying protocol version, suite, keygen transcript hash,
session id, round id, sender party id, signing-set hash, payload kind/domain,
and payload length. It also includes typed codecs for preprocessing
commit/open, signing request, partial signature, and final signature payloads,
DKG commit/share/complaint/finalize payloads, plus context validation,
duplicate-sender rejection, canonical signing-set hashing, and order-stable
round transcript hashing. The same crate now exposes runtime-agnostic
`AuthenticatedP2pTransport` and `EquivocationResistantBroadcast` traits,
with an `InMemoryTransport` test bus that validates channel sender identity,
unknown parties, duplicate senders, incomplete broadcast views, and
equivocating broadcast payloads. `PqTransportSessionBinding` gives
application transport adapters a canonical boundary for binding ML-KEM
channel/session establishment and ML-DSA operational identity authentication
into the TALUS `ExpectedContext`; DKG prime-field MPC state machines can now
accept that externally supplied context and place its session id into outgoing
wire headers. `SynchronousBroadcastContract` defines the product broadcast
semantics expected from embedding applications: for each session, round, and
sender, every honest observer must deliver identical canonical wire bytes or
the adapter must report equivocation/abort; incomplete views are waiting states,
not protocol progress. Tests now include an explicit application-provided PQ
adapter harness that binds ML-KEM session establishment and ML-DSA operational
identity authentication into the TALUS session context, detects duplicate
private-message replay, rejects wrong expected contexts, and exercises
equivocation through the synchronous broadcast contract.

Transport ownership decision:

```text
TALUS crates must not implement or choose TCP, QUIC, libp2p, TLS, Noise,
tokio, async-std, retry policy, socket ownership, or deployment identity.

TALUS crates define:
  - canonical WireMessage encodings
  - typed protocol payloads
  - transport traits
  - protocol state machines
  - transcript validation
  - in-memory test transports

Embedding software provides:
  - concrete networking stack
  - ML-KEM channel/session establishment
  - ML-DSA operational party identity authentication
  - durable message logs and retransmission
  - deployment key management and access control

InMemoryTransport and NetworkedShamirPrimeFieldMpcBackend are test/protocol
adapters. They must not become production networking backends.

Testing rule:
  - protocol unit tests may use InMemoryTransport to model an already
    authenticated channel
  - transport-adapter integration tests must exercise real ML-KEM session
    establishment and ML-DSA party identity authentication
  - tests must reject wrong party keys, wrong session/context binding,
    downgraded suite ids, replayed messages, sender/header mismatches, and
    equivocated broadcasts
  - current tests perform deterministic ML-KEM-768 encapsulation/decapsulation
    and ML-DSA-65 identity signing/verification, derive a
    PqTransportSessionBinding, bind its session id into the wire context, pass
    that context into the DKG transport state machine, and reject wrong
    identity, wrong session context, downgraded suite, duplicate party ids, and
    malformed party sets
```

## 16. State machine and nonce lifetime

Use Rust types to enforce one-time use.

```rust
pub struct FreshToken<P: MlDsaParams>(PreprocessedToken<P>);
pub struct PendingToken<P: MlDsaParams>(PreprocessedToken<P>);
pub struct ConsumedToken<P: MlDsaParams>(SessionId);
```

Allowed transitions:

```text
FreshToken -> PendingToken -> ConsumedToken
FreshToken -> ConsumedToken on offline invalidation
PendingToken -> ConsumedToken on success, verify failure, timeout, or blame
```

Forbidden:

```text
ConsumedToken -> FreshToken
PendingToken -> FreshToken
cloning FreshToken
serializing y_share after use
```

Implementation:

```rust
impl Drop for PreprocessedToken<_> {
    fn drop(&mut self) {
        self.y_share.zeroize();
    }
}
```

Persistent storage must record token consumption before sending (z_i).

## 17. Test plan

### 17.1 FIPS 204 tests

Use FIPS 204 and ACVP-compatible JSON tests for:

```text
ML-DSA-44 keygen/sign/verify
ML-DSA-65 keygen/sign/verify
ML-DSA-87 keygen/sign/verify
valid and invalid signature verification
modified message
modified ctilde
modified z
modified hint
context handling
external mu handling
pre-hash mode if supported
```

NIST’s ACVP ML-DSA schema covers `keyGen`, `sigGen`, and `sigVer` test groups and specifies the expected test vector fields. ([NIST Pages][5])

Use Tidecoin's local ML-DSA integration as the first code oracle:

```text
../rust-tidecoin/tidecoin/src/crypto/pq.rs
../rust-tidecoin/consensus-core/src/pq.rs
```

Cross-check TALUS signatures against:

```text
tidecoin::crypto::pq::PqSignature::verify_msg32 / verify_msg64
tidecoin-consensus-core::PqSignature::verify_msg32 / verify_msg64
fips204::ml_dsa_44::PublicKey::verify
fips204::ml_dsa_65::PublicKey::verify
fips204::ml_dsa_87::PublicKey::verify
```

The Tidecoin wrappers use an empty FIPS context (`&[]`) for the current message-digest verification paths; TALUS tests must explicitly cover empty context, non-empty context where exposed by TALUS, and reject accidental context mismatches.

### 17.2 TALUS arithmetic tests

```text
bcc_safety_all_params
bcc_rate_monte_carlo_all_params
hint_weight_distribution
hint_usehint_identity
cef_identity_clear_all_params
cef_identity_masked_all_params
delta_boundary_cases
q_minus_one_decompose_cases
high_mod_44_vs_16_cases
```

### 17.3 MPC backend tests

```text
gf128_field_laws
auth_share_addition
auth_share_public_addition
auth_share_multiplication
open_checked_valid
open_checked_detects_bad_value_share
open_checked_detects_bad_mac_share
triple_sacrifice_accepts_valid
triple_sacrifice_rejects_invalid
and_gate_truth_table
xor_gate_truth_table
not_gate_truth_table
full_adder_truth_table
comparator_truth_table_all_8bit_values
u19_comparator_random
range_check_accepts_valid_rho
range_check_rejects_alpha_over_t
bitness_rejects_non_bit_field_element
```

### 17.4 CarryCompare tests

For each parameter set and many (T,N):

```text
random rho_i in range
random public t
MPC result kappa == clear [sum rho_i > t]
MPC result delta == clear [sum rho_i < t − gamma2 + kappa*alpha]
MAC failure aborts before kappa/delta output
invalid triple aborts before kappa/delta output
wrong rho range aborts before kappa/delta output
```

### 17.5 End-to-end honest tests

```text
t_of_n_keygen
preprocess_certifies_token
single_attempt_may_fail_without_output
multi_attempt_sign_succeeds
signature_verifies_with_internal_verifier
signature_verifies_with_independent_fips204_crate
signature_verifies_with_rustcrypto_ml_dsa_if_api_supports_it
all_params_end_to_end
different_signing_sets
key_refresh_then_sign
```

### 17.6 Malicious tests

Codex should implement malicious party simulators.

Cases:

```text
wrong VSS share
wrong nonce commitment
wrong Htilde
wrong btilde
wrong rho bits
rho out of range
malformed authenticated share
bad MAC share
bad triple c != a*b
reused triple
replayed preprocessing session id
replayed online sign request
wrong z_i
missing z_i
duplicate party message
equivocating broadcast message
rushing attempt in Round 1
signing with consumed token
same token used for two messages
wrong signer set
wrong context
wrong parameter set
wrong public key transcript
```

Expected outcomes:

```text
- either token not certified
- or Blame(i)
- or RetryExhausted for non-malicious BCC failures
- never invalid signature returned
- never honest nonce revealed after challenge
```

Current implementation status: `talus-tests` has a deterministic adversarial
wire harness that mutates canonical messages and verifies rejection for bad
headers, malformed payloads, cross-context replay, unknown senders, duplicate
senders, dropped senders, and wrong-round messages. It also has deterministic
preprocessing malicious simulators for empty/duplicate signer inputs,
coefficient-count mismatch, invalid high/low values, replayed session ids,
equivocated masked broadcasts, mutated commitment salts, wrong transcript
hashes with valid commitments, duplicate opened parties, and uncertified token
pool candidates. Online malicious simulators cover wrong request session, wrong
signer set, wrong token transcript hash, wrong partial session/challenge
binding, final verifier rejection, consumed-token reuse, and retry exhaustion
after final-verifier failures. MPC-core malicious simulators cover bad MAC
openings, bad input MACs, bad Beaver triple `c` MAC shares, MAC-valid but
relation-invalid triple candidates, reused triples, non-bit authenticated
inputs, and insufficient triple supply.

### 17.7 Fuzz and property tests

Use `proptest` for:

```text
canonical encoding roundtrips
reject non-canonical encodings
random network reorderings
random dropped messages
random duplicate messages
random signer sets
random message/context lengths
random token-pool depletion
```

Current implementation status: before adding `proptest`, `talus-tests` has
deterministic property-style loops for:

```text
CEF boundary identities across ML-DSA-44/65/87
canonical wire message encode/decode/re-encode
payload trailing-byte rejection
FIPS signature payload lengths for all suites
signer-set permutation hashing
```

### 17.8 Side-channel tests

```text
dudect for:
  polynomial multiplication
  challenge multiplication c*s1_share
  z_i computation
  hint computation where secret-dependent behavior could exist
  authenticated share operations where secret bits are handled

Miri:
  memory safety
  no use-after-zeroize logic errors

Loom:
  concurrent token-pool consumption
  persistent counter races
```

Secret logging status: authenticated share material, MAC-key shares, Beaver
triple shares, authenticated bits/integers, preprocessing nonce-share
inputs/tokens, typed online signing shares, and service adapters use manual
redacted `Debug` implementations. Persistent key-share serialization policy is
still a production hardening item because the real DKG/key package types have
not landed yet.

### 17.9 Release-gate tests

A release build fails CI if:

```text
trusted-dealer-test feature is enabled
unsafe code appears outside explicitly reviewed modules
any secret type implements unredacted Debug
any secret type implements Clone without a reason
any nonce token can be reused
any invalid signature is returned in adversarial tests
any MAC failure still releases kappa/delta
any preprocessing token enters pool without certification
```

## 18. Benchmarks and expected metrics

Benchmark separately:

```text
FIPS core:
  NTT multiplication
  ExpandA
  HighBits/LowBits
  UseHint
  verification

MPC core:
  GF(2^128) multiplication
  authenticated AND gate
  batch open
  triple sacrifice
  u19 comparison

TALUS-MPC:
  keygen
  preprocessing per token
  preprocessing per certified token
  online attempt
  successful signature with retries
  bytes sent per party
  total bytes per signature
```

Report:

```text
attempt_success_rate
tokens_per_success
preprocessing_latency
online_latency
round count
bytes per certified token
bytes per signing attempt
MAC-check failures caught
triple-check failures caught
```

Compare BCC rates to theory:

```text
ML-DSA-44:
  approx p = (1 − 78 / 95_232)^(4*256)

ML-DSA-65:
  approx p = (1 − 196 / 261_888)^(6*256)

ML-DSA-87:
  approx p = (1 − 120 / 261_888)^(8*256)
```

## 19. API sketch

### 19.1 Key generation

```rust
pub async fn distributed_keygen<P: MlDsaParams, T: Transport>(
    cfg: KeygenConfig<P>,
    transport: T,
    rng: &mut impl CryptoRngCore,
) -> Result<PartyKeyPackage<P>, TalusError>;
```

### 19.2 Preprocessing

```rust
pub async fn preprocess<P: MlDsaParams, T: Transport>(
    key: &mut PartyKeyPackage<P>,
    signing_set: SigningSet,
    count: usize,
    transport: T,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<FreshToken<P>>, TalusError>;
```

### 19.3 Signing

```rust
pub async fn sign<P: MlDsaParams, T: Transport>(
    key: &mut PartyKeyPackage<P>,
    token_pool: &mut TokenPool<P>,
    message: &[u8],
    context: &[u8],
    max_attempts: usize,
    transport: T,
) -> Result<SignOutcome<P>, TalusError>;
```

### 19.4 Verification

```rust
pub fn verify<P: MlDsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    context: &[u8],
    sig: &Signature<P>,
) -> bool;
```

## 20. Codex implementation order

Codex should not start with networking or full DKG. Build in this order:

```text
Milestone 1:
  fips204 dependency and TALUS adapter layer
  minimal fips204 extension/fork or vendored adapter for required internals
  HighBits/LowBits/UseHint exposure
  standard ML-DSA verify through fips204/Tidecoin wrappers
  adapter parity tests and standard verifier cross-checks

Milestone 2:
  BCC
  public TALUS hint computation
  CEF clear identity
  CEF masked identity with clear carry bits

Milestone 3:
  GF(2^128)
  authenticated shares
  MAC checked opening
  authenticated Beaver multiplication
  Boolean gates
  u19 comparison

Milestone 4:
  CarryCompare using authenticated MPC
  kappa and delta correctness
  no output before MAC checks

Milestone 5:
  local in-process TALUS-MPC preprocessing
  certified tokens
  no networking
  deterministic test transport

Milestone 6:
  online signing
  z_i commitment checks
  final FIPS verification gate
  retry loop

Milestone 7:
  malicious tests
  token one-time-use enforcement
  session persistence
  side-channel tests

Milestone 8:
  real transport abstraction
  DKG
  key refresh
  production triple provider

Current implementation status for transport:

```text
Implemented in talus-wire:
  - AuthenticatedP2pTransport trait for directed private messages
  - EquivocationResistantBroadcast trait for broadcast collection
  - PqTransportSessionBinding for application-supplied ML-KEM/ML-DSA
    transport-session binding into ExpectedContext
  - InMemoryTransport for deterministic tests and local adapters
  - DkgPrimeFieldMpcPayload for DKG private-MPC subprotocol messages
  - channel sender/header binding checks
  - unknown-party rejection
  - incomplete broadcast-view rejection
  - cross-observer equivocation detection

Architecture rule:
  - TALUS crates own protocol messages, validation, and state machines
  - embedding applications own concrete sockets, runtimes, retry policy, and
    PQ channel/identity setup
  - crate-provided transports are test transports unless explicitly reviewed
    and release-gated as production adapters
  - production transport adapters must have integration tests for ML-KEM
    channel establishment and ML-DSA party authentication, even though the
    core protocol unit tests may use in-memory authenticated channels
  - current tests exercise ML-KEM-768 and ML-DSA-65 in the transport-adapter
    harness, derive PqTransportSessionBinding, and verify DKG prime-field MPC
    messages use the adapter-supplied session id

Not implemented as production networking yet:
  - application-supplied concrete transport adapter wiring
  - durable message logs and retransmission
  - deployment-level identity/key management
  - reliable broadcast protocol proof/review
```

Milestone 9:
  audit package:
    spec
    proofs
    test vectors
    benchmarks
    threat model
    known limitations
```

## 21. Release blockers and non-negotiable product rules

No production release until:

```text
- setup supports reviewed PQ key-share provisioning and native honest-majority IT-DKG/VSS
- production triple generation uses honest-majority IT-MPC/VSS certified authenticated triples, not trusted-dealer test triples
- preprocessing certifies masked-broadcast consistency and CarryCompare before challenge
- post-challenge reveal-on-failure is disabled by default; any forensic mode has separate proof and review
- token/session persistence prevents reuse across crashes
- transport provides authenticated P2P plus equivocation-resistant broadcast
```

```text
1. Never output invalid signatures.

2. Never reuse a preprocessed nonce.

3. Never reuse a session id τ.

4. Never release kappa/delta from CarryCompare until MAC checks and triple checks pass.

5. Never allow a token into the signing pool unless preprocessing is certified.

6. Never reveal honest nonce material after an online challenge has been computed.

7. Never use unauthenticated Beaver triples in production.

8. Never compile trusted-dealer triple generation into release builds.

9. Never branch on secret data in arithmetic paths.

10. Never serialize secrets through Debug/logging.

11. Always verify final σ with the standard fips204/Tidecoin verifier path before returning.

12. Always bind every message to suite, pk, session id, signer set, and transcript hash.
```

## 22. Main risks Codex must track

The hard parts are:

```text
- exact FIPS 204 Decompose/UseHint behavior
- q ≡ 1 mod α boundary correction δ
- ML-DSA-44 HIGH_MOD = 44, not 16
- authenticated Beaver triple generation
- not releasing carry outputs before MAC checks
- proving masked-broadcast consistency
- preventing nonce reuse across crashes
- not revealing nonce material after z_i is sent
- DKG bounded sampling for s1
- malicious tests that actually simulate adaptive message tampering
```

The TALUS paper gives the core BCC and CEF construction, but product-grade full malicious privacy requires implementing and reviewing the authenticated-MPC extension, because the paper explicitly defers SPDZ-style MACs for that exact purpose. ([arXiv][1])

[1]: https://arxiv.org/pdf/2603.22109 "TALUS: Threshold ML-DSA with One-Round Online Signing via Boundary Clearance and Carry Elimination"
[2]: https://docs.rs/fips204?utm_source=chatgpt.com "fips204 - Rust"
[3]: https://www.nist.gov/publications/module-lattice-based-digital-signature-standard?utm_source=chatgpt.com "Module-Lattice-Based Digital Signature Standard | NIST"
[4]: https://research-information.bris.ac.uk/en/publications/multiparty-computation-from-somewhat-homomorphic-encryption/?utm_source=chatgpt.com "Multiparty Computation from Somewhat Homomorphic Encryption - University of Bristol"
[5]: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html?utm_source=chatgpt.com "ACVP ML-DSA JSON Specification"
