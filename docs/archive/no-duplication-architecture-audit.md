# No-Duplication Architecture Audit

This audit records the current production, dev/test, and scaffold-shaped paths
so we do not accidentally implement the same cryptographic work twice.

The rule is simple:

```text
Production code owns one canonical implementation path.
Tests/dev code may simulate or attack that path, but must not become an
alternate production path.
```

## Current Production Map

### Strict Signing

Canonical production-facing entry points:

- `talus-mpc/src/online.rs:782`:
  `StrictSigningSession` is the app-facing strict signing session facade.
- `talus-mpc/src/online.rs:1130`:
  `StrictSigningSession::finish` consumes the whole token batch before the
  private backend receives token material.
- `talus-mpc/src/online.rs:3154`:
  `sign_strict_no_rejected_z` is the direct strict signing helper with the
  same consumption-before-response rule.

Canonical strict private computation stack:

- `talus-mpc/src/online.rs:1758`:
  `StrictPrivateSigningBackend`.
- `talus-mpc/src/online.rs:1835`:
  `StrictResponsePreparationBackend`.
- `talus-mpc/src/online.rs:1850`:
  `ProductionStrictSigningBackend`.
- `talus-mpc/src/online.rs:2060`:
  `ProductionVectorResponsePreparationBackend`.
- `talus-mpc/src/online.rs:2134`:
  `ProductionVectorResponseBoundCheckBackend`.
- `talus-mpc/src/online.rs:2167`:
  `ProductionVectorHintCheckBackend`.
- `talus-mpc/src/online.rs:2224`:
  `ProductionVectorPrivateSelectionBackend`.
- `talus-mpc/src/online.rs:2289`:
  `ProductionVectorSelectedOpeningBackend`.
- `talus-mpc/src/online.rs:2402`:
  strict check/select/open traits.

Canonical strict wire/session shell:

- `talus-mpc/src/online.rs:443`:
  `StrictSigningSessionId`.
- `talus-mpc/src/online.rs:462`:
  `StrictSigningRuntimeSlot`.
- `talus-mpc/src/online.rs:508`:
  `StrictSigningSessionCursor`.
- `talus-mpc/src/online.rs:535`:
  `StrictSigningRuntimeSlotProgress`.
- `talus-mpc/src/online.rs:575`:
  `StrictSigningDistributedRuntime`.
- `talus-wire/src/lib.rs:71`:
  `RoundId::StrictSignMpc`.
- `talus-wire/src/lib.rs:125`:
  `PayloadKind::StrictSignMpc`.
- `talus-wire/src/lib.rs:270`:
  `StrictSignMpcSlot`.
- `talus-wire/src/lib.rs:309`:
  `StrictSignMpcPayload`.
- `talus-wire/src/lib.rs:1555`:
  strict MPC payload encoding.

Current duplication risk:

`ProductionStrictSigningBackend` is the existing response/check/select/open
pipeline. `StrictSigningDistributedRuntime` is the newer transport/session
runtime boundary. These are not duplicates yet, but they can become duplicates
if the distributed runtime reimplements response preparation, z-bound checks,
hint checks, selection, or selected opening.

Current cleanup:

The default direct-component session runtime is now
`DirectStrictSigningComponentRuntime`. It rejects strict MPC wire messages
instead of silently accepting them. Distributed strict signing must install an
explicit `StrictSigningDistributedRuntime`, and source scans reject strict
response/check/select/open cryptographic logic inside the distributed runtime
boundary.

Hard rule:

```text
The distributed runtime must adapt the existing strict component traits.
It must not contain a second response-check algorithm.
```

Important current caveat:

The names `ProductionVectorResponsePreparationBackend`,
`ProductionVectorResponseBoundCheckBackend`, `ProductionVectorHintCheckBackend`,
`ProductionVectorPrivateSelectionBackend`, and
`ProductionVectorSelectedOpeningBackend` are production-shaped boundaries, but
their current implementation is still local/vector-clear in places. For
example, response preparation aggregates local shares in
`talus-mpc/src/online.rs:2060` and the bound/hint predicates are computed on a
local `StrictVectorCandidateHandle`.

The production target is not to write a parallel implementation. The target is
to replace the internals behind these same boundaries with app-driven batched
IT-MPC handles.

### Dev/Test Strict Signing

Dev/test-only signing artifacts:

- `talus-mpc/src/lib.rs:69`:
  `dev_backends` is compiled only under `cfg(test)` or `paper-fast-dev`.
- `talus-mpc/src/online_dev.rs:39`:
  clear `PartialSignature`.
- `talus-mpc/src/online_dev.rs:56`:
  clear `PolynomialPartialSignature`.
- `talus-mpc/src/online_dev.rs:303`:
  `CommitmentBackedPartialVerifier`.
- `talus-mpc/src/local_dev.rs:32`:
  `ClearMaskedBroadcastConsistencyVerifier`.
- `talus-wire/src/lib.rs:225`:
  wire dev backends for legacy partial-signature payloads.

Existing release guard:

- `talus-mpc/src/lib.rs:1`:
  `production-release-checks` cannot be combined with `paper-fast-dev`.
- `talus-tests/src/production_api_scan.rs:30`:
  production API scan checks that paper-fast and rejected-z symbols do not leak
  into normal APIs.

Hard rule:

```text
Do not move dev/test code into normal modules to make tests easier.
If a test needs it, keep it under dev_backends, cfg(test), or paper-fast-dev.
```

### Native DKG

Canonical production-facing DKG session:

- `talus-dkg/src/lib.rs:6487`:
  `NativeDkgSession`.
- `talus-dkg/src/lib.rs:6466`:
  `NativeDkgSessionOptions`.
- `talus-dkg/src/lib.rs:6443`:
  `NativeDkgOutbound`.
- `talus-dkg/src/lib.rs:6627`:
  `set_power2round_output`.
- `talus-dkg/src/lib.rs:6633`:
  `finish` returns `ProductionNativeDkgAssemblyOutput`.

Canonical production DKG output:

- `talus-dkg/src/lib.rs:4011`:
  `ProductionNativeDkgAssemblyOutput`.
- `talus-dkg/src/lib.rs:4020`:
  `ProductionNativeDkgAssemblyOutput::new`.
- `talus-dkg/src/lib.rs:4047`:
  `try_from_assembled` is `cfg(test)` only.

Scaffold output still present:

- `talus-dkg/src/lib.rs:3990`:
  `NativeDkgAssemblyScaffoldOutput` is `doc(hidden)`.

Current status:

Production wrapping no longer needs a public scaffold conversion. That is good.
The remaining risk is internal code that still carries scaffold terminology,
especially helper paths around `InProcessScalarVss*` and
`InProcessHashBindingScaffold`.

Hard rule:

```text
Production DKG output must be constructible only from production artifacts:
production IT-VSS commitments/certificates, production public coins,
production Power2Round output, and production assembly certificate.
```

### IT-VSS

Canonical production IT-VSS backend:

- `talus-dkg/src/it_vss.rs:1`:
  `ItVssBackendId` distinguishes `ProductionInformationChecking` from
  `InProcessHashBindingScaffold`.
- `talus-dkg/src/it_vss.rs:1947`:
  `ProductionInformationCheckingVssBackend`.
- `talus-dkg/src/scalar_vss.rs:1314`:
  vector private payload.
- `talus-dkg/src/scalar_vss.rs:1675`:
  vector honest-deal construction.
- `talus-dkg/src/scalar_vss.rs:1803`:
  vector acceptance.

Scaffold/test IT-VSS artifacts still present:

- `talus-dkg/src/scalar_vss.rs:178`:
  `InProcessScalarVssShareBinding`.
- `talus-dkg/src/scalar_vss.rs:195`:
  `InProcessScalarVssPublicCheck`.
- `talus-dkg/src/scalar_vss.rs:211`:
  `InProcessScalarVssPrivateShare`.
- `talus-dkg/src/scalar_vss.rs:491`:
  `InProcessScalarVssDeal`.
- `talus-dkg/src/scalar_vss.rs:3004`:
  in-process scalar-VSS backend implementation.

Current duplication risk:

Scalar IT-VSS and vector IT-VSS currently coexist. That is acceptable only if
scalar IT-VSS remains a correctness/test subprotocol and vector IT-VSS remains
the production-scaled DKG path.

Hard rule:

```text
Do not wire scalar-per-coefficient IT-VSS into production DKG.
Production DKG uses vector/chunk IT-VSS only.
```

### Power2Round

Canonical production Power2Round artifacts:

- `talus-dkg/src/power2round.rs:148`:
  `ProductionPower2RoundOutput`.
- `talus-dkg/src/power2round.rs:6567`:
  `ProductionPower2RoundDriverPhase`.
- `talus-dkg/src/power2round.rs:6594`:
  `ProductionPower2RoundPerPartyDriver`.

Dev/test Power2Round artifacts:

- `talus-dkg/src/power2round/dev_backends.rs`:
  dev backends and local driver helpers.

Current duplication risk:

The production driver phases are the right shape. The risk is keeping
scalar-per-coefficient correctness harnesses visible enough that they are
mistaken for production execution.

Hard rule:

```text
Production Power2Round must stay vectorized and app-driven.
Scalar correctness tests cannot become release-capable paths.
```

### Nonce Preprocessing

Canonical production-facing preprocessing API:

- `talus-mpc/src/local.rs:82`:
  `PreprocessingSessionOptions`.
- `talus-mpc/src/local.rs:125`:
  `PreprocessingSession`.
- `talus-mpc/src/local.rs:691`:
  `MaskedBroadcastConsistencyVerifier`.
- `talus-mpc/src/local.rs:719`:
  `ProductMaskedBroadcastConsistencyVerifier`.
- `talus-mpc/src/local.rs:908`:
  `CertifiedToken`.
- `talus-mpc/src/local.rs:982`:
  `TokenPool`.
- `talus-mpc/src/local.rs:1440`:
  product token certification entry point.

Current status:

`talus-mpc/src/local.rs` is now an internal implementation module, not a public
`talus_mpc::local` API. Normal callers should use crate-root production
exports or `talus_mpc::preprocessing`. Clear-audit and paper-compatible
helpers remain under gated `dev_backends`.

The preprocessing path is not a blank slate. Current implemented pieces are:

- `PreprocessingSession` app-facing facade.
- `DistributedNonceShare` without public exact `A*y`/`A*nonce` commitments.
- Masked-broadcast commit/open validation.
- `MaskedBroadcastConsistencyVerifier` and
  `ProductMaskedBroadcastConsistencyVerifier` boundary.
- `CertifiedToken`, `PreChallengeCertificationEvidence`, and token-pool
  admission policy.
- File-backed preprocessing session-id reuse prevention.
- Vector CEF/BCC admission with the approved `+ delta` correction.

The remaining production work is to replace local/in-process witnesses behind
those boundaries, not to build another preprocessing path.

Remaining naming problem:

The internal file still mixes production-shaped preprocessing APIs,
product-verifier stubs, and implementation helpers. That is not cryptographic
duplication, but it is still an architecture smell until the file is split by
domain.

Hard rule:

```text
Split production preprocessing API from local/dev harness naming.
Do not build a second preprocessing algorithm; move/gate harness helpers and
keep the production session/token API as the only normal API.
```

## Duplicates And Near-Duplicates Found

### 1. Strict signing computation vs distributed runtime

Status:

```text
Near-duplicate boundary, not yet duplicate algorithm.
```

What exists:

- `ProductionStrictSigningBackend` executes the strict private pipeline.
- `StrictSigningDistributedRuntime` validates and routes production strict MPC
  wire payloads.
- `StrictSigningSession::finish` still calls the local backend after token
  consumption.

Risk:

Future work might implement response preparation, bound checks, hint checks,
selection, and selected opening directly inside a distributed runtime, creating
two signing algorithms.

Required fix:

- [ ] Define a distributed adapter that implements the existing strict
  component traits or delegates to them phase-by-phase.
- [ ] Make `StrictSigningSession` use that adapter for production distributed
  execution.
- [ ] Keep local/direct execution as test/dev/internal until the distributed
  adapter is complete.
- [ ] Add a test that the production strict session and the component stack
  traverse the same `STRICT_RESPONSE_CHECK_PHASES`.

Completion condition:

```text
One response-check algorithm exists.
The app/wire driver only transports and persists messages for that algorithm.
```

### 2. Scalar IT-VSS vs vector IT-VSS

Status:

```text
Intentional test/proof subprotocol plus production-scaled protocol.
```

Risk:

Scalar IT-VSS helper types are still prominent and can be accidentally used as
production DKG material.

Required fix:

- [ ] Move `InProcessScalarVss*` helpers into a clearly named test/dev module
  or gate them behind test/dev features.
- [ ] Keep public scalar types only if they are protocol-neutral and needed by
  vector IT-VSS.
- [ ] Add source comments around scalar correctness paths:
  "not production DKG; vector/chunk IT-VSS only."
- [ ] Add release scan for `InProcessScalarVss` outside dev/test modules.

Completion condition:

```text
Normal DKG users see vector IT-VSS APIs first.
Scalar correctness helpers cannot satisfy production release gates.
```

### 3. Native DKG scaffold output vs production output

Status:

```text
Mostly fixed.
```

Good:

- `ProductionNativeDkgAssemblyOutput::new` is the normal constructor.
- `try_from_assembled` is `cfg(test)` only.
- `NativeDkgAssemblyScaffoldOutput` is `doc(hidden)`.

Remaining cleanup:

- [ ] Audit internal assembly helpers for names that still say scaffold while
  feeding production-shaped flows.
- [ ] Rename internal scaffold helpers only when they are not test-only.
- [ ] Keep test-only scaffold helpers under `cfg(test)` or a dev module.

Completion condition:

```text
No production function accepts or returns a type named Scaffold.
```

### 4. Preprocessing product API vs local harness module

Status:

```text
Mixed module, not necessarily duplicate algorithm.
```

Risk:

The module name/doc says local deterministic harness while exported API names
are production-facing. That invites future duplication or accidental reliance
on local clear-audit paths.

Required fix:

- [x] Stop exposing `talus_mpc::local` as a normal public module.
- [x] Add `talus_mpc::preprocessing` as the explicit production-facing module.
- [ ] Split `talus-mpc/src/local.rs` into production-facing modules without
  changing the algorithm:
  `preprocessing/session.rs`, `preprocessing/token.rs`,
  `preprocessing/masked_broadcast.rs`, `preprocessing/certification.rs`.
- [ ] Keep `local_dev.rs` as the only clear-audit and local harness location.
- [ ] Replace deterministic masked-broadcast proof hashes/local recomputation
  with the final private certification backend behind
  `MaskedBroadcastConsistencyVerifier`.
- [ ] Replace local CEF/BCC aggregate witnesses with production vector IT-MPC
  evidence behind the existing token-certification evidence types.
- [ ] Add durable preprocessing token inventory; do not confuse it with the
  already implemented consumed-token store used by strict signing.
- [ ] Make `ProductMaskedBroadcastConsistencyVerifier` the normal verifier.
- [ ] Keep `ClearMaskedBroadcastConsistencyVerifier` test/dev-only.
- [ ] Add release scan for `MaskedBroadcastClearAudit` outside `cfg(test)` or
  `paper-fast-dev` contexts.

Completion condition:

```text
Production preprocessing docs/API do not live under a module described as a
deterministic in-process harness.
```

### 5. Legacy wire partial signatures vs strict MPC wire

Status:

```text
Mostly fixed.
```

Good:

- `StrictSignMpcPayload` is normal wire API.
- Legacy `PartialSignaturePayload` is inside `talus-wire::dev_backends`.
- Production API scans check for leakage.

Remaining cleanup:

- [ ] Keep adversarial tests that mention legacy partial signatures clearly
  under paper-compat/dev test modules.
- [ ] Add comments in wire tests explaining that legacy partial-signature
  payloads are attack/regression fixtures only.

Completion condition:

```text
Normal wire API exposes strict MPC payloads only.
Legacy partial-signature payloads compile only for tests/dev.
```

## Step-By-Step Cleanup Plan

### Phase A: Freeze Canonical Ownership

- [x] Add a short code comment near `ProductionStrictSigningBackend`:
  "canonical strict response-check pipeline; distributed runtimes must adapt
  this boundary."
- [x] Add a short code comment near `StrictSigningDistributedRuntime`:
  "transport/session boundary only; no independent response-check algorithm."
- [x] Add a short code comment near `ProductionInformationCheckingVssBackend`:
  "canonical vector IT-VSS backend for production DKG."
- [x] Add a short code comment near `InProcessScalarVss*`:
  "test/scalar correctness only, never production DKG."

Gate:

- [ ] `rg "InProcessScalarVss|Scaffold|PartialSignature|CommitmentBackedPartialVerifier"`
  has every non-test occurrence classified.

### Phase B: Deduplicate Strict Signing Execution

- [ ] Define one adapter from strict signing component phases to strict MPC
  runtime slots:
  ```text
  ResponsePreparation -> StrictResponsePreparationBackend
  ResponseBoundChecks -> StrictResponseBoundCheckBackend
  HintChecks          -> StrictHintCheckBackend
  PrivateSelection   -> StrictPrivateSelectionBackend
  SelectedOpening    -> StrictSelectedOpeningBackend
  ```
- [ ] Replace any new distributed-runtime-local cryptographic logic with calls
  through the existing component traits.
- [ ] Keep `StrictSigningSession` as the only normal production user-facing
  strict signing API.
- [ ] Decide whether `sign_strict_no_rejected_z` remains a lower-level helper
  or becomes `pub(crate)` after session-driven signing is complete.

Gate:

- [ ] One test runs strict signing through `StrictSigningSession`.
- [ ] One test proves no `StrictSigningDistributedRuntime` implementation
  computes response predicates without going through component traits.
- [ ] Counter/evidence output comes from one response-check driver only.

### Phase C: Separate IT-VSS Production From Scalar/In-Process Helpers

- [ ] Move in-process scalar helpers into `it_vss_dev` or `scalar_vss_dev`.
- [ ] Keep protocol-neutral scalar field/tag primitives only where vector
  production code uses them.
- [ ] Ensure vector IT-VSS is the only DKG path that creates release-valid
  sampler certificates.
- [ ] Add release scan for `ItVssBackendId::InProcessHashBindingScaffold` in
  release-valid assembly paths.

Gate:

- [ ] `NativeDkgSession` cannot finish from in-process scalar VSS artifacts.
- [ ] Production sampler accepts only verified/vector IT-VSS inputs.
- [ ] Scalar correctness tests still pass under test/dev modules.

### Phase D: Split Preprocessing Modules

- [ ] Create production module boundaries for preprocessing without changing
  behavior.
- [ ] Move clear-audit-only helpers out of normal API paths.
- [ ] Rename docstrings that call production-facing code a deterministic
  harness.
- [ ] Keep product certification evidence types in production modules.

Gate:

- [ ] Normal crate docs show `PreprocessingSession`, `CertifiedToken`, and
  `TokenPool` as production-facing.
- [ ] Clear audit types are absent from normal docs/API.
- [ ] Production preprocessing tests still prove token certification, token
  pool insertion, and no token reuse.

### Phase E: Refactor Tests Without Creating New APIs

- [ ] Split large tests by domain:
  ```text
  strict_signing/
  dkg/
  it_vss/
  power2round/
  preprocessing/
  attack_tests/
  production_api_scan/
  ```
- [ ] Keep attack demonstrations in `attack_tests`.
- [ ] Keep paper-compatible fixtures under explicit dev/test module names.
- [ ] Do not add shell scripts for release checks unless Rust tests cannot
  express the rule.

Gate:

- [ ] Tests remain discoverable by domain.
- [ ] Production API scans remain Rust tests.
- [ ] No new public API is added only to make tests easier.

## Production Completion Checklist

### Must Be True Before Production Claim

- [ ] Normal compile contains no paper-fast signing API.
- [ ] Normal compile contains no clear partial `z_i` API.
- [ ] Normal compile contains no public exact `A*secret` commitment verifier.
- [ ] Strict signing exposes one production session API.
- [ ] Strict signing has one response-check algorithm.
- [ ] Distributed strict signing runtime adapts the canonical component stack.
- [ ] DKG exposes one production session API.
- [ ] DKG finish returns only `ProductionNativeDkgAssemblyOutput`.
- [ ] DKG production path uses vector IT-VSS only.
- [ ] Power2Round production path is vector/app-driven only.
- [ ] Preprocessing exposes one production session/token API.
- [ ] Clear preprocessing audit paths are test/dev-only.
- [ ] Tests are split by domain and do not require production APIs to expose
  test fixtures.

### Must Not Be Done

- [ ] Do not implement a second strict response-bound checker inside a
  distributed runtime.
- [ ] Do not implement a second strict hint checker inside a distributed
  runtime.
- [ ] Do not implement a second selected-opening algorithm.
- [ ] Do not wire scalar-per-coefficient IT-VSS into production DKG.
- [ ] Do not make scaffold output convertible to production outside tests.
- [ ] Do not expose `PartialSignaturePayload` in normal wire API.
- [ ] Do not solve test organization by promoting dev helpers to normal API.

## Next Workable Slices

1. Classify and comment the current boundaries.
   - Status: in progress. Strict signing and vector IT-VSS ownership comments
     are in code. `talus_mpc::local` is no longer public. The no-op strict
     distributed runtime name has been removed.
   - Completion: every `InProcess*`, `Scaffold*`, `PartialSignature*`, and
     `CommitmentBacked*` occurrence is either test/dev-only or documented as
     a production-forbidden artifact.

2. Deduplicate strict signing runtime.
   - Completion: `StrictSigningDistributedRuntime` implementations call the
     existing strict component stack, and no second response-check algorithm
     exists.

3. Move scalar/in-process IT-VSS helpers out of normal production view.
   - Completion: vector IT-VSS remains production DKG path; scalar helpers are
     clearly correctness/dev fixtures.

4. Split preprocessing production modules from local harness helpers.
   - Completion: `PreprocessingSession`, `CertifiedToken`, token persistence,
     masked-broadcast product verifier, and BCC/CEF certification live under
     production-facing module names; clear audit remains dev-only.

5. Refactor tests by domain.
   - Completion: tests stop being one giant pile, but no new production API is
     introduced just for tests.
