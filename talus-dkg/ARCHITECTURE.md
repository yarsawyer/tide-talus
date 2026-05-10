# TALUS DKG Crate Architecture

`talus-dkg` is a production-oriented library. Normal crate users should import
one DKG API surface, not choose between production, scaffold, and simulator
emitters.

Tests may use in-memory transports, deterministic samplers, clear
Power2Round, and local Shamir harnesses. Those implementations are test
substrates only. They must not be available as normal user-facing release
paths, and they must not emit production identities.

## Production Contract

The production DKG output type is `ProductionNativeDkgAssemblyOutput`. It can
only be constructed after the centralized release checks accept:

- `DkgSetupBackendId::ProductionInformationTheoretic`
- `ItVssBackendId::ProductionInformationChecking`
- `Power2RoundBackendId::ProductionItMpc`
- empty release blockers
- ML-KEM private-channel evidence in the application transport context
- ML-DSA operational identity evidence in the application transport context
- reliable-broadcast conformance evidence
- no private setup payloads in release artifact logs
- no scaffold backend ids in persisted public artifacts

Production DKG must also use the vectorized execution model documented in
[`docs/dkg-production-performance.md`](../docs/dkg-production-performance.md).
In particular, production Power2Round must batch across coefficients, openings,
checks, and circuit layers. Scalar-per-coefficient Power2Round is a test
harness shape only.

The full remaining production checklist is tracked in
[`docs/dkg-production-completion-plan.md`](../docs/dkg-production-completion-plan.md).

`NativeDkgAssemblyScaffoldOutput` is a test/scaffold output type. It is not
release material and must never be accepted by application code without first
passing through `ProductionNativeDkgAssemblyOutput::try_from_assembled`.

## Module Boundaries

- `types.rs`: public DKG data types, suite/config/output/share packages.
- `shamir.rs`: Shamir field sharing helpers and bounded-vector validation.
- `it_vss.rs`: production IT-VSS identifiers, information-checking tags,
  artifacts, complaint resolution, vector certificates, and IT-VSS release
  policy.
- `scalar_vss.rs`: scalar VSS mechanics and test harness support. Production
  DKG must use the batched/vector IT-VSS path, not scalar-per-coefficient setup.
- `power2round.rs`: Power2Round protocol types, transport phase drivers,
  release evidence, and test-only Power2Round harnesses.
- `test_dealer.rs`: test-only clear dealer helpers compiled only under
  `cfg(test)`.
- `error.rs`: DKG error types.
- `tests.rs`: unit, restart, adversarial, and conformance tests.

## Test Substrates

The following are test-only or release-rejected:

- `ClearSimPower2RoundBackend`
- `LocalPrimeFieldMpcBackend`
- `InProcessShamirPrimeFieldMpcBackend`
- `NetworkedShamirPrimeFieldMpcBackend`
- `TransportBackedShamirPrimeFieldMpcBackend`
- `RuntimeCoordinatedTransportShamirPrimeFieldMpcBackend`
- `TransportEvidenceShamirPower2RoundTestHarness`
- `TestItMpcPower2RoundBackend`
- `TestInformationCheckingVssBackend`
- `DeterministicItVssTestBackend`
- `InMemoryNativeDkgScaffoldCoordinator`
- `InProcessHashBindingScaffold` IT-VSS artifacts
- test-dealer helpers

If a type wraps simulator substrate, it must not return
`Power2RoundBackendId::ProductionItMpc`. Production identity is reserved for a
genuine production MPC backend.

## Current Hard Boundaries

The crate keeps trait and wire boundaries for production MPC and VSS, but it
does not cosmetically label test substrates as production. If a production
component is incomplete, the normal API must expose the missing boundary
honestly instead of providing a fake production emitter.

Concretely:

- `Power2RoundBackendId::ProductionItMpc` is a certificate identity, not a
  license for a Shamir simulator to call itself production.
- `ItVssBackendId::ProductionInformationChecking` is the final IT-VSS artifact
  identity. Test helpers may create production-identity artifacts only under
  `cfg(test)` for release-gate tests.
- Concrete normal-build production implementations must be added behind these
  boundaries only when they perform the selected protocol phases, not just the
  artifact shape.

The next production work should focus on replacing test substrates behind the
existing boundaries, not on adding more alternate user-facing paths.

The most important replacement is a vectorized prime-field IT-MPC backend with
`ShareVec` and `BitShareVec`. It must make DKG round complexity follow circuit
depth rather than coefficient count.
