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

Production DKG must also use the vectorized execution model tracked in the live
workspace plan, [`IMPLEMENTATION_PLAN.md`](../IMPLEMENTATION_PLAN.md). In
particular, production Power2Round must batch across coefficients, openings,
checks, and circuit layers. Scalar-per-coefficient Power2Round is a test
harness shape only.

Historical DKG/performance checklists are archived under `docs/archive/`.
They are useful context, but they are not the live production checklist.

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
- Concrete normal-build production implementations must live behind these
  boundaries only when they perform the selected protocol phases, not just the
  artifact shape.

The vector prime-field IT-MPC boundary is now part of the normal build:
`ShareVec`, `BitShareVec`, batched checked openings, batched zero/bitness
checks, batched random bits, vector multiplication layers, public-constant
local multiplication, vector comparisons, vector canonical bit recovery, and
selected high-bit opening are all normal-build circuit primitives. The local
Shamir and clear simulators remain test/dev substrates.

Release readiness for `Power2RoundBackendId::ProductionItMpc` requires
`ProductionItMpcReadiness` to assert vector runtime operations, durable public
round logs, durable local wire logs, release counters, no scalarized execution,
local public-constant multiplication, PQ-authenticated transport, and
abort/blame policy.

The normal production Power2Round boundary is `ProductionPower2RoundOutput`
with durable app-driven vector IT-MPC runtime evidence. The older generic
`ProductionItMpcPower2RoundBackend` wrapper is test/dev-only because it is
generic over `ItMpcPrimeFieldBackend`, which still includes local-compatible
substrates. Release assembly accepts typed `ProductionPower2RoundOutput`;
normal production callers cannot select local, in-process, clear, transport
simulator, or generic backend-private Power2Round substrates.

All release-capable Power2Round transport phases are exposed through
`ProductionVectorPrimeFieldMpcRuntime`: masked `C` opening, wrap comparison,
canonical subtractor, bitness/range/equality checks, add-4095, and selected
`t1` high-bit opening. The mutable lower-level runtime escape hatch is
test/scaffold-dev only. `ProductionPower2RoundCircuitState` owns the nonlinear
state used for release certification: it derives `C = t + A_mask`, wrap bits,
canonical `R` bits, `R < q` and equality checks, `S = R + 4095`, and the
selected `t1` high-bit openings before certifying `ProductionPower2RoundOutput`.
Legacy helper-heavy phase drivers remain only for adversarial/dev coverage and
must not satisfy release certification by themselves.

Native DKG assembly now has one normal production entry point:

- `assemble_logged_native_dkg_production_from_logs` accepts a typed
  `ProductionPower2RoundOutput` when an application has already driven the
  Power2Round runtime externally.

`assemble_logged_native_dkg_production_with_power2round_backend` and
`NativeDkgSession::finish_with_power2round_backend` exist only under
`cfg(test)` / `scaffold-dev` for correctness and migration tests. Output
packages retain only `rho`, `t1`, `pk`, local `s1` share, and public
certificates. `s2`, `t`, `t0`, low bits, masks, and simulator material are
temporary assembly state and must not appear in output, public logs, or debug
output.

Phase 5 assembly coverage is split by cost:

- `production_native_dkg_assembly_all_suites_release_valid` proves release-valid
  native DKG assembly for ML-DSA-44/65/87 using production Power2Round evidence
  and the production output constructor.
- `native_dkg_application_driver_uses_production_it_vss_batch_path_to_assembly`
  proves the transport-shaped app-driver path for ML-DSA-44, including
  production vector IT-VSS logs and production vector Power2Round. This test is
  slower because it exercises the local vector Power2Round runtime over a full
  ML-DSA-44 vector.
