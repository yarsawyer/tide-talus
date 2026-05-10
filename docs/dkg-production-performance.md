# DKG Production Performance Shape

This document records the production execution model for TALUS native DKG.

The current scalar Power2Round test harness is useful for correctness and
adversarial testing, but it is not the product execution model. Production DKG
must be vectorized and batched across both IT-VSS and Power2Round.

## Rule

Do not implement production DKG as 1024, 1536, or 2048 independent
coefficient-level MPC executions.

Production must batch:

- IT-VSS dealer vector sharings
- IT-VSS private deliveries
- IT-VSS information-checking tags
- IT-VSS polynomial-consistency rounds
- all coefficients in one vector circuit
- all openings of the same phase
- all multiplications in the same circuit layer
- all bitness and zero checks in vector form
- all transport payloads as vectors, not scalar messages
- canonical masks and mask-bit certification before public-key assembly where
  possible

If DKG takes days, the implementation is wrong. DKG can be heavier than online
signing, but a production implementation should target seconds to tens of
seconds on a LAN and tens of seconds to a few minutes on a WAN, depending on
party count, RTT, and durable logging.

## Why

Naive scalar Power2Round does roughly:

```text
ML-DSA-44:
  coefficients = 4 * 256 = 1024
  per-coefficient private circuit ~= hundreds of multiplications/checks
  result = hundreds of thousands of scalar MPC gates
```

The scalar test harness turns those gates into many in-memory wire/log records.
That is acceptable for a correctness stress test. It is not acceptable as the
production execution strategy.

## Production Data Model

IT-VSS must operate on vectors and chunks, not scalar-per-coefficient shares:

```rust
VssVectorShare       // one holder's F_q^M vector share
VectorIcTag         // one IC tag authenticating F_q^M
VectorConsistency   // one consistency round over F_q^M[x]
```

Power2Round uses the prime-field MPC vector types.

The prime-field MPC backend must expose vector shares:

```rust
Share       // one F_q secret share
ShareVec    // vector of F_q secret shares
BitShareVec // vector of secret bits, one lane per coefficient
```

For each ML-DSA suite:

```text
ML-DSA-44: ShareVec length = 1024
ML-DSA-65: ShareVec length = 1536
ML-DSA-87: ShareVec length = 2048
```

The vector backend must support:

- local vector addition/subtraction
- local public-scalar multiplication
- vector multiplication scheduled by circuit layer
- vector random-bit generation
- vector `assert_zero`
- vector `assert_bit`
- vector `open_many_checked`
- transcript-bound vector labels
- payload byte counters and round counters

Public constants must not use MPC multiplication. Multiplication by public
constants is a local operation.

## Production Power2Round Circuit

Production Power2Round computes:

```text
[t] = A[s1] + [s2] mod q
t1 = Power2Round([t]).high
```

It opens only `t1`.

The vectorized circuit runs across every coefficient lane at once:

1. Use precomputed/certified canonical random masks `A_mask` and mask bits for
   all coefficients.
2. Compute vector `[C] = [t] + [A_mask] mod q`.
3. Batch-open all `C` values.
4. Compute all secret wrap bits `[A_mask > C]`.
5. Recover all canonical `R` bit vectors with vector subtractors.
6. Batch-check every `R` bit is boolean.
7. Batch-check every `R < q`.
8. Batch-check `sum_j 2^j R_j == t mod q`.
9. Add public constant `4095` across every coefficient lane.
10. Batch-open only bits `13..22` of every coefficient.
11. Pack public `t1` and emit transcript-bound `Power2RoundEvidence`.
12. Advance the per-party driver only through typed phase outputs, not generic
    phase markers.
13. Recover accepted vector phase outputs from durable logs after restart,
    rather than regenerating masks, shares, or openings.
14. Erase masks, low bits, `R` bits, `t`, `s2`, and all witnesses.

The round complexity should follow circuit depth, not coefficient count.

## Production IT-VSS

Production IT-VSS must use the batched/vector Rabin-Ben-Or-style shape from
`docs/it-vss-rabin-ben-or.md`.

Scalar VSS is allowed only as a correctness and adversarial-test target.
Production DKG must not share every bounded coefficient independently.

For each dealer, production setup should send:

```text
one S1 vector-domain sharing
one S2 vector-domain sharing
```

or a small number of bounded-size chunks if memory/MTU limits require
chunking. It must not send:

```text
one VSS instance per coefficient
one IC audit per coefficient
one polynomial consistency proof per coefficient
```

Vector IT-VSS must batch:

- private payload commitments
- retained/audited receiver-side IC tags
- holder-side `y_vec` tags
- polynomial mask shares
- polynomial consistency challenges
- complaint broadcasts
- complaint resolution/certification

The soundness logic is unchanged: one hidden scalar multiplier authenticates a
whole vector, and repeated independent tags provide the security margin. The
implementation must choose vector/chunk sizes that keep memory and wire payloads
bounded without falling back to scalar-per-coefficient VSS.

## Preprocessing

Production should precompute and certify Power2Round masks before public-key
assembly:

- random canonical mask values in `Z_q`
- 23 mask bits per coefficient
- bitness certificates
- `A_mask < q` certificates
- transcript binding to DKG session, suite, epoch, party set, and rho hash

Precomputed masks are one-time DKG material. Reuse is forbidden.

## Transport

The DKG crate should not implement TCP sockets. The embedding application
provides transport through the crate interfaces:

- authenticated private delivery
- ML-KEM channel/session establishment evidence
- ML-DSA operational identity evidence
- equivocation-resistant reliable broadcast evidence
- durable message/cursor logs

The crate emits and consumes canonical vector wire messages. Tests may use
in-memory transport, but production must be application-driven.

Current implementation status:

- prime-field MPC wire payloads support scalar rounds and vector rounds
- scalar collectors reject vector payloads
- vector collectors reject scalar/empty payloads and inconsistent lane counts
- transport-backed state-machine tests cover directed vector delivery and
  reliable-broadcast vector collection
- the networked Shamir prime-field backend emits vector messages for vector
  operations instead of one scalar message per lane
- Power2Round mask batches have unchecked, certified, and consumed type-state
  wrappers; certified masks are transcript-bound and must be marked consumed
  through a mask-use log before they can open `C = t + A`
- file-backed mask-use logs persist consumed mask ids across restart and reject
  duplicate ids on reopen without storing mask values or bits
- precomputed mask batches can be generated/certified before decomposition and
  are consumed through the caller's durable mask-use log only when `C = t + A`
  is opened
- the per-party Power2Round driver records a certified mask batch id before it
  can enter the masked-opening phase and can resume from that persisted id
- vector masked openings can be sent, delayed, collected, logged, and recovered
  through the per-party prime-field MPC runtime using reliable-broadcast vector
  payloads
- vector masked-opening arithmetic is a named Power2Round operation:
  `open_power2round_masked_c_vec` validates the consumed mask batch shape,
  computes `[C] = [t] + [A_mask]`, and opens under the canonical
  `open_masked_c` transcript child
- vector wrap comparison is a named Power2Round operation:
  `power2round_wrap_compare_vec` validates the opened `C` vector, computes
  secret bits `[A_mask > C]`, and uses the canonical `a_gt_c` transcript child
- vector wrap-comparison reliable-broadcast send/collect/recover phases are
  available through the per-party prime-field MPC runtime
- vector canonical `R` bit recovery is a named Power2Round operation:
  `power2round_recover_canonical_r_bits_vec` computes
  `R = C + q*wrap - A_mask` with the vector subtractor under the canonical
  `recover_r_bits` transcript child
- vector subtractor reliable-broadcast send/collect/recover phases are
  available per subtractor bit through the per-party prime-field MPC runtime
- post-recovery canonical checks are named Power2Round operations:
  bitness, `R < q`, and `sum 2^j R_j == t mod q`
- vector reliable-broadcast send/collect/recover phases are available for
  `R < q` and equality-check payloads
- add-4095 and public `t1` high-bit opening are named Power2Round operations:
  `power2round_add_4095_vec` and `power2round_open_t1_bits_vec`
- vector reliable-broadcast send/collect/recover phases are available for
  add-4095 carry/share payloads and `T1BitOpening` payloads
- the per-party Power2Round driver requires typed masked-opening lane evidence
  and typed canonical-bit-recovery lane evidence before later phases can run

Remaining transport-performance work:

- byte counters for vector private/broadcast payloads
- production adapter conformance suite that embedders can run against their own
  transport implementation
- full Power2Round canonical-bit recovery using vector payloads across every
  circuit layer, with restart cursors and phase counters

## Counters

Production and performance tests must collect:

- IT-VSS vector count
- IT-VSS chunk count
- IT-VSS IC tag count
- IT-VSS consistency round count
- MPC rounds
- multiplication gates
- bit gates
- `assert_zero` checks
- `assert_bit` checks
- private messages
- broadcast messages
- bytes sent privately
- bytes broadcast
- durable log records
- elapsed time by phase

These counters are release-quality diagnostics. They should make scalarized
regressions obvious.

## Test Policy

Scalar-per-coefficient Power2Round tests are correctness stress tests only.

They must be:

- named as scalar/test harnesses
- excluded from normal production API
- marked slow or ignored if they dominate CI time
- kept separate from vectorized production backend tests

Production tests should focus on the vectorized backend and assert that round
counts scale with circuit depth rather than coefficient count.

## Immediate Engineering Tasks

1. [x] Add `ShareVec` and `BitShareVec` to the prime-field MPC backend
   boundary.
2. [x] Add local public-scalar multiplication for shares and vectors.
3. [x] Implement vectorized Power2Round over `ShareVec` in the local
   correctness backend.
4. [x] Add vector prime-field MPC wire payloads and transport state-machine
   collectors.
5. [x] Make the networked Shamir test backend emit vector messages for vector
   operations.
6. [ ] Add vector/chunk configuration to IT-VSS and DKG setup.
7. [ ] Implement vector IT-VSS production transport phases end to end.
8. [ ] Implement production batched `open_many_checked`.
9. [ ] Implement production batched `assert_zero` and bitness checks.
10. [x] Add unchecked/certified/consumed type-state wrappers for canonical
    Power2Round masks.
11. [x] Add persistent production mask-use logs for crash-safe reuse
    prevention.
12. [x] Add precomputed/certified canonical mask generation over the vector
    backend boundary.
13. [x] Wire precomputed mask generation into the production per-party
    Power2Round driver phases.
14. [ ] Drive masked-opening and canonical-bit recovery phases through the
    per-party application transport runtime.
    - [x] Vector masked-opening broadcast send/collect/recover path.
    - [x] Vector masked-opening arithmetic helper with consumed mask type-state.
    - [x] Vector wrap-comparison broadcast send/collect/recover path.
    - [x] Vector wrap-comparison arithmetic helper with consumed mask type-state.
    - [x] Vector subtractor broadcast send/collect/recover path.
    - [x] Vector canonical `R` bit recovery helper with consumed mask
      type-state.
    - [x] Named vector bitness, `R < q`, and equality certification helpers.
    - [x] Vector canonical range-check and equality-check broadcast
      send/collect/recover paths.
    - [x] Named vector add-4095 and `t1` high-bit opening helpers.
    - [x] Vector add-4095 and `T1BitOpening` broadcast send/collect/recover
      paths.
    - [x] Driver requires typed masked-opening and canonical-bit-recovery lane
      evidence.
    - [ ] Full canonical-bit recovery circuit driven through runtime phases.
15. [ ] Add counters for gates, rounds, messages, bytes, logs, and elapsed
    time.
16. [ ] Mark full scalar transport Power2Round tests as slow/ignored if needed.

This is the required production direction. The scalar harness proves the circuit
logic; it is not the product execution model.
