# TALUS Optimization Principles

This document records cross-cutting performance rules for the production TALUS
implementation. It is not a replacement for the protocol docs. It is the
engineering checklist for making DKG, preprocessing, BCC, and strict signing
usable without weakening the security model.

## Core Rule

Optimize by batching and vectorizing protocol phases, not by skipping checks.

Production must preserve:

- no public exact `A*secret` images
- no rejected-`z` leakage
- receiver-private retained IT-VSS tags
- checked openings before dependent public output
- durable one-time-use state for masks, tokens, and preprocessing material
- transcript-bound labels for every lane, chunk, token, and phase

The implementation may change scheduling, payload shape, and batching. It must
not change the algebraic checks or leak extra intermediate values.

## What Must Be Batched

Production paths must avoid scalar-per-coefficient execution for:

- IT-VSS sharing and reconstruction
- bounded ML-DSA secret sampling
- DKG `Power2Round`
- nonce-share generation
- masked-broadcast commit/open
- masked-broadcast consistency checks
- CEF reconstruction
- CarryCompare
- BCC certification
- strict signing response checks
- final candidate selection
- durable message logging

If a phase touches 1024, 1536, or 2048 ML-DSA coefficients, the release path
should use vectors or bounded chunks.

## Vector Types

The production runtime should expose vector primitives as first-class APIs:

```text
ShareVec
BitShareVec
VssVectorShare
VectorIcTag
VectorConsistencyRound
TokenBatch
CertifiedMaskBatch
CertifiedPreprocessingBatch
```

Scalar APIs may exist for unit tests and small reference checks. They must not
be the release-capable execution strategy.

## Round Complexity Target

Round count should scale with:

```text
protocol phase count
circuit depth
chunk count
token batch count
network synchronization points
```

Round count must not scale linearly with:

```text
coefficient count
bit lane count where a vector layer can handle all lanes together
number of scalar gates when they are in the same circuit layer
```

The basic target is:

```text
bad:  rounds ~= coefficients * circuit_depth
good: rounds ~= chunks * circuit_depth
```

## Payload Strategy

Prefer fewer larger canonical messages over many tiny messages:

- one vector private-delivery batch per receiver
- one vector broadcast per phase/sender
- one vector `open_many_checked` per opening group
- one vector complaint batch per dealer/receiver set
- one durable cursor update per phase boundary

Chunk messages only for practical limits:

- memory ceiling
- MTU or application transport limit
- durable log segment size
- retry/retransmission granularity
- cache and serialization cost

Chunking must keep the chunk label in the transcript:

```text
suite
epoch
session id
party set hash
token batch id
chunk id
lane range
phase
gate/layer id
```

## Precomputation

Precompute work that is independent of the online message:

- DKG `Power2Round` canonical masks
- nonce VSS vector sharings
- CEF high/low masks
- CarryCompare random bits and comparison masks
- BCC comparison masks
- multiplication resources required by the IT-MPC backend
- token batches

Precomputed material is one-time use unless a reviewed protocol says otherwise.
The default release rule is:

```text
precomputed material must be consumed durably before it can influence an
opening, response computation, or token admission decision.
```

## Signing Optimization

Strict production signing should be fast because expensive nonce work is done in
preprocessing.

The online path should:

- pull a prepared BCC-certified token batch
- durably consume the batch before response work
- compute candidate responses privately in vector form
- privately check z-bound and hint weight
- select one valid candidate by private/random-priority selection
- open only selected `ctilde`, `z`, and `h`
- run final FIPS verification

It must not optimize by sending clear partial `z_i`, exposing rejected aggregate
`z`, or revealing per-token failure reasons.

## DKG Optimization

DKG should use:

- batched/vector IT-VSS for `s1` and `s2`
- exact distributed `Z_m` sampler for bounded ML-DSA secrets
- local linear assembly of `[t] = A[s1] + [s2]`
- vectorized private `Power2Round`
- precomputed certified canonical masks
- batched openings and checks

It must not:

- run one VSS per coefficient
- run one private `Power2Round` state machine per coefficient
- persist `s2`, `t`, `t0`, low bits, or mask witnesses
- publish public `A*s1_i`

## Preprocessing And BCC Optimization

Nonce preprocessing should produce certified token batches.

The preprocessing path should:

- share nonce material as vectors/chunks
- commit/open masked high/low values in vector form
- run CEF and CarryCompare as vector circuits
- certify BCC privately before challenge
- discard BCC-failing tokens pre-challenge
- persist token identities and consumption state

It must not:

- reveal nonce shares after challenge
- reveal boundary distances or failed coefficient positions
- use public exact `A*nonce` commitments
- accept caller-provided clear `y_shares` on release paths

## Counters Are Release Gates

Every production phase should emit counters:

```text
rounds
MPC gates
MPC multiplication layers
vector lanes
chunks
private messages
broadcast messages
wire bytes
durable log bytes
open_many phases
assert_zero/assert_bit phases
tokens requested
tokens certified
tokens rejected pre-challenge
wall-clock time
```

Release checks should reject scalarized execution. For example:

```text
Power2Round over ML-DSA-44 must not emit one transport phase per coefficient.
IT-VSS over s1/s2 must not emit one sharing per coefficient.
Preprocessing must not emit one BCC circuit per coefficient.
```

## Benchmark Matrix

Maintain benchmarks for:

- ML-DSA-44, ML-DSA-65, ML-DSA-87
- 2-of-3, 3-of-5, 4-of-7 where supported by the honest-majority profile
- LAN-like RTT
- WAN-like RTT
- durable logging enabled
- restart/resume from mid-phase
- token batch sizes used by strict signing

Benchmarks should report:

```text
DKG time
preprocessing token throughput
strict signing latency with prepared tokens
strict signing latency when token pool is empty
message count
wire bytes
durable log bytes
peak memory
```

## Follow-Up Tasks

- [ ] Add release counters to every production phase.
- [ ] Add scalarization detectors for IT-VSS, Power2Round, preprocessing, and
  strict signing.
- [ ] Add benchmark harnesses for DKG, preprocessing, and strict signing.
- [ ] Add token-batch sizing experiments.
- [ ] Add chunk-size tuning experiments.
- [ ] Add LAN/WAN RTT simulation tests.
- [ ] Add restart/resume performance tests.
- [ ] Add documentation for recommended production batch sizes once measured.
- [ ] Add CI performance smoke tests with conservative thresholds.
- [ ] Add non-CI extended benchmarks for release candidates.
