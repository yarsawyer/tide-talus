# Threshold ML-DSA Alternative Scheme Evaluation

This document tracks external schemes that may influence the TALUS production
direction. It is an evaluation track, not an implementation plan. The live
TALUS task list remains `IMPLEMENTATION_PLAN.md`.

Current date for this snapshot: 2026-05-13.

## Evaluation Rules

Do not replace the TALUS production design based on marketing claims or crate
README text alone.

Each candidate must be evaluated against:

```text
- standard FIPS 204 verifier compatibility;
- DKG or key-import story;
- threshold shapes supported;
- online round count and WAN latency;
- communication per party;
- fail-closed behavior;
- malicious behavior / abort model;
- trusted setup, trusted dealer, TEE, coordinator, or CRS assumptions;
- implementation provenance and audit status;
- dependency quality;
- tests with an independent FIPS 204 verifier;
- fit with ML-KEM channels and ML-DSA operational identities.
```

## Track A: Mithril Evaluation

Primary public pointers:

```text
Paper:
  ePrint 2026/013, "Efficient Threshold ML-DSA"

Project site:
  https://mithril-th.org/

Public Go implementation:
  https://github.com/Threshold-ML-DSA/Threshold-ML-DSA

Rust crate:
  https://docs.rs/threshold-ml-dsa/latest/threshold_ml_dsa/
```

Initial public-source findings:

```text
- Mithril targets ML-DSA-compatible threshold signatures.
- Public site claims support up to 6 parties and 3 rounds per signing attempt.
- Public site claims millisecond computation and WAN-friendly signing.
- Public site reports ML-DSA-44 communication costs from about 10.5 kB to
  524.8 kB for listed N/T combinations and says WAN attempts are under 1s.
- GitHub repository is Go-heavy and explicitly labels the implementation as an
  academic proof-of-concept, not production-ready.
- GitHub repository says local implementation covers ML-DSA-44/65/87 and network
  examples are ML-DSA-44 oriented.
- Rust `threshold-ml-dsa` crate claims a hardened 3-round RSS / hyperball local
  rejection implementation, but docs.rs currently shows ML-DSA-44-focused SDK
  modules and verification delegated to `dilithium-rs`.
```

Local code snapshots:

```text
Go proof-of-concept:
  path: mithril/go
  remote: https://github.com/Threshold-ML-DSA/Threshold-ML-DSA
  commit: fca21f80ed40103b2f893b9edb73546d23ded647

Rust crate implementation:
  path: mithril/rust
  remote: https://github.com/lattice-safe/threshold-ml-dsa
  commit: db589fc6b9353d426395ce4dcf0bff1d25edb4de
  crate version inspected: threshold-ml-dsa 0.3.6
  license: MIT
```

Observed local tests and benchmarks:

```text
Rust:
  command run from /tmp copy because Cargo treats mithril/rust as inside the
  TALUS workspace:
    CARGO_HOME=/tmp/talus-cargo \
    CARGO_TARGET_DIR=/tmp/talus-mithril-rust-target \
    cargo test --test v03_tests

  result:
    12 passed, 0 failed
    covered end-to-end examples:
      (2,2), (2,3), (3,3), (3,4), (4,6), (5,6)
    runtime:
      about 3.31s for v03_tests after compile

Go:
  environment:
    GOPATH=/tmp/talus-gopath
    GOMODCACHE=/tmp/talus-gomodcache
    GOCACHE=/tmp/talus-gocache

  commands/results:
    go run main.go type=d iter=1 t=2 n=3 p=44
      per-party local signing work: about 0.66-0.69 ms
      combine: about 0.15 ms per run
      bytes per party:
        round 1: 32
        round 2: 8,832
        round 3: 6,912

    go run main.go type=d iter=1 t=3 n=5 p=44
      per-party local signing work: about 2.25-2.39 ms
      combine: about 0.61 ms
      bytes per party:
        round 1: 32
        round 2: 41,216
        round 3: 32,256

    go run main.go type=d iter=1 t=4 n=6 p=44
      per-party local signing work: about 13.17-15.28 ms
      combine: about 3.56 ms
      bytes per party:
        round 1: 32
        round 2: 217,856
        round 3: 170,496

    go run main.go type=d iter=1 t=3 n=5 p=65
      per-party local signing work: about 14.51-21.72 ms
      combine: about 2.42 ms
      bytes per party:
        round 1: 32
        round 2: 273,792
        round 3: 198,400
```

Why Mithril is fast, based on code inspection:

```text
1. It does not run private online MPC circuits for response validity.

   Parties send clear threshold response material to the coordinator. The
   coordinator aggregates candidate z values, checks z norm, computes
   Az - c*t1*2^d, constructs hints, and runs standard verification in the clear.

2. It avoids Shamir/Lagrange coefficient blow-up using replicated secret sharing
   (RSS), so reconstruction is additive rather than Lagrange-weighted.

3. It uses K parallel commitment slots per signing attempt. One network attempt
   carries many candidate nonces/responses, and the coordinator tries slots until
   one produces a valid FIPS 204 signature.

4. Rejection is local/clear rather than hidden:
   - party-side `round3` consumes `StRound1`;
   - locally rejected slots are returned as zero response vectors;
   - accepted partial z responses are visible to the coordinator;
   - if final combine rejects a slot, candidate aggregate material has still
     been processed in the clear.

5. DKG in the Rust crate is not a dealerless IT-VSS DKG. It is fresh RSS keygen
   from a seed / in-process SDK shape. The README explicitly says there is no
   existing key decomposition.
```

Security implications for TALUS:

```text
- Mithril's speed is not evidence that our StrictPqHmProduction path should
  remove private z-bound/hint checks. Mithril is using a different proof shape
  and a different security target.

- Important correction after reading the full paper:
  Mithril is not merely "forgetting" the rejected-z problem. The paper starts
  from the same Fiat-Shamir-with-aborts issue: rejected candidates must not be
  leaked. Its answer is per-party hyperball rejection. Once a party response
  passes that local rejection, the paper treats the clear partial response as
  safe to reveal. Later global rejection is treated as correctness/size
  compatibility rather than the main secrecy-preserving rejection.

- The useful engineering lessons are:
    RSS avoids Lagrange blow-up.
    K-parallel candidates amortize rejection.
    keep online work in a few message rounds.
    make candidate arithmetic local/linear where the proof allows it.

- The risky/mismatched part for our current production standard is:
    accepted partial z is clear to the coordinator;
    candidate aggregate z values are processed by the coordinator;
    local rejection/abort behavior is observable;
    the proof target is game-based unforgeability, not our current strict
    no-rejected-z-leakage / full malicious-privacy discipline.

  This does not automatically make Mithril insecure. It means it cannot be
  dropped into StrictPqHmProduction without deciding whether to accept Mithril's
  security model and proof obligations instead of our stricter MPC-hidden
  transcript rule.
```

Paper-read summary:

```text
Paper read:
  Full version hosted by Brave Research, "Efficient Threshold ML-DSA",
  USENIX Security 2026. It says it supersedes the ePrint 2026/013 preprint.

Core model:
  - threshold signature scheme with aborts;
  - static corruptions;
  - adversary controls the communication channel in the TS-UF game;
  - up to T-1 corruptions, therefore dishonest-majority threshold-signature
    style rather than honest-majority MPC;
  - security theorem is game-based unforgeability in the random oracle model;
  - correctness is probabilistic termination, not guaranteed output delivery.

Core construction:
  - replicated secret sharing over subsets of size N-T+1;
  - any T signers cover all subset secrets;
  - RSSRecover partitions subset secrets among active parties to minimize each
    party's partial secret norm;
  - no Lagrange coefficients in signing;
  - per-party commitments are full MLWE samples w_i = A*r_i, where r_i includes
    the extra e component, not plain A*y;
  - challenge is derived from HighBits(sum w_i);
  - each party computes z_i = c*s_i_partial + r_i and runs hyperball rejection;
  - combine aggregates z and performs final ML-DSA-compatible checks/hint
    construction.

Why accepted partial z can be clear in their model:
  - the first per-party rejection step is the secrecy-preserving step;
  - the paper explicitly says this step is required for security and is meant to
    ensure partial signature reveal does not leak the secret;
  - the later global checks are described as compatibility/correctness checks;
  - the proof uses Rej/Ideal hybrids and bounds divergence between real and
    ideal response distributions.

Rejected/local abort handling in the proof:
  - the proof explicitly discusses rejected z distributions;
  - rejected responses are sampled from an aborting distribution in hybrids;
  - commitments corresponding to rejected responses are later replaced under
    MLWE-style indistinguishability arguments.

DKG:
  - the simple keygen figure uses a trusted dealer for clarity;
  - Appendix D gives a 4-round-plus-aggregation DKG;
  - it uses group leaders for subset secrets;
  - leaders distribute group secrets over secure point-to-point channels;
  - all parties commit/reveal randomness to derive global R and rho;
  - leaders commit/reveal partial public keys;
  - transcript signatures are used so parties agree on the DKG transcript.
  - current inspected Go/Rust code does not expose this full DKG as a normal
    implementation path. The Rust crate uses deterministic fresh RSS keygen
    from a seed, and the Go benchmark path uses seed-derived threshold keys.

Mithril DKG adaptation assessment:
  - Effective for Mithril signing:
      yes, if Appendix D is implemented as specified. It creates RSS subset
      secrets directly, so signing avoids Shamir/Lagrange blow-up. It is only
      four communication rounds plus local aggregation, much lighter than our
      IT-VSS/IT-MPC DKG.

  - Drop-in replacement for TALUS DKG:
      no. It produces an RSS/subset-secret key structure for Mithril signing,
      not Shamir/IT-VSS shares of s1/s2 for the current TALUS strict MPC path.

  - Public A-secret concern:
      lower than the broken TALUS public A*s1_i path because Appendix D reveals
      partial public keys t_S = A*s1_S + s2_S, not noiseless A*s1_S. The s2
      noise is essential. Any adaptation must preserve this and must never
      publish a noiseless exact A-image of a secret.

  - Liveness/malicious behavior:
      conservative abort/fail-closed is plausible, but production code needs
      explicit handling for equivocated KS, mismatched commitments, missing
      reveals, wrong transcript signatures, replay, wrong subset leader, and
      bad partial public-key reveals.

  - Integration path:
      implement only as a separate Mithril backend prototype, not by replacing
      the current TALUS IT-VSS DKG in-place.

Important limitations for us:
  - not UC malicious MPC;
  - not our current strict hidden-candidate signing transcript;
  - supports small N, with parameters evaluated up to N=6;
  - DKG is a different RSS/subset construction, not our IT-VSS DKG;
  - proof-of-concept Go repository says it is not production-ready;
  - Rust crate is ML-DSA-44-focused in high-level SDK and uses dilithium-rs for
    verification.
```

Evaluation tasks:

```text
[x] Read ePrint 2026/013 / full USENIX 2026 version.
[ ] Extract exact security model:
    - honest/dishonest majority;
    - static/adaptive corruption;
    - identifiable abort or fail-closed only;
    - replay/retry behavior;
    - coordinator assumptions.
[x] Initial security-model extraction:
    - static corruption threshold-signature unforgeability;
    - dishonest-majority style with fewer than T corruptions;
    - channel controlled by adversary in the game;
    - probabilistic abort/correctness;
    - no guaranteed output delivery;
    - not UC malicious MPC.
[ ] Extract threshold limits:
    - confirm max N and threshold constraints;
    - test N=3,4,5,6;
    - record which T values are supported.
[ ] Inspect Go implementation:
    - protocol phases;
    - DKG/keygen;
    - key import if any;
    - transport assumptions;
    - fail-closed final verification;
    - use of CIRCL and any modified ML-DSA internals.
[~] Run Go local tests and benchmarks:
    - N=3..6;
    - ML-DSA-44/65/87 where supported;
    - record success rate, latency, communication.
[ ] Run Go network example where practical:
    - LAN first;
    - WAN simulation later;
    - confirm round count and failure behavior.
[~] Inspect Rust `threshold-ml-dsa` crate provenance:
    - owner/publisher;
    - repository;
    - license;
    - dependency tree;
    - audit claims;
    - supported suites;
    - DKG/key-import APIs.
[~] Test Rust crate:
    - N=3..6 where supported;
    - generate signatures;
    - verify with an independent FIPS 204 verifier, not only crate verifier;
    - compare output size and public key compatibility.
[ ] Malicious/fail-closed tests:
    - missing party;
    - malformed share;
    - wrong challenge;
    - replayed message;
    - duplicate party id;
    - invalid aggregator output;
    - ensure invalid signatures are not returned.
[ ] Determine integration fit:
    - can TALUS use Mithril as a backend?
    - does it need DKG or can it import existing ML-DSA shares?
    - can it fit our ML-KEM/ML-DSA transport contract?
    - can it satisfy no public exact A-secret image and no rejected-z leakage
      requirements?
[ ] Prototype Mithril Appendix-D DKG only if Track A remains promising:
    - implement as separate RSS/Mithril backend;
    - do not wire into TALUS Shamir/IT-VSS DKG;
    - test all subset-leader paths for N=3..6;
    - verify public key with independent FIPS 204 verifier;
    - adversarial tests for equivocation, replay, missing KS, bad transcript
      signatures, bad partial public-key reveal, wrong leader, wrong subset.
```

Completion gate:

```text
Mithril is either:
  - rejected with concrete reasons;
  - accepted as a possible future backend with documented limits;
  - selected for prototype integration behind a feature-gated evaluation crate.

No production replacement decision is allowed before independent verifier tests
and malicious/fail-closed tests pass.
```

## Track B: Quorus Evaluation

Primary public pointers:

```text
Paper:
  ePrint 2025/1163,
  "Efficient, Scalable Threshold ML-DSA Signatures: An MPC Approach"

NIST MPTS 2026 presentation:
  "Quorus: Scalable Threshold ML-DSA from MPC"
```

Initial public-source findings:

```text
- Quorus targets FIPS 204-compatible ML-DSA verification.
- ePrint abstract says the protocol is MPC-friendly, supports all three ML-DSA
  security levels, and in the honest-majority setting avoids additional public
  key assumptions.
- ePrint abstract says online communication can be as little as about 100 kB per
  party per rejection-sampling round.
- NIST MPTS page says Quorus includes DKG, offline preprocessing, UC-style strong
  guarantees, scalability to medium-sized groups such as up to 64 under honest
  majority, and low online signing latency.
```

Evaluation tasks:

```text
[ ] Read ePrint 2025/1163 fully.
[ ] Extract exact honest-majority model:
    - n/f/T threshold constraints;
    - malicious vs semi-honest components;
    - abort/fairness/output-delivery claims;
    - UC theorem assumptions.
[ ] Extract DKG protocol:
    - public/private channels;
    - preprocessing requirements;
    - whether it aligns with our IT-VSS/IT-MPC direction.
[ ] Extract signing protocol:
    - online rounds;
    - offline rounds;
    - rejection sampling behavior;
    - whether rejected candidate material is public or hidden;
    - final verifier/fail-closed behavior.
[ ] Compute expected latency:
    - LAN with 1 ms RTT;
    - regional WAN with 20-50 ms RTT;
    - global WAN with 100-200 ms RTT;
    - compare online round count against our strict path.
[ ] Search and inspect implementation availability:
    - public repo;
    - artifact from authors;
    - NIST submission package;
    - dependency/license/audit status.
[ ] Compare with TALUS IT-VSS/IT-MPC:
    - can Quorus replace our DKG/preprocessing/signing core?
    - can we reuse our transport/evidence/logging framework?
    - does Quorus make our BCC/CEF path unnecessary?
    - what performance/security tradeoffs change?
[ ] Independent verification tests if implementation is available:
    - ML-DSA-44/65/87;
    - N/T matrix matching paper claims;
    - verify signatures with independent FIPS 204 verifier.
```

Completion gate:

```text
Quorus is either:
  - rejected with concrete reasons;
  - accepted as design input for our IT-MPC runtime;
  - selected for prototype integration behind a feature-gated evaluation crate.

No production replacement decision is allowed before round/latency analysis and
implementation availability are clear.
```

## Comparison Matrix To Fill

```text
Criterion                         TALUS strict current   Mithril   Quorus
---------------------------------------------------------------------------
FIPS 204 verifier compatibility    yes                    TBD       claimed
All ML-DSA suites                  yes                    TBD       claimed
N > 6                              intended               likely no claimed up to ~64
Honest-majority fit                yes                    TBD       yes
Dishonest-majority fit             no                     TBD       TBD
DKG included                       yes                    TBD       claimed
Key import                         planned/partial         TBD       TBD
Online rounds                      too high currently      claimed 3 TBD
WAN latency                        not acceptable yet      claimed <1s TBD
Rejected-z hidden                  yes                    TBD       TBD
No public A-secret image           yes                    TBD       TBD
Fail-closed final verify           yes                    claimed   TBD
Implementation public              yes                    Go/Rust   TBD
Production audit status            no external audit       no        TBD
```

## Sources Checked

```text
Mithril project site:
  https://mithril-th.org/

Mithril Go proof-of-concept:
  https://github.com/Threshold-ML-DSA/Threshold-ML-DSA

Rust threshold-ml-dsa docs:
  https://docs.rs/threshold-ml-dsa/latest/threshold_ml_dsa/

Quorus ePrint:
  https://eprint.iacr.org/2025/1163

NIST MPTS Quorus page:
  https://csrc.nist.gov/presentations/2026/mpts2026-3b6
```
