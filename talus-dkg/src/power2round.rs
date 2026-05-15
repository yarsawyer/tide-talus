use super::*;

/// Public-key assembly transcript label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyAssemblyLabel {
    /// DKG configuration hash.
    pub config_hash: KeygenTranscriptHash,
    /// Hash of public matrix seed `rho`.
    pub rho_hash: [u8; 32],
}

impl PublicKeyAssemblyLabel {
    /// Builds a label for one DKG public-key assembly.
    pub fn new(config: &DkgConfig, rho: [u8; 32]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/public-key-assembly-rho");
        hasher.update(config.transcript_hash().0);
        hasher.update(rho);
        Self {
            config_hash: config.transcript_hash(),
            rho_hash: hasher.finalize().into(),
        }
    }
}

/// Origin metadata for a temporary shared `t = A*s1+s2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedTOrigin {
    /// Shared `t` originated from DKG public-key assembly.
    DkgPublicKeyAssembly {
        /// DKG epoch.
        epoch: KeygenEpoch,
        /// Hash of the configured party set.
        party_set_hash: [u8; 32],
    },
}

/// One party's share of temporary `t = A*s1+s2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedTPartyShare {
    /// Receiver party.
    pub party: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Share of `t`.
    pub t_share: PolyVec,
}

/// Temporary consumed secret `t = A*s1+s2`.
///
/// `SharedT` is intentionally not `Clone`. It is consumed by
/// `MpcPower2RoundBackend::power2round_t1`, and its coefficient buffers are
/// zeroed on drop.
pub struct SharedT {
    /// Party shares of `t`.
    pub shares: Vec<SharedTPartyShare>,
    /// Transcript label.
    pub assembly_label: PublicKeyAssemblyLabel,
    /// Origin metadata.
    pub origin: SharedTOrigin,
}

impl fmt::Debug for SharedT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedT")
            .field("shares", &"<redacted>")
            .field("assembly_label", &self.assembly_label)
            .field("origin", &self.origin)
            .finish()
    }
}

impl Drop for SharedT {
    fn drop(&mut self) {
        for share in &mut self.shares {
            for poly in share.t_share.polys_mut() {
                poly.coeffs_mut().zeroize();
            }
        }
    }
}

/// Public `t1` opened by the Power2Round backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicT1 {
    /// Packed public-key `t1` bytes.
    pub bytes: Vec<u8>,
    /// Public unpacked `t1` coefficients.
    pub coeffs: Vec<u16>,
}

/// Power2Round backend identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Power2RoundBackendId {
    /// Insecure clear simulator.
    #[cfg(test)]
    InsecureClearSimulator,
    /// Local deterministic prime-field simulator for circuit tests.
    #[cfg(test)]
    LocalPrimeFieldSimulator,
    /// In-process Shamir data-model simulator.
    #[cfg(test)]
    InProcessShamirSimulator,
    /// Networked Shamir round simulator.
    #[cfg(test)]
    NetworkedShamirSimulator,
    /// Transport-backed Shamir round simulator using canonical wire payloads.
    #[cfg(test)]
    TransportBackedShamirSimulator,
    /// Multi-runtime transport-backed Shamir simulator using per-party runtimes.
    #[cfg(test)]
    RuntimeCoordinatedTransportShamirSimulator,
    /// Transport-backed per-party Power2Round skeleton.
    #[cfg(test)]
    TransportBackedPerPartySkeleton,
    /// Transport-backed per-party Power2Round phase driver.
    #[cfg(test)]
    TransportBackedPerPartyDriver,
    /// Production IT-MPC backend.
    ProductionItMpc,
}

/// Public evidence for the Power2Round opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Power2RoundEvidence {
    /// Backend that produced this evidence.
    pub backend_id: Power2RoundBackendId,
    /// DKG epoch.
    pub epoch: KeygenEpoch,
    /// ML-DSA suite.
    pub suite: DkgSuite,
    /// Party-set hash.
    pub party_set_hash: [u8; 32],
    /// Rho hash.
    pub rho_hash: [u8; 32],
    /// Hash of opened `t1` bytes.
    pub output_t1_hash: [u8; 32],
    /// Transcript hash for this opening.
    pub transcript_hash: [u8; 32],
}

/// Public output produced by the production vector Power2Round driver.
///
/// This type is the assembly boundary for production DKG. It can only be
/// constructed when the public `t1` bytes and transcript evidence are bound to
/// the DKG config, rho, party set, and `ProductionItMpc` backend identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPower2RoundOutput {
    /// Public `t1` opened by the production Power2Round protocol.
    pub t1: PublicT1,
    /// Public evidence bound to `t1` and the DKG assembly label.
    pub evidence: Power2RoundEvidence,
    /// Durable vector IT-MPC runtime evidence for the protocol transcript.
    ///
    /// This is optional at the low-level output boundary so correctness tests
    /// can still exercise the pure `t1`/evidence binding. Release-valid DKG
    /// assembly requires this field to be present in the final public
    /// certificate.
    pub runtime_evidence: Option<ProductionVectorItMpcRuntimeEvidence>,
    /// Optional hash binding this Power2Round output to the setup transcript
    /// that produced `[t] = A[s1] + [s2]`.
    ///
    /// Generic correctness tests may omit this. Release-valid native DKG
    /// assembly requires it to match the recovered production setup
    /// certificate, preventing a valid `t1` output for the same config/rho from
    /// being attached to unrelated sampler/IT-VSS setup logs.
    pub setup_input_hash: Option<[u8; 32]>,
}

impl ProductionPower2RoundOutput {
    /// Validates and constructs a production Power2Round output.
    pub fn new(
        config: &DkgConfig,
        assembly_label: PublicKeyAssemblyLabel,
        t1: PublicT1,
        evidence: Power2RoundEvidence,
    ) -> Result<Self, DkgError> {
        Self::new_with_runtime_evidence(config, assembly_label, t1, evidence, None)
    }

    /// Validates and constructs a production Power2Round output with durable
    /// vector IT-MPC runtime evidence.
    pub fn new_with_runtime_evidence(
        config: &DkgConfig,
        assembly_label: PublicKeyAssemblyLabel,
        t1: PublicT1,
        evidence: Power2RoundEvidence,
        runtime_evidence: Option<ProductionVectorItMpcRuntimeEvidence>,
    ) -> Result<Self, DkgError> {
        if evidence.backend_id != Power2RoundBackendId::ProductionItMpc {
            return Err(DkgError::InsecurePower2RoundBackend);
        }
        if t1.bytes.len() != config.suite.t1_len() {
            return Err(DkgError::InvalidT1Length {
                expected: config.suite.t1_len(),
                got: t1.bytes.len(),
            });
        }
        let expected = power2round_certify_public_t1_evidence(
            Power2RoundBackendId::ProductionItMpc,
            config,
            assembly_label,
            &t1,
        );
        if evidence != expected {
            return Err(DkgError::Power2RoundEvidenceRequired);
        }
        if let Some(runtime) = &runtime_evidence {
            ensure_production_power2round_runtime_evidence_for_release(runtime)?;
        }
        Ok(Self {
            t1,
            evidence,
            runtime_evidence,
            setup_input_hash: None,
        })
    }

    /// Attaches the setup-input binding hash expected by release-valid native
    /// DKG assembly.
    pub fn with_setup_input_hash(mut self, setup_input_hash: [u8; 32]) -> Self {
        self.setup_input_hash = Some(setup_input_hash);
        self
    }

    /// Returns the setup-input binding hash, when present.
    pub const fn setup_input_hash(&self) -> Option<[u8; 32]> {
        self.setup_input_hash
    }

    /// Splits the validated public output into its parts.
    pub fn into_parts(
        self,
    ) -> (
        PublicT1,
        Power2RoundEvidence,
        Option<ProductionVectorItMpcRuntimeEvidence>,
    ) {
        (self.t1, self.evidence, self.runtime_evidence)
    }
}

/// DKG setup backend identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgSetupBackendId {
    /// Local in-process scaffold using hash-bound scalar checks.
    InProcessScaffold,
    /// Production information-checking VSS/MPC backend.
    ProductionInformationTheoretic,
}

/// Release blockers attached to scaffold DKG certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgReleaseBlocker {
    /// Setup used scaffold-derived IT-VSS public artifacts.
    ScaffoldItVssAdapters,
    /// Production Rabin-Ben-Or-style IT-VSS is not yet selected.
    ProductionItVss,
    /// Production honest-majority IT-MPC is not yet selected.
    ProductionItMpc,
    /// Application transport conformance is incomplete.
    TransportConformance,
    /// Optional external cryptographic/security audit blocker.
    ExternalReview,
}

/// Transcript certificate for native DKG setup phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgSetupTranscriptCertificate {
    /// DKG setup backend identity.
    pub setup_backend_id: DkgSetupBackendId,
    /// Hash of accepted `s1` bounded-sampler residue rounds.
    pub sampler_s1_hash: [u8; 32],
    /// Hash of accepted `s2` bounded-sampler residue rounds.
    pub sampler_s2_hash: [u8; 32],
    /// Hash of accepted VSS public-check commits.
    pub vss_commit_hash: [u8; 32],
    /// Hash of accepted VSS directed-share payloads for this local package.
    pub vss_share_hash: [u8; 32],
    /// Hash of accepted VSS complaints.
    pub complaint_hash: [u8; 32],
    /// Hash of persisted IT-VSS public commitment artifacts.
    pub it_vss_public_artifact_hash: [u8; 32],
    /// Hash of persisted IT-VSS complaint-resolution artifact.
    pub it_vss_resolution_hash: [u8; 32],
    /// IT-VSS artifact backend id used during setup.
    pub it_vss_backend_id: ItVssBackendId,
    /// Complaint payloads accepted by the setup complaint resolver.
    ///
    /// These are public evidence records. They must not contain raw secret
    /// shares; each payload is hash/binding evidence sufficient to reproduce
    /// the dealer rejection decision.
    pub complaints: Vec<DkgComplaintPayload>,
    /// Accepted dealer parties.
    pub accepted_dealers: Vec<PartyId>,
    /// Rejected dealer parties.
    pub rejected_dealers: Vec<PartyId>,
    /// Remaining blockers before this certificate can be production-grade.
    pub release_blockers: Vec<DkgReleaseBlocker>,
}

/// Transcript label for coefficient-level MPC `Power2Round` subprotocols.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Power2RoundTranscriptLabel {
    path: String,
}

impl Power2RoundTranscriptLabel {
    /// Creates a root Power2Round label bound to the DKG configuration and rho.
    pub fn root(config: &DkgConfig, rho_hash: [u8; 32]) -> Self {
        Self {
            path: format!(
                "TALUS-DKG-Power2Round-v1/suite_{:?}/epoch_{}/threshold_{}/party_set_{:02x?}/rho_{:02x?}",
                config.suite,
                config.epoch.0,
                config.threshold,
                dkg_party_set_hash(config),
                rho_hash
            ),
        }
    }

    /// Creates a root label for preprocessing vector IT-MPC phases.
    pub fn preprocessing_root(session_id: [u8; 32], transcript_hash: [u8; 32]) -> Self {
        Self {
            path: format!(
                "TALUS-Preprocessing-Vector-IT-MPC-v1/session_{session_id:02x?}/transcript_{transcript_hash:02x?}"
            ),
        }
    }

    /// Derives a child label.
    pub fn child(&self, name: impl AsRef<str>) -> Self {
        Self {
            path: format!("{}/{}", self.path, name.as_ref()),
        }
    }

    /// Returns the canonical label path.
    pub fn as_str(&self) -> &str {
        &self.path
    }
}

impl fmt::Debug for Power2RoundTranscriptLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Power2RoundTranscriptLabel")
            .field(&self.path)
            .finish()
    }
}

/// Public DKG certificate for key-package assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyAssemblyCertificate {
    /// Power2Round public evidence.
    pub power2round: Power2RoundEvidence,
    /// Durable vector IT-MPC runtime evidence used by Power2Round.
    ///
    /// Release-valid production packages must include this evidence and it
    /// must prove full Phase 3 vector coverage. Tests and scaffold outputs may
    /// leave it empty, but release gates reject those certificates.
    pub power2round_runtime: Option<ProductionVectorItMpcRuntimeEvidence>,
    /// Optional native DKG setup transcript certificate.
    pub setup: Option<DkgSetupTranscriptCertificate>,
    /// Hash binding the Power2Round output to the native DKG setup transcript
    /// that produced the shared `t` input.
    ///
    /// Release-valid native DKG certificates must include this when `setup` is
    /// present, and it must match the setup certificate.
    pub power2round_setup_input_hash: Option<[u8; 32]>,
}

/// Hashes the setup transcript material that determines the secret-shared
/// Power2Round input `[t] = A[s1] + [s2]`.
pub fn production_power2round_setup_input_hash(
    config: &DkgConfig,
    rho: [u8; 32],
    setup: &DkgSetupTranscriptCertificate,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/production-power2round-setup-input");
    hasher.update(config.transcript_hash().0);
    hasher.update(rho);
    hasher.update([match setup.setup_backend_id {
        DkgSetupBackendId::InProcessScaffold => 1,
        DkgSetupBackendId::ProductionInformationTheoretic => 2,
    }]);
    hasher.update(setup.sampler_s1_hash);
    hasher.update(setup.sampler_s2_hash);
    hasher.update(setup.vss_commit_hash);
    hasher.update(setup.vss_share_hash);
    hasher.update(setup.complaint_hash);
    hasher.update(setup.it_vss_public_artifact_hash);
    hasher.update(setup.it_vss_resolution_hash);
    hasher.update([setup.it_vss_backend_id.as_u8()]);
    hasher.update((setup.complaints.len() as u32).to_le_bytes());
    for complaint in &setup.complaints {
        hasher.update(complaint.complainant.0.to_le_bytes());
        hasher.update(complaint.dealer.0.to_le_bytes());
        hasher.update(complaint.receiver.0.to_le_bytes());
        hasher.update([complaint.reason.as_u8()]);
        hasher.update((complaint.evidence.len() as u32).to_le_bytes());
        hasher.update(&complaint.evidence);
    }
    hasher.update((setup.accepted_dealers.len() as u32).to_le_bytes());
    for dealer in &setup.accepted_dealers {
        hasher.update(dealer.0.to_le_bytes());
    }
    hasher.update((setup.rejected_dealers.len() as u32).to_le_bytes());
    for dealer in &setup.rejected_dealers {
        hasher.update(dealer.0.to_le_bytes());
    }
    hasher.finalize().into()
}

/// DKG key package shape. This intentionally contains no `s2`, `t`, `t0`, low
/// bits, bit-decomposition witnesses, or simulator private material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgKeyPackage {
    /// Suite.
    pub suite: DkgSuite,
    /// Epoch.
    pub epoch: KeygenEpoch,
    /// Party owning this package.
    pub party: PartyId,
    /// Threshold.
    pub threshold: u16,
    /// Public matrix seed.
    pub rho: [u8; 32],
    /// Opened public `t1`.
    pub t1: PublicT1,
    /// Serialized FIPS public key.
    pub public_key: Vec<u8>,
    /// Long-term `s1` share package.
    pub s1_share: DkgS1SecretShare,
    /// Private long-term `[As1] = [A*s1]` helper share package.
    pub as1_share: DkgAs1SecretShare,
    /// Public certificate.
    pub certificate: PublicKeyAssemblyCertificate,
}

/// Trait boundary for the non-linear MPC `Power2Round` public-key assembly step.
pub trait MpcPower2RoundBackend {
    /// Public evidence type.
    type Evidence;

    /// Backend identifier.
    fn backend_id(&self) -> Power2RoundBackendId;

    /// Consumes shared `t`, opens public `t1`, and returns transcript-bound evidence.
    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError>;
}

/// Prime-field share used by the local Fq IT-MPC simulator.
#[derive(Clone, Eq, PartialEq)]
pub struct PrimeFieldShare {
    value: Coeff,
}

#[cfg(test)]
impl PrimeFieldShare {
    fn new<P: MlDsaParams>(value: Coeff) -> Self {
        Self {
            value: reduce_mod_q::<P>(value),
        }
    }
}

impl fmt::Debug for PrimeFieldShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimeFieldShare")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for PrimeFieldShare {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// Secret bit represented as a field element in Fq.
#[derive(Clone, Eq, PartialEq)]
pub struct PrimeFieldBitShare {
    share: PrimeFieldShare,
}

impl fmt::Debug for PrimeFieldBitShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimeFieldBitShare")
            .field("share", &"<redacted>")
            .finish()
    }
}

impl Zeroize for PrimeFieldBitShare {
    fn zeroize(&mut self) {
        self.share.zeroize();
    }
}

/// Vector of prime-field shares processed as one batched MPC payload.
#[derive(Clone, Eq, PartialEq)]
pub struct ShareVec<S: Zeroize> {
    lanes: Vec<S>,
}

impl<S: Zeroize> ShareVec<S> {
    /// Builds a vector share from individual lanes.
    pub fn from_lanes(lanes: Vec<S>) -> Self {
        Self { lanes }
    }

    /// Returns the number of lanes.
    pub fn len(&self) -> usize {
        self.lanes.len()
    }

    /// Returns true if this vector has no lanes.
    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }

    /// Returns the lanes.
    pub fn lanes(&self) -> &[S] {
        &self.lanes
    }

    /// Consumes the wrapper and returns the lanes.
    pub fn into_lanes(self) -> Vec<S> {
        self.lanes
    }
}

impl<S: Zeroize> fmt::Debug for ShareVec<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareVec")
            .field("len", &self.lanes.len())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

impl<S: Zeroize> Zeroize for ShareVec<S> {
    fn zeroize(&mut self) {
        self.lanes.zeroize();
    }
}

/// Vector of secret bit shares processed as one batched MPC payload.
#[derive(Clone, Eq, PartialEq)]
pub struct BitShareVec<B: Zeroize> {
    lanes: Vec<B>,
}

impl<B: Zeroize> BitShareVec<B> {
    /// Builds a vector bit share from individual lanes.
    pub fn from_lanes(lanes: Vec<B>) -> Self {
        Self { lanes }
    }

    /// Returns the number of lanes.
    pub fn len(&self) -> usize {
        self.lanes.len()
    }

    /// Returns true if this vector has no lanes.
    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }

    /// Returns the lanes.
    pub fn lanes(&self) -> &[B] {
        &self.lanes
    }

    /// Consumes the wrapper and returns the lanes.
    pub fn into_lanes(self) -> Vec<B> {
        self.lanes
    }
}

impl<B: Zeroize> fmt::Debug for BitShareVec<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitShareVec")
            .field("len", &self.lanes.len())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

impl<B: Zeroize> Zeroize for BitShareVec<B> {
    fn zeroize(&mut self) {
        self.lanes.zeroize();
    }
}

/// Performance counters for prime-field MPC backends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrimeFieldMpcCounters {
    /// Distinct MPC round labels observed in durable evidence.
    pub rounds: u64,
    /// Private wire messages observed in durable evidence.
    pub private_messages: u64,
    /// Broadcast wire messages observed in durable evidence.
    pub broadcasts: u64,
    /// Canonical wire bytes observed in durable evidence.
    pub wire_bytes: u64,
    /// Approximate durable log bytes required to persist observed evidence.
    pub durable_log_bytes: u64,
    /// Total vector lanes observed across vectorized phases.
    pub vector_lanes: u64,
    /// Distinct vector multiplication layers observed in durable evidence.
    pub multiplication_layers: u64,
    /// Wall-clock runtime in milliseconds, when supplied by a concrete backend.
    pub wall_clock_ms: u64,
    /// Scalar multiplication gates.
    pub scalar_mul_gates: u64,
    /// Vector multiplication gates, counted per lane.
    pub vector_mul_lanes: u64,
    /// Scalar checked openings.
    pub scalar_openings: u64,
    /// Vector checked openings, counted per lane.
    pub vector_opening_lanes: u64,
    /// Scalar assert-zero checks.
    pub scalar_assert_zero: u64,
    /// Vector assert-zero checks, counted per lane.
    pub vector_assert_zero_lanes: u64,
    /// Secret random bits.
    pub random_bits: u64,
    /// Public-constant lane multiplications performed locally.
    pub local_public_mul_lanes: u64,
}

/// Vector operation coverage proven by durable prime-field MPC wire records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionVectorItMpcRuntimeCoverage {
    /// A vector checked-opening phase was recorded.
    pub open_many_checked: bool,
    /// A vector assert-zero phase was recorded.
    pub assert_zero_vec: bool,
    /// Vector field-backed bitness checks were recorded.
    pub assert_bit_vec: bool,
    /// Vector random-bit generation was recorded.
    pub random_bit_vec: bool,
    /// Vector multiplication/degree-reduction was recorded.
    pub mul_vec: bool,
    /// A vector public comparison phase was recorded.
    pub comparison_to_public: bool,
    /// A vector equality-to-public/linear relation check was recorded.
    pub equality_to_public: bool,
    /// A vector bit-sum or threshold-check phase was recorded.
    pub bit_sum_or_threshold_check: bool,
    /// A vector private one-hot selection phase was recorded.
    pub private_one_hot_selection: bool,
    /// Preprocessing masked-broadcast consistency openings were recorded.
    pub preprocessing_masked_broadcast: bool,
    /// Preprocessing CarryCompare certification phases were recorded.
    pub preprocessing_carry_compare: bool,
    /// Preprocessing CEF/BCC certification phases were recorded.
    pub preprocessing_cef_bcc: bool,
}

impl ProductionVectorItMpcRuntimeCoverage {
    /// Returns true when the evidence covers the generic vector operations
    /// needed by all Phase 3 consumers.
    pub fn covers_all_phase3_consumers(self) -> bool {
        self.open_many_checked
            && self.assert_zero_vec
            && self.assert_bit_vec
            && self.random_bit_vec
            && self.mul_vec
            && self.comparison_to_public
            && self.equality_to_public
            && self.bit_sum_or_threshold_check
            && self.private_one_hot_selection
            && self.preprocessing_masked_broadcast
            && self.preprocessing_carry_compare
            && self.preprocessing_cef_bcc
    }

    /// Returns true when the evidence covers the Power2Round vector circuit.
    pub fn covers_power2round(self) -> bool {
        self.open_many_checked
            && self.assert_zero_vec
            && self.assert_bit_vec
            && self.mul_vec
            && self.comparison_to_public
            && self.equality_to_public
            && self.bit_sum_or_threshold_check
    }

    /// Returns true when the evidence covers the vector operations needed by
    /// strict no-rejected-z signing.
    ///
    /// Strict signing consumes already-certified preprocessing tokens, so this
    /// gate is intentionally scoped to response preparation/check/selection and
    /// selected opening. Preprocessing-specific proof phases, including
    /// canonical helper-mask bitness, are checked by the token certification
    /// path, not by the online signing handoff.
    pub fn covers_strict_signing(self) -> bool {
        self.open_many_checked
            && self.assert_zero_vec
            && self.mul_vec
            && self.comparison_to_public
            && self.bit_sum_or_threshold_check
            && self.private_one_hot_selection
    }
}

/// Durable evidence that a prime-field MPC runtime executed vector phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionVectorItMpcRuntimeEvidence {
    /// Runtime counters derived from durable wire records.
    pub counters: PrimeFieldMpcCounters,
    /// Operation coverage derived from durable wire records.
    pub coverage: ProductionVectorItMpcRuntimeCoverage,
    /// Hash of the durable runtime wire transcript used for this evidence.
    pub transcript_hash: [u8; 32],
}

/// Durable wire-record profile for one MPC kind/phase pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimeFieldMpcPhaseProfile {
    /// MPC round kind.
    pub kind: PrimeFieldMpcRoundKind,
    /// MPC phase.
    pub phase: PrimeFieldMpcPhase,
    /// Wire records observed for this kind/phase.
    pub records: u64,
    /// Private-channel wire records observed for this kind/phase.
    pub private_records: u64,
    /// Broadcast wire records observed for this kind/phase.
    pub broadcast_records: u64,
    /// Distinct transcript labels observed for this kind/phase.
    pub distinct_labels: u64,
    /// Total vector lanes carried by this kind/phase.
    pub vector_lanes: u64,
    /// Maximum vector lanes carried by a single durable wire record.
    pub max_record_lanes: u64,
    /// Canonical wire bytes for this kind/phase.
    pub wire_bytes: u64,
    /// Estimated durable log bytes for this kind/phase.
    pub durable_log_bytes: u64,
}

impl PrimeFieldMpcPhaseProfile {
    /// Returns true when this phase carried vector lanes.
    pub const fn is_vectorized(self) -> bool {
        self.vector_lanes != 0
    }
}

/// Returns the highest-cost phase-profile entries by durable log bytes.
pub fn top_prime_field_mpc_phase_profiles_by_durable_log_bytes(
    profile: &[PrimeFieldMpcPhaseProfile],
    limit: usize,
) -> Vec<PrimeFieldMpcPhaseProfile> {
    let mut entries = profile.to_vec();
    entries.sort_by(|left, right| {
        right
            .durable_log_bytes
            .cmp(&left.durable_log_bytes)
            .then_with(|| right.wire_bytes.cmp(&left.wire_bytes))
            .then_with(|| right.records.cmp(&left.records))
    });
    entries.truncate(limit);
    entries
}

/// Ensures every durable MPC wire record respects the suite chunk-size policy.
///
/// This is intentionally a payload-size guard, not a performance claim: large
/// vectors should be split into bounded chunks for memory/transport safety, but
/// chunks must still stay vector-sized enough that release paths do not
/// devolve into scalar-per-coefficient scheduling.
pub fn ensure_prime_field_mpc_phase_profile_within_chunk_policy<P: MlDsaParams>(
    profile: &[PrimeFieldMpcPhaseProfile],
) -> Result<(), DkgError> {
    let policy = ProductionBatchSizingPolicy::for_suite::<P>();
    if profile
        .iter()
        .any(|entry| entry.max_record_lanes as usize > policy.max_vector_lanes_per_chunk)
    {
        return Err(DkgError::PrimeFieldMpcScalarizedReleaseBlocked);
    }
    Ok(())
}

impl PrimeFieldMpcCounters {
    /// Returns true if any scalar gate/open/check path was used.
    ///
    /// Scalar paths are useful for correctness tests, but production DKG must
    /// run Power2Round over vector phases so round count follows circuit depth
    /// rather than coefficient count.
    pub fn used_scalar_execution(self) -> bool {
        self.scalar_mul_gates != 0 || self.scalar_openings != 0 || self.scalar_assert_zero != 0
    }

    /// Returns true if any vectorized phase was exercised.
    pub fn used_vector_execution(self) -> bool {
        self.vector_mul_lanes != 0
            || self.vector_opening_lanes != 0
            || self.vector_assert_zero_lanes != 0
            || self.local_public_mul_lanes != 0
    }

    /// Returns true when durable evidence contains enough operational data to
    /// audit a release-capable vector runtime.
    pub fn has_durable_runtime_evidence(self) -> bool {
        self.rounds != 0
            && self.wire_bytes != 0
            && self.durable_log_bytes != 0
            && self.vector_lanes != 0
            && (self.private_messages != 0 || self.broadcasts != 0)
    }
}

/// Derives per-kind/per-phase profiling data from durable wire records.
pub fn prime_field_mpc_phase_profile_from_wire_records(
    records: &[PrimeFieldMpcWireMessageRecord],
) -> Result<Vec<PrimeFieldMpcPhaseProfile>, DkgError> {
    #[derive(Clone, Debug)]
    struct PhaseProfileAccumulator {
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        records: u64,
        private_records: u64,
        broadcast_records: u64,
        labels: std::collections::BTreeSet<[u8; 32]>,
        vector_lanes: u64,
        max_record_lanes: u64,
        wire_bytes: u64,
        durable_log_bytes: u64,
    }

    let mut grouped = std::collections::BTreeMap::<(u8, u8), PhaseProfileAccumulator>::new();
    for record in records {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        let phase =
            prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?;
        let encoded =
            encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let entry = grouped
            .entry((payload.round_kind, payload.phase))
            .or_insert_with(|| PhaseProfileAccumulator {
                kind,
                phase,
                records: 0,
                private_records: 0,
                broadcast_records: 0,
                labels: std::collections::BTreeSet::new(),
                vector_lanes: 0,
                max_record_lanes: 0,
                wire_bytes: 0,
                durable_log_bytes: 0,
            });
        entry.records = entry.records.saturating_add(1);
        match record.direction {
            PrimeFieldMpcWireDirection::SentPrivate
            | PrimeFieldMpcWireDirection::AcceptedPrivate => {
                entry.private_records = entry.private_records.saturating_add(1);
            }
            PrimeFieldMpcWireDirection::SentBroadcast
            | PrimeFieldMpcWireDirection::AcceptedBroadcast => {
                entry.broadcast_records = entry.broadcast_records.saturating_add(1);
            }
        }
        entry.labels.insert(payload.label_hash);
        entry.vector_lanes = entry
            .vector_lanes
            .saturating_add(u64::try_from(payload.values.len()).unwrap_or(u64::MAX));
        entry.max_record_lanes = entry
            .max_record_lanes
            .max(u64::try_from(payload.values.len()).unwrap_or(u64::MAX));
        let encoded_len = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        entry.wire_bytes = entry.wire_bytes.saturating_add(encoded_len);
        entry.durable_log_bytes = entry.durable_log_bytes.saturating_add(
            // Conservative per-record estimate. FilePrimeFieldMpcWireMessageLog
            // may compact same-layer batches into grouped durable lines.
            2 + 1 + 5 + 1 + encoded_len.saturating_mul(2) + 1,
        );
    }
    Ok(grouped
        .into_values()
        .map(|entry| PrimeFieldMpcPhaseProfile {
            kind: entry.kind,
            phase: entry.phase,
            records: entry.records,
            private_records: entry.private_records,
            broadcast_records: entry.broadcast_records,
            distinct_labels: entry.labels.len() as u64,
            vector_lanes: entry.vector_lanes,
            max_record_lanes: entry.max_record_lanes,
            wire_bytes: entry.wire_bytes,
            durable_log_bytes: entry.durable_log_bytes,
        })
        .collect())
}

/// Release gate for Power2Round/prime-field MPC execution counters.
///
/// Production DKG must not certify packages from scalar-per-coefficient
/// execution. This check is intended for runtime/benchmark evidence and CI
/// guards around release profiles; simulators may still use scalar counters in
/// tests that do not claim production readiness.
pub fn ensure_prime_field_mpc_counters_vectorized_for_release(
    counters: PrimeFieldMpcCounters,
) -> Result<(), DkgError> {
    if counters.used_scalar_execution() || !counters.used_vector_execution() {
        return Err(DkgError::PrimeFieldMpcScalarizedReleaseBlocked);
    }
    Ok(())
}

/// Release gate for a concrete prime-field MPC backend's own counters.
///
/// Production wrappers must not rely on trait default vector methods silently
/// scalarizing work. A release-capable backend has to expose counters, and
/// those counters must prove vector execution with no scalar gate/open/check
/// usage.
pub fn ensure_prime_field_mpc_backend_vectorized_for_release<P, B>(
    backend: &B,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let counters = backend.counters().ok_or(DkgError::BlockedPendingReview)?;
    ensure_prime_field_mpc_counters_vectorized_for_release(counters)
}

/// Derives prime-field MPC execution counters from durable wire records.
pub fn prime_field_mpc_counters_from_wire_records(
    records: &[PrimeFieldMpcWireMessageRecord],
) -> Result<PrimeFieldMpcCounters, DkgError> {
    let mut counters = PrimeFieldMpcCounters::default();
    let mut round_labels = std::collections::BTreeSet::new();
    let mut multiplication_layers = std::collections::BTreeSet::new();
    for record in records {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let encoded =
            encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        counters.wire_bytes = counters
            .wire_bytes
            .saturating_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX));
        counters.durable_log_bytes = counters.durable_log_bytes.saturating_add(
            // Conservative per-record estimate. FilePrimeFieldMpcWireMessageLog
            // may compact same-layer batches into grouped durable lines.
            2 + 1
                + 5
                + 1
                + u64::try_from(encoded.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2)
                + 1,
        );
        match record.direction {
            PrimeFieldMpcWireDirection::SentPrivate
            | PrimeFieldMpcWireDirection::AcceptedPrivate => {
                counters.private_messages = counters.private_messages.saturating_add(1);
            }
            PrimeFieldMpcWireDirection::SentBroadcast
            | PrimeFieldMpcWireDirection::AcceptedBroadcast => {
                counters.broadcasts = counters.broadcasts.saturating_add(1);
            }
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?;
        round_labels.insert((payload.round_kind, payload.phase, payload.label_hash));
        let lanes = payload.values.len() as u64;
        if payload.values.is_empty() {
            match kind {
                PrimeFieldMpcRoundKind::MulDegreeReduce => counters.scalar_mul_gates += 1,
                PrimeFieldMpcRoundKind::Open => counters.scalar_openings += 1,
                PrimeFieldMpcRoundKind::AssertZero => counters.scalar_assert_zero += 1,
                PrimeFieldMpcRoundKind::RandomBit => counters.random_bits += 1,
            }
        } else {
            counters.vector_lanes = counters.vector_lanes.saturating_add(lanes);
            match kind {
                PrimeFieldMpcRoundKind::MulDegreeReduce => {
                    counters.vector_mul_lanes += lanes;
                    multiplication_layers.insert((payload.phase, payload.label_hash));
                }
                PrimeFieldMpcRoundKind::Open => counters.vector_opening_lanes += lanes,
                PrimeFieldMpcRoundKind::AssertZero => counters.vector_assert_zero_lanes += lanes,
                PrimeFieldMpcRoundKind::RandomBit => counters.random_bits += lanes,
            }
        }
    }
    counters.rounds = round_labels.len() as u64;
    counters.multiplication_layers = multiplication_layers.len() as u64;
    Ok(counters)
}

fn update_runtime_coverage_from_phase(
    coverage: &mut ProductionVectorItMpcRuntimeCoverage,
    kind: PrimeFieldMpcRoundKind,
    phase: PrimeFieldMpcPhase,
    lanes: usize,
) {
    if lanes == 0 {
        return;
    }
    match kind {
        PrimeFieldMpcRoundKind::MulDegreeReduce => coverage.mul_vec = true,
        PrimeFieldMpcRoundKind::Open => coverage.open_many_checked = true,
        PrimeFieldMpcRoundKind::AssertZero => coverage.assert_zero_vec = true,
        PrimeFieldMpcRoundKind::RandomBit => coverage.random_bit_vec = true,
    }
    match phase {
        PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck
        | PrimeFieldMpcPhase::AssertBitCheck => coverage.assert_bit_vec = true,
        PrimeFieldMpcPhase::ComparatorShare
        | PrimeFieldMpcPhase::Power2RoundWrapCompare
        | PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck
        | PrimeFieldMpcPhase::ComparisonToPublicCheck => {
            coverage.comparison_to_public = true;
        }
        PrimeFieldMpcPhase::Power2RoundEqualityCheck
        | PrimeFieldMpcPhase::EqualityToPublicCheck => {
            coverage.equality_to_public = true;
        }
        PrimeFieldMpcPhase::Power2RoundAdd4095 => {
            coverage.bit_sum_or_threshold_check = true;
        }
        PrimeFieldMpcPhase::BitSumThresholdCheck => {
            coverage.comparison_to_public = true;
            coverage.bit_sum_or_threshold_check = true;
        }
        PrimeFieldMpcPhase::PrivateSelectionCheck => coverage.private_one_hot_selection = true,
        PrimeFieldMpcPhase::PreprocessingMaskedBroadcast => {
            coverage.preprocessing_masked_broadcast = true;
        }
        PrimeFieldMpcPhase::PreprocessingCarryCompare => {
            coverage.comparison_to_public = true;
            coverage.preprocessing_carry_compare = true;
        }
        PrimeFieldMpcPhase::PreprocessingCefBcc => {
            coverage.comparison_to_public = true;
            coverage.bit_sum_or_threshold_check = true;
            coverage.preprocessing_cef_bcc = true;
        }
        _ => {}
    }
}

/// Derives vector IT-MPC operation coverage from durable wire records.
pub fn production_vector_it_mpc_runtime_coverage_from_wire_records(
    records: &[PrimeFieldMpcWireMessageRecord],
) -> Result<ProductionVectorItMpcRuntimeCoverage, DkgError> {
    let mut coverage = ProductionVectorItMpcRuntimeCoverage::default();
    for record in records {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        let phase =
            prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?;
        update_runtime_coverage_from_phase(&mut coverage, kind, phase, payload.values.len());
    }
    Ok(coverage)
}

/// Derives release evidence from a durable prime-field MPC wire log.
pub fn production_vector_it_mpc_runtime_evidence_from_wire_log<L>(
    log: &L,
) -> Result<ProductionVectorItMpcRuntimeEvidence, DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    let records = log.wire_records();
    let counters = prime_field_mpc_counters_from_wire_records(records)?;
    let coverage = production_vector_it_mpc_runtime_coverage_from_wire_records(records)?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/production-vector-it-mpc-runtime-evidence");
    for record in records {
        hasher.update([record.direction.as_u8()]);
        hasher.update(record.peer.map_or(0, |party| party.0).to_le_bytes());
        let encoded =
            encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(encoded);
    }
    Ok(ProductionVectorItMpcRuntimeEvidence {
        counters,
        coverage,
        transcript_hash: hasher.finalize().into(),
    })
}

/// Release gate for public openings in a Power2Round runtime log.
///
/// A production Power2Round transcript may publicly open only:
///
/// - masked values `C = t + A_mask`, protected by the certified one-time mask;
/// - public `t1` high bits after canonicality/range/equality checks complete.
///
/// Generic openings, low-bit openings, masks, witnesses, `t`, `t0`, or failed
/// diffs must not appear as `Open` rounds in a release-capable Power2Round log.
pub fn ensure_power2round_wire_log_openings_allowed_for_release<L>(log: &L) -> Result<(), DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    for record in log.wire_records() {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        if kind != PrimeFieldMpcRoundKind::Open {
            continue;
        }
        let phase =
            prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?;
        match phase {
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC | PrimeFieldMpcPhase::T1BitOpening => {}
            _ => return Err(DkgError::Power2RoundForbiddenOpeningInRelease),
        }
    }
    Ok(())
}

/// Ensures a durable prime-field MPC wire log contains one collected
/// broadcast vector phase with the exact expected public marker values from
/// every expected sender.
///
/// This is used by production adapters that first bind a public statement into
/// a vector runtime marker phase before producing release evidence. A phase
/// cursor alone only proves a round reached the collected state; this check
/// also proves the durable wire transcript carried the expected statement
/// marker lanes.
pub fn ensure_prime_field_mpc_wire_log_contains_broadcast_vec<L>(
    log: &L,
    kind: PrimeFieldMpcRoundKind,
    phase: PrimeFieldMpcPhase,
    label: &Power2RoundTranscriptLabel,
    expected_senders: &[PartyId],
    expected_values: &[Coeff],
) -> Result<(), DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    if expected_senders.is_empty() || expected_values.is_empty() {
        return Err(DkgError::PrimeFieldMpcTransport);
    }
    let label_hash = power2round_label_hash(label);
    let mut seen = Vec::with_capacity(expected_senders.len());
    for record in log.wire_records() {
        if !matches!(
            record.direction,
            PrimeFieldMpcWireDirection::SentBroadcast
                | PrimeFieldMpcWireDirection::AcceptedBroadcast
        ) || record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc
        {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        if prime_field_round_kind_from_u8(payload.round_kind) != Some(kind)
            || prime_field_phase_from_u8(payload.phase) != Some(phase)
            || payload.receiver_party_id != 0
            || payload.label_hash != label_hash
            || payload.values != expected_values
        {
            continue;
        }
        let sender = PartyId(record.message.header.sender_party_id);
        if expected_senders.contains(&sender) && !seen.contains(&sender) {
            seen.push(sender);
        }
    }
    if expected_senders.iter().all(|sender| seen.contains(sender)) {
        Ok(())
    } else {
        Err(DkgError::PrimeFieldMpcTransport)
    }
}

/// Ensures a preprocessing release transcript contains private vector circuit
/// layers for CarryCompare and CEF/BCC, not only public marker broadcasts.
///
/// Marker phases bind a statement into the durable runtime log. This gate
/// additionally requires vector multiplication/degree-reduction layers in the
/// preprocessing CarryCompare and CEF/BCC phases, which are the phases used by
/// the private comparison and threshold circuits.
pub fn ensure_preprocessing_wire_log_private_circuits_for_release<L>(
    log: &L,
    expected_carry_compare_mul_labels: &[Power2RoundTranscriptLabel],
    expected_cef_bcc_mul_labels: &[Power2RoundTranscriptLabel],
) -> Result<(), DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    if expected_carry_compare_mul_labels.is_empty() || expected_cef_bcc_mul_labels.is_empty() {
        return Err(DkgError::BlockedPendingReview);
    }
    let carry_label_hashes = expected_carry_compare_mul_labels
        .iter()
        .map(power2round_label_hash)
        .collect::<Vec<_>>();
    let cef_bcc_label_hashes = expected_cef_bcc_mul_labels
        .iter()
        .map(power2round_label_hash)
        .collect::<Vec<_>>();
    let mut carry_compare = false;
    let mut cef_bcc = false;
    for record in log.wire_records() {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        let phase =
            prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?;
        if kind != PrimeFieldMpcRoundKind::MulDegreeReduce || payload.values.is_empty() {
            continue;
        }
        match phase {
            PrimeFieldMpcPhase::PreprocessingCarryCompare
                if carry_label_hashes.contains(&payload.label_hash) =>
            {
                carry_compare = true;
            }
            PrimeFieldMpcPhase::PreprocessingCefBcc
                if cef_bcc_label_hashes.contains(&payload.label_hash) =>
            {
                cef_bcc = true;
            }
            _ => {}
        }
    }
    if carry_compare && cef_bcc {
        Ok(())
    } else {
        Err(DkgError::BlockedPendingReview)
    }
}

/// Release gate proving that nonlinear Power2Round values were generated by
/// the vector runtime, not supplied as already-computed phase vectors.
///
/// This intentionally looks for private vector multiplication layers in the
/// nonlinear phases. Caller-supplied wrap/subtractor/add vectors can produce
/// phase-ordering broadcasts, but they do not produce these runtime-owned
/// private circuit layers.
pub fn ensure_power2round_state_owned_nonlinear_wire_log_for_release<L>(
    log: &L,
) -> Result<(), DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    let mut comparison = false;
    let mut subtractor = false;
    let mut bitness = false;
    let mut add_4095 = false;
    for record in log.wire_records() {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        let phase =
            prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?;
        if kind != PrimeFieldMpcRoundKind::MulDegreeReduce || payload.values.is_empty() {
            continue;
        }
        match phase {
            PrimeFieldMpcPhase::ComparisonToPublicCheck => comparison = true,
            PrimeFieldMpcPhase::SubtractorShare => subtractor = true,
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck => bitness = true,
            PrimeFieldMpcPhase::Power2RoundAdd4095 => add_4095 = true,
            _ => {}
        }
    }
    if comparison && subtractor && bitness && add_4095 {
        Ok(())
    } else {
        Err(DkgError::BlockedPendingReview)
    }
}

/// Release gate for durable prime-field MPC wire logs.
pub fn ensure_prime_field_mpc_wire_log_vectorized_for_release<L>(log: &L) -> Result<(), DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    let evidence = production_vector_it_mpc_runtime_evidence_from_wire_log(log)?;
    let counters = evidence.counters;
    ensure_prime_field_mpc_counters_vectorized_for_release(counters)?;
    if !counters.has_durable_runtime_evidence() {
        return Err(DkgError::PrimeFieldMpcScalarizedReleaseBlocked);
    }
    Ok(())
}

/// Release gate for runtime evidence covering the complete Phase 3 vector
/// operation set. This is stricter than the generic vector-log scalarization
/// check: it proves the durable transcript includes the operation families used
/// by Power2Round, preprocessing checks, and strict private selection.
pub fn ensure_production_vector_it_mpc_runtime_evidence_for_release(
    evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> Result<(), DkgError> {
    ensure_prime_field_mpc_counters_vectorized_for_release(evidence.counters)?;
    if !evidence.counters.has_durable_runtime_evidence()
        || !evidence.coverage.covers_all_phase3_consumers()
    {
        return Err(DkgError::BlockedPendingReview);
    }
    Ok(())
}

/// Release gate for Power2Round-specific durable vector IT-MPC evidence.
///
/// Power2Round does not exercise strict-signing private selection by itself,
/// so this gate requires the vector operation families used by the private
/// Power2Round circuit while the broader Phase 3 runtime-readiness gate still
/// requires coverage for all consumers.
pub fn ensure_production_power2round_runtime_evidence_for_release(
    evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> Result<(), DkgError> {
    ensure_prime_field_mpc_counters_vectorized_for_release(evidence.counters)?;
    if !evidence.counters.has_durable_runtime_evidence() || !evidence.coverage.covers_power2round()
    {
        return Err(DkgError::BlockedPendingReview);
    }
    Ok(())
}

/// Release gate for strict-signing-specific durable vector IT-MPC evidence.
pub fn ensure_production_strict_signing_runtime_evidence_for_release(
    evidence: &ProductionVectorItMpcRuntimeEvidence,
) -> Result<(), DkgError> {
    ensure_prime_field_mpc_counters_vectorized_for_release(evidence.counters)?;
    if !evidence.counters.has_durable_runtime_evidence()
        || !evidence.coverage.covers_strict_signing()
    {
        return Err(DkgError::BlockedPendingReview);
    }
    Ok(())
}

/// Derives the Phase 3 readiness bitset from durable runtime evidence plus the
/// embedding application's transport/failure-policy attestations.
pub fn production_it_mpc_readiness_from_runtime_evidence(
    evidence: &ProductionVectorItMpcRuntimeEvidence,
    pq_authenticated_transport: bool,
    public_const_mul_local: bool,
    blame_abort_policy: bool,
) -> ProductionItMpcReadiness {
    let runtime_ok = evidence.counters.has_durable_runtime_evidence()
        && !evidence.counters.used_scalar_execution()
        && evidence.coverage.covers_all_phase3_consumers();
    ProductionItMpcReadiness {
        per_party_power2round: evidence.coverage.covers_power2round(),
        vector_runtime_operations: runtime_ok,
        pq_authenticated_transport,
        durable_round_log: evidence.counters.rounds != 0,
        durable_wire_log: evidence.counters.durable_log_bytes != 0,
        release_counters: evidence.counters.used_vector_execution(),
        no_scalarized_execution: !evidence.counters.used_scalar_execution(),
        public_const_mul_local,
        blame_abort_policy,
        external_review: false,
    }
}

/// Converts prime-field MPC counters into the shared TALUS performance model.
pub fn talus_performance_counters_from_prime_field_mpc(
    counters: PrimeFieldMpcCounters,
) -> TalusPerformanceCounters {
    TalusPerformanceCounters {
        rounds: counters.rounds,
        private_messages: counters.private_messages,
        broadcasts: counters.broadcasts,
        wire_bytes: counters.wire_bytes,
        durable_log_bytes: counters.durable_log_bytes,
        vector_lanes: counters.vector_lanes,
        multiplication_layers: counters.multiplication_layers,
        opened_lanes: counters.vector_opening_lanes,
        checked_lanes: counters
            .vector_assert_zero_lanes
            .saturating_add(counters.random_bits),
        wall_clock_micros: counters.wall_clock_ms.saturating_mul(1_000),
        scalar_operations: counters
            .scalar_mul_gates
            .saturating_add(counters.scalar_openings)
            .saturating_add(counters.scalar_assert_zero),
        ..TalusPerformanceCounters::default()
    }
}

/// In-process Shamir sharing over Fq used by the distributed prime-field MPC
/// simulator.
#[derive(Clone, Eq, PartialEq)]
pub struct ShamirPrimeFieldShare {
    shares: Vec<ShamirScalarShare>,
}

impl fmt::Debug for ShamirPrimeFieldShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShamirPrimeFieldShare")
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ShamirPrimeFieldShare {
    fn zeroize(&mut self) {
        for share in &mut self.shares {
            share.value.zeroize();
        }
    }
}

/// Secret bit represented as Shamir shares of 0/1 in Fq.
#[derive(Clone, Eq, PartialEq)]
pub struct ShamirPrimeFieldBitShare {
    share: ShamirPrimeFieldShare,
}

impl fmt::Debug for ShamirPrimeFieldBitShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShamirPrimeFieldBitShare")
            .field("share", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ShamirPrimeFieldBitShare {
    fn zeroize(&mut self) {
        self.share.zeroize();
    }
}

/// Prime-field arithmetic backend boundary for DKG `Power2Round`.
///
/// The production backend must implement these operations with Shamir /
/// honest-majority IT-MPC over Fq. The local implementation below is only a
/// deterministic in-process simulator for protocol-shape tests.
pub trait ItMpcPrimeFieldBackend<P: MlDsaParams> {
    /// Secret field share.
    type Share: Clone + Zeroize;
    /// Secret bit share, represented as 0/1 in Fq.
    type BitShare: Clone + Zeroize;

    /// Secret share from a private coefficient already in this backend.
    fn secret_share(&self, value: Coeff) -> Self::Share;
    /// Public field constant.
    fn public_const(&self, value: Coeff) -> Self::Share;
    /// Public bit constant.
    fn public_bit(&self, value: bool) -> Self::BitShare;
    /// Converts a bit share into its field share representation.
    fn bit_to_share(&self, bit: &Self::BitShare) -> Self::Share;
    /// Treats a checked field share as a bit share.
    fn bit_from_share_unchecked(&self, share: Self::Share) -> Self::BitShare;

    /// Field addition.
    fn add(&self, x: Self::Share, y: Self::Share) -> Self::Share;
    /// Field subtraction.
    fn sub(&self, x: Self::Share, y: Self::Share) -> Self::Share;
    /// Field multiplication through the MPC multiplication/checking path.
    fn mul(
        &mut self,
        x: Self::Share,
        y: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::Share, DkgError>;

    /// Asserts a private value is zero without returning the failed raw value.
    fn assert_zero(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>;
    /// Opens a checked field value.
    fn open_checked(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Coeff, DkgError>;
    /// Opens checked field values.
    fn open_many_checked(
        &mut self,
        xs: &[Self::Share],
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError>;
    /// Returns a secret random bit.
    fn random_bit(&mut self, label: Power2RoundTranscriptLabel)
        -> Result<Self::BitShare, DkgError>;

    /// Returns backend counters when available.
    fn counters(&self) -> Option<PrimeFieldMpcCounters> {
        None
    }

    /// Builds a vector share from scalar lanes.
    fn share_vec_from_lanes(&self, lanes: Vec<Self::Share>) -> ShareVec<Self::Share> {
        ShareVec::from_lanes(lanes)
    }

    /// Builds a vector bit share from scalar lanes.
    fn bit_vec_from_lanes(&self, lanes: Vec<Self::BitShare>) -> BitShareVec<Self::BitShare> {
        BitShareVec::from_lanes(lanes)
    }

    /// Public constant vector.
    fn public_const_vec(&self, value: Coeff, len: usize) -> ShareVec<Self::Share> {
        ShareVec::from_lanes((0..len).map(|_| self.public_const(value)).collect())
    }

    /// Field-vector addition.
    fn add_vec(
        &self,
        x: ShareVec<Self::Share>,
        y: ShareVec<Self::Share>,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != y.len() {
            return Err(DkgError::Backend("prime-field vector length mismatch"));
        }
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .zip(y.into_lanes())
                .map(|(left, right)| self.add(left, right))
                .collect(),
        ))
    }

    /// Field-vector subtraction.
    fn sub_vec(
        &self,
        x: ShareVec<Self::Share>,
        y: ShareVec<Self::Share>,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != y.len() {
            return Err(DkgError::Backend("prime-field vector length mismatch"));
        }
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .zip(y.into_lanes())
                .map(|(left, right)| self.sub(left, right))
                .collect(),
        ))
    }

    /// Local multiplication by a public scalar.
    ///
    /// This must not use the MPC multiplication path.
    fn mul_public_const(
        &self,
        x: Self::Share,
        constant: Coeff,
        label: Power2RoundTranscriptLabel,
    ) -> Self::Share;

    /// Local vector multiplication by a public scalar.
    ///
    /// This must not use the MPC multiplication path.
    fn mul_public_const_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        constant: Coeff,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .enumerate()
                .map(|(index, lane)| {
                    self.mul_public_const(lane, constant, label.child(format!("lane_{index}")))
                })
                .collect(),
        ))
    }

    /// Local lane-wise multiplication by public scalars.
    ///
    /// This must not use the MPC multiplication path.
    fn mul_public_const_lanes(
        &mut self,
        x: ShareVec<Self::Share>,
        constants: &[Coeff],
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != constants.len() {
            return Err(DkgError::Backend(
                "prime-field public-constant lane mismatch",
            ));
        }
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .zip(constants.iter().copied())
                .enumerate()
                .map(|(index, (lane, constant))| {
                    self.mul_public_const(lane, constant, label.child(format!("lane_{index}")))
                })
                .collect(),
        ))
    }

    /// Vector multiplication. Production backends must batch this by circuit
    /// layer; this default scalarizes for tests and compatibility only.
    fn mul_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        y: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != y.len() {
            return Err(DkgError::Backend("prime-field vector length mismatch"));
        }
        x.into_lanes()
            .into_iter()
            .zip(y.into_lanes())
            .enumerate()
            .map(|(index, (left, right))| {
                self.mul(left, right, label.child(format!("lane_{index}")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(ShareVec::from_lanes)
    }

    /// Batched assert-zero. Production backends must open/check this as a
    /// vector phase; this default scalarizes for tests and compatibility only.
    fn assert_zero_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        for (index, lane) in x.into_lanes().into_iter().enumerate() {
            self.assert_zero(lane, label.child(format!("lane_{index}")))?;
        }
        Ok(())
    }

    /// Batched bitness check for field-backed secret bits.
    ///
    /// Production backends should evaluate this as one vector multiplication
    /// layer followed by one vector checked zero assertion.
    fn assert_bit_vec(
        &mut self,
        bits: BitShareVec<Self::BitShare>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        let values = self.share_vec_from_lanes(
            bits.lanes()
                .iter()
                .map(|bit| self.bit_to_share(bit))
                .collect(),
        );
        let values_minus_one = self.share_vec_from_lanes(
            bits.lanes()
                .iter()
                .map(|bit| self.sub(self.bit_to_share(bit), self.public_const(1)))
                .collect(),
        );
        let products = self.mul_vec(values, values_minus_one, label.child("b_times_b_minus_1"))?;
        self.assert_zero_vec(products, label.child("assert_zero"))
    }

    /// Batched checked opening. Production backends must implement this as a
    /// vector phase; the default delegates to scalar `open_many_checked`.
    fn open_vec_checked(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.open_many_checked(&x.into_lanes(), label)
    }

    /// Batched random bit generation. Production backends must implement this
    /// as a vector phase; this default scalarizes for tests and compatibility.
    fn random_bit_vec(
        &mut self,
        len: usize,
        label: Power2RoundTranscriptLabel,
    ) -> Result<BitShareVec<Self::BitShare>, DkgError> {
        (0..len)
            .map(|index| self.random_bit(label.child(format!("lane_{index}"))))
            .collect::<Result<Vec<_>, _>>()
            .map(BitShareVec::from_lanes)
    }
}

/// Development and test backend implementations.
///
/// Production code should not depend on this module. It exists so local parity
/// tests, transport conformance tests, and scaffold/dev builds can exercise the
/// protocol machinery without exposing simulator names as the primary
/// production API.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub mod dev_backends;

#[cfg(test)]
fn mul_shamir_share_public_const<P: MlDsaParams>(
    x: ShamirPrimeFieldShare,
    constant: Coeff,
) -> ShamirPrimeFieldShare {
    ShamirPrimeFieldShare {
        shares: x
            .shares
            .into_iter()
            .map(|share| ShamirScalarShare {
                point: share.point,
                value: (i64::from(share.value) * i64::from(constant)).rem_euclid(i64::from(P::Q))
                    as Coeff,
            })
            .collect(),
    }
}

/// Networked Shamir simulator message kind for prime-field MPC rounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeFieldMpcRoundKind {
    /// Directed degree-reduction resharing for multiplication.
    MulDegreeReduce,
    /// Broadcast shares for a checked opening.
    Open,
    /// Broadcast shares for an assert-zero check.
    AssertZero,
    /// Directed random-bit resharing.
    RandomBit,
}

/// Typed phase inside a prime-field MPC round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeFieldMpcPhase {
    /// A party contributes a random-bit share.
    RandomBitShare,
    /// A party sends a multiplication degree-reduction share.
    MulDegreeReductionShare,
    /// A party broadcasts a checked-opening share.
    OpenShare,
    /// A party broadcasts an assert-zero opening share.
    AssertZeroShare,
    /// Comparator subprotocol bit/share message.
    ComparatorShare,
    /// Subtractor/borrow subprotocol bit/share message.
    SubtractorShare,
    /// Public opening of one `t1` high bit.
    T1BitOpening,
    /// Random canonical mask bit generation.
    Power2RoundMaskBit,
    /// Private/public mask range check.
    Power2RoundMaskRangeCheck,
    /// Masked opening `C = r + A mod q`.
    Power2RoundMaskedOpenC,
    /// Wrap comparison `[A > C]`.
    Power2RoundWrapCompare,
    /// Canonical `R` bitness checks `R_j(R_j - 1) = 0`.
    Power2RoundCanonicalBitnessCheck,
    /// Canonical `R < q` range check.
    Power2RoundCanonicalRangeCheck,
    /// Equality check `sum 2^j R_j == r mod q`.
    Power2RoundEqualityCheck,
    /// Add-4095 carry/share phase.
    Power2RoundAdd4095,
    /// Generic vector bit-sum or public-threshold check phase.
    BitSumThresholdCheck,
    /// Generic private one-hot selection check phase.
    PrivateSelectionCheck,
    /// Generic vector bitness check phase.
    AssertBitCheck,
    /// Generic vector comparison-to-public check phase.
    ComparisonToPublicCheck,
    /// Generic vector equality-to-public check phase.
    EqualityToPublicCheck,
    /// Preprocessing masked-broadcast consistency opening/check phase.
    PreprocessingMaskedBroadcast,
    /// Preprocessing CarryCompare certification phase.
    PreprocessingCarryCompare,
    /// Preprocessing CEF/BCC certification phase.
    PreprocessingCefBcc,
}

/// Accepted transport-backed prime-field MPC round metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPrimeFieldMpcRound {
    /// Round kind.
    pub kind: PrimeFieldMpcRoundKind,
    /// Typed phase inside the round.
    pub phase: PrimeFieldMpcPhase,
    /// Transcript label hash.
    pub label_hash: [u8; 32],
    /// Accepted sender parties.
    pub senders: Vec<PartyId>,
}

/// Completion marker for one `Power2Round` coefficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Power2RoundCoefficientCompletion {
    /// Polynomial index in `t`.
    pub poly_idx: usize,
    /// Coefficient index in the polynomial.
    pub coeff_idx: usize,
    /// Opened public `t1` coefficient.
    pub t1: u16,
    /// Transcript label hash for the coefficient.
    pub label_hash: [u8; 32],
}

/// Public durable log contract for accepted prime-field MPC rounds.
///
/// Implementations must persist only public round metadata. They must not log
/// mask bits, lower Power2Round bits, `t`, `t0`, `s2`, or failed-check raw
/// values.
pub trait PrimeFieldMpcRoundLog {
    /// Persists one accepted round if it has not already been recorded.
    fn persist_round(&mut self, round: &AcceptedPrimeFieldMpcRound) -> Result<(), DkgError>;
    /// Persists one completed coefficient if it has not already been recorded.
    fn persist_coefficient(
        &mut self,
        completion: &Power2RoundCoefficientCompletion,
    ) -> Result<(), DkgError>;
}

/// Durable wire-message direction for local prime-field MPC recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeFieldMpcWireDirection {
    /// Message sent on a private channel by this local party.
    SentPrivate,
    /// Message broadcast by this local party.
    SentBroadcast,
    /// Private-channel message accepted by this local party.
    AcceptedPrivate,
    /// Broadcast message accepted by this local party after equivocation checks.
    AcceptedBroadcast,
}

impl PrimeFieldMpcWireDirection {
    fn as_u8(self) -> u8 {
        match self {
            Self::SentPrivate => 1,
            Self::SentBroadcast => 2,
            Self::AcceptedPrivate => 3,
            Self::AcceptedBroadcast => 4,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SentPrivate),
            2 => Some(Self::SentBroadcast),
            3 => Some(Self::AcceptedPrivate),
            4 => Some(Self::AcceptedBroadcast),
            _ => None,
        }
    }
}

/// One durable prime-field MPC wire message.
///
/// Unlike `AcceptedPrimeFieldMpcRound`, this record can contain private share
/// payloads. Production storage must treat it as local secret state and protect
/// it with the same crash/rollback controls as key-generation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimeFieldMpcWireMessageRecord {
    /// Direction relative to the local party.
    pub direction: PrimeFieldMpcWireDirection,
    /// Peer for private messages. Broadcast records use `None`.
    pub peer: Option<PartyId>,
    /// Canonical wire message.
    pub message: WireMessage,
}

/// Durable local wire-message log for resumable prime-field MPC.
pub trait PrimeFieldMpcWireMessageLog {
    /// Persists one wire message. Re-persisting the same canonical message is
    /// idempotent; persisting a different message with the same replay key is
    /// rejected.
    fn persist_wire_message(
        &mut self,
        record: &PrimeFieldMpcWireMessageRecord,
    ) -> Result<(), DkgError>;

    /// Persists a same-layer batch of wire messages atomically when the
    /// backend supports grouped durable records. The default implementation
    /// preserves existing per-record behavior.
    fn persist_wire_messages(
        &mut self,
        records: &[PrimeFieldMpcWireMessageRecord],
    ) -> Result<(), DkgError> {
        for record in records {
            self.persist_wire_message(record)?;
        }
        Ok(())
    }

    /// Returns durable records known to this local party.
    fn wire_records(&self) -> &[PrimeFieldMpcWireMessageRecord];
}

/// In-memory durable wire-message log for tests and adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryPrimeFieldMpcWireMessageLog {
    records: Vec<PrimeFieldMpcWireMessageRecord>,
}

impl InMemoryPrimeFieldMpcWireMessageLog {
    /// Returns durable wire-message records.
    pub fn records(&self) -> &[PrimeFieldMpcWireMessageRecord] {
        &self.records
    }
}

impl PrimeFieldMpcWireMessageLog for InMemoryPrimeFieldMpcWireMessageLog {
    fn persist_wire_message(
        &mut self,
        record: &PrimeFieldMpcWireMessageRecord,
    ) -> Result<(), DkgError> {
        persist_wire_message_record(&mut self.records, record)
    }

    fn wire_records(&self) -> &[PrimeFieldMpcWireMessageRecord] {
        &self.records
    }
}

fn filter_new_wire_message_records(
    existing: &[PrimeFieldMpcWireMessageRecord],
    records: &[PrimeFieldMpcWireMessageRecord],
) -> Result<Vec<PrimeFieldMpcWireMessageRecord>, DkgError> {
    let mut scratch = existing.to_vec();
    let mut new_records = Vec::new();
    for record in records {
        let before = scratch.len();
        persist_wire_message_record(&mut scratch, record)?;
        if scratch.len() != before {
            new_records.push(record.clone());
        }
    }
    Ok(new_records)
}

/// In-memory accepted MPC round log for tests and adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryPrimeFieldMpcRoundLog {
    accepted: Vec<AcceptedPrimeFieldMpcRound>,
    completed_coefficients: Vec<Power2RoundCoefficientCompletion>,
}

impl InMemoryPrimeFieldMpcRoundLog {
    /// Returns accepted rounds.
    pub fn accepted(&self) -> &[AcceptedPrimeFieldMpcRound] {
        &self.accepted
    }

    /// Returns completed coefficient markers.
    pub fn completed_coefficients(&self) -> &[Power2RoundCoefficientCompletion] {
        &self.completed_coefficients
    }
}

impl PrimeFieldMpcRoundLog for InMemoryPrimeFieldMpcRoundLog {
    fn persist_round(&mut self, round: &AcceptedPrimeFieldMpcRound) -> Result<(), DkgError> {
        if self.accepted.iter().any(|known| {
            known.kind == round.kind
                && known.phase == round.phase
                && known.label_hash == round.label_hash
        }) {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
        self.accepted.push(round.clone());
        Ok(())
    }

    fn persist_coefficient(
        &mut self,
        completion: &Power2RoundCoefficientCompletion,
    ) -> Result<(), DkgError> {
        if self.completed_coefficients.iter().any(|known| {
            known.poly_idx == completion.poly_idx && known.coeff_idx == completion.coeff_idx
        }) {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
        self.completed_coefficients.push(completion.clone());
        Ok(())
    }
}

pub(crate) fn persist_wire_message_record(
    records: &mut Vec<PrimeFieldMpcWireMessageRecord>,
    record: &PrimeFieldMpcWireMessageRecord,
) -> Result<(), DkgError> {
    let key = wire_message_replay_key(record)?;
    let encoded = encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
    if let Some(existing) = records
        .iter()
        .find(|known| wire_message_replay_key(known).as_ref() == Ok(&key))
    {
        let existing_encoded =
            encode_message(&existing.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        if existing_encoded == encoded {
            return Ok(());
        }
        return Err(DkgError::PrimeFieldMpcReplayDetected);
    }
    records.push(record.clone());
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrimeFieldMpcWireReplayKey {
    direction: PrimeFieldMpcWireDirection,
    peer: Option<PartyId>,
    sender: PartyId,
    round_kind: PrimeFieldMpcRoundKind,
    phase: PrimeFieldMpcPhase,
    receiver: Option<PartyId>,
    label_hash: [u8; 32],
}

pub(crate) fn wire_message_replay_key(
    record: &PrimeFieldMpcWireMessageRecord,
) -> Result<PrimeFieldMpcWireReplayKey, DkgError> {
    let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
    Ok(PrimeFieldMpcWireReplayKey {
        direction: record.direction,
        peer: record.peer,
        sender: PartyId(record.message.header.sender_party_id),
        round_kind: prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?,
        phase: prime_field_phase_from_u8(payload.phase).ok_or(DkgError::PrimeFieldMpcTransport)?,
        receiver: if payload.receiver_party_id == 0 {
            None
        } else {
            Some(PartyId(payload.receiver_party_id))
        },
        label_hash: payload.label_hash,
    })
}

pub(crate) fn find_sent_wire_message(
    records: &[PrimeFieldMpcWireMessageRecord],
    wanted: PrimeFieldMpcWireReplayKey,
) -> Result<Option<WireMessage>, DkgError> {
    for record in records {
        let key = wire_message_replay_key(record)?;
        if key == wanted {
            return Ok(Some(record.message.clone()));
        }
    }
    Ok(None)
}

/// File-backed public MPC round log for crash/reopen tests and adapters.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePrimeFieldMpcRoundLog {
    path: std::path::PathBuf,
    inner: InMemoryPrimeFieldMpcRoundLog,
}

#[cfg(feature = "std")]
impl FilePrimeFieldMpcRoundLog {
    /// Opens or creates a public MPC round log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut inner = InMemoryPrimeFieldMpcRoundLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let round = parse_prime_field_mpc_round_log_line(line).ok_or(
                        DkgError::PrimeFieldMpcRoundLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    match round {
                        PrimeFieldMpcLogEntry::Round(round) => inner.persist_round(&round)?,
                        PrimeFieldMpcLogEntry::Coefficient(completion) => {
                            inner.persist_coefficient(&completion)?
                        }
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns accepted public rounds.
    pub fn accepted(&self) -> &[AcceptedPrimeFieldMpcRound] {
        self.inner.accepted()
    }

    /// Returns completed coefficient markers.
    pub fn completed_coefficients(&self) -> &[Power2RoundCoefficientCompletion] {
        self.inner.completed_coefficients()
    }
}

#[cfg(feature = "std")]
impl PrimeFieldMpcRoundLog for FilePrimeFieldMpcRoundLog {
    fn persist_round(&mut self, round: &AcceptedPrimeFieldMpcRound) -> Result<(), DkgError> {
        self.inner.persist_round(round)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        write!(
            file,
            "{} {} {}",
            prime_field_round_kind_to_u8(round.kind),
            prime_field_phase_to_u8(round.phase),
            Hex32(round.label_hash)
        )
        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        for sender in &round.senders {
            write!(file, " {}", sender.0)
                .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        }
        writeln!(file).map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }

    fn persist_coefficient(
        &mut self,
        completion: &Power2RoundCoefficientCompletion,
    ) -> Result<(), DkgError> {
        self.inner.persist_coefficient(completion)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "C {} {} {} {}",
            completion.poly_idx,
            completion.coeff_idx,
            completion.t1,
            Hex32(completion.label_hash)
        )
        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }
}

/// File-backed local wire-message log for resumable prime-field MPC.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePrimeFieldMpcWireMessageLog {
    path: std::path::PathBuf,
    inner: InMemoryPrimeFieldMpcWireMessageLog,
}

#[cfg(feature = "std")]
impl FilePrimeFieldMpcWireMessageLog {
    /// Opens or creates a local durable wire-message log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut inner = InMemoryPrimeFieldMpcWireMessageLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let records = parse_prime_field_mpc_wire_log_records(line).ok_or(
                        DkgError::PrimeFieldMpcWireLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.persist_wire_messages(&records)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns durable wire-message records.
    pub fn records(&self) -> &[PrimeFieldMpcWireMessageRecord] {
        self.inner.records()
    }
}

#[cfg(feature = "std")]
impl PrimeFieldMpcWireMessageLog for FilePrimeFieldMpcWireMessageLog {
    fn persist_wire_message(
        &mut self,
        record: &PrimeFieldMpcWireMessageRecord,
    ) -> Result<(), DkgError> {
        let before = self.inner.records().len();
        self.inner.persist_wire_message(record)?;
        if self.inner.records().len() == before {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        write_prime_field_mpc_wire_log_record(&mut file, record)?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }

    fn persist_wire_messages(
        &mut self,
        records: &[PrimeFieldMpcWireMessageRecord],
    ) -> Result<(), DkgError> {
        let new_records = filter_new_wire_message_records(self.inner.records(), records)?;
        if new_records.is_empty() {
            return Ok(());
        }
        for record in &new_records {
            self.inner.persist_wire_message(record)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        if new_records.len() == 1 {
            write_prime_field_mpc_wire_log_record(&mut file, &new_records[0])?;
        } else {
            let same_direction = new_records
                .iter()
                .all(|record| record.direction == new_records[0].direction);
            let same_peer = new_records
                .iter()
                .all(|record| record.peer == new_records[0].peer);
            if same_direction && same_peer {
                write!(
                    file,
                    "S {} {} {}",
                    new_records.len(),
                    new_records[0].direction.as_u8(),
                    new_records[0].peer.map_or(0, |party| party.0)
                )
                .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
                for record in &new_records {
                    let encoded = encode_message(&record.message)
                        .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                    write!(file, " {}", HexBytes(&encoded))
                        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
                }
            } else if same_direction {
                write!(
                    file,
                    "D {} {}",
                    new_records.len(),
                    new_records[0].direction.as_u8()
                )
                .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
                for record in &new_records {
                    let encoded = encode_message(&record.message)
                        .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                    write!(
                        file,
                        " {} {}",
                        record.peer.map_or(0, |party| party.0),
                        HexBytes(&encoded)
                    )
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
                }
            } else {
                write!(file, "G {}", new_records.len())
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
                for record in &new_records {
                    let encoded = encode_message(&record.message)
                        .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                    write!(
                        file,
                        " {} {} {}",
                        record.direction.as_u8(),
                        record.peer.map_or(0, |party| party.0),
                        HexBytes(&encoded)
                    )
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
                }
            }
            writeln!(file).map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        }
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }

    fn wire_records(&self) -> &[PrimeFieldMpcWireMessageRecord] {
        self.inner.records()
    }
}

#[cfg(feature = "std")]
fn write_prime_field_mpc_wire_log_record(
    file: &mut std::fs::File,
    record: &PrimeFieldMpcWireMessageRecord,
) -> Result<(), DkgError> {
    use std::io::Write;
    let encoded = encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
    writeln!(
        file,
        "{} {} {}",
        record.direction.as_u8(),
        record.peer.map_or(0, |party| party.0),
        HexBytes(&encoded)
    )
    .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
    Ok(())
}

/// File-backed local phase-cursor log for resumable prime-field MPC.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePrimeFieldMpcPhaseCursorLog {
    path: std::path::PathBuf,
    inner: InMemoryPrimeFieldMpcPhaseCursorLog,
}

#[cfg(feature = "std")]
impl FilePrimeFieldMpcPhaseCursorLog {
    /// Opens or creates a local durable phase-cursor log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut inner = InMemoryPrimeFieldMpcPhaseCursorLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let cursor = parse_prime_field_mpc_phase_cursor_log_line(line).ok_or(
                        DkgError::PrimeFieldMpcPhaseCursorLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.persist_phase_cursor(&cursor)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns persisted cursors.
    pub fn cursors(&self) -> &[PrimeFieldMpcPhaseCursor] {
        self.inner.cursors()
    }
}

#[cfg(feature = "std")]
impl PrimeFieldMpcPhaseCursorLog for FilePrimeFieldMpcPhaseCursorLog {
    fn persist_phase_cursor(&mut self, cursor: &PrimeFieldMpcPhaseCursor) -> Result<(), DkgError> {
        let before = self.inner.phase_cursors().len();
        self.inner.persist_phase_cursor(cursor)?;
        if self.inner.phase_cursors().len() == before {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "{} {} {} {} {} {} {}",
            prime_field_round_kind_to_u8(cursor.kind),
            prime_field_phase_to_u8(cursor.phase),
            cursor.receiver.map_or(0, |party| party.0),
            Hex32(cursor.label_hash),
            cursor.state.as_u8(),
            cursor.expected,
            cursor.got
        )
        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }

    fn phase_cursors(&self) -> &[PrimeFieldMpcPhaseCursor] {
        self.inner.phase_cursors()
    }
}

/// File-backed DKG setup wire log for crash/reopen tests and adapters.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDkgWireMessageLog {
    path: std::path::PathBuf,
    inner: InMemoryDkgWireMessageLog,
}

#[cfg(feature = "std")]
impl FileDkgWireMessageLog {
    /// Opens or creates a local durable DKG wire-message log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut inner = InMemoryDkgWireMessageLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let record =
                        parse_dkg_wire_log_line(line).ok_or(DkgError::DkgWireLogCorrupt {
                            line: line_index + 1,
                        })?;
                    inner.persist_dkg_wire_message(&record)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns durable records.
    pub fn records(&self) -> &[DkgWireMessageRecord] {
        self.inner.records()
    }
}

#[cfg(feature = "std")]
impl DkgWireMessageLog for FileDkgWireMessageLog {
    fn persist_dkg_wire_message(&mut self, record: &DkgWireMessageRecord) -> Result<(), DkgError> {
        let before = self.inner.records().len();
        self.inner.persist_dkg_wire_message(record)?;
        if self.inner.records().len() == before {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        let encoded =
            encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        writeln!(
            file,
            "{} {} {}",
            record.direction.as_u8(),
            record.peer.map_or(0, |party| party.0),
            HexBytes(&encoded)
        )
        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }

    fn dkg_wire_records(&self) -> &[DkgWireMessageRecord] {
        self.inner.records()
    }
}

/// Local-party state machine for transport-backed DKG prime-field MPC rounds.
///
/// This is the production-shaped transport boundary for task-1 networking:
/// callers provide a concrete `AuthenticatedP2pTransport` and
/// `EquivocationResistantBroadcast`, while TALUS builds canonical MPC wire
/// payloads, validates transcript context, rejects replayed labels, and records
/// accepted public round metadata. It is intentionally separate from the
/// all-parties-in-one-process Power2Round simulators.
#[derive(Clone, Debug)]
pub struct TransportPrimeFieldMpcStateMachine<T> {
    config: DkgConfig,
    local_party: PartyId,
    transport: T,
    expected_context: ExpectedContext,
    accepted_rounds: Vec<AcceptedPrimeFieldMpcRound>,
    completed: Vec<(
        PrimeFieldMpcRoundKind,
        PrimeFieldMpcPhase,
        [u8; 32],
        Option<PartyId>,
    )>,
}

impl<T> TransportPrimeFieldMpcStateMachine<T>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
{
    /// Creates a local-party transport-backed MPC state machine.
    pub fn new(config: DkgConfig, local_party: PartyId, transport: T) -> Result<Self, DkgError> {
        let expected_context = default_prime_field_mpc_expected_context(&config);
        Self::new_with_expected_context(config, local_party, transport, expected_context)
    }

    /// Creates a local-party transport-backed MPC state machine with an
    /// application-supplied transport context.
    ///
    /// Production adapters should pass the `ExpectedContext` derived from their
    /// ML-KEM channel/session establishment and ML-DSA party-identity binding.
    /// The context must match the DKG config, but the session id may be the
    /// adapter's PQ-bound session id instead of the deterministic test id.
    pub fn new_with_expected_context(
        config: DkgConfig,
        local_party: PartyId,
        transport: T,
        expected_context: ExpectedContext,
    ) -> Result<Self, DkgError> {
        if !config.parties.contains(&local_party) {
            return Err(DkgError::UnknownParty(local_party));
        }
        validate_prime_field_expected_context(&config, &expected_context)?;
        Ok(Self {
            config,
            local_party,
            transport,
            expected_context,
            accepted_rounds: Vec::new(),
            completed: Vec::new(),
        })
    }

    /// Returns the local party.
    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    /// Returns the wrapped transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the mutable wrapped transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns accepted public round metadata.
    pub fn accepted_rounds(&self) -> &[AcceptedPrimeFieldMpcRound] {
        &self.accepted_rounds
    }

    /// Persists all accepted public round metadata into the supplied log.
    pub fn persist_accepted_rounds<L: PrimeFieldMpcRoundLog>(
        &self,
        log: &mut L,
    ) -> Result<(), DkgError> {
        for round in &self.accepted_rounds {
            log.persist_round(round)?;
        }
        Ok(())
    }

    /// Persists one completed coefficient marker.
    pub fn persist_completed_coefficient<L: PrimeFieldMpcRoundLog>(
        &self,
        log: &mut L,
        completion: &Power2RoundCoefficientCompletion,
    ) -> Result<(), DkgError> {
        log.persist_coefficient(completion)
    }

    /// Sends one directed field value through the supplied transport.
    pub fn send_directed_value(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.send_directed_phase(
            receiver,
            kind,
            default_prime_field_phase(kind),
            label,
            value,
        )
    }

    /// Sends one typed directed field value through the supplied transport.
    pub fn send_directed_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.require_party(receiver)?;
        let message = self.wire_message(kind, phase, label, Some(receiver), value)?;
        self.transport
            .send_private(receiver.0, message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Sends one typed directed vector of field values through the supplied
    /// transport.
    pub fn send_directed_phase_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.require_party(receiver)?;
        let message = self.wire_message_vec(kind, phase, label, Some(receiver), values)?;
        self.transport
            .send_private(receiver.0, message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Sends one typed directed value with durable wire-message logging.
    ///
    /// If the same sent message already exists in `wire_log`, the persisted
    /// canonical bytes are replayed instead of rebuilding the message. This is
    /// the crash-recovery path callers should use after restart.
    pub fn send_directed_phase_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let message = match find_sent_wire_message(
            wire_log.wire_records(),
            PrimeFieldMpcWireReplayKey {
                direction: PrimeFieldMpcWireDirection::SentPrivate,
                peer: Some(receiver),
                sender: self.local_party,
                round_kind: kind,
                phase,
                receiver: Some(receiver),
                label_hash,
            },
        )? {
            Some(message) => message,
            None => {
                let message = self.wire_message(kind, phase, label, Some(receiver), value)?;
                wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::SentPrivate,
                    peer: Some(receiver),
                    message: message.clone(),
                })?;
                message
            }
        };
        self.transport
            .send_private(receiver.0, message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Sends one typed directed vector with durable wire-message logging.
    pub fn send_directed_phase_vec_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let message = match find_sent_wire_message(
            wire_log.wire_records(),
            PrimeFieldMpcWireReplayKey {
                direction: PrimeFieldMpcWireDirection::SentPrivate,
                peer: Some(receiver),
                sender: self.local_party,
                round_kind: kind,
                phase,
                receiver: Some(receiver),
                label_hash,
            },
        )? {
            Some(message) => message,
            None => {
                let message = self.wire_message_vec(kind, phase, label, Some(receiver), values)?;
                wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::SentPrivate,
                    peer: Some(receiver),
                    message: message.clone(),
                })?;
                message
            }
        };
        self.transport
            .send_private(receiver.0, message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Broadcasts one field value through the supplied broadcast transport.
    pub fn broadcast_value(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(kind, default_prime_field_phase(kind), label, value)
    }

    /// Broadcasts one typed field value through the supplied broadcast
    /// transport.
    pub fn broadcast_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        let message = self.wire_message(kind, phase, label, None, value)?;
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Broadcasts one typed vector of field values through the supplied
    /// broadcast transport.
    pub fn broadcast_phase_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        let message = self.wire_message_vec(kind, phase, label, None, values)?;
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Broadcasts one typed value with durable wire-message logging.
    pub fn broadcast_phase_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        let label_hash = power2round_label_hash(label);
        let message = match find_sent_wire_message(
            wire_log.wire_records(),
            PrimeFieldMpcWireReplayKey {
                direction: PrimeFieldMpcWireDirection::SentBroadcast,
                peer: None,
                sender: self.local_party,
                round_kind: kind,
                phase,
                receiver: None,
                label_hash,
            },
        )? {
            Some(message) => message,
            None => {
                let message = self.wire_message(kind, phase, label, None, value)?;
                wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::SentBroadcast,
                    peer: None,
                    message: message.clone(),
                })?;
                message
            }
        };
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Broadcasts one typed vector with durable wire-message logging.
    pub fn broadcast_phase_vec_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        let label_hash = power2round_label_hash(label);
        let message = match find_sent_wire_message(
            wire_log.wire_records(),
            PrimeFieldMpcWireReplayKey {
                direction: PrimeFieldMpcWireDirection::SentBroadcast,
                peer: None,
                sender: self.local_party,
                round_kind: kind,
                phase,
                receiver: None,
                label_hash,
            },
        )? {
            Some(message) => message,
            None => {
                let message = self.wire_message_vec(kind, phase, label, None, values)?;
                wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::SentBroadcast,
                    peer: None,
                    message: message.clone(),
                })?;
                message
            }
        };
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)?;
        Ok(())
    }

    /// Replays all locally sent durable wire messages into the current
    /// transport without regenerating shares, masks, random bits, or openings.
    pub fn replay_logged_sent_messages<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &L,
    ) -> Result<(), DkgError> {
        let mut private_batches = std::collections::BTreeMap::<u16, Vec<WireMessage>>::new();
        let mut broadcasts = Vec::<WireMessage>::new();
        for record in wire_log.wire_records() {
            if record.message.header.sender_party_id != self.local_party.0 {
                continue;
            }
            match record.direction {
                PrimeFieldMpcWireDirection::SentPrivate => {
                    let receiver = record.peer.ok_or(DkgError::PrimeFieldMpcTransport)?;
                    private_batches
                        .entry(receiver.0)
                        .or_default()
                        .push(record.message.clone());
                }
                PrimeFieldMpcWireDirection::SentBroadcast => {
                    broadcasts.push(record.message.clone());
                }
                PrimeFieldMpcWireDirection::AcceptedPrivate
                | PrimeFieldMpcWireDirection::AcceptedBroadcast => {}
            }
        }
        for (receiver, messages) in private_batches {
            self.transport
                .send_private_batch(receiver, messages)
                .map_err(map_transport_error)?;
        }
        if !broadcasts.is_empty() {
            self.transport
                .broadcast_batch(broadcasts)
                .map_err(map_transport_error)?;
        }
        Ok(())
    }

    /// Collects and validates directed values for one receiver/gate label.
    pub fn collect_directed_values(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_directed_phase(receiver, kind, default_prime_field_phase(kind), label)
    }

    /// Collects and validates typed directed values for one receiver/gate label.
    pub fn collect_directed_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_private_round(
                receiver.0,
                RoundId::DkgPrimeFieldMpc,
                &self.expected_context(),
            )
            .map_err(map_transport_error)?;
        self.decode_values(messages, kind, phase, label_hash, Some(receiver))
    }

    /// Collects and validates typed directed vectors for one receiver/gate
    /// label.
    pub fn collect_directed_phase_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_private_round(
                receiver.0,
                RoundId::DkgPrimeFieldMpc,
                &self.expected_context(),
            )
            .map_err(map_transport_error)?;
        self.decode_vector_values(messages, kind, phase, label_hash, Some(receiver))
    }

    /// Collects directed values and durably records the exact accepted wire
    /// messages for crash recovery/audit.
    pub fn collect_directed_phase_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_private_round(
                receiver.0,
                RoundId::DkgPrimeFieldMpc,
                &self.expected_context(),
            )
            .map_err(map_transport_error)?;
        let values =
            self.decode_values(messages.clone(), kind, phase, label_hash, Some(receiver))?;
        let records = messages
            .iter()
            .map(|message| PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedPrivate,
                peer: Some(PartyId(message.header.sender_party_id)),
                message: message.clone(),
            })
            .collect::<Vec<_>>();
        wire_log.persist_wire_messages(&records)?;
        Ok(values)
    }

    /// Collects directed vectors and durably records the exact accepted wire
    /// messages for crash recovery/audit.
    pub fn collect_directed_phase_vec_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_private_round(
                receiver.0,
                RoundId::DkgPrimeFieldMpc,
                &self.expected_context(),
            )
            .map_err(map_transport_error)?;
        let values =
            self.decode_vector_values(messages.clone(), kind, phase, label_hash, Some(receiver))?;
        let records = messages
            .iter()
            .map(|message| PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedPrivate,
                peer: Some(PartyId(message.header.sender_party_id)),
                message: message.clone(),
            })
            .collect::<Vec<_>>();
        wire_log.persist_wire_messages(&records)?;
        Ok(values)
    }

    /// Recovers previously accepted directed values from the durable wire log
    /// without using the transport.
    pub fn collect_directed_phase_from_wire_log<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &L,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let messages = self.messages_from_wire_log(
            wire_log,
            PrimeFieldMpcWireDirection::AcceptedPrivate,
            kind,
            phase,
            label_hash,
            Some(receiver),
        )?;
        self.decode_values(messages, kind, phase, label_hash, Some(receiver))
    }

    /// Recovers previously accepted directed vectors from the durable wire log
    /// without using the transport.
    pub fn collect_directed_phase_vec_from_wire_log<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &L,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.require_party(receiver)?;
        let label_hash = power2round_label_hash(label);
        let messages = self.messages_from_wire_log(
            wire_log,
            PrimeFieldMpcWireDirection::AcceptedPrivate,
            kind,
            phase,
            label_hash,
            Some(receiver),
        )?;
        self.decode_vector_values(messages, kind, phase, label_hash, Some(receiver))
    }

    /// Collects and validates equivocation-checked broadcast values for one
    /// gate label.
    pub fn collect_broadcast_values(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(kind, default_prime_field_phase(kind), label)
    }

    /// Collects and validates typed equivocation-checked broadcast values for
    /// one gate label.
    pub fn collect_broadcast_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_equivocation_checked_round(RoundId::DkgPrimeFieldMpc, &self.expected_context())
            .map_err(map_transport_error)?;
        self.decode_values(messages, kind, phase, label_hash, None)
    }

    /// Collects and validates typed equivocation-checked broadcast vectors for
    /// one gate label.
    pub fn collect_broadcast_phase_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_equivocation_checked_round(RoundId::DkgPrimeFieldMpc, &self.expected_context())
            .map_err(map_transport_error)?;
        self.decode_vector_values(messages, kind, phase, label_hash, None)
    }

    /// Collects equivocation-checked broadcast values and durably records the
    /// exact accepted wire messages.
    pub fn collect_broadcast_phase_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_equivocation_checked_round(RoundId::DkgPrimeFieldMpc, &self.expected_context())
            .map_err(map_transport_error)?;
        let values = self.decode_values(messages.clone(), kind, phase, label_hash, None)?;
        let records = messages
            .iter()
            .map(|message| PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message: message.clone(),
            })
            .collect::<Vec<_>>();
        wire_log.persist_wire_messages(&records)?;
        Ok(values)
    }

    /// Collects equivocation-checked broadcast vectors and durably records the
    /// exact accepted wire messages.
    pub fn collect_broadcast_phase_vec_logged<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &mut L,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        let label_hash = power2round_label_hash(label);
        let messages = self
            .transport
            .collect_equivocation_checked_round(RoundId::DkgPrimeFieldMpc, &self.expected_context())
            .map_err(map_transport_error)?;
        let values = self.decode_vector_values(messages.clone(), kind, phase, label_hash, None)?;
        let records = messages
            .iter()
            .map(|message| PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message: message.clone(),
            })
            .collect::<Vec<_>>();
        wire_log.persist_wire_messages(&records)?;
        Ok(values)
    }

    /// Recovers previously accepted broadcast values from the durable wire log
    /// without using the transport.
    pub fn collect_broadcast_phase_from_wire_log<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &L,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        let label_hash = power2round_label_hash(label);
        let messages = self.messages_from_wire_log(
            wire_log,
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            kind,
            phase,
            label_hash,
            None,
        )?;
        self.decode_values(messages, kind, phase, label_hash, None)
    }

    /// Recovers previously accepted broadcast vectors from the durable wire
    /// log without using the transport.
    pub fn collect_broadcast_phase_vec_from_wire_log<L: PrimeFieldMpcWireMessageLog>(
        &mut self,
        wire_log: &L,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        let label_hash = power2round_label_hash(label);
        let messages = self.messages_from_wire_log(
            wire_log,
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            kind,
            phase,
            label_hash,
            None,
        )?;
        self.decode_vector_values(messages, kind, phase, label_hash, None)
    }

    /// Sends a random-bit contribution share.
    pub fn send_random_bit_share(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.send_directed_phase(
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            label,
            value,
        )
    }

    /// Collects random-bit contribution shares.
    pub fn collect_random_bit_shares(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_directed_phase(
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            label,
        )
    }

    /// Sends a multiplication degree-reduction share.
    pub fn send_mul_degree_reduction_share(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.send_directed_phase(
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
            value,
        )
    }

    /// Collects multiplication degree-reduction shares.
    pub fn collect_mul_degree_reduction_shares(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_directed_phase(
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
        )
    }

    /// Broadcasts a checked-opening share.
    pub fn broadcast_open_share(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            label,
            value,
        )
    }

    /// Collects checked-opening shares.
    pub fn collect_open_shares(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            label,
        )
    }

    /// Broadcasts an assert-zero opening share.
    pub fn broadcast_assert_zero_share(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            label,
            value,
        )
    }

    /// Collects assert-zero opening shares.
    pub fn collect_assert_zero_shares(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            label,
        )
    }

    /// Broadcasts a public `t1` high-bit opening.
    pub fn broadcast_t1_bit_opening(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            label,
            bit,
        )
    }

    /// Collects public `t1` high-bit openings.
    pub fn collect_t1_bit_openings(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            label,
        )
    }

    /// Sends a `Power2Round` random mask bit share.
    pub fn send_power2round_mask_bit(
        &mut self,
        receiver: PartyId,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.send_directed_phase(
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::Power2RoundMaskBit,
            &coeff_label.child(format!("mask/random_bit_{bit_idx}")),
            value,
        )
    }

    /// Collects `Power2Round` random mask bit shares.
    pub fn collect_power2round_mask_bits(
        &mut self,
        receiver: PartyId,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_directed_phase(
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::Power2RoundMaskBit,
            &coeff_label.child(format!("mask/random_bit_{bit_idx}")),
        )
    }

    /// Broadcasts a `Power2Round` mask range-check share.
    pub fn broadcast_power2round_mask_range_check(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundMaskRangeCheck,
            &coeff_label.child("mask/lt_q"),
            value,
        )
    }

    /// Collects `Power2Round` mask range-check shares.
    pub fn collect_power2round_mask_range_checks(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundMaskRangeCheck,
            &coeff_label.child("mask/lt_q"),
        )
    }

    /// Broadcasts a masked opening `C = r + A mod q`.
    pub fn broadcast_power2round_masked_c(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &coeff_label.child("open_masked_c"),
            value,
        )
    }

    /// Collects masked openings `C = r + A mod q`.
    pub fn collect_power2round_masked_c(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &coeff_label.child("open_masked_c"),
        )
    }

    /// Broadcasts a vector masked opening `C = r + A mod q`.
    pub fn broadcast_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &label.child("open_masked_c"),
            values,
        )
    }

    /// Collects vector masked openings `C = r + A mod q`.
    pub fn collect_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &label.child("open_masked_c"),
        )
    }

    /// Broadcasts a wrap-comparison share `[A > C]`.
    pub fn broadcast_power2round_wrap_compare(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &coeff_label.child("a_gt_c"),
            value,
        )
    }

    /// Collects wrap-comparison shares `[A > C]`.
    pub fn collect_power2round_wrap_compare(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &coeff_label.child("a_gt_c"),
        )
    }

    /// Broadcasts vector wrap-comparison shares `[A > C]`.
    pub fn broadcast_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &label.child("a_gt_c"),
            values,
        )
    }

    /// Collects vector wrap-comparison shares `[A > C]`.
    pub fn collect_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &label.child("a_gt_c"),
        )
    }

    /// Broadcasts a subtractor/borrow recovery share.
    pub fn broadcast_power2round_subtractor_share(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &coeff_label.child(format!("recover_r_bits/subtract_bit_{bit_idx}")),
            value,
        )
    }

    /// Collects subtractor/borrow recovery shares.
    pub fn collect_power2round_subtractor_shares(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &coeff_label.child(format!("recover_r_bits/subtract_bit_{bit_idx}")),
        )
    }

    /// Broadcasts vector subtractor/borrow recovery shares.
    pub fn broadcast_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &label.child(format!("recover_r_bits/subtract_bit_{bit_idx}")),
            values,
        )
    }

    /// Collects vector subtractor/borrow recovery shares.
    pub fn collect_power2round_subtractor_shares_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &label.child(format!("recover_r_bits/subtract_bit_{bit_idx}")),
        )
    }

    /// Broadcasts vector canonical bitness-check shares.
    pub fn broadcast_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero")),
            values,
        )
    }

    /// Collects vector canonical bitness-check shares.
    pub fn collect_power2round_canonical_bitness_checks_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero")),
        )
    }

    /// Broadcasts the canonical `R < q` check share.
    pub fn broadcast_power2round_canonical_range_check(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &coeff_label.child("r_lt_q"),
            value,
        )
    }

    /// Collects canonical `R < q` check shares.
    pub fn collect_power2round_canonical_range_checks(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &coeff_label.child("r_lt_q"),
        )
    }

    /// Broadcasts vector canonical `R < q` check shares.
    pub fn broadcast_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &label.child("r_lt_q"),
            values,
        )
    }

    /// Collects vector canonical `R < q` check shares.
    pub fn collect_power2round_canonical_range_checks_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &label.child("r_lt_q"),
        )
    }

    /// Broadcasts the equality check `sum 2^j R_j == r mod q`.
    pub fn broadcast_power2round_equality_check(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &coeff_label.child("assert_bits_equal_r_mod_q"),
            value,
        )
    }

    /// Collects equality-check shares.
    pub fn collect_power2round_equality_checks(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &coeff_label.child("assert_bits_equal_r_mod_q"),
        )
    }

    /// Broadcasts vector equality-check shares `sum 2^j R_j == r mod q`.
    pub fn broadcast_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &label.child("assert_bits_equal_r_mod_q"),
            values,
        )
    }

    /// Collects vector equality-check shares.
    pub fn collect_power2round_equality_checks_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &label.child("assert_bits_equal_r_mod_q"),
        )
    }

    /// Broadcasts an add-4095 carry/share value.
    pub fn broadcast_power2round_add4095_share(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &coeff_label.child(format!("add_4095/carry_{bit_idx}")),
            value,
        )
    }

    /// Collects add-4095 carry/share values.
    pub fn collect_power2round_add4095_shares(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &coeff_label.child(format!("add_4095/carry_{bit_idx}")),
        )
    }

    /// Broadcasts vector add-4095 carry/share values.
    pub fn broadcast_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &label.child(format!("add_4095/carry_{bit_idx}")),
            values,
        )
    }

    /// Collects vector add-4095 carry/share values.
    pub fn collect_power2round_add4095_shares_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &label.child(format!("add_4095/carry_{bit_idx}")),
        )
    }

    /// Broadcasts an opened public `t1` bit.
    pub fn broadcast_power2round_t1_bit(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &coeff_label.child(format!("open_t1_bits/bit_{bit_idx}")),
            value,
        )
    }

    /// Collects opened public `t1` bits.
    pub fn collect_power2round_t1_bits(
        &mut self,
        coeff_label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.collect_broadcast_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &coeff_label.child(format!("open_t1_bits/bit_{bit_idx}")),
        )
    }

    /// Broadcasts vector opened public `t1` bits.
    pub fn broadcast_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<(), DkgError> {
        self.broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &label.child(format!("open_t1_bits/bit_{bit_idx}")),
            values,
        )
    }

    /// Collects vector opened public `t1` bits.
    pub fn collect_power2round_t1_bits_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &label.child(format!("open_t1_bits/bit_{bit_idx}")),
        )
    }

    pub(crate) fn wire_message(
        &self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        receiver: Option<PartyId>,
        value: Coeff,
    ) -> Result<WireMessage, DkgError> {
        let payload = DkgPrimeFieldMpcPayload {
            round_kind: prime_field_round_kind_to_u8(kind),
            phase: prime_field_phase_to_u8(phase),
            receiver_party_id: receiver.map_or(0, |party| party.0),
            label_hash: power2round_label_hash(label),
            value,
            values: Vec::new(),
        };
        Ok(WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: wire_suite(self.config.suite),
                round: RoundId::DkgPrimeFieldMpc,
                sender_party_id: self.local_party.0,
                keygen_transcript_hash: self.expected_context.keygen_transcript_hash,
                session_id: self.expected_context.session_id,
                signing_set_hash: self.expected_context.signing_set_hash,
                payload_kind: PayloadKind::DkgPrimeFieldMpc,
            },
            payload: encode_dkg_prime_field_mpc_payload(&payload),
        })
    }

    pub(crate) fn wire_message_vec(
        &self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        receiver: Option<PartyId>,
        values: &[Coeff],
    ) -> Result<WireMessage, DkgError> {
        if values.is_empty() {
            return Err(DkgError::PrimeFieldMpcTransport);
        }
        let payload = DkgPrimeFieldMpcPayload {
            round_kind: prime_field_round_kind_to_u8(kind),
            phase: prime_field_phase_to_u8(phase),
            receiver_party_id: receiver.map_or(0, |party| party.0),
            label_hash: power2round_label_hash(label),
            value: 0,
            values: values.to_vec(),
        };
        Ok(WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: wire_suite(self.config.suite),
                round: RoundId::DkgPrimeFieldMpc,
                sender_party_id: self.local_party.0,
                keygen_transcript_hash: self.expected_context.keygen_transcript_hash,
                session_id: self.expected_context.session_id,
                signing_set_hash: self.expected_context.signing_set_hash,
                payload_kind: PayloadKind::DkgPrimeFieldMpc,
            },
            payload: encode_dkg_prime_field_mpc_payload(&payload),
        })
    }

    fn expected_context(&self) -> ExpectedContext {
        self.expected_context.clone()
    }

    fn messages_from_wire_log<L: PrimeFieldMpcWireMessageLog>(
        &self,
        wire_log: &L,
        direction: PrimeFieldMpcWireDirection,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label_hash: [u8; 32],
        receiver: Option<PartyId>,
    ) -> Result<Vec<WireMessage>, DkgError> {
        let mut messages = Vec::new();
        for record in wire_log.wire_records() {
            let key = wire_message_replay_key(record)?;
            if key.direction == direction
                && key.round_kind == kind
                && key.phase == phase
                && key.label_hash == label_hash
                && key.receiver == receiver
            {
                messages.push(record.message.clone());
            }
        }
        validate_round_batch(
            &messages,
            RoundId::DkgPrimeFieldMpc,
            &self.expected_context(),
        )
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        Ok(messages)
    }

    fn decode_values(
        &mut self,
        messages: Vec<WireMessage>,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label_hash: [u8; 32],
        receiver: Option<PartyId>,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.mark_completed(kind, phase, label_hash, receiver)?;
        let mut values = Vec::with_capacity(messages.len());
        for message in messages {
            if message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
                return Err(DkgError::PrimeFieldMpcTransport);
            }
            let payload = decode_dkg_prime_field_mpc_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            if payload.round_kind != prime_field_round_kind_to_u8(kind)
                || payload.phase != prime_field_phase_to_u8(phase)
                || payload.label_hash != label_hash
                || payload.receiver_party_id != receiver.map_or(0, |party| party.0)
                || !payload.values.is_empty()
            {
                return Err(DkgError::PrimeFieldMpcTransport);
            }
            values.push((PartyId(message.header.sender_party_id), payload.value));
        }
        let senders = values.iter().map(|(party, _)| *party).collect();
        self.accepted_rounds.push(AcceptedPrimeFieldMpcRound {
            kind,
            phase,
            label_hash,
            senders,
        });
        Ok(values)
    }

    fn decode_vector_values(
        &mut self,
        messages: Vec<WireMessage>,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label_hash: [u8; 32],
        receiver: Option<PartyId>,
    ) -> Result<Vec<(PartyId, Vec<Coeff>)>, DkgError> {
        self.mark_completed(kind, phase, label_hash, receiver)?;
        let mut values = Vec::with_capacity(messages.len());
        let mut expected_len = None;
        for message in messages {
            if message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
                return Err(DkgError::PrimeFieldMpcTransport);
            }
            let payload = decode_dkg_prime_field_mpc_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            if payload.round_kind != prime_field_round_kind_to_u8(kind)
                || payload.phase != prime_field_phase_to_u8(phase)
                || payload.label_hash != label_hash
                || payload.receiver_party_id != receiver.map_or(0, |party| party.0)
                || payload.values.is_empty()
            {
                return Err(DkgError::PrimeFieldMpcTransport);
            }
            if let Some(len) = expected_len {
                if payload.values.len() != len {
                    return Err(DkgError::PrimeFieldMpcTransport);
                }
            } else {
                expected_len = Some(payload.values.len());
            }
            values.push((PartyId(message.header.sender_party_id), payload.values));
        }
        let senders = values.iter().map(|(party, _)| *party).collect();
        self.accepted_rounds.push(AcceptedPrimeFieldMpcRound {
            kind,
            phase,
            label_hash,
            senders,
        });
        Ok(values)
    }

    fn mark_completed(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label_hash: [u8; 32],
        receiver: Option<PartyId>,
    ) -> Result<(), DkgError> {
        if self
            .completed
            .contains(&(kind, phase, label_hash, receiver))
        {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
        self.completed.push((kind, phase, label_hash, receiver));
        Ok(())
    }

    fn require_party(&self, party: PartyId) -> Result<(), DkgError> {
        if self.config.parties.contains(&party) {
            Ok(())
        } else {
            Err(DkgError::UnknownParty(party))
        }
    }
}

/// Resumable single-party runtime for transport-backed prime-field MPC.
///
/// The runtime owns one local-party state machine and one durable wire-message
/// log. It never schedules other parties. Callers drive each phase by asking
/// the local party to send its own value, collect peer values, and resume from
/// logged sent messages after a crash.
#[derive(Clone, Debug)]
pub struct TransportPrimeFieldMpcPartyRuntime<T, L> {
    state: TransportPrimeFieldMpcStateMachine<T>,
    wire_log: L,
}

/// Single-party phase-driver status for DKG prime-field MPC.
///
/// This is the production-shaped scheduler boundary: one node drives only its
/// local party, emits canonical wire messages through the configured transport,
/// and reports what it is waiting for. The embedding application owns actual
/// delivery, retry, persistence policy, and network runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrimeFieldMpcPhaseDriverStatus {
    /// A directed private message was sent by this party.
    SentPrivate {
        /// Receiver party.
        receiver: PartyId,
        /// Round kind.
        kind: PrimeFieldMpcRoundKind,
        /// Round phase.
        phase: PrimeFieldMpcPhase,
        /// Transcript label hash.
        label_hash: [u8; 32],
    },
    /// A broadcast message was sent by this party.
    SentBroadcast {
        /// Round kind.
        kind: PrimeFieldMpcRoundKind,
        /// Round phase.
        phase: PrimeFieldMpcPhase,
        /// Transcript label hash.
        label_hash: [u8; 32],
    },
    /// The party is waiting for a directed private round to be delivered.
    WaitingPrivate {
        /// Receiver party.
        receiver: PartyId,
        /// Round kind.
        kind: PrimeFieldMpcRoundKind,
        /// Round phase.
        phase: PrimeFieldMpcPhase,
        /// Transcript label hash.
        label_hash: [u8; 32],
        /// Expected number of messages.
        expected: usize,
        /// Messages currently available.
        got: usize,
    },
    /// The party is waiting for an equivocation-resistant broadcast round.
    WaitingBroadcast {
        /// Round kind.
        kind: PrimeFieldMpcRoundKind,
        /// Round phase.
        phase: PrimeFieldMpcPhase,
        /// Transcript label hash.
        label_hash: [u8; 32],
        /// Expected number of messages.
        expected: usize,
        /// Messages currently available.
        got: usize,
    },
    /// A private or broadcast phase was collected and validated.
    Collected {
        /// Directed receiver, if this was a private phase.
        receiver: Option<PartyId>,
        /// Round kind.
        kind: PrimeFieldMpcRoundKind,
        /// Round phase.
        phase: PrimeFieldMpcPhase,
        /// Transcript label hash.
        label_hash: [u8; 32],
        /// Accepted sender parties.
        senders: Vec<PartyId>,
    },
}

/// Durable state of one local prime-field MPC phase cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeFieldMpcPhaseCursorState {
    /// Local party sent a directed message.
    SentPrivate,
    /// Local party sent a broadcast message.
    SentBroadcast,
    /// Local party is waiting for more directed messages.
    WaitingPrivate,
    /// Local party is waiting for more broadcast deliveries.
    WaitingBroadcast,
    /// Local party collected and accepted the phase.
    Collected,
}

impl PrimeFieldMpcPhaseCursorState {
    fn as_u8(self) -> u8 {
        match self {
            Self::SentPrivate => 1,
            Self::SentBroadcast => 2,
            Self::WaitingPrivate => 3,
            Self::WaitingBroadcast => 4,
            Self::Collected => 5,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SentPrivate),
            2 => Some(Self::SentBroadcast),
            3 => Some(Self::WaitingPrivate),
            4 => Some(Self::WaitingBroadcast),
            5 => Some(Self::Collected),
            _ => None,
        }
    }
}

/// Durable cursor for phase continuation after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimeFieldMpcPhaseCursor {
    /// Round kind.
    pub kind: PrimeFieldMpcRoundKind,
    /// Round phase.
    pub phase: PrimeFieldMpcPhase,
    /// Optional directed receiver.
    pub receiver: Option<PartyId>,
    /// Transcript label hash.
    pub label_hash: [u8; 32],
    /// Phase state.
    pub state: PrimeFieldMpcPhaseCursorState,
    /// Expected message count, if applicable.
    pub expected: usize,
    /// Observed message count, if applicable.
    pub got: usize,
}

impl PrimeFieldMpcPhaseCursor {
    /// Builds a cursor from a driver status.
    pub fn from_driver_status(status: &PrimeFieldMpcPhaseDriverStatus) -> Self {
        match status {
            PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver,
                kind,
                phase,
                label_hash,
            } => Self {
                kind: *kind,
                phase: *phase,
                receiver: Some(*receiver),
                label_hash: *label_hash,
                state: PrimeFieldMpcPhaseCursorState::SentPrivate,
                expected: 0,
                got: 0,
            },
            PrimeFieldMpcPhaseDriverStatus::SentBroadcast {
                kind,
                phase,
                label_hash,
            } => Self {
                kind: *kind,
                phase: *phase,
                receiver: None,
                label_hash: *label_hash,
                state: PrimeFieldMpcPhaseCursorState::SentBroadcast,
                expected: 0,
                got: 0,
            },
            PrimeFieldMpcPhaseDriverStatus::WaitingPrivate {
                receiver,
                kind,
                phase,
                label_hash,
                expected,
                got,
            } => Self {
                kind: *kind,
                phase: *phase,
                receiver: Some(*receiver),
                label_hash: *label_hash,
                state: PrimeFieldMpcPhaseCursorState::WaitingPrivate,
                expected: *expected,
                got: *got,
            },
            PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                kind,
                phase,
                label_hash,
                expected,
                got,
            } => Self {
                kind: *kind,
                phase: *phase,
                receiver: None,
                label_hash: *label_hash,
                state: PrimeFieldMpcPhaseCursorState::WaitingBroadcast,
                expected: *expected,
                got: *got,
            },
            PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver,
                kind,
                phase,
                label_hash,
                senders,
            } => Self {
                kind: *kind,
                phase: *phase,
                receiver: *receiver,
                label_hash: *label_hash,
                state: PrimeFieldMpcPhaseCursorState::Collected,
                expected: senders.len(),
                got: senders.len(),
            },
        }
    }
}

/// Durable phase-cursor log for restart/continuation.
pub trait PrimeFieldMpcPhaseCursorLog {
    /// Persists one phase cursor.
    fn persist_phase_cursor(&mut self, cursor: &PrimeFieldMpcPhaseCursor) -> Result<(), DkgError>;

    /// Returns all persisted cursors.
    fn phase_cursors(&self) -> &[PrimeFieldMpcPhaseCursor];

    /// Returns the latest cursor, if any.
    fn latest_phase_cursor(&self) -> Option<&PrimeFieldMpcPhaseCursor> {
        self.phase_cursors().last()
    }
}

/// In-memory phase-cursor log for tests and adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryPrimeFieldMpcPhaseCursorLog {
    cursors: Vec<PrimeFieldMpcPhaseCursor>,
}

impl InMemoryPrimeFieldMpcPhaseCursorLog {
    /// Returns persisted cursors.
    pub fn cursors(&self) -> &[PrimeFieldMpcPhaseCursor] {
        &self.cursors
    }
}

impl PrimeFieldMpcPhaseCursorLog for InMemoryPrimeFieldMpcPhaseCursorLog {
    fn persist_phase_cursor(&mut self, cursor: &PrimeFieldMpcPhaseCursor) -> Result<(), DkgError> {
        if self.cursors.last() == Some(cursor) {
            return Ok(());
        }
        self.cursors.push(cursor.clone());
        Ok(())
    }

    fn phase_cursors(&self) -> &[PrimeFieldMpcPhaseCursor] {
        &self.cursors
    }
}

/// Cursor-aware single-party runtime for restartable prime-field MPC phases.
#[derive(Clone, Debug)]
pub struct CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C> {
    runtime: TransportPrimeFieldMpcPartyRuntime<T, L>,
    cursor_log: C,
}

/// Result of a restartable vector Power2Round collection phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProductionPower2RoundVectorCollectResult<T> {
    /// More peer messages are needed before the phase can be accepted.
    Waiting(Vec<PrimeFieldMpcPhaseDriverStatus>),
    /// The phase was fully collected/recovered and accepted.
    Collected(T),
}

/// Local party share vector for the production Power2Round circuit.
///
/// This is local secret state. It contains this party's Shamir evaluation of a
/// full vector wire, ordered by polynomial then coefficient.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionPower2RoundLocalShareVector {
    party: PartyId,
    point: u32,
    lanes: Vec<Coeff>,
}

impl ProductionPower2RoundLocalShareVector {
    /// Builds a local vector share from caller-owned lanes.
    pub fn new(party: PartyId, point: u32, lanes: Vec<Coeff>) -> Result<Self, DkgError> {
        if lanes.is_empty() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(Self {
            party,
            point,
            lanes,
        })
    }

    /// Builds a local vector share from one `SharedT` party share.
    pub fn from_shared_t_party_share<P: MlDsaParams>(
        share: &SharedTPartyShare,
    ) -> Result<Self, DkgError> {
        if share.t_share.polys().len() != P::K {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let mut lanes = Vec::with_capacity(P::K * P::N);
        for poly in share.t_share.polys() {
            if poly.coeffs().len() != P::N {
                return Err(DkgError::Power2RoundMaskShapeMismatch);
            }
            lanes.extend(poly.coeffs().iter().copied());
        }
        Self::new(share.party, share.point, lanes)
    }

    /// Returns the owner party.
    pub fn party(&self) -> PartyId {
        self.party
    }

    /// Returns the owner interpolation point.
    pub fn point(&self) -> u32 {
        self.point
    }

    /// Returns the lane count.
    pub fn len(&self) -> usize {
        self.lanes.len()
    }

    /// Returns true if there are no lanes.
    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }

    fn lanes(&self) -> &[Coeff] {
        &self.lanes
    }
}

impl fmt::Debug for ProductionPower2RoundLocalShareVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionPower2RoundLocalShareVector")
            .field("party", &self.party)
            .field("point", &self.point)
            .field("len", &self.lanes.len())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ProductionPower2RoundLocalShareVector {
    fn zeroize(&mut self) {
        self.lanes.zeroize();
    }
}

impl Drop for ProductionPower2RoundLocalShareVector {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Local party share of a previously certified Power2Round canonical mask.
///
/// Certification happens before this local state is constructed; this type
/// carries the certified batch id plus this party's local mask-value shares.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionPower2RoundLocalMaskShare {
    id: Power2RoundMaskBatchId,
    value: ProductionPower2RoundLocalShareVector,
}

impl ProductionPower2RoundLocalMaskShare {
    /// Builds a local mask share bound to a certified mask batch id.
    pub fn new(
        id: Power2RoundMaskBatchId,
        value: ProductionPower2RoundLocalShareVector,
    ) -> Result<Self, DkgError> {
        if id.lane_count == 0 || id.lane_count != value.len() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(Self { id, value })
    }

    /// Returns the certified mask batch id.
    pub fn id(&self) -> Power2RoundMaskBatchId {
        self.id
    }
}

impl fmt::Debug for ProductionPower2RoundLocalMaskShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionPower2RoundLocalMaskShare")
            .field("id", &self.id)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ProductionPower2RoundLocalMaskShare {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for ProductionPower2RoundLocalMaskShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Runtime-owned local state for vector Power2Round execution.
///
/// This state is the production-facing direction for closing Phase 4: phase
/// values are derived from local secret circuit state, not supplied as
/// ad-hoc vectors by the caller. The first closed operation is the masked
/// opening `C = t + A_mask`; remaining nonlinear bit-circuit generation is
/// tracked separately in the implementation plan.
pub struct ProductionPower2RoundCircuitState {
    t: ProductionPower2RoundLocalShareVector,
    mask: ProductionPower2RoundLocalMaskShare,
    opened_masked_c: Option<Vec<Coeff>>,
}

impl ProductionPower2RoundCircuitState {
    /// Starts local Power2Round circuit execution from a local `[t]` share and
    /// a certified local mask share.
    pub fn new(
        label: &Power2RoundTranscriptLabel,
        t: ProductionPower2RoundLocalShareVector,
        mask: ProductionPower2RoundLocalMaskShare,
    ) -> Result<Self, DkgError> {
        if t.party() != mask.value.party()
            || t.point() != mask.value.point()
            || t.len() != mask.id.lane_count
        {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let expected = Power2RoundMaskBatchId::new(&label.child("mask"), t.len());
        if mask.id != expected {
            return Err(DkgError::Power2RoundMaskTranscriptMismatch);
        }
        Ok(Self {
            t,
            mask,
            opened_masked_c: None,
        })
    }

    /// Returns this circuit lane count.
    pub fn lane_count(&self) -> usize {
        self.t.len()
    }

    /// Returns the opened public masked `C` vector if it has been collected.
    pub fn opened_masked_c(&self) -> Option<&[Coeff]> {
        self.opened_masked_c.as_deref()
    }

    /// Computes this party's local shares of `C = t + A_mask mod q` and
    /// broadcasts them through the production vector runtime.
    pub fn drive_masked_c_opening<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let values = self
            .t
            .lanes()
            .iter()
            .zip(self.mask.value.lanes())
            .map(|(&left, &right)| reduce_mod_q::<P>(left + right))
            .collect::<Vec<_>>();
        runtime.drive_power2round_masked_c_vec(label, &values)
    }

    /// Collects the masked-`C` opening, advances the Power2Round driver, and
    /// stores the reconstructed public `C` vector for later nonlinear phases.
    pub fn drive_collect_masked_c_opening<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<Vec<Coeff>>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        match runtime.drive_collect_power2round_masked_c_vec_and_advance(driver, label)? {
            ProductionPower2RoundVectorCollectResult::Waiting(statuses) => {
                Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses))
            }
            ProductionPower2RoundVectorCollectResult::Collected(values) => {
                let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
                if opened.len() != self.lane_count()
                    || opened.iter().any(|&value| value < 0 || value >= P::Q)
                {
                    return Err(DkgError::Power2RoundCanonicalityFailure);
                }
                self.opened_masked_c = Some(opened.clone());
                Ok(ProductionPower2RoundVectorCollectResult::Collected(opened))
            }
        }
    }
}

impl fmt::Debug for ProductionPower2RoundCircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionPower2RoundCircuitState")
            .field("party", &self.t.party())
            .field("lane_count", &self.lane_count())
            .field("mask_id", &self.mask.id())
            .field(
                "opened_masked_c",
                &self.opened_masked_c.as_ref().map(Vec::len),
            )
            .finish()
    }
}

impl Zeroize for ProductionPower2RoundCircuitState {
    fn zeroize(&mut self) {
        self.t.zeroize();
        self.mask.zeroize();
        self.opened_masked_c.zeroize();
    }
}

impl Drop for ProductionPower2RoundCircuitState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Runtime-owned handle state for the nonlinear vector Power2Round circuit.
///
/// Unlike the lower-level phase helpers, this state owns the secret handles
/// needed to derive nonlinear Power2Round material from prior private state.
/// It is the production-facing path for closing the gap between "the runtime
/// can verify phase outputs" and "the runtime derives those outputs".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPower2RoundRuntimeCircuitState {
    t: ProductionShareVec,
    mask_value: ProductionShareVec,
    mask_bits_by_bit: Vec<ProductionBitShareVec>,
    opened_masked_c: Option<Vec<Coeff>>,
    wrap_comparison: Option<ProductionPublicComparisonVecState>,
    wrap: Option<ProductionBitShareVec>,
    canonical_recovery: Option<ProductionPower2RoundCanonicalRecoveryState>,
    r_bits_by_bit: Option<Vec<ProductionBitShareVec>>,
    r_bitness_products: Vec<Option<ProductionShareVec>>,
    r_lt_q_comparison: Option<ProductionPublicComparisonVecState>,
    r_lt_q_special: Option<ProductionCanonicalLtQVecState>,
    r_lt_q: Option<ProductionBitShareVec>,
    add_4095: Option<ProductionPower2RoundAdd4095State>,
    s_bits_by_bit: Option<Vec<ProductionBitShareVec>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionPower2RoundCanonicalRecoveryPendingKind {
    InitProducts,
    PrefixLayer { distance: usize },
    DiffProducts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionPower2RoundCanonicalRecoveryPrefixSegment {
    generate: ProductionBitShareVec,
    propagate: ProductionBitShareVec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionPower2RoundCanonicalRecoveryState {
    base_bits_by_bit: Vec<ProductionBitShareVec>,
    a_bits_by_bit: Vec<ProductionBitShareVec>,
    xor_bits_by_bit: Vec<Option<ProductionBitShareVec>>,
    prefix_segments: Vec<Option<ProductionPower2RoundCanonicalRecoveryPrefixSegment>>,
    prefix_distance: usize,
    out_bits_by_bit: Vec<Option<ProductionBitShareVec>>,
    overflow_bit: Option<ProductionBitShareVec>,
    final_borrow: Option<ProductionBitShareVec>,
    pending: Option<ProductionPower2RoundCanonicalRecoveryPendingKind>,
    done: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionPower2RoundAdd4095State {
    r_bits_by_bit: Vec<ProductionBitShareVec>,
    out_bits_by_bit: Vec<Option<ProductionBitShareVec>>,
    carry: ProductionBitShareVec,
    bit_idx: usize,
    pending: bool,
    done: bool,
}

impl ProductionPower2RoundRuntimeCircuitState {
    /// Builds runtime-owned Power2Round state from this party's `[t]` share,
    /// canonical mask value share, and canonical mask bit shares.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        t: ProductionShareVec,
        mask_value: ProductionShareVec,
        mask_bits_by_bit: Vec<ProductionBitShareVec>,
    ) -> Result<Self, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime.validate_share_vec_context::<P>(config, &t)?;
        runtime.validate_share_vec_context::<P>(config, &mask_value)?;
        runtime.ensure_same_share_shape(&t, &mask_value)?;
        if mask_bits_by_bit.len() != 23 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        for bits in &mask_bits_by_bit {
            runtime.validate_share_vec_context::<P>(config, bits.share())?;
            runtime.ensure_same_share_shape(&t, bits.share())?;
        }
        Ok(Self {
            t,
            mask_value,
            mask_bits_by_bit,
            opened_masked_c: None,
            wrap_comparison: None,
            wrap: None,
            canonical_recovery: None,
            r_bits_by_bit: None,
            r_bitness_products: vec![None; 23],
            r_lt_q_comparison: None,
            r_lt_q_special: None,
            r_lt_q: None,
            add_4095: None,
            s_bits_by_bit: None,
        })
    }

    /// Returns the vector lane count.
    pub fn lane_count(&self) -> usize {
        self.t.len()
    }

    /// Returns opened masked `C` values after collection.
    pub fn opened_masked_c(&self) -> Option<&[Coeff]> {
        self.opened_masked_c.as_deref()
    }

    /// Returns the private wrap bits after the state-owned comparison
    /// completes.
    pub fn wrap(&self) -> Option<&ProductionBitShareVec> {
        self.wrap.as_ref()
    }

    /// Returns recovered canonical `R` bits after the runtime-owned recovery
    /// and certification phases complete.
    pub fn r_bits_by_bit(&self) -> Option<&[ProductionBitShareVec]> {
        self.r_bits_by_bit.as_deref()
    }

    /// Returns secret bits of `S = R + 4095` after the runtime-owned adder
    /// completes.
    pub fn s_bits_by_bit(&self) -> Option<&[ProductionBitShareVec]> {
        self.s_bits_by_bit.as_deref()
    }

    /// Returns the private `R < q` result after the range circuit completes.
    pub fn r_lt_q(&self) -> Option<&ProductionBitShareVec> {
        self.r_lt_q.as_ref()
    }

    fn selected_base_bit_for_recovery<P, T, L, C>(
        &self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        c_values: &[Coeff],
        bit_idx: usize,
        wrap: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let c_plus_q = c_values
            .iter()
            .map(|&value| {
                if value < 0 || value >= P::Q {
                    Err(DkgError::Power2RoundCanonicalityFailure)
                } else {
                    Ok(value as u32 + P::Q as u32)
                }
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        let base_bits = c_values
            .iter()
            .map(|&value| (((value as u32) >> bit_idx) & 1) as Coeff)
            .collect::<Vec<_>>();
        let diff = c_values
            .iter()
            .zip(c_plus_q.iter())
            .map(|(&c, &c_q)| {
                let b0 = ((c as u32 >> bit_idx) & 1) as Coeff;
                let b1 = ((c_q >> bit_idx) & 1) as Coeff;
                reduce_mod_q::<P>(b1 - b0)
            })
            .collect::<Vec<_>>();
        let base = runtime.public_lanes_share_vec::<P>(
            config,
            &label.child(format!("recover_r_bits/bit_{bit_idx}/base")),
            &base_bits,
        )?;
        let selected_delta = runtime.mul_public_lanes_share_vec::<P>(
            config,
            wrap.share(),
            &diff,
            &label.child(format!("recover_r_bits/bit_{bit_idx}/wrap_delta")),
        )?;
        Ok(ProductionBitShareVec::new(runtime.add_share_vec::<P>(
            config,
            &base,
            &selected_delta,
            &label.child(format!("recover_r_bits/bit_{bit_idx}/selected_base")),
        )?))
    }

    fn recovery_a_bit<P, T, L, C>(
        &self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        bit_idx: usize,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if bit_idx < 23 {
            Ok(self.mask_bits_by_bit[bit_idx].clone())
        } else {
            runtime.public_bit_share_vec::<P>(
                config,
                &label.child("recover_r_bits/a_bit_23_zero"),
                false,
                self.lane_count(),
            )
        }
    }

    /// Computes and broadcasts this party's share of `C = t + A_mask`.
    pub fn drive_masked_c_opening<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let masked = runtime.add_share_vec::<P>(
            config,
            &self.t,
            &self.mask_value,
            &label.child("masked_c"),
        )?;
        runtime.drive_power2round_masked_c_vec(label, masked.lanes())
    }

    /// Collects opened `C`, advances the Power2Round driver, and stores the
    /// public masked values for subsequent state-owned nonlinear phases.
    pub fn collect_masked_c_opening<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<Vec<Coeff>>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        match runtime.drive_collect_power2round_masked_c_vec_and_advance(driver, label)? {
            ProductionPower2RoundVectorCollectResult::Waiting(statuses) => {
                Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses))
            }
            ProductionPower2RoundVectorCollectResult::Collected(values) => {
                let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
                if opened.len() != self.lane_count()
                    || opened.iter().any(|&value| value < 0 || value >= P::Q)
                {
                    return Err(DkgError::Power2RoundCanonicalityFailure);
                }
                self.opened_masked_c = Some(opened.clone());
                Ok(ProductionPower2RoundVectorCollectResult::Collected(opened))
            }
        }
    }

    /// Opens masked `C = x + A (mod q)` through the generic checked vector
    /// opening path.
    ///
    /// This is used by consumers such as strict signing that reuse the
    /// canonical decomposition circuit but are not executing the Power2Round
    /// public-key-assembly cursor.
    pub fn drive_masked_c_opening_checked<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let masked = runtime.add_share_vec::<P>(
            config,
            &self.t,
            &self.mask_value,
            &label.child("masked_c"),
        )?;
        runtime.drive_open_share_vec::<P>(config, &masked, &label.child("open_masked_c"))
    }

    /// Collects generic checked masked `C` openings and stores canonical public
    /// `C` values for later private bit recovery.
    pub fn collect_masked_c_opening_checked<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<Vec<Coeff>>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        match runtime.collect_open_share_vec::<P>(config, &label.child("open_masked_c"))? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => {
                if value.len() != self.lane_count()
                    || value.iter().any(|&lane| lane < 0 || lane >= P::Q)
                {
                    return Err(DkgError::Power2RoundCanonicalityFailure);
                }
                self.opened_masked_c = Some(value.clone());
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value })
            }
        }
    }

    /// Starts the private lane-wise wrap comparison `[A_mask > C]` from
    /// runtime-owned mask bit shares and the previously opened masked values.
    pub fn start_wrap_comparison<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let c = self
            .opened_masked_c
            .as_ref()
            .ok_or(DkgError::Power2RoundMaskedOpeningsRequired)?;
        self.wrap_comparison = Some(runtime.start_gt_public_lanes_vec::<P>(
            config,
            &self.mask_bits_by_bit,
            c,
            &label.child("a_gt_c"),
        )?);
        Ok(())
    }

    /// Drives one multiplication layer of the state-owned wrap comparison.
    pub fn drive_wrap_comparison_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        let state = self
            .wrap_comparison
            .as_mut()
            .ok_or(DkgError::Power2RoundMaskedOpeningsRequired)?;
        runtime.drive_public_comparison_vec_step::<P, E>(config, state, entropy)
    }

    /// Collects one multiplication layer of the state-owned wrap comparison.
    pub fn collect_wrap_comparison_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let state = self
            .wrap_comparison
            .as_mut()
            .ok_or(DkgError::Power2RoundMaskedOpeningsRequired)?;
        let result = runtime.collect_public_comparison_vec_step::<P>(config, state)?;
        if state.is_done() {
            self.wrap = Some(
                state
                    .result()
                    .ok_or(DkgError::Power2RoundCanonicalityFailure)?
                    .clone(),
            );
        }
        Ok(result)
    }

    /// Starts runtime-owned canonical recovery of secret bits of
    /// `R = C + q*[A>C] - A`.
    pub fn start_canonical_r_bit_recovery<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let c_values = self
            .opened_masked_c
            .as_ref()
            .ok_or(DkgError::Power2RoundMaskedOpeningsRequired)?
            .clone();
        let wrap = self
            .wrap
            .as_ref()
            .ok_or(DkgError::Power2RoundMaskedOpeningsRequired)?
            .clone();
        if c_values.len() != self.lane_count() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let mut base_bits_by_bit = Vec::with_capacity(24);
        let mut a_bits_by_bit = Vec::with_capacity(24);
        for bit_idx in 0..24 {
            base_bits_by_bit.push(self.selected_base_bit_for_recovery::<P, _, _, _>(
                runtime, config, &c_values, bit_idx, &wrap, label,
            )?);
            a_bits_by_bit.push(self.recovery_a_bit::<P, _, _, _>(runtime, config, bit_idx, label)?);
        }
        self.canonical_recovery = Some(ProductionPower2RoundCanonicalRecoveryState {
            base_bits_by_bit,
            a_bits_by_bit,
            xor_bits_by_bit: vec![None; 24],
            prefix_segments: vec![None; 24],
            prefix_distance: 1,
            out_bits_by_bit: vec![None; 23],
            overflow_bit: None,
            final_borrow: None,
            pending: None,
            done: false,
        });
        self.r_bits_by_bit = None;
        Ok(())
    }

    /// Drives one multiplication layer of runtime-owned canonical `R` bit
    /// recovery.
    pub fn drive_canonical_r_recovery_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        let Some(state_snapshot) = self.canonical_recovery.as_ref() else {
            return Err(DkgError::Power2RoundCanonicalBitsRequired);
        };
        if state_snapshot.done {
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: PrimeFieldMpcPhase::SubtractorShare,
                label_hash: power2round_label_hash(label),
                senders: Vec::new(),
            });
        }
        if state_snapshot.pending.is_some() {
            return Err(DkgError::Backend(
                "Power2Round canonical recovery step already pending",
            ));
        }
        let (op_label, packed_left, packed_right, pending) =
            if state_snapshot.prefix_segments.iter().any(Option::is_none) {
                let mut left = Vec::with_capacity(48);
                let mut right = Vec::with_capacity(48);
                for bit_idx in 0..24 {
                    let base = state_snapshot
                        .base_bits_by_bit
                        .get(bit_idx)
                        .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                    let a_bit = state_snapshot
                        .a_bits_by_bit
                        .get(bit_idx)
                        .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                    let not_base = runtime.bit_not_vec::<P>(
                        config,
                        base,
                        &label.child(format!("recover_r_bits/prefix_init/bit_{bit_idx}/not_base")),
                    )?;
                    left.push(base.clone());
                    right.push(a_bit.clone());
                    left.push(not_base);
                    right.push(a_bit.clone());
                }
                (
                    label.child("recover_r_bits/prefix_init"),
                    runtime.pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &left,
                        &label.child("recover_r_bits/prefix_init/left"),
                    )?,
                    runtime.pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &right,
                        &label.child("recover_r_bits/prefix_init/right"),
                    )?,
                    ProductionPower2RoundCanonicalRecoveryPendingKind::InitProducts,
                )
            } else if state_snapshot.prefix_distance < 24 {
                let distance = state_snapshot.prefix_distance;
                let mut left = Vec::with_capacity((24 - distance) * 2);
                let mut right = Vec::with_capacity((24 - distance) * 2);
                for bit_idx in distance..24 {
                    let current = state_snapshot
                        .prefix_segments
                        .get(bit_idx)
                        .and_then(Clone::clone)
                        .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                    let lower = state_snapshot
                        .prefix_segments
                        .get(bit_idx - distance)
                        .and_then(Clone::clone)
                        .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                    left.push(current.propagate.clone());
                    right.push(lower.generate);
                    left.push(current.propagate);
                    right.push(lower.propagate);
                }
                (
                    label.child(format!("recover_r_bits/prefix_borrow_distance_{distance}")),
                    runtime.pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &left,
                        &label.child(format!(
                            "recover_r_bits/prefix_borrow_distance_{distance}/left"
                        )),
                    )?,
                    runtime.pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &right,
                        &label.child(format!(
                            "recover_r_bits/prefix_borrow_distance_{distance}/right"
                        )),
                    )?,
                    ProductionPower2RoundCanonicalRecoveryPendingKind::PrefixLayer { distance },
                )
            } else {
                let segments = state_snapshot
                    .prefix_segments
                    .iter()
                    .cloned()
                    .collect::<Option<Vec<_>>>()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                let xor_bits = state_snapshot
                    .xor_bits_by_bit
                    .iter()
                    .cloned()
                    .collect::<Option<Vec<_>>>()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                let mut left = Vec::with_capacity(23);
                let mut right = Vec::with_capacity(23);
                for bit_idx in 1..24 {
                    left.push(xor_bits[bit_idx].clone());
                    right.push(segments[bit_idx - 1].generate.clone());
                }
                (
                    label.child("recover_r_bits/prefix_diff"),
                    runtime.pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &left,
                        &label.child("recover_r_bits/prefix_diff/left"),
                    )?,
                    runtime.pack_bit_share_vecs_for_runtime_batch::<P>(
                        config,
                        &right,
                        &label.child("recover_r_bits/prefix_diff/right"),
                    )?,
                    ProductionPower2RoundCanonicalRecoveryPendingKind::DiffProducts,
                )
            };
        runtime.drive_bit_and_vec_with_phase::<P, E>(
            config,
            &packed_left,
            &packed_right,
            &op_label,
            PrimeFieldMpcPhase::SubtractorShare,
            entropy,
        )?;
        let state = self
            .canonical_recovery
            .as_mut()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        state.pending = Some(pending);
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: power2round_label_hash(&op_label.child("bit_and").child("mul_layer")),
        })
    }

    /// Collects one multiplication layer of runtime-owned canonical `R` bit
    /// recovery.
    pub fn collect_canonical_r_recovery_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let pending = self
            .canonical_recovery
            .as_mut()
            .and_then(|state| state.pending.take())
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let op_label = match pending {
            ProductionPower2RoundCanonicalRecoveryPendingKind::InitProducts => {
                label.child("recover_r_bits/prefix_init")
            }
            ProductionPower2RoundCanonicalRecoveryPendingKind::PrefixLayer { distance } => {
                label.child(format!("recover_r_bits/prefix_borrow_distance_{distance}"))
            }
            ProductionPower2RoundCanonicalRecoveryPendingKind::DiffProducts => {
                label.child("recover_r_bits/prefix_diff")
            }
        };
        let (status, and_result) = match runtime.collect_bit_and_vec_with_phase::<P>(
            config,
            &op_label,
            PrimeFieldMpcPhase::SubtractorShare,
        )? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                let state = self
                    .canonical_recovery
                    .as_mut()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                state.pending = Some(pending);
                return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
        };
        match pending {
            ProductionPower2RoundCanonicalRecoveryPendingKind::InitProducts => {
                let products = runtime.unpack_bit_share_vec_runtime_batch::<P>(
                    config,
                    &and_result,
                    self.lane_count(),
                    &op_label.child("products"),
                )?;
                if products.len() != 48 {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
                let (base_bits, a_bits) = self
                    .canonical_recovery
                    .as_ref()
                    .map(|state| (state.base_bits_by_bit.clone(), state.a_bits_by_bit.clone()))
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                let mut xor_bits = Vec::with_capacity(24);
                let mut segments = Vec::with_capacity(24);
                for bit_idx in 0..24 {
                    let base_and_a = &products[bit_idx * 2];
                    let not_base_and_a = products[bit_idx * 2 + 1].clone();
                    let xor = runtime.bit_xor_from_and_vec::<P>(
                        config,
                        &base_bits[bit_idx],
                        &a_bits[bit_idx],
                        base_and_a,
                        &op_label.child(format!("bit_{bit_idx}/base_xor_a")),
                    )?;
                    let propagate = runtime.bit_not_vec::<P>(
                        config,
                        &xor,
                        &op_label.child(format!("bit_{bit_idx}/propagate")),
                    )?;
                    xor_bits.push(Some(xor));
                    segments.push(Some(ProductionPower2RoundCanonicalRecoveryPrefixSegment {
                        generate: not_base_and_a,
                        propagate,
                    }));
                }
                let state = self
                    .canonical_recovery
                    .as_mut()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                state.xor_bits_by_bit = xor_bits;
                state.prefix_segments = segments;
                state.prefix_distance = 1;
            }
            ProductionPower2RoundCanonicalRecoveryPendingKind::PrefixLayer { distance } => {
                let products = runtime.unpack_bit_share_vec_runtime_batch::<P>(
                    config,
                    &and_result,
                    self.lane_count(),
                    &op_label.child("products"),
                )?;
                if distance == 0 || distance >= 24 || products.len() != (24 - distance) * 2 {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
                let old_segments = self
                    .canonical_recovery
                    .as_ref()
                    .and_then(|state| {
                        state
                            .prefix_segments
                            .iter()
                            .cloned()
                            .collect::<Option<Vec<_>>>()
                    })
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                let mut next_segments = old_segments.clone();
                for bit_idx in distance..24 {
                    let product_idx = (bit_idx - distance) * 2;
                    let current = &old_segments[bit_idx];
                    let propagate_and_lower_generate = &products[product_idx];
                    let propagate_and_lower_propagate = products[product_idx + 1].clone();
                    let generate = ProductionBitShareVec::new(runtime.add_share_vec::<P>(
                        config,
                        current.generate.share(),
                        propagate_and_lower_generate.share(),
                        &op_label.child(format!("bit_{bit_idx}/generate")),
                    )?);
                    next_segments[bit_idx] = ProductionPower2RoundCanonicalRecoveryPrefixSegment {
                        generate,
                        propagate: propagate_and_lower_propagate,
                    };
                }
                let state = self
                    .canonical_recovery
                    .as_mut()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                state.prefix_segments = next_segments.into_iter().map(Some).collect();
                state.prefix_distance = distance * 2;
            }
            ProductionPower2RoundCanonicalRecoveryPendingKind::DiffProducts => {
                let products = runtime.unpack_bit_share_vec_runtime_batch::<P>(
                    config,
                    &and_result,
                    self.lane_count(),
                    &op_label.child("products"),
                )?;
                if products.len() != 23 {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
                let (xor_bits, segments) = self
                    .canonical_recovery
                    .as_ref()
                    .and_then(|state| {
                        Some((
                            state
                                .xor_bits_by_bit
                                .iter()
                                .cloned()
                                .collect::<Option<Vec<_>>>()?,
                            state
                                .prefix_segments
                                .iter()
                                .cloned()
                                .collect::<Option<Vec<_>>>()?,
                        ))
                    })
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                let mut out_bits = vec![None; 23];
                out_bits[0] = Some(xor_bits[0].clone());
                let mut overflow_bit = None;
                for bit_idx in 1..24 {
                    let diff = runtime.bit_xor_from_and_vec::<P>(
                        config,
                        &xor_bits[bit_idx],
                        &segments[bit_idx - 1].generate,
                        &products[bit_idx - 1],
                        &op_label.child(format!("bit_{bit_idx}/diff")),
                    )?;
                    if bit_idx < 23 {
                        out_bits[bit_idx] = Some(diff);
                    } else {
                        overflow_bit = Some(diff);
                    }
                }
                let final_borrow = segments
                    .last()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?
                    .generate
                    .clone();
                let out = out_bits
                    .iter()
                    .cloned()
                    .collect::<Option<Vec<_>>>()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                let state = self
                    .canonical_recovery
                    .as_mut()
                    .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
                state.out_bits_by_bit = out_bits;
                state.overflow_bit = overflow_bit;
                state.final_borrow = Some(final_borrow);
                state.done = true;
                self.r_bits_by_bit = Some(out);
                self.r_bitness_products = vec![None; 23];
            }
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    fn canonical_r_value_share<P, T, L, C>(
        &self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let r_bits = self
            .r_bits_by_bit
            .as_ref()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let mut weighted_bits = Vec::with_capacity(r_bits.len());
        for (bit_idx, bit) in r_bits.iter().enumerate() {
            weighted_bits.push(
                runtime.mul_public_const_share_vec::<P>(
                    config,
                    bit.share(),
                    1_i32
                        .checked_shl(bit_idx as u32)
                        .ok_or(DkgError::Power2RoundCanonicalityFailure)?,
                    &label.child(format!("r_from_bits/bit_{bit_idx}")),
                )?,
            );
        }
        runtime.sum_share_vecs::<P>(config, &weighted_bits, &label.child("r_from_bits/sum"))
    }

    /// Drives the multiplication product for the state-owned bitness check
    /// `R_bit * (R_bit - 1)`.
    pub fn drive_r_bitness_product<P, T, L, C, E>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        let r_bits = self
            .r_bits_by_bit
            .as_ref()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let bit = r_bits
            .get(bit_idx)
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let one = runtime.public_const_share_vec::<P>(
            config,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}/one")),
            1,
            self.lane_count(),
        )?;
        let bit_minus_one = runtime.sub_share_vec::<P>(
            config,
            bit.share(),
            &one,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}/bit_minus_one")),
        )?;
        runtime.drive_mul_vec_degree_reduction_with_phase::<P, E>(
            config,
            bit.share(),
            &bit_minus_one,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}")),
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            entropy,
        )?;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: power2round_label_hash(
                &label
                    .child(format!("r_bits_boolean/bit_{bit_idx}"))
                    .child("mul_layer"),
            ),
        })
    }

    /// Collects the state-owned bitness product for `R_bit`.
    pub fn collect_r_bitness_product<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let (status, product) = match runtime.collect_mul_vec_degree_reduction_with_phase::<P>(
            config,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}")),
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
        )? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
        };
        let slot = self
            .r_bitness_products
            .get_mut(bit_idx)
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        *slot = Some(product);
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Opens only the zero residual for the state-owned `R_bit` bitness
    /// product. Failed raw values are checked and discarded by the runtime.
    pub fn drive_r_bitness_zero_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let product = self
            .r_bitness_products
            .get(bit_idx)
            .and_then(|product| product.as_ref())
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        runtime.drive_assert_zero_share_vec::<P>(
            config,
            product,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero")),
        )
    }

    /// Collects the zero residual for the state-owned `R_bit` bitness product.
    pub fn collect_r_bitness_zero_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime.collect_assert_zero_share_vec::<P>(
            config,
            &label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero")),
        )
    }

    /// Starts runtime-owned private range certification for recovered
    /// canonical `R` bits.
    pub fn start_r_lt_q_check<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let r_bits = self
            .r_bits_by_bit
            .as_ref()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        self.r_lt_q_special = Some(runtime.start_canonical_lt_q_vec::<P>(
            config,
            r_bits,
            &label.child("r_lt_q"),
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
        )?);
        self.r_lt_q_comparison = None;
        self.r_lt_q = None;
        Ok(())
    }

    /// Drives one multiplication layer of state-owned `R < q`.
    pub fn drive_r_lt_q_check_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        let state = self
            .r_lt_q_special
            .as_mut()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        runtime.drive_canonical_lt_q_vec_step::<P, E>(config, state, entropy)
    }

    /// Collects one multiplication layer of state-owned `R < q`.
    pub fn collect_r_lt_q_check_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let state = self
            .r_lt_q_special
            .as_mut()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let result = runtime.collect_canonical_lt_q_vec_step::<P>(config, state)?;
        if state.is_done() {
            self.r_lt_q = Some(
                state
                    .result()
                    .ok_or(DkgError::Power2RoundCanonicalityFailure)?
                    .clone(),
            );
        }
        Ok(result)
    }

    /// Drives the final checked assertion that recovered `R` bits satisfy
    /// `sum 2^j R_j == t (mod q)`.
    pub fn drive_r_bits_equal_t_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let r_from_bits = self.canonical_r_value_share::<P, _, _, _>(runtime, config, label)?;
        let residual = runtime.sub_share_vec::<P>(
            config,
            &r_from_bits,
            &self.t,
            &label.child("assert_bits_equal_r_mod_q/residual"),
        )?;
        runtime.drive_assert_zero_share_vec::<P>(
            config,
            &residual,
            &label.child("assert_bits_equal_r_mod_q"),
        )
    }

    /// Collects the final checked assertion that recovered `R` bits equal
    /// `[t] mod q`.
    pub fn collect_r_bits_equal_t_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime
            .collect_assert_zero_share_vec::<P>(config, &label.child("assert_bits_equal_r_mod_q"))
    }

    /// Drives a zero assertion for `1 - [R < q]`.
    pub fn drive_r_lt_q_assert_true<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let r_lt_q = self
            .r_lt_q
            .as_ref()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let not_lt =
            runtime.bit_not_vec::<P>(config, r_lt_q, &label.child("assert_r_lt_q/not_lt"))?;
        runtime.drive_assert_zero_share_vec::<P>(
            config,
            not_lt.share(),
            &label.child("assert_r_lt_q"),
        )
    }

    /// Collects the zero assertion for `1 - [R < q]`.
    pub fn collect_r_lt_q_assert_true<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        runtime.collect_assert_zero_share_vec::<P>(config, &label.child("assert_r_lt_q"))
    }

    /// Installs canonical `R` bits as the source for subsequent runtime-owned
    /// checks/addition.
    ///
    /// This is intentionally narrow: it exists to connect the already
    /// recovered bit handles to the state-owned check/add/open phases. The
    /// release path is expected to call this only from the runtime-owned
    /// canonical recovery phase, not from caller-supplied nonlinear artifacts.
    pub fn accept_recovered_r_bits<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        r_bits_by_bit: Vec<ProductionBitShareVec>,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if r_bits_by_bit.len() != 23 {
            return Err(DkgError::Power2RoundCanonicalBitsRequired);
        }
        for bits in &r_bits_by_bit {
            runtime.validate_share_vec_context::<P>(config, bits.share())?;
            runtime.ensure_same_share_shape(&self.t, bits.share())?;
        }
        self.r_bits_by_bit = Some(r_bits_by_bit);
        self.r_bitness_products = vec![None; 23];
        Ok(())
    }

    /// Starts the runtime-owned ripple adder for `S = R + 4095`.
    pub fn start_add_4095<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let r_bits = self
            .r_bits_by_bit
            .as_ref()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?
            .clone();
        let carry = runtime.public_bit_share_vec::<P>(
            config,
            &label.child("add_4095/carry_init"),
            false,
            self.lane_count(),
        )?;
        self.add_4095 = Some(ProductionPower2RoundAdd4095State {
            r_bits_by_bit: r_bits,
            out_bits_by_bit: vec![None; 23],
            carry,
            bit_idx: 0,
            pending: false,
            done: false,
        });
        self.s_bits_by_bit = None;
        Ok(())
    }

    /// Drives one multiplication layer of the runtime-owned `R + 4095`
    /// ripple adder.
    pub fn drive_add_4095_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        let state = self
            .add_4095
            .as_mut()
            .ok_or(DkgError::Power2RoundAddRoundConstantRequired)?;
        if state.done {
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: PrimeFieldMpcPhase::Power2RoundAdd4095,
                label_hash: power2round_label_hash(label),
                senders: Vec::new(),
            });
        }
        if state.pending {
            return Err(DkgError::Backend(
                "Power2Round add-4095 step already pending",
            ));
        }
        if state.bit_idx >= 23 {
            return Err(DkgError::Power2RoundAddRoundConstantRequired);
        }
        let step_label = label.child(format!("add_4095/bit_{}/carry", state.bit_idx));
        runtime.drive_bit_and_vec_with_phase::<P, E>(
            config,
            &state.r_bits_by_bit[state.bit_idx],
            &state.carry,
            &step_label,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            entropy,
        )?;
        state.pending = true;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: runtime.local_party(),
            kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: power2round_label_hash(&step_label.child("bit_and").child("mul_layer")),
        })
    }

    /// Collects one multiplication layer of the runtime-owned `R + 4095`
    /// ripple adder.
    pub fn collect_add_4095_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        let state = self
            .add_4095
            .as_mut()
            .ok_or(DkgError::Power2RoundAddRoundConstantRequired)?;
        if state.done {
            return Ok(ProductionVectorItMpcCollectResult::Collected {
                status: PrimeFieldMpcPhaseDriverStatus::Collected {
                    receiver: None,
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    phase: PrimeFieldMpcPhase::Power2RoundAdd4095,
                    label_hash: power2round_label_hash(label),
                    senders: Vec::new(),
                },
                value: (),
            });
        }
        if !state.pending || state.bit_idx >= 23 {
            return Err(DkgError::Backend(
                "Power2Round add-4095 step has no pending layer",
            ));
        }
        let bit_idx = state.bit_idx;
        let step_label = label.child(format!("add_4095/bit_{bit_idx}/carry"));
        let (status, x_and_carry) = match runtime.collect_bit_and_vec_with_phase::<P>(
            config,
            &step_label,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
        )? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
        };
        let x = &state.r_bits_by_bit[bit_idx];
        let x_xor_carry = runtime.bit_xor_from_and_vec::<P>(
            config,
            x,
            &state.carry,
            &x_and_carry,
            &label.child(format!("add_4095/bit_{bit_idx}/sum_xor")),
        )?;
        let constant_bit = bit_idx < 12;
        let sum_bit = if constant_bit {
            runtime.bit_not_vec::<P>(
                config,
                &x_xor_carry,
                &label.child(format!("add_4095/bit_{bit_idx}/sum")),
            )?
        } else {
            x_xor_carry
        };
        let next_carry = if constant_bit {
            runtime.bit_or_from_and_vec::<P>(
                config,
                x,
                &state.carry,
                &x_and_carry,
                &label.child(format!("add_4095/bit_{bit_idx}/carry_or")),
            )?
        } else {
            x_and_carry
        };
        state.out_bits_by_bit[bit_idx] = Some(sum_bit);
        state.carry = next_carry;
        state.bit_idx += 1;
        state.pending = false;
        if state.bit_idx == 23 {
            state.done = true;
            let out = state
                .out_bits_by_bit
                .iter()
                .cloned()
                .collect::<Option<Vec<_>>>()
                .ok_or(DkgError::Power2RoundAddRoundConstantRequired)?;
            self.s_bits_by_bit = Some(out);
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Drives the selected public opening of one `t1` high bit from
    /// state-owned `S = R + 4095` bits.
    pub fn drive_t1_high_bit_opening<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        t1_bit_idx: usize,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        if t1_bit_idx >= 10 {
            return Err(DkgError::Power2RoundT1BitsRequired);
        }
        let s_bits = self
            .s_bits_by_bit
            .as_ref()
            .ok_or(DkgError::Power2RoundAddRoundConstantRequired)?;
        let bit = &s_bits[13 + t1_bit_idx];
        runtime.validate_share_vec_context::<P>(config, bit.share())?;
        runtime.drive_power2round_t1_bit_vec(label, t1_bit_idx, bit.share().lanes())
    }
}

/// Generic runtime-owned canonical bit-decomposition state for a secret
/// `ProductionShareVec`.
///
/// This reuses the reviewed Power2Round canonical-mask/open/subtract/check
/// machinery without tying callers to a `t1` public-key assembly. Callers
/// provide a canonical random mask value and mask bits, open only
/// `C = x + A (mod q)`, recover private canonical bits of `x`, and can then
/// run the same bitness, range, and equality checks used by Power2Round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionCanonicalBitDecompositionState {
    inner: ProductionPower2RoundRuntimeCircuitState,
}

impl ProductionCanonicalBitDecompositionState {
    /// Builds generic canonical bit-decomposition state from a secret value
    /// share and certified canonical mask shares.
    pub fn new<P, T, L, C>(
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        value: ProductionShareVec,
        mask_value: ProductionShareVec,
        mask_bits_by_bit: Vec<ProductionBitShareVec>,
    ) -> Result<Self, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        Ok(Self {
            inner: ProductionPower2RoundRuntimeCircuitState::new::<P, _, _, _>(
                runtime,
                config,
                value,
                mask_value,
                mask_bits_by_bit,
            )?,
        })
    }

    /// Returns the vector lane count.
    pub fn lane_count(&self) -> usize {
        self.inner.lane_count()
    }

    /// Returns opened masked `C` values after collection.
    pub fn opened_masked_c(&self) -> Option<&[Coeff]> {
        self.inner.opened_masked_c()
    }

    /// Returns recovered canonical bits after recovery and checks are ready.
    pub fn r_bits_by_bit(&self) -> Option<&[ProductionBitShareVec]> {
        self.inner.r_bits_by_bit()
    }

    /// Returns the private `R < q` bit after range checking.
    pub fn r_lt_q(&self) -> Option<&ProductionBitShareVec> {
        self.inner.r_lt_q()
    }

    /// Opens only the masked value `C = x + A (mod q)`.
    pub fn drive_masked_c_opening<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .drive_masked_c_opening::<P, _, _, _>(runtime, config, label)
    }

    /// Collects opened masked values and stores them for later private
    /// recovery. The supplied Power2Round driver is reused as the durable
    /// vector opening cursor/evidence source.
    pub fn collect_masked_c_opening<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<Vec<Coeff>>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_masked_c_opening::<P, _, _, _>(runtime, driver, config, label)
    }

    /// Opens masked `C = x + A (mod q)` through the generic checked vector
    /// opening path.
    pub fn drive_masked_c_opening_checked<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .drive_masked_c_opening_checked::<P, _, _, _>(runtime, config, label)
    }

    /// Collects generic checked masked `C` openings.
    pub fn collect_masked_c_opening_checked<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<Vec<Coeff>>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_masked_c_opening_checked::<P, _, _, _>(runtime, config, label)
    }

    /// Starts private wrap comparison `[A > C]`.
    pub fn start_wrap_comparison<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .start_wrap_comparison::<P, _, _, _>(runtime, config, label)
    }

    /// Drives one wrap-comparison multiplication layer.
    pub fn drive_wrap_comparison_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        self.inner
            .drive_wrap_comparison_step::<P, _, _, _, _>(runtime, config, entropy)
    }

    /// Collects one wrap-comparison multiplication layer.
    pub fn collect_wrap_comparison_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_wrap_comparison_step::<P, _, _, _>(runtime, config)
    }

    /// Starts canonical bit recovery for `R = C + q*[A>C] - A`.
    pub fn start_canonical_bit_recovery<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .start_canonical_r_bit_recovery::<P, _, _, _>(runtime, config, label)
    }

    /// Drives one canonical bit-recovery multiplication layer.
    pub fn drive_canonical_bit_recovery_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        self.inner
            .drive_canonical_r_recovery_step::<P, _, _, _, _>(runtime, config, label, entropy)
    }

    /// Collects one canonical bit-recovery multiplication layer.
    pub fn collect_canonical_bit_recovery_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_canonical_r_recovery_step::<P, _, _, _>(runtime, config, label)
    }

    /// Starts private `R < q` range certification.
    pub fn start_r_lt_q_check<P, T, L, C>(
        &mut self,
        runtime: &ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .start_r_lt_q_check::<P, _, _, _>(runtime, config, label)
    }

    /// Drives one `R < q` multiplication layer.
    pub fn drive_r_lt_q_check_step<P, T, L, C, E>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        self.inner
            .drive_r_lt_q_check_step::<P, _, _, _, _>(runtime, config, entropy)
    }

    /// Collects one `R < q` multiplication layer.
    pub fn collect_r_lt_q_check_step<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_r_lt_q_check_step::<P, _, _, _>(runtime, config)
    }

    /// Drives one bitness-product layer for recovered canonical bits.
    pub fn drive_r_bitness_product<P, T, L, C, E>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
        E: ProductionVectorItMpcEntropy,
    {
        self.inner
            .drive_r_bitness_product::<P, _, _, _, _>(runtime, config, label, bit_idx, entropy)
    }

    /// Collects one bitness-product layer for recovered canonical bits.
    pub fn collect_r_bitness_product<P, T, L, C>(
        &mut self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_r_bitness_product::<P, _, _, _>(runtime, config, label, bit_idx)
    }

    /// Drives the zero-check for one recovered-bit bitness product.
    pub fn drive_r_bitness_zero_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .drive_r_bitness_zero_check::<P, _, _, _>(runtime, config, label, bit_idx)
    }

    /// Collects the zero-check for one recovered-bit bitness product.
    pub fn collect_r_bitness_zero_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_r_bitness_zero_check::<P, _, _, _>(runtime, config, label, bit_idx)
    }

    /// Drives the checked equality `sum 2^j R_j == x (mod q)`.
    pub fn drive_r_bits_equal_value_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .drive_r_bits_equal_t_check::<P, _, _, _>(runtime, config, label)
    }

    /// Collects the checked equality `sum 2^j R_j == x (mod q)`.
    pub fn collect_r_bits_equal_value_check<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_r_bits_equal_t_check::<P, _, _, _>(runtime, config, label)
    }

    /// Drives the checked assertion that recovered canonical bits encode
    /// values below `q`.
    pub fn drive_r_lt_q_assert_true<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .drive_r_lt_q_assert_true::<P, _, _, _>(runtime, config, label)
    }

    /// Collects the checked assertion that recovered canonical bits encode
    /// values below `q`.
    pub fn collect_r_lt_q_assert_true<P, T, L, C>(
        &self,
        runtime: &mut ProductionVectorPrimeFieldMpcRuntime<T, L, C>,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError>
    where
        P: MlDsaParams,
        T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        self.inner
            .collect_r_lt_q_assert_true::<P, _, _, _>(runtime, config, label)
    }
}

impl<T, L, C> CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    /// Creates a cursor-aware runtime.
    pub fn new(runtime: TransportPrimeFieldMpcPartyRuntime<T, L>, cursor_log: C) -> Self {
        Self {
            runtime,
            cursor_log,
        }
    }

    /// Returns the inner runtime.
    pub fn runtime(&self) -> &TransportPrimeFieldMpcPartyRuntime<T, L> {
        &self.runtime
    }

    /// Returns the mutable inner runtime.
    pub fn runtime_mut(&mut self) -> &mut TransportPrimeFieldMpcPartyRuntime<T, L> {
        &mut self.runtime
    }

    /// Returns the cursor log.
    pub fn cursor_log(&self) -> &C {
        &self.cursor_log
    }

    /// Returns the mutable cursor log.
    pub fn cursor_log_mut(&mut self) -> &mut C {
        &mut self.cursor_log
    }

    /// Replays locally sent messages after restart and leaves the latest
    /// cursor available to the application scheduler.
    pub fn resume(&mut self) -> Result<Option<PrimeFieldMpcPhaseCursor>, DkgError> {
        self.runtime.resume_sent_messages()?;
        Ok(self.cursor_log.latest_phase_cursor().cloned())
    }

    /// Drives and persists a directed send phase.
    pub fn drive_send_directed_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_send_directed_phase(receiver, kind, phase, label, value)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists a directed vector send phase.
    pub fn drive_send_directed_phase_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_send_directed_phase_vec(receiver, kind, phase, label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists a broadcast send phase.
    pub fn drive_broadcast_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_broadcast_phase(kind, phase, label, value)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists a broadcast vector send phase.
    pub fn drive_broadcast_phase_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_broadcast_phase_vec(kind, phase, label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists the Power2Round vector masked-opening broadcast.
    pub fn drive_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self.runtime.drive_power2round_masked_c_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists a preprocessing masked-broadcast consistency vector
    /// opening.
    pub fn drive_preprocessing_masked_broadcast_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_preprocessing_masked_broadcast_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists a preprocessing CarryCompare certification vector
    /// check.
    pub fn drive_preprocessing_carry_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_preprocessing_carry_compare_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Drives and persists a preprocessing CEF/BCC certification vector check.
    pub fn drive_preprocessing_cef_bcc_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_preprocessing_cef_bcc_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists directed phase collection.
    pub fn drive_collect_directed_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Coeff)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_directed_phase(receiver, kind, phase, label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists directed vector phase collection.
    pub fn drive_collect_directed_phase_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_directed_phase_vec(receiver, kind, phase, label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists broadcast phase collection.
    pub fn drive_collect_broadcast_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Coeff)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_broadcast_phase(kind, phase, label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists broadcast vector phase collection.
    pub fn drive_collect_broadcast_phase_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_broadcast_phase_vec(kind, phase, label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists Power2Round vector masked-opening collection.
    pub fn drive_collect_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self.runtime.drive_collect_power2round_masked_c_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists preprocessing masked-broadcast consistency vector
    /// collection.
    pub fn drive_collect_preprocessing_masked_broadcast_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_preprocessing_masked_broadcast_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists preprocessing CarryCompare certification vector
    /// collection.
    pub fn drive_collect_preprocessing_carry_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_preprocessing_carry_compare_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Attempts and persists preprocessing CEF/BCC certification vector
    /// collection.
    pub fn drive_collect_preprocessing_cef_bcc_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_preprocessing_cef_bcc_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Collects or recovers the Power2Round masked-opening vector and advances
    /// the production driver when the lane shape is complete.
    pub fn drive_collect_power2round_masked_c_vec_and_advance(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<Vec<(PartyId, Vec<Coeff>)>>, DkgError>
    {
        let phase_label = label.child("open_masked_c");
        let (status, values) = self.collect_or_recover_broadcast_vec_phase(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &phase_label,
        )?;
        if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
            return Ok(ProductionPower2RoundVectorCollectResult::Waiting(vec![
                status,
            ]));
        }
        let lane_count = uniform_collected_vector_lane_count(&values)?;
        driver.accept_masked_openings(lane_count)?;
        Ok(ProductionPower2RoundVectorCollectResult::Collected(values))
    }

    /// Drives and persists the Power2Round vector wrap-comparison broadcast.
    pub fn drive_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_wrap_compare_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector wrap-comparison collection.
    pub fn drive_collect_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_wrap_compare_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Collects or recovers all vector phases that certify canonical `R` bit
    /// recovery, then advances the production driver once the complete phase
    /// set has been accepted.
    pub fn drive_collect_power2round_canonical_recovery_all_vec_and_advance<P: MlDsaParams>(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<usize>, DkgError> {
        let mut statuses = Vec::with_capacity(50);
        let mut lane_count = None;

        let wrap_label = label.child("a_gt_c");
        let (status, values) = self.collect_or_recover_broadcast_vec_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &wrap_label,
        )?;
        if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
            statuses.push(status);
            return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
        }
        lane_count = Some(record_power2round_lane_count(lane_count, &values)?);
        ensure_collected_vector_reconstructs_zero::<P>(config, &values)?;
        statuses.push(status);

        for bit_idx in 0..24 {
            let phase_label = label.child(format!("recover_r_bits/subtract_bit_{bit_idx}"));
            let (status, values) = self.collect_or_recover_broadcast_vec_phase(
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::SubtractorShare,
                &phase_label,
            )?;
            if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
                statuses.push(status);
                return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
            }
            lane_count = Some(record_power2round_lane_count(lane_count, &values)?);
            ensure_collected_vector_reconstructs_zero::<P>(config, &values)?;
            statuses.push(status);
        }

        for bit_idx in 0..23 {
            let phase_label = label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero"));
            let (status, values) = self.collect_or_recover_broadcast_vec_phase(
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
                &phase_label,
            )?;
            if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
                statuses.push(status);
                return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
            }
            lane_count = Some(record_power2round_lane_count(lane_count, &values)?);
            ensure_collected_vector_reconstructs_zero::<P>(config, &values)?;
            statuses.push(status);
        }

        let range_label = label.child("r_lt_q");
        let (status, values) = self.collect_or_recover_broadcast_vec_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &range_label,
        )?;
        if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
            statuses.push(status);
            return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
        }
        lane_count = Some(record_power2round_lane_count(lane_count, &values)?);
        ensure_collected_vector_reconstructs_zero::<P>(config, &values)?;
        statuses.push(status);

        let equality_label = label.child("assert_bits_equal_r_mod_q");
        let (status, values) = self.collect_or_recover_broadcast_vec_phase(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &equality_label,
        )?;
        if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
            statuses.push(status);
            return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
        }
        lane_count = Some(record_power2round_lane_count(lane_count, &values)?);
        ensure_collected_vector_reconstructs_zero::<P>(config, &values)?;

        let lane_count = lane_count.ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        driver.accept_canonical_bit_recovery(lane_count)?;
        Ok(ProductionPower2RoundVectorCollectResult::Collected(
            lane_count,
        ))
    }

    /// Drives and persists a Power2Round vector subtractor/borrow broadcast.
    pub fn drive_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_subtractor_share_vec(label, bit_idx, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector subtractor/borrow collection.
    pub fn drive_collect_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_subtractor_share_vec(label, bit_idx)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a Power2Round vector canonical bitness-check
    /// broadcast.
    pub fn drive_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_canonical_bitness_check_vec(label, bit_idx, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector canonical bitness-check
    /// collection.
    pub fn drive_collect_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_canonical_bitness_check_vec(label, bit_idx)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a Power2Round vector canonical range-check broadcast.
    pub fn drive_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_canonical_range_check_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector canonical range-check collection.
    pub fn drive_collect_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_canonical_range_check_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a Power2Round vector equality-check broadcast.
    pub fn drive_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_equality_check_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector equality-check collection.
    pub fn drive_collect_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_equality_check_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a Power2Round vector add-4095 carry/share broadcast.
    pub fn drive_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_add4095_share_vec(label, bit_idx, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector add-4095 carry/share collection.
    pub fn drive_collect_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_add4095_share_vec(label, bit_idx)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a Power2Round vector `t1` public bit-opening broadcast.
    pub fn drive_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_power2round_t1_bit_vec(label, bit_idx, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists Power2Round vector `t1` public bit-opening collection.
    pub fn drive_collect_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_power2round_t1_bit_vec(label, bit_idx)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a generic vector bit-sum / threshold-check
    /// broadcast for preprocessing or strict signing circuits.
    pub fn drive_bit_sum_threshold_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_bit_sum_threshold_check_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists generic vector bit-sum / threshold-check
    /// collection.
    pub fn drive_collect_bit_sum_threshold_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_bit_sum_threshold_check_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Drives and persists a generic vector private one-hot selection check
    /// broadcast for strict signing circuits.
    pub fn drive_private_selection_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let status = self
            .runtime
            .drive_private_selection_check_vec(label, values)?;
        self.persist_status(&status)?;
        Ok(status)
    }

    /// Attempts and persists generic vector private one-hot selection check
    /// collection.
    pub fn drive_collect_private_selection_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let (status, values) = self
            .runtime
            .drive_collect_private_selection_check_vec(label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    /// Collects or recovers all 23 add-4095 vector carry/share phases and
    /// advances the production driver once every bit phase is complete.
    pub fn drive_collect_power2round_add4095_all_vec_and_advance<P: MlDsaParams>(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<usize>, DkgError> {
        let mut statuses = Vec::with_capacity(23);
        let mut lane_count = None;
        for bit_idx in 0..23 {
            let phase_label = label.child(format!("add_4095/carry_{bit_idx}"));
            let (status, values) = self.collect_or_recover_broadcast_vec_phase(
                PrimeFieldMpcRoundKind::AssertZero,
                PrimeFieldMpcPhase::Power2RoundAdd4095,
                &phase_label,
            )?;
            if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
                statuses.push(status);
                return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
            }
            lane_count = Some(record_power2round_lane_count(lane_count, &values)?);
            ensure_collected_vector_reconstructs_zero::<P>(config, &values)?;
            statuses.push(status);
        }
        let lane_count = lane_count.ok_or(DkgError::Power2RoundAddRoundConstantRequired)?;
        driver.accept_add_round_constant(lane_count)?;
        Ok(ProductionPower2RoundVectorCollectResult::Collected(
            lane_count,
        ))
    }

    /// Collects or recovers all ten public `t1` bit-opening phases,
    /// reconstructs the public `t1` vector, emits evidence, and completes the
    /// production driver.
    pub fn drive_collect_power2round_t1_bits_and_certify<P: MlDsaParams>(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        assembly_label: PublicKeyAssemblyLabel,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<ProductionPower2RoundOutput>, DkgError>
    {
        let mut statuses = Vec::with_capacity(10);
        let mut opened_bits_by_bit = Vec::with_capacity(10);
        let mut lane_count = None;
        for bit_idx in 0..10 {
            let phase_label = label.child(format!("open_t1_bits/bit_{bit_idx}"));
            let (status, values) = self.collect_or_recover_broadcast_vec_phase(
                PrimeFieldMpcRoundKind::Open,
                PrimeFieldMpcPhase::T1BitOpening,
                &phase_label,
            )?;
            if !matches!(status, PrimeFieldMpcPhaseDriverStatus::Collected { .. }) {
                statuses.push(status);
                return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
            }
            let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
            if opened
                .iter()
                .any(|&value| opened_coeff_to_bit(value).is_err())
            {
                return Err(DkgError::Power2RoundInvalidOpenedBit);
            }
            if let Some(expected) = lane_count {
                if opened.len() != expected {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
            } else {
                lane_count = Some(opened.len());
            }
            opened_bits_by_bit.push(opened);
            statuses.push(status);
        }
        let lane_count = lane_count.ok_or(DkgError::Power2RoundT1BitsRequired)?;
        let mut coeffs = vec![0u16; lane_count];
        for (bit_idx, opened_bits) in opened_bits_by_bit.into_iter().enumerate() {
            for (lane_idx, value) in opened_bits.into_iter().enumerate() {
                coeffs[lane_idx] |= u16::from(opened_coeff_to_bit(value)?) << bit_idx;
            }
        }
        let t1 = power2round_public_t1_from_coeffs::<P>(coeffs)?;
        driver.accept_opened_t1(&t1)?;
        let evidence = power2round_certify_public_t1_evidence(
            Power2RoundBackendId::ProductionItMpc,
            config,
            assembly_label,
            &t1,
        );
        driver.accept_certified_evidence(&evidence)?;
        ensure_power2round_wire_log_openings_allowed_for_release(self.runtime.wire_log())?;
        let output = ProductionPower2RoundOutput::new(config, assembly_label, t1, evidence)?;
        Ok(ProductionPower2RoundVectorCollectResult::Collected(output))
    }

    fn persist_status(&mut self, status: &PrimeFieldMpcPhaseDriverStatus) -> Result<(), DkgError> {
        self.cursor_log
            .persist_phase_cursor(&PrimeFieldMpcPhaseCursor::from_driver_status(status))
    }

    fn collect_or_recover_broadcast_vec_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let label_hash = power2round_label_hash(label);
        if self.has_accepted_broadcast_vec_phase(kind, phase, label_hash)? {
            let values = self
                .runtime
                .state
                .collect_broadcast_phase_vec_from_wire_log(
                    &self.runtime.wire_log,
                    kind,
                    phase,
                    label,
                )?;
            let status = PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind,
                phase,
                label_hash,
                senders: values.iter().map(|(party, _)| *party).collect(),
            };
            self.persist_status(&status)?;
            return Ok((status, values));
        }
        let (status, values) = self
            .runtime
            .drive_collect_broadcast_phase_vec(kind, phase, label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    fn collect_or_recover_directed_vec_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let label_hash = power2round_label_hash(label);
        if self.has_accepted_directed_vec_phase(receiver, kind, phase, label_hash)? {
            let values = self
                .runtime
                .state
                .collect_directed_phase_vec_from_wire_log(
                    &self.runtime.wire_log,
                    receiver,
                    kind,
                    phase,
                    label,
                )?;
            let status = PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: Some(receiver),
                kind,
                phase,
                label_hash,
                senders: values.iter().map(|(party, _)| *party).collect(),
            };
            self.persist_status(&status)?;
            return Ok((status, values));
        }
        let (status, values) = self
            .runtime
            .drive_collect_directed_phase_vec(receiver, kind, phase, label)?;
        self.persist_status(&status)?;
        Ok((status, values))
    }

    fn has_accepted_broadcast_vec_phase(
        &self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label_hash: [u8; 32],
    ) -> Result<bool, DkgError> {
        for record in self.runtime.wire_log.wire_records() {
            let key = wire_message_replay_key(record)?;
            if key.direction == PrimeFieldMpcWireDirection::AcceptedBroadcast
                && key.round_kind == kind
                && key.phase == phase
                && key.receiver.is_none()
                && key.label_hash == label_hash
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn has_accepted_directed_vec_phase(
        &self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label_hash: [u8; 32],
    ) -> Result<bool, DkgError> {
        for record in self.runtime.wire_log.wire_records() {
            let key = wire_message_replay_key(record)?;
            if key.direction == PrimeFieldMpcWireDirection::AcceptedPrivate
                && key.round_kind == kind
                && key.phase == phase
                && key.receiver == Some(receiver)
                && key.label_hash == label_hash
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Normal-build vector-only prime-field MPC runtime boundary.
///
/// This wrapper is intentionally not an implementation of
/// `ItMpcPrimeFieldBackend`: it exposes only app-driven vector phases and
/// derives release evidence from durable wire logs. Scalar compatibility
/// defaults remain confined to the trait/test harnesses and cannot satisfy this
/// runtime's release gate.
#[derive(Clone, Debug)]
pub struct ProductionVectorPrimeFieldMpcRuntime<T, L, C> {
    inner: CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C>,
}

/// Transcript-bound identifier for a production vector share.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionShareVectorId {
    /// Hash of the transcript label that produced this handle.
    pub label_hash: [u8; 32],
    /// Number of field lanes carried by the handle.
    pub lane_count: usize,
}

impl fmt::Debug for ProductionShareVectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionShareVectorId")
            .field("label_hash", &self.label_hash)
            .field("lane_count", &self.lane_count)
            .finish()
    }
}

/// One party's local lanes for a production vector secret share.
///
/// This is the normal-build handle type for Phase 3 vector IT-MPC. It is not
/// an `ItMpcPrimeFieldBackend` scalar compatibility share, and it carries only
/// the local party's Shamir evaluations. The underlying lanes are intentionally
/// redacted from `Debug` and zeroized on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionShareVec {
    id: ProductionShareVectorId,
    holder: PartyId,
    point: u32,
    lanes: Vec<Coeff>,
}

impl ProductionShareVec {
    pub(crate) fn new(
        holder: PartyId,
        point: u32,
        label: &Power2RoundTranscriptLabel,
        lanes: Vec<Coeff>,
    ) -> Result<Self, DkgError> {
        if lanes.is_empty() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(Self {
            id: ProductionShareVectorId {
                label_hash: power2round_label_hash(label),
                lane_count: lanes.len(),
            },
            holder,
            point,
            lanes,
        })
    }

    /// Returns the transcript-bound identifier.
    pub fn id(&self) -> ProductionShareVectorId {
        self.id
    }

    /// Returns the local holder.
    pub fn holder(&self) -> PartyId {
        self.holder
    }

    /// Returns the local Shamir interpolation point.
    pub fn point(&self) -> u32 {
        self.point
    }

    /// Returns the vector lane count.
    pub fn len(&self) -> usize {
        self.lanes.len()
    }

    /// Returns true when the vector has no lanes.
    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }

    pub(crate) fn lanes(&self) -> &[Coeff] {
        &self.lanes
    }
}

impl fmt::Debug for ProductionShareVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionShareVec")
            .field("id", &self.id)
            .field("holder", &self.holder)
            .field("point", &self.point)
            .field("lanes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ProductionShareVec {
    fn zeroize(&mut self) {
        self.lanes.zeroize();
    }
}

impl Drop for ProductionShareVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// One party's local lanes for a production vector bit share.
///
/// The wrapped lanes are field shares of values that have been or will be
/// checked as bits by the production vector runtime.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionBitShareVec {
    share: ProductionShareVec,
}

impl ProductionBitShareVec {
    fn new(share: ProductionShareVec) -> Self {
        Self { share }
    }

    /// Builds a bit-vector handle from a share handle after a runtime circuit
    /// has produced a value that is already constrained as bits.
    pub fn from_certified_share(share: ProductionShareVec) -> Self {
        Self::new(share)
    }

    /// Returns the transcript-bound identifier.
    pub fn id(&self) -> ProductionShareVectorId {
        self.share.id()
    }

    /// Returns the local holder.
    pub fn holder(&self) -> PartyId {
        self.share.holder()
    }

    /// Returns the local Shamir interpolation point.
    pub fn point(&self) -> u32 {
        self.share.point()
    }

    /// Returns the vector lane count.
    pub fn len(&self) -> usize {
        self.share.len()
    }

    /// Returns true when the vector has no lanes.
    pub fn is_empty(&self) -> bool {
        self.share.is_empty()
    }

    pub(crate) fn share(&self) -> &ProductionShareVec {
        &self.share
    }

    /// Returns the underlying share handle for callers that need to feed
    /// certified bit vectors into generic share-vector operations.
    pub fn certified_share(&self) -> &ProductionShareVec {
        &self.share
    }
}

impl fmt::Debug for ProductionBitShareVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionBitShareVec")
            .field("id", &self.id())
            .field("holder", &self.holder())
            .field("point", &self.point())
            .field("lanes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ProductionBitShareVec {
    fn zeroize(&mut self) {
        self.share.zeroize();
    }
}

/// App-supplied entropy for production vector Shamir resharing.
///
/// The crate does not invent production randomness here. Embedding
/// applications provide entropy bound to the supplied transcript label, while
/// tests can use deterministic implementations.
pub trait ProductionVectorItMpcEntropy {
    /// Returns `count` field coefficients in `[0, q)`.
    fn fill_field_coefficients<P: MlDsaParams>(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        count: usize,
    ) -> Result<Vec<Coeff>, DkgError>;

    /// Returns `count` random bits as `0/1` field coefficients.
    fn fill_bits<P: MlDsaParams>(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        count: usize,
    ) -> Result<Vec<Coeff>, DkgError> {
        Ok(self
            .fill_field_coefficients::<P>(label, count)?
            .into_iter()
            .map(|value| reduce_mod_q::<P>(value) & 1)
            .collect())
    }
}

/// Collection result for app-driven production vector IT-MPC operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProductionVectorItMpcCollectResult<T> {
    /// More transport messages are needed before collection can complete.
    Waiting(PrimeFieldMpcPhaseDriverStatus),
    /// The vector operation completed and produced a local handle/output.
    Collected {
        /// Driver status written to the durable cursor log.
        status: PrimeFieldMpcPhaseDriverStatus,
        /// Collected output.
        value: T,
    },
}

/// Public-comparison direction for production handle-level bit circuits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionPublicComparisonKind {
    /// Compute private bit `[x < C]`.
    LessThan,
    /// Compute private bit `[x > C]`.
    GreaterThan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionPublicComparisonPendingKind {
    CandidateAndEquality,
    UpdateEquality,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionPublicComparisonPrefixSegment {
    generate: ProductionBitShareVec,
    equal: ProductionBitShareVec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionPublicComparisonPrefixPending {
    pair_count: usize,
    next_segments: Vec<ProductionPublicComparisonPrefixSegment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionPublicComparisonPrefixState {
    segments: Vec<ProductionPublicComparisonPrefixSegment>,
    layer_idx: usize,
    pending: Option<ProductionPublicComparisonPrefixPending>,
    lane_count: usize,
}

/// Driver state for a private comparison of secret bit vectors with a public
/// constant.
///
/// This state advances through app-driven vector multiplication layers. It does
/// not open the comparison input bits or result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPublicComparisonVecState {
    kind: ProductionPublicComparisonKind,
    bits_by_bit_le: Vec<ProductionBitShareVec>,
    constant: u32,
    public_bits_by_bit_le: Option<Vec<Vec<bool>>>,
    label: Power2RoundTranscriptLabel,
    phase: PrimeFieldMpcPhase,
    bit_idx: isize,
    eq: ProductionBitShareVec,
    comparison: ProductionBitShareVec,
    pending: Option<ProductionPublicComparisonPendingKind>,
    prefix: Option<ProductionPublicComparisonPrefixState>,
    done: bool,
}

impl ProductionPublicComparisonVecState {
    /// Returns true when the comparison result is available.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Returns the private comparison result when complete.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.done.then_some(&self.comparison)
    }

    /// Returns the transcript label that owns this comparison state.
    pub fn label(&self) -> &Power2RoundTranscriptLabel {
        &self.label
    }
}

/// Driver state for private `sum(bits) <= threshold` over vector lanes.
///
/// The state builds a private binary accumulator using ripple-carry addition of
/// secret bit vectors, then compares the accumulator to the public threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionBitSumLeqPublicVecState {
    bits: Vec<ProductionBitShareVec>,
    threshold: u32,
    label: Power2RoundTranscriptLabel,
    phase: PrimeFieldMpcPhase,
    accumulator_bits_le: Vec<ProductionBitShareVec>,
    input_idx: usize,
    bit_idx: usize,
    carry: Option<ProductionBitShareVec>,
    pending_carry_and: bool,
    fast: Option<ProductionBitSumFastReducerState>,
    comparison: Option<ProductionPublicComparisonVecState>,
    result: Option<ProductionBitShareVec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProductionCanonicalLtQPending {
    TreeLayer {
        low_pair_count: usize,
        high_pair_count: usize,
        low_remainder: Option<ProductionBitShareVec>,
        high_remainder: Option<ProductionBitShareVec>,
    },
    FinalInvalid,
}

/// Specialized private `[x < q]` state for 23-bit ML-DSA canonical values.
///
/// ML-DSA has `q = 2^23 - 8191`. For a 23-bit value, the only invalid
/// representatives are `q..2^23-1`, equivalently:
///
/// ```text
/// high bits 13..22 are all one AND low bits 0..12 are nonzero.
/// ```
///
/// This avoids a generic public comparator for the canonicality check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionCanonicalLtQVecState {
    low_any_terms: Vec<ProductionBitShareVec>,
    high_all_terms: Vec<ProductionBitShareVec>,
    label: Power2RoundTranscriptLabel,
    phase: PrimeFieldMpcPhase,
    layer_idx: usize,
    pending: Option<ProductionCanonicalLtQPending>,
    result: Option<ProductionBitShareVec>,
}

impl ProductionCanonicalLtQVecState {
    /// Returns true when `[x < q]` is available.
    pub fn is_done(&self) -> bool {
        self.result.is_some()
    }

    /// Returns the private `[x < q]` bit.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.result.as_ref()
    }
}

impl ProductionBitSumLeqPublicVecState {
    /// Returns true when the private threshold predicate result is available.
    pub fn is_done(&self) -> bool {
        self.result.is_some()
    }

    /// Returns the private predicate bit `[sum(bits) <= threshold]`.
    pub fn result(&self) -> Option<&ProductionBitShareVec> {
        self.result.as_ref()
    }

    /// Returns the private accumulator bits once all additions have completed.
    pub fn accumulator_bits_le(&self) -> &[ProductionBitShareVec] {
        &self.accumulator_bits_le
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProductionBitSumFastPending {
    CsaAb {
        triples: Vec<usize>,
        next_columns: Vec<Vec<ProductionBitShareVec>>,
        a: ProductionBitShareVec,
        b: ProductionBitShareVec,
        c: ProductionBitShareVec,
    },
    CsaAxc {
        triples: Vec<usize>,
        next_columns: Vec<Vec<ProductionBitShareVec>>,
        c: ProductionBitShareVec,
        ab: ProductionBitShareVec,
        axorb: ProductionBitShareVec,
        driven: bool,
    },
    RippleHalfAnd {
        column: usize,
        left: ProductionBitShareVec,
        right: ProductionBitShareVec,
    },
    RippleFullAb {
        column: usize,
        a: ProductionBitShareVec,
        b: ProductionBitShareVec,
        c: ProductionBitShareVec,
    },
    RippleFullAxc {
        column: usize,
        c: ProductionBitShareVec,
        ab: ProductionBitShareVec,
        axorb: ProductionBitShareVec,
        driven: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionBitSumFastReducerState {
    columns: Vec<Vec<ProductionBitShareVec>>,
    lane_count: usize,
    layer_idx: usize,
    pending: Option<ProductionBitSumFastPending>,
    ripple_column: usize,
    ripple_carry: Option<ProductionBitShareVec>,
    normal_bits_le: Vec<ProductionBitShareVec>,
    normal_width: usize,
}

fn bit_width_for_public_sum(max_sum: usize) -> usize {
    let mut width = 1usize;
    let mut capacity = 2usize;
    while capacity <= max_sum {
        width += 1;
        capacity <<= 1;
    }
    width
}

impl<T, L, C> ProductionVectorPrimeFieldMpcRuntime<T, L, C>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
    C: PrimeFieldMpcPhaseCursorLog,
{
    /// Creates a vector-only production runtime wrapper.
    pub fn new(inner: CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C>) -> Self {
        Self { inner }
    }

    /// Returns the wrapped cursor-aware runtime.
    pub fn inner(&self) -> &CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C> {
        &self.inner
    }

    /// Returns the mutable wrapped cursor-aware runtime.
    ///
    /// This is available only for tests and scaffold/dev builds. Normal
    /// production code must drive concrete operations through this wrapper's
    /// typed vector methods so release evidence cannot be assembled through a
    /// lower-level runtime escape hatch.
    #[cfg(any(test, feature = "scaffold-dev"))]
    pub fn inner_mut(&mut self) -> &mut CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C> {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the inner runtime.
    pub fn into_inner(self) -> CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C> {
        self.inner
    }

    /// Returns the local party.
    pub fn local_party(&self) -> PartyId {
        self.inner.runtime().local_party()
    }

    fn local_point<P: MlDsaParams>(&self, config: &DkgConfig) -> Result<u32, DkgError> {
        config.interpolation_point::<P>(self.local_party())
    }

    fn validate_share_vec_context<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        share: &ProductionShareVec,
    ) -> Result<(), DkgError> {
        if share.holder != self.local_party() || share.point != self.local_point::<P>(config)? {
            return Err(DkgError::Backend(
                "production vector share belongs to another party",
            ));
        }
        if share.lanes.is_empty() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(())
    }

    fn ensure_same_share_shape(
        &self,
        left: &ProductionShareVec,
        right: &ProductionShareVec,
    ) -> Result<(), DkgError> {
        if left.holder != right.holder || left.point != right.point || left.len() != right.len() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(())
    }

    /// Builds a production share handle from this party's local lanes.
    pub fn share_vec_from_local_lanes<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        lanes: Vec<Coeff>,
    ) -> Result<ProductionShareVec, DkgError> {
        ProductionShareVec::new(
            self.local_party(),
            self.local_point::<P>(config)?,
            label,
            lanes.into_iter().map(reduce_mod_q::<P>).collect::<Vec<_>>(),
        )
    }

    /// Builds a production bit-share handle from this party's local lanes.
    pub fn bit_share_vec_from_local_lanes<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        lanes: Vec<Coeff>,
    ) -> Result<ProductionBitShareVec, DkgError> {
        Ok(ProductionBitShareVec::new(
            self.share_vec_from_local_lanes::<P>(config, label, lanes)?,
        ))
    }

    /// Reshapes a contiguous private share-vector lane range into a new
    /// transcript-bound handle without opening it.
    pub fn slice_share_vec_lanes_for_runtime_chunk<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        range: core::ops::Range<usize>,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        if range.start >= range.end || range.end > share.len() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        self.share_vec_from_local_lanes::<P>(config, label, share.lanes()[range].to_vec())
    }

    /// Reshapes a contiguous private bit-share-vector lane range into a new
    /// transcript-bound handle without opening it.
    pub fn slice_bit_share_vec_lanes_for_runtime_chunk<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        range: core::ops::Range<usize>,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        Ok(ProductionBitShareVec::new(
            self.slice_share_vec_lanes_for_runtime_chunk::<P>(config, bits.share(), range, label)?,
        ))
    }

    /// Builds a local degree-zero public constant vector handle.
    pub fn public_const_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
        lane_count: usize,
    ) -> Result<ProductionShareVec, DkgError> {
        self.share_vec_from_local_lanes::<P>(
            config,
            label,
            vec![reduce_mod_q::<P>(value); lane_count],
        )
    }

    /// Builds a local degree-zero public vector from public lane constants.
    pub fn public_lanes_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        lanes: &[Coeff],
    ) -> Result<ProductionShareVec, DkgError> {
        self.share_vec_from_local_lanes::<P>(
            config,
            label,
            lanes.iter().copied().map(reduce_mod_q::<P>).collect(),
        )
    }

    /// Builds a local degree-zero public bit vector handle.
    pub fn public_bit_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        value: bool,
        lane_count: usize,
    ) -> Result<ProductionBitShareVec, DkgError> {
        Ok(ProductionBitShareVec::new(
            self.public_const_share_vec::<P>(config, label, if value { 1 } else { 0 }, lane_count)?,
        ))
    }

    /// Local vector addition over Fq.
    pub fn add_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        left: &ProductionShareVec,
        right: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, left)?;
        self.validate_share_vec_context::<P>(config, right)?;
        self.ensure_same_share_shape(left, right)?;
        self.share_vec_from_local_lanes::<P>(
            config,
            label,
            left.lanes
                .iter()
                .zip(&right.lanes)
                .map(|(&x, &y)| reduce_mod_q::<P>(x + y))
                .collect(),
        )
    }

    /// Local vector subtraction over Fq.
    pub fn sub_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        left: &ProductionShareVec,
        right: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, left)?;
        self.validate_share_vec_context::<P>(config, right)?;
        self.ensure_same_share_shape(left, right)?;
        self.share_vec_from_local_lanes::<P>(
            config,
            label,
            left.lanes
                .iter()
                .zip(&right.lanes)
                .map(|(&x, &y)| reduce_mod_q::<P>(x - y))
                .collect(),
        )
    }

    /// Local vector multiplication by a public field constant.
    pub fn mul_public_const_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        constant: Coeff,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        let q = i64::from(P::Q);
        let constant = i64::from(reduce_mod_q::<P>(constant));
        self.share_vec_from_local_lanes::<P>(
            config,
            label,
            share
                .lanes
                .iter()
                .map(|&lane| (i64::from(lane) * constant).rem_euclid(q) as Coeff)
                .collect(),
        )
    }

    /// Local lane-wise multiplication by public field constants.
    pub fn mul_public_lanes_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        constants: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        if share.len() != constants.len() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let q = i64::from(P::Q);
        self.share_vec_from_local_lanes::<P>(
            config,
            label,
            share
                .lanes
                .iter()
                .zip(constants.iter().copied())
                .map(|(&lane, constant)| {
                    (i64::from(lane) * i64::from(reduce_mod_q::<P>(constant))).rem_euclid(q)
                        as Coeff
                })
                .collect(),
        )
    }

    /// Bitwise NOT for field-backed secret bit vectors.
    pub fn bit_not_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, bits.share())?;
        Ok(ProductionBitShareVec::new(
            self.share_vec_from_local_lanes::<P>(
                config,
                label,
                bits.share()
                    .lanes()
                    .iter()
                    .map(|&lane| reduce_mod_q::<P>(1 - lane))
                    .collect(),
            )?,
        ))
    }

    /// Applies the public ML-DSA challenge-polynomial multiplication to a
    /// flattened `PolyVecL` share.
    ///
    /// This is a local linear operation over Shamir shares. It does not open
    /// the share and does not require an MPC multiplication round because the
    /// challenge polynomial is public. The input and output lane order is
    /// polynomial-major: `poly_0[0..256], poly_1[0..256], ...`.
    pub fn mul_public_challenge_polyvec_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        ctilde: &[u8],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        if ctilde.len() != P::CTILDE_LEN || share.len() != P::L * P::N {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let challenge = talus_core::sample_in_ball::<P>(ctilde);
        let mut out = Vec::with_capacity(share.len());
        for poly_idx in 0..P::L {
            let input = &share.lanes()[poly_idx * P::N..(poly_idx + 1) * P::N];
            let mut coeffs = [0; 256];
            coeffs.copy_from_slice(input);
            let poly = talus_core::mul_challenge_poly::<P>(&challenge, &Poly::from_coeffs(coeffs));
            out.extend_from_slice(poly.coeffs());
        }
        self.share_vec_from_local_lanes::<P>(config, label, out)
    }

    /// Applies the public ML-DSA challenge-polynomial multiplication to a
    /// flattened `PolyVecK` share.
    ///
    /// This is used by optimized strict signing for precomputed `[A*s1]`
    /// handles. It is a local linear operation over Shamir shares and does not
    /// open the share or require an MPC multiplication round.
    pub fn mul_public_challenge_polyveck_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        ctilde: &[u8],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        if ctilde.len() != P::CTILDE_LEN || share.len() != P::K * P::N {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let challenge = talus_core::sample_in_ball::<P>(ctilde);
        let mut out = Vec::with_capacity(share.len());
        for poly_idx in 0..P::K {
            let input = &share.lanes()[poly_idx * P::N..(poly_idx + 1) * P::N];
            let mut coeffs = [0; 256];
            coeffs.copy_from_slice(input);
            let poly = talus_core::mul_challenge_poly::<P>(&challenge, &Poly::from_coeffs(coeffs));
            out.extend_from_slice(poly.coeffs());
        }
        self.share_vec_from_local_lanes::<P>(config, label, out)
    }

    /// Applies public matrix expansion `A = ExpandA(rho)` to a flattened
    /// `PolyVecL` share.
    ///
    /// This is a local linear operation over Shamir shares and returns a
    /// flattened `PolyVecK` share. It does not expose the private lanes.
    pub fn az_from_rho_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        rho: &[u8; 32],
        share: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        if share.len() != P::L * P::N {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let mut polys = Vec::with_capacity(P::L);
        for poly_idx in 0..P::L {
            let input = &share.lanes()[poly_idx * P::N..(poly_idx + 1) * P::N];
            let mut coeffs = [0; 256];
            coeffs.copy_from_slice(input);
            polys.push(Poly::from_coeffs(coeffs));
        }
        let az = talus_core::az_from_rho::<P>(rho, &PolyVec::new(polys))
            .map_err(|_| DkgError::Backend("public A*z transform failed"))?;
        let mut out = Vec::with_capacity(P::K * P::N);
        for poly in az.polys() {
            out.extend_from_slice(poly.coeffs());
        }
        self.share_vec_from_local_lanes::<P>(config, label, out)
    }

    /// Selects lane-wise between two private bit vectors using public selector
    /// lanes. `selector_lanes[idx] == 1` chooses `when_true[idx]`; zero chooses
    /// `when_false[idx]`.
    pub fn public_lane_select_bit_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        when_true: &ProductionBitShareVec,
        when_false: &ProductionBitShareVec,
        selector_lanes: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, when_true.share())?;
        self.validate_share_vec_context::<P>(config, when_false.share())?;
        self.ensure_same_share_shape(when_true.share(), when_false.share())?;
        if when_true.len() != selector_lanes.len()
            || selector_lanes.iter().any(|&lane| lane != 0 && lane != 1)
        {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let selected_true = self.mul_public_lanes_share_vec::<P>(
            config,
            when_true.share(),
            selector_lanes,
            &label.child("selected_true"),
        )?;
        let inverse = selector_lanes
            .iter()
            .map(|&lane| 1 - lane)
            .collect::<Vec<_>>();
        let selected_false = self.mul_public_lanes_share_vec::<P>(
            config,
            when_false.share(),
            &inverse,
            &label.child("selected_false"),
        )?;
        Ok(ProductionBitShareVec::new(self.add_share_vec::<P>(
            config,
            &selected_true,
            &selected_false,
            &label.child("selected"),
        )?))
    }

    /// Splits a private bit vector into one-lane bit vectors without opening.
    ///
    /// This is used by threshold circuits that need to sum across all lanes
    /// rather than lane-wise across a set of same-shaped vectors.
    pub fn split_bit_share_vec_lanes<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<ProductionBitShareVec>, DkgError> {
        self.validate_share_vec_context::<P>(config, bits.share())?;
        bits.share()
            .lanes()
            .iter()
            .enumerate()
            .map(|(idx, &lane)| {
                self.bit_share_vec_from_local_lanes::<P>(
                    config,
                    &label.child(format!("lane_{idx}")),
                    vec![lane],
                )
            })
            .collect()
    }

    /// Transposes same-shaped private bit vectors into per-lane bit vectors.
    ///
    /// Input order is `candidate -> coefficient lane`; output order is
    /// `coefficient lane -> candidate`. This is a handle reshape only and does
    /// not open the private bits. It lets threshold circuits run once with
    /// candidates as vector lanes instead of once per candidate.
    pub fn transpose_bit_share_vec_lanes_for_runtime_batch<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<ProductionBitShareVec>, DkgError> {
        let first = bits.first().ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        self.validate_share_vec_context::<P>(config, first.share())?;
        let lane_count = first.len();
        for bit in bits {
            self.validate_share_vec_context::<P>(config, bit.share())?;
            self.ensure_same_share_shape(first.share(), bit.share())?;
        }
        (0..lane_count)
            .map(|lane_idx| {
                let lanes = bits
                    .iter()
                    .map(|bit| bit.share().lanes()[lane_idx])
                    .collect::<Vec<_>>();
                self.bit_share_vec_from_local_lanes::<P>(
                    config,
                    &label.child(format!("lane_{lane_idx}")),
                    lanes,
                )
            })
            .collect()
    }

    /// Repeats a one-lane private bit share to a vector of `lane_count` lanes.
    ///
    /// This lets selection bits multiply whole private response or hint
    /// vectors without opening the selected index.
    pub fn repeat_one_lane_bit_share_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bit: &ProductionBitShareVec,
        lane_count: usize,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, bit.share())?;
        if bit.len() != 1 || lane_count == 0 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(ProductionBitShareVec::new(
            self.share_vec_from_local_lanes::<P>(
                config,
                label,
                vec![bit.share().lanes()[0]; lane_count],
            )?,
        ))
    }

    /// Sends a vector bitwise-AND multiplication layer.
    pub fn drive_bit_and_vec<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        left: &ProductionBitShareVec,
        right: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        self.drive_bit_and_vec_with_phase::<P, E>(
            config,
            left,
            right,
            label,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            entropy,
        )
    }

    fn drive_bit_and_vec_with_phase<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        left: &ProductionBitShareVec,
        right: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        self.drive_mul_vec_degree_reduction_with_phase::<P, E>(
            config,
            left.share(),
            right.share(),
            &label.child("bit_and"),
            phase,
            entropy,
        )
    }

    fn drive_mul_vec_degree_reduction_with_phase<
        P: MlDsaParams,
        E: ProductionVectorItMpcEntropy,
    >(
        &mut self,
        config: &DkgConfig,
        left: &ProductionShareVec,
        right: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        self.validate_share_vec_context::<P>(config, left)?;
        self.validate_share_vec_context::<P>(config, right)?;
        self.ensure_same_share_shape(left, right)?;

        let points = config
            .interpolation_points::<P>()?
            .into_iter()
            .map(|(_, point)| point)
            .collect::<Vec<_>>();
        let lambdas = lagrange_coefficients_at_zero::<P>(&points)
            .map_err(|_| DkgError::Backend("degree-reduction coefficients failed"))?;
        let local_index = config
            .parties
            .iter()
            .position(|party| *party == self.local_party())
            .ok_or(DkgError::UnknownParty(self.local_party()))?;
        let lambda = i64::from(lambdas[local_index]);
        let q = i64::from(P::Q);
        let weighted = left
            .lanes
            .iter()
            .zip(&right.lanes)
            .map(|(&x, &y)| {
                let product = (i64::from(x) * i64::from(y)).rem_euclid(q);
                (product * lambda).rem_euclid(q) as Coeff
            })
            .collect::<Vec<_>>();

        let degree = usize::from(config.threshold.saturating_sub(1));
        let receivers = config.interpolation_points::<P>()?;
        let mut shares_by_receiver = receivers
            .iter()
            .map(|(receiver, _)| (*receiver, Vec::with_capacity(weighted.len())))
            .collect::<Vec<_>>();
        for (lane_idx, &secret) in weighted.iter().enumerate() {
            let coeff_label = label.child(format!(
                "degree_reduce/dealer_{}/lane_{lane_idx}",
                self.local_party().0
            ));
            let mut coefficients = Vec::with_capacity(degree + 1);
            coefficients.push(secret);
            coefficients.extend(entropy.fill_field_coefficients::<P>(&coeff_label, degree)?);
            for ((_, receiver_point), (_, shares_for_receiver)) in
                receivers.iter().zip(shares_by_receiver.iter_mut())
            {
                shares_for_receiver.push(evaluate_shamir_polynomial::<P>(
                    &coefficients,
                    *receiver_point,
                )?);
            }
        }
        for (receiver, shares_for_receiver) in shares_by_receiver {
            self.send_mul_layer_vec_with_phase(receiver, phase, label, &shares_for_receiver)?;
        }
        Ok(())
    }

    fn collect_mul_vec_degree_reduction_with_phase<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, DkgError> {
        let receiver = self.local_party();
        let (status, values) = self.collect_mul_layer_vec_with_phase(receiver, phase, label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingPrivate { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let lane_count = uniform_collected_vector_lane_count(&values)?;
        let mut lanes = vec![0; lane_count];
        for (_sender, sender_lanes) in values {
            for (out, value) in lanes.iter_mut().zip(sender_lanes) {
                *out = reduce_mod_q::<P>(*out + value);
            }
        }
        let share = self.share_vec_from_local_lanes::<P>(config, label, lanes)?;
        Ok(ProductionVectorItMpcCollectResult::Collected {
            status,
            value: share,
        })
    }

    fn collect_bit_and_vec_with_phase<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionBitShareVec>, DkgError> {
        match self.collect_mul_vec_degree_reduction_with_phase::<P>(
            config,
            &label.child("bit_and"),
            phase,
        )? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => {
                Ok(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: ProductionBitShareVec::new(value),
                })
            }
        }
    }

    /// Collects a vector bitwise-AND result.
    pub fn collect_bit_and_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionBitShareVec>, DkgError> {
        match self.collect_mul_vec_degree_reduction::<P>(config, &label.child("bit_and"))? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => {
                Ok(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: ProductionBitShareVec::new(value),
                })
            }
        }
    }

    /// Initializes a private `[x < constant]` comparison over little-endian
    /// secret bit vectors.
    pub fn start_lt_public_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit_le: &[ProductionBitShareVec],
        constant: u32,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        self.start_public_comparison_vec::<P>(
            config,
            ProductionPublicComparisonKind::LessThan,
            bits_by_bit_le,
            constant,
            label,
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
        )
    }

    /// Initializes a private `[x > constant]` comparison over little-endian
    /// secret bit vectors.
    pub fn start_gt_public_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit_le: &[ProductionBitShareVec],
        constant: u32,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        self.start_public_comparison_vec::<P>(
            config,
            ProductionPublicComparisonKind::GreaterThan,
            bits_by_bit_le,
            constant,
            label,
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
        )
    }

    /// Initializes specialized private `[x < q]` for a 23-bit canonical
    /// ML-DSA representative.
    pub fn start_canonical_lt_q_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit_le: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
    ) -> Result<ProductionCanonicalLtQVecState, DkgError> {
        if bits_by_bit_le.len() != 23 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let first = bits_by_bit_le
            .first()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        self.validate_share_vec_context::<P>(config, first.share())?;
        for bits in bits_by_bit_le {
            self.validate_share_vec_context::<P>(config, bits.share())?;
            self.ensure_same_share_shape(first.share(), bits.share())?;
        }
        Ok(ProductionCanonicalLtQVecState {
            low_any_terms: bits_by_bit_le[..13].to_vec(),
            high_all_terms: bits_by_bit_le[13..23].to_vec(),
            label: label.clone(),
            phase,
            layer_idx: 0,
            pending: None,
            result: None,
        })
    }

    /// Initializes a private lane-wise `[x > C_lane]` comparison over
    /// little-endian secret bit vectors and public per-lane constants.
    pub fn start_gt_public_lanes_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit_le: &[ProductionBitShareVec],
        constants: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        self.start_public_comparison_lanes_vec::<P>(
            config,
            ProductionPublicComparisonKind::GreaterThan,
            bits_by_bit_le,
            constants,
            label,
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
        )
    }

    /// Initializes a private lane-wise `[x < C_lane]` comparison over
    /// little-endian secret bit vectors and public per-lane constants.
    pub fn start_lt_public_lanes_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit_le: &[ProductionBitShareVec],
        constants: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        self.start_public_comparison_lanes_vec::<P>(
            config,
            ProductionPublicComparisonKind::LessThan,
            bits_by_bit_le,
            constants,
            label,
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
        )
    }

    /// Initializes a preprocessing CarryCompare private lane-wise `[x > C]`
    /// comparison over little-endian secret bit vectors and public per-lane
    /// constants.
    pub fn start_preprocessing_carry_compare_gt_public_lanes_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits_by_bit_le: &[ProductionBitShareVec],
        constants: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        self.start_public_comparison_lanes_vec::<P>(
            config,
            ProductionPublicComparisonKind::GreaterThan,
            bits_by_bit_le,
            constants,
            label,
            PrimeFieldMpcPhase::PreprocessingCarryCompare,
        )
    }

    fn start_public_comparison_lanes_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        kind: ProductionPublicComparisonKind,
        bits_by_bit_le: &[ProductionBitShareVec],
        constants: &[Coeff],
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        let first = bits_by_bit_le
            .first()
            .ok_or(DkgError::Backend("empty production comparison input"))?;
        self.validate_share_vec_context::<P>(config, first.share())?;
        if constants.len() != first.len()
            || constants
                .iter()
                .any(|&constant| constant < 0 || constant >= P::Q)
        {
            return Err(DkgError::Power2RoundCanonicalityFailure);
        }
        for bits in bits_by_bit_le {
            self.validate_share_vec_context::<P>(config, bits.share())?;
            self.ensure_same_share_shape(first.share(), bits.share())?;
        }
        let public_bits_by_bit_le = (0..bits_by_bit_le.len())
            .map(|bit_idx| {
                constants
                    .iter()
                    .map(|&constant| (((constant as u32) >> bit_idx) & 1) == 1)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let lane_count = first.len();
        let mut state = ProductionPublicComparisonVecState {
            kind,
            bits_by_bit_le: bits_by_bit_le.to_vec(),
            constant: 0,
            public_bits_by_bit_le: Some(public_bits_by_bit_le),
            label: label.clone(),
            phase,
            bit_idx: bits_by_bit_le.len() as isize - 1,
            eq: self.public_bit_share_vec::<P>(
                config,
                &label.child("eq_init"),
                true,
                lane_count,
            )?,
            comparison: self.public_bit_share_vec::<P>(
                config,
                &label.child("comparison_init"),
                false,
                lane_count,
            )?,
            pending: None,
            prefix: None,
            done: false,
        };
        self.initialize_public_comparison_prefix::<P>(config, &mut state)?;
        Ok(state)
    }

    fn start_public_comparison_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        kind: ProductionPublicComparisonKind,
        bits_by_bit_le: &[ProductionBitShareVec],
        constant: u32,
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
    ) -> Result<ProductionPublicComparisonVecState, DkgError> {
        let first = bits_by_bit_le
            .first()
            .ok_or(DkgError::Backend("empty production comparison input"))?;
        self.validate_share_vec_context::<P>(config, first.share())?;
        for bits in bits_by_bit_le {
            self.validate_share_vec_context::<P>(config, bits.share())?;
            self.ensure_same_share_shape(first.share(), bits.share())?;
        }
        let lane_count = first.len();
        let mut state = ProductionPublicComparisonVecState {
            kind,
            bits_by_bit_le: bits_by_bit_le.to_vec(),
            constant,
            public_bits_by_bit_le: None,
            label: label.clone(),
            phase,
            bit_idx: bits_by_bit_le.len() as isize - 1,
            eq: self.public_bit_share_vec::<P>(
                config,
                &label.child("eq_init"),
                true,
                lane_count,
            )?,
            comparison: self.public_bit_share_vec::<P>(
                config,
                &label.child("comparison_init"),
                false,
                lane_count,
            )?,
            pending: None,
            prefix: None,
            done: false,
        };
        self.initialize_public_comparison_prefix::<P>(config, &mut state)?;
        Ok(state)
    }

    fn initialize_public_comparison_prefix<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        state: &mut ProductionPublicComparisonVecState,
    ) -> Result<(), DkgError> {
        let lane_count = state.eq.len();
        let mut segments = Vec::with_capacity(state.bits_by_bit_le.len());
        for bit_idx in (0..state.bits_by_bit_le.len()).rev() {
            let generate = match self.comparison_candidate_condition::<P>(config, state, bit_idx)? {
                Some(condition) => condition,
                None => self.public_bit_share_vec::<P>(
                    config,
                    &state
                        .label
                        .child(format!("prefix_bit_{bit_idx}/generate_false")),
                    false,
                    lane_count,
                )?,
            };
            let equal = self.comparison_eq_condition::<P>(config, state, bit_idx)?;
            segments.push(ProductionPublicComparisonPrefixSegment { generate, equal });
        }
        state.prefix = Some(ProductionPublicComparisonPrefixState {
            segments,
            layer_idx: 0,
            pending: None,
            lane_count,
        });
        Ok(())
    }

    fn comparison_candidate_condition<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        state: &ProductionPublicComparisonVecState,
        bit_idx: usize,
    ) -> Result<Option<ProductionBitShareVec>, DkgError> {
        let xj = &state.bits_by_bit_le[bit_idx];
        if let Some(public_bits_by_bit_le) = &state.public_bits_by_bit_le {
            let c_bits = &public_bits_by_bit_le[bit_idx];
            let constants = match state.kind {
                ProductionPublicComparisonKind::LessThan => {
                    let not_x = self.bit_not_vec::<P>(
                        config,
                        xj,
                        &state.label.child(format!("not_x_{bit_idx}")),
                    )?;
                    return Ok(Some(ProductionBitShareVec::new(
                        self.mul_public_lanes_share_vec::<P>(
                            config,
                            not_x.share(),
                            &c_bits
                                .iter()
                                .map(|&bit| if bit { 1 } else { 0 })
                                .collect::<Vec<_>>(),
                            &state
                                .label
                                .child(format!("lt_public_lane_select_{bit_idx}")),
                        )?,
                    )));
                }
                ProductionPublicComparisonKind::GreaterThan => c_bits
                    .iter()
                    .map(|&bit| if bit { 0 } else { 1 })
                    .collect::<Vec<_>>(),
            };
            return Ok(Some(ProductionBitShareVec::new(
                self.mul_public_lanes_share_vec::<P>(
                    config,
                    xj.share(),
                    &constants,
                    &state
                        .label
                        .child(format!("gt_public_lane_select_{bit_idx}")),
                )?,
            )));
        }
        let cj = ((state.constant >> bit_idx) & 1) == 1;
        match (state.kind, cj) {
            (ProductionPublicComparisonKind::LessThan, true) => self
                .bit_not_vec::<P>(config, xj, &state.label.child(format!("not_x_{bit_idx}")))
                .map(Some),
            (ProductionPublicComparisonKind::LessThan, false) => Ok(None),
            (ProductionPublicComparisonKind::GreaterThan, false) => Ok(Some(xj.clone())),
            (ProductionPublicComparisonKind::GreaterThan, true) => Ok(None),
        }
    }

    fn comparison_eq_condition<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        state: &ProductionPublicComparisonVecState,
        bit_idx: usize,
    ) -> Result<ProductionBitShareVec, DkgError> {
        let xj = &state.bits_by_bit_le[bit_idx];
        if let Some(public_bits_by_bit_le) = &state.public_bits_by_bit_le {
            let c_bits = &public_bits_by_bit_le[bit_idx];
            let not_x = self.bit_not_vec::<P>(
                config,
                xj,
                &state.label.child(format!("eq_not_x_{bit_idx}")),
            )?;
            let x_when_one = self.mul_public_lanes_share_vec::<P>(
                config,
                xj.share(),
                &c_bits
                    .iter()
                    .map(|&bit| if bit { 1 } else { 0 })
                    .collect::<Vec<_>>(),
                &state.label.child(format!("eq_x_when_one_{bit_idx}")),
            )?;
            let not_x_when_zero = self.mul_public_lanes_share_vec::<P>(
                config,
                not_x.share(),
                &c_bits
                    .iter()
                    .map(|&bit| if bit { 0 } else { 1 })
                    .collect::<Vec<_>>(),
                &state.label.child(format!("eq_not_x_when_zero_{bit_idx}")),
            )?;
            return Ok(ProductionBitShareVec::new(self.add_share_vec::<P>(
                config,
                &x_when_one,
                &not_x_when_zero,
                &state.label.child(format!("eq_condition_{bit_idx}")),
            )?));
        }
        let cj = ((state.constant >> bit_idx) & 1) == 1;
        if cj {
            Ok(xj.clone())
        } else {
            self.bit_not_vec::<P>(
                config,
                xj,
                &state.label.child(format!("eq_not_x_{bit_idx}")),
            )
        }
    }

    fn drive_public_comparison_prefix_vec_step<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionPublicComparisonVecState,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let prefix = state
            .prefix
            .as_mut()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        if prefix.pending.is_some() {
            return Err(DkgError::Backend(
                "production prefix comparison step already pending",
            ));
        }
        if prefix.segments.len() == 1 {
            let segment = prefix
                .segments
                .first()
                .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
            state.comparison = segment.generate.clone();
            state.eq = segment.equal.clone();
            state.done = true;
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::AssertZero,
                phase: state.phase,
                label_hash: power2round_label_hash(&state.label),
                senders: Vec::new(),
            });
        }

        let pair_count = prefix.segments.len() / 2;
        let layer = state
            .label
            .child(format!("prefix_layer_{}", prefix.layer_idx));
        let mut left = Vec::with_capacity(pair_count * 2);
        let mut right = Vec::with_capacity(pair_count * 2);
        let mut next_segments = Vec::with_capacity(pair_count + prefix.segments.len() % 2);
        for pair in prefix.segments[..pair_count * 2].chunks_exact(2) {
            let high = &pair[0];
            let low = &pair[1];
            left.push(high.equal.clone());
            right.push(low.generate.clone());
            left.push(high.equal.clone());
            right.push(low.equal.clone());
        }
        if let Some(remainder) = prefix.segments.get(pair_count * 2) {
            next_segments.push(remainder.clone());
        }
        let packed_left =
            self.pack_bit_share_vecs::<P>(config, &left, &layer.child("packed_left"))?;
        let packed_right =
            self.pack_bit_share_vecs::<P>(config, &right, &layer.child("packed_right"))?;
        self.drive_bit_and_vec_with_phase::<P, E>(
            config,
            &packed_left,
            &packed_right,
            &layer,
            state.phase,
            entropy,
        )?;
        prefix.pending = Some(ProductionPublicComparisonPrefixPending {
            pair_count,
            next_segments,
        });
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: self.local_party(),
            kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: power2round_label_hash(&layer.child("bit_and").child("mul_layer")),
        })
    }

    fn collect_public_comparison_prefix_vec_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionPublicComparisonVecState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        if state.done {
            return Ok(ProductionVectorItMpcCollectResult::Collected {
                status: PrimeFieldMpcPhaseDriverStatus::Collected {
                    receiver: None,
                    kind: PrimeFieldMpcRoundKind::AssertZero,
                    phase: state.phase,
                    label_hash: power2round_label_hash(&state.label),
                    senders: Vec::new(),
                },
                value: (),
            });
        }
        let prefix = state
            .prefix
            .as_mut()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        let Some(pending) = prefix.pending.take() else {
            if prefix.segments.len() == 1 {
                let segment = prefix
                    .segments
                    .first()
                    .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
                state.comparison = segment.generate.clone();
                state.eq = segment.equal.clone();
                state.done = true;
                return Ok(ProductionVectorItMpcCollectResult::Collected {
                    status: PrimeFieldMpcPhaseDriverStatus::Collected {
                        receiver: None,
                        kind: PrimeFieldMpcRoundKind::AssertZero,
                        phase: state.phase,
                        label_hash: power2round_label_hash(&state.label),
                        senders: Vec::new(),
                    },
                    value: (),
                });
            }
            return Err(DkgError::Backend(
                "production prefix comparison has no pending step",
            ));
        };
        let layer = state
            .label
            .child(format!("prefix_layer_{}", prefix.layer_idx));
        let (status, packed_products) =
            match self.collect_bit_and_vec_with_phase::<P>(config, &layer, state.phase)? {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    prefix.pending = Some(pending);
                    return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                }
                ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
            };
        let products = self.unpack_bit_share_vec_chunks::<P>(
            config,
            &packed_products,
            prefix.lane_count,
            &layer.child("products"),
        )?;
        if products.len() != pending.pair_count * 2 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let mut next_segments =
            Vec::with_capacity(pending.pair_count + pending.next_segments.len());
        for pair_idx in 0..pending.pair_count {
            let high = &prefix.segments[pair_idx * 2];
            let high_equal_low_generate = &products[pair_idx * 2];
            let high_equal_low_equal = products[pair_idx * 2 + 1].clone();
            let generate = ProductionBitShareVec::new(self.add_share_vec::<P>(
                config,
                high.generate.share(),
                high_equal_low_generate.share(),
                &layer.child(format!("pair_{pair_idx}/generate")),
            )?);
            next_segments.push(ProductionPublicComparisonPrefixSegment {
                generate,
                equal: high_equal_low_equal,
            });
        }
        next_segments.extend(pending.next_segments);
        prefix.segments = next_segments;
        prefix.layer_idx += 1;
        if prefix.segments.len() == 1 {
            let segment = prefix
                .segments
                .first()
                .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
            state.comparison = segment.generate.clone();
            state.eq = segment.equal.clone();
            state.done = true;
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Drives one packed multiplication layer for specialized canonical
    /// `[x < q]`.
    pub fn drive_canonical_lt_q_vec_step<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionCanonicalLtQVecState,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        if state.result.is_some() {
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: state.phase,
                label_hash: power2round_label_hash(&state.label),
                senders: Vec::new(),
            });
        }
        if state.pending.is_some() {
            return Err(DkgError::Backend(
                "canonical lt-q specialization step already pending",
            ));
        }
        if state.low_any_terms.len() > 1 || state.high_all_terms.len() > 1 {
            let layer = state
                .label
                .child(format!("lt_q_special_tree_{}", state.layer_idx));
            let mut left = Vec::new();
            let mut right = Vec::new();
            let low_pair_count = state.low_any_terms.len() / 2;
            let high_pair_count = state.high_all_terms.len() / 2;
            for pair in state.low_any_terms[..low_pair_count * 2].chunks_exact(2) {
                left.push(pair[0].clone());
                right.push(pair[1].clone());
            }
            for pair in state.high_all_terms[..high_pair_count * 2].chunks_exact(2) {
                left.push(pair[0].clone());
                right.push(pair[1].clone());
            }
            let low_remainder = state.low_any_terms.get(low_pair_count * 2).cloned();
            let high_remainder = state.high_all_terms.get(high_pair_count * 2).cloned();
            let packed_left = self.pack_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &left,
                &layer.child("left"),
            )?;
            let packed_right = self.pack_bit_share_vecs_for_runtime_batch::<P>(
                config,
                &right,
                &layer.child("right"),
            )?;
            self.drive_bit_and_vec_with_phase::<P, E>(
                config,
                &packed_left,
                &packed_right,
                &layer,
                state.phase,
                entropy,
            )?;
            state.pending = Some(ProductionCanonicalLtQPending::TreeLayer {
                low_pair_count,
                high_pair_count,
                low_remainder,
                high_remainder,
            });
            return Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver: self.local_party(),
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                label_hash: power2round_label_hash(&layer.child("bit_and").child("mul_layer")),
            });
        }

        let low_any = state
            .low_any_terms
            .first()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        let high_all = state
            .high_all_terms
            .first()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        let label = state.label.child("lt_q_special_invalid");
        self.drive_bit_and_vec_with_phase::<P, E>(
            config,
            low_any,
            high_all,
            &label,
            state.phase,
            entropy,
        )?;
        state.pending = Some(ProductionCanonicalLtQPending::FinalInvalid);
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: self.local_party(),
            kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: power2round_label_hash(&label.child("bit_and").child("mul_layer")),
        })
    }

    /// Collects one packed multiplication layer for specialized canonical
    /// `[x < q]`.
    pub fn collect_canonical_lt_q_vec_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionCanonicalLtQVecState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        if state.result.is_some() {
            return Ok(ProductionVectorItMpcCollectResult::Collected {
                status: PrimeFieldMpcPhaseDriverStatus::Collected {
                    receiver: None,
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    phase: state.phase,
                    label_hash: power2round_label_hash(&state.label),
                    senders: Vec::new(),
                },
                value: (),
            });
        }
        let pending = state
            .pending
            .take()
            .ok_or(DkgError::Power2RoundCanonicalBitsRequired)?;
        let label = match &pending {
            ProductionCanonicalLtQPending::TreeLayer { .. } => state
                .label
                .child(format!("lt_q_special_tree_{}", state.layer_idx)),
            ProductionCanonicalLtQPending::FinalInvalid => {
                state.label.child("lt_q_special_invalid")
            }
        };
        let (status, packed_products) =
            match self.collect_bit_and_vec_with_phase::<P>(config, &label, state.phase)? {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    state.pending = Some(pending);
                    return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                }
                ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
            };
        match pending {
            ProductionCanonicalLtQPending::TreeLayer {
                low_pair_count,
                high_pair_count,
                low_remainder,
                high_remainder,
            } => {
                let products = self.unpack_bit_share_vec_runtime_batch::<P>(
                    config,
                    &packed_products,
                    state
                        .low_any_terms
                        .first()
                        .or_else(|| state.high_all_terms.first())
                        .ok_or(DkgError::Power2RoundMaskShapeMismatch)?
                        .len(),
                    &label.child("products"),
                )?;
                if products.len() != low_pair_count + high_pair_count {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
                let mut next_low =
                    Vec::with_capacity(low_pair_count + usize::from(low_remainder.is_some()));
                for pair_idx in 0..low_pair_count {
                    let left = &state.low_any_terms[pair_idx * 2];
                    let right = &state.low_any_terms[pair_idx * 2 + 1];
                    next_low.push(self.bit_or_from_and_vec::<P>(
                        config,
                        left,
                        right,
                        &products[pair_idx],
                        &label.child(format!("low_or_{pair_idx}")),
                    )?);
                }
                if let Some(bit) = low_remainder {
                    next_low.push(bit);
                }
                let mut next_high =
                    Vec::with_capacity(high_pair_count + usize::from(high_remainder.is_some()));
                for pair_idx in 0..high_pair_count {
                    next_high.push(products[low_pair_count + pair_idx].clone());
                }
                if let Some(bit) = high_remainder {
                    next_high.push(bit);
                }
                state.low_any_terms = next_low;
                state.high_all_terms = next_high;
                state.layer_idx += 1;
            }
            ProductionCanonicalLtQPending::FinalInvalid => {
                state.result = Some(self.bit_not_vec::<P>(
                    config,
                    &packed_products,
                    &label.child("canonical_lt_q"),
                )?);
            }
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Drives the next multiplication layer for a public comparison.
    pub fn drive_public_comparison_vec_step<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionPublicComparisonVecState,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        if state.done {
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::AssertZero,
                phase: state.phase,
                label_hash: power2round_label_hash(&state.label),
                senders: Vec::new(),
            });
        }
        if state.prefix.is_some() {
            return self.drive_public_comparison_prefix_vec_step::<P, E>(config, state, entropy);
        }
        if state.pending.is_some() {
            return Err(DkgError::Backend(
                "production comparison step already pending",
            ));
        }
        if state.bit_idx < 0 {
            state.done = true;
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::AssertZero,
                phase: state.phase,
                label_hash: power2round_label_hash(&state.label),
                senders: Vec::new(),
            });
        }
        let bit_idx = state.bit_idx as usize;
        if let Some(condition) = self.comparison_candidate_condition::<P>(config, state, bit_idx)? {
            let eq_condition = self.comparison_eq_condition::<P>(config, state, bit_idx)?;
            let label = state.label.child(format!("bit_{bit_idx}/candidate_and_eq"));
            let packed_eq = self.pack_bit_share_vecs::<P>(
                config,
                &[state.eq.clone(), state.eq.clone()],
                &label.child("packed_eq"),
            )?;
            let packed_condition = self.pack_bit_share_vecs::<P>(
                config,
                &[condition, eq_condition],
                &label.child("packed_condition"),
            )?;
            self.drive_bit_and_vec_with_phase::<P, E>(
                config,
                &packed_eq,
                &packed_condition,
                &label,
                state.phase,
                entropy,
            )?;
            state.pending = Some(ProductionPublicComparisonPendingKind::CandidateAndEquality);
            Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver: self.local_party(),
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                label_hash: power2round_label_hash(&label.child("bit_and").child("mul_layer")),
            })
        } else {
            let eq_condition = self.comparison_eq_condition::<P>(config, state, bit_idx)?;
            let label = state.label.child(format!("bit_{bit_idx}/eq_update"));
            self.drive_bit_and_vec_with_phase::<P, E>(
                config,
                &state.eq,
                &eq_condition,
                &label,
                state.phase,
                entropy,
            )?;
            state.pending = Some(ProductionPublicComparisonPendingKind::UpdateEquality);
            Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver: self.local_party(),
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                label_hash: power2round_label_hash(&label.child("bit_and").child("mul_layer")),
            })
        }
    }

    /// Collects the pending multiplication layer for a public comparison and
    /// updates the private comparison state.
    pub fn collect_public_comparison_vec_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionPublicComparisonVecState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        if state.prefix.is_some() {
            return self.collect_public_comparison_prefix_vec_step::<P>(config, state);
        }
        let Some(pending) = state.pending else {
            if state.done {
                return Ok(ProductionVectorItMpcCollectResult::Collected {
                    status: PrimeFieldMpcPhaseDriverStatus::Collected {
                        receiver: None,
                        kind: PrimeFieldMpcRoundKind::AssertZero,
                        phase: state.phase,
                        label_hash: power2round_label_hash(&state.label),
                        senders: Vec::new(),
                    },
                    value: (),
                });
            }
            return Err(DkgError::Backend(
                "production comparison has no pending step",
            ));
        };
        let bit_idx = state.bit_idx as usize;
        let label = match pending {
            ProductionPublicComparisonPendingKind::CandidateAndEquality => {
                state.label.child(format!("bit_{bit_idx}/candidate_and_eq"))
            }
            ProductionPublicComparisonPendingKind::UpdateEquality => {
                state.label.child(format!("bit_{bit_idx}/eq_update"))
            }
        };
        let collected =
            match self.collect_bit_and_vec_with_phase::<P>(config, &label, state.phase)? {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                }
                ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
            };
        let (status, and_result) = collected;
        match pending {
            ProductionPublicComparisonPendingKind::CandidateAndEquality => {
                let split = self.unpack_bit_share_vec_chunks::<P>(
                    config,
                    &and_result,
                    state.eq.len(),
                    &state
                        .label
                        .child(format!("bit_{bit_idx}/candidate_and_eq_split")),
                )?;
                if split.len() != 2 {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
                state.comparison = ProductionBitShareVec::new(self.add_share_vec::<P>(
                    config,
                    state.comparison.share(),
                    split[0].share(),
                    &state.label.child(format!("bit_{bit_idx}/comparison_add")),
                )?);
                state.eq = split[1].clone();
                state.pending = None;
                state.bit_idx -= 1;
                if state.bit_idx < 0 {
                    state.done = true;
                }
            }
            ProductionPublicComparisonPendingKind::UpdateEquality => {
                state.eq = and_result;
                state.pending = None;
                state.bit_idx -= 1;
                if state.bit_idx < 0 {
                    state.done = true;
                }
            }
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Initializes a private `[sum(bits) <= threshold]` circuit over vector
    /// lanes.
    pub fn start_bit_sum_leq_public_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        threshold: u32,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitSumLeqPublicVecState, DkgError> {
        self.start_bit_sum_leq_public_vec_with_phase::<P>(
            config,
            bits,
            threshold,
            label,
            PrimeFieldMpcPhase::BitSumThresholdCheck,
        )
    }

    /// Initializes a preprocessing CEF/BCC private `[sum(bits) <= threshold]`
    /// circuit over vector lanes.
    pub fn start_preprocessing_cef_bcc_bit_sum_leq_public_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        threshold: u32,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitSumLeqPublicVecState, DkgError> {
        self.start_bit_sum_leq_public_vec_with_phase::<P>(
            config,
            bits,
            threshold,
            label,
            PrimeFieldMpcPhase::PreprocessingCefBcc,
        )
    }

    /// Initializes a preprocessing masked-broadcast private
    /// `[sum(bits) <= threshold]` circuit over vector lanes.
    pub fn start_preprocessing_masked_broadcast_bit_sum_leq_public_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        threshold: u32,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitSumLeqPublicVecState, DkgError> {
        self.start_bit_sum_leq_public_vec_with_phase::<P>(
            config,
            bits,
            threshold,
            label,
            PrimeFieldMpcPhase::PreprocessingMaskedBroadcast,
        )
    }

    fn start_bit_sum_leq_public_vec_with_phase<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        threshold: u32,
        label: &Power2RoundTranscriptLabel,
        phase: PrimeFieldMpcPhase,
    ) -> Result<ProductionBitSumLeqPublicVecState, DkgError> {
        let first = bits
            .first()
            .ok_or(DkgError::Backend("empty production threshold input"))?;
        if usize::try_from(threshold)
            .ok()
            .is_none_or(|t| t > bits.len())
        {
            return Err(DkgError::Backend("production threshold exceeds bit count"));
        }
        self.validate_share_vec_context::<P>(config, first.share())?;
        for bit in bits {
            self.validate_share_vec_context::<P>(config, bit.share())?;
            self.ensure_same_share_shape(first.share(), bit.share())?;
        }
        let lane_count = first.len();
        let width = bit_width_for_public_sum(bits.len());
        let accumulator_bits_le = (0..width)
            .map(|idx| {
                self.public_bit_share_vec::<P>(
                    config,
                    &label.child(format!("acc_init_{idx}")),
                    false,
                    lane_count,
                )
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        Ok(ProductionBitSumLeqPublicVecState {
            bits: Vec::new(),
            threshold,
            label: label.clone(),
            phase,
            accumulator_bits_le,
            input_idx: 0,
            bit_idx: 0,
            carry: bits.first().cloned(),
            pending_carry_and: false,
            fast: Some(ProductionBitSumFastReducerState {
                columns: {
                    let mut columns = vec![Vec::new(); width];
                    columns[0] = bits.to_vec();
                    columns
                },
                lane_count,
                layer_idx: 0,
                pending: None,
                ripple_column: 0,
                ripple_carry: None,
                normal_bits_le: Vec::with_capacity(width + 1),
                normal_width: width + 1,
            }),
            comparison: None,
            result: None,
        })
    }

    fn pack_bit_share_vecs<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        let first = bits.first().ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        self.validate_share_vec_context::<P>(config, first.share())?;
        let lane_count = first.len();
        let mut lanes = Vec::with_capacity(bits.len() * lane_count);
        for bit in bits {
            self.validate_share_vec_context::<P>(config, bit.share())?;
            self.ensure_same_share_shape(first.share(), bit.share())?;
            lanes.extend_from_slice(bit.share().lanes());
        }
        Ok(ProductionBitShareVec::new(
            self.share_vec_from_local_lanes::<P>(config, label, lanes)?,
        ))
    }

    /// Packs same-shaped bit-share vectors into one larger vector handle for a
    /// single batched runtime phase.
    ///
    /// This is a handle reshape only: it does not open or serialize the bit
    /// shares. The resulting lane order is `bits[0] || bits[1] || ...`.
    pub fn pack_bit_share_vecs_for_runtime_batch<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.pack_bit_share_vecs::<P>(config, bits, label)
    }

    /// Concatenates bit-share vectors into one larger vector handle for a
    /// batched runtime phase.
    ///
    /// Unlike [`Self::pack_bit_share_vecs_for_runtime_batch`], inputs may have
    /// different lane counts. They must still belong to this runtime's local
    /// holder and interpolation point. The resulting lane order is
    /// `bits[0] || bits[1] || ...`.
    pub fn concat_bit_share_vecs_for_runtime_batch<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        let first = bits.first().ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        self.validate_share_vec_context::<P>(config, first.share())?;
        let mut lanes = Vec::new();
        for bit in bits {
            self.validate_share_vec_context::<P>(config, bit.share())?;
            if bit.holder() != first.holder() || bit.point() != first.point() {
                return Err(DkgError::Power2RoundMaskShapeMismatch);
            }
            lanes.extend_from_slice(bit.share().lanes());
        }
        Ok(ProductionBitShareVec::new(
            self.share_vec_from_local_lanes::<P>(config, label, lanes)?,
        ))
    }

    /// Concatenates share vectors into one larger vector handle for a batched
    /// runtime phase.
    ///
    /// This is a handle reshape only. It does not open the shares. The
    /// resulting lane order is `shares[0] || shares[1] || ...`.
    pub fn concat_share_vecs_for_runtime_batch<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        shares: &[ProductionShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        let first = shares
            .first()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        self.validate_share_vec_context::<P>(config, first)?;
        let mut lanes = Vec::new();
        for share in shares {
            self.validate_share_vec_context::<P>(config, share)?;
            if share.holder() != first.holder() || share.point() != first.point() {
                return Err(DkgError::Power2RoundMaskShapeMismatch);
            }
            lanes.extend_from_slice(share.lanes());
        }
        self.share_vec_from_local_lanes::<P>(config, label, lanes)
    }

    fn unpack_bit_share_vec_chunks<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        chunk_len: usize,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<ProductionBitShareVec>, DkgError> {
        self.validate_share_vec_context::<P>(config, bits.share())?;
        if chunk_len == 0 || bits.len() % chunk_len != 0 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        bits.share()
            .lanes()
            .chunks(chunk_len)
            .enumerate()
            .map(|(idx, lanes)| {
                Ok(ProductionBitShareVec::new(
                    self.share_vec_from_local_lanes::<P>(
                        config,
                        &label.child(format!("chunk_{idx}")),
                        lanes.to_vec(),
                    )?,
                ))
            })
            .collect()
    }

    /// Splits a packed bit-share vector produced by
    /// [`Self::pack_bit_share_vecs_for_runtime_batch`] back into fixed-size
    /// bit-share vector handles.
    ///
    /// This is a handle reshape only and does not expose clear bit values.
    pub fn unpack_bit_share_vec_runtime_batch<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        chunk_len: usize,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<ProductionBitShareVec>, DkgError> {
        self.unpack_bit_share_vec_chunks::<P>(config, bits, chunk_len, label)
    }

    fn constant_bit_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
        value: bool,
        lane_count: usize,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.public_bit_share_vec::<P>(config, label, value, lane_count)
    }

    fn drive_fast_bit_sum_step<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionBitSumLeqPublicVecState,
        entropy: &mut E,
    ) -> Result<Option<PrimeFieldMpcPhaseDriverStatus>, DkgError> {
        let Some(fast) = state.fast.as_mut() else {
            return Ok(None);
        };
        if let Some(pending) = fast.pending.take() {
            match pending {
                ProductionBitSumFastPending::CsaAxc {
                    triples,
                    next_columns,
                    c,
                    ab,
                    axorb,
                    driven: false,
                } => {
                    let layer = state
                        .label
                        .child(format!("fast_csa_layer_{}", fast.layer_idx));
                    self.drive_bit_and_vec_with_phase::<P, E>(
                        config,
                        &axorb,
                        &c,
                        &layer.child("axorb_c"),
                        state.phase,
                        entropy,
                    )?;
                    fast.pending = Some(ProductionBitSumFastPending::CsaAxc {
                        triples,
                        next_columns,
                        c,
                        ab,
                        axorb,
                        driven: true,
                    });
                    return Ok(Some(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                        receiver: self.local_party(),
                        kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                        phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                        label_hash: power2round_label_hash(
                            &layer.child("axorb_c").child("bit_and").child("mul_layer"),
                        ),
                    }));
                }
                ProductionBitSumFastPending::RippleFullAxc {
                    column,
                    c,
                    ab,
                    axorb,
                    driven: false,
                } => {
                    let label = state
                        .label
                        .child(format!("fast_ripple_{column}/full_axorb_c"));
                    self.drive_bit_and_vec_with_phase::<P, E>(
                        config,
                        &axorb,
                        &c,
                        &label,
                        state.phase,
                        entropy,
                    )?;
                    fast.pending = Some(ProductionBitSumFastPending::RippleFullAxc {
                        column,
                        c,
                        ab,
                        axorb,
                        driven: true,
                    });
                    return Ok(Some(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                        receiver: self.local_party(),
                        kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                        phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                        label_hash: power2round_label_hash(
                            &label.child("bit_and").child("mul_layer"),
                        ),
                    }));
                }
                other => {
                    fast.pending = Some(other);
                    return Err(DkgError::Backend(
                        "production fast threshold step already pending",
                    ));
                }
            }
        }
        if state.result.is_some() || state.comparison.is_some() {
            return Ok(None);
        }

        let mut triples = Vec::new();
        let mut next_columns = fast
            .columns
            .iter()
            .map(|_| Vec::new())
            .collect::<Vec<Vec<ProductionBitShareVec>>>();
        let mut a_bits = Vec::new();
        let mut b_bits = Vec::new();
        let mut c_bits = Vec::new();
        for (column, bits) in fast.columns.iter().enumerate() {
            let mut chunks = bits.chunks_exact(3);
            for triple in &mut chunks {
                triples.push(column);
                a_bits.push(triple[0].clone());
                b_bits.push(triple[1].clone());
                c_bits.push(triple[2].clone());
            }
            next_columns[column].extend(chunks.remainder().iter().cloned());
        }
        if !triples.is_empty() {
            if fast.columns.len() == next_columns.len() {
                next_columns.push(Vec::new());
            }
            let layer = state
                .label
                .child(format!("fast_csa_layer_{}", fast.layer_idx));
            let a = self.pack_bit_share_vecs::<P>(config, &a_bits, &layer.child("a"))?;
            let b = self.pack_bit_share_vecs::<P>(config, &b_bits, &layer.child("b"))?;
            let c = self.pack_bit_share_vecs::<P>(config, &c_bits, &layer.child("c"))?;
            self.drive_bit_and_vec_with_phase::<P, E>(
                config,
                &a,
                &b,
                &layer.child("ab"),
                state.phase,
                entropy,
            )?;
            fast.pending = Some(ProductionBitSumFastPending::CsaAb {
                triples,
                next_columns,
                a,
                b,
                c,
            });
            return Ok(Some(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                receiver: self.local_party(),
                kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                label_hash: power2round_label_hash(
                    &layer.child("ab").child("bit_and").child("mul_layer"),
                ),
            }));
        }

        if fast.ripple_column >= fast.normal_width {
            state.accumulator_bits_le = fast.normal_bits_le.clone();
            state.comparison = Some(self.start_public_comparison_vec::<P>(
                config,
                ProductionPublicComparisonKind::GreaterThan,
                &state.accumulator_bits_le,
                state.threshold,
                &state.label.child("sum_gt_threshold"),
                state.phase,
            )?);
            return self
                .drive_public_comparison_vec_step::<P, E>(
                    config,
                    state
                        .comparison
                        .as_mut()
                        .ok_or(DkgError::Power2RoundMaskShapeMismatch)?,
                    entropy,
                )
                .map(Some);
        }

        let mut operands = fast
            .columns
            .get(fast.ripple_column)
            .cloned()
            .unwrap_or_default();
        if let Some(carry) = fast.ripple_carry.take() {
            operands.push(carry);
        }
        match operands.len() {
            0 => {
                fast.normal_bits_le.push(
                    self.constant_bit_vec::<P>(
                        config,
                        &state
                            .label
                            .child(format!("fast_ripple_{}/zero", fast.ripple_column)),
                        false,
                        fast.lane_count,
                    )?,
                );
                fast.ripple_column += 1;
                self.drive_fast_bit_sum_step::<P, E>(config, state, entropy)
            }
            1 => {
                fast.normal_bits_le.push(operands.remove(0));
                fast.ripple_column += 1;
                self.drive_fast_bit_sum_step::<P, E>(config, state, entropy)
            }
            2 => {
                let label = state
                    .label
                    .child(format!("fast_ripple_{}/half", fast.ripple_column));
                self.drive_bit_and_vec_with_phase::<P, E>(
                    config,
                    &operands[0],
                    &operands[1],
                    &label,
                    state.phase,
                    entropy,
                )?;
                fast.pending = Some(ProductionBitSumFastPending::RippleHalfAnd {
                    column: fast.ripple_column,
                    left: operands[0].clone(),
                    right: operands[1].clone(),
                });
                Ok(Some(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                    receiver: self.local_party(),
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                    label_hash: power2round_label_hash(&label.child("bit_and").child("mul_layer")),
                }))
            }
            3 => {
                let label = state
                    .label
                    .child(format!("fast_ripple_{}/full_ab", fast.ripple_column));
                self.drive_bit_and_vec_with_phase::<P, E>(
                    config,
                    &operands[0],
                    &operands[1],
                    &label,
                    state.phase,
                    entropy,
                )?;
                fast.pending = Some(ProductionBitSumFastPending::RippleFullAb {
                    column: fast.ripple_column,
                    a: operands[0].clone(),
                    b: operands[1].clone(),
                    c: operands[2].clone(),
                });
                Ok(Some(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
                    receiver: self.local_party(),
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
                    label_hash: power2round_label_hash(&label.child("bit_and").child("mul_layer")),
                }))
            }
            _ => Err(DkgError::Power2RoundMaskShapeMismatch),
        }
    }

    fn collect_fast_bit_sum_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionBitSumLeqPublicVecState,
    ) -> Result<Option<ProductionVectorItMpcCollectResult<()>>, DkgError> {
        let Some(fast) = state.fast.as_mut() else {
            return Ok(None);
        };
        let Some(pending) = fast.pending.take() else {
            return Ok(None);
        };
        match pending {
            ProductionBitSumFastPending::CsaAb {
                triples,
                next_columns,
                a,
                b,
                c,
            } => {
                let layer = state
                    .label
                    .child(format!("fast_csa_layer_{}", fast.layer_idx));
                let (status, ab) = match self.collect_bit_and_vec_with_phase::<P>(
                    config,
                    &layer.child("ab"),
                    state.phase,
                )? {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        fast.pending = Some(ProductionBitSumFastPending::CsaAb {
                            triples,
                            next_columns,
                            a,
                            b,
                            c,
                        });
                        return Ok(Some(ProductionVectorItMpcCollectResult::Waiting(status)));
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, value } => {
                        (status, value)
                    }
                };
                let axorb =
                    self.bit_xor_from_and_vec::<P>(config, &a, &b, &ab, &layer.child("a_xor_b"))?;
                fast.pending = Some(ProductionBitSumFastPending::CsaAxc {
                    triples,
                    next_columns,
                    c,
                    ab,
                    axorb,
                    driven: false,
                });
                Ok(Some(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: (),
                }))
            }
            ProductionBitSumFastPending::CsaAxc {
                triples,
                mut next_columns,
                c,
                ab,
                axorb,
                driven,
            } => {
                if !driven {
                    fast.pending = Some(ProductionBitSumFastPending::CsaAxc {
                        triples,
                        next_columns,
                        c,
                        ab,
                        axorb,
                        driven,
                    });
                    return Err(DkgError::Backend(
                        "production fast threshold axc step not driven",
                    ));
                }
                let layer = state
                    .label
                    .child(format!("fast_csa_layer_{}", fast.layer_idx));
                let (status, axc) = match self.collect_bit_and_vec_with_phase::<P>(
                    config,
                    &layer.child("axorb_c"),
                    state.phase,
                )? {
                    ProductionVectorItMpcCollectResult::Waiting(status) => {
                        fast.pending = Some(ProductionBitSumFastPending::CsaAxc {
                            triples,
                            next_columns,
                            c,
                            ab,
                            axorb,
                            driven,
                        });
                        return Ok(Some(ProductionVectorItMpcCollectResult::Waiting(status)));
                    }
                    ProductionVectorItMpcCollectResult::Collected { status, value } => {
                        (status, value)
                    }
                };
                let sum =
                    self.bit_xor_from_and_vec::<P>(config, &axorb, &c, &axc, &layer.child("sum"))?;
                let carry = ProductionBitShareVec::new(self.add_share_vec::<P>(
                    config,
                    ab.share(),
                    axc.share(),
                    &layer.child("carry"),
                )?);
                let sum_chunks = self.unpack_bit_share_vec_chunks::<P>(
                    config,
                    &sum,
                    fast.lane_count,
                    &layer.child("sum_chunks"),
                )?;
                let carry_chunks = self.unpack_bit_share_vec_chunks::<P>(
                    config,
                    &carry,
                    fast.lane_count,
                    &layer.child("carry_chunks"),
                )?;
                for ((column, sum_bit), carry_bit) in triples
                    .into_iter()
                    .zip(sum_chunks.into_iter())
                    .zip(carry_chunks.into_iter())
                {
                    if column + 1 >= next_columns.len() {
                        next_columns.resize_with(column + 2, Vec::new);
                    }
                    next_columns[column].push(sum_bit);
                    next_columns[column + 1].push(carry_bit);
                }
                fast.columns = next_columns;
                fast.layer_idx += 1;
                Ok(Some(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: (),
                }))
            }
            ProductionBitSumFastPending::RippleHalfAnd {
                column,
                left,
                right,
            } => {
                let label = state.label.child(format!("fast_ripple_{column}/half"));
                let (status, and) =
                    match self.collect_bit_and_vec_with_phase::<P>(config, &label, state.phase)? {
                        ProductionVectorItMpcCollectResult::Waiting(status) => {
                            fast.pending = Some(ProductionBitSumFastPending::RippleHalfAnd {
                                column,
                                left,
                                right,
                            });
                            return Ok(Some(ProductionVectorItMpcCollectResult::Waiting(status)));
                        }
                        ProductionVectorItMpcCollectResult::Collected { status, value } => {
                            (status, value)
                        }
                    };
                let sum = self.bit_xor_from_and_vec::<P>(
                    config,
                    &left,
                    &right,
                    &and,
                    &label.child("sum"),
                )?;
                fast.normal_bits_le.push(sum);
                fast.ripple_carry = Some(and);
                fast.ripple_column = column + 1;
                Ok(Some(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: (),
                }))
            }
            ProductionBitSumFastPending::RippleFullAb { column, a, b, c } => {
                let label = state.label.child(format!("fast_ripple_{column}/full_ab"));
                let (status, ab) =
                    match self.collect_bit_and_vec_with_phase::<P>(config, &label, state.phase)? {
                        ProductionVectorItMpcCollectResult::Waiting(status) => {
                            fast.pending =
                                Some(ProductionBitSumFastPending::RippleFullAb { column, a, b, c });
                            return Ok(Some(ProductionVectorItMpcCollectResult::Waiting(status)));
                        }
                        ProductionVectorItMpcCollectResult::Collected { status, value } => {
                            (status, value)
                        }
                    };
                let axorb =
                    self.bit_xor_from_and_vec::<P>(config, &a, &b, &ab, &label.child("a_xor_b"))?;
                fast.pending = Some(ProductionBitSumFastPending::RippleFullAxc {
                    column,
                    c,
                    ab,
                    axorb,
                    driven: false,
                });
                Ok(Some(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: (),
                }))
            }
            ProductionBitSumFastPending::RippleFullAxc {
                column,
                c,
                ab,
                axorb,
                driven,
            } => {
                if !driven {
                    fast.pending = Some(ProductionBitSumFastPending::RippleFullAxc {
                        column,
                        c,
                        ab,
                        axorb,
                        driven,
                    });
                    return Err(DkgError::Backend(
                        "production fast threshold ripple axc step not driven",
                    ));
                }
                let label = state
                    .label
                    .child(format!("fast_ripple_{column}/full_axorb_c"));
                let (status, axc) =
                    match self.collect_bit_and_vec_with_phase::<P>(config, &label, state.phase)? {
                        ProductionVectorItMpcCollectResult::Waiting(status) => {
                            fast.pending = Some(ProductionBitSumFastPending::RippleFullAxc {
                                column,
                                c,
                                ab,
                                axorb,
                                driven,
                            });
                            return Ok(Some(ProductionVectorItMpcCollectResult::Waiting(status)));
                        }
                        ProductionVectorItMpcCollectResult::Collected { status, value } => {
                            (status, value)
                        }
                    };
                let sum =
                    self.bit_xor_from_and_vec::<P>(config, &axorb, &c, &axc, &label.child("sum"))?;
                let carry = ProductionBitShareVec::new(self.add_share_vec::<P>(
                    config,
                    ab.share(),
                    axc.share(),
                    &label.child("carry"),
                )?);
                fast.normal_bits_le.push(sum);
                fast.ripple_carry = Some(carry);
                fast.ripple_column = column + 1;
                Ok(Some(ProductionVectorItMpcCollectResult::Collected {
                    status,
                    value: (),
                }))
            }
        }
    }

    /// Drives the next multiplication layer for a private bit-sum threshold
    /// circuit.
    pub fn drive_bit_sum_leq_public_vec_step<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionBitSumLeqPublicVecState,
        entropy: &mut E,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        if state.result.is_some() {
            return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind: PrimeFieldMpcRoundKind::AssertZero,
                phase: state.phase,
                label_hash: power2round_label_hash(&state.label),
                senders: Vec::new(),
            });
        }
        if let Some(comparison) = state.comparison.as_mut() {
            if comparison.is_done() {
                let gt = comparison
                    .result()
                    .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
                state.result = Some(self.bit_not_vec::<P>(
                    config,
                    gt,
                    &state.label.child("not_gt_threshold"),
                )?);
                return Ok(PrimeFieldMpcPhaseDriverStatus::Collected {
                    receiver: None,
                    kind: PrimeFieldMpcRoundKind::AssertZero,
                    phase: state.phase,
                    label_hash: power2round_label_hash(&state.label),
                    senders: Vec::new(),
                });
            }
            return self.drive_public_comparison_vec_step::<P, E>(config, comparison, entropy);
        }
        if state.fast.is_some() {
            if let Some(status) = self.drive_fast_bit_sum_step::<P, E>(config, state, entropy)? {
                return Ok(status);
            }
        }
        if state.pending_carry_and {
            return Err(DkgError::Backend(
                "production threshold step already pending",
            ));
        }
        if state.input_idx >= state.bits.len() {
            state.comparison = Some(self.start_public_comparison_vec::<P>(
                config,
                ProductionPublicComparisonKind::GreaterThan,
                &state.accumulator_bits_le,
                state.threshold,
                &state.label.child("sum_gt_threshold"),
                state.phase,
            )?);
            return self.drive_bit_sum_leq_public_vec_step::<P, E>(config, state, entropy);
        }
        if state.bit_idx >= state.accumulator_bits_le.len() {
            state.input_idx += 1;
            state.bit_idx = 0;
            state.carry = state.bits.get(state.input_idx).cloned();
            return self.drive_bit_sum_leq_public_vec_step::<P, E>(config, state, entropy);
        }
        let carry = state
            .carry
            .as_ref()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        let label = state.label.child(format!(
            "add_input_{}/bit_{}/carry",
            state.input_idx, state.bit_idx
        ));
        self.drive_bit_and_vec_with_phase::<P, E>(
            config,
            &state.accumulator_bits_le[state.bit_idx],
            carry,
            &label,
            state.phase,
            entropy,
        )?;
        state.pending_carry_and = true;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver: self.local_party(),
            kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase: PrimeFieldMpcPhase::MulDegreeReductionShare,
            label_hash: power2round_label_hash(&label.child("bit_and").child("mul_layer")),
        })
    }

    /// Collects the pending multiplication layer for a private bit-sum
    /// threshold circuit.
    pub fn collect_bit_sum_leq_public_vec_step<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        state: &mut ProductionBitSumLeqPublicVecState,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        if let Some(comparison) = state.comparison.as_mut() {
            if comparison.is_done() {
                let gt = comparison
                    .result()
                    .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
                state.result = Some(self.bit_not_vec::<P>(
                    config,
                    gt,
                    &state.label.child("not_gt_threshold"),
                )?);
                return Ok(ProductionVectorItMpcCollectResult::Collected {
                    status: PrimeFieldMpcPhaseDriverStatus::Collected {
                        receiver: None,
                        kind: PrimeFieldMpcRoundKind::AssertZero,
                        phase: state.phase,
                        label_hash: power2round_label_hash(&state.label),
                        senders: Vec::new(),
                    },
                    value: (),
                });
            }
            let result = self.collect_public_comparison_vec_step::<P>(config, comparison)?;
            if comparison.is_done() {
                let gt = comparison
                    .result()
                    .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
                state.result = Some(self.bit_not_vec::<P>(
                    config,
                    gt,
                    &state.label.child("not_gt_threshold"),
                )?);
            }
            return Ok(result);
        }
        if state.fast.is_some() {
            if let Some(result) = self.collect_fast_bit_sum_step::<P>(config, state)? {
                return Ok(result);
            }
        }
        if !state.pending_carry_and {
            return Err(DkgError::Backend(
                "production threshold has no pending step",
            ));
        }
        let label = state.label.child(format!(
            "add_input_{}/bit_{}/carry",
            state.input_idx, state.bit_idx
        ));
        let and_result =
            match self.collect_bit_and_vec_with_phase::<P>(config, &label, state.phase)? {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                }
                ProductionVectorItMpcCollectResult::Collected { status, value } => (status, value),
            };
        let (status, new_carry) = and_result;
        let carry = state
            .carry
            .as_ref()
            .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
        state.accumulator_bits_le[state.bit_idx] = self.bit_xor_from_and_vec::<P>(
            config,
            &state.accumulator_bits_le[state.bit_idx],
            carry,
            &new_carry,
            &state.label.child(format!(
                "add_input_{}/bit_{}/sum",
                state.input_idx, state.bit_idx
            )),
        )?;
        state.carry = Some(new_carry);
        state.bit_idx += 1;
        state.pending_carry_and = false;
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Computes vector bitwise XOR from `x`, `y`, and their already-computed
    /// `x AND y` handle.
    pub fn bit_xor_from_and_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        left: &ProductionBitShareVec,
        right: &ProductionBitShareVec,
        and: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, left.share())?;
        self.validate_share_vec_context::<P>(config, right.share())?;
        self.validate_share_vec_context::<P>(config, and.share())?;
        self.ensure_same_share_shape(left.share(), right.share())?;
        self.ensure_same_share_shape(left.share(), and.share())?;
        let two_and =
            self.mul_public_const_share_vec::<P>(config, and.share(), 2, &label.child("two_and"))?;
        let sum = self.add_share_vec::<P>(
            config,
            left.share(),
            right.share(),
            &label.child("left_plus_right"),
        )?;
        Ok(ProductionBitShareVec::new(self.sub_share_vec::<P>(
            config,
            &sum,
            &two_and,
            &label.child("xor"),
        )?))
    }

    /// Computes vector bitwise OR from `x`, `y`, and their already-computed
    /// `x AND y` handle.
    pub fn bit_or_from_and_vec<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        left: &ProductionBitShareVec,
        right: &ProductionBitShareVec,
        and: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionBitShareVec, DkgError> {
        self.validate_share_vec_context::<P>(config, left.share())?;
        self.validate_share_vec_context::<P>(config, right.share())?;
        self.validate_share_vec_context::<P>(config, and.share())?;
        self.ensure_same_share_shape(left.share(), right.share())?;
        self.ensure_same_share_shape(left.share(), and.share())?;
        let sum = self.add_share_vec::<P>(
            config,
            left.share(),
            right.share(),
            &label.child("left_plus_right"),
        )?;
        Ok(ProductionBitShareVec::new(self.sub_share_vec::<P>(
            config,
            &sum,
            and.share(),
            &label.child("or"),
        )?))
    }

    /// Sums field share vectors lane-wise as a local linear operation.
    pub fn sum_share_vecs<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        shares: &[ProductionShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        let first = shares
            .first()
            .ok_or(DkgError::Backend("empty production vector sum"))?;
        self.validate_share_vec_context::<P>(config, first)?;
        let mut lanes = vec![0; first.len()];
        for share in shares {
            self.validate_share_vec_context::<P>(config, share)?;
            self.ensure_same_share_shape(first, share)?;
            for (out, &lane) in lanes.iter_mut().zip(share.lanes()) {
                *out = reduce_mod_q::<P>(*out + lane);
            }
        }
        self.share_vec_from_local_lanes::<P>(config, label, lanes)
    }

    /// Sums bit share vectors lane-wise as field shares.
    pub fn sum_bit_share_vecs_as_share<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        let shares = bits
            .iter()
            .map(|bit| bit.share().clone())
            .collect::<Vec<_>>();
        self.sum_share_vecs::<P>(config, &shares, label)
    }

    /// Sends the multiplication layer for a bitness check `b * (b - 1)`.
    ///
    /// The caller must collect the returned product and assert it is zero with
    /// `drive_assert_zero_share_vec` / `collect_assert_zero_share_vec`.
    pub fn drive_assert_bit_product_vec<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        self.validate_share_vec_context::<P>(config, bits.share())?;
        let one = self.public_const_share_vec::<P>(config, &label.child("one"), 1, bits.len())?;
        let bit_minus_one =
            self.sub_share_vec::<P>(config, bits.share(), &one, &label.child("bit_minus_one"))?;
        self.drive_mul_vec_degree_reduction::<P, E>(
            config,
            bits.share(),
            &bit_minus_one,
            &label.child("bit_product"),
            entropy,
        )
    }

    /// Collects the multiplication product for a bitness check.
    pub fn collect_assert_bit_product_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, DkgError> {
        self.collect_mul_vec_degree_reduction::<P>(config, &label.child("bit_product"))
    }

    /// Builds the field-share expression for a one-hot selection assertion:
    /// `sum(selection_bits) - 1`.
    ///
    /// The returned share must be checked with the normal zero-assertion
    /// transport phase.
    pub fn one_hot_sum_minus_one<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        selection_bits: &[ProductionBitShareVec],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionShareVec, DkgError> {
        let sum = self.sum_bit_share_vecs_as_share::<P>(
            config,
            selection_bits,
            &label.child("sum_selection_bits"),
        )?;
        let one = self.public_const_share_vec::<P>(config, &label.child("one"), 1, sum.len())?;
        self.sub_share_vec::<P>(config, &sum, &one, &label.child("sum_minus_one"))
    }

    /// Sends one multiplication layer for a private selection product
    /// `selection * value`.
    ///
    /// Production callers should drive and collect each candidate product under
    /// its own transcript label before queuing another directed phase. This
    /// preserves the current reliable-transport invariant that one directed
    /// phase label is collected at a time.
    pub fn drive_selection_product_vec<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        selection_bit: &ProductionBitShareVec,
        value: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        self.validate_share_vec_context::<P>(config, selection_bit.share())?;
        self.validate_share_vec_context::<P>(config, value)?;
        self.ensure_same_share_shape(selection_bit.share(), value)?;
        self.drive_mul_vec_degree_reduction::<P, E>(
            config,
            selection_bit.share(),
            value,
            &label.child("selection_product"),
            entropy,
        )
    }

    /// Collects one private selection product.
    pub fn collect_selection_product_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, DkgError> {
        self.collect_mul_vec_degree_reduction::<P>(config, &label.child("selection_product"))
    }

    /// Sends multiplication layers for private selection products
    /// `selection_j * value_j`.
    ///
    /// Prefer `drive_selection_product_vec` in production drivers unless the
    /// embedding transport explicitly supports concurrently queued directed
    /// vector phase labels.
    pub fn drive_selection_products_vec<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        selection_bits: &[ProductionBitShareVec],
        values: &[ProductionShareVec],
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        if selection_bits.len() != values.len() || selection_bits.is_empty() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        for (idx, (bit, value)) in selection_bits.iter().zip(values).enumerate() {
            self.drive_selection_product_vec::<P, E>(
                config,
                bit,
                value,
                &label.child(format!("selection_product_{idx}")),
                entropy,
            )?;
        }
        Ok(())
    }

    /// Collects private selection products and locally sums them into the
    /// selected vector share.
    pub fn collect_selection_products_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        candidate_count: usize,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, DkgError> {
        if candidate_count == 0 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let mut products = Vec::with_capacity(candidate_count);
        let mut last_status = None;
        for idx in 0..candidate_count {
            match self.collect_selection_product_vec::<P>(
                config,
                &label.child(format!("selection_product_{idx}")),
            )? {
                ProductionVectorItMpcCollectResult::Waiting(status) => {
                    return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
                }
                ProductionVectorItMpcCollectResult::Collected { status, value } => {
                    last_status = Some(status);
                    products.push(value);
                }
            }
        }
        let selected = self.sum_share_vecs::<P>(config, &products, &label.child("selected_sum"))?;
        Ok(ProductionVectorItMpcCollectResult::Collected {
            status: last_status.ok_or(DkgError::Power2RoundMaskShapeMismatch)?,
            value: selected,
        })
    }

    /// Sends this party's private random-bit contribution shares to all
    /// receivers.
    ///
    /// The output bits are not controlled by this party alone: every party
    /// contributes a private bit vector, and callers combine the collected
    /// contribution handles with private XOR rounds.
    pub fn drive_random_bit_contribution_vec<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        lane_count: usize,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        if lane_count == 0 {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let secrets = entropy.fill_bits::<P>(&label.child("secret_bits"), lane_count)?;
        let degree = usize::from(config.threshold.saturating_sub(1));
        let receivers = config.interpolation_points::<P>()?;
        let mut shares_by_receiver = receivers
            .iter()
            .map(|(receiver, _)| (*receiver, Vec::with_capacity(lane_count)))
            .collect::<Vec<_>>();
        for (lane_idx, &secret) in secrets.iter().enumerate() {
            let coeff_label = label.child(format!(
                "random_bit/dealer_{}/lane_{lane_idx}",
                self.local_party().0
            ));
            let mut coefficients = Vec::with_capacity(degree + 1);
            coefficients.push(secret);
            coefficients.extend(entropy.fill_field_coefficients::<P>(&coeff_label, degree)?);
            for ((_, receiver_point), (_, shares_for_receiver)) in
                receivers.iter().zip(shares_by_receiver.iter_mut())
            {
                shares_for_receiver.push(evaluate_shamir_polynomial::<P>(
                    &coefficients,
                    *receiver_point,
                )?);
            }
        }
        for (receiver, shares_for_receiver) in shares_by_receiver {
            self.send_random_bit_vec(receiver, label, &shares_for_receiver)?;
        }
        Ok(())
    }

    /// Collects dealer random-bit contribution shares for the local party.
    pub fn collect_random_bit_contribution_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<Vec<ProductionBitShareVec>>, DkgError> {
        let receiver = self.local_party();
        let (status, values) = self.collect_random_bit_vec(receiver, label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingPrivate { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let _lane_count = uniform_collected_vector_lane_count(&values)?;
        let mut sorted = values;
        sorted.sort_by_key(|(party, _)| party.0);
        let mut contributions = Vec::with_capacity(sorted.len());
        for (dealer, lanes) in sorted {
            contributions.push(self.bit_share_vec_from_local_lanes::<P>(
                config,
                &label.child(format!("dealer_{}", dealer.0)),
                lanes,
            )?);
        }
        Ok(ProductionVectorItMpcCollectResult::Collected {
            status,
            value: contributions,
        })
    }

    /// Sends this party's degree-reduction resharing for a vector
    /// multiplication layer.
    ///
    /// Each party locally multiplies its lanes, weights by its Lagrange
    /// coefficient at zero, then Shamir-reshares the weighted vector to all
    /// receivers. Collection sums all dealer resharings into the receiver's
    /// local product share.
    pub fn drive_mul_vec_degree_reduction<P: MlDsaParams, E: ProductionVectorItMpcEntropy>(
        &mut self,
        config: &DkgConfig,
        left: &ProductionShareVec,
        right: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
        entropy: &mut E,
    ) -> Result<(), DkgError> {
        self.validate_share_vec_context::<P>(config, left)?;
        self.validate_share_vec_context::<P>(config, right)?;
        self.ensure_same_share_shape(left, right)?;

        let points = config
            .interpolation_points::<P>()?
            .into_iter()
            .map(|(_, point)| point)
            .collect::<Vec<_>>();
        let lambdas = lagrange_coefficients_at_zero::<P>(&points)
            .map_err(|_| DkgError::Backend("degree-reduction coefficients failed"))?;
        let local_index = config
            .parties
            .iter()
            .position(|party| *party == self.local_party())
            .ok_or(DkgError::UnknownParty(self.local_party()))?;
        let lambda = i64::from(lambdas[local_index]);
        let q = i64::from(P::Q);
        let weighted = left
            .lanes
            .iter()
            .zip(&right.lanes)
            .map(|(&x, &y)| {
                let product = (i64::from(x) * i64::from(y)).rem_euclid(q);
                (product * lambda).rem_euclid(q) as Coeff
            })
            .collect::<Vec<_>>();

        let degree = usize::from(config.threshold.saturating_sub(1));
        let receivers = config.interpolation_points::<P>()?;
        let mut shares_by_receiver = receivers
            .iter()
            .map(|(receiver, _)| (*receiver, Vec::with_capacity(weighted.len())))
            .collect::<Vec<_>>();
        for (lane_idx, &secret) in weighted.iter().enumerate() {
            let coeff_label = label.child(format!(
                "degree_reduce/dealer_{}/lane_{lane_idx}",
                self.local_party().0
            ));
            let mut coefficients = Vec::with_capacity(degree + 1);
            coefficients.push(secret);
            coefficients.extend(entropy.fill_field_coefficients::<P>(&coeff_label, degree)?);
            for ((_, receiver_point), (_, shares_for_receiver)) in
                receivers.iter().zip(shares_by_receiver.iter_mut())
            {
                shares_for_receiver.push(evaluate_shamir_polynomial::<P>(
                    &coefficients,
                    *receiver_point,
                )?);
            }
        }
        for (receiver, shares_for_receiver) in shares_by_receiver {
            self.send_mul_layer_vec(receiver, label, &shares_for_receiver)?;
        }
        Ok(())
    }

    /// Collects a vector multiplication layer for the local party.
    pub fn collect_mul_vec_degree_reduction<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<ProductionShareVec>, DkgError> {
        let receiver = self.local_party();
        let (status, values) = self.collect_mul_layer_vec(receiver, label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingPrivate { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let lane_count = uniform_collected_vector_lane_count(&values)?;
        let mut lanes = vec![0; lane_count];
        for (_sender, sender_lanes) in values {
            for (out, value) in lanes.iter_mut().zip(sender_lanes) {
                *out = reduce_mod_q::<P>(*out + value);
            }
        }
        let share = self.share_vec_from_local_lanes::<P>(config, label, lanes)?;
        Ok(ProductionVectorItMpcCollectResult::Collected {
            status,
            value: share,
        })
    }

    /// Broadcasts this party's local lanes for a checked vector opening.
    pub fn drive_open_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        self.open_many_checked_vec(label, share.lanes())
    }

    /// Collects and reconstructs a checked vector opening.
    pub fn collect_open_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<Vec<Coeff>>, DkgError> {
        let (status, values) = self.collect_open_many_checked_vec(label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
        Ok(ProductionVectorItMpcCollectResult::Collected {
            status,
            value: opened,
        })
    }

    /// Broadcasts this party's local bit lanes for a checked vector opening.
    pub fn drive_open_bit_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_open_share_vec::<P>(config, bits.share(), label)
    }

    /// Collects and reconstructs a checked vector bit opening.
    pub fn collect_open_bit_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<Vec<Coeff>>, DkgError> {
        match self.collect_open_share_vec::<P>(config, label)? {
            ProductionVectorItMpcCollectResult::Waiting(status) => {
                Ok(ProductionVectorItMpcCollectResult::Waiting(status))
            }
            ProductionVectorItMpcCollectResult::Collected { status, value } => {
                if value.iter().any(|&lane| lane != 0 && lane != 1) {
                    return Err(DkgError::Power2RoundInvalidOpenedBit);
                }
                Ok(ProductionVectorItMpcCollectResult::Collected { status, value })
            }
        }
    }

    /// Broadcasts this party's local lanes for a checked zero assertion.
    pub fn drive_assert_zero_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        self.assert_zero_vec(label, share.lanes())
    }

    /// Collects a checked zero assertion without exposing failed raw values.
    pub fn collect_assert_zero_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        let (status, values) = self.collect_assert_zero_vec(label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
        if opened.iter().any(|&value| reduce_mod_q::<P>(value) != 0) {
            return Err(DkgError::Power2RoundCanonicalityFailure);
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Broadcasts a checked assertion that every lane of a private bit vector
    /// is one.
    ///
    /// This is a specialized fast path for one-bit threshold assertions such
    /// as canonical-mask `lt_q == 1`: it checks `bit - 1 == 0` directly rather
    /// than invoking the generic bit-sum equality circuit.
    pub fn drive_assert_bit_vec_all_ones<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        bits: &ProductionBitShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.validate_share_vec_context::<P>(config, bits.share())?;
        let one = self.public_const_share_vec::<P>(config, &label.child("one"), 1, bits.len())?;
        let residual =
            self.sub_share_vec::<P>(config, bits.share(), &one, &label.child("bit_minus_one"))?;
        self.drive_assert_zero_share_vec::<P>(config, &residual, label)
    }

    /// Collects a checked all-ones assertion for a private bit vector.
    pub fn collect_assert_bit_vec_all_ones<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        self.collect_assert_zero_share_vec::<P>(config, label)
    }

    /// Broadcasts this party's equality-to-public check residuals.
    ///
    /// The residual is `share - public_expected`. Collection verifies that the
    /// reconstructed residual vector is zero without returning failed raw
    /// values.
    pub fn drive_equality_to_public_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        share: &ProductionShareVec,
        expected: &[Coeff],
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.validate_share_vec_context::<P>(config, share)?;
        if share.len() != expected.len() {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        let expected_share =
            self.public_lanes_share_vec::<P>(config, &label.child("expected"), expected)?;
        let residual =
            self.sub_share_vec::<P>(config, share, &expected_share, &label.child("residual"))?;
        self.equality_to_public_vec(label, residual.lanes())
    }

    /// Collects a public equality check without exposing failed raw values.
    pub fn collect_equality_to_public_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        let (status, values) = self.collect_equality_to_public_vec(label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
        if opened.iter().any(|&value| reduce_mod_q::<P>(value) != 0) {
            return Err(DkgError::Power2RoundCanonicalityFailure);
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Broadcasts the residual for a public bit-sum equality check:
    /// `sum(bits) - expected_sum`.
    pub fn drive_bit_sum_equals_public_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        bits: &[ProductionBitShareVec],
        expected_sum: Coeff,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let sum = self.sum_bit_share_vecs_as_share::<P>(config, bits, &label.child("sum_bits"))?;
        let expected = self.public_const_share_vec::<P>(
            config,
            &label.child("expected_sum"),
            expected_sum,
            sum.len(),
        )?;
        let residual =
            self.sub_share_vec::<P>(config, &sum, &expected, &label.child("residual"))?;
        self.bit_sum_threshold_check_vec(label, residual.lanes())
    }

    /// Collects a public bit-sum equality check without exposing failed raw
    /// values.
    pub fn collect_bit_sum_equals_public_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        let (status, values) = self.collect_bit_sum_threshold_check_vec(label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
        if opened.iter().any(|&value| reduce_mod_q::<P>(value) != 0) {
            return Err(DkgError::Power2RoundCanonicalityFailure);
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Broadcasts a private one-hot selection residual check without opening the
    /// selected bit pattern.
    ///
    /// The residual is typically `sum(selected_bits) - 1`. Collection verifies
    /// that it reconstructs to zero and records the dedicated private-selection
    /// phase in the durable runtime log.
    pub fn drive_private_selection_check_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        residual: &ProductionShareVec,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.validate_share_vec_context::<P>(config, residual)?;
        self.private_selection_check_vec(label, residual.lanes())
    }

    /// Collects a private one-hot selection residual check without returning
    /// failed raw values.
    pub fn collect_private_selection_check_share_vec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionVectorItMpcCollectResult<()>, DkgError> {
        let (status, values) = self.collect_private_selection_check_vec(label)?;
        if matches!(
            status,
            PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast { .. }
        ) {
            return Ok(ProductionVectorItMpcCollectResult::Waiting(status));
        }
        let opened = reconstruct_collected_prime_field_vector::<P>(config, &values)?;
        if opened.iter().any(|&value| reduce_mod_q::<P>(value) != 0) {
            return Err(DkgError::Power2RoundCanonicalityFailure);
        }
        Ok(ProductionVectorItMpcCollectResult::Collected { status, value: () })
    }

    /// Derives durable runtime evidence from the local wire log.
    pub fn runtime_evidence(&self) -> Result<ProductionVectorItMpcRuntimeEvidence, DkgError> {
        production_vector_it_mpc_runtime_evidence_from_wire_log(self.inner.runtime().wire_log())
    }

    /// Derives per-phase profiling data from the local durable wire log.
    pub fn runtime_phase_profile(&self) -> Result<Vec<PrimeFieldMpcPhaseProfile>, DkgError> {
        prime_field_mpc_phase_profile_from_wire_records(
            self.inner.runtime().wire_log().wire_records(),
        )
    }

    /// Applies the complete Phase 3 vector runtime release gate.
    pub fn ensure_release_ready(&self) -> Result<(), DkgError> {
        let evidence = self.runtime_evidence()?;
        ensure_production_vector_it_mpc_runtime_evidence_for_release(&evidence)
    }

    fn drive_broadcast_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_broadcast_phase_vec(kind, phase, label, values)
    }

    fn collect_broadcast_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .collect_or_recover_broadcast_vec_phase(kind, phase, label)
    }

    fn send_directed_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_send_directed_phase_vec(receiver, kind, phase, label, values)
    }

    fn collect_directed_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .collect_or_recover_directed_vec_phase(receiver, kind, phase, label)
    }

    /// Sends a vector multiplication degree-reduction share batch.
    pub fn send_mul_layer_vec(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.send_mul_layer_vec_with_phase(
            receiver,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
            values,
        )
    }

    fn send_mul_layer_vec_with_phase(
        &mut self,
        receiver: PartyId,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.send_directed_vec(
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase,
            &label.child("mul_layer"),
            values,
        )
    }

    /// Collects a vector multiplication degree-reduction share batch.
    pub fn collect_mul_layer_vec(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_mul_layer_vec_with_phase(
            receiver,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
        )
    }

    fn collect_mul_layer_vec_with_phase(
        &mut self,
        receiver: PartyId,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_directed_vec(
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            phase,
            &label.child("mul_layer"),
        )
    }

    /// Broadcasts a checked vector opening batch.
    pub fn open_many_checked_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label.child("open_many_checked"),
            values,
        )
    }

    /// Collects a checked vector opening batch.
    pub fn collect_open_many_checked_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_broadcast_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            &label.child("open_many_checked"),
        )
    }

    /// Broadcasts a vector assert-zero check batch.
    pub fn assert_zero_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            &label.child("assert_zero_vec"),
            values,
        )
    }

    /// Collects a vector assert-zero check batch.
    pub fn collect_assert_zero_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            &label.child("assert_zero_vec"),
        )
    }

    /// Broadcasts a vector bitness check batch.
    pub fn assert_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertBitCheck,
            &label.child("assert_bit_vec"),
            values,
        )
    }

    /// Collects a vector bitness check batch.
    pub fn collect_assert_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertBitCheck,
            &label.child("assert_bit_vec"),
        )
    }

    /// Sends random-bit vector shares to one receiver.
    pub fn send_random_bit_vec(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.send_directed_vec(
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label.child("random_bit_vec"),
            values,
        )
    }

    /// Collects random-bit vector shares for one receiver.
    pub fn collect_random_bit_vec(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_directed_vec(
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            &label.child("random_bit_vec"),
        )
    }

    /// Broadcasts a vector comparison-to-public check batch.
    pub fn comparison_to_public_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
            &label.child("comparison_to_public_vec"),
            values,
        )
    }

    /// Collects a vector comparison-to-public check batch.
    pub fn collect_comparison_to_public_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::ComparisonToPublicCheck,
            &label.child("comparison_to_public_vec"),
        )
    }

    /// Broadcasts a vector equality-to-public check batch.
    pub fn equality_to_public_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::EqualityToPublicCheck,
            &label.child("equality_to_public_vec"),
            values,
        )
    }

    /// Collects a vector equality-to-public check batch.
    pub fn collect_equality_to_public_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.collect_broadcast_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::EqualityToPublicCheck,
            &label.child("equality_to_public_vec"),
        )
    }

    /// Broadcasts a vector bit-sum / threshold check batch.
    pub fn bit_sum_threshold_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner.drive_bit_sum_threshold_check_vec(label, values)
    }

    /// Collects a vector bit-sum / threshold check batch.
    pub fn collect_bit_sum_threshold_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner.drive_collect_bit_sum_threshold_check_vec(label)
    }

    /// Broadcasts a private one-hot selection check batch.
    pub fn private_selection_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner.drive_private_selection_check_vec(label, values)
    }

    /// Collects a private one-hot selection check batch.
    pub fn collect_private_selection_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner.drive_collect_private_selection_check_vec(label)
    }

    /// Broadcasts the vector masked opening `C = t + A_mask mod q` for
    /// Power2Round.
    pub fn drive_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner.drive_power2round_masked_c_vec(label, values)
    }

    /// Broadcasts preprocessing masked-broadcast consistency vector lanes.
    pub fn drive_preprocessing_masked_broadcast_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_preprocessing_masked_broadcast_vec(label, values)
    }

    /// Collects preprocessing masked-broadcast consistency vector lanes.
    pub fn drive_collect_preprocessing_masked_broadcast_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_preprocessing_masked_broadcast_vec(label)
    }

    /// Broadcasts preprocessing CarryCompare certification vector lanes.
    pub fn drive_preprocessing_carry_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_preprocessing_carry_compare_vec(label, values)
    }

    /// Collects preprocessing CarryCompare certification vector lanes.
    pub fn drive_collect_preprocessing_carry_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_preprocessing_carry_compare_vec(label)
    }

    /// Broadcasts preprocessing CEF/BCC certification vector lanes.
    pub fn drive_preprocessing_cef_bcc_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner.drive_preprocessing_cef_bcc_vec(label, values)
    }

    /// Collects preprocessing CEF/BCC certification vector lanes.
    pub fn drive_collect_preprocessing_cef_bcc_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner.drive_collect_preprocessing_cef_bcc_vec(label)
    }

    /// Collects vector masked openings and advances the Power2Round driver.
    pub fn drive_collect_power2round_masked_c_vec_and_advance(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<Vec<(PartyId, Vec<Coeff>)>>, DkgError>
    {
        self.inner
            .drive_collect_power2round_masked_c_vec_and_advance(driver, label)
    }

    /// Broadcasts the vector wrap comparison `[A_mask > C]`.
    pub fn drive_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner.drive_power2round_wrap_compare_vec(label, values)
    }

    /// Collects vector wrap comparisons.
    pub fn drive_collect_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner.drive_collect_power2round_wrap_compare_vec(label)
    }

    /// Broadcasts one vector subtractor/borrow phase for canonical `R`
    /// recovery.
    pub fn drive_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_power2round_subtractor_share_vec(label, bit_idx, values)
    }

    /// Collects one vector subtractor/borrow phase.
    pub fn drive_collect_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_power2round_subtractor_share_vec(label, bit_idx)
    }

    /// Broadcasts one vector canonical-bit bitness check.
    pub fn drive_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_power2round_canonical_bitness_check_vec(label, bit_idx, values)
    }

    /// Collects one vector canonical-bit bitness check.
    pub fn drive_collect_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_power2round_canonical_bitness_check_vec(label, bit_idx)
    }

    /// Broadcasts the vector canonical range check `R < q`.
    pub fn drive_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_power2round_canonical_range_check_vec(label, values)
    }

    /// Collects the vector canonical range check `R < q`.
    pub fn drive_collect_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_power2round_canonical_range_check_vec(label)
    }

    /// Broadcasts the vector equality check `sum 2^j R_j == t mod q`.
    pub fn drive_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_power2round_equality_check_vec(label, values)
    }

    /// Collects the vector equality check `sum 2^j R_j == t mod q`.
    pub fn drive_collect_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_power2round_equality_check_vec(label)
    }

    /// Collects all vector canonical-recovery phases and advances the
    /// Power2Round driver.
    pub fn drive_collect_power2round_canonical_recovery_all_vec_and_advance<P: MlDsaParams>(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<usize>, DkgError> {
        self.inner
            .drive_collect_power2round_canonical_recovery_all_vec_and_advance::<P>(
                driver, config, label,
            )
    }

    /// Broadcasts one vector add-4095 carry/share phase.
    pub fn drive_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_power2round_add4095_share_vec(label, bit_idx, values)
    }

    /// Collects one vector add-4095 carry/share phase.
    pub fn drive_collect_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_power2round_add4095_share_vec(label, bit_idx)
    }

    /// Collects all vector add-4095 phases and advances the Power2Round
    /// driver.
    pub fn drive_collect_power2round_add4095_all_vec_and_advance<P: MlDsaParams>(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<usize>, DkgError> {
        self.inner
            .drive_collect_power2round_add4095_all_vec_and_advance::<P>(driver, config, label)
    }

    /// Broadcasts one vector public `t1` bit-opening phase.
    pub fn drive_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.inner
            .drive_power2round_t1_bit_vec(label, bit_idx, values)
    }

    /// Collects one vector public `t1` bit-opening phase.
    pub fn drive_collect_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.inner
            .drive_collect_power2round_t1_bit_vec(label, bit_idx)
    }

    /// Collects `t1` bit openings and certifies a release-capable
    /// Power2Round output using durable vector IT-MPC runtime evidence.
    ///
    /// The lower-level Power2Round phase driver can prove phase ordering and
    /// `t1` binding, but release-capable output must also prove that the
    /// embedding runtime executed the vector MPC operation families used by
    /// the circuit. This method is the normal-build boundary that combines
    /// both pieces and rejects phase-ordering-only transcripts.
    pub fn drive_collect_power2round_t1_bits_and_certify<P: MlDsaParams>(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
        config: &DkgConfig,
        assembly_label: PublicKeyAssemblyLabel,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<ProductionPower2RoundVectorCollectResult<ProductionPower2RoundOutput>, DkgError>
    {
        let output = match self
            .inner
            .drive_collect_power2round_t1_bits_and_certify::<P>(
                driver,
                config,
                assembly_label,
                label,
            )? {
            ProductionPower2RoundVectorCollectResult::Waiting(statuses) => {
                return Ok(ProductionPower2RoundVectorCollectResult::Waiting(statuses));
            }
            ProductionPower2RoundVectorCollectResult::Collected(output) => output,
        };
        let (t1, evidence, _) = output.into_parts();
        ensure_power2round_state_owned_nonlinear_wire_log_for_release(
            self.inner.runtime().wire_log(),
        )?;
        let runtime_evidence = self.runtime_evidence()?;
        let output = ProductionPower2RoundOutput::new_with_runtime_evidence(
            config,
            assembly_label,
            t1,
            evidence,
            Some(runtime_evidence),
        )?;
        Ok(ProductionPower2RoundVectorCollectResult::Collected(output))
    }
}

fn uniform_collected_vector_lane_count(
    values: &[(PartyId, Vec<Coeff>)],
) -> Result<usize, DkgError> {
    let lane_count =
        values
            .first()
            .map(|(_, lanes)| lanes.len())
            .ok_or(DkgError::MissingRoundMessages {
                round: DkgRound::Finalize,
                expected: 1,
                got: 0,
            })?;
    if lane_count == 0 || values.iter().any(|(_, lanes)| lanes.len() != lane_count) {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    Ok(lane_count)
}

fn record_power2round_lane_count(
    expected: Option<usize>,
    values: &[(PartyId, Vec<Coeff>)],
) -> Result<usize, DkgError> {
    let current = uniform_collected_vector_lane_count(values)?;
    if let Some(expected) = expected {
        if current != expected {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
    }
    Ok(current)
}

fn ensure_collected_vector_reconstructs_zero<P: MlDsaParams>(
    config: &DkgConfig,
    values: &[(PartyId, Vec<Coeff>)],
) -> Result<(), DkgError> {
    let opened = reconstruct_collected_prime_field_vector::<P>(config, values)?;
    if opened.iter().all(|&value| value == 0) {
        Ok(())
    } else {
        Err(DkgError::Power2RoundCanonicalityFailure)
    }
}

fn reconstruct_collected_prime_field_vector<P: MlDsaParams>(
    config: &DkgConfig,
    values: &[(PartyId, Vec<Coeff>)],
) -> Result<Vec<Coeff>, DkgError> {
    let lane_count = uniform_collected_vector_lane_count(values)?;
    let threshold = usize::from(config.threshold);
    if values.len() < threshold {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Finalize,
            expected: threshold,
            got: values.len(),
        });
    }
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|(party, _)| party.0);
    let interpolation_points = sorted
        .iter()
        .map(|(party, _)| config.interpolation_point::<P>(*party))
        .collect::<Result<Vec<_>, DkgError>>()?;
    let base_points = interpolation_points
        .iter()
        .copied()
        .take(threshold)
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(lane_count);
    for lane_idx in 0..lane_count {
        let shares = interpolation_points
            .iter()
            .copied()
            .zip(sorted.iter())
            .map(|(point, (_, lanes))| ShamirScalarShare {
                point,
                value: lanes[lane_idx],
            })
            .collect::<Vec<_>>();
        let base_shares = shares.iter().copied().take(threshold).collect::<Vec<_>>();
        for share in &shares {
            let expected =
                interpolate_scalar_at_point::<P>(&base_points, &base_shares, share.point)?;
            if expected != share.value {
                return Err(DkgError::Power2RoundCanonicalityFailure);
            }
        }
        out.push(reconstruct_scalar_at_zero::<P>(&base_shares)?);
    }
    Ok(out)
}

fn interpolate_scalar_at_point<P: MlDsaParams>(
    base_points: &[u32],
    shares: &[ShamirScalarShare],
    x: u32,
) -> Result<Coeff, DkgError> {
    if base_points.len() != shares.len() || shares.is_empty() {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let q = i64::from(P::Q);
    let x = i64::from(x).rem_euclid(q);
    let mut value = 0i64;
    for (i, share) in shares.iter().enumerate() {
        let xi = i64::from(base_points[i]).rem_euclid(q);
        let mut numerator = 1i64;
        let mut denominator = 1i64;
        for (j, &point_j) in base_points.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = i64::from(point_j).rem_euclid(q);
            if xi == xj {
                return Err(DkgError::DuplicateInterpolationPoint);
            }
            numerator = (numerator * (x - xj).rem_euclid(q)).rem_euclid(q);
            denominator = (denominator * (xi - xj).rem_euclid(q)).rem_euclid(q);
        }
        let term = (i64::from(share.value) * numerator).rem_euclid(q)
            * mod_inverse_prime_i64(denominator, q);
        value = (value + term.rem_euclid(q)).rem_euclid(q);
    }
    Ok(value as Coeff)
}

fn mod_inverse_prime_i64(value: i64, modulus: i64) -> i64 {
    mod_pow_i64(value, modulus - 2, modulus)
}

fn mod_pow_i64(mut base: i64, mut exponent: i64, modulus: i64) -> i64 {
    base = base.rem_euclid(modulus);
    let mut result = 1i64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (result * base).rem_euclid(modulus);
        }
        base = (base * base).rem_euclid(modulus);
        exponent >>= 1;
    }
    result
}

impl<T, L> TransportPrimeFieldMpcPartyRuntime<T, L>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: PrimeFieldMpcWireMessageLog,
{
    /// Creates a single-party runtime.
    pub fn new(state: TransportPrimeFieldMpcStateMachine<T>, wire_log: L) -> Self {
        Self { state, wire_log }
    }

    /// Returns the local party.
    pub fn local_party(&self) -> PartyId {
        self.state.local_party()
    }

    /// Returns the state machine.
    pub fn state(&self) -> &TransportPrimeFieldMpcStateMachine<T> {
        &self.state
    }

    /// Returns the mutable state machine.
    pub fn state_mut(&mut self) -> &mut TransportPrimeFieldMpcStateMachine<T> {
        &mut self.state
    }

    /// Returns the durable wire-message log.
    pub fn wire_log(&self) -> &L {
        &self.wire_log
    }

    /// Returns the mutable durable wire-message log.
    pub fn wire_log_mut(&mut self) -> &mut L {
        &mut self.wire_log
    }

    /// Replays locally sent messages after restart without rebuilding them.
    pub fn resume_sent_messages(&mut self) -> Result<(), DkgError> {
        self.state.replay_logged_sent_messages(&self.wire_log)
    }

    /// Drives one local directed-send phase and reports the emitted message.
    pub fn drive_send_directed_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.state.send_directed_phase_logged(
            &mut self.wire_log,
            receiver,
            kind,
            phase,
            label,
            value,
        )?;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver,
            kind,
            phase,
            label_hash: power2round_label_hash(label),
        })
    }

    /// Drives one local directed-send vector phase and reports the emitted
    /// message.
    pub fn drive_send_directed_phase_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.state.send_directed_phase_vec_logged(
            &mut self.wire_log,
            receiver,
            kind,
            phase,
            label,
            values,
        )?;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentPrivate {
            receiver,
            kind,
            phase,
            label_hash: power2round_label_hash(label),
        })
    }

    /// Drives one local broadcast-send vector phase and reports the emitted
    /// message.
    pub fn drive_broadcast_phase_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.state
            .broadcast_phase_vec_logged(&mut self.wire_log, kind, phase, label, values)?;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentBroadcast {
            kind,
            phase,
            label_hash: power2round_label_hash(label),
        })
    }

    /// Drives the Power2Round vector masked-opening broadcast.
    pub fn drive_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child("open_masked_c");
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &phase_label,
            values,
        )
    }

    /// Drives the preprocessing masked-broadcast consistency vector opening.
    pub fn drive_preprocessing_masked_broadcast_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::PreprocessingMaskedBroadcast,
            &label.child("preprocessing_masked_broadcast"),
            values,
        )
    }

    /// Attempts to collect the preprocessing masked-broadcast consistency
    /// vector opening.
    pub fn drive_collect_preprocessing_masked_broadcast_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::PreprocessingMaskedBroadcast,
            &label.child("preprocessing_masked_broadcast"),
        )
    }

    /// Drives a preprocessing CarryCompare certification vector check.
    pub fn drive_preprocessing_carry_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCarryCompare,
            &label.child("preprocessing_carry_compare"),
            values,
        )
    }

    /// Attempts to collect a preprocessing CarryCompare certification vector
    /// check.
    pub fn drive_collect_preprocessing_carry_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCarryCompare,
            &label.child("preprocessing_carry_compare"),
        )
    }

    /// Drives a preprocessing CEF/BCC certification vector check.
    pub fn drive_preprocessing_cef_bcc_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCefBcc,
            &label.child("preprocessing_cef_bcc"),
            values,
        )
    }

    /// Attempts to collect a preprocessing CEF/BCC certification vector check.
    pub fn drive_collect_preprocessing_cef_bcc_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PreprocessingCefBcc,
            &label.child("preprocessing_cef_bcc"),
        )
    }

    /// Drives one local broadcast-send phase and reports the emitted message.
    pub fn drive_broadcast_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        self.state
            .broadcast_phase_logged(&mut self.wire_log, kind, phase, label, value)?;
        Ok(PrimeFieldMpcPhaseDriverStatus::SentBroadcast {
            kind,
            phase,
            label_hash: power2round_label_hash(label),
        })
    }

    /// Attempts to collect one directed phase.
    ///
    /// If the transport has fewer messages than the configured party count,
    /// the driver reports `WaitingPrivate` instead of treating it as a protocol
    /// failure. Malformed, replayed, wrong-session, or duplicate messages still
    /// return an error.
    pub fn drive_collect_directed_phase(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Coeff)>), DkgError> {
        let label_hash = power2round_label_hash(label);
        let expected = self.state.config.parties.len();
        let available = self
            .state
            .transport()
            .collect_private_round(
                receiver.0,
                RoundId::DkgPrimeFieldMpc,
                &self.state.expected_context(),
            )
            .map_err(map_transport_error)?;
        if available.len() < expected {
            return Ok((
                PrimeFieldMpcPhaseDriverStatus::WaitingPrivate {
                    receiver,
                    kind,
                    phase,
                    label_hash,
                    expected,
                    got: available.len(),
                },
                Vec::new(),
            ));
        }
        let values = self.state.collect_directed_phase_logged(
            &mut self.wire_log,
            receiver,
            kind,
            phase,
            label,
        )?;
        Ok((
            PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: Some(receiver),
                kind,
                phase,
                label_hash,
                senders: values.iter().map(|(party, _)| *party).collect(),
            },
            values,
        ))
    }

    /// Attempts to collect one directed vector phase.
    pub fn drive_collect_directed_phase_vec(
        &mut self,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let label_hash = power2round_label_hash(label);
        let expected = self.state.config.parties.len();
        let available = self
            .state
            .transport()
            .collect_private_round(
                receiver.0,
                RoundId::DkgPrimeFieldMpc,
                &self.state.expected_context(),
            )
            .map_err(map_transport_error)?;
        if available.len() < expected {
            return Ok((
                PrimeFieldMpcPhaseDriverStatus::WaitingPrivate {
                    receiver,
                    kind,
                    phase,
                    label_hash,
                    expected,
                    got: available.len(),
                },
                Vec::new(),
            ));
        }
        let values = self.state.collect_directed_phase_vec_logged(
            &mut self.wire_log,
            receiver,
            kind,
            phase,
            label,
        )?;
        Ok((
            PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: Some(receiver),
                kind,
                phase,
                label_hash,
                senders: values.iter().map(|(party, _)| *party).collect(),
            },
            values,
        ))
    }

    /// Attempts to collect one equivocation-resistant broadcast phase.
    pub fn drive_collect_broadcast_phase(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Coeff)>), DkgError> {
        let label_hash = power2round_label_hash(label);
        let expected = self.state.config.parties.len();
        match self.state.transport().collect_equivocation_checked_round(
            RoundId::DkgPrimeFieldMpc,
            &self.state.expected_context(),
        ) {
            Ok(messages) if messages.len() < expected => {
                return Ok((
                    PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                        kind,
                        phase,
                        label_hash,
                        expected,
                        got: messages.len(),
                    },
                    Vec::new(),
                ));
            }
            Ok(_) => {}
            Err(TransportError::IncompleteBroadcastView { got, .. }) => {
                return Ok((
                    PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                        kind,
                        phase,
                        label_hash,
                        expected,
                        got,
                    },
                    Vec::new(),
                ));
            }
            Err(err) => return Err(map_transport_error(err)),
        }
        let values =
            self.state
                .collect_broadcast_phase_logged(&mut self.wire_log, kind, phase, label)?;
        if values.len() < expected {
            return Ok((
                PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                    kind,
                    phase,
                    label_hash,
                    expected,
                    got: values.len(),
                },
                Vec::new(),
            ));
        }
        Ok((
            PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind,
                phase,
                label_hash,
                senders: values.iter().map(|(party, _)| *party).collect(),
            },
            values,
        ))
    }

    /// Attempts to collect one equivocation-resistant broadcast vector phase.
    pub fn drive_collect_broadcast_phase_vec(
        &mut self,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let label_hash = power2round_label_hash(label);
        let expected = self.state.config.parties.len();
        match self.state.transport().collect_equivocation_checked_round(
            RoundId::DkgPrimeFieldMpc,
            &self.state.expected_context(),
        ) {
            Ok(messages) if messages.len() < expected => {
                return Ok((
                    PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                        kind,
                        phase,
                        label_hash,
                        expected,
                        got: messages.len(),
                    },
                    Vec::new(),
                ));
            }
            Ok(_) => {}
            Err(TransportError::IncompleteBroadcastView { got, .. }) => {
                return Ok((
                    PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                        kind,
                        phase,
                        label_hash,
                        expected,
                        got,
                    },
                    Vec::new(),
                ));
            }
            Err(err) => return Err(map_transport_error(err)),
        }
        let values = self.state.collect_broadcast_phase_vec_logged(
            &mut self.wire_log,
            kind,
            phase,
            label,
        )?;
        if values.len() < expected {
            return Ok((
                PrimeFieldMpcPhaseDriverStatus::WaitingBroadcast {
                    kind,
                    phase,
                    label_hash,
                    expected,
                    got: values.len(),
                },
                Vec::new(),
            ));
        }
        Ok((
            PrimeFieldMpcPhaseDriverStatus::Collected {
                receiver: None,
                kind,
                phase,
                label_hash,
                senders: values.iter().map(|(party, _)| *party).collect(),
            },
            values,
        ))
    }

    /// Attempts to collect the Power2Round vector masked-opening broadcast.
    pub fn drive_collect_power2round_masked_c_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child("open_masked_c");
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::Power2RoundMaskedOpenC,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector wrap-comparison broadcast.
    pub fn drive_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child("a_gt_c");
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector wrap-comparison broadcast.
    pub fn drive_collect_power2round_wrap_compare_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child("a_gt_c");
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundWrapCompare,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector subtractor/borrow broadcast.
    pub fn drive_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child(format!("recover_r_bits/subtract_bit_{bit_idx}"));
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector subtractor/borrow broadcast.
    pub fn drive_collect_power2round_subtractor_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child(format!("recover_r_bits/subtract_bit_{bit_idx}"));
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::SubtractorShare,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector canonical bitness-check broadcast.
    pub fn drive_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero"));
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector canonical bitness-check
    /// broadcast.
    pub fn drive_collect_power2round_canonical_bitness_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child(format!("r_bits_boolean/bit_{bit_idx}/assert_zero"));
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector canonical range-check broadcast.
    pub fn drive_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child("r_lt_q");
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector canonical range-check broadcast.
    pub fn drive_collect_power2round_canonical_range_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child("r_lt_q");
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector equality-check broadcast.
    pub fn drive_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child("assert_bits_equal_r_mod_q");
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector equality-check broadcast.
    pub fn drive_collect_power2round_equality_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child("assert_bits_equal_r_mod_q");
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundEqualityCheck,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector add-4095 carry/share broadcast.
    pub fn drive_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child(format!("add_4095/carry_{bit_idx}"));
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector add-4095 carry/share broadcast.
    pub fn drive_collect_power2round_add4095_share_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child(format!("add_4095/carry_{bit_idx}"));
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::Power2RoundAdd4095,
            &phase_label,
        )
    }

    /// Drives the Power2Round vector `t1` public bit-opening broadcast.
    pub fn drive_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child(format!("open_t1_bits/bit_{bit_idx}"));
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect the Power2Round vector `t1` public bit-opening broadcast.
    pub fn drive_collect_power2round_t1_bit_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        bit_idx: usize,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child(format!("open_t1_bits/bit_{bit_idx}"));
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::T1BitOpening,
            &phase_label,
        )
    }

    /// Drives a generic vector bit-sum / public-threshold check broadcast.
    pub fn drive_bit_sum_threshold_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child("bit_sum_threshold_check");
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::BitSumThresholdCheck,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect a generic vector bit-sum / public-threshold check
    /// broadcast.
    pub fn drive_collect_bit_sum_threshold_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child("bit_sum_threshold_check");
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::BitSumThresholdCheck,
            &phase_label,
        )
    }

    /// Drives a generic vector private one-hot selection check broadcast.
    pub fn drive_private_selection_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        values: &[Coeff],
    ) -> Result<PrimeFieldMpcPhaseDriverStatus, DkgError> {
        let phase_label = label.child("private_selection_check");
        self.drive_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PrivateSelectionCheck,
            &phase_label,
            values,
        )
    }

    /// Attempts to collect a generic vector private one-hot selection check
    /// broadcast.
    pub fn drive_collect_private_selection_check_vec(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<(PrimeFieldMpcPhaseDriverStatus, Vec<(PartyId, Vec<Coeff>)>), DkgError> {
        let phase_label = label.child("private_selection_check");
        self.drive_collect_broadcast_phase_vec(
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::PrivateSelectionCheck,
            &phase_label,
        )
    }

    /// Sends this party's multiplication degree-reduction share.
    pub fn send_mul_degree_reduction_share(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.state.send_directed_phase_logged(
            &mut self.wire_log,
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
            value,
        )
    }

    /// Collects multiplication degree-reduction shares for this party.
    pub fn collect_mul_degree_reduction_shares(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_directed_phase_logged(
            &mut self.wire_log,
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
        )
    }

    /// Recovers already accepted multiplication shares from the durable log.
    pub fn recover_mul_degree_reduction_shares(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_directed_phase_from_wire_log(
            &self.wire_log,
            receiver,
            PrimeFieldMpcRoundKind::MulDegreeReduce,
            PrimeFieldMpcPhase::MulDegreeReductionShare,
            label,
        )
    }

    /// Sends this party's random-bit contribution share.
    pub fn send_random_bit_share(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.state.send_directed_phase_logged(
            &mut self.wire_log,
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            label,
            value,
        )
    }

    /// Collects random-bit contribution shares for this party.
    pub fn collect_random_bit_shares(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_directed_phase_logged(
            &mut self.wire_log,
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            label,
        )
    }

    /// Recovers already accepted random-bit shares from the durable log.
    pub fn recover_random_bit_shares(
        &mut self,
        receiver: PartyId,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_directed_phase_from_wire_log(
            &self.wire_log,
            receiver,
            PrimeFieldMpcRoundKind::RandomBit,
            PrimeFieldMpcPhase::RandomBitShare,
            label,
        )
    }

    /// Broadcasts this party's checked-opening share.
    pub fn broadcast_open_share(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.state.broadcast_phase_logged(
            &mut self.wire_log,
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            label,
            value,
        )
    }

    /// Collects checked-opening shares.
    pub fn collect_open_shares(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_broadcast_phase_logged(
            &mut self.wire_log,
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            label,
        )
    }

    /// Recovers already accepted checked-opening shares from the durable log.
    pub fn recover_open_shares(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_broadcast_phase_from_wire_log(
            &self.wire_log,
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
            label,
        )
    }

    /// Broadcasts this party's assert-zero share.
    pub fn broadcast_assert_zero_share(
        &mut self,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        self.state.broadcast_phase_logged(
            &mut self.wire_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            label,
            value,
        )
    }

    /// Collects assert-zero shares.
    pub fn collect_assert_zero_shares(
        &mut self,
        label: &Power2RoundTranscriptLabel,
    ) -> Result<Vec<(PartyId, Coeff)>, DkgError> {
        self.state.collect_broadcast_phase_logged(
            &mut self.wire_log,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
            label,
        )
    }
}

pub(crate) fn wire_suite(suite: DkgSuite) -> WireSuiteId {
    match suite {
        DkgSuite::MlDsa44 => WireSuiteId::MlDsa44,
        DkgSuite::MlDsa65 => WireSuiteId::MlDsa65,
        DkgSuite::MlDsa87 => WireSuiteId::MlDsa87,
    }
}

pub(crate) fn prime_field_mpc_session_id(config: &DkgConfig) -> [u8; 32] {
    hash_bytes32(
        b"TALUS-DKG-v1/prime-field-mpc-session",
        &config.transcript_hash().0,
    )
}

pub(crate) fn default_prime_field_mpc_expected_context(config: &DkgConfig) -> ExpectedContext {
    ExpectedContext {
        suite: wire_suite(config.suite),
        keygen_transcript_hash: config.transcript_hash().0,
        session_id: prime_field_mpc_session_id(config),
        signing_set_hash: talus_wire::signing_set_hash(
            &config
                .parties
                .iter()
                .map(|party| party.0)
                .collect::<Vec<_>>(),
        ),
        allowed_parties: config.parties.iter().map(|party| party.0).collect(),
    }
}

pub(crate) fn validate_prime_field_expected_context(
    config: &DkgConfig,
    expected: &ExpectedContext,
) -> Result<(), DkgError> {
    let default = default_prime_field_mpc_expected_context(config);
    if expected.suite != default.suite
        || expected.keygen_transcript_hash != default.keygen_transcript_hash
        || expected.signing_set_hash != default.signing_set_hash
        || expected.allowed_parties != default.allowed_parties
        || expected.session_id == [0; 32]
    {
        return Err(DkgError::PrimeFieldMpcContextMismatch);
    }
    Ok(())
}

pub(crate) fn prime_field_round_kind_to_u8(kind: PrimeFieldMpcRoundKind) -> u8 {
    match kind {
        PrimeFieldMpcRoundKind::MulDegreeReduce => 1,
        PrimeFieldMpcRoundKind::Open => 2,
        PrimeFieldMpcRoundKind::AssertZero => 3,
        PrimeFieldMpcRoundKind::RandomBit => 4,
    }
}

pub(crate) fn prime_field_round_kind_from_u8(value: u8) -> Option<PrimeFieldMpcRoundKind> {
    match value {
        1 => Some(PrimeFieldMpcRoundKind::MulDegreeReduce),
        2 => Some(PrimeFieldMpcRoundKind::Open),
        3 => Some(PrimeFieldMpcRoundKind::AssertZero),
        4 => Some(PrimeFieldMpcRoundKind::RandomBit),
        _ => None,
    }
}

pub(crate) fn prime_field_phase_to_u8(phase: PrimeFieldMpcPhase) -> u8 {
    match phase {
        PrimeFieldMpcPhase::RandomBitShare => 1,
        PrimeFieldMpcPhase::MulDegreeReductionShare => 2,
        PrimeFieldMpcPhase::OpenShare => 3,
        PrimeFieldMpcPhase::AssertZeroShare => 4,
        PrimeFieldMpcPhase::ComparatorShare => 5,
        PrimeFieldMpcPhase::SubtractorShare => 6,
        PrimeFieldMpcPhase::T1BitOpening => 7,
        PrimeFieldMpcPhase::Power2RoundMaskBit => 8,
        PrimeFieldMpcPhase::Power2RoundMaskRangeCheck => 9,
        PrimeFieldMpcPhase::Power2RoundMaskedOpenC => 10,
        PrimeFieldMpcPhase::Power2RoundWrapCompare => 11,
        PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck => 12,
        PrimeFieldMpcPhase::Power2RoundEqualityCheck => 13,
        PrimeFieldMpcPhase::Power2RoundAdd4095 => 14,
        PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck => 15,
        PrimeFieldMpcPhase::BitSumThresholdCheck => 16,
        PrimeFieldMpcPhase::PrivateSelectionCheck => 17,
        PrimeFieldMpcPhase::AssertBitCheck => 18,
        PrimeFieldMpcPhase::ComparisonToPublicCheck => 19,
        PrimeFieldMpcPhase::EqualityToPublicCheck => 20,
        PrimeFieldMpcPhase::PreprocessingMaskedBroadcast => 21,
        PrimeFieldMpcPhase::PreprocessingCarryCompare => 22,
        PrimeFieldMpcPhase::PreprocessingCefBcc => 23,
    }
}

pub(crate) fn prime_field_phase_from_u8(value: u8) -> Option<PrimeFieldMpcPhase> {
    match value {
        1 => Some(PrimeFieldMpcPhase::RandomBitShare),
        2 => Some(PrimeFieldMpcPhase::MulDegreeReductionShare),
        3 => Some(PrimeFieldMpcPhase::OpenShare),
        4 => Some(PrimeFieldMpcPhase::AssertZeroShare),
        5 => Some(PrimeFieldMpcPhase::ComparatorShare),
        6 => Some(PrimeFieldMpcPhase::SubtractorShare),
        7 => Some(PrimeFieldMpcPhase::T1BitOpening),
        8 => Some(PrimeFieldMpcPhase::Power2RoundMaskBit),
        9 => Some(PrimeFieldMpcPhase::Power2RoundMaskRangeCheck),
        10 => Some(PrimeFieldMpcPhase::Power2RoundMaskedOpenC),
        11 => Some(PrimeFieldMpcPhase::Power2RoundWrapCompare),
        12 => Some(PrimeFieldMpcPhase::Power2RoundCanonicalRangeCheck),
        13 => Some(PrimeFieldMpcPhase::Power2RoundEqualityCheck),
        14 => Some(PrimeFieldMpcPhase::Power2RoundAdd4095),
        15 => Some(PrimeFieldMpcPhase::Power2RoundCanonicalBitnessCheck),
        16 => Some(PrimeFieldMpcPhase::BitSumThresholdCheck),
        17 => Some(PrimeFieldMpcPhase::PrivateSelectionCheck),
        18 => Some(PrimeFieldMpcPhase::AssertBitCheck),
        19 => Some(PrimeFieldMpcPhase::ComparisonToPublicCheck),
        20 => Some(PrimeFieldMpcPhase::EqualityToPublicCheck),
        21 => Some(PrimeFieldMpcPhase::PreprocessingMaskedBroadcast),
        22 => Some(PrimeFieldMpcPhase::PreprocessingCarryCompare),
        23 => Some(PrimeFieldMpcPhase::PreprocessingCefBcc),
        _ => None,
    }
}

pub(crate) fn default_prime_field_phase(kind: PrimeFieldMpcRoundKind) -> PrimeFieldMpcPhase {
    match kind {
        PrimeFieldMpcRoundKind::MulDegreeReduce => PrimeFieldMpcPhase::MulDegreeReductionShare,
        PrimeFieldMpcRoundKind::Open => PrimeFieldMpcPhase::OpenShare,
        PrimeFieldMpcRoundKind::AssertZero => PrimeFieldMpcPhase::AssertZeroShare,
        PrimeFieldMpcRoundKind::RandomBit => PrimeFieldMpcPhase::RandomBitShare,
    }
}

pub(crate) fn map_transport_error(_err: TransportError) -> DkgError {
    DkgError::PrimeFieldMpcTransport
}

/// Secret canonical mask for Fq bit decomposition.
pub struct CanonicalMaskQ<S: Zeroize, B: Zeroize> {
    bits_le: Vec<B>,
    value: S,
}

impl<S: Zeroize, B: Zeroize> Zeroize for CanonicalMaskQ<S, B> {
    fn zeroize(&mut self) {
        self.bits_le.zeroize();
        self.value.zeroize();
    }
}

impl<S: Zeroize, B: Zeroize> Drop for CanonicalMaskQ<S, B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Public identifier for a one-time Power2Round mask batch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Power2RoundMaskBatchId {
    /// Transcript label hash for the mask batch.
    pub label_hash: [u8; 32],
    /// Number of coefficient lanes covered by this batch.
    pub lane_count: usize,
}

impl Power2RoundMaskBatchId {
    /// Builds an id for a mask batch bound to `label`.
    pub fn new(label: &Power2RoundTranscriptLabel, lane_count: usize) -> Self {
        Self {
            label_hash: power2round_label_hash(label),
            lane_count,
        }
    }
}

/// Durable one-time-use contract for Power2Round masks.
///
/// A production implementation must persist these ids before a mask batch is
/// used to open `C = t + A`. Reusing a mask batch can leak information about
/// different `t` values.
pub trait Power2RoundMaskUseLog {
    /// Marks a certified mask batch as consumed.
    fn mark_mask_consumed(&mut self, id: Power2RoundMaskBatchId) -> Result<(), DkgError>;
}

/// In-memory mask-use log for tests and local driver checks.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryPower2RoundMaskUseLog {
    consumed: Vec<Power2RoundMaskBatchId>,
}

impl InMemoryPower2RoundMaskUseLog {
    /// Returns consumed mask batch ids.
    pub fn consumed(&self) -> &[Power2RoundMaskBatchId] {
        &self.consumed
    }
}

impl Power2RoundMaskUseLog for InMemoryPower2RoundMaskUseLog {
    fn mark_mask_consumed(&mut self, id: Power2RoundMaskBatchId) -> Result<(), DkgError> {
        if self.consumed.contains(&id) {
            return Err(DkgError::Power2RoundMaskAlreadyConsumed);
        }
        self.consumed.push(id);
        Ok(())
    }
}

/// File-backed Power2Round mask-use log.
///
/// This log is local secret-state metadata: it does not contain mask values or
/// bits, only ids proving one-time mask batches were already consumed. Reopen
/// fails closed if a duplicate id appears in the log.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePower2RoundMaskUseLog {
    path: std::path::PathBuf,
    inner: InMemoryPower2RoundMaskUseLog,
}

#[cfg(feature = "std")]
impl FilePower2RoundMaskUseLog {
    /// Opens or creates a file-backed mask-use log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut inner = InMemoryPower2RoundMaskUseLog::default();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let id = parse_power2round_mask_use_log_line(line).ok_or(
                        DkgError::Power2RoundMaskUseLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.mark_mask_consumed(id)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns consumed mask ids.
    pub fn consumed(&self) -> &[Power2RoundMaskBatchId] {
        self.inner.consumed()
    }
}

#[cfg(feature = "std")]
impl Power2RoundMaskUseLog for FilePower2RoundMaskUseLog {
    fn mark_mask_consumed(&mut self, id: Power2RoundMaskBatchId) -> Result<(), DkgError> {
        self.inner.mark_mask_consumed(id)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(file, "{} {}", id.lane_count, Hex32(id.label_hash))
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }
}

#[cfg(feature = "std")]
fn parse_power2round_mask_use_log_line(line: &str) -> Option<Power2RoundMaskBatchId> {
    let mut fields = line.split_whitespace();
    let lane_count = fields.next()?.parse::<usize>().ok()?;
    let label_hash = parse_hex32(fields.next()?)?;
    if fields.next().is_some() || lane_count == 0 {
        return None;
    }
    Some(Power2RoundMaskBatchId {
        label_hash,
        lane_count,
    })
}

/// Unchecked batched canonical masks for Fq bit decomposition.
///
/// This type only proves shape and transcript binding. It must be certified
/// with `certify_power2round_mask_batch` before use.
pub struct UncheckedPower2RoundMaskBatch<S: Zeroize, B: Zeroize> {
    id: Power2RoundMaskBatchId,
    bits_by_bit: Vec<BitShareVec<B>>,
    value: ShareVec<S>,
}

impl<S: Zeroize, B: Zeroize> UncheckedPower2RoundMaskBatch<S, B> {
    /// Builds an unchecked mask batch.
    pub fn new(
        label: &Power2RoundTranscriptLabel,
        bits_by_bit: Vec<BitShareVec<B>>,
        value: ShareVec<S>,
    ) -> Result<Self, DkgError> {
        let lane_count = value.len();
        if lane_count == 0
            || bits_by_bit.len() != 23
            || bits_by_bit.iter().any(|bits| bits.len() != lane_count)
        {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        Ok(Self {
            id: Power2RoundMaskBatchId::new(label, lane_count),
            bits_by_bit,
            value,
        })
    }

    /// Returns this batch id.
    pub fn id(&self) -> Power2RoundMaskBatchId {
        self.id
    }
}

impl<S: Zeroize, B: Zeroize> fmt::Debug for UncheckedPower2RoundMaskBatch<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UncheckedPower2RoundMaskBatch")
            .field("id", &self.id)
            .field("bits_by_bit", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<S: Zeroize, B: Zeroize> Zeroize for UncheckedPower2RoundMaskBatch<S, B> {
    fn zeroize(&mut self) {
        self.bits_by_bit.zeroize();
        self.value.zeroize();
    }
}

impl<S: Zeroize, B: Zeroize> Drop for UncheckedPower2RoundMaskBatch<S, B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Certified batched canonical masks for Fq bit decomposition.
///
/// Certification means: every mask bit is boolean, mask values equal the bit
/// decompositions modulo q, every mask value is canonical (`A < q`), and the
/// batch is bound to one transcript label and lane count.
pub struct CertifiedPower2RoundMaskBatch<S: Zeroize, B: Zeroize> {
    id: Power2RoundMaskBatchId,
    bits_by_bit: Vec<BitShareVec<B>>,
    value: ShareVec<S>,
}

impl<S: Zeroize, B: Zeroize> CertifiedPower2RoundMaskBatch<S, B> {
    /// Returns this batch id.
    pub fn id(&self) -> Power2RoundMaskBatchId {
        self.id
    }

    /// Returns mask bits grouped by bit index.
    pub fn bits_by_bit(&self) -> &[BitShareVec<B>] {
        &self.bits_by_bit
    }

    /// Returns the batched mask values.
    pub fn value(&self) -> &ShareVec<S> {
        &self.value
    }

    /// Marks this certified batch consumed and returns the secret material for
    /// one Power2Round use.
    pub fn consume<L: Power2RoundMaskUseLog>(
        mut self,
        use_log: &mut L,
    ) -> Result<ConsumedPower2RoundMaskBatch<S, B>, DkgError> {
        use_log.mark_mask_consumed(self.id)?;
        Ok(ConsumedPower2RoundMaskBatch {
            id: self.id,
            bits_by_bit: core::mem::take(&mut self.bits_by_bit),
            value: core::mem::replace(&mut self.value, ShareVec::from_lanes(Vec::new())),
        })
    }
}

impl<S: Zeroize, B: Zeroize> fmt::Debug for CertifiedPower2RoundMaskBatch<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedPower2RoundMaskBatch")
            .field("id", &self.id)
            .field("bits_by_bit", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<S: Zeroize, B: Zeroize> Zeroize for CertifiedPower2RoundMaskBatch<S, B> {
    fn zeroize(&mut self) {
        self.bits_by_bit.zeroize();
        self.value.zeroize();
    }
}

impl<S: Zeroize, B: Zeroize> Drop for CertifiedPower2RoundMaskBatch<S, B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Consumed one-time Power2Round mask batch.
pub struct ConsumedPower2RoundMaskBatch<S: Zeroize, B: Zeroize> {
    id: Power2RoundMaskBatchId,
    bits_by_bit: Vec<BitShareVec<B>>,
    value: ShareVec<S>,
}

impl<S: Zeroize, B: Zeroize> ConsumedPower2RoundMaskBatch<S, B> {
    /// Returns this batch id.
    pub fn id(&self) -> Power2RoundMaskBatchId {
        self.id
    }

    /// Returns mask bits grouped by bit index.
    pub fn bits_by_bit(&self) -> &[BitShareVec<B>] {
        &self.bits_by_bit
    }

    /// Returns the batched mask values.
    pub fn value(&self) -> &ShareVec<S> {
        &self.value
    }
}

impl<S: Zeroize, B: Zeroize> fmt::Debug for ConsumedPower2RoundMaskBatch<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumedPower2RoundMaskBatch")
            .field("id", &self.id)
            .field("bits_by_bit", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<S: Zeroize, B: Zeroize> Zeroize for ConsumedPower2RoundMaskBatch<S, B> {
    fn zeroize(&mut self) {
        self.bits_by_bit.zeroize();
        self.value.zeroize();
    }
}

impl<S: Zeroize, B: Zeroize> Drop for ConsumedPower2RoundMaskBatch<S, B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Alias kept for existing test helpers while production code moves toward the
/// unchecked/certified/consumed type-state names above.
pub type CanonicalMaskQVec<S, B> = CertifiedPower2RoundMaskBatch<S, B>;

/// Hashes a Power2Round transcript label for wire records, mask ids, and
/// one-time-use logs.
pub fn power2round_label_hash(label: &Power2RoundTranscriptLabel) -> [u8; 32] {
    hash_bytes32(
        b"TALUS-DKG-v1/prime-field-mpc-label",
        label.as_str().as_bytes(),
    )
}

#[cfg(test)]
pub(crate) fn local_share_vec_from_shared_t<P: MlDsaParams>(
    config: &DkgConfig,
    shared_t: &SharedT,
) -> Result<ShareVec<PrimeFieldShare>, DkgError> {
    if shared_t.shares.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: shared_t.shares.len(),
        });
    }
    let mut lanes = Vec::with_capacity(P::K * P::N);
    for poly_idx in 0..P::K {
        for coeff_idx in 0..P::N {
            let shares = shared_t
                .shares
                .iter()
                .take(usize::from(config.threshold))
                .map(|share| ShamirScalarShare {
                    point: share.point,
                    value: share.t_share.polys()[poly_idx].coeffs()[coeff_idx],
                })
                .collect::<Vec<_>>();
            let value = reconstruct_scalar_at_zero::<P>(&shares)?;
            lanes.push(PrimeFieldShare::new::<P>(value));
        }
    }
    Ok(ShareVec::from_lanes(lanes))
}

#[cfg(test)]
pub(crate) fn shamir_share_from_shared_t<P: MlDsaParams>(
    config: &DkgConfig,
    shared_t: &SharedT,
    poly_idx: usize,
    coeff_idx: usize,
) -> Result<ShamirPrimeFieldShare, DkgError> {
    if shared_t.shares.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: config.parties.len(),
            got: shared_t.shares.len(),
        });
    }
    let mut shares = Vec::with_capacity(shared_t.shares.len());
    for (share, &party) in shared_t.shares.iter().zip(&config.parties) {
        let expected = config.interpolation_point::<P>(party)?;
        if share.point != expected {
            return Err(DkgError::InvalidSharePoint {
                party,
                expected,
                got: share.point,
            });
        }
        shares.push(ShamirScalarShare {
            point: share.point,
            value: share.t_share.polys()[poly_idx].coeffs()[coeff_idx],
        });
    }
    Ok(ShamirPrimeFieldShare { shares })
}

#[allow(dead_code)]
pub(crate) fn bit_not<P, B>(ctx: &B, x: B::BitShare) -> B::BitShare
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let one = ctx.public_const(1);
    let share = ctx.sub(one, ctx.bit_to_share(&x));
    ctx.bit_from_share_unchecked(share)
}

#[cfg(test)]
pub(crate) fn bit_and<P, B>(
    ctx: &mut B,
    x: B::BitShare,
    y: B::BitShare,
    label: Power2RoundTranscriptLabel,
) -> Result<B::BitShare, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let product = ctx.mul(ctx.bit_to_share(&x), ctx.bit_to_share(&y), label)?;
    Ok(ctx.bit_from_share_unchecked(product))
}

#[cfg(test)]
pub(crate) fn bit_or<P, B>(
    ctx: &mut B,
    x: B::BitShare,
    y: B::BitShare,
    label: Power2RoundTranscriptLabel,
) -> Result<B::BitShare, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let product = ctx.mul(
        ctx.bit_to_share(&x),
        ctx.bit_to_share(&y),
        label.child("and"),
    )?;
    let sum = ctx.add(ctx.bit_to_share(&x), ctx.bit_to_share(&y));
    Ok(ctx.bit_from_share_unchecked(ctx.sub(sum, product)))
}

#[cfg(test)]
pub(crate) fn bit_xor<P, B>(
    ctx: &mut B,
    x: B::BitShare,
    y: B::BitShare,
    label: Power2RoundTranscriptLabel,
) -> Result<B::BitShare, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let product = ctx.mul(
        ctx.bit_to_share(&x),
        ctx.bit_to_share(&y),
        label.child("and"),
    )?;
    let two_product = ctx.add(product.clone(), product);
    let sum = ctx.add(ctx.bit_to_share(&x), ctx.bit_to_share(&y));
    Ok(ctx.bit_from_share_unchecked(ctx.sub(sum, two_product)))
}

#[allow(dead_code)]
fn bit_shares_to_share_vec<P, B>(ctx: &B, bits: &[B::BitShare]) -> ShareVec<B::Share>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.share_vec_from_lanes(bits.iter().map(|bit| ctx.bit_to_share(bit)).collect())
}

#[allow(dead_code)]
fn share_vec_to_bit_vec_unchecked<P, B>(
    ctx: &B,
    shares: ShareVec<B::Share>,
) -> BitShareVec<B::BitShare>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.bit_vec_from_lanes(
        shares
            .into_lanes()
            .into_iter()
            .map(|share| ctx.bit_from_share_unchecked(share))
            .collect(),
    )
}

#[allow(dead_code)]
pub(crate) fn bit_not_vec<P, B>(ctx: &B, x: BitShareVec<B::BitShare>) -> BitShareVec<B::BitShare>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.bit_vec_from_lanes(
        x.into_lanes()
            .into_iter()
            .map(|bit| bit_not::<P, B>(ctx, bit))
            .collect(),
    )
}

#[allow(dead_code)]
pub(crate) fn bit_and_vec<P, B>(
    ctx: &mut B,
    x: BitShareVec<B::BitShare>,
    y: BitShareVec<B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if x.len() != y.len() {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }
    let x_shares = bit_shares_to_share_vec::<P, B>(ctx, x.lanes());
    let y_shares = bit_shares_to_share_vec::<P, B>(ctx, y.lanes());
    let product = ctx.mul_vec(x_shares, y_shares, label)?;
    Ok(share_vec_to_bit_vec_unchecked::<P, B>(ctx, product))
}

#[allow(dead_code)]
pub(crate) fn bit_xor_vec<P, B>(
    ctx: &mut B,
    x: BitShareVec<B::BitShare>,
    y: BitShareVec<B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if x.len() != y.len() {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }
    let x_shares = bit_shares_to_share_vec::<P, B>(ctx, x.lanes());
    let y_shares = bit_shares_to_share_vec::<P, B>(ctx, y.lanes());
    let product = ctx.mul_vec(
        bit_shares_to_share_vec::<P, B>(ctx, x.lanes()),
        bit_shares_to_share_vec::<P, B>(ctx, y.lanes()),
        label.child("and"),
    )?;
    let two_product = ctx.mul_public_const_vec(product, 2, label.child("double_and"))?;
    let sum = ctx.add_vec(x_shares, y_shares)?;
    let xor = ctx.sub_vec(sum, two_product)?;
    Ok(share_vec_to_bit_vec_unchecked::<P, B>(ctx, xor))
}

#[allow(dead_code)]
pub(crate) fn bit_or_vec<P, B>(
    ctx: &mut B,
    x: BitShareVec<B::BitShare>,
    y: BitShareVec<B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if x.len() != y.len() {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }
    let x_shares = bit_shares_to_share_vec::<P, B>(ctx, x.lanes());
    let y_shares = bit_shares_to_share_vec::<P, B>(ctx, y.lanes());
    let product = ctx.mul_vec(
        bit_shares_to_share_vec::<P, B>(ctx, x.lanes()),
        bit_shares_to_share_vec::<P, B>(ctx, y.lanes()),
        label.child("and"),
    )?;
    let sum = ctx.add_vec(x_shares, y_shares)?;
    let or = ctx.sub_vec(sum, product)?;
    Ok(share_vec_to_bit_vec_unchecked::<P, B>(ctx, or))
}

#[allow(dead_code)]
fn public_bit_vec<P, B>(ctx: &B, value: bool, len: usize) -> BitShareVec<B::BitShare>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.bit_vec_from_lanes((0..len).map(|_| ctx.public_bit(value)).collect())
}

#[allow(dead_code)]
fn public_bit_vec_from_bools<P, B>(ctx: &B, values: &[bool]) -> BitShareVec<B::BitShare>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.bit_vec_from_lanes(values.iter().map(|&value| ctx.public_bit(value)).collect())
}

#[cfg(test)]
pub(crate) fn assert_bit<P, B>(
    ctx: &mut B,
    bit: &B::BitShare,
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let value = ctx.bit_to_share(bit);
    let value_minus_one = ctx.sub(value.clone(), ctx.public_const(1));
    let product = ctx.mul(value, value_minus_one, label.child("b_times_b_minus_1"))?;
    ctx.assert_zero(product, label.child("assert_zero"))
}

#[cfg(test)]
pub(crate) fn assert_bits<P, B>(
    ctx: &mut B,
    bits: &[B::BitShare],
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let values = bit_shares_to_share_vec::<P, B>(ctx, bits);
    let values_minus_one = ctx.share_vec_from_lanes(
        bits.iter()
            .map(|bit| ctx.sub(ctx.bit_to_share(bit), ctx.public_const(1)))
            .collect(),
    );
    let products = ctx.mul_vec(values, values_minus_one, label.child("b_times_b_minus_1"))?;
    ctx.assert_zero_vec(products, label.child("assert_zero"))
}

#[cfg(test)]
pub(crate) fn assert_one_bit<P, B>(
    ctx: &mut B,
    bit: &B::BitShare,
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let one_minus = ctx.sub(ctx.public_const(1), ctx.bit_to_share(bit));
    ctx.assert_zero(one_minus, label)
}

#[cfg(test)]
pub(crate) fn lt_public<P, B>(
    ctx: &mut B,
    x: &[B::BitShare],
    constant: u32,
    label: Power2RoundTranscriptLabel,
) -> Result<B::BitShare, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let mut eq = ctx.public_bit(true);
    let mut lt = ctx.public_bit(false);

    for j in (0..x.len()).rev() {
        let xj = x[j].clone();
        let cj = ((constant >> j) & 1) == 1;
        if cj {
            let candidate = bit_and::<P, B>(
                ctx,
                eq.clone(),
                bit_not::<P, B>(ctx, xj.clone()),
                label.child(format!("lt_candidate_{j}")),
            )?;
            lt = bit_or::<P, B>(ctx, lt, candidate, label.child(format!("lt_update_{j}")))?;
            eq = bit_and::<P, B>(ctx, eq, xj, label.child(format!("eq_update_{j}")))?;
        } else {
            eq = bit_and::<P, B>(
                ctx,
                eq,
                bit_not::<P, B>(ctx, xj),
                label.child(format!("eq_update_{j}")),
            )?;
        }
    }

    Ok(lt)
}

#[cfg(test)]
pub(crate) fn gt_public<P, B>(
    ctx: &mut B,
    x: &[B::BitShare],
    constant: u32,
    label: Power2RoundTranscriptLabel,
) -> Result<B::BitShare, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let mut eq = ctx.public_bit(true);
    let mut gt = ctx.public_bit(false);

    for j in (0..x.len()).rev() {
        let xj = x[j].clone();
        let cj = ((constant >> j) & 1) == 1;
        if !cj {
            let candidate = bit_and::<P, B>(
                ctx,
                eq.clone(),
                xj.clone(),
                label.child(format!("gt_candidate_{j}")),
            )?;
            gt = bit_or::<P, B>(ctx, gt, candidate, label.child(format!("gt_update_{j}")))?;
            eq = bit_and::<P, B>(
                ctx,
                eq,
                bit_not::<P, B>(ctx, xj),
                label.child(format!("eq_update_{j}")),
            )?;
        } else {
            eq = bit_and::<P, B>(ctx, eq, xj, label.child(format!("eq_update_{j}")))?;
        }
    }

    Ok(gt)
}

#[allow(dead_code)]
pub(crate) fn lt_public_vec<P, B>(
    ctx: &mut B,
    x_bits_by_bit: &[BitShareVec<B::BitShare>],
    constant: u32,
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = x_bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty lt_public_vec input"))?;
    if x_bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }

    let mut eq = public_bit_vec::<P, B>(ctx, true, lane_count);
    let mut lt = public_bit_vec::<P, B>(ctx, false, lane_count);
    for j in (0..x_bits_by_bit.len()).rev() {
        let xj = x_bits_by_bit[j].clone();
        let cj = ((constant >> j) & 1) == 1;
        if cj {
            let candidate = bit_and_vec::<P, B>(
                ctx,
                eq.clone(),
                bit_not_vec::<P, B>(ctx, xj.clone()),
                label.child(format!("lt_candidate_{j}")),
            )?;
            lt = bit_or_vec::<P, B>(ctx, lt, candidate, label.child(format!("lt_update_{j}")))?;
            eq = bit_and_vec::<P, B>(ctx, eq, xj, label.child(format!("eq_update_{j}")))?;
        } else {
            eq = bit_and_vec::<P, B>(
                ctx,
                eq,
                bit_not_vec::<P, B>(ctx, xj),
                label.child(format!("eq_update_{j}")),
            )?;
        }
    }
    Ok(lt)
}

#[allow(dead_code)]
pub(crate) fn gt_public_vec<P, B>(
    ctx: &mut B,
    x_bits_by_bit: &[BitShareVec<B::BitShare>],
    constant: u32,
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = x_bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty gt_public_vec input"))?;
    if x_bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }

    let mut eq = public_bit_vec::<P, B>(ctx, true, lane_count);
    let mut gt = public_bit_vec::<P, B>(ctx, false, lane_count);
    for j in (0..x_bits_by_bit.len()).rev() {
        let xj = x_bits_by_bit[j].clone();
        let cj = ((constant >> j) & 1) == 1;
        if !cj {
            let candidate = bit_and_vec::<P, B>(
                ctx,
                eq.clone(),
                xj.clone(),
                label.child(format!("gt_candidate_{j}")),
            )?;
            gt = bit_or_vec::<P, B>(ctx, gt, candidate, label.child(format!("gt_update_{j}")))?;
            eq = bit_and_vec::<P, B>(
                ctx,
                eq,
                bit_not_vec::<P, B>(ctx, xj),
                label.child(format!("eq_update_{j}")),
            )?;
        } else {
            eq = bit_and_vec::<P, B>(ctx, eq, xj, label.child(format!("eq_update_{j}")))?;
        }
    }
    Ok(gt)
}

#[allow(dead_code)]
pub(crate) fn gt_public_var_vec<P, B>(
    ctx: &mut B,
    x_bits_by_bit: &[BitShareVec<B::BitShare>],
    constants: &[u32],
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = x_bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty gt_public_var_vec input"))?;
    if lane_count != constants.len() || x_bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }

    let mut eq = public_bit_vec::<P, B>(ctx, true, lane_count);
    let mut gt = public_bit_vec::<P, B>(ctx, false, lane_count);
    for j in (0..x_bits_by_bit.len()).rev() {
        let xj = x_bits_by_bit[j].clone();
        let constant_bits = constants
            .iter()
            .map(|constant| ((constant >> j) & 1) == 1)
            .collect::<Vec<_>>();
        let cj = public_bit_vec_from_bools::<P, B>(ctx, &constant_bits);
        let not_cj = bit_not_vec::<P, B>(ctx, cj.clone());

        let eq_and_x = bit_and_vec::<P, B>(
            ctx,
            eq.clone(),
            xj.clone(),
            label.child(format!("eq_and_x_{j}")),
        )?;
        let candidate = bit_and_vec::<P, B>(
            ctx,
            eq_and_x,
            not_cj,
            label.child(format!("gt_candidate_{j}")),
        )?;
        gt = bit_or_vec::<P, B>(ctx, gt, candidate, label.child(format!("gt_update_{j}")))?;

        let x_xor_c = bit_xor_vec::<P, B>(ctx, xj, cj, label.child(format!("x_xor_c_{j}")))?;
        let eq_bit = bit_not_vec::<P, B>(ctx, x_xor_c);
        eq = bit_and_vec::<P, B>(ctx, eq, eq_bit, label.child(format!("eq_update_{j}")))?;
    }
    Ok(gt)
}

#[cfg(test)]
pub(crate) fn linear_combination_pow2_mod_q<P, B>(
    ctx: &mut B,
    bits: &[B::BitShare],
    label: Power2RoundTranscriptLabel,
) -> Result<B::Share, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let mut acc = ctx.public_const(0);
    let mut pow2 = 1;
    for (index, bit) in bits.iter().enumerate() {
        let term = ctx.mul_public_const(
            ctx.bit_to_share(bit),
            pow2,
            label.child(format!("pow2_term_{index}")),
        );
        acc = ctx.add(acc, term);
        pow2 = ((i64::from(pow2) * 2).rem_euclid(i64::from(P::Q))) as Coeff;
    }
    Ok(acc)
}

#[allow(dead_code)]
pub(crate) fn linear_combination_pow2_mod_q_vec<P, B>(
    ctx: &mut B,
    bits_by_bit: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<ShareVec<B::Share>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty pow2 vector input"))?;
    if bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }

    let mut acc = ctx.public_const_vec(0, lane_count);
    let mut pow2 = 1;
    for (index, bits) in bits_by_bit.iter().enumerate() {
        let term = ctx.mul_public_const_vec(
            bit_shares_to_share_vec::<P, B>(ctx, bits.lanes()),
            pow2,
            label.child(format!("pow2_term_{index}")),
        )?;
        acc = ctx.add_vec(acc, term)?;
        pow2 = ((i64::from(pow2) * 2).rem_euclid(i64::from(P::Q))) as Coeff;
    }
    Ok(acc)
}

#[allow(dead_code)]
pub(crate) fn assert_bit_vec_columns<P, B>(
    ctx: &mut B,
    bits_by_bit: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty bit-column input"))?;
    if bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }
    for (index, bits) in bits_by_bit.iter().enumerate() {
        ctx.assert_bit_vec(bits.clone(), label.child(format!("bit_{index}")))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn random_canonical_mask_q<P, B>(
    ctx: &mut B,
    label: Power2RoundTranscriptLabel,
) -> Result<CanonicalMaskQ<B::Share, B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    for attempt in 0..64 {
        let attempt_label = label.child(format!("attempt_{attempt}"));
        let mut bits = Vec::with_capacity(23);
        for bit_index in 0..23 {
            let bit = ctx.random_bit(attempt_label.child(format!("random_bit_{bit_index}")))?;
            assert_bit::<P, B>(
                ctx,
                &bit,
                attempt_label.child(format!("assert_mask_bit_{bit_index}")),
            )?;
            bits.push(bit);
        }
        let value =
            linear_combination_pow2_mod_q::<P, B>(ctx, &bits, attempt_label.child("mask_value"))?;
        let lt_q = lt_public::<P, B>(ctx, &bits, P::Q as u32, attempt_label.child("mask_lt_q"))?;
        let opened = ctx.open_checked(
            ctx.bit_to_share(&lt_q),
            attempt_label.child("open_mask_lt_q"),
        )?;
        if opened == 1 {
            return Ok(CanonicalMaskQ {
                bits_le: bits,
                value,
            });
        }
    }
    Err(DkgError::Power2RoundMaskRetriesExceeded)
}

#[allow(dead_code)]
pub(crate) fn random_canonical_mask_q_vec<P, B>(
    ctx: &mut B,
    lane_count: usize,
    label: Power2RoundTranscriptLabel,
) -> Result<CanonicalMaskQVec<B::Share, B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    precompute_certified_power2round_mask_batch::<P, B>(ctx, lane_count, label)
}

#[allow(dead_code)]
pub(crate) fn precompute_certified_power2round_mask_batch<P, B>(
    ctx: &mut B,
    lane_count: usize,
    label: Power2RoundTranscriptLabel,
) -> Result<CertifiedPower2RoundMaskBatch<B::Share, B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if lane_count == 0 {
        return Err(DkgError::Backend("empty canonical mask vector"));
    }
    for attempt in 0..64 {
        let attempt_label = label.child(format!("attempt_{attempt}"));
        let mut bits_by_bit = Vec::with_capacity(23);
        for bit_index in 0..23 {
            bits_by_bit.push(ctx.random_bit_vec(
                lane_count,
                attempt_label.child(format!("random_bit_{bit_index}")),
            )?);
        }
        assert_bit_vec_columns::<P, B>(ctx, &bits_by_bit, attempt_label.child("assert_mask_bits"))?;
        let value = linear_combination_pow2_mod_q_vec::<P, B>(
            ctx,
            &bits_by_bit,
            attempt_label.child("mask_value"),
        )?;
        let lt_q = lt_public_vec::<P, B>(
            ctx,
            &bits_by_bit,
            P::Q as u32,
            attempt_label.child("mask_lt_q"),
        )?;
        let opened = ctx.open_vec_checked(
            bit_shares_to_share_vec::<P, B>(ctx, lt_q.lanes()),
            attempt_label.child("open_mask_lt_q"),
        )?;
        if opened.iter().all(|value| *value == 1) {
            let unchecked = UncheckedPower2RoundMaskBatch::new(&label, bits_by_bit, value)?;
            return certify_power2round_mask_batch::<P, B>(ctx, unchecked, label);
        }
    }
    Err(DkgError::Power2RoundMaskRetriesExceeded)
}

#[allow(dead_code)]
pub(crate) fn certify_power2round_mask_batch<P, B>(
    ctx: &mut B,
    mut unchecked: UncheckedPower2RoundMaskBatch<B::Share, B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<CertifiedPower2RoundMaskBatch<B::Share, B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let id = unchecked.id();
    if id != Power2RoundMaskBatchId::new(&label, id.lane_count) {
        return Err(DkgError::Power2RoundMaskTranscriptMismatch);
    }
    if id.lane_count == 0
        || unchecked.bits_by_bit.len() != 23
        || unchecked
            .bits_by_bit
            .iter()
            .any(|bits| bits.len() != id.lane_count)
        || unchecked.value.len() != id.lane_count
    {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }

    assert_bit_vec_columns::<P, B>(
        ctx,
        &unchecked.bits_by_bit,
        label.child("certify_mask_bits"),
    )?;
    let value_from_bits = linear_combination_pow2_mod_q_vec::<P, B>(
        ctx,
        &unchecked.bits_by_bit,
        label.child("certify_mask_value"),
    )?;
    let diff = ctx.sub_vec(value_from_bits, unchecked.value.clone())?;
    ctx.assert_zero_vec(diff, label.child("certify_mask_value_matches_bits"))?;
    let lt_q = lt_public_vec::<P, B>(
        ctx,
        &unchecked.bits_by_bit,
        P::Q as u32,
        label.child("certify_mask_lt_q"),
    )?;
    let one_minus = ctx.sub_vec(
        ctx.public_const_vec(1, id.lane_count),
        bit_shares_to_share_vec::<P, B>(ctx, lt_q.lanes()),
    )?;
    ctx.assert_zero_vec(one_minus, label.child("certify_mask_assert_lt_q"))?;

    Ok(CertifiedPower2RoundMaskBatch {
        id,
        bits_by_bit: core::mem::take(&mut unchecked.bits_by_bit),
        value: core::mem::replace(&mut unchecked.value, ShareVec::from_lanes(Vec::new())),
    })
}

#[cfg(test)]
pub(crate) fn select_public_bit<P, B>(
    ctx: &mut B,
    bit0: bool,
    bit1: bool,
    wrap: &B::BitShare,
    label: Power2RoundTranscriptLabel,
) -> Result<B::BitShare, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let base = ctx.public_const(i32::from(bit0));
    let diff = match (bit0, bit1) {
        (false, false) | (true, true) => 0,
        (false, true) => 1,
        (true, false) => P::Q - 1,
    };
    let selected_delta = ctx.mul_public_const(ctx.bit_to_share(wrap), diff, label);
    Ok(ctx.bit_from_share_unchecked(ctx.add(base, selected_delta)))
}

#[allow(dead_code)]
pub(crate) fn select_public_bits_vec<P, B>(
    ctx: &mut B,
    bit0: &[bool],
    bit1: &[bool],
    wrap: &BitShareVec<B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if bit0.len() != bit1.len() || bit0.len() != wrap.len() {
        return Err(DkgError::Backend(
            "prime-field public-bit selection mismatch",
        ));
    }
    let base = ctx.share_vec_from_lanes(
        bit0.iter()
            .map(|&bit| ctx.public_const(i32::from(bit)))
            .collect(),
    );
    let constants = bit0
        .iter()
        .zip(bit1)
        .map(|(&left, &right)| match (left, right) {
            (false, false) | (true, true) => 0,
            (false, true) => 1,
            (true, false) => P::Q - 1,
        })
        .collect::<Vec<_>>();
    let selected_delta = ctx.mul_public_const_lanes(
        bit_shares_to_share_vec::<P, B>(ctx, wrap.lanes()),
        &constants,
        label,
    )?;
    let selected = ctx.add_vec(base, selected_delta)?;
    Ok(share_vec_to_bit_vec_unchecked::<P, B>(ctx, selected))
}

#[cfg(test)]
pub(crate) fn subtract_secret_a_from_selected_c_or_c_plus_q<P, B>(
    ctx: &mut B,
    c: u32,
    wrap: B::BitShare,
    mask_bits: &[B::BitShare],
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let c_plus_q = c + P::Q as u32;
    let mut out = Vec::with_capacity(24);
    let mut borrow = ctx.public_bit(false);

    let mut j = 0;
    while j < 24 {
        let b0 = ((c >> j) & 1) == 1;
        let b1 = ((c_plus_q >> j) & 1) == 1;
        let bj = select_public_bit::<P, B>(
            ctx,
            b0,
            b1,
            &wrap,
            label.child(format!("select_base_bit_{j}")),
        )?;
        let aj = if j < 23 {
            mask_bits[j].clone()
        } else {
            ctx.public_bit(false)
        };

        let b_xor_a = bit_xor::<P, B>(
            ctx,
            bj.clone(),
            aj.clone(),
            label.child(format!("b_xor_a_{j}")),
        )?;
        let dj = bit_xor::<P, B>(
            ctx,
            b_xor_a.clone(),
            borrow.clone(),
            label.child(format!("diff_bit_{j}")),
        )?;

        let not_b_and_a = bit_and::<P, B>(
            ctx,
            bit_not::<P, B>(ctx, bj),
            aj,
            label.child(format!("not_b_and_a_{j}")),
        )?;
        let not_b_xor_a_and_borrow = bit_and::<P, B>(
            ctx,
            bit_not::<P, B>(ctx, b_xor_a),
            borrow,
            label.child(format!("not_xor_and_borrow_{j}")),
        )?;
        borrow = bit_or::<P, B>(
            ctx,
            not_b_and_a,
            not_b_xor_a_and_borrow,
            label.child(format!("borrow_update_{j}")),
        )?;
        out.push(dj);
        j += 1;
    }

    ctx.assert_zero(
        ctx.bit_to_share(&borrow),
        label.child("assert_no_final_borrow"),
    )?;
    ctx.assert_zero(
        ctx.bit_to_share(&out[23]),
        label.child("assert_high_bit_zero"),
    )?;
    Ok(out.into_iter().take(23).collect())
}

#[allow(dead_code)]
pub(crate) fn subtract_secret_a_from_selected_c_or_c_plus_q_vec<P, B>(
    ctx: &mut B,
    c_values: &[u32],
    wrap: BitShareVec<B::BitShare>,
    mask_bits_by_bit: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = c_values.len();
    if lane_count == 0
        || wrap.len() != lane_count
        || mask_bits_by_bit.len() != 23
        || mask_bits_by_bit.iter().any(|bits| bits.len() != lane_count)
    {
        return Err(DkgError::Backend(
            "prime-field vector subtractor shape mismatch",
        ));
    }

    let c_plus_q = c_values
        .iter()
        .map(|&value| value + P::Q as u32)
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(24);
    let mut borrow = public_bit_vec::<P, B>(ctx, false, lane_count);
    for j in 0..24 {
        let b0 = c_values
            .iter()
            .map(|value| ((value >> j) & 1) == 1)
            .collect::<Vec<_>>();
        let b1 = c_plus_q
            .iter()
            .map(|value| ((value >> j) & 1) == 1)
            .collect::<Vec<_>>();
        let bj = select_public_bits_vec::<P, B>(
            ctx,
            &b0,
            &b1,
            &wrap,
            label.child(format!("select_base_bit_{j}")),
        )?;
        let aj = if j < 23 {
            mask_bits_by_bit[j].clone()
        } else {
            public_bit_vec::<P, B>(ctx, false, lane_count)
        };

        let b_xor_a = bit_xor_vec::<P, B>(
            ctx,
            bj.clone(),
            aj.clone(),
            label.child(format!("b_xor_a_{j}")),
        )?;
        let dj = bit_xor_vec::<P, B>(
            ctx,
            b_xor_a.clone(),
            borrow.clone(),
            label.child(format!("diff_bit_{j}")),
        )?;
        let not_b_and_a = bit_and_vec::<P, B>(
            ctx,
            bit_not_vec::<P, B>(ctx, bj),
            aj,
            label.child(format!("not_b_and_a_{j}")),
        )?;
        let not_b_xor_a_and_borrow = bit_and_vec::<P, B>(
            ctx,
            bit_not_vec::<P, B>(ctx, b_xor_a),
            borrow,
            label.child(format!("not_xor_and_borrow_{j}")),
        )?;
        borrow = bit_or_vec::<P, B>(
            ctx,
            not_b_and_a,
            not_b_xor_a_and_borrow,
            label.child(format!("borrow_update_{j}")),
        )?;
        out.push(dj);
    }

    ctx.assert_zero_vec(
        bit_shares_to_share_vec::<P, B>(ctx, borrow.lanes()),
        label.child("assert_no_final_borrow"),
    )?;
    ctx.assert_zero_vec(
        bit_shares_to_share_vec::<P, B>(ctx, out[23].lanes()),
        label.child("assert_high_bit_zero"),
    )?;
    Ok(out.into_iter().take(23).collect())
}

#[cfg(test)]
pub(crate) fn canonical_bit_decompose_mod_q<P, B>(
    ctx: &mut B,
    r: B::Share,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    // Privacy: the only value opened here is C = r + A mod q, where A is a
    // secret random canonical mask independent of r. For any fixed r, C is
    // uniform in Z_q. Correctness: after opening C, the circuit computes
    // R = C - A if A <= C and R = C + q - A otherwise, then checks R < q and
    // sum_j 2^j R_j == r mod q before any t1 bits are opened.
    let mask = random_canonical_mask_q::<P, B>(ctx, label.child("mask"))?;
    let c_share = ctx.add(r.clone(), mask.value.clone());
    let c = ctx.open_checked(c_share, label.child("open_masked_c"))? as u32;
    let wrap = gt_public::<P, B>(ctx, &mask.bits_le, c, label.child("a_gt_c"))?;
    let r_bits = subtract_secret_a_from_selected_c_or_c_plus_q::<P, B>(
        ctx,
        c,
        wrap,
        &mask.bits_le,
        label.child("recover_r_bits"),
    )?;
    assert_bits::<P, B>(ctx, &r_bits, label.child("r_bits_boolean"))?;
    let r_lt_q = lt_public::<P, B>(ctx, &r_bits, P::Q as u32, label.child("r_lt_q"))?;
    assert_one_bit::<P, B>(ctx, &r_lt_q, label.child("assert_r_lt_q"))?;
    let r_from_bits =
        linear_combination_pow2_mod_q::<P, B>(ctx, &r_bits, label.child("r_from_bits"))?;
    ctx.assert_zero(
        ctx.sub(r_from_bits, r),
        label.child("assert_bits_equal_r_mod_q"),
    )?;
    Ok(r_bits)
}

#[allow(dead_code)]
pub(crate) fn canonical_bit_decompose_mod_q_vec<P, B>(
    ctx: &mut B,
    r: ShareVec<B::Share>,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = r.len();
    if lane_count == 0 {
        return Err(DkgError::Backend(
            "empty canonical bit decomposition vector",
        ));
    }
    let mask_label = label.child("mask");
    let mask = random_canonical_mask_q_vec::<P, B>(ctx, lane_count, mask_label)?;
    let mut use_log = InMemoryPower2RoundMaskUseLog::default();
    canonical_bit_decompose_mod_q_vec_with_certified_mask::<P, B, _>(
        ctx,
        r,
        mask,
        &mut use_log,
        label,
    )
}

#[allow(dead_code)]
pub(crate) fn canonical_bit_decompose_mod_q_vec_with_certified_mask<P, B, L>(
    ctx: &mut B,
    r: ShareVec<B::Share>,
    mask: CertifiedPower2RoundMaskBatch<B::Share, B::BitShare>,
    use_log: &mut L,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
    L: Power2RoundMaskUseLog,
{
    let lane_count = r.len();
    if lane_count == 0 {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let expected = Power2RoundMaskBatchId::new(&label.child("mask"), lane_count);
    if mask.id() != expected {
        return Err(DkgError::Power2RoundMaskTranscriptMismatch);
    }
    let mask = mask.consume(use_log)?;
    canonical_bit_decompose_mod_q_vec_with_mask::<P, B>(ctx, r, mask, label)
}

#[allow(dead_code)]
pub(crate) fn open_power2round_masked_c_vec<P, B>(
    ctx: &mut B,
    r: ShareVec<B::Share>,
    mask: &ConsumedPower2RoundMaskBatch<B::Share, B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<Coeff>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = r.len();
    if lane_count == 0 || mask.id().lane_count != lane_count {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let c_share = ctx.add_vec(r, mask.value().clone())?;
    ctx.open_vec_checked(c_share, label.child("open_masked_c"))
}

#[allow(dead_code)]
pub(crate) fn power2round_wrap_compare_vec<P, B>(
    ctx: &mut B,
    mask: &ConsumedPower2RoundMaskBatch<B::Share, B::BitShare>,
    c_values: &[Coeff],
    label: Power2RoundTranscriptLabel,
) -> Result<BitShareVec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if mask.id().lane_count == 0 || mask.id().lane_count != c_values.len() {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    if c_values.iter().any(|&value| value < 0 || value >= P::Q) {
        return Err(DkgError::Power2RoundCanonicalityFailure);
    }
    let c_values = c_values
        .iter()
        .map(|&value| value as u32)
        .collect::<Vec<_>>();
    gt_public_var_vec::<P, B>(ctx, mask.bits_by_bit(), &c_values, label.child("a_gt_c"))
}

#[allow(dead_code)]
pub(crate) fn power2round_recover_canonical_r_bits_vec<P, B>(
    ctx: &mut B,
    c_values: &[Coeff],
    wrap: BitShareVec<B::BitShare>,
    mask: &ConsumedPower2RoundMaskBatch<B::Share, B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if mask.id().lane_count == 0 || mask.id().lane_count != c_values.len() {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    if c_values.iter().any(|&value| value < 0 || value >= P::Q) {
        return Err(DkgError::Power2RoundCanonicalityFailure);
    }
    let c_values = c_values
        .iter()
        .map(|&value| value as u32)
        .collect::<Vec<_>>();
    subtract_secret_a_from_selected_c_or_c_plus_q_vec::<P, B>(
        ctx,
        &c_values,
        wrap,
        mask.bits_by_bit(),
        label.child("recover_r_bits"),
    )
}

#[allow(dead_code)]
pub(crate) fn power2round_assert_r_bits_boolean_vec<P, B>(
    ctx: &mut B,
    r_bits: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if r_bits.len() != 23 {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    assert_bit_vec_columns::<P, B>(ctx, r_bits, label.child("r_bits_boolean"))
}

#[allow(dead_code)]
pub(crate) fn power2round_assert_r_lt_q_vec<P, B>(
    ctx: &mut B,
    r_bits: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = r_bits
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
    if r_bits.len() != 23 || lane_count == 0 || r_bits.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let r_lt_q = lt_public_vec::<P, B>(ctx, r_bits, P::Q as u32, label.child("r_lt_q"))?;
    let one_minus = ctx.sub_vec(
        ctx.public_const_vec(1, lane_count),
        bit_shares_to_share_vec::<P, B>(ctx, r_lt_q.lanes()),
    )?;
    ctx.assert_zero_vec(one_minus, label.child("assert_r_lt_q"))
}

#[allow(dead_code)]
pub(crate) fn power2round_assert_r_bits_equal_t_vec<P, B>(
    ctx: &mut B,
    r_bits: &[BitShareVec<B::BitShare>],
    r: ShareVec<B::Share>,
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = r_bits
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Power2RoundMaskShapeMismatch)?;
    if r_bits.len() != 23 || lane_count == 0 || r.len() != lane_count {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let r_from_bits =
        linear_combination_pow2_mod_q_vec::<P, B>(ctx, r_bits, label.child("r_from_bits"))?;
    let diff = ctx.sub_vec(r_from_bits, r)?;
    ctx.assert_zero_vec(diff, label.child("assert_bits_equal_r_mod_q"))
}

#[allow(dead_code)]
pub(crate) fn power2round_certify_canonical_r_bits_vec<P, B>(
    ctx: &mut B,
    r_bits: &[BitShareVec<B::BitShare>],
    r: ShareVec<B::Share>,
    label: Power2RoundTranscriptLabel,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    power2round_assert_r_bits_boolean_vec::<P, B>(ctx, r_bits, label.clone())?;
    power2round_assert_r_lt_q_vec::<P, B>(ctx, r_bits, label.clone())?;
    power2round_assert_r_bits_equal_t_vec::<P, B>(ctx, r_bits, r, label)
}

#[allow(dead_code)]
pub(crate) fn canonical_bit_decompose_mod_q_vec_with_mask<P, B>(
    ctx: &mut B,
    r: ShareVec<B::Share>,
    mask: ConsumedPower2RoundMaskBatch<B::Share, B::BitShare>,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = r.len();
    if lane_count == 0 || mask.id().lane_count != lane_count {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let c_values = open_power2round_masked_c_vec::<P, B>(ctx, r.clone(), &mask, label.clone())?
        .into_iter()
        .map(|value| value as u32)
        .collect::<Vec<_>>();
    let c_values_coeff = c_values
        .iter()
        .map(|&value| value as Coeff)
        .collect::<Vec<_>>();
    let wrap = power2round_wrap_compare_vec::<P, B>(ctx, &mask, &c_values_coeff, label.clone())?;
    let r_bits = power2round_recover_canonical_r_bits_vec::<P, B>(
        ctx,
        &c_values_coeff,
        wrap,
        &mask,
        label.clone(),
    )?;
    power2round_certify_canonical_r_bits_vec::<P, B>(ctx, &r_bits, r, label)?;
    Ok(r_bits)
}

#[cfg(test)]
pub(crate) fn add_public_constant_bits_23<P, B>(
    ctx: &mut B,
    x_bits: &[B::BitShare],
    constant: u32,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<B::BitShare>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if x_bits.len() != 23 || constant >= (1 << 23) {
        return Err(DkgError::Backend("invalid 23-bit adder input"));
    }

    let mut out = Vec::with_capacity(23);
    let mut carry = ctx.public_bit(false);
    for (j, xj) in x_bits.iter().enumerate() {
        let constant_bit = ((constant >> j) & 1) == 1;
        if !constant_bit {
            out.push(bit_xor::<P, B>(
                ctx,
                xj.clone(),
                carry.clone(),
                label.child(format!("sum_bit_{j}")),
            )?);
            carry = bit_and::<P, B>(ctx, xj.clone(), carry, label.child(format!("carry_{j}")))?;
        } else {
            let x_xor_carry = bit_xor::<P, B>(
                ctx,
                xj.clone(),
                carry.clone(),
                label.child(format!("xor_for_sum_bit_{j}")),
            )?;
            out.push(bit_not::<P, B>(ctx, x_xor_carry));
            carry = bit_or::<P, B>(ctx, xj.clone(), carry, label.child(format!("carry_{j}")))?;
        }
    }
    ctx.assert_zero(ctx.bit_to_share(&carry), label.child("assert_no_overflow"))?;
    Ok(out)
}

#[allow(dead_code)]
pub(crate) fn add_public_constant_bits_23_vec<P, B>(
    ctx: &mut B,
    x_bits_by_bit: &[BitShareVec<B::BitShare>],
    constant: u32,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if x_bits_by_bit.len() != 23 || constant >= (1 << 23) {
        return Err(DkgError::Backend("invalid 23-bit vector adder input"));
    }
    let lane_count = x_bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty 23-bit vector adder input"))?;
    if x_bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }

    let mut out = Vec::with_capacity(23);
    let mut carry = public_bit_vec::<P, B>(ctx, false, lane_count);
    for (j, xj) in x_bits_by_bit.iter().enumerate() {
        let constant_bit = ((constant >> j) & 1) == 1;
        if !constant_bit {
            out.push(bit_xor_vec::<P, B>(
                ctx,
                xj.clone(),
                carry.clone(),
                label.child(format!("sum_bit_{j}")),
            )?);
            carry = bit_and_vec::<P, B>(ctx, xj.clone(), carry, label.child(format!("carry_{j}")))?;
        } else {
            let x_xor_carry = bit_xor_vec::<P, B>(
                ctx,
                xj.clone(),
                carry.clone(),
                label.child(format!("xor_for_sum_bit_{j}")),
            )?;
            out.push(bit_not_vec::<P, B>(ctx, x_xor_carry));
            carry = bit_or_vec::<P, B>(ctx, xj.clone(), carry, label.child(format!("carry_{j}")))?;
        }
    }
    ctx.assert_zero_vec(
        bit_shares_to_share_vec::<P, B>(ctx, carry.lanes()),
        label.child("assert_no_overflow"),
    )?;
    Ok(out)
}

#[allow(dead_code)]
pub(crate) fn power2round_add_4095_vec<P, B>(
    ctx: &mut B,
    r_bits_by_bit: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<BitShareVec<B::BitShare>>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    add_public_constant_bits_23_vec::<P, B>(ctx, r_bits_by_bit, 4095, label.child("add_4095"))
}

pub(crate) fn opened_coeff_to_bit(value: Coeff) -> Result<u8, DkgError> {
    match value {
        0 => Ok(0),
        1 => Ok(1),
        _ => Err(DkgError::Power2RoundInvalidOpenedBit),
    }
}

#[allow(dead_code)]
pub(crate) fn open_t1_bits_vec<P, B>(
    ctx: &mut B,
    s_bits_by_bit: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<u16>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    if s_bits_by_bit.len() != 23 {
        return Err(DkgError::Backend("invalid t1 bit vector input"));
    }
    let lane_count = s_bits_by_bit
        .first()
        .map(BitShareVec::len)
        .ok_or(DkgError::Backend("empty t1 bit vector input"))?;
    if s_bits_by_bit.iter().any(|bits| bits.len() != lane_count) {
        return Err(DkgError::Backend("prime-field bit vector length mismatch"));
    }

    let mut high_bit_shares = Vec::with_capacity(lane_count * 10);
    for high_bit in &s_bits_by_bit[13..23] {
        high_bit_shares.extend(high_bit.lanes().iter().map(|bit| ctx.bit_to_share(bit)));
    }
    let opened = ctx.open_vec_checked(
        ctx.share_vec_from_lanes(high_bit_shares),
        label.child("open_t1_bits"),
    )?;
    let mut out = vec![0u16; lane_count];
    for (flat_index, value) in opened.into_iter().enumerate() {
        let high_bit_index = flat_index / lane_count;
        let lane_index = flat_index % lane_count;
        out[lane_index] |= u16::from(opened_coeff_to_bit(value)?) << high_bit_index;
    }
    Ok(out)
}

#[allow(dead_code)]
pub(crate) fn power2round_open_t1_bits_vec<P, B>(
    ctx: &mut B,
    s_bits_by_bit: &[BitShareVec<B::BitShare>],
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<u16>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    open_t1_bits_vec::<P, B>(ctx, s_bits_by_bit, label.child("open_t1_vec"))
}

pub(crate) fn power2round_public_t1_from_coeffs<P: MlDsaParams>(
    coeffs: Vec<u16>,
) -> Result<PublicT1, DkgError> {
    Ok(PublicT1 {
        bytes: pack_t1_coeffs::<P>(&coeffs)?,
        coeffs,
    })
}

pub(crate) fn power2round_certify_public_t1_evidence(
    backend_id: Power2RoundBackendId,
    config: &DkgConfig,
    label: PublicKeyAssemblyLabel,
    t1: &PublicT1,
) -> Power2RoundEvidence {
    power2round_evidence(backend_id, config, label, &t1.bytes)
}

pub(crate) fn power2round_public_t1_hash(t1: &PublicT1) -> [u8; 32] {
    hash_bytes32(b"TALUS-DKG-v1/power2round-t1", &t1.bytes)
}

#[cfg(test)]
pub(crate) fn power2round_t1_coeff<P, B>(
    ctx: &mut B,
    r: B::Share,
    label: Power2RoundTranscriptLabel,
) -> Result<u16, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let mut r_bits =
        canonical_bit_decompose_mod_q::<P, B>(ctx, r, label.child("canonical_bit_decompose"))?;
    let mut s_bits =
        add_public_constant_bits_23::<P, B>(ctx, &r_bits, 4095, label.child("add_4095"))?;
    let opened = ctx.open_vec_checked(
        ctx.share_vec_from_lanes(
            s_bits[13..23]
                .iter()
                .map(|bit| ctx.bit_to_share(bit))
                .collect(),
        ),
        label.child("open_t1_bits"),
    )?;
    let mut r1 = 0u16;
    for (index, value) in opened.into_iter().enumerate() {
        r1 |= u16::from(opened_coeff_to_bit(value)?) << index;
    }
    r_bits.zeroize();
    s_bits.zeroize();
    Ok(r1)
}

#[allow(dead_code)]
pub(crate) fn power2round_t1_vec<P, B>(
    ctx: &mut B,
    r: ShareVec<B::Share>,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<u16>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let lane_count = r.len();
    if lane_count == 0 {
        return Err(DkgError::Backend("empty Power2Round vector"));
    }
    let mut r_bits =
        canonical_bit_decompose_mod_q_vec::<P, B>(ctx, r, label.child("canonical_bit_decompose"))?;
    let mut s_bits = power2round_add_4095_vec::<P, B>(ctx, &r_bits, label.clone())?;
    let t1 = power2round_open_t1_bits_vec::<P, B>(ctx, &s_bits, label.clone())?;
    if t1.len() != lane_count {
        return Err(DkgError::Backend(
            "Power2Round vector output length mismatch",
        ));
    }
    r_bits.zeroize();
    s_bits.zeroize();
    Ok(t1)
}

/// Computes vector `Power2Round([t]) -> t1` using a caller-supplied certified
/// canonical mask batch and durable mask-use log.
///
/// This is a test/dev circuit harness because it is generic over
/// `ItMpcPrimeFieldBackend`, which still includes local-compatible substrates.
/// Normal production assembly must use app-driven vector runtime evidence and
/// consume `ProductionPower2RoundOutput` instead of selecting this backend.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub fn power2round_t1_vec_with_certified_mask<P, B, L>(
    ctx: &mut B,
    r: ShareVec<B::Share>,
    mask: CertifiedPower2RoundMaskBatch<B::Share, B::BitShare>,
    mask_use_log: &mut L,
    label: Power2RoundTranscriptLabel,
) -> Result<Vec<u16>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
    L: Power2RoundMaskUseLog,
{
    let lane_count = r.len();
    if lane_count == 0 || mask.id().lane_count != lane_count {
        return Err(DkgError::Power2RoundMaskShapeMismatch);
    }
    let mut r_bits = canonical_bit_decompose_mod_q_vec_with_certified_mask::<P, B, L>(
        ctx,
        r,
        mask,
        mask_use_log,
        label.child("canonical_bit_decompose"),
    )?;
    let mut s_bits = power2round_add_4095_vec::<P, B>(ctx, &r_bits, label.clone())?;
    let t1 = power2round_open_t1_bits_vec::<P, B>(ctx, &s_bits, label.clone())?;
    if t1.len() != lane_count {
        return Err(DkgError::Backend(
            "Power2Round vector output length mismatch",
        ));
    }
    r_bits.zeroize();
    s_bits.zeroize();
    Ok(t1)
}

/// Test/dev vector IT-MPC `Power2Round` backend wrapper.
///
/// The wrapper owns a generic prime-field MPC backend and mask-use log. It is
/// intentionally hidden from normal builds because `ItMpcPrimeFieldBackend`
/// still includes local-compatible substrates. Production code must obtain
/// `ProductionPower2RoundOutput` from the app-driven vector runtime evidence
/// boundary.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub struct ProductionItMpcPower2RoundBackend<B, L> {
    backend: B,
    mask_use_log: L,
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl<B, L> fmt::Debug for ProductionItMpcPower2RoundBackend<B, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionItMpcPower2RoundBackend")
            .field("backend", &"<redacted>")
            .field("mask_use_log", &"<redacted>")
            .finish()
    }
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl<B, L> ProductionItMpcPower2RoundBackend<B, L> {
    /// Creates a production vector Power2Round wrapper.
    pub fn new(backend: B, mask_use_log: L) -> Self {
        Self {
            backend,
            mask_use_log,
        }
    }

    /// Returns the wrapped prime-field MPC backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Returns the mutable wrapped prime-field MPC backend.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Returns the durable mask-use log.
    pub fn mask_use_log(&self) -> &L {
        &self.mask_use_log
    }

    /// Returns the mutable durable mask-use log.
    pub fn mask_use_log_mut(&mut self) -> &mut L {
        &mut self.mask_use_log
    }
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl<B, L> ProductionItMpcPower2RoundBackend<B, L> {
    /// Runs vector Power2Round over a backend-private share vector and returns
    /// release-valid production output.
    pub fn power2round_t1_from_share_vec<P>(
        &mut self,
        config: &DkgConfig,
        assembly_label: PublicKeyAssemblyLabel,
        t_share: ShareVec<B::Share>,
    ) -> Result<ProductionPower2RoundOutput, DkgError>
    where
        P: MlDsaParams,
        B: ItMpcPrimeFieldBackend<P>,
        L: Power2RoundMaskUseLog,
    {
        let lane_count = t_share.len();
        if lane_count != P::K * P::N {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: P::K * P::N,
                got: lane_count,
            });
        }
        let label = Power2RoundTranscriptLabel::root(config, assembly_label.rho_hash)
            .child("power2round_t1_vec");
        let mask = precompute_certified_power2round_mask_batch::<P, B>(
            &mut self.backend,
            lane_count,
            label.child("canonical_bit_decompose/mask"),
        )?;
        let t1_coeffs = power2round_t1_vec_with_certified_mask::<P, B, L>(
            &mut self.backend,
            t_share,
            mask,
            &mut self.mask_use_log,
            label,
        )?;
        ensure_prime_field_mpc_backend_vectorized_for_release::<P, B>(&self.backend)?;
        let t1 = power2round_public_t1_from_coeffs::<P>(t1_coeffs)?;
        let evidence = power2round_certify_public_t1_evidence(
            Power2RoundBackendId::ProductionItMpc,
            config,
            assembly_label,
            &t1,
        );
        ProductionPower2RoundOutput::new(config, assembly_label, t1, evidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionPower2RoundDriverPhase {
    /// Generate/certify canonical masks for private bit decomposition.
    GenerateCanonicalMasks,
    /// Open one-time-padded `C = t + A mod q` values.
    OpenMaskedValues,
    /// Recover and certify canonical `t` bits without opening low material.
    RecoverCanonicalBits,
    /// Add the public `4095` round constant in secret bits.
    AddRoundConstant,
    /// Open only `t1` high bits.
    OpenT1Bits,
    /// Build public evidence for the completed vector.
    CertifyEvidence,
}

/// Ordered production `Power2Round` phases.
pub const PRODUCTION_POWER2ROUND_DRIVER_PHASES: &[ProductionPower2RoundDriverPhase] = &[
    ProductionPower2RoundDriverPhase::GenerateCanonicalMasks,
    ProductionPower2RoundDriverPhase::OpenMaskedValues,
    ProductionPower2RoundDriverPhase::RecoverCanonicalBits,
    ProductionPower2RoundDriverPhase::AddRoundConstant,
    ProductionPower2RoundDriverPhase::OpenT1Bits,
    ProductionPower2RoundDriverPhase::CertifyEvidence,
];

/// Minimal state machine for the production per-party `Power2Round` driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPower2RoundPerPartyDriver {
    next_phase_index: usize,
    mask_batch_id: Option<Power2RoundMaskBatchId>,
    opened_masked_value_lanes: Option<usize>,
    canonical_bit_lanes: Option<usize>,
    add_round_constant_lanes: Option<usize>,
    opened_t1_lanes: Option<usize>,
    opened_t1_hash: Option<[u8; 32]>,
    evidence_transcript_hash: Option<[u8; 32]>,
}

impl ProductionPower2RoundPerPartyDriver {
    /// Starts at canonical-mask generation.
    pub const fn new() -> Self {
        Self {
            next_phase_index: 0,
            mask_batch_id: None,
            opened_masked_value_lanes: None,
            canonical_bit_lanes: None,
            add_round_constant_lanes: None,
            opened_t1_lanes: None,
            opened_t1_hash: None,
            evidence_transcript_hash: None,
        }
    }

    /// Restores a driver that has already completed canonical-mask
    /// certification and persisted the consumed/prepared mask id.
    pub fn resume_after_precomputed_masks(mask_batch_id: Power2RoundMaskBatchId) -> Self {
        Self {
            next_phase_index: 1,
            mask_batch_id: Some(mask_batch_id),
            opened_masked_value_lanes: None,
            canonical_bit_lanes: None,
            add_round_constant_lanes: None,
            opened_t1_lanes: None,
            opened_t1_hash: None,
            evidence_transcript_hash: None,
        }
    }

    /// Returns the next required phase.
    pub fn next_phase(&self) -> Option<ProductionPower2RoundDriverPhase> {
        PRODUCTION_POWER2ROUND_DRIVER_PHASES
            .get(self.next_phase_index)
            .copied()
    }

    /// Returns the certified mask batch id accepted by the first driver phase.
    pub fn mask_batch_id(&self) -> Option<Power2RoundMaskBatchId> {
        self.mask_batch_id
    }

    /// Returns the vector lane count accepted for masked openings.
    pub fn opened_masked_value_lanes(&self) -> Option<usize> {
        self.opened_masked_value_lanes
    }

    /// Returns the vector lane count accepted for canonical-bit recovery.
    pub fn canonical_bit_lanes(&self) -> Option<usize> {
        self.canonical_bit_lanes
    }

    /// Returns the vector lane count accepted after adding the public
    /// Power2Round round constant.
    pub fn add_round_constant_lanes(&self) -> Option<usize> {
        self.add_round_constant_lanes
    }

    /// Returns the vector lane count accepted for opened `t1` coefficients.
    pub fn opened_t1_lanes(&self) -> Option<usize> {
        self.opened_t1_lanes
    }

    /// Returns the hash of the packed public `t1` bytes accepted by the
    /// high-bit opening phase.
    pub fn opened_t1_hash(&self) -> Option<[u8; 32]> {
        self.opened_t1_hash
    }

    /// Returns the transcript hash from the accepted public evidence.
    pub fn evidence_transcript_hash(&self) -> Option<[u8; 32]> {
        self.evidence_transcript_hash
    }

    /// Accepts the canonical-mask generation phase using a certified
    /// precomputed mask batch.
    pub fn accept_precomputed_masks<S: Zeroize, B: Zeroize>(
        &mut self,
        mask: &CertifiedPower2RoundMaskBatch<S, B>,
    ) -> Result<(), DkgError> {
        if self.next_phase() != Some(ProductionPower2RoundDriverPhase::GenerateCanonicalMasks) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        self.mask_batch_id = Some(mask.id());
        self.next_phase_index += 1;
        Ok(())
    }

    /// Accepts the masked-opening phase after collecting the opened
    /// `C = t + A` vector.
    pub fn accept_masked_openings(&mut self, opened_lane_count: usize) -> Result<(), DkgError> {
        if self.next_phase() != Some(ProductionPower2RoundDriverPhase::OpenMaskedValues) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        let Some(mask_id) = self.mask_batch_id else {
            return Err(DkgError::Power2RoundCertifiedMaskRequired);
        };
        if opened_lane_count == 0 || opened_lane_count != mask_id.lane_count {
            return Err(DkgError::Power2RoundMaskShapeMismatch);
        }
        self.opened_masked_value_lanes = Some(opened_lane_count);
        self.next_phase_index += 1;
        Ok(())
    }

    /// Accepts canonical-bit recovery after the vector subtractor/range/equality
    /// checks have completed.
    pub fn accept_canonical_bit_recovery(&mut self, lane_count: usize) -> Result<(), DkgError> {
        if self.next_phase() != Some(ProductionPower2RoundDriverPhase::RecoverCanonicalBits) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        if Some(lane_count) != self.opened_masked_value_lanes || lane_count == 0 {
            return Err(DkgError::Power2RoundMaskedOpeningsRequired);
        }
        self.canonical_bit_lanes = Some(lane_count);
        self.next_phase_index += 1;
        Ok(())
    }

    /// Accepts the secret-bit vector produced after adding the public
    /// `4095` Power2Round constant.
    pub fn accept_add_round_constant(&mut self, lane_count: usize) -> Result<(), DkgError> {
        if self.next_phase() != Some(ProductionPower2RoundDriverPhase::AddRoundConstant) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        if Some(lane_count) != self.canonical_bit_lanes || lane_count == 0 {
            return Err(DkgError::Power2RoundCanonicalBitsRequired);
        }
        self.add_round_constant_lanes = Some(lane_count);
        self.next_phase_index += 1;
        Ok(())
    }

    /// Accepts the packed public `t1` result after opening only the high bits.
    pub fn accept_opened_t1(&mut self, t1: &PublicT1) -> Result<(), DkgError> {
        if self.next_phase() != Some(ProductionPower2RoundDriverPhase::OpenT1Bits) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        let Some(expected_lanes) = self.add_round_constant_lanes else {
            return Err(DkgError::Power2RoundAddRoundConstantRequired);
        };
        if expected_lanes == 0 || t1.coeffs.len() != expected_lanes {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: expected_lanes,
                got: t1.coeffs.len(),
            });
        }
        if t1.bytes.is_empty() || t1.coeffs.iter().any(|&coefficient| coefficient > 1023) {
            return Err(DkgError::Power2RoundT1BitsRequired);
        }
        self.opened_t1_lanes = Some(expected_lanes);
        self.opened_t1_hash = Some(power2round_public_t1_hash(t1));
        self.next_phase_index += 1;
        Ok(())
    }

    /// Accepts public evidence for the completed vector Power2Round result.
    pub fn accept_certified_evidence(
        &mut self,
        evidence: &Power2RoundEvidence,
    ) -> Result<(), DkgError> {
        if self.next_phase() != Some(ProductionPower2RoundDriverPhase::CertifyEvidence) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        let Some(opened_t1_hash) = self.opened_t1_hash else {
            return Err(DkgError::Power2RoundT1BitsRequired);
        };
        if evidence.output_t1_hash != opened_t1_hash {
            return Err(DkgError::Power2RoundEvidenceRequired);
        }
        self.evidence_transcript_hash = Some(evidence.transcript_hash);
        self.next_phase_index += 1;
        Ok(())
    }

    /// Accepts exactly the next phase in order.
    pub fn accept_phase(
        &mut self,
        phase: ProductionPower2RoundDriverPhase,
    ) -> Result<(), DkgError> {
        if self.next_phase() != Some(phase) {
            return Err(DkgError::Power2RoundDriverPhaseOutOfOrder);
        }
        if phase == ProductionPower2RoundDriverPhase::GenerateCanonicalMasks {
            return Err(DkgError::Power2RoundCertifiedMaskRequired);
        }
        if phase == ProductionPower2RoundDriverPhase::OpenMaskedValues {
            return Err(DkgError::Power2RoundMaskedOpeningsRequired);
        }
        if phase == ProductionPower2RoundDriverPhase::RecoverCanonicalBits {
            return Err(DkgError::Power2RoundCanonicalBitsRequired);
        }
        if phase == ProductionPower2RoundDriverPhase::AddRoundConstant {
            return Err(DkgError::Power2RoundAddRoundConstantRequired);
        }
        if phase == ProductionPower2RoundDriverPhase::OpenT1Bits {
            return Err(DkgError::Power2RoundT1BitsRequired);
        }
        if phase == ProductionPower2RoundDriverPhase::CertifyEvidence {
            return Err(DkgError::Power2RoundEvidenceRequired);
        }
        if self.mask_batch_id.is_none() {
            return Err(DkgError::Power2RoundCertifiedMaskRequired);
        }
        if matches!(
            phase,
            ProductionPower2RoundDriverPhase::AddRoundConstant
                | ProductionPower2RoundDriverPhase::OpenT1Bits
                | ProductionPower2RoundDriverPhase::CertifyEvidence
        ) && self.canonical_bit_lanes.is_none()
        {
            return Err(DkgError::Power2RoundCanonicalBitsRequired);
        }
        self.next_phase_index += 1;
        Ok(())
    }

    /// Returns true once public evidence has been certified.
    pub fn is_complete(&self) -> bool {
        self.next_phase_index == PRODUCTION_POWER2ROUND_DRIVER_PHASES.len()
    }

    /// Returns a restart cursor for the current Power2Round driver state.
    pub fn cursor(&self) -> ProductionPower2RoundDriverCursor {
        ProductionPower2RoundDriverCursor {
            next_phase_index: self.next_phase_index,
            mask_batch_id: self.mask_batch_id,
            opened_masked_value_lanes: self.opened_masked_value_lanes,
            canonical_bit_lanes: self.canonical_bit_lanes,
            add_round_constant_lanes: self.add_round_constant_lanes,
            opened_t1_lanes: self.opened_t1_lanes,
            opened_t1_hash: self.opened_t1_hash,
            evidence_transcript_hash: self.evidence_transcript_hash,
        }
    }

    /// Restores a Power2Round driver from a persisted restart cursor.
    pub fn resume_from_cursor(
        cursor: &ProductionPower2RoundDriverCursor,
    ) -> Result<Self, DkgError> {
        if cursor.next_phase_index > PRODUCTION_POWER2ROUND_DRIVER_PHASES.len() {
            return Err(DkgError::PrimeFieldMpcPhaseCursorLogCorrupt { line: 1 });
        }
        Ok(Self {
            next_phase_index: cursor.next_phase_index,
            mask_batch_id: cursor.mask_batch_id,
            opened_masked_value_lanes: cursor.opened_masked_value_lanes,
            canonical_bit_lanes: cursor.canonical_bit_lanes,
            add_round_constant_lanes: cursor.add_round_constant_lanes,
            opened_t1_lanes: cursor.opened_t1_lanes,
            opened_t1_hash: cursor.opened_t1_hash,
            evidence_transcript_hash: cursor.evidence_transcript_hash,
        })
    }
}

impl Default for ProductionPower2RoundPerPartyDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Durable restart cursor for the Power2Round phase driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPower2RoundDriverCursor {
    /// Index of the next required phase in `PRODUCTION_POWER2ROUND_DRIVER_PHASES`.
    pub next_phase_index: usize,
    /// Certified mask batch accepted by the mask generation phase.
    pub mask_batch_id: Option<Power2RoundMaskBatchId>,
    /// Lane count accepted after masked `C` openings.
    pub opened_masked_value_lanes: Option<usize>,
    /// Lane count accepted after canonical bit recovery.
    pub canonical_bit_lanes: Option<usize>,
    /// Lane count accepted after adding 4095.
    pub add_round_constant_lanes: Option<usize>,
    /// Lane count accepted after opening public `t1` bits.
    pub opened_t1_lanes: Option<usize>,
    /// Hash of the accepted public `t1` bytes.
    pub opened_t1_hash: Option<[u8; 32]>,
    /// Transcript hash of accepted public evidence.
    pub evidence_transcript_hash: Option<[u8; 32]>,
}

/// File-backed log for Power2Round driver restart cursors.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePower2RoundDriverCursorLog {
    path: std::path::PathBuf,
    cursors: Vec<ProductionPower2RoundDriverCursor>,
}

#[cfg(feature = "std")]
impl FilePower2RoundDriverCursorLog {
    /// Opens or creates a durable Power2Round driver cursor log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut cursors = Vec::new();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let cursor = parse_power2round_driver_cursor_line(line).ok_or(
                        DkgError::PrimeFieldMpcPhaseCursorLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    cursors.push(cursor);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo { operation: "read" });
            }
        }
        Ok(Self { path, cursors })
    }

    /// Persists a driver cursor.
    pub fn persist_driver_cursor(
        &mut self,
        cursor: &ProductionPower2RoundDriverCursor,
    ) -> Result<(), DkgError> {
        self.cursors.push(cursor.clone());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        let (mask_present, mask_lanes, mask_hash) = match cursor.mask_batch_id {
            Some(id) => (1u8, id.lane_count, id.label_hash),
            None => (0u8, 0usize, [0u8; 32]),
        };
        let (t1_hash_present, t1_hash) = match cursor.opened_t1_hash {
            Some(hash) => (1u8, hash),
            None => (0u8, [0u8; 32]),
        };
        let (evidence_hash_present, evidence_hash) = match cursor.evidence_transcript_hash {
            Some(hash) => (1u8, hash),
            None => (0u8, [0u8; 32]),
        };
        writeln!(
            file,
            "{} {} {} {} {} {} {} {} {} {} {} {}",
            cursor.next_phase_index,
            mask_present,
            mask_lanes,
            Hex32(mask_hash),
            cursor.opened_masked_value_lanes.unwrap_or(0),
            cursor.canonical_bit_lanes.unwrap_or(0),
            cursor.add_round_constant_lanes.unwrap_or(0),
            cursor.opened_t1_lanes.unwrap_or(0),
            t1_hash_present,
            Hex32(t1_hash),
            evidence_hash_present,
            Hex32(evidence_hash)
        )
        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        Ok(())
    }

    /// Returns all persisted driver cursors.
    pub fn cursors(&self) -> &[ProductionPower2RoundDriverCursor] {
        &self.cursors
    }

    /// Returns the latest persisted driver cursor.
    pub fn latest_driver_cursor(&self) -> Option<&ProductionPower2RoundDriverCursor> {
        self.cursors.last()
    }
}

#[cfg(feature = "std")]
fn parse_power2round_driver_cursor_line(line: &str) -> Option<ProductionPower2RoundDriverCursor> {
    let mut fields = line.split_whitespace();
    let next_phase_index = fields.next()?.parse::<usize>().ok()?;
    if next_phase_index > PRODUCTION_POWER2ROUND_DRIVER_PHASES.len() {
        return None;
    }
    let mask_present = fields.next()?.parse::<u8>().ok()?;
    let mask_lanes = fields.next()?.parse::<usize>().ok()?;
    let mask_hash = parse_hex32(fields.next()?)?;
    let mask_batch_id = match mask_present {
        0 if mask_lanes == 0 && mask_hash == [0u8; 32] => None,
        1 if mask_lanes != 0 => Some(Power2RoundMaskBatchId {
            label_hash: mask_hash,
            lane_count: mask_lanes,
        }),
        _ => return None,
    };
    let opened_masked_value_lanes = parse_optional_nonzero_usize(fields.next()?)?;
    let canonical_bit_lanes = parse_optional_nonzero_usize(fields.next()?)?;
    let add_round_constant_lanes = parse_optional_nonzero_usize(fields.next()?)?;
    let opened_t1_lanes = parse_optional_nonzero_usize(fields.next()?)?;
    let t1_hash_present = fields.next()?.parse::<u8>().ok()?;
    let t1_hash = parse_hex32(fields.next()?)?;
    let opened_t1_hash = match t1_hash_present {
        0 if t1_hash == [0u8; 32] => None,
        1 => Some(t1_hash),
        _ => return None,
    };
    let evidence_hash_present = fields.next()?.parse::<u8>().ok()?;
    let evidence_hash = parse_hex32(fields.next()?)?;
    let evidence_transcript_hash = match evidence_hash_present {
        0 if evidence_hash == [0u8; 32] => None,
        1 => Some(evidence_hash),
        _ => return None,
    };
    if fields.next().is_some() {
        return None;
    }
    Some(ProductionPower2RoundDriverCursor {
        next_phase_index,
        mask_batch_id,
        opened_masked_value_lanes,
        canonical_bit_lanes,
        add_round_constant_lanes,
        opened_t1_lanes,
        opened_t1_hash,
        evidence_transcript_hash,
    })
}

#[cfg(feature = "std")]
fn parse_optional_nonzero_usize(value: &str) -> Option<Option<usize>> {
    match value.parse::<usize>().ok()? {
        0 => Some(None),
        value => Some(Some(value)),
    }
}
