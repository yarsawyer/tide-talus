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
}

impl ProductionPower2RoundOutput {
    /// Validates and constructs a production Power2Round output.
    pub fn new(
        config: &DkgConfig,
        assembly_label: PublicKeyAssemblyLabel,
        t1: PublicT1,
        evidence: Power2RoundEvidence,
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
        Ok(Self { t1, evidence })
    }

    /// Splits the validated public output into its parts.
    pub fn into_parts(self) -> (PublicT1, Power2RoundEvidence) {
        (self.t1, self.evidence)
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
    /// Optional native DKG setup transcript certificate.
    pub setup: Option<DkgSetupTranscriptCertificate>,
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

/// Derives prime-field MPC execution counters from durable wire records.
pub fn prime_field_mpc_counters_from_wire_records(
    records: &[PrimeFieldMpcWireMessageRecord],
) -> Result<PrimeFieldMpcCounters, DkgError> {
    let mut counters = PrimeFieldMpcCounters::default();
    for record in records {
        if record.message.header.payload_kind != PayloadKind::DkgPrimeFieldMpc {
            continue;
        }
        let payload = decode_dkg_prime_field_mpc_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
        let kind = prime_field_round_kind_from_u8(payload.round_kind)
            .ok_or(DkgError::PrimeFieldMpcTransport)?;
        let lanes = payload.values.len() as u64;
        if payload.values.is_empty() {
            match kind {
                PrimeFieldMpcRoundKind::MulDegreeReduce => counters.scalar_mul_gates += 1,
                PrimeFieldMpcRoundKind::Open => counters.scalar_openings += 1,
                PrimeFieldMpcRoundKind::AssertZero => counters.scalar_assert_zero += 1,
                PrimeFieldMpcRoundKind::RandomBit => counters.random_bits += 1,
            }
        } else {
            match kind {
                PrimeFieldMpcRoundKind::MulDegreeReduce => counters.vector_mul_lanes += lanes,
                PrimeFieldMpcRoundKind::Open => counters.vector_opening_lanes += lanes,
                PrimeFieldMpcRoundKind::AssertZero => counters.vector_assert_zero_lanes += lanes,
                PrimeFieldMpcRoundKind::RandomBit => counters.random_bits += lanes,
            }
        }
    }
    Ok(counters)
}

/// Release gate for durable prime-field MPC wire logs.
pub fn ensure_prime_field_mpc_wire_log_vectorized_for_release<L>(log: &L) -> Result<(), DkgError>
where
    L: PrimeFieldMpcWireMessageLog,
{
    ensure_prime_field_mpc_counters_vectorized_for_release(
        prime_field_mpc_counters_from_wire_records(log.wire_records())?,
    )
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
                    let record = parse_prime_field_mpc_wire_log_line(line).ok_or(
                        DkgError::PrimeFieldMpcWireLogCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    inner.persist_wire_message(&record)?;
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

    fn wire_records(&self) -> &[PrimeFieldMpcWireMessageRecord] {
        self.inner.records()
    }
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
        self.inner.persist_phase_cursor(cursor)?;
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
        for record in wire_log.wire_records() {
            if record.message.header.sender_party_id != self.local_party.0 {
                continue;
            }
            match record.direction {
                PrimeFieldMpcWireDirection::SentPrivate => {
                    let receiver = record.peer.ok_or(DkgError::PrimeFieldMpcTransport)?;
                    self.transport
                        .send_private(receiver.0, record.message.clone())
                        .map_err(map_transport_error)?;
                }
                PrimeFieldMpcWireDirection::SentBroadcast => {
                    self.transport
                        .broadcast(record.message.clone())
                        .map_err(map_transport_error)?;
                }
                PrimeFieldMpcWireDirection::AcceptedPrivate
                | PrimeFieldMpcWireDirection::AcceptedBroadcast => {}
            }
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
        for message in &messages {
            wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedPrivate,
                peer: Some(PartyId(message.header.sender_party_id)),
                message: message.clone(),
            })?;
        }
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
        for message in &messages {
            wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message: message.clone(),
            })?;
        }
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
        for message in &messages {
            wire_log.persist_wire_message(&PrimeFieldMpcWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message: message.clone(),
            })?;
        }
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
    pub fn drive_collect_power2round_canonical_recovery_all_vec_and_advance(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
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

    /// Collects or recovers all 23 add-4095 vector carry/share phases and
    /// advances the production driver once every bit phase is complete.
    pub fn drive_collect_power2round_add4095_all_vec_and_advance(
        &mut self,
        driver: &mut ProductionPower2RoundPerPartyDriver,
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
            let current_lane_count = uniform_collected_vector_lane_count(&values)?;
            if let Some(expected) = lane_count {
                if current_lane_count != expected {
                    return Err(DkgError::Power2RoundMaskShapeMismatch);
                }
            } else {
                lane_count = Some(current_lane_count);
            }
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

fn reconstruct_collected_prime_field_vector<P: MlDsaParams>(
    config: &DkgConfig,
    values: &[(PartyId, Vec<Coeff>)],
) -> Result<Vec<Coeff>, DkgError> {
    let lane_count = uniform_collected_vector_lane_count(values)?;
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|(party, _)| party.0);
    let mut out = Vec::with_capacity(lane_count);
    for lane_idx in 0..lane_count {
        let shares = sorted
            .iter()
            .map(|(party, lanes)| {
                Ok(ShamirScalarShare {
                    point: config.interpolation_point::<P>(*party)?,
                    value: lanes[lane_idx],
                })
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        out.push(reconstruct_scalar_at_zero::<P>(&shares)?);
    }
    Ok(out)
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
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn bit_shares_to_share_vec<P, B>(ctx: &B, bits: &[B::BitShare]) -> ShareVec<B::Share>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.share_vec_from_lanes(bits.iter().map(|bit| ctx.bit_to_share(bit)).collect())
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn public_bit_vec<P, B>(ctx: &B, value: bool, len: usize) -> BitShareVec<B::BitShare>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    ctx.bit_vec_from_lanes((0..len).map(|_| ctx.public_bit(value)).collect())
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
        let values = bit_shares_to_share_vec::<P, B>(ctx, bits.lanes());
        let values_minus_one = ctx.share_vec_from_lanes(
            bits.lanes()
                .iter()
                .map(|bit| ctx.sub(ctx.bit_to_share(bit), ctx.public_const(1)))
                .collect(),
        );
        let products = ctx.mul_vec(
            values,
            values_minus_one,
            label.child(format!("bit_{index}/b_times_b_minus_1")),
        )?;
        ctx.assert_zero_vec(products, label.child(format!("bit_{index}/assert_zero")))?;
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
}

impl Default for ProductionPower2RoundPerPartyDriver {
    fn default() -> Self {
        Self::new()
    }
}
