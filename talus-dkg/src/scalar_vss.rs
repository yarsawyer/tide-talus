use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarVssShare {
    /// Dealer that generated the sharing.
    pub dealer: PartyId,
    /// Receiver that owns this share.
    pub receiver: PartyId,
    /// Non-zero public interpolation point for `receiver`.
    pub point: u32,
    /// Scalar share value at `point`.
    pub value: Coeff,
}

/// Complaint evidence for one invalid scalar VSS share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarVssComplaintEvidence {
    /// Dealer whose share failed verification.
    pub dealer: PartyId,
    /// Receiver that detected the invalid share.
    pub receiver: PartyId,
    /// Interpolation point used by the receiver.
    pub point: u32,
    /// Share value that failed verification.
    pub got: Coeff,
    /// Value expected by the verifier.
    pub expected: Coeff,
    /// Commitment/check binding for the dealer polynomial.
    pub commitment_binding: [u8; 32],
}

impl ScalarVssComplaintEvidence {
    /// Encodes complaint evidence for transcript binding and wire payloads.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 + 4 + 4 + 4 + 32);
        out.extend_from_slice(&self.dealer.0.to_le_bytes());
        out.extend_from_slice(&self.receiver.0.to_le_bytes());
        out.extend_from_slice(&self.point.to_le_bytes());
        out.extend_from_slice(&self.got.to_le_bytes());
        out.extend_from_slice(&self.expected.to_le_bytes());
        out.extend_from_slice(&self.commitment_binding);
        out
    }

    /// Decodes canonical complaint evidence.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DkgError> {
        const LEN: usize = 2 + 2 + 4 + 4 + 4 + 32;
        if bytes.len() != LEN {
            return Err(DkgError::InvalidComplaintEvidenceLength {
                expected: LEN,
                got: bytes.len(),
            });
        }

        let dealer = PartyId(u16::from_le_bytes([bytes[0], bytes[1]]));
        let receiver = PartyId(u16::from_le_bytes([bytes[2], bytes[3]]));
        let point = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let got = Coeff::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let expected = Coeff::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let mut commitment_binding = [0u8; 32];
        commitment_binding.copy_from_slice(&bytes[16..48]);

        Ok(Self {
            dealer,
            receiver,
            point,
            got,
            expected,
            commitment_binding,
        })
    }
}

/// Test-only scalar VSS complaint-resolution result.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOnlyScalarVssResolution {
    /// Dealers with no valid complaint.
    pub accepted_dealers: Vec<PartyId>,
    /// Dealers with at least one valid complaint.
    pub rejected_dealers: Vec<PartyId>,
}

/// One receiver's combined scalar DKG share after accepted dealer contributions
/// are summed.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestOnlyCombinedScalarShare {
    /// Receiver that owns the combined share.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Sum of accepted dealer shares at `point`.
    pub value: Coeff,
}

/// Test-only scalar DKG combination output.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOnlyScalarDkgOutput {
    /// Dealers whose contributions were accepted.
    pub accepted_dealers: Vec<PartyId>,
    /// Dealers rejected by valid complaints.
    pub rejected_dealers: Vec<PartyId>,
    /// Clear combined secret. Test-only; never expose this in production.
    pub clear_secret: Coeff,
    /// Receiver shares of the summed accepted polynomial.
    pub shares: Vec<TestOnlyCombinedScalarShare>,
}

/// Test-only deal for one bounded ML-DSA secret vector.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOnlyBoundedSecretVectorDeal {
    /// Dealer that contributed this bounded vector.
    pub dealer: PartyId,
    /// Clear bounded coefficients in signed form. Test-only.
    pub clear_secret_coeffs: Vec<Coeff>,
    /// Per-coefficient scalar VSS deals.
    pub coefficient_deals: Vec<TestOnlyScalarVssDeal>,
}

/// One receiver's combined bounded-vector DKG share.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOnlyBoundedSecretVectorShare {
    /// Receiver that owns this share.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Field-valued coefficient shares.
    pub coeffs: Vec<Coeff>,
}

/// Test-only bounded-vector DKG output.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOnlyBoundedSecretVectorDkgOutput {
    /// Accepted dealer contributions.
    pub accepted_dealers: Vec<PartyId>,
    /// Rejected dealer contributions.
    pub rejected_dealers: Vec<PartyId>,
    /// Clear combined bounded secret coefficients. Test-only.
    pub clear_secret_coeffs: Vec<Coeff>,
    /// Receiver shares of the combined vector.
    pub shares: Vec<TestOnlyBoundedSecretVectorShare>,
}

/// Scalar IT-VSS backend shape for correctness and scaffold/dev checks.
///
/// Production native DKG must use vector/chunk IT-VSS certificates for bounded
/// ML-DSA secret material. This scalar trait remains as a narrow helper for
/// scalar tests and scaffold-only code; it must not become a scalar-per-
/// coefficient production DKG backend.
pub trait ScalarItVssBackend {
    /// Backend-specific public commitment/check object.
    type PublicCheck;
    /// Backend-specific private share object.
    type PrivateShare;
    /// Backend-specific complaint evidence.
    type ComplaintEvidence;

    /// Deals one scalar secret to all receivers.
    fn deal_scalar<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        dealer: PartyId,
        secret: Coeff,
    ) -> Result<(Self::PublicCheck, Vec<Self::PrivateShare>), DkgError>;

    /// Verifies one received scalar share.
    fn verify_scalar_share<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_check: &Self::PublicCheck,
        share: &Self::PrivateShare,
    ) -> Result<(), Self::ComplaintEvidence>;
}

/// Public share-binding entry for the local in-process scalar IT-VSS backend.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InProcessScalarVssShareBinding {
    /// Receiver whose directed share is bound.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Transcript binding for the directed share value.
    pub binding: [u8; 32],
}

/// Public check object for the local in-process scalar IT-VSS backend.
///
/// This is a local test backend for exercising native DKG round semantics. It
/// is not the final Rabin-Ben-Or information-checking backend because the
/// public checks are hash bindings, not IT authentication tags over private
/// channels.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InProcessScalarVssPublicCheck {
    /// Dealer that generated the sharing.
    pub dealer: PartyId,
    /// Threshold degree plus one used for the Shamir polynomial.
    pub threshold: u16,
    /// DKG configuration hash bound into this check.
    pub config_hash: KeygenTranscriptHash,
    /// Per-coefficient public check commitments.
    pub commitments: Vec<VssCommitment>,
    /// Per-receiver directed share bindings.
    pub share_bindings: Vec<InProcessScalarVssShareBinding>,
}

/// Directed private scalar share for the local in-process IT-VSS backend.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InProcessScalarVssPrivateShare {
    /// Scalar VSS share value and routing metadata.
    pub share: ScalarVssShare,
    /// Binding proving this is the delivered value for the public check.
    pub delivery_binding: [u8; 32],
}

/// Complaint evidence for the local in-process scalar IT-VSS backend.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InProcessScalarVssComplaintEvidence {
    /// Dealer whose directed share failed.
    pub dealer: PartyId,
    /// Receiver that detected the failure.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Delivered share value.
    pub got: Coeff,
    /// Binding advertised in the public check.
    pub expected_binding: [u8; 32],
    /// Binding recomputed from the delivered value.
    pub got_binding: [u8; 32],
    /// Binding of the dealer public check.
    pub public_check_binding: [u8; 32],
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl InProcessScalarVssComplaintEvidence {
    /// Encodes complaint evidence for DKG complaint payloads.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 + 4 + 4 + 32 + 32 + 32);
        out.extend_from_slice(&self.dealer.0.to_le_bytes());
        out.extend_from_slice(&self.receiver.0.to_le_bytes());
        out.extend_from_slice(&self.point.to_le_bytes());
        out.extend_from_slice(&self.got.to_le_bytes());
        out.extend_from_slice(&self.expected_binding);
        out.extend_from_slice(&self.got_binding);
        out.extend_from_slice(&self.public_check_binding);
        out
    }

    /// Decodes canonical complaint evidence.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DkgError> {
        const LEN: usize = 2 + 2 + 4 + 4 + 32 + 32 + 32;
        if bytes.len() != LEN {
            return Err(DkgError::InvalidComplaintEvidenceLength {
                expected: LEN,
                got: bytes.len(),
            });
        }

        let dealer = PartyId(u16::from_le_bytes([bytes[0], bytes[1]]));
        let receiver = PartyId(u16::from_le_bytes([bytes[2], bytes[3]]));
        let point = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let got = Coeff::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let mut expected_binding = [0u8; 32];
        expected_binding.copy_from_slice(&bytes[12..44]);
        let mut got_binding = [0u8; 32];
        got_binding.copy_from_slice(&bytes[44..76]);
        let mut public_check_binding = [0u8; 32];
        public_check_binding.copy_from_slice(&bytes[76..108]);

        Ok(Self {
            dealer,
            receiver,
            point,
            got,
            expected_binding,
            got_binding,
            public_check_binding,
        })
    }
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn encode_in_process_scalar_vss_public_check(
    check: &InProcessScalarVssPublicCheck,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IN_PROCESS_SCALAR_VSS_PUBLIC_CHECK_MAGIC);
    out.extend_from_slice(&check.dealer.0.to_le_bytes());
    out.extend_from_slice(&check.threshold.to_le_bytes());
    out.extend_from_slice(&check.config_hash.0);
    out.extend_from_slice(&(check.commitments.len() as u32).to_le_bytes());
    for commitment in &check.commitments {
        out.extend_from_slice(&(commitment.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&commitment.bytes);
    }
    out.extend_from_slice(&(check.share_bindings.len() as u32).to_le_bytes());
    for binding in &check.share_bindings {
        out.extend_from_slice(&binding.receiver.0.to_le_bytes());
        out.extend_from_slice(&binding.point.to_le_bytes());
        out.extend_from_slice(&binding.binding);
    }
    out
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn decode_in_process_scalar_vss_public_check(
    bytes: &[u8],
) -> Result<InProcessScalarVssPublicCheck, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(IN_PROCESS_SCALAR_VSS_PUBLIC_CHECK_MAGIC)?;
    let dealer = PartyId(cursor.read_u16()?);
    let threshold = cursor.read_u16()?;
    let mut config_hash = [0u8; 32];
    config_hash.copy_from_slice(cursor.read_exact(32)?);
    let commitment_len = cursor.read_u32()? as usize;
    let mut commitments = Vec::with_capacity(commitment_len);
    for _ in 0..commitment_len {
        let len = cursor.read_u32()? as usize;
        commitments.push(VssCommitment {
            bytes: cursor.read_exact(len)?.to_vec(),
        });
    }
    let binding_len = cursor.read_u32()? as usize;
    let mut share_bindings = Vec::with_capacity(binding_len);
    for _ in 0..binding_len {
        let receiver = PartyId(cursor.read_u16()?);
        let point = cursor.read_u32()?;
        let mut binding = [0u8; 32];
        binding.copy_from_slice(cursor.read_exact(32)?);
        share_bindings.push(InProcessScalarVssShareBinding {
            receiver,
            point,
            binding,
        });
    }
    cursor.finish()?;
    Ok(InProcessScalarVssPublicCheck {
        dealer,
        threshold,
        config_hash: KeygenTranscriptHash(config_hash),
        commitments,
        share_bindings,
    })
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn encode_in_process_scalar_vss_private_share(
    share: &InProcessScalarVssPrivateShare,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 2 + 2 + 4 + 4 + 32);
    out.extend_from_slice(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_MAGIC);
    out.extend_from_slice(&share.share.dealer.0.to_le_bytes());
    out.extend_from_slice(&share.share.receiver.0.to_le_bytes());
    out.extend_from_slice(&share.share.point.to_le_bytes());
    out.extend_from_slice(&share.share.value.to_le_bytes());
    out.extend_from_slice(&share.delivery_binding);
    out
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn encode_in_process_scalar_vss_private_share_vector(
    shares: &[InProcessScalarVssPrivateShare],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_VECTOR_MAGIC);
    out.extend_from_slice(&(shares.len() as u32).to_le_bytes());
    for share in shares {
        let encoded = encode_in_process_scalar_vss_private_share(share);
        out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        out.extend_from_slice(&encoded);
    }
    out
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn decode_in_process_scalar_vss_private_share(
    bytes: &[u8],
) -> Result<InProcessScalarVssPrivateShare, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_MAGIC)?;
    let dealer = PartyId(cursor.read_u16()?);
    let receiver = PartyId(cursor.read_u16()?);
    let point = cursor.read_u32()?;
    let value = cursor.read_i32()?;
    let mut delivery_binding = [0u8; 32];
    delivery_binding.copy_from_slice(cursor.read_exact(32)?);
    cursor.finish()?;
    Ok(InProcessScalarVssPrivateShare {
        share: ScalarVssShare {
            dealer,
            receiver,
            point,
            value,
        },
        delivery_binding,
    })
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn decode_in_process_scalar_vss_private_share_vector(
    bytes: &[u8],
) -> Result<Vec<InProcessScalarVssPrivateShare>, DkgError> {
    if bytes.starts_with(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_MAGIC) {
        return Ok(vec![decode_in_process_scalar_vss_private_share(bytes)?]);
    }
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_VECTOR_MAGIC)?;
    let len = cursor.read_u32()? as usize;
    let mut shares = Vec::with_capacity(len);
    for _ in 0..len {
        let share_len = cursor.read_u32()? as usize;
        shares.push(decode_in_process_scalar_vss_private_share(
            cursor.read_exact(share_len)?,
        )?);
    }
    cursor.finish()?;
    Ok(shares)
}

pub(crate) struct CanonicalCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn read_magic(&mut self, magic: &[u8]) -> Result<(), DkgError> {
        let got = self.read_exact(magic.len())?;
        if got != magic {
            return Err(DkgError::InvalidSecretShareEncoding(
                "in-process scalar vss magic",
            ));
        }
        Ok(())
    }

    pub(crate) fn read_exact(&mut self, len: usize) -> Result<&'a [u8], DkgError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DkgError::InvalidSecretShareEncoding(
                "in-process scalar vss length",
            ))?;
        if end > self.bytes.len() {
            return Err(DkgError::InvalidSecretShareEncoding(
                "in-process scalar vss length",
            ));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, DkgError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, DkgError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[cfg(any(test, feature = "scaffold-dev"))]
    fn read_i32(&mut self) -> Result<i32, DkgError> {
        let bytes = self.read_exact(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn finish(self) -> Result<(), DkgError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DkgError::InvalidSecretShareEncoding(
                "in-process scalar vss trailing bytes",
            ))
        }
    }
}

/// One local in-process scalar IT-VSS deal.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InProcessScalarVssDeal {
    /// Public check broadcast by the dealer.
    pub public_check: InProcessScalarVssPublicCheck,
    /// Directed private shares delivered to receivers.
    pub shares: Vec<InProcessScalarVssPrivateShare>,
}

/// Complaint-resolution result for scalar IT-VSS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarVssResolution {
    /// Dealers whose public checks survived complaint resolution.
    pub accepted_dealers: Vec<PartyId>,
    /// Dealers rejected by valid complaints.
    pub rejected_dealers: Vec<PartyId>,
}

/// Production IT-VSS complaint-resolution phase boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionItVssComplaintPhase {
    /// Dealers broadcast hashes binding their private deliveries before any
    /// public consistency coins are known.
    BroadcastPublicPrecommitments,
    /// Parties broadcast public-coin shares after precommitments are fixed.
    BroadcastPublicCoins,
    /// Dealers broadcast public information-checking metadata.
    BroadcastPublicCommitments,
    /// Dealers send directed private shares and information-checking tags.
    DeliverPrivateShares,
    /// Receivers verify directed private deliveries locally.
    VerifyPrivateDeliveries,
    /// Receivers broadcast public complaints for invalid deliveries.
    BroadcastComplaints,
    /// Parties resolve complaints without revealing unrelated private shares.
    ResolveComplaints,
    /// Accepted sharings emit public verified-sharing certificates.
    CertifyAcceptedSharings,
}

impl ProductionItVssComplaintPhase {
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::BroadcastPublicPrecommitments => 1,
            Self::BroadcastPublicCoins => 2,
            Self::BroadcastPublicCommitments => 3,
            Self::DeliverPrivateShares => 4,
            Self::VerifyPrivateDeliveries => 5,
            Self::BroadcastComplaints => 6,
            Self::ResolveComplaints => 7,
            Self::CertifyAcceptedSharings => 8,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::BroadcastPublicPrecommitments),
            2 => Some(Self::BroadcastPublicCoins),
            3 => Some(Self::BroadcastPublicCommitments),
            4 => Some(Self::DeliverPrivateShares),
            5 => Some(Self::VerifyPrivateDeliveries),
            6 => Some(Self::BroadcastComplaints),
            7 => Some(Self::ResolveComplaints),
            8 => Some(Self::CertifyAcceptedSharings),
            _ => None,
        }
    }
}

/// Ordered production IT-VSS complaint-resolution phases.
pub const PRODUCTION_IT_VSS_COMPLAINT_PHASES: &[ProductionItVssComplaintPhase] = &[
    ProductionItVssComplaintPhase::BroadcastPublicPrecommitments,
    ProductionItVssComplaintPhase::BroadcastPublicCoins,
    ProductionItVssComplaintPhase::BroadcastPublicCommitments,
    ProductionItVssComplaintPhase::DeliverPrivateShares,
    ProductionItVssComplaintPhase::VerifyPrivateDeliveries,
    ProductionItVssComplaintPhase::BroadcastComplaints,
    ProductionItVssComplaintPhase::ResolveComplaints,
    ProductionItVssComplaintPhase::CertifyAcceptedSharings,
];

/// Minimal state machine for the production IT-VSS complaint resolver shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionItVssComplaintStateMachine {
    next_phase_index: usize,
}

impl ProductionItVssComplaintStateMachine {
    /// Starts at public commitment broadcast.
    pub const fn new() -> Self {
        Self {
            next_phase_index: 0,
        }
    }

    /// Returns the next required phase.
    pub fn next_phase(&self) -> Option<ProductionItVssComplaintPhase> {
        PRODUCTION_IT_VSS_COMPLAINT_PHASES
            .get(self.next_phase_index)
            .copied()
    }

    /// Accepts exactly the next phase in order.
    pub fn accept_phase(&mut self, phase: ProductionItVssComplaintPhase) -> Result<(), DkgError> {
        if self.next_phase() != Some(phase) {
            return Err(DkgError::ItVssComplaintPhaseOutOfOrder);
        }
        self.next_phase_index += 1;
        Ok(())
    }

    /// Returns true after accepted-sharing certification.
    pub fn is_complete(&self) -> bool {
        self.next_phase_index == PRODUCTION_IT_VSS_COMPLAINT_PHASES.len()
    }
}

impl Default for ProductionItVssComplaintStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// Scalar Rabin-Ben-Or IT-VSS driver phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarItVssPhase {
    /// Context and transcript label have been fixed.
    Context,
    /// Dealer sends private Shamir shares, mask shares, and IC material.
    PrivatePayload,
    /// Holders audit opened/discarded receiver-side IC tags.
    IcAudit,
    /// Parties check random masked polynomial consistency rounds.
    PolynomialConsistency,
    /// Accepted sharing evidence is finalized.
    Accepted,
}

impl ScalarItVssPhase {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Context => 1,
            Self::PrivatePayload => 2,
            Self::IcAudit => 3,
            Self::PolynomialConsistency => 4,
            Self::Accepted => 5,
        }
    }
}

/// Ordered scalar IT-VSS phases.
pub const SCALAR_IT_VSS_PHASES: &[ScalarItVssPhase] = &[
    ScalarItVssPhase::Context,
    ScalarItVssPhase::PrivatePayload,
    ScalarItVssPhase::IcAudit,
    ScalarItVssPhase::PolynomialConsistency,
    ScalarItVssPhase::Accepted,
];

/// Conservative abort reasons for scalar IT-VSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarItVssAbortReason {
    /// Missing private payload or unrecoverable private-channel delivery gap.
    MissingPrivatePayload,
    /// IC audit dispute lacks objective public attribution.
    IcAuditDispute,
    /// Polynomial-consistency dispute lacks objective public attribution.
    PolynomialConsistencyDispute,
    /// Transcript mismatch or replay without attributable public evidence.
    TranscriptMismatch,
    /// Reconstruction/opening was ambiguous.
    AmbiguousReconstruction,
}

impl ScalarItVssAbortReason {
    const fn as_u8(self) -> u8 {
        match self {
            Self::MissingPrivatePayload => 1,
            Self::IcAuditDispute => 2,
            Self::PolynomialConsistencyDispute => 3,
            Self::TranscriptMismatch => 4,
            Self::AmbiguousReconstruction => 5,
        }
    }
}

/// Terminal scalar IT-VSS failure classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarItVssFailure {
    /// Abort without blame because attribution would require private material.
    AbortNoBlame {
        /// Conservative abort reason.
        reason: ScalarItVssAbortReason,
        /// Public transcript hash for the terminal decision.
        transcript_hash: [u8; 32],
    },
    /// Dealer blame backed by public evidence.
    BlameDealer {
        /// Blamed dealer.
        dealer: PartyId,
        /// Hash of public evidence.
        evidence_hash: [u8; 32],
    },
    /// Party blame backed by public evidence.
    BlameParty {
        /// Blamed party.
        party: PartyId,
        /// Hash of public evidence.
        evidence_hash: [u8; 32],
    },
}

/// Transcript-bound scalar IT-VSS context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarItVssContext {
    /// DKG config hash.
    pub config_hash: KeygenTranscriptHash,
    /// ML-DSA suite.
    pub suite: DkgSuite,
    /// Keygen epoch.
    pub epoch: KeygenEpoch,
    /// Dealer for this scalar sharing.
    pub dealer: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Canonical party-set hash.
    pub party_set_hash: [u8; 32],
    /// Maximum corrupted parties `f`.
    pub threshold_f: u16,
}

impl ScalarItVssContext {
    /// Builds a scalar IT-VSS context from the DKG config and sharing label.
    pub fn new(config: &DkgConfig, label: ItVssSharingLabel) -> Result<Self, DkgError> {
        config.validate()?;
        if label.config_hash != config.transcript_hash() {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        if !config.parties.contains(&label.dealer) {
            return Err(DkgError::UnknownParty(label.dealer));
        }
        Ok(Self {
            config_hash: config.transcript_hash(),
            suite: config.suite,
            epoch: config.epoch,
            dealer: label.dealer,
            label_hash: label.label_hash,
            party_set_hash: dkg_party_set_hash(config),
            threshold_f: config.threshold - 1,
        })
    }

    /// Stable context transcript hash.
    pub fn transcript_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-context");
        hasher.update(self.config_hash.0);
        hasher.update([self.suite.as_u8()]);
        hasher.update(self.epoch.0.to_le_bytes());
        hasher.update(self.dealer.0.to_le_bytes());
        hasher.update(self.label_hash);
        hasher.update(self.party_set_hash);
        hasher.update(self.threshold_f.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Replay key for scalar IT-VSS driver messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarItVssMessageKey {
    /// Scalar phase.
    pub phase: ScalarItVssPhase,
    /// Message sender.
    pub sender: PartyId,
    /// Directed receiver, if any.
    pub receiver: Option<PartyId>,
    /// Phase-local round number.
    pub round: u32,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
}

/// Scalar IT-VSS state-machine skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssStateMachine {
    context: ScalarItVssContext,
    parties: Vec<PartyId>,
    next_phase_index: usize,
    seen_messages: Vec<ScalarItVssMessageKey>,
    terminal_failure: Option<ScalarItVssFailure>,
}

/// Durable scalar IT-VSS cursor state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarItVssCursorState {
    /// Phase has started but is not yet complete.
    Started,
    /// Phase completed successfully.
    Completed,
    /// Session is terminal without accepted output.
    Aborted,
    /// Session emitted accepted evidence.
    Accepted,
}

/// Durable scalar IT-VSS continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssCursor {
    /// Scalar context hash.
    pub context_hash: [u8; 32],
    /// Current phase.
    pub phase: ScalarItVssPhase,
    /// Cursor state.
    pub state: ScalarItVssCursorState,
    /// Optional terminal failure.
    pub terminal_failure: Option<ScalarItVssFailure>,
    /// Current public transcript hash.
    pub transcript_hash: [u8; 32],
}

/// Durable scalar IT-VSS private state summary.
///
/// This does not make private material public. It records only the hashes needed
/// to prove restart is continuing the same private payload/retained-tag state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssPrivateStateRecord {
    /// Scalar context hash.
    pub context_hash: [u8; 32],
    /// Local receiver.
    pub receiver: PartyId,
    /// Hash of the local private payload.
    pub private_payload_hash: [u8; 32],
    /// Hash of local retained receiver-side tag state.
    pub retained_receiver_tag_state_hash: [u8; 32],
}

/// Durable scalar IT-VSS cursor/private-state log.
pub trait ScalarItVssPersistenceLog {
    /// Persists one scalar cursor.
    fn persist_scalar_it_vss_cursor(&mut self, cursor: &ScalarItVssCursor) -> Result<(), DkgError>;

    /// Persists one private-state record.
    fn persist_scalar_it_vss_private_state(
        &mut self,
        record: &ScalarItVssPrivateStateRecord,
    ) -> Result<(), DkgError>;

    /// Returns persisted cursors.
    fn scalar_it_vss_cursors(&self) -> &[ScalarItVssCursor];

    /// Returns persisted private-state records.
    fn scalar_it_vss_private_state(&self) -> &[ScalarItVssPrivateStateRecord];

    /// Returns the latest cursor, if any.
    fn latest_scalar_it_vss_cursor(&self) -> Option<&ScalarItVssCursor> {
        self.scalar_it_vss_cursors().last()
    }
}

/// In-memory scalar IT-VSS persistence log for tests and application adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryScalarItVssPersistenceLog {
    cursors: Vec<ScalarItVssCursor>,
    pub(crate) private_state: Vec<ScalarItVssPrivateStateRecord>,
}

impl InMemoryScalarItVssPersistenceLog {
    /// Returns persisted cursors.
    pub fn cursors(&self) -> &[ScalarItVssCursor] {
        &self.cursors
    }

    /// Returns persisted private-state records.
    pub fn private_state(&self) -> &[ScalarItVssPrivateStateRecord] {
        &self.private_state
    }
}

impl ScalarItVssPersistenceLog for InMemoryScalarItVssPersistenceLog {
    fn persist_scalar_it_vss_cursor(&mut self, cursor: &ScalarItVssCursor) -> Result<(), DkgError> {
        self.cursors.push(cursor.clone());
        Ok(())
    }

    fn persist_scalar_it_vss_private_state(
        &mut self,
        record: &ScalarItVssPrivateStateRecord,
    ) -> Result<(), DkgError> {
        self.private_state.push(record.clone());
        Ok(())
    }

    fn scalar_it_vss_cursors(&self) -> &[ScalarItVssCursor] {
        &self.cursors
    }

    fn scalar_it_vss_private_state(&self) -> &[ScalarItVssPrivateStateRecord] {
        &self.private_state
    }
}

impl ScalarItVssStateMachine {
    /// Starts a scalar IT-VSS driver at the context phase.
    pub fn new(config: &DkgConfig, label: ItVssSharingLabel) -> Result<Self, DkgError> {
        let context = ScalarItVssContext::new(config, label)?;
        Ok(Self {
            context,
            parties: config.parties.clone(),
            next_phase_index: 0,
            seen_messages: Vec::new(),
            terminal_failure: None,
        })
    }

    /// Returns the fixed context.
    pub const fn context(&self) -> ScalarItVssContext {
        self.context
    }

    /// Returns the next required phase unless the session is terminal.
    pub fn next_phase(&self) -> Option<ScalarItVssPhase> {
        if self.terminal_failure.is_some() {
            return None;
        }
        SCALAR_IT_VSS_PHASES.get(self.next_phase_index).copied()
    }

    /// Accepts exactly the next scalar IT-VSS phase.
    pub fn accept_phase(&mut self, phase: ScalarItVssPhase) -> Result<(), DkgError> {
        self.ensure_not_terminal()?;
        if self.next_phase() != Some(phase) {
            return Err(DkgError::ItVssScalarPhaseOutOfOrder);
        }
        self.next_phase_index += 1;
        Ok(())
    }

    /// Records a transcript-bound message key for the current phase.
    pub fn record_message(
        &mut self,
        phase: ScalarItVssPhase,
        sender: PartyId,
        receiver: Option<PartyId>,
        round: u32,
    ) -> Result<[u8; 32], DkgError> {
        self.ensure_not_terminal()?;
        if self.next_phase() != Some(phase) {
            return Err(DkgError::ItVssScalarPhaseOutOfOrder);
        }
        if !self.parties.contains(&sender) {
            return Err(DkgError::UnknownParty(sender));
        }
        if let Some(receiver) = receiver {
            if !self.parties.contains(&receiver) {
                return Err(DkgError::UnknownParty(receiver));
            }
        }
        let key = ScalarItVssMessageKey {
            phase,
            sender,
            receiver,
            round,
            label_hash: self.context.label_hash,
        };
        if self.seen_messages.contains(&key) {
            return Err(DkgError::ItVssScalarReplayDetected);
        }
        self.seen_messages.push(key);
        Ok(self.message_transcript_hash(&key))
    }

    /// Records an abort-without-blame terminal decision.
    pub fn abort_no_blame(
        &mut self,
        reason: ScalarItVssAbortReason,
    ) -> Result<ScalarItVssFailure, DkgError> {
        self.ensure_not_terminal()?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-abort-no-blame");
        hasher.update(self.context.transcript_hash());
        hasher.update([reason.as_u8()]);
        hasher.update([self.next_phase().map_or(0, ScalarItVssPhase::as_u8)]);
        let failure = ScalarItVssFailure::AbortNoBlame {
            reason,
            transcript_hash: hasher.finalize().into(),
        };
        self.terminal_failure = Some(failure.clone());
        Ok(failure)
    }

    /// Records objective dealer blame backed by public evidence.
    pub fn blame_dealer(
        &mut self,
        evidence_hash: [u8; 32],
    ) -> Result<ScalarItVssFailure, DkgError> {
        self.ensure_not_terminal()?;
        if evidence_hash == [0u8; 32] {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let failure = ScalarItVssFailure::BlameDealer {
            dealer: self.context.dealer,
            evidence_hash,
        };
        self.terminal_failure = Some(failure.clone());
        Ok(failure)
    }

    /// Records objective party blame backed by public evidence.
    pub fn blame_party(
        &mut self,
        party: PartyId,
        evidence_hash: [u8; 32],
    ) -> Result<ScalarItVssFailure, DkgError> {
        self.ensure_not_terminal()?;
        if !self.parties.contains(&party) {
            return Err(DkgError::UnknownParty(party));
        }
        if evidence_hash == [0u8; 32] {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let failure = ScalarItVssFailure::BlameParty {
            party,
            evidence_hash,
        };
        self.terminal_failure = Some(failure.clone());
        Ok(failure)
    }

    /// Returns the terminal failure if the session has aborted or blamed.
    pub fn terminal_failure(&self) -> Option<&ScalarItVssFailure> {
        self.terminal_failure.as_ref()
    }

    /// Returns true after the accepted phase.
    pub fn is_complete(&self) -> bool {
        self.terminal_failure.is_none() && self.next_phase_index == SCALAR_IT_VSS_PHASES.len()
    }

    /// Builds a durable cursor for the current scalar state.
    pub fn persistence_cursor(&self) -> ScalarItVssCursor {
        let state = if self.terminal_failure.is_some() {
            ScalarItVssCursorState::Aborted
        } else if self.is_complete() {
            ScalarItVssCursorState::Accepted
        } else if self.next_phase_index == 0 {
            ScalarItVssCursorState::Started
        } else {
            ScalarItVssCursorState::Completed
        };
        let phase = self.next_phase().unwrap_or(ScalarItVssPhase::Accepted);
        ScalarItVssCursor {
            context_hash: self.context.transcript_hash(),
            phase,
            state,
            terminal_failure: self.terminal_failure.clone(),
            transcript_hash: self.persistence_transcript_hash(state, phase),
        }
    }

    /// Persists the current scalar state into a cursor log.
    pub fn persist_cursor<L: ScalarItVssPersistenceLog>(
        &self,
        log: &mut L,
    ) -> Result<(), DkgError> {
        log.persist_scalar_it_vss_cursor(&self.persistence_cursor())
    }

    fn ensure_not_terminal(&self) -> Result<(), DkgError> {
        if self.terminal_failure.is_some() {
            Err(DkgError::ItVssScalarSessionTerminal)
        } else {
            Ok(())
        }
    }

    fn message_transcript_hash(&self, key: &ScalarItVssMessageKey) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-message");
        hasher.update(self.context.transcript_hash());
        hasher.update([key.phase.as_u8()]);
        hasher.update(key.sender.0.to_le_bytes());
        match key.receiver {
            Some(receiver) => {
                hasher.update([1]);
                hasher.update(receiver.0.to_le_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(key.round.to_le_bytes());
        hasher.update(key.label_hash);
        hasher.finalize().into()
    }

    fn persistence_transcript_hash(
        &self,
        state: ScalarItVssCursorState,
        phase: ScalarItVssPhase,
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-persistence-cursor");
        hasher.update(self.context.transcript_hash());
        hasher.update([phase.as_u8()]);
        hasher.update([scalar_it_vss_cursor_state_to_u8(state)]);
        if let Some(failure) = &self.terminal_failure {
            hasher.update(hash_scalar_it_vss_failure(failure));
        }
        hasher.finalize().into()
    }
}

/// Persists private scalar IT-VSS payload state by hash.
pub fn persist_scalar_it_vss_private_state<L: ScalarItVssPersistenceLog>(
    log: &mut L,
    context: &ScalarItVssContext,
    payload: &ScalarItVssPrivatePayload,
) -> Result<(), DkgError> {
    log.persist_scalar_it_vss_private_state(&ScalarItVssPrivateStateRecord {
        context_hash: context.transcript_hash(),
        receiver: payload.receiver,
        private_payload_hash: hash_scalar_it_vss_private_payload_commitment(context, payload),
        retained_receiver_tag_state_hash: hash_scalar_it_vss_retained_receiver_state(payload),
    })
}

/// Ensures a persisted scalar IT-VSS session can be used as accepted output.
pub fn ensure_scalar_it_vss_restart_allows_accepted<L: ScalarItVssPersistenceLog>(
    context: &ScalarItVssContext,
    log: &L,
) -> Result<(), DkgError> {
    let Some(cursor) = log.latest_scalar_it_vss_cursor() else {
        return Err(DkgError::ScalarItVssIncompleteAfterRestart);
    };
    if cursor.context_hash != context.transcript_hash() {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    if cursor.state == ScalarItVssCursorState::Aborted || cursor.terminal_failure.is_some() {
        return Err(DkgError::ScalarItVssAbortedAfterRestart);
    }
    if cursor.state != ScalarItVssCursorState::Accepted
        || cursor.phase != ScalarItVssPhase::Accepted
    {
        return Err(DkgError::ScalarItVssIncompleteAfterRestart);
    }
    if log.scalar_it_vss_private_state().is_empty() {
        return Err(DkgError::ScalarItVssIncompleteAfterRestart);
    }
    for record in log.scalar_it_vss_private_state() {
        if record.context_hash != context.transcript_hash()
            || record.private_payload_hash == [0u8; 32]
            || record.retained_receiver_tag_state_hash == [0u8; 32]
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
    }
    Ok(())
}

/// Release wrapper for scalar IT-VSS restart validation.
///
/// Scalar IT-VSS is a correctness and adversarial-test target in v1, not the
/// production DKG scale path. Any scalar session that is incomplete or aborted
/// after restart must nevertheless be rejected before its evidence can be used
/// as accepted output.
pub fn ensure_scalar_it_vss_release_state_allows_accepted<L: ScalarItVssPersistenceLog>(
    context: &ScalarItVssContext,
    log: &L,
) -> Result<(), DkgError> {
    ensure_scalar_it_vss_restart_allows_accepted(context, log)
}

pub(crate) fn scalar_it_vss_cursor_state_to_u8(state: ScalarItVssCursorState) -> u8 {
    match state {
        ScalarItVssCursorState::Started => 1,
        ScalarItVssCursorState::Completed => 2,
        ScalarItVssCursorState::Aborted => 3,
        ScalarItVssCursorState::Accepted => 4,
    }
}

pub(crate) fn hash_scalar_it_vss_failure(failure: &ScalarItVssFailure) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-failure");
    match failure {
        ScalarItVssFailure::AbortNoBlame {
            reason,
            transcript_hash,
        } => {
            hasher.update([1, reason.as_u8()]);
            hasher.update(transcript_hash);
        }
        ScalarItVssFailure::BlameDealer {
            dealer,
            evidence_hash,
        } => {
            hasher.update([2]);
            hasher.update(dealer.0.to_le_bytes());
            hasher.update(evidence_hash);
        }
        ScalarItVssFailure::BlameParty {
            party,
            evidence_hash,
        } => {
            hasher.update([3]);
            hasher.update(party.0.to_le_bytes());
            hasher.update(evidence_hash);
        }
    }
    hasher.finalize().into()
}

/// Scalar IT-VSS security parameters for the correctness implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarItVssSecurityParams {
    /// Number of retained IC tags per holder/receiver pair.
    pub ic_retained_tags: u16,
    /// Number of audited IC tags per holder/receiver pair.
    pub ic_audit_tags: u16,
    /// Number of polynomial-consistency mask rounds.
    pub poly_consistency_rounds: u16,
}

impl Default for ScalarItVssSecurityParams {
    fn default() -> Self {
        Self {
            ic_retained_tags: 8,
            ic_audit_tags: 8,
            poly_consistency_rounds: 192,
        }
    }
}

/// Salted public commitment to one scalar IT-VSS private payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssPrivatePayloadCommitment {
    /// Receiver whose private payload is committed.
    pub receiver: PartyId,
    /// Salted private-payload commitment hash.
    pub commitment_hash: [u8; 32],
}

/// Private scalar IT-VSS payload owned by one receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct ScalarItVssPrivatePayload {
    /// Dealer that created this scalar sharing.
    pub dealer: PartyId,
    /// Receiver that owns this payload.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Shamir share `beta_i = F(alpha_i)`.
    pub beta: ItVssFq,
    /// Mask shares `gamma_{r,i} = G_r(alpha_i)`.
    pub gamma_shares: Vec<ItVssFq>,
    /// Private 256-bit salt used for public payload commitment.
    pub payload_salt: [u8; 32],
    /// Holder-side audited `y` tags for this holder to all receivers.
    pub holder_audit_tags: Vec<ItVssHolderSideTag>,
    /// Holder-side retained `y` tags for this holder to all receivers.
    pub holder_retained_tags: Vec<ItVssHolderSideTag>,
    /// Receiver-side audited tags for other holders, opened only during audit.
    pub audited_receiver_tags: Vec<AuditedReceiverTag>,
    /// Receiver-private retained tags for reconstruction.
    pub retained_receiver_tags: Vec<RetainedReceiverTag>,
}

impl fmt::Debug for ScalarItVssPrivatePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScalarItVssPrivatePayload")
            .field("dealer", &self.dealer)
            .field("receiver", &self.receiver)
            .field("point", &self.point)
            .field("beta", &"<redacted>")
            .field("gamma_shares", &self.gamma_shares.len())
            .field("payload_salt", &"<redacted>")
            .field("holder_audit_tags", &self.holder_audit_tags.len())
            .field("holder_retained_tags", &self.holder_retained_tags.len())
            .field("audited_receiver_tags", &self.audited_receiver_tags.len())
            .field("retained_receiver_tags", &self.retained_receiver_tags.len())
            .finish()
    }
}

/// Public polynomial-consistency round for scalar IT-VSS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssPolynomialConsistencyRound {
    /// Round index.
    pub round: u16,
    /// Public challenge bit `e_r`.
    pub challenge: bool,
    /// Coefficients of `H_r(x) = G_r(x) + e_r*F(x)`.
    pub h_coefficients: Vec<ItVssFq>,
}

/// Complete scalar honest-path deal used by the first IT-VSS implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssHonestDeal {
    /// Transcript-bound scalar context.
    pub context: ScalarItVssContext,
    /// Security parameters.
    pub params: ScalarItVssSecurityParams,
    /// Public salted payload commitments.
    pub payload_commitments: Vec<ScalarItVssPrivatePayloadCommitment>,
    /// Directed private payloads.
    pub private_payloads: Vec<ScalarItVssPrivatePayload>,
    /// Public polynomial consistency rounds.
    pub consistency_rounds: Vec<ScalarItVssPolynomialConsistencyRound>,
    /// Public transcript hash of the deal.
    pub transcript_hash: [u8; 32],
}

/// Accepted scalar IT-VSS sharing evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedScalarItVssSharing {
    /// Transcript-bound scalar context.
    pub context: ScalarItVssContext,
    /// Receivers accepted by the honest-path checks.
    pub accepted_receivers: Vec<PartyId>,
    /// Public salted payload commitments.
    pub payload_commitments: Vec<ScalarItVssPrivatePayloadCommitment>,
    /// Public transcript hash.
    pub transcript_hash: [u8; 32],
}

/// Private vector IT-VSS payload owned by one receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct VectorItVssPrivatePayload {
    /// Dealer that created this vector sharing.
    pub dealer: PartyId,
    /// Receiver that owns this payload.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Vector Shamir share `beta_i = F(alpha_i)`.
    pub beta: Vec<ItVssFq>,
    /// Mask vector shares `gamma_{r,i} = G_r(alpha_i)`.
    pub gamma_shares: Vec<Vec<ItVssFq>>,
    /// Private 256-bit salt used for public payload commitment.
    pub payload_salt: [u8; 32],
    /// Holder-side audited vector `y` tags for this holder to all receivers.
    pub holder_audit_tags: Vec<ItVssVectorHolderSideTag>,
    /// Holder-side retained vector `y` tags for this holder to all receivers.
    pub holder_retained_tags: Vec<ItVssVectorHolderSideTag>,
    /// Receiver-side audited vector tags for other holders.
    pub audited_receiver_tags: Vec<AuditedVectorReceiverTag>,
    /// Receiver-private retained vector tags for reconstruction.
    pub retained_receiver_tags: Vec<RetainedVectorReceiverTag>,
}

impl fmt::Debug for VectorItVssPrivatePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VectorItVssPrivatePayload")
            .field("dealer", &self.dealer)
            .field("receiver", &self.receiver)
            .field("point", &self.point)
            .field("beta", &"<redacted>")
            .field("vector_len", &self.beta.len())
            .field("gamma_shares", &self.gamma_shares.len())
            .field("payload_salt", &"<redacted>")
            .field("holder_audit_tags", &self.holder_audit_tags.len())
            .field("holder_retained_tags", &self.holder_retained_tags.len())
            .field("audited_receiver_tags", &self.audited_receiver_tags.len())
            .field("retained_receiver_tags", &self.retained_receiver_tags.len())
            .finish()
    }
}

/// Public polynomial-consistency round for vector IT-VSS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorItVssPolynomialConsistencyRound {
    /// Round index.
    pub round: u16,
    /// Public challenge bit `e_r`.
    pub challenge: bool,
    /// Coefficients of `H_r(x) = G_r(x) + e_r*F(x)` for every vector coordinate.
    pub h_coefficients: Vec<Vec<ItVssFq>>,
}

/// Complete vector honest-path deal used by the batched IT-VSS implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorItVssHonestDeal {
    /// Transcript-bound context.
    pub context: ScalarItVssContext,
    /// Security parameters.
    pub params: ScalarItVssSecurityParams,
    /// Shared vector length.
    pub vector_len: usize,
    /// Public salted payload commitments.
    pub payload_commitments: Vec<ScalarItVssPrivatePayloadCommitment>,
    /// Directed private vector payloads.
    pub private_payloads: Vec<VectorItVssPrivatePayload>,
    /// Public polynomial consistency rounds.
    pub consistency_rounds: Vec<VectorItVssPolynomialConsistencyRound>,
    /// Public transcript hash of the deal.
    pub transcript_hash: [u8; 32],
}

/// Accepted vector IT-VSS sharing evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedVectorItVssSharing {
    /// Transcript-bound context.
    pub context: ScalarItVssContext,
    /// Shared vector length.
    pub vector_len: usize,
    /// Receivers accepted by the honest-path checks.
    pub accepted_receivers: Vec<PartyId>,
    /// Public salted payload commitments.
    pub payload_commitments: Vec<ScalarItVssPrivatePayloadCommitment>,
    /// Public transcript hash.
    pub transcript_hash: [u8; 32],
}

/// Public reconstruction share broadcast by one holder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssReconstructionShare {
    /// Holder broadcasting this point.
    pub holder: PartyId,
    /// Public interpolation point.
    pub point: u32,
    /// Broadcast `beta_i`.
    pub beta: ItVssFq,
    /// Holder-side retained `y` tags for receivers to verify.
    pub retained_y_tags: Vec<ItVssHolderSideTag>,
}

/// Receiver vote for one reconstructed holder point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarItVssReconstructionVote {
    /// Receiver/verifier.
    pub receiver: PartyId,
    /// Holder whose point was checked.
    pub holder: PartyId,
    /// Whether the receiver accepted the retained IC tags.
    pub accepted: bool,
}

/// Output of scalar IT-VSS reconstruction/opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarItVssReconstructionOutput {
    /// Reconstructed secret at zero.
    pub secret: ItVssFq,
    /// Points accepted by enough verifier votes.
    pub accepted_points: Vec<ShamirScalarShare>,
    /// Public receiver votes.
    pub votes: Vec<ScalarItVssReconstructionVote>,
    /// Transcript hash for the reconstruction.
    pub transcript_hash: [u8; 32],
}

/// Public vector reconstruction share broadcast by one holder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorItVssReconstructionShare {
    /// Holder broadcasting this point.
    pub holder: PartyId,
    /// Public interpolation point.
    pub point: u32,
    /// Broadcast vector `beta_i`.
    pub beta: Vec<ItVssFq>,
    /// Holder-side retained vector `y` tags for receivers to verify.
    pub retained_y_tags: Vec<ItVssVectorHolderSideTag>,
}

/// Receiver vote for one reconstructed vector holder point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VectorItVssReconstructionVote {
    /// Receiver/verifier.
    pub receiver: PartyId,
    /// Holder whose vector point was checked.
    pub holder: PartyId,
    /// Whether the receiver accepted the retained vector IC tags.
    pub accepted: bool,
}

/// Output of vector IT-VSS reconstruction/opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorItVssReconstructionOutput {
    /// Reconstructed vector secret at zero.
    pub secret: Vec<ItVssFq>,
    /// Per-coordinate accepted points.
    pub accepted_points_by_coordinate: Vec<Vec<ShamirScalarShare>>,
    /// Public receiver votes.
    pub votes: Vec<VectorItVssReconstructionVote>,
    /// Transcript hash for the reconstruction.
    pub transcript_hash: [u8; 32],
}

/// Forbidden public marker for retained IC receiver-side tag material.
pub const RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC: &[u8; 8] = b"TIVRT1\0\0";

/// Creates a scalar honest-path IT-VSS deal from caller-provided polynomial
/// coefficients and deterministic seed material.
///
/// This is the correctness path for scalar Rabin-Ben-Or IC checks. It is not
/// the production randomness source and must not be used as the final batched
/// DKG backend.
pub fn scalar_it_vss_deal_honest_path<P: MlDsaParams>(
    config: &DkgConfig,
    label: ItVssSharingLabel,
    polynomial_coefficients: &[Coeff],
    mask_polynomials: &[Vec<Coeff>],
    params: ScalarItVssSecurityParams,
    seed: [u8; 32],
) -> Result<ScalarItVssHonestDeal, DkgError> {
    config.validate()?;
    let context = ScalarItVssContext::new(config, label)?;
    let expected_degree_len = usize::from(config.threshold);
    if polynomial_coefficients.len() != expected_degree_len {
        return Err(DkgError::Backend("bad scalar IT-VSS polynomial degree"));
    }
    if mask_polynomials.len() != usize::from(params.poly_consistency_rounds)
        || mask_polynomials
            .iter()
            .any(|poly| poly.len() != expected_degree_len)
    {
        return Err(DkgError::Backend("bad scalar IT-VSS mask polynomial shape"));
    }

    let points = config.interpolation_points::<P>()?;
    let mut private_payloads = Vec::with_capacity(points.len());
    for &(receiver, point) in &points {
        let beta =
            ItVssFq::new(evaluate_shamir_polynomial::<P>(polynomial_coefficients, point)? as u32)?;
        let gamma_shares = mask_polynomials
            .iter()
            .map(|poly| {
                Ok(ItVssFq::new(
                    evaluate_shamir_polynomial::<P>(poly, point)? as u32
                )?)
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        let payload_salt =
            scalar_it_vss_derive_bytes(seed, &context, b"payload-salt", receiver, receiver, 0);
        private_payloads.push(ScalarItVssPrivatePayload {
            dealer: context.dealer,
            receiver,
            point,
            beta,
            gamma_shares,
            payload_salt,
            holder_audit_tags: Vec::new(),
            holder_retained_tags: Vec::new(),
            audited_receiver_tags: Vec::new(),
            retained_receiver_tags: Vec::new(),
        });
    }

    let total_tags = params
        .ic_audit_tags
        .checked_add(params.ic_retained_tags)
        .ok_or(DkgError::Backend("too many scalar IT-VSS IC tags"))?;
    for holder_index in 0..private_payloads.len() {
        let holder = private_payloads[holder_index].receiver;
        let value = private_payloads[holder_index].beta;
        for receiver_index in 0..private_payloads.len() {
            let receiver = private_payloads[receiver_index].receiver;
            for tag_index in 0..total_tags {
                let b = scalar_it_vss_derive_nonzero_fq(
                    seed, &context, b"ic-b", holder, receiver, tag_index,
                )?;
                let y =
                    scalar_it_vss_derive_fq(seed, &context, b"ic-y", holder, receiver, tag_index)?;
                if tag_index < params.ic_audit_tags {
                    let (holder_tag, receiver_tag) =
                        it_vss_audited_ic_tag_pair(holder, receiver, tag_index, value, b, y)?;
                    private_payloads[holder_index]
                        .holder_audit_tags
                        .push(holder_tag);
                    private_payloads[receiver_index]
                        .audited_receiver_tags
                        .push(receiver_tag);
                } else {
                    let (holder_tag, receiver_tag) =
                        it_vss_retained_ic_tag_pair(holder, receiver, tag_index, value, b, y)?;
                    private_payloads[holder_index]
                        .holder_retained_tags
                        .push(holder_tag);
                    private_payloads[receiver_index]
                        .retained_receiver_tags
                        .push(receiver_tag);
                }
            }
        }
    }

    let payload_commitments = private_payloads
        .iter()
        .map(|payload| ScalarItVssPrivatePayloadCommitment {
            receiver: payload.receiver,
            commitment_hash: hash_scalar_it_vss_private_payload_commitment(&context, payload),
        })
        .collect::<Vec<_>>();
    let consistency_rounds = scalar_it_vss_consistency_rounds::<P>(
        &context,
        polynomial_coefficients,
        mask_polynomials,
        &payload_commitments,
    )?;
    let transcript_hash =
        hash_scalar_it_vss_honest_deal(&context, &payload_commitments, &consistency_rounds);
    Ok(ScalarItVssHonestDeal {
        context,
        params,
        payload_commitments,
        private_payloads,
        consistency_rounds,
        transcript_hash,
    })
}

/// Verifies and accepts a scalar honest-path IT-VSS deal.
pub fn accept_scalar_it_vss_honest_deal<P: MlDsaParams>(
    config: &DkgConfig,
    deal: &ScalarItVssHonestDeal,
) -> Result<AcceptedScalarItVssSharing, DkgError> {
    config.validate()?;
    if deal.context.config_hash != config.transcript_hash()
        || deal.context.party_set_hash != dkg_party_set_hash(config)
        || deal.private_payloads.len() != config.parties.len()
        || deal.payload_commitments.len() != config.parties.len()
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    validate_exact_party_set(
        config,
        DkgRound::Share,
        deal.private_payloads.iter().map(|payload| payload.receiver),
    )?;
    validate_exact_party_set(
        config,
        DkgRound::Commit,
        deal.payload_commitments
            .iter()
            .map(|commitment| commitment.receiver),
    )?;

    for payload in &deal.private_payloads {
        let expected_point = config.interpolation_point::<P>(payload.receiver)?;
        if payload.dealer != deal.context.dealer || payload.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: payload.receiver,
                expected: expected_point,
                got: payload.point,
            });
        }
        let commitment = deal
            .payload_commitments
            .iter()
            .find(|commitment| commitment.receiver == payload.receiver)
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        if commitment.commitment_hash
            != hash_scalar_it_vss_private_payload_commitment(&deal.context, payload)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
    }

    verify_scalar_it_vss_audits(deal)?;
    verify_scalar_it_vss_polynomial_consistency::<P>(config, deal)?;
    let transcript_hash = hash_scalar_it_vss_honest_deal(
        &deal.context,
        &deal.payload_commitments,
        &deal.consistency_rounds,
    );
    if transcript_hash != deal.transcript_hash {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    Ok(AcceptedScalarItVssSharing {
        context: deal.context,
        accepted_receivers: config.parties.clone(),
        payload_commitments: deal.payload_commitments.clone(),
        transcript_hash,
    })
}

/// Creates a vector honest-path IT-VSS deal from caller-provided vector
/// polynomial coefficients and deterministic seed material.
///
/// This is the first batched/vector correctness path. It authenticates whole
/// `F_q^M` payloads with vector IC tags and is not yet the full production
/// backend.
pub fn vector_it_vss_deal_honest_path<P: MlDsaParams>(
    config: &DkgConfig,
    label: ItVssSharingLabel,
    polynomial_coefficients: &[Vec<Coeff>],
    mask_polynomials: &[Vec<Vec<Coeff>>],
    params: ScalarItVssSecurityParams,
    seed: [u8; 32],
) -> Result<VectorItVssHonestDeal, DkgError> {
    config.validate()?;
    let context = ScalarItVssContext::new(config, label)?;
    let vector_len = validate_vector_it_vss_polynomial_shape(config, polynomial_coefficients)?;
    if mask_polynomials.len() != usize::from(params.poly_consistency_rounds) {
        return Err(DkgError::Backend("bad vector IT-VSS mask round count"));
    }
    for mask_poly in mask_polynomials {
        let got = validate_vector_it_vss_polynomial_shape(config, mask_poly)?;
        if got != vector_len {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: vector_len,
                got,
            });
        }
    }

    let points = config.interpolation_points::<P>()?;
    let mut private_payloads = Vec::with_capacity(points.len());
    for &(receiver, point) in &points {
        let beta = evaluate_vector_it_vss_polynomial::<P>(polynomial_coefficients, point)?;
        let gamma_shares = mask_polynomials
            .iter()
            .map(|poly| evaluate_vector_it_vss_polynomial::<P>(poly, point))
            .collect::<Result<Vec<_>, DkgError>>()?;
        let payload_salt = scalar_it_vss_derive_bytes(
            seed,
            &context,
            b"vector-payload-salt",
            receiver,
            receiver,
            0,
        );
        private_payloads.push(VectorItVssPrivatePayload {
            dealer: context.dealer,
            receiver,
            point,
            beta,
            gamma_shares,
            payload_salt,
            holder_audit_tags: Vec::new(),
            holder_retained_tags: Vec::new(),
            audited_receiver_tags: Vec::new(),
            retained_receiver_tags: Vec::new(),
        });
    }

    let total_tags = params
        .ic_audit_tags
        .checked_add(params.ic_retained_tags)
        .ok_or(DkgError::Backend("too many vector IT-VSS IC tags"))?;
    for holder_index in 0..private_payloads.len() {
        let holder = private_payloads[holder_index].receiver;
        let values = private_payloads[holder_index].beta.clone();
        for receiver_index in 0..private_payloads.len() {
            let receiver = private_payloads[receiver_index].receiver;
            for tag_index in 0..total_tags {
                let b = scalar_it_vss_derive_nonzero_fq(
                    seed,
                    &context,
                    b"vector-ic-b",
                    holder,
                    receiver,
                    tag_index,
                )?;
                let y = vector_it_vss_derive_fq_vec(
                    seed,
                    &context,
                    b"vector-ic-y",
                    holder,
                    receiver,
                    tag_index,
                    vector_len,
                )?;
                if tag_index < params.ic_audit_tags {
                    let (holder_tag, receiver_tag) = it_vss_audited_vector_ic_tag_pair(
                        holder, receiver, tag_index, &values, b, &y,
                    )?;
                    private_payloads[holder_index]
                        .holder_audit_tags
                        .push(holder_tag);
                    private_payloads[receiver_index]
                        .audited_receiver_tags
                        .push(receiver_tag);
                } else {
                    let (holder_tag, receiver_tag) = it_vss_retained_vector_ic_tag_pair(
                        holder, receiver, tag_index, &values, b, &y,
                    )?;
                    private_payloads[holder_index]
                        .holder_retained_tags
                        .push(holder_tag);
                    private_payloads[receiver_index]
                        .retained_receiver_tags
                        .push(receiver_tag);
                }
            }
        }
    }

    let payload_commitments = private_payloads
        .iter()
        .map(|payload| ScalarItVssPrivatePayloadCommitment {
            receiver: payload.receiver,
            commitment_hash: hash_vector_it_vss_private_payload_commitment(&context, payload),
        })
        .collect::<Vec<_>>();
    let consistency_rounds = vector_it_vss_consistency_rounds::<P>(
        &context,
        polynomial_coefficients,
        mask_polynomials,
        &payload_commitments,
    )?;
    let transcript_hash =
        hash_vector_it_vss_honest_deal(&context, &payload_commitments, &consistency_rounds);
    Ok(VectorItVssHonestDeal {
        context,
        params,
        vector_len,
        payload_commitments,
        private_payloads,
        consistency_rounds,
        transcript_hash,
    })
}

/// Verifies and accepts a vector honest-path IT-VSS deal.
pub fn accept_vector_it_vss_honest_deal<P: MlDsaParams>(
    config: &DkgConfig,
    deal: &VectorItVssHonestDeal,
) -> Result<AcceptedVectorItVssSharing, DkgError> {
    config.validate()?;
    if deal.context.config_hash != config.transcript_hash()
        || deal.context.party_set_hash != dkg_party_set_hash(config)
        || deal.private_payloads.len() != config.parties.len()
        || deal.payload_commitments.len() != config.parties.len()
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    validate_exact_party_set(
        config,
        DkgRound::Share,
        deal.private_payloads.iter().map(|payload| payload.receiver),
    )?;
    validate_exact_party_set(
        config,
        DkgRound::Commit,
        deal.payload_commitments
            .iter()
            .map(|commitment| commitment.receiver),
    )?;

    for payload in &deal.private_payloads {
        let expected_point = config.interpolation_point::<P>(payload.receiver)?;
        if payload.dealer != deal.context.dealer || payload.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: payload.receiver,
                expected: expected_point,
                got: payload.point,
            });
        }
        if payload.beta.len() != deal.vector_len
            || payload
                .gamma_shares
                .iter()
                .any(|gamma| gamma.len() != deal.vector_len)
        {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: deal.vector_len,
                got: payload.beta.len(),
            });
        }
        let commitment = deal
            .payload_commitments
            .iter()
            .find(|commitment| commitment.receiver == payload.receiver)
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        if commitment.commitment_hash
            != hash_vector_it_vss_private_payload_commitment(&deal.context, payload)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
    }

    verify_vector_it_vss_audits(deal)?;
    verify_vector_it_vss_polynomial_consistency::<P>(config, deal)?;
    let transcript_hash = hash_vector_it_vss_honest_deal(
        &deal.context,
        &deal.payload_commitments,
        &deal.consistency_rounds,
    );
    if transcript_hash != deal.transcript_hash {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    Ok(AcceptedVectorItVssSharing {
        context: deal.context,
        vector_len: deal.vector_len,
        accepted_receivers: config.parties.clone(),
        payload_commitments: deal.payload_commitments.clone(),
        transcript_hash,
    })
}

/// Builds reconstruction shares from a verified scalar honest-path deal.
pub fn scalar_it_vss_reconstruction_shares(
    deal: &ScalarItVssHonestDeal,
) -> Vec<ScalarItVssReconstructionShare> {
    deal.private_payloads
        .iter()
        .map(|payload| ScalarItVssReconstructionShare {
            holder: payload.receiver,
            point: payload.point,
            beta: payload.beta,
            retained_y_tags: payload.holder_retained_tags.clone(),
        })
        .collect()
}

/// Builds vector reconstruction shares from a verified vector honest-path deal.
pub fn vector_it_vss_reconstruction_shares(
    deal: &VectorItVssHonestDeal,
) -> Vec<VectorItVssReconstructionShare> {
    deal.private_payloads
        .iter()
        .map(|payload| VectorItVssReconstructionShare {
            holder: payload.receiver,
            point: payload.point,
            beta: payload.beta.clone(),
            retained_y_tags: payload.holder_retained_tags.clone(),
        })
        .collect()
}

/// Reconstructs a scalar IT-VSS sharing from public holder broadcasts and
/// receiver-private retained IC tags.
pub fn reconstruct_scalar_it_vss_opening<P: MlDsaParams>(
    config: &DkgConfig,
    accepted: &AcceptedScalarItVssSharing,
    private_payloads: &[ScalarItVssPrivatePayload],
    reconstruction_shares: &[ScalarItVssReconstructionShare],
) -> Result<ScalarItVssReconstructionOutput, DkgError> {
    config.validate()?;
    if accepted.context.config_hash != config.transcript_hash()
        || accepted.context.party_set_hash != dkg_party_set_hash(config)
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    validate_exact_party_set(
        config,
        DkgRound::Share,
        private_payloads.iter().map(|payload| payload.receiver),
    )?;
    validate_exact_party_set(
        config,
        DkgRound::Share,
        accepted.accepted_receivers.iter().copied(),
    )?;
    validate_exact_party_set(
        config,
        DkgRound::Finalize,
        reconstruction_shares.iter().map(|share| share.holder),
    )?;
    for payload in private_payloads {
        let commitment = accepted
            .payload_commitments
            .iter()
            .find(|commitment| commitment.receiver == payload.receiver)
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        if commitment.commitment_hash
            != hash_scalar_it_vss_private_payload_commitment(&accepted.context, payload)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
    }

    let mut votes = Vec::new();
    let mut accepted_points = Vec::new();
    for share in reconstruction_shares {
        validate_scalar_it_vss_reconstruction_share_shape(config, share)?;
        let expected_point = config.interpolation_point::<P>(share.holder)?;
        if share.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: share.holder,
                expected: expected_point,
                got: share.point,
            });
        }
        let mut approvals = 0usize;
        for receiver_payload in private_payloads {
            let accepted_by_receiver =
                scalar_it_vss_receiver_accepts_reconstruction_share(receiver_payload, share);
            if accepted_by_receiver {
                approvals += 1;
            }
            votes.push(ScalarItVssReconstructionVote {
                receiver: receiver_payload.receiver,
                holder: share.holder,
                accepted: accepted_by_receiver,
            });
        }
        if approvals >= usize::from(config.threshold) {
            accepted_points.push(ShamirScalarShare {
                point: share.point,
                value: share.beta.value() as Coeff,
            });
        }
    }

    if accepted_points.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedReconstructionPoints {
            threshold: config.threshold,
            accepted: accepted_points.len(),
        });
    }
    let secret = ItVssFq::new(reconstruct_scalar_at_zero::<P>(
        &accepted_points[..usize::from(config.threshold)],
    )? as u32)?;
    ensure_scalar_it_vss_reconstruction_unambiguous::<P>(
        &accepted_points,
        usize::from(config.threshold),
        secret,
    )?;
    let transcript_hash =
        hash_scalar_it_vss_reconstruction(&accepted.context, &accepted_points, &votes);
    Ok(ScalarItVssReconstructionOutput {
        secret,
        accepted_points,
        votes,
        transcript_hash,
    })
}

/// Reconstructs a vector IT-VSS sharing from public holder broadcasts and
/// receiver-private retained vector IC tags.
pub fn reconstruct_vector_it_vss_opening<P: MlDsaParams>(
    config: &DkgConfig,
    accepted: &AcceptedVectorItVssSharing,
    private_payloads: &[VectorItVssPrivatePayload],
    reconstruction_shares: &[VectorItVssReconstructionShare],
) -> Result<VectorItVssReconstructionOutput, DkgError> {
    config.validate()?;
    if accepted.context.config_hash != config.transcript_hash()
        || accepted.context.party_set_hash != dkg_party_set_hash(config)
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    validate_exact_party_set(
        config,
        DkgRound::Share,
        private_payloads.iter().map(|payload| payload.receiver),
    )?;
    validate_exact_party_set(
        config,
        DkgRound::Share,
        accepted.accepted_receivers.iter().copied(),
    )?;
    validate_exact_party_set(
        config,
        DkgRound::Finalize,
        reconstruction_shares.iter().map(|share| share.holder),
    )?;
    for payload in private_payloads {
        if payload.beta.len() != accepted.vector_len {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: accepted.vector_len,
                got: payload.beta.len(),
            });
        }
        let commitment = accepted
            .payload_commitments
            .iter()
            .find(|commitment| commitment.receiver == payload.receiver)
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        if commitment.commitment_hash
            != hash_vector_it_vss_private_payload_commitment(&accepted.context, payload)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
    }

    let mut votes = Vec::new();
    let mut accepted_shares = Vec::new();
    for share in reconstruction_shares {
        validate_vector_it_vss_reconstruction_share_shape(config, accepted.vector_len, share)?;
        let expected_point = config.interpolation_point::<P>(share.holder)?;
        if share.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: share.holder,
                expected: expected_point,
                got: share.point,
            });
        }
        let mut approvals = 0usize;
        for receiver_payload in private_payloads {
            let accepted_by_receiver =
                vector_it_vss_receiver_accepts_reconstruction_share(receiver_payload, share);
            if accepted_by_receiver {
                approvals += 1;
            }
            votes.push(VectorItVssReconstructionVote {
                receiver: receiver_payload.receiver,
                holder: share.holder,
                accepted: accepted_by_receiver,
            });
        }
        if approvals >= usize::from(config.threshold) {
            accepted_shares.push(share.clone());
        }
    }

    if accepted_shares.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedReconstructionPoints {
            threshold: config.threshold,
            accepted: accepted_shares.len(),
        });
    }

    let mut secret = Vec::with_capacity(accepted.vector_len);
    let mut accepted_points_by_coordinate = Vec::with_capacity(accepted.vector_len);
    for coordinate in 0..accepted.vector_len {
        let points = accepted_shares
            .iter()
            .map(|share| {
                Ok(ShamirScalarShare {
                    point: share.point,
                    value: share
                        .beta
                        .get(coordinate)
                        .ok_or(DkgError::ItVssVectorLengthMismatch {
                            expected: accepted.vector_len,
                            got: share.beta.len(),
                        })?
                        .value() as Coeff,
                })
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        let coordinate_secret = ItVssFq::new(reconstruct_scalar_at_zero::<P>(
            &points[..usize::from(config.threshold)],
        )? as u32)?;
        ensure_scalar_it_vss_reconstruction_unambiguous::<P>(
            &points,
            usize::from(config.threshold),
            coordinate_secret,
        )?;
        secret.push(coordinate_secret);
        accepted_points_by_coordinate.push(points);
    }

    let transcript_hash = hash_vector_it_vss_reconstruction(&accepted.context, &secret, &votes);
    Ok(VectorItVssReconstructionOutput {
        secret,
        accepted_points_by_coordinate,
        votes,
        transcript_hash,
    })
}

pub(crate) fn scalar_it_vss_receiver_accepts_reconstruction_share(
    receiver_payload: &ScalarItVssPrivatePayload,
    share: &ScalarItVssReconstructionShare,
) -> bool {
    let retained_for_receiver = receiver_payload
        .retained_receiver_tags
        .iter()
        .filter(|tag| tag.holder() == share.holder && tag.receiver() == receiver_payload.receiver)
        .collect::<Vec<_>>();
    if retained_for_receiver.is_empty() {
        return false;
    }
    for receiver_tag in retained_for_receiver {
        let Some(holder_tag) = share.retained_y_tags.iter().find(|holder_tag| {
            holder_tag.holder == share.holder
                && holder_tag.receiver == receiver_payload.receiver
                && holder_tag.tag_index == receiver_tag.tag_index()
        }) else {
            return false;
        };
        if !receiver_tag.verify_private(share.beta, *holder_tag) {
            return false;
        }
    }
    true
}

pub(crate) fn vector_it_vss_receiver_accepts_reconstruction_share(
    receiver_payload: &VectorItVssPrivatePayload,
    share: &VectorItVssReconstructionShare,
) -> bool {
    let retained_for_receiver = receiver_payload
        .retained_receiver_tags
        .iter()
        .filter(|tag| tag.holder() == share.holder && tag.receiver() == receiver_payload.receiver)
        .collect::<Vec<_>>();
    if retained_for_receiver.is_empty() {
        return false;
    }
    for receiver_tag in retained_for_receiver {
        let Some(holder_tag) = share.retained_y_tags.iter().find(|holder_tag| {
            holder_tag.holder == share.holder
                && holder_tag.receiver == receiver_payload.receiver
                && holder_tag.tag_index == receiver_tag.tag_index()
        }) else {
            return false;
        };
        if !receiver_tag.verify_private(&share.beta, holder_tag) {
            return false;
        }
    }
    true
}

pub(crate) fn validate_scalar_it_vss_reconstruction_share_shape(
    config: &DkgConfig,
    share: &ScalarItVssReconstructionShare,
) -> Result<(), DkgError> {
    if !config.parties.contains(&share.holder) {
        return Err(DkgError::UnknownParty(share.holder));
    }
    for tag in &share.retained_y_tags {
        if tag.holder != share.holder {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        if !config.parties.contains(&tag.receiver) {
            return Err(DkgError::UnknownParty(tag.receiver));
        }
    }
    for receiver in &config.parties {
        let mut seen = Vec::new();
        for tag in share
            .retained_y_tags
            .iter()
            .filter(|tag| tag.receiver == *receiver)
        {
            if seen.contains(&tag.tag_index) {
                return Err(DkgError::DuplicateScalarItVssRetainedTag {
                    holder: share.holder,
                    receiver: *receiver,
                    tag_index: tag.tag_index,
                });
            }
            seen.push(tag.tag_index);
        }
        if seen.is_empty() {
            return Err(DkgError::MissingScalarItVssRetainedTag {
                holder: share.holder,
                receiver: *receiver,
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_vector_it_vss_reconstruction_share_shape(
    config: &DkgConfig,
    vector_len: usize,
    share: &VectorItVssReconstructionShare,
) -> Result<(), DkgError> {
    if !config.parties.contains(&share.holder) {
        return Err(DkgError::UnknownParty(share.holder));
    }
    if share.beta.len() != vector_len {
        return Err(DkgError::ItVssVectorLengthMismatch {
            expected: vector_len,
            got: share.beta.len(),
        });
    }
    for tag in &share.retained_y_tags {
        if tag.holder != share.holder {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        if tag.y.len() != vector_len {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: vector_len,
                got: tag.y.len(),
            });
        }
        if !config.parties.contains(&tag.receiver) {
            return Err(DkgError::UnknownParty(tag.receiver));
        }
    }
    for receiver in &config.parties {
        let mut seen = Vec::new();
        for tag in share
            .retained_y_tags
            .iter()
            .filter(|tag| tag.receiver == *receiver)
        {
            if seen.contains(&tag.tag_index) {
                return Err(DkgError::DuplicateScalarItVssRetainedTag {
                    holder: share.holder,
                    receiver: *receiver,
                    tag_index: tag.tag_index,
                });
            }
            seen.push(tag.tag_index);
        }
        if seen.is_empty() {
            return Err(DkgError::MissingScalarItVssRetainedTag {
                holder: share.holder,
                receiver: *receiver,
            });
        }
    }
    Ok(())
}

pub(crate) fn ensure_scalar_it_vss_reconstruction_unambiguous<P: MlDsaParams>(
    accepted_points: &[ShamirScalarShare],
    threshold: usize,
    expected_secret: ItVssFq,
) -> Result<(), DkgError> {
    let mut subset = Vec::with_capacity(threshold);
    check_scalar_it_vss_reconstruction_subsets::<P>(
        accepted_points,
        threshold,
        0,
        &mut subset,
        expected_secret,
    )
}

pub(crate) fn check_scalar_it_vss_reconstruction_subsets<P: MlDsaParams>(
    accepted_points: &[ShamirScalarShare],
    threshold: usize,
    start: usize,
    subset: &mut Vec<ShamirScalarShare>,
    expected_secret: ItVssFq,
) -> Result<(), DkgError> {
    if subset.len() == threshold {
        let secret = ItVssFq::new(reconstruct_scalar_at_zero::<P>(subset)? as u32)?;
        if secret != expected_secret {
            return Err(DkgError::AmbiguousScalarItVssReconstruction);
        }
        return Ok(());
    }
    let remaining_needed = threshold - subset.len();
    if accepted_points.len().saturating_sub(start) < remaining_needed {
        return Ok(());
    }
    for index in start..accepted_points.len() {
        subset.push(accepted_points[index]);
        check_scalar_it_vss_reconstruction_subsets::<P>(
            accepted_points,
            threshold,
            index + 1,
            subset,
            expected_secret,
        )?;
        subset.pop();
    }
    Ok(())
}

pub(crate) fn verify_scalar_it_vss_audits(deal: &ScalarItVssHonestDeal) -> Result<(), DkgError> {
    for holder_payload in &deal.private_payloads {
        for holder_tag in &holder_payload.holder_audit_tags {
            let receiver_payload = deal
                .private_payloads
                .iter()
                .find(|payload| payload.receiver == holder_tag.receiver)
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let receiver_tag = receiver_payload
                .audited_receiver_tags
                .iter()
                .find(|tag| {
                    tag.holder == holder_tag.holder
                        && tag.receiver == holder_tag.receiver
                        && tag.tag_index == holder_tag.tag_index
                })
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            if !receiver_tag.verify(holder_payload.beta, *holder_tag) {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_scalar_it_vss_polynomial_consistency<P: MlDsaParams>(
    config: &DkgConfig,
    deal: &ScalarItVssHonestDeal,
) -> Result<(), DkgError> {
    if deal.consistency_rounds.len() != usize::from(deal.params.poly_consistency_rounds) {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    for round in &deal.consistency_rounds {
        for payload in &deal.private_payloads {
            let h_at_point = evaluate_shamir_polynomial::<P>(
                &it_vss_fq_coeffs(&round.h_coefficients),
                payload.point,
            )?;
            let gamma = payload
                .gamma_shares
                .get(usize::from(round.round))
                .copied()
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let expected = if round.challenge {
                gamma.add_mod(payload.beta)
            } else {
                gamma
            };
            if ItVssFq::new(h_at_point as u32)? != expected {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
            config.interpolation_point::<P>(payload.receiver)?;
        }
    }
    Ok(())
}

pub(crate) fn verify_vector_it_vss_audits(deal: &VectorItVssHonestDeal) -> Result<(), DkgError> {
    for holder_payload in &deal.private_payloads {
        for holder_tag in &holder_payload.holder_audit_tags {
            let receiver_payload = deal
                .private_payloads
                .iter()
                .find(|payload| payload.receiver == holder_tag.receiver)
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let receiver_tag = receiver_payload
                .audited_receiver_tags
                .iter()
                .find(|tag| {
                    tag.holder == holder_tag.holder
                        && tag.receiver == holder_tag.receiver
                        && tag.tag_index == holder_tag.tag_index
                })
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            if !receiver_tag.verify(&holder_payload.beta, holder_tag) {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_vector_it_vss_polynomial_consistency<P: MlDsaParams>(
    config: &DkgConfig,
    deal: &VectorItVssHonestDeal,
) -> Result<(), DkgError> {
    if deal.consistency_rounds.len() != usize::from(deal.params.poly_consistency_rounds) {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    for round in &deal.consistency_rounds {
        if round.h_coefficients.len() != usize::from(config.threshold) {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        for payload in &deal.private_payloads {
            let h_at_point = evaluate_vector_it_vss_polynomial::<P>(
                &it_vss_fq_vector_coeffs(&round.h_coefficients),
                payload.point,
            )?;
            let gamma = payload
                .gamma_shares
                .get(usize::from(round.round))
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let expected = if round.challenge {
                vector_it_vss_add(gamma, &payload.beta)?
            } else {
                gamma.clone()
            };
            if h_at_point != expected {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
            config.interpolation_point::<P>(payload.receiver)?;
        }
    }
    Ok(())
}

pub(crate) fn scalar_it_vss_consistency_rounds<P: MlDsaParams>(
    context: &ScalarItVssContext,
    polynomial_coefficients: &[Coeff],
    mask_polynomials: &[Vec<Coeff>],
    payload_commitments: &[ScalarItVssPrivatePayloadCommitment],
) -> Result<Vec<ScalarItVssPolynomialConsistencyRound>, DkgError> {
    mask_polynomials
        .iter()
        .enumerate()
        .map(|(round, mask_poly)| {
            let challenge = scalar_it_vss_challenge_bit(context, payload_commitments, round as u16);
            let h_coefficients = mask_poly
                .iter()
                .zip(polynomial_coefficients)
                .map(|(&g, &f)| {
                    let value = if challenge {
                        reduce_mod_q::<P>(g + f)
                    } else {
                        reduce_mod_q::<P>(g)
                    };
                    ItVssFq::new(value as u32)
                })
                .collect::<Result<Vec<_>, DkgError>>()?;
            Ok(ScalarItVssPolynomialConsistencyRound {
                round: round as u16,
                challenge,
                h_coefficients,
            })
        })
        .collect()
}

pub(crate) fn vector_it_vss_consistency_rounds<P: MlDsaParams>(
    context: &ScalarItVssContext,
    polynomial_coefficients: &[Vec<Coeff>],
    mask_polynomials: &[Vec<Vec<Coeff>>],
    payload_commitments: &[ScalarItVssPrivatePayloadCommitment],
) -> Result<Vec<VectorItVssPolynomialConsistencyRound>, DkgError> {
    mask_polynomials
        .iter()
        .enumerate()
        .map(|(round, mask_poly)| {
            let challenge = scalar_it_vss_challenge_bit(context, payload_commitments, round as u16);
            let h_coefficients = mask_poly
                .iter()
                .zip(polynomial_coefficients)
                .map(|(g_vec, f_vec)| {
                    if g_vec.len() != f_vec.len() {
                        return Err(DkgError::ItVssVectorLengthMismatch {
                            expected: f_vec.len(),
                            got: g_vec.len(),
                        });
                    }
                    g_vec
                        .iter()
                        .zip(f_vec.iter())
                        .map(|(&g, &f)| {
                            let value = if challenge {
                                reduce_mod_q::<P>(g + f)
                            } else {
                                reduce_mod_q::<P>(g)
                            };
                            ItVssFq::new(value as u32)
                        })
                        .collect::<Result<Vec<_>, DkgError>>()
                })
                .collect::<Result<Vec<_>, DkgError>>()?;
            Ok(VectorItVssPolynomialConsistencyRound {
                round: round as u16,
                challenge,
                h_coefficients,
            })
        })
        .collect()
}

pub(crate) fn scalar_it_vss_challenge_bit(
    context: &ScalarItVssContext,
    payload_commitments: &[ScalarItVssPrivatePayloadCommitment],
    round: u16,
) -> bool {
    let mut commitments = payload_commitments.to_vec();
    commitments.sort_by_key(|commitment| commitment.receiver.0);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-consistency-challenge");
    hasher.update(context.transcript_hash());
    hasher.update(round.to_le_bytes());
    for commitment in commitments {
        hasher.update(commitment.receiver.0.to_le_bytes());
        hasher.update(commitment.commitment_hash);
    }
    hasher.finalize()[0] & 1 == 1
}

pub(crate) fn validate_vector_it_vss_polynomial_shape(
    config: &DkgConfig,
    polynomial: &[Vec<Coeff>],
) -> Result<usize, DkgError> {
    let expected_degree_len = usize::from(config.threshold);
    if polynomial.len() != expected_degree_len {
        return Err(DkgError::Backend("bad vector IT-VSS polynomial degree"));
    }
    let Some(first) = polynomial.first() else {
        return Err(DkgError::Backend("empty vector IT-VSS polynomial"));
    };
    let vector_len = first.len();
    if vector_len == 0 {
        return Err(DkgError::Backend("empty vector IT-VSS share"));
    }
    for coeff in polynomial {
        if coeff.len() != vector_len {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: vector_len,
                got: coeff.len(),
            });
        }
    }
    Ok(vector_len)
}

pub(crate) fn evaluate_vector_it_vss_polynomial<P: MlDsaParams>(
    polynomial: &[Vec<Coeff>],
    point: u32,
) -> Result<Vec<ItVssFq>, DkgError> {
    let Some(first) = polynomial.first() else {
        return Err(DkgError::Backend("empty vector IT-VSS polynomial"));
    };
    let vector_len = first.len();
    let mut out = Vec::with_capacity(vector_len);
    for coordinate in 0..vector_len {
        let coeffs = polynomial
            .iter()
            .map(|degree_coeffs| {
                degree_coeffs
                    .get(coordinate)
                    .copied()
                    .ok_or(DkgError::ItVssVectorLengthMismatch {
                        expected: vector_len,
                        got: degree_coeffs.len(),
                    })
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        out.push(ItVssFq::new(
            evaluate_shamir_polynomial::<P>(&coeffs, point)? as u32,
        )?);
    }
    Ok(out)
}

pub(crate) fn hash_scalar_it_vss_private_payload_commitment(
    context: &ScalarItVssContext,
    payload: &ScalarItVssPrivatePayload,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/private-payload-commitment");
    hasher.update(context.transcript_hash());
    hasher.update(payload.dealer.0.to_le_bytes());
    hasher.update(payload.receiver.0.to_le_bytes());
    hasher.update(payload.point.to_le_bytes());
    hasher.update(payload.payload_salt);
    hasher.update(payload.beta.value().to_le_bytes());
    hasher.update((payload.gamma_shares.len() as u32).to_le_bytes());
    for gamma in &payload.gamma_shares {
        hasher.update(gamma.value().to_le_bytes());
    }
    hash_holder_tags(&mut hasher, &payload.holder_audit_tags);
    hash_holder_tags(&mut hasher, &payload.holder_retained_tags);
    hash_audited_receiver_tags(&mut hasher, &payload.audited_receiver_tags);
    hash_retained_receiver_tags(&mut hasher, &payload.retained_receiver_tags);
    hasher.finalize().into()
}

pub(crate) fn hash_vector_it_vss_private_payload_commitment(
    context: &ScalarItVssContext,
    payload: &VectorItVssPrivatePayload,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/vector-private-payload-commitment");
    hasher.update(context.transcript_hash());
    hasher.update(payload.dealer.0.to_le_bytes());
    hasher.update(payload.receiver.0.to_le_bytes());
    hasher.update(payload.point.to_le_bytes());
    hasher.update(payload.payload_salt);
    hash_it_vss_fq_vec(&mut hasher, &payload.beta);
    hasher.update((payload.gamma_shares.len() as u32).to_le_bytes());
    for gamma in &payload.gamma_shares {
        hash_it_vss_fq_vec(&mut hasher, gamma);
    }
    hash_vector_holder_tags(&mut hasher, &payload.holder_audit_tags);
    hash_vector_holder_tags(&mut hasher, &payload.holder_retained_tags);
    hash_audited_vector_receiver_tags(&mut hasher, &payload.audited_receiver_tags);
    hash_retained_vector_receiver_tags(&mut hasher, &payload.retained_receiver_tags);
    hasher.finalize().into()
}

pub(crate) fn hash_scalar_it_vss_retained_receiver_state(
    payload: &ScalarItVssPrivatePayload,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/retained-receiver-state");
    hasher.update(payload.dealer.0.to_le_bytes());
    hasher.update(payload.receiver.0.to_le_bytes());
    hasher.update(payload.point.to_le_bytes());
    hash_retained_receiver_tags(&mut hasher, &payload.retained_receiver_tags);
    hasher.finalize().into()
}

pub(crate) fn hash_vector_it_vss_honest_deal(
    context: &ScalarItVssContext,
    payload_commitments: &[ScalarItVssPrivatePayloadCommitment],
    consistency_rounds: &[VectorItVssPolynomialConsistencyRound],
) -> [u8; 32] {
    let mut commitments = payload_commitments.to_vec();
    commitments.sort_by_key(|commitment| commitment.receiver.0);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/vector-honest-deal");
    hasher.update(context.transcript_hash());
    for commitment in commitments {
        hasher.update(commitment.receiver.0.to_le_bytes());
        hasher.update(commitment.commitment_hash);
    }
    hasher.update((consistency_rounds.len() as u32).to_le_bytes());
    for round in consistency_rounds {
        hasher.update(round.round.to_le_bytes());
        hasher.update([round.challenge as u8]);
        hasher.update((round.h_coefficients.len() as u32).to_le_bytes());
        for coefficient in &round.h_coefficients {
            hash_it_vss_fq_vec(&mut hasher, coefficient);
        }
    }
    hasher.finalize().into()
}

pub(crate) fn hash_scalar_it_vss_honest_deal(
    context: &ScalarItVssContext,
    payload_commitments: &[ScalarItVssPrivatePayloadCommitment],
    consistency_rounds: &[ScalarItVssPolynomialConsistencyRound],
) -> [u8; 32] {
    let mut commitments = payload_commitments.to_vec();
    commitments.sort_by_key(|commitment| commitment.receiver.0);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-honest-deal");
    hasher.update(context.transcript_hash());
    for commitment in commitments {
        hasher.update(commitment.receiver.0.to_le_bytes());
        hasher.update(commitment.commitment_hash);
    }
    hasher.update((consistency_rounds.len() as u32).to_le_bytes());
    for round in consistency_rounds {
        hasher.update(round.round.to_le_bytes());
        hasher.update([round.challenge as u8]);
        for coefficient in &round.h_coefficients {
            hasher.update(coefficient.value().to_le_bytes());
        }
    }
    hasher.finalize().into()
}

pub(crate) fn hash_scalar_it_vss_reconstruction(
    context: &ScalarItVssContext,
    accepted_points: &[ShamirScalarShare],
    votes: &[ScalarItVssReconstructionVote],
) -> [u8; 32] {
    let mut points = accepted_points.to_vec();
    points.sort_by_key(|point| point.point);
    let mut votes = votes.to_vec();
    votes.sort_by_key(|vote| (vote.holder.0, vote.receiver.0));
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-reconstruction");
    hasher.update(context.transcript_hash());
    hasher.update((points.len() as u32).to_le_bytes());
    for point in points {
        hasher.update(point.point.to_le_bytes());
        hasher.update(point.value.to_le_bytes());
    }
    hasher.update((votes.len() as u32).to_le_bytes());
    for vote in votes {
        hasher.update(vote.receiver.0.to_le_bytes());
        hasher.update(vote.holder.0.to_le_bytes());
        hasher.update([vote.accepted as u8]);
    }
    hasher.finalize().into()
}

pub(crate) fn hash_vector_it_vss_reconstruction(
    context: &ScalarItVssContext,
    secret: &[ItVssFq],
    votes: &[VectorItVssReconstructionVote],
) -> [u8; 32] {
    let mut votes = votes.to_vec();
    votes.sort_by_key(|vote| (vote.holder.0, vote.receiver.0));
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/vector-reconstruction");
    hasher.update(context.transcript_hash());
    hash_it_vss_fq_vec(&mut hasher, secret);
    hasher.update((votes.len() as u32).to_le_bytes());
    for vote in votes {
        hasher.update(vote.receiver.0.to_le_bytes());
        hasher.update(vote.holder.0.to_le_bytes());
        hasher.update([vote.accepted as u8]);
    }
    hasher.finalize().into()
}

pub(crate) fn hash_accepted_vector_it_vss_sharing(
    accepted: &AcceptedVectorItVssSharing,
) -> [u8; 32] {
    let mut commitments = accepted.payload_commitments.clone();
    commitments.sort_by_key(|commitment| commitment.receiver.0);
    let mut receivers = accepted.accepted_receivers.clone();
    receivers.sort();
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/accepted-vector-sharing");
    hasher.update(accepted.context.transcript_hash());
    hasher.update((accepted.vector_len as u32).to_le_bytes());
    hasher.update(accepted.transcript_hash);
    hasher.update((receivers.len() as u32).to_le_bytes());
    for receiver in receivers {
        hasher.update(receiver.0.to_le_bytes());
    }
    for commitment in commitments {
        hasher.update(commitment.receiver.0.to_le_bytes());
        hasher.update(commitment.commitment_hash);
    }
    hasher.finalize().into()
}

pub(crate) fn hash_holder_tags(hasher: &mut Sha3_256, tags: &[ItVssHolderSideTag]) {
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag in tags {
        hasher.update(tag.holder.0.to_le_bytes());
        hasher.update(tag.receiver.0.to_le_bytes());
        hasher.update(tag.tag_index.to_le_bytes());
        hasher.update(tag.y.value().to_le_bytes());
    }
}

pub(crate) fn hash_vector_holder_tags(hasher: &mut Sha3_256, tags: &[ItVssVectorHolderSideTag]) {
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag in tags {
        hasher.update(tag.holder.0.to_le_bytes());
        hasher.update(tag.receiver.0.to_le_bytes());
        hasher.update(tag.tag_index.to_le_bytes());
        hash_it_vss_fq_vec(hasher, &tag.y);
    }
}

pub(crate) fn hash_audited_receiver_tags(hasher: &mut Sha3_256, tags: &[AuditedReceiverTag]) {
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag in tags {
        hasher.update(tag.holder.0.to_le_bytes());
        hasher.update(tag.receiver.0.to_le_bytes());
        hasher.update(tag.tag_index.to_le_bytes());
        hasher.update(tag.b.value().to_le_bytes());
        hasher.update(tag.c.value().to_le_bytes());
    }
}

pub(crate) fn hash_audited_vector_receiver_tags(
    hasher: &mut Sha3_256,
    tags: &[AuditedVectorReceiverTag],
) {
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag in tags {
        hasher.update(tag.holder.0.to_le_bytes());
        hasher.update(tag.receiver.0.to_le_bytes());
        hasher.update(tag.tag_index.to_le_bytes());
        hasher.update(tag.b.value().to_le_bytes());
        hash_it_vss_fq_vec(hasher, &tag.c);
    }
}

pub(crate) fn hash_retained_receiver_tags(hasher: &mut Sha3_256, tags: &[RetainedReceiverTag]) {
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag in tags {
        hasher.update(tag.holder().0.to_le_bytes());
        hasher.update(tag.receiver().0.to_le_bytes());
        hasher.update(tag.tag_index().to_le_bytes());
        hasher.update(tag.b().value().to_le_bytes());
        hasher.update(tag.c().value().to_le_bytes());
    }
}

pub(crate) fn hash_retained_vector_receiver_tags(
    hasher: &mut Sha3_256,
    tags: &[RetainedVectorReceiverTag],
) {
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag in tags {
        hasher.update(tag.holder().0.to_le_bytes());
        hasher.update(tag.receiver().0.to_le_bytes());
        hasher.update(tag.tag_index().to_le_bytes());
        hasher.update(tag.b().value().to_le_bytes());
        hash_it_vss_fq_vec(hasher, tag.c());
    }
}

pub(crate) fn it_vss_fq_coeffs(values: &[ItVssFq]) -> Vec<Coeff> {
    values.iter().map(|value| value.value() as Coeff).collect()
}

pub(crate) fn it_vss_fq_vector_coeffs(values: &[Vec<ItVssFq>]) -> Vec<Vec<Coeff>> {
    values
        .iter()
        .map(|row| row.iter().map(|value| value.value() as Coeff).collect())
        .collect()
}

pub(crate) fn hash_it_vss_fq_vec(hasher: &mut Sha3_256, values: &[ItVssFq]) {
    hasher.update((values.len() as u32).to_le_bytes());
    for value in values {
        hasher.update(value.value().to_le_bytes());
    }
}

pub(crate) fn vector_it_vss_add(
    lhs: &[ItVssFq],
    rhs: &[ItVssFq],
) -> Result<Vec<ItVssFq>, DkgError> {
    if lhs.len() != rhs.len() {
        return Err(DkgError::ItVssVectorLengthMismatch {
            expected: lhs.len(),
            got: rhs.len(),
        });
    }
    Ok(lhs
        .iter()
        .zip(rhs.iter())
        .map(|(lhs, rhs)| lhs.add_mod(*rhs))
        .collect())
}

pub(crate) fn scalar_it_vss_derive_fq(
    seed: [u8; 32],
    context: &ScalarItVssContext,
    purpose: &'static [u8],
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
) -> Result<ItVssFq, DkgError> {
    let bytes = scalar_it_vss_derive_bytes(seed, context, purpose, holder, receiver, tag_index);
    let mut wide = [0u8; 8];
    wide.copy_from_slice(&bytes[..8]);
    ItVssFq::new((u64::from_le_bytes(wide) % u64::from(IT_VSS_FIELD_Q)) as u32)
}

pub(crate) fn scalar_it_vss_derive_nonzero_fq(
    seed: [u8; 32],
    context: &ScalarItVssContext,
    purpose: &'static [u8],
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
) -> Result<ItVssFq, DkgError> {
    for attempt in 0u16..=u16::MAX {
        let bytes = scalar_it_vss_derive_bytes_with_attempt(
            seed, context, purpose, holder, receiver, tag_index, attempt,
        );
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&bytes[..8]);
        let value = (u64::from_le_bytes(wide) % u64::from(IT_VSS_FIELD_Q)) as u32;
        if value != 0 {
            return ItVssFq::nonzero(value);
        }
    }
    Err(DkgError::Backend("failed to derive nonzero IT-VSS Fq"))
}

pub(crate) fn vector_it_vss_derive_fq_vec(
    seed: [u8; 32],
    context: &ScalarItVssContext,
    purpose: &'static [u8],
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    len: usize,
) -> Result<Vec<ItVssFq>, DkgError> {
    (0..len)
        .map(|coordinate| {
            let coordinate = u16::try_from(coordinate)
                .map_err(|_| DkgError::Backend("vector IT-VSS coordinate index overflow"))?;
            let bytes = scalar_it_vss_derive_bytes_with_attempt(
                seed, context, purpose, holder, receiver, tag_index, coordinate,
            );
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&bytes[..8]);
            ItVssFq::new((u64::from_le_bytes(wide) % u64::from(IT_VSS_FIELD_Q)) as u32)
        })
        .collect()
}

pub(crate) fn scalar_it_vss_derive_bytes(
    seed: [u8; 32],
    context: &ScalarItVssContext,
    purpose: &'static [u8],
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
) -> [u8; 32] {
    scalar_it_vss_derive_bytes_with_attempt(seed, context, purpose, holder, receiver, tag_index, 0)
}

pub(crate) fn scalar_it_vss_derive_bytes_with_attempt(
    seed: [u8; 32],
    context: &ScalarItVssContext,
    purpose: &'static [u8],
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    attempt: u16,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/scalar-derive");
    hasher.update(seed);
    hasher.update(context.transcript_hash());
    hasher.update(purpose);
    hasher.update(holder.0.to_le_bytes());
    hasher.update(receiver.0.to_le_bytes());
    hasher.update(tag_index.to_le_bytes());
    hasher.update(attempt.to_le_bytes());
    hasher.finalize().into()
}

/// Test/dev compatibility alias for one receiver's combined scalar share after
/// accepted dealer contributions.
#[cfg(any(test, feature = "scaffold-dev"))]
pub type InProcessCombinedScalarShare = SharedSmallScalarShare;

/// Combined scalar output from local in-process IT-VSS dealer resolution.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InProcessScalarDkgOutput {
    /// Dealers whose contributions were accepted.
    pub accepted_dealers: Vec<PartyId>,
    /// Dealers whose contributions were rejected.
    pub rejected_dealers: Vec<PartyId>,
    /// Receiver shares of the accepted summed polynomial.
    pub shares: Vec<InProcessCombinedScalarShare>,
}

/// Local in-process scalar IT-VSS backend.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InProcessScalarItVssBackend {
    seed: [u8; 32],
    counter: u64,
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl InProcessScalarItVssBackend {
    /// Creates a deterministic in-process backend instance.
    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    /// Deals one scalar and returns the complete local deal object.
    pub fn deal<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        dealer: PartyId,
        secret: Coeff,
    ) -> Result<InProcessScalarVssDeal, DkgError> {
        let (public_check, shares) = self.deal_scalar::<P>(config, dealer, secret)?;
        Ok(InProcessScalarVssDeal {
            public_check,
            shares,
        })
    }
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl ScalarItVssBackend for InProcessScalarItVssBackend {
    type PublicCheck = InProcessScalarVssPublicCheck;
    type PrivateShare = InProcessScalarVssPrivateShare;
    type ComplaintEvidence = InProcessScalarVssComplaintEvidence;

    fn deal_scalar<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        dealer: PartyId,
        secret: Coeff,
    ) -> Result<(Self::PublicCheck, Vec<Self::PrivateShare>), DkgError> {
        config.validate()?;
        if !config.parties.contains(&dealer) {
            return Err(DkgError::UnknownParty(dealer));
        }

        let deal_index = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(DkgError::Backend("in-process scalar VSS counter overflow"))?;

        let mut coefficients = Vec::with_capacity(usize::from(config.threshold));
        coefficients.push(reduce_mod_q::<P>(secret));
        for degree in 1..usize::from(config.threshold) {
            coefficients.push(in_process_scalar_vss_mask::<P>(
                self.seed, deal_index, dealer, degree,
            ));
        }

        let commitments = coefficients
            .iter()
            .enumerate()
            .map(|(index, &coefficient)| VssCommitment {
                bytes: in_process_scalar_vss_coefficient_commitment::<P>(
                    config,
                    dealer,
                    index,
                    coefficient,
                )
                .to_vec(),
            })
            .collect::<Vec<_>>();
        let config_hash = config.transcript_hash();
        let public_check_binding = in_process_scalar_vss_public_check_binding(
            dealer,
            config.threshold,
            config_hash,
            &commitments,
        );

        let mut shares = Vec::with_capacity(config.parties.len());
        let mut share_bindings = Vec::with_capacity(config.parties.len());
        for (receiver, point) in config.interpolation_points::<P>()? {
            let value = evaluate_shamir_polynomial::<P>(&coefficients, point)?;
            let binding = in_process_scalar_vss_share_binding::<P>(
                config_hash,
                public_check_binding,
                dealer,
                receiver,
                point,
                value,
            );
            share_bindings.push(InProcessScalarVssShareBinding {
                receiver,
                point,
                binding,
            });
            shares.push(InProcessScalarVssPrivateShare {
                share: ScalarVssShare {
                    dealer,
                    receiver,
                    point,
                    value,
                },
                delivery_binding: binding,
            });
        }

        Ok((
            InProcessScalarVssPublicCheck {
                dealer,
                threshold: config.threshold,
                config_hash,
                commitments,
                share_bindings,
            },
            shares,
        ))
    }

    fn verify_scalar_share<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_check: &Self::PublicCheck,
        share: &Self::PrivateShare,
    ) -> Result<(), Self::ComplaintEvidence> {
        verify_in_process_scalar_vss_share::<P>(config, public_check, share)
    }
}

/// Verifies one in-process scalar VSS share and returns complaint evidence on
/// failure.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verify_in_process_scalar_vss_share<P: MlDsaParams>(
    config: &DkgConfig,
    public_check: &InProcessScalarVssPublicCheck,
    private_share: &InProcessScalarVssPrivateShare,
) -> Result<(), InProcessScalarVssComplaintEvidence> {
    let share = private_share.share;
    let public_check_binding = in_process_scalar_vss_public_check_binding(
        public_check.dealer,
        public_check.threshold,
        public_check.config_hash,
        &public_check.commitments,
    );
    let got_binding = in_process_scalar_vss_share_binding::<P>(
        public_check.config_hash,
        public_check_binding,
        share.dealer,
        share.receiver,
        share.point,
        share.value,
    );
    let expected_binding = public_check
        .share_bindings
        .iter()
        .find(|binding| binding.receiver == share.receiver)
        .map(|binding| binding.binding)
        .unwrap_or([0u8; 32]);

    let failure = InProcessScalarVssComplaintEvidence {
        dealer: share.dealer,
        receiver: share.receiver,
        point: share.point,
        got: reduce_mod_q::<P>(share.value),
        expected_binding,
        got_binding,
        public_check_binding,
    };

    if config.validate().is_err()
        || public_check.config_hash != config.transcript_hash()
        || public_check.dealer != share.dealer
        || public_check.threshold != config.threshold
        || !config.parties.contains(&share.dealer)
        || !config.parties.contains(&share.receiver)
    {
        return Err(failure);
    }

    let expected_point = match config.interpolation_point::<P>(share.receiver) {
        Ok(point) => point,
        Err(_) => return Err(failure),
    };
    if share.point != expected_point || private_share.delivery_binding != got_binding {
        return Err(failure);
    }

    match public_check
        .share_bindings
        .iter()
        .find(|binding| binding.receiver == share.receiver)
    {
        Some(binding) if binding.point == share.point && binding.binding == got_binding => Ok(()),
        _ => Err(failure),
    }
}

/// Verifies all directed shares in one in-process scalar VSS deal.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verify_in_process_scalar_vss_round<P: MlDsaParams>(
    config: &DkgConfig,
    deal: &InProcessScalarVssDeal,
) -> Result<Vec<DkgComplaintPayload>, DkgError> {
    config.validate()?;
    if !config.parties.contains(&deal.public_check.dealer) {
        return Err(DkgError::UnknownParty(deal.public_check.dealer));
    }
    if deal.shares.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: config.parties.len(),
            got: deal.shares.len(),
        });
    }

    let mut seen = Vec::with_capacity(deal.shares.len());
    let mut complaints = Vec::new();
    for share in &deal.shares {
        if share.share.dealer != deal.public_check.dealer {
            return Err(DkgError::PartyMismatch {
                expected: deal.public_check.dealer,
                got: share.share.dealer,
            });
        }
        if !config.parties.contains(&share.share.receiver) {
            return Err(DkgError::UnknownParty(share.share.receiver));
        }
        if seen.contains(&share.share.receiver) {
            return Err(DkgError::DuplicateShare {
                dealer: share.share.dealer,
                receiver: share.share.receiver,
            });
        }
        seen.push(share.share.receiver);

        if let Err(evidence) =
            verify_in_process_scalar_vss_share::<P>(config, &deal.public_check, share)
        {
            complaints.push(DkgComplaintPayload {
                complainant: evidence.receiver,
                dealer: evidence.dealer,
                receiver: evidence.receiver,
                reason: DkgComplaintReason::InvalidVssShare,
                evidence: evidence.to_canonical_bytes(),
            });
        }
    }

    Ok(complaints)
}

/// Resolves in-process scalar VSS complaints into accepted and rejected dealers.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn resolve_in_process_scalar_vss_complaints<P: MlDsaParams>(
    config: &DkgConfig,
    public_checks: &[InProcessScalarVssPublicCheck],
    complaints: &[DkgComplaintPayload],
) -> Result<ScalarVssResolution, DkgError> {
    config.validate()?;
    validate_exact_party_set(
        config,
        DkgRound::Commit,
        public_checks.iter().map(|check| check.dealer),
    )?;

    let mut rejected_dealers = Vec::new();
    let mut seen_complaints = Vec::with_capacity(complaints.len());
    for complaint in complaints {
        if complaint.reason != DkgComplaintReason::InvalidVssShare {
            return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
        }
        if complaint.receiver != complaint.complainant {
            return Err(DkgError::PartyMismatch {
                expected: complaint.complainant,
                got: complaint.receiver,
            });
        }
        if !config.parties.contains(&complaint.complainant) {
            return Err(DkgError::UnknownParty(complaint.complainant));
        }
        if !config.parties.contains(&complaint.dealer) {
            return Err(DkgError::UnknownParty(complaint.dealer));
        }
        let complaint_key = (complaint.complainant, complaint.dealer, complaint.receiver);
        if seen_complaints.contains(&complaint_key) {
            return Err(DkgError::DuplicateComplaint {
                complainant: complaint.complainant,
                dealer: complaint.dealer,
                receiver: complaint.receiver,
            });
        }
        seen_complaints.push(complaint_key);

        let evidence =
            InProcessScalarVssComplaintEvidence::from_canonical_bytes(&complaint.evidence)?;
        if evidence.dealer != complaint.dealer || evidence.receiver != complaint.receiver {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected_point = config.interpolation_point::<P>(evidence.receiver)?;
        if evidence.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: evidence.receiver,
                expected: expected_point,
                got: evidence.point,
            });
        }

        let Some(public_check) = public_checks
            .iter()
            .find(|check| check.dealer == evidence.dealer)
        else {
            return Err(DkgError::UnknownParty(evidence.dealer));
        };
        let public_check_binding = in_process_scalar_vss_public_check_binding(
            public_check.dealer,
            public_check.threshold,
            public_check.config_hash,
            &public_check.commitments,
        );
        if evidence.public_check_binding != public_check_binding {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected_binding = public_check
            .share_bindings
            .iter()
            .find(|binding| binding.receiver == evidence.receiver)
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        if expected_binding.point != evidence.point
            || expected_binding.binding != evidence.expected_binding
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let got_binding = in_process_scalar_vss_share_binding::<P>(
            public_check.config_hash,
            public_check_binding,
            evidence.dealer,
            evidence.receiver,
            evidence.point,
            evidence.got,
        );
        if evidence.got_binding != got_binding || evidence.got_binding == evidence.expected_binding
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }

        if !rejected_dealers.contains(&evidence.dealer) {
            rejected_dealers.push(evidence.dealer);
        }
    }

    let accepted_dealers = config
        .parties
        .iter()
        .copied()
        .filter(|party| !rejected_dealers.contains(party))
        .collect();

    Ok(ScalarVssResolution {
        accepted_dealers,
        rejected_dealers,
    })
}

/// Resolves complaints for a vector/polynomial VSS setup. One valid complaint
/// against any coefficient rejects the dealer's whole vector contribution.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn resolve_in_process_scalar_vss_vector_complaints<P: MlDsaParams>(
    config: &DkgConfig,
    public_check_vectors: &[Vec<InProcessScalarVssPublicCheck>],
    complaints: &[DkgComplaintPayload],
) -> Result<ScalarVssResolution, DkgError> {
    config.validate()?;
    if public_check_vectors.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Commit,
            expected: config.parties.len(),
            got: public_check_vectors.len(),
        });
    }

    let mut dealer_ids = Vec::with_capacity(public_check_vectors.len());
    for vector in public_check_vectors {
        let first = vector.first().ok_or(DkgError::EmptyPublicCommitments)?;
        if !config.parties.contains(&first.dealer) {
            return Err(DkgError::UnknownParty(first.dealer));
        }
        for check in vector {
            if check.dealer != first.dealer {
                return Err(DkgError::PartyMismatch {
                    expected: first.dealer,
                    got: check.dealer,
                });
            }
            if check.threshold != config.threshold {
                return Err(DkgError::InvalidThreshold {
                    threshold: check.threshold,
                    parties: config.parties.len(),
                });
            }
            if check.config_hash != config.transcript_hash() {
                return Err(DkgError::FinalOutputConfigMismatch);
            }
        }
        dealer_ids.push(first.dealer);
    }
    validate_exact_party_set(config, DkgRound::Commit, dealer_ids.into_iter())?;

    let mut rejected_dealers = Vec::new();
    let mut seen_complaints = Vec::with_capacity(complaints.len());
    for complaint in complaints {
        if complaint.reason != DkgComplaintReason::InvalidVssShare {
            return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
        }
        if complaint.receiver != complaint.complainant {
            return Err(DkgError::PartyMismatch {
                expected: complaint.complainant,
                got: complaint.receiver,
            });
        }
        if !config.parties.contains(&complaint.complainant) {
            return Err(DkgError::UnknownParty(complaint.complainant));
        }
        if !config.parties.contains(&complaint.dealer) {
            return Err(DkgError::UnknownParty(complaint.dealer));
        }
        let complaint_key = (complaint.complainant, complaint.dealer, complaint.receiver);
        if seen_complaints.contains(&complaint_key) {
            return Err(DkgError::DuplicateComplaint {
                complainant: complaint.complainant,
                dealer: complaint.dealer,
                receiver: complaint.receiver,
            });
        }
        seen_complaints.push(complaint_key);

        let evidence =
            InProcessScalarVssComplaintEvidence::from_canonical_bytes(&complaint.evidence)?;
        if evidence.dealer != complaint.dealer || evidence.receiver != complaint.receiver {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected_point = config.interpolation_point::<P>(evidence.receiver)?;
        if evidence.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: evidence.receiver,
                expected: expected_point,
                got: evidence.point,
            });
        }

        let Some(public_check_vector) = public_check_vectors
            .iter()
            .find(|vector| vector.first().map(|check| check.dealer) == Some(evidence.dealer))
        else {
            return Err(DkgError::UnknownParty(evidence.dealer));
        };
        let mut matched_check = None;
        for check in public_check_vector {
            let binding = in_process_scalar_vss_public_check_binding(
                check.dealer,
                check.threshold,
                check.config_hash,
                &check.commitments,
            );
            if binding == evidence.public_check_binding {
                matched_check = Some((check, binding));
                break;
            }
        }
        let Some((public_check, public_check_binding)) = matched_check else {
            return Err(DkgError::ComplaintEvidenceMismatch);
        };

        let expected_binding = public_check
            .share_bindings
            .iter()
            .find(|binding| binding.receiver == evidence.receiver)
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        if expected_binding.point != evidence.point
            || expected_binding.binding != evidence.expected_binding
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let got_binding = in_process_scalar_vss_share_binding::<P>(
            public_check.config_hash,
            public_check_binding,
            evidence.dealer,
            evidence.receiver,
            evidence.point,
            evidence.got,
        );
        if evidence.got_binding != got_binding || evidence.got_binding == evidence.expected_binding
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }

        if !rejected_dealers.contains(&evidence.dealer) {
            rejected_dealers.push(evidence.dealer);
        }
    }

    let accepted_dealers = config
        .parties
        .iter()
        .copied()
        .filter(|party| !rejected_dealers.contains(party))
        .collect::<Vec<_>>();
    if accepted_dealers.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: accepted_dealers.len(),
        });
    }

    Ok(ScalarVssResolution {
        accepted_dealers,
        rejected_dealers,
    })
}

#[cfg(any(test, feature = "scaffold-dev"))]
pub(crate) fn hash_in_process_scalar_vss_public_check_vector(
    vector: &[InProcessScalarVssPublicCheck],
) -> Result<[u8; 32], DkgError> {
    let first = vector.first().ok_or(DkgError::EmptyPublicCommitments)?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/in-process-vector-public-check");
    hasher.update(first.dealer.0.to_le_bytes());
    hasher.update((vector.len() as u32).to_le_bytes());
    for check in vector {
        if check.dealer != first.dealer {
            return Err(DkgError::PartyMismatch {
                expected: first.dealer,
                got: check.dealer,
            });
        }
        hash_bytes(
            &mut hasher,
            &encode_in_process_scalar_vss_public_check(check),
        );
    }
    Ok(hasher.finalize().into())
}

/// Builds test IT-VSS public artifacts from the current in-process vector VSS
/// resolver.
///
/// This is a scaffold adapter only: it lets the native DKG path exercise the
/// same public certificate and complaint-resolution validation shape that the
/// Rabin-Ben-Or information-checking backend must emit later.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn scaffold_it_vss_resolution_from_in_process_scalar_vss_vector_resolution(
    config: &DkgConfig,
    public_check_vectors: &[Vec<InProcessScalarVssPublicCheck>],
    complaints: &[DkgComplaintPayload],
    scalar_resolution: &ScalarVssResolution,
) -> Result<(Vec<ItVssPublicCommitment>, ItVssComplaintResolution), DkgError> {
    config.validate()?;
    let complaint_hash = hash_dkg_complaint_payloads(complaints);
    let mut public_commitments = Vec::with_capacity(public_check_vectors.len());
    let mut certificates = Vec::new();

    for vector in public_check_vectors {
        let first = vector.first().ok_or(DkgError::EmptyPublicCommitments)?;
        let label = ItVssSharingLabel::new(
            config,
            first.dealer,
            ItVssSharingDomain::PrimeFieldMpcAux,
            None,
        )?;
        let public_commitment = ItVssPublicCommitment {
            backend_id: ItVssBackendId::InProcessHashBindingScaffold,
            dealer: first.dealer,
            label_hash: label.label_hash,
            public_metadata_hash: hash_in_process_scalar_vss_public_check_vector(vector)?,
        };
        if scalar_resolution.accepted_dealers.contains(&first.dealer) {
            certificates.push(VerifiedItVssSharingCertificate {
                backend_id: ItVssBackendId::InProcessHashBindingScaffold,
                dealer: first.dealer,
                label_hash: label.label_hash,
                accepted_receivers: config.parties.clone(),
                complaint_hash,
                transcript_hash: hash_it_vss_public_commitment(&public_commitment),
            });
        }
        public_commitments.push(public_commitment);
    }

    let resolution = ItVssComplaintResolution {
        accepted_dealers: scalar_resolution.accepted_dealers.clone(),
        rejected_dealers: scalar_resolution.rejected_dealers.clone(),
        complaints: complaints.to_vec(),
        certificates,
    };
    validate_it_vss_complaint_resolution_for_backend(
        config,
        &public_commitments,
        &resolution,
        ItVssBackendId::InProcessHashBindingScaffold,
    )?;
    Ok((public_commitments, resolution))
}

/// Combines accepted in-process scalar VSS dealer contributions into one
/// scalar sharing.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn combine_accepted_in_process_scalar_vss_deals<P: MlDsaParams>(
    config: &DkgConfig,
    deals: &[InProcessScalarVssDeal],
    complaints: &[DkgComplaintPayload],
) -> Result<InProcessScalarDkgOutput, DkgError> {
    let public_checks = deals
        .iter()
        .map(|deal| deal.public_check.clone())
        .collect::<Vec<_>>();
    let resolution =
        resolve_in_process_scalar_vss_complaints::<P>(config, &public_checks, complaints)?;
    if resolution.accepted_dealers.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: resolution.accepted_dealers.len(),
        });
    }

    let q = i64::from(P::Q);
    let mut shares = Vec::with_capacity(config.parties.len());
    for (receiver, point) in config.interpolation_points::<P>()? {
        let mut value = 0i64;
        for deal in deals {
            if !resolution
                .accepted_dealers
                .contains(&deal.public_check.dealer)
            {
                continue;
            }
            let Some(share) = deal
                .shares
                .iter()
                .find(|share| share.share.receiver == receiver)
            else {
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: config.parties.len(),
                    got: deal.shares.len(),
                });
            };
            if share.share.point != point {
                return Err(DkgError::InvalidSharePoint {
                    party: receiver,
                    expected: point,
                    got: share.share.point,
                });
            }
            value = (value + i64::from(reduce_mod_q::<P>(share.share.value))).rem_euclid(q);
        }
        shares.push(InProcessCombinedScalarShare {
            receiver,
            point,
            value: value as Coeff,
        });
    }

    Ok(InProcessScalarDkgOutput {
        accepted_dealers: resolution.accepted_dealers,
        rejected_dealers: resolution.rejected_dealers,
        shares,
    })
}
