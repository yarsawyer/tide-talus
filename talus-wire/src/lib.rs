#![forbid(unsafe_code)]
#![doc = "Canonical TALUS wire encodings and transport traits."]
//!
//! This crate defines canonical TALUS wire encodings, context binding, and
//! app-facing transport traits. It intentionally does not implement sockets,
//! TCP, QUIC, libp2p, retry policy, or deployment key management.
//!
//! Normal builds expose production wire domains such as strict signing MPC,
//! DKG, preprocessing commit/open, and final signature messages. Paper-fast
//! partial-signature payloads are test/dev only under `cfg(test)` or the
//! explicit non-production `paper-fast-dev` feature, and
//! `production-release-checks` refuses to build with that feature enabled.

#[cfg(all(feature = "production-release-checks", feature = "paper-fast-dev"))]
compile_error!(
    "production-release-checks must not be built with paper-fast-dev insecure primitives"
);

use core::fmt;

use sha3::{Digest, Sha3_256};

/// Current TALUS wire protocol version.
pub const WIRE_PROTOCOL_VERSION: u16 = 1;

const MAGIC: &[u8; 8] = b"TALUSW1\0";
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 2 + 32 + 32 + 2 + 32 + 4;
const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// ML-DSA suite id used on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuiteId {
    /// ML-DSA-44.
    MlDsa44 = 1,
    /// ML-DSA-65.
    MlDsa65 = 2,
    /// ML-DSA-87.
    MlDsa87 = 3,
}

impl SuiteId {
    fn from_u8(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::MlDsa44),
            2 => Ok(Self::MlDsa65),
            3 => Ok(Self::MlDsa87),
            _ => Err(WireError::UnknownSuite(value)),
        }
    }
}

/// Protocol round id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundId {
    /// Preprocessing commit round.
    PreprocessCommit = 1,
    /// Preprocessing open round.
    PreprocessOpen = 2,
    /// Online signing request round.
    SignRequest = 3,
    /// Online partial signature round.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    SignPartial = 4,
    /// Final signature announcement round.
    SignFinal = 5,
    /// DKG commitment broadcast round.
    DkgCommit = 6,
    /// DKG directed share round.
    DkgShare = 7,
    /// DKG complaint round.
    DkgComplaint = 8,
    /// DKG finalization round.
    DkgFinalize = 9,
    /// DKG bounded small-residue input round.
    DkgSmallResidue = 10,
    /// DKG prime-field MPC subprotocol round.
    DkgPrimeFieldMpc = 11,
    /// DKG IT-VSS public artifact persistence round.
    DkgItVssArtifact = 12,
    /// Strict signing private MPC runtime round.
    StrictSignMpc = 13,
}

impl RoundId {
    fn from_u8(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::PreprocessCommit),
            2 => Ok(Self::PreprocessOpen),
            3 => Ok(Self::SignRequest),
            #[cfg(any(test, feature = "paper-fast-dev"))]
            4 => Ok(Self::SignPartial),
            5 => Ok(Self::SignFinal),
            6 => Ok(Self::DkgCommit),
            7 => Ok(Self::DkgShare),
            8 => Ok(Self::DkgComplaint),
            9 => Ok(Self::DkgFinalize),
            10 => Ok(Self::DkgSmallResidue),
            11 => Ok(Self::DkgPrimeFieldMpc),
            12 => Ok(Self::DkgItVssArtifact),
            13 => Ok(Self::StrictSignMpc),
            _ => Err(WireError::UnknownRound(value)),
        }
    }
}

/// Payload domain and type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadKind {
    /// Hash commitment for a later preprocessing opening.
    PreprocessCommit = 1,
    /// Opened masked preprocessing broadcast.
    MaskedBroadcastOpen = 2,
    /// Online signing request.
    SignRequest = 3,
    /// Online partial signature.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    PartialSignature = 4,
    /// Final signature.
    FinalSignature = 5,
    /// DKG commitment payload.
    DkgCommit = 6,
    /// DKG directed share payload.
    DkgShare = 7,
    /// DKG complaint payload.
    DkgComplaint = 8,
    /// DKG finalization payload.
    DkgFinalize = 9,
    /// DKG bounded small-residue contribution payload.
    DkgSmallResidue = 10,
    /// DKG prime-field MPC subprotocol payload.
    DkgPrimeFieldMpc = 11,
    /// DKG IT-VSS public artifact payload.
    DkgItVssArtifact = 12,
    /// Strict signing private MPC runtime payload.
    StrictSignMpc = 13,
}

impl PayloadKind {
    fn from_u16(value: u16) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::PreprocessCommit),
            2 => Ok(Self::MaskedBroadcastOpen),
            3 => Ok(Self::SignRequest),
            #[cfg(any(test, feature = "paper-fast-dev"))]
            4 => Ok(Self::PartialSignature),
            5 => Ok(Self::FinalSignature),
            6 => Ok(Self::DkgCommit),
            7 => Ok(Self::DkgShare),
            8 => Ok(Self::DkgComplaint),
            9 => Ok(Self::DkgFinalize),
            10 => Ok(Self::DkgSmallResidue),
            11 => Ok(Self::DkgPrimeFieldMpc),
            12 => Ok(Self::DkgItVssArtifact),
            13 => Ok(Self::StrictSignMpc),
            _ => Err(WireError::UnknownPayloadKind(value)),
        }
    }
}

/// Wire envelope header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireHeader {
    /// Protocol version.
    pub protocol_version: u16,
    /// Parameter set.
    pub suite: SuiteId,
    /// Round id.
    pub round: RoundId,
    /// Sender party id.
    pub sender_party_id: u16,
    /// Key generation transcript hash.
    pub keygen_transcript_hash: [u8; 32],
    /// Preprocessing/signing session id.
    pub session_id: [u8; 32],
    /// Hash of the canonical signing set.
    pub signing_set_hash: [u8; 32],
    /// Payload kind/domain.
    pub payload_kind: PayloadKind,
}

/// Canonical wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireMessage {
    /// Header fields.
    pub header: WireHeader,
    /// Canonical payload bytes.
    pub payload: Vec<u8>,
}

/// Preprocessing commit payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPayload {
    /// Commitment bytes.
    pub commitment: [u8; 32],
}

/// Opened masked broadcast payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedBroadcastOpenPayload {
    /// Masked unsigned high bits.
    pub masked_highs: Vec<u32>,
    /// Masked unsigned low bits.
    pub masked_lows: Vec<u32>,
    /// Public nonce commitment.
    pub nonce_commitment: [u8; 32],
    /// Rho-bit input commitment.
    pub rho_bits_commitment: [u8; 32],
    /// Claimed transcript hash.
    pub transcript_hash: [u8; 32],
    /// Private masked-broadcast consistency certification artifact.
    pub consistency_proof: Vec<u8>,
    /// Commit/open salt.
    pub salt: [u8; 32],
}

/// Sign request payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignRequestPayload {
    /// Message bytes.
    pub message: Vec<u8>,
    /// FIPS context bytes.
    pub context: Vec<u8>,
    /// Optional externally supplied `mu`.
    pub external_mu: Option<[u8; 64]>,
    /// Certified token transcript hash.
    pub token_transcript_hash: [u8; 32],
}

/// Test/dev-only wire payloads for paper-fast compatibility paths.
///
/// This module is intentionally absent from normal production builds. The
/// partial-signature payload carries clear `z_i` material and must not be part
/// of production transport.
#[cfg(any(test, feature = "paper-fast-dev"))]
pub mod dev_backends {
    use super::{put_bytes, Cursor, WireError};

    /// Partial signature payload.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PartialSignaturePayload {
        /// Challenge seed.
        pub ctilde: Vec<u8>,
        /// Encoded partial response.
        pub z_share: Vec<u8>,
    }

    /// Encodes a partial signature payload.
    pub fn encode_partial_signature_payload(payload: &PartialSignaturePayload) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, &payload.ctilde);
        put_bytes(&mut out, &payload.z_share);
        out
    }

    /// Decodes a partial signature payload.
    pub fn decode_partial_signature_payload(
        bytes: &[u8],
    ) -> Result<PartialSignaturePayload, WireError> {
        let mut cursor = Cursor::new(bytes);
        let ctilde = cursor.take_bytes()?;
        let z_share = cursor.take_bytes()?;
        cursor.finish()?;
        Ok(PartialSignaturePayload { ctilde, z_share })
    }
}

/// Final signature payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalSignaturePayload {
    /// Serialized FIPS ML-DSA signature.
    pub signature: Vec<u8>,
}

/// Strict signing MPC runtime slot.
///
/// These slots are safe production transport domains. They carry only
/// backend-specific private MPC messages and transcript bindings; selected
/// public signature material is still emitted only through `FinalSignature`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictSignMpcSlot {
    /// Build private candidate-share handles from consumed certified tokens.
    PrepareCandidateShares = 1,
    /// Private response-bound predicate evaluation.
    BoundChecks = 2,
    /// Private hint/high-bits predicate evaluation.
    HintChecks = 3,
    /// Private one-hot candidate selection.
    PrivateSelection = 4,
    /// Open selected public signature material only.
    SelectedOpening = 5,
}

impl StrictSignMpcSlot {
    /// Returns the canonical wire code.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a canonical wire code.
    pub fn from_u8(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::PrepareCandidateShares),
            2 => Ok(Self::BoundChecks),
            3 => Ok(Self::HintChecks),
            4 => Ok(Self::PrivateSelection),
            5 => Ok(Self::SelectedOpening),
            flag => Err(WireError::NonCanonicalFlag(flag)),
        }
    }
}

/// Strict signing private MPC runtime payload.
///
/// The payload intentionally stays opaque at the wire layer. Production
/// adapters use it to carry authenticated private-MPC messages for the strict
/// signing runtime while preserving the invariant that unselected candidates,
/// private predicate bits, and failure details are not first-class wire fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSignMpcPayload {
    /// Strict signing runtime slot.
    pub slot: StrictSignMpcSlot,
    /// Slot-local phase number.
    pub phase: u8,
    /// Optional directed receiver; zero means broadcast/opening.
    pub receiver_party_id: u16,
    /// Transcript label hash for this runtime message.
    pub label_hash: [u8; 32],
    /// Runtime transcript hash before this payload.
    pub transcript_hash: [u8; 32],
    /// Backend-owned authenticated MPC message bytes.
    pub opaque_payload: Vec<u8>,
}

/// DKG commitment payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgCommitPayload {
    /// IT-VSS commitment/check bytes.
    pub vss_commitments: Vec<Vec<u8>>,
    /// Serialized `A * s1_i` commitment vector.
    ///
    /// Scaffold/test-only. Production wire builds must not contain exact public
    /// `A*secret` images.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    pub as1_commitment: Vec<u8>,
    /// Pairwise seed commitment.
    pub pairwise_seed_commitment: [u8; 32],
}

impl DkgCommitPayload {
    /// Creates a production DKG commit payload without paper-compatible
    /// public `A*secret` material.
    pub fn new(vss_commitments: Vec<Vec<u8>>, pairwise_seed_commitment: [u8; 32]) -> Self {
        Self {
            vss_commitments,
            #[cfg(any(test, feature = "paper-fast-dev"))]
            as1_commitment: Vec::new(),
            pairwise_seed_commitment,
        }
    }

    /// Creates a paper-compatible scaffold DKG commit payload containing a
    /// public exact `A*s1_i` image.
    #[cfg(any(test, feature = "paper-fast-dev"))]
    pub fn new_paper_fast_dev(
        vss_commitments: Vec<Vec<u8>>,
        as1_commitment: Vec<u8>,
        pairwise_seed_commitment: [u8; 32],
    ) -> Self {
        Self {
            vss_commitments,
            as1_commitment,
            pairwise_seed_commitment,
        }
    }
}

/// DKG directed share payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgSharePayload {
    /// Intended receiver party id.
    pub receiver_party_id: u16,
    /// Authenticated encrypted VSS share bytes.
    pub encrypted_share: Vec<u8>,
    /// Authenticated encrypted pairwise seed-share bytes.
    pub encrypted_seed_share: Vec<u8>,
    /// Backend proof or channel transcript binding bytes.
    pub proof: Vec<u8>,
}

/// DKG complaint payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgComplaintPayload {
    /// Dealer whose directed share is challenged.
    pub dealer_party_id: u16,
    /// Receiver for the challenged share.
    pub receiver_party_id: u16,
    /// Stable reason code interpreted by the DKG backend.
    pub reason_code: u16,
    /// Backend-specific evidence bytes.
    pub evidence: Vec<u8>,
}

/// DKG finalization payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgFinalizePayload {
    /// Serialized FIPS ML-DSA public key.
    pub public_key: Vec<u8>,
    /// Public matrix seed `rho`.
    pub rho: [u8; 32],
    /// Encoded public `t1` component.
    pub t1: Vec<u8>,
    /// Accepted dealer parties in canonical order.
    pub accepted_parties: Vec<u16>,
    /// Accepted public-output transcript hash.
    pub keygen_transcript_hash: [u8; 32],
}

/// DKG bounded small-residue contribution payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgSmallResiduePayload {
    /// `1 = s1`, `2 = s2`.
    pub vector_kind: u8,
    /// Coefficient index in polynomial-major order.
    pub coefficient_index: u32,
    /// ML-DSA eta value.
    pub eta: u8,
    /// Residue in `Z_(2*eta+1)`.
    pub residue: u8,
    /// Little-endian bit decomposition.
    pub bits: Vec<u8>,
}

/// Prime-field MPC round message payload for DKG subprotocols.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgPrimeFieldMpcPayload {
    /// Backend-specific round kind.
    pub round_kind: u8,
    /// Typed subprotocol phase inside the round kind.
    pub phase: u8,
    /// Optional directed receiver; zero means broadcast/opening.
    pub receiver_party_id: u16,
    /// Transcript label hash for the gate/subprotocol.
    pub label_hash: [u8; 32],
    /// Field value encoded as a signed little-endian integer reduced by the caller.
    pub value: i32,
    /// Optional vector field values for batched MPC rounds.
    ///
    /// Empty means this is a scalar payload and `value` is the only lane.
    pub values: Vec<i32>,
}

/// DKG IT-VSS public commitment wire payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssPublicCommitmentPayload {
    /// IT-VSS backend id.
    pub backend_id: u8,
    /// Dealer party id.
    pub dealer_party_id: u16,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Public metadata hash.
    pub public_metadata_hash: [u8; 32],
}

/// DKG IT-VSS public precommitment wire payload. This is broadcast before
/// public coins are collected; final commitments are derived only after the
/// coin transcript exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssPublicPrecommitmentPayload {
    /// IT-VSS backend id.
    pub backend_id: u8,
    /// Dealer party id.
    pub dealer_party_id: u16,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Public precommitment hash.
    pub public_precommitment_hash: [u8; 32],
}

/// DKG IT-VSS public-coin share wire payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssPublicCoinSharePayload {
    /// Broadcast party id.
    pub party_id: u16,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Public coin contribution.
    pub coin: [u8; 32],
    /// Transcript hash generated by the IT-VSS backend.
    pub transcript_hash: [u8; 32],
}

/// DKG IT-VSS public audit/discard record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssAuditRecordPayload {
    /// Dealer whose sharing is audited.
    pub dealer_party_id: u16,
    /// Holder/intermediary whose vector share is authenticated.
    pub holder_party_id: u16,
    /// Receiver/verifier that opened the audited receiver-side tag.
    pub receiver_party_id: u16,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Audited tag index.
    pub tag_index: u16,
    /// Opened audited receiver-side tag bytes. These bytes are public only
    /// because the audited tag is discarded and never retained for opening.
    pub audited_receiver_tag: Vec<u8>,
    /// Hash of the opened audited receiver-side tag.
    pub audited_receiver_tag_hash: [u8; 32],
}

/// DKG IT-VSS public vector-polynomial consistency record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssConsistencyRecordPayload {
    /// Dealer whose sharing is checked.
    pub dealer_party_id: u16,
    /// Holder whose polynomial point is checked.
    pub holder_party_id: u16,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Consistency round.
    pub round: u16,
    /// Public challenge bit.
    pub challenge_bit: u8,
    /// Opened public masked evaluation vector bytes for this holder/round.
    pub masked_eval: Vec<u8>,
    /// Hash of the public masked evaluation vector.
    pub masked_eval_hash: [u8; 32],
}

/// DKG verified IT-VSS sharing certificate wire payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssCertificatePayload {
    /// IT-VSS backend id.
    pub backend_id: u8,
    /// Dealer party id.
    pub dealer_party_id: u16,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Accepted receiver party ids.
    pub accepted_receivers: Vec<u16>,
    /// Hash of public complaints.
    pub complaint_hash: [u8; 32],
    /// Certificate transcript hash.
    pub transcript_hash: [u8; 32],
}

/// DKG IT-VSS complaint record inside a persisted resolution artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssComplaintPayload {
    /// Complainant party id.
    pub complainant_party_id: u16,
    /// Dealer whose directed share is challenged.
    pub dealer_party_id: u16,
    /// Receiver for the challenged share.
    pub receiver_party_id: u16,
    /// Stable reason code interpreted by the DKG backend.
    pub reason_code: u16,
    /// Backend-specific public evidence bytes.
    pub evidence: Vec<u8>,
}

/// DKG IT-VSS public complaint-resolution wire payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgItVssResolutionPayload {
    /// Accepted dealer party ids.
    pub accepted_dealers: Vec<u16>,
    /// Rejected dealer party ids.
    pub rejected_dealers: Vec<u16>,
    /// Canonical complaint payloads.
    pub complaints: Vec<DkgItVssComplaintPayload>,
    /// Verified sharing certificates.
    pub certificates: Vec<DkgItVssCertificatePayload>,
}

/// DKG IT-VSS artifact envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DkgItVssArtifactPayload {
    /// One public commitment artifact.
    PublicCommitment(DkgItVssPublicCommitmentPayload),
    /// One public precommitment artifact.
    PublicPrecommitment(DkgItVssPublicPrecommitmentPayload),
    /// A batch of public commitment artifacts from one sender.
    PublicCommitmentBatch(Vec<DkgItVssPublicCommitmentPayload>),
    /// One public-coin share artifact for consistency challenges.
    PublicCoinShare(DkgItVssPublicCoinSharePayload),
    /// Public audit/discard records for vector information-checking tags.
    PublicAuditRecords(Vec<DkgItVssAuditRecordPayload>),
    /// Public vector-polynomial consistency records.
    PublicConsistencyRecords(Vec<DkgItVssConsistencyRecordPayload>),
    /// One complaint-resolution artifact.
    ComplaintResolution(DkgItVssResolutionPayload),
}

/// Expected message context used for replay checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedContext {
    /// Expected suite.
    pub suite: SuiteId,
    /// Expected keygen transcript hash.
    pub keygen_transcript_hash: [u8; 32],
    /// Expected session id.
    pub session_id: [u8; 32],
    /// Expected signing set hash.
    pub signing_set_hash: [u8; 32],
    /// Allowed party ids.
    pub allowed_parties: Vec<u16>,
}

/// Canonical PQ transport session binding supplied by an application adapter.
///
/// TALUS does not own sockets or key management, but protocol messages must be
/// bound to the concrete ML-KEM channel establishment transcript and ML-DSA
/// operational party-identity authentication transcript used by the embedding
/// application. This structure is the wire crate's stable boundary for that
/// binding: adapters provide transcript hashes, and TALUS derives the session
/// id and `ExpectedContext` used by every message validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqTransportSessionBinding {
    /// ML-DSA suite for this protocol session.
    pub suite: SuiteId,
    /// Key-generation transcript hash.
    pub keygen_transcript_hash: [u8; 32],
    /// Canonical sorted party ids.
    pub party_ids: Vec<u16>,
    /// Transcript hash covering ML-KEM channel/session establishment.
    pub ml_kem_transcript_hash: [u8; 32],
    /// Transcript hash covering ML-DSA operational identity authentication.
    pub ml_dsa_identity_transcript_hash: [u8; 32],
    /// Derived session id to place in every `WireMessage` header.
    pub session_id: [u8; 32],
}

impl PqTransportSessionBinding {
    /// Creates a canonical PQ transport session binding.
    pub fn new(
        suite: SuiteId,
        keygen_transcript_hash: [u8; 32],
        party_ids: &[u16],
        ml_kem_transcript_hash: [u8; 32],
        ml_dsa_identity_transcript_hash: [u8; 32],
    ) -> Result<Self, WireError> {
        let party_ids = canonical_party_ids(party_ids)?;
        let session_id = derive_pq_transport_session_id(
            suite,
            keygen_transcript_hash,
            &party_ids,
            ml_kem_transcript_hash,
            ml_dsa_identity_transcript_hash,
        )?;
        Ok(Self {
            suite,
            keygen_transcript_hash,
            party_ids,
            ml_kem_transcript_hash,
            ml_dsa_identity_transcript_hash,
            session_id,
        })
    }

    /// Builds the expected wire context for this bound session.
    pub fn expected_context(&self) -> ExpectedContext {
        ExpectedContext {
            suite: self.suite,
            keygen_transcript_hash: self.keygen_transcript_hash,
            session_id: self.session_id,
            signing_set_hash: signing_set_hash(&self.party_ids),
            allowed_parties: self.party_ids.clone(),
        }
    }
}

/// Evidence that the embedding application established PQ private channels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemChannelSessionEvidence {
    /// Transcript hash covering ML-KEM channel/session establishment.
    pub transcript_hash: [u8; 32],
}

impl MlKemChannelSessionEvidence {
    /// Creates ML-KEM channel/session evidence.
    pub fn new(transcript_hash: [u8; 32]) -> Result<Self, WireError> {
        require_nonzero_evidence_hash("ml-kem channel/session", transcript_hash)?;
        Ok(Self { transcript_hash })
    }
}

/// Evidence that operational party identities were authenticated with ML-DSA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlDsaOperationalIdentityEvidence {
    /// Transcript hash covering ML-DSA identity authentication.
    pub transcript_hash: [u8; 32],
}

impl MlDsaOperationalIdentityEvidence {
    /// Creates ML-DSA identity evidence.
    pub fn new(transcript_hash: [u8; 32]) -> Result<Self, WireError> {
        require_nonzero_evidence_hash("ml-dsa operational identity", transcript_hash)?;
        Ok(Self { transcript_hash })
    }
}

/// Evidence that the application broadcast adapter satisfies the TALUS
/// synchronous reliable-broadcast contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliableBroadcastEvidence {
    /// Transcript or audit hash for reliable-broadcast conformance evidence.
    pub evidence_hash: [u8; 32],
}

impl ReliableBroadcastEvidence {
    /// Creates reliable-broadcast conformance evidence.
    pub fn new(evidence_hash: [u8; 32]) -> Result<Self, WireError> {
        require_nonzero_evidence_hash("reliable broadcast", evidence_hash)?;
        Ok(Self { evidence_hash })
    }
}

/// Application-supplied production transport evidence for native DKG.
///
/// This is a skeleton boundary, not a socket implementation. Applications
/// perform ML-KEM channel/session setup, ML-DSA identity authentication, and
/// reliable-broadcast conformance outside the crate, then provide hashes here.
/// TALUS derives the existing `PqTransportSessionBinding` and expected wire
/// context from this evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDkgTransportEvidence {
    /// ML-DSA suite for the native DKG session.
    pub suite: SuiteId,
    /// Key-generation transcript hash.
    pub keygen_transcript_hash: [u8; 32],
    /// Canonical sorted party ids.
    pub party_ids: Vec<u16>,
    /// ML-KEM channel/session establishment evidence.
    pub ml_kem: MlKemChannelSessionEvidence,
    /// ML-DSA operational party identity evidence.
    pub ml_dsa_identity: MlDsaOperationalIdentityEvidence,
    /// Reliable-broadcast conformance evidence.
    pub reliable_broadcast: ReliableBroadcastEvidence,
}

impl NativeDkgTransportEvidence {
    /// Creates native DKG transport evidence from application-supplied hashes.
    pub fn new(
        suite: SuiteId,
        keygen_transcript_hash: [u8; 32],
        party_ids: &[u16],
        ml_kem: MlKemChannelSessionEvidence,
        ml_dsa_identity: MlDsaOperationalIdentityEvidence,
        reliable_broadcast: ReliableBroadcastEvidence,
    ) -> Result<Self, WireError> {
        require_nonzero_evidence_hash("keygen transcript", keygen_transcript_hash)?;
        Ok(Self {
            suite,
            keygen_transcript_hash,
            party_ids: canonical_party_ids(party_ids)?,
            ml_kem,
            ml_dsa_identity,
            reliable_broadcast,
        })
    }

    /// Builds the canonical PQ session binding used by existing wire validators.
    pub fn pq_session_binding(&self) -> Result<PqTransportSessionBinding, WireError> {
        PqTransportSessionBinding::new(
            self.suite,
            self.keygen_transcript_hash,
            &self.party_ids,
            self.ml_kem.transcript_hash,
            self.ml_dsa_identity.transcript_hash,
        )
    }

    /// Builds the expected wire context for this application-supplied evidence.
    pub fn expected_context(&self) -> Result<ExpectedContext, WireError> {
        Ok(self.pq_session_binding()?.expected_context())
    }

    /// Hashes the full transport evidence, including reliable-broadcast proof.
    pub fn evidence_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS native DKG transport evidence v1");
        hasher.update(WIRE_PROTOCOL_VERSION.to_le_bytes());
        hasher.update([self.suite as u8]);
        hasher.update(self.keygen_transcript_hash);
        hasher.update(signing_set_hash(&self.party_ids));
        for party in &self.party_ids {
            hasher.update(party.to_le_bytes());
        }
        hasher.update(self.ml_kem.transcript_hash);
        hasher.update(self.ml_dsa_identity.transcript_hash);
        hasher.update(self.reliable_broadcast.evidence_hash);
        hasher.finalize().into()
    }
}

/// Trait implemented by app transport adapters that can expose native DKG
/// transport evidence to TALUS without giving the crate ownership of sockets.
pub trait NativeDkgApplicationTransportEvidenceProvider {
    /// Returns the application-supplied transport evidence.
    fn native_dkg_transport_evidence(&self) -> &NativeDkgTransportEvidence;

    /// Returns the derived PQ session binding.
    fn pq_session_binding(&self) -> Result<PqTransportSessionBinding, WireError> {
        self.native_dkg_transport_evidence().pq_session_binding()
    }

    /// Returns the expected wire context.
    fn expected_context(&self) -> Result<ExpectedContext, WireError> {
        self.native_dkg_transport_evidence().expected_context()
    }
}

/// Directed authenticated P2P message delivered through the transport layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateWireMessage {
    /// Authenticated sender party id from the channel identity.
    pub sender_party_id: u16,
    /// Authenticated receiver party id from the channel identity.
    pub receiver_party_id: u16,
    /// Canonical wire message carried by the channel.
    pub message: WireMessage,
}

/// Broadcast delivery as observed by one party.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastDelivery {
    /// Party that observed this delivery.
    pub observer_party_id: u16,
    /// Broadcast message seen by the observer.
    pub message: WireMessage,
}

/// Authenticated directed-channel transport contract.
///
/// TALUS crates intentionally do not prescribe TCP, QUIC, libp2p, TLS, Noise,
/// async runtime, retry policy, or socket ownership. Embedding software supplies
/// a transport implementation that already authenticates channel endpoints and
/// carries canonical `WireMessage` values. The in-crate implementations are
/// deterministic test buses and protocol adapters only.
pub trait AuthenticatedP2pTransport {
    /// Sends one private message to `receiver_party_id`.
    fn send_private(
        &mut self,
        receiver_party_id: u16,
        message: WireMessage,
    ) -> Result<(), TransportError>;

    /// Collects private messages addressed to `receiver_party_id` for one round.
    fn collect_private_round(
        &self,
        receiver_party_id: u16,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError>;
}

/// Equivocation-resistant broadcast transport contract.
///
/// Production implementations must provide the broadcast semantics required by
/// the protocol state machines: every honest observer either accepts the same
/// sender message for a round or detects equivocation/abort. The concrete
/// networking stack and PQ identity/session setup live in the embedding
/// application, not in this crate.
pub trait EquivocationResistantBroadcast {
    /// Broadcasts one message to every configured party.
    fn broadcast(&mut self, message: WireMessage) -> Result<(), TransportError>;

    /// Collects one observer's broadcast view for one round.
    fn collect_broadcast_view(
        &self,
        observer_party_id: u16,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError>;

    /// Collects a round only after checking all observer views are identical.
    fn collect_equivocation_checked_round(
        &self,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError>;
}

/// Synchronous reliable-broadcast product contract for embedding apps.
///
/// TALUS assumes a round-based broadcast service with authenticated sender
/// identities. For each `(session_id, round, sender)` an honest observer must
/// either deliver the same canonical `WireMessage` bytes delivered to every
/// other honest observer, or the adapter must return `Equivocation`/abort for
/// that round. Partial views are not valid progress: they are reported as
/// `IncompleteBroadcastView` until the application either delivers the missing
/// messages or aborts the protocol. Messages must be bound to the supplied
/// `ExpectedContext`, and duplicate senders in one round are rejected.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SynchronousBroadcastContract;

impl SynchronousBroadcastContract {
    /// Collects a broadcast round using the required product semantics.
    pub fn collect_round<T: EquivocationResistantBroadcast>(
        transport: &T,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        transport.collect_equivocation_checked_round(expected_round, expected)
    }
}

/// Deterministic in-memory transport for tests and protocol adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryTransport {
    local_party_id: u16,
    parties: Vec<u16>,
    private_messages: Vec<PrivateWireMessage>,
    broadcast_deliveries: Vec<BroadcastDelivery>,
}

impl InMemoryTransport {
    /// Creates an empty in-memory transport for one local sender.
    pub fn new(local_party_id: u16, mut parties: Vec<u16>) -> Result<Self, TransportError> {
        parties.sort_unstable();
        parties.dedup();
        if !parties.contains(&local_party_id) {
            return Err(TransportError::UnknownParty(local_party_id));
        }

        Ok(Self {
            local_party_id,
            parties,
            private_messages: Vec::new(),
            broadcast_deliveries: Vec::new(),
        })
    }

    /// Returns queued private messages.
    pub fn private_messages(&self) -> &[PrivateWireMessage] {
        &self.private_messages
    }

    /// Returns queued broadcast deliveries.
    pub fn broadcast_deliveries(&self) -> &[BroadcastDelivery] {
        &self.broadcast_deliveries
    }

    /// Clears queued test-bus messages.
    ///
    /// This is intended for deterministic in-process protocol schedulers that
    /// have already durably logged accepted messages and are advancing to the
    /// next subround. Production transports should provide their own durable
    /// message cursors instead of using this test helper.
    pub fn clear_queued_messages(&mut self) {
        self.private_messages.clear();
        self.broadcast_deliveries.clear();
    }

    /// Injects a private message with explicit channel identities.
    pub fn inject_private(
        &mut self,
        sender_party_id: u16,
        receiver_party_id: u16,
        message: WireMessage,
    ) -> Result<(), TransportError> {
        self.validate_channel_parties(sender_party_id, Some(receiver_party_id))?;
        validate_header_sender(sender_party_id, &message)?;
        self.private_messages.push(PrivateWireMessage {
            sender_party_id,
            receiver_party_id,
            message,
        });
        Ok(())
    }

    /// Injects a broadcast delivery to one observer.
    pub fn inject_broadcast_delivery(
        &mut self,
        observer_party_id: u16,
        message: WireMessage,
    ) -> Result<(), TransportError> {
        self.validate_channel_parties(message.header.sender_party_id, Some(observer_party_id))?;
        self.broadcast_deliveries.push(BroadcastDelivery {
            observer_party_id,
            message,
        });
        Ok(())
    }

    fn validate_channel_parties(
        &self,
        sender_party_id: u16,
        receiver_party_id: Option<u16>,
    ) -> Result<(), TransportError> {
        if !self.parties.contains(&sender_party_id) {
            return Err(TransportError::UnknownParty(sender_party_id));
        }
        if let Some(receiver) = receiver_party_id {
            if !self.parties.contains(&receiver) {
                return Err(TransportError::UnknownParty(receiver));
            }
        }
        Ok(())
    }
}

impl AuthenticatedP2pTransport for InMemoryTransport {
    fn send_private(
        &mut self,
        receiver_party_id: u16,
        message: WireMessage,
    ) -> Result<(), TransportError> {
        self.inject_private(self.local_party_id, receiver_party_id, message)
    }

    fn collect_private_round(
        &self,
        receiver_party_id: u16,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        if !self.parties.contains(&receiver_party_id) {
            return Err(TransportError::UnknownParty(receiver_party_id));
        }

        let messages: Vec<WireMessage> = self
            .private_messages
            .iter()
            .filter(|delivery| delivery.receiver_party_id == receiver_party_id)
            .map(|delivery| delivery.message.clone())
            .collect();
        validate_round_batch(&messages, expected_round, expected).map_err(TransportError::Wire)?;
        Ok(messages)
    }
}

impl EquivocationResistantBroadcast for InMemoryTransport {
    fn broadcast(&mut self, message: WireMessage) -> Result<(), TransportError> {
        let sender = self.local_party_id;
        self.validate_channel_parties(sender, None)?;
        validate_header_sender(sender, &message)?;
        for observer in &self.parties {
            self.broadcast_deliveries.push(BroadcastDelivery {
                observer_party_id: *observer,
                message: message.clone(),
            });
        }
        Ok(())
    }

    fn collect_broadcast_view(
        &self,
        observer_party_id: u16,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        if !self.parties.contains(&observer_party_id) {
            return Err(TransportError::UnknownParty(observer_party_id));
        }
        let messages: Vec<WireMessage> = self
            .broadcast_deliveries
            .iter()
            .filter(|delivery| delivery.observer_party_id == observer_party_id)
            .map(|delivery| delivery.message.clone())
            .collect();
        validate_round_batch(&messages, expected_round, expected).map_err(TransportError::Wire)?;
        Ok(messages)
    }

    fn collect_equivocation_checked_round(
        &self,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        let mut canonical: Vec<WireMessage> = Vec::new();
        for observer in &self.parties {
            let view = self.collect_broadcast_view(*observer, expected_round, expected)?;
            if view.len() != expected.allowed_parties.len() {
                return Err(TransportError::IncompleteBroadcastView {
                    observer_party_id: *observer,
                    expected: expected.allowed_parties.len(),
                    got: view.len(),
                });
            }
            for message in view {
                let sender = message.header.sender_party_id;
                match canonical
                    .iter()
                    .position(|known| known.header.sender_party_id == sender)
                {
                    Some(idx) => {
                        if encode_message(&canonical[idx]).map_err(TransportError::Wire)?
                            != encode_message(&message).map_err(TransportError::Wire)?
                        {
                            return Err(TransportError::Equivocation { sender });
                        }
                    }
                    None => canonical.push(message),
                }
            }
        }

        canonical.sort_by_key(|message| message.header.sender_party_id);
        validate_round_batch(&canonical, expected_round, expected).map_err(TransportError::Wire)?;
        Ok(canonical)
    }
}

/// Wire encoding or validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    /// Encoded bytes were shorter than the fixed header.
    TooShort {
        /// Actual byte length.
        got: usize,
    },
    /// Magic prefix mismatch.
    BadMagic,
    /// Unsupported protocol version.
    BadProtocolVersion {
        /// Expected version.
        expected: u16,
        /// Actual version.
        got: u16,
    },
    /// Unknown suite id.
    UnknownSuite(u8),
    /// Unknown round id.
    UnknownRound(u8),
    /// Unknown payload kind.
    UnknownPayloadKind(u16),
    /// Payload length field did not match the encoded byte count.
    PayloadLengthMismatch {
        /// Expected total encoded length.
        expected_total: usize,
        /// Actual total encoded length.
        got_total: usize,
    },
    /// Payload exceeded the implementation cap.
    PayloadTooLarge(usize),
    /// Payload codec reached end of input.
    TruncatedPayload,
    /// Payload codec found trailing bytes.
    TrailingPayloadBytes(usize),
    /// Payload vector lengths were inconsistent.
    VectorLengthMismatch {
        /// Left length.
        lhs: usize,
        /// Right length.
        rhs: usize,
    },
    /// Nested payload had the wrong artifact kind.
    InvalidNestedPayload,
    /// Boolean/option flag was not canonical.
    NonCanonicalFlag(u8),
    /// Message did not match expected context.
    ContextMismatch,
    /// Message round mismatch.
    RoundMismatch {
        /// Expected round.
        expected: RoundId,
        /// Actual round.
        got: RoundId,
    },
    /// Duplicate sender in one round.
    DuplicateSender(u16),
    /// Sender is not in the allowed party set.
    UnknownSender(u16),
    /// Party sets must not be empty.
    EmptyPartySet,
    /// Party id zero is reserved for "no directed receiver" in some payloads.
    InvalidPartyId(u16),
    /// Duplicate party id in a party set.
    DuplicateParty(u16),
    /// Required application-supplied transport evidence was missing.
    MissingTransportEvidence(&'static str),
}

/// Transport-level failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// Canonical wire validation failed.
    Wire(WireError),
    /// Party id is not configured for this transport.
    UnknownParty(u16),
    /// Authenticated channel identity did not match the wire header sender.
    SenderMismatch {
        /// Sender authenticated by the transport.
        channel_sender: u16,
        /// Sender declared in the canonical wire header.
        header_sender: u16,
    },
    /// One observer did not receive the complete broadcast set.
    IncompleteBroadcastView {
        /// Observer party id.
        observer_party_id: u16,
        /// Expected number of broadcast messages.
        expected: usize,
        /// Actual number of broadcast messages.
        got: usize,
    },
    /// Broadcast views disagree for one sender.
    Equivocation {
        /// Equivocating sender party id.
        sender: u16,
    },
    /// Backend-specific transport failure.
    Backend(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => write!(f, "wire message too short: {got} bytes"),
            Self::BadMagic => write!(f, "bad wire magic"),
            Self::BadProtocolVersion { expected, got } => {
                write!(f, "bad wire version: expected {expected}, got {got}")
            }
            Self::UnknownSuite(suite) => write!(f, "unknown suite id {suite}"),
            Self::UnknownRound(round) => write!(f, "unknown round id {round}"),
            Self::UnknownPayloadKind(kind) => write!(f, "unknown payload kind {kind}"),
            Self::PayloadLengthMismatch {
                expected_total,
                got_total,
            } => write!(
                f,
                "payload length mismatch: expected total {expected_total}, got {got_total}"
            ),
            Self::PayloadTooLarge(len) => write!(f, "payload too large: {len} bytes"),
            Self::TruncatedPayload => write!(f, "truncated payload"),
            Self::TrailingPayloadBytes(len) => write!(f, "trailing payload bytes: {len}"),
            Self::VectorLengthMismatch { lhs, rhs } => {
                write!(f, "vector length mismatch: lhs {lhs}, rhs {rhs}")
            }
            Self::InvalidNestedPayload => write!(f, "invalid nested payload"),
            Self::NonCanonicalFlag(flag) => write!(f, "non-canonical flag {flag}"),
            Self::ContextMismatch => write!(f, "wire context mismatch"),
            Self::RoundMismatch { expected, got } => {
                write!(f, "wire round mismatch: expected {expected:?}, got {got:?}")
            }
            Self::DuplicateSender(sender) => write!(f, "duplicate sender {sender}"),
            Self::UnknownSender(sender) => write!(f, "unknown sender {sender}"),
            Self::EmptyPartySet => write!(f, "empty party set"),
            Self::InvalidPartyId(party) => write!(f, "invalid party id {party}"),
            Self::DuplicateParty(party) => write!(f, "duplicate party id {party}"),
            Self::MissingTransportEvidence(name) => {
                write!(f, "missing transport evidence: {name}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WireError {}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(err) => write!(f, "wire validation failed: {err}"),
            Self::UnknownParty(party) => write!(f, "unknown transport party {party}"),
            Self::SenderMismatch {
                channel_sender,
                header_sender,
            } => write!(
                f,
                "transport sender mismatch: channel {channel_sender}, header {header_sender}"
            ),
            Self::IncompleteBroadcastView {
                observer_party_id,
                expected,
                got,
            } => write!(
                f,
                "incomplete broadcast view for observer {observer_party_id}: expected {expected}, got {got}"
            ),
            Self::Equivocation { sender } => write!(f, "broadcast equivocation by sender {sender}"),
            Self::Backend(message) => write!(f, "transport backend error: {message}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransportError {}

fn validate_header_sender(
    channel_sender: u16,
    message: &WireMessage,
) -> Result<(), TransportError> {
    if message.header.sender_party_id == channel_sender {
        Ok(())
    } else {
        Err(TransportError::SenderMismatch {
            channel_sender,
            header_sender: message.header.sender_party_id,
        })
    }
}

/// Encodes a message with canonical little-endian integer fields.
pub fn encode_message(message: &WireMessage) -> Result<Vec<u8>, WireError> {
    if message.payload.len() > MAX_PAYLOAD_LEN {
        return Err(WireError::PayloadTooLarge(message.payload.len()));
    }

    let mut out = Vec::with_capacity(HEADER_LEN + message.payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&message.header.protocol_version.to_le_bytes());
    out.push(message.header.suite as u8);
    out.push(message.header.round as u8);
    out.extend_from_slice(&message.header.sender_party_id.to_le_bytes());
    out.extend_from_slice(&message.header.keygen_transcript_hash);
    out.extend_from_slice(&message.header.session_id);
    out.extend_from_slice(&(message.header.payload_kind as u16).to_le_bytes());
    out.extend_from_slice(&message.header.signing_set_hash);
    out.extend_from_slice(&(message.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&message.payload);
    Ok(out)
}

/// Decodes one canonical wire message.
pub fn decode_message(bytes: &[u8]) -> Result<WireMessage, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::TooShort { got: bytes.len() });
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(WireError::BadMagic);
    }

    let mut cursor = Cursor::new(&bytes[MAGIC.len()..]);
    let protocol_version = cursor.take_u16()?;
    if protocol_version != WIRE_PROTOCOL_VERSION {
        return Err(WireError::BadProtocolVersion {
            expected: WIRE_PROTOCOL_VERSION,
            got: protocol_version,
        });
    }
    let suite = SuiteId::from_u8(cursor.take_u8()?)?;
    let round = RoundId::from_u8(cursor.take_u8()?)?;
    let sender_party_id = cursor.take_u16()?;
    let keygen_transcript_hash = cursor.take_array::<32>()?;
    let session_id = cursor.take_array::<32>()?;
    let payload_kind = PayloadKind::from_u16(cursor.take_u16()?)?;
    let signing_set_hash = cursor.take_array::<32>()?;
    let payload_len = cursor.take_u32()? as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(WireError::PayloadTooLarge(payload_len));
    }

    let expected_total = HEADER_LEN + payload_len;
    if bytes.len() != expected_total {
        return Err(WireError::PayloadLengthMismatch {
            expected_total,
            got_total: bytes.len(),
        });
    }

    Ok(WireMessage {
        header: WireHeader {
            protocol_version,
            suite,
            round,
            sender_party_id,
            keygen_transcript_hash,
            session_id,
            signing_set_hash,
            payload_kind,
        },
        payload: bytes[HEADER_LEN..].to_vec(),
    })
}

/// Validates one decoded message against the expected replay context.
pub fn validate_message_context(
    message: &WireMessage,
    expected: &ExpectedContext,
) -> Result<(), WireError> {
    if message.header.suite != expected.suite
        || message.header.keygen_transcript_hash != expected.keygen_transcript_hash
        || message.header.session_id != expected.session_id
        || message.header.signing_set_hash != expected.signing_set_hash
    {
        return Err(WireError::ContextMismatch);
    }
    if !expected
        .allowed_parties
        .contains(&message.header.sender_party_id)
    {
        return Err(WireError::UnknownSender(message.header.sender_party_id));
    }
    Ok(())
}

/// Validates one batch of same-round messages for context, round, allowed
/// senders, and duplicate senders.
pub fn validate_round_batch(
    messages: &[WireMessage],
    expected_round: RoundId,
    expected: &ExpectedContext,
) -> Result<(), WireError> {
    let mut seen = Vec::with_capacity(messages.len());
    for message in messages {
        validate_message_context(message, expected)?;
        if message.header.round != expected_round {
            return Err(WireError::RoundMismatch {
                expected: expected_round,
                got: message.header.round,
            });
        }
        if seen.contains(&message.header.sender_party_id) {
            return Err(WireError::DuplicateSender(message.header.sender_party_id));
        }
        seen.push(message.header.sender_party_id);
    }
    Ok(())
}

/// Computes a canonical signing-set hash.
pub fn signing_set_hash(parties: &[u16]) -> [u8; 32] {
    let mut sorted = parties.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS signing set v1");
    for party in sorted {
        hasher.update(party.to_le_bytes());
    }
    hasher.finalize().into()
}

fn canonical_party_ids(parties: &[u16]) -> Result<Vec<u16>, WireError> {
    if parties.is_empty() {
        return Err(WireError::EmptyPartySet);
    }
    let mut sorted = parties.to_vec();
    sorted.sort_unstable();
    let mut previous = None;
    for party in &sorted {
        if *party == 0 {
            return Err(WireError::InvalidPartyId(*party));
        }
        if Some(*party) == previous {
            return Err(WireError::DuplicateParty(*party));
        }
        previous = Some(*party);
    }
    Ok(sorted)
}

fn require_nonzero_evidence_hash(name: &'static str, value: [u8; 32]) -> Result<(), WireError> {
    if value == [0u8; 32] {
        Err(WireError::MissingTransportEvidence(name))
    } else {
        Ok(())
    }
}

/// Derives the TALUS session id from application-supplied PQ transport proofs.
pub fn derive_pq_transport_session_id(
    suite: SuiteId,
    keygen_transcript_hash: [u8; 32],
    party_ids: &[u16],
    ml_kem_transcript_hash: [u8; 32],
    ml_dsa_identity_transcript_hash: [u8; 32],
) -> Result<[u8; 32], WireError> {
    let party_ids = canonical_party_ids(party_ids)?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS PQ transport session v1");
    hasher.update(WIRE_PROTOCOL_VERSION.to_le_bytes());
    hasher.update([suite as u8]);
    hasher.update(keygen_transcript_hash);
    hasher.update(signing_set_hash(&party_ids));
    for party in &party_ids {
        hasher.update(party.to_le_bytes());
    }
    hasher.update(ml_kem_transcript_hash);
    hasher.update(ml_dsa_identity_transcript_hash);
    Ok(hasher.finalize().into())
}

/// Computes the next transcript hash from canonical round messages.
pub fn transcript_hash_round(previous: [u8; 32], messages: &[WireMessage]) -> [u8; 32] {
    let mut ordered = messages.to_vec();
    ordered.sort_by_key(|message| message.header.sender_party_id);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-MPC transcript round v1");
    hasher.update(previous);
    for message in ordered {
        if let Ok(encoded) = encode_message(&message) {
            hasher.update(encoded);
        }
    }
    hasher.finalize().into()
}

/// Encodes a commit payload.
pub fn encode_commit_payload(payload: &CommitPayload) -> Vec<u8> {
    payload.commitment.to_vec()
}

/// Decodes a commit payload.
pub fn decode_commit_payload(bytes: &[u8]) -> Result<CommitPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let commitment = cursor.take_array::<32>()?;
    cursor.finish()?;
    Ok(CommitPayload { commitment })
}

/// Encodes an opened masked broadcast payload.
pub fn encode_masked_broadcast_open_payload(
    payload: &MaskedBroadcastOpenPayload,
) -> Result<Vec<u8>, WireError> {
    if payload.masked_highs.len() != payload.masked_lows.len() {
        return Err(WireError::VectorLengthMismatch {
            lhs: payload.masked_highs.len(),
            rhs: payload.masked_lows.len(),
        });
    }
    let mut out = Vec::new();
    put_u32_vec(&mut out, &payload.masked_highs);
    put_u32_vec(&mut out, &payload.masked_lows);
    out.extend_from_slice(&payload.nonce_commitment);
    out.extend_from_slice(&payload.rho_bits_commitment);
    out.extend_from_slice(&payload.transcript_hash);
    put_bytes(&mut out, &payload.consistency_proof);
    out.extend_from_slice(&payload.salt);
    Ok(out)
}

/// Decodes an opened masked broadcast payload.
pub fn decode_masked_broadcast_open_payload(
    bytes: &[u8],
) -> Result<MaskedBroadcastOpenPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let masked_highs = cursor.take_u32_vec()?;
    let masked_lows = cursor.take_u32_vec()?;
    if masked_highs.len() != masked_lows.len() {
        return Err(WireError::VectorLengthMismatch {
            lhs: masked_highs.len(),
            rhs: masked_lows.len(),
        });
    }
    let nonce_commitment = cursor.take_array::<32>()?;
    let rho_bits_commitment = cursor.take_array::<32>()?;
    let transcript_hash = cursor.take_array::<32>()?;
    let consistency_proof = cursor.take_bytes()?;
    let salt = cursor.take_array::<32>()?;
    cursor.finish()?;
    Ok(MaskedBroadcastOpenPayload {
        masked_highs,
        masked_lows,
        nonce_commitment,
        rho_bits_commitment,
        transcript_hash,
        consistency_proof,
        salt,
    })
}

/// Encodes a sign request payload.
pub fn encode_sign_request_payload(payload: &SignRequestPayload) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, &payload.message);
    put_bytes(&mut out, &payload.context);
    match payload.external_mu {
        Some(mu) => {
            out.push(1);
            out.extend_from_slice(&mu);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&payload.token_transcript_hash);
    out
}

/// Decodes a sign request payload.
pub fn decode_sign_request_payload(bytes: &[u8]) -> Result<SignRequestPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let message = cursor.take_bytes()?;
    let context = cursor.take_bytes()?;
    let external_mu = match cursor.take_u8()? {
        0 => None,
        1 => Some(cursor.take_array::<64>()?),
        flag => return Err(WireError::NonCanonicalFlag(flag)),
    };
    let token_transcript_hash = cursor.take_array::<32>()?;
    cursor.finish()?;
    Ok(SignRequestPayload {
        message,
        context,
        external_mu,
        token_transcript_hash,
    })
}

/// Encodes a final signature payload.
pub fn encode_final_signature_payload(payload: &FinalSignaturePayload) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, &payload.signature);
    out
}

/// Decodes a final signature payload.
pub fn decode_final_signature_payload(bytes: &[u8]) -> Result<FinalSignaturePayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let signature = cursor.take_bytes()?;
    cursor.finish()?;
    Ok(FinalSignaturePayload { signature })
}

/// Encodes a strict signing private MPC runtime payload.
pub fn encode_strict_sign_mpc_payload(payload: &StrictSignMpcPayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(payload.slot.as_u8());
    out.push(payload.phase);
    out.extend_from_slice(&payload.receiver_party_id.to_le_bytes());
    out.extend_from_slice(&payload.label_hash);
    out.extend_from_slice(&payload.transcript_hash);
    put_bytes(&mut out, &payload.opaque_payload);
    out
}

/// Decodes a strict signing private MPC runtime payload.
pub fn decode_strict_sign_mpc_payload(bytes: &[u8]) -> Result<StrictSignMpcPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let slot = StrictSignMpcSlot::from_u8(cursor.take_u8()?)?;
    let phase = cursor.take_u8()?;
    let receiver_party_id = cursor.take_u16()?;
    let label_hash = cursor.take_array::<32>()?;
    let transcript_hash = cursor.take_array::<32>()?;
    let opaque_payload = cursor.take_bytes()?;
    cursor.finish()?;
    Ok(StrictSignMpcPayload {
        slot,
        phase,
        receiver_party_id,
        label_hash,
        transcript_hash,
        opaque_payload,
    })
}

/// Encodes a DKG commitment payload.
pub fn encode_dkg_commit_payload(payload: &DkgCommitPayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(payload.vss_commitments.len() as u32).to_le_bytes());
    for commitment in &payload.vss_commitments {
        put_bytes(&mut out, commitment);
    }
    #[cfg(any(test, feature = "paper-fast-dev"))]
    put_bytes(&mut out, &payload.as1_commitment);
    out.extend_from_slice(&payload.pairwise_seed_commitment);
    out
}

/// Decodes a DKG commitment payload.
pub fn decode_dkg_commit_payload(bytes: &[u8]) -> Result<DkgCommitPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let len = cursor.take_u32()? as usize;
    let mut vss_commitments = Vec::with_capacity(len);
    for _ in 0..len {
        vss_commitments.push(cursor.take_bytes()?);
    }
    #[cfg(any(test, feature = "paper-fast-dev"))]
    let as1_commitment = cursor.take_bytes()?;
    let pairwise_seed_commitment = cursor.take_array::<32>()?;
    cursor.finish()?;
    Ok(DkgCommitPayload {
        vss_commitments,
        #[cfg(any(test, feature = "paper-fast-dev"))]
        as1_commitment,
        pairwise_seed_commitment,
    })
}

/// Encodes a DKG directed share payload.
pub fn encode_dkg_share_payload(payload: &DkgSharePayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&payload.receiver_party_id.to_le_bytes());
    put_bytes(&mut out, &payload.encrypted_share);
    put_bytes(&mut out, &payload.encrypted_seed_share);
    put_bytes(&mut out, &payload.proof);
    out
}

/// Decodes a DKG directed share payload.
pub fn decode_dkg_share_payload(bytes: &[u8]) -> Result<DkgSharePayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let receiver_party_id = cursor.take_u16()?;
    let encrypted_share = cursor.take_bytes()?;
    let encrypted_seed_share = cursor.take_bytes()?;
    let proof = cursor.take_bytes()?;
    cursor.finish()?;
    Ok(DkgSharePayload {
        receiver_party_id,
        encrypted_share,
        encrypted_seed_share,
        proof,
    })
}

/// Encodes a DKG complaint payload.
pub fn encode_dkg_complaint_payload(payload: &DkgComplaintPayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&payload.dealer_party_id.to_le_bytes());
    out.extend_from_slice(&payload.receiver_party_id.to_le_bytes());
    out.extend_from_slice(&payload.reason_code.to_le_bytes());
    put_bytes(&mut out, &payload.evidence);
    out
}

/// Decodes a DKG complaint payload.
pub fn decode_dkg_complaint_payload(bytes: &[u8]) -> Result<DkgComplaintPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let dealer_party_id = cursor.take_u16()?;
    let receiver_party_id = cursor.take_u16()?;
    let reason_code = cursor.take_u16()?;
    let evidence = cursor.take_bytes()?;
    cursor.finish()?;
    Ok(DkgComplaintPayload {
        dealer_party_id,
        receiver_party_id,
        reason_code,
        evidence,
    })
}

/// Encodes a DKG finalization payload.
pub fn encode_dkg_finalize_payload(payload: &DkgFinalizePayload) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, &payload.public_key);
    out.extend_from_slice(&payload.rho);
    put_bytes(&mut out, &payload.t1);
    out.extend_from_slice(&(payload.accepted_parties.len() as u32).to_le_bytes());
    for party in &payload.accepted_parties {
        out.extend_from_slice(&party.to_le_bytes());
    }
    out.extend_from_slice(&payload.keygen_transcript_hash);
    out
}

/// Decodes a DKG finalization payload.
pub fn decode_dkg_finalize_payload(bytes: &[u8]) -> Result<DkgFinalizePayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let public_key = cursor.take_bytes()?;
    let rho = cursor.take_array::<32>()?;
    let t1 = cursor.take_bytes()?;
    let accepted_len = cursor.take_u32()? as usize;
    let mut accepted_parties = Vec::with_capacity(accepted_len);
    for _ in 0..accepted_len {
        accepted_parties.push(cursor.take_u16()?);
    }
    let keygen_transcript_hash = cursor.take_array::<32>()?;
    cursor.finish()?;
    Ok(DkgFinalizePayload {
        public_key,
        rho,
        t1,
        accepted_parties,
        keygen_transcript_hash,
    })
}

/// Encodes a DKG bounded small-residue contribution payload.
pub fn encode_dkg_small_residue_payload(payload: &DkgSmallResiduePayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(payload.vector_kind);
    out.extend_from_slice(&payload.coefficient_index.to_le_bytes());
    out.push(payload.eta);
    out.push(payload.residue);
    put_bytes(&mut out, &payload.bits);
    out
}

/// Decodes a DKG bounded small-residue contribution payload.
pub fn decode_dkg_small_residue_payload(bytes: &[u8]) -> Result<DkgSmallResiduePayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let vector_kind = cursor.take_u8()?;
    let coefficient_index = cursor.take_u32()?;
    let eta = cursor.take_u8()?;
    let residue = cursor.take_u8()?;
    let bits = cursor.take_bytes()?;
    cursor.finish()?;
    Ok(DkgSmallResiduePayload {
        vector_kind,
        coefficient_index,
        eta,
        residue,
        bits,
    })
}

/// Encodes a DKG prime-field MPC round payload.
pub fn encode_dkg_prime_field_mpc_payload(payload: &DkgPrimeFieldMpcPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + 4 + payload.values.len() * 4);
    out.push(payload.round_kind);
    out.push(payload.phase);
    out.extend_from_slice(&payload.receiver_party_id.to_le_bytes());
    out.extend_from_slice(&payload.label_hash);
    out.extend_from_slice(&payload.value.to_le_bytes());
    if !payload.values.is_empty() {
        out.extend_from_slice(&(payload.values.len() as u32).to_le_bytes());
        for value in &payload.values {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out
}

/// Decodes a DKG prime-field MPC round payload.
pub fn decode_dkg_prime_field_mpc_payload(
    bytes: &[u8],
) -> Result<DkgPrimeFieldMpcPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let round_kind = cursor.take_u8()?;
    let phase = cursor.take_u8()?;
    let receiver_party_id = cursor.take_u16()?;
    let label_hash = cursor.take_array::<32>()?;
    let value = i32::from_le_bytes(cursor.take_array::<4>()?);
    let values = if cursor.remaining() == 0 {
        Vec::new()
    } else {
        cursor.take_i32_vec()?
    };
    cursor.finish()?;
    Ok(DkgPrimeFieldMpcPayload {
        round_kind,
        phase,
        receiver_party_id,
        label_hash,
        value,
        values,
    })
}

/// Encodes one DKG IT-VSS public artifact payload.
pub fn encode_dkg_it_vss_artifact_payload(payload: &DkgItVssArtifactPayload) -> Vec<u8> {
    let mut out = Vec::new();
    match payload {
        DkgItVssArtifactPayload::PublicCommitment(commitment) => {
            out.push(1);
            out.push(commitment.backend_id);
            out.extend_from_slice(&commitment.dealer_party_id.to_le_bytes());
            out.extend_from_slice(&commitment.label_hash);
            out.extend_from_slice(&commitment.public_metadata_hash);
        }
        DkgItVssArtifactPayload::PublicPrecommitment(precommitment) => {
            out.push(5);
            out.push(precommitment.backend_id);
            out.extend_from_slice(&precommitment.dealer_party_id.to_le_bytes());
            out.extend_from_slice(&precommitment.label_hash);
            out.extend_from_slice(&precommitment.public_precommitment_hash);
        }
        DkgItVssArtifactPayload::PublicCommitmentBatch(commitments) => {
            out.push(3);
            out.extend_from_slice(&(commitments.len() as u32).to_le_bytes());
            for commitment in commitments {
                put_bytes(
                    &mut out,
                    &encode_dkg_it_vss_artifact_payload(
                        &DkgItVssArtifactPayload::PublicCommitment(commitment.clone()),
                    ),
                );
            }
        }
        DkgItVssArtifactPayload::PublicCoinShare(share) => {
            out.push(4);
            out.extend_from_slice(&share.party_id.to_le_bytes());
            out.extend_from_slice(&share.label_hash);
            out.extend_from_slice(&share.coin);
            out.extend_from_slice(&share.transcript_hash);
        }
        DkgItVssArtifactPayload::PublicAuditRecords(records) => {
            out.push(6);
            out.extend_from_slice(&(records.len() as u32).to_le_bytes());
            for record in records {
                out.extend_from_slice(&record.dealer_party_id.to_le_bytes());
                out.extend_from_slice(&record.holder_party_id.to_le_bytes());
                out.extend_from_slice(&record.receiver_party_id.to_le_bytes());
                out.extend_from_slice(&record.label_hash);
                out.extend_from_slice(&record.tag_index.to_le_bytes());
                put_bytes(&mut out, &record.audited_receiver_tag);
                out.extend_from_slice(&record.audited_receiver_tag_hash);
            }
        }
        DkgItVssArtifactPayload::PublicConsistencyRecords(records) => {
            out.push(7);
            out.extend_from_slice(&(records.len() as u32).to_le_bytes());
            for record in records {
                out.extend_from_slice(&record.dealer_party_id.to_le_bytes());
                out.extend_from_slice(&record.holder_party_id.to_le_bytes());
                out.extend_from_slice(&record.label_hash);
                out.extend_from_slice(&record.round.to_le_bytes());
                out.push(record.challenge_bit);
                put_bytes(&mut out, &record.masked_eval);
                out.extend_from_slice(&record.masked_eval_hash);
            }
        }
        DkgItVssArtifactPayload::ComplaintResolution(resolution) => {
            out.push(2);
            put_u16_vec(&mut out, &resolution.accepted_dealers);
            put_u16_vec(&mut out, &resolution.rejected_dealers);
            out.extend_from_slice(&(resolution.complaints.len() as u32).to_le_bytes());
            for complaint in &resolution.complaints {
                put_bytes(&mut out, &encode_dkg_it_vss_complaint_payload(complaint));
            }
            out.extend_from_slice(&(resolution.certificates.len() as u32).to_le_bytes());
            for certificate in &resolution.certificates {
                put_bytes(
                    &mut out,
                    &encode_dkg_it_vss_certificate_payload(certificate),
                );
            }
        }
    }
    out
}

/// Decodes one DKG IT-VSS public artifact payload.
pub fn decode_dkg_it_vss_artifact_payload(
    bytes: &[u8],
) -> Result<DkgItVssArtifactPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let kind = cursor.take_u8()?;
    let payload = match kind {
        1 => DkgItVssArtifactPayload::PublicCommitment(DkgItVssPublicCommitmentPayload {
            backend_id: cursor.take_u8()?,
            dealer_party_id: cursor.take_u16()?,
            label_hash: cursor.take_array::<32>()?,
            public_metadata_hash: cursor.take_array::<32>()?,
        }),
        5 => DkgItVssArtifactPayload::PublicPrecommitment(DkgItVssPublicPrecommitmentPayload {
            backend_id: cursor.take_u8()?,
            dealer_party_id: cursor.take_u16()?,
            label_hash: cursor.take_array::<32>()?,
            public_precommitment_hash: cursor.take_array::<32>()?,
        }),
        3 => {
            let commitment_len = cursor.take_u32()? as usize;
            let mut commitments = Vec::with_capacity(commitment_len);
            for _ in 0..commitment_len {
                match decode_dkg_it_vss_artifact_payload(&cursor.take_bytes()?)? {
                    DkgItVssArtifactPayload::PublicCommitment(commitment) => {
                        commitments.push(commitment);
                    }
                    _ => return Err(WireError::InvalidNestedPayload),
                }
            }
            DkgItVssArtifactPayload::PublicCommitmentBatch(commitments)
        }
        4 => DkgItVssArtifactPayload::PublicCoinShare(DkgItVssPublicCoinSharePayload {
            party_id: cursor.take_u16()?,
            label_hash: cursor.take_array::<32>()?,
            coin: cursor.take_array::<32>()?,
            transcript_hash: cursor.take_array::<32>()?,
        }),
        6 => {
            let len = cursor.take_u32()? as usize;
            let mut records = Vec::with_capacity(len);
            for _ in 0..len {
                records.push(DkgItVssAuditRecordPayload {
                    dealer_party_id: cursor.take_u16()?,
                    holder_party_id: cursor.take_u16()?,
                    receiver_party_id: cursor.take_u16()?,
                    label_hash: cursor.take_array::<32>()?,
                    tag_index: cursor.take_u16()?,
                    audited_receiver_tag: cursor.take_bytes()?,
                    audited_receiver_tag_hash: cursor.take_array::<32>()?,
                });
            }
            DkgItVssArtifactPayload::PublicAuditRecords(records)
        }
        7 => {
            let len = cursor.take_u32()? as usize;
            let mut records = Vec::with_capacity(len);
            for _ in 0..len {
                records.push(DkgItVssConsistencyRecordPayload {
                    dealer_party_id: cursor.take_u16()?,
                    holder_party_id: cursor.take_u16()?,
                    label_hash: cursor.take_array::<32>()?,
                    round: cursor.take_u16()?,
                    challenge_bit: cursor.take_u8()?,
                    masked_eval: cursor.take_bytes()?,
                    masked_eval_hash: cursor.take_array::<32>()?,
                });
            }
            DkgItVssArtifactPayload::PublicConsistencyRecords(records)
        }
        2 => {
            let accepted_dealers = cursor.take_u16_vec()?;
            let rejected_dealers = cursor.take_u16_vec()?;
            let complaint_len = cursor.take_u32()? as usize;
            let mut complaints = Vec::with_capacity(complaint_len);
            for _ in 0..complaint_len {
                complaints.push(decode_dkg_it_vss_complaint_payload(&cursor.take_bytes()?)?);
            }
            let certificate_len = cursor.take_u32()? as usize;
            let mut certificates = Vec::with_capacity(certificate_len);
            for _ in 0..certificate_len {
                certificates.push(decode_dkg_it_vss_certificate_payload(
                    &cursor.take_bytes()?,
                )?);
            }
            DkgItVssArtifactPayload::ComplaintResolution(DkgItVssResolutionPayload {
                accepted_dealers,
                rejected_dealers,
                complaints,
                certificates,
            })
        }
        flag => return Err(WireError::NonCanonicalFlag(flag)),
    };
    cursor.finish()?;
    Ok(payload)
}

fn encode_dkg_it_vss_certificate_payload(payload: &DkgItVssCertificatePayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(payload.backend_id);
    out.extend_from_slice(&payload.dealer_party_id.to_le_bytes());
    out.extend_from_slice(&payload.label_hash);
    put_u16_vec(&mut out, &payload.accepted_receivers);
    out.extend_from_slice(&payload.complaint_hash);
    out.extend_from_slice(&payload.transcript_hash);
    out
}

fn encode_dkg_it_vss_complaint_payload(payload: &DkgItVssComplaintPayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&payload.complainant_party_id.to_le_bytes());
    out.extend_from_slice(&payload.dealer_party_id.to_le_bytes());
    out.extend_from_slice(&payload.receiver_party_id.to_le_bytes());
    out.extend_from_slice(&payload.reason_code.to_le_bytes());
    put_bytes(&mut out, &payload.evidence);
    out
}

fn decode_dkg_it_vss_complaint_payload(
    bytes: &[u8],
) -> Result<DkgItVssComplaintPayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let payload = DkgItVssComplaintPayload {
        complainant_party_id: cursor.take_u16()?,
        dealer_party_id: cursor.take_u16()?,
        receiver_party_id: cursor.take_u16()?,
        reason_code: cursor.take_u16()?,
        evidence: cursor.take_bytes()?,
    };
    cursor.finish()?;
    Ok(payload)
}

fn decode_dkg_it_vss_certificate_payload(
    bytes: &[u8],
) -> Result<DkgItVssCertificatePayload, WireError> {
    let mut cursor = Cursor::new(bytes);
    let payload = DkgItVssCertificatePayload {
        backend_id: cursor.take_u8()?,
        dealer_party_id: cursor.take_u16()?,
        label_hash: cursor.take_array::<32>()?,
        accepted_receivers: cursor.take_u16_vec()?,
        complaint_hash: cursor.take_array::<32>()?,
        transcript_hash: cursor.take_array::<32>()?,
    };
    cursor.finish()?;
    Ok(payload)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn put_u16_vec(out: &mut Vec<u8>, values: &[u16]) {
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_u32_vec(out: &mut Vec<u8>, values: &[u32]) {
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take_u8(&mut self) -> Result<u8, WireError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn take_u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn take_bytes(&mut self) -> Result<Vec<u8>, WireError> {
        let len = self.take_u32()? as usize;
        if len > MAX_PAYLOAD_LEN {
            return Err(WireError::PayloadTooLarge(len));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn take_u32_vec(&mut self) -> Result<Vec<u32>, WireError> {
        let len = self.take_u32()? as usize;
        let byte_len = len.checked_mul(4).ok_or(WireError::PayloadTooLarge(len))?;
        if byte_len > self.remaining() {
            return Err(WireError::TruncatedPayload);
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.take_u32()?);
        }
        Ok(out)
    }

    fn take_i32_vec(&mut self) -> Result<Vec<i32>, WireError> {
        let len = self.take_u32()? as usize;
        let byte_len = len.checked_mul(4).ok_or(WireError::PayloadTooLarge(len))?;
        if byte_len > self.remaining() {
            return Err(WireError::TruncatedPayload);
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(i32::from_le_bytes(self.take_array()?));
        }
        Ok(out)
    }

    fn take_u16_vec(&mut self) -> Result<Vec<u16>, WireError> {
        let len = self.take_u32()? as usize;
        let byte_len = len.checked_mul(2).ok_or(WireError::PayloadTooLarge(len))?;
        if byte_len > self.remaining() {
            return Err(WireError::TruncatedPayload);
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.take_u16()?);
        }
        Ok(out)
    }

    fn finish(&self) -> Result<(), WireError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(WireError::TrailingPayloadBytes(remaining))
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(WireError::TruncatedPayload)?;
        if end > self.bytes.len() {
            return Err(WireError::TruncatedPayload);
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::dev_backends::{
        decode_partial_signature_payload, encode_partial_signature_payload, PartialSignaturePayload,
    };
    use super::*;

    fn header(sender: u16, round: RoundId, kind: PayloadKind) -> WireHeader {
        let parties = [1, 2, 3];
        WireHeader {
            protocol_version: WIRE_PROTOCOL_VERSION,
            suite: SuiteId::MlDsa65,
            round,
            sender_party_id: sender,
            keygen_transcript_hash: [0x11; 32],
            session_id: [0x22; 32],
            signing_set_hash: signing_set_hash(&parties),
            payload_kind: kind,
        }
    }

    fn context() -> ExpectedContext {
        ExpectedContext {
            suite: SuiteId::MlDsa65,
            keygen_transcript_hash: [0x11; 32],
            session_id: [0x22; 32],
            signing_set_hash: signing_set_hash(&[1, 2, 3]),
            allowed_parties: vec![1, 2, 3],
        }
    }

    #[test]
    fn wire_message_roundtrip_is_canonical() {
        let payload = encode_commit_payload(&CommitPayload {
            commitment: [0x33; 32],
        });
        let message = WireMessage {
            header: header(1, RoundId::PreprocessCommit, PayloadKind::PreprocessCommit),
            payload,
        };

        let encoded = encode_message(&message).expect("encode message");
        assert_eq!(decode_message(&encoded), Ok(message));
    }

    #[test]
    fn decode_rejects_bad_version_and_payload_length_mismatch() {
        let message = WireMessage {
            header: header(1, RoundId::PreprocessCommit, PayloadKind::PreprocessCommit),
            payload: vec![1, 2, 3],
        };
        let mut encoded = encode_message(&message).expect("encode message");
        encoded[8] = 0;
        encoded[9] = 0;
        assert_eq!(
            decode_message(&encoded),
            Err(WireError::BadProtocolVersion {
                expected: WIRE_PROTOCOL_VERSION,
                got: 0,
            })
        );

        let mut encoded = encode_message(&message).expect("encode message");
        encoded.push(0);
        assert_eq!(
            decode_message(&encoded),
            Err(WireError::PayloadLengthMismatch {
                expected_total: HEADER_LEN + 3,
                got_total: HEADER_LEN + 4,
            })
        );
    }

    #[test]
    fn payload_codecs_roundtrip_and_reject_trailing_bytes() {
        let open = MaskedBroadcastOpenPayload {
            masked_highs: vec![1, 2],
            masked_lows: vec![3, 4],
            nonce_commitment: [5; 32],
            rho_bits_commitment: [6; 32],
            transcript_hash: [7; 32],
            consistency_proof: vec![9, 10, 11],
            salt: [8; 32],
        };
        let encoded = encode_masked_broadcast_open_payload(&open).expect("encode open");
        assert_eq!(decode_masked_broadcast_open_payload(&encoded), Ok(open));

        let mut with_trailing = encode_commit_payload(&CommitPayload {
            commitment: [9; 32],
        });
        with_trailing.push(0);
        assert_eq!(
            decode_commit_payload(&with_trailing),
            Err(WireError::TrailingPayloadBytes(1))
        );
    }

    #[test]
    fn payload_codecs_reject_noncanonical_flags_and_mismatched_vectors() {
        let sign_request = SignRequestPayload {
            message: b"message".to_vec(),
            context: b"ctx".to_vec(),
            external_mu: None,
            token_transcript_hash: [0xaa; 32],
        };
        let mut encoded = encode_sign_request_payload(&sign_request);
        let flag_index = 4 + sign_request.message.len() + 4 + sign_request.context.len();
        encoded[flag_index] = 2;
        assert_eq!(
            decode_sign_request_payload(&encoded),
            Err(WireError::NonCanonicalFlag(2))
        );

        let open = MaskedBroadcastOpenPayload {
            masked_highs: vec![1],
            masked_lows: vec![2, 3],
            nonce_commitment: [5; 32],
            rho_bits_commitment: [6; 32],
            transcript_hash: [7; 32],
            consistency_proof: vec![9, 10, 11],
            salt: [8; 32],
        };
        assert_eq!(
            encode_masked_broadcast_open_payload(&open),
            Err(WireError::VectorLengthMismatch { lhs: 1, rhs: 2 })
        );
    }

    #[test]
    fn sign_and_partial_payloads_roundtrip() {
        let sign_request = SignRequestPayload {
            message: b"message".to_vec(),
            context: b"ctx".to_vec(),
            external_mu: Some([0x44; 64]),
            token_transcript_hash: [0xaa; 32],
        };
        let encoded = encode_sign_request_payload(&sign_request);
        assert_eq!(decode_sign_request_payload(&encoded), Ok(sign_request));

        let partial = PartialSignaturePayload {
            ctilde: vec![1, 2, 3],
            z_share: vec![4, 5, 6],
        };
        let encoded = encode_partial_signature_payload(&partial);
        assert_eq!(decode_partial_signature_payload(&encoded), Ok(partial));

        let final_sig = FinalSignaturePayload {
            signature: vec![7, 8, 9],
        };
        let encoded = encode_final_signature_payload(&final_sig);
        assert_eq!(decode_final_signature_payload(&encoded), Ok(final_sig));

        let strict_mpc = StrictSignMpcPayload {
            slot: StrictSignMpcSlot::PrivateSelection,
            phase: 7,
            receiver_party_id: 2,
            label_hash: [0x51; 32],
            transcript_hash: [0x52; 32],
            opaque_payload: vec![10, 11, 12, 13],
        };
        let encoded = encode_strict_sign_mpc_payload(&strict_mpc);
        assert_eq!(decode_strict_sign_mpc_payload(&encoded), Ok(strict_mpc));
    }

    #[test]
    fn strict_sign_mpc_payload_rejects_unknown_slot_and_trailing_bytes() {
        let strict_mpc = StrictSignMpcPayload {
            slot: StrictSignMpcSlot::BoundChecks,
            phase: 1,
            receiver_party_id: 0,
            label_hash: [0x31; 32],
            transcript_hash: [0x32; 32],
            opaque_payload: vec![1, 2, 3],
        };
        let mut encoded = encode_strict_sign_mpc_payload(&strict_mpc);
        encoded[0] = 99;
        assert_eq!(
            decode_strict_sign_mpc_payload(&encoded),
            Err(WireError::NonCanonicalFlag(99))
        );

        let mut encoded = encode_strict_sign_mpc_payload(&strict_mpc);
        encoded.push(0);
        assert_eq!(
            decode_strict_sign_mpc_payload(&encoded),
            Err(WireError::TrailingPayloadBytes(1))
        );
    }

    #[test]
    fn dkg_payloads_roundtrip() {
        let commit = DkgCommitPayload {
            vss_commitments: vec![vec![1, 2], vec![3, 4, 5]],
            as1_commitment: vec![6, 7],
            pairwise_seed_commitment: [8; 32],
        };
        let encoded = encode_dkg_commit_payload(&commit);
        assert_eq!(decode_dkg_commit_payload(&encoded), Ok(commit));

        let share = DkgSharePayload {
            receiver_party_id: 2,
            encrypted_share: vec![9, 10],
            encrypted_seed_share: vec![11, 12],
            proof: vec![13],
        };
        let encoded = encode_dkg_share_payload(&share);
        assert_eq!(decode_dkg_share_payload(&encoded), Ok(share));

        let complaint = DkgComplaintPayload {
            dealer_party_id: 1,
            receiver_party_id: 2,
            reason_code: 3,
            evidence: vec![14, 15],
        };
        let encoded = encode_dkg_complaint_payload(&complaint);
        assert_eq!(decode_dkg_complaint_payload(&encoded), Ok(complaint));

        let finalize = DkgFinalizePayload {
            public_key: vec![16, 17],
            rho: [18; 32],
            t1: vec![19, 20],
            accepted_parties: vec![1, 2, 3],
            keygen_transcript_hash: [21; 32],
        };
        let encoded = encode_dkg_finalize_payload(&finalize);
        assert_eq!(decode_dkg_finalize_payload(&encoded), Ok(finalize));

        let residue = DkgSmallResiduePayload {
            vector_kind: 1,
            coefficient_index: 257,
            eta: 4,
            residue: 8,
            bits: vec![0, 0, 0, 1],
        };
        let encoded = encode_dkg_small_residue_payload(&residue);
        assert_eq!(decode_dkg_small_residue_payload(&encoded), Ok(residue));

        let mpc = DkgPrimeFieldMpcPayload {
            round_kind: 4,
            phase: 1,
            receiver_party_id: 2,
            label_hash: [0x5a; 32],
            value: 12345,
            values: Vec::new(),
        };
        let encoded = encode_dkg_prime_field_mpc_payload(&mpc);
        assert_eq!(decode_dkg_prime_field_mpc_payload(&encoded), Ok(mpc));

        let mpc_vec = DkgPrimeFieldMpcPayload {
            round_kind: 1,
            phase: 2,
            receiver_party_id: 3,
            label_hash: [0x6b; 32],
            value: 0,
            values: vec![11, 22, 33],
        };
        let encoded = encode_dkg_prime_field_mpc_payload(&mpc_vec);
        assert_eq!(decode_dkg_prime_field_mpc_payload(&encoded), Ok(mpc_vec));
    }

    #[test]
    fn dkg_wire_rounds_validate_in_envelope() {
        let message = WireMessage {
            header: header(1, RoundId::DkgCommit, PayloadKind::DkgCommit),
            payload: encode_dkg_commit_payload(&DkgCommitPayload {
                vss_commitments: vec![vec![1]],
                as1_commitment: vec![2],
                pairwise_seed_commitment: [3; 32],
            }),
        };
        let encoded = encode_message(&message).expect("encode message");
        assert_eq!(decode_message(&encoded), Ok(message.clone()));
        assert_eq!(
            validate_round_batch(&[message], RoundId::DkgCommit, &context()),
            Ok(())
        );

        let residue = WireMessage {
            header: header(1, RoundId::DkgSmallResidue, PayloadKind::DkgSmallResidue),
            payload: encode_dkg_small_residue_payload(&DkgSmallResiduePayload {
                vector_kind: 1,
                coefficient_index: 0,
                eta: 4,
                residue: 3,
                bits: vec![1, 1, 0, 0],
            }),
        };
        let encoded = encode_message(&residue).expect("encode residue");
        assert_eq!(decode_message(&encoded), Ok(residue.clone()));
        assert_eq!(
            validate_round_batch(&[residue], RoundId::DkgSmallResidue, &context()),
            Ok(())
        );

        let strict_mpc = WireMessage {
            header: header(1, RoundId::StrictSignMpc, PayloadKind::StrictSignMpc),
            payload: encode_strict_sign_mpc_payload(&StrictSignMpcPayload {
                slot: StrictSignMpcSlot::SelectedOpening,
                phase: 3,
                receiver_party_id: 0,
                label_hash: [0x41; 32],
                transcript_hash: [0x42; 32],
                opaque_payload: vec![9, 10],
            }),
        };
        let encoded = encode_message(&strict_mpc).expect("encode strict mpc");
        assert_eq!(decode_message(&encoded), Ok(strict_mpc.clone()));
        assert_eq!(
            validate_round_batch(&[strict_mpc], RoundId::StrictSignMpc, &context()),
            Ok(())
        );
    }

    fn message(sender: u16, round: RoundId, kind: PayloadKind, payload: Vec<u8>) -> WireMessage {
        WireMessage {
            header: header(sender, round, kind),
            payload,
        }
    }

    #[test]
    fn in_memory_transport_private_messages_validate_channel_identity() {
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        let private = message(1, RoundId::DkgShare, PayloadKind::DkgShare, vec![7]);

        transport
            .send_private(2, private.clone())
            .expect("private send accepted");
        assert_eq!(
            transport.collect_private_round(2, RoundId::DkgShare, &context()),
            Ok(vec![private])
        );

        let wrong_sender = message(3, RoundId::DkgShare, PayloadKind::DkgShare, vec![8]);
        assert_eq!(
            transport.send_private(2, wrong_sender),
            Err(TransportError::SenderMismatch {
                channel_sender: 1,
                header_sender: 3,
            })
        );
    }

    #[test]
    fn pq_transport_adapter_harness_uses_ml_kem_and_ml_dsa_bindings() {
        use fips204::ml_dsa_65;
        use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
        use ml_kem::{
            kem::{Decapsulate, FromSeed},
            MlKem768,
        };
        use sha3::{Digest, Sha3_256};

        let (identity_pk, identity_sk) = ml_dsa_65::KG::keygen_from_seed(&[0x11; 32]);
        let (wrong_identity_pk, _) = ml_dsa_65::KG::keygen_from_seed(&[0x22; 32]);

        let mut kem_seed = ml_kem::Seed::default();
        kem_seed.copy_from_slice(&[0x33; 64]);
        let (receiver_dk, receiver_ek) = MlKem768::from_seed(&kem_seed);
        let mut encapsulation_randomness = ml_kem::B32::default();
        encapsulation_randomness.copy_from_slice(&[0x44; 32]);
        let (ciphertext, send_key) =
            receiver_ek.encapsulate_deterministic(&encapsulation_randomness);
        let recv_key = receiver_dk.decapsulate(&ciphertext);
        assert_eq!(send_key, recv_key);

        let mut kem_hasher = Sha3_256::new();
        kem_hasher.update(b"TALUS-test-ML-KEM-transport-session");
        kem_hasher.update(send_key.as_slice());
        kem_hasher.update(recv_key.as_slice());
        kem_hasher.update(ciphertext.as_slice());
        let ml_kem_transcript_hash: [u8; 32] = kem_hasher.finalize().into();

        let mut identity_hasher = Sha3_256::new();
        identity_hasher.update(b"TALUS-test-ML-DSA-identity-set");
        identity_hasher.update(identity_pk.clone().into_bytes());
        let ml_dsa_identity_transcript_hash: [u8; 32] = identity_hasher.finalize().into();

        let binding = PqTransportSessionBinding::new(
            SuiteId::MlDsa65,
            [0x66; 32],
            &[3, 1, 2],
            ml_kem_transcript_hash,
            ml_dsa_identity_transcript_hash,
        )
        .expect("pq transport binding");
        assert_eq!(binding.party_ids, vec![1, 2, 3]);
        assert_eq!(
            PqTransportSessionBinding::new(
                SuiteId::MlDsa65,
                [0x66; 32],
                &[1, 2, 2],
                ml_kem_transcript_hash,
                ml_dsa_identity_transcript_hash,
            ),
            Err(WireError::DuplicateParty(2))
        );

        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-test-ML-DSA-transport-auth");
        hasher.update(binding.session_id);
        hasher.update(send_key.as_slice());
        hasher.update(ciphertext.as_slice());
        let auth_transcript: [u8; 32] = hasher.finalize().into();

        let mut auth_message = Vec::new();
        auth_message.extend_from_slice(b"TALUS-test-ML-DSA-transport-auth");
        auth_message.extend_from_slice(&binding.session_id);
        auth_message.extend_from_slice(&auth_transcript);
        auth_message.extend_from_slice(ciphertext.as_slice());
        let signature = identity_sk
            .try_sign_with_seed(&[0x55; 32], &auth_message, b"TALUS")
            .expect("ml-dsa sign");
        assert!(identity_pk.verify(&auth_message, &signature, b"TALUS"));
        assert!(!wrong_identity_pk.verify(&auth_message, &signature, b"TALUS"));

        let expected = binding.expected_context();
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        let msg = WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: SuiteId::MlDsa65,
                round: RoundId::DkgShare,
                sender_party_id: 1,
                keygen_transcript_hash: expected.keygen_transcript_hash,
                session_id: binding.session_id,
                signing_set_hash: expected.signing_set_hash,
                payload_kind: PayloadKind::DkgShare,
            },
            payload: vec![9],
        };
        transport
            .send_private(2, msg)
            .expect("send authenticated message");
        assert_eq!(
            transport
                .collect_private_round(2, RoundId::DkgShare, &expected)
                .expect("collect authenticated round")
                .len(),
            1
        );

        let mut wrong_session = expected.clone();
        wrong_session.session_id = [0x77; 32];
        assert_eq!(
            transport.collect_private_round(2, RoundId::DkgShare, &wrong_session),
            Err(TransportError::Wire(WireError::ContextMismatch))
        );

        let mut downgraded = expected.clone();
        downgraded.suite = SuiteId::MlDsa44;
        assert_eq!(
            transport.collect_private_round(2, RoundId::DkgShare, &downgraded),
            Err(TransportError::Wire(WireError::ContextMismatch))
        );
    }

    #[test]
    fn pq_transport_adapter_harness_rejects_delivery_faults() {
        let binding = PqTransportSessionBinding::new(
            SuiteId::MlDsa65,
            [0x66; 32],
            &[1, 2, 3],
            [0x77; 32],
            [0x88; 32],
        )
        .expect("pq binding");
        let expected = binding.expected_context();
        let msg = |sender: u16, payload: Vec<u8>| WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: SuiteId::MlDsa65,
                round: RoundId::DkgShare,
                sender_party_id: sender,
                keygen_transcript_hash: expected.keygen_transcript_hash,
                session_id: expected.session_id,
                signing_set_hash: expected.signing_set_hash,
                payload_kind: PayloadKind::DkgShare,
            },
            payload,
        };

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        assert_eq!(
            transport.send_private(2, msg(2, vec![1])),
            Err(TransportError::SenderMismatch {
                channel_sender: 1,
                header_sender: 2,
            })
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        transport
            .inject_private(3, 2, msg(3, vec![3]))
            .expect("inject sender 3");
        transport
            .inject_private(1, 2, msg(1, vec![1]))
            .expect("inject sender 1");
        transport
            .inject_private(2, 2, msg(2, vec![2]))
            .expect("inject sender 2");
        let collected = transport
            .collect_private_round(2, RoundId::DkgShare, &expected)
            .expect("reordered messages accepted");
        assert_eq!(
            collected
                .iter()
                .map(|message| message.header.sender_party_id)
                .collect::<Vec<_>>(),
            vec![3, 1, 2]
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        transport
            .inject_private(1, 2, msg(1, vec![1]))
            .expect("inject first duplicate");
        transport
            .inject_private(1, 2, msg(1, vec![9]))
            .expect("inject second duplicate");
        assert_eq!(
            transport.collect_private_round(2, RoundId::DkgShare, &expected),
            Err(TransportError::Wire(WireError::DuplicateSender(1)))
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for sender in [1u16, 2, 3] {
            let message = msg(sender, vec![sender as u8]);
            for observer in [1u16, 2] {
                transport
                    .inject_broadcast_delivery(observer, message.clone())
                    .expect("inject partial broadcast");
            }
        }
        assert_eq!(
            transport.collect_equivocation_checked_round(RoundId::DkgShare, &expected),
            Err(TransportError::IncompleteBroadcastView {
                observer_party_id: 3,
                expected: 3,
                got: 0,
            })
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for sender in [1u16, 2, 3] {
            for observer in [1u16, 2, 3] {
                let mut payload = vec![sender as u8];
                if sender == 2 && observer == 3 {
                    payload = vec![99];
                }
                transport
                    .inject_broadcast_delivery(observer, msg(sender, payload))
                    .expect("inject equivocation");
            }
        }
        assert_eq!(
            transport.collect_equivocation_checked_round(RoundId::DkgShare, &expected),
            Err(TransportError::Equivocation { sender: 2 })
        );

        let mut wrong_session = expected.clone();
        wrong_session.session_id = [0x99; 32];
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        transport
            .inject_private(1, 2, msg(1, vec![1]))
            .expect("inject wrong-session test");
        assert_eq!(
            transport.collect_private_round(2, RoundId::DkgShare, &wrong_session),
            Err(TransportError::Wire(WireError::ContextMismatch))
        );
    }

    #[derive(Clone, Debug)]
    struct AppProvidedPqTransportAdapter {
        inner: InMemoryTransport,
        evidence: NativeDkgTransportEvidence,
        expected: ExpectedContext,
    }

    impl AppProvidedPqTransportAdapter {
        fn new(local_party: u16, evidence: NativeDkgTransportEvidence) -> Self {
            let binding = evidence.pq_session_binding().expect("pq session binding");
            Self {
                inner: InMemoryTransport::new(local_party, binding.party_ids.clone())
                    .expect("app transport inner bus"),
                expected: binding.expected_context(),
                evidence,
            }
        }

        fn expected_context(&self) -> &ExpectedContext {
            &self.expected
        }

        fn inject_private(
            &mut self,
            sender: u16,
            receiver: u16,
            message: WireMessage,
        ) -> Result<(), TransportError> {
            self.inner.inject_private(sender, receiver, message)
        }

        fn inject_broadcast_delivery(
            &mut self,
            observer: u16,
            message: WireMessage,
        ) -> Result<(), TransportError> {
            self.inner.inject_broadcast_delivery(observer, message)
        }
    }

    impl NativeDkgApplicationTransportEvidenceProvider for AppProvidedPqTransportAdapter {
        fn native_dkg_transport_evidence(&self) -> &NativeDkgTransportEvidence {
            &self.evidence
        }
    }

    impl AuthenticatedP2pTransport for AppProvidedPqTransportAdapter {
        fn send_private(
            &mut self,
            receiver_party_id: u16,
            message: WireMessage,
        ) -> Result<(), TransportError> {
            self.inner.send_private(receiver_party_id, message)
        }

        fn collect_private_round(
            &self,
            receiver_party_id: u16,
            expected_round: RoundId,
            expected: &ExpectedContext,
        ) -> Result<Vec<WireMessage>, TransportError> {
            if expected != &self.expected {
                return Err(TransportError::Wire(WireError::ContextMismatch));
            }
            self.inner
                .collect_private_round(receiver_party_id, expected_round, expected)
        }
    }

    impl EquivocationResistantBroadcast for AppProvidedPqTransportAdapter {
        fn broadcast(&mut self, message: WireMessage) -> Result<(), TransportError> {
            self.inner.broadcast(message)
        }

        fn collect_broadcast_view(
            &self,
            observer_party_id: u16,
            expected_round: RoundId,
            expected: &ExpectedContext,
        ) -> Result<Vec<WireMessage>, TransportError> {
            if expected != &self.expected {
                return Err(TransportError::Wire(WireError::ContextMismatch));
            }
            self.inner
                .collect_broadcast_view(observer_party_id, expected_round, expected)
        }

        fn collect_equivocation_checked_round(
            &self,
            expected_round: RoundId,
            expected: &ExpectedContext,
        ) -> Result<Vec<WireMessage>, TransportError> {
            if expected != &self.expected {
                return Err(TransportError::Wire(WireError::ContextMismatch));
            }
            self.inner
                .collect_equivocation_checked_round(expected_round, expected)
        }
    }

    #[test]
    fn app_provided_pq_transport_adapter_binds_session_identity_and_replay() {
        use fips204::ml_dsa_65;
        use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
        use ml_kem::{
            kem::{Decapsulate, FromSeed},
            MlKem768,
        };
        use sha3::{Digest, Sha3_256};

        let (identity_pk, identity_sk) = ml_dsa_65::KG::keygen_from_seed(&[0x13; 32]);
        let (wrong_identity_pk, _) = ml_dsa_65::KG::keygen_from_seed(&[0x14; 32]);
        let mut kem_seed = ml_kem::Seed::default();
        kem_seed.copy_from_slice(&[0x15; 64]);
        let (receiver_dk, receiver_ek) = MlKem768::from_seed(&kem_seed);
        let mut randomness = ml_kem::B32::default();
        randomness.copy_from_slice(&[0x16; 32]);
        let (ciphertext, send_key) = receiver_ek.encapsulate_deterministic(&randomness);
        let recv_key = receiver_dk.decapsulate(&ciphertext);
        assert_eq!(send_key, recv_key);

        let mut kem_hasher = Sha3_256::new();
        kem_hasher.update(b"TALUS-test-app-adapter-kem");
        kem_hasher.update(send_key.as_slice());
        kem_hasher.update(recv_key.as_slice());
        kem_hasher.update(ciphertext.as_slice());
        let ml_kem_transcript_hash: [u8; 32] = kem_hasher.finalize().into();

        let mut identity_hasher = Sha3_256::new();
        identity_hasher.update(b"TALUS-test-app-adapter-identity");
        identity_hasher.update(identity_pk.clone().into_bytes());
        let ml_dsa_identity_transcript_hash: [u8; 32] = identity_hasher.finalize().into();

        let evidence = NativeDkgTransportEvidence::new(
            SuiteId::MlDsa65,
            [0x66; 32],
            &[1, 2, 3],
            MlKemChannelSessionEvidence::new(ml_kem_transcript_hash).expect("ml-kem evidence"),
            MlDsaOperationalIdentityEvidence::new(ml_dsa_identity_transcript_hash)
                .expect("ml-dsa evidence"),
            ReliableBroadcastEvidence::new([0x18; 32]).expect("broadcast evidence"),
        )
        .expect("native dkg transport evidence");
        let binding = evidence.pq_session_binding().expect("binding");

        let auth_message = {
            let mut msg = Vec::new();
            msg.extend_from_slice(b"TALUS-test-app-adapter-auth");
            msg.extend_from_slice(&binding.session_id);
            msg.extend_from_slice(ciphertext.as_slice());
            msg
        };
        let signature = identity_sk
            .try_sign_with_seed(&[0x17; 32], &auth_message, b"TALUS")
            .expect("sign identity binding");
        assert!(identity_pk.verify(&auth_message, &signature, b"TALUS"));
        assert!(!wrong_identity_pk.verify(&auth_message, &signature, b"TALUS"));

        let mut adapter = AppProvidedPqTransportAdapter::new(1, evidence.clone());
        assert_eq!(
            adapter.pq_session_binding().expect("adapter binding"),
            binding
        );
        assert_eq!(
            <AppProvidedPqTransportAdapter as NativeDkgApplicationTransportEvidenceProvider>::expected_context(&adapter)
                .expect("provider expected context"),
            binding.expected_context()
        );
        assert_ne!(
            adapter.native_dkg_transport_evidence().evidence_hash(),
            [0u8; 32]
        );
        let expected = adapter.expected_context().clone();
        let msg = WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: SuiteId::MlDsa65,
                round: RoundId::DkgShare,
                sender_party_id: 1,
                keygen_transcript_hash: expected.keygen_transcript_hash,
                session_id: expected.session_id,
                signing_set_hash: expected.signing_set_hash,
                payload_kind: PayloadKind::DkgShare,
            },
            payload: vec![42],
        };
        adapter
            .send_private(2, msg.clone())
            .expect("app adapter sends private");
        assert_eq!(
            adapter.collect_private_round(2, RoundId::DkgShare, &expected),
            Ok(vec![msg.clone()])
        );
        adapter
            .inject_private(1, 2, msg)
            .expect("inject replayed duplicate");
        assert_eq!(
            adapter.collect_private_round(2, RoundId::DkgShare, &expected),
            Err(TransportError::Wire(WireError::DuplicateSender(1)))
        );

        let mut wrong_session = expected.clone();
        wrong_session.session_id = [0x99; 32];
        assert_eq!(
            adapter.collect_private_round(2, RoundId::DkgShare, &wrong_session),
            Err(TransportError::Wire(WireError::ContextMismatch))
        );

        let mut broadcast_adapter = AppProvidedPqTransportAdapter::new(1, evidence);
        for sender in [1u16, 2, 3] {
            for observer in [1u16, 2, 3] {
                let payload = if sender == 3 && observer == 2 {
                    vec![9]
                } else {
                    vec![sender as u8]
                };
                broadcast_adapter
                    .inject_broadcast_delivery(
                        observer,
                        WireMessage {
                            header: WireHeader {
                                protocol_version: WIRE_PROTOCOL_VERSION,
                                suite: SuiteId::MlDsa65,
                                round: RoundId::DkgCommit,
                                sender_party_id: sender,
                                keygen_transcript_hash: expected.keygen_transcript_hash,
                                session_id: expected.session_id,
                                signing_set_hash: expected.signing_set_hash,
                                payload_kind: PayloadKind::DkgCommit,
                            },
                            payload,
                        },
                    )
                    .expect("inject app broadcast");
            }
        }
        assert_eq!(
            SynchronousBroadcastContract::collect_round(
                &broadcast_adapter,
                RoundId::DkgCommit,
                &expected
            ),
            Err(TransportError::Equivocation { sender: 3 })
        );
    }

    #[test]
    fn native_dkg_transport_evidence_requires_kem_identity_and_broadcast_hashes() {
        assert_eq!(
            MlKemChannelSessionEvidence::new([0u8; 32]),
            Err(WireError::MissingTransportEvidence(
                "ml-kem channel/session"
            ))
        );
        assert_eq!(
            MlDsaOperationalIdentityEvidence::new([0u8; 32]),
            Err(WireError::MissingTransportEvidence(
                "ml-dsa operational identity"
            ))
        );
        assert_eq!(
            ReliableBroadcastEvidence::new([0u8; 32]),
            Err(WireError::MissingTransportEvidence("reliable broadcast"))
        );

        let evidence = NativeDkgTransportEvidence::new(
            SuiteId::MlDsa65,
            [0x41; 32],
            &[3, 1, 2],
            MlKemChannelSessionEvidence::new([0x42; 32]).expect("kem evidence"),
            MlDsaOperationalIdentityEvidence::new([0x43; 32]).expect("identity evidence"),
            ReliableBroadcastEvidence::new([0x44; 32]).expect("broadcast evidence"),
        )
        .expect("native evidence");
        assert_eq!(evidence.party_ids, vec![1, 2, 3]);

        let binding = evidence.pq_session_binding().expect("pq binding");
        assert_eq!(
            binding.expected_context(),
            evidence.expected_context().expect("context")
        );
        assert_ne!(evidence.evidence_hash(), [0u8; 32]);

        let changed_broadcast = NativeDkgTransportEvidence::new(
            SuiteId::MlDsa65,
            [0x41; 32],
            &[1, 2, 3],
            MlKemChannelSessionEvidence::new([0x42; 32]).expect("kem evidence"),
            MlDsaOperationalIdentityEvidence::new([0x43; 32]).expect("identity evidence"),
            ReliableBroadcastEvidence::new([0x45; 32]).expect("broadcast evidence"),
        )
        .expect("changed broadcast evidence");
        assert_eq!(
            changed_broadcast
                .pq_session_binding()
                .expect("binding")
                .session_id,
            binding.session_id
        );
        assert_ne!(changed_broadcast.evidence_hash(), evidence.evidence_hash());

        assert_eq!(
            NativeDkgTransportEvidence::new(
                SuiteId::MlDsa65,
                [0u8; 32],
                &[1, 2, 3],
                MlKemChannelSessionEvidence::new([0x42; 32]).expect("kem evidence"),
                MlDsaOperationalIdentityEvidence::new([0x43; 32]).expect("identity evidence"),
                ReliableBroadcastEvidence::new([0x44; 32]).expect("broadcast evidence"),
            ),
            Err(WireError::MissingTransportEvidence("keygen transcript"))
        );
    }

    #[test]
    fn in_memory_broadcast_detects_complete_consistent_views() {
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for sender in [1, 2, 3] {
            let msg = message(
                sender,
                RoundId::PreprocessCommit,
                PayloadKind::PreprocessCommit,
                vec![sender as u8],
            );
            for observer in [1, 2, 3] {
                transport
                    .inject_broadcast_delivery(observer, msg.clone())
                    .expect("inject broadcast delivery");
            }
        }

        let collected = transport
            .collect_equivocation_checked_round(RoundId::PreprocessCommit, &context())
            .expect("consistent broadcast accepted");
        assert_eq!(
            collected
                .iter()
                .map(|msg| msg.header.sender_party_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn in_memory_broadcast_rejects_equivocation_and_missing_views() {
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for sender in [1, 2, 3] {
            let mut msg = message(
                sender,
                RoundId::PreprocessCommit,
                PayloadKind::PreprocessCommit,
                vec![sender as u8],
            );
            for observer in [1, 2, 3] {
                if sender == 2 && observer == 3 {
                    msg.payload = vec![99];
                }
                transport
                    .inject_broadcast_delivery(observer, msg.clone())
                    .expect("inject broadcast delivery");
                msg.payload = vec![sender as u8];
            }
        }

        assert_eq!(
            transport.collect_equivocation_checked_round(RoundId::PreprocessCommit, &context()),
            Err(TransportError::Equivocation { sender: 2 })
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for observer in [1, 2, 3] {
            transport
                .inject_broadcast_delivery(
                    observer,
                    message(
                        1,
                        RoundId::PreprocessCommit,
                        PayloadKind::PreprocessCommit,
                        vec![1],
                    ),
                )
                .expect("inject broadcast delivery");
        }
        assert_eq!(
            transport.collect_equivocation_checked_round(RoundId::PreprocessCommit, &context()),
            Err(TransportError::IncompleteBroadcastView {
                observer_party_id: 1,
                expected: 3,
                got: 1,
            })
        );
    }

    #[test]
    fn synchronous_broadcast_contract_requires_identical_honest_views_or_abort() {
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for sender in [1, 2, 3] {
            let msg = message(
                sender,
                RoundId::DkgCommit,
                PayloadKind::DkgCommit,
                vec![sender as u8],
            );
            for observer in [1, 2, 3] {
                transport
                    .inject_broadcast_delivery(observer, msg.clone())
                    .expect("inject consistent broadcast");
            }
        }
        assert_eq!(
            SynchronousBroadcastContract::collect_round(&transport, RoundId::DkgCommit, &context())
                .expect("consistent views"),
            vec![
                message(1, RoundId::DkgCommit, PayloadKind::DkgCommit, vec![1]),
                message(2, RoundId::DkgCommit, PayloadKind::DkgCommit, vec![2]),
                message(3, RoundId::DkgCommit, PayloadKind::DkgCommit, vec![3]),
            ]
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for sender in [1, 2, 3] {
            for observer in [1, 2, 3] {
                let payload = if sender == 2 && observer == 3 {
                    vec![99]
                } else {
                    vec![sender as u8]
                };
                transport
                    .inject_broadcast_delivery(
                        observer,
                        message(sender, RoundId::DkgCommit, PayloadKind::DkgCommit, payload),
                    )
                    .expect("inject equivocated broadcast");
            }
        }
        assert_eq!(
            SynchronousBroadcastContract::collect_round(&transport, RoundId::DkgCommit, &context()),
            Err(TransportError::Equivocation { sender: 2 })
        );

        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        for observer in [1, 2] {
            transport
                .inject_broadcast_delivery(
                    observer,
                    message(1, RoundId::DkgCommit, PayloadKind::DkgCommit, vec![1]),
                )
                .expect("inject partial broadcast");
        }
        assert_eq!(
            SynchronousBroadcastContract::collect_round(&transport, RoundId::DkgCommit, &context()),
            Err(TransportError::IncompleteBroadcastView {
                observer_party_id: 1,
                expected: 3,
                got: 1,
            })
        );
    }

    #[test]
    fn in_memory_broadcast_method_delivers_to_all_observers() {
        let mut transport =
            InMemoryTransport::new(1, vec![1, 2, 3]).expect("valid transport parties");
        transport
            .broadcast(message(
                1,
                RoundId::PreprocessCommit,
                PayloadKind::PreprocessCommit,
                vec![1],
            ))
            .expect("broadcast accepted");

        assert_eq!(transport.broadcast_deliveries().len(), 3);
        assert_eq!(
            transport.collect_broadcast_view(2, RoundId::PreprocessCommit, &context()),
            Ok(vec![message(
                1,
                RoundId::PreprocessCommit,
                PayloadKind::PreprocessCommit,
                vec![1],
            )])
        );
    }

    #[test]
    fn context_and_round_validation_reject_replay_shapes() {
        let message = WireMessage {
            header: header(4, RoundId::PreprocessCommit, PayloadKind::PreprocessCommit),
            payload: vec![],
        };
        assert_eq!(
            validate_message_context(&message, &context()),
            Err(WireError::UnknownSender(4))
        );

        let message = WireMessage {
            header: header(1, RoundId::SignPartial, PayloadKind::PartialSignature),
            payload: vec![],
        };
        assert_eq!(
            validate_round_batch(&[message], RoundId::PreprocessCommit, &context()),
            Err(WireError::RoundMismatch {
                expected: RoundId::PreprocessCommit,
                got: RoundId::SignPartial,
            })
        );
    }

    #[test]
    fn dkg_it_vss_artifact_payloads_round_trip() {
        let commitment =
            DkgItVssArtifactPayload::PublicCommitment(DkgItVssPublicCommitmentPayload {
                backend_id: 2,
                dealer_party_id: 1,
                label_hash: [0x11; 32],
                public_metadata_hash: [0x12; 32],
            });
        assert_eq!(
            decode_dkg_it_vss_artifact_payload(&encode_dkg_it_vss_artifact_payload(&commitment)),
            Ok(commitment)
        );

        let precommitment =
            DkgItVssArtifactPayload::PublicPrecommitment(DkgItVssPublicPrecommitmentPayload {
                backend_id: 2,
                dealer_party_id: 1,
                label_hash: [0x13; 32],
                public_precommitment_hash: [0x14; 32],
            });
        assert_eq!(
            decode_dkg_it_vss_artifact_payload(&encode_dkg_it_vss_artifact_payload(&precommitment)),
            Ok(precommitment)
        );

        let public_coin =
            DkgItVssArtifactPayload::PublicCoinShare(DkgItVssPublicCoinSharePayload {
                party_id: 3,
                label_hash: [0x15; 32],
                coin: [0x17; 32],
                transcript_hash: [0x18; 32],
            });
        assert_eq!(
            decode_dkg_it_vss_artifact_payload(&encode_dkg_it_vss_artifact_payload(&public_coin)),
            Ok(public_coin)
        );

        let resolution = DkgItVssArtifactPayload::ComplaintResolution(DkgItVssResolutionPayload {
            accepted_dealers: vec![1, 3],
            rejected_dealers: vec![2],
            complaints: vec![DkgItVssComplaintPayload {
                complainant_party_id: 3,
                dealer_party_id: 2,
                receiver_party_id: 3,
                reason_code: 1,
                evidence: vec![9, 8, 7],
            }],
            certificates: vec![DkgItVssCertificatePayload {
                backend_id: 2,
                dealer_party_id: 1,
                label_hash: [0x21; 32],
                accepted_receivers: vec![1, 2, 3],
                complaint_hash: [0x22; 32],
                transcript_hash: [0x23; 32],
            }],
        });
        assert_eq!(
            decode_dkg_it_vss_artifact_payload(&encode_dkg_it_vss_artifact_payload(&resolution)),
            Ok(resolution)
        );
    }

    #[test]
    fn round_validation_rejects_duplicate_sender() {
        let first = WireMessage {
            header: header(1, RoundId::PreprocessCommit, PayloadKind::PreprocessCommit),
            payload: vec![],
        };
        let second = first.clone();

        assert_eq!(
            validate_round_batch(&[first, second], RoundId::PreprocessCommit, &context()),
            Err(WireError::DuplicateSender(1))
        );
    }

    #[test]
    fn signing_set_hash_and_transcript_are_order_stable() {
        assert_eq!(signing_set_hash(&[3, 1, 2]), signing_set_hash(&[1, 2, 3]));

        let first = WireMessage {
            header: header(1, RoundId::PreprocessCommit, PayloadKind::PreprocessCommit),
            payload: vec![1],
        };
        let second = WireMessage {
            header: header(2, RoundId::PreprocessCommit, PayloadKind::PreprocessCommit),
            payload: vec![2],
        };
        assert_eq!(
            transcript_hash_round([0; 32], &[first.clone(), second.clone()]),
            transcript_hash_round([0; 32], &[second, first])
        );
    }

    #[test]
    fn production_wire_api_does_not_compile_clear_partial_or_public_a_secret_payloads() {
        const DEV_CFG: &str = "#[cfg(any(test, feature = \"paper-fast-dev\"))]";

        fn assert_cfg_gated(source: &str, needle: &str) {
            let mut offset = 0;
            while let Some(relative) = source[offset..].find(needle) {
                let index = offset + relative;
                let prefix = source[..index]
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(
                    prefix.contains(DEV_CFG),
                    "`{needle}` must be gated by `{DEV_CFG}`"
                );
                offset = index + needle.len();
            }
        }

        let source = include_str!("lib.rs");
        for needle in [
            "\n    SignPartial = 4,",
            "\n    PartialSignature = 4,",
            "\npub struct PartialSignaturePayload",
            "\npub fn encode_partial_signature_payload",
            "\npub fn decode_partial_signature_payload",
            "\n    pub as1_commitment: Vec<u8>",
        ] {
            assert_cfg_gated(source, needle);
        }
    }
}
