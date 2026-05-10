use super::*;

/// Production IT-VSS backend identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItVssBackendId {
    /// Reviewed Rabin-Ben-Or-style information-checking VSS over private
    /// channels and equivocation-resistant broadcast.
    ProductionInformationChecking,
    /// Local hash-binding scaffold, never acceptable for production.
    InProcessHashBindingScaffold,
}

impl ItVssBackendId {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::ProductionInformationChecking => 1,
            Self::InProcessHashBindingScaffold => 2,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ProductionInformationChecking),
            2 => Some(Self::InProcessHashBindingScaffold),
            _ => None,
        }
    }
}

/// Secret-sharing domain for production IT-VSS transcript labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItVssSharingDomain {
    /// ML-DSA `s1` bounded secret material.
    MldsaS1,
    /// ML-DSA `s2` bounded secret material.
    MldsaS2,
    /// Small-residue input for exact bounded sampling.
    SmallResidue,
    /// Prime-field MPC auxiliary material.
    PrimeFieldMpcAux,
    /// Online preprocessing nonce-share generation material.
    NoncePreprocessing,
}

impl ItVssSharingDomain {
    fn as_u8(self) -> u8 {
        match self {
            Self::MldsaS1 => 1,
            Self::MldsaS2 => 2,
            Self::SmallResidue => 3,
            Self::PrimeFieldMpcAux => 4,
            Self::NoncePreprocessing => 5,
        }
    }

    /// Maps an ML-DSA secret-vector kind to its IT-VSS domain.
    pub fn for_secret_vector(vector: SecretVectorKind) -> Self {
        match vector {
            SecretVectorKind::S1 => Self::MldsaS1,
            SecretVectorKind::S2 => Self::MldsaS2,
        }
    }
}

/// Transcript label for one production IT-VSS sharing instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItVssSharingLabel {
    /// DKG config hash.
    pub config_hash: KeygenTranscriptHash,
    /// Dealer creating this sharing.
    pub dealer: PartyId,
    /// Sharing domain.
    pub domain: ItVssSharingDomain,
    /// Optional coefficient/gate index within the domain.
    pub index: Option<u32>,
    /// Stable hash used in wire payloads, tags, and certificates.
    pub label_hash: [u8; 32],
}

impl ItVssSharingLabel {
    /// Builds a transcript-bound IT-VSS sharing label.
    pub fn new(
        config: &DkgConfig,
        dealer: PartyId,
        domain: ItVssSharingDomain,
        index: Option<u32>,
    ) -> Result<Self, DkgError> {
        config.validate()?;
        if !config.parties.contains(&dealer) {
            return Err(DkgError::UnknownParty(dealer));
        }
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/sharing-label");
        hasher.update(config.transcript_hash().0);
        hasher.update(dealer.0.to_le_bytes());
        hasher.update([domain.as_u8()]);
        match index {
            Some(value) => {
                hasher.update([1]);
                hasher.update(value.to_le_bytes());
            }
            None => hasher.update([0]),
        }
        Ok(Self {
            config_hash: config.transcript_hash(),
            dealer,
            domain,
            index,
            label_hash: hasher.finalize().into(),
        })
    }
}

/// Prime field modulus used by ML-DSA and TALUS IT-VSS scalar checks.
pub const IT_VSS_FIELD_Q: u32 = 8_380_417;

/// Canonical IT-VSS field element in `F_q`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ItVssFq(u32);

impl ItVssFq {
    /// Returns zero.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Returns one.
    pub const fn one() -> Self {
        Self(1)
    }

    /// Builds a canonical field element.
    pub fn new(value: u32) -> Result<Self, DkgError> {
        if value >= IT_VSS_FIELD_Q {
            return Err(DkgError::FieldShareCoefficientOutOfRange {
                index: 0,
                coefficient: value as Coeff,
                modulus: IT_VSS_FIELD_Q as Coeff,
            });
        }
        Ok(Self(value))
    }

    /// Builds a nonzero field element.
    pub fn nonzero(value: u32) -> Result<Self, DkgError> {
        let value = Self::new(value)?;
        if value.0 == 0 {
            return Err(DkgError::Backend("zero IT-VSS IC tag multiplier"));
        }
        Ok(value)
    }

    /// Returns the canonical representative.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Adds two field elements.
    pub fn add_mod(self, rhs: Self) -> Self {
        Self(((u64::from(self.0) + u64::from(rhs.0)) % u64::from(IT_VSS_FIELD_Q)) as u32)
    }

    /// Subtracts two field elements.
    pub fn sub_mod(self, rhs: Self) -> Self {
        Self(
            ((u64::from(self.0) + u64::from(IT_VSS_FIELD_Q) - u64::from(rhs.0))
                % u64::from(IT_VSS_FIELD_Q)) as u32,
        )
    }

    /// Multiplies two field elements.
    pub fn mul_mod(self, rhs: Self) -> Self {
        Self(((u64::from(self.0) * u64::from(rhs.0)) % u64::from(IT_VSS_FIELD_Q)) as u32)
    }
}

impl fmt::Debug for ItVssFq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ItVssFq").field(&self.0).finish()
    }
}

/// Marker proving an audited IC receiver tag is discarded after audit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscardAfterAudit;

/// Marker proving a retained IC receiver tag is receiver-private only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverPrivateOnly;

/// Holder-side information-checking tag material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItVssHolderSideTag {
    /// Holder/intermediary whose value is authenticated.
    pub holder: PartyId,
    /// Receiver/verifier for this tag.
    pub receiver: PartyId,
    /// Tag index within the holder/receiver pair.
    pub tag_index: u16,
    /// Holder-side randomizer `y`.
    pub y: ItVssFq,
}

/// Receiver-side information-checking tag opened only for audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditedReceiverTag {
    /// Holder/intermediary whose value is authenticated.
    pub holder: PartyId,
    /// Receiver/verifier for this tag.
    pub receiver: PartyId,
    /// Tag index within the holder/receiver pair.
    pub tag_index: u16,
    /// Receiver-side nonzero multiplier `b`.
    pub b: ItVssFq,
    /// Receiver-side check value `c = s + b*y`.
    pub c: ItVssFq,
    /// Marker: this tag is never retained for reconstruction.
    pub discard_after_audit: DiscardAfterAudit,
}

impl AuditedReceiverTag {
    /// Builds an audited receiver tag.
    pub fn new(
        holder: PartyId,
        receiver: PartyId,
        tag_index: u16,
        b: ItVssFq,
        c: ItVssFq,
    ) -> Result<Self, DkgError> {
        if b.value() == 0 {
            return Err(DkgError::Backend("zero IT-VSS IC tag multiplier"));
        }
        Ok(Self {
            holder,
            receiver,
            tag_index,
            b,
            c,
            discard_after_audit: DiscardAfterAudit,
        })
    }

    /// Verifies `c = value + b*y`.
    pub fn verify(self, value: ItVssFq, holder_tag: ItVssHolderSideTag) -> bool {
        self.holder == holder_tag.holder
            && self.receiver == holder_tag.receiver
            && self.tag_index == holder_tag.tag_index
            && self.c == value.add_mod(self.b.mul_mod(holder_tag.y))
    }
}

/// Receiver-side information-checking tag retained for reconstruction.
///
/// The `b` and `c` fields are deliberately private. Retained receiver-side
/// tags must remain receiver-private forever and must not have public wire
/// encodings. Opening them would let the holder forge another value by
/// computing a matching `y`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RetainedReceiverTag {
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    b: ItVssFq,
    c: ItVssFq,
    visibility: ReceiverPrivateOnly,
}

impl RetainedReceiverTag {
    /// Builds a receiver-private retained tag.
    pub fn new_private(
        holder: PartyId,
        receiver: PartyId,
        tag_index: u16,
        b: ItVssFq,
        c: ItVssFq,
    ) -> Result<Self, DkgError> {
        if b.value() == 0 {
            return Err(DkgError::Backend("zero IT-VSS IC tag multiplier"));
        }
        Ok(Self {
            holder,
            receiver,
            tag_index,
            b,
            c,
            visibility: ReceiverPrivateOnly,
        })
    }

    /// Holder authenticated by this retained tag.
    pub const fn holder(&self) -> PartyId {
        self.holder
    }

    /// Receiver that privately owns this retained tag.
    pub const fn receiver(&self) -> PartyId {
        self.receiver
    }

    /// Tag index within the holder/receiver pair.
    pub const fn tag_index(&self) -> u16 {
        self.tag_index
    }

    pub(crate) const fn b(&self) -> ItVssFq {
        self.b
    }

    pub(crate) const fn c(&self) -> ItVssFq {
        self.c
    }

    /// Verifies `c = value + b*y` without exposing retained `(b,c)`.
    pub fn verify_private(&self, value: ItVssFq, holder_tag: ItVssHolderSideTag) -> bool {
        self.holder == holder_tag.holder
            && self.receiver == holder_tag.receiver
            && self.tag_index == holder_tag.tag_index
            && self.c == value.add_mod(self.b.mul_mod(holder_tag.y))
    }
}

impl fmt::Debug for RetainedReceiverTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedReceiverTag")
            .field("holder", &self.holder)
            .field("receiver", &self.receiver)
            .field("tag_index", &self.tag_index)
            .field("b", &"<receiver-private>")
            .field("c", &"<receiver-private>")
            .field("visibility", &self.visibility)
            .finish()
    }
}

/// Computes `c = value + b*y` for an information-checking tag.
pub fn it_vss_ic_tag_check_value(value: ItVssFq, b: ItVssFq, y: ItVssFq) -> ItVssFq {
    value.add_mod(b.mul_mod(y))
}

/// Builds matching holder/audited receiver IC tags for tests and audited
/// production phases.
pub fn it_vss_audited_ic_tag_pair(
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    value: ItVssFq,
    b: ItVssFq,
    y: ItVssFq,
) -> Result<(ItVssHolderSideTag, AuditedReceiverTag), DkgError> {
    let holder_tag = ItVssHolderSideTag {
        holder,
        receiver,
        tag_index,
        y,
    };
    let receiver_tag = AuditedReceiverTag::new(
        holder,
        receiver,
        tag_index,
        b,
        it_vss_ic_tag_check_value(value, b, y),
    )?;
    Ok((holder_tag, receiver_tag))
}

/// Builds matching holder/retained receiver IC tags.
pub fn it_vss_retained_ic_tag_pair(
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    value: ItVssFq,
    b: ItVssFq,
    y: ItVssFq,
) -> Result<(ItVssHolderSideTag, RetainedReceiverTag), DkgError> {
    let holder_tag = ItVssHolderSideTag {
        holder,
        receiver,
        tag_index,
        y,
    };
    let receiver_tag = RetainedReceiverTag::new_private(
        holder,
        receiver,
        tag_index,
        b,
        it_vss_ic_tag_check_value(value, b, y),
    )?;
    Ok((holder_tag, receiver_tag))
}

/// Holder-side vector information-checking tag material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssVectorHolderSideTag {
    /// Holder/intermediary whose vector is authenticated.
    pub holder: PartyId,
    /// Receiver/verifier for this tag.
    pub receiver: PartyId,
    /// Tag index within the holder/receiver pair.
    pub tag_index: u16,
    /// Holder-side randomizer vector `y`.
    pub y: Vec<ItVssFq>,
}

/// Receiver-side vector information-checking tag opened only for audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedVectorReceiverTag {
    /// Holder/intermediary whose vector is authenticated.
    pub holder: PartyId,
    /// Receiver/verifier for this tag.
    pub receiver: PartyId,
    /// Tag index within the holder/receiver pair.
    pub tag_index: u16,
    /// Receiver-side nonzero multiplier `b`.
    pub b: ItVssFq,
    /// Receiver-side check vector `c = value + b*y`.
    pub c: Vec<ItVssFq>,
    /// Marker: this tag is never retained for reconstruction.
    pub discard_after_audit: DiscardAfterAudit,
}

impl AuditedVectorReceiverTag {
    /// Builds an audited receiver vector tag.
    pub fn new(
        holder: PartyId,
        receiver: PartyId,
        tag_index: u16,
        b: ItVssFq,
        c: Vec<ItVssFq>,
    ) -> Result<Self, DkgError> {
        if b.value() == 0 {
            return Err(DkgError::Backend("zero IT-VSS IC tag multiplier"));
        }
        Ok(Self {
            holder,
            receiver,
            tag_index,
            b,
            c,
            discard_after_audit: DiscardAfterAudit,
        })
    }

    /// Verifies `c_vec = value_vec + b*y_vec`.
    pub fn verify(&self, values: &[ItVssFq], holder_tag: &ItVssVectorHolderSideTag) -> bool {
        self.holder == holder_tag.holder
            && self.receiver == holder_tag.receiver
            && self.tag_index == holder_tag.tag_index
            && self.c.len() == values.len()
            && holder_tag.y.len() == values.len()
            && self
                .c
                .iter()
                .zip(values.iter().zip(holder_tag.y.iter()))
                .all(|(c, (value, y))| *c == value.add_mod(self.b.mul_mod(*y)))
    }
}

/// Receiver-side vector information-checking tag retained for reconstruction.
///
/// As with scalar retained tags, the multiplier and check vector are
/// receiver-private forever. Publishing retained `(b,c_vec)` lets the holder
/// forge a different vector with matching `y_vec`.
#[derive(Clone, Eq, PartialEq)]
pub struct RetainedVectorReceiverTag {
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    b: ItVssFq,
    c: Vec<ItVssFq>,
    visibility: ReceiverPrivateOnly,
}

impl RetainedVectorReceiverTag {
    /// Builds a receiver-private retained vector tag.
    pub fn new_private(
        holder: PartyId,
        receiver: PartyId,
        tag_index: u16,
        b: ItVssFq,
        c: Vec<ItVssFq>,
    ) -> Result<Self, DkgError> {
        if b.value() == 0 {
            return Err(DkgError::Backend("zero IT-VSS IC tag multiplier"));
        }
        Ok(Self {
            holder,
            receiver,
            tag_index,
            b,
            c,
            visibility: ReceiverPrivateOnly,
        })
    }

    /// Holder authenticated by this retained vector tag.
    pub const fn holder(&self) -> PartyId {
        self.holder
    }

    /// Receiver that privately owns this retained vector tag.
    pub const fn receiver(&self) -> PartyId {
        self.receiver
    }

    /// Tag index within the holder/receiver pair.
    pub const fn tag_index(&self) -> u16 {
        self.tag_index
    }

    pub(crate) const fn b(&self) -> ItVssFq {
        self.b
    }

    pub(crate) fn c(&self) -> &[ItVssFq] {
        &self.c
    }

    /// Verifies `c_vec = value_vec + b*y_vec` without exposing retained
    /// receiver-side material.
    pub fn verify_private(
        &self,
        values: &[ItVssFq],
        holder_tag: &ItVssVectorHolderSideTag,
    ) -> bool {
        self.holder == holder_tag.holder
            && self.receiver == holder_tag.receiver
            && self.tag_index == holder_tag.tag_index
            && self.c.len() == values.len()
            && holder_tag.y.len() == values.len()
            && self
                .c
                .iter()
                .zip(values.iter().zip(holder_tag.y.iter()))
                .all(|(c, (value, y))| *c == value.add_mod(self.b.mul_mod(*y)))
    }
}

impl fmt::Debug for RetainedVectorReceiverTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedVectorReceiverTag")
            .field("holder", &self.holder)
            .field("receiver", &self.receiver)
            .field("tag_index", &self.tag_index)
            .field("b", &"<receiver-private>")
            .field("c", &"<receiver-private>")
            .field("len", &self.c.len())
            .field("visibility", &self.visibility)
            .finish()
    }
}

/// Computes `c_vec = values + b*y_vec` for vector information checking.
pub fn it_vss_vector_ic_tag_check_values(
    values: &[ItVssFq],
    b: ItVssFq,
    y: &[ItVssFq],
) -> Result<Vec<ItVssFq>, DkgError> {
    if values.len() != y.len() {
        return Err(DkgError::ItVssVectorLengthMismatch {
            expected: values.len(),
            got: y.len(),
        });
    }
    Ok(values
        .iter()
        .zip(y.iter())
        .map(|(value, y)| value.add_mod(b.mul_mod(*y)))
        .collect())
}

/// Builds matching holder/audited receiver vector IC tags.
pub fn it_vss_audited_vector_ic_tag_pair(
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    values: &[ItVssFq],
    b: ItVssFq,
    y: &[ItVssFq],
) -> Result<(ItVssVectorHolderSideTag, AuditedVectorReceiverTag), DkgError> {
    let holder_tag = ItVssVectorHolderSideTag {
        holder,
        receiver,
        tag_index,
        y: y.to_vec(),
    };
    let receiver_tag = AuditedVectorReceiverTag::new(
        holder,
        receiver,
        tag_index,
        b,
        it_vss_vector_ic_tag_check_values(values, b, y)?,
    )?;
    Ok((holder_tag, receiver_tag))
}

/// Builds matching holder/retained receiver vector IC tags.
pub fn it_vss_retained_vector_ic_tag_pair(
    holder: PartyId,
    receiver: PartyId,
    tag_index: u16,
    values: &[ItVssFq],
    b: ItVssFq,
    y: &[ItVssFq],
) -> Result<(ItVssVectorHolderSideTag, RetainedVectorReceiverTag), DkgError> {
    let holder_tag = ItVssVectorHolderSideTag {
        holder,
        receiver,
        tag_index,
        y: y.to_vec(),
    };
    let receiver_tag = RetainedVectorReceiverTag::new_private(
        holder,
        receiver,
        tag_index,
        b,
        it_vss_vector_ic_tag_check_values(values, b, y)?,
    )?;
    Ok((holder_tag, receiver_tag))
}

/// Public audit-phase encoding for audited receiver-side tags only.
pub fn encode_it_vss_audited_receiver_tag(tag: &AuditedReceiverTag) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tag.holder.0.to_le_bytes());
    out.extend_from_slice(&tag.receiver.0.to_le_bytes());
    out.extend_from_slice(&tag.tag_index.to_le_bytes());
    out.extend_from_slice(&tag.b.value().to_le_bytes());
    out.extend_from_slice(&tag.c.value().to_le_bytes());
    out
}

/// Public audit-phase encoding for audited vector receiver-side tags only.
pub fn encode_it_vss_audited_vector_receiver_tag(tag: &AuditedVectorReceiverTag) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tag.holder.0.to_le_bytes());
    out.extend_from_slice(&tag.receiver.0.to_le_bytes());
    out.extend_from_slice(&tag.tag_index.to_le_bytes());
    out.extend_from_slice(&tag.b.value().to_le_bytes());
    out.extend_from_slice(&(tag.c.len() as u32).to_le_bytes());
    for value in &tag.c {
        out.extend_from_slice(&value.value().to_le_bytes());
    }
    out
}

/// Private information-checking tag delivered over pairwise private channels.
#[derive(Clone, Eq, PartialEq)]
pub struct ItVssInformationTag {
    /// Party that generated the tag material.
    pub tagger: PartyId,
    /// Party expected to verify/hold the tag material.
    pub verifier: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Opaque tag bytes.
    pub tag: Vec<u8>,
}

impl fmt::Debug for ItVssInformationTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItVssInformationTag")
            .field("tagger", &self.tagger)
            .field("verifier", &self.verifier)
            .field("label_hash", &self.label_hash)
            .field("tag", &"<redacted>")
            .finish()
    }
}

/// Public information-checking tag descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssInformationCheckTagDescriptor {
    /// Dealer whose sharing is being checked.
    pub dealer: PartyId,
    /// Receiver whose directed share is being checked.
    pub receiver: PartyId,
    /// Party that generated/verifies this information-checking tag.
    pub tagger: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Commitment/hash of the private tag material.
    pub tag_hash: [u8; 32],
}

/// Public complaint evidence for one failed information-checking tag.
///
/// This evidence shape is deliberately hash/transcript based. It must not
/// carry raw private shares, raw tags, long-term seeds, or unrelated receiver
/// material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssInformationCheckComplaintEvidence {
    /// Dealer whose directed share failed.
    pub dealer: PartyId,
    /// Receiver that detected the failed check.
    pub receiver: PartyId,
    /// Tagger associated with the failed information-checking tag.
    pub tagger: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Expected public tag hash.
    pub expected_tag_hash: [u8; 32],
    /// Hash of the received share material under the complaint transcript.
    pub received_share_hash: [u8; 32],
    /// Hash of the exact directed private delivery transcript.
    pub delivery_transcript_hash: [u8; 32],
    /// Complaint transcript hash.
    pub transcript_hash: [u8; 32],
}

#[cfg(test)]
pub(crate) fn deterministic_it_vss_public_metadata_hash(
    label_hash: [u8; 32],
    dealer: PartyId,
    secret: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/deterministic-metadata");
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hash_bytes(&mut hasher, secret);
    hasher.finalize().into()
}

#[cfg(test)]
pub(crate) fn deterministic_it_vss_tag_bytes(
    seed: [u8; 32],
    label_hash: [u8; 32],
    dealer: PartyId,
    receiver: PartyId,
    tagger: PartyId,
    share: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/deterministic-tag");
    hasher.update(seed);
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update(receiver.0.to_le_bytes());
    hasher.update(tagger.0.to_le_bytes());
    hash_bytes(&mut hasher, share);
    hasher.finalize().to_vec()
}

#[cfg(test)]
pub(crate) fn production_it_vss_public_metadata_hash(
    label_hash: [u8; 32],
    dealer: PartyId,
    secret: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/production-information-checking-metadata");
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hash_bytes(&mut hasher, secret);
    hasher.finalize().into()
}

#[cfg(test)]
pub(crate) fn production_it_vss_tag_bytes(
    label_hash: [u8; 32],
    dealer: PartyId,
    receiver: PartyId,
    tagger: PartyId,
    share: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/production-information-checking-tag");
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update(receiver.0.to_le_bytes());
    hasher.update(tagger.0.to_le_bytes());
    hash_bytes(&mut hasher, share);
    hasher.finalize().to_vec()
}

pub(crate) fn hash_it_vss_tag(tag: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/tag-hash");
    hash_bytes(&mut hasher, tag);
    hasher.finalize().into()
}

pub(crate) fn hash_it_vss_received_share(
    label_hash: [u8; 32],
    dealer: PartyId,
    receiver: PartyId,
    share: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/received-share-hash");
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update(receiver.0.to_le_bytes());
    hash_bytes(&mut hasher, share);
    hasher.finalize().into()
}

/// Public transcript hash for one directed IT-VSS private delivery.
///
/// This commits complaint evidence to the exact accepted directed delivery
/// without making the private share or raw information-checking tags public.
pub fn hash_it_vss_private_delivery_transcript(delivery: &ItVssPrivateShareDelivery) -> [u8; 32] {
    let mut tags = delivery
        .information_tags
        .iter()
        .map(|tag| {
            let mut hasher = Sha3_256::new();
            hasher.update(b"TALUS-DKG-IT-VSS-v1/private-delivery/tag");
            hasher.update(tag.tagger.0.to_le_bytes());
            hasher.update(tag.verifier.0.to_le_bytes());
            hasher.update(tag.label_hash);
            hasher.update(hash_it_vss_tag(&tag.tag));
            hasher.finalize().into()
        })
        .collect::<Vec<[u8; 32]>>();
    tags.sort();
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/private-delivery/transcript");
    hasher.update(delivery.dealer.0.to_le_bytes());
    hasher.update(delivery.receiver.0.to_le_bytes());
    hasher.update(delivery.label_hash);
    hash_bytes(&mut hasher, &delivery.share);
    hasher.update((tags.len() as u32).to_le_bytes());
    for tag_hash in tags {
        hasher.update(tag_hash);
    }
    hasher.finalize().into()
}

pub(crate) fn transcript_hash_it_vss_information_check_complaint(
    expected_tag_hash: [u8; 32],
    received_share_hash: [u8; 32],
    delivery_transcript_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/information-check-complaint");
    hasher.update(expected_tag_hash);
    hasher.update(received_share_hash);
    hasher.update(delivery_transcript_hash);
    hasher.finalize().into()
}

/// Canonically encodes public information-checking complaint evidence.
pub fn encode_it_vss_information_check_complaint_evidence(
    evidence: &ItVssInformationCheckComplaintEvidence,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&evidence.dealer.0.to_le_bytes());
    out.extend_from_slice(&evidence.receiver.0.to_le_bytes());
    out.extend_from_slice(&evidence.tagger.0.to_le_bytes());
    out.extend_from_slice(&evidence.label_hash);
    out.extend_from_slice(&evidence.expected_tag_hash);
    out.extend_from_slice(&evidence.received_share_hash);
    out.extend_from_slice(&evidence.delivery_transcript_hash);
    out.extend_from_slice(&evidence.transcript_hash);
    out
}

/// Decodes public information-checking complaint evidence.
pub fn decode_it_vss_information_check_complaint_evidence(
    bytes: &[u8],
) -> Result<ItVssInformationCheckComplaintEvidence, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    let dealer = PartyId(cursor.read_u16()?);
    let receiver = PartyId(cursor.read_u16()?);
    let tagger = PartyId(cursor.read_u16()?);
    let mut label_hash = [0u8; 32];
    label_hash.copy_from_slice(cursor.read_exact(32)?);
    let mut expected_tag_hash = [0u8; 32];
    expected_tag_hash.copy_from_slice(cursor.read_exact(32)?);
    let mut received_share_hash = [0u8; 32];
    received_share_hash.copy_from_slice(cursor.read_exact(32)?);
    let mut delivery_transcript_hash = [0u8; 32];
    delivery_transcript_hash.copy_from_slice(cursor.read_exact(32)?);
    let mut transcript_hash = [0u8; 32];
    transcript_hash.copy_from_slice(cursor.read_exact(32)?);
    cursor.finish()?;
    Ok(ItVssInformationCheckComplaintEvidence {
        dealer,
        receiver,
        tagger,
        label_hash,
        expected_tag_hash,
        received_share_hash,
        delivery_transcript_hash,
        transcript_hash,
    })
}

/// Validates the public shape of an IT-VSS information-checking complaint.
pub fn validate_it_vss_information_check_complaint_evidence(
    config: &DkgConfig,
    commitment: &ItVssPublicCommitment,
    evidence: &ItVssInformationCheckComplaintEvidence,
) -> Result<(), DkgError> {
    config.validate()?;
    for party in [evidence.dealer, evidence.receiver, evidence.tagger] {
        if !config.parties.contains(&party) {
            return Err(DkgError::UnknownParty(party));
        }
    }
    if commitment.dealer != evidence.dealer || commitment.label_hash != evidence.label_hash {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    if evidence.expected_tag_hash == [0u8; 32]
        || evidence.received_share_hash == [0u8; 32]
        || evidence.delivery_transcript_hash == [0u8; 32]
        || evidence.transcript_hash == [0u8; 32]
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    if evidence.transcript_hash
        != transcript_hash_it_vss_information_check_complaint(
            evidence.expected_tag_hash,
            evidence.received_share_hash,
            evidence.delivery_transcript_hash,
        )
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    Ok(())
}

/// Validates complaint evidence against the public commitment and the exact
/// directed private delivery recovered from the setup log.
pub fn validate_it_vss_information_check_complaint_evidence_for_delivery(
    config: &DkgConfig,
    commitment: &ItVssPublicCommitment,
    delivery: &ItVssPrivateShareDelivery,
    evidence: &ItVssInformationCheckComplaintEvidence,
) -> Result<(), DkgError> {
    validate_it_vss_information_check_complaint_evidence(config, commitment, evidence)?;
    if delivery.dealer != evidence.dealer
        || delivery.receiver != evidence.receiver
        || delivery.label_hash != evidence.label_hash
        || evidence.received_share_hash
            != hash_it_vss_received_share(
                delivery.label_hash,
                delivery.dealer,
                delivery.receiver,
                &delivery.share,
            )
        || evidence.delivery_transcript_hash != hash_it_vss_private_delivery_transcript(delivery)
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    Ok(())
}

/// Public commitment/metadata for one IT-VSS sharing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssPublicCommitment {
    /// Backend that produced this commitment.
    pub backend_id: ItVssBackendId,
    /// Dealer creating the sharing.
    pub dealer: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Public metadata hash. This is not a Feldman/Pedersen commitment.
    pub public_metadata_hash: [u8; 32],
}

/// Public precommitment for one production IT-VSS sharing. This is broadcast
/// before public coins are collected and before final metadata exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssPublicPrecommitment {
    /// Backend that produced this precommitment.
    pub backend_id: ItVssBackendId,
    /// Dealer creating the sharing.
    pub dealer: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Hash binding the prepared private deliveries without revealing them.
    pub public_precommitment_hash: [u8; 32],
}

/// Directed private share delivery for one production IT-VSS sharing.
#[derive(Clone, Eq, PartialEq)]
pub struct ItVssPrivateShareDelivery {
    /// Dealer that sent the share.
    pub dealer: PartyId,
    /// Receiver that owns the share.
    pub receiver: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Opaque encoded private share.
    pub share: Vec<u8>,
    /// Information-checking tags needed to verify this delivery.
    pub information_tags: Vec<ItVssInformationTag>,
}

impl fmt::Debug for ItVssPrivateShareDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItVssPrivateShareDelivery")
            .field("dealer", &self.dealer)
            .field("receiver", &self.receiver)
            .field("label_hash", &self.label_hash)
            .field("share", &"<redacted>")
            .field("information_tags", &self.information_tags.len())
            .finish()
    }
}

/// Canonically encodes one directed IT-VSS private delivery for the crate's
/// transport-shaped setup driver. The bytes are still private-channel payload
/// material and must not be broadcast or logged as public artifacts.
pub fn encode_it_vss_private_share_delivery(delivery: &ItVssPrivateShareDelivery) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IT_VSS_PRIVATE_DELIVERY_MAGIC);
    out.extend_from_slice(&delivery.dealer.0.to_le_bytes());
    out.extend_from_slice(&delivery.receiver.0.to_le_bytes());
    out.extend_from_slice(&delivery.label_hash);
    out.extend_from_slice(&(delivery.share.len() as u32).to_le_bytes());
    out.extend_from_slice(&delivery.share);
    out.extend_from_slice(&(delivery.information_tags.len() as u32).to_le_bytes());
    for tag in &delivery.information_tags {
        out.extend_from_slice(&tag.tagger.0.to_le_bytes());
        out.extend_from_slice(&tag.verifier.0.to_le_bytes());
        out.extend_from_slice(&tag.label_hash);
        out.extend_from_slice(&(tag.tag.len() as u32).to_le_bytes());
        out.extend_from_slice(&tag.tag);
    }
    out
}

/// Decodes one directed IT-VSS private delivery.
pub fn decode_it_vss_private_share_delivery(
    bytes: &[u8],
) -> Result<ItVssPrivateShareDelivery, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(IT_VSS_PRIVATE_DELIVERY_MAGIC)?;
    let dealer = PartyId(cursor.read_u16()?);
    let receiver = PartyId(cursor.read_u16()?);
    let mut label_hash = [0u8; 32];
    label_hash.copy_from_slice(cursor.read_exact(32)?);
    let share_len = cursor.read_u32()? as usize;
    let share = cursor.read_exact(share_len)?.to_vec();
    let tag_len = cursor.read_u32()? as usize;
    let mut information_tags = Vec::with_capacity(tag_len);
    for _ in 0..tag_len {
        let tagger = PartyId(cursor.read_u16()?);
        let verifier = PartyId(cursor.read_u16()?);
        let mut tag_label_hash = [0u8; 32];
        tag_label_hash.copy_from_slice(cursor.read_exact(32)?);
        let private_tag_len = cursor.read_u32()? as usize;
        let tag = cursor.read_exact(private_tag_len)?.to_vec();
        information_tags.push(ItVssInformationTag {
            tagger,
            verifier,
            label_hash: tag_label_hash,
            tag,
        });
    }
    cursor.finish()?;
    Ok(ItVssPrivateShareDelivery {
        dealer,
        receiver,
        label_hash,
        share,
        information_tags,
    })
}

/// Canonically encodes a batch of directed IT-VSS private deliveries for one
/// receiver. The batch remains private-channel material.
pub fn encode_it_vss_private_share_delivery_batch(
    deliveries: &[ItVssPrivateShareDelivery],
) -> Result<Vec<u8>, DkgError> {
    let Some(first) = deliveries.first() else {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 1,
            got: 0,
        });
    };
    for delivery in deliveries {
        if delivery.dealer != first.dealer || delivery.receiver != first.receiver {
            return Err(DkgError::PartyMismatch {
                expected: first.receiver,
                got: delivery.receiver,
            });
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(IT_VSS_PRIVATE_DELIVERY_BATCH_MAGIC);
    out.extend_from_slice(&(deliveries.len() as u32).to_le_bytes());
    for delivery in deliveries {
        let encoded = encode_it_vss_private_share_delivery(delivery);
        out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        out.extend_from_slice(&encoded);
    }
    Ok(out)
}

/// Decodes a batch of directed IT-VSS private deliveries.
pub fn decode_it_vss_private_share_delivery_batch(
    bytes: &[u8],
) -> Result<Vec<ItVssPrivateShareDelivery>, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(IT_VSS_PRIVATE_DELIVERY_BATCH_MAGIC)?;
    let len = cursor.read_u32()? as usize;
    let mut deliveries = Vec::with_capacity(len);
    for _ in 0..len {
        let encoded_len = cursor.read_u32()? as usize;
        deliveries.push(decode_it_vss_private_share_delivery(
            cursor.read_exact(encoded_len)?,
        )?);
    }
    cursor.finish()?;
    if deliveries.is_empty() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 1,
            got: 0,
        });
    }
    Ok(deliveries)
}

pub(crate) fn hash_it_vss_private_delivery_batch(
    deliveries: &[ItVssPrivateShareDelivery],
) -> [u8; 32] {
    let mut hashes = deliveries
        .iter()
        .map(hash_it_vss_private_delivery_transcript)
        .collect::<Vec<_>>();
    hashes.sort();
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/private-delivery-batch/transcript");
    hasher.update((hashes.len() as u32).to_le_bytes());
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

/// Wraps a directed IT-VSS delivery in the setup private-share wire payload.
pub fn dkg_share_payload_from_it_vss_private_delivery(
    delivery: &ItVssPrivateShareDelivery,
) -> DkgSharePayload {
    DkgSharePayload {
        dealer: delivery.dealer,
        receiver: delivery.receiver,
        encrypted_share: encode_it_vss_private_share_delivery(delivery),
        encrypted_seed_share: Vec::new(),
        proof: hash_it_vss_private_delivery_transcript(delivery).to_vec(),
    }
}

/// Wraps a batch of directed IT-VSS deliveries for one receiver in the setup
/// private-share wire payload.
pub fn dkg_share_payload_from_it_vss_private_delivery_batch(
    deliveries: &[ItVssPrivateShareDelivery],
) -> Result<DkgSharePayload, DkgError> {
    let Some(first) = deliveries.first() else {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 1,
            got: 0,
        });
    };
    let encrypted_share = encode_it_vss_private_share_delivery_batch(deliveries)?;
    Ok(DkgSharePayload {
        dealer: first.dealer,
        receiver: first.receiver,
        encrypted_share,
        encrypted_seed_share: Vec::new(),
        proof: hash_it_vss_private_delivery_batch(deliveries).to_vec(),
    })
}

/// Extracts a directed IT-VSS delivery from a setup private-share wire payload
/// and validates the public transcript binding in `proof`.
pub fn it_vss_private_delivery_from_dkg_share(
    payload: &DkgSharePayload,
) -> Result<ItVssPrivateShareDelivery, DkgError> {
    let delivery = decode_it_vss_private_share_delivery(&payload.encrypted_share)?;
    let expected_proof = hash_it_vss_private_delivery_transcript(&delivery);
    if payload.dealer != delivery.dealer
        || payload.receiver != delivery.receiver
        || payload.proof != expected_proof
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    Ok(delivery)
}

/// Extracts one or more directed IT-VSS deliveries from a setup private-share
/// wire payload and validates the transcript binding in `proof`.
pub fn it_vss_private_deliveries_from_dkg_share(
    payload: &DkgSharePayload,
) -> Result<Vec<ItVssPrivateShareDelivery>, DkgError> {
    if let Ok(delivery) = it_vss_private_delivery_from_dkg_share(payload) {
        return Ok(vec![delivery]);
    }
    let deliveries = decode_it_vss_private_share_delivery_batch(&payload.encrypted_share)?;
    if deliveries
        .iter()
        .any(|delivery| delivery.dealer != payload.dealer || delivery.receiver != payload.receiver)
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    if payload.proof != hash_it_vss_private_delivery_batch(&deliveries) {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    Ok(deliveries)
}

/// Dealer output for one IT-VSS sharing instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssDealerOutput {
    /// Public commitment/metadata broadcast by the dealer.
    pub public_commitment: ItVssPublicCommitment,
    /// Directed private deliveries, one per configured receiver.
    pub deliveries: Vec<ItVssPrivateShareDelivery>,
}

/// Prepared production IT-VSS output before public consistency coins exist.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionItVssPreparedDealerOutput {
    /// Public precommitment broadcast before public coins.
    pub public_precommitment: ItVssPublicPrecommitment,
    /// Directed private deliveries prepared for this sharing.
    pub deliveries: Vec<ItVssPrivateShareDelivery>,
    vector_len: usize,
}

/// Public certificate that one IT-VSS sharing was verified or resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedItVssSharingCertificate {
    /// Backend that produced this certificate.
    pub backend_id: ItVssBackendId,
    /// Dealer whose sharing is certified.
    pub dealer: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Receivers whose shares survived verification/complaint resolution.
    pub accepted_receivers: Vec<PartyId>,
    /// Hash of public complaints used in resolution.
    pub complaint_hash: [u8; 32],
    /// Public transcript hash for the verified sharing.
    pub transcript_hash: [u8; 32],
}

/// Resolution result for production IT-VSS complaint processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssComplaintResolution {
    /// Dealers whose sharing certificates survived.
    pub accepted_dealers: Vec<PartyId>,
    /// Dealers rejected by valid complaints.
    pub rejected_dealers: Vec<PartyId>,
    /// Public complaint evidence included in the decision.
    pub complaints: Vec<DkgComplaintPayload>,
    /// Verified sharing certificates for accepted dealers.
    pub certificates: Vec<VerifiedItVssSharingCertificate>,
}

/// Canonical hash for one production IT-VSS public commitment.
pub fn hash_it_vss_public_commitment(commitment: &ItVssPublicCommitment) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-commitment");
    hasher.update([commitment.backend_id.as_u8()]);
    hasher.update(commitment.dealer.0.to_le_bytes());
    hasher.update(commitment.label_hash);
    hasher.update(commitment.public_metadata_hash);
    hasher.finalize().into()
}

/// Canonical hash for one production IT-VSS public precommitment.
pub fn hash_it_vss_public_precommitment(precommitment: &ItVssPublicPrecommitment) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-precommitment");
    hasher.update([precommitment.backend_id.as_u8()]);
    hasher.update(precommitment.dealer.0.to_le_bytes());
    hasher.update(precommitment.label_hash);
    hasher.update(precommitment.public_precommitment_hash);
    hasher.finalize().into()
}

/// Canonical hash for one verified IT-VSS sharing certificate.
pub fn hash_verified_it_vss_sharing_certificate(
    certificate: &VerifiedItVssSharingCertificate,
) -> [u8; 32] {
    let mut accepted_receivers = certificate.accepted_receivers.clone();
    accepted_receivers.sort_by_key(|party| party.0);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/verified-sharing-certificate");
    hasher.update([certificate.backend_id.as_u8()]);
    hasher.update(certificate.dealer.0.to_le_bytes());
    hasher.update(certificate.label_hash);
    hasher.update((accepted_receivers.len() as u32).to_le_bytes());
    for receiver in accepted_receivers {
        hasher.update(receiver.0.to_le_bytes());
    }
    hasher.update(certificate.complaint_hash);
    hasher.update(certificate.transcript_hash);
    hasher.finalize().into()
}

/// Canonical hash for a production IT-VSS complaint-resolution result.
pub fn hash_it_vss_complaint_resolution(resolution: &ItVssComplaintResolution) -> [u8; 32] {
    let mut accepted_dealers = resolution.accepted_dealers.clone();
    accepted_dealers.sort_by_key(|party| party.0);
    let mut rejected_dealers = resolution.rejected_dealers.clone();
    rejected_dealers.sort_by_key(|party| party.0);
    let mut certificate_hashes = resolution
        .certificates
        .iter()
        .map(hash_verified_it_vss_sharing_certificate)
        .collect::<Vec<_>>();
    certificate_hashes.sort();

    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/complaint-resolution");
    hasher.update((accepted_dealers.len() as u32).to_le_bytes());
    for dealer in accepted_dealers {
        hasher.update(dealer.0.to_le_bytes());
    }
    hasher.update((rejected_dealers.len() as u32).to_le_bytes());
    for dealer in rejected_dealers {
        hasher.update(dealer.0.to_le_bytes());
    }
    hasher.update(hash_dkg_complaint_payloads(&resolution.complaints));
    hasher.update((certificate_hashes.len() as u32).to_le_bytes());
    for certificate_hash in certificate_hashes {
        hasher.update(certificate_hash);
    }
    hasher.finalize().into()
}

pub(crate) fn wire_it_vss_public_commitment(
    commitment: &ItVssPublicCommitment,
) -> DkgItVssPublicCommitmentPayload {
    DkgItVssPublicCommitmentPayload {
        backend_id: commitment.backend_id.as_u8(),
        dealer_party_id: commitment.dealer.0,
        label_hash: commitment.label_hash,
        public_metadata_hash: commitment.public_metadata_hash,
    }
}

pub(crate) fn it_vss_public_commitment_from_wire(
    payload: &DkgItVssPublicCommitmentPayload,
) -> Result<ItVssPublicCommitment, DkgError> {
    Ok(ItVssPublicCommitment {
        backend_id: ItVssBackendId::from_u8(payload.backend_id)
            .ok_or(DkgError::ItVssCertificateBackendMismatch)?,
        dealer: PartyId(payload.dealer_party_id),
        label_hash: payload.label_hash,
        public_metadata_hash: payload.public_metadata_hash,
    })
}

pub(crate) fn wire_it_vss_public_precommitment(
    precommitment: &ItVssPublicPrecommitment,
) -> DkgItVssPublicPrecommitmentPayload {
    DkgItVssPublicPrecommitmentPayload {
        backend_id: precommitment.backend_id.as_u8(),
        dealer_party_id: precommitment.dealer.0,
        label_hash: precommitment.label_hash,
        public_precommitment_hash: precommitment.public_precommitment_hash,
    }
}

pub(crate) fn it_vss_public_precommitment_from_wire(
    payload: &DkgItVssPublicPrecommitmentPayload,
) -> Result<ItVssPublicPrecommitment, DkgError> {
    Ok(ItVssPublicPrecommitment {
        backend_id: ItVssBackendId::from_u8(payload.backend_id)
            .ok_or(DkgError::ItVssCertificateBackendMismatch)?,
        dealer: PartyId(payload.dealer_party_id),
        label_hash: payload.label_hash,
        public_precommitment_hash: payload.public_precommitment_hash,
    })
}

pub(crate) fn wire_it_vss_public_coin_share(
    share: &ProductionItVssPublicCoinShare,
) -> DkgItVssPublicCoinSharePayload {
    DkgItVssPublicCoinSharePayload {
        party_id: share.party.0,
        label_hash: share.label_hash,
        coin: share.coin,
        transcript_hash: share.transcript_hash,
    }
}

pub(crate) fn it_vss_public_coin_share_from_wire(
    payload: &DkgItVssPublicCoinSharePayload,
) -> ProductionItVssPublicCoinShare {
    ProductionItVssPublicCoinShare {
        party: PartyId(payload.party_id),
        label_hash: payload.label_hash,
        coin: payload.coin,
        transcript_hash: payload.transcript_hash,
    }
}

pub(crate) fn wire_it_vss_certificate(
    certificate: &VerifiedItVssSharingCertificate,
) -> DkgItVssCertificatePayload {
    DkgItVssCertificatePayload {
        backend_id: certificate.backend_id.as_u8(),
        dealer_party_id: certificate.dealer.0,
        label_hash: certificate.label_hash,
        accepted_receivers: certificate
            .accepted_receivers
            .iter()
            .map(|party| party.0)
            .collect(),
        complaint_hash: certificate.complaint_hash,
        transcript_hash: certificate.transcript_hash,
    }
}

pub(crate) fn it_vss_certificate_from_wire(
    payload: &DkgItVssCertificatePayload,
) -> Result<VerifiedItVssSharingCertificate, DkgError> {
    Ok(VerifiedItVssSharingCertificate {
        backend_id: ItVssBackendId::from_u8(payload.backend_id)
            .ok_or(DkgError::ItVssCertificateBackendMismatch)?,
        dealer: PartyId(payload.dealer_party_id),
        label_hash: payload.label_hash,
        accepted_receivers: payload
            .accepted_receivers
            .iter()
            .copied()
            .map(PartyId)
            .collect(),
        complaint_hash: payload.complaint_hash,
        transcript_hash: payload.transcript_hash,
    })
}

pub(crate) fn wire_it_vss_resolution(
    resolution: &ItVssComplaintResolution,
) -> DkgItVssResolutionPayload {
    DkgItVssResolutionPayload {
        accepted_dealers: resolution
            .accepted_dealers
            .iter()
            .map(|party| party.0)
            .collect(),
        rejected_dealers: resolution
            .rejected_dealers
            .iter()
            .map(|party| party.0)
            .collect(),
        complaints: resolution
            .complaints
            .iter()
            .map(|complaint| DkgItVssComplaintPayload {
                complainant_party_id: complaint.complainant.0,
                dealer_party_id: complaint.dealer.0,
                receiver_party_id: complaint.receiver.0,
                reason_code: complaint.reason.as_u8() as u16,
                evidence: complaint.evidence.clone(),
            })
            .collect(),
        certificates: resolution
            .certificates
            .iter()
            .map(wire_it_vss_certificate)
            .collect(),
    }
}

pub(crate) fn it_vss_resolution_from_wire(
    payload: &DkgItVssResolutionPayload,
) -> Result<ItVssComplaintResolution, DkgError> {
    let mut complaints = Vec::with_capacity(payload.complaints.len());
    for complaint in &payload.complaints {
        let reason = match complaint.reason_code {
            1 => DkgComplaintReason::InvalidVssShare,
            2 => DkgComplaintReason::InvalidPairwiseSeed,
            3 => DkgComplaintReason::MissingShare,
            255 => DkgComplaintReason::Backend,
            _ => return Err(DkgError::PrimeFieldMpcTransport),
        };
        complaints.push(DkgComplaintPayload {
            complainant: PartyId(complaint.complainant_party_id),
            dealer: PartyId(complaint.dealer_party_id),
            receiver: PartyId(complaint.receiver_party_id),
            reason,
            evidence: complaint.evidence.clone(),
        });
    }
    Ok(ItVssComplaintResolution {
        accepted_dealers: payload
            .accepted_dealers
            .iter()
            .copied()
            .map(PartyId)
            .collect(),
        rejected_dealers: payload
            .rejected_dealers
            .iter()
            .copied()
            .map(PartyId)
            .collect(),
        complaints,
        certificates: payload
            .certificates
            .iter()
            .map(it_vss_certificate_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Canonically encodes one IT-VSS public commitment artifact.
pub fn encode_it_vss_public_commitment_artifact(commitment: &ItVssPublicCommitment) -> Vec<u8> {
    wire_encode_dkg_it_vss_artifact_payload(&DkgItVssArtifactPayload::PublicCommitment(
        wire_it_vss_public_commitment(commitment),
    ))
}

/// Canonically encodes one IT-VSS public precommitment artifact.
pub fn encode_it_vss_public_precommitment_artifact(
    precommitment: &ItVssPublicPrecommitment,
) -> Vec<u8> {
    wire_encode_dkg_it_vss_artifact_payload(&DkgItVssArtifactPayload::PublicPrecommitment(
        wire_it_vss_public_precommitment(precommitment),
    ))
}

/// Canonically encodes a batch of IT-VSS public commitment artifacts.
pub fn encode_it_vss_public_commitment_batch_artifact(
    commitments: &[ItVssPublicCommitment],
) -> Vec<u8> {
    wire_encode_dkg_it_vss_artifact_payload(&DkgItVssArtifactPayload::PublicCommitmentBatch(
        commitments
            .iter()
            .map(wire_it_vss_public_commitment)
            .collect(),
    ))
}

/// Canonically encodes one IT-VSS public-coin share artifact.
pub fn encode_it_vss_public_coin_share_artifact(share: &ProductionItVssPublicCoinShare) -> Vec<u8> {
    wire_encode_dkg_it_vss_artifact_payload(&DkgItVssArtifactPayload::PublicCoinShare(
        wire_it_vss_public_coin_share(share),
    ))
}

/// Decodes one IT-VSS public-coin share artifact.
pub fn decode_it_vss_public_coin_share_artifact(
    bytes: &[u8],
) -> Result<ProductionItVssPublicCoinShare, DkgError> {
    match wire_decode_dkg_it_vss_artifact_payload(bytes)
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?
    {
        DkgItVssArtifactPayload::PublicCoinShare(share) => {
            Ok(it_vss_public_coin_share_from_wire(&share))
        }
        DkgItVssArtifactPayload::PublicCommitment(_)
        | DkgItVssArtifactPayload::PublicPrecommitment(_)
        | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
        | DkgItVssArtifactPayload::ComplaintResolution(_) => Err(DkgError::PrimeFieldMpcTransport),
    }
}

/// Decodes one IT-VSS public commitment artifact.
pub fn decode_it_vss_public_commitment_artifact(
    bytes: &[u8],
) -> Result<ItVssPublicCommitment, DkgError> {
    match wire_decode_dkg_it_vss_artifact_payload(bytes)
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?
    {
        DkgItVssArtifactPayload::PublicCommitment(commitment) => {
            it_vss_public_commitment_from_wire(&commitment)
        }
        DkgItVssArtifactPayload::PublicPrecommitment(_)
        | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
        | DkgItVssArtifactPayload::PublicCoinShare(_)
        | DkgItVssArtifactPayload::ComplaintResolution(_) => Err(DkgError::PrimeFieldMpcTransport),
    }
}

/// Decodes one IT-VSS public precommitment artifact.
pub fn decode_it_vss_public_precommitment_artifact(
    bytes: &[u8],
) -> Result<ItVssPublicPrecommitment, DkgError> {
    match wire_decode_dkg_it_vss_artifact_payload(bytes)
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?
    {
        DkgItVssArtifactPayload::PublicPrecommitment(precommitment) => {
            it_vss_public_precommitment_from_wire(&precommitment)
        }
        DkgItVssArtifactPayload::PublicCommitment(_)
        | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
        | DkgItVssArtifactPayload::PublicCoinShare(_)
        | DkgItVssArtifactPayload::ComplaintResolution(_) => Err(DkgError::PrimeFieldMpcTransport),
    }
}

/// Canonically encodes one IT-VSS complaint-resolution artifact.
pub fn encode_it_vss_complaint_resolution_artifact(
    resolution: &ItVssComplaintResolution,
) -> Vec<u8> {
    wire_encode_dkg_it_vss_artifact_payload(&DkgItVssArtifactPayload::ComplaintResolution(
        wire_it_vss_resolution(resolution),
    ))
}

/// Decodes one IT-VSS complaint-resolution artifact.
pub fn decode_it_vss_complaint_resolution_artifact(
    bytes: &[u8],
) -> Result<ItVssComplaintResolution, DkgError> {
    match wire_decode_dkg_it_vss_artifact_payload(bytes)
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?
    {
        DkgItVssArtifactPayload::PublicCommitment(_)
        | DkgItVssArtifactPayload::PublicPrecommitment(_)
        | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
        | DkgItVssArtifactPayload::PublicCoinShare(_) => Err(DkgError::PrimeFieldMpcTransport),
        DkgItVssArtifactPayload::ComplaintResolution(resolution) => {
            it_vss_resolution_from_wire(&resolution)
        }
    }
}

/// Validates public complaint-resolution shape before an IT-VSS result is used
/// by bounded sampling or DKG key assembly.
pub fn validate_it_vss_complaint_resolution(
    config: &DkgConfig,
    public_commitments: &[ItVssPublicCommitment],
    resolution: &ItVssComplaintResolution,
) -> Result<(), DkgError> {
    validate_it_vss_complaint_resolution_for_backend(
        config,
        public_commitments,
        resolution,
        ItVssBackendId::ProductionInformationChecking,
    )
}

pub(crate) fn validate_it_vss_complaint_resolution_for_backend(
    config: &DkgConfig,
    public_commitments: &[ItVssPublicCommitment],
    resolution: &ItVssComplaintResolution,
    allowed_backend: ItVssBackendId,
) -> Result<(), DkgError> {
    config.validate()?;
    validate_accepted_dealer_subset(config, &resolution.accepted_dealers)?;
    validate_dealer_subset(config, DkgRound::Complaint, &resolution.rejected_dealers)?;

    for &dealer in &resolution.accepted_dealers {
        if resolution.rejected_dealers.contains(&dealer) {
            return Err(DkgError::ItVssResolutionDealerOverlap { dealer });
        }
    }

    let mut commitment_keys = Vec::with_capacity(public_commitments.len());
    for commitment in public_commitments {
        if !config.parties.contains(&commitment.dealer) {
            return Err(DkgError::UnknownParty(commitment.dealer));
        }
        if commitment.backend_id != allowed_backend {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        let key = (commitment.dealer, commitment.label_hash);
        if commitment_keys.contains(&key) {
            return Err(DkgError::DuplicateItVssPublicCommitment {
                dealer: commitment.dealer,
                label_hash: commitment.label_hash,
            });
        }
        commitment_keys.push(key);
    }

    let complaint_hash = hash_dkg_complaint_payloads(&resolution.complaints);
    let mut certificate_keys = Vec::with_capacity(resolution.certificates.len());
    for certificate in &resolution.certificates {
        if !config.parties.contains(&certificate.dealer) {
            return Err(DkgError::UnknownParty(certificate.dealer));
        }
        if !resolution.accepted_dealers.contains(&certificate.dealer) {
            return Err(DkgError::ItVssResolutionUnexpectedCertificate {
                dealer: certificate.dealer,
            });
        }
        if resolution.rejected_dealers.contains(&certificate.dealer) {
            return Err(DkgError::ItVssResolutionDealerOverlap {
                dealer: certificate.dealer,
            });
        }
        if certificate.backend_id != allowed_backend {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        if certificate.complaint_hash != complaint_hash {
            return Err(DkgError::ItVssCertificateComplaintHashMismatch);
        }
        validate_exact_party_set(
            config,
            DkgRound::Share,
            certificate.accepted_receivers.iter().copied(),
        )?;
        let key = (certificate.dealer, certificate.label_hash);
        if certificate_keys.contains(&key) {
            return Err(DkgError::DuplicateItVssCertificate {
                dealer: certificate.dealer,
                label_hash: certificate.label_hash,
            });
        }
        if !commitment_keys.contains(&key) {
            return Err(DkgError::ItVssCertificateMissingCommitment {
                dealer: certificate.dealer,
                label_hash: certificate.label_hash,
            });
        }
        certificate_keys.push(key);
    }

    for &dealer in &resolution.accepted_dealers {
        if !resolution
            .certificates
            .iter()
            .any(|certificate| certificate.dealer == dealer)
        {
            return Err(DkgError::ItVssResolutionMissingCertificate { dealer });
        }
    }

    Ok(())
}

/// Validates that public complaint evidence is bound to both the persisted
/// public commitment and the accepted directed private delivery transcript.
pub fn validate_it_vss_complaints_against_private_deliveries(
    config: &DkgConfig,
    public_commitments: &[ItVssPublicCommitment],
    deliveries: &[ItVssPrivateShareDelivery],
    complaints: &[DkgComplaintPayload],
) -> Result<(), DkgError> {
    for complaint in complaints {
        if complaint.reason != DkgComplaintReason::InvalidVssShare {
            return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
        }
        let evidence = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)?;
        let commitment = public_commitments
            .iter()
            .find(|commitment| {
                commitment.dealer == complaint.dealer
                    && commitment.label_hash == evidence.label_hash
            })
            .ok_or(DkgError::ItVssCertificateMissingCommitment {
                dealer: complaint.dealer,
                label_hash: evidence.label_hash,
            })?;
        let delivery = deliveries
            .iter()
            .find(|delivery| {
                delivery.dealer == complaint.dealer
                    && delivery.receiver == complaint.receiver
                    && delivery.label_hash == evidence.label_hash
            })
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        validate_it_vss_information_check_complaint_evidence_for_delivery(
            config, commitment, delivery, &evidence,
        )?;
    }
    Ok(())
}

/// Verifies the local receiver's directed IT-VSS deliveries and builds public
/// complaints for invalid deliveries through the selected IT-VSS backend.
///
/// This is the per-party private-delivery verification phase used by the
/// transport-shaped DKG driver. It never opens unrelated deliveries or raw
/// shares; complaint payloads contain only hash-bound evidence.
pub fn verify_it_vss_private_deliveries_for_receiver<P, B>(
    backend: &B,
    config: &DkgConfig,
    receiver: PartyId,
    public_commitments: &[ItVssPublicCommitment],
    deliveries: &[ItVssPrivateShareDelivery],
) -> Result<Vec<DkgComplaintPayload>, DkgError>
where
    P: MlDsaParams,
    B: ProductionItVssBackend,
{
    config.validate()?;
    if !config.parties.contains(&receiver) {
        return Err(DkgError::UnknownParty(receiver));
    }
    let mut seen = Vec::new();
    let mut complaints = Vec::new();
    for delivery in deliveries {
        if delivery.receiver != receiver {
            return Err(DkgError::PartyMismatch {
                expected: receiver,
                got: delivery.receiver,
            });
        }
        if !config.parties.contains(&delivery.dealer) {
            return Err(DkgError::UnknownParty(delivery.dealer));
        }
        let key = (delivery.dealer, delivery.label_hash);
        if seen.contains(&key) {
            return Err(DkgError::DuplicateShare {
                dealer: delivery.dealer,
                receiver,
            });
        }
        seen.push(key);
        let commitment = public_commitments
            .iter()
            .find(|commitment| {
                commitment.dealer == delivery.dealer
                    && commitment.label_hash == delivery.label_hash
                    && commitment.backend_id == backend.backend_id()
            })
            .ok_or(DkgError::ItVssCertificateMissingCommitment {
                dealer: delivery.dealer,
                label_hash: delivery.label_hash,
            })?;
        if backend
            .verify_private_delivery::<P>(config, commitment, delivery)
            .is_err()
        {
            complaints
                .push(backend.complaint_for_invalid_delivery::<P>(config, commitment, delivery)?);
        }
    }
    Ok(complaints)
}

/// Production boundary for Rabin-Ben-Or-style information-checking IT-VSS.
///
/// The concrete v1 instantiation is pinned in
/// `docs/it-vss-rabin-ben-or.md`. Implementations must keep retained
/// receiver-side information-checking tags receiver-private, must not reveal
/// `beta_i` share points for liveness in v1, and must distinguish objective
/// public blame evidence from conservative abort-without-blame failures.
pub trait ProductionItVssBackend {
    /// Returns backend identity.
    fn backend_id(&self) -> ItVssBackendId;

    /// Creates one dealer sharing with public metadata and private deliveries.
    fn share_secret<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: ItVssSharingLabel,
        secret: &[u8],
    ) -> Result<ItVssDealerOutput, DkgError>;

    /// Verifies one directed private delivery without opening unrelated shares.
    fn verify_private_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<(), DkgError>;

    /// Builds a public complaint for a failed private delivery.
    fn complaint_for_invalid_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgComplaintPayload, DkgError>;

    /// Resolves public complaints into accepted/rejected dealer certificates.
    fn resolve_complaints<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
        complaints: &[DkgComplaintPayload],
    ) -> Result<ItVssComplaintResolution, DkgError>;
}

const PRODUCTION_IT_VSS_SHARE_MAGIC: &[u8; 8] = b"PIVSS1\0\0";
const PRODUCTION_IT_VSS_TAG_MAGIC: &[u8; 8] = b"PIVST1\0\0";
const PRODUCTION_IT_VSS_TAG_HOLDER_Y: u8 = 1;
const PRODUCTION_IT_VSS_TAG_RECEIVER_BC: u8 = 2;
const PRODUCTION_IT_VSS_TAG_HOLDER_Y_AUDIT: u8 = 3;
const PRODUCTION_IT_VSS_TAG_RECEIVER_BC_AUDIT: u8 = 4;
const PRODUCTION_IT_VSS_TAG_CONSISTENCY_GAMMA: u8 = 5;

/// Security parameters for the production information-checking VSS backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionItVssSecurityParams {
    /// Number of audited information-checking tags opened and discarded for
    /// each holder/receiver pair.
    pub audit_tags: usize,
    /// Number of receiver-private retained information-checking tags for each
    /// holder/receiver pair.
    pub retained_tags: usize,
    /// Number of cut-and-choose consistency challenge rounds represented in
    /// the public metadata transcript.
    pub consistency_rounds: usize,
    /// Maximum vector lanes accepted in one vector sharing chunk.
    pub max_vector_lanes_per_chunk: usize,
    /// Maximum encoded directed private delivery size accepted for one chunk.
    pub max_private_delivery_bytes: usize,
}

impl Default for ProductionItVssSecurityParams {
    fn default() -> Self {
        Self {
            audit_tags: 8,
            retained_tags: 8,
            consistency_rounds: 192,
            max_vector_lanes_per_chunk: 65_536,
            max_private_delivery_bytes: 16 * 1024 * 1024,
        }
    }
}

/// One party's public-coin contribution for vector IT-VSS consistency
/// challenges. Applications broadcast these only after the VSS private payload
/// commitments for the label have been fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionItVssPublicCoinShare {
    /// Broadcast party.
    pub party: PartyId,
    /// Sharing label this coin is bound to.
    pub label_hash: [u8; 32],
    /// Public random contribution.
    pub coin: [u8; 32],
    /// Hash of this coin-share wire transcript.
    pub transcript_hash: [u8; 32],
}

/// Public-coin transcript used to derive vector polynomial consistency
/// challenge bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionItVssPublicCoinTranscript {
    /// Sharing label this transcript is bound to.
    pub label_hash: [u8; 32],
    /// Ordered party set hash from the DKG config.
    pub party_set_hash: [u8; 32],
    /// Hash of all public coin shares.
    pub coin_hash: [u8; 32],
    /// Hash of the complete public-coin transcript.
    pub transcript_hash: [u8; 32],
}

/// Production Rabin-Ben-Or-style vector information-checking VSS backend.
///
/// The backend treats each input secret as one vector over `F_q`, Shamir-shares
/// the vector with degree `f = threshold - 1`, and emits receiver-private
/// information-checking material for every holder/receiver pair. It is
/// intentionally vector/chunk oriented: one sharing certifies an entire `s1` or
/// `s2` vector label, not one coefficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionInformationCheckingVssBackend {
    entropy: [u8; 32],
    counter: u64,
    params: ProductionItVssSecurityParams,
    public_coin_transcripts: Vec<ProductionItVssPublicCoinTranscript>,
}

impl ProductionInformationCheckingVssBackend {
    /// Creates a backend from application-supplied DKG entropy.
    ///
    /// Embedding applications must provide fresh, session-bound entropy. The
    /// backend uses it only for dealer polynomial masks and IC tag material; it
    /// does not implement transport or durable storage.
    pub const fn from_entropy(entropy: [u8; 32]) -> Self {
        Self {
            entropy,
            counter: 0,
            params: ProductionItVssSecurityParams {
                audit_tags: 8,
                retained_tags: 8,
                consistency_rounds: 192,
                max_vector_lanes_per_chunk: 65_536,
                max_private_delivery_bytes: 16 * 1024 * 1024,
            },
            public_coin_transcripts: Vec::new(),
        }
    }

    /// Creates a backend with explicit security parameters.
    pub fn with_params(
        entropy: [u8; 32],
        params: ProductionItVssSecurityParams,
    ) -> Result<Self, DkgError> {
        if params.audit_tags == 0
            || params.retained_tags == 0
            || params.consistency_rounds == 0
            || params.max_vector_lanes_per_chunk == 0
            || params.max_private_delivery_bytes == 0
        {
            return Err(DkgError::Backend("invalid production IT-VSS parameters"));
        }
        Ok(Self {
            entropy,
            counter: 0,
            params,
            public_coin_transcripts: Vec::new(),
        })
    }

    /// Installs app-broadcast public coin transcripts for consistency
    /// challenges. Every transcript must be label-bound and party-set-bound;
    /// `share_secret` consumes the transcript matching its label hash.
    pub fn with_public_coin_transcripts(
        mut self,
        transcripts: Vec<ProductionItVssPublicCoinTranscript>,
    ) -> Result<Self, DkgError> {
        let mut seen = Vec::with_capacity(transcripts.len());
        for transcript in &transcripts {
            if seen.contains(&transcript.label_hash) {
                return Err(DkgError::DuplicateRoundSender {
                    round: DkgRound::Commit,
                    sender: PartyId(0),
                });
            }
            seen.push(transcript.label_hash);
        }
        self.public_coin_transcripts = transcripts;
        Ok(self)
    }

    /// Returns configured security parameters.
    pub const fn params(&self) -> ProductionItVssSecurityParams {
        self.params
    }

    /// Prepares a production vector sharing before public consistency coins
    /// are known. Applications should broadcast `public_precommitment`, then
    /// run public-coin broadcast, and only then call
    /// `finalize_prepared_secret`.
    pub fn prepare_secret<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: ItVssSharingLabel,
        secret: &[u8],
    ) -> Result<ProductionItVssPreparedDealerOutput, DkgError> {
        config.validate()?;
        if label.config_hash != config.transcript_hash() {
            return Err(DkgError::FinalOutputConfigMismatch);
        }
        if label.index.is_some() && label.domain != ItVssSharingDomain::NoncePreprocessing {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
        if !config.parties.contains(&label.dealer) {
            return Err(DkgError::UnknownParty(label.dealer));
        }

        let vector = production_it_vss_secret_to_vector(secret);
        if vector.len() > self.params.max_vector_lanes_per_chunk {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: self.params.max_vector_lanes_per_chunk,
                got: vector.len(),
            });
        }
        let degree = usize::from(config.threshold.saturating_sub(1));
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(vector.clone());
        for degree_index in 1..=degree {
            let mut coefficient = Vec::with_capacity(vector.len());
            for lane in 0..vector.len() {
                coefficient.push(self.next_fq(
                    label.label_hash,
                    format!("poly/degree_{degree_index}/lane_{lane}").as_bytes(),
                ));
            }
            coefficients.push(coefficient);
        }
        let mut consistency_coefficients = Vec::with_capacity(self.params.consistency_rounds);
        for round in 0..self.params.consistency_rounds {
            let mut round_coefficients = Vec::with_capacity(degree + 1);
            for degree_index in 0..=degree {
                let mut coefficient = Vec::with_capacity(vector.len());
                for lane in 0..vector.len() {
                    coefficient.push(
                        self.next_fq(
                            label.label_hash,
                            format!("consistency/round_{round}/degree_{degree_index}/lane_{lane}")
                                .as_bytes(),
                        ),
                    );
                }
                round_coefficients.push(coefficient);
            }
            consistency_coefficients.push(round_coefficients);
        }

        let mut beta_by_holder = Vec::with_capacity(config.parties.len());
        let mut gamma_by_round_holder = Vec::with_capacity(self.params.consistency_rounds);
        for &holder in &config.parties {
            let point = ItVssFq::new(config.interpolation_point::<P>(holder)?)?;
            let beta = production_it_vss_eval_vector_polynomial(&coefficients, point)?;
            beta_by_holder.push((holder, beta));
        }
        for round_coefficients in &consistency_coefficients {
            let mut round_gammas = Vec::with_capacity(config.parties.len());
            for &holder in &config.parties {
                let point = ItVssFq::new(config.interpolation_point::<P>(holder)?)?;
                let gamma = production_it_vss_eval_vector_polynomial(round_coefficients, point)?;
                round_gammas.push((holder, gamma));
            }
            gamma_by_round_holder.push(round_gammas);
        }

        let mut deliveries = Vec::with_capacity(config.parties.len());
        for &(receiver, ref beta) in &beta_by_holder {
            let mut information_tags = Vec::new();
            for &verifier in &config.parties {
                for tag_index in 0..self.params.audit_tags {
                    let mut y = Vec::with_capacity(vector.len());
                    for lane in 0..vector.len() {
                        y.push(
                            self.derive_fq(
                                label.label_hash,
                                format!(
                                "audit_holder_y/holder_{}/verifier_{}/tag_{tag_index}/lane_{lane}",
                                receiver.0, verifier.0
                            )
                                .as_bytes(),
                            ),
                        );
                    }
                    information_tags.push(ItVssInformationTag {
                        tagger: receiver,
                        verifier,
                        label_hash: label.label_hash,
                        tag: encode_production_it_vss_audit_holder_y_tag(
                            label.label_hash,
                            receiver,
                            verifier,
                            tag_index as u16,
                            &y,
                        ),
                    });
                }
                for tag_index in 0..self.params.retained_tags {
                    let mut y = Vec::with_capacity(vector.len());
                    for lane in 0..vector.len() {
                        y.push(
                            self.derive_fq(
                                label.label_hash,
                                format!(
                                    "holder_y/holder_{}/verifier_{}/tag_{tag_index}/lane_{lane}",
                                    receiver.0, verifier.0
                                )
                                .as_bytes(),
                            ),
                        );
                    }
                    information_tags.push(ItVssInformationTag {
                        tagger: receiver,
                        verifier,
                        label_hash: label.label_hash,
                        tag: encode_production_it_vss_holder_y_tag(
                            label.label_hash,
                            receiver,
                            verifier,
                            tag_index as u16,
                            &y,
                        ),
                    });
                }
            }
            for &(holder, ref holder_beta) in &beta_by_holder {
                for tag_index in 0..self.params.audit_tags {
                    let b = self.derive_nonzero_fq(
                        label.label_hash,
                        format!(
                            "audit_receiver_b/holder_{}/verifier_{}/tag_{tag_index}",
                            holder.0, receiver.0
                        )
                        .as_bytes(),
                    );
                    let mut y = Vec::with_capacity(vector.len());
                    for lane in 0..vector.len() {
                        y.push(
                            self.derive_fq(
                                label.label_hash,
                                format!(
                                "audit_holder_y/holder_{}/verifier_{}/tag_{tag_index}/lane_{lane}",
                                holder.0, receiver.0
                            )
                                .as_bytes(),
                            ),
                        );
                    }
                    let c = it_vss_vector_ic_tag_check_values(holder_beta, b, &y)?;
                    information_tags.push(ItVssInformationTag {
                        tagger: holder,
                        verifier: receiver,
                        label_hash: label.label_hash,
                        tag: encode_production_it_vss_audit_receiver_bc_tag(
                            label.label_hash,
                            holder,
                            receiver,
                            tag_index as u16,
                            b,
                            &c,
                        ),
                    });
                }
                for tag_index in 0..self.params.retained_tags {
                    let b = self.derive_nonzero_fq(
                        label.label_hash,
                        format!(
                            "receiver_b/holder_{}/verifier_{}/tag_{tag_index}",
                            holder.0, receiver.0
                        )
                        .as_bytes(),
                    );
                    let mut y = Vec::with_capacity(vector.len());
                    for lane in 0..vector.len() {
                        y.push(
                            self.derive_fq(
                                label.label_hash,
                                format!(
                                    "holder_y/holder_{}/verifier_{}/tag_{tag_index}/lane_{lane}",
                                    holder.0, receiver.0
                                )
                                .as_bytes(),
                            ),
                        );
                    }
                    let c = it_vss_vector_ic_tag_check_values(holder_beta, b, &y)?;
                    information_tags.push(ItVssInformationTag {
                        tagger: holder,
                        verifier: receiver,
                        label_hash: label.label_hash,
                        tag: encode_production_it_vss_receiver_bc_tag(
                            label.label_hash,
                            holder,
                            receiver,
                            tag_index as u16,
                            b,
                            &c,
                        ),
                    });
                }
            }
            for (round, round_gammas) in gamma_by_round_holder.iter().enumerate() {
                let gamma = round_gammas
                    .iter()
                    .find(|(holder, _)| *holder == receiver)
                    .map(|(_, gamma)| gamma)
                    .ok_or(DkgError::ComplaintEvidenceMismatch)?;
                information_tags.push(ItVssInformationTag {
                    tagger: label.dealer,
                    verifier: receiver,
                    label_hash: label.label_hash,
                    tag: encode_production_it_vss_consistency_gamma_tag(
                        label.label_hash,
                        receiver,
                        round as u16,
                        gamma,
                    ),
                });
            }
            deliveries.push(ItVssPrivateShareDelivery {
                dealer: label.dealer,
                receiver,
                label_hash: label.label_hash,
                share: encode_production_it_vss_share(label.label_hash, receiver, beta),
                information_tags,
            });
            let delivery = deliveries.last().expect("just pushed delivery");
            let delivery_bytes = delivery.share.len()
                + delivery
                    .information_tags
                    .iter()
                    .map(|tag| tag.tag.len())
                    .sum::<usize>();
            if delivery_bytes > self.params.max_private_delivery_bytes {
                return Err(DkgError::Backend(
                    "production IT-VSS private delivery too large",
                ));
            }
        }

        let public_precommitment = ItVssPublicPrecommitment {
            backend_id: self.backend_id(),
            dealer: label.dealer,
            label_hash: label.label_hash,
            public_precommitment_hash: production_it_vss_precommitment_hash(
                label.label_hash,
                label.dealer,
                vector.len(),
                self.params,
                &deliveries,
            ),
        };
        Ok(ProductionItVssPreparedDealerOutput {
            public_precommitment,
            deliveries,
            vector_len: vector.len(),
        })
    }

    /// Finalizes a prepared production sharing after the public-coin transcript
    /// has been broadcast and collected.
    pub fn finalize_prepared_secret(
        &self,
        config: &DkgConfig,
        prepared: ProductionItVssPreparedDealerOutput,
        public_coin: ProductionItVssPublicCoinTranscript,
    ) -> Result<ItVssDealerOutput, DkgError> {
        config.validate()?;
        if public_coin.label_hash != prepared.public_precommitment.label_hash
            || public_coin.party_set_hash != dkg_party_set_hash(config)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected_precommitment_hash = production_it_vss_precommitment_hash(
            prepared.public_precommitment.label_hash,
            prepared.public_precommitment.dealer,
            prepared.vector_len,
            self.params,
            &prepared.deliveries,
        );
        if prepared.public_precommitment.public_precommitment_hash != expected_precommitment_hash {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let preliminary_output = ItVssDealerOutput {
            public_commitment: ItVssPublicCommitment {
                backend_id: prepared.public_precommitment.backend_id,
                dealer: prepared.public_precommitment.dealer,
                label_hash: prepared.public_precommitment.label_hash,
                public_metadata_hash: [0u8; 32],
            },
            deliveries: prepared.deliveries,
        };
        let public_audit_hash = hash_production_it_vss_audit_records(
            &production_it_vss_public_audit_records_from_output(
                config,
                &preliminary_output,
                self.params,
            )?,
        );
        let public_consistency_hash = hash_production_it_vss_consistency_records(
            &production_it_vss_public_consistency_records_from_output_with_coin(
                config,
                &preliminary_output,
                self.params,
                Some(public_coin.coin_hash),
            )?,
        );
        Ok(ItVssDealerOutput {
            public_commitment: ItVssPublicCommitment {
                backend_id: preliminary_output.public_commitment.backend_id,
                dealer: preliminary_output.public_commitment.dealer,
                label_hash: preliminary_output.public_commitment.label_hash,
                public_metadata_hash: production_it_vss_metadata_hash(
                    preliminary_output.public_commitment.label_hash,
                    preliminary_output.public_commitment.dealer,
                    prepared.vector_len,
                    self.params,
                    Some(public_coin.coin_hash),
                    public_audit_hash,
                    public_consistency_hash,
                ),
            },
            deliveries: preliminary_output.deliveries,
        })
    }

    fn next_fq(&mut self, label_hash: [u8; 32], purpose: &[u8]) -> ItVssFq {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/production-rng");
        hasher.update(self.entropy);
        hasher.update(self.counter.to_le_bytes());
        hasher.update(label_hash);
        hash_bytes(&mut hasher, purpose);
        self.counter = self.counter.wrapping_add(1);
        let digest: [u8; 32] = hasher.finalize().into();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"))
            % u64::from(IT_VSS_FIELD_Q);
        ItVssFq(value as u32)
    }

    fn derive_fq(&self, label_hash: [u8; 32], purpose: &[u8]) -> ItVssFq {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-IT-VSS-v1/production-ic-derive");
        hasher.update(self.entropy);
        hasher.update(label_hash);
        hash_bytes(&mut hasher, purpose);
        let digest: [u8; 32] = hasher.finalize().into();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"))
            % u64::from(IT_VSS_FIELD_Q);
        ItVssFq(value as u32)
    }

    fn derive_nonzero_fq(&self, label_hash: [u8; 32], purpose: &[u8]) -> ItVssFq {
        let mut attempt = 0u32;
        loop {
            let mut with_attempt = purpose.to_vec();
            with_attempt.extend_from_slice(&attempt.to_le_bytes());
            let value = self.derive_fq(label_hash, &with_attempt);
            if value.value() != 0 {
                return value;
            }
            attempt = attempt.wrapping_add(1);
        }
    }
}

fn production_it_vss_secret_to_vector(secret: &[u8]) -> Vec<ItVssFq> {
    secret
        .iter()
        .copied()
        .map(|byte| ItVssFq(byte as u32))
        .collect()
}

fn production_it_vss_eval_vector_polynomial(
    coefficients: &[Vec<ItVssFq>],
    point: ItVssFq,
) -> Result<Vec<ItVssFq>, DkgError> {
    let Some(first) = coefficients.first() else {
        return Err(DkgError::Backend("empty IT-VSS vector polynomial"));
    };
    let mut out = vec![ItVssFq::zero(); first.len()];
    let mut power = ItVssFq::one();
    for coefficient in coefficients {
        if coefficient.len() != first.len() {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: first.len(),
                got: coefficient.len(),
            });
        }
        for (out, value) in out.iter_mut().zip(coefficient) {
            *out = out.add_mod(value.mul_mod(power));
        }
        power = power.mul_mod(point);
    }
    Ok(out)
}

fn production_it_vss_metadata_hash(
    label_hash: [u8; 32],
    dealer: PartyId,
    vector_len: usize,
    params: ProductionItVssSecurityParams,
    public_coin_hash: Option<[u8; 32]>,
    public_audit_hash: [u8; 32],
    public_consistency_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/production-vector-metadata");
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((vector_len as u32).to_le_bytes());
    hasher.update((params.audit_tags as u32).to_le_bytes());
    hasher.update((params.retained_tags as u32).to_le_bytes());
    hasher.update((params.consistency_rounds as u32).to_le_bytes());
    hasher.update((params.max_vector_lanes_per_chunk as u32).to_le_bytes());
    hasher.update((params.max_private_delivery_bytes as u64).to_le_bytes());
    match public_coin_hash {
        Some(hash) => {
            hasher.update([1]);
            hasher.update(hash);
        }
        None => hasher.update([0]),
    }
    hasher.update(public_audit_hash);
    hasher.update(public_consistency_hash);
    hasher.finalize().into()
}

fn production_it_vss_precommitment_hash(
    label_hash: [u8; 32],
    dealer: PartyId,
    vector_len: usize,
    params: ProductionItVssSecurityParams,
    deliveries: &[ItVssPrivateShareDelivery],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/production-vector-precommitment");
    hasher.update(label_hash);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((vector_len as u32).to_le_bytes());
    hasher.update((params.audit_tags as u32).to_le_bytes());
    hasher.update((params.retained_tags as u32).to_le_bytes());
    hasher.update((params.consistency_rounds as u32).to_le_bytes());
    hasher.update((deliveries.len() as u32).to_le_bytes());
    for delivery in deliveries {
        hasher.update(delivery.receiver.0.to_le_bytes());
        hasher.update(hash_it_vss_private_delivery_transcript(delivery));
    }
    hasher.finalize().into()
}

fn production_it_vss_consistency_challenge_bit_with_coin(
    label_hash: [u8; 32],
    public_coin_hash: Option<[u8; 32]>,
    round: usize,
) -> u8 {
    let mut challenge = Sha3_256::new();
    challenge.update(b"TALUS-DKG-IT-VSS-v1/consistency-challenge");
    challenge.update(label_hash);
    match public_coin_hash {
        Some(hash) => {
            challenge.update([1]);
            challenge.update(hash);
        }
        None => challenge.update([0]),
    }
    challenge.update((round as u32).to_le_bytes());
    let digest: [u8; 32] = challenge.finalize().into();
    digest[0] & 1
}

/// Builds one public-coin share for app broadcast.
pub fn production_it_vss_public_coin_share(
    config: &DkgConfig,
    label_hash: [u8; 32],
    party: PartyId,
    coin: [u8; 32],
) -> Result<ProductionItVssPublicCoinShare, DkgError> {
    config.validate()?;
    if !config.parties.contains(&party) {
        return Err(DkgError::UnknownParty(party));
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-coin-share");
    hasher.update(config.transcript_hash().0);
    hasher.update(label_hash);
    hasher.update(party.0.to_le_bytes());
    hasher.update(coin);
    Ok(ProductionItVssPublicCoinShare {
        party,
        label_hash,
        coin,
        transcript_hash: hasher.finalize().into(),
    })
}

/// Assembles and validates the final public-coin transcript for one vector
/// IT-VSS label.
pub fn production_it_vss_public_coin_transcript(
    config: &DkgConfig,
    label_hash: [u8; 32],
    shares: &[ProductionItVssPublicCoinShare],
) -> Result<ProductionItVssPublicCoinTranscript, DkgError> {
    config.validate()?;
    if shares.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Commit,
            expected: config.parties.len(),
            got: shares.len(),
        });
    }

    let mut sorted = shares.to_vec();
    sorted.sort_by_key(|share| share.party.0);
    for (share, expected_party) in sorted.iter().zip(config.parties.iter()) {
        if share.party != *expected_party {
            if !config.parties.contains(&share.party) {
                return Err(DkgError::UnknownParty(share.party));
            }
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Commit,
                expected: config.parties.len(),
                got: shares.len(),
            });
        }
        if share.label_hash != label_hash {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected =
            production_it_vss_public_coin_share(config, share.label_hash, share.party, share.coin)?;
        if expected.transcript_hash != share.transcript_hash {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
    }
    for pair in sorted.windows(2) {
        if pair[0].party == pair[1].party {
            return Err(DkgError::DuplicateRoundSender {
                round: DkgRound::Commit,
                sender: pair[0].party,
            });
        }
    }

    let mut coin_hasher = Sha3_256::new();
    coin_hasher.update(b"TALUS-DKG-IT-VSS-v1/public-coin-hash");
    coin_hasher.update(config.transcript_hash().0);
    coin_hasher.update(label_hash);
    for share in &sorted {
        coin_hasher.update(share.party.0.to_le_bytes());
        coin_hasher.update(share.coin);
        coin_hasher.update(share.transcript_hash);
    }
    let coin_hash = coin_hasher.finalize().into();

    let mut transcript_hasher = Sha3_256::new();
    transcript_hasher.update(b"TALUS-DKG-IT-VSS-v1/public-coin-transcript");
    transcript_hasher.update(config.transcript_hash().0);
    transcript_hasher.update(label_hash);
    let party_set_hash = dkg_party_set_hash(config);
    transcript_hasher.update(party_set_hash);
    transcript_hasher.update(coin_hash);

    Ok(ProductionItVssPublicCoinTranscript {
        label_hash,
        party_set_hash,
        coin_hash,
        transcript_hash: transcript_hasher.finalize().into(),
    })
}

fn hash_production_it_vss_consistency_records(
    records: &[ProductionItVssConsistencyRecord],
) -> [u8; 32] {
    let mut records = records.to_vec();
    records.sort_by_key(|record| {
        (
            record.dealer.0,
            record.holder.0,
            record.label_hash,
            record.round,
        )
    });
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-consistency-records");
    hasher.update((records.len() as u32).to_le_bytes());
    for record in &records {
        hasher.update(record.dealer.0.to_le_bytes());
        hasher.update(record.holder.0.to_le_bytes());
        hasher.update(record.label_hash);
        hasher.update(record.round.to_le_bytes());
        hasher.update([record.challenge_bit]);
        hasher.update(record.masked_eval_hash);
    }
    hasher.finalize().into()
}

fn hash_it_vss_fq_vec(hasher: &mut Sha3_256, values: &[ItVssFq]) {
    hasher.update((values.len() as u32).to_le_bytes());
    for value in values {
        hasher.update(value.value().to_le_bytes());
    }
}

fn encode_production_it_vss_share(
    label_hash: [u8; 32],
    receiver: PartyId,
    values: &[ItVssFq],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PRODUCTION_IT_VSS_SHARE_MAGIC);
    out.extend_from_slice(&label_hash);
    out.extend_from_slice(&receiver.0.to_le_bytes());
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        out.extend_from_slice(&value.value().to_le_bytes());
    }
    out
}

fn decode_production_it_vss_share(
    bytes: &[u8],
    expected_label_hash: [u8; 32],
    expected_receiver: PartyId,
) -> Result<Vec<ItVssFq>, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(PRODUCTION_IT_VSS_SHARE_MAGIC)?;
    let mut label_hash = [0u8; 32];
    label_hash.copy_from_slice(cursor.read_exact(32)?);
    let receiver = PartyId(cursor.read_u16()?);
    if label_hash != expected_label_hash || receiver != expected_receiver {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    let len = cursor.read_u32()? as usize;
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        let value = cursor.read_u32()?;
        out.push(
            ItVssFq::new(value).map_err(|_| DkgError::FieldShareCoefficientOutOfRange {
                index,
                coefficient: value as Coeff,
                modulus: IT_VSS_FIELD_Q as Coeff,
            })?,
        );
    }
    cursor.finish()?;
    Ok(out)
}

fn encode_production_it_vss_holder_y_tag_with_kind(
    kind: u8,
    label_hash: [u8; 32],
    holder: PartyId,
    verifier: PartyId,
    tag_index: u16,
    y: &[ItVssFq],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PRODUCTION_IT_VSS_TAG_MAGIC);
    out.push(kind);
    out.extend_from_slice(&label_hash);
    out.extend_from_slice(&holder.0.to_le_bytes());
    out.extend_from_slice(&verifier.0.to_le_bytes());
    out.extend_from_slice(&tag_index.to_le_bytes());
    out.extend_from_slice(&(y.len() as u32).to_le_bytes());
    for value in y {
        out.extend_from_slice(&value.value().to_le_bytes());
    }
    out
}

fn encode_production_it_vss_holder_y_tag(
    label_hash: [u8; 32],
    holder: PartyId,
    verifier: PartyId,
    tag_index: u16,
    y: &[ItVssFq],
) -> Vec<u8> {
    encode_production_it_vss_holder_y_tag_with_kind(
        PRODUCTION_IT_VSS_TAG_HOLDER_Y,
        label_hash,
        holder,
        verifier,
        tag_index,
        y,
    )
}

fn encode_production_it_vss_audit_holder_y_tag(
    label_hash: [u8; 32],
    holder: PartyId,
    verifier: PartyId,
    tag_index: u16,
    y: &[ItVssFq],
) -> Vec<u8> {
    encode_production_it_vss_holder_y_tag_with_kind(
        PRODUCTION_IT_VSS_TAG_HOLDER_Y_AUDIT,
        label_hash,
        holder,
        verifier,
        tag_index,
        y,
    )
}

fn encode_production_it_vss_receiver_bc_tag_with_kind(
    kind: u8,
    label_hash: [u8; 32],
    holder: PartyId,
    verifier: PartyId,
    tag_index: u16,
    b: ItVssFq,
    c: &[ItVssFq],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PRODUCTION_IT_VSS_TAG_MAGIC);
    out.push(kind);
    out.extend_from_slice(&label_hash);
    out.extend_from_slice(&holder.0.to_le_bytes());
    out.extend_from_slice(&verifier.0.to_le_bytes());
    out.extend_from_slice(&tag_index.to_le_bytes());
    out.extend_from_slice(&b.value().to_le_bytes());
    out.extend_from_slice(&(c.len() as u32).to_le_bytes());
    for value in c {
        out.extend_from_slice(&value.value().to_le_bytes());
    }
    out
}

fn encode_production_it_vss_receiver_bc_tag(
    label_hash: [u8; 32],
    holder: PartyId,
    verifier: PartyId,
    tag_index: u16,
    b: ItVssFq,
    c: &[ItVssFq],
) -> Vec<u8> {
    encode_production_it_vss_receiver_bc_tag_with_kind(
        PRODUCTION_IT_VSS_TAG_RECEIVER_BC,
        label_hash,
        holder,
        verifier,
        tag_index,
        b,
        c,
    )
}

fn encode_production_it_vss_audit_receiver_bc_tag(
    label_hash: [u8; 32],
    holder: PartyId,
    verifier: PartyId,
    tag_index: u16,
    b: ItVssFq,
    c: &[ItVssFq],
) -> Vec<u8> {
    encode_production_it_vss_receiver_bc_tag_with_kind(
        PRODUCTION_IT_VSS_TAG_RECEIVER_BC_AUDIT,
        label_hash,
        holder,
        verifier,
        tag_index,
        b,
        c,
    )
}

fn encode_production_it_vss_consistency_gamma_tag(
    label_hash: [u8; 32],
    holder: PartyId,
    round: u16,
    gamma: &[ItVssFq],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PRODUCTION_IT_VSS_TAG_MAGIC);
    out.push(PRODUCTION_IT_VSS_TAG_CONSISTENCY_GAMMA);
    out.extend_from_slice(&label_hash);
    out.extend_from_slice(&holder.0.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&(gamma.len() as u32).to_le_bytes());
    for value in gamma {
        out.extend_from_slice(&value.value().to_le_bytes());
    }
    out
}

enum ProductionItVssDecodedTag {
    HolderY {
        audit: bool,
        holder: PartyId,
        verifier: PartyId,
        tag_index: u16,
        y: Vec<ItVssFq>,
    },
    ReceiverBc {
        audit: bool,
        holder: PartyId,
        verifier: PartyId,
        tag_index: u16,
        b: ItVssFq,
        c: Vec<ItVssFq>,
    },
    ConsistencyGamma {
        holder: PartyId,
        round: u16,
        gamma: Vec<ItVssFq>,
    },
}

fn decode_production_it_vss_tag(
    bytes: &[u8],
    expected_label_hash: [u8; 32],
) -> Result<ProductionItVssDecodedTag, DkgError> {
    let mut cursor = CanonicalCursor::new(bytes);
    cursor.read_magic(PRODUCTION_IT_VSS_TAG_MAGIC)?;
    let kind = cursor.read_exact(1)?[0];
    let mut label_hash = [0u8; 32];
    label_hash.copy_from_slice(cursor.read_exact(32)?);
    if label_hash != expected_label_hash {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    let holder = PartyId(cursor.read_u16()?);
    let verifier = PartyId(cursor.read_u16()?);
    let tag_index = cursor.read_u16()?;
    match kind {
        PRODUCTION_IT_VSS_TAG_HOLDER_Y | PRODUCTION_IT_VSS_TAG_HOLDER_Y_AUDIT => {
            let len = cursor.read_u32()? as usize;
            let mut y = Vec::with_capacity(len);
            for index in 0..len {
                let value = cursor.read_u32()?;
                y.push(ItVssFq::new(value).map_err(|_| {
                    DkgError::FieldShareCoefficientOutOfRange {
                        index,
                        coefficient: value as Coeff,
                        modulus: IT_VSS_FIELD_Q as Coeff,
                    }
                })?);
            }
            cursor.finish()?;
            Ok(ProductionItVssDecodedTag::HolderY {
                audit: kind == PRODUCTION_IT_VSS_TAG_HOLDER_Y_AUDIT,
                holder,
                verifier,
                tag_index,
                y,
            })
        }
        PRODUCTION_IT_VSS_TAG_RECEIVER_BC | PRODUCTION_IT_VSS_TAG_RECEIVER_BC_AUDIT => {
            let b = ItVssFq::nonzero(cursor.read_u32()?)?;
            let len = cursor.read_u32()? as usize;
            let mut c = Vec::with_capacity(len);
            for index in 0..len {
                let value = cursor.read_u32()?;
                c.push(ItVssFq::new(value).map_err(|_| {
                    DkgError::FieldShareCoefficientOutOfRange {
                        index,
                        coefficient: value as Coeff,
                        modulus: IT_VSS_FIELD_Q as Coeff,
                    }
                })?);
            }
            cursor.finish()?;
            Ok(ProductionItVssDecodedTag::ReceiverBc {
                audit: kind == PRODUCTION_IT_VSS_TAG_RECEIVER_BC_AUDIT,
                holder,
                verifier,
                tag_index,
                b,
                c,
            })
        }
        PRODUCTION_IT_VSS_TAG_CONSISTENCY_GAMMA => {
            let len = cursor.read_u32()? as usize;
            let mut gamma = Vec::with_capacity(len);
            for index in 0..len {
                let value = cursor.read_u32()?;
                gamma.push(ItVssFq::new(value).map_err(|_| {
                    DkgError::FieldShareCoefficientOutOfRange {
                        index,
                        coefficient: value as Coeff,
                        modulus: IT_VSS_FIELD_Q as Coeff,
                    }
                })?);
            }
            cursor.finish()?;
            Ok(ProductionItVssDecodedTag::ConsistencyGamma {
                holder,
                round: tag_index,
                gamma,
            })
        }
        _ => Err(DkgError::ComplaintEvidenceMismatch),
    }
}

/// Public audit/discard record for one audited vector IC tag.
///
/// This record represents the receiver-side `(b, c_vec)` tag opened for audit.
/// It is safe to persist publicly only because audited tags are discarded and
/// never used for reconstruction. Retained receiver-side tags must never be
/// converted into this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionItVssAuditRecord {
    /// Dealer whose sharing is audited.
    pub dealer: PartyId,
    /// Holder/intermediary whose vector share is authenticated.
    pub holder: PartyId,
    /// Receiver/verifier that opened the audited receiver-side tag.
    pub receiver: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Audited tag index within the holder/receiver pair.
    pub tag_index: u16,
    /// Hash of the public audited receiver-side tag.
    pub audited_receiver_tag_hash: [u8; 32],
    /// Marker that this tag is discarded and not retained.
    pub discard_after_audit: DiscardAfterAudit,
}

/// Public vector-polynomial consistency record for one holder and challenge
/// round.
///
/// The record represents the public masked evaluation
/// `H_r(alpha_i) = gamma_{r,i} + e_r * beta_i`. It does not contain the
/// private `gamma_{r,i}` mask evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionItVssConsistencyRecord {
    /// Dealer whose sharing is checked.
    pub dealer: PartyId,
    /// Holder whose polynomial point is checked.
    pub holder: PartyId,
    /// Sharing label hash.
    pub label_hash: [u8; 32],
    /// Consistency round.
    pub round: u16,
    /// Public challenge bit.
    pub challenge_bit: u8,
    /// Hash of the public masked evaluation vector.
    pub masked_eval_hash: [u8; 32],
}

fn hash_production_it_vss_audit_record(record: &ProductionItVssAuditRecord) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-audit-record");
    hasher.update(record.dealer.0.to_le_bytes());
    hasher.update(record.holder.0.to_le_bytes());
    hasher.update(record.receiver.0.to_le_bytes());
    hasher.update(record.label_hash);
    hasher.update(record.tag_index.to_le_bytes());
    hasher.update(record.audited_receiver_tag_hash);
    hasher.finalize().into()
}

/// Hashes public audit records for inclusion in the production public
/// commitment metadata.
pub fn hash_production_it_vss_audit_records(records: &[ProductionItVssAuditRecord]) -> [u8; 32] {
    let mut records = records.to_vec();
    records.sort_by_key(|record| {
        (
            record.dealer.0,
            record.holder.0,
            record.receiver.0,
            record.label_hash,
            record.tag_index,
        )
    });
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-audit-records");
    hasher.update((records.len() as u32).to_le_bytes());
    for record in &records {
        hasher.update(hash_production_it_vss_audit_record(record));
    }
    hasher.finalize().into()
}

fn production_it_vss_delivery_beta(
    delivery: &ItVssPrivateShareDelivery,
) -> Result<Vec<ItVssFq>, DkgError> {
    decode_production_it_vss_share(&delivery.share, delivery.label_hash, delivery.receiver)
        .map_err(|_| DkgError::ComplaintEvidenceMismatch)
}

fn production_it_vss_decoded_delivery_tags(
    delivery: &ItVssPrivateShareDelivery,
) -> Result<Vec<ProductionItVssDecodedTag>, DkgError> {
    delivery
        .information_tags
        .iter()
        .map(|tag| {
            if tag.label_hash != delivery.label_hash {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
            decode_production_it_vss_tag(&tag.tag, delivery.label_hash)
                .map_err(|_| DkgError::ComplaintEvidenceMismatch)
        })
        .collect()
}

/// Verifies the production IT-VSS public audit/discard transcript derivable
/// from a dealer output.
///
/// This function opens only audited receiver-side tags into public records.
/// Retained tags are used only by private delivery verification and are not
/// represented in the returned public audit records.
pub fn production_it_vss_public_audit_records_from_output(
    config: &DkgConfig,
    output: &ItVssDealerOutput,
    params: ProductionItVssSecurityParams,
) -> Result<Vec<ProductionItVssAuditRecord>, DkgError> {
    config.validate()?;
    let commitment = &output.public_commitment;
    if commitment.backend_id != ItVssBackendId::ProductionInformationChecking {
        return Err(DkgError::ItVssCertificateBackendMismatch);
    }
    if !config.parties.contains(&commitment.dealer) {
        return Err(DkgError::UnknownParty(commitment.dealer));
    }
    if output.deliveries.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: config.parties.len(),
            got: output.deliveries.len(),
        });
    }

    let mut decoded = Vec::with_capacity(output.deliveries.len());
    for delivery in &output.deliveries {
        if delivery.dealer != commitment.dealer || delivery.label_hash != commitment.label_hash {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let beta = production_it_vss_delivery_beta(delivery)?;
        let tags = production_it_vss_decoded_delivery_tags(delivery)?;
        decoded.push((delivery.receiver, beta, tags));
    }

    let mut records = Vec::new();
    for &(holder, ref beta, ref holder_tags) in &decoded {
        for &(receiver, _, ref receiver_tags) in &decoded {
            for tag_index in 0..params.audit_tags as u16 {
                let holder_y = holder_tags
                    .iter()
                    .find_map(|tag| match tag {
                        ProductionItVssDecodedTag::HolderY {
                            audit,
                            holder: tag_holder,
                            verifier,
                            tag_index: index,
                            y,
                        } if *audit
                            && *tag_holder == holder
                            && *verifier == receiver
                            && *index == tag_index =>
                        {
                            Some(y)
                        }
                        _ => None,
                    })
                    .ok_or(DkgError::ComplaintEvidenceMismatch)?;
                let (b, c) = receiver_tags
                    .iter()
                    .find_map(|tag| match tag {
                        ProductionItVssDecodedTag::ReceiverBc {
                            audit,
                            holder: tag_holder,
                            verifier,
                            tag_index: index,
                            b,
                            c,
                        } if *audit
                            && *tag_holder == holder
                            && *verifier == receiver
                            && *index == tag_index =>
                        {
                            Some((*b, c))
                        }
                        _ => None,
                    })
                    .ok_or(DkgError::ComplaintEvidenceMismatch)?;
                if it_vss_vector_ic_tag_check_values(beta, b, holder_y)? != *c {
                    return Err(DkgError::ComplaintEvidenceMismatch);
                }
                let audited =
                    AuditedVectorReceiverTag::new(holder, receiver, tag_index, b, c.clone())?;
                records.push(ProductionItVssAuditRecord {
                    dealer: commitment.dealer,
                    holder,
                    receiver,
                    label_hash: commitment.label_hash,
                    tag_index,
                    audited_receiver_tag_hash: {
                        let mut hasher = Sha3_256::new();
                        hasher.update(b"TALUS-DKG-IT-VSS-v1/opened-audited-vector-tag");
                        hasher.update(encode_it_vss_audited_vector_receiver_tag(&audited));
                        hasher.finalize().into()
                    },
                    discard_after_audit: DiscardAfterAudit,
                });
            }
        }
    }
    Ok(records)
}

/// Derives and verifies public vector-polynomial consistency records from a
/// dealer output.
///
/// Private deliveries carry only each holder's `gamma_{r,i}` mask evaluation.
/// The returned public records hash the masked public evaluation
/// `gamma_{r,i} + e_r * beta_i`, which is the per-holder value implied by the
/// broadcast masked polynomial.
pub fn production_it_vss_public_consistency_records_from_output(
    config: &DkgConfig,
    output: &ItVssDealerOutput,
    params: ProductionItVssSecurityParams,
) -> Result<Vec<ProductionItVssConsistencyRecord>, DkgError> {
    production_it_vss_public_consistency_records_from_output_with_coin(config, output, params, None)
}

/// Derives and verifies public vector-polynomial consistency records using an
/// app-broadcast public coin transcript.
pub fn production_it_vss_public_consistency_records_from_output_with_coin(
    config: &DkgConfig,
    output: &ItVssDealerOutput,
    params: ProductionItVssSecurityParams,
    public_coin_hash: Option<[u8; 32]>,
) -> Result<Vec<ProductionItVssConsistencyRecord>, DkgError> {
    config.validate()?;
    let commitment = &output.public_commitment;
    if commitment.backend_id != ItVssBackendId::ProductionInformationChecking {
        return Err(DkgError::ItVssCertificateBackendMismatch);
    }
    let mut records = Vec::new();
    for delivery in &output.deliveries {
        if delivery.dealer != commitment.dealer || delivery.label_hash != commitment.label_hash {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let beta = production_it_vss_delivery_beta(delivery)?;
        let tags = production_it_vss_decoded_delivery_tags(delivery)?;
        for round in 0..params.consistency_rounds as u16 {
            let gamma = tags
                .iter()
                .find_map(|tag| match tag {
                    ProductionItVssDecodedTag::ConsistencyGamma {
                        holder,
                        round: tag_round,
                        gamma,
                    } if *holder == delivery.receiver && *tag_round == round => Some(gamma),
                    _ => None,
                })
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            if gamma.len() != beta.len() {
                return Err(DkgError::ItVssVectorLengthMismatch {
                    expected: beta.len(),
                    got: gamma.len(),
                });
            }
            let challenge_bit = production_it_vss_consistency_challenge_bit_with_coin(
                delivery.label_hash,
                public_coin_hash,
                round as usize,
            );
            let masked_eval = gamma
                .iter()
                .zip(&beta)
                .map(|(gamma, beta)| {
                    if challenge_bit == 0 {
                        *gamma
                    } else {
                        gamma.add_mod(*beta)
                    }
                })
                .collect::<Vec<_>>();
            let mut hasher = Sha3_256::new();
            hasher.update(b"TALUS-DKG-IT-VSS-v1/public-consistency-masked-eval");
            hasher.update(delivery.dealer.0.to_le_bytes());
            hasher.update(delivery.receiver.0.to_le_bytes());
            hasher.update(delivery.label_hash);
            hasher.update(round.to_le_bytes());
            hasher.update([challenge_bit]);
            hash_it_vss_fq_vec(&mut hasher, &masked_eval);
            records.push(ProductionItVssConsistencyRecord {
                dealer: delivery.dealer,
                holder: delivery.receiver,
                label_hash: delivery.label_hash,
                round,
                challenge_bit,
                masked_eval_hash: hasher.finalize().into(),
            });
        }
    }
    Ok(records)
}

/// Vector IT-VSS execution counters used by release gates and performance
/// tests. Counts are lane-oriented so product paths can distinguish batched
/// vector execution from scalar-per-coefficient execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionItVssCounters {
    /// Number of vector sharing instances.
    pub vector_sharings: u64,
    /// Total lanes across vector sharings.
    pub vector_lanes: u64,
    /// Directed private deliveries.
    pub private_deliveries: u64,
    /// Audited vector tag count.
    pub audited_tag_vectors: u64,
    /// Retained vector tag count.
    pub retained_tag_vectors: u64,
    /// Total audited tag lanes.
    pub audited_tag_lanes: u64,
    /// Total retained tag lanes.
    pub retained_tag_lanes: u64,
    /// Vector polynomial consistency challenge rounds.
    pub consistency_rounds: u64,
    /// Total encoded directed private delivery bytes for this sharing.
    pub private_delivery_bytes: u64,
    /// Public audit/discard records implied by this sharing.
    pub public_audit_records: u64,
    /// Public consistency records implied by this sharing.
    pub public_consistency_records: u64,
    /// Optional elapsed runtime in microseconds when measured by a driver.
    pub elapsed_micros: u64,
}

impl ProductionItVssCounters {
    /// Returns true if this counter set proves vector/batched execution.
    pub const fn used_vector_execution(self) -> bool {
        self.vector_sharings != 0 && self.vector_lanes != 0
    }

    /// Returns true if audit and retained IC material are both present.
    pub const fn has_information_checking(self) -> bool {
        self.audited_tag_vectors != 0 && self.retained_tag_vectors != 0
    }
}

/// Derives vector IT-VSS counters from one dealer output.
pub fn production_it_vss_counters_from_dealer_output_with_params(
    output: &ItVssDealerOutput,
    params: ProductionItVssSecurityParams,
) -> Result<ProductionItVssCounters, DkgError> {
    let Some(first_delivery) = output.deliveries.first() else {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: 1,
            got: 0,
        });
    };
    let lane_count = production_it_vss_delivery_beta(first_delivery)?.len() as u64;
    let mut counters = ProductionItVssCounters {
        vector_sharings: 1,
        vector_lanes: lane_count,
        private_deliveries: output.deliveries.len() as u64,
        consistency_rounds: params.consistency_rounds as u64,
        public_audit_records: (output.deliveries.len()
            * output.deliveries.len()
            * params.audit_tags) as u64,
        public_consistency_records: (output.deliveries.len() * params.consistency_rounds) as u64,
        ..ProductionItVssCounters::default()
    };
    for delivery in &output.deliveries {
        let beta_len = production_it_vss_delivery_beta(delivery)?.len() as u64;
        if beta_len != lane_count {
            return Err(DkgError::ItVssVectorLengthMismatch {
                expected: lane_count as usize,
                got: beta_len as usize,
            });
        }
        for tag in production_it_vss_decoded_delivery_tags(delivery)? {
            counters.private_delivery_bytes += tag_encoded_len(&tag) as u64;
            match tag {
                ProductionItVssDecodedTag::HolderY { audit, y, .. } => {
                    if y.len() as u64 != lane_count {
                        return Err(DkgError::ItVssVectorLengthMismatch {
                            expected: lane_count as usize,
                            got: y.len(),
                        });
                    }
                    if audit {
                        counters.audited_tag_vectors += 1;
                        counters.audited_tag_lanes += lane_count;
                    } else {
                        counters.retained_tag_vectors += 1;
                        counters.retained_tag_lanes += lane_count;
                    }
                }
                ProductionItVssDecodedTag::ReceiverBc { audit, c, .. } => {
                    if c.len() as u64 != lane_count {
                        return Err(DkgError::ItVssVectorLengthMismatch {
                            expected: lane_count as usize,
                            got: c.len(),
                        });
                    }
                    if audit {
                        counters.audited_tag_vectors += 1;
                        counters.audited_tag_lanes += lane_count;
                    } else {
                        counters.retained_tag_vectors += 1;
                        counters.retained_tag_lanes += lane_count;
                    }
                }
                ProductionItVssDecodedTag::ConsistencyGamma { gamma, .. } => {
                    if gamma.len() as u64 != lane_count {
                        return Err(DkgError::ItVssVectorLengthMismatch {
                            expected: lane_count as usize,
                            got: gamma.len(),
                        });
                    }
                }
            }
        }
        counters.private_delivery_bytes += delivery.share.len() as u64;
    }
    Ok(counters)
}

fn tag_encoded_len(tag: &ProductionItVssDecodedTag) -> usize {
    match tag {
        ProductionItVssDecodedTag::HolderY {
            holder,
            verifier,
            tag_index,
            y,
            audit,
        } => if *audit {
            encode_production_it_vss_audit_holder_y_tag(
                [0u8; 32], *holder, *verifier, *tag_index, y,
            )
        } else {
            encode_production_it_vss_holder_y_tag([0u8; 32], *holder, *verifier, *tag_index, y)
        }
        .len(),
        ProductionItVssDecodedTag::ReceiverBc {
            holder,
            verifier,
            tag_index,
            b,
            c,
            audit,
        } => if *audit {
            encode_production_it_vss_audit_receiver_bc_tag(
                [0u8; 32], *holder, *verifier, *tag_index, *b, c,
            )
        } else {
            encode_production_it_vss_receiver_bc_tag(
                [0u8; 32], *holder, *verifier, *tag_index, *b, c,
            )
        }
        .len(),
        ProductionItVssDecodedTag::ConsistencyGamma {
            holder,
            round,
            gamma,
        } => {
            encode_production_it_vss_consistency_gamma_tag([0u8; 32], *holder, *round, gamma).len()
        }
    }
}

/// Derives vector IT-VSS counters from one dealer output when security
/// parameters are unavailable to the caller. The returned counters intentionally
/// leave `consistency_rounds = 0`; release checks should use
/// `production_it_vss_counters_from_dealer_output_with_params`.
pub fn production_it_vss_counters_from_dealer_output(
    output: &ItVssDealerOutput,
) -> Result<ProductionItVssCounters, DkgError> {
    production_it_vss_counters_from_dealer_output_with_params(
        output,
        ProductionItVssSecurityParams {
            audit_tags: 1,
            retained_tags: 1,
            consistency_rounds: 0,
            ..ProductionItVssSecurityParams::default()
        },
    )
}

/// Release gate for vector IT-VSS execution counters.
pub fn ensure_production_it_vss_counters_allowed_for_release(
    counters: ProductionItVssCounters,
) -> Result<(), DkgError> {
    if !counters.used_vector_execution()
        || !counters.has_information_checking()
        || counters.consistency_rounds == 0
        || counters.private_delivery_bytes == 0
        || counters.public_audit_records == 0
        || counters.public_consistency_records == 0
    {
        return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
    }
    Ok(())
}

impl ProductionItVssBackend for ProductionInformationCheckingVssBackend {
    fn backend_id(&self) -> ItVssBackendId {
        ItVssBackendId::ProductionInformationChecking
    }

    fn share_secret<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: ItVssSharingLabel,
        secret: &[u8],
    ) -> Result<ItVssDealerOutput, DkgError> {
        let prepared = self.prepare_secret::<P>(config, label, secret)?;
        let public_coin = self
            .public_coin_transcripts
            .iter()
            .find(|transcript| transcript.label_hash == label.label_hash)
            .copied()
            .ok_or(DkgError::Backend(
                "missing production IT-VSS public coin transcript",
            ))?;
        self.finalize_prepared_secret(config, prepared, public_coin)
    }

    fn verify_private_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<(), DkgError> {
        config.validate()?;
        if public_commitment.backend_id != self.backend_id()
            || public_commitment.dealer != delivery.dealer
            || public_commitment.label_hash != delivery.label_hash
            || !config.parties.contains(&delivery.receiver)
            || !config.parties.contains(&delivery.dealer)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let beta =
            decode_production_it_vss_share(&delivery.share, delivery.label_hash, delivery.receiver)
                .map_err(|_| DkgError::ComplaintEvidenceMismatch)?;

        let mut holder_y = Vec::new();
        let mut receiver_bc = Vec::new();
        let mut consistency_gamma = Vec::new();
        for tag in &delivery.information_tags {
            if tag.label_hash != delivery.label_hash {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
            match decode_production_it_vss_tag(&tag.tag, delivery.label_hash)
                .map_err(|_| DkgError::ComplaintEvidenceMismatch)?
            {
                ProductionItVssDecodedTag::HolderY {
                    audit,
                    holder,
                    verifier,
                    tag_index,
                    y,
                } => {
                    if tag.tagger != holder
                        || tag.verifier != verifier
                        || holder != delivery.receiver
                        || !config.parties.contains(&verifier)
                        || y.len() != beta.len()
                    {
                        return Err(DkgError::ComplaintEvidenceMismatch);
                    }
                    holder_y.push((audit, verifier, tag_index, y));
                }
                ProductionItVssDecodedTag::ReceiverBc {
                    audit,
                    holder,
                    verifier,
                    tag_index,
                    b,
                    c,
                } => {
                    if tag.tagger != holder
                        || tag.verifier != verifier
                        || verifier != delivery.receiver
                        || !config.parties.contains(&holder)
                        || c.len() != beta.len()
                    {
                        return Err(DkgError::ComplaintEvidenceMismatch);
                    }
                    receiver_bc.push((audit, holder, tag_index, b, c));
                }
                ProductionItVssDecodedTag::ConsistencyGamma {
                    holder,
                    round,
                    gamma,
                } => {
                    if tag.tagger != delivery.dealer
                        || tag.verifier != delivery.receiver
                        || holder != delivery.receiver
                        || gamma.len() != beta.len()
                    {
                        return Err(DkgError::ComplaintEvidenceMismatch);
                    }
                    consistency_gamma.push((round, gamma));
                }
            }
        }

        for &party in &config.parties {
            for tag_index in 0..self.params.audit_tags as u16 {
                if !holder_y.iter().any(|(audit, verifier, index, y)| {
                    *audit && *verifier == party && *index == tag_index && y.len() == beta.len()
                }) {
                    return Err(DkgError::ComplaintEvidenceMismatch);
                }
                if !receiver_bc.iter().any(|(audit, holder, index, _b, c)| {
                    *audit && *holder == party && *index == tag_index && c.len() == beta.len()
                }) {
                    return Err(DkgError::ComplaintEvidenceMismatch);
                }
            }
            for tag_index in 0..self.params.retained_tags as u16 {
                if !holder_y.iter().any(|(audit, verifier, index, y)| {
                    !*audit && *verifier == party && *index == tag_index && y.len() == beta.len()
                }) {
                    return Err(DkgError::ComplaintEvidenceMismatch);
                }
                if !receiver_bc.iter().any(|(audit, holder, index, _b, c)| {
                    !*audit && *holder == party && *index == tag_index && c.len() == beta.len()
                }) {
                    return Err(DkgError::ComplaintEvidenceMismatch);
                }
            }
        }
        for round in 0..self.params.consistency_rounds as u16 {
            if !consistency_gamma
                .iter()
                .any(|(tag_round, gamma)| *tag_round == round && gamma.len() == beta.len())
            {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
        }

        for tag_index in 0..self.params.audit_tags as u16 {
            let y = holder_y
                .iter()
                .find(|(audit, verifier, index, _)| {
                    *audit && *verifier == delivery.receiver && *index == tag_index
                })
                .map(|(_, _, _, y)| y)
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let (b, c) = receiver_bc
                .iter()
                .find(|(audit, holder, index, _, _)| {
                    *audit && *holder == delivery.receiver && *index == tag_index
                })
                .map(|(_, _, _, b, c)| (*b, c))
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let expected = it_vss_vector_ic_tag_check_values(&beta, b, y)?;
            if expected != *c {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
        }

        for tag_index in 0..self.params.retained_tags as u16 {
            let y = holder_y
                .iter()
                .find(|(audit, verifier, index, _)| {
                    !*audit && *verifier == delivery.receiver && *index == tag_index
                })
                .map(|(_, _, _, y)| y)
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let (b, c) = receiver_bc
                .iter()
                .find(|(audit, holder, index, _, _)| {
                    !*audit && *holder == delivery.receiver && *index == tag_index
                })
                .map(|(_, _, _, b, c)| (*b, c))
                .ok_or(DkgError::ComplaintEvidenceMismatch)?;
            let expected = it_vss_vector_ic_tag_check_values(&beta, b, y)?;
            if expected != *c {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
        }
        Ok(())
    }

    fn complaint_for_invalid_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgComplaintPayload, DkgError> {
        if self
            .verify_private_delivery::<P>(config, public_commitment, delivery)
            .is_ok()
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected_tag_hash = hash_it_vss_tag(&public_commitment.public_metadata_hash);
        let received_share_hash = hash_it_vss_received_share(
            delivery.label_hash,
            delivery.dealer,
            delivery.receiver,
            &delivery.share,
        );
        let delivery_transcript_hash = hash_it_vss_private_delivery_transcript(delivery);
        let evidence = ItVssInformationCheckComplaintEvidence {
            dealer: delivery.dealer,
            receiver: delivery.receiver,
            tagger: delivery.receiver,
            label_hash: delivery.label_hash,
            expected_tag_hash,
            received_share_hash,
            delivery_transcript_hash,
            transcript_hash: transcript_hash_it_vss_information_check_complaint(
                expected_tag_hash,
                received_share_hash,
                delivery_transcript_hash,
            ),
        };
        validate_it_vss_information_check_complaint_evidence(config, public_commitment, &evidence)?;
        Ok(DkgComplaintPayload {
            complainant: delivery.receiver,
            dealer: delivery.dealer,
            receiver: delivery.receiver,
            reason: DkgComplaintReason::InvalidVssShare,
            evidence: encode_it_vss_information_check_complaint_evidence(&evidence),
        })
    }

    fn resolve_complaints<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
        complaints: &[DkgComplaintPayload],
    ) -> Result<ItVssComplaintResolution, DkgError> {
        config.validate()?;
        let mut rejected_dealers = Vec::new();
        for complaint in complaints {
            if complaint.reason != DkgComplaintReason::InvalidVssShare {
                return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
            }
            let evidence = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)?;
            let commitment = public_commitments
                .iter()
                .find(|commitment| {
                    commitment.dealer == complaint.dealer
                        && commitment.label_hash == evidence.label_hash
                        && commitment.backend_id == self.backend_id()
                })
                .ok_or(DkgError::ItVssCertificateMissingCommitment {
                    dealer: complaint.dealer,
                    label_hash: evidence.label_hash,
                })?;
            validate_it_vss_information_check_complaint_evidence(config, commitment, &evidence)?;
            if !rejected_dealers.contains(&complaint.dealer) {
                rejected_dealers.push(complaint.dealer);
            }
        }

        let accepted_dealers = config
            .parties
            .iter()
            .copied()
            .filter(|party| !rejected_dealers.contains(party))
            .collect::<Vec<_>>();
        validate_accepted_dealer_subset(config, &accepted_dealers)?;
        let complaint_hash = hash_dkg_complaint_payloads(complaints);
        let certificates = public_commitments
            .iter()
            .filter(|commitment| accepted_dealers.contains(&commitment.dealer))
            .map(|commitment| VerifiedItVssSharingCertificate {
                backend_id: self.backend_id(),
                dealer: commitment.dealer,
                label_hash: commitment.label_hash,
                accepted_receivers: config.parties.clone(),
                complaint_hash,
                transcript_hash: hash_it_vss_public_commitment(commitment),
            })
            .collect::<Vec<_>>();
        let resolution = ItVssComplaintResolution {
            accepted_dealers,
            rejected_dealers,
            complaints: complaints.to_vec(),
            certificates,
        };
        validate_it_vss_complaint_resolution_for_backend(
            config,
            public_commitments,
            &resolution,
            self.backend_id(),
        )?;
        Ok(resolution)
    }
}

/// Test artifact backend for production-identity IT-VSS certificates.
///
/// This exercises the production artifact shape and release gates in tests. It
/// is not the full Rabin-Ben-Or information-checking VSS protocol and is not
/// compiled into normal crate builds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
pub struct TestInformationCheckingVssBackend;

#[cfg(test)]
impl TestInformationCheckingVssBackend {
    fn first_failed_tag(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<Option<ItVssInformationCheckComplaintEvidence>, DkgError> {
        if public_commitment.backend_id != ItVssBackendId::ProductionInformationChecking
            || public_commitment.dealer != delivery.dealer
            || public_commitment.label_hash != delivery.label_hash
            || public_commitment.public_metadata_hash
                != production_it_vss_public_metadata_hash(
                    delivery.label_hash,
                    delivery.dealer,
                    &delivery.share,
                )
        {
            let received_share_hash = hash_it_vss_received_share(
                delivery.label_hash,
                delivery.dealer,
                delivery.receiver,
                &delivery.share,
            );
            let delivery_transcript_hash = hash_it_vss_private_delivery_transcript(delivery);
            let expected_tag_hash = hash_it_vss_tag(&[]);
            return Ok(Some(ItVssInformationCheckComplaintEvidence {
                dealer: delivery.dealer,
                receiver: delivery.receiver,
                tagger: delivery.receiver,
                label_hash: delivery.label_hash,
                expected_tag_hash,
                received_share_hash,
                delivery_transcript_hash,
                transcript_hash: transcript_hash_it_vss_information_check_complaint(
                    expected_tag_hash,
                    received_share_hash,
                    delivery_transcript_hash,
                ),
            }));
        }

        validate_exact_party_set(
            config,
            DkgRound::Share,
            delivery.information_tags.iter().map(|tag| tag.tagger),
        )?;
        for tag in &delivery.information_tags {
            if tag.verifier != delivery.receiver || tag.label_hash != delivery.label_hash {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
            let expected = production_it_vss_tag_bytes(
                delivery.label_hash,
                delivery.dealer,
                delivery.receiver,
                tag.tagger,
                &delivery.share,
            );
            if tag.tag != expected {
                let expected_tag_hash = hash_it_vss_tag(&expected);
                let received_share_hash = hash_it_vss_received_share(
                    delivery.label_hash,
                    delivery.dealer,
                    delivery.receiver,
                    &delivery.share,
                );
                let delivery_transcript_hash = hash_it_vss_private_delivery_transcript(delivery);
                return Ok(Some(ItVssInformationCheckComplaintEvidence {
                    dealer: delivery.dealer,
                    receiver: delivery.receiver,
                    tagger: tag.tagger,
                    label_hash: delivery.label_hash,
                    expected_tag_hash,
                    received_share_hash,
                    delivery_transcript_hash,
                    transcript_hash: transcript_hash_it_vss_information_check_complaint(
                        expected_tag_hash,
                        received_share_hash,
                        delivery_transcript_hash,
                    ),
                }));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
impl ProductionItVssBackend for TestInformationCheckingVssBackend {
    fn backend_id(&self) -> ItVssBackendId {
        ItVssBackendId::ProductionInformationChecking
    }

    fn share_secret<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: ItVssSharingLabel,
        secret: &[u8],
    ) -> Result<ItVssDealerOutput, DkgError> {
        config.validate()?;
        if label.config_hash != config.transcript_hash() {
            return Err(DkgError::FinalOutputConfigMismatch);
        }
        if !config.parties.contains(&label.dealer) {
            return Err(DkgError::UnknownParty(label.dealer));
        }
        let public_commitment = ItVssPublicCommitment {
            backend_id: self.backend_id(),
            dealer: label.dealer,
            label_hash: label.label_hash,
            public_metadata_hash: production_it_vss_public_metadata_hash(
                label.label_hash,
                label.dealer,
                secret,
            ),
        };
        let deliveries = config
            .parties
            .iter()
            .map(|&receiver| {
                let information_tags = config
                    .parties
                    .iter()
                    .map(|&tagger| ItVssInformationTag {
                        tagger,
                        verifier: receiver,
                        label_hash: label.label_hash,
                        tag: production_it_vss_tag_bytes(
                            label.label_hash,
                            label.dealer,
                            receiver,
                            tagger,
                            secret,
                        ),
                    })
                    .collect();
                ItVssPrivateShareDelivery {
                    dealer: label.dealer,
                    receiver,
                    label_hash: label.label_hash,
                    share: secret.to_vec(),
                    information_tags,
                }
            })
            .collect();
        Ok(ItVssDealerOutput {
            public_commitment,
            deliveries,
        })
    }

    fn verify_private_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<(), DkgError> {
        if self
            .first_failed_tag(config, public_commitment, delivery)?
            .is_some()
        {
            Err(DkgError::ComplaintEvidenceMismatch)
        } else {
            Ok(())
        }
    }

    fn complaint_for_invalid_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgComplaintPayload, DkgError> {
        let evidence = self
            .first_failed_tag(config, public_commitment, delivery)?
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        validate_it_vss_information_check_complaint_evidence(config, public_commitment, &evidence)?;
        Ok(DkgComplaintPayload {
            complainant: delivery.receiver,
            dealer: delivery.dealer,
            receiver: delivery.receiver,
            reason: DkgComplaintReason::InvalidVssShare,
            evidence: encode_it_vss_information_check_complaint_evidence(&evidence),
        })
    }

    fn resolve_complaints<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
        complaints: &[DkgComplaintPayload],
    ) -> Result<ItVssComplaintResolution, DkgError> {
        config.validate()?;
        let mut rejected_dealers = Vec::new();
        for complaint in complaints {
            if complaint.reason != DkgComplaintReason::InvalidVssShare {
                return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
            }
            let evidence = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)?;
            let commitment = public_commitments
                .iter()
                .find(|commitment| {
                    commitment.dealer == complaint.dealer
                        && commitment.label_hash == evidence.label_hash
                })
                .ok_or(DkgError::ItVssCertificateMissingCommitment {
                    dealer: complaint.dealer,
                    label_hash: evidence.label_hash,
                })?;
            validate_it_vss_information_check_complaint_evidence(config, commitment, &evidence)?;
            if commitment.backend_id != self.backend_id() {
                return Err(DkgError::ItVssCertificateBackendMismatch);
            }
            if !rejected_dealers.contains(&complaint.dealer) {
                rejected_dealers.push(complaint.dealer);
            }
        }
        let accepted_dealers = config
            .parties
            .iter()
            .copied()
            .filter(|party| !rejected_dealers.contains(party))
            .collect::<Vec<_>>();
        validate_accepted_dealer_subset(config, &accepted_dealers)?;
        let complaint_hash = hash_dkg_complaint_payloads(complaints);
        let certificates = public_commitments
            .iter()
            .filter(|commitment| accepted_dealers.contains(&commitment.dealer))
            .map(|commitment| VerifiedItVssSharingCertificate {
                backend_id: self.backend_id(),
                dealer: commitment.dealer,
                label_hash: commitment.label_hash,
                accepted_receivers: config.parties.clone(),
                complaint_hash,
                transcript_hash: hash_it_vss_public_commitment(commitment),
            })
            .collect::<Vec<_>>();
        let resolution = ItVssComplaintResolution {
            accepted_dealers,
            rejected_dealers,
            complaints: complaints.to_vec(),
            certificates,
        };
        validate_it_vss_complaint_resolution_for_backend(
            config,
            public_commitments,
            &resolution,
            self.backend_id(),
        )?;
        Ok(resolution)
    }
}

/// Deterministic information-checking backend used to exercise the production
/// IT-VSS phase shape in tests. This is not production-secure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub struct DeterministicItVssTestBackend {
    seed: [u8; 32],
}

#[cfg(test)]
impl DeterministicItVssTestBackend {
    /// Creates a deterministic test backend.
    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    fn first_failed_tag(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<Option<ItVssInformationCheckComplaintEvidence>, DkgError> {
        if public_commitment.backend_id != ItVssBackendId::InProcessHashBindingScaffold
            || public_commitment.dealer != delivery.dealer
            || public_commitment.label_hash != delivery.label_hash
            || public_commitment.public_metadata_hash
                != deterministic_it_vss_public_metadata_hash(
                    delivery.label_hash,
                    delivery.dealer,
                    &delivery.share,
                )
        {
            let received_share_hash = hash_it_vss_received_share(
                delivery.label_hash,
                delivery.dealer,
                delivery.receiver,
                &delivery.share,
            );
            let delivery_transcript_hash = hash_it_vss_private_delivery_transcript(delivery);
            let expected_tag_hash = hash_it_vss_tag(&[]);
            return Ok(Some(ItVssInformationCheckComplaintEvidence {
                dealer: delivery.dealer,
                receiver: delivery.receiver,
                tagger: delivery.receiver,
                label_hash: delivery.label_hash,
                expected_tag_hash,
                received_share_hash,
                delivery_transcript_hash,
                transcript_hash: transcript_hash_it_vss_information_check_complaint(
                    expected_tag_hash,
                    received_share_hash,
                    delivery_transcript_hash,
                ),
            }));
        }

        validate_exact_party_set(
            config,
            DkgRound::Share,
            delivery.information_tags.iter().map(|tag| tag.tagger),
        )?;
        for tag in &delivery.information_tags {
            if tag.verifier != delivery.receiver || tag.label_hash != delivery.label_hash {
                return Err(DkgError::ComplaintEvidenceMismatch);
            }
            let expected = deterministic_it_vss_tag_bytes(
                self.seed,
                delivery.label_hash,
                delivery.dealer,
                delivery.receiver,
                tag.tagger,
                &delivery.share,
            );
            if tag.tag != expected {
                let expected_tag_hash = hash_it_vss_tag(&expected);
                let received_share_hash = hash_it_vss_received_share(
                    delivery.label_hash,
                    delivery.dealer,
                    delivery.receiver,
                    &delivery.share,
                );
                let delivery_transcript_hash = hash_it_vss_private_delivery_transcript(delivery);
                return Ok(Some(ItVssInformationCheckComplaintEvidence {
                    dealer: delivery.dealer,
                    receiver: delivery.receiver,
                    tagger: tag.tagger,
                    label_hash: delivery.label_hash,
                    expected_tag_hash,
                    received_share_hash,
                    delivery_transcript_hash,
                    transcript_hash: transcript_hash_it_vss_information_check_complaint(
                        expected_tag_hash,
                        received_share_hash,
                        delivery_transcript_hash,
                    ),
                }));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
impl ProductionItVssBackend for DeterministicItVssTestBackend {
    fn backend_id(&self) -> ItVssBackendId {
        ItVssBackendId::InProcessHashBindingScaffold
    }

    fn share_secret<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: ItVssSharingLabel,
        secret: &[u8],
    ) -> Result<ItVssDealerOutput, DkgError> {
        config.validate()?;
        let public_commitment = ItVssPublicCommitment {
            backend_id: self.backend_id(),
            dealer: label.dealer,
            label_hash: label.label_hash,
            public_metadata_hash: deterministic_it_vss_public_metadata_hash(
                label.label_hash,
                label.dealer,
                secret,
            ),
        };
        let deliveries = config
            .parties
            .iter()
            .map(|&receiver| {
                let information_tags = config
                    .parties
                    .iter()
                    .map(|&tagger| ItVssInformationTag {
                        tagger,
                        verifier: receiver,
                        label_hash: label.label_hash,
                        tag: deterministic_it_vss_tag_bytes(
                            self.seed,
                            label.label_hash,
                            label.dealer,
                            receiver,
                            tagger,
                            secret,
                        ),
                    })
                    .collect();
                ItVssPrivateShareDelivery {
                    dealer: label.dealer,
                    receiver,
                    label_hash: label.label_hash,
                    share: secret.to_vec(),
                    information_tags,
                }
            })
            .collect();
        Ok(ItVssDealerOutput {
            public_commitment,
            deliveries,
        })
    }

    fn verify_private_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<(), DkgError> {
        if self
            .first_failed_tag(config, public_commitment, delivery)?
            .is_some()
        {
            Err(DkgError::ComplaintEvidenceMismatch)
        } else {
            Ok(())
        }
    }

    fn complaint_for_invalid_delivery<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitment: &ItVssPublicCommitment,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgComplaintPayload, DkgError> {
        let evidence = self
            .first_failed_tag(config, public_commitment, delivery)?
            .ok_or(DkgError::ComplaintEvidenceMismatch)?;
        validate_it_vss_information_check_complaint_evidence(config, public_commitment, &evidence)?;
        Ok(DkgComplaintPayload {
            complainant: delivery.receiver,
            dealer: delivery.dealer,
            receiver: delivery.receiver,
            reason: DkgComplaintReason::InvalidVssShare,
            evidence: encode_it_vss_information_check_complaint_evidence(&evidence),
        })
    }

    fn resolve_complaints<P: MlDsaParams>(
        &self,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
        complaints: &[DkgComplaintPayload],
    ) -> Result<ItVssComplaintResolution, DkgError> {
        config.validate()?;
        let mut rejected_dealers = Vec::new();
        for complaint in complaints {
            if complaint.reason != DkgComplaintReason::InvalidVssShare {
                return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
            }
            let evidence = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)?;
            let commitment = public_commitments
                .iter()
                .find(|commitment| {
                    commitment.dealer == complaint.dealer
                        && commitment.label_hash == evidence.label_hash
                })
                .ok_or(DkgError::ItVssCertificateMissingCommitment {
                    dealer: complaint.dealer,
                    label_hash: evidence.label_hash,
                })?;
            validate_it_vss_information_check_complaint_evidence(config, commitment, &evidence)?;
            if !rejected_dealers.contains(&complaint.dealer) {
                rejected_dealers.push(complaint.dealer);
            }
        }
        let accepted_dealers = config
            .parties
            .iter()
            .copied()
            .filter(|party| !rejected_dealers.contains(party))
            .collect::<Vec<_>>();
        validate_accepted_dealer_subset(config, &accepted_dealers)?;
        let complaint_hash = hash_dkg_complaint_payloads(complaints);
        let certificates = public_commitments
            .iter()
            .filter(|commitment| accepted_dealers.contains(&commitment.dealer))
            .map(|commitment| VerifiedItVssSharingCertificate {
                backend_id: self.backend_id(),
                dealer: commitment.dealer,
                label_hash: commitment.label_hash,
                accepted_receivers: config.parties.clone(),
                complaint_hash,
                transcript_hash: hash_it_vss_public_commitment(commitment),
            })
            .collect::<Vec<_>>();
        let resolution = ItVssComplaintResolution {
            accepted_dealers,
            rejected_dealers,
            complaints: complaints.to_vec(),
            certificates,
        };
        validate_it_vss_complaint_resolution_for_backend(
            config,
            public_commitments,
            &resolution,
            self.backend_id(),
        )?;
        Ok(resolution)
    }
}

/// DKG integration mode for the Rabin-Ben-Or-style IT-VSS backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItVssProductionDkgMode {
    /// Production-scale vector/batched IT-VSS. This is the only release mode.
    BatchedVector,
    /// Scalar IT-VSS repeated per secret coefficient. Useful for correctness
    /// tests, but too heavy and not the selected production DKG shape.
    ScalarPerCoefficient,
}

/// V1 release policy for the production information-checking IT-VSS path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItVssV1ReleasePolicy {
    /// DKG integration mode.
    pub dkg_mode: ItVssProductionDkgMode,
    /// Whether the VSS implementation can reveal private share points for
    /// liveness. V1 release forbids public `beta_i` reveal.
    pub public_beta_reveal: bool,
    /// Whether retained receiver-side `(b,c)` IC tags can appear in public
    /// artifacts. V1 release requires these tags to remain receiver-private.
    pub retained_receiver_tags_public: bool,
}

impl Default for ItVssV1ReleasePolicy {
    fn default() -> Self {
        Self {
            dkg_mode: ItVssProductionDkgMode::BatchedVector,
            public_beta_reveal: false,
            retained_receiver_tags_public: false,
        }
    }
}

/// Implementation gates required before the production information-checking
/// IT-VSS backend may be selected for a release DKG setup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionItVssReadiness {
    /// V1 production policy for this backend.
    pub release_policy: ItVssV1ReleasePolicy,
    /// Rabin-Ben-Or-style information checking has been implemented.
    pub information_checking_protocol: bool,
    /// Directed private deliveries run over PQ-authenticated private channels.
    pub pq_private_channels: bool,
    /// Public commitment/complaint phases use equivocation-resistant broadcast.
    pub equivocation_resistant_broadcast: bool,
    /// Complaint resolution/blame policy is implemented and covered by tests.
    pub complaint_resolution_policy: bool,
    /// Optional post-implementation audit metadata. This is intentionally not
    /// a readiness requirement; cryptographic review happens after a complete
    /// production-shaped implementation exists.
    pub external_review: bool,
}

/// Ensures an IT-VSS backend may claim production readiness.
pub fn ensure_production_it_vss_readiness(
    backend_id: ItVssBackendId,
    readiness: ProductionItVssReadiness,
) -> Result<(), DkgError> {
    if backend_id != ItVssBackendId::ProductionInformationChecking {
        return Err(DkgError::ItVssCertificateBackendMismatch);
    }
    ensure_it_vss_v1_release_policy_allowed(readiness.release_policy)?;
    if readiness.information_checking_protocol
        && readiness.pq_private_channels
        && readiness.equivocation_resistant_broadcast
        && readiness.complaint_resolution_policy
    {
        Ok(())
    } else {
        Err(DkgError::BlockedPendingReview)
    }
}

/// Enforces the v1 production IT-VSS policy before a backend can be selected
/// for native DKG release paths.
pub fn ensure_it_vss_v1_release_policy_allowed(
    policy: ItVssV1ReleasePolicy,
) -> Result<(), DkgError> {
    if policy.dkg_mode == ItVssProductionDkgMode::ScalarPerCoefficient {
        return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
    }
    if policy.public_beta_reveal {
        return Err(DkgError::ItVssPublicBetaRevealReleaseBlocked);
    }
    if policy.retained_receiver_tags_public {
        return Err(DkgError::ItVssRetainedTagPublicArtifactReleaseBlocked);
    }
    Ok(())
}
