use super::*;

/// ML-DSA suite selected for a DKG transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgSuite {
    /// ML-DSA-44.
    MlDsa44 = 1,
    /// ML-DSA-65.
    MlDsa65 = 2,
    /// ML-DSA-87.
    MlDsa87 = 3,
}

impl DkgSuite {
    /// Returns the suite for a parameter type.
    pub fn for_params<P: MlDsaParams>() -> Self {
        match P::NAME {
            "ML-DSA-44" => Self::MlDsa44,
            "ML-DSA-65" => Self::MlDsa65,
            "ML-DSA-87" => Self::MlDsa87,
            _ => unreachable!("unknown ML-DSA params"),
        }
    }

    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(value: u8) -> Result<Self, DkgError> {
        match value {
            1 => Ok(Self::MlDsa44),
            2 => Ok(Self::MlDsa65),
            3 => Ok(Self::MlDsa87),
            _ => Err(DkgError::UnknownSuite(value)),
        }
    }

    /// Serialized FIPS ML-DSA public-key length for this suite.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => talus_core::MlDsa44::PK_LEN,
            Self::MlDsa65 => talus_core::MlDsa65::PK_LEN,
            Self::MlDsa87 => talus_core::MlDsa87::PK_LEN,
        }
    }

    /// Encoded public `t1` length for this suite.
    pub const fn t1_len(self) -> usize {
        self.public_key_len() - 32
    }
}

/// Key-generation epoch number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeygenEpoch(pub u64);

/// Hash binding the DKG configuration and accepted public transcript.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeygenTranscriptHash(pub [u8; 32]);

/// Canonical DKG configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgConfig {
    /// ML-DSA suite.
    pub suite: DkgSuite,
    /// Threshold number of signers needed online.
    pub threshold: u16,
    /// Sorted participating parties.
    pub parties: Vec<PartyId>,
    /// Key-generation epoch.
    pub epoch: KeygenEpoch,
    /// Whether to require `N >= 2T - 1` in this deployment profile.
    pub enforce_honest_majority_shape: bool,
}

impl DkgConfig {
    /// Builds and validates a DKG config for one ML-DSA suite.
    pub fn new<P: MlDsaParams>(
        threshold: u16,
        parties: Vec<PartyId>,
        epoch: KeygenEpoch,
    ) -> Result<Self, DkgError> {
        Self::new_for_suite(DkgSuite::for_params::<P>(), threshold, parties, epoch)
    }

    /// Builds and validates a DKG config for an explicit suite id.
    pub fn new_for_suite(
        suite: DkgSuite,
        threshold: u16,
        parties: Vec<PartyId>,
        epoch: KeygenEpoch,
    ) -> Result<Self, DkgError> {
        let config = Self {
            suite,
            threshold,
            parties,
            epoch,
            enforce_honest_majority_shape: true,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates party ordering, threshold bounds, and deployment shape.
    pub fn validate(&self) -> Result<(), DkgError> {
        if self.threshold == 0 {
            return Err(DkgError::InvalidThreshold {
                threshold: self.threshold,
                parties: self.parties.len(),
            });
        }

        if usize::from(self.threshold) > self.parties.len() {
            return Err(DkgError::InvalidThreshold {
                threshold: self.threshold,
                parties: self.parties.len(),
            });
        }

        if self.parties.is_empty() {
            return Err(DkgError::EmptyPartySet);
        }

        let mut last = None;
        for &party in &self.parties {
            if let Some(previous) = last {
                if party == previous {
                    return Err(DkgError::DuplicateParty(party));
                }
                if party < previous {
                    return Err(DkgError::UnsortedParties);
                }
            }
            last = Some(party);
        }

        if self.enforce_honest_majority_shape {
            let required = usize::from(self.threshold)
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or(DkgError::InvalidThreshold {
                    threshold: self.threshold,
                    parties: self.parties.len(),
                })?;

            if self.parties.len() < required {
                return Err(DkgError::InsufficientPartiesForThreshold {
                    threshold: self.threshold,
                    parties: self.parties.len(),
                    required,
                });
            }
        }

        Ok(())
    }

    /// Computes the deterministic hash of this configuration.
    pub fn transcript_hash(&self) -> KeygenTranscriptHash {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/config");
        hasher.update([self.suite.as_u8()]);
        hasher.update(self.threshold.to_le_bytes());
        hasher.update(self.epoch.0.to_le_bytes());
        hasher.update((self.parties.len() as u32).to_le_bytes());
        for party in &self.parties {
            hasher.update(party.0.to_le_bytes());
        }
        KeygenTranscriptHash(hasher.finalize().into())
    }

    /// Returns the canonical Shamir interpolation point for `party`.
    ///
    /// TALUS currently uses the numeric party id as the public field point.
    /// Party id zero is therefore invalid for Shamir-backed DKG output.
    pub fn interpolation_point<P: MlDsaParams>(&self, party: PartyId) -> Result<u32, DkgError> {
        if !self.parties.contains(&party) {
            return Err(DkgError::UnknownParty(party));
        }
        let point = u32::from(party.0);
        validate_interpolation_point::<P>(point).map_err(|_| DkgError::InvalidSharePoint {
            party,
            expected: point,
            got: point,
        })?;
        Ok(point)
    }

    /// Returns `(party, interpolation_point)` for all configured parties.
    pub fn interpolation_points<P: MlDsaParams>(&self) -> Result<Vec<(PartyId, u32)>, DkgError> {
        self.parties
            .iter()
            .map(|&party| Ok((party, self.interpolation_point::<P>(party)?)))
            .collect()
    }
}

/// Public IT-VSS commitment/check bytes for one polynomial coefficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VssCommitment {
    /// Commitment/check bytes in the selected VSS backend encoding.
    pub bytes: Vec<u8>,
}

/// Backwards-compatible alias for older scaffold naming.
#[deprecated(note = "use VssCommitment; production VSS is information-theoretic, not Pedersen")]
pub type PedersenCommitment = VssCommitment;

/// Public commitment to one party's `A * s1_i` contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct As1Commitment {
    /// Party whose secret share is committed.
    pub party: PartyId,
    /// Serialized `A * s1_i` commitment vector.
    pub bytes: Vec<u8>,
}

/// Public commitment to pairwise seed setup material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairwiseSeedCommitment {
    /// Party that sent the seed commitment.
    pub party: PartyId,
    /// Commitment bytes.
    pub commitment: [u8; 32],
}

/// Public output of an accepted TALUS DKG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgPublicOutput {
    /// DKG configuration.
    pub config: DkgConfig,
    /// Hash of the accepted key-generation transcript.
    pub keygen_transcript_hash: KeygenTranscriptHash,
    /// Serialized FIPS ML-DSA public key.
    pub public_key: Vec<u8>,
    /// Public matrix seed `rho`.
    pub rho: [u8; 32],
    /// Encoded public `t1` component, kept opaque to avoid duplicating FIPS encoders.
    pub t1: Vec<u8>,
    /// Accepted VSS commitments.
    pub vss_commitments: Vec<VssCommitment>,
    /// Accepted `A * s1_i` commitments for online partial verification.
    pub as1_commitments: Vec<As1Commitment>,
    /// Accepted pairwise seed commitments for preprocessing/triple derivation.
    pub pairwise_seed_commitments: Vec<PairwiseSeedCommitment>,
}

impl DkgPublicOutput {
    /// Validates canonical public-output shape independent of transcript hash.
    pub fn validate_shape(&self) -> Result<(), DkgError> {
        self.config.validate()?;
        if self.public_key.len() != self.config.suite.public_key_len() {
            return Err(DkgError::InvalidPublicKeyLength {
                expected: self.config.suite.public_key_len(),
                got: self.public_key.len(),
            });
        }
        if self.t1.len() != self.config.suite.t1_len() {
            return Err(DkgError::InvalidT1Length {
                expected: self.config.suite.t1_len(),
                got: self.t1.len(),
            });
        }
        if self.vss_commitments.is_empty() {
            return Err(DkgError::EmptyPublicCommitments);
        }
        validate_commitment_party_set(
            &self.config,
            self.as1_commitments.iter().map(|item| item.party),
            CommitmentSet::As1,
        )?;
        validate_commitment_party_set(
            &self.config,
            self.pairwise_seed_commitments.iter().map(|item| item.party),
            CommitmentSet::PairwiseSeed,
        )?;
        Ok(())
    }

    /// Recomputes the transcript binding for this public output.
    pub fn transcript_binding(&self) -> KeygenTranscriptHash {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/output");
        hasher.update(self.config.transcript_hash().0);
        hasher.update((self.public_key.len() as u32).to_le_bytes());
        hasher.update(&self.public_key);
        hasher.update(self.rho);
        hasher.update((self.t1.len() as u32).to_le_bytes());
        hasher.update(&self.t1);
        hash_len_prefixed_vecs(
            &mut hasher,
            self.vss_commitments.iter().map(|item| &item.bytes),
        );
        hash_party_vecs(
            &mut hasher,
            self.as1_commitments
                .iter()
                .map(|item| (item.party, &item.bytes)),
        );
        hasher.update((self.pairwise_seed_commitments.len() as u32).to_le_bytes());
        for item in &self.pairwise_seed_commitments {
            hasher.update(item.party.0.to_le_bytes());
            hasher.update(item.commitment);
        }
        KeygenTranscriptHash(hasher.finalize().into())
    }

    /// Checks that embedded output fields match the declared transcript hash.
    pub fn validate_binding(&self) -> Result<(), DkgError> {
        self.validate_shape()?;
        let expected = self.transcript_binding();
        if expected != self.keygen_transcript_hash {
            return Err(DkgError::TranscriptMismatch {
                expected,
                got: self.keygen_transcript_hash,
            });
        }
        Ok(())
    }
}

/// Local secret share material produced by a DKG backend.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgSecretShare {
    /// Owning party.
    pub party: PartyId,
    /// Opaque encoded `s1` share.
    pub s1_share: Vec<u8>,
    /// Opaque encoded `s2` share.
    pub s2_share: Vec<u8>,
    /// Opaque encoded `t0` share.
    pub t0_share: Vec<u8>,
    /// Pairwise PRF seeds, opaque to this scaffold.
    pub pairwise_seed_shares: Vec<Vec<u8>>,
}

impl fmt::Debug for DkgSecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgSecretShare")
            .field("party", &self.party)
            .field("s1_share", &"<redacted>")
            .field("s2_share", &"<redacted>")
            .field("t0_share", &"<redacted>")
            .field("pairwise_seed_shares", &"<redacted>")
            .finish()
    }
}

/// Local long-term `s1` share stored in a DKG key package.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgS1SecretShare {
    /// Owning party.
    pub party: PartyId,
    /// Opaque encoded `s1` share.
    pub s1_share: Vec<u8>,
    /// Pairwise PRF seeds, opaque to this scaffold.
    pub pairwise_seed_shares: Vec<Vec<u8>>,
}

impl fmt::Debug for DkgS1SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgS1SecretShare")
            .field("party", &self.party)
            .field("s1_share", &"<redacted>")
            .field("pairwise_seed_shares", &"<redacted>")
            .finish()
    }
}

/// Typed field-valued bounded-vector share stored in a `DkgSecretShare`.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedSecretVectorShare {
    /// Owning receiver party.
    pub party: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Field-valued coefficient shares.
    pub coeffs: Vec<Coeff>,
}

impl fmt::Debug for BoundedSecretVectorShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedSecretVectorShare")
            .field("party", &self.party)
            .field("point", &self.point)
            .field("coeffs", &"<redacted>")
            .finish()
    }
}

impl BoundedSecretVectorShare {
    /// Creates and validates a typed bounded-vector share.
    pub fn new<P: MlDsaParams>(
        config: &DkgConfig,
        party: PartyId,
        point: u32,
        coeffs: Vec<Coeff>,
    ) -> Result<Self, DkgError> {
        let expected_point = config.interpolation_point::<P>(party)?;
        if point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party,
                expected: expected_point,
                got: point,
            });
        }
        validate_field_vector_share::<P>(&coeffs)?;
        Ok(Self {
            party,
            point,
            coeffs,
        })
    }

    /// Canonically encodes this secret share for local storage/provisioning.
    pub fn encode<P: MlDsaParams>(&self, config: &DkgConfig) -> Result<Vec<u8>, DkgError> {
        let expected_point = config.interpolation_point::<P>(self.party)?;
        if self.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: self.party,
                expected: expected_point,
                got: self.point,
            });
        }
        validate_field_vector_share::<P>(&self.coeffs)?;

        let mut out = Vec::with_capacity(8 + 1 + 2 + 4 + 4 + self.coeffs.len() * 4);
        out.extend_from_slice(BOUNDED_VECTOR_SHARE_MAGIC);
        out.push(DkgSuite::for_params::<P>().as_u8());
        out.extend_from_slice(&self.party.0.to_le_bytes());
        out.extend_from_slice(&self.point.to_le_bytes());
        out.extend_from_slice(&(self.coeffs.len() as u32).to_le_bytes());
        for &coefficient in &self.coeffs {
            out.extend_from_slice(&coefficient.to_le_bytes());
        }
        Ok(out)
    }

    /// Decodes a canonical field-valued bounded-vector share.
    pub fn decode<P: MlDsaParams>(config: &DkgConfig, bytes: &[u8]) -> Result<Self, DkgError> {
        let min_len = 8 + 1 + 2 + 4 + 4;
        if bytes.len() < min_len {
            return Err(DkgError::InvalidSecretShareEncoding(
                "bounded vector share is truncated",
            ));
        }
        if &bytes[..8] != BOUNDED_VECTOR_SHARE_MAGIC {
            return Err(DkgError::InvalidSecretShareEncoding(
                "bounded vector share magic mismatch",
            ));
        }
        let suite = DkgSuite::from_u8(bytes[8])?;
        if suite != config.suite || suite != DkgSuite::for_params::<P>() {
            return Err(DkgError::InvalidSecretShareEncoding(
                "bounded vector share suite mismatch",
            ));
        }

        let party = PartyId(u16::from_le_bytes([bytes[9], bytes[10]]));
        let point = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
        let count = u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]) as usize;
        let expected_count = P::L * P::N;
        if count != expected_count {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: expected_count,
                got: count,
            });
        }
        let expected_len = min_len + count * 4;
        if bytes.len() != expected_len {
            return Err(DkgError::InvalidSecretShareEncoding(
                "bounded vector share length mismatch",
            ));
        }

        let mut coeffs = Vec::with_capacity(count);
        for chunk in bytes[min_len..].chunks_exact(4) {
            coeffs.push(Coeff::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
            ]));
        }
        Self::new::<P>(config, party, point, coeffs)
    }
}

/// One party's complete DKG result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgPartyOutput {
    /// Public output shared by all honest parties.
    pub public: DkgPublicOutput,
    /// Local party secret share.
    pub secret: DkgSecretShare,
}

/// Explicit provisioning package for one party before native IT-DKG is ready.
///
/// This is an operational setup input, not a trusted-dealer shortcut. Every
/// package must carry the same public transcript and one owner-bound secret
/// share, and import must validate the complete party set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionedKeyShare {
    /// Party receiving this package.
    pub party: PartyId,
    /// Public key-generation output agreed by the ceremony.
    pub public: DkgPublicOutput,
    /// Local secret material for `party`.
    pub secret: DkgSecretShare,
    /// Hash of the external provisioning ceremony transcript.
    pub ceremony_transcript_hash: [u8; 32],
}

/// Validates and imports explicit reviewed PQ key-share provisioning packages.
pub fn import_provisioned_key_shares(
    config: &DkgConfig,
    packages: Vec<ProvisionedKeyShare>,
) -> Result<Vec<DkgPartyOutput>, DkgError> {
    config.validate()?;
    validate_exact_party_set(
        config,
        DkgRound::Finalize,
        packages.iter().map(|package| package.party),
    )?;

    let Some(first) = packages.first() else {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Finalize,
            expected: config.parties.len(),
            got: 0,
        });
    };
    let first_public = first.public.clone();
    if first_public.config != *config {
        return Err(DkgError::FinalOutputConfigMismatch);
    }
    first_public.validate_binding()?;

    let ceremony_hash = first.ceremony_transcript_hash;
    if ceremony_hash == [0u8; 32] {
        return Err(DkgError::EmptyProvisioningTranscript);
    }

    let mut outputs = Vec::with_capacity(packages.len());
    for package in packages {
        if package.public != first_public {
            return Err(DkgError::ProvisionedPublicOutputDisagreement);
        }
        if package.ceremony_transcript_hash != ceremony_hash {
            return Err(DkgError::ProvisioningTranscriptDisagreement);
        }
        if package.secret.party != package.party {
            return Err(DkgError::PartyMismatch {
                expected: package.party,
                got: package.secret.party,
            });
        }
        validate_secret_share_shape(&package.public.config, &package.secret)?;
        outputs.push(DkgPartyOutput {
            public: package.public,
            secret: package.secret,
        });
    }

    Ok(outputs)
}

/// Validates canonical encoded `s1` share bytes for the configured suite.
pub fn validate_encoded_s1_share(
    config: &DkgConfig,
    party: PartyId,
    bytes: &[u8],
) -> Result<(), DkgError> {
    match config.suite {
        DkgSuite::MlDsa44 => {
            validate_encoded_s1_share_for_params::<talus_core::MlDsa44>(config, party, bytes)
        }
        DkgSuite::MlDsa65 => {
            validate_encoded_s1_share_for_params::<talus_core::MlDsa65>(config, party, bytes)
        }
        DkgSuite::MlDsa87 => {
            validate_encoded_s1_share_for_params::<talus_core::MlDsa87>(config, party, bytes)
        }
    }
}
