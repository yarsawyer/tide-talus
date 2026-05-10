#[cfg(test)]
use super::*;

/// Deterministic local Fq backend for exercising the private Power2Round
/// circuit. It records only public opening labels and is not a distributed MPC
/// backend.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct LocalPrimeFieldMpcBackend {
    seed: [u8; 32],
    counter: u64,
    opened_labels: Vec<String>,
    counters: PrimeFieldMpcCounters,
}

#[cfg(test)]
impl LocalPrimeFieldMpcBackend {
    /// Creates a deterministic local backend.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            opened_labels: Vec::new(),
            counters: PrimeFieldMpcCounters::default(),
        }
    }

    /// Returns the public opening labels observed by this backend.
    pub fn opened_labels(&self) -> &[String] {
        &self.opened_labels
    }

    /// Returns backend operation counters.
    pub fn operation_counters(&self) -> PrimeFieldMpcCounters {
        self.counters
    }

    fn next_u64(&mut self, label: &Power2RoundTranscriptLabel) -> u64 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/local-prime-field-mpc-rng");
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        hasher.update(label.as_str().as_bytes());
        self.counter = self.counter.wrapping_add(1);
        let digest: [u8; 32] = hasher.finalize().into();
        u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"))
    }
}

#[cfg(test)]
impl<P: MlDsaParams> ItMpcPrimeFieldBackend<P> for LocalPrimeFieldMpcBackend {
    type Share = PrimeFieldShare;
    type BitShare = PrimeFieldBitShare;

    fn secret_share(&self, value: Coeff) -> Self::Share {
        PrimeFieldShare::new::<P>(value)
    }

    fn public_const(&self, value: Coeff) -> Self::Share {
        PrimeFieldShare::new::<P>(value)
    }

    fn public_bit(&self, value: bool) -> Self::BitShare {
        PrimeFieldBitShare {
            share: PrimeFieldShare::new::<P>(i32::from(value)),
        }
    }

    fn bit_to_share(&self, bit: &Self::BitShare) -> Self::Share {
        bit.share.clone()
    }

    fn bit_from_share_unchecked(&self, share: Self::Share) -> Self::BitShare {
        PrimeFieldBitShare { share }
    }

    fn add(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        PrimeFieldShare::new::<P>(x.value + y.value)
    }

    fn sub(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        PrimeFieldShare::new::<P>(x.value - y.value)
    }

    fn mul(
        &mut self,
        x: Self::Share,
        y: Self::Share,
        _label: Power2RoundTranscriptLabel,
    ) -> Result<Self::Share, DkgError> {
        self.counters.scalar_mul_gates += 1;
        let product = (i64::from(x.value) * i64::from(y.value)).rem_euclid(i64::from(P::Q));
        Ok(PrimeFieldShare::new::<P>(product as Coeff))
    }

    fn mul_public_const(
        &self,
        x: Self::Share,
        constant: Coeff,
        _label: Power2RoundTranscriptLabel,
    ) -> Self::Share {
        let product = (i64::from(x.value) * i64::from(constant)).rem_euclid(i64::from(P::Q));
        PrimeFieldShare::new::<P>(product as Coeff)
    }

    fn assert_zero(
        &mut self,
        x: Self::Share,
        _label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.counters.scalar_assert_zero += 1;
        if reduce_mod_q::<P>(x.value) == 0 {
            Ok(())
        } else {
            Err(DkgError::Power2RoundCanonicalityFailure)
        }
    }

    fn open_checked(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Coeff, DkgError> {
        self.counters.scalar_openings += 1;
        self.opened_labels.push(label.as_str().to_owned());
        Ok(reduce_mod_q::<P>(x.value))
    }

    fn open_many_checked(
        &mut self,
        xs: &[Self::Share],
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.counters.scalar_openings += xs.len() as u64;
        self.opened_labels.push(label.as_str().to_owned());
        Ok(xs
            .iter()
            .map(|share| reduce_mod_q::<P>(share.value))
            .collect())
    }

    fn random_bit(
        &mut self,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::BitShare, DkgError> {
        self.counters.random_bits += 1;
        let bit = (self.next_u64(&label) & 1) == 1;
        Ok(<Self as ItMpcPrimeFieldBackend<P>>::public_bit(self, bit))
    }

    fn counters(&self) -> Option<PrimeFieldMpcCounters> {
        Some(self.counters)
    }

    fn mul_public_const_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        constant: Coeff,
        _label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        self.counters.local_public_mul_lanes += x.len() as u64;
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .map(|lane| {
                    let product =
                        (i64::from(lane.value) * i64::from(constant)).rem_euclid(i64::from(P::Q));
                    PrimeFieldShare::new::<P>(product as Coeff)
                })
                .collect(),
        ))
    }

    fn mul_public_const_lanes(
        &mut self,
        x: ShareVec<Self::Share>,
        constants: &[Coeff],
        _label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != constants.len() {
            return Err(DkgError::Backend(
                "prime-field public-constant lane mismatch",
            ));
        }
        self.counters.local_public_mul_lanes += x.len() as u64;
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .zip(constants.iter().copied())
                .map(|(lane, constant)| {
                    let product =
                        (i64::from(lane.value) * i64::from(constant)).rem_euclid(i64::from(P::Q));
                    PrimeFieldShare::new::<P>(product as Coeff)
                })
                .collect(),
        ))
    }

    fn mul_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        y: ShareVec<Self::Share>,
        _label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != y.len() {
            return Err(DkgError::Backend("prime-field vector length mismatch"));
        }
        self.counters.vector_mul_lanes += x.len() as u64;
        Ok(ShareVec::from_lanes(
            x.into_lanes()
                .into_iter()
                .zip(y.into_lanes())
                .map(|(left, right)| {
                    let product = (i64::from(left.value) * i64::from(right.value))
                        .rem_euclid(i64::from(P::Q));
                    PrimeFieldShare::new::<P>(product as Coeff)
                })
                .collect(),
        ))
    }

    fn assert_zero_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        _label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.counters.vector_assert_zero_lanes += x.len() as u64;
        if x.lanes()
            .iter()
            .all(|share| reduce_mod_q::<P>(share.value) == 0)
        {
            Ok(())
        } else {
            Err(DkgError::Power2RoundCanonicalityFailure)
        }
    }

    fn open_vec_checked(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.counters.vector_opening_lanes += x.len() as u64;
        self.opened_labels.push(label.as_str().to_owned());
        Ok(x.into_lanes()
            .into_iter()
            .map(|share| reduce_mod_q::<P>(share.value))
            .collect())
    }

    fn random_bit_vec(
        &mut self,
        len: usize,
        label: Power2RoundTranscriptLabel,
    ) -> Result<BitShareVec<Self::BitShare>, DkgError> {
        self.counters.random_bits += len as u64;
        Ok(BitShareVec::from_lanes(
            (0..len)
                .map(|index| {
                    let bit = (self.next_u64(&label.child(format!("lane_{index}"))) & 1) == 1;
                    <Self as ItMpcPrimeFieldBackend<P>>::public_bit(self, bit)
                })
                .collect(),
        ))
    }
}

/// In-process Shamir/IT-MPC shaped backend for DKG `Power2Round`.
///
/// This backend preserves the distributed share representation and transcript
/// labels, but multiplication and checked openings are implemented by local
/// reconstruction in the test process followed by deterministic resharing. It
/// is the integration target for native DKG tests, not the production network
/// backend.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct InProcessShamirPrimeFieldMpcBackend {
    config: DkgConfig,
    seed: [u8; 32],
    counter: u64,
    opened_labels: Vec<String>,
    gate_labels: Vec<String>,
}

#[cfg(test)]
impl InProcessShamirPrimeFieldMpcBackend {
    /// Creates a deterministic in-process Shamir backend.
    pub fn new(config: DkgConfig, seed: [u8; 32]) -> Self {
        Self {
            config,
            seed,
            counter: 0,
            opened_labels: Vec::new(),
            gate_labels: Vec::new(),
        }
    }

    /// Returns public opening labels.
    pub fn opened_labels(&self) -> &[String] {
        &self.opened_labels
    }

    /// Returns multiplication/assertion gate labels.
    pub fn gate_labels(&self) -> &[String] {
        &self.gate_labels
    }

    fn next_mask<P: MlDsaParams>(&mut self, label: &Power2RoundTranscriptLabel) -> Coeff {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/in-process-shamir-prime-mask");
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        hasher.update(label.as_str().as_bytes());
        self.counter = self.counter.wrapping_add(1);
        let digest: [u8; 32] = hasher.finalize().into();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
        (value % (P::Q as u64)) as Coeff
    }

    fn points<P: MlDsaParams>(&self) -> Result<Vec<u32>, DkgError> {
        self.config
            .parties
            .iter()
            .map(|&party| self.config.interpolation_point::<P>(party))
            .collect()
    }

    fn share_secret<P: MlDsaParams>(
        &mut self,
        secret: Coeff,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShamirPrimeFieldShare, DkgError> {
        let mut coefficients = Vec::with_capacity(usize::from(self.config.threshold));
        coefficients.push(reduce_mod_q::<P>(secret));
        for degree in 1..usize::from(self.config.threshold) {
            coefficients.push(self.next_mask::<P>(&label.child(format!("degree_{degree}"))));
        }
        Ok(ShamirPrimeFieldShare {
            shares: share_scalar_with_polynomial::<P>(&coefficients, &self.points::<P>()?)?,
        })
    }

    fn reconstruct<P: MlDsaParams>(
        &self,
        share: &ShamirPrimeFieldShare,
    ) -> Result<Coeff, DkgError> {
        reconstruct_scalar_at_zero::<P>(
            &share
                .shares
                .iter()
                .take(usize::from(self.config.threshold))
                .copied()
                .collect::<Vec<_>>(),
        )
    }

    fn validate_share_shape<P: MlDsaParams>(
        &self,
        share: &ShamirPrimeFieldShare,
    ) -> Result<(), DkgError> {
        if share.shares.len() != self.config.parties.len() {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Share,
                expected: self.config.parties.len(),
                got: share.shares.len(),
            });
        }
        for (share, &party) in share.shares.iter().zip(&self.config.parties) {
            let expected = self.config.interpolation_point::<P>(party)?;
            if share.point != expected {
                return Err(DkgError::InvalidSharePoint {
                    party,
                    expected,
                    got: share.point,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
impl<P: MlDsaParams> ItMpcPrimeFieldBackend<P> for InProcessShamirPrimeFieldMpcBackend {
    type Share = ShamirPrimeFieldShare;
    type BitShare = ShamirPrimeFieldBitShare;

    fn secret_share(&self, value: Coeff) -> Self::Share {
        let points = self
            .config
            .interpolation_points::<P>()
            .expect("validated config points")
            .into_iter()
            .map(|(_, point)| point)
            .collect::<Vec<_>>();
        ShamirPrimeFieldShare {
            shares: points
                .into_iter()
                .map(|point| ShamirScalarShare {
                    point,
                    value: reduce_mod_q::<P>(value),
                })
                .collect(),
        }
    }

    fn public_const(&self, value: Coeff) -> Self::Share {
        <Self as ItMpcPrimeFieldBackend<P>>::secret_share(self, value)
    }

    fn public_bit(&self, value: bool) -> Self::BitShare {
        ShamirPrimeFieldBitShare {
            share: <Self as ItMpcPrimeFieldBackend<P>>::public_const(self, i32::from(value)),
        }
    }

    fn bit_to_share(&self, bit: &Self::BitShare) -> Self::Share {
        bit.share.clone()
    }

    fn bit_from_share_unchecked(&self, share: Self::Share) -> Self::BitShare {
        ShamirPrimeFieldBitShare { share }
    }

    fn add(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        ShamirPrimeFieldShare {
            shares: x
                .shares
                .iter()
                .zip(y.shares)
                .map(|(left, right)| ShamirScalarShare {
                    point: left.point,
                    value: reduce_mod_q::<P>(left.value + right.value),
                })
                .collect(),
        }
    }

    fn sub(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        ShamirPrimeFieldShare {
            shares: x
                .shares
                .iter()
                .zip(y.shares)
                .map(|(left, right)| ShamirScalarShare {
                    point: left.point,
                    value: reduce_mod_q::<P>(left.value - right.value),
                })
                .collect(),
        }
    }

    fn mul(
        &mut self,
        x: Self::Share,
        y: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::Share, DkgError> {
        self.validate_share_shape::<P>(&x)?;
        self.validate_share_shape::<P>(&y)?;
        self.gate_labels.push(label.as_str().to_owned());
        let left = self.reconstruct::<P>(&x)?;
        let right = self.reconstruct::<P>(&y)?;
        let product = (i64::from(left) * i64::from(right)).rem_euclid(i64::from(P::Q)) as Coeff;
        self.share_secret::<P>(product, label.child("degree_reduce_reshare"))
    }

    fn mul_public_const(
        &self,
        x: Self::Share,
        constant: Coeff,
        _label: Power2RoundTranscriptLabel,
    ) -> Self::Share {
        mul_shamir_share_public_const::<P>(x, constant)
    }

    fn assert_zero(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.validate_share_shape::<P>(&x)?;
        self.gate_labels.push(label.as_str().to_owned());
        if self.reconstruct::<P>(&x)? == 0 {
            Ok(())
        } else {
            Err(DkgError::Power2RoundCanonicalityFailure)
        }
    }

    fn open_checked(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Coeff, DkgError> {
        self.validate_share_shape::<P>(&x)?;
        self.opened_labels.push(label.as_str().to_owned());
        self.reconstruct::<P>(&x)
    }

    fn open_many_checked(
        &mut self,
        xs: &[Self::Share],
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        xs.iter()
            .map(|share| {
                self.validate_share_shape::<P>(share)?;
                self.reconstruct::<P>(share)
            })
            .collect()
    }

    fn random_bit(
        &mut self,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::BitShare, DkgError> {
        let bit = (self.next_mask::<P>(&label) & 1) == 1;
        Ok(ShamirPrimeFieldBitShare {
            share: self.share_secret::<P>(i32::from(bit), label.child("share_random_bit"))?,
        })
    }

    fn mul_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        y: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != y.len() {
            return Err(DkgError::Backend("prime-field vector length mismatch"));
        }
        self.gate_labels.push(label.as_str().to_owned());
        let lanes = x
            .into_lanes()
            .into_iter()
            .zip(y.into_lanes())
            .enumerate()
            .map(|(index, (left_share, right_share))| {
                self.validate_share_shape::<P>(&left_share)?;
                self.validate_share_shape::<P>(&right_share)?;
                let left = self.reconstruct::<P>(&left_share)?;
                let right = self.reconstruct::<P>(&right_share)?;
                let product =
                    (i64::from(left) * i64::from(right)).rem_euclid(i64::from(P::Q)) as Coeff;
                self.share_secret::<P>(
                    product,
                    label.child(format!("lane_{index}/degree_reduce_reshare")),
                )
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        Ok(ShareVec::from_lanes(lanes))
    }

    fn assert_zero_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.gate_labels.push(label.as_str().to_owned());
        for lane in x.into_lanes() {
            self.validate_share_shape::<P>(&lane)?;
            if self.reconstruct::<P>(&lane)? != 0 {
                return Err(DkgError::Power2RoundCanonicalityFailure);
            }
        }
        Ok(())
    }

    fn open_vec_checked(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        x.into_lanes()
            .into_iter()
            .map(|lane| {
                self.validate_share_shape::<P>(&lane)?;
                self.reconstruct::<P>(&lane)
            })
            .collect()
    }

    fn random_bit_vec(
        &mut self,
        len: usize,
        label: Power2RoundTranscriptLabel,
    ) -> Result<BitShareVec<Self::BitShare>, DkgError> {
        (0..len)
            .map(|index| {
                let bit = (self.next_mask::<P>(&label.child(format!("lane_{index}"))) & 1) == 1;
                Ok(ShamirPrimeFieldBitShare {
                    share: self.share_secret::<P>(
                        i32::from(bit),
                        label.child(format!("lane_{index}/share_random_bit")),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, DkgError>>()
            .map(BitShareVec::from_lanes)
    }
}

/// One in-memory networked prime-field MPC message.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimeFieldMpcMessage {
    /// Sender party.
    pub sender: PartyId,
    /// Optional directed receiver.
    pub receiver: Option<PartyId>,
    /// Round kind.
    pub kind: PrimeFieldMpcRoundKind,
    /// Transcript label hash.
    pub label_hash: [u8; 32],
    /// Field value share.
    pub value: Coeff,
}

/// One in-memory networked prime-field MPC vector message.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimeFieldMpcVectorMessage {
    /// Sender party.
    pub sender: PartyId,
    /// Optional directed receiver.
    pub receiver: Option<PartyId>,
    /// Round kind.
    pub kind: PrimeFieldMpcRoundKind,
    /// Transcript label hash.
    pub label_hash: [u8; 32],
    /// Field value shares, one per vector lane.
    pub values: Vec<Coeff>,
}

/// In-memory network transcript for the Shamir prime-field MPC backend.
#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryPrimeFieldMpcNetwork {
    messages: Vec<PrimeFieldMpcMessage>,
    vector_messages: Vec<PrimeFieldMpcVectorMessage>,
}

#[cfg(test)]
impl InMemoryPrimeFieldMpcNetwork {
    /// Returns recorded messages.
    pub fn messages(&self) -> &[PrimeFieldMpcMessage] {
        &self.messages
    }

    /// Returns recorded vector messages.
    pub fn vector_messages(&self) -> &[PrimeFieldMpcVectorMessage] {
        &self.vector_messages
    }

    pub(crate) fn send(&mut self, message: PrimeFieldMpcMessage) -> Result<(), DkgError> {
        if self.messages.iter().any(|known| {
            known.sender == message.sender
                && known.receiver == message.receiver
                && known.kind == message.kind
                && known.label_hash == message.label_hash
        }) {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
        self.messages.push(message);
        Ok(())
    }

    pub(crate) fn send_vector(
        &mut self,
        message: PrimeFieldMpcVectorMessage,
    ) -> Result<(), DkgError> {
        if self.vector_messages.iter().any(|known| {
            known.sender == message.sender
                && known.receiver == message.receiver
                && known.kind == message.kind
                && known.label_hash == message.label_hash
        }) {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
        self.vector_messages.push(message);
        Ok(())
    }
}

/// Networked, round-shaped Shamir/IT-MPC simulator for DKG `Power2Round`.
///
/// This backend records explicit directed resharing/opening messages and uses
/// BGW-style degree reduction for multiplication. It is still an in-memory
/// simulator, not a transport-backed production backend.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct NetworkedShamirPrimeFieldMpcBackend {
    config: DkgConfig,
    seed: [u8; 32],
    counter: u64,
    network: InMemoryPrimeFieldMpcNetwork,
    opened_labels: Vec<String>,
    gate_labels: Vec<String>,
}

#[cfg(test)]
impl NetworkedShamirPrimeFieldMpcBackend {
    /// Creates an empty networked Shamir simulator.
    pub fn new(config: DkgConfig, seed: [u8; 32]) -> Self {
        Self {
            config,
            seed,
            counter: 0,
            network: InMemoryPrimeFieldMpcNetwork::default(),
            opened_labels: Vec::new(),
            gate_labels: Vec::new(),
        }
    }

    /// Returns the recorded network transcript.
    pub fn network(&self) -> &InMemoryPrimeFieldMpcNetwork {
        &self.network
    }

    /// Returns public opening labels.
    pub fn opened_labels(&self) -> &[String] {
        &self.opened_labels
    }

    /// Returns multiplication/assertion gate labels.
    pub fn gate_labels(&self) -> &[String] {
        &self.gate_labels
    }

    fn next_mask<P: MlDsaParams>(&mut self, label: &Power2RoundTranscriptLabel) -> Coeff {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/networked-shamir-prime-mask");
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        hasher.update(label.as_str().as_bytes());
        self.counter = self.counter.wrapping_add(1);
        let digest: [u8; 32] = hasher.finalize().into();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
        (value % (P::Q as u64)) as Coeff
    }

    fn points<P: MlDsaParams>(&self) -> Result<Vec<u32>, DkgError> {
        self.config
            .parties
            .iter()
            .map(|&party| self.config.interpolation_point::<P>(party))
            .collect()
    }

    fn share_secret<P: MlDsaParams>(
        &mut self,
        secret: Coeff,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShamirPrimeFieldShare, DkgError> {
        let mut coefficients = Vec::with_capacity(usize::from(self.config.threshold));
        coefficients.push(reduce_mod_q::<P>(secret));
        for degree in 1..usize::from(self.config.threshold) {
            coefficients.push(self.next_mask::<P>(&label.child(format!("degree_{degree}"))));
        }
        Ok(ShamirPrimeFieldShare {
            shares: share_scalar_with_polynomial::<P>(&coefficients, &self.points::<P>()?)?,
        })
    }

    fn validate_share_shape<P: MlDsaParams>(
        &self,
        share: &ShamirPrimeFieldShare,
    ) -> Result<(), DkgError> {
        if share.shares.len() != self.config.parties.len() {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Share,
                expected: self.config.parties.len(),
                got: share.shares.len(),
            });
        }
        for (share, &party) in share.shares.iter().zip(&self.config.parties) {
            let expected = self.config.interpolation_point::<P>(party)?;
            if share.point != expected {
                return Err(DkgError::InvalidSharePoint {
                    party,
                    expected,
                    got: share.point,
                });
            }
        }
        Ok(())
    }

    fn open_from_messages<P: MlDsaParams>(
        &mut self,
        share: &ShamirPrimeFieldShare,
        label: Power2RoundTranscriptLabel,
        kind: PrimeFieldMpcRoundKind,
    ) -> Result<Coeff, DkgError> {
        self.validate_share_shape::<P>(share)?;
        let label_hash = power2round_label_hash(&label);
        for (share, &party) in share.shares.iter().zip(&self.config.parties) {
            self.network.send(PrimeFieldMpcMessage {
                sender: party,
                receiver: None,
                kind,
                label_hash,
                value: share.value,
            })?;
        }
        reconstruct_scalar_at_zero::<P>(&share.shares)
    }
}

#[cfg(test)]
impl<P: MlDsaParams> ItMpcPrimeFieldBackend<P> for NetworkedShamirPrimeFieldMpcBackend {
    type Share = ShamirPrimeFieldShare;
    type BitShare = ShamirPrimeFieldBitShare;

    fn secret_share(&self, value: Coeff) -> Self::Share {
        let points = self
            .config
            .interpolation_points::<P>()
            .expect("validated config points")
            .into_iter()
            .map(|(_, point)| point)
            .collect::<Vec<_>>();
        ShamirPrimeFieldShare {
            shares: points
                .into_iter()
                .map(|point| ShamirScalarShare {
                    point,
                    value: reduce_mod_q::<P>(value),
                })
                .collect(),
        }
    }

    fn public_const(&self, value: Coeff) -> Self::Share {
        <Self as ItMpcPrimeFieldBackend<P>>::secret_share(self, value)
    }

    fn public_bit(&self, value: bool) -> Self::BitShare {
        ShamirPrimeFieldBitShare {
            share: <Self as ItMpcPrimeFieldBackend<P>>::public_const(self, i32::from(value)),
        }
    }

    fn bit_to_share(&self, bit: &Self::BitShare) -> Self::Share {
        bit.share.clone()
    }

    fn bit_from_share_unchecked(&self, share: Self::Share) -> Self::BitShare {
        ShamirPrimeFieldBitShare { share }
    }

    fn add(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        ShamirPrimeFieldShare {
            shares: x
                .shares
                .iter()
                .zip(y.shares)
                .map(|(left, right)| ShamirScalarShare {
                    point: left.point,
                    value: reduce_mod_q::<P>(left.value + right.value),
                })
                .collect(),
        }
    }

    fn sub(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        ShamirPrimeFieldShare {
            shares: x
                .shares
                .iter()
                .zip(y.shares)
                .map(|(left, right)| ShamirScalarShare {
                    point: left.point,
                    value: reduce_mod_q::<P>(left.value - right.value),
                })
                .collect(),
        }
    }

    fn mul(
        &mut self,
        x: Self::Share,
        y: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::Share, DkgError> {
        self.validate_share_shape::<P>(&x)?;
        self.validate_share_shape::<P>(&y)?;
        self.gate_labels.push(label.as_str().to_owned());

        let label_hash = power2round_label_hash(&label);
        let points = self.points::<P>()?;
        let lambdas = lagrange_coefficients_at_zero::<P>(&points)
            .map_err(|_| DkgError::Backend("degree-reduction coefficients failed"))?;
        let mut per_receiver = vec![0; self.config.parties.len()];

        for (dealer_index, &dealer) in self.config.parties.clone().iter().enumerate() {
            let local_product = (i64::from(x.shares[dealer_index].value)
                * i64::from(y.shares[dealer_index].value))
            .rem_euclid(i64::from(P::Q)) as Coeff;
            let weighted = (i64::from(local_product) * i64::from(lambdas[dealer_index]))
                .rem_euclid(i64::from(P::Q)) as Coeff;
            let resharing = self.share_secret::<P>(
                weighted,
                label.child(format!("degree_reduce_dealer_{}", dealer.0)),
            )?;
            for (receiver_index, (&receiver, share)) in self
                .config
                .parties
                .clone()
                .iter()
                .zip(resharing.shares)
                .enumerate()
            {
                self.network.send(PrimeFieldMpcMessage {
                    sender: dealer,
                    receiver: Some(receiver),
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    label_hash,
                    value: share.value,
                })?;
                per_receiver[receiver_index] =
                    reduce_mod_q::<P>(per_receiver[receiver_index] + share.value);
            }
        }

        Ok(ShamirPrimeFieldShare {
            shares: self
                .config
                .parties
                .iter()
                .zip(points)
                .zip(per_receiver)
                .map(|((&_party, point), value)| ShamirScalarShare { point, value })
                .collect(),
        })
    }

    fn mul_public_const(
        &self,
        x: Self::Share,
        constant: Coeff,
        _label: Power2RoundTranscriptLabel,
    ) -> Self::Share {
        mul_shamir_share_public_const::<P>(x, constant)
    }

    fn assert_zero(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.gate_labels.push(label.as_str().to_owned());
        let opened = self.open_from_messages::<P>(&x, label, PrimeFieldMpcRoundKind::AssertZero)?;
        if opened == 0 {
            Ok(())
        } else {
            Err(DkgError::Power2RoundCanonicalityFailure)
        }
    }

    fn open_checked(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Coeff, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        self.open_from_messages::<P>(&x, label, PrimeFieldMpcRoundKind::Open)
    }

    fn open_many_checked(
        &mut self,
        xs: &[Self::Share],
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        xs.iter()
            .enumerate()
            .map(|(index, share)| {
                self.open_from_messages::<P>(
                    share,
                    label.child(format!("item_{index}")),
                    PrimeFieldMpcRoundKind::Open,
                )
            })
            .collect()
    }

    fn random_bit(
        &mut self,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::BitShare, DkgError> {
        let mut bits = Vec::with_capacity(self.config.parties.len());
        for party in self.config.parties.clone() {
            let bit = self.next_mask::<P>(&label.child(format!("party_{}", party.0))) & 1;
            let share =
                self.share_secret::<P>(bit, label.child(format!("random_bit_dealer_{}", party.0)))?;
            bits.push((party, share));
        }

        let mut result = <Self as ItMpcPrimeFieldBackend<P>>::public_bit(self, false);
        let label_hash = power2round_label_hash(&label);
        for (dealer, share) in bits {
            for (&receiver, directed) in self.config.parties.clone().iter().zip(&share.shares) {
                self.network.send(PrimeFieldMpcMessage {
                    sender: dealer,
                    receiver: Some(receiver),
                    kind: PrimeFieldMpcRoundKind::RandomBit,
                    label_hash,
                    value: directed.value,
                })?;
            }
            result = bit_xor::<P, Self>(
                self,
                result,
                ShamirPrimeFieldBitShare { share },
                label.child(format!("xor_party_{}", dealer.0)),
            )?;
        }
        Ok(result)
    }

    fn mul_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        y: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShareVec<Self::Share>, DkgError> {
        if x.len() != y.len() {
            return Err(DkgError::Backend("prime-field vector length mismatch"));
        }
        self.gate_labels.push(label.as_str().to_owned());
        let lane_count = x.len();
        let left_lanes = x.into_lanes();
        let right_lanes = y.into_lanes();
        for lane in left_lanes.iter().chain(right_lanes.iter()) {
            self.validate_share_shape::<P>(lane)?;
        }
        let label_hash = power2round_label_hash(&label);
        let points = self.points::<P>()?;
        let lambdas = lagrange_coefficients_at_zero::<P>(&points)
            .map_err(|_| DkgError::Backend("degree-reduction coefficients failed"))?;
        let mut per_lane_receiver = vec![vec![0; self.config.parties.len()]; lane_count];

        for (dealer_index, &dealer) in self.config.parties.clone().iter().enumerate() {
            let mut receiver_values =
                vec![Vec::with_capacity(lane_count); self.config.parties.len()];
            for (lane_index, (left_share, right_share)) in
                left_lanes.iter().zip(&right_lanes).enumerate()
            {
                let local_product = (i64::from(left_share.shares[dealer_index].value)
                    * i64::from(right_share.shares[dealer_index].value))
                .rem_euclid(i64::from(P::Q)) as Coeff;
                let weighted = (i64::from(local_product) * i64::from(lambdas[dealer_index]))
                    .rem_euclid(i64::from(P::Q)) as Coeff;
                let resharing = self.share_secret::<P>(
                    weighted,
                    label.child(format!(
                        "lane_{lane_index}/degree_reduce_dealer_{}",
                        dealer.0
                    )),
                )?;
                for (receiver_index, share) in resharing.shares.into_iter().enumerate() {
                    receiver_values[receiver_index].push(share.value);
                    per_lane_receiver[lane_index][receiver_index] = reduce_mod_q::<P>(
                        per_lane_receiver[lane_index][receiver_index] + share.value,
                    );
                }
            }
            for (receiver_index, &receiver) in self.config.parties.clone().iter().enumerate() {
                self.network.send_vector(PrimeFieldMpcVectorMessage {
                    sender: dealer,
                    receiver: Some(receiver),
                    kind: PrimeFieldMpcRoundKind::MulDegreeReduce,
                    label_hash,
                    values: receiver_values[receiver_index].clone(),
                })?;
            }
        }

        Ok(ShareVec::from_lanes(
            per_lane_receiver
                .into_iter()
                .map(|per_receiver| ShamirPrimeFieldShare {
                    shares: self
                        .config
                        .parties
                        .iter()
                        .zip(&points)
                        .zip(per_receiver)
                        .map(|((&_party, &point), value)| ShamirScalarShare { point, value })
                        .collect(),
                })
                .collect(),
        ))
    }

    fn assert_zero_vec(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.gate_labels.push(label.as_str().to_owned());
        let lanes = x.into_lanes();
        for lane in &lanes {
            self.validate_share_shape::<P>(lane)?;
        }
        let label_hash = power2round_label_hash(&label);
        for (party_index, &party) in self.config.parties.iter().enumerate() {
            self.network.send_vector(PrimeFieldMpcVectorMessage {
                sender: party,
                receiver: None,
                kind: PrimeFieldMpcRoundKind::AssertZero,
                label_hash,
                values: lanes
                    .iter()
                    .map(|lane| lane.shares[party_index].value)
                    .collect(),
            })?;
        }
        for lane in lanes {
            let opened = reconstruct_scalar_at_zero::<P>(&lane.shares)?;
            if opened != 0 {
                return Err(DkgError::Power2RoundCanonicalityFailure);
            }
        }
        Ok(())
    }

    fn open_vec_checked(
        &mut self,
        x: ShareVec<Self::Share>,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        let lanes = x.into_lanes();
        for lane in &lanes {
            self.validate_share_shape::<P>(lane)?;
        }
        let label_hash = power2round_label_hash(&label);
        for (party_index, &party) in self.config.parties.iter().enumerate() {
            self.network.send_vector(PrimeFieldMpcVectorMessage {
                sender: party,
                receiver: None,
                kind: PrimeFieldMpcRoundKind::Open,
                label_hash,
                values: lanes
                    .iter()
                    .map(|lane| lane.shares[party_index].value)
                    .collect(),
            })?;
        }
        lanes
            .iter()
            .map(|lane| reconstruct_scalar_at_zero::<P>(&lane.shares))
            .collect()
    }

    fn random_bit_vec(
        &mut self,
        len: usize,
        label: Power2RoundTranscriptLabel,
    ) -> Result<BitShareVec<Self::BitShare>, DkgError> {
        let label_hash = power2round_label_hash(&label);
        let mut clear_bits = vec![0; len];
        for party in self.config.parties.clone() {
            let mut receiver_values = vec![Vec::with_capacity(len); self.config.parties.len()];
            for (lane_index, clear_bit) in clear_bits.iter_mut().enumerate() {
                let bit = self
                    .next_mask::<P>(&label.child(format!("lane_{lane_index}/party_{}", party.0)))
                    & 1;
                *clear_bit ^= bit;
                let share = self.share_secret::<P>(
                    bit,
                    label.child(format!("lane_{lane_index}/random_bit_dealer_{}", party.0)),
                )?;
                for (receiver_index, directed) in share.shares.into_iter().enumerate() {
                    receiver_values[receiver_index].push(directed.value);
                }
            }
            for (receiver_index, &receiver) in self.config.parties.clone().iter().enumerate() {
                self.network.send_vector(PrimeFieldMpcVectorMessage {
                    sender: party,
                    receiver: Some(receiver),
                    kind: PrimeFieldMpcRoundKind::RandomBit,
                    label_hash,
                    values: receiver_values[receiver_index].clone(),
                })?;
            }
        }
        clear_bits
            .into_iter()
            .enumerate()
            .map(|(lane_index, clear_bit)| {
                Ok(ShamirPrimeFieldBitShare {
                    share: self.share_secret::<P>(
                        clear_bit,
                        label.child(format!("lane_{lane_index}/combined_random_bit_share")),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, DkgError>>()
            .map(BitShareVec::from_lanes)
    }
}

/// Transport-backed Shamir/IT-MPC simulator for DKG `Power2Round`.
///
/// This backend keeps the all-parties test harness in-process, but every
/// multiplication, checked opening, assert-zero, and random-bit contribution
/// is encoded as canonical `talus-wire` prime-field MPC payloads and accepted
/// through `TransportPrimeFieldMpcStateMachine`. It is still release-blocked:
/// production must replace the in-process scheduler and test transport with a
/// per-party runtime over PQ-authenticated channels.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct TransportBackedShamirPrimeFieldMpcBackend {
    config: DkgConfig,
    seed: [u8; 32],
    counter: u64,
    opened_labels: Vec<String>,
    gate_labels: Vec<String>,
    accepted_rounds: Vec<AcceptedPrimeFieldMpcRound>,
}

#[cfg(test)]
impl TransportBackedShamirPrimeFieldMpcBackend {
    /// Creates a transport-backed Shamir simulator.
    pub fn new(config: DkgConfig, seed: [u8; 32]) -> Self {
        Self {
            config,
            seed,
            counter: 0,
            opened_labels: Vec::new(),
            gate_labels: Vec::new(),
            accepted_rounds: Vec::new(),
        }
    }

    /// Returns public opening labels.
    pub fn opened_labels(&self) -> &[String] {
        &self.opened_labels
    }

    /// Returns multiplication/assertion gate labels.
    pub fn gate_labels(&self) -> &[String] {
        &self.gate_labels
    }

    /// Returns accepted transport round metadata.
    pub fn accepted_rounds(&self) -> &[AcceptedPrimeFieldMpcRound] {
        &self.accepted_rounds
    }

    fn next_mask<P: MlDsaParams>(&mut self, label: &Power2RoundTranscriptLabel) -> Coeff {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-v1/transport-backed-shamir-prime-mask");
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        hasher.update(label.as_str().as_bytes());
        self.counter = self.counter.wrapping_add(1);
        let digest: [u8; 32] = hasher.finalize().into();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
        (value % (P::Q as u64)) as Coeff
    }

    fn points<P: MlDsaParams>(&self) -> Result<Vec<u32>, DkgError> {
        self.config
            .parties
            .iter()
            .map(|&party| self.config.interpolation_point::<P>(party))
            .collect()
    }

    fn share_secret<P: MlDsaParams>(
        &mut self,
        secret: Coeff,
        label: Power2RoundTranscriptLabel,
    ) -> Result<ShamirPrimeFieldShare, DkgError> {
        let mut coefficients = Vec::with_capacity(usize::from(self.config.threshold));
        coefficients.push(reduce_mod_q::<P>(secret));
        for degree in 1..usize::from(self.config.threshold) {
            coefficients.push(self.next_mask::<P>(&label.child(format!("degree_{degree}"))));
        }
        Ok(ShamirPrimeFieldShare {
            shares: share_scalar_with_polynomial::<P>(&coefficients, &self.points::<P>()?)?,
        })
    }

    fn validate_share_shape<P: MlDsaParams>(
        &self,
        share: &ShamirPrimeFieldShare,
    ) -> Result<(), DkgError> {
        if share.shares.len() != self.config.parties.len() {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Share,
                expected: self.config.parties.len(),
                got: share.shares.len(),
            });
        }
        for (share, &party) in share.shares.iter().zip(&self.config.parties) {
            let expected = self.config.interpolation_point::<P>(party)?;
            if share.point != expected {
                return Err(DkgError::InvalidSharePoint {
                    party,
                    expected,
                    got: share.point,
                });
            }
        }
        Ok(())
    }

    fn fresh_state(
        &self,
    ) -> Result<TransportPrimeFieldMpcStateMachine<talus_wire::InMemoryTransport>, DkgError> {
        let parties = self.config.parties.iter().map(|party| party.0).collect();
        let local_party = self.config.parties[0];
        let transport = talus_wire::InMemoryTransport::new(local_party.0, parties)
            .map_err(map_transport_error)?;
        TransportPrimeFieldMpcStateMachine::new(self.config.clone(), local_party, transport)
    }

    fn inject_directed_phase(
        state: &mut TransportPrimeFieldMpcStateMachine<talus_wire::InMemoryTransport>,
        sender: PartyId,
        receiver: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        let mut message = state.wire_message(kind, phase, label, Some(receiver), value)?;
        message.header.sender_party_id = sender.0;
        state
            .transport_mut()
            .inject_private(sender.0, receiver.0, message)
            .map_err(map_transport_error)
    }

    fn inject_broadcast_phase(
        state: &mut TransportPrimeFieldMpcStateMachine<talus_wire::InMemoryTransport>,
        sender: PartyId,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
        label: &Power2RoundTranscriptLabel,
        value: Coeff,
    ) -> Result<(), DkgError> {
        let mut message = state.wire_message(kind, phase, label, None, value)?;
        message.header.sender_party_id = sender.0;
        let observers = state.config.parties.clone();
        for observer in observers {
            state
                .transport_mut()
                .inject_broadcast_delivery(observer.0, message.clone())
                .map_err(map_transport_error)?;
        }
        Ok(())
    }

    fn record_rounds(
        &mut self,
        state: &TransportPrimeFieldMpcStateMachine<talus_wire::InMemoryTransport>,
    ) {
        self.accepted_rounds
            .extend_from_slice(state.accepted_rounds());
    }

    fn open_from_transport_messages<P: MlDsaParams>(
        &mut self,
        share: &ShamirPrimeFieldShare,
        label: Power2RoundTranscriptLabel,
        kind: PrimeFieldMpcRoundKind,
        phase: PrimeFieldMpcPhase,
    ) -> Result<Coeff, DkgError> {
        self.validate_share_shape::<P>(share)?;
        let mut state = self.fresh_state()?;
        for (share, &party) in share.shares.iter().zip(&self.config.parties) {
            Self::inject_broadcast_phase(&mut state, party, kind, phase, &label, share.value)?;
        }
        let opened = state.collect_broadcast_phase(kind, phase, &label)?;
        self.record_rounds(&state);
        if opened.len() != self.config.parties.len() {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Share,
                expected: self.config.parties.len(),
                got: opened.len(),
            });
        }
        let shares = opened
            .into_iter()
            .map(|(party, value)| {
                Ok(ShamirScalarShare {
                    point: self.config.interpolation_point::<P>(party)?,
                    value,
                })
            })
            .collect::<Result<Vec<_>, DkgError>>()?;
        reconstruct_scalar_at_zero::<P>(&shares)
    }
}

#[cfg(test)]
impl<P: MlDsaParams> ItMpcPrimeFieldBackend<P> for TransportBackedShamirPrimeFieldMpcBackend {
    type Share = ShamirPrimeFieldShare;
    type BitShare = ShamirPrimeFieldBitShare;

    fn secret_share(&self, value: Coeff) -> Self::Share {
        let points = self
            .config
            .interpolation_points::<P>()
            .expect("validated config points")
            .into_iter()
            .map(|(_, point)| point)
            .collect::<Vec<_>>();
        ShamirPrimeFieldShare {
            shares: points
                .into_iter()
                .map(|point| ShamirScalarShare {
                    point,
                    value: reduce_mod_q::<P>(value),
                })
                .collect(),
        }
    }

    fn public_const(&self, value: Coeff) -> Self::Share {
        <Self as ItMpcPrimeFieldBackend<P>>::secret_share(self, value)
    }

    fn public_bit(&self, value: bool) -> Self::BitShare {
        ShamirPrimeFieldBitShare {
            share: <Self as ItMpcPrimeFieldBackend<P>>::public_const(self, i32::from(value)),
        }
    }

    fn bit_to_share(&self, bit: &Self::BitShare) -> Self::Share {
        bit.share.clone()
    }

    fn bit_from_share_unchecked(&self, share: Self::Share) -> Self::BitShare {
        ShamirPrimeFieldBitShare { share }
    }

    fn add(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        ShamirPrimeFieldShare {
            shares: x
                .shares
                .iter()
                .zip(y.shares)
                .map(|(left, right)| ShamirScalarShare {
                    point: left.point,
                    value: reduce_mod_q::<P>(left.value + right.value),
                })
                .collect(),
        }
    }

    fn sub(&self, x: Self::Share, y: Self::Share) -> Self::Share {
        ShamirPrimeFieldShare {
            shares: x
                .shares
                .iter()
                .zip(y.shares)
                .map(|(left, right)| ShamirScalarShare {
                    point: left.point,
                    value: reduce_mod_q::<P>(left.value - right.value),
                })
                .collect(),
        }
    }

    fn mul(
        &mut self,
        x: Self::Share,
        y: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::Share, DkgError> {
        self.validate_share_shape::<P>(&x)?;
        self.validate_share_shape::<P>(&y)?;
        self.gate_labels.push(label.as_str().to_owned());

        let points = self.points::<P>()?;
        let lambdas = lagrange_coefficients_at_zero::<P>(&points)
            .map_err(|_| DkgError::Backend("degree-reduction coefficients failed"))?;
        let mut state = self.fresh_state()?;

        for (dealer_index, &dealer) in self.config.parties.clone().iter().enumerate() {
            let local_product = (i64::from(x.shares[dealer_index].value)
                * i64::from(y.shares[dealer_index].value))
            .rem_euclid(i64::from(P::Q)) as Coeff;
            let weighted = (i64::from(local_product) * i64::from(lambdas[dealer_index]))
                .rem_euclid(i64::from(P::Q)) as Coeff;
            let resharing = self.share_secret::<P>(
                weighted,
                label.child(format!("degree_reduce_dealer_{}", dealer.0)),
            )?;
            for (&receiver, directed) in self.config.parties.clone().iter().zip(&resharing.shares) {
                Self::inject_directed_phase(
                    &mut state,
                    dealer,
                    receiver,
                    PrimeFieldMpcRoundKind::MulDegreeReduce,
                    PrimeFieldMpcPhase::MulDegreeReductionShare,
                    &label,
                    directed.value,
                )?;
            }
        }

        let mut output = Vec::with_capacity(self.config.parties.len());
        for (&receiver, &point) in self.config.parties.iter().zip(&points) {
            let values = state.collect_mul_degree_reduction_shares(receiver, &label)?;
            if values.len() != self.config.parties.len() {
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: self.config.parties.len(),
                    got: values.len(),
                });
            }
            let value = values
                .into_iter()
                .fold(0, |acc, (_sender, share)| reduce_mod_q::<P>(acc + share));
            output.push(ShamirScalarShare { point, value });
        }
        self.record_rounds(&state);
        Ok(ShamirPrimeFieldShare { shares: output })
    }

    fn mul_public_const(
        &self,
        x: Self::Share,
        constant: Coeff,
        _label: Power2RoundTranscriptLabel,
    ) -> Self::Share {
        mul_shamir_share_public_const::<P>(x, constant)
    }

    fn assert_zero(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<(), DkgError> {
        self.gate_labels.push(label.as_str().to_owned());
        let opened = self.open_from_transport_messages::<P>(
            &x,
            label,
            PrimeFieldMpcRoundKind::AssertZero,
            PrimeFieldMpcPhase::AssertZeroShare,
        )?;
        if opened == 0 {
            Ok(())
        } else {
            Err(DkgError::Power2RoundCanonicalityFailure)
        }
    }

    fn open_checked(
        &mut self,
        x: Self::Share,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Coeff, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        self.open_from_transport_messages::<P>(
            &x,
            label,
            PrimeFieldMpcRoundKind::Open,
            PrimeFieldMpcPhase::OpenShare,
        )
    }

    fn open_many_checked(
        &mut self,
        xs: &[Self::Share],
        label: Power2RoundTranscriptLabel,
    ) -> Result<Vec<Coeff>, DkgError> {
        self.opened_labels.push(label.as_str().to_owned());
        xs.iter()
            .enumerate()
            .map(|(index, share)| {
                self.open_from_transport_messages::<P>(
                    share,
                    label.child(format!("item_{index}")),
                    PrimeFieldMpcRoundKind::Open,
                    PrimeFieldMpcPhase::T1BitOpening,
                )
            })
            .collect()
    }

    fn random_bit(
        &mut self,
        label: Power2RoundTranscriptLabel,
    ) -> Result<Self::BitShare, DkgError> {
        let mut state = self.fresh_state()?;
        let mut dealer_bits = Vec::with_capacity(self.config.parties.len());
        for party in self.config.parties.clone() {
            let bit = self.next_mask::<P>(&label.child(format!("party_{}", party.0))) & 1;
            let share =
                self.share_secret::<P>(bit, label.child(format!("random_bit_dealer_{}", party.0)))?;
            for (&receiver, directed) in self.config.parties.clone().iter().zip(&share.shares) {
                Self::inject_directed_phase(
                    &mut state,
                    party,
                    receiver,
                    PrimeFieldMpcRoundKind::RandomBit,
                    PrimeFieldMpcPhase::RandomBitShare,
                    &label,
                    directed.value,
                )?;
            }
            dealer_bits.push((party, share));
        }

        for &receiver in &self.config.parties {
            let values = state.collect_random_bit_shares(receiver, &label)?;
            if values.len() != self.config.parties.len() {
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: self.config.parties.len(),
                    got: values.len(),
                });
            }
        }
        self.record_rounds(&state);

        let mut result = <Self as ItMpcPrimeFieldBackend<P>>::public_bit(self, false);
        for (dealer, share) in dealer_bits {
            result = bit_xor::<P, Self>(
                self,
                result,
                ShamirPrimeFieldBitShare { share },
                label.child(format!("xor_party_{}", dealer.0)),
            )?;
        }
        Ok(result)
    }
}

/// Test-only Power2Round harness over application-bound Shamir transport.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct TransportEvidenceShamirPower2RoundTestHarness {
    inner: TransportBackedShamirPrimeFieldMpcBackend,
    transport_evidence: NativeDkgTransportEvidence,
}

#[cfg(test)]
impl TransportEvidenceShamirPower2RoundTestHarness {
    /// Creates a transport-evidence-bound Power2Round test harness.
    pub fn new(
        config: DkgConfig,
        seed: [u8; 32],
        transport_evidence: NativeDkgTransportEvidence,
    ) -> Result<Self, DkgError> {
        ensure_native_dkg_transport_evidence_matches_config(&config, &transport_evidence)?;
        Ok(Self {
            inner: TransportBackedShamirPrimeFieldMpcBackend::new(config, seed),
            transport_evidence,
        })
    }

    /// Returns the transport evidence this backend was bound to.
    pub fn transport_evidence(&self) -> &NativeDkgTransportEvidence {
        &self.transport_evidence
    }

    /// Counts accepted public round metadata.
    pub fn accepted_round_count(&self) -> usize {
        self.inner.accepted_rounds().len()
    }

    /// Returns public opening labels.
    pub fn opened_labels(&self) -> &[String] {
        self.inner.opened_labels()
    }
}

/// Test Power2Round wrapper over a prime-field MPC backend.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct TestItMpcPower2RoundBackend<B> {
    backend: B,
}

#[cfg(test)]
impl<B> TestItMpcPower2RoundBackend<B> {
    /// Creates a backend wrapper.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Returns the wrapped backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

/// Transport-backed per-party `Power2Round` phase-driver boundary.
#[cfg(test)]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct TransportBackedPower2RoundBackend<T> {
    state: TransportPrimeFieldMpcStateMachine<T>,
}

#[cfg(test)]
impl<T> TransportBackedPower2RoundBackend<T>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
{
    /// Creates a release-blocked transport-backed phase-driver boundary.
    pub fn new(state: TransportPrimeFieldMpcStateMachine<T>) -> Self {
        Self { state }
    }

    /// Returns the local-party state machine.
    pub fn state(&self) -> &TransportPrimeFieldMpcStateMachine<T> {
        &self.state
    }

    /// Returns the mutable local-party state machine.
    pub fn state_mut(&mut self) -> &mut TransportPrimeFieldMpcStateMachine<T> {
        &mut self.state
    }

    /// Returns a cursor-aware runtime using caller-supplied durable logs.
    pub fn into_cursored_runtime<L, C>(
        self,
        wire_log: L,
        cursor_log: C,
    ) -> CursoredTransportPrimeFieldMpcPartyRuntime<T, L, C>
    where
        L: PrimeFieldMpcWireMessageLog,
        C: PrimeFieldMpcPhaseCursorLog,
    {
        CursoredTransportPrimeFieldMpcPartyRuntime::new(
            TransportPrimeFieldMpcPartyRuntime::new(self.state, wire_log),
            cursor_log,
        )
    }

    /// Starts the production per-party `Power2Round` driver skeleton.
    pub fn begin_production_driver(&self) -> ProductionPower2RoundPerPartyDriver {
        ProductionPower2RoundPerPartyDriver::new()
    }
}

#[cfg(test)]
impl<T> MpcPower2RoundBackend for TransportBackedPower2RoundBackend<T>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
{
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::TransportBackedPerPartyDriver
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        _config: &DkgConfig,
        _shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        Err(DkgError::Power2RoundRequiresSinglePartyDriver)
    }
}

#[cfg(test)]
impl MpcPower2RoundBackend for TestItMpcPower2RoundBackend<LocalPrimeFieldMpcBackend> {
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::LocalPrimeFieldSimulator
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        let root_label = Power2RoundTranscriptLabel::root(config, shared_t.assembly_label.rho_hash);
        let r = local_share_vec_from_shared_t::<P>(config, &shared_t)?;
        let t1_coeffs = power2round_t1_vec::<P, _>(
            &mut self.backend,
            r,
            root_label.child("power2round_t1_vec"),
        )?;
        let t1 = power2round_public_t1_from_coeffs::<P>(t1_coeffs)?;
        let evidence = power2round_certify_public_t1_evidence(
            self.backend_id(),
            config,
            shared_t.assembly_label,
            &t1,
        );
        Ok((t1, evidence))
    }
}

#[cfg(test)]
impl MpcPower2RoundBackend for TestItMpcPower2RoundBackend<InProcessShamirPrimeFieldMpcBackend> {
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::InProcessShamirSimulator
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        power2round_t1_coeffwise_with::<P, _>(
            &mut self.backend,
            config,
            shared_t,
            Power2RoundBackendId::InProcessShamirSimulator,
        )
    }
}

#[cfg(test)]
impl MpcPower2RoundBackend for TestItMpcPower2RoundBackend<NetworkedShamirPrimeFieldMpcBackend> {
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::NetworkedShamirSimulator
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        power2round_t1_coeffwise_with::<P, _>(
            &mut self.backend,
            config,
            shared_t,
            Power2RoundBackendId::NetworkedShamirSimulator,
        )
    }
}

#[cfg(test)]
impl MpcPower2RoundBackend
    for TestItMpcPower2RoundBackend<TransportBackedShamirPrimeFieldMpcBackend>
{
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::TransportBackedShamirSimulator
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        power2round_t1_coeffwise_with::<P, _>(
            &mut self.backend,
            config,
            shared_t,
            Power2RoundBackendId::TransportBackedShamirSimulator,
        )
    }
}

#[cfg(test)]
impl MpcPower2RoundBackend for TransportEvidenceShamirPower2RoundTestHarness {
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::TransportBackedShamirSimulator
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        ensure_native_dkg_transport_evidence_matches_config(config, &self.transport_evidence)?;
        power2round_t1_coeffwise_with::<P, _>(
            &mut self.inner,
            config,
            shared_t,
            Power2RoundBackendId::TransportBackedShamirSimulator,
        )
    }
}

/// Insecure clear simulator for public-key assembly shape/parity tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[doc(hidden)]
pub struct ClearSimPower2RoundBackend;

#[cfg(test)]
impl MpcPower2RoundBackend for ClearSimPower2RoundBackend {
    type Evidence = Power2RoundEvidence;

    fn backend_id(&self) -> Power2RoundBackendId {
        Power2RoundBackendId::InsecureClearSimulator
    }

    fn power2round_t1<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        shared_t: SharedT,
    ) -> Result<(PublicT1, Self::Evidence), DkgError> {
        let t = reconstruct_shared_t::<P>(config, &shared_t)?;
        let mut t0_temp = Vec::with_capacity(P::K * P::N);
        let mut t1_coeffs = Vec::with_capacity(P::K * P::N);
        for poly in t.polys() {
            for &coefficient in poly.coeffs() {
                let (high, low) = talus_core::power2round::<P>(coefficient);
                t1_coeffs.push(high as u16);
                t0_temp.push(low);
            }
        }
        let t1 = power2round_public_t1_from_coeffs::<P>(t1_coeffs)?;
        t0_temp.zeroize();
        let evidence = power2round_certify_public_t1_evidence(
            self.backend_id(),
            config,
            shared_t.assembly_label,
            &t1,
        );
        Ok((t1, evidence))
    }
}

#[cfg(test)]
fn power2round_t1_coeffwise_with<P, B>(
    backend: &mut B,
    config: &DkgConfig,
    shared_t: SharedT,
    backend_id: Power2RoundBackendId,
) -> Result<(PublicT1, Power2RoundEvidence), DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P, Share = ShamirPrimeFieldShare>,
{
    let assembly_label = shared_t.assembly_label;
    let root_label = Power2RoundTranscriptLabel::root(config, assembly_label.rho_hash);
    let mut t1_coeffs = Vec::with_capacity(P::K * P::N);
    for poly_idx in 0..P::K {
        for coeff_idx in 0..P::N {
            let coeff_label = root_label.child(format!("poly_{poly_idx}/coeff_{coeff_idx}"));
            let r = shamir_share_from_shared_t::<P>(config, &shared_t, poly_idx, coeff_idx)?;
            let r1 = power2round_t1_coeff::<P, _>(
                backend,
                r,
                coeff_label.child("power2round_t1_coeff"),
            )?;
            t1_coeffs.push(r1);
        }
    }
    let t1 = power2round_public_t1_from_coeffs::<P>(t1_coeffs)?;
    let evidence = power2round_certify_public_t1_evidence(backend_id, config, assembly_label, &t1);
    Ok((t1, evidence))
}
