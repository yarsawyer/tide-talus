#![doc = "Online TALUS-MPC signing state-machine shell."]

use core::{fmt, marker::PhantomData};

use talus_core::{
    aggregate_z_shares, aggregate_z_shares_lagrange, az_from_rho, compute_ctilde, compute_mu,
    compute_talus_hint_polyvec, infinity_norm, mul_challenge_polyvec, partial_z_share,
    public_approx_from_az, public_key_decode, sample_in_ball, signature_encode, w1_encode,
    z_bound_holds, Fips204Verifier, HintError, MlDsaParams, NttError, Poly, PolyError, PolyVec,
    PublicKeyDecodeError, SignatureEncodingError, VerifyError,
};
use talus_dkg::{BoundedSecretVectorShare, DkgConfig, DkgError, DkgKeyPackage, DkgSecretShare};
use talus_mpc_core::PartyId;
use zeroize::Zeroize;

use crate::local::{CertifiedToken, SessionId, TokenPool, TokenPoolError, TranscriptHash};

/// Current online protocol version.
pub const ONLINE_PROTOCOL_VERSION: u16 = 1;

/// Online signing request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignRequest {
    /// Protocol version.
    pub protocol_version: u16,
    /// ML-DSA suite name.
    pub suite: &'static str,
    /// Preprocessing session id.
    pub session_id: SessionId,
    /// Signing set, expected to match the token exactly.
    pub signing_set: Vec<PartyId>,
    /// Message bytes, when `external_mu` is not supplied.
    pub message: Vec<u8>,
    /// Optional externally supplied FIPS `mu`.
    pub external_mu: Option<[u8; 64]>,
    /// FIPS context string.
    pub context: Vec<u8>,
    /// Token transcript hash.
    pub token_transcript_hash: TranscriptHash,
}

/// Challenge material derived from a valid request and certified token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeMaterial {
    /// FIPS message representative.
    pub mu: [u8; 64],
    /// Encoded `w1` used in the challenge hash.
    pub encoded_w1: Vec<u8>,
    /// Challenge seed `ctilde`.
    pub ctilde: Vec<u8>,
}

/// Partial signing response placeholder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSignature {
    /// Session id.
    pub session_id: SessionId,
    /// Party id.
    pub party: PartyId,
    /// Partial `z_i` representation supplied by the current adapter layer.
    pub z_share: Vec<u8>,
    /// Challenge seed bound into the response.
    pub challenge: Vec<u8>,
}

/// Typed polynomial partial signing response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialPartialSignature {
    /// Session id.
    pub session_id: SessionId,
    /// Party id.
    pub party: PartyId,
    /// Partial response share `z_i = y_i + c*s1_i`.
    pub z_share: PolyVec,
    /// Challenge seed bound into the response.
    pub challenge: Vec<u8>,
}

/// Aggregated polynomial response material before FIPS signature encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialResponse {
    /// Challenge seed `ctilde`.
    pub ctilde: Vec<u8>,
    /// Aggregated response vector `z`.
    pub z: PolyVec,
}

/// One party's typed online signing shares.
#[derive(Clone, Eq, PartialEq)]
pub struct PolynomialSigningShare {
    /// Party id.
    pub party: PartyId,
    /// Local nonce share `y_i`.
    pub y_share: PolyVec,
    /// Local secret-key share `s1_i`.
    pub s1_share: PolyVec,
}

impl fmt::Debug for PolynomialSigningShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolynomialSigningShare")
            .field("party", &self.party)
            .field("y_share", &"<redacted>")
            .field("s1_share", &"<redacted>")
            .finish()
    }
}

/// Public commitments used to verify one typed online partial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialPartialCommitment {
    /// Party id.
    pub party: PartyId,
    /// Public commitment to local nonce product `A*y_i`.
    pub ay_commitment: PolyVec,
    /// Public commitment to local secret share product `A*s1_i`.
    pub as1_commitment: PolyVec,
}

/// Aggregation mode for typed polynomial partial responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolynomialAggregation {
    /// Additive shares, used by deterministic local tests and simple adapters.
    Additive,
    /// Shamir-style shares interpolated at zero with party ids as points.
    LagrangeAtZero,
}

/// Final signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalSignature {
    /// Serialized FIPS ML-DSA signature.
    pub bytes: Vec<u8>,
}

/// Independent `fips204` final verifier adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FipsFinalVerifier<P: MlDsaParams> {
    verifier: Fips204Verifier<P>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> FipsFinalVerifier<P> {
    /// Creates a verifier from serialized public key bytes.
    pub fn new(public_key: Vec<u8>) -> Result<Self, VerifyError> {
        Ok(Self {
            verifier: Fips204Verifier::<P>::new(public_key)?,
            _params: PhantomData,
        })
    }
}

impl<P: MlDsaParams> FinalVerifier for FipsFinalVerifier<P> {
    fn verify_final(&self, request: &SignRequest, signature: &FinalSignature) -> bool {
        if request.external_mu.is_some() {
            return false;
        }
        self.verifier
            .verify(&request.message, &signature.bytes, &request.context)
    }
}

/// Trait used to verify the final assembled FIPS signature before returning it.
pub trait FinalVerifier {
    /// Returns whether `signature` verifies for this request.
    fn verify_final(&self, request: &SignRequest, signature: &FinalSignature) -> bool;
}

/// Deterministic partial-response adapter for the current non-polynomial shell.
pub trait PartialSigner {
    /// Produces one partial response from local nonce-share material.
    fn sign_partial(
        &self,
        session_id: SessionId,
        party: PartyId,
        challenge: &ChallengeMaterial,
        y_share: &[u8],
    ) -> Result<PartialSignature, OnlineError>;
}

/// Deterministic final-assembly adapter for the current non-polynomial shell.
pub trait SignatureAssembler {
    /// Assembles a final signature candidate from partial responses.
    fn assemble(
        &self,
        request: &SignRequest,
        challenge: &ChallengeMaterial,
        partials: &[PartialSignature],
    ) -> Result<FinalSignature, OnlineError>;
}

/// Source for typed per-party polynomial signing shares.
pub trait PolynomialShareProvider {
    /// Returns the local online signing shares for `party` in `session_id`.
    fn signing_share(
        &self,
        session_id: SessionId,
        party: PartyId,
    ) -> Result<PolynomialSigningShare, OnlineError>;
}

/// Decodes a canonical DKG bounded-vector `s1` share into the polynomial-vector
/// shape used by online ML-DSA signing.
pub fn polyvec_from_bounded_secret_vector_share<P: MlDsaParams>(
    share: &BoundedSecretVectorShare,
) -> Result<PolyVec, OnlineError> {
    let expected = P::L * P::N;
    if share.coeffs.len() != expected {
        return Err(OnlineError::Dkg(
            DkgError::InvalidBoundedSecretVectorLength {
                expected,
                got: share.coeffs.len(),
            },
        ));
    }

    let mut polys = Vec::with_capacity(P::L);
    for row in 0..P::L {
        let coeffs = core::array::from_fn(|index| share.coeffs[row * P::N + index]);
        polys.push(Poly::from_coeffs(coeffs));
    }

    Ok(PolyVec::new(polys))
}

/// Decodes a `DkgSecretShare.s1_share` package into the typed online `s1_i`
/// polynomial vector for the selected ML-DSA suite.
pub fn polyvec_from_dkg_s1_share<P: MlDsaParams>(
    config: &DkgConfig,
    secret: &DkgSecretShare,
) -> Result<PolyVec, OnlineError> {
    let decoded = BoundedSecretVectorShare::decode::<P>(config, &secret.s1_share)?;
    if decoded.party != secret.party {
        return Err(OnlineError::Dkg(DkgError::PartyMismatch {
            expected: secret.party,
            got: decoded.party,
        }));
    }

    polyvec_from_bounded_secret_vector_share::<P>(&decoded)
}

/// Polynomial share provider backed by imported DKG secret-share packages.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgBackedPolynomialShareProvider<P: MlDsaParams> {
    session_id: SessionId,
    dkg_config: DkgConfig,
    y_shares: Vec<(PartyId, PolyVec)>,
    dkg_secret_shares: Vec<DkgSecretShare>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> DkgBackedPolynomialShareProvider<P> {
    /// Creates a provider for one preprocessing/signing session.
    pub fn new(
        session_id: SessionId,
        dkg_config: DkgConfig,
        y_shares: Vec<(PartyId, PolyVec)>,
        dkg_secret_shares: Vec<DkgSecretShare>,
    ) -> Self {
        Self {
            session_id,
            dkg_config,
            y_shares,
            dkg_secret_shares,
            _params: PhantomData,
        }
    }

    /// Creates a provider from native DKG key packages. Only retained `s1`
    /// material is imported; `s2`, `t`, and `t0` remain absent from key
    /// packages.
    pub fn from_key_packages(
        session_id: SessionId,
        dkg_config: DkgConfig,
        y_shares: Vec<(PartyId, PolyVec)>,
        key_packages: Vec<DkgKeyPackage>,
    ) -> Self {
        let dkg_secret_shares = key_packages
            .into_iter()
            .map(|package| DkgSecretShare {
                party: package.party,
                s1_share: package.s1_share.s1_share,
                s2_share: vec![0],
                t0_share: vec![0],
                pairwise_seed_shares: package.s1_share.pairwise_seed_shares,
            })
            .collect();
        Self::new(session_id, dkg_config, y_shares, dkg_secret_shares)
    }
}

impl<P: MlDsaParams> fmt::Debug for DkgBackedPolynomialShareProvider<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgBackedPolynomialShareProvider")
            .field("session_id", &self.session_id)
            .field("dkg_config", &self.dkg_config)
            .field("y_shares", &"<redacted>")
            .field("dkg_secret_shares", &"<redacted>")
            .finish()
    }
}

impl<P: MlDsaParams> PolynomialShareProvider for DkgBackedPolynomialShareProvider<P> {
    fn signing_share(
        &self,
        session_id: SessionId,
        party: PartyId,
    ) -> Result<PolynomialSigningShare, OnlineError> {
        if session_id != self.session_id {
            return Err(OnlineError::SessionMismatch);
        }

        let y_share = self
            .y_shares
            .iter()
            .find(|(candidate, _)| *candidate == party)
            .map(|(_, share)| share.clone())
            .ok_or(OnlineError::PartialSignerFailed(party))?;
        let secret = self
            .dkg_secret_shares
            .iter()
            .find(|secret| secret.party == party)
            .ok_or(OnlineError::PartialSignerFailed(party))?;
        let s1_share = polyvec_from_dkg_s1_share::<P>(&self.dkg_config, secret)?;

        Ok(PolynomialSigningShare {
            party,
            y_share,
            s1_share,
        })
    }
}

/// Verifier for typed online partial responses before aggregation.
pub trait PolynomialPartialVerifier {
    /// Verifies `partial` against public commitments.
    fn verify_partial<P: MlDsaParams>(
        &self,
        public_key: &[u8],
        session_id: SessionId,
        challenge: &ChallengeMaterial,
        partial: &PolynomialPartialSignature,
    ) -> Result<(), OnlineError>;
}

/// No-op typed partial verifier used only by scaffolding tests that do not yet
/// model public `A*y_i` and `A*s1_i` commitments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopPolynomialPartialVerifier;

impl PolynomialPartialVerifier for NoopPolynomialPartialVerifier {
    fn verify_partial<P: MlDsaParams>(
        &self,
        _public_key: &[u8],
        _session_id: SessionId,
        _challenge: &ChallengeMaterial,
        _partial: &PolynomialPartialSignature,
    ) -> Result<(), OnlineError> {
        Ok(())
    }
}

/// Commitment-backed typed partial verifier.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitmentBackedPartialVerifier {
    commitments: Vec<PolynomialPartialCommitment>,
}

impl CommitmentBackedPartialVerifier {
    /// Creates a verifier from public per-party commitments.
    pub fn new(commitments: Vec<PolynomialPartialCommitment>) -> Self {
        Self { commitments }
    }

    fn commitment(&self, party: PartyId) -> Result<&PolynomialPartialCommitment, OnlineError> {
        self.commitments
            .iter()
            .find(|commitment| commitment.party == party)
            .ok_or(OnlineError::PublicCommitmentMissing(party))
    }
}

impl PolynomialPartialVerifier for CommitmentBackedPartialVerifier {
    fn verify_partial<P: MlDsaParams>(
        &self,
        public_key: &[u8],
        session_id: SessionId,
        challenge: &ChallengeMaterial,
        partial: &PolynomialPartialSignature,
    ) -> Result<(), OnlineError> {
        if partial.session_id != session_id || partial.challenge != challenge.ctilde {
            return Err(OnlineError::Blame(partial.party));
        }
        if challenge.ctilde.len() != P::CTILDE_LEN {
            return Err(OnlineError::Polynomial(PolyError::ChallengeLength {
                expected: P::CTILDE_LEN,
                got: challenge.ctilde.len(),
            }));
        }

        let commitment = self.commitment(partial.party)?;
        validate_public_commitment_len::<P>(partial.party, &commitment.ay_commitment)?;
        validate_public_commitment_len::<P>(partial.party, &commitment.as1_commitment)?;

        let public_key = public_key_decode::<P>(public_key)?;
        let az = az_from_rho::<P>(&public_key.rho, &partial.z_share)?;
        let challenge_poly = sample_in_ball::<P>(&challenge.ctilde);
        let c_as1 = mul_challenge_polyvec::<P>(&challenge_poly, &commitment.as1_commitment);
        let expected = commitment.ay_commitment.add_mod_q::<P>(&c_as1);

        if az == expected {
            Ok(())
        } else {
            Err(OnlineError::Blame(partial.party))
        }
    }
}

/// Online signing service adapters.
pub struct OnlineServices<'a, PS, SA, FV> {
    /// Public key transcript hash `tr`.
    pub tr: &'a [u8; 64],
    /// Partial signer.
    pub partial_signer: &'a PS,
    /// Final assembler.
    pub assembler: &'a SA,
    /// Independent final verifier.
    pub verifier: &'a FV,
}

impl<PS, SA, FV> fmt::Debug for OnlineServices<'_, PS, SA, FV> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineServices")
            .field("tr", &"<redacted>")
            .field("partial_signer", &"<adapter>")
            .field("assembler", &"<adapter>")
            .field("verifier", &"<adapter>")
            .finish()
    }
}

impl<'a, PS, SA, FV> Clone for OnlineServices<'a, PS, SA, FV> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, PS, SA, FV> Copy for OnlineServices<'a, PS, SA, FV> {}

/// Typed polynomial online signing service adapters.
pub struct PolynomialOnlineServices<'a, SP, PV, FV> {
    /// Public key transcript hash `tr`.
    pub tr: &'a [u8; 64],
    /// Serialized FIPS public key.
    pub public_key: &'a [u8],
    /// Typed response aggregation mode.
    pub aggregation: PolynomialAggregation,
    /// Typed polynomial share provider.
    pub share_provider: &'a SP,
    /// Typed partial verifier.
    pub partial_verifier: &'a PV,
    /// Independent final verifier.
    pub verifier: &'a FV,
}

impl<SP, PV, FV> fmt::Debug for PolynomialOnlineServices<'_, SP, PV, FV> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolynomialOnlineServices")
            .field("tr", &"<redacted>")
            .field("public_key_len", &self.public_key.len())
            .field("aggregation", &self.aggregation)
            .field("share_provider", &"<adapter>")
            .field("partial_verifier", &"<adapter>")
            .field("verifier", &"<adapter>")
            .finish()
    }
}

impl<'a, SP, PV, FV> Clone for PolynomialOnlineServices<'a, SP, PV, FV> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, SP, PV, FV> Copy for PolynomialOnlineServices<'a, SP, PV, FV> {}

/// Consumed-token persistence surface.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsumedTokenStore {
    consumed: Vec<SessionId>,
}

/// Durable consumed-token persistence API.
pub trait TokenConsumptionStore {
    /// Persists token consumption durably.
    fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError>;

    /// Returns whether a token has already been consumed.
    fn is_consumed(&self, session_id: SessionId) -> bool;
}

impl ConsumedTokenStore {
    /// Creates an empty consumed-token store.
    pub const fn new() -> Self {
        Self {
            consumed: Vec::new(),
        }
    }
}

impl TokenConsumptionStore for ConsumedTokenStore {
    fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError> {
        if self.consumed.contains(&session_id) {
            return Err(OnlineError::TokenAlreadyConsumed(session_id));
        }

        self.consumed.push(session_id);
        Ok(())
    }

    fn is_consumed(&self, session_id: SessionId) -> bool {
        self.consumed.contains(&session_id)
    }
}

/// File-backed consumed-token store for deterministic crash/reopen tests.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConsumedTokenStore {
    path: std::path::PathBuf,
    inner: ConsumedTokenStore,
}

#[cfg(feature = "std")]
impl FileConsumedTokenStore {
    /// Opens or creates a consumed-token log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, OnlineError> {
        let path = path.into();
        let mut inner = ConsumedTokenStore::new();

        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let session_id = parse_session_id_hex(line).ok_or(
                        OnlineError::ConsumedTokenStoreCorrupt {
                            line: line_index + 1,
                        },
                    )?;
                    if !inner.consumed.contains(&session_id) {
                        inner.consumed.push(session_id);
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| OnlineError::ConsumedTokenStoreIo {
                        operation: "create",
                    })?;
                file.sync_all()
                    .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "sync" })?;
            }
            Err(_) => {
                return Err(OnlineError::ConsumedTokenStoreIo { operation: "read" });
            }
        }

        Ok(Self { path, inner })
    }
}

#[cfg(feature = "std")]
impl TokenConsumptionStore for FileConsumedTokenStore {
    fn persist_consumed(&mut self, session_id: SessionId) -> Result<(), OnlineError> {
        if self.inner.is_consumed(session_id) {
            return Err(OnlineError::TokenAlreadyConsumed(session_id));
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(file, "{}", hex32(session_id.0))
            .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| OnlineError::ConsumedTokenStoreIo { operation: "sync" })?;

        self.inner.persist_consumed(session_id)
    }

    fn is_consumed(&self, session_id: SessionId) -> bool {
        self.inner.is_consumed(session_id)
    }
}

/// Online signing counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigningCounters {
    /// Attempts started.
    pub attempts: u64,
    /// Tokens consumed.
    pub tokens_consumed: u64,
    /// Attempts that returned a verified signature.
    pub signatures_returned: u64,
    /// Attempts that failed final verification after consuming a token.
    pub final_verify_failures: u64,
    /// Retry attempts exhausted without returning a signature.
    pub retry_exhausted: u64,
}

/// Retry policy for online signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of attempts.
    pub max_attempts: usize,
}

/// Online signing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnlineError {
    /// Protocol version mismatch.
    BadProtocolVersion {
        /// Expected version.
        expected: u16,
        /// Actual version.
        got: u16,
    },
    /// Suite mismatch.
    SuiteMismatch {
        /// Expected suite.
        expected: &'static str,
        /// Actual suite.
        got: &'static str,
    },
    /// Session mismatch.
    SessionMismatch,
    /// Signing-set mismatch.
    SigningSetMismatch,
    /// Token transcript hash mismatch.
    TranscriptMismatch,
    /// Empty message without external `mu`.
    EmptyMessage,
    /// Context is too long for FIPS 204 domain separation.
    ContextTooLong(usize),
    /// Token pool failure.
    TokenPool(TokenPoolError),
    /// Token was already consumed.
    TokenAlreadyConsumed(SessionId),
    /// Consumed-token store I/O failed.
    ConsumedTokenStoreIo {
        /// Storage operation.
        operation: &'static str,
    },
    /// Consumed-token store file was malformed.
    ConsumedTokenStoreCorrupt {
        /// One-based line number.
        line: usize,
    },
    /// Partial signer failed.
    PartialSignerFailed(PartyId),
    /// Partial response count mismatch.
    PartialCountMismatch {
        /// Expected number of partials.
        expected: usize,
        /// Actual number of partials.
        got: usize,
    },
    /// Partial response was not bound to the request.
    PartialMismatch(PartyId),
    /// A party is blamed for an invalid partial response.
    Blame(PartyId),
    /// Public partial-verification commitment was missing.
    PublicCommitmentMissing(PartyId),
    /// Public partial-verification commitment had the wrong vector length.
    PublicCommitmentLength {
        /// Party identifier.
        party: PartyId,
        /// Expected polynomial count.
        expected: usize,
        /// Actual polynomial count.
        got: usize,
    },
    /// Polynomial adapter failure.
    Polynomial(PolyError),
    /// DKG key-share package failure.
    Dkg(DkgError),
    /// Public hint computation failure.
    Hint(HintError),
    /// Signature encoding failure.
    SignatureEncoding(SignatureEncodingError),
    /// Public key decoding failure.
    PublicKeyDecode(PublicKeyDecodeError),
    /// NTT/ExpandA adapter failure.
    Ntt(NttError),
    /// Aggregated `z` exceeds the strict ML-DSA signing bound.
    ZNormExceeded {
        /// Observed infinity norm.
        norm: i32,
        /// Required strict upper bound.
        bound: i32,
    },
    /// Final signature failed independent verification.
    FinalVerifyFailed,
    /// Retry policy exhausted all supplied attempts.
    RetryExhausted,
}

impl fmt::Display for OnlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadProtocolVersion { expected, got } => {
                write!(f, "bad protocol version: expected {expected}, got {got}")
            }
            Self::SuiteMismatch { expected, got } => {
                write!(f, "suite mismatch: expected {expected}, got {got}")
            }
            Self::SessionMismatch => write!(f, "sign request session does not match token"),
            Self::SigningSetMismatch => write!(f, "sign request signing set does not match token"),
            Self::TranscriptMismatch => {
                write!(f, "sign request transcript hash does not match token")
            }
            Self::EmptyMessage => write!(f, "sign request has empty message and no external mu"),
            Self::ContextTooLong(len) => write!(f, "FIPS context too long: {len} bytes"),
            Self::TokenPool(err) => write!(f, "token pool error: {err:?}"),
            Self::TokenAlreadyConsumed(session_id) => {
                write!(f, "token already consumed: {}", hex32(session_id.0))
            }
            Self::ConsumedTokenStoreIo { operation } => {
                write!(f, "consumed-token store I/O failed during {operation}")
            }
            Self::ConsumedTokenStoreCorrupt { line } => {
                write!(f, "consumed-token store corrupt at line {line}")
            }
            Self::PartialSignerFailed(party) => {
                write!(f, "partial signer failed for party {}", party.0)
            }
            Self::PartialCountMismatch { expected, got } => {
                write!(f, "partial count mismatch: expected {expected}, got {got}")
            }
            Self::PartialMismatch(party) => {
                write!(f, "partial response mismatch for party {}", party.0)
            }
            Self::Blame(party) => write!(f, "blame party {}", party.0),
            Self::PublicCommitmentMissing(party) => {
                write!(f, "missing public commitment for party {}", party.0)
            }
            Self::PublicCommitmentLength {
                party,
                expected,
                got,
            } => {
                write!(
                    f,
                    "bad public commitment length for party {}: expected {expected}, got {got}",
                    party.0
                )
            }
            Self::Polynomial(err) => write!(f, "polynomial adapter error: {err}"),
            Self::Dkg(err) => write!(f, "DKG key-share error: {err:?}"),
            Self::Hint(err) => write!(f, "hint computation error: {err:?}"),
            Self::SignatureEncoding(err) => write!(f, "signature encoding error: {err:?}"),
            Self::PublicKeyDecode(err) => write!(f, "public key decode error: {err:?}"),
            Self::Ntt(err) => write!(f, "NTT adapter error: {err}"),
            Self::ZNormExceeded { norm, bound } => {
                write!(f, "z norm exceeded: norm {norm}, bound {bound}")
            }
            Self::FinalVerifyFailed => write!(f, "final signature failed independent verification"),
            Self::RetryExhausted => write!(f, "retry policy exhausted"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OnlineError {}

impl From<TokenPoolError> for OnlineError {
    fn from(value: TokenPoolError) -> Self {
        Self::TokenPool(value)
    }
}

impl From<PolyError> for OnlineError {
    fn from(value: PolyError) -> Self {
        Self::Polynomial(value)
    }
}

impl From<DkgError> for OnlineError {
    fn from(value: DkgError) -> Self {
        Self::Dkg(value)
    }
}

impl From<HintError> for OnlineError {
    fn from(value: HintError) -> Self {
        Self::Hint(value)
    }
}

impl From<SignatureEncodingError> for OnlineError {
    fn from(value: SignatureEncodingError) -> Self {
        Self::SignatureEncoding(value)
    }
}

impl From<PublicKeyDecodeError> for OnlineError {
    fn from(value: PublicKeyDecodeError) -> Self {
        Self::PublicKeyDecode(value)
    }
}

impl From<NttError> for OnlineError {
    fn from(value: NttError) -> Self {
        Self::Ntt(value)
    }
}

/// Validates one sign request against a certified token.
pub fn validate_sign_request<P: MlDsaParams>(
    request: &SignRequest,
    token: &CertifiedToken,
) -> Result<(), OnlineError> {
    if request.protocol_version != ONLINE_PROTOCOL_VERSION {
        return Err(OnlineError::BadProtocolVersion {
            expected: ONLINE_PROTOCOL_VERSION,
            got: request.protocol_version,
        });
    }
    if request.suite != P::NAME {
        return Err(OnlineError::SuiteMismatch {
            expected: P::NAME,
            got: request.suite,
        });
    }
    if request.session_id != token.session_id {
        return Err(OnlineError::SessionMismatch);
    }
    if request.signing_set != token.signer_set {
        return Err(OnlineError::SigningSetMismatch);
    }
    if request.token_transcript_hash != token.transcript_hash {
        return Err(OnlineError::TranscriptMismatch);
    }
    if request.external_mu.is_none() && request.message.is_empty() {
        return Err(OnlineError::EmptyMessage);
    }
    if request.context.len() > u8::MAX as usize {
        return Err(OnlineError::ContextTooLong(request.context.len()));
    }

    Ok(())
}

/// Computes `mu`, `w1Encode(w1)`, and `ctilde` for the online challenge.
pub fn compute_challenge_material<P: MlDsaParams>(
    request: &SignRequest,
    token: &CertifiedToken,
    tr: &[u8; 64],
) -> ChallengeMaterial {
    let mu = request
        .external_mu
        .unwrap_or_else(|| compute_mu(tr, &request.context, &request.message));
    let encoded_w1 = w1_encode::<P>(&token.w1);
    let ctilde = compute_ctilde::<P>(&mu, &encoded_w1);

    ChallengeMaterial {
        mu,
        encoded_w1,
        ctilde,
    }
}

/// Computes one typed polynomial partial response.
pub fn compute_polynomial_partial<P: MlDsaParams>(
    session_id: SessionId,
    party: PartyId,
    challenge: &ChallengeMaterial,
    y_share: &PolyVec,
    s1_share: &PolyVec,
) -> Result<PolynomialPartialSignature, OnlineError> {
    let z_share = partial_z_share::<P>(&challenge.ctilde, y_share, s1_share)?;
    Ok(PolynomialPartialSignature {
        session_id,
        party,
        z_share,
        challenge: challenge.ctilde.clone(),
    })
}

/// Validates and aggregates typed polynomial partial responses.
pub fn assemble_polynomial_response<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    challenge: &ChallengeMaterial,
    partials: &[PolynomialPartialSignature],
) -> Result<PolynomialResponse, OnlineError> {
    if partials.len() != signer_set.len() {
        return Err(OnlineError::PartialCountMismatch {
            expected: signer_set.len(),
            got: partials.len(),
        });
    }

    let mut z_shares = Vec::with_capacity(partials.len());
    for (&expected_party, partial) in signer_set.iter().zip(partials) {
        if partial.session_id != session_id
            || partial.party != expected_party
            || partial.challenge != challenge.ctilde
        {
            return Err(OnlineError::Blame(expected_party));
        }
        z_shares.push(partial.z_share.clone());
    }

    let z = aggregate_z_shares::<P>(&z_shares)?;
    if !z_bound_holds::<P>(&z) {
        return Err(OnlineError::ZNormExceeded {
            norm: infinity_norm::<P>(&z),
            bound: P::GAMMA1 - P::BETA,
        });
    }

    Ok(PolynomialResponse {
        ctilde: challenge.ctilde.clone(),
        z,
    })
}

/// Validates and aggregates Shamir-style typed partial responses at zero using
/// party ids as interpolation points.
pub fn assemble_polynomial_response_lagrange<P: MlDsaParams>(
    session_id: SessionId,
    signer_set: &[PartyId],
    challenge: &ChallengeMaterial,
    partials: &[PolynomialPartialSignature],
) -> Result<PolynomialResponse, OnlineError> {
    if partials.len() != signer_set.len() {
        return Err(OnlineError::PartialCountMismatch {
            expected: signer_set.len(),
            got: partials.len(),
        });
    }

    let mut points = Vec::with_capacity(partials.len());
    let mut z_shares = Vec::with_capacity(partials.len());
    for (&expected_party, partial) in signer_set.iter().zip(partials) {
        if partial.session_id != session_id
            || partial.party != expected_party
            || partial.challenge != challenge.ctilde
        {
            return Err(OnlineError::Blame(expected_party));
        }
        points.push(u32::from(expected_party.0));
        z_shares.push(partial.z_share.clone());
    }

    let z = aggregate_z_shares_lagrange::<P>(&points, &z_shares)?;
    if !z_bound_holds::<P>(&z) {
        return Err(OnlineError::ZNormExceeded {
            norm: infinity_norm::<P>(&z),
            bound: P::GAMMA1 - P::BETA,
        });
    }

    Ok(PolynomialResponse {
        ctilde: challenge.ctilde.clone(),
        z,
    })
}

/// Computes public TALUS hints and encodes a final FIPS signature candidate.
///
/// The returned candidate is not safe to output until an independent FIPS
/// verifier accepts it.
pub fn encode_final_signature_candidate<P: MlDsaParams>(
    response: &PolynomialResponse,
    public_approx: &PolyVec,
    w1: &[u32],
) -> Result<FinalSignature, OnlineError> {
    if !z_bound_holds::<P>(&response.z) {
        return Err(OnlineError::ZNormExceeded {
            norm: infinity_norm::<P>(&response.z),
            bound: P::GAMMA1 - P::BETA,
        });
    }

    let hints = compute_talus_hint_polyvec::<P>(public_approx, w1)?;
    let bytes = signature_encode::<P>(&response.ctilde, &response.z, &hints)?;
    Ok(FinalSignature { bytes })
}

/// Encodes a final FIPS signature candidate from decoded public key bytes and
/// externally computed `A*z`.
///
/// This is the current boundary before the `ExpandA/NTT` adapter lands: callers
/// provide `az`, while this helper decodes `t1`, computes
/// `w'_approx = az - c*t1*2^d`, computes hints, and encodes the candidate.
pub fn encode_final_signature_candidate_from_public_key<P: MlDsaParams>(
    response: &PolynomialResponse,
    public_key: &[u8],
    az: &PolyVec,
    w1: &[u32],
) -> Result<FinalSignature, OnlineError> {
    let public_key = public_key_decode::<P>(public_key)?;
    let public_approx = public_approx_from_az::<P>(az, &response.ctilde, &public_key.t1)?;
    encode_final_signature_candidate::<P>(response, &public_approx, w1)
}

/// Encodes a final FIPS signature candidate by deriving `A*z` from the public
/// key seed and typed response.
///
/// The returned candidate is still gated by independent final verification
/// before any signing API may output it.
pub fn encode_final_signature_candidate_with_az<P: MlDsaParams>(
    response: &PolynomialResponse,
    public_key: &[u8],
    w1: &[u32],
) -> Result<FinalSignature, OnlineError> {
    let public_key = public_key_decode::<P>(public_key)?;
    let az = az_from_rho::<P>(&public_key.rho, &response.z)?;
    let public_approx = public_approx_from_az::<P>(&az, &response.ctilde, &public_key.t1)?;
    encode_final_signature_candidate::<P>(response, &public_approx, w1)
}

/// Consumes a certified token and produces a verified final signature.
pub fn sign_with_token<
    P: MlDsaParams,
    PS: PartialSigner,
    SA: SignatureAssembler,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    request: &SignRequest,
    services: OnlineServices<'_, PS, SA, FV>,
) -> Result<FinalSignature, OnlineError> {
    counters.attempts += 1;
    if consumed.is_consumed(request.session_id) {
        return Err(OnlineError::TokenAlreadyConsumed(request.session_id));
    }

    let mut token = pool.take_certified(request.session_id)?;
    validate_sign_request::<P>(request, &token)?;

    let challenge = compute_challenge_material::<P>(request, &token, services.tr);
    consumed.persist_consumed(token.session_id)?;
    counters.tokens_consumed += 1;

    let mut partials = Vec::with_capacity(token.signer_set.len());
    for &party in &token.signer_set {
        let partial = services.partial_signer.sign_partial(
            token.session_id,
            party,
            &challenge,
            token.y_share.as_slice(),
        )?;
        if partial.session_id != token.session_id
            || partial.party != party
            || partial.challenge != challenge.ctilde
        {
            return Err(OnlineError::Blame(party));
        }
        partials.push(partial);
    }
    token.y_share.zeroize();

    let signature = services
        .assembler
        .assemble(request, &challenge, &partials)?;
    if !services.verifier.verify_final(request, &signature) {
        counters.final_verify_failures += 1;
        return Err(OnlineError::FinalVerifyFailed);
    }

    counters.signatures_returned += 1;
    Ok(signature)
}

/// Consumes a certified token and produces a verified final signature using
/// typed polynomial `y_i` and `s1_i` shares.
pub fn sign_polynomial_with_token<
    P: MlDsaParams,
    SP: PolynomialShareProvider,
    PV: PolynomialPartialVerifier,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    request: &SignRequest,
    services: PolynomialOnlineServices<'_, SP, PV, FV>,
) -> Result<FinalSignature, OnlineError> {
    counters.attempts += 1;
    if consumed.is_consumed(request.session_id) {
        return Err(OnlineError::TokenAlreadyConsumed(request.session_id));
    }

    let mut token = pool.take_certified(request.session_id)?;
    validate_sign_request::<P>(request, &token)?;

    let challenge = compute_challenge_material::<P>(request, &token, services.tr);
    consumed.persist_consumed(token.session_id)?;
    counters.tokens_consumed += 1;

    let mut partials = Vec::with_capacity(token.signer_set.len());
    for &party in &token.signer_set {
        let share = services
            .share_provider
            .signing_share(token.session_id, party)?;
        if share.party != party {
            return Err(OnlineError::Blame(party));
        }

        let partial = compute_polynomial_partial::<P>(
            token.session_id,
            party,
            &challenge,
            &share.y_share,
            &share.s1_share,
        )?;
        services.partial_verifier.verify_partial::<P>(
            services.public_key,
            token.session_id,
            &challenge,
            &partial,
        )?;
        partials.push(partial);
    }
    token.y_share.zeroize();

    let response = match services.aggregation {
        PolynomialAggregation::Additive => assemble_polynomial_response::<P>(
            token.session_id,
            &token.signer_set,
            &challenge,
            &partials,
        )?,
        PolynomialAggregation::LagrangeAtZero => assemble_polynomial_response_lagrange::<P>(
            token.session_id,
            &token.signer_set,
            &challenge,
            &partials,
        )?,
    };
    let signature =
        encode_final_signature_candidate_with_az::<P>(&response, services.public_key, &token.w1)?;
    if !services.verifier.verify_final(request, &signature) {
        counters.final_verify_failures += 1;
        return Err(OnlineError::FinalVerifyFailed);
    }

    counters.signatures_returned += 1;
    Ok(signature)
}

/// Runs online signing attempts until a verified signature is returned or the
/// retry policy is exhausted.
pub fn sign_with_retry<
    P: MlDsaParams,
    PS: PartialSigner,
    SA: SignatureAssembler,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    requests: &[SignRequest],
    services: OnlineServices<'_, PS, SA, FV>,
    policy: RetryPolicy,
) -> Result<FinalSignature, OnlineError> {
    for request in requests.iter().take(policy.max_attempts) {
        match sign_with_token::<P, _, _, _, _>(pool, consumed, counters, request, services) {
            Ok(signature) => return Ok(signature),
            Err(OnlineError::FinalVerifyFailed) => continue,
            Err(err) => return Err(err),
        }
    }

    counters.retry_exhausted += 1;
    Err(OnlineError::RetryExhausted)
}

/// Runs typed polynomial online signing attempts until a verified signature is
/// returned or the retry policy is exhausted.
pub fn sign_polynomial_with_retry<
    P: MlDsaParams,
    SP: PolynomialShareProvider,
    PV: PolynomialPartialVerifier,
    FV: FinalVerifier,
    CS: TokenConsumptionStore,
>(
    pool: &mut TokenPool,
    consumed: &mut CS,
    counters: &mut SigningCounters,
    requests: &[SignRequest],
    services: PolynomialOnlineServices<'_, SP, PV, FV>,
    policy: RetryPolicy,
) -> Result<FinalSignature, OnlineError> {
    for request in requests.iter().take(policy.max_attempts) {
        match sign_polynomial_with_token::<P, _, _, _, _>(
            pool, consumed, counters, request, services,
        ) {
            Ok(signature) => return Ok(signature),
            Err(OnlineError::FinalVerifyFailed) => continue,
            Err(err) => return Err(err),
        }
    }

    counters.retry_exhausted += 1;
    Err(OnlineError::RetryExhausted)
}

fn hex32(bytes: [u8; 32]) -> Hex32 {
    Hex32(bytes)
}

#[cfg(feature = "std")]
fn parse_session_id_hex(value: &str) -> Option<SessionId> {
    if value.len() != 64 {
        return None;
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(SessionId(bytes))
}

#[cfg(feature = "std")]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_public_commitment_len<P: MlDsaParams>(
    party: PartyId,
    commitment: &PolyVec,
) -> Result<(), OnlineError> {
    if commitment.len() != P::K {
        return Err(OnlineError::PublicCommitmentLength {
            party,
            expected: P::K,
            got: commitment.len(),
        });
    }

    Ok(())
}

struct Hex32([u8; 32]);

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{
        certify_preprocessing_token, Commitment, NonceCommitment, PartyPreprocessInput,
        SessionRegistry,
    };
    use core::cell::Cell;
    use fips204::traits::{KeyGen, SerDes, Signer};
    use talus_core::{MlDsa65, Poly, PolyVec};
    use talus_dkg::{
        DkgKeyPackage, DkgS1SecretShare, KeygenEpoch, Power2RoundBackendId, Power2RoundEvidence,
        PublicKeyAssemblyCertificate, PublicT1,
    };

    struct TestPartialSigner;

    impl PartialSigner for TestPartialSigner {
        fn sign_partial(
            &self,
            _session_id: SessionId,
            party: PartyId,
            challenge: &ChallengeMaterial,
            y_share: &[u8],
        ) -> Result<PartialSignature, OnlineError> {
            if y_share.is_empty() {
                return Err(OnlineError::PartialSignerFailed(party));
            }
            Ok(PartialSignature {
                session_id: SessionId([8; 32]),
                party,
                z_share: challenge.ctilde[..8].to_vec(),
                challenge: challenge.ctilde.clone(),
            })
        }
    }

    struct SessionAwarePartialSigner;

    impl PartialSigner for SessionAwarePartialSigner {
        fn sign_partial(
            &self,
            session_id: SessionId,
            party: PartyId,
            challenge: &ChallengeMaterial,
            y_share: &[u8],
        ) -> Result<PartialSignature, OnlineError> {
            let mut z_share = Vec::new();
            z_share.extend_from_slice(&challenge.ctilde[..8]);
            z_share.extend_from_slice(&(y_share.len() as u32).to_le_bytes());
            Ok(PartialSignature {
                session_id,
                party,
                z_share,
                challenge: challenge.ctilde.clone(),
            })
        }
    }

    struct TestAssembler;

    impl SignatureAssembler for TestAssembler {
        fn assemble(
            &self,
            _request: &SignRequest,
            challenge: &ChallengeMaterial,
            partials: &[PartialSignature],
        ) -> Result<FinalSignature, OnlineError> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&challenge.ctilde);
            for partial in partials {
                bytes.extend_from_slice(&partial.z_share);
            }
            Ok(FinalSignature { bytes })
        }
    }

    struct AcceptVerifier;

    impl FinalVerifier for AcceptVerifier {
        fn verify_final(&self, _request: &SignRequest, _signature: &FinalSignature) -> bool {
            true
        }
    }

    struct RejectVerifier;

    impl FinalVerifier for RejectVerifier {
        fn verify_final(&self, _request: &SignRequest, _signature: &FinalSignature) -> bool {
            false
        }
    }

    struct FailThenAcceptVerifier {
        calls: Cell<u32>,
    }

    impl FinalVerifier for FailThenAcceptVerifier {
        fn verify_final(&self, _request: &SignRequest, _signature: &FinalSignature) -> bool {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            calls != 0
        }
    }

    struct TestPolynomialShareProvider {
        shares: Vec<PolynomialSigningShare>,
        misbind_party: bool,
    }

    impl PolynomialShareProvider for TestPolynomialShareProvider {
        fn signing_share(
            &self,
            _session_id: SessionId,
            party: PartyId,
        ) -> Result<PolynomialSigningShare, OnlineError> {
            let Some(share) = self.shares.iter().find(|share| share.party == party) else {
                return Err(OnlineError::PartialSignerFailed(party));
            };

            let mut share = share.clone();
            if self.misbind_party {
                share.party = PartyId(share.party.0 + 100);
            }
            Ok(share)
        }
    }

    fn session(byte: u8) -> SessionId {
        SessionId([byte; 32])
    }

    fn input(party: u16) -> PartyPreprocessInput {
        let coeffs = MlDsa65::K * MlDsa65::N;
        PartyPreprocessInput {
            party: PartyId(party),
            highs: vec![party as u32; coeffs],
            lows: vec![party as u32 + 2; coeffs],
            y_share: vec![party as u8; 4],
            ay_contribution: None,
            nonce_commitment: NonceCommitment([party as u8; 32]),
            randomness_commitment: Commitment([(party + 10) as u8; 32]),
        }
    }

    fn token_and_request() -> (CertifiedToken, SignRequest) {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(9),
            vec![input(1), input(2)],
        )
        .expect("test token certifies");
        let request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: token.session_id,
            signing_set: token.signer_set.clone(),
            message: b"message".to_vec(),
            external_mu: None,
            context: b"ctx".to_vec(),
            token_transcript_hash: token.transcript_hash,
        };
        (token, request)
    }

    fn token_and_request_for(byte: u8) -> (CertifiedToken, SignRequest) {
        let mut registry = SessionRegistry::new();
        let token = certify_preprocessing_token::<MlDsa65>(
            &mut registry,
            session(byte),
            vec![input(1), input(2)],
        )
        .expect("test token certifies");
        let request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: token.session_id,
            signing_set: token.signer_set.clone(),
            message: b"message".to_vec(),
            external_mu: None,
            context: b"ctx".to_vec(),
            token_transcript_hash: token.transcript_hash,
        };
        (token, request)
    }

    fn poly_with_coeffs(coeffs: &[(usize, i32)]) -> Poly {
        let mut poly = Poly::zero();
        for &(index, coeff) in coeffs {
            poly.coeffs_mut()[index] = coeff;
        }
        poly
    }

    fn polyvec_with_const(value: i32) -> PolyVec {
        PolyVec::new(vec![poly_with_coeffs(&[(0, value)]); MlDsa65::L])
    }

    fn zero_polynomial_share_provider(signers: &[PartyId]) -> TestPolynomialShareProvider {
        TestPolynomialShareProvider {
            shares: signers
                .iter()
                .map(|&party| PolynomialSigningShare {
                    party,
                    y_share: PolyVec::zero(MlDsa65::L),
                    s1_share: PolyVec::zero(MlDsa65::L),
                })
                .collect(),
            misbind_party: false,
        }
    }

    fn dkg_config() -> DkgConfig {
        DkgConfig::new::<MlDsa65>(2, vec![PartyId(1), PartyId(2), PartyId(3)], KeygenEpoch(7))
            .expect("valid DKG config")
    }

    fn dkg_secret_share(config: &DkgConfig, party: PartyId, coeffs: Vec<i32>) -> DkgSecretShare {
        let point = config
            .interpolation_point::<MlDsa65>(party)
            .expect("configured party");
        let s1_share = BoundedSecretVectorShare::new::<MlDsa65>(config, party, point, coeffs)
            .expect("typed s1 share")
            .encode::<MlDsa65>(config)
            .expect("encoded s1 share");

        DkgSecretShare {
            party,
            s1_share,
            s2_share: vec![1],
            t0_share: vec![1],
            pairwise_seed_shares: vec![vec![1]],
        }
    }

    fn zero_dkg_secret_share(config: &DkgConfig, party: PartyId) -> DkgSecretShare {
        dkg_secret_share(config, party, vec![0; MlDsa65::L * MlDsa65::N])
    }

    fn dkg_key_package_from_secret(config: &DkgConfig, secret: DkgSecretShare) -> DkgKeyPackage {
        DkgKeyPackage {
            suite: config.suite,
            epoch: config.epoch,
            party: secret.party,
            threshold: config.threshold,
            rho: [0u8; 32],
            t1: PublicT1 {
                bytes: vec![0; config.suite.t1_len()],
                coeffs: Vec::new(),
            },
            public_key: vec![0; config.suite.public_key_len()],
            s1_share: DkgS1SecretShare {
                party: secret.party,
                s1_share: secret.s1_share,
                pairwise_seed_shares: secret.pairwise_seed_shares,
            },
            certificate: PublicKeyAssemblyCertificate {
                power2round: Power2RoundEvidence {
                    backend_id: Power2RoundBackendId::ProductionItMpc,
                    epoch: config.epoch,
                    suite: config.suite,
                    party_set_hash: [0u8; 32],
                    rho_hash: [0u8; 32],
                    output_t1_hash: [0u8; 32],
                    transcript_hash: [0u8; 32],
                },
                setup: None,
            },
        }
    }

    fn commitment_verifier_for(
        public_key: &[u8],
        shares: &[PolynomialSigningShare],
    ) -> CommitmentBackedPartialVerifier {
        let public_key = public_key_decode::<MlDsa65>(public_key).expect("decode test pk");
        CommitmentBackedPartialVerifier::new(
            shares
                .iter()
                .map(|share| PolynomialPartialCommitment {
                    party: share.party,
                    ay_commitment: az_from_rho::<MlDsa65>(&public_key.rho, &share.y_share)
                        .expect("A*y commitment"),
                    as1_commitment: az_from_rho::<MlDsa65>(&public_key.rho, &share.s1_share)
                        .expect("A*s1 commitment"),
                })
                .collect(),
        )
    }

    fn zero_w1_token_and_request() -> (CertifiedToken, SignRequest) {
        let (mut token, request) = token_and_request();
        token.w1.fill(0);
        (token, request)
    }

    #[cfg(feature = "std")]
    fn test_store_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "talus-consumed-{name}-{}-{unique}.log",
            std::process::id()
        ))
    }

    #[test]
    fn sign_request_validation_rejects_mismatch() {
        let (token, mut request) = token_and_request();
        request.protocol_version = 0;
        assert_eq!(
            validate_sign_request::<MlDsa65>(&request, &token),
            Err(OnlineError::BadProtocolVersion {
                expected: ONLINE_PROTOCOL_VERSION,
                got: 0,
            })
        );
    }

    #[test]
    fn challenge_material_is_stable_and_bound_to_w1() {
        let (mut token, request) = token_and_request();
        let tr = [0x42; 64];
        let first = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let second = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        assert_eq!(first, second);

        token.w1[0] ^= 1;
        let changed = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        assert_ne!(first.ctilde, changed.ctilde);
    }

    #[test]
    fn commitment_backed_partial_verifier_accepts_matching_commitment() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let share = PolynomialSigningShare {
            party: PartyId(1),
            y_share: polyvec_with_const(3),
            s1_share: polyvec_with_const(2),
        };
        let partial = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            share.party,
            &challenge,
            &share.y_share,
            &share.s1_share,
        )
        .expect("partial");
        let verifier = commitment_verifier_for(&public_key, &[share]);

        verifier
            .verify_partial::<MlDsa65>(&public_key, token.session_id, &challenge, &partial)
            .expect("partial verifies");
    }

    #[test]
    fn commitment_backed_partial_verifier_blames_bad_partial() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let share = PolynomialSigningShare {
            party: PartyId(1),
            y_share: polyvec_with_const(3),
            s1_share: polyvec_with_const(2),
        };
        let mut partial = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            share.party,
            &challenge,
            &share.y_share,
            &share.s1_share,
        )
        .expect("partial");
        partial.z_share.polys_mut()[0].coeffs_mut()[0] ^= 1;
        let verifier = commitment_verifier_for(&public_key, &[share]);

        assert_eq!(
            verifier
                .verify_partial::<MlDsa65>(&public_key, token.session_id, &challenge, &partial,),
            Err(OnlineError::Blame(PartyId(1)))
        );
    }

    #[test]
    fn commitment_backed_partial_verifier_rejects_missing_commitment() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let partial = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: PolyVec::zero(MlDsa65::L),
            challenge: challenge.ctilde.clone(),
        };

        assert_eq!(
            CommitmentBackedPartialVerifier::default().verify_partial::<MlDsa65>(
                &public_key,
                token.session_id,
                &challenge,
                &partial,
            ),
            Err(OnlineError::PublicCommitmentMissing(PartyId(1)))
        );
    }

    #[test]
    fn commitment_backed_partial_verifier_rejects_bad_commitment_length() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let partial = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: PolyVec::zero(MlDsa65::L),
            challenge: challenge.ctilde.clone(),
        };
        let verifier = CommitmentBackedPartialVerifier::new(vec![PolynomialPartialCommitment {
            party: PartyId(1),
            ay_commitment: PolyVec::zero(MlDsa65::K - 1),
            as1_commitment: PolyVec::zero(MlDsa65::K),
        }]);

        assert_eq!(
            verifier
                .verify_partial::<MlDsa65>(&public_key, token.session_id, &challenge, &partial,),
            Err(OnlineError::PublicCommitmentLength {
                party: PartyId(1),
                expected: MlDsa65::K,
                got: MlDsa65::K - 1,
            })
        );
    }

    #[test]
    fn dkg_s1_share_decodes_to_online_polyvec_shape() {
        let config = dkg_config();
        let mut coeffs = vec![0; MlDsa65::L * MlDsa65::N];
        coeffs[0] = 5;
        coeffs[MlDsa65::N] = 7;
        coeffs[MlDsa65::L * MlDsa65::N - 1] = MlDsa65::Q - 1;
        let secret = dkg_secret_share(&config, PartyId(2), coeffs);

        let s1 = polyvec_from_dkg_s1_share::<MlDsa65>(&config, &secret)
            .expect("decode DKG s1 into online polyvec");

        assert_eq!(s1.len(), MlDsa65::L);
        assert_eq!(s1.polys()[0].coeffs()[0], 5);
        assert_eq!(s1.polys()[1].coeffs()[0], 7);
        assert_eq!(
            s1.polys()[MlDsa65::L - 1].coeffs()[MlDsa65::N - 1],
            MlDsa65::Q - 1
        );
    }

    #[test]
    fn dkg_s1_share_decode_rejects_bad_party_binding() {
        let config = dkg_config();
        let mut secret = zero_dkg_secret_share(&config, PartyId(1));
        secret.party = PartyId(2);

        assert_eq!(
            polyvec_from_dkg_s1_share::<MlDsa65>(&config, &secret),
            Err(OnlineError::Dkg(DkgError::PartyMismatch {
                expected: PartyId(2),
                got: PartyId(1),
            }))
        );
    }

    #[test]
    fn dkg_backed_provider_returns_y_and_decoded_s1() {
        let config = dkg_config();
        let session_id = session(61);
        let mut coeffs = vec![0; MlDsa65::L * MlDsa65::N];
        coeffs[3] = 11;
        let secret = dkg_secret_share(&config, PartyId(2), coeffs);
        let y_share = polyvec_with_const(13);
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::new(
            session_id,
            config,
            vec![(PartyId(2), y_share.clone())],
            vec![secret],
        );

        let share = provider
            .signing_share(session_id, PartyId(2))
            .expect("provider returns decoded share");

        assert_eq!(share.party, PartyId(2));
        assert_eq!(share.y_share, y_share);
        assert_eq!(share.s1_share.polys()[0].coeffs()[3], 11);
    }

    #[test]
    fn dkg_backed_provider_rejects_wrong_session() {
        let config = dkg_config();
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::new(
            session(61),
            config.clone(),
            vec![(PartyId(1), PolyVec::zero(MlDsa65::L))],
            vec![zero_dkg_secret_share(&config, PartyId(1))],
        );

        assert_eq!(
            provider.signing_share(session(62), PartyId(1)),
            Err(OnlineError::SessionMismatch)
        );
    }

    #[test]
    fn polynomial_partial_computes_and_aggregates_z() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);

        let signer_set = vec![PartyId(1), PartyId(2)];
        let first = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            PartyId(1),
            &challenge,
            &polyvec_with_const(3),
            &PolyVec::zero(MlDsa65::L),
        )
        .expect("first partial");
        let second = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            PartyId(2),
            &challenge,
            &polyvec_with_const(4),
            &PolyVec::zero(MlDsa65::L),
        )
        .expect("second partial");

        let response = assemble_polynomial_response::<MlDsa65>(
            token.session_id,
            &signer_set,
            &challenge,
            &[first, second],
        )
        .expect("aggregate polynomial response");

        assert_eq!(response.ctilde, challenge.ctilde);
        for poly in response.z.polys() {
            assert_eq!(poly.coeffs()[0], 7);
        }
    }

    #[test]
    fn polynomial_lagrange_response_interpolates_at_zero() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let signer_set = vec![PartyId(1), PartyId(2)];
        let first = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: polyvec_with_const(14),
            challenge: challenge.ctilde.clone(),
        };
        let second = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(2),
            z_share: polyvec_with_const(17),
            challenge: challenge.ctilde.clone(),
        };

        let response = assemble_polynomial_response_lagrange::<MlDsa65>(
            token.session_id,
            &signer_set,
            &challenge,
            &[first, second],
        )
        .expect("lagrange aggregate");

        for poly in response.z.polys() {
            assert_eq!(poly.coeffs()[0], 11);
        }
    }

    #[test]
    fn polynomial_partial_blames_wrong_binding() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let mut partial = compute_polynomial_partial::<MlDsa65>(
            token.session_id,
            PartyId(1),
            &challenge,
            &polyvec_with_const(3),
            &PolyVec::zero(MlDsa65::L),
        )
        .expect("partial");
        partial.challenge[0] ^= 1;

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                token.session_id,
                &[PartyId(1)],
                &challenge,
                &[partial],
            ),
            Err(OnlineError::Blame(PartyId(1)))
        );
    }

    #[test]
    fn polynomial_response_rejects_norm_failure() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let partial = PolynomialPartialSignature {
            session_id: token.session_id,
            party: PartyId(1),
            z_share: polyvec_with_const(MlDsa65::GAMMA1 - MlDsa65::BETA),
            challenge: challenge.ctilde.clone(),
        };

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                token.session_id,
                &[PartyId(1)],
                &challenge,
                &[partial],
            ),
            Err(OnlineError::ZNormExceeded {
                norm: MlDsa65::GAMMA1 - MlDsa65::BETA,
                bound: MlDsa65::GAMMA1 - MlDsa65::BETA,
            })
        );
    }

    #[test]
    fn polynomial_response_rejects_partial_count_mismatch() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);

        assert_eq!(
            assemble_polynomial_response::<MlDsa65>(
                token.session_id,
                &[PartyId(1)],
                &challenge,
                &[],
            ),
            Err(OnlineError::PartialCountMismatch {
                expected: 1,
                got: 0,
            })
        );
    }

    #[test]
    fn final_signature_candidate_encodes_typed_response_and_hints() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let public_approx = PolyVec::zero(MlDsa65::K);
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        let signature = encode_final_signature_candidate::<MlDsa65>(&response, &public_approx, &w1)
            .expect("signature candidate encodes");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(
            &signature.bytes[..MlDsa65::CTILDE_LEN],
            response.ctilde.as_slice()
        );
    }

    #[test]
    fn final_signature_candidate_rejects_hint_weight_failure() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let mut public_approx = PolyVec::zero(MlDsa65::K);
        for coeff_index in 0..=MlDsa65::OMEGA {
            public_approx.polys_mut()[0].coeffs_mut()[coeff_index] = MlDsa65::alpha();
        }
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        assert_eq!(
            encode_final_signature_candidate::<MlDsa65>(&response, &public_approx, &w1),
            Err(OnlineError::SignatureEncoding(
                SignatureEncodingError::HintWeight {
                    omega: MlDsa65::OMEGA,
                    got: MlDsa65::OMEGA + 1,
                }
            ))
        );
    }

    #[test]
    fn final_signature_candidate_from_public_key_decodes_t1_and_uses_az() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let az = PolyVec::zero(MlDsa65::K);
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        let signature = encode_final_signature_candidate_from_public_key::<MlDsa65>(
            &response,
            &public_key,
            &az,
            &w1,
        )
        .expect("signature candidate from pk");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(
            &signature.bytes[..MlDsa65::CTILDE_LEN],
            response.ctilde.as_slice()
        );
    }

    #[test]
    fn final_signature_candidate_from_public_key_rejects_bad_key_length() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };

        assert_eq!(
            encode_final_signature_candidate_from_public_key::<MlDsa65>(
                &response,
                &[0u8; 31],
                &PolyVec::zero(MlDsa65::K),
                &vec![0u32; MlDsa65::K * MlDsa65::N],
            ),
            Err(OnlineError::PublicKeyDecode(
                PublicKeyDecodeError::PublicKeyLength {
                    expected: MlDsa65::PK_LEN,
                    got: 31,
                }
            ))
        );
    }

    #[test]
    fn final_signature_candidate_with_az_computes_public_approx_from_key_seed() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L),
        };
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        let signature =
            encode_final_signature_candidate_with_az::<MlDsa65>(&response, &public_key, &w1)
                .expect("signature candidate computes A*z");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert_eq!(
            &signature.bytes[..MlDsa65::CTILDE_LEN],
            response.ctilde.as_slice()
        );
    }

    #[test]
    fn final_signature_candidate_with_az_rejects_bad_z_shape() {
        let (token, request) = token_and_request();
        let tr = [0x42; 64];
        let challenge = compute_challenge_material::<MlDsa65>(&request, &token, &tr);
        let response = PolynomialResponse {
            ctilde: challenge.ctilde.clone(),
            z: PolyVec::zero(MlDsa65::L - 1),
        };
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let w1 = vec![0u32; MlDsa65::K * MlDsa65::N];

        assert_eq!(
            encode_final_signature_candidate_with_az::<MlDsa65>(&response, &public_key, &w1),
            Err(OnlineError::Ntt(NttError::ZLength {
                expected: MlDsa65::L,
                got: MlDsa65::L - 1,
            }))
        );
    }

    #[test]
    fn fips_final_verifier_accepts_real_fips_signature() {
        let message = b"message".to_vec();
        let context = b"ctx".to_vec();
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[0x41; 32]);
        let signature = sk
            .try_sign_with_seed(&[0x42; 32], &message, &context)
            .expect("fips signature");
        let verifier =
            FipsFinalVerifier::<MlDsa65>::new(pk.into_bytes().to_vec()).expect("verifier");
        let request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: session(50),
            signing_set: vec![PartyId(1)],
            message: message.clone(),
            external_mu: None,
            context: context.clone(),
            token_transcript_hash: TranscriptHash([0; 32]),
        };

        assert!(verifier.verify_final(
            &request,
            &FinalSignature {
                bytes: signature.to_vec()
            }
        ));

        let mut bad_signature = signature.to_vec();
        bad_signature[0] ^= 1;
        assert!(!verifier.verify_final(
            &request,
            &FinalSignature {
                bytes: bad_signature
            }
        ));
    }

    #[test]
    fn fips_final_verifier_rejects_external_mu_requests() {
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[0x51; 32]);
        let signature = sk
            .try_sign_with_seed(&[0x52; 32], b"message", b"ctx")
            .expect("fips signature");
        let verifier =
            FipsFinalVerifier::<MlDsa65>::new(pk.into_bytes().to_vec()).expect("verifier");
        let request = SignRequest {
            protocol_version: ONLINE_PROTOCOL_VERSION,
            suite: MlDsa65::NAME,
            session_id: session(51),
            signing_set: vec![PartyId(1)],
            message: b"message".to_vec(),
            external_mu: Some([0u8; 64]),
            context: b"ctx".to_vec(),
            token_transcript_hash: TranscriptHash([0; 32]),
        };

        assert!(!verifier.verify_final(
            &request,
            &FinalSignature {
                bytes: signature.to_vec()
            }
        ));
    }

    #[test]
    fn signing_consumes_token_and_returns_verified_signature() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        let signature = sign_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            OnlineServices {
                tr: &tr,
                partial_signer: &SessionAwarePartialSigner,
                assembler: &TestAssembler,
                verifier: &AcceptVerifier,
            },
        )
        .expect("valid shell signing succeeds");

        assert!(!signature.bytes.is_empty());
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn polynomial_signing_consumes_token_and_returns_verified_candidate() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = zero_polynomial_share_provider(&token.signer_set);
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];
        let partial_verifier = commitment_verifier_for(&public_key, &share_provider.shares);

        let signature = sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            PolynomialOnlineServices {
                tr: &tr,
                public_key: &public_key,
                aggregation: PolynomialAggregation::Additive,
                partial_verifier: &partial_verifier,
                share_provider: &share_provider,
                verifier: &AcceptVerifier,
            },
        )
        .expect("typed signing succeeds");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn polynomial_signing_uses_dkg_backed_s1_shares() {
        let (token, request) = zero_w1_token_and_request();
        let config = dkg_config();
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::new(
            token.session_id,
            config.clone(),
            token
                .signer_set
                .iter()
                .map(|&party| (party, PolyVec::zero(MlDsa65::L)))
                .collect(),
            token
                .signer_set
                .iter()
                .map(|&party| zero_dkg_secret_share(&config, party))
                .collect(),
        );
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        let signature = sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            PolynomialOnlineServices {
                tr: &tr,
                public_key: &public_key,
                aggregation: PolynomialAggregation::Additive,
                partial_verifier: &NoopPolynomialPartialVerifier,
                share_provider: &provider,
                verifier: &AcceptVerifier,
            },
        )
        .expect("typed signing succeeds with DKG-backed s1 shares");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn polynomial_signing_accepts_native_dkg_key_packages() {
        let (token, request) = zero_w1_token_and_request();
        let config = dkg_config();
        let key_packages = token
            .signer_set
            .iter()
            .map(|&party| {
                dkg_key_package_from_secret(&config, zero_dkg_secret_share(&config, party))
            })
            .collect();
        let provider = DkgBackedPolynomialShareProvider::<MlDsa65>::from_key_packages(
            token.session_id,
            config,
            token
                .signer_set
                .iter()
                .map(|&party| (party, PolyVec::zero(MlDsa65::L)))
                .collect(),
            key_packages,
        );
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        let signature = sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            PolynomialOnlineServices {
                tr: &tr,
                public_key: &public_key,
                aggregation: PolynomialAggregation::Additive,
                partial_verifier: &NoopPolynomialPartialVerifier,
                share_provider: &provider,
                verifier: &AcceptVerifier,
            },
        )
        .expect("typed signing succeeds with native DKG key packages");

        assert_eq!(signature.bytes.len(), MlDsa65::SIG_LEN);
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.tokens_consumed, 1);
        assert_eq!(counters.signatures_returned, 1);
    }

    #[test]
    fn debug_redacts_polynomial_signing_shares() {
        let share = PolynomialSigningShare {
            party: PartyId(9),
            y_share: polyvec_with_const(1234),
            s1_share: polyvec_with_const(5678),
        };

        assert_eq!(
            format!("{share:?}"),
            "PolynomialSigningShare { party: PartyId(9), y_share: \"<redacted>\", s1_share: \"<redacted>\" }"
        );
    }

    #[test]
    fn consumed_token_cannot_sign_again() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        let first = sign_with_token::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &request,
            OnlineServices {
                tr: &tr,
                partial_signer: &SessionAwarePartialSigner,
                assembler: &TestAssembler,
                verifier: &AcceptVerifier,
            },
        );
        assert!(first.is_ok());
        assert_eq!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &SessionAwarePartialSigner,
                    assembler: &TestAssembler,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::TokenAlreadyConsumed(request.session_id))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_consumed_token_store_survives_reopen() {
        let path = test_store_path("survives_reopen");
        let _ = std::fs::remove_file(&path);
        let session_id = session(77);

        {
            let mut store = FileConsumedTokenStore::open(&path).expect("open store");
            store
                .persist_consumed(session_id)
                .expect("persist consumed");
            assert!(store.is_consumed(session_id));
        }

        let mut reopened = FileConsumedTokenStore::open(&path).expect("reopen store");
        assert!(reopened.is_consumed(session_id));
        assert_eq!(
            reopened.persist_consumed(session_id),
            Err(OnlineError::TokenAlreadyConsumed(session_id))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_consumed_token_store_blocks_restored_token() {
        let path = test_store_path("blocks_restored_token");
        let _ = std::fs::remove_file(&path);
        let (token, request) = token_and_request();
        let mut store = FileConsumedTokenStore::open(&path).expect("open store");
        store
            .persist_consumed(request.session_id)
            .expect("persist prior consumption");

        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert restored certified token");
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        assert_eq!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut store,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &SessionAwarePartialSigner,
                    assembler: &TestAssembler,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::TokenAlreadyConsumed(request.session_id))
        );
        assert!(pool.contains(request.session_id));
        assert_eq!(counters.tokens_consumed, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_consumed_token_store_rejects_corrupt_log() {
        let path = test_store_path("rejects_corrupt_log");
        std::fs::write(&path, "not-hex\n").expect("write corrupt store");

        assert_eq!(
            FileConsumedTokenStore::open(&path),
            Err(OnlineError::ConsumedTokenStoreCorrupt { line: 1 })
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn final_verify_failure_consumes_token_without_output() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        assert_eq!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &SessionAwarePartialSigner,
                    assembler: &TestAssembler,
                    verifier: &RejectVerifier,
                },
            ),
            Err(OnlineError::FinalVerifyFailed)
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.final_verify_failures, 1);
    }

    #[test]
    fn polynomial_final_verify_failure_consumes_token_without_output() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = zero_polynomial_share_provider(&token.signer_set);
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        assert_eq!(
            sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                PolynomialOnlineServices {
                    tr: &tr,
                    public_key: &public_key,
                    aggregation: PolynomialAggregation::Additive,
                    partial_verifier: &NoopPolynomialPartialVerifier,
                    share_provider: &share_provider,
                    verifier: &RejectVerifier,
                },
            ),
            Err(OnlineError::FinalVerifyFailed)
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
        assert_eq!(counters.final_verify_failures, 1);
    }

    #[test]
    fn partial_mismatch_consumes_token_without_output() {
        let (token, request) = token_and_request();
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];

        assert!(matches!(
            sign_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                OnlineServices {
                    tr: &tr,
                    partial_signer: &TestPartialSigner,
                    assembler: &TestAssembler,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::Blame(_))
        ));
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
    }

    #[test]
    fn polynomial_missing_share_consumes_token_without_output() {
        let (token, request) = zero_w1_token_and_request();
        let share_provider = TestPolynomialShareProvider {
            shares: vec![],
            misbind_party: false,
        };
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        assert_eq!(
            sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                PolynomialOnlineServices {
                    tr: &tr,
                    public_key: &public_key,
                    aggregation: PolynomialAggregation::Additive,
                    partial_verifier: &NoopPolynomialPartialVerifier,
                    share_provider: &share_provider,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::PartialSignerFailed(PartyId(1)))
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
    }

    #[test]
    fn polynomial_misbound_share_blames_party() {
        let (token, request) = zero_w1_token_and_request();
        let mut share_provider = zero_polynomial_share_provider(&token.signer_set);
        share_provider.misbind_party = true;
        let mut pool = TokenPool::new();
        pool.insert_certified(token)
            .expect("insert certified token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let public_key = vec![0u8; MlDsa65::PK_LEN];

        assert_eq!(
            sign_polynomial_with_token::<MlDsa65, _, _, _, _>(
                &mut pool,
                &mut consumed,
                &mut counters,
                &request,
                PolynomialOnlineServices {
                    tr: &tr,
                    public_key: &public_key,
                    aggregation: PolynomialAggregation::Additive,
                    partial_verifier: &NoopPolynomialPartialVerifier,
                    share_provider: &share_provider,
                    verifier: &AcceptVerifier,
                },
            ),
            Err(OnlineError::Blame(PartyId(1)))
        );
        assert!(pool.is_empty());
        assert!(consumed.is_consumed(request.session_id));
    }

    #[test]
    fn retry_consumes_failed_token_and_succeeds_with_next() {
        let (first_token, first_request) = token_and_request_for(10);
        let (second_token, second_request) = token_and_request_for(11);
        let mut pool = TokenPool::new();
        pool.insert_certified(first_token)
            .expect("insert first token");
        pool.insert_certified(second_token)
            .expect("insert second token");
        let mut consumed = ConsumedTokenStore::new();
        let mut counters = SigningCounters::default();
        let tr = [0x42; 64];
        let verifier = FailThenAcceptVerifier {
            calls: Cell::new(0),
        };

        let signature = sign_with_retry::<MlDsa65, _, _, _, _>(
            &mut pool,
            &mut consumed,
            &mut counters,
            &[first_request.clone(), second_request.clone()],
            OnlineServices {
                tr: &tr,
                partial_signer: &SessionAwarePartialSigner,
                assembler: &TestAssembler,
                verifier: &verifier,
            },
            RetryPolicy { max_attempts: 2 },
        );

        assert!(signature.expect("second retry succeeds").bytes.len() > 32);
        assert!(consumed.is_consumed(first_request.session_id));
        assert!(consumed.is_consumed(second_request.session_id));
        assert_eq!(counters.attempts, 2);
        assert_eq!(counters.tokens_consumed, 2);
        assert_eq!(counters.final_verify_failures, 1);
        assert_eq!(counters.signatures_returned, 1);
    }
}
