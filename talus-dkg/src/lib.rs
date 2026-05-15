#![forbid(unsafe_code)]
#![doc = "Production TALUS distributed key generation interfaces."]
//!
//! Normal builds expose the production-oriented native DKG API: vector
//! IT-VSS/DKG setup, typed production Power2Round evidence, and
//! `ProductionNativeDkgAssemblyOutput`.
//!
//! Scaffold assembly, simulator Power2Round backends, scalar-per-coefficient
//! correctness harnesses, and paper-compatible public exact `A*secret`
//! artifacts are test/dev material only. Release checks reject scaffold/dev
//! backend identities and `production-release-checks` refuses to build with the
//! `scaffold-dev` feature enabled.

#[cfg(all(feature = "production-release-checks", feature = "scaffold-dev"))]
compile_error!("production-release-checks must not be built with scaffold-dev insecure primitives");

use core::{cell::RefCell, fmt, marker::PhantomData};
use std::collections::VecDeque;

use sha3::{Digest, Sha3_256};
use talus_core::{
    az_from_rho, lagrange_coefficients_at_zero, reduce_mod_q, Coeff, MlDsaParams, Poly, PolyVec,
    ProductionBatchSizingPolicy, TalusPerformanceCounters,
};
use talus_mpc_core::PartyId;
use talus_wire::{
    decode_dkg_commit_payload as wire_decode_dkg_commit_payload,
    decode_dkg_complaint_payload as wire_decode_dkg_complaint_payload,
    decode_dkg_it_vss_artifact_payload as wire_decode_dkg_it_vss_artifact_payload,
    decode_dkg_prime_field_mpc_payload, decode_dkg_share_payload as wire_decode_dkg_share_payload,
    decode_dkg_small_residue_payload as wire_decode_dkg_small_residue_payload, decode_message,
    encode_dkg_commit_payload as wire_encode_dkg_commit_payload,
    encode_dkg_complaint_payload as wire_encode_dkg_complaint_payload,
    encode_dkg_it_vss_artifact_payload as wire_encode_dkg_it_vss_artifact_payload,
    encode_dkg_prime_field_mpc_payload, encode_dkg_share_payload as wire_encode_dkg_share_payload,
    encode_dkg_small_residue_payload as wire_encode_dkg_small_residue_payload, encode_message,
    validate_round_batch, AuthenticatedP2pTransport, DkgCommitPayload as WireDkgCommitPayload,
    DkgComplaintPayload as WireDkgComplaintPayload, DkgItVssArtifactPayload,
    DkgItVssAuditRecordPayload, DkgItVssCertificatePayload, DkgItVssComplaintPayload,
    DkgItVssConsistencyRecordPayload, DkgItVssPublicCoinSharePayload,
    DkgItVssPublicCommitmentPayload, DkgItVssPublicPrecommitmentPayload, DkgItVssResolutionPayload,
    DkgPrimeFieldMpcPayload, DkgSharePayload as WireDkgSharePayload,
    DkgSmallResiduePayload as WireDkgSmallResiduePayload, EquivocationResistantBroadcast,
    ExpectedContext, NativeDkgTransportEvidence, PayloadKind, RoundId, SuiteId as WireSuiteId,
    TransportError, WireHeader, WireMessage, WIRE_PROTOCOL_VERSION,
};
use zeroize::Zeroize;

const BOUNDED_VECTOR_SHARE_MAGIC: &[u8; 8] = b"TBVS1\0\0\0";
const AS1_VECTOR_SHARE_MAGIC: &[u8; 8] = b"TAS1V1\0\0";
#[cfg(any(test, feature = "scaffold-dev"))]
const IN_PROCESS_SCALAR_VSS_PUBLIC_CHECK_MAGIC: &[u8; 8] = b"TIVPC1\0\0";
const IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_MAGIC: &[u8; 8] = b"TIVPS1\0\0";
const IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_VECTOR_MAGIC: &[u8; 8] = b"TIVPV1\0\0";
const IT_VSS_PRIVATE_DELIVERY_MAGIC: &[u8; 8] = b"TIVSD1\0\0";
const IT_VSS_PRIVATE_DELIVERY_BATCH_MAGIC: &[u8; 8] = b"TIVDB1\0\0";

mod types;
pub use types::*;

mod shamir;
pub use shamir::*;

mod scalar_vss;
pub use scalar_vss::*;

mod it_vss;
pub use it_vss::*;

mod error;
pub use error::*;

mod power2round;
pub use power2round::*;

#[cfg(test)]
mod test_dealer;
#[cfg(test)]
pub use test_dealer::*;

/// Restart decision for an incomplete native DKG setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgSetupRestartDecision {
    /// No setup phase was started.
    Fresh,
    /// The latest phase is waiting/collected and can be resumed from logs.
    Resume,
    /// The latest phase completed local collection.
    Complete,
    /// The latest phase only sent local private material; scheduler must
    /// replay sent messages and wait for an accepted round before assembly.
    ReplaySentThenResume,
    /// Setup reached an abort cursor and cannot become accepted.
    Aborted,
}

/// Classifies how a setup scheduler should continue from the latest cursor.
pub fn classify_dkg_setup_restart(latest: Option<&DkgSetupPhaseCursor>) -> DkgSetupRestartDecision {
    match latest.map(|cursor| cursor.state) {
        None => DkgSetupRestartDecision::Fresh,
        Some(DkgSetupPhaseCursorState::Sent) => DkgSetupRestartDecision::ReplaySentThenResume,
        Some(DkgSetupPhaseCursorState::Waiting) => DkgSetupRestartDecision::Resume,
        Some(DkgSetupPhaseCursorState::Collected) => DkgSetupRestartDecision::Complete,
        Some(DkgSetupPhaseCursorState::Aborted) => DkgSetupRestartDecision::Aborted,
    }
}

fn validate_small_residue_contribution(
    label: SamplerLabel,
    eta: SmallSecretEta,
    contribution: &SmallResidueContribution,
) -> Result<(), DkgError> {
    if contribution.label != label || contribution.eta != eta {
        return Err(DkgError::SmallSamplerLabelMismatch);
    }
    if contribution.residue >= eta.modulus() {
        return Err(DkgError::InvalidSmallResidue {
            dealer: contribution.dealer,
            modulus: eta.modulus(),
            got: contribution.residue,
        });
    }
    if contribution.bits.len() != eta.bit_width() {
        return Err(DkgError::InvalidSecretShareEncoding(
            "small residue bit width mismatch",
        ));
    }

    let mut value = 0u8;
    for (index, &bit) in contribution.bits.iter().enumerate() {
        if bit > 1 {
            return Err(DkgError::InvalidSmallResidueBit {
                dealer: contribution.dealer,
                bit_index: index,
                bit,
            });
        }
        value |= bit << index;
    }
    if value != contribution.residue {
        return Err(DkgError::InvalidSecretShareEncoding(
            "small residue bit decomposition mismatch",
        ));
    }

    Ok(())
}

fn wire_dkg_commit_payload_from_dkg_commit(commit: &DkgCommitPayload) -> WireDkgCommitPayload {
    let vss_commitments = commit
        .vss_commitments
        .iter()
        .map(|commitment| commitment.bytes.clone())
        .collect();
    WireDkgCommitPayload::new(vss_commitments, commit.pairwise_seed_commitment.commitment)
}

fn validate_verified_small_residue_input(
    label: SamplerLabel,
    eta: SmallSecretEta,
    input: &VerifiedSmallResidueInput,
) -> Result<(), DkgError> {
    if input.label != label || input.eta != eta {
        return Err(DkgError::SmallSamplerLabelMismatch);
    }
    match input.verification {
        #[cfg(any(test, feature = "scaffold-dev"))]
        SmallResidueInputVerification::InProcessScaffold => {}
        SmallResidueInputVerification::ItVssCertificate {
            label_hash,
            certificate_hash,
        } => {
            if label_hash == [0u8; 32] || certificate_hash == [0u8; 32] {
                return Err(DkgError::UnverifiedSmallResidueInput {
                    dealer: input.dealer,
                });
            }
        }
        #[cfg(test)]
        SmallResidueInputVerification::Unverified => {
            return Err(DkgError::UnverifiedSmallResidueInput {
                dealer: input.dealer,
            });
        }
    }
    if input.residue >= eta.modulus() {
        return Err(DkgError::InvalidSmallResidue {
            dealer: input.dealer,
            modulus: eta.modulus(),
            got: input.residue,
        });
    }
    Ok(())
}

fn coeffs_to_polyvec<P: MlDsaParams>(
    coeffs: &[Coeff],
    poly_count: usize,
) -> Result<PolyVec, DkgError> {
    let expected = poly_count * P::N;
    if coeffs.len() != expected {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected,
            got: coeffs.len(),
        });
    }

    Ok(PolyVec::new(
        (0..poly_count)
            .map(|row| {
                Poly::from_coeffs(core::array::from_fn(|index| {
                    reduce_mod_q::<P>(coeffs[row * P::N + index])
                }))
            })
            .collect(),
    ))
}

fn as1_share_from_s1_share_for_params<P: MlDsaParams>(
    config: &DkgConfig,
    rho: &[u8; 32],
    s1_share: &DkgS1SecretShare,
) -> Result<DkgAs1SecretShare, DkgError> {
    let decoded = BoundedSecretVectorShare::decode::<P>(config, &s1_share.s1_share)?;
    if decoded.party != s1_share.party {
        return Err(DkgError::PartyMismatch {
            expected: s1_share.party,
            got: decoded.party,
        });
    }
    let s1_polyvec = coeffs_to_polyvec::<P>(&decoded.coeffs, P::L)?;
    let as1 = az_from_rho::<P>(rho, &s1_polyvec)
        .map_err(|_| DkgError::Backend("private As1 derivation failed"))?;
    let mut coeffs = Vec::with_capacity(P::K * P::N);
    for poly in as1.polys() {
        coeffs.extend_from_slice(poly.coeffs());
    }
    let as1_share = As1SecretVectorShare::new::<P>(config, s1_share.party, decoded.point, coeffs)?
        .encode::<P>(config)?;
    Ok(DkgAs1SecretShare {
        party: s1_share.party,
        as1_share,
    })
}

fn as1_share_from_s1_share(
    config: &DkgConfig,
    rho: &[u8; 32],
    s1_share: &DkgS1SecretShare,
) -> Result<DkgAs1SecretShare, DkgError> {
    match config.suite {
        DkgSuite::MlDsa44 => {
            as1_share_from_s1_share_for_params::<talus_core::MlDsa44>(config, rho, s1_share)
        }
        DkgSuite::MlDsa65 => {
            as1_share_from_s1_share_for_params::<talus_core::MlDsa65>(config, rho, s1_share)
        }
        DkgSuite::MlDsa87 => {
            as1_share_from_s1_share_for_params::<talus_core::MlDsa87>(config, rho, s1_share)
        }
    }
}

fn validate_as1_matches_s1_share(
    config: &DkgConfig,
    rho: &[u8; 32],
    s1_share: &DkgS1SecretShare,
    as1_share: &DkgAs1SecretShare,
) -> Result<(), DkgError> {
    let expected = as1_share_from_s1_share(config, rho, s1_share)?;
    if &expected != as1_share {
        return Err(DkgError::DkgKeyPackagePublicMaterialMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn reconstruct_shared_t<P: MlDsaParams>(
    config: &DkgConfig,
    shared_t: &SharedT,
) -> Result<PolyVec, DkgError> {
    if shared_t.shares.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: shared_t.shares.len(),
        });
    }
    let mut polys = Vec::with_capacity(P::K);
    for row in 0..P::K {
        let mut coeffs = [0; 256];
        for (index, coefficient) in coeffs.iter_mut().enumerate() {
            let shares = shared_t
                .shares
                .iter()
                .take(usize::from(config.threshold))
                .map(|share| ShamirScalarShare {
                    point: share.point,
                    value: share.t_share.polys()[row].coeffs()[index],
                })
                .collect::<Vec<_>>();
            *coefficient = reconstruct_scalar_at_zero::<P>(&shares)?;
        }
        polys.push(Poly::from_coeffs(coeffs));
    }
    Ok(PolyVec::new(polys))
}

fn pack_t1_coeffs<P: MlDsaParams>(coeffs: &[u16]) -> Result<Vec<u8>, DkgError> {
    let expected = P::K * P::N;
    if coeffs.len() != expected {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected,
            got: coeffs.len(),
        });
    }
    let mut out = vec![0u8; P::K * 320];
    let mut bit_pos = 0usize;
    for &coefficient in coeffs {
        if coefficient > 1023 {
            return Err(DkgError::Backend("t1 coefficient out of range"));
        }
        for bit in 0..10 {
            if ((coefficient >> bit) & 1) == 1 {
                out[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
    Ok(out)
}

fn power2round_evidence(
    backend_id: Power2RoundBackendId,
    config: &DkgConfig,
    label: PublicKeyAssemblyLabel,
    t1: &[u8],
) -> Power2RoundEvidence {
    let output_t1_hash = hash_bytes32(b"TALUS-DKG-v1/power2round-t1", t1);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/power2round-evidence");
    hasher.update(config.transcript_hash().0);
    hasher.update([config.suite.as_u8()]);
    hasher.update(config.epoch.0.to_le_bytes());
    hasher.update(dkg_party_set_hash(config));
    hasher.update(label.rho_hash);
    hasher.update(output_t1_hash);
    hasher.update([match backend_id {
        #[cfg(test)]
        Power2RoundBackendId::InsecureClearSimulator => 1,
        #[cfg(test)]
        Power2RoundBackendId::LocalPrimeFieldSimulator => 2,
        #[cfg(test)]
        Power2RoundBackendId::InProcessShamirSimulator => 3,
        #[cfg(test)]
        Power2RoundBackendId::NetworkedShamirSimulator => 4,
        #[cfg(test)]
        Power2RoundBackendId::TransportBackedShamirSimulator => 5,
        #[cfg(test)]
        Power2RoundBackendId::RuntimeCoordinatedTransportShamirSimulator => 6,
        #[cfg(test)]
        Power2RoundBackendId::TransportBackedPerPartySkeleton => 7,
        #[cfg(test)]
        Power2RoundBackendId::TransportBackedPerPartyDriver => 8,
        Power2RoundBackendId::ProductionItMpc => 9,
    }]);
    Power2RoundEvidence {
        backend_id,
        epoch: config.epoch,
        suite: config.suite,
        party_set_hash: dkg_party_set_hash(config),
        rho_hash: label.rho_hash,
        output_t1_hash,
        transcript_hash: hasher.finalize().into(),
    }
}

fn dkg_party_set_hash(config: &DkgConfig) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/party-set");
    hasher.update(config.threshold.to_le_bytes());
    hasher.update((config.parties.len() as u32).to_le_bytes());
    for party in &config.parties {
        hasher.update(party.0.to_le_bytes());
    }
    hasher.finalize().into()
}

fn hash_bytes32(domain: &'static [u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hash_bytes(&mut hasher, bytes);
    hasher.finalize().into()
}

fn scaffold_party_commitment(
    config: &DkgConfig,
    domain: &'static [u8],
    party: PartyId,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/in-process-public-output-party");
    hasher.update(domain);
    hasher.update(config.transcript_hash().0);
    hasher.update(party.0.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(feature = "std")]
fn parse_dkg_store_line(line: &str) -> Option<(KeygenEpoch, KeygenTranscriptHash)> {
    let (epoch, hash) = line.split_once(' ')?;
    let epoch = epoch.parse::<u64>().ok()?;
    let hash = parse_hex32(hash)?;
    Some((KeygenEpoch(epoch), KeygenTranscriptHash(hash)))
}

#[cfg(feature = "std")]
enum PrimeFieldMpcLogEntry {
    Round(AcceptedPrimeFieldMpcRound),
    Coefficient(Power2RoundCoefficientCompletion),
}

#[cfg(feature = "std")]
fn parse_prime_field_mpc_round_log_line(line: &str) -> Option<PrimeFieldMpcLogEntry> {
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    if first == "C" {
        let poly_idx = fields.next()?.parse::<usize>().ok()?;
        let coeff_idx = fields.next()?.parse::<usize>().ok()?;
        let t1 = fields.next()?.parse::<u16>().ok()?;
        let label_hash = parse_hex32(fields.next()?)?;
        if fields.next().is_some() {
            return None;
        }
        return Some(PrimeFieldMpcLogEntry::Coefficient(
            Power2RoundCoefficientCompletion {
                poly_idx,
                coeff_idx,
                t1,
                label_hash,
            },
        ));
    }
    let kind = prime_field_round_kind_from_u8(first.parse::<u8>().ok()?)?;
    let phase = prime_field_phase_from_u8(fields.next()?.parse::<u8>().ok()?)?;
    let label_hash = parse_hex32(fields.next()?)?;
    let mut senders = Vec::new();
    for field in fields {
        senders.push(PartyId(field.parse::<u16>().ok()?));
    }
    Some(PrimeFieldMpcLogEntry::Round(AcceptedPrimeFieldMpcRound {
        kind,
        phase,
        label_hash,
        senders,
    }))
}

#[cfg(feature = "std")]
fn parse_prime_field_mpc_wire_log_records(
    line: &str,
) -> Option<Vec<PrimeFieldMpcWireMessageRecord>> {
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    if first == "S" {
        let count = fields.next()?.parse::<usize>().ok()?;
        if count == 0 {
            return None;
        }
        let direction = PrimeFieldMpcWireDirection::from_u8(fields.next()?.parse::<u8>().ok()?)?;
        let peer = match fields.next()?.parse::<u16>().ok()? {
            0 => None,
            value => Some(PartyId(value)),
        };
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let message_bytes = parse_hex_bytes(fields.next()?)?;
            let message = decode_message(&message_bytes).ok()?;
            records.push(PrimeFieldMpcWireMessageRecord {
                direction,
                peer,
                message,
            });
        }
        if fields.next().is_some() {
            return None;
        }
        return Some(records);
    }
    if first == "D" {
        let count = fields.next()?.parse::<usize>().ok()?;
        if count == 0 {
            return None;
        }
        let direction = PrimeFieldMpcWireDirection::from_u8(fields.next()?.parse::<u8>().ok()?)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let peer = match fields.next()?.parse::<u16>().ok()? {
                0 => None,
                value => Some(PartyId(value)),
            };
            let message_bytes = parse_hex_bytes(fields.next()?)?;
            let message = decode_message(&message_bytes).ok()?;
            records.push(PrimeFieldMpcWireMessageRecord {
                direction,
                peer,
                message,
            });
        }
        if fields.next().is_some() {
            return None;
        }
        return Some(records);
    }
    if first == "G" {
        let count = fields.next()?.parse::<usize>().ok()?;
        if count == 0 {
            return None;
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let direction =
                PrimeFieldMpcWireDirection::from_u8(fields.next()?.parse::<u8>().ok()?)?;
            let peer = match fields.next()?.parse::<u16>().ok()? {
                0 => None,
                value => Some(PartyId(value)),
            };
            let message_bytes = parse_hex_bytes(fields.next()?)?;
            let message = decode_message(&message_bytes).ok()?;
            records.push(PrimeFieldMpcWireMessageRecord {
                direction,
                peer,
                message,
            });
        }
        if fields.next().is_some() {
            return None;
        }
        return Some(records);
    }
    Some(vec![parse_prime_field_mpc_wire_log_line(line)?])
}

#[cfg(feature = "std")]
fn parse_prime_field_mpc_wire_log_line(line: &str) -> Option<PrimeFieldMpcWireMessageRecord> {
    let mut fields = line.split_whitespace();
    let direction = PrimeFieldMpcWireDirection::from_u8(fields.next()?.parse::<u8>().ok()?)?;
    let peer = match fields.next()?.parse::<u16>().ok()? {
        0 => None,
        value => Some(PartyId(value)),
    };
    let message_bytes = parse_hex_bytes(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    let message = decode_message(&message_bytes).ok()?;
    Some(PrimeFieldMpcWireMessageRecord {
        direction,
        peer,
        message,
    })
}

#[cfg(feature = "std")]
fn parse_prime_field_mpc_phase_cursor_log_line(line: &str) -> Option<PrimeFieldMpcPhaseCursor> {
    let mut fields = line.split_whitespace();
    let kind = prime_field_round_kind_from_u8(fields.next()?.parse::<u8>().ok()?)?;
    let phase = prime_field_phase_from_u8(fields.next()?.parse::<u8>().ok()?)?;
    let receiver = match fields.next()?.parse::<u16>().ok()? {
        0 => None,
        value => Some(PartyId(value)),
    };
    let label_hash = parse_hex32(fields.next()?)?;
    let state = PrimeFieldMpcPhaseCursorState::from_u8(fields.next()?.parse::<u8>().ok()?)?;
    let expected = fields.next()?.parse::<usize>().ok()?;
    let got = fields.next()?.parse::<usize>().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(PrimeFieldMpcPhaseCursor {
        kind,
        phase,
        receiver,
        label_hash,
        state,
        expected,
        got,
    })
}

#[cfg(feature = "std")]
fn parse_dkg_wire_log_line(line: &str) -> Option<DkgWireMessageRecord> {
    let mut fields = line.split_whitespace();
    let direction = PrimeFieldMpcWireDirection::from_u8(fields.next()?.parse::<u8>().ok()?)?;
    let peer = match fields.next()?.parse::<u16>().ok()? {
        0 => None,
        value => Some(PartyId(value)),
    };
    let message_bytes = parse_hex_bytes(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    let message = decode_message(&message_bytes).ok()?;
    Some(DkgWireMessageRecord {
        direction,
        peer,
        message,
    })
}

#[cfg(feature = "std")]
fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

#[cfg(feature = "std")]
fn parse_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
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

struct Hex32([u8; 32]);

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
struct HexBytes<'a>(&'a [u8]);

#[cfg(feature = "std")]
impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn residue_bits(value: u8, bit_width: usize) -> Vec<u8> {
    (0..bit_width).map(|index| (value >> index) & 1).collect()
}

fn small_sampler_share_mask<P: MlDsaParams>(
    seed: [u8; 32],
    share_index: u64,
    label: SamplerLabel,
    degree: usize,
) -> Coeff {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/small-sampler-share-mask");
    hasher.update([DkgSuite::for_params::<P>().as_u8()]);
    hasher.update(seed);
    hasher.update(share_index.to_le_bytes());
    hasher.update(label.config_hash.0);
    hasher.update([label.vector.as_u8()]);
    hasher.update(label.coefficient_index.to_le_bytes());
    hasher.update((degree as u32).to_le_bytes());
    let digest = hasher.finalize();
    let mut wide = [0u8; 8];
    wide.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(wide) % P::Q as u64) as Coeff
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn in_process_scalar_vss_mask<P: MlDsaParams>(
    seed: [u8; 32],
    deal_index: u64,
    dealer: PartyId,
    degree: usize,
) -> Coeff {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/in-process-scalar-it-vss-mask");
    hasher.update([DkgSuite::for_params::<P>().as_u8()]);
    hasher.update(seed);
    hasher.update(deal_index.to_le_bytes());
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((degree as u32).to_le_bytes());
    let digest = hasher.finalize();
    let mut wide = [0u8; 8];
    wide.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(wide) % P::Q as u64) as Coeff
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn in_process_scalar_vss_coefficient_commitment<P: MlDsaParams>(
    config: &DkgConfig,
    dealer: PartyId,
    index: usize,
    coefficient: Coeff,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/in-process-scalar-it-vss-coeff");
    hasher.update(config.transcript_hash().0);
    hasher.update([DkgSuite::for_params::<P>().as_u8()]);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((index as u32).to_le_bytes());
    hasher.update(reduce_mod_q::<P>(coefficient).to_le_bytes());
    hasher.finalize().into()
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn in_process_scalar_vss_public_check_binding(
    dealer: PartyId,
    threshold: u16,
    config_hash: KeygenTranscriptHash,
    commitments: &[VssCommitment],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/in-process-scalar-it-vss-public-check");
    hasher.update(config_hash.0);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update(threshold.to_le_bytes());
    hash_len_prefixed_vecs(
        &mut hasher,
        commitments.iter().map(|commitment| &commitment.bytes),
    );
    hasher.finalize().into()
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn in_process_scalar_vss_share_binding<P: MlDsaParams>(
    config_hash: KeygenTranscriptHash,
    public_check_binding: [u8; 32],
    dealer: PartyId,
    receiver: PartyId,
    point: u32,
    value: Coeff,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/in-process-scalar-it-vss-share");
    hasher.update(config_hash.0);
    hasher.update(public_check_binding);
    hasher.update([DkgSuite::for_params::<P>().as_u8()]);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update(receiver.0.to_le_bytes());
    hasher.update(point.to_le_bytes());
    hasher.update(reduce_mod_q::<P>(value).to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
fn scalar_vss_coefficient_commitment<P: MlDsaParams>(
    dealer: PartyId,
    index: usize,
    coefficient: Coeff,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/test-only-scalar-vss-coeff");
    hasher.update([DkgSuite::for_params::<P>().as_u8()]);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((index as u32).to_le_bytes());
    hasher.update(reduce_mod_q::<P>(coefficient).to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
fn scalar_vss_commitment_binding(commitments: &[VssCommitment]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/test-only-scalar-vss-binding");
    hash_len_prefixed_vecs(
        &mut hasher,
        commitments.iter().map(|commitment| &commitment.bytes),
    );
    hasher.finalize().into()
}

/// Public DKG round labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgRound {
    /// Share commitments are broadcast.
    Commit = 1,
    /// Encrypted shares and seed commitments are exchanged.
    Share = 2,
    /// Complaints and openings are resolved.
    Complaint = 3,
    /// Final public key, commitments, and transcript are accepted.
    Finalize = 4,
}

/// DKG state-machine phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgState {
    /// Not started.
    Init,
    /// Waiting for round messages.
    Waiting(DkgRound),
    /// DKG completed.
    Complete,
    /// DKG failed.
    Failed,
}

/// Commit-round broadcast for one DKG dealer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgCommitPayload {
    /// Dealer/sender party id.
    pub dealer: PartyId,
    /// IT-VSS commitments/checks for the dealer's secret polynomial.
    pub vss_commitments: Vec<VssCommitment>,
    /// Public commitment to this dealer's pairwise seed setup material.
    pub pairwise_seed_commitment: PairwiseSeedCommitment,
}

/// Share-round private payload from one dealer to one receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgSharePayload {
    /// Dealer/sender party id.
    pub dealer: PartyId,
    /// Intended receiver party id.
    pub receiver: PartyId,
    /// Authenticated encrypted VSS share bytes, opaque to this scaffold.
    pub encrypted_share: Vec<u8>,
    /// Authenticated encrypted pairwise seed-share bytes, opaque to this scaffold.
    pub encrypted_seed_share: Vec<u8>,
    /// Backend proof or channel transcript binding bytes.
    pub proof: Vec<u8>,
}

impl fmt::Debug for DkgSharePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgSharePayload")
            .field("dealer", &self.dealer)
            .field("receiver", &self.receiver)
            .field("encrypted_share", &"<redacted>")
            .field("encrypted_seed_share", &"<redacted>")
            .field("proof_len", &self.proof.len())
            .finish()
    }
}

/// Complaint-round reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgComplaintReason {
    /// VSS share failed against the dealer commitments.
    InvalidVssShare = 1,
    /// Pairwise seed setup failed.
    InvalidPairwiseSeed = 2,
    /// Dealer omitted a required private share.
    MissingShare = 3,
    /// Backend-specific complaint.
    Backend = 255,
}

impl DkgComplaintReason {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Complaint-round broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgComplaintPayload {
    /// Party raising the complaint.
    pub complainant: PartyId,
    /// Dealer whose message is challenged.
    pub dealer: PartyId,
    /// Receiver for the challenged share.
    pub receiver: PartyId,
    /// Complaint category.
    pub reason: DkgComplaintReason,
    /// Backend-specific evidence bytes.
    pub evidence: Vec<u8>,
}

/// Finalize-round broadcast for one party.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgFinalizePayload {
    /// Sender party id.
    pub sender: PartyId,
    /// Public output accepted by this sender.
    pub output: DkgPublicOutput,
}

/// Deterministic local DKG state-machine scaffold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgLocalStateMachine {
    config: DkgConfig,
    state: DkgState,
    transcript_hash: KeygenTranscriptHash,
    commits: Vec<DkgCommitPayload>,
    shares: Vec<DkgSharePayload>,
    complaints: Vec<DkgComplaintPayload>,
}

impl DkgLocalStateMachine {
    /// Creates a new local DKG runner in the commit phase.
    pub fn new(config: DkgConfig) -> Result<Self, DkgError> {
        config.validate()?;
        let transcript_hash = config.transcript_hash();
        Ok(Self {
            config,
            state: DkgState::Waiting(DkgRound::Commit),
            transcript_hash,
            commits: Vec::new(),
            shares: Vec::new(),
            complaints: Vec::new(),
        })
    }

    /// Returns the current DKG phase.
    pub const fn state(&self) -> DkgState {
        self.state
    }

    /// Returns the accumulated round transcript hash.
    pub const fn transcript_hash(&self) -> KeygenTranscriptHash {
        self.transcript_hash
    }

    /// Accepts and validates the complete commit-round broadcast set.
    pub fn accept_commit_round(&mut self, commits: Vec<DkgCommitPayload>) -> Result<(), DkgError> {
        self.expect_round(DkgRound::Commit)?;
        validate_exact_party_set(
            &self.config,
            DkgRound::Commit,
            commits.iter().map(|commit| commit.dealer),
        )?;
        for commit in &commits {
            if commit.vss_commitments.is_empty() {
                return Err(DkgError::EmptyDkgCommitments(commit.dealer));
            }
            if commit.pairwise_seed_commitment.party != commit.dealer {
                return Err(DkgError::PartyMismatch {
                    expected: commit.dealer,
                    got: commit.pairwise_seed_commitment.party,
                });
            }
        }

        self.transcript_hash = hash_commit_round(self.transcript_hash, &commits);
        self.commits = commits;
        self.state = DkgState::Waiting(DkgRound::Share);
        Ok(())
    }

    /// Accepts and validates the complete directed share-round message set.
    pub fn accept_share_round(&mut self, shares: Vec<DkgSharePayload>) -> Result<(), DkgError> {
        self.expect_round(DkgRound::Share)?;
        let n = self.config.parties.len();
        let expected = n.checked_mul(n.saturating_sub(1)).ok_or(DkgError::Backend(
            "dkg share-round expected-message count overflow",
        ))?;
        if shares.len() != expected {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Share,
                expected,
                got: shares.len(),
            });
        }

        let mut seen = Vec::with_capacity(shares.len());
        for share in &shares {
            self.require_party(share.dealer)?;
            self.require_party(share.receiver)?;
            if share.dealer == share.receiver {
                return Err(DkgError::InvalidShareReceiver {
                    dealer: share.dealer,
                    receiver: share.receiver,
                });
            }
            let pair = (share.dealer, share.receiver);
            if seen.contains(&pair) {
                return Err(DkgError::DuplicateShare {
                    dealer: share.dealer,
                    receiver: share.receiver,
                });
            }
            seen.push(pair);
        }

        self.transcript_hash = hash_share_round(self.transcript_hash, &shares);
        self.shares = shares;
        self.state = DkgState::Waiting(DkgRound::Complaint);
        Ok(())
    }

    /// Accepts and validates complaint-round broadcasts.
    pub fn accept_complaint_round(
        &mut self,
        complaints: Vec<DkgComplaintPayload>,
    ) -> Result<(), DkgError> {
        self.expect_round(DkgRound::Complaint)?;
        let mut seen = Vec::with_capacity(complaints.len());
        for complaint in &complaints {
            self.require_party(complaint.complainant)?;
            self.require_party(complaint.dealer)?;
            self.require_party(complaint.receiver)?;
            if complaint.dealer == complaint.receiver {
                return Err(DkgError::InvalidShareReceiver {
                    dealer: complaint.dealer,
                    receiver: complaint.receiver,
                });
            }
            let key = (complaint.complainant, complaint.dealer, complaint.receiver);
            if seen.contains(&key) {
                return Err(DkgError::DuplicateComplaint {
                    complainant: complaint.complainant,
                    dealer: complaint.dealer,
                    receiver: complaint.receiver,
                });
            }
            seen.push(key);
        }

        self.transcript_hash = hash_complaint_round(self.transcript_hash, &complaints);
        self.complaints = complaints;
        self.state = DkgState::Waiting(DkgRound::Finalize);
        Ok(())
    }

    /// Accepts finalize broadcasts and returns the unanimously accepted public output.
    pub fn accept_finalize_round(
        &mut self,
        finalizers: Vec<DkgFinalizePayload>,
    ) -> Result<DkgPublicOutput, DkgError> {
        self.expect_round(DkgRound::Finalize)?;
        validate_exact_party_set(
            &self.config,
            DkgRound::Finalize,
            finalizers.iter().map(|payload| payload.sender),
        )?;
        let Some(first) = finalizers.first() else {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Finalize,
                expected: self.config.parties.len(),
                got: 0,
            });
        };
        first.output.validate_binding()?;
        if first.output.config != self.config {
            return Err(DkgError::FinalOutputConfigMismatch);
        }

        for payload in finalizers.iter().skip(1) {
            payload.output.validate_binding()?;
            if payload.output != first.output {
                return Err(DkgError::FinalizeDisagreement);
            }
        }

        self.transcript_hash = hash_finalize_round(self.transcript_hash, &finalizers);
        self.state = DkgState::Complete;
        Ok(first.output.clone())
    }

    fn expect_round(&self, expected: DkgRound) -> Result<(), DkgError> {
        match self.state {
            DkgState::Waiting(got) if got == expected => Ok(()),
            got => Err(DkgError::UnexpectedRound { expected, got }),
        }
    }

    fn require_party(&self, party: PartyId) -> Result<(), DkgError> {
        if self.config.parties.contains(&party) {
            Ok(())
        } else {
            Err(DkgError::UnknownParty(party))
        }
    }
}

/// DKG transport phase used by per-party DKG drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgTransportPhase {
    /// Bounded `Z_m` residue contribution broadcast.
    SmallResidue,
    /// IT-VSS public-check/commit broadcast.
    VssCommit,
    /// IT-VSS directed private-share delivery.
    VssShare,
    /// IT-VSS complaint broadcast.
    VssComplaint,
    /// IT-VSS public artifact persistence.
    ItVssArtifact,
}

impl DkgTransportPhase {
    fn round_id(self) -> RoundId {
        match self {
            Self::SmallResidue => RoundId::DkgSmallResidue,
            Self::VssCommit => RoundId::DkgCommit,
            Self::VssShare => RoundId::DkgShare,
            Self::VssComplaint => RoundId::DkgComplaint,
            Self::ItVssArtifact => RoundId::DkgItVssArtifact,
        }
    }

    fn payload_kind(self) -> PayloadKind {
        match self {
            Self::SmallResidue => PayloadKind::DkgSmallResidue,
            Self::VssCommit => PayloadKind::DkgCommit,
            Self::VssShare => PayloadKind::DkgShare,
            Self::VssComplaint => PayloadKind::DkgComplaint,
            Self::ItVssArtifact => PayloadKind::DkgItVssArtifact,
        }
    }
}

/// Status returned by a single-party DKG transport phase driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DkgTransportPhaseDriverStatus {
    /// Local party sent a directed private message.
    SentPrivate {
        /// DKG phase.
        phase: DkgTransportPhase,
        /// Receiver.
        receiver: PartyId,
    },
    /// Local party sent a broadcast message.
    SentBroadcast {
        /// DKG phase.
        phase: DkgTransportPhase,
    },
    /// Local party is waiting for directed messages.
    WaitingPrivate {
        /// DKG phase.
        phase: DkgTransportPhase,
        /// Receiver.
        receiver: PartyId,
        /// Expected message count.
        expected: usize,
        /// Available message count.
        got: usize,
    },
    /// Local party is waiting for broadcast messages.
    WaitingBroadcast {
        /// DKG phase.
        phase: DkgTransportPhase,
        /// Expected message count.
        expected: usize,
        /// Available message count.
        got: usize,
    },
    /// Phase messages were collected and validated.
    Collected {
        /// DKG phase.
        phase: DkgTransportPhase,
        /// Directed receiver, if private.
        receiver: Option<PartyId>,
        /// Accepted sender set.
        senders: Vec<PartyId>,
    },
}

/// Durable local state for one DKG setup transport phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgSetupPhaseCursorState {
    /// The local party sent its phase message.
    Sent = 1,
    /// The local party is waiting for peers.
    Waiting = 2,
    /// The local party collected and accepted a phase.
    Collected = 3,
    /// The local setup instance aborted and cannot become accepted.
    Aborted = 4,
}

impl DkgSetupPhaseCursorState {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Sent),
            2 => Some(Self::Waiting),
            3 => Some(Self::Collected),
            4 => Some(Self::Aborted),
            _ => None,
        }
    }
}

/// Durable cursor for native DKG setup continuation after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgSetupPhaseCursor {
    /// DKG setup phase.
    pub phase: DkgTransportPhase,
    /// Cursor state.
    pub state: DkgSetupPhaseCursorState,
    /// Directed receiver for private-share phases.
    pub receiver: Option<PartyId>,
    /// Bounded-secret vector, for small-residue coefficient phases.
    pub vector: Option<SecretVectorKind>,
    /// Bounded-secret coefficient index, for small-residue phases.
    pub coefficient_index: Option<u32>,
    /// IT-VSS complaint-resolution subphase for production setup shape.
    pub it_vss_phase: Option<ProductionItVssComplaintPhase>,
    /// Expected messages for wait/collect phases.
    pub expected: usize,
    /// Available or collected messages.
    pub got: usize,
}

impl DkgSetupPhaseCursor {
    /// Builds a cursor from a phase-driver status.
    pub fn from_driver_status(status: &DkgTransportPhaseDriverStatus) -> Self {
        match status {
            DkgTransportPhaseDriverStatus::SentPrivate { phase, receiver } => Self {
                phase: *phase,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: Some(*receiver),
                vector: None,
                coefficient_index: None,
                it_vss_phase: None,
                expected: 1,
                got: 1,
            },
            DkgTransportPhaseDriverStatus::SentBroadcast { phase } => Self {
                phase: *phase,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: None,
                expected: 1,
                got: 1,
            },
            DkgTransportPhaseDriverStatus::WaitingPrivate {
                phase,
                receiver,
                expected,
                got,
            } => Self {
                phase: *phase,
                state: DkgSetupPhaseCursorState::Waiting,
                receiver: Some(*receiver),
                vector: None,
                coefficient_index: None,
                it_vss_phase: None,
                expected: *expected,
                got: *got,
            },
            DkgTransportPhaseDriverStatus::WaitingBroadcast {
                phase,
                expected,
                got,
            } => Self {
                phase: *phase,
                state: DkgSetupPhaseCursorState::Waiting,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: None,
                expected: *expected,
                got: *got,
            },
            DkgTransportPhaseDriverStatus::Collected {
                phase,
                receiver,
                senders,
            } => Self {
                phase: *phase,
                state: DkgSetupPhaseCursorState::Collected,
                receiver: *receiver,
                vector: None,
                coefficient_index: None,
                it_vss_phase: None,
                expected: senders.len(),
                got: senders.len(),
            },
        }
    }

    /// Adds bounded-sampler coefficient context to the cursor.
    pub fn with_sampler_label(mut self, label: SamplerLabel) -> Self {
        self.vector = Some(label.vector);
        self.coefficient_index = Some(label.coefficient_index);
        self
    }

    /// Adds bounded-sampler vector context to the cursor.
    pub fn with_sampler_vector(mut self, vector: SecretVectorKind) -> Self {
        self.vector = Some(vector);
        self.coefficient_index = None;
        self
    }

    /// Adds IT-VSS complaint-resolution subphase context to the cursor.
    pub fn with_it_vss_phase(mut self, phase: ProductionItVssComplaintPhase) -> Self {
        self.it_vss_phase = Some(phase);
        self
    }
}

/// Durable DKG setup phase-cursor log.
pub trait DkgSetupPhaseCursorLog {
    /// Persists one phase cursor.
    fn persist_setup_phase_cursor(&mut self, cursor: &DkgSetupPhaseCursor) -> Result<(), DkgError>;

    /// Returns all persisted cursors.
    fn setup_phase_cursors(&self) -> &[DkgSetupPhaseCursor];

    /// Returns the latest cursor, if any.
    fn latest_setup_phase_cursor(&self) -> Option<&DkgSetupPhaseCursor> {
        self.setup_phase_cursors().last()
    }
}

/// In-memory DKG setup phase-cursor log for tests and adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryDkgSetupPhaseCursorLog {
    cursors: Vec<DkgSetupPhaseCursor>,
}

impl InMemoryDkgSetupPhaseCursorLog {
    /// Returns persisted cursors.
    pub fn cursors(&self) -> &[DkgSetupPhaseCursor] {
        &self.cursors
    }
}

impl DkgSetupPhaseCursorLog for InMemoryDkgSetupPhaseCursorLog {
    fn persist_setup_phase_cursor(&mut self, cursor: &DkgSetupPhaseCursor) -> Result<(), DkgError> {
        if self.cursors.last() == Some(cursor) {
            return Ok(());
        }
        self.cursors.push(cursor.clone());
        Ok(())
    }

    fn setup_phase_cursors(&self) -> &[DkgSetupPhaseCursor] {
        &self.cursors
    }
}

#[cfg(feature = "std")]
/// File-backed DKG setup phase-cursor log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDkgSetupPhaseCursorLog {
    path: std::path::PathBuf,
    inner: InMemoryDkgSetupPhaseCursorLog,
}

#[cfg(feature = "std")]
impl FileDkgSetupPhaseCursorLog {
    /// Opens or creates a DKG setup phase-cursor log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        use std::io::BufRead;

        let path = path.into();
        let mut inner = InMemoryDkgSetupPhaseCursorLog::default();
        match std::fs::File::open(&path) {
            Ok(file) => {
                for (index, line) in std::io::BufReader::new(file).lines().enumerate() {
                    let line = line.map_err(|_| DkgError::TranscriptStoreIo {
                        operation: "read dkg setup phase cursor log",
                    })?;
                    let cursor = parse_dkg_setup_phase_cursor_log_line(&line)
                        .ok_or(DkgError::DkgSetupPhaseCursorLogCorrupt { line: index + 1 })?;
                    inner.persist_setup_phase_cursor(&cursor)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(DkgError::TranscriptStoreIo {
                    operation: "open dkg setup phase cursor log",
                })
            }
        }
        Ok(Self { path, inner })
    }

    /// Returns persisted cursors.
    pub fn cursors(&self) -> &[DkgSetupPhaseCursor] {
        self.inner.cursors()
    }
}

#[cfg(feature = "std")]
impl DkgSetupPhaseCursorLog for FileDkgSetupPhaseCursorLog {
    fn persist_setup_phase_cursor(&mut self, cursor: &DkgSetupPhaseCursor) -> Result<(), DkgError> {
        let before = self.inner.setup_phase_cursors().len();
        self.inner.persist_setup_phase_cursor(cursor)?;
        if self.inner.setup_phase_cursors().len() == before {
            return Ok(());
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo {
                operation: "append dkg setup phase cursor log",
            })?;
        writeln!(
            file,
            "{},{},{},{},{},{},{},{}",
            dkg_transport_phase_to_u8(cursor.phase),
            cursor.state.as_u8(),
            cursor.receiver.map_or(0, |party| party.0),
            cursor.vector.map_or(0, SecretVectorKind::as_u8),
            cursor.coefficient_index.unwrap_or(u32::MAX),
            cursor.it_vss_phase.map_or(0, |phase| phase.as_u8()),
            cursor.expected,
            cursor.got
        )
        .map_err(|_| DkgError::TranscriptStoreIo {
            operation: "write dkg setup phase cursor log",
        })
    }

    fn setup_phase_cursors(&self) -> &[DkgSetupPhaseCursor] {
        self.inner.setup_phase_cursors()
    }
}

fn dkg_transport_phase_to_u8(phase: DkgTransportPhase) -> u8 {
    match phase {
        DkgTransportPhase::SmallResidue => 1,
        DkgTransportPhase::VssCommit => 2,
        DkgTransportPhase::VssShare => 3,
        DkgTransportPhase::VssComplaint => 4,
        DkgTransportPhase::ItVssArtifact => 5,
    }
}

fn dkg_transport_phase_from_u8(value: u8) -> Option<DkgTransportPhase> {
    match value {
        1 => Some(DkgTransportPhase::SmallResidue),
        2 => Some(DkgTransportPhase::VssCommit),
        3 => Some(DkgTransportPhase::VssShare),
        4 => Some(DkgTransportPhase::VssComplaint),
        5 => Some(DkgTransportPhase::ItVssArtifact),
        _ => None,
    }
}

fn secret_vector_kind_from_u8(value: u8) -> Option<SecretVectorKind> {
    match value {
        1 => Some(SecretVectorKind::S1),
        2 => Some(SecretVectorKind::S2),
        _ => None,
    }
}

fn parse_dkg_setup_phase_cursor_log_line(line: &str) -> Option<DkgSetupPhaseCursor> {
    let mut fields = line.split(',');
    let phase = dkg_transport_phase_from_u8(fields.next()?.parse().ok()?)?;
    let state = DkgSetupPhaseCursorState::from_u8(fields.next()?.parse().ok()?)?;
    let receiver_raw: u16 = fields.next()?.parse().ok()?;
    let vector_raw: u8 = fields.next()?.parse().ok()?;
    let coefficient_raw: u32 = fields.next()?.parse().ok()?;
    let maybe_it_vss_or_expected = fields.next()?;
    let rest = fields.collect::<Vec<_>>();
    let (it_vss_phase, expected, got) = match rest.as_slice() {
        [expected, got] => {
            let phase_raw: u8 = maybe_it_vss_or_expected.parse().ok()?;
            let phase = if phase_raw == 0 {
                None
            } else {
                ProductionItVssComplaintPhase::from_u8(phase_raw)
            };
            (phase, expected.parse().ok()?, got.parse().ok()?)
        }
        [got] => (
            None,
            maybe_it_vss_or_expected.parse().ok()?,
            got.parse().ok()?,
        ),
        _ => return None,
    };
    if it_vss_phase.is_none()
        && maybe_it_vss_or_expected.parse::<usize>().ok().is_none()
        && rest.len() == 2
    {
        return None;
    }
    Some(DkgSetupPhaseCursor {
        phase,
        state,
        receiver: (receiver_raw != 0).then_some(PartyId(receiver_raw)),
        vector: (vector_raw != 0)
            .then(|| secret_vector_kind_from_u8(vector_raw))
            .flatten(),
        coefficient_index: (coefficient_raw != u32::MAX).then_some(coefficient_raw),
        it_vss_phase,
        expected,
        got,
    })
}

/// Local-party state machine for native DKG transport phases.
#[derive(Clone, Debug)]
pub struct DkgTransportStateMachine<T> {
    config: DkgConfig,
    local_party: PartyId,
    transport: T,
    expected_context: ExpectedContext,
}

impl<T> DkgTransportStateMachine<T>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
{
    /// Creates a DKG transport state machine using the deterministic test
    /// session id derived from the DKG config.
    pub fn new(config: DkgConfig, local_party: PartyId, transport: T) -> Result<Self, DkgError> {
        let expected_context = default_prime_field_mpc_expected_context(&config);
        Self::new_with_expected_context(config, local_party, transport, expected_context)
    }

    /// Creates a DKG transport state machine using an application-supplied
    /// PQ-bound expected context.
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

    /// Broadcasts one bounded small-residue contribution.
    pub fn broadcast_small_residue(
        &mut self,
        contribution: &SmallResidueContribution,
    ) -> Result<(), DkgError> {
        if contribution.dealer != self.local_party {
            return Err(DkgError::PartyMismatch {
                expected: self.local_party,
                got: contribution.dealer,
            });
        }
        let message = self.wire_message(
            DkgTransportPhase::SmallResidue,
            wire_encode_dkg_small_residue_payload(&WireDkgSmallResiduePayload {
                vector_kind: contribution.label.vector.as_u8(),
                coefficient_index: contribution.label.coefficient_index,
                eta: contribution.eta.bound() as u8,
                residue: contribution.residue,
                bits: contribution.bits.clone(),
            }),
        );
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)
    }

    /// Collects one equivocation-checked small-residue contribution round.
    pub fn collect_small_residue_round(
        &self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<Vec<SmallResidueContribution>, DkgError> {
        let messages = self.collect_broadcast_messages(DkgTransportPhase::SmallResidue)?;
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            let payload = wire_decode_dkg_small_residue_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            let vector = match payload.vector_kind {
                1 => SecretVectorKind::S1,
                2 => SecretVectorKind::S2,
                _ => return Err(DkgError::SmallSamplerLabelMismatch),
            };
            let got_label = SamplerLabel {
                config_hash: self.config.transcript_hash(),
                vector,
                coefficient_index: payload.coefficient_index,
            };
            let got_eta = match payload.eta {
                2 => SmallSecretEta::Two,
                4 => SmallSecretEta::Four,
                _ => {
                    return Err(DkgError::InvalidSmallResidue {
                        dealer: PartyId(message.header.sender_party_id),
                        modulus: eta.modulus(),
                        got: payload.residue,
                    })
                }
            };
            let contribution = SmallResidueContribution {
                dealer: PartyId(message.header.sender_party_id),
                label: got_label,
                eta: got_eta,
                residue: payload.residue,
                bits: payload.bits,
            };
            validate_small_residue_contribution(label, eta, &contribution)?;
            out.push(contribution);
        }
        Ok(out)
    }

    /// Broadcasts one VSS public check/commit.
    pub fn broadcast_vss_commit(&mut self, commit: &DkgCommitPayload) -> Result<(), DkgError> {
        if commit.dealer != self.local_party {
            return Err(DkgError::PartyMismatch {
                expected: self.local_party,
                got: commit.dealer,
            });
        }
        let message = self.wire_message(
            DkgTransportPhase::VssCommit,
            wire_encode_dkg_commit_payload(&wire_dkg_commit_payload_from_dkg_commit(commit)),
        );
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)
    }

    /// Collects one equivocation-checked VSS commit round.
    pub fn collect_vss_commit_round(&self) -> Result<Vec<DkgCommitPayload>, DkgError> {
        let messages = self.collect_broadcast_messages(DkgTransportPhase::VssCommit)?;
        messages
            .into_iter()
            .map(|message| {
                let dealer = PartyId(message.header.sender_party_id);
                let payload = wire_decode_dkg_commit_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                Ok(DkgCommitPayload {
                    dealer,
                    vss_commitments: payload
                        .vss_commitments
                        .into_iter()
                        .map(|bytes| VssCommitment { bytes })
                        .collect(),
                    pairwise_seed_commitment: PairwiseSeedCommitment {
                        party: dealer,
                        commitment: payload.pairwise_seed_commitment,
                    },
                })
            })
            .collect()
    }

    /// Sends one VSS directed private share.
    pub fn send_vss_share(
        &mut self,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) -> Result<(), DkgError> {
        if share.dealer != self.local_party || share.receiver != receiver {
            return Err(DkgError::PartyMismatch {
                expected: receiver,
                got: share.receiver,
            });
        }
        self.require_party(receiver)?;
        let message = self.wire_message(
            DkgTransportPhase::VssShare,
            wire_encode_dkg_share_payload(&WireDkgSharePayload {
                receiver_party_id: receiver.0,
                encrypted_share: share.encrypted_share.clone(),
                encrypted_seed_share: share.encrypted_seed_share.clone(),
                proof: share.proof.clone(),
            }),
        );
        self.transport
            .send_private(receiver.0, message)
            .map_err(map_transport_error)
    }

    /// Collects VSS directed private shares for one receiver.
    pub fn collect_vss_share_round(
        &self,
        receiver: PartyId,
    ) -> Result<Vec<DkgSharePayload>, DkgError> {
        self.require_party(receiver)?;
        let messages = self.collect_private_messages(receiver, DkgTransportPhase::VssShare)?;
        messages
            .into_iter()
            .map(|message| {
                let payload = wire_decode_dkg_share_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                if payload.receiver_party_id != receiver.0 {
                    return Err(DkgError::PrimeFieldMpcTransport);
                }
                Ok(DkgSharePayload {
                    dealer: PartyId(message.header.sender_party_id),
                    receiver,
                    encrypted_share: payload.encrypted_share,
                    encrypted_seed_share: payload.encrypted_seed_share,
                    proof: payload.proof,
                })
            })
            .collect()
    }

    /// Broadcasts one VSS complaint.
    pub fn broadcast_vss_complaint(
        &mut self,
        complaint: &DkgComplaintPayload,
    ) -> Result<(), DkgError> {
        if complaint.complainant != self.local_party {
            return Err(DkgError::PartyMismatch {
                expected: self.local_party,
                got: complaint.complainant,
            });
        }
        let message = self.wire_message(
            DkgTransportPhase::VssComplaint,
            wire_encode_dkg_complaint_payload(&WireDkgComplaintPayload {
                dealer_party_id: complaint.dealer.0,
                receiver_party_id: complaint.receiver.0,
                reason_code: complaint.reason.as_u8() as u16,
                evidence: complaint.evidence.clone(),
            }),
        );
        self.transport
            .broadcast(message)
            .map_err(map_transport_error)
    }

    /// Collects one equivocation-checked VSS complaint round.
    pub fn collect_vss_complaint_round(&self) -> Result<Vec<DkgComplaintPayload>, DkgError> {
        let messages = self.collect_broadcast_messages(DkgTransportPhase::VssComplaint)?;
        messages
            .into_iter()
            .map(|message| {
                let payload = wire_decode_dkg_complaint_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                let reason = match payload.reason_code {
                    1 => DkgComplaintReason::InvalidVssShare,
                    2 => DkgComplaintReason::InvalidPairwiseSeed,
                    3 => DkgComplaintReason::MissingShare,
                    255 => DkgComplaintReason::Backend,
                    _ => return Err(DkgError::PrimeFieldMpcTransport),
                };
                Ok(DkgComplaintPayload {
                    complainant: PartyId(message.header.sender_party_id),
                    dealer: PartyId(payload.dealer_party_id),
                    receiver: PartyId(payload.receiver_party_id),
                    reason,
                    evidence: payload.evidence,
                })
            })
            .collect()
    }

    fn collect_broadcast_messages(
        &self,
        phase: DkgTransportPhase,
    ) -> Result<Vec<WireMessage>, DkgError> {
        self.transport
            .collect_equivocation_checked_round(phase.round_id(), &self.expected_context)
            .map_err(map_transport_error)
    }

    fn collect_private_messages(
        &self,
        receiver: PartyId,
        phase: DkgTransportPhase,
    ) -> Result<Vec<WireMessage>, DkgError> {
        self.transport
            .collect_private_round(receiver.0, phase.round_id(), &self.expected_context)
            .map_err(map_transport_error)
    }

    fn wire_message(&self, phase: DkgTransportPhase, payload: Vec<u8>) -> WireMessage {
        WireMessage {
            header: WireHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                suite: wire_suite(self.config.suite),
                round: phase.round_id(),
                sender_party_id: self.local_party.0,
                keygen_transcript_hash: self.expected_context.keygen_transcript_hash,
                session_id: self.expected_context.session_id,
                signing_set_hash: self.expected_context.signing_set_hash,
                payload_kind: phase.payload_kind(),
            },
            payload,
        }
    }

    fn require_party(&self, party: PartyId) -> Result<(), DkgError> {
        if self.config.parties.contains(&party) {
            Ok(())
        } else {
            Err(DkgError::UnknownParty(party))
        }
    }
}

/// One durable DKG setup wire message.
///
/// These records may contain encrypted/private VSS shares or bounded-sampler
/// residue inputs, so production storage must treat them as local DKG state,
/// not as public debug logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgWireMessageRecord {
    /// Direction relative to the local party.
    pub direction: PrimeFieldMpcWireDirection,
    /// Peer for directed private messages. Broadcast records use `None`.
    pub peer: Option<PartyId>,
    /// Canonical wire message.
    pub message: WireMessage,
}

/// Durable DKG setup wire-message log.
pub trait DkgWireMessageLog {
    /// Persists one message idempotently, rejecting changed bytes under the
    /// same logical replay key.
    fn persist_dkg_wire_message(&mut self, record: &DkgWireMessageRecord) -> Result<(), DkgError>;

    /// Returns all records known to this local party.
    fn dkg_wire_records(&self) -> &[DkgWireMessageRecord];
}

/// In-memory DKG wire log for tests and application adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryDkgWireMessageLog {
    records: Vec<DkgWireMessageRecord>,
}

impl InMemoryDkgWireMessageLog {
    /// Returns durable wire-message records.
    pub fn records(&self) -> &[DkgWireMessageRecord] {
        &self.records
    }
}

impl DkgWireMessageLog for InMemoryDkgWireMessageLog {
    fn persist_dkg_wire_message(&mut self, record: &DkgWireMessageRecord) -> Result<(), DkgError> {
        persist_dkg_wire_message_record(&mut self.records, record)
    }

    fn dkg_wire_records(&self) -> &[DkgWireMessageRecord] {
        &self.records
    }
}

fn persist_dkg_wire_message_record(
    records: &mut Vec<DkgWireMessageRecord>,
    record: &DkgWireMessageRecord,
) -> Result<(), DkgError> {
    let key = dkg_wire_message_replay_key(record)?;
    let encoded = encode_message(&record.message).map_err(|_| DkgError::PrimeFieldMpcTransport)?;
    if let Some(existing) = records
        .iter()
        .find(|known| dkg_wire_message_replay_key(known).as_ref() == Ok(&key))
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct DkgWireReplayKey {
    direction: PrimeFieldMpcWireDirection,
    peer: Option<PartyId>,
    sender: PartyId,
    round: RoundId,
    payload_kind: PayloadKind,
    logical: DkgWireLogicalKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DkgWireLogicalKey {
    SmallResidue {
        vector_kind: u8,
        coefficient_index: u32,
    },
    Commit,
    Share {
        receiver: PartyId,
        label_hash: Option<[u8; 32]>,
    },
    Complaint {
        dealer: PartyId,
        receiver: PartyId,
        reason_code: u16,
    },
    ItVssArtifact {
        kind: u8,
        dealer: Option<PartyId>,
        label_hash: Option<[u8; 32]>,
    },
}

fn dkg_wire_message_replay_key(
    record: &DkgWireMessageRecord,
) -> Result<DkgWireReplayKey, DkgError> {
    let sender = PartyId(record.message.header.sender_party_id);
    let logical = match record.message.header.payload_kind {
        PayloadKind::DkgSmallResidue => {
            let payload = wire_decode_dkg_small_residue_payload(&record.message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            DkgWireLogicalKey::SmallResidue {
                vector_kind: payload.vector_kind,
                coefficient_index: payload.coefficient_index,
            }
        }
        PayloadKind::DkgCommit => DkgWireLogicalKey::Commit,
        PayloadKind::DkgShare => {
            let payload = wire_decode_dkg_share_payload(&record.message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            let label_hash = decode_it_vss_private_share_delivery(&payload.encrypted_share)
                .ok()
                .map(|delivery| delivery.label_hash)
                .or_else(|| {
                    decode_it_vss_private_share_delivery_batch(&payload.encrypted_share)
                        .ok()
                        .and_then(|deliveries| {
                            deliveries
                                .first()
                                .map(|_| hash_it_vss_private_delivery_batch(&deliveries))
                        })
                });
            DkgWireLogicalKey::Share {
                receiver: PartyId(payload.receiver_party_id),
                label_hash,
            }
        }
        PayloadKind::DkgComplaint => {
            let payload = wire_decode_dkg_complaint_payload(&record.message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            DkgWireLogicalKey::Complaint {
                dealer: PartyId(payload.dealer_party_id),
                receiver: PartyId(payload.receiver_party_id),
                reason_code: payload.reason_code,
            }
        }
        PayloadKind::DkgItVssArtifact => {
            let payload = wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            match payload {
                DkgItVssArtifactPayload::PublicCommitment(commitment) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 1,
                        dealer: Some(PartyId(commitment.dealer_party_id)),
                        label_hash: Some(commitment.label_hash),
                    }
                }
                DkgItVssArtifactPayload::PublicPrecommitment(precommitment) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 5,
                        dealer: Some(PartyId(precommitment.dealer_party_id)),
                        label_hash: Some(precommitment.label_hash),
                    }
                }
                DkgItVssArtifactPayload::PublicCommitmentBatch(_) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 3,
                        dealer: Some(sender),
                        label_hash: None,
                    }
                }
                DkgItVssArtifactPayload::PublicCoinShare(share) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 4,
                        dealer: Some(PartyId(share.party_id)),
                        label_hash: Some(share.label_hash),
                    }
                }
                DkgItVssArtifactPayload::PublicAuditRecords(_) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 6,
                        dealer: Some(sender),
                        label_hash: None,
                    }
                }
                DkgItVssArtifactPayload::PublicConsistencyRecords(_) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 7,
                        dealer: Some(sender),
                        label_hash: None,
                    }
                }
                DkgItVssArtifactPayload::ComplaintResolution(_) => {
                    DkgWireLogicalKey::ItVssArtifact {
                        kind: 2,
                        dealer: None,
                        label_hash: None,
                    }
                }
            }
        }
        _ => return Err(DkgError::PrimeFieldMpcTransport),
    };
    Ok(DkgWireReplayKey {
        direction: record.direction,
        peer: record.peer,
        sender,
        round: record.message.header.round,
        payload_kind: record.message.header.payload_kind,
        logical,
    })
}

fn find_sent_dkg_wire_message(
    records: &[DkgWireMessageRecord],
    wanted: DkgWireReplayKey,
) -> Result<Option<WireMessage>, DkgError> {
    for record in records {
        if dkg_wire_message_replay_key(record)? == wanted {
            return Ok(Some(record.message.clone()));
        }
    }
    Ok(None)
}

/// Single-party runtime for DKG bounded-sampler and IT-VSS transport phases.
#[derive(Clone, Debug)]
pub struct DkgTransportPartyRuntime<T> {
    state: DkgTransportStateMachine<T>,
}

impl<T> DkgTransportPartyRuntime<T>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
{
    /// Creates a runtime.
    pub fn new(state: DkgTransportStateMachine<T>) -> Self {
        Self { state }
    }

    /// Returns the local party.
    pub fn local_party(&self) -> PartyId {
        self.state.local_party()
    }

    /// Returns the state machine.
    pub fn state(&self) -> &DkgTransportStateMachine<T> {
        &self.state
    }

    /// Returns the mutable state machine.
    pub fn state_mut(&mut self) -> &mut DkgTransportStateMachine<T> {
        &mut self.state
    }

    /// Broadcasts a bounded-sampler residue contribution.
    pub fn drive_broadcast_small_residue(
        &mut self,
        contribution: &SmallResidueContribution,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.state.broadcast_small_residue(contribution)?;
        Ok(DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::SmallResidue,
        })
    }

    /// Collects a bounded-sampler residue round, or reports waiting.
    pub fn drive_collect_small_residue_round(
        &mut self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<SmallResidueContribution>), DkgError> {
        match self.state.collect_small_residue_round(label, eta) {
            Ok(values) => Ok((
                DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::SmallResidue,
                    receiver: None,
                    senders: values.iter().map(|value| value.dealer).collect(),
                },
                values,
            )),
            Err(DkgError::PrimeFieldMpcTransport) => Ok((
                DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::SmallResidue,
                    expected: self.state.config.parties.len(),
                    got: 0,
                },
                Vec::new(),
            )),
            Err(err) => Err(err),
        }
    }

    /// Broadcasts a VSS public check/commit.
    pub fn drive_broadcast_vss_commit(
        &mut self,
        commit: &DkgCommitPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.state.broadcast_vss_commit(commit)?;
        Ok(DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::VssCommit,
        })
    }

    /// Collects a VSS commit round, or reports waiting.
    pub fn drive_collect_vss_commit_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgCommitPayload>), DkgError> {
        match self.state.collect_vss_commit_round() {
            Ok(values) => Ok((
                DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssCommit,
                    receiver: None,
                    senders: values.iter().map(|value| value.dealer).collect(),
                },
                values,
            )),
            Err(DkgError::PrimeFieldMpcTransport) => Ok((
                DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::VssCommit,
                    expected: self.state.config.parties.len(),
                    got: 0,
                },
                Vec::new(),
            )),
            Err(err) => Err(err),
        }
    }

    /// Sends a VSS directed private share.
    pub fn drive_send_vss_share(
        &mut self,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.state.send_vss_share(receiver, share)?;
        Ok(DkgTransportPhaseDriverStatus::SentPrivate {
            phase: DkgTransportPhase::VssShare,
            receiver,
        })
    }

    /// Collects VSS directed shares for one receiver, or reports waiting.
    pub fn drive_collect_vss_share_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgSharePayload>), DkgError> {
        let expected = self.state.config.parties.len().saturating_sub(1);
        match self.state.collect_vss_share_round(receiver) {
            Ok(values) if values.len() == expected => Ok((
                DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssShare,
                    receiver: Some(receiver),
                    senders: values.iter().map(|value| value.dealer).collect(),
                },
                values,
            )),
            Ok(values) => Ok((
                DkgTransportPhaseDriverStatus::WaitingPrivate {
                    phase: DkgTransportPhase::VssShare,
                    receiver,
                    expected,
                    got: values.len(),
                },
                Vec::new(),
            )),
            Err(DkgError::PrimeFieldMpcTransport) => Ok((
                DkgTransportPhaseDriverStatus::WaitingPrivate {
                    phase: DkgTransportPhase::VssShare,
                    receiver,
                    expected,
                    got: 0,
                },
                Vec::new(),
            )),
            Err(err) => Err(err),
        }
    }

    /// Broadcasts a VSS complaint.
    pub fn drive_broadcast_vss_complaint(
        &mut self,
        complaint: &DkgComplaintPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.state.broadcast_vss_complaint(complaint)?;
        Ok(DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::VssComplaint,
        })
    }

    /// Collects VSS complaints, or reports waiting.
    pub fn drive_collect_vss_complaint_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgComplaintPayload>), DkgError> {
        match self.state.collect_vss_complaint_round() {
            Ok(values) => Ok((
                DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssComplaint,
                    receiver: None,
                    senders: values.iter().map(|value| value.complainant).collect(),
                },
                values,
            )),
            Err(DkgError::PrimeFieldMpcTransport) => Ok((
                DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::VssComplaint,
                    expected: self.state.config.parties.len(),
                    got: 0,
                },
                Vec::new(),
            )),
            Err(err) => Err(err),
        }
    }
}

/// Single-party DKG runtime with durable sent/accepted wire-message logging.
#[derive(Clone, Debug)]
pub struct LoggedDkgTransportPartyRuntime<T, L> {
    state: DkgTransportStateMachine<T>,
    wire_log: L,
}

impl<T, L> LoggedDkgTransportPartyRuntime<T, L>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    /// Creates a logged DKG transport runtime.
    pub fn new(state: DkgTransportStateMachine<T>, wire_log: L) -> Self {
        Self { state, wire_log }
    }

    /// Returns the local party.
    pub fn local_party(&self) -> PartyId {
        self.state.local_party()
    }

    /// Returns the state machine.
    pub fn state(&self) -> &DkgTransportStateMachine<T> {
        &self.state
    }

    /// Returns the mutable state machine.
    pub fn state_mut(&mut self) -> &mut DkgTransportStateMachine<T> {
        &mut self.state
    }

    /// Returns the wire log.
    pub fn wire_log(&self) -> &L {
        &self.wire_log
    }

    /// Replays sent DKG setup messages after restart.
    pub fn resume_sent_messages(&mut self) -> Result<(), DkgError> {
        for record in self.wire_log.dkg_wire_records() {
            if record.message.header.sender_party_id != self.local_party().0 {
                continue;
            }
            match record.direction {
                PrimeFieldMpcWireDirection::SentPrivate => {
                    let receiver = record.peer.ok_or(DkgError::PrimeFieldMpcTransport)?;
                    self.state
                        .transport_mut()
                        .send_private(receiver.0, record.message.clone())
                        .map_err(map_transport_error)?;
                }
                PrimeFieldMpcWireDirection::SentBroadcast => {
                    self.state
                        .transport_mut()
                        .broadcast(record.message.clone())
                        .map_err(map_transport_error)?;
                }
                PrimeFieldMpcWireDirection::AcceptedPrivate
                | PrimeFieldMpcWireDirection::AcceptedBroadcast => {}
            }
        }
        Ok(())
    }

    /// Broadcasts a small-residue contribution with durable sent logging.
    pub fn broadcast_small_residue_logged(
        &mut self,
        contribution: &SmallResidueContribution,
    ) -> Result<(), DkgError> {
        let payload = wire_encode_dkg_small_residue_payload(&WireDkgSmallResiduePayload {
            vector_kind: contribution.label.vector.as_u8(),
            coefficient_index: contribution.label.coefficient_index,
            eta: contribution.eta.bound() as u8,
            residue: contribution.residue,
            bits: contribution.bits.clone(),
        });
        self.broadcast_logged(DkgTransportPhase::SmallResidue, payload)
    }

    /// Broadcasts a VSS commit with durable sent logging.
    pub fn broadcast_vss_commit_logged(
        &mut self,
        commit: &DkgCommitPayload,
    ) -> Result<(), DkgError> {
        let payload =
            wire_encode_dkg_commit_payload(&wire_dkg_commit_payload_from_dkg_commit(commit));
        self.broadcast_logged(DkgTransportPhase::VssCommit, payload)
    }

    /// Broadcasts one IT-VSS public commitment with durable sent logging.
    pub fn broadcast_it_vss_public_commitment_logged(
        &mut self,
        commitment: &ItVssPublicCommitment,
    ) -> Result<(), DkgError> {
        self.broadcast_logged(
            DkgTransportPhase::ItVssArtifact,
            encode_it_vss_public_commitment_artifact(commitment),
        )
    }

    /// Broadcasts one IT-VSS public precommitment with durable sent logging.
    pub fn broadcast_it_vss_public_precommitment_logged(
        &mut self,
        precommitment: &ItVssPublicPrecommitment,
    ) -> Result<(), DkgError> {
        self.broadcast_logged(
            DkgTransportPhase::ItVssArtifact,
            encode_it_vss_public_precommitment_artifact(precommitment),
        )
    }

    /// Broadcasts a batch of IT-VSS public commitments with durable sent
    /// logging. This keeps one reliable-broadcast message per sender/round.
    pub fn broadcast_it_vss_public_commitment_batch_logged(
        &mut self,
        commitments: &[ItVssPublicCommitment],
    ) -> Result<(), DkgError> {
        self.broadcast_logged(
            DkgTransportPhase::ItVssArtifact,
            encode_it_vss_public_commitment_batch_artifact(commitments),
        )
    }

    /// Broadcasts one IT-VSS public-coin share with durable sent logging.
    pub fn broadcast_it_vss_public_coin_share_logged(
        &mut self,
        share: &ProductionItVssPublicCoinShare,
    ) -> Result<(), DkgError> {
        self.broadcast_logged(
            DkgTransportPhase::ItVssArtifact,
            encode_it_vss_public_coin_share_artifact(share),
        )
    }

    /// Broadcasts replayable public IT-VSS audit/discard records.
    pub fn broadcast_it_vss_public_audit_records_logged(
        &mut self,
        records: &[ProductionItVssAuditRecord],
    ) -> Result<(), DkgError> {
        self.broadcast_logged(
            DkgTransportPhase::ItVssArtifact,
            encode_it_vss_public_audit_records_artifact(records),
        )
    }

    /// Broadcasts replayable public IT-VSS vector consistency records.
    pub fn broadcast_it_vss_public_consistency_records_logged(
        &mut self,
        records: &[ProductionItVssConsistencyRecord],
    ) -> Result<(), DkgError> {
        self.broadcast_logged(
            DkgTransportPhase::ItVssArtifact,
            encode_it_vss_public_consistency_records_artifact(records),
        )
    }

    /// Sends a VSS private share with durable sent logging.
    pub fn send_vss_share_logged(
        &mut self,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) -> Result<(), DkgError> {
        let payload = wire_encode_dkg_share_payload(&WireDkgSharePayload {
            receiver_party_id: receiver.0,
            encrypted_share: share.encrypted_share.clone(),
            encrypted_seed_share: share.encrypted_seed_share.clone(),
            proof: share.proof.clone(),
        });
        self.send_private_logged(receiver, DkgTransportPhase::VssShare, payload)
    }

    /// Sends one IT-VSS directed private delivery with durable sent logging.
    pub fn send_it_vss_private_delivery_logged(
        &mut self,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<(), DkgError> {
        let share = dkg_share_payload_from_it_vss_private_delivery(delivery);
        self.send_vss_share_logged(delivery.receiver, &share)
    }

    /// Sends a batch of IT-VSS private deliveries for one receiver with durable
    /// sent logging. This keeps one private message per sender/receiver/round.
    pub fn send_it_vss_private_delivery_batch_logged(
        &mut self,
        receiver: PartyId,
        deliveries: &[ItVssPrivateShareDelivery],
    ) -> Result<(), DkgError> {
        let share = dkg_share_payload_from_it_vss_private_delivery_batch(deliveries)?;
        if share.receiver != receiver {
            return Err(DkgError::PartyMismatch {
                expected: receiver,
                got: share.receiver,
            });
        }
        self.send_vss_share_logged(receiver, &share)
    }

    /// Broadcasts a VSS complaint with durable sent logging.
    pub fn broadcast_vss_complaint_logged(
        &mut self,
        complaint: &DkgComplaintPayload,
    ) -> Result<(), DkgError> {
        let payload = wire_encode_dkg_complaint_payload(&WireDkgComplaintPayload {
            dealer_party_id: complaint.dealer.0,
            receiver_party_id: complaint.receiver.0,
            reason_code: complaint.reason.as_u8() as u16,
            evidence: complaint.evidence.clone(),
        });
        self.broadcast_logged(DkgTransportPhase::VssComplaint, payload)
    }

    /// Collects and logs accepted small-residue broadcast messages.
    pub fn collect_small_residue_round_logged(
        &mut self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<Vec<SmallResidueContribution>, DkgError> {
        let messages = self.accept_broadcast_logged(DkgTransportPhase::SmallResidue)?;
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            let payload = wire_decode_dkg_small_residue_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            let vector = match payload.vector_kind {
                1 => SecretVectorKind::S1,
                2 => SecretVectorKind::S2,
                _ => return Err(DkgError::SmallSamplerLabelMismatch),
            };
            if vector != label.vector || payload.coefficient_index != label.coefficient_index {
                continue;
            }
            let contribution = SmallResidueContribution {
                dealer: PartyId(message.header.sender_party_id),
                label: SamplerLabel {
                    config_hash: self.state.config.transcript_hash(),
                    vector,
                    coefficient_index: payload.coefficient_index,
                },
                eta: match payload.eta {
                    2 => SmallSecretEta::Two,
                    4 => SmallSecretEta::Four,
                    _ => {
                        return Err(DkgError::InvalidSmallResidue {
                            dealer: PartyId(message.header.sender_party_id),
                            modulus: eta.modulus(),
                            got: payload.residue,
                        })
                    }
                },
                residue: payload.residue,
                bits: payload.bits,
            };
            validate_small_residue_contribution(label, eta, &contribution)?;
            out.push(contribution);
        }
        Ok(out)
    }

    /// Recovers accepted small-residue broadcasts from the durable log without
    /// using transport.
    pub fn recover_small_residue_round_from_log(
        &self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<Vec<SmallResidueContribution>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::SmallResidue,
        )?;
        self.small_residue_contributions_from_messages(messages, label, eta)
    }

    /// Collects and logs accepted VSS public-check broadcasts.
    pub fn collect_vss_commit_round_logged(&mut self) -> Result<Vec<DkgCommitPayload>, DkgError> {
        let messages = self.accept_broadcast_logged(DkgTransportPhase::VssCommit)?;
        self.vss_commits_from_messages(messages)
    }

    /// Recovers accepted VSS public-check broadcasts from the durable log
    /// without using transport.
    pub fn recover_vss_commit_round_from_log(&self) -> Result<Vec<DkgCommitPayload>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::VssCommit,
        )?;
        self.vss_commits_from_messages(messages)
    }

    /// Collects and logs accepted IT-VSS public commitment broadcasts.
    pub fn collect_it_vss_public_commitments_logged(
        &mut self,
    ) -> Result<Vec<ItVssPublicCommitment>, DkgError> {
        let messages = self.accept_broadcast_logged(DkgTransportPhase::ItVssArtifact)?;
        self.it_vss_public_commitments_from_messages(messages)
    }

    /// Recovers accepted IT-VSS public commitments from the durable log.
    pub fn recover_it_vss_public_commitments_from_log(
        &self,
    ) -> Result<Vec<ItVssPublicCommitment>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::ItVssArtifact,
        )?;
        self.it_vss_public_commitments_from_messages(messages)
    }

    /// Collects and logs accepted IT-VSS public precommitment broadcasts.
    pub fn collect_it_vss_public_precommitments_logged(
        &mut self,
    ) -> Result<Vec<ItVssPublicPrecommitment>, DkgError> {
        let messages = self.accept_broadcast_logged(DkgTransportPhase::ItVssArtifact)?;
        self.it_vss_public_precommitments_from_messages(messages)
    }

    /// Recovers accepted IT-VSS public precommitments from the durable log.
    pub fn recover_it_vss_public_precommitments_from_log(
        &self,
    ) -> Result<Vec<ItVssPublicPrecommitment>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::ItVssArtifact,
        )?;
        self.it_vss_public_precommitments_from_messages(messages)
    }

    /// Collects and logs accepted IT-VSS public-coin share broadcasts.
    pub fn collect_it_vss_public_coin_shares_logged(
        &mut self,
        label_hash: [u8; 32],
    ) -> Result<Vec<ProductionItVssPublicCoinShare>, DkgError> {
        let messages = self.accept_broadcast_logged(DkgTransportPhase::ItVssArtifact)?;
        self.it_vss_public_coin_shares_from_messages(messages, label_hash)
    }

    /// Recovers accepted IT-VSS public-coin share broadcasts from the durable
    /// log without using transport.
    pub fn recover_it_vss_public_coin_shares_from_log(
        &self,
        label_hash: [u8; 32],
    ) -> Result<Vec<ProductionItVssPublicCoinShare>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::ItVssArtifact,
        )?;
        self.it_vss_public_coin_shares_from_messages(messages, label_hash)
    }

    /// Collects and logs accepted VSS shares for one receiver.
    pub fn collect_vss_share_round_logged(
        &mut self,
        receiver: PartyId,
    ) -> Result<Vec<DkgSharePayload>, DkgError> {
        let messages = self.accept_private_logged(receiver, DkgTransportPhase::VssShare)?;
        messages
            .into_iter()
            .map(|message| {
                let payload = wire_decode_dkg_share_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                if payload.receiver_party_id != receiver.0 {
                    return Err(DkgError::PrimeFieldMpcTransport);
                }
                Ok(DkgSharePayload {
                    dealer: PartyId(message.header.sender_party_id),
                    receiver,
                    encrypted_share: payload.encrypted_share,
                    encrypted_seed_share: payload.encrypted_seed_share,
                    proof: payload.proof,
                })
            })
            .collect()
    }

    /// Collects and logs IT-VSS private deliveries for one receiver.
    pub fn collect_it_vss_private_delivery_round_logged(
        &mut self,
        receiver: PartyId,
    ) -> Result<Vec<ItVssPrivateShareDelivery>, DkgError> {
        let mut deliveries = Vec::new();
        for payload in self.collect_vss_share_round_logged(receiver)? {
            deliveries.extend(it_vss_private_deliveries_from_dkg_share(&payload)?);
        }
        Ok(deliveries)
    }

    /// Recovers accepted VSS shares from the durable log without transport.
    pub fn recover_vss_share_round_from_log(
        &self,
        receiver: PartyId,
    ) -> Result<Vec<DkgSharePayload>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedPrivate,
            Some(receiver),
            DkgTransportPhase::VssShare,
        )?;
        messages
            .into_iter()
            .map(|message| {
                let payload = wire_decode_dkg_share_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                Ok(DkgSharePayload {
                    dealer: PartyId(message.header.sender_party_id),
                    receiver,
                    encrypted_share: payload.encrypted_share,
                    encrypted_seed_share: payload.encrypted_seed_share,
                    proof: payload.proof,
                })
            })
            .collect()
    }

    /// Recovers accepted IT-VSS private deliveries from the durable log.
    pub fn recover_it_vss_private_delivery_round_from_log(
        &self,
        receiver: PartyId,
    ) -> Result<Vec<ItVssPrivateShareDelivery>, DkgError> {
        let mut deliveries = Vec::new();
        for payload in self.recover_vss_share_round_from_log(receiver)? {
            deliveries.extend(it_vss_private_deliveries_from_dkg_share(&payload)?);
        }
        Ok(deliveries)
    }

    /// Collects and logs accepted VSS complaint broadcasts.
    pub fn collect_vss_complaint_round_logged(
        &mut self,
    ) -> Result<Vec<DkgComplaintPayload>, DkgError> {
        let messages = self.accept_broadcast_logged(DkgTransportPhase::VssComplaint)?;
        self.vss_complaints_from_messages(messages)
    }

    /// Recovers accepted VSS complaint broadcasts from the durable log without
    /// using transport.
    pub fn recover_vss_complaint_round_from_log(
        &self,
    ) -> Result<Vec<DkgComplaintPayload>, DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::VssComplaint,
        )?;
        self.vss_complaints_from_messages(messages)
    }

    /// Persists IT-VSS public artifacts as first-class durable setup records.
    pub fn persist_it_vss_artifacts_logged(
        &mut self,
        public_commitments: &[ItVssPublicCommitment],
        resolution: &ItVssComplaintResolution,
    ) -> Result<(), DkgError> {
        for commitment in public_commitments {
            let payload = encode_it_vss_public_commitment_artifact(commitment);
            let message = self
                .state
                .wire_message(DkgTransportPhase::ItVssArtifact, payload);
            self.wire_log
                .persist_dkg_wire_message(&DkgWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                    peer: None,
                    message,
                })?;
        }
        self.persist_it_vss_resolution_logged(resolution)
    }

    /// Persists IT-VSS public precommitments as accepted broadcast records.
    pub fn persist_it_vss_public_precommitments_logged(
        &mut self,
        precommitments: &[ItVssPublicPrecommitment],
    ) -> Result<(), DkgError> {
        for precommitment in precommitments {
            let payload = encode_it_vss_public_precommitment_artifact(precommitment);
            let message = self
                .state
                .wire_message(DkgTransportPhase::ItVssArtifact, payload);
            self.wire_log
                .persist_dkg_wire_message(&DkgWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                    peer: None,
                    message,
                })?;
        }
        Ok(())
    }

    /// Persists IT-VSS public-coin shares as accepted broadcast records.
    pub fn persist_it_vss_public_coin_shares_logged(
        &mut self,
        shares: &[ProductionItVssPublicCoinShare],
    ) -> Result<(), DkgError> {
        for share in shares {
            let payload = encode_it_vss_public_coin_share_artifact(share);
            let message = self
                .state
                .wire_message(DkgTransportPhase::ItVssArtifact, payload);
            self.wire_log
                .persist_dkg_wire_message(&DkgWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                    peer: None,
                    message,
                })?;
        }
        Ok(())
    }

    /// Persists IT-VSS public audit/discard records as accepted broadcast
    /// records.
    pub fn persist_it_vss_public_audit_records_logged(
        &mut self,
        records: &[ProductionItVssAuditRecord],
    ) -> Result<(), DkgError> {
        let payload = encode_it_vss_public_audit_records_artifact(records);
        let message = self
            .state
            .wire_message(DkgTransportPhase::ItVssArtifact, payload);
        self.wire_log
            .persist_dkg_wire_message(&DkgWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message,
            })?;
        Ok(())
    }

    /// Persists IT-VSS vector consistency records as accepted broadcast
    /// records.
    pub fn persist_it_vss_public_consistency_records_logged(
        &mut self,
        records: &[ProductionItVssConsistencyRecord],
    ) -> Result<(), DkgError> {
        let payload = encode_it_vss_public_consistency_records_artifact(records);
        let message = self
            .state
            .wire_message(DkgTransportPhase::ItVssArtifact, payload);
        self.wire_log
            .persist_dkg_wire_message(&DkgWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message,
            })?;
        Ok(())
    }

    /// Persists the IT-VSS complaint-resolution artifact without duplicating
    /// public commitments that were already accepted through the phase driver.
    pub fn persist_it_vss_resolution_logged(
        &mut self,
        resolution: &ItVssComplaintResolution,
    ) -> Result<(), DkgError> {
        let payload = encode_it_vss_complaint_resolution_artifact(resolution);
        let message = self
            .state
            .wire_message(DkgTransportPhase::ItVssArtifact, payload);
        self.wire_log
            .persist_dkg_wire_message(&DkgWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                peer: None,
                message,
            })?;
        Ok(())
    }

    /// Recovers persisted IT-VSS public artifacts from the durable setup log.
    pub fn recover_it_vss_artifacts_from_log(
        &self,
    ) -> Result<(Vec<ItVssPublicCommitment>, Option<ItVssComplaintResolution>), DkgError> {
        let messages = self.messages_from_log(
            PrimeFieldMpcWireDirection::AcceptedBroadcast,
            None,
            DkgTransportPhase::ItVssArtifact,
        )?;
        let mut public_commitments = Vec::new();
        let mut resolution = None;
        for message in messages {
            match wire_decode_dkg_it_vss_artifact_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicCommitment(commitment) => {
                    public_commitments.push(it_vss_public_commitment_from_wire(&commitment)?);
                }
                DkgItVssArtifactPayload::PublicCommitmentBatch(commitments) => {
                    for commitment in commitments {
                        public_commitments.push(it_vss_public_commitment_from_wire(&commitment)?);
                    }
                }
                DkgItVssArtifactPayload::PublicPrecommitment(_) => {}
                DkgItVssArtifactPayload::PublicCoinShare(_) => {}
                DkgItVssArtifactPayload::PublicAuditRecords(_) => {}
                DkgItVssArtifactPayload::PublicConsistencyRecords(_) => {}
                DkgItVssArtifactPayload::ComplaintResolution(next) => {
                    if resolution.is_some() {
                        return Err(DkgError::PrimeFieldMpcReplayDetected);
                    }
                    resolution = Some(it_vss_resolution_from_wire(&next)?);
                }
            }
        }
        Ok((public_commitments, resolution))
    }

    fn broadcast_logged(
        &mut self,
        phase: DkgTransportPhase,
        payload: Vec<u8>,
    ) -> Result<(), DkgError> {
        let message = self.state.wire_message(phase, payload);
        let key = dkg_wire_message_replay_key(&DkgWireMessageRecord {
            direction: PrimeFieldMpcWireDirection::SentBroadcast,
            peer: None,
            message: message.clone(),
        })?;
        let message =
            find_sent_dkg_wire_message(self.wire_log.dkg_wire_records(), key)?.unwrap_or(message);
        self.wire_log
            .persist_dkg_wire_message(&DkgWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::SentBroadcast,
                peer: None,
                message: message.clone(),
            })?;
        self.state
            .transport_mut()
            .broadcast(message)
            .map_err(map_transport_error)
    }

    fn send_private_logged(
        &mut self,
        receiver: PartyId,
        phase: DkgTransportPhase,
        payload: Vec<u8>,
    ) -> Result<(), DkgError> {
        let message = self.state.wire_message(phase, payload);
        let key = dkg_wire_message_replay_key(&DkgWireMessageRecord {
            direction: PrimeFieldMpcWireDirection::SentPrivate,
            peer: Some(receiver),
            message: message.clone(),
        })?;
        let message =
            find_sent_dkg_wire_message(self.wire_log.dkg_wire_records(), key)?.unwrap_or(message);
        self.wire_log
            .persist_dkg_wire_message(&DkgWireMessageRecord {
                direction: PrimeFieldMpcWireDirection::SentPrivate,
                peer: Some(receiver),
                message: message.clone(),
            })?;
        self.state
            .transport_mut()
            .send_private(receiver.0, message)
            .map_err(map_transport_error)
    }

    fn accept_broadcast_logged(
        &mut self,
        phase: DkgTransportPhase,
    ) -> Result<Vec<WireMessage>, DkgError> {
        let messages = self
            .state
            .transport()
            .collect_equivocation_checked_round(phase.round_id(), &self.state.expected_context)
            .map_err(map_transport_error)?;
        for message in &messages {
            self.wire_log
                .persist_dkg_wire_message(&DkgWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                    peer: None,
                    message: message.clone(),
                })?;
        }
        Ok(messages)
    }

    fn accept_private_logged(
        &mut self,
        receiver: PartyId,
        phase: DkgTransportPhase,
    ) -> Result<Vec<WireMessage>, DkgError> {
        let messages = self
            .state
            .transport()
            .collect_private_round(receiver.0, phase.round_id(), &self.state.expected_context)
            .map_err(map_transport_error)?;
        for message in &messages {
            self.wire_log
                .persist_dkg_wire_message(&DkgWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::AcceptedPrivate,
                    peer: Some(PartyId(message.header.sender_party_id)),
                    message: message.clone(),
                })?;
        }
        Ok(messages)
    }

    fn messages_from_log(
        &self,
        direction: PrimeFieldMpcWireDirection,
        receiver: Option<PartyId>,
        phase: DkgTransportPhase,
    ) -> Result<Vec<WireMessage>, DkgError> {
        let mut messages = Vec::new();
        for record in self.wire_log.dkg_wire_records() {
            if record.direction != direction || record.message.header.round != phase.round_id() {
                continue;
            }
            if direction == PrimeFieldMpcWireDirection::AcceptedPrivate
                && record.message.header.payload_kind == PayloadKind::DkgShare
            {
                let payload = wire_decode_dkg_share_payload(&record.message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                if Some(PartyId(payload.receiver_party_id)) != receiver {
                    continue;
                }
            }
            messages.push(record.message.clone());
        }
        Ok(messages)
    }

    fn small_residue_contributions_from_messages(
        &self,
        messages: Vec<WireMessage>,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<Vec<SmallResidueContribution>, DkgError> {
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            let payload = wire_decode_dkg_small_residue_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
            let vector = match payload.vector_kind {
                1 => SecretVectorKind::S1,
                2 => SecretVectorKind::S2,
                _ => return Err(DkgError::SmallSamplerLabelMismatch),
            };
            if vector != label.vector || payload.coefficient_index != label.coefficient_index {
                continue;
            }
            let contribution = SmallResidueContribution {
                dealer: PartyId(message.header.sender_party_id),
                label: SamplerLabel {
                    config_hash: self.state.config.transcript_hash(),
                    vector,
                    coefficient_index: payload.coefficient_index,
                },
                eta: match payload.eta {
                    2 => SmallSecretEta::Two,
                    4 => SmallSecretEta::Four,
                    _ => {
                        return Err(DkgError::InvalidSmallResidue {
                            dealer: PartyId(message.header.sender_party_id),
                            modulus: eta.modulus(),
                            got: payload.residue,
                        })
                    }
                },
                residue: payload.residue,
                bits: payload.bits,
            };
            validate_small_residue_contribution(label, eta, &contribution)?;
            out.push(contribution);
        }
        Ok(out)
    }

    fn vss_commits_from_messages(
        &self,
        messages: Vec<WireMessage>,
    ) -> Result<Vec<DkgCommitPayload>, DkgError> {
        messages
            .into_iter()
            .map(|message| {
                let dealer = PartyId(message.header.sender_party_id);
                let payload = wire_decode_dkg_commit_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                Ok(DkgCommitPayload {
                    dealer,
                    vss_commitments: payload
                        .vss_commitments
                        .into_iter()
                        .map(|bytes| VssCommitment { bytes })
                        .collect(),
                    pairwise_seed_commitment: PairwiseSeedCommitment {
                        party: dealer,
                        commitment: payload.pairwise_seed_commitment,
                    },
                })
            })
            .collect()
    }

    fn vss_complaints_from_messages(
        &self,
        messages: Vec<WireMessage>,
    ) -> Result<Vec<DkgComplaintPayload>, DkgError> {
        messages
            .into_iter()
            .map(|message| {
                let complainant = PartyId(message.header.sender_party_id);
                let payload = wire_decode_dkg_complaint_payload(&message.payload)
                    .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
                let reason = match payload.reason_code {
                    1 => DkgComplaintReason::InvalidVssShare,
                    2 => DkgComplaintReason::InvalidPairwiseSeed,
                    3 => DkgComplaintReason::MissingShare,
                    255 => DkgComplaintReason::Backend,
                    _ => return Err(DkgError::PrimeFieldMpcTransport),
                };
                Ok(DkgComplaintPayload {
                    complainant,
                    dealer: PartyId(payload.dealer_party_id),
                    receiver: PartyId(payload.receiver_party_id),
                    reason,
                    evidence: payload.evidence,
                })
            })
            .collect()
    }

    fn it_vss_public_commitments_from_messages(
        &self,
        messages: Vec<WireMessage>,
    ) -> Result<Vec<ItVssPublicCommitment>, DkgError> {
        let mut commitments = Vec::new();
        for message in messages {
            match wire_decode_dkg_it_vss_artifact_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicCommitment(commitment) => {
                    commitments.push(it_vss_public_commitment_from_wire(&commitment)?);
                }
                DkgItVssArtifactPayload::PublicCommitmentBatch(batch) => {
                    for commitment in batch {
                        commitments.push(it_vss_public_commitment_from_wire(&commitment)?);
                    }
                }
                DkgItVssArtifactPayload::PublicPrecommitment(_) => {}
                DkgItVssArtifactPayload::PublicCoinShare(_) => {}
                DkgItVssArtifactPayload::PublicAuditRecords(_) => {}
                DkgItVssArtifactPayload::PublicConsistencyRecords(_) => {}
                DkgItVssArtifactPayload::ComplaintResolution(_) => {}
            }
        }
        Ok(commitments)
    }

    fn it_vss_public_precommitments_from_messages(
        &self,
        messages: Vec<WireMessage>,
    ) -> Result<Vec<ItVssPublicPrecommitment>, DkgError> {
        let mut precommitments = Vec::new();
        for message in messages {
            match wire_decode_dkg_it_vss_artifact_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicPrecommitment(precommitment) => {
                    precommitments.push(it_vss_public_precommitment_from_wire(&precommitment)?);
                }
                DkgItVssArtifactPayload::PublicCommitment(_)
                | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
                | DkgItVssArtifactPayload::PublicAuditRecords(_)
                | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
                | DkgItVssArtifactPayload::ComplaintResolution(_)
                | DkgItVssArtifactPayload::PublicCoinShare(_) => {}
            }
        }
        Ok(precommitments)
    }

    fn it_vss_public_coin_shares_from_messages(
        &self,
        messages: Vec<WireMessage>,
        label_hash: [u8; 32],
    ) -> Result<Vec<ProductionItVssPublicCoinShare>, DkgError> {
        let mut shares = Vec::new();
        for message in messages {
            match wire_decode_dkg_it_vss_artifact_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicCoinShare(share)
                    if share.label_hash == label_hash =>
                {
                    shares.push(it_vss_public_coin_share_from_wire(&share));
                }
                DkgItVssArtifactPayload::PublicCommitment(_)
                | DkgItVssArtifactPayload::PublicPrecommitment(_)
                | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
                | DkgItVssArtifactPayload::PublicAuditRecords(_)
                | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
                | DkgItVssArtifactPayload::ComplaintResolution(_)
                | DkgItVssArtifactPayload::PublicCoinShare(_) => {}
            }
        }
        Ok(shares)
    }

    fn it_vss_public_audit_records_from_messages(
        &self,
        messages: Vec<WireMessage>,
    ) -> Result<Vec<ProductionItVssAuditRecord>, DkgError> {
        let mut records = Vec::new();
        for message in messages {
            match wire_decode_dkg_it_vss_artifact_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicAuditRecords(next) => {
                    records.extend(next.iter().map(it_vss_audit_record_from_wire));
                }
                DkgItVssArtifactPayload::PublicCommitment(_)
                | DkgItVssArtifactPayload::PublicPrecommitment(_)
                | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
                | DkgItVssArtifactPayload::PublicCoinShare(_)
                | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
                | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
            }
        }
        Ok(records)
    }

    fn it_vss_public_consistency_records_from_messages(
        &self,
        messages: Vec<WireMessage>,
    ) -> Result<Vec<ProductionItVssConsistencyRecord>, DkgError> {
        let mut records = Vec::new();
        for message in messages {
            match wire_decode_dkg_it_vss_artifact_payload(&message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicConsistencyRecords(next) => {
                    records.extend(next.iter().map(it_vss_consistency_record_from_wire));
                }
                DkgItVssArtifactPayload::PublicCommitment(_)
                | DkgItVssArtifactPayload::PublicPrecommitment(_)
                | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
                | DkgItVssArtifactPayload::PublicCoinShare(_)
                | DkgItVssArtifactPayload::PublicAuditRecords(_)
                | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
            }
        }
        Ok(records)
    }
}

/// Collects a logged bounded-sampler residue round and samples one coefficient.
#[cfg(test)]
pub fn sample_logged_small_coeff<P, T, L>(
    sampler: &mut impl DistributedSmallSampler,
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    label: SamplerLabel,
) -> Result<SharedSmallCoeff, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    let contributions = runtime.collect_small_residue_round_logged(label, eta)?;
    let certified =
        scaffold_it_vss_certified_small_residue_inputs::<P>(config, label, eta, &contributions)?;
    sampler.sample_verified_small_coeff::<P>(config, label, &certified.inputs)
}

/// Recovers a logged bounded-sampler residue round and samples one coefficient
/// without reading transport queues.
#[cfg(test)]
pub fn sample_logged_small_coeff_from_log<P, T, L>(
    sampler: &mut impl DistributedSmallSampler,
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    label: SamplerLabel,
) -> Result<SharedSmallCoeff, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    let contributions = runtime.recover_small_residue_round_from_log(label, eta)?;
    let certified =
        scaffold_it_vss_certified_small_residue_inputs::<P>(config, label, eta, &contributions)?;
    sampler.sample_verified_small_coeff::<P>(config, label, &certified.inputs)
}

/// Samples a full small ML-DSA vector from accepted small-residue coefficient
/// rounds recovered from the durable DKG setup log.
#[cfg(test)]
pub fn sample_logged_small_polyvec_from_log<P, T, L>(
    sampler: &mut impl DistributedSmallSampler,
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    vector: SecretVectorKind,
) -> Result<SharedSmallPolyVec, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    let mut contributions = Vec::with_capacity(vector.coefficient_count::<P>());
    for index in 0..vector.coefficient_count::<P>() {
        let label = SamplerLabel::new::<P>(config, vector, index)?;
        let round = runtime.recover_small_residue_round_from_log(label, eta)?;
        let certified =
            scaffold_it_vss_certified_small_residue_inputs::<P>(config, label, eta, &round)?;
        contributions.push(certified.inputs);
    }
    sampler.sample_verified_small_polyvec::<P>(config, vector, &contributions)
}

/// Recovers a bounded-sampler coefficient round and requires each residue to
/// be backed by an already-persisted IT-VSS certificate artifact.
pub fn verified_logged_small_residue_inputs_from_it_vss_artifacts<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    label: SamplerLabel,
) -> Result<Vec<VerifiedSmallResidueInput>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    verified_logged_small_residue_inputs_from_it_vss_artifacts_for_backend::<P, T, L>(
        config,
        runtime,
        label,
        ItVssBackendId::InProcessHashBindingScaffold,
    )
}

fn verified_logged_small_residue_inputs_from_it_vss_artifacts_for_backend<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    label: SamplerLabel,
    expected_backend: ItVssBackendId,
) -> Result<Vec<VerifiedSmallResidueInput>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    let contributions = runtime.recover_small_residue_round_from_log(label, eta)?;
    let (public_commitments, resolution) = runtime.recover_it_vss_artifacts_from_log()?;
    if let Some(resolution) = resolution.as_ref() {
        validate_it_vss_complaint_resolution_for_backend(
            config,
            &public_commitments,
            resolution,
            expected_backend,
        )?;
    }

    contributions
        .iter()
        .map(|contribution| {
            validate_small_residue_contribution(label, eta, contribution)?;
            let sharing_label = ItVssSharingLabel::new(
                config,
                contribution.dealer,
                ItVssSharingDomain::for_secret_vector(label.vector),
                Some(label.coefficient_index),
            )?;
            let commitment = public_commitments
                .iter()
                .find(|commitment| {
                    commitment.backend_id == expected_backend
                        && commitment.dealer == contribution.dealer
                        && commitment.label_hash == sharing_label.label_hash
                })
                .ok_or(DkgError::ItVssCertificateMissingCommitment {
                    dealer: contribution.dealer,
                    label_hash: sharing_label.label_hash,
                })?;
            Ok(VerifiedSmallResidueInput::from_it_vss_certificate(
                contribution.dealer,
                label,
                eta,
                contribution.residue,
                sharing_label.label_hash,
                hash_it_vss_public_commitment(commitment),
            ))
        })
        .collect()
}

#[cfg(test)]
fn verified_small_residue_inputs_from_recovered_it_vss_artifacts<P>(
    config: &DkgConfig,
    label: SamplerLabel,
    contributions: &[SmallResidueContribution],
    public_commitments: &[ItVssPublicCommitment],
) -> Result<Vec<VerifiedSmallResidueInput>, DkgError>
where
    P: MlDsaParams,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    contributions
        .iter()
        .map(|contribution| {
            validate_small_residue_contribution(label, eta, contribution)?;
            let sharing_label = ItVssSharingLabel::new(
                config,
                contribution.dealer,
                ItVssSharingDomain::for_secret_vector(label.vector),
                Some(label.coefficient_index),
            )?;
            let commitment = public_commitments
                .iter()
                .find(|commitment| {
                    commitment.backend_id == ItVssBackendId::InProcessHashBindingScaffold
                        && commitment.dealer == contribution.dealer
                        && commitment.label_hash == sharing_label.label_hash
                })
                .ok_or(DkgError::ItVssCertificateMissingCommitment {
                    dealer: contribution.dealer,
                    label_hash: sharing_label.label_hash,
                })?;
            Ok(VerifiedSmallResidueInput::from_it_vss_certificate(
                contribution.dealer,
                label,
                eta,
                contribution.residue,
                sharing_label.label_hash,
                hash_it_vss_public_commitment(commitment),
            ))
        })
        .collect()
}

fn verified_small_residue_inputs_from_recovered_vector_it_vss_artifacts<P>(
    config: &DkgConfig,
    label: SamplerLabel,
    contributions: &[SmallResidueContribution],
    public_commitments: &[ItVssPublicCommitment],
    resolution: &ItVssComplaintResolution,
    expected_backend: ItVssBackendId,
) -> Result<Vec<VerifiedSmallResidueInput>, DkgError>
where
    P: MlDsaParams,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    contributions
        .iter()
        .map(|contribution| {
            validate_small_residue_contribution(label, eta, contribution)?;
            let sharing_label = ItVssSharingLabel::new(
                config,
                contribution.dealer,
                ItVssSharingDomain::for_secret_vector(label.vector),
                None,
            )?;
            let commitment = public_commitments
                .iter()
                .find(|commitment| {
                    commitment.backend_id == expected_backend
                        && commitment.dealer == contribution.dealer
                        && commitment.label_hash == sharing_label.label_hash
                })
                .ok_or(DkgError::ItVssCertificateMissingCommitment {
                    dealer: contribution.dealer,
                    label_hash: sharing_label.label_hash,
                })?;
            let certificate = resolution.certificates.iter().find(|certificate| {
                certificate.dealer == contribution.dealer
                    && certificate.label_hash == sharing_label.label_hash
            });
            let Some(certificate) = certificate else {
                if expected_backend == ItVssBackendId::InProcessHashBindingScaffold {
                    return Ok(VerifiedSmallResidueInput::from_it_vss_certificate(
                        contribution.dealer,
                        label,
                        eta,
                        contribution.residue,
                        sharing_label.label_hash,
                        hash_it_vss_public_commitment(commitment),
                    ));
                }
                return Err(DkgError::ItVssResolutionMissingCertificate {
                    dealer: contribution.dealer,
                });
            };
            if certificate.transcript_hash != hash_it_vss_public_commitment(commitment) {
                return Err(DkgError::TranscriptMismatch {
                    expected: KeygenTranscriptHash(hash_it_vss_public_commitment(commitment)),
                    got: KeygenTranscriptHash(certificate.transcript_hash),
                });
            }
            VerifiedSmallResidueInput::from_verified_vector_it_vss_certificate_for_backend(
                config,
                label,
                eta,
                contribution.residue,
                sharing_label,
                certificate,
                expected_backend,
            )
        })
        .collect()
}

/// Samples a full small ML-DSA vector from durable logged residue rounds and
/// pre-existing IT-VSS certificate artifacts. Unlike
/// `sample_logged_small_polyvec_from_log`, this function does not mint
/// scaffold certificates during assembly.
pub fn sample_logged_small_polyvec_from_certified_log<P, T, L>(
    sampler: &mut impl DistributedSmallSampler,
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    vector: SecretVectorKind,
) -> Result<SharedSmallPolyVec, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    sample_logged_small_polyvec_from_certified_log_for_backend::<P, T, L>(
        sampler,
        config,
        runtime,
        vector,
        ItVssBackendId::InProcessHashBindingScaffold,
    )
}

fn sample_logged_small_polyvec_from_certified_log_for_backend<P, T, L>(
    sampler: &mut impl DistributedSmallSampler,
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    vector: SecretVectorKind,
    expected_backend: ItVssBackendId,
) -> Result<SharedSmallPolyVec, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let (public_commitments, resolution) = runtime.recover_it_vss_artifacts_from_log()?;
    let resolution = resolution
        .as_ref()
        .ok_or(DkgError::MissingDkgSetupCertificate)?;
    validate_it_vss_complaint_resolution_for_backend(
        config,
        &public_commitments,
        resolution,
        expected_backend,
    )?;
    let eta = SmallSecretEta::for_params::<P>()?;
    let mut inputs = Vec::with_capacity(vector.coefficient_count::<P>());
    for index in 0..vector.coefficient_count::<P>() {
        let label = SamplerLabel::new::<P>(config, vector, index)?;
        let contributions = runtime.recover_small_residue_round_from_log(label, eta)?;
        inputs.push(
            verified_small_residue_inputs_from_recovered_vector_it_vss_artifacts::<P>(
                config,
                label,
                &contributions,
                &public_commitments,
                resolution,
                expected_backend,
            )?,
        );
    }
    sampler.sample_verified_small_polyvec::<P>(config, vector, &inputs)
}

/// Production-shaped certificate bundle for one scaffold small-residue round.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct ScaffoldItVssCertifiedSmallResidueInputs {
    /// Public IT-VSS commitments for every residue dealer.
    pub public_commitments: Vec<ItVssPublicCommitment>,
    /// Validated complaint resolution for the round.
    pub resolution: ItVssComplaintResolution,
    /// Verified sampler inputs derived from the certificates.
    pub inputs: Vec<VerifiedSmallResidueInput>,
}

fn encode_small_residue_it_vss_secret(
    label: SamplerLabel,
    eta: SmallSecretEta,
    contribution: &SmallResidueContribution,
) -> Result<Vec<u8>, DkgError> {
    validate_small_residue_contribution(label, eta, contribution)?;
    let mut out = Vec::new();
    out.extend_from_slice(b"TALUS-DKG-IT-VSS-v1/small-residue-secret");
    out.extend_from_slice(&label.config_hash.0);
    out.push(label.vector.as_u8());
    out.extend_from_slice(&label.coefficient_index.to_le_bytes());
    out.push(eta.bound() as u8);
    out.push(eta.modulus());
    out.extend_from_slice(&contribution.dealer.0.to_le_bytes());
    out.push(contribution.residue);
    out.extend_from_slice(&(contribution.bits.len() as u32).to_le_bytes());
    out.extend_from_slice(&contribution.bits);
    Ok(out)
}

fn encode_small_residue_vector_it_vss_secret<P: MlDsaParams>(
    config: &DkgConfig,
    vector: SecretVectorKind,
    eta: SmallSecretEta,
    dealer: PartyId,
    contributions: &[SmallResidueContribution],
) -> Result<Vec<u8>, DkgError> {
    let expected = vector.coefficient_count::<P>();
    if contributions.len() != expected {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected,
            got: contributions.len(),
        });
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"TALUS-DKG-IT-VSS-v1/small-residue-vector-secret");
    out.extend_from_slice(&config.transcript_hash().0);
    out.push(vector.as_u8());
    out.push(eta.bound() as u8);
    out.push(eta.modulus());
    out.extend_from_slice(&dealer.0.to_le_bytes());
    out.extend_from_slice(&(contributions.len() as u32).to_le_bytes());
    for (index, contribution) in contributions.iter().enumerate() {
        let label = SamplerLabel::new::<P>(config, vector, index)?;
        validate_small_residue_contribution(label, eta, contribution)?;
        if contribution.dealer != dealer {
            return Err(DkgError::PartyMismatch {
                expected: dealer,
                got: contribution.dealer,
            });
        }
        out.extend_from_slice(&(index as u32).to_le_bytes());
        out.push(contribution.residue);
        out.extend_from_slice(&(contribution.bits.len() as u32).to_le_bytes());
        out.extend_from_slice(&contribution.bits);
    }
    Ok(out)
}

/// Shares one exact bounded-sampler residue through the selected IT-VSS
/// backend. The deterministic scaffold backend implements the same trait for
/// tests; the production information-checking backend uses the production
/// backend identity and transcript-bound private-delivery checks. Separate
/// release readiness gates require Rabin-Ben-Or-style IT-VSS evidence before
/// production artifacts are accepted.
pub fn it_vss_share_small_residue_contribution<P, B>(
    backend: &mut B,
    config: &DkgConfig,
    label: SamplerLabel,
    eta: SmallSecretEta,
    contribution: &SmallResidueContribution,
) -> Result<ItVssDealerOutput, DkgError>
where
    P: MlDsaParams,
    B: ProductionItVssBackend,
{
    validate_small_residue_contribution(label, eta, contribution)?;
    let sharing_label = ItVssSharingLabel::new(
        config,
        contribution.dealer,
        ItVssSharingDomain::for_secret_vector(label.vector),
        Some(label.coefficient_index),
    )?;
    let secret = encode_small_residue_it_vss_secret(label, eta, contribution)?;
    backend.share_secret::<P>(config, sharing_label, &secret)
}

/// Shares one dealer's full bounded-sampler residue vector through the
/// selected IT-VSS backend.
///
/// This is the batched/vector sampler boundary for native DKG setup. The
/// sharing label is vector-domain (`index = None`), so one public commitment
/// certifies the dealer's entire contribution to an `s1` or `s2` sampler
/// vector. Production DKG must use this shape instead of scalar-per-coefficient
/// IT-VSS commitments.
pub fn it_vss_share_small_residue_vector_contribution<P, B>(
    backend: &mut B,
    config: &DkgConfig,
    vector: SecretVectorKind,
    eta: SmallSecretEta,
    dealer: PartyId,
    contributions: &[SmallResidueContribution],
) -> Result<ItVssDealerOutput, DkgError>
where
    P: MlDsaParams,
    B: ProductionItVssBackend,
{
    config.validate()?;
    if !config.parties.contains(&dealer) {
        return Err(DkgError::UnknownParty(dealer));
    }
    let sharing_label = ItVssSharingLabel::new(
        config,
        dealer,
        ItVssSharingDomain::for_secret_vector(vector),
        None,
    )?;
    let secret =
        encode_small_residue_vector_it_vss_secret::<P>(config, vector, eta, dealer, contributions)?;
    let mut batch = it_vss_share_batched_vector_secrets::<P, B>(
        backend,
        config,
        dealer,
        &[ItVssBatchedSecret {
            label: sharing_label,
            secret,
        }],
    )?;
    Ok(ItVssDealerOutput {
        public_commitment: batch.public_commitments.remove(0),
        deliveries: batch.deliveries,
    })
}

/// One vector-domain secret to share through the batched IT-VSS boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssBatchedSecret {
    /// Vector-domain sharing label. Production DKG requires `index = None`.
    pub label: ItVssSharingLabel,
    /// Encoded private secret material for this vector sharing.
    pub secret: Vec<u8>,
}

/// Batched/vector IT-VSS dealer output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItVssBatchedDealerOutput {
    /// Public commitments, one per vector-domain sharing.
    pub public_commitments: Vec<ItVssPublicCommitment>,
    /// Directed private deliveries for all vector-domain sharings.
    pub deliveries: Vec<ItVssPrivateShareDelivery>,
}

fn it_vss_dealer_outputs_from_batched_output(
    output: &ItVssBatchedDealerOutput,
) -> Result<Vec<ItVssDealerOutput>, DkgError> {
    let mut out = Vec::with_capacity(output.public_commitments.len());
    for commitment in &output.public_commitments {
        let deliveries = output
            .deliveries
            .iter()
            .filter(|delivery| {
                delivery.dealer == commitment.dealer && delivery.label_hash == commitment.label_hash
            })
            .cloned()
            .collect::<Vec<_>>();
        if deliveries.is_empty() {
            return Err(DkgError::MissingDkgSetupCertificate);
        }
        out.push(ItVssDealerOutput {
            public_commitment: commitment.clone(),
            deliveries,
        });
    }
    Ok(out)
}

fn production_it_vss_public_audit_records_from_batched_output(
    config: &DkgConfig,
    output: &ItVssBatchedDealerOutput,
    params: ProductionItVssSecurityParams,
) -> Result<Vec<ProductionItVssAuditRecord>, DkgError> {
    let mut records = Vec::new();
    for dealer_output in it_vss_dealer_outputs_from_batched_output(output)? {
        records.extend(production_it_vss_public_audit_records_from_output(
            config,
            &dealer_output,
            params,
        )?);
    }
    Ok(records)
}

fn production_it_vss_public_consistency_records_from_batched_output(
    config: &DkgConfig,
    output: &ItVssBatchedDealerOutput,
    params: ProductionItVssSecurityParams,
    public_coin_transcripts: &[ProductionItVssPublicCoinTranscript],
) -> Result<Vec<ProductionItVssConsistencyRecord>, DkgError> {
    let mut records = Vec::new();
    for dealer_output in it_vss_dealer_outputs_from_batched_output(output)? {
        let transcript = public_coin_transcripts
            .iter()
            .find(|transcript| transcript.label_hash == dealer_output.public_commitment.label_hash)
            .ok_or(DkgError::MissingDkgSetupCertificate)?;
        records.extend(
            production_it_vss_public_consistency_records_from_output_with_coin(
                config,
                &dealer_output,
                params,
                Some(transcript.coin_hash),
            )?,
        );
    }
    Ok(records)
}

/// One dealer's bounded-sampler contribution to a whole ML-DSA secret vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmallResidueVectorContributionBatch {
    /// Secret vector being contributed.
    pub vector: SecretVectorKind,
    /// Per-coefficient residues for this dealer and vector.
    pub contributions: Vec<SmallResidueContribution>,
}

/// Ensures a sharing label is the production-shaped vector/batched DKG label.
pub fn ensure_it_vss_batched_vector_label(label: ItVssSharingLabel) -> Result<(), DkgError> {
    if label.index.is_some() {
        return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
    }
    match label.domain {
        ItVssSharingDomain::MldsaS1 | ItVssSharingDomain::MldsaS2 => Ok(()),
        ItVssSharingDomain::SmallResidue
        | ItVssSharingDomain::PrimeFieldMpcAux
        | ItVssSharingDomain::NoncePreprocessing => Err(DkgError::ItVssCertificateLabelMismatch),
    }
}

/// Shares a batch of vector-domain secrets through the selected IT-VSS backend.
///
/// This is the production-shaped DKG boundary: labels must be whole-vector
/// `s1`/`s2` labels (`index = None`), and per-coefficient scalar labels are
/// rejected before the backend can emit transport messages.
pub fn it_vss_share_batched_vector_secrets<P, B>(
    backend: &mut B,
    config: &DkgConfig,
    dealer: PartyId,
    secrets: &[ItVssBatchedSecret],
) -> Result<ItVssBatchedDealerOutput, DkgError>
where
    P: MlDsaParams,
    B: ProductionItVssBackend,
{
    config.validate()?;
    if !config.parties.contains(&dealer) {
        return Err(DkgError::UnknownParty(dealer));
    }
    if secrets.is_empty() {
        return Err(DkgError::EmptyPublicCommitments);
    }

    let mut seen_labels = Vec::with_capacity(secrets.len());
    let mut public_commitments = Vec::with_capacity(secrets.len());
    let mut deliveries = Vec::with_capacity(secrets.len() * config.parties.len());
    let mut seen_deliveries = Vec::with_capacity(secrets.len() * config.parties.len());

    for item in secrets {
        if item.label.config_hash != config.transcript_hash() {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        if item.label.dealer != dealer {
            return Err(DkgError::PartyMismatch {
                expected: dealer,
                got: item.label.dealer,
            });
        }
        ensure_it_vss_batched_vector_label(item.label)?;
        if seen_labels.contains(&item.label.label_hash) {
            return Err(DkgError::DuplicateItVssPublicCommitment {
                dealer,
                label_hash: item.label.label_hash,
            });
        }
        seen_labels.push(item.label.label_hash);

        let output = backend.share_secret::<P>(config, item.label, &item.secret)?;
        if output.public_commitment.dealer != dealer
            || output.public_commitment.label_hash != item.label.label_hash
            || output.public_commitment.backend_id != backend.backend_id()
        {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        for delivery in output.deliveries {
            if delivery.dealer != dealer || delivery.label_hash != item.label.label_hash {
                return Err(DkgError::ItVssCertificateLabelMismatch);
            }
            if !config.parties.contains(&delivery.receiver) {
                return Err(DkgError::UnknownParty(delivery.receiver));
            }
            let key = (delivery.receiver, delivery.label_hash);
            if seen_deliveries.contains(&key) {
                return Err(DkgError::DuplicateShare {
                    dealer,
                    receiver: delivery.receiver,
                });
            }
            seen_deliveries.push(key);
            deliveries.push(delivery);
        }
        public_commitments.push(output.public_commitment);
    }

    Ok(ItVssBatchedDealerOutput {
        public_commitments,
        deliveries,
    })
}

/// Shares one dealer's `s1`/`s2` bounded-sampler residue vectors through the
/// batched/vector IT-VSS boundary.
pub fn it_vss_share_small_residue_vector_batches<P, B>(
    backend: &mut B,
    config: &DkgConfig,
    eta: SmallSecretEta,
    dealer: PartyId,
    batches: &[SmallResidueVectorContributionBatch],
) -> Result<ItVssBatchedDealerOutput, DkgError>
where
    P: MlDsaParams,
    B: ProductionItVssBackend,
{
    let mut secrets = Vec::with_capacity(batches.len());
    for batch in batches {
        let label = ItVssSharingLabel::new(
            config,
            dealer,
            ItVssSharingDomain::for_secret_vector(batch.vector),
            None,
        )?;
        let secret = encode_small_residue_vector_it_vss_secret::<P>(
            config,
            batch.vector,
            eta,
            dealer,
            &batch.contributions,
        )?;
        secrets.push(ItVssBatchedSecret { label, secret });
    }
    it_vss_share_batched_vector_secrets::<P, B>(backend, config, dealer, &secrets)
}

/// Adapts a checked scaffold small-residue round into test IT-VSS
/// certificates, validates the public resolution, then returns verified sampler
/// inputs.
#[cfg(test)]
pub fn scaffold_it_vss_certified_small_residue_inputs<P: MlDsaParams>(
    config: &DkgConfig,
    label: SamplerLabel,
    eta: SmallSecretEta,
    contributions: &[SmallResidueContribution],
) -> Result<ScaffoldItVssCertifiedSmallResidueInputs, DkgError> {
    config.validate()?;
    let mut backend = DeterministicItVssTestBackend::new([0u8; 32]);
    let mut public_commitments = Vec::with_capacity(contributions.len());
    let mut certificates = Vec::with_capacity(contributions.len());

    for contribution in contributions {
        let dealer_output = it_vss_share_small_residue_contribution::<P, _>(
            &mut backend,
            config,
            label,
            eta,
            contribution,
        )?;
        let sharing_label = ItVssSharingLabel::new(
            config,
            contribution.dealer,
            ItVssSharingDomain::for_secret_vector(label.vector),
            Some(label.coefficient_index),
        )?;
        let public_commitment = dealer_output.public_commitment;
        certificates.push(VerifiedItVssSharingCertificate {
            backend_id: ItVssBackendId::InProcessHashBindingScaffold,
            dealer: contribution.dealer,
            label_hash: sharing_label.label_hash,
            accepted_receivers: config.parties.clone(),
            complaint_hash: hash_dkg_complaint_payloads(&[]),
            transcript_hash: hash_it_vss_public_commitment(&public_commitment),
        });
        public_commitments.push(public_commitment);
    }

    let resolution = ItVssComplaintResolution {
        accepted_dealers: config.parties.clone(),
        rejected_dealers: Vec::new(),
        complaints: Vec::new(),
        certificates,
    };
    validate_it_vss_complaint_resolution_for_backend(
        config,
        &public_commitments,
        &resolution,
        ItVssBackendId::InProcessHashBindingScaffold,
    )?;

    let mut inputs = Vec::with_capacity(contributions.len());
    for contribution in contributions {
        let sharing_label = ItVssSharingLabel::new(
            config,
            contribution.dealer,
            ItVssSharingDomain::for_secret_vector(label.vector),
            Some(label.coefficient_index),
        )?;
        let certificate = resolution
            .certificates
            .iter()
            .find(|certificate| {
                certificate.dealer == contribution.dealer
                    && certificate.label_hash == sharing_label.label_hash
            })
            .ok_or(DkgError::ItVssResolutionMissingCertificate {
                dealer: contribution.dealer,
            })?;
        inputs.push(
            VerifiedSmallResidueInput::from_verified_it_vss_certificate_for_backend(
                config,
                label,
                eta,
                contribution.residue,
                sharing_label,
                certificate,
                ItVssBackendId::InProcessHashBindingScaffold,
            )?,
        );
    }

    Ok(ScaffoldItVssCertifiedSmallResidueInputs {
        public_commitments,
        resolution,
        inputs,
    })
}

#[cfg(test)]
fn scaffold_it_vss_small_residue_public_commitments_from_logs<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    vector: SecretVectorKind,
) -> Result<Vec<ItVssPublicCommitment>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    let mut backend = DeterministicItVssTestBackend::new([0u8; 32]);
    let mut public_commitments = Vec::new();
    for &dealer in &config.parties {
        let mut contributions = Vec::with_capacity(vector.coefficient_count::<P>());
        for index in 0..vector.coefficient_count::<P>() {
            let label = SamplerLabel::new::<P>(config, vector, index)?;
            let round = runtime.recover_small_residue_round_from_log(label, eta)?;
            let contribution = round
                .into_iter()
                .find(|contribution| contribution.dealer == dealer)
                .ok_or(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: config.parties.len(),
                    got: 0,
                })?;
            contributions.push(contribution);
        }
        let sharing_label = ItVssSharingLabel::new(
            config,
            dealer,
            ItVssSharingDomain::for_secret_vector(vector),
            None,
        )?;
        let secret = encode_small_residue_vector_it_vss_secret::<P>(
            config,
            vector,
            eta,
            dealer,
            &contributions,
        )?;
        let dealer_output = backend.share_secret::<P>(config, sharing_label, &secret)?;
        public_commitments.push(dealer_output.public_commitment);
    }
    Ok(public_commitments)
}

/// Encodes an in-process scalar VSS public check as a DKG commit payload.
///
/// This is the transport-shaped scaffold for the native DKG path. Production
/// VSS will replace the in-process proof bytes with information-checking
/// material while keeping the same logged DKG transport boundary.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn dkg_commit_from_in_process_scalar_vss_public_check(
    public_check: &InProcessScalarVssPublicCheck,
) -> DkgCommitPayload {
    dkg_commit_from_in_process_scalar_vss_public_checks(std::slice::from_ref(public_check))
}

/// Encodes a vector of in-process scalar VSS public checks as one DKG commit
/// payload for a dealer.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn dkg_commit_from_in_process_scalar_vss_public_checks(
    public_checks: &[InProcessScalarVssPublicCheck],
) -> DkgCommitPayload {
    let dealer = public_checks
        .first()
        .map(|check| check.dealer)
        .unwrap_or(PartyId(0));
    DkgCommitPayload {
        dealer,
        vss_commitments: public_checks
            .iter()
            .map(|check| VssCommitment {
                bytes: encode_in_process_scalar_vss_public_check(check),
            })
            .collect(),
        pairwise_seed_commitment: PairwiseSeedCommitment {
            party: dealer,
            commitment: [0u8; 32],
        },
    }
}

/// Decodes an in-process scalar VSS public check from a logged DKG commit.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn in_process_scalar_vss_public_check_from_dkg_commit(
    commit: &DkgCommitPayload,
) -> Result<InProcessScalarVssPublicCheck, DkgError> {
    let checks = in_process_scalar_vss_public_checks_from_dkg_commit(commit)?;
    if checks.len() != 1 {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: 1,
            got: checks.len(),
        });
    }
    Ok(checks[0].clone())
}

/// Decodes a vector of in-process scalar VSS public checks from a logged DKG
/// commit.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn in_process_scalar_vss_public_checks_from_dkg_commit(
    commit: &DkgCommitPayload,
) -> Result<Vec<InProcessScalarVssPublicCheck>, DkgError> {
    if commit.vss_commitments.is_empty() {
        return Err(DkgError::EmptyDkgCommitments(commit.dealer));
    }
    commit
        .vss_commitments
        .iter()
        .map(|commitment| {
            let check = decode_in_process_scalar_vss_public_check(&commitment.bytes)?;
            if check.dealer != commit.dealer {
                return Err(DkgError::PartyMismatch {
                    expected: commit.dealer,
                    got: check.dealer,
                });
            }
            Ok(check)
        })
        .collect()
}

/// Encodes an in-process scalar VSS private share as a DKG directed-share
/// payload.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn dkg_share_from_in_process_scalar_vss_private_share(
    share: &InProcessScalarVssPrivateShare,
) -> DkgSharePayload {
    dkg_share_from_in_process_scalar_vss_private_shares(std::slice::from_ref(share))
}

/// Encodes a vector of in-process scalar VSS private shares as one DKG
/// directed-share payload.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn dkg_share_from_in_process_scalar_vss_private_shares(
    shares: &[InProcessScalarVssPrivateShare],
) -> DkgSharePayload {
    let first = shares
        .first()
        .copied()
        .unwrap_or(InProcessScalarVssPrivateShare {
            share: ScalarVssShare {
                dealer: PartyId(0),
                receiver: PartyId(0),
                point: 0,
                value: 0,
            },
            delivery_binding: [0u8; 32],
        });
    DkgSharePayload {
        dealer: first.share.dealer,
        receiver: first.share.receiver,
        encrypted_share: encode_in_process_scalar_vss_private_share_vector(shares),
        encrypted_seed_share: Vec::new(),
        proof: first.delivery_binding.to_vec(),
    }
}

/// Decodes an in-process scalar VSS private share from a logged DKG
/// directed-share payload.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn in_process_scalar_vss_private_share_from_dkg_share(
    payload: &DkgSharePayload,
) -> Result<InProcessScalarVssPrivateShare, DkgError> {
    let shares = in_process_scalar_vss_private_shares_from_dkg_share(payload)?;
    if shares.len() != 1 {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: 1,
            got: shares.len(),
        });
    }
    Ok(shares[0])
}

/// Decodes a vector of in-process scalar VSS private shares from a logged DKG
/// directed-share payload.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn in_process_scalar_vss_private_shares_from_dkg_share(
    payload: &DkgSharePayload,
) -> Result<Vec<InProcessScalarVssPrivateShare>, DkgError> {
    let shares = decode_in_process_scalar_vss_private_share_vector(&payload.encrypted_share)?;
    for share in &shares {
        if share.share.dealer != payload.dealer || share.share.receiver != payload.receiver {
            return Err(DkgError::PartyMismatch {
                expected: payload.receiver,
                got: share.share.receiver,
            });
        }
    }
    if !payload.proof.is_empty() {
        let Some(first) = shares.first() else {
            return Err(DkgError::PrimeFieldMpcTransport);
        };
        if payload.proof != first.delivery_binding {
            return Err(DkgError::PrimeFieldMpcTransport);
        }
    }
    Ok(shares)
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn is_in_process_scalar_vss_private_share_payload(payload: &DkgSharePayload) -> bool {
    payload
        .encrypted_share
        .starts_with(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_MAGIC)
        || payload
            .encrypted_share
            .starts_with(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_VECTOR_MAGIC)
}

/// Collects logged VSS commit broadcasts and decodes in-process scalar public
/// checks.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn collect_logged_in_process_scalar_vss_public_checks<T, L>(
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
) -> Result<Vec<InProcessScalarVssPublicCheck>, DkgError>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    runtime
        .collect_vss_commit_round_logged()?
        .iter()
        .map(in_process_scalar_vss_public_check_from_dkg_commit)
        .collect()
}

/// Collects logged VSS commit broadcasts and decodes vector/polynomial
/// in-process scalar public checks.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn collect_logged_in_process_scalar_vss_public_check_vectors<T, L>(
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
) -> Result<Vec<Vec<InProcessScalarVssPublicCheck>>, DkgError>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    runtime
        .collect_vss_commit_round_logged()?
        .iter()
        .map(in_process_scalar_vss_public_checks_from_dkg_commit)
        .collect()
}

/// Recovers logged VSS commits and decodes in-process scalar public checks
/// without using transport queues.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn recover_logged_in_process_scalar_vss_public_checks<T, L>(
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
) -> Result<Vec<InProcessScalarVssPublicCheck>, DkgError>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    runtime
        .recover_vss_commit_round_from_log()?
        .iter()
        .map(in_process_scalar_vss_public_check_from_dkg_commit)
        .collect()
}

/// Recovers logged VSS commits and decodes vector/polynomial in-process scalar
/// public checks without using transport queues.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn recover_logged_in_process_scalar_vss_public_check_vectors<T, L>(
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
) -> Result<Vec<Vec<InProcessScalarVssPublicCheck>>, DkgError>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    runtime
        .recover_vss_commit_round_from_log()?
        .iter()
        .map(in_process_scalar_vss_public_checks_from_dkg_commit)
        .collect()
}

/// Collects logged VSS private shares for the local receiver and returns
/// complaint payloads for any share that fails its public check.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verify_logged_in_process_scalar_vss_receiver_shares<P, T, L>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    public_checks: &[InProcessScalarVssPublicCheck],
) -> Result<Vec<DkgComplaintPayload>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let receiver = runtime.local_party();
    let shares = runtime.collect_vss_share_round_logged(receiver)?;
    verify_logged_in_process_scalar_vss_receiver_payloads::<P>(
        config,
        receiver,
        public_checks,
        &shares,
    )
}

/// Recovers logged VSS private shares for the local receiver and returns
/// complaint payloads without using transport queues.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verify_logged_in_process_scalar_vss_receiver_shares_from_log<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    public_checks: &[InProcessScalarVssPublicCheck],
) -> Result<Vec<DkgComplaintPayload>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let receiver = runtime.local_party();
    let shares = runtime.recover_vss_share_round_from_log(receiver)?;
    verify_logged_in_process_scalar_vss_receiver_payloads::<P>(
        config,
        receiver,
        public_checks,
        &shares,
    )
}

/// Collects logged vector/polynomial VSS private shares for the local receiver
/// and returns complaint payloads for any dealer vector that fails its public
/// checks.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verify_logged_in_process_scalar_vss_receiver_vector_shares<P, T, L>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    public_check_vectors: &[Vec<InProcessScalarVssPublicCheck>],
) -> Result<Vec<DkgComplaintPayload>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let receiver = runtime.local_party();
    let shares = runtime.collect_vss_share_round_logged(receiver)?;
    verify_logged_in_process_scalar_vss_receiver_vector_payloads::<P>(
        config,
        receiver,
        public_check_vectors,
        &shares,
    )
}

/// Recovers logged vector/polynomial VSS private shares for the local receiver
/// and verifies them without using transport queues.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verify_logged_in_process_scalar_vss_receiver_vector_shares_from_log<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    public_check_vectors: &[Vec<InProcessScalarVssPublicCheck>],
) -> Result<Vec<DkgComplaintPayload>, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let receiver = runtime.local_party();
    let shares = runtime.recover_vss_share_round_from_log(receiver)?;
    verify_logged_in_process_scalar_vss_receiver_vector_payloads::<P>(
        config,
        receiver,
        public_check_vectors,
        &shares,
    )
}

/// Combines accepted vector/polynomial scalar VSS deals coefficientwise.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn combine_accepted_in_process_scalar_vss_vector_deals<P: MlDsaParams>(
    config: &DkgConfig,
    dealer_vectors: &[Vec<InProcessScalarVssDeal>],
    complaints: &[DkgComplaintPayload],
) -> Result<Vec<InProcessScalarDkgOutput>, DkgError> {
    if dealer_vectors.is_empty() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Commit,
            expected: config.parties.len(),
            got: 0,
        });
    }
    let coefficient_count = dealer_vectors[0].len();
    if coefficient_count == 0 {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: 1,
            got: 0,
        });
    }
    for vector in dealer_vectors {
        if vector.len() != coefficient_count {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: coefficient_count,
                got: vector.len(),
            });
        }
    }

    let mut out = Vec::with_capacity(coefficient_count);
    for coefficient_index in 0..coefficient_count {
        let deals = dealer_vectors
            .iter()
            .map(|vector| vector[coefficient_index].clone())
            .collect::<Vec<_>>();
        out.push(combine_accepted_in_process_scalar_vss_deals::<P>(
            config, &deals, complaints,
        )?);
    }
    Ok(out)
}

/// Output of the scaffold native DKG assembly driver.
#[cfg(any(test, feature = "scaffold-dev"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct NativeDkgAssemblyScaffoldOutput {
    /// Transcript-bound public DKG output.
    pub public: DkgPublicOutput,
    /// Per-party key packages containing only retained `s1` shares.
    pub key_packages: Vec<DkgKeyPackage>,
    /// Public assembly certificate.
    pub certificate: PublicKeyAssemblyCertificate,
    /// Accepted dealer parties.
    pub accepted_dealers: Vec<PartyId>,
    /// Rejected dealer parties.
    pub rejected_dealers: Vec<PartyId>,
    /// Complaints included in setup resolution.
    pub complaints: Vec<DkgComplaintPayload>,
}

/// Release-valid native DKG assembly output.
///
/// This type is intentionally separate from `NativeDkgAssemblyScaffoldOutput`.
/// Production callers receive this type only after the certificate and every
/// key package pass the centralized release gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionNativeDkgAssemblyOutput {
    public: DkgPublicOutput,
    key_packages: Vec<DkgKeyPackage>,
    certificate: PublicKeyAssemblyCertificate,
    accepted_dealers: Vec<PartyId>,
    rejected_dealers: Vec<PartyId>,
    complaints: Vec<DkgComplaintPayload>,
}

impl ProductionNativeDkgAssemblyOutput {
    /// Validates and constructs release-valid native DKG assembly material.
    pub fn new(
        public: DkgPublicOutput,
        key_packages: Vec<DkgKeyPackage>,
        certificate: PublicKeyAssemblyCertificate,
        accepted_dealers: Vec<PartyId>,
        rejected_dealers: Vec<PartyId>,
        complaints: Vec<DkgComplaintPayload>,
    ) -> Result<Self, DkgError> {
        ensure_native_dkg_assembly_parts_allowed_for_release(&certificate, &key_packages)?;
        ensure_power2round_setup_binding_matches_config(&public.config, public.rho, &certificate)?;
        Ok(Self {
            public,
            key_packages,
            certificate,
            accepted_dealers,
            rejected_dealers,
            complaints,
        })
    }

    /// Validates and wraps a scaffold output as release-valid material.
    ///
    /// This conversion exists only for tests that assert scaffold material is
    /// rejected by release gates. Production assembly must call `new` with
    /// production-shaped parts directly.
    #[cfg(test)]
    pub fn try_from_assembled(output: NativeDkgAssemblyScaffoldOutput) -> Result<Self, DkgError> {
        Self::new(
            output.public,
            output.key_packages,
            output.certificate,
            output.accepted_dealers,
            output.rejected_dealers,
            output.complaints,
        )
    }

    /// Returns the transcript-bound public DKG output.
    pub const fn public(&self) -> &DkgPublicOutput {
        &self.public
    }

    /// Returns per-party release-valid key packages.
    pub fn key_packages(&self) -> &[DkgKeyPackage] {
        &self.key_packages
    }

    /// Returns the release-valid public assembly certificate.
    pub const fn certificate(&self) -> &PublicKeyAssemblyCertificate {
        &self.certificate
    }

    /// Returns accepted dealer parties.
    pub fn accepted_dealers(&self) -> &[PartyId] {
        &self.accepted_dealers
    }

    /// Returns rejected dealer parties.
    pub fn rejected_dealers(&self) -> &[PartyId] {
        &self.rejected_dealers
    }

    /// Returns setup complaints included in the public resolution transcript.
    pub fn complaints(&self) -> &[DkgComplaintPayload] {
        &self.complaints
    }

    /// Applies the complete production release context gate to this output.
    pub fn ensure_context_allowed_for_release<L, C>(
        &self,
        setup_log: &L,
        cursor_log: &C,
        readiness: ProductionNativeDkgCoordinatorReadiness,
        transport_evidence: &NativeDkgTransportEvidence,
    ) -> Result<DkgConfig, DkgError>
    where
        L: DkgWireMessageLog,
        C: DkgSetupPhaseCursorLog,
    {
        ensure_production_native_dkg_output_context_allowed_for_release(
            self,
            setup_log,
            cursor_log,
            readiness,
            transport_evidence,
        )
    }
}

/// In-memory runtime used by the native DKG scaffold coordinator.
///
/// This is an application/test harness over the crate transport interfaces,
/// not a production networking stack. Embedding software remains responsible
/// for providing authenticated private transport and reliable broadcast.
#[cfg(test)]
pub type InMemoryNativeDkgScaffoldRuntime = CursoredLoggedDkgTransportPartyRuntime<
    talus_wire::InMemoryTransport,
    InMemoryDkgWireMessageLog,
    InMemoryDkgSetupPhaseCursorLog,
>;

/// Full in-memory coordinator for the native DKG scaffold path.
///
/// The coordinator owns one runtime per party and routes messages between
/// those runtimes using `talus-wire`'s in-memory transport. It is deliberately
/// scaffold-shaped: sampler IT-VSS and scalar VSS use deterministic in-process
/// backends, while `Power2Round` is supplied by the caller. The value of this
/// type is sequencing: raw sampler residues, vector-domain sampler IT-VSS,
/// scalar VSS setup logs, certified `s1`/`s2` sampling, and public-key assembly
/// are driven end-to-end through the same logs used by restart/resume tests.
#[derive(Clone, Debug)]
#[cfg(test)]
pub struct InMemoryNativeDkgScaffoldCoordinator {
    config: DkgConfig,
    runtimes: Vec<InMemoryNativeDkgScaffoldRuntime>,
    private_offsets: Vec<usize>,
    broadcast_offsets: Vec<usize>,
}

#[cfg(test)]
impl InMemoryNativeDkgScaffoldCoordinator {
    /// Coordinator kind advertised by this scaffold harness.
    pub const COORDINATOR_KIND: NativeDkgCoordinatorKind =
        NativeDkgCoordinatorKind::InMemoryScaffold;

    /// This coordinator is never allowed on a production release path.
    pub const PRODUCTION_ALLOWED: bool = false;

    /// Creates one in-memory DKG setup runtime per configured party.
    pub fn new(config: DkgConfig) -> Result<Self, DkgError> {
        config.validate()?;
        let party_ids = config
            .parties
            .iter()
            .map(|party| party.0)
            .collect::<Vec<_>>();
        let mut runtimes = Vec::with_capacity(config.parties.len());
        for &party in &config.parties {
            let transport = talus_wire::InMemoryTransport::new(party.0, party_ids.clone())
                .map_err(map_transport_error)?;
            let state = DkgTransportStateMachine::new(config.clone(), party, transport)?;
            runtimes.push(CursoredLoggedDkgTransportPartyRuntime::new(
                LoggedDkgTransportPartyRuntime::new(state, InMemoryDkgWireMessageLog::default()),
                InMemoryDkgSetupPhaseCursorLog::default(),
            ));
        }
        let count = runtimes.len();
        Ok(Self {
            config,
            runtimes,
            private_offsets: vec![0; count],
            broadcast_offsets: vec![0; count],
        })
    }

    /// Returns the DKG config.
    pub const fn config(&self) -> &DkgConfig {
        &self.config
    }

    /// Returns this coordinator's release profile kind.
    pub const fn coordinator_kind(&self) -> NativeDkgCoordinatorKind {
        Self::COORDINATOR_KIND
    }

    /// Returns a release-readiness profile for this coordinator.
    ///
    /// The profile is intentionally not production-ready: it records the
    /// deterministic in-memory scheduler and scaffold backends so release gates
    /// fail before any certificate or setup artifact is mistaken for product
    /// output.
    pub fn production_readiness_profile(&self) -> ProductionNativeDkgCoordinatorReadiness {
        ProductionNativeDkgCoordinatorReadiness {
            coordinator: Self::COORDINATOR_KIND,
            setup_backend_id: DkgSetupBackendId::InProcessScaffold,
            it_vss_backend_id: ItVssBackendId::InProcessHashBindingScaffold,
            power2round_backend_id: {
                #[cfg(test)]
                {
                    Power2RoundBackendId::InsecureClearSimulator
                }
                #[cfg(not(test))]
                {
                    Power2RoundBackendId::ProductionItMpc
                }
            },
            it_vss_readiness: ProductionItVssReadiness::default(),
            it_mpc_readiness: ProductionItMpcReadiness::default(),
            application_transport_contract: false,
            reliable_broadcast_conformance: false,
            ml_kem_private_channels: false,
            ml_dsa_operational_identities: false,
            durable_restart_policy: false,
            no_scaffold_backends: false,
            external_review: false,
        }
    }

    /// Returns all party runtimes.
    pub fn runtimes(&self) -> &[InMemoryNativeDkgScaffoldRuntime] {
        &self.runtimes
    }

    /// Returns one party runtime.
    pub fn runtime(&self, party: PartyId) -> Result<&InMemoryNativeDkgScaffoldRuntime, DkgError> {
        let index = self.party_index(party)?;
        Ok(&self.runtimes[index])
    }

    fn party_index(&self, party: PartyId) -> Result<usize, DkgError> {
        self.config
            .parties
            .iter()
            .position(|known| *known == party)
            .ok_or(DkgError::UnknownParty(party))
    }

    fn route_new_broadcast_messages(&mut self) -> Result<(), DkgError> {
        let mut deliveries = Vec::new();
        for source_idx in 0..self.runtimes.len() {
            let local_party = self.runtimes[source_idx].local_party().0;
            deliveries.extend(
                self.runtimes[source_idx]
                    .runtime()
                    .state()
                    .transport()
                    .broadcast_deliveries()[self.broadcast_offsets[source_idx]..]
                    .iter()
                    .filter(|delivery| delivery.message.header.sender_party_id == local_party)
                    .cloned(),
            );
            self.broadcast_offsets[source_idx] = self.runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .broadcast_deliveries()
                .len();
        }
        for delivery in deliveries {
            for runtime in &mut self.runtimes {
                if runtime.local_party().0 == delivery.message.header.sender_party_id {
                    continue;
                }
                runtime
                    .runtime_mut()
                    .state_mut()
                    .transport_mut()
                    .inject_broadcast_delivery(delivery.observer_party_id, delivery.message.clone())
                    .map_err(map_transport_error)?;
            }
        }
        Ok(())
    }

    fn route_new_private_messages(&mut self) -> Result<(), DkgError> {
        let mut deliveries = Vec::new();
        for source_idx in 0..self.runtimes.len() {
            let local_party = self.runtimes[source_idx].local_party().0;
            deliveries.extend(
                self.runtimes[source_idx]
                    .runtime()
                    .state()
                    .transport()
                    .private_messages()[self.private_offsets[source_idx]..]
                    .iter()
                    .filter(|delivery| delivery.sender_party_id == local_party)
                    .cloned(),
            );
            self.private_offsets[source_idx] = self.runtimes[source_idx]
                .runtime()
                .state()
                .transport()
                .private_messages()
                .len();
        }
        for delivery in deliveries {
            let receiver_idx = self.party_index(PartyId(delivery.receiver_party_id))?;
            if self.runtimes[receiver_idx].local_party().0 == delivery.sender_party_id {
                continue;
            }
            self.runtimes[receiver_idx]
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .inject_private(
                    delivery.sender_party_id,
                    delivery.receiver_party_id,
                    delivery.message,
                )
                .map_err(map_transport_error)?;
        }
        Ok(())
    }

    fn clear_transport_queues(&mut self) {
        for runtime in &mut self.runtimes {
            runtime
                .runtime_mut()
                .state_mut()
                .transport_mut()
                .clear_queued_messages();
        }
        self.private_offsets.fill(0);
        self.broadcast_offsets.fill(0);
    }

    fn deterministic_small_residue<P: MlDsaParams>(
        &self,
        party: PartyId,
        index: usize,
    ) -> Result<u8, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        Ok(((index + usize::from(party.0)) % usize::from(eta.modulus())) as u8)
    }

    fn deterministic_small_contribution<P: MlDsaParams>(
        &self,
        party: PartyId,
        vector: SecretVectorKind,
        index: usize,
    ) -> Result<SmallResidueContribution, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        let label = SamplerLabel::new::<P>(&self.config, vector, index)?;
        Ok(SmallResidueContribution::new(
            party,
            label,
            eta,
            self.deterministic_small_residue::<P>(party, index)?,
        ))
    }

    fn deterministic_dealer_vector_contributions<P: MlDsaParams>(
        &self,
        dealer: PartyId,
        vector: SecretVectorKind,
    ) -> Result<Vec<SmallResidueContribution>, DkgError> {
        (0..vector.coefficient_count::<P>())
            .map(|index| self.deterministic_small_contribution::<P>(dealer, vector, index))
            .collect()
    }

    fn drive_raw_sampler_residue_rounds<P: MlDsaParams>(
        &mut self,
        receiver: PartyId,
    ) -> Result<(), DkgError> {
        let receiver_idx = self.party_index(receiver)?;
        let eta = SmallSecretEta::for_params::<P>()?;
        for vector in [SecretVectorKind::S1, SecretVectorKind::S2] {
            for index in 0..vector.coefficient_count::<P>() {
                let contributions = self
                    .config
                    .parties
                    .iter()
                    .copied()
                    .map(|party| self.deterministic_small_contribution::<P>(party, vector, index))
                    .collect::<Result<Vec<_>, _>>()?;
                for (runtime, contribution) in self.runtimes.iter_mut().zip(&contributions) {
                    runtime.drive_broadcast_small_residue(contribution)?;
                }
                self.route_new_broadcast_messages()?;
                let label = SamplerLabel::new::<P>(&self.config, vector, index)?;
                self.runtimes[receiver_idx].drive_collect_small_residue_round(label, eta)?;
                self.clear_transport_queues();
            }
        }
        Ok(())
    }

    fn drive_vector_sampler_it_vss<P, B>(
        &mut self,
        receiver: PartyId,
        backend: &mut B,
    ) -> Result<(), DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        let receiver_idx = self.party_index(receiver)?;
        for index in 0..self.runtimes.len() {
            let dealer = self.runtimes[index].local_party();
            let s1_contributions =
                self.deterministic_dealer_vector_contributions::<P>(dealer, SecretVectorKind::S1)?;
            let s2_contributions =
                self.deterministic_dealer_vector_contributions::<P>(dealer, SecretVectorKind::S2)?;
            self.runtimes[index].drive_share_small_residue_vector_batches_it_vss::<P, _>(
                backend,
                &self.config,
                &[
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S1,
                        contributions: s1_contributions,
                    },
                    SmallResidueVectorContributionBatch {
                        vector: SecretVectorKind::S2,
                        contributions: s2_contributions,
                    },
                ],
            )?;
        }
        self.route_new_broadcast_messages()?;
        let (_, public_commitments) =
            self.runtimes[receiver_idx].drive_collect_it_vss_public_commitments()?;
        let expected_keys = expected_sampler_vector_it_vss_keys(
            &self.config,
            &[SecretVectorKind::S1, SecretVectorKind::S2],
        )?;
        let public_commitments =
            select_expected_it_vss_public_commitments(&public_commitments, &expected_keys)?;
        self.route_new_private_messages()?;
        let (_, deliveries) =
            self.runtimes[receiver_idx].drive_collect_it_vss_private_delivery_round(receiver)?;
        let deliveries = select_expected_it_vss_private_deliveries(
            &self.config,
            receiver,
            &deliveries,
            &expected_keys,
        )?;
        let complaints = verify_it_vss_private_deliveries_for_receiver::<P, _>(
            backend,
            &self.config,
            receiver,
            &public_commitments,
            &deliveries,
        )?;
        for complaint in &complaints {
            self.runtimes[receiver_idx].drive_broadcast_vss_complaint(complaint)?;
        }
        self.runtimes[receiver_idx].persist_it_vss_complaint_phase_cursor(
            ProductionItVssComplaintPhase::BroadcastComplaints,
            DkgSetupPhaseCursorState::Sent,
            complaints.len(),
            complaints.len(),
        )?;
        self.clear_transport_queues();
        persist_logged_sampler_it_vss_artifacts_from_phase_logs::<P, _, _, _>(
            &self.config,
            self.runtimes[receiver_idx].runtime_mut(),
            backend,
        )?;
        Ok(())
    }

    fn scaffold_scalar_vss_deals<P: MlDsaParams>(
        &self,
        backend: &mut InProcessScalarItVssBackend,
    ) -> Result<Vec<Vec<InProcessScalarVssDeal>>, DkgError> {
        self.config
            .parties
            .iter()
            .map(|&dealer| {
                Ok(vec![
                    backend.deal::<P>(&self.config, dealer, Coeff::from(dealer.0))?,
                    backend.deal::<P>(&self.config, dealer, Coeff::from(dealer.0) + 10)?,
                ])
            })
            .collect()
    }

    fn drive_scalar_vss_setup<P: MlDsaParams>(
        &mut self,
        receiver: PartyId,
        backend: &mut InProcessScalarItVssBackend,
    ) -> Result<(), DkgError> {
        let receiver_idx = self.party_index(receiver)?;
        let dealer_vectors = self.scaffold_scalar_vss_deals::<P>(backend)?;
        let commits = dealer_vectors
            .iter()
            .map(|vector| {
                dkg_commit_from_in_process_scalar_vss_public_checks(
                    &vector
                        .iter()
                        .map(|deal| deal.public_check.clone())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        for (runtime, commit) in self.runtimes.iter_mut().zip(&commits) {
            runtime.drive_broadcast_vss_commit(commit)?;
        }
        self.route_new_broadcast_messages()?;
        self.runtimes[receiver_idx].drive_collect_vss_commit_round()?;
        self.clear_transport_queues();

        for (runtime, vector) in self.runtimes.iter_mut().zip(&dealer_vectors) {
            let receiver_shares = vector
                .iter()
                .map(|deal| {
                    deal.shares
                        .iter()
                        .find(|share| share.share.receiver == receiver)
                        .copied()
                        .ok_or(DkgError::MissingRoundMessages {
                            round: DkgRound::Share,
                            expected: 1,
                            got: 0,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            runtime.drive_send_vss_share(
                receiver,
                &dkg_share_from_in_process_scalar_vss_private_shares(&receiver_shares),
            )?;
        }
        self.route_new_private_messages()?;
        self.runtimes[receiver_idx].drive_collect_vss_share_round(receiver)?;
        self.clear_transport_queues();
        Ok(())
    }

    /// Drives the full native DKG scaffold and assembles the receiver's view.
    pub fn drive_setup_and_assemble<P, B>(
        &mut self,
        receiver: PartyId,
        rho: [u8; 32],
        sampler_seed: [u8; 32],
        sampler_it_vss_seed: [u8; 32],
        scalar_vss_seed: [u8; 32],
        power2round: &mut B,
    ) -> Result<NativeDkgAssemblyScaffoldOutput, DkgError>
    where
        P: MlDsaParams,
        B: MpcPower2RoundBackend,
        B::Evidence: Into<Power2RoundEvidence>,
    {
        self.config.validate()?;
        let receiver_idx = self.party_index(receiver)?;
        self.drive_raw_sampler_residue_rounds::<P>(receiver)?;
        let mut sampler_it_vss = DeterministicItVssTestBackend::new(sampler_it_vss_seed);
        self.drive_vector_sampler_it_vss::<P, _>(receiver, &mut sampler_it_vss)?;
        let mut scalar_vss = InProcessScalarItVssBackend::new(scalar_vss_seed);
        self.drive_scalar_vss_setup::<P>(receiver, &mut scalar_vss)?;
        let mut sampler = InProcessDistributedSmallSampler::new(sampler_seed);
        assemble_logged_native_dkg_scaffold_from_logs::<P, _, _, _>(
            &self.config,
            rho,
            self.runtimes[receiver_idx].runtime_mut(),
            &mut sampler,
            power2round,
        )
    }
}

/// Assembles native DKG output from logged setup state.
///
/// This is a scaffold/dev driver for tests. It is hidden from normal builds so
/// product callers cannot assemble release material through a generic
/// `MpcPower2RoundBackend`.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub fn assemble_logged_native_dkg_scaffold_from_logs<P, T, L, B>(
    config: &DkgConfig,
    rho: [u8; 32],
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
    power2round: &mut B,
) -> Result<NativeDkgAssemblyScaffoldOutput, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: MpcPower2RoundBackend,
    B::Evidence: Into<Power2RoundEvidence>,
{
    assemble_logged_native_dkg_from_logs_with_backend::<P, T, L, B>(
        config,
        rho,
        runtime,
        sampler,
        power2round,
        ItVssBackendId::InProcessHashBindingScaffold,
        DkgSetupBackendId::InProcessScaffold,
        vec![
            DkgReleaseBlocker::ScaffoldItVssAdapters,
            DkgReleaseBlocker::ProductionItVss,
            DkgReleaseBlocker::ProductionItMpc,
            DkgReleaseBlocker::TransportConformance,
        ],
    )
}

/// Assembles logged native DKG state that used the production IT-VSS backend
/// identity for the batched sampler path.
///
/// This removes the sampler IT-VSS scaffold adapter from assembly, but the
/// output is still not release material unless the caller also supplies a
/// production setup backend, production Power2Round evidence, completed
/// transport conformance, and an empty blocker set. The current wrapper keeps
/// the setup backend scaffold-marked because the surrounding scalar VSS and
/// assembly scheduler are still in-process test substrates.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub fn assemble_logged_native_dkg_with_production_it_vss_from_logs<P, T, L, B>(
    config: &DkgConfig,
    rho: [u8; 32],
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
    power2round: &mut B,
) -> Result<NativeDkgAssemblyScaffoldOutput, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: MpcPower2RoundBackend,
    B::Evidence: Into<Power2RoundEvidence>,
{
    assemble_logged_native_dkg_from_logs_with_backend::<P, T, L, B>(
        config,
        rho,
        runtime,
        sampler,
        power2round,
        ItVssBackendId::ProductionInformationChecking,
        DkgSetupBackendId::InProcessScaffold,
        vec![
            DkgReleaseBlocker::ProductionItMpc,
            DkgReleaseBlocker::TransportConformance,
        ],
    )
}

/// Assembles logged native DKG state with production IT-VSS, production setup
/// identity, typed production Power2Round output, and no release blockers.
///
/// This is the product-shaped assembly entry point for application-driven
/// native DKG logs. The caller must have already persisted production IT-VSS
/// public artifacts and driven the per-party production Power2Round phases to
/// a `ProductionPower2RoundOutput`.
pub fn assemble_logged_native_dkg_production_from_logs<P, T, L>(
    config: &DkgConfig,
    rho: [u8; 32],
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
    power2round_output: ProductionPower2RoundOutput,
) -> Result<ProductionNativeDkgAssemblyOutput, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let recovered =
        recover_logged_native_dkg_production_setup_from_logs::<P, T, L>(config, runtime, sampler)?;
    assemble_recovered_logged_native_dkg_production(config, rho, recovered, power2round_output)
}

/// Assembles logged native DKG state by recovering certified production setup
/// material, computing shared `t = A*s1+s2`, and driving production vector
/// Power2Round through the supplied prime-field MPC backend.
///
/// Test/dev compatibility path for native DKG assembly through a generic
/// `ItMpcPrimeFieldBackend`.
///
/// Normal production builds do not expose this function because the generic
/// backend trait still includes local-compatible substrates. Production callers
/// must drive the app-level vector IT-MPC runtime and pass the resulting
/// `ProductionPower2RoundOutput` to
/// `assemble_logged_native_dkg_production_from_logs`.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub fn assemble_logged_native_dkg_production_with_power2round_backend<P, T, L, B, M>(
    config: &DkgConfig,
    rho: [u8; 32],
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
    power2round: &mut ProductionItMpcPower2RoundBackend<B, M>,
) -> Result<ProductionNativeDkgAssemblyOutput, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: ItMpcPrimeFieldBackend<P>,
    M: Power2RoundMaskUseLog,
{
    let local_party = runtime.local_party();
    let recovered =
        recover_logged_native_dkg_production_setup_from_logs::<P, T, L>(config, runtime, sampler)?;
    let RecoveredLoggedNativeDkgSetup {
        material,
        s1_packages,
        setup_certificate,
        public_commitments,
        accepted_dealers,
        rejected_dealers,
        complaints,
    } = recovered;
    let shared_t = assemble_shared_t::<P>(config, rho, &material.s1, material.s2)?;
    let t_share = shared_t_party_share_vec::<P, B>(&shared_t, local_party, power2round.backend())?;
    let power2round_output =
        power2round.power2round_t1_from_share_vec::<P>(config, shared_t.assembly_label, t_share)?;
    let power2round_output = power2round_output.with_setup_input_hash(
        production_power2round_setup_input_hash(config, rho, &setup_certificate),
    );
    assemble_logged_native_dkg_production_parts(
        config,
        rho,
        s1_packages,
        setup_certificate,
        public_commitments,
        accepted_dealers,
        rejected_dealers,
        complaints,
        power2round_output,
    )
}

fn assemble_recovered_logged_native_dkg_production(
    config: &DkgConfig,
    rho: [u8; 32],
    recovered: RecoveredLoggedNativeDkgSetup,
    power2round_output: ProductionPower2RoundOutput,
) -> Result<ProductionNativeDkgAssemblyOutput, DkgError> {
    let RecoveredLoggedNativeDkgSetup {
        #[cfg(any(test, feature = "scaffold-dev"))]
            material: _,
        s1_packages,
        setup_certificate,
        public_commitments,
        accepted_dealers,
        rejected_dealers,
        complaints,
    } = recovered;
    assemble_logged_native_dkg_production_parts(
        config,
        rho,
        s1_packages,
        setup_certificate,
        public_commitments,
        accepted_dealers,
        rejected_dealers,
        complaints,
        power2round_output,
    )
}

fn assemble_logged_native_dkg_production_parts(
    config: &DkgConfig,
    rho: [u8; 32],
    s1_packages: Vec<DkgSecretShare>,
    setup_certificate: DkgSetupTranscriptCertificate,
    public_commitments: Vec<ItVssPublicCommitment>,
    accepted_dealers: Vec<PartyId>,
    rejected_dealers: Vec<PartyId>,
    complaints: Vec<DkgComplaintPayload>,
    power2round_output: ProductionPower2RoundOutput,
) -> Result<ProductionNativeDkgAssemblyOutput, DkgError> {
    let expected_power2round_setup_input_hash =
        production_power2round_setup_input_hash(config, rho, &setup_certificate);
    if power2round_output.setup_input_hash() != Some(expected_power2round_setup_input_hash) {
        return Err(DkgError::Power2RoundEvidenceRequired);
    }
    let (mut public, mut certificate) = assemble_public_output_from_production_power2round(
        config,
        rho,
        &accepted_dealers,
        power2round_output,
    )?;
    apply_production_it_vss_artifacts_to_public_output(
        &mut public,
        &public_commitments,
        &accepted_dealers,
    )?;
    certificate.setup = Some(setup_certificate);
    certificate.power2round_setup_input_hash = Some(expected_power2round_setup_input_hash);
    let key_packages =
        dkg_key_packages_from_public_output(&public, s1_packages, certificate.clone())?;

    ProductionNativeDkgAssemblyOutput::new(
        public,
        key_packages,
        certificate,
        accepted_dealers,
        rejected_dealers,
        complaints,
    )
}

struct RecoveredLoggedNativeDkgSetup {
    #[cfg(any(test, feature = "scaffold-dev"))]
    material: SharedMldsaSecretMaterial,
    s1_packages: Vec<DkgSecretShare>,
    setup_certificate: DkgSetupTranscriptCertificate,
    public_commitments: Vec<ItVssPublicCommitment>,
    accepted_dealers: Vec<PartyId>,
    rejected_dealers: Vec<PartyId>,
    complaints: Vec<DkgComplaintPayload>,
}

fn recover_logged_native_dkg_production_setup_from_logs<P, T, L>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
) -> Result<RecoveredLoggedNativeDkgSetup, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let expected_it_vss_backend = ItVssBackendId::ProductionInformationChecking;
    let s1 = sample_logged_small_polyvec_from_certified_log_for_backend::<P, _, _>(
        sampler,
        config,
        runtime,
        SecretVectorKind::S1,
        expected_it_vss_backend,
    )?;
    let _s2 = sample_logged_small_polyvec_from_certified_log_for_backend::<P, _, _>(
        sampler,
        config,
        runtime,
        SecretVectorKind::S2,
        expected_it_vss_backend,
    )?;

    let (public_commitments, resolution) =
        recover_logged_production_it_vss_artifacts_for_sampler(config, runtime)?;
    let accepted_dealers = resolution.accepted_dealers.clone();
    let rejected_dealers = resolution.rejected_dealers.clone();
    let complaints = resolution.complaints.clone();

    let s1_packages = sampled_s1_to_dkg_secret_shares::<P>(config, &s1)?;
    #[cfg(any(test, feature = "scaffold-dev"))]
    let material = SharedMldsaSecretMaterial { s1, s2: _s2 };
    let setup_certificate = DkgSetupTranscriptCertificate {
        setup_backend_id: DkgSetupBackendId::ProductionInformationTheoretic,
        sampler_s1_hash: hash_logged_small_sampler_vector::<P, _, _>(
            config,
            runtime,
            SecretVectorKind::S1,
        )?,
        sampler_s2_hash: hash_logged_small_sampler_vector::<P, _, _>(
            config,
            runtime,
            SecretVectorKind::S2,
        )?,
        vss_commit_hash: hash_dkg_commit_payloads(&[]),
        vss_share_hash: hash_dkg_share_payloads(&[]),
        complaint_hash: hash_dkg_complaint_payloads(&complaints),
        it_vss_public_artifact_hash: hash_it_vss_public_artifacts(&public_commitments),
        it_vss_resolution_hash: hash_it_vss_complaint_resolution(&resolution),
        it_vss_backend_id: expected_it_vss_backend,
        complaints: complaints.clone(),
        accepted_dealers: accepted_dealers.clone(),
        rejected_dealers: rejected_dealers.clone(),
        release_blockers: Vec::new(),
    };

    Ok(RecoveredLoggedNativeDkgSetup {
        #[cfg(any(test, feature = "scaffold-dev"))]
        material,
        s1_packages,
        setup_certificate,
        public_commitments,
        accepted_dealers,
        rejected_dealers,
        complaints,
    })
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn recover_logged_native_dkg_setup_from_logs<P, T, L>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
    expected_it_vss_backend: ItVssBackendId,
    setup_backend_id: DkgSetupBackendId,
    release_blockers: Vec<DkgReleaseBlocker>,
) -> Result<RecoveredLoggedNativeDkgSetup, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let s1 = sample_logged_small_polyvec_from_certified_log_for_backend::<P, _, _>(
        sampler,
        config,
        runtime,
        SecretVectorKind::S1,
        expected_it_vss_backend,
    )?;
    let s2 = sample_logged_small_polyvec_from_certified_log_for_backend::<P, _, _>(
        sampler,
        config,
        runtime,
        SecretVectorKind::S2,
        expected_it_vss_backend,
    )?;
    let public_check_vectors = recover_logged_in_process_scalar_vss_public_check_vectors(runtime)?;
    let mut complaints = verify_logged_in_process_scalar_vss_receiver_vector_shares_from_log::<
        P,
        _,
        _,
    >(config, runtime, &public_check_vectors)?;
    for complaint in runtime.recover_vss_complaint_round_from_log()? {
        if !complaints.contains(&complaint) {
            complaints.push(complaint);
        }
    }

    let scalar_complaint_resolution = resolve_in_process_scalar_vss_vector_complaints::<P>(
        config,
        &public_check_vectors,
        &complaints,
    )?;
    let (recovered_it_vss_public_commitments, recovered_it_vss_resolution) =
        runtime.recover_it_vss_artifacts_from_log()?;
    let recovered_it_vss_resolution = recovered_it_vss_resolution
        .as_ref()
        .ok_or(DkgError::MissingDkgSetupCertificate)?;
    validate_it_vss_complaint_resolution_for_backend(
        config,
        &recovered_it_vss_public_commitments,
        recovered_it_vss_resolution,
        expected_it_vss_backend,
    )?;
    if recovered_it_vss_resolution.accepted_dealers != scalar_complaint_resolution.accepted_dealers
        || recovered_it_vss_resolution.rejected_dealers
            != scalar_complaint_resolution.rejected_dealers
        || recovered_it_vss_resolution.complaints != complaints
    {
        return Err(DkgError::ComplaintEvidenceMismatch);
    }
    let accepted_dealers = recovered_it_vss_resolution.accepted_dealers.clone();
    let rejected_dealers = recovered_it_vss_resolution.rejected_dealers.clone();

    let material = SharedMldsaSecretMaterial { s1, s2 };
    let s1_packages = sampled_s1_to_dkg_secret_shares::<P>(config, &material.s1)?;
    let setup_certificate = DkgSetupTranscriptCertificate {
        setup_backend_id,
        sampler_s1_hash: hash_logged_small_sampler_vector::<P, _, _>(
            config,
            runtime,
            SecretVectorKind::S1,
        )?,
        sampler_s2_hash: hash_logged_small_sampler_vector::<P, _, _>(
            config,
            runtime,
            SecretVectorKind::S2,
        )?,
        vss_commit_hash: hash_dkg_commit_payloads(&runtime.recover_vss_commit_round_from_log()?),
        vss_share_hash: hash_dkg_share_payloads(
            &runtime.recover_vss_share_round_from_log(runtime.local_party())?,
        ),
        complaint_hash: hash_dkg_complaint_payloads(&complaints),
        it_vss_public_artifact_hash: hash_it_vss_public_artifacts(
            &recovered_it_vss_public_commitments,
        ),
        it_vss_resolution_hash: hash_it_vss_complaint_resolution(recovered_it_vss_resolution),
        it_vss_backend_id: expected_it_vss_backend,
        complaints: complaints.clone(),
        accepted_dealers: accepted_dealers.clone(),
        rejected_dealers: rejected_dealers.clone(),
        release_blockers,
    };

    Ok(RecoveredLoggedNativeDkgSetup {
        material,
        s1_packages,
        setup_certificate,
        public_commitments: recovered_it_vss_public_commitments,
        accepted_dealers,
        rejected_dealers,
        complaints,
    })
}

fn recover_logged_production_it_vss_artifacts_for_sampler<T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
) -> Result<(Vec<ItVssPublicCommitment>, ItVssComplaintResolution), DkgError>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let expected_backend = ItVssBackendId::ProductionInformationChecking;
    let expected_keys =
        expected_sampler_vector_it_vss_keys(config, &[SecretVectorKind::S1, SecretVectorKind::S2])?;

    let all_precommitments = runtime.recover_it_vss_public_precommitments_from_log()?;
    let precommitments =
        select_expected_it_vss_public_precommitments(&all_precommitments, &expected_keys)?;
    for precommitment in &precommitments {
        if precommitment.backend_id != expected_backend {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        let shares =
            runtime.recover_it_vss_public_coin_shares_from_log(precommitment.label_hash)?;
        production_it_vss_public_coin_transcript(config, precommitment.label_hash, &shares)?;
    }

    let (all_public_commitments, resolution) = runtime.recover_it_vss_artifacts_from_log()?;
    let public_commitments =
        select_expected_it_vss_public_commitments(&all_public_commitments, &expected_keys)?;
    for commitment in &public_commitments {
        if commitment.backend_id != expected_backend {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        if !precommitments.iter().any(|precommitment| {
            precommitment.dealer == commitment.dealer
                && precommitment.label_hash == commitment.label_hash
        }) {
            return Err(DkgError::ItVssCertificateMissingCommitment {
                dealer: commitment.dealer,
                label_hash: commitment.label_hash,
            });
        }
    }

    let resolution = resolution.ok_or(DkgError::MissingDkgSetupCertificate)?;
    validate_it_vss_complaint_resolution_for_backend(
        config,
        &public_commitments,
        &resolution,
        expected_backend,
    )?;
    ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release(config, runtime.wire_log())?;
    ensure_it_vss_public_coin_flow_complete_for_release(config, runtime.wire_log())?;
    ensure_it_vss_public_audit_consistency_complete_for_release(config, runtime.wire_log())?;
    Ok((public_commitments, resolution))
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn assemble_logged_native_dkg_from_logs_with_backend<P, T, L, B>(
    config: &DkgConfig,
    rho: [u8; 32],
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    sampler: &mut impl DistributedSmallSampler,
    power2round: &mut B,
    expected_it_vss_backend: ItVssBackendId,
    setup_backend_id: DkgSetupBackendId,
    release_blockers: Vec<DkgReleaseBlocker>,
) -> Result<NativeDkgAssemblyScaffoldOutput, DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: MpcPower2RoundBackend,
    B::Evidence: Into<Power2RoundEvidence>,
{
    let recovered = recover_logged_native_dkg_setup_from_logs::<P, T, L>(
        config,
        runtime,
        sampler,
        expected_it_vss_backend,
        setup_backend_id,
        release_blockers,
    )?;

    let (mut public, mut certificate) = assemble_public_output_scaffold::<P, B>(
        config,
        rho,
        recovered.material,
        &recovered.accepted_dealers,
        power2round,
    )?;
    apply_logged_vss_commitments_to_public_output(
        &mut public,
        runtime,
        &recovered.accepted_dealers,
    )?;
    certificate.setup = Some(recovered.setup_certificate);
    let key_packages =
        dkg_key_packages_from_public_output(&public, recovered.s1_packages, certificate.clone())?;

    Ok(NativeDkgAssemblyScaffoldOutput {
        public,
        key_packages,
        certificate,
        accepted_dealers: recovered.accepted_dealers,
        rejected_dealers: recovered.rejected_dealers,
        complaints: recovered.complaints,
    })
}

/// Resolves logged scaffold VSS complaints into IT-VSS public artifacts and
/// persists them as a setup phase before public-key assembly.
#[cfg(test)]
pub fn persist_logged_scaffold_it_vss_artifacts_from_logs<P, T, L>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
) -> Result<(Vec<ItVssPublicCommitment>, ItVssComplaintResolution), DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let mut public_commitments = Vec::new();
    public_commitments.extend(
        scaffold_it_vss_small_residue_public_commitments_from_logs::<P, _, _>(
            config,
            runtime,
            SecretVectorKind::S1,
        )?,
    );
    public_commitments.extend(
        scaffold_it_vss_small_residue_public_commitments_from_logs::<P, _, _>(
            config,
            runtime,
            SecretVectorKind::S2,
        )?,
    );

    let public_check_vectors = recover_logged_in_process_scalar_vss_public_check_vectors(runtime)?;
    let mut complaints = verify_logged_in_process_scalar_vss_receiver_vector_shares_from_log::<
        P,
        _,
        _,
    >(config, runtime, &public_check_vectors)?;
    for complaint in runtime.recover_vss_complaint_round_from_log()? {
        if !complaints.contains(&complaint) {
            complaints.push(complaint);
        }
    }
    let scalar_resolution = resolve_in_process_scalar_vss_vector_complaints::<P>(
        config,
        &public_check_vectors,
        &complaints,
    )?;
    let (vss_public_commitments, resolution) =
        scaffold_it_vss_resolution_from_in_process_scalar_vss_vector_resolution(
            config,
            &public_check_vectors,
            &complaints,
            &scalar_resolution,
        )?;
    public_commitments.extend(vss_public_commitments);
    runtime.persist_it_vss_artifacts_logged(&public_commitments, &resolution)?;
    Ok((public_commitments, resolution))
}

/// Resolves sampler IT-VSS public/private/complaint phases already present in
/// the durable setup log, then persists only the complaint-resolution artifact.
///
/// Public commitments must have been accepted through
/// `drive_share_small_residue_it_vss`/`drive_collect_it_vss_public_commitments`;
/// directed private deliveries must have been accepted through the private
/// delivery phase. This function does not mint sampler commitments from raw
/// residue rounds.
pub fn persist_logged_sampler_it_vss_artifacts_for_labels_from_phase_logs<P, T, L, B>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    backend: &B,
    labels: &[SamplerLabel],
) -> Result<(Vec<ItVssPublicCommitment>, ItVssComplaintResolution), DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: ProductionItVssBackend,
{
    config.validate()?;
    let expected_keys = expected_sampler_it_vss_keys(config, labels)?;
    let all_commitments = runtime.recover_it_vss_public_commitments_from_log()?;
    let public_commitments =
        select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)?;

    let receiver = runtime.local_party();
    let deliveries = runtime.recover_it_vss_private_delivery_round_from_log(receiver)?;
    let deliveries =
        select_expected_it_vss_private_deliveries(config, receiver, &deliveries, &expected_keys)?;
    let mut complaints = verify_it_vss_private_deliveries_for_receiver::<P, _>(
        backend,
        config,
        receiver,
        &public_commitments,
        &deliveries,
    )?;
    validate_it_vss_complaints_against_private_deliveries(
        config,
        &public_commitments,
        &deliveries,
        &complaints,
    )?;

    for complaint in runtime.recover_vss_complaint_round_from_log()? {
        let Ok(evidence) = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)
        else {
            continue;
        };
        let expected_label = expected_keys
            .iter()
            .any(|(_, label_hash)| *label_hash == evidence.label_hash);
        if !expected_label {
            return Err(DkgError::ItVssCertificateMissingCommitment {
                dealer: complaint.dealer,
                label_hash: evidence.label_hash,
            });
        }
        if !complaints.contains(&complaint) {
            complaints.push(complaint);
        }
    }

    let resolution = backend.resolve_complaints::<P>(config, &public_commitments, &complaints)?;
    runtime.persist_it_vss_resolution_logged(&resolution)?;
    Ok((public_commitments, resolution))
}

/// Resolves all logged sampler IT-VSS phases for every `s1` and `s2`
/// coefficient.
pub fn persist_logged_sampler_it_vss_artifacts_from_phase_logs<P, T, L, B>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    backend: &B,
) -> Result<(Vec<ItVssPublicCommitment>, ItVssComplaintResolution), DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: ProductionItVssBackend,
{
    persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs::<P, T, L, B>(
        config,
        runtime,
        backend,
        &[SecretVectorKind::S1, SecretVectorKind::S2],
    )
}

/// Resolves logged sampler IT-VSS phases for a batch of whole-vector
/// `s1`/`s2` sharings.
///
/// A valid complaint against any vector sharing rejects that dealer from the
/// whole batch because `ProductionItVssBackend::resolve_complaints` returns
/// accepted/rejected dealer sets, not per-label acceptances.
pub fn persist_logged_small_residue_vector_batch_it_vss_artifacts_from_phase_logs<P, T, L, B>(
    config: &DkgConfig,
    runtime: &mut LoggedDkgTransportPartyRuntime<T, L>,
    backend: &B,
    vectors: &[SecretVectorKind],
) -> Result<(Vec<ItVssPublicCommitment>, ItVssComplaintResolution), DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    B: ProductionItVssBackend,
{
    config.validate()?;
    if vectors.is_empty() {
        return Err(DkgError::EmptyPublicCommitments);
    }
    let expected_keys = expected_sampler_vector_it_vss_keys(config, vectors)?;
    let all_commitments = runtime.recover_it_vss_public_commitments_from_log()?;
    let public_commitments =
        select_expected_it_vss_public_commitments(&all_commitments, &expected_keys)?;

    let receiver = runtime.local_party();
    let deliveries = runtime.recover_it_vss_private_delivery_round_from_log(receiver)?;
    let deliveries =
        select_expected_it_vss_private_deliveries(config, receiver, &deliveries, &expected_keys)?;
    let mut complaints = verify_it_vss_private_deliveries_for_receiver::<P, _>(
        backend,
        config,
        receiver,
        &public_commitments,
        &deliveries,
    )?;
    validate_it_vss_complaints_against_private_deliveries(
        config,
        &public_commitments,
        &deliveries,
        &complaints,
    )?;

    for complaint in runtime.recover_vss_complaint_round_from_log()? {
        let Ok(evidence) = decode_it_vss_information_check_complaint_evidence(&complaint.evidence)
        else {
            continue;
        };
        let expected_label = expected_keys
            .iter()
            .any(|(_, label_hash)| *label_hash == evidence.label_hash);
        if !expected_label {
            return Err(DkgError::ItVssCertificateMissingCommitment {
                dealer: complaint.dealer,
                label_hash: evidence.label_hash,
            });
        }
        if !complaints.contains(&complaint) {
            complaints.push(complaint);
        }
    }

    let resolution = backend.resolve_complaints::<P>(config, &public_commitments, &complaints)?;
    runtime.persist_it_vss_resolution_logged(&resolution)?;
    Ok((public_commitments, resolution))
}

fn expected_sampler_it_vss_keys(
    config: &DkgConfig,
    labels: &[SamplerLabel],
) -> Result<Vec<(PartyId, [u8; 32])>, DkgError> {
    let mut keys = Vec::new();
    for &label in labels {
        if label.config_hash != config.transcript_hash() {
            return Err(DkgError::SmallSamplerLabelMismatch);
        }
        for &dealer in &config.parties {
            let sharing_label = ItVssSharingLabel::new(
                config,
                dealer,
                ItVssSharingDomain::for_secret_vector(label.vector),
                Some(label.coefficient_index),
            )?;
            let key = (dealer, sharing_label.label_hash);
            if keys.contains(&key) {
                return Err(DkgError::DuplicateItVssPublicCommitment {
                    dealer,
                    label_hash: sharing_label.label_hash,
                });
            }
            keys.push(key);
        }
    }
    Ok(keys)
}

fn expected_sampler_vector_it_vss_keys(
    config: &DkgConfig,
    vectors: &[SecretVectorKind],
) -> Result<Vec<(PartyId, [u8; 32])>, DkgError> {
    let mut keys = Vec::new();
    for &vector in vectors {
        for &dealer in &config.parties {
            let sharing_label = ItVssSharingLabel::new(
                config,
                dealer,
                ItVssSharingDomain::for_secret_vector(vector),
                None,
            )?;
            let key = (dealer, sharing_label.label_hash);
            if keys.contains(&key) {
                return Err(DkgError::DuplicateItVssPublicCommitment {
                    dealer,
                    label_hash: sharing_label.label_hash,
                });
            }
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Returns the whole-vector IT-VSS labels used by the native bounded sampler
/// for the given vector kinds. Applications use these labels to drive
/// post-commitment public-coin broadcasts before final production IT-VSS
/// metadata is accepted.
pub fn sampler_vector_it_vss_sharing_labels(
    config: &DkgConfig,
    vectors: &[SecretVectorKind],
) -> Result<Vec<ItVssSharingLabel>, DkgError> {
    config.validate()?;
    let mut labels = Vec::new();
    for &vector in vectors {
        for &dealer in &config.parties {
            let label = ItVssSharingLabel::new(
                config,
                dealer,
                ItVssSharingDomain::for_secret_vector(vector),
                None,
            )?;
            if labels
                .iter()
                .any(|seen: &ItVssSharingLabel| seen.label_hash == label.label_hash)
            {
                return Err(DkgError::DuplicateItVssPublicCommitment {
                    dealer,
                    label_hash: label.label_hash,
                });
            }
            labels.push(label);
        }
    }
    Ok(labels)
}

fn select_expected_it_vss_public_commitments(
    commitments: &[ItVssPublicCommitment],
    expected_keys: &[(PartyId, [u8; 32])],
) -> Result<Vec<ItVssPublicCommitment>, DkgError> {
    let mut out = Vec::with_capacity(expected_keys.len());
    for &(dealer, label_hash) in expected_keys {
        let matches = commitments
            .iter()
            .filter(|commitment| commitment.dealer == dealer && commitment.label_hash == label_hash)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [commitment] => out.push((*commitment).clone()),
            [] => {
                return Err(DkgError::ItVssCertificateMissingCommitment { dealer, label_hash });
            }
            _ => return Err(DkgError::DuplicateItVssPublicCommitment { dealer, label_hash }),
        }
    }
    Ok(out)
}

fn select_expected_it_vss_public_precommitments(
    precommitments: &[ItVssPublicPrecommitment],
    expected_keys: &[(PartyId, [u8; 32])],
) -> Result<Vec<ItVssPublicPrecommitment>, DkgError> {
    let mut out = Vec::with_capacity(expected_keys.len());
    for &(dealer, label_hash) in expected_keys {
        let matches = precommitments
            .iter()
            .filter(|precommitment| {
                precommitment.dealer == dealer && precommitment.label_hash == label_hash
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [precommitment] => out.push((*precommitment).clone()),
            [] => {
                return Err(DkgError::ItVssCertificateMissingCommitment { dealer, label_hash });
            }
            _ => return Err(DkgError::DuplicateItVssPublicCommitment { dealer, label_hash }),
        }
    }
    Ok(out)
}

fn select_expected_it_vss_private_deliveries(
    config: &DkgConfig,
    receiver: PartyId,
    deliveries: &[ItVssPrivateShareDelivery],
    expected_keys: &[(PartyId, [u8; 32])],
) -> Result<Vec<ItVssPrivateShareDelivery>, DkgError> {
    let mut out = Vec::new();
    for &(dealer, label_hash) in expected_keys {
        if dealer == receiver {
            continue;
        }
        let matches = deliveries
            .iter()
            .filter(|delivery| {
                delivery.dealer == dealer
                    && delivery.receiver == receiver
                    && delivery.label_hash == label_hash
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [delivery] => out.push((*delivery).clone()),
            [] => {
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: config.parties.len().saturating_sub(1),
                    got: out.len(),
                });
            }
            _ => return Err(DkgError::DuplicateShare { dealer, receiver }),
        }
    }
    Ok(out)
}

fn unique_it_vss_private_delivery_dealers(
    deliveries: &[ItVssPrivateShareDelivery],
) -> Vec<PartyId> {
    let mut dealers = Vec::new();
    for delivery in deliveries {
        if !dealers.contains(&delivery.dealer) {
            dealers.push(delivery.dealer);
        }
    }
    dealers
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn verify_logged_in_process_scalar_vss_receiver_payloads<P: MlDsaParams>(
    config: &DkgConfig,
    receiver: PartyId,
    public_checks: &[InProcessScalarVssPublicCheck],
    shares: &[DkgSharePayload],
) -> Result<Vec<DkgComplaintPayload>, DkgError> {
    config.validate()?;
    let mut complaints = Vec::new();
    for payload in shares {
        if !is_in_process_scalar_vss_private_share_payload(payload) {
            continue;
        }
        if payload.receiver != receiver {
            return Err(DkgError::PartyMismatch {
                expected: receiver,
                got: payload.receiver,
            });
        }
        let private_share = in_process_scalar_vss_private_share_from_dkg_share(payload)?;
        let Some(public_check) = public_checks
            .iter()
            .find(|check| check.dealer == payload.dealer)
        else {
            return Err(DkgError::UnknownParty(payload.dealer));
        };
        if let Err(evidence) =
            verify_in_process_scalar_vss_share::<P>(config, public_check, &private_share)
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

#[cfg(any(test, feature = "scaffold-dev"))]
fn verify_logged_in_process_scalar_vss_receiver_vector_payloads<P: MlDsaParams>(
    config: &DkgConfig,
    receiver: PartyId,
    public_check_vectors: &[Vec<InProcessScalarVssPublicCheck>],
    shares: &[DkgSharePayload],
) -> Result<Vec<DkgComplaintPayload>, DkgError> {
    config.validate()?;
    let mut complaints = Vec::new();
    let mut complained_dealers = Vec::new();
    for payload in shares {
        if !is_in_process_scalar_vss_private_share_payload(payload) {
            continue;
        }
        if payload.receiver != receiver {
            return Err(DkgError::PartyMismatch {
                expected: receiver,
                got: payload.receiver,
            });
        }
        let private_shares = in_process_scalar_vss_private_shares_from_dkg_share(payload)?;
        let Some(public_checks) = public_check_vectors
            .iter()
            .find(|checks| checks.first().map(|check| check.dealer) == Some(payload.dealer))
        else {
            return Err(DkgError::UnknownParty(payload.dealer));
        };
        if public_checks.len() != private_shares.len() {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: public_checks.len(),
                got: private_shares.len(),
            });
        }
        for (public_check, private_share) in public_checks.iter().zip(&private_shares) {
            if let Err(evidence) =
                verify_in_process_scalar_vss_share::<P>(config, public_check, private_share)
            {
                if !complained_dealers.contains(&evidence.dealer) {
                    complaints.push(DkgComplaintPayload {
                        complainant: evidence.receiver,
                        dealer: evidence.dealer,
                        receiver: evidence.receiver,
                        reason: DkgComplaintReason::InvalidVssShare,
                        evidence: evidence.to_canonical_bytes(),
                    });
                    complained_dealers.push(evidence.dealer);
                }
                break;
            }
        }
    }
    Ok(complaints)
}

#[cfg(any(test, feature = "scaffold-dev"))]
fn apply_logged_vss_commitments_to_public_output<T, L>(
    output: &mut DkgPublicOutput,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    accepted_dealers: &[PartyId],
) -> Result<(), DkgError>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let commits = runtime.recover_vss_commit_round_from_log()?;
    validate_accepted_dealer_subset(&output.config, accepted_dealers)?;
    validate_exact_party_set(
        &output.config,
        DkgRound::Commit,
        commits.iter().map(|commit| commit.dealer),
    )?;
    let accepted_commits = commits
        .iter()
        .filter(|commit| accepted_dealers.contains(&commit.dealer))
        .collect::<Vec<_>>();
    output.vss_commitments = accepted_commits
        .iter()
        .flat_map(|commit| commit.vss_commitments.iter().cloned())
        .collect();
    output.pairwise_seed_commitments = commits
        .iter()
        .map(|commit| commit.pairwise_seed_commitment.clone())
        .collect();
    output.keygen_transcript_hash = output.transcript_binding();
    output.validate_binding()
}

fn production_it_vss_dealer_commitment_summary(
    config: &DkgConfig,
    dealer: PartyId,
    commitments: &[ItVssPublicCommitment],
) -> Result<[u8; 32], DkgError> {
    if !config.parties.contains(&dealer) {
        return Err(DkgError::UnknownParty(dealer));
    }
    let mut dealer_commitments = commitments
        .iter()
        .filter(|commitment| commitment.dealer == dealer)
        .collect::<Vec<_>>();
    if dealer_commitments.is_empty() {
        return Err(DkgError::ItVssCertificateMissingCommitment {
            dealer,
            label_hash: [0u8; 32],
        });
    }
    dealer_commitments.sort_by_key(|commitment| commitment.label_hash);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/production-it-vss-dealer-public-summary");
    hasher.update(config.transcript_hash().0);
    hasher.update(dealer.0.to_le_bytes());
    hasher.update((dealer_commitments.len() as u32).to_le_bytes());
    for commitment in dealer_commitments {
        if commitment.backend_id != ItVssBackendId::ProductionInformationChecking {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        hasher.update(hash_it_vss_public_commitment(commitment));
    }
    Ok(hasher.finalize().into())
}

fn apply_production_it_vss_artifacts_to_public_output(
    output: &mut DkgPublicOutput,
    public_commitments: &[ItVssPublicCommitment],
    accepted_dealers: &[PartyId],
) -> Result<(), DkgError> {
    validate_accepted_dealer_subset(&output.config, accepted_dealers)?;
    let expected_keys = expected_sampler_vector_it_vss_keys(
        &output.config,
        &[SecretVectorKind::S1, SecretVectorKind::S2],
    )?;
    let selected_commitments =
        select_expected_it_vss_public_commitments(public_commitments, &expected_keys)?;
    if selected_commitments.len() != expected_keys.len() {
        return Err(DkgError::MissingDkgSetupCertificate);
    }
    output.vss_commitments = selected_commitments
        .iter()
        .filter(|commitment| accepted_dealers.contains(&commitment.dealer))
        .map(|commitment| VssCommitment {
            bytes: encode_it_vss_public_commitment_artifact(commitment),
        })
        .collect();
    output.pairwise_seed_commitments = output
        .config
        .parties
        .iter()
        .copied()
        .map(|party| {
            Ok(PairwiseSeedCommitment {
                party,
                commitment: production_it_vss_dealer_commitment_summary(
                    &output.config,
                    party,
                    &selected_commitments,
                )?,
            })
        })
        .collect::<Result<Vec<_>, DkgError>>()?;
    output.keygen_transcript_hash = output.transcript_binding();
    output.validate_binding()
}

fn validate_accepted_dealer_subset(
    config: &DkgConfig,
    accepted_dealers: &[PartyId],
) -> Result<(), DkgError> {
    let mut seen = Vec::with_capacity(accepted_dealers.len());
    for &dealer in accepted_dealers {
        if !config.parties.contains(&dealer) {
            return Err(DkgError::UnknownParty(dealer));
        }
        if seen.contains(&dealer) {
            return Err(DkgError::DuplicateRoundSender {
                round: DkgRound::Commit,
                sender: dealer,
            });
        }
        seen.push(dealer);
    }
    if seen.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: seen.len(),
        });
    }
    Ok(())
}

fn validate_dealer_subset(
    config: &DkgConfig,
    round: DkgRound,
    dealers: &[PartyId],
) -> Result<(), DkgError> {
    let mut seen = Vec::with_capacity(dealers.len());
    for &dealer in dealers {
        if !config.parties.contains(&dealer) {
            return Err(DkgError::UnknownParty(dealer));
        }
        if seen.contains(&dealer) {
            return Err(DkgError::DuplicateRoundSender {
                round,
                sender: dealer,
            });
        }
        seen.push(dealer);
    }
    Ok(())
}

fn hash_logged_small_sampler_vector<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    vector: SecretVectorKind,
) -> Result<[u8; 32], DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let eta = SmallSecretEta::for_params::<P>()?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/certificate/small-sampler-vector");
    hasher.update([vector.as_u8()]);
    hasher.update((vector.coefficient_count::<P>() as u32).to_le_bytes());
    for index in 0..vector.coefficient_count::<P>() {
        let label = SamplerLabel::new::<P>(config, vector, index)?;
        let mut contributions = runtime.recover_small_residue_round_from_log(label, eta)?;
        contributions.sort_by_key(|contribution| contribution.dealer);
        hasher.update((index as u32).to_le_bytes());
        hasher.update((contributions.len() as u32).to_le_bytes());
        for contribution in contributions {
            hasher.update(contribution.dealer.0.to_le_bytes());
            hasher.update([contribution.eta.modulus()]);
            hasher.update([contribution.residue]);
            hasher.update((contribution.bits.len() as u32).to_le_bytes());
            hasher.update(&contribution.bits);
        }
    }
    Ok(hasher.finalize().into())
}

fn hash_dkg_commit_payloads(commits: &[DkgCommitPayload]) -> [u8; 32] {
    let mut ordered = commits.to_vec();
    ordered.sort_by_key(|commit| commit.dealer);
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/certificate/vss-commits");
    for commit in &ordered {
        hasher.update(commit.dealer.0.to_le_bytes());
        hash_len_prefixed_vecs(
            &mut hasher,
            commit.vss_commitments.iter().map(|item| &item.bytes),
        );
        hasher.update(commit.pairwise_seed_commitment.party.0.to_le_bytes());
        hasher.update(commit.pairwise_seed_commitment.commitment);
    }
    hasher.finalize().into()
}

fn hash_dkg_share_payloads(shares: &[DkgSharePayload]) -> [u8; 32] {
    let mut ordered = shares.to_vec();
    ordered.sort_by_key(|share| (share.dealer, share.receiver));
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/certificate/vss-shares");
    for share in &ordered {
        hasher.update(share.dealer.0.to_le_bytes());
        hasher.update(share.receiver.0.to_le_bytes());
        hash_bytes(&mut hasher, &share.encrypted_share);
        hash_bytes(&mut hasher, &share.encrypted_seed_share);
        hash_bytes(&mut hasher, &share.proof);
    }
    hasher.finalize().into()
}

fn hash_dkg_complaint_payloads(complaints: &[DkgComplaintPayload]) -> [u8; 32] {
    let mut ordered = complaints.to_vec();
    ordered.sort_by_key(|complaint| {
        (
            complaint.complainant,
            complaint.dealer,
            complaint.receiver,
            complaint.reason.as_u8(),
        )
    });
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-v1/certificate/vss-complaints");
    for complaint in &ordered {
        hasher.update(complaint.complainant.0.to_le_bytes());
        hasher.update(complaint.dealer.0.to_le_bytes());
        hasher.update(complaint.receiver.0.to_le_bytes());
        hasher.update([complaint.reason.as_u8()]);
        hash_bytes(&mut hasher, &complaint.evidence);
    }
    hasher.finalize().into()
}

fn hash_it_vss_public_artifacts(public_commitments: &[ItVssPublicCommitment]) -> [u8; 32] {
    let mut hashes = public_commitments
        .iter()
        .map(hash_it_vss_public_commitment)
        .collect::<Vec<_>>();
    hashes.sort();
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-artifact-set");
    hasher.update((hashes.len() as u32).to_le_bytes());
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

/// Cursor-aware logged DKG setup runtime.
#[derive(Clone, Debug)]
pub struct CursoredLoggedDkgTransportPartyRuntime<T, L, C> {
    runtime: LoggedDkgTransportPartyRuntime<T, L>,
    cursor_log: C,
}

impl<T, L, C> CursoredLoggedDkgTransportPartyRuntime<T, L, C>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    C: DkgSetupPhaseCursorLog,
{
    /// Creates a cursor-aware logged DKG setup runtime.
    pub fn new(runtime: LoggedDkgTransportPartyRuntime<T, L>, cursor_log: C) -> Self {
        Self {
            runtime,
            cursor_log,
        }
    }

    /// Returns the local party.
    pub fn local_party(&self) -> PartyId {
        self.runtime.local_party()
    }

    /// Returns the wrapped logged runtime.
    pub fn runtime(&self) -> &LoggedDkgTransportPartyRuntime<T, L> {
        &self.runtime
    }

    /// Returns the mutable wrapped logged runtime.
    pub fn runtime_mut(&mut self) -> &mut LoggedDkgTransportPartyRuntime<T, L> {
        &mut self.runtime
    }

    /// Returns the setup cursor log.
    pub fn cursor_log(&self) -> &C {
        &self.cursor_log
    }

    /// Returns the mutable setup cursor log.
    pub fn cursor_log_mut(&mut self) -> &mut C {
        &mut self.cursor_log
    }

    /// Replays locally sent messages and returns the latest setup cursor.
    pub fn resume(&mut self) -> Result<Option<DkgSetupPhaseCursor>, DkgError> {
        self.runtime.resume_sent_messages()?;
        Ok(self.cursor_log.latest_setup_phase_cursor().cloned())
    }

    /// Broadcasts a small-residue contribution and persists a coefficient
    /// cursor.
    pub fn drive_broadcast_small_residue(
        &mut self,
        contribution: &SmallResidueContribution,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime.broadcast_small_residue_logged(contribution)?;
        let status = DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::SmallResidue,
        };
        self.cursor_log.persist_setup_phase_cursor(
            &DkgSetupPhaseCursor::from_driver_status(&status)
                .with_sampler_label(contribution.label),
        )?;
        Ok(status)
    }

    /// Broadcasts an IT-VSS public commitment and persists a cursor.
    pub fn drive_broadcast_it_vss_public_commitment(
        &mut self,
        commitment: &ItVssPublicCommitment,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime
            .broadcast_it_vss_public_commitment_logged(commitment)?;
        let status = DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::ItVssArtifact,
        };
        self.cursor_log.persist_setup_phase_cursor(
            &DkgSetupPhaseCursor::from_driver_status(&status)
                .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
        )?;
        Ok(status)
    }

    /// Broadcasts an IT-VSS public precommitment and persists a cursor.
    pub fn drive_broadcast_it_vss_public_precommitment(
        &mut self,
        precommitment: &ItVssPublicPrecommitment,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime
            .broadcast_it_vss_public_precommitment_logged(precommitment)?;
        let status = DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::ItVssArtifact,
        };
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicPrecommitments),
                expected: 1,
                got: 1,
            })?;
        Ok(status)
    }

    /// Shares this party's bounded-sampler residue through the IT-VSS backend
    /// and drives the corresponding public-commitment and private-delivery
    /// transport phases.
    pub fn drive_share_small_residue_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        contribution: &SmallResidueContribution,
    ) -> Result<ItVssDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        if contribution.dealer != self.local_party() {
            return Err(DkgError::PartyMismatch {
                expected: self.local_party(),
                got: contribution.dealer,
            });
        }
        let output = it_vss_share_small_residue_contribution::<P, _>(
            backend,
            config,
            contribution.label,
            contribution.eta,
            contribution,
        )?;
        self.persist_it_vss_complaint_phase_cursor(
            ProductionItVssComplaintPhase::BroadcastPublicCommitments,
            DkgSetupPhaseCursorState::Sent,
            1,
            1,
        )?;
        self.drive_broadcast_it_vss_public_commitment(&output.public_commitment)?;

        let mut sent = 0usize;
        for delivery in &output.deliveries {
            if delivery.receiver == self.local_party() {
                continue;
            }
            self.drive_send_it_vss_private_delivery(delivery)?;
            sent += 1;
        }
        self.persist_it_vss_complaint_phase_cursor(
            ProductionItVssComplaintPhase::DeliverPrivateShares,
            DkgSetupPhaseCursorState::Sent,
            config.parties.len().saturating_sub(1),
            sent,
        )?;
        Ok(output)
    }

    /// Shares this party's full bounded-sampler residue vector through the
    /// IT-VSS backend and drives the public-commitment and private-delivery
    /// phases using the vector-domain sampler label.
    pub fn drive_share_small_residue_vector_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        vector: SecretVectorKind,
        contributions: &[SmallResidueContribution],
    ) -> Result<ItVssDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        let dealer = self.local_party();
        let eta = SmallSecretEta::for_params::<P>()?;
        if contributions
            .iter()
            .any(|contribution| contribution.dealer != dealer)
        {
            let got = contributions
                .iter()
                .find(|contribution| contribution.dealer != dealer)
                .map(|contribution| contribution.dealer)
                .unwrap_or(dealer);
            return Err(DkgError::PartyMismatch {
                expected: dealer,
                got,
            });
        }
        let output = it_vss_share_small_residue_vector_contribution::<P, _>(
            backend,
            config,
            vector,
            eta,
            dealer,
            contributions,
        )?;
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: Some(vector),
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicCommitments),
                expected: 1,
                got: 1,
            })?;
        self.runtime
            .broadcast_it_vss_public_commitment_logged(&output.public_commitment)?;

        let mut sent = 0usize;
        for &receiver in &config.parties {
            if receiver == dealer {
                continue;
            }
            let receiver_deliveries = output
                .deliveries
                .iter()
                .filter(|delivery| delivery.receiver == receiver)
                .cloned()
                .collect::<Vec<_>>();
            self.runtime
                .send_it_vss_private_delivery_batch_logged(receiver, &receiver_deliveries)?;
            let status = DkgTransportPhaseDriverStatus::SentPrivate {
                phase: DkgTransportPhase::VssShare,
                receiver,
            };
            self.cursor_log.persist_setup_phase_cursor(
                &DkgSetupPhaseCursor::from_driver_status(&status)
                    .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
            )?;
            sent += receiver_deliveries.len();
        }
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::VssShare,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: Some(vector),
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::DeliverPrivateShares),
                expected: config.parties.len().saturating_sub(1),
                got: sent,
            })?;
        Ok(output)
    }

    /// Shares this party's bounded-sampler residue vector batch through the
    /// IT-VSS backend and drives all public-commitment/private-delivery
    /// messages for the batch. For native DKG this is the app-facing path for
    /// emitting one `s1` and one `s2` vector commitment for a dealer.
    pub fn drive_share_small_residue_vector_batches_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        batches: &[SmallResidueVectorContributionBatch],
    ) -> Result<ItVssBatchedDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        let dealer = self.local_party();
        let eta = SmallSecretEta::for_params::<P>()?;
        for batch in batches {
            if batch
                .contributions
                .iter()
                .any(|contribution| contribution.dealer != dealer)
            {
                let got = batch
                    .contributions
                    .iter()
                    .find(|contribution| contribution.dealer != dealer)
                    .map(|contribution| contribution.dealer)
                    .unwrap_or(dealer);
                return Err(DkgError::PartyMismatch {
                    expected: dealer,
                    got,
                });
            }
        }
        let output = it_vss_share_small_residue_vector_batches::<P, _>(
            backend, config, eta, dealer, batches,
        )?;
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicCommitments),
                expected: output.public_commitments.len(),
                got: output.public_commitments.len(),
            })?;
        self.runtime
            .broadcast_it_vss_public_commitment_batch_logged(&output.public_commitments)?;

        let mut sent = 0usize;
        for &receiver in &config.parties {
            if receiver == dealer {
                continue;
            }
            let receiver_deliveries = output
                .deliveries
                .iter()
                .filter(|delivery| delivery.receiver == receiver)
                .cloned()
                .collect::<Vec<_>>();
            self.runtime
                .send_it_vss_private_delivery_batch_logged(receiver, &receiver_deliveries)?;
            let status = DkgTransportPhaseDriverStatus::SentPrivate {
                phase: DkgTransportPhase::VssShare,
                receiver,
            };
            self.cursor_log.persist_setup_phase_cursor(
                &DkgSetupPhaseCursor::from_driver_status(&status)
                    .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
            )?;
            sent += receiver_deliveries.len();
        }
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::VssShare,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::DeliverPrivateShares),
                expected: output.public_commitments.len() * config.parties.len().saturating_sub(1),
                got: sent,
            })?;
        Ok(output)
    }

    /// Collects a small-residue coefficient round and persists the cursor.
    pub fn drive_collect_small_residue_round(
        &mut self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<SmallResidueContribution>), DkgError> {
        match self.runtime.collect_small_residue_round_logged(label, eta) {
            Ok(values) => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::SmallResidue,
                    receiver: None,
                    senders: values.iter().map(|value| value.dealer).collect(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status).with_sampler_label(label),
                )?;
                Ok((status, values))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::SmallResidue,
                    expected: self.runtime.state.config.parties.len(),
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status).with_sampler_label(label),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    /// Broadcasts a VSS public-check commit and persists a cursor.
    pub fn drive_broadcast_vss_commit(
        &mut self,
        commit: &DkgCommitPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime.broadcast_vss_commit_logged(commit)?;
        let status = DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::VssCommit,
        };
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor::from_driver_status(&status))?;
        Ok(status)
    }

    /// Collects VSS commits and persists a cursor.
    pub fn drive_collect_vss_commit_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgCommitPayload>), DkgError> {
        match self.runtime.collect_vss_commit_round_logged() {
            Ok(values) => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssCommit,
                    receiver: None,
                    senders: values.iter().map(|value| value.dealer).collect(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
                )?;
                Ok((status, values))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::VssCommit,
                    expected: self.runtime.state.config.parties.len(),
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    /// Collects IT-VSS public commitments and persists a cursor.
    pub fn drive_collect_it_vss_public_commitments(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<ItVssPublicCommitment>), DkgError> {
        match self.runtime.collect_it_vss_public_commitments_logged() {
            Ok(values) => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::ItVssArtifact,
                    receiver: None,
                    senders: values.iter().map(|value| value.dealer).collect(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status).with_it_vss_phase(
                        ProductionItVssComplaintPhase::BroadcastPublicCommitments,
                    ),
                )?;
                Ok((status, values))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::ItVssArtifact,
                    expected: self.runtime.state.config.parties.len(),
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status).with_it_vss_phase(
                        ProductionItVssComplaintPhase::BroadcastPublicCommitments,
                    ),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    /// Collects IT-VSS public precommitments and persists a cursor.
    pub fn drive_collect_it_vss_public_precommitments(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<ItVssPublicPrecommitment>), DkgError> {
        match self.runtime.collect_it_vss_public_precommitments_logged() {
            Ok(values) => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::ItVssArtifact,
                    receiver: None,
                    senders: values.iter().map(|value| value.dealer).collect(),
                };
                self.cursor_log
                    .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                        phase: DkgTransportPhase::ItVssArtifact,
                        state: DkgSetupPhaseCursorState::Collected,
                        receiver: None,
                        vector: None,
                        coefficient_index: None,
                        it_vss_phase: Some(
                            ProductionItVssComplaintPhase::BroadcastPublicPrecommitments,
                        ),
                        expected: self.runtime.state.config.parties.len(),
                        got: values.len(),
                    })?;
                Ok((status, values))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::ItVssArtifact,
                    expected: self.runtime.state.config.parties.len(),
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status).with_it_vss_phase(
                        ProductionItVssComplaintPhase::BroadcastPublicPrecommitments,
                    ),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    /// Broadcasts one IT-VSS public-coin share and persists a cursor.
    pub fn drive_broadcast_it_vss_public_coin_share(
        &mut self,
        share: &ProductionItVssPublicCoinShare,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime
            .broadcast_it_vss_public_coin_share_logged(share)?;
        let status = DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::ItVssArtifact,
        };
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Sent,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicCoins),
                expected: 1,
                got: 1,
            })?;
        Ok(status)
    }

    /// Collects IT-VSS public-coin shares for one label and persists a cursor.
    pub fn drive_collect_it_vss_public_coin_transcript(
        &mut self,
        config: &DkgConfig,
        label_hash: [u8; 32],
    ) -> Result<
        (
            DkgTransportPhaseDriverStatus,
            ProductionItVssPublicCoinTranscript,
        ),
        DkgError,
    > {
        match self
            .runtime
            .collect_it_vss_public_coin_shares_logged(label_hash)
        {
            Ok(shares) => {
                let transcript =
                    production_it_vss_public_coin_transcript(config, label_hash, &shares)?;
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::ItVssArtifact,
                    receiver: None,
                    senders: shares.iter().map(|share| share.party).collect(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::BroadcastPublicCoins),
                )?;
                Ok((status, transcript))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::ItVssArtifact,
                    expected: config.parties.len(),
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::BroadcastPublicCoins),
                )?;
                Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Commit,
                    expected: config.parties.len(),
                    got: 0,
                })
            }
            Err(err) => Err(err),
        }
    }

    /// Persists an explicit IT-VSS complaint-resolution subphase cursor. This
    /// lets the embedding scheduler resume the public-commitment,
    /// private-delivery, verify, complaint, resolve, and certify phases without
    /// inferring them from generic transport records.
    pub fn persist_it_vss_complaint_phase_cursor(
        &mut self,
        phase: ProductionItVssComplaintPhase,
        state: DkgSetupPhaseCursorState,
        expected: usize,
        got: usize,
    ) -> Result<(), DkgError> {
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(phase),
                expected,
                got,
            })
    }

    /// Sends a VSS private-share payload and persists a cursor.
    pub fn drive_send_vss_share(
        &mut self,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime.send_vss_share_logged(receiver, share)?;
        let status = DkgTransportPhaseDriverStatus::SentPrivate {
            phase: DkgTransportPhase::VssShare,
            receiver,
        };
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor::from_driver_status(&status))?;
        Ok(status)
    }

    /// Sends an IT-VSS private delivery and persists a cursor.
    pub fn drive_send_it_vss_private_delivery(
        &mut self,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime.send_it_vss_private_delivery_logged(delivery)?;
        let status = DkgTransportPhaseDriverStatus::SentPrivate {
            phase: DkgTransportPhase::VssShare,
            receiver: delivery.receiver,
        };
        self.cursor_log.persist_setup_phase_cursor(
            &DkgSetupPhaseCursor::from_driver_status(&status)
                .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
        )?;
        Ok(status)
    }

    /// Collects VSS private-share payloads and persists a cursor.
    pub fn drive_collect_vss_share_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgSharePayload>), DkgError> {
        let expected = self.runtime.state.config.parties.len();
        match self.runtime.collect_vss_share_round_logged(receiver) {
            Ok(values) if values.len() == expected => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssShare,
                    receiver: Some(receiver),
                    senders: values.iter().map(|value| value.dealer).collect(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
                )?;
                Ok((status, values))
            }
            Ok(values) => {
                let status = DkgTransportPhaseDriverStatus::WaitingPrivate {
                    phase: DkgTransportPhase::VssShare,
                    receiver,
                    expected,
                    got: values.len(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
                )?;
                Ok((status, Vec::new()))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingPrivate {
                    phase: DkgTransportPhase::VssShare,
                    receiver,
                    expected,
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    /// Collects IT-VSS private deliveries and persists a cursor.
    pub fn drive_collect_it_vss_private_delivery_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<
        (
            DkgTransportPhaseDriverStatus,
            Vec<ItVssPrivateShareDelivery>,
        ),
        DkgError,
    > {
        let expected = self.runtime.state.config.parties.len().saturating_sub(1);
        match self
            .runtime
            .collect_it_vss_private_delivery_round_logged(receiver)
        {
            Ok(values) if unique_it_vss_private_delivery_dealers(&values).len() >= expected => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssShare,
                    receiver: Some(receiver),
                    senders: unique_it_vss_private_delivery_dealers(&values),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status)
                        .with_it_vss_phase(ProductionItVssComplaintPhase::DeliverPrivateShares),
                )?;
                Ok((status, values))
            }
            Ok(values) => {
                let got = unique_it_vss_private_delivery_dealers(&values).len();
                let status = DkgTransportPhaseDriverStatus::WaitingPrivate {
                    phase: DkgTransportPhase::VssShare,
                    receiver,
                    expected,
                    got,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status),
                )?;
                Ok((status, Vec::new()))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingPrivate {
                    phase: DkgTransportPhase::VssShare,
                    receiver,
                    expected,
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    /// Collects this receiver's IT-VSS private deliveries, verifies them
    /// against accepted public commitments, broadcasts any public complaints,
    /// and persists the verification/complaint subphase cursors.
    pub fn drive_verify_it_vss_private_deliveries<P, B>(
        &mut self,
        backend: &B,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
    ) -> Result<Vec<DkgComplaintPayload>, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        let receiver = self.local_party();
        let (_, deliveries) = self.drive_collect_it_vss_private_delivery_round(receiver)?;
        if deliveries.is_empty() && config.parties.len() > 1 {
            return Err(DkgError::PrimeFieldMpcTransport);
        }
        let complaints = verify_it_vss_private_deliveries_for_receiver::<P, _>(
            backend,
            config,
            receiver,
            public_commitments,
            &deliveries,
        )?;
        self.persist_it_vss_complaint_phase_cursor(
            ProductionItVssComplaintPhase::VerifyPrivateDeliveries,
            DkgSetupPhaseCursorState::Collected,
            config.parties.len().saturating_sub(1),
            deliveries.len(),
        )?;
        for complaint in &complaints {
            self.drive_broadcast_vss_complaint(complaint)?;
        }
        self.persist_it_vss_complaint_phase_cursor(
            ProductionItVssComplaintPhase::BroadcastComplaints,
            DkgSetupPhaseCursorState::Sent,
            complaints.len(),
            complaints.len(),
        )?;
        Ok(complaints)
    }

    /// Broadcasts a VSS complaint and persists a cursor.
    pub fn drive_broadcast_vss_complaint(
        &mut self,
        complaint: &DkgComplaintPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        self.runtime.broadcast_vss_complaint_logged(complaint)?;
        let status = DkgTransportPhaseDriverStatus::SentBroadcast {
            phase: DkgTransportPhase::VssComplaint,
        };
        self.cursor_log
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor::from_driver_status(&status))?;
        Ok(status)
    }

    /// Collects VSS complaints and persists a cursor.
    pub fn drive_collect_vss_complaint_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgComplaintPayload>), DkgError> {
        match self.runtime.collect_vss_complaint_round_logged() {
            Ok(values) => {
                let status = DkgTransportPhaseDriverStatus::Collected {
                    phase: DkgTransportPhase::VssComplaint,
                    receiver: None,
                    senders: values.iter().map(|value| value.complainant).collect(),
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status),
                )?;
                Ok((status, values))
            }
            Err(DkgError::PrimeFieldMpcTransport) => {
                let status = DkgTransportPhaseDriverStatus::WaitingBroadcast {
                    phase: DkgTransportPhase::VssComplaint,
                    expected: self.runtime.state.config.parties.len(),
                    got: 0,
                };
                self.cursor_log.persist_setup_phase_cursor(
                    &DkgSetupPhaseCursor::from_driver_status(&status),
                )?;
                Ok((status, Vec::new()))
            }
            Err(err) => Err(err),
        }
    }
}

/// Outbound native DKG wire message emitted by [`NativeDkgSession`].
///
/// The crate produces canonical TALUS wire messages only. The embedding
/// application owns actual networking, ML-KEM channel setup, ML-DSA identity
/// authentication, retries, and durable delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeDkgOutbound {
    /// Directed authenticated private delivery.
    Private {
        /// Authenticated receiver party id.
        receiver: PartyId,
        /// Canonical wire message to carry over the private channel.
        message: WireMessage,
    },
    /// Equivocation-resistant broadcast delivery.
    Broadcast {
        /// Canonical wire message to deliver through reliable broadcast.
        message: WireMessage,
    },
}

/// Options for starting a production-facing native DKG session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDkgSessionOptions {
    /// Public ML-DSA `rho` seed used to derive `A = ExpandA(rho)`.
    pub rho: [u8; 32],
    /// Fresh, session-bound entropy for local bounded-residue contributions.
    pub sampler_entropy: [u8; 32],
    /// Fresh, session-bound entropy for production IT-VSS masks/tags.
    pub it_vss_entropy: [u8; 32],
    /// Fresh, session-bound entropy for post-precommitment public-coin shares.
    pub public_coin_entropy: [u8; 32],
    /// Production IT-VSS security parameters.
    pub it_vss_security: ProductionItVssSecurityParams,
}

/// User-facing production native DKG session facade.
///
/// This is the narrow API applications should use for native DKG setup:
/// create a session, route private/broadcast messages through the app's
/// transport, drain outbound messages, then finish with a validated production
/// Power2Round output. The facade hides raw sampler rounds, IT-VSS
/// precommitment/public-coin/finalization sequencing, logs, cursors, and
/// complaint resolution behind a single state machine.
pub struct NativeDkgSession<P, L, C>
where
    P: MlDsaParams,
    L: DkgWireMessageLog,
    C: DkgSetupPhaseCursorLog,
{
    config: DkgConfig,
    rho: [u8; 32],
    sampler_entropy: [u8; 32],
    public_coin_entropy: [u8; 32],
    runtime: CursoredLoggedDkgTransportPartyRuntime<NativeDkgSessionTransport, L, C>,
    sampler: VerifiedDistributedSmallSampler,
    it_vss_backend: ProductionInformationCheckingVssBackend,
    prepared_it_vss: Vec<NativeDkgPreparedItVss>,
    public_coin_transcripts: Vec<ProductionItVssPublicCoinTranscript>,
    phase: NativeDkgSessionPhase,
    power2round_output: Option<ProductionPower2RoundOutput>,
    _params: PhantomData<P>,
}

impl<P, L, C> NativeDkgSession<P, L, C>
where
    P: MlDsaParams,
    L: DkgWireMessageLog,
    C: DkgSetupPhaseCursorLog,
{
    fn new_unadvanced(
        config: DkgConfig,
        local_party: PartyId,
        wire_log: L,
        cursor_log: C,
        options: NativeDkgSessionOptions,
    ) -> Result<Self, DkgError> {
        config.validate()?;
        if config.suite != DkgSuite::for_params::<P>() {
            return Err(DkgError::FinalOutputConfigMismatch);
        }
        if !config.parties.contains(&local_party) {
            return Err(DkgError::UnknownParty(local_party));
        }

        let transport = NativeDkgSessionTransport::new(local_party, &config);
        let state = DkgTransportStateMachine::new(config.clone(), local_party, transport)?;
        let runtime = LoggedDkgTransportPartyRuntime::new(state, wire_log);
        let runtime = CursoredLoggedDkgTransportPartyRuntime::new(runtime, cursor_log);
        let mut it_vss_backend = ProductionInformationCheckingVssBackend::with_params(
            options.it_vss_entropy,
            options.it_vss_security,
        )?;
        let prepared_it_vss = prepare_native_dkg_session_it_vss::<P>(
            &config,
            local_party,
            options.sampler_entropy,
            &mut it_vss_backend,
        )?;

        let session = Self {
            config,
            rho: options.rho,
            sampler_entropy: options.sampler_entropy,
            public_coin_entropy: options.public_coin_entropy,
            runtime,
            sampler: VerifiedDistributedSmallSampler::new(options.sampler_entropy),
            it_vss_backend,
            prepared_it_vss,
            public_coin_transcripts: Vec::new(),
            phase: NativeDkgSessionPhase::SmallResidue {
                vector_pos: 0,
                coeff_index: 0,
                sent: false,
            },
            power2round_output: None,
            _params: PhantomData,
        };
        Ok(session)
    }

    /// Starts a native DKG session for one local party.
    pub fn start(
        config: DkgConfig,
        local_party: PartyId,
        wire_log: L,
        cursor_log: C,
        options: NativeDkgSessionOptions,
    ) -> Result<Self, DkgError> {
        let mut session = Self::new_unadvanced(config, local_party, wire_log, cursor_log, options)?;
        session.advance()?;
        Ok(session)
    }

    /// Resumes a native DKG session from durable wire and cursor logs.
    ///
    /// This replays locally sent messages, reconstructs completed public-coin
    /// transcripts from accepted broadcast records, positions the app-driver
    /// state machine at the next incomplete vector IT-VSS phase, and then
    /// advances only as far as durable logs and currently queued messages
    /// permit.
    pub fn resume(
        config: DkgConfig,
        local_party: PartyId,
        wire_log: L,
        cursor_log: C,
        options: NativeDkgSessionOptions,
    ) -> Result<Self, DkgError> {
        let mut session = Self::new_unadvanced(config, local_party, wire_log, cursor_log, options)?;
        if session
            .runtime
            .cursor_log()
            .setup_phase_cursors()
            .iter()
            .any(|cursor| cursor.state == DkgSetupPhaseCursorState::Aborted)
        {
            return Err(DkgError::DkgSetupAbortedAfterRestart);
        }
        session.runtime.resume()?;
        session.public_coin_transcripts = session.recover_public_coin_transcripts_from_log()?;
        session.phase = session.resume_phase_from_logs()?;
        session.advance()?;
        Ok(session)
    }

    /// Returns the local party id.
    pub fn local_party(&self) -> PartyId {
        self.runtime.local_party()
    }

    /// Returns true once setup messages and IT-VSS resolution have completed.
    pub fn setup_complete(&self) -> bool {
        matches!(self.phase, NativeDkgSessionPhase::SetupComplete)
    }

    /// Returns the durable wire-message log owned by this session.
    pub fn wire_log(&self) -> &L {
        self.runtime.runtime().wire_log()
    }

    /// Returns the durable setup cursor log owned by this session.
    pub fn cursor_log(&self) -> &C {
        self.runtime.cursor_log()
    }

    /// Injects one application-authenticated private message addressed to this
    /// session's local party.
    pub fn handle_private(
        &mut self,
        sender: PartyId,
        message: WireMessage,
    ) -> Result<(), DkgError> {
        let receiver = self.local_party();
        self.runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .inject_private(sender, receiver, message)
            .map_err(map_transport_error)?;
        self.advance()
    }

    /// Injects one reliable-broadcast message delivered to this local party.
    pub fn handle_broadcast(&mut self, message: WireMessage) -> Result<(), DkgError> {
        let observer = self.local_party();
        self.runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .inject_broadcast(observer, message)
            .map_err(map_transport_error)?;
        self.advance()
    }

    /// Returns the next outbound message for the embedding application to
    /// deliver.
    pub fn next_outbound(&mut self) -> Option<NativeDkgOutbound> {
        self.runtime
            .runtime_mut()
            .state_mut()
            .transport_mut()
            .pop_outbound()
    }

    /// Installs the validated production Power2Round output needed by
    /// [`Self::finish`].
    pub fn set_power2round_output(&mut self, output: ProductionPower2RoundOutput) {
        self.power2round_output = Some(output);
    }

    /// Finishes DKG assembly and returns the release-valid production output.
    ///
    /// This succeeds only after setup is complete and a typed production
    /// Power2Round output has been installed.
    pub fn finish(mut self) -> Result<ProductionNativeDkgAssemblyOutput, DkgError> {
        self.advance()?;
        if !self.setup_complete() {
            return Err(DkgError::MissingDkgSetupCertificate);
        }
        let power2round_output = self
            .power2round_output
            .take()
            .ok_or(DkgError::Power2RoundEvidenceRequired)?;
        assemble_logged_native_dkg_production_from_logs::<P, _, _>(
            &self.config,
            self.rho,
            self.runtime.runtime_mut(),
            &mut self.sampler,
            power2round_output,
        )
    }

    /// Finishes DKG assembly and immediately applies the full release-context
    /// gate.
    ///
    /// This is the preferred application boundary for release material because
    /// it composes:
    ///
    /// - typed production native DKG output;
    /// - durable setup wire log;
    /// - durable setup phase cursors;
    /// - production coordinator/backend readiness;
    /// - ML-KEM / ML-DSA / reliable-broadcast transport evidence.
    pub fn finish_release_validated(
        mut self,
        readiness: ProductionNativeDkgCoordinatorReadiness,
        transport_evidence: &NativeDkgTransportEvidence,
    ) -> Result<ProductionNativeDkgAssemblyOutput, DkgError> {
        self.advance()?;
        if !self.setup_complete() {
            return Err(DkgError::MissingDkgSetupCertificate);
        }
        let power2round_output = self
            .power2round_output
            .take()
            .ok_or(DkgError::Power2RoundEvidenceRequired)?;
        let output = assemble_logged_native_dkg_production_from_logs::<P, _, _>(
            &self.config,
            self.rho,
            self.runtime.runtime_mut(),
            &mut self.sampler,
            power2round_output,
        )?;
        output.ensure_context_allowed_for_release(
            self.runtime.runtime().wire_log(),
            self.runtime.cursor_log(),
            readiness,
            transport_evidence,
        )?;
        Ok(output)
    }

    /// Finishes DKG assembly by driving the test/dev generic Power2Round
    /// backend from certified setup logs.
    ///
    /// Hidden from normal production builds because generic
    /// `ItMpcPrimeFieldBackend` substrates are not the final app-driven vector
    /// runtime.
    #[cfg(any(test, feature = "scaffold-dev"))]
    #[doc(hidden)]
    pub fn finish_with_power2round_backend<B, M>(
        mut self,
        power2round: &mut ProductionItMpcPower2RoundBackend<B, M>,
    ) -> Result<ProductionNativeDkgAssemblyOutput, DkgError>
    where
        B: ItMpcPrimeFieldBackend<P>,
        M: Power2RoundMaskUseLog,
    {
        self.advance()?;
        if !self.setup_complete() {
            return Err(DkgError::MissingDkgSetupCertificate);
        }
        assemble_logged_native_dkg_production_with_power2round_backend::<P, _, _, B, M>(
            &self.config,
            self.rho,
            self.runtime.runtime_mut(),
            &mut self.sampler,
            power2round,
        )
    }

    fn advance(&mut self) -> Result<(), DkgError> {
        loop {
            if self.runtime.runtime().state().transport().has_outbound() {
                return Ok(());
            }

            match self.phase {
                NativeDkgSessionPhase::SmallResidue {
                    vector_pos,
                    coeff_index,
                    sent,
                } => {
                    let vector = native_dkg_session_vectors()
                        .get(vector_pos)
                        .copied()
                        .ok_or(DkgError::Backend("invalid native DKG small-residue phase"))?;
                    let coeff_count = vector.coefficient_count::<P>();
                    if coeff_index >= coeff_count {
                        self.phase = NativeDkgSessionPhase::SmallResidue {
                            vector_pos: vector_pos + 1,
                            coeff_index: 0,
                            sent: false,
                        };
                        continue;
                    }
                    if !sent {
                        let contribution =
                            self.local_small_residue_contribution(vector, coeff_index)?;
                        self.runtime.drive_broadcast_small_residue(&contribution)?;
                        self.phase = NativeDkgSessionPhase::SmallResidue {
                            vector_pos,
                            coeff_index,
                            sent: true,
                        };
                        continue;
                    }
                    let eta = SmallSecretEta::for_params::<P>()?;
                    let label = SamplerLabel::new::<P>(&self.config, vector, coeff_index)?;
                    let (_, values) = self.runtime.drive_collect_small_residue_round(label, eta)?;
                    if values.len() == self.config.parties.len() {
                        let next_index = coeff_index + 1;
                        if next_index >= coeff_count
                            && vector_pos + 1 >= native_dkg_session_vectors().len()
                        {
                            self.phase = NativeDkgSessionPhase::Precommit {
                                vector_pos: 0,
                                sent: false,
                            };
                        } else if next_index >= coeff_count {
                            self.phase = NativeDkgSessionPhase::SmallResidue {
                                vector_pos: vector_pos + 1,
                                coeff_index: 0,
                                sent: false,
                            };
                        } else {
                            self.phase = NativeDkgSessionPhase::SmallResidue {
                                vector_pos,
                                coeff_index: next_index,
                                sent: false,
                            };
                        }
                        continue;
                    }
                    return Ok(());
                }
                NativeDkgSessionPhase::Precommit { vector_pos, sent } => {
                    let Some(vector) = native_dkg_session_vectors().get(vector_pos).copied() else {
                        self.phase = NativeDkgSessionPhase::PublicCoin {
                            label_pos: 0,
                            sent: false,
                        };
                        continue;
                    };
                    if !sent {
                        let precommitment = self
                            .prepared_it_vss
                            .iter()
                            .find(|prepared| prepared.vector == vector)
                            .ok_or(DkgError::MissingDkgSetupCertificate)?
                            .prepared
                            .as_ref()
                            .ok_or(DkgError::MissingDkgSetupCertificate)?
                            .public_precommitment
                            .clone();
                        self.runtime
                            .drive_broadcast_it_vss_public_precommitment(&precommitment)?;
                        self.phase = NativeDkgSessionPhase::Precommit {
                            vector_pos,
                            sent: true,
                        };
                        continue;
                    }
                    let precommitments = match self.collect_expected_it_vss_precommitments(vector) {
                        Ok(precommitments) => precommitments,
                        Err(DkgError::MissingRoundMessages { .. }) => return Ok(()),
                        Err(err) => return Err(err),
                    };
                    let expected_keys =
                        expected_sampler_vector_it_vss_keys(&self.config, &[vector])?;
                    let selected = select_expected_it_vss_public_precommitments(
                        &precommitments,
                        &expected_keys,
                    )?;
                    if selected.len() == self.config.parties.len() {
                        self.phase = NativeDkgSessionPhase::Precommit {
                            vector_pos: vector_pos + 1,
                            sent: false,
                        };
                        continue;
                    }
                    return Ok(());
                }
                NativeDkgSessionPhase::PublicCoin { label_pos, sent } => {
                    let labels = sampler_vector_it_vss_sharing_labels(
                        &self.config,
                        native_dkg_session_vectors(),
                    )?;
                    let Some(label) = labels.get(label_pos).copied() else {
                        self.phase = NativeDkgSessionPhase::FinalCommitments { sent: false };
                        continue;
                    };
                    if !sent {
                        let coin = self.public_coin(label.label_hash);
                        let share = production_it_vss_public_coin_share(
                            &self.config,
                            label.label_hash,
                            self.local_party(),
                            coin,
                        )?;
                        self.runtime
                            .drive_broadcast_it_vss_public_coin_share(&share)?;
                        self.phase = NativeDkgSessionPhase::PublicCoin {
                            label_pos,
                            sent: true,
                        };
                        continue;
                    }
                    match self.collect_expected_it_vss_public_coin_transcript(label.label_hash) {
                        Ok(transcript) => {
                            if !self
                                .public_coin_transcripts
                                .iter()
                                .any(|known| known.label_hash == transcript.label_hash)
                            {
                                self.public_coin_transcripts.push(transcript);
                            }
                            self.phase = NativeDkgSessionPhase::PublicCoin {
                                label_pos: label_pos + 1,
                                sent: false,
                            };
                            continue;
                        }
                        Err(DkgError::MissingRoundMessages { .. }) => return Ok(()),
                        Err(err) => return Err(err),
                    }
                }
                NativeDkgSessionPhase::FinalCommitments { sent } => {
                    if !sent {
                        let output = self.finalize_local_it_vss_batch()?;
                        self.runtime
                            .runtime_mut()
                            .broadcast_it_vss_public_commitment_batch_logged(
                                &output.public_commitments,
                            )?;
                        let audit_records =
                            production_it_vss_public_audit_records_from_batched_output(
                                &self.config,
                                &output,
                                self.it_vss_backend.params(),
                            )?;
                        self.runtime
                            .runtime_mut()
                            .broadcast_it_vss_public_audit_records_logged(&audit_records)?;
                        self.runtime.cursor_log_mut().persist_setup_phase_cursor(
                            &DkgSetupPhaseCursor {
                                phase: DkgTransportPhase::ItVssArtifact,
                                state: DkgSetupPhaseCursorState::Sent,
                                receiver: None,
                                vector: None,
                                coefficient_index: None,
                                it_vss_phase: Some(
                                    ProductionItVssComplaintPhase::BroadcastPublicAudits,
                                ),
                                expected: audit_records.len(),
                                got: audit_records.len(),
                            },
                        )?;
                        let consistency_records =
                            production_it_vss_public_consistency_records_from_batched_output(
                                &self.config,
                                &output,
                                self.it_vss_backend.params(),
                                &self.public_coin_transcripts,
                            )?;
                        self.runtime
                            .runtime_mut()
                            .broadcast_it_vss_public_consistency_records_logged(
                                &consistency_records,
                            )?;
                        self.runtime.cursor_log_mut().persist_setup_phase_cursor(
                            &DkgSetupPhaseCursor {
                                phase: DkgTransportPhase::ItVssArtifact,
                                state: DkgSetupPhaseCursorState::Sent,
                                receiver: None,
                                vector: None,
                                coefficient_index: None,
                                it_vss_phase: Some(
                                    ProductionItVssComplaintPhase::BroadcastConsistencyRecords,
                                ),
                                expected: consistency_records.len(),
                                got: consistency_records.len(),
                            },
                        )?;
                        for &receiver in &self.config.parties {
                            if receiver == self.local_party() {
                                continue;
                            }
                            let deliveries = output
                                .deliveries
                                .iter()
                                .filter(|delivery| delivery.receiver == receiver)
                                .cloned()
                                .collect::<Vec<_>>();
                            self.runtime
                                .runtime_mut()
                                .send_it_vss_private_delivery_batch_logged(receiver, &deliveries)?;
                        }
                        self.phase = NativeDkgSessionPhase::FinalCommitments { sent: true };
                        return Ok(());
                    }

                    let expected_keys = expected_sampler_vector_it_vss_keys(
                        &self.config,
                        native_dkg_session_vectors(),
                    )?;
                    let public_commitments =
                        match self.collect_expected_it_vss_public_commitments(&expected_keys) {
                            Ok(public_commitments) => public_commitments,
                            Err(DkgError::MissingRoundMessages { .. }) => return Ok(()),
                            Err(err) => return Err(err),
                        };
                    let public_commitments = select_expected_it_vss_public_commitments(
                        &public_commitments,
                        &expected_keys,
                    )?;
                    if public_commitments.len() != expected_keys.len() {
                        return Ok(());
                    }
                    self.phase =
                        NativeDkgSessionPhase::PublicAuditConsistency { public_commitments };
                    continue;
                }
                NativeDkgSessionPhase::PublicAuditConsistency {
                    ref public_commitments,
                } => {
                    let public_commitments = public_commitments.clone();
                    let expected_keys = expected_sampler_vector_it_vss_keys(
                        &self.config,
                        native_dkg_session_vectors(),
                    )?;
                    let audit_records =
                        match self.collect_expected_it_vss_public_audit_records(&expected_keys) {
                            Ok(records) => records,
                            Err(DkgError::MissingRoundMessages { .. }) => return Ok(()),
                            Err(err) => return Err(err),
                        };
                    if audit_records.is_empty() {
                        return Ok(());
                    }
                    self.phase = NativeDkgSessionPhase::PublicConsistency { public_commitments };
                    continue;
                }
                NativeDkgSessionPhase::PublicConsistency {
                    ref public_commitments,
                } => {
                    let public_commitments = public_commitments.clone();
                    let expected_keys = expected_sampler_vector_it_vss_keys(
                        &self.config,
                        native_dkg_session_vectors(),
                    )?;
                    let consistency_records = match self
                        .collect_expected_it_vss_public_consistency_records(&expected_keys)
                    {
                        Ok(records) => records,
                        Err(DkgError::MissingRoundMessages { .. }) => return Ok(()),
                        Err(err) => return Err(err),
                    };
                    if consistency_records.is_empty() {
                        return Ok(());
                    }
                    self.phase = NativeDkgSessionPhase::VerifyPrivate { public_commitments };
                    continue;
                }
                NativeDkgSessionPhase::VerifyPrivate {
                    ref public_commitments,
                } => {
                    match self.runtime.drive_verify_it_vss_private_deliveries::<P, _>(
                        &self.it_vss_backend,
                        &self.config,
                        public_commitments,
                    ) {
                        Ok(_) => {}
                        Err(DkgError::PrimeFieldMpcTransport) => return Ok(()),
                        Err(err) => return Err(err),
                    }
                    let (accepted_commitments, resolution) =
                        persist_logged_sampler_it_vss_artifacts_from_phase_logs::<P, _, _, _>(
                            &self.config,
                            self.runtime.runtime_mut(),
                            &self.it_vss_backend,
                        )?;
                    self.runtime.cursor_log_mut().persist_setup_phase_cursor(
                        &DkgSetupPhaseCursor {
                            phase: DkgTransportPhase::VssComplaint,
                            state: DkgSetupPhaseCursorState::Collected,
                            receiver: None,
                            vector: None,
                            coefficient_index: None,
                            it_vss_phase: Some(ProductionItVssComplaintPhase::ResolveComplaints),
                            expected: resolution.complaints.len(),
                            got: resolution.complaints.len(),
                        },
                    )?;
                    self.runtime.cursor_log_mut().persist_setup_phase_cursor(
                        &DkgSetupPhaseCursor {
                            phase: DkgTransportPhase::ItVssArtifact,
                            state: DkgSetupPhaseCursorState::Collected,
                            receiver: None,
                            vector: None,
                            coefficient_index: None,
                            it_vss_phase: Some(
                                ProductionItVssComplaintPhase::CertifyAcceptedSharings,
                            ),
                            expected: accepted_commitments.len(),
                            got: resolution.certificates.len(),
                        },
                    )?;
                    self.phase = NativeDkgSessionPhase::SetupComplete;
                    continue;
                }
                NativeDkgSessionPhase::SetupComplete => return Ok(()),
            }
        }
    }

    fn resume_phase_from_logs(&self) -> Result<NativeDkgSessionPhase, DkgError> {
        let Some(latest) = self.runtime.cursor_log().latest_setup_phase_cursor() else {
            return Ok(NativeDkgSessionPhase::SmallResidue {
                vector_pos: 0,
                coeff_index: 0,
                sent: false,
            });
        };
        if latest.state == DkgSetupPhaseCursorState::Aborted {
            return Err(DkgError::DkgSetupAbortedAfterRestart);
        }
        if self.it_vss_certification_complete_from_logs()? {
            return Ok(NativeDkgSessionPhase::SetupComplete);
        }

        if latest.phase == DkgTransportPhase::SmallResidue {
            let vector = latest.vector.unwrap_or(SecretVectorKind::S1);
            let vector_pos = native_dkg_session_vectors()
                .iter()
                .position(|candidate| *candidate == vector)
                .unwrap_or(0);
            let coeff_index = latest.coefficient_index.unwrap_or(0) as usize;
            return Ok(match latest.state {
                DkgSetupPhaseCursorState::Collected => {
                    self.next_small_residue_phase_after(vector_pos, coeff_index)?
                }
                DkgSetupPhaseCursorState::Sent | DkgSetupPhaseCursorState::Waiting => {
                    NativeDkgSessionPhase::SmallResidue {
                        vector_pos,
                        coeff_index,
                        sent: true,
                    }
                }
                DkgSetupPhaseCursorState::Aborted => {
                    return Err(DkgError::DkgSetupAbortedAfterRestart)
                }
            });
        }

        match latest.it_vss_phase {
            Some(ProductionItVssComplaintPhase::BroadcastPublicPrecommitments) => {
                let vector_pos = self.next_precommit_vector_pos_from_log()?;
                Ok(NativeDkgSessionPhase::Precommit {
                    vector_pos,
                    sent: latest.state != DkgSetupPhaseCursorState::Collected,
                })
            }
            Some(ProductionItVssComplaintPhase::BroadcastPublicCoins) => {
                let label_pos = self.next_public_coin_label_pos_from_log()?;
                Ok(NativeDkgSessionPhase::PublicCoin {
                    label_pos,
                    sent: latest.state != DkgSetupPhaseCursorState::Collected,
                })
            }
            Some(ProductionItVssComplaintPhase::BroadcastPublicCommitments) => {
                if latest.state == DkgSetupPhaseCursorState::Collected {
                    let public_commitments = self.recover_expected_public_commitments_from_log()?;
                    Ok(NativeDkgSessionPhase::PublicAuditConsistency { public_commitments })
                } else {
                    Ok(NativeDkgSessionPhase::FinalCommitments { sent: true })
                }
            }
            Some(ProductionItVssComplaintPhase::BroadcastPublicAudits)
                if latest.state == DkgSetupPhaseCursorState::Collected =>
            {
                let public_commitments = self.recover_expected_public_commitments_from_log()?;
                Ok(NativeDkgSessionPhase::PublicConsistency { public_commitments })
            }
            Some(ProductionItVssComplaintPhase::BroadcastPublicAudits)
            | Some(ProductionItVssComplaintPhase::BroadcastConsistencyRecords) => {
                let public_commitments = self.recover_expected_public_commitments_from_log()?;
                Ok(NativeDkgSessionPhase::PublicAuditConsistency { public_commitments })
            }
            Some(ProductionItVssComplaintPhase::DeliverPrivateShares)
            | Some(ProductionItVssComplaintPhase::VerifyPrivateDeliveries)
            | Some(ProductionItVssComplaintPhase::BroadcastComplaints)
            | Some(ProductionItVssComplaintPhase::ResolveComplaints) => {
                let public_commitments = self.recover_expected_public_commitments_from_log()?;
                Ok(NativeDkgSessionPhase::VerifyPrivate { public_commitments })
            }
            Some(ProductionItVssComplaintPhase::CertifyAcceptedSharings) => {
                Ok(NativeDkgSessionPhase::SetupComplete)
            }
            None => Ok(NativeDkgSessionPhase::SmallResidue {
                vector_pos: 0,
                coeff_index: 0,
                sent: false,
            }),
        }
    }

    fn next_small_residue_phase_after(
        &self,
        vector_pos: usize,
        coeff_index: usize,
    ) -> Result<NativeDkgSessionPhase, DkgError> {
        let vector = native_dkg_session_vectors()
            .get(vector_pos)
            .copied()
            .ok_or(DkgError::Backend("invalid native DKG resume vector"))?;
        let next_index = coeff_index + 1;
        if next_index >= vector.coefficient_count::<P>() {
            if vector_pos + 1 >= native_dkg_session_vectors().len() {
                Ok(NativeDkgSessionPhase::Precommit {
                    vector_pos: 0,
                    sent: false,
                })
            } else {
                Ok(NativeDkgSessionPhase::SmallResidue {
                    vector_pos: vector_pos + 1,
                    coeff_index: 0,
                    sent: false,
                })
            }
        } else {
            Ok(NativeDkgSessionPhase::SmallResidue {
                vector_pos,
                coeff_index: next_index,
                sent: false,
            })
        }
    }

    fn next_precommit_vector_pos_from_log(&self) -> Result<usize, DkgError> {
        let precommitments = self
            .runtime
            .runtime()
            .recover_it_vss_public_precommitments_from_log()?;
        for (vector_pos, &vector) in native_dkg_session_vectors().iter().enumerate() {
            let expected = expected_sampler_vector_it_vss_keys(&self.config, &[vector])?;
            if select_expected_it_vss_public_precommitments(&precommitments, &expected).is_err() {
                return Ok(vector_pos);
            }
        }
        Ok(native_dkg_session_vectors().len())
    }

    fn recover_public_coin_transcripts_from_log(
        &self,
    ) -> Result<Vec<ProductionItVssPublicCoinTranscript>, DkgError> {
        let labels =
            sampler_vector_it_vss_sharing_labels(&self.config, native_dkg_session_vectors())?;
        let mut out = Vec::new();
        for label in labels {
            let shares = self
                .runtime
                .runtime()
                .recover_it_vss_public_coin_shares_from_log(label.label_hash)?;
            if shares.len() == self.config.parties.len() {
                out.push(production_it_vss_public_coin_transcript(
                    &self.config,
                    label.label_hash,
                    &shares,
                )?);
            }
        }
        Ok(out)
    }

    fn next_public_coin_label_pos_from_log(&self) -> Result<usize, DkgError> {
        let labels =
            sampler_vector_it_vss_sharing_labels(&self.config, native_dkg_session_vectors())?;
        for (label_pos, label) in labels.iter().enumerate() {
            let shares = self
                .runtime
                .runtime()
                .recover_it_vss_public_coin_shares_from_log(label.label_hash)?;
            if shares.len() != self.config.parties.len() {
                return Ok(label_pos);
            }
            production_it_vss_public_coin_transcript(&self.config, label.label_hash, &shares)?;
        }
        Ok(labels.len())
    }

    fn recover_expected_public_commitments_from_log(
        &self,
    ) -> Result<Vec<ItVssPublicCommitment>, DkgError> {
        let expected =
            expected_sampler_vector_it_vss_keys(&self.config, native_dkg_session_vectors())?;
        let commitments = self
            .runtime
            .runtime()
            .recover_it_vss_public_commitments_from_log()?;
        select_expected_it_vss_public_commitments(&commitments, &expected)
    }

    fn it_vss_certification_complete_from_logs(&self) -> Result<bool, DkgError> {
        let latest = self.runtime.cursor_log().latest_setup_phase_cursor();
        if latest.is_some_and(|cursor| {
            cursor.it_vss_phase == Some(ProductionItVssComplaintPhase::CertifyAcceptedSharings)
                && cursor.state == DkgSetupPhaseCursorState::Collected
                && cursor.got >= cursor.expected
        }) {
            return Ok(true);
        }
        let (_, resolution) = self.runtime.runtime().recover_it_vss_artifacts_from_log()?;
        Ok(resolution.is_some())
    }

    fn local_small_residue_contribution(
        &self,
        vector: SecretVectorKind,
        index: usize,
    ) -> Result<SmallResidueContribution, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        let label = SamplerLabel::new::<P>(&self.config, vector, index)?;
        Ok(SmallResidueContribution::new(
            self.local_party(),
            label,
            eta,
            native_dkg_session_residue(
                self.sampler_entropy,
                self.config.transcript_hash(),
                self.local_party(),
                vector,
                index,
                eta,
            ),
        ))
    }

    fn collect_expected_it_vss_precommitments(
        &mut self,
        vector: SecretVectorKind,
    ) -> Result<Vec<ItVssPublicPrecommitment>, DkgError> {
        let expected_keys = expected_sampler_vector_it_vss_keys(&self.config, &[vector])?;
        let messages =
            match self.collect_it_vss_artifact_messages_matching(expected_keys.len(), |message| {
                matches!(
                    wire_decode_dkg_it_vss_artifact_payload(&message.payload),
                    Ok(DkgItVssArtifactPayload::PublicPrecommitment(ref payload))
                        if expected_keys
                            .iter()
                            .any(|(dealer, label_hash)| *dealer == PartyId(payload.dealer_party_id)
                                && *label_hash == payload.label_hash)
                )
            }) {
                Ok(messages) => messages,
                Err(DkgError::MissingRoundMessages { expected, got, .. }) => {
                    self.runtime.cursor_log_mut().persist_setup_phase_cursor(
                        &DkgSetupPhaseCursor {
                            phase: DkgTransportPhase::ItVssArtifact,
                            state: DkgSetupPhaseCursorState::Waiting,
                            receiver: None,
                            vector: Some(vector),
                            coefficient_index: None,
                            it_vss_phase: Some(
                                ProductionItVssComplaintPhase::BroadcastPublicPrecommitments,
                            ),
                            expected,
                            got,
                        },
                    )?;
                    return Err(DkgError::MissingRoundMessages {
                        round: DkgRound::Commit,
                        expected,
                        got,
                    });
                }
                Err(err) => return Err(err),
            };
        let precommitments = self
            .runtime
            .runtime()
            .it_vss_public_precommitments_from_messages(messages)?;
        self.runtime
            .cursor_log_mut()
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Collected,
                receiver: None,
                vector: Some(vector),
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicPrecommitments),
                expected: expected_keys.len(),
                got: precommitments.len(),
            })?;
        Ok(precommitments)
    }

    fn collect_expected_it_vss_public_coin_transcript(
        &mut self,
        label_hash: [u8; 32],
    ) -> Result<ProductionItVssPublicCoinTranscript, DkgError> {
        let messages = match self.collect_it_vss_artifact_messages_matching(
            self.config.parties.len(),
            |message| {
                matches!(
                    wire_decode_dkg_it_vss_artifact_payload(&message.payload),
                    Ok(DkgItVssArtifactPayload::PublicCoinShare(ref payload))
                        if payload.label_hash == label_hash
                )
            },
        ) {
            Ok(messages) => messages,
            Err(DkgError::MissingRoundMessages { expected, got, .. }) => {
                self.runtime
                    .cursor_log_mut()
                    .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                        phase: DkgTransportPhase::ItVssArtifact,
                        state: DkgSetupPhaseCursorState::Waiting,
                        receiver: None,
                        vector: None,
                        coefficient_index: None,
                        it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicCoins),
                        expected,
                        got,
                    })?;
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Commit,
                    expected,
                    got,
                });
            }
            Err(err) => return Err(err),
        };
        let shares = self
            .runtime
            .runtime()
            .it_vss_public_coin_shares_from_messages(messages, label_hash)?;
        let transcript =
            production_it_vss_public_coin_transcript(&self.config, label_hash, &shares)?;
        self.runtime
            .cursor_log_mut()
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Collected,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicCoins),
                expected: self.config.parties.len(),
                got: shares.len(),
            })?;
        Ok(transcript)
    }

    fn collect_expected_it_vss_public_commitments(
        &mut self,
        expected_keys: &[(PartyId, [u8; 32])],
    ) -> Result<Vec<ItVssPublicCommitment>, DkgError> {
        let messages = match self.collect_it_vss_artifact_messages_matching(
            self.config.parties.len(),
            |message| match wire_decode_dkg_it_vss_artifact_payload(&message.payload) {
                Ok(DkgItVssArtifactPayload::PublicCommitment(ref payload)) => {
                    expected_keys.iter().any(|(dealer, label_hash)| {
                        *dealer == PartyId(payload.dealer_party_id)
                            && *label_hash == payload.label_hash
                    })
                }
                Ok(DkgItVssArtifactPayload::PublicCommitmentBatch(ref payloads)) => {
                    !payloads.is_empty()
                        && payloads.iter().all(|payload| {
                            expected_keys.iter().any(|(dealer, label_hash)| {
                                *dealer == PartyId(payload.dealer_party_id)
                                    && *label_hash == payload.label_hash
                            })
                        })
                }
                _ => false,
            },
        ) {
            Ok(messages) => messages,
            Err(DkgError::MissingRoundMessages { expected, got, .. }) => {
                self.runtime
                    .cursor_log_mut()
                    .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                        phase: DkgTransportPhase::ItVssArtifact,
                        state: DkgSetupPhaseCursorState::Waiting,
                        receiver: None,
                        vector: None,
                        coefficient_index: None,
                        it_vss_phase: Some(
                            ProductionItVssComplaintPhase::BroadcastPublicCommitments,
                        ),
                        expected,
                        got,
                    })?;
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Commit,
                    expected,
                    got,
                });
            }
            Err(err) => return Err(err),
        };
        let commitments = self
            .runtime
            .runtime()
            .it_vss_public_commitments_from_messages(messages)?;
        self.runtime
            .cursor_log_mut()
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Collected,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicCommitments),
                expected: expected_keys.len(),
                got: commitments.len(),
            })?;
        Ok(commitments)
    }

    fn collect_expected_it_vss_public_audit_records(
        &mut self,
        expected_keys: &[(PartyId, [u8; 32])],
    ) -> Result<Vec<ProductionItVssAuditRecord>, DkgError> {
        let messages = match self.collect_it_vss_artifact_messages_matching(
            self.config.parties.len(),
            |message| match wire_decode_dkg_it_vss_artifact_payload(&message.payload) {
                Ok(DkgItVssArtifactPayload::PublicAuditRecords(ref records)) => {
                    !records.is_empty()
                        && records.iter().all(|record| {
                            expected_keys.iter().any(|(dealer, label_hash)| {
                                *dealer == PartyId(record.dealer_party_id)
                                    && *label_hash == record.label_hash
                            })
                        })
                }
                _ => false,
            },
        ) {
            Ok(messages) => messages,
            Err(DkgError::MissingRoundMessages { expected, got, .. }) => {
                self.runtime
                    .cursor_log_mut()
                    .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                        phase: DkgTransportPhase::ItVssArtifact,
                        state: DkgSetupPhaseCursorState::Waiting,
                        receiver: None,
                        vector: None,
                        coefficient_index: None,
                        it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicAudits),
                        expected,
                        got,
                    })?;
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Commit,
                    expected,
                    got,
                });
            }
            Err(err) => return Err(err),
        };
        let records = self
            .runtime
            .runtime()
            .it_vss_public_audit_records_from_messages(messages)?;
        self.runtime
            .cursor_log_mut()
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Collected,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastPublicAudits),
                expected: self.config.parties.len(),
                got: self.config.parties.len(),
            })?;
        Ok(records)
    }

    fn collect_expected_it_vss_public_consistency_records(
        &mut self,
        expected_keys: &[(PartyId, [u8; 32])],
    ) -> Result<Vec<ProductionItVssConsistencyRecord>, DkgError> {
        let messages = match self.collect_it_vss_artifact_messages_matching(
            self.config.parties.len(),
            |message| match wire_decode_dkg_it_vss_artifact_payload(&message.payload) {
                Ok(DkgItVssArtifactPayload::PublicConsistencyRecords(ref records)) => {
                    !records.is_empty()
                        && records.iter().all(|record| {
                            expected_keys.iter().any(|(dealer, label_hash)| {
                                *dealer == PartyId(record.dealer_party_id)
                                    && *label_hash == record.label_hash
                            })
                        })
                }
                _ => false,
            },
        ) {
            Ok(messages) => messages,
            Err(DkgError::MissingRoundMessages { expected, got, .. }) => {
                self.runtime
                    .cursor_log_mut()
                    .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                        phase: DkgTransportPhase::ItVssArtifact,
                        state: DkgSetupPhaseCursorState::Waiting,
                        receiver: None,
                        vector: None,
                        coefficient_index: None,
                        it_vss_phase: Some(
                            ProductionItVssComplaintPhase::BroadcastConsistencyRecords,
                        ),
                        expected,
                        got,
                    })?;
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Commit,
                    expected,
                    got,
                });
            }
            Err(err) => return Err(err),
        };
        let records = self
            .runtime
            .runtime()
            .it_vss_public_consistency_records_from_messages(messages)?;
        self.runtime
            .cursor_log_mut()
            .persist_setup_phase_cursor(&DkgSetupPhaseCursor {
                phase: DkgTransportPhase::ItVssArtifact,
                state: DkgSetupPhaseCursorState::Collected,
                receiver: None,
                vector: None,
                coefficient_index: None,
                it_vss_phase: Some(ProductionItVssComplaintPhase::BroadcastConsistencyRecords),
                expected: self.config.parties.len(),
                got: self.config.parties.len(),
            })?;
        Ok(records)
    }

    fn collect_it_vss_artifact_messages_matching<F>(
        &mut self,
        expected_count: usize,
        predicate: F,
    ) -> Result<Vec<WireMessage>, DkgError>
    where
        F: Fn(&WireMessage) -> bool,
    {
        let messages = self
            .runtime
            .runtime()
            .state()
            .transport()
            .collect_broadcast_matching(
                RoundId::DkgItVssArtifact,
                &self.runtime.runtime().state().expected_context,
                expected_count,
                predicate,
            )
            .map_err(|err| match err {
                TransportError::IncompleteBroadcastView { expected, got, .. } => {
                    DkgError::MissingRoundMessages {
                        round: DkgRound::Commit,
                        expected,
                        got,
                    }
                }
                other => map_transport_error(other),
            })?;
        for message in &messages {
            self.runtime
                .runtime
                .wire_log
                .persist_dkg_wire_message(&DkgWireMessageRecord {
                    direction: PrimeFieldMpcWireDirection::AcceptedBroadcast,
                    peer: None,
                    message: message.clone(),
                })?;
        }
        Ok(messages)
    }

    fn public_coin(&self, label_hash: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"TALUS-DKG-NativeDkgSession-v1/public-coin");
        hasher.update(self.public_coin_entropy);
        hasher.update(self.config.transcript_hash().0);
        hasher.update(self.local_party().0.to_le_bytes());
        hasher.update(label_hash);
        hasher.finalize().into()
    }

    fn finalize_local_it_vss_batch(&mut self) -> Result<ItVssBatchedDealerOutput, DkgError> {
        let mut public_commitments = Vec::with_capacity(self.prepared_it_vss.len());
        let mut deliveries = Vec::new();
        for item in &mut self.prepared_it_vss {
            let prepared = item
                .prepared
                .take()
                .ok_or(DkgError::MissingDkgSetupCertificate)?;
            let transcript = self
                .public_coin_transcripts
                .iter()
                .find(|transcript| transcript.label_hash == item.label.label_hash)
                .cloned()
                .ok_or(DkgError::MissingDkgSetupCertificate)?;
            let output =
                self.it_vss_backend
                    .finalize_prepared_secret(&self.config, prepared, transcript)?;
            public_commitments.push(output.public_commitment);
            deliveries.extend(output.deliveries);
        }
        Ok(ItVssBatchedDealerOutput {
            public_commitments,
            deliveries,
        })
    }
}

#[derive(Clone)]
struct NativeDkgPreparedItVss {
    vector: SecretVectorKind,
    label: ItVssSharingLabel,
    prepared: Option<ProductionItVssPreparedDealerOutput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeDkgSessionPhase {
    SmallResidue {
        vector_pos: usize,
        coeff_index: usize,
        sent: bool,
    },
    Precommit {
        vector_pos: usize,
        sent: bool,
    },
    PublicCoin {
        label_pos: usize,
        sent: bool,
    },
    FinalCommitments {
        sent: bool,
    },
    PublicAuditConsistency {
        public_commitments: Vec<ItVssPublicCommitment>,
    },
    PublicConsistency {
        public_commitments: Vec<ItVssPublicCommitment>,
    },
    VerifyPrivate {
        public_commitments: Vec<ItVssPublicCommitment>,
    },
    SetupComplete,
}

#[derive(Clone, Debug)]
struct NativeDkgSessionTransport {
    local_party: PartyId,
    private_inbox: RefCell<Vec<talus_wire::PrivateWireMessage>>,
    broadcast_inbox: RefCell<Vec<talus_wire::BroadcastDelivery>>,
    outbound: RefCell<VecDeque<NativeDkgOutbound>>,
}

impl NativeDkgSessionTransport {
    fn new(local_party: PartyId, _config: &DkgConfig) -> Self {
        Self {
            local_party,
            private_inbox: RefCell::new(Vec::new()),
            broadcast_inbox: RefCell::new(Vec::new()),
            outbound: RefCell::new(VecDeque::new()),
        }
    }

    fn inject_private(
        &mut self,
        sender: PartyId,
        receiver: PartyId,
        message: WireMessage,
    ) -> Result<(), TransportError> {
        if receiver != self.local_party {
            return Err(TransportError::Backend("private message receiver mismatch"));
        }
        if message.header.sender_party_id != sender.0 {
            return Err(TransportError::SenderMismatch {
                channel_sender: sender.0,
                header_sender: message.header.sender_party_id,
            });
        }
        self.private_inbox
            .borrow_mut()
            .push(talus_wire::PrivateWireMessage {
                sender_party_id: sender.0,
                receiver_party_id: receiver.0,
                message,
            });
        Ok(())
    }

    fn inject_broadcast(
        &mut self,
        observer: PartyId,
        message: WireMessage,
    ) -> Result<(), TransportError> {
        if observer != self.local_party {
            return Err(TransportError::Backend("broadcast observer mismatch"));
        }
        self.broadcast_inbox
            .borrow_mut()
            .push(talus_wire::BroadcastDelivery {
                observer_party_id: observer.0,
                message,
            });
        Ok(())
    }

    fn pop_outbound(&self) -> Option<NativeDkgOutbound> {
        self.outbound.borrow_mut().pop_front()
    }

    fn has_outbound(&self) -> bool {
        !self.outbound.borrow().is_empty()
    }

    fn collect_broadcast_matching<F>(
        &self,
        expected_round: RoundId,
        expected: &ExpectedContext,
        expected_count: usize,
        predicate: F,
    ) -> Result<Vec<WireMessage>, TransportError>
    where
        F: Fn(&WireMessage) -> bool,
    {
        let mut inbox = self.broadcast_inbox.borrow_mut();
        let mut selected = Vec::new();
        let mut selected_indices = Vec::new();
        let mut selected_senders = Vec::new();
        for (index, delivery) in inbox.iter().enumerate() {
            if delivery.observer_party_id == self.local_party.0
                && delivery.message.header.round == expected_round
                && predicate(&delivery.message)
                && !selected_senders.contains(&delivery.message.header.sender_party_id)
            {
                selected_senders.push(delivery.message.header.sender_party_id);
                selected.push(delivery.message.clone());
                selected_indices.push(index);
            }
        }
        if selected.len() < expected_count {
            return Err(TransportError::IncompleteBroadcastView {
                observer_party_id: self.local_party.0,
                expected: expected_count,
                got: selected.len(),
            });
        }
        validate_round_batch(&selected, expected_round, expected).map_err(TransportError::Wire)?;
        for index in selected_indices.into_iter().rev() {
            inbox.remove(index);
        }
        Ok(selected)
    }
}

impl AuthenticatedP2pTransport for NativeDkgSessionTransport {
    fn send_private(
        &mut self,
        receiver_party_id: u16,
        message: WireMessage,
    ) -> Result<(), TransportError> {
        self.outbound
            .borrow_mut()
            .push_back(NativeDkgOutbound::Private {
                receiver: PartyId(receiver_party_id),
                message,
            });
        Ok(())
    }

    fn collect_private_round(
        &self,
        receiver_party_id: u16,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        if receiver_party_id != self.local_party.0 {
            return Err(TransportError::Backend(
                "private collection receiver mismatch",
            ));
        }
        let expected_count = expected.allowed_parties.len().saturating_sub(1);
        let mut inbox = self.private_inbox.borrow_mut();
        let mut selected = Vec::new();
        let mut selected_indices = Vec::new();
        let mut selected_senders = Vec::new();
        for (index, delivery) in inbox.iter().enumerate() {
            if delivery.receiver_party_id == receiver_party_id
                && delivery.message.header.round == expected_round
                && !selected_senders.contains(&delivery.message.header.sender_party_id)
            {
                selected_senders.push(delivery.message.header.sender_party_id);
                selected.push(delivery.message.clone());
                selected_indices.push(index);
            }
        }
        if selected.len() < expected_count {
            return Err(TransportError::IncompleteBroadcastView {
                observer_party_id: receiver_party_id,
                expected: expected_count,
                got: selected.len(),
            });
        }
        validate_round_batch(&selected, expected_round, expected).map_err(TransportError::Wire)?;
        for index in selected_indices.into_iter().rev() {
            inbox.remove(index);
        }
        Ok(selected)
    }
}

impl EquivocationResistantBroadcast for NativeDkgSessionTransport {
    fn broadcast(&mut self, message: WireMessage) -> Result<(), TransportError> {
        self.outbound
            .borrow_mut()
            .push_back(NativeDkgOutbound::Broadcast { message });
        Ok(())
    }

    fn collect_broadcast_view(
        &self,
        observer_party_id: u16,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        if observer_party_id != self.local_party.0 {
            return Err(TransportError::Backend("broadcast observer mismatch"));
        }
        let expected_count = expected.allowed_parties.len();
        let mut inbox = self.broadcast_inbox.borrow_mut();
        let mut selected = Vec::new();
        let mut selected_indices = Vec::new();
        let mut selected_senders = Vec::new();
        for (index, delivery) in inbox.iter().enumerate() {
            if delivery.observer_party_id == observer_party_id
                && delivery.message.header.round == expected_round
                && !selected_senders.contains(&delivery.message.header.sender_party_id)
            {
                selected_senders.push(delivery.message.header.sender_party_id);
                selected.push(delivery.message.clone());
                selected_indices.push(index);
            }
        }
        if selected.len() < expected_count {
            return Err(TransportError::IncompleteBroadcastView {
                observer_party_id,
                expected: expected_count,
                got: selected.len(),
            });
        }
        validate_round_batch(&selected, expected_round, expected).map_err(TransportError::Wire)?;
        for index in selected_indices.into_iter().rev() {
            inbox.remove(index);
        }
        Ok(selected)
    }

    fn collect_equivocation_checked_round(
        &self,
        expected_round: RoundId,
        expected: &ExpectedContext,
    ) -> Result<Vec<WireMessage>, TransportError> {
        self.collect_broadcast_view(self.local_party.0, expected_round, expected)
    }
}

fn prepare_native_dkg_session_it_vss<P: MlDsaParams>(
    config: &DkgConfig,
    dealer: PartyId,
    sampler_entropy: [u8; 32],
    backend: &mut ProductionInformationCheckingVssBackend,
) -> Result<Vec<NativeDkgPreparedItVss>, DkgError> {
    let eta = SmallSecretEta::for_params::<P>()?;
    native_dkg_session_vectors()
        .iter()
        .copied()
        .map(|vector| {
            let contributions = (0..vector.coefficient_count::<P>())
                .map(|index| {
                    let label = SamplerLabel::new::<P>(config, vector, index)?;
                    Ok(SmallResidueContribution::new(
                        dealer,
                        label,
                        eta,
                        native_dkg_session_residue(
                            sampler_entropy,
                            config.transcript_hash(),
                            dealer,
                            vector,
                            index,
                            eta,
                        ),
                    ))
                })
                .collect::<Result<Vec<_>, DkgError>>()?;
            let label = ItVssSharingLabel::new(
                config,
                dealer,
                ItVssSharingDomain::for_secret_vector(vector),
                None,
            )?;
            let secret = encode_small_residue_vector_it_vss_secret::<P>(
                config,
                vector,
                eta,
                dealer,
                &contributions,
            )?;
            let prepared = backend.prepare_secret::<P>(config, label, &secret)?;
            Ok(NativeDkgPreparedItVss {
                vector,
                label,
                prepared: Some(prepared),
            })
        })
        .collect()
}

fn native_dkg_session_vectors() -> &'static [SecretVectorKind] {
    &[SecretVectorKind::S1, SecretVectorKind::S2]
}

fn native_dkg_session_residue(
    entropy: [u8; 32],
    config_hash: KeygenTranscriptHash,
    party: PartyId,
    vector: SecretVectorKind,
    index: usize,
    eta: SmallSecretEta,
) -> u8 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-NativeDkgSession-v1/small-residue");
    hasher.update(entropy);
    hasher.update(config_hash.0);
    hasher.update(party.0.to_le_bytes());
    hasher.update([vector.as_u8()]);
    hasher.update((index as u32).to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    (u16::from_le_bytes([digest[0], digest[1]]) % u16::from(eta.modulus())) as u8
}

/// Application-owned native DKG setup scheduler boundary.
///
/// The TALUS crate does not own TCP sockets, task scheduling, retries, or a
/// production database. An embedding application provides the authenticated
/// transport and durable logs, then drives these typed setup phases until the
/// native DKG transcript is complete. Each method persists enough wire/cursor
/// state for restart and returns a status the application scheduler can use to
/// decide whether to wait for more network messages, route locally available
/// test messages, or advance to the next phase.
pub trait NativeDkgApplicationSetupDriver {
    /// Application-supplied authenticated private channel and reliable
    /// broadcast implementation.
    type Transport: AuthenticatedP2pTransport + EquivocationResistantBroadcast;
    /// Application-supplied durable wire-message log.
    type WireLog: DkgWireMessageLog;
    /// Application-supplied durable setup-phase cursor log.
    type CursorLog: DkgSetupPhaseCursorLog;

    /// Returns the local party.
    fn local_party(&self) -> PartyId;

    /// Returns the durable wire-message log.
    fn wire_log(&self) -> &Self::WireLog;

    /// Returns the durable setup cursor log.
    fn cursor_log(&self) -> &Self::CursorLog;

    /// Replays locally sent messages into the application transport and
    /// returns the latest persisted setup cursor.
    fn resume_setup(&mut self) -> Result<Option<DkgSetupPhaseCursor>, DkgError>;

    /// Broadcasts a raw bounded-sampler residue contribution.
    fn drive_broadcast_small_residue(
        &mut self,
        contribution: &SmallResidueContribution,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects one raw bounded-sampler residue round.
    fn drive_collect_small_residue_round(
        &mut self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<SmallResidueContribution>), DkgError>;

    /// Shares this party's full bounded-sampler residue vector through
    /// information-checking IT-VSS and emits the public/private transport
    /// messages for the application to deliver.
    fn drive_share_small_residue_vector_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        vector: SecretVectorKind,
        contributions: &[SmallResidueContribution],
    ) -> Result<ItVssDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend;

    /// Shares this party's bounded-sampler residue vector batch through
    /// information-checking IT-VSS. Native DKG uses this to emit the dealer's
    /// whole-vector `s1` and `s2` commitments/deliveries in one app-driver
    /// phase.
    fn drive_share_small_residue_vector_batches_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        batches: &[SmallResidueVectorContributionBatch],
    ) -> Result<ItVssBatchedDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend;

    /// Broadcasts an IT-VSS public commitment.
    fn drive_broadcast_it_vss_public_commitment(
        &mut self,
        commitment: &ItVssPublicCommitment,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Broadcasts an IT-VSS public precommitment before public coins are
    /// derived.
    fn drive_broadcast_it_vss_public_precommitment(
        &mut self,
        precommitment: &ItVssPublicPrecommitment,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects IT-VSS public precommitments.
    fn drive_collect_it_vss_public_precommitments(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<ItVssPublicPrecommitment>), DkgError>;

    /// Collects IT-VSS public commitments.
    fn drive_collect_it_vss_public_commitments(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<ItVssPublicCommitment>), DkgError>;

    /// Broadcasts an IT-VSS public-coin share.
    fn drive_broadcast_it_vss_public_coin_share(
        &mut self,
        share: &ProductionItVssPublicCoinShare,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects IT-VSS public-coin shares for a label and assembles the
    /// validated public-coin transcript.
    fn drive_collect_it_vss_public_coin_transcript(
        &mut self,
        config: &DkgConfig,
        label_hash: [u8; 32],
    ) -> Result<
        (
            DkgTransportPhaseDriverStatus,
            ProductionItVssPublicCoinTranscript,
        ),
        DkgError,
    >;

    /// Sends one directed IT-VSS private delivery.
    fn drive_send_it_vss_private_delivery(
        &mut self,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects directed IT-VSS private deliveries for `receiver`.
    fn drive_collect_it_vss_private_delivery_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<
        (
            DkgTransportPhaseDriverStatus,
            Vec<ItVssPrivateShareDelivery>,
        ),
        DkgError,
    >;

    /// Verifies this party's received IT-VSS private deliveries against public
    /// commitments and broadcasts any complaint payloads.
    fn drive_verify_it_vss_private_deliveries<P, B>(
        &mut self,
        backend: &B,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
    ) -> Result<Vec<DkgComplaintPayload>, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend;

    /// Broadcasts one VSS complaint payload.
    fn drive_broadcast_vss_complaint(
        &mut self,
        complaint: &DkgComplaintPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects VSS complaints.
    fn drive_collect_vss_complaint_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgComplaintPayload>), DkgError>;

    /// Broadcasts a scalar VSS public-check commit.
    fn drive_broadcast_vss_commit(
        &mut self,
        commit: &DkgCommitPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects scalar VSS public-check commits.
    fn drive_collect_vss_commit_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgCommitPayload>), DkgError>;

    /// Sends a scalar VSS private-share payload.
    fn drive_send_vss_share(
        &mut self,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError>;

    /// Collects scalar VSS private-share payloads for `receiver`.
    fn drive_collect_vss_share_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgSharePayload>), DkgError>;

    /// Persists an explicit IT-VSS complaint-resolution subphase cursor.
    fn persist_it_vss_complaint_phase_cursor(
        &mut self,
        phase: ProductionItVssComplaintPhase,
        state: DkgSetupPhaseCursorState,
        expected: usize,
        got: usize,
    ) -> Result<(), DkgError>;
}

impl<T, L, C> NativeDkgApplicationSetupDriver for CursoredLoggedDkgTransportPartyRuntime<T, L, C>
where
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
    C: DkgSetupPhaseCursorLog,
{
    type Transport = T;
    type WireLog = L;
    type CursorLog = C;

    fn local_party(&self) -> PartyId {
        CursoredLoggedDkgTransportPartyRuntime::local_party(self)
    }

    fn wire_log(&self) -> &Self::WireLog {
        self.runtime().wire_log()
    }

    fn cursor_log(&self) -> &Self::CursorLog {
        CursoredLoggedDkgTransportPartyRuntime::cursor_log(self)
    }

    fn resume_setup(&mut self) -> Result<Option<DkgSetupPhaseCursor>, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::resume(self)
    }

    fn drive_broadcast_small_residue(
        &mut self,
        contribution: &SmallResidueContribution,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_broadcast_small_residue(self, contribution)
    }

    fn drive_collect_small_residue_round(
        &mut self,
        label: SamplerLabel,
        eta: SmallSecretEta,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<SmallResidueContribution>), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_small_residue_round(self, label, eta)
    }

    fn drive_share_small_residue_vector_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        vector: SecretVectorKind,
        contributions: &[SmallResidueContribution],
    ) -> Result<ItVssDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        CursoredLoggedDkgTransportPartyRuntime::drive_share_small_residue_vector_it_vss::<P, B>(
            self,
            backend,
            config,
            vector,
            contributions,
        )
    }

    fn drive_share_small_residue_vector_batches_it_vss<P, B>(
        &mut self,
        backend: &mut B,
        config: &DkgConfig,
        batches: &[SmallResidueVectorContributionBatch],
    ) -> Result<ItVssBatchedDealerOutput, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        CursoredLoggedDkgTransportPartyRuntime::drive_share_small_residue_vector_batches_it_vss::<
            P,
            B,
        >(self, backend, config, batches)
    }

    fn drive_broadcast_it_vss_public_commitment(
        &mut self,
        commitment: &ItVssPublicCommitment,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_broadcast_it_vss_public_commitment(
            self, commitment,
        )
    }

    fn drive_broadcast_it_vss_public_precommitment(
        &mut self,
        precommitment: &ItVssPublicPrecommitment,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_broadcast_it_vss_public_precommitment(
            self,
            precommitment,
        )
    }

    fn drive_collect_it_vss_public_precommitments(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<ItVssPublicPrecommitment>), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_it_vss_public_precommitments(self)
    }

    fn drive_collect_it_vss_public_commitments(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<ItVssPublicCommitment>), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_it_vss_public_commitments(self)
    }

    fn drive_broadcast_it_vss_public_coin_share(
        &mut self,
        share: &ProductionItVssPublicCoinShare,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_broadcast_it_vss_public_coin_share(
            self, share,
        )
    }

    fn drive_collect_it_vss_public_coin_transcript(
        &mut self,
        config: &DkgConfig,
        label_hash: [u8; 32],
    ) -> Result<
        (
            DkgTransportPhaseDriverStatus,
            ProductionItVssPublicCoinTranscript,
        ),
        DkgError,
    > {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_it_vss_public_coin_transcript(
            self, config, label_hash,
        )
    }

    fn drive_send_it_vss_private_delivery(
        &mut self,
        delivery: &ItVssPrivateShareDelivery,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_send_it_vss_private_delivery(self, delivery)
    }

    fn drive_collect_it_vss_private_delivery_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<
        (
            DkgTransportPhaseDriverStatus,
            Vec<ItVssPrivateShareDelivery>,
        ),
        DkgError,
    > {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_it_vss_private_delivery_round(
            self, receiver,
        )
    }

    fn drive_verify_it_vss_private_deliveries<P, B>(
        &mut self,
        backend: &B,
        config: &DkgConfig,
        public_commitments: &[ItVssPublicCommitment],
    ) -> Result<Vec<DkgComplaintPayload>, DkgError>
    where
        P: MlDsaParams,
        B: ProductionItVssBackend,
    {
        CursoredLoggedDkgTransportPartyRuntime::drive_verify_it_vss_private_deliveries::<P, B>(
            self,
            backend,
            config,
            public_commitments,
        )
    }

    fn drive_broadcast_vss_complaint(
        &mut self,
        complaint: &DkgComplaintPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_broadcast_vss_complaint(self, complaint)
    }

    fn drive_collect_vss_complaint_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgComplaintPayload>), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_vss_complaint_round(self)
    }

    fn drive_broadcast_vss_commit(
        &mut self,
        commit: &DkgCommitPayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_broadcast_vss_commit(self, commit)
    }

    fn drive_collect_vss_commit_round(
        &mut self,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgCommitPayload>), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_vss_commit_round(self)
    }

    fn drive_send_vss_share(
        &mut self,
        receiver: PartyId,
        share: &DkgSharePayload,
    ) -> Result<DkgTransportPhaseDriverStatus, DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_send_vss_share(self, receiver, share)
    }

    fn drive_collect_vss_share_round(
        &mut self,
        receiver: PartyId,
    ) -> Result<(DkgTransportPhaseDriverStatus, Vec<DkgSharePayload>), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::drive_collect_vss_share_round(self, receiver)
    }

    fn persist_it_vss_complaint_phase_cursor(
        &mut self,
        phase: ProductionItVssComplaintPhase,
        state: DkgSetupPhaseCursorState,
        expected: usize,
        got: usize,
    ) -> Result<(), DkgError> {
        CursoredLoggedDkgTransportPartyRuntime::persist_it_vss_complaint_phase_cursor(
            self, phase, state, expected, got,
        )
    }
}

/// Bounded sampler for ML-DSA secret shares.
pub trait BoundedSecretSampler {
    /// Samples one encoded `s1` share with coefficients in the selected ML-DSA bound.
    fn sample_s1_share<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        party: PartyId,
    ) -> Result<Vec<u8>, DkgError>;
}

/// ML-DSA secret-vector name sampled by the bounded distributed sampler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretVectorKind {
    /// ML-DSA `s1`, with `L` polynomials.
    S1,
    /// ML-DSA `s2`, with `K` polynomials.
    S2,
}

impl SecretVectorKind {
    /// Returns the number of polynomials for this vector in the selected suite.
    pub const fn poly_count<P: MlDsaParams>(self) -> usize {
        match self {
            Self::S1 => P::L,
            Self::S2 => P::K,
        }
    }

    /// Returns the coefficient count for this vector in the selected suite.
    pub const fn coefficient_count<P: MlDsaParams>(self) -> usize {
        self.poly_count::<P>() * P::N
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::S1 => 1,
            Self::S2 => 2,
        }
    }
}

/// ML-DSA bounded-secret distribution parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmallSecretEta {
    /// `eta = 2`, modulus `m = 5`.
    Two,
    /// `eta = 4`, modulus `m = 9`.
    Four,
}

impl SmallSecretEta {
    /// Returns the eta value for one ML-DSA parameter set.
    pub fn for_params<P: MlDsaParams>() -> Result<Self, DkgError> {
        match P::ETA {
            2 => Ok(Self::Two),
            4 => Ok(Self::Four),
            _ => Err(DkgError::Backend("unsupported ML-DSA eta")),
        }
    }

    /// Returns `eta` as a signed coefficient bound.
    pub const fn bound(self) -> Coeff {
        match self {
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    /// Returns `m = 2*eta + 1`.
    pub const fn modulus(self) -> u8 {
        match self {
            Self::Two => 5,
            Self::Four => 9,
        }
    }

    /// Returns the bit width used to validate a private residue input.
    pub const fn bit_width(self) -> usize {
        match self {
            Self::Two => 3,
            Self::Four => 4,
        }
    }
}

/// Transcript label for one bounded-secret coefficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SamplerLabel {
    /// DKG configuration hash.
    pub config_hash: KeygenTranscriptHash,
    /// Vector being sampled.
    pub vector: SecretVectorKind,
    /// Coefficient index inside the vector.
    pub coefficient_index: u32,
}

impl SamplerLabel {
    /// Builds a label bound to one DKG configuration.
    pub fn new<P: MlDsaParams>(
        config: &DkgConfig,
        vector: SecretVectorKind,
        coefficient_index: usize,
    ) -> Result<Self, DkgError> {
        let expected = vector.coefficient_count::<P>();
        if coefficient_index >= expected {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected,
                got: coefficient_index + 1,
            });
        }

        Ok(Self {
            config_hash: config.transcript_hash(),
            vector,
            coefficient_index: coefficient_index as u32,
        })
    }
}

/// One dealer's private residue input for a bounded-secret coefficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmallResidueContribution {
    /// Dealer contributing this residue.
    pub dealer: PartyId,
    /// Transcript label this contribution is bound to.
    pub label: SamplerLabel,
    /// ML-DSA eta distribution parameter.
    pub eta: SmallSecretEta,
    /// Residue value in `Z_m`.
    pub residue: u8,
    /// Little-endian bit decomposition of `residue`.
    pub bits: Vec<u8>,
}

impl SmallResidueContribution {
    /// Creates a contribution with canonical little-endian bits.
    pub fn new(dealer: PartyId, label: SamplerLabel, eta: SmallSecretEta, residue: u8) -> Self {
        Self {
            dealer,
            label,
            eta,
            residue,
            bits: residue_bits(residue, eta.bit_width()),
        }
    }
}

/// Verification provenance for one bounded-sampler residue input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmallResidueInputVerification {
    /// Input was checked by the in-process scaffold adapter.
    #[cfg(any(test, feature = "scaffold-dev"))]
    InProcessScaffold,
    /// Input was produced by a verified production IT-VSS sharing.
    ItVssCertificate {
        /// Hash of the IT-VSS sharing label.
        label_hash: [u8; 32],
        /// Hash of the verified sharing certificate.
        certificate_hash: [u8; 32],
    },
    /// Test-only marker for rejected unverified inputs.
    #[cfg(test)]
    Unverified,
}

/// Verified residue input consumed by the exact bounded-secret sampler core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSmallResidueInput {
    /// Dealer contributing this residue.
    pub dealer: PartyId,
    /// Transcript label this contribution is bound to.
    pub label: SamplerLabel,
    /// ML-DSA eta distribution parameter.
    pub eta: SmallSecretEta,
    /// Residue value in `Z_m`.
    pub residue: u8,
    /// Verification provenance.
    pub verification: SmallResidueInputVerification,
}

impl VerifiedSmallResidueInput {
    /// Builds a verified residue input from a checked scaffold contribution.
    #[cfg(any(test, feature = "scaffold-dev"))]
    pub fn from_scaffold_contribution(
        label: SamplerLabel,
        eta: SmallSecretEta,
        contribution: &SmallResidueContribution,
    ) -> Result<Self, DkgError> {
        validate_small_residue_contribution(label, eta, contribution)?;
        Ok(Self {
            dealer: contribution.dealer,
            label: contribution.label,
            eta: contribution.eta,
            residue: contribution.residue,
            verification: SmallResidueInputVerification::InProcessScaffold,
        })
    }

    /// Builds a verified residue input from production IT-VSS certificate
    /// evidence.
    pub fn from_it_vss_certificate(
        dealer: PartyId,
        label: SamplerLabel,
        eta: SmallSecretEta,
        residue: u8,
        label_hash: [u8; 32],
        certificate_hash: [u8; 32],
    ) -> Self {
        Self {
            dealer,
            label,
            eta,
            residue,
            verification: SmallResidueInputVerification::ItVssCertificate {
                label_hash,
                certificate_hash,
            },
        }
    }

    /// Builds all per-coordinate verified residue inputs from one accepted
    /// vector IT-VSS opening. The vector sharing label is bound to the whole
    /// ML-DSA secret vector (`index = None`); individual sampler labels are
    /// derived per coordinate.
    pub fn from_vector_it_vss_opening<P: MlDsaParams>(
        config: &DkgConfig,
        vector: SecretVectorKind,
        accepted: &AcceptedVectorItVssSharing,
        opening: &VectorItVssReconstructionOutput,
    ) -> Result<Vec<Self>, DkgError> {
        config.validate()?;
        if accepted.context.config_hash != config.transcript_hash()
            || accepted.context.party_set_hash != dkg_party_set_hash(config)
        {
            return Err(DkgError::SmallSamplerLabelMismatch);
        }
        let expected_len = vector.coefficient_count::<P>();
        if accepted.vector_len != expected_len || opening.secret.len() != expected_len {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: expected_len,
                got: opening.secret.len(),
            });
        }
        let sharing_label = ItVssSharingLabel::new(
            config,
            accepted.context.dealer,
            ItVssSharingDomain::for_secret_vector(vector),
            None,
        )?;
        if accepted.context.label_hash != sharing_label.label_hash {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        validate_exact_party_set(
            config,
            DkgRound::Share,
            accepted.accepted_receivers.iter().copied(),
        )?;
        if opening.transcript_hash
            != hash_vector_it_vss_reconstruction(&accepted.context, &opening.secret, &opening.votes)
        {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let eta = SmallSecretEta::for_params::<P>()?;
        let certificate_hash = hash_accepted_vector_it_vss_sharing(accepted);
        if certificate_hash == [0u8; 32] {
            return Err(DkgError::UnverifiedSmallResidueInput {
                dealer: accepted.context.dealer,
            });
        }
        opening
            .secret
            .iter()
            .enumerate()
            .map(|(index, residue)| {
                let label = SamplerLabel::new::<P>(config, vector, index)?;
                let residue =
                    u8::try_from(residue.value()).map_err(|_| DkgError::InvalidSmallResidue {
                        dealer: accepted.context.dealer,
                        modulus: eta.modulus(),
                        got: u8::MAX,
                    })?;
                let input = Self::from_it_vss_certificate(
                    accepted.context.dealer,
                    label,
                    eta,
                    residue,
                    sharing_label.label_hash,
                    certificate_hash,
                );
                validate_verified_small_residue_input(label, eta, &input)?;
                Ok(input)
            })
            .collect()
    }

    /// Builds a verified residue input from a production IT-VSS certificate.
    pub fn from_verified_it_vss_certificate(
        config: &DkgConfig,
        label: SamplerLabel,
        eta: SmallSecretEta,
        residue: u8,
        sharing_label: ItVssSharingLabel,
        certificate: &VerifiedItVssSharingCertificate,
    ) -> Result<Self, DkgError> {
        Self::from_verified_it_vss_certificate_for_backend(
            config,
            label,
            eta,
            residue,
            sharing_label,
            certificate,
            ItVssBackendId::ProductionInformationChecking,
        )
    }

    fn from_verified_it_vss_certificate_for_backend(
        config: &DkgConfig,
        label: SamplerLabel,
        eta: SmallSecretEta,
        residue: u8,
        sharing_label: ItVssSharingLabel,
        certificate: &VerifiedItVssSharingCertificate,
        allowed_backend: ItVssBackendId,
    ) -> Result<Self, DkgError> {
        config.validate()?;
        if label.config_hash != config.transcript_hash()
            || sharing_label.config_hash != config.transcript_hash()
        {
            return Err(DkgError::SmallSamplerLabelMismatch);
        }
        if sharing_label.domain != ItVssSharingDomain::for_secret_vector(label.vector)
            || sharing_label.index != Some(label.coefficient_index)
        {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        if certificate.backend_id != allowed_backend {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        if certificate.dealer != sharing_label.dealer
            || certificate.label_hash != sharing_label.label_hash
        {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        validate_exact_party_set(
            config,
            DkgRound::Share,
            certificate.accepted_receivers.iter().copied(),
        )?;
        let certificate_hash = hash_verified_it_vss_sharing_certificate(certificate);
        if certificate_hash == [0u8; 32] {
            return Err(DkgError::UnverifiedSmallResidueInput {
                dealer: certificate.dealer,
            });
        }
        let input = Self::from_it_vss_certificate(
            certificate.dealer,
            label,
            eta,
            residue,
            sharing_label.label_hash,
            certificate_hash,
        );
        validate_verified_small_residue_input(label, eta, &input)?;
        Ok(input)
    }

    fn from_verified_vector_it_vss_certificate_for_backend(
        config: &DkgConfig,
        label: SamplerLabel,
        eta: SmallSecretEta,
        residue: u8,
        sharing_label: ItVssSharingLabel,
        certificate: &VerifiedItVssSharingCertificate,
        allowed_backend: ItVssBackendId,
    ) -> Result<Self, DkgError> {
        config.validate()?;
        if label.config_hash != config.transcript_hash()
            || sharing_label.config_hash != config.transcript_hash()
        {
            return Err(DkgError::SmallSamplerLabelMismatch);
        }
        if sharing_label.domain != ItVssSharingDomain::for_secret_vector(label.vector)
            || sharing_label.index.is_some()
        {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        if certificate.backend_id != allowed_backend {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        if certificate.dealer != sharing_label.dealer
            || certificate.label_hash != sharing_label.label_hash
        {
            return Err(DkgError::ItVssCertificateLabelMismatch);
        }
        validate_exact_party_set(
            config,
            DkgRound::Share,
            certificate.accepted_receivers.iter().copied(),
        )?;
        let certificate_hash = hash_verified_it_vss_sharing_certificate(certificate);
        if certificate_hash == [0u8; 32] {
            return Err(DkgError::UnverifiedSmallResidueInput {
                dealer: certificate.dealer,
            });
        }
        let input = Self::from_it_vss_certificate(
            certificate.dealer,
            label,
            eta,
            residue,
            sharing_label.label_hash,
            certificate_hash,
        );
        validate_verified_small_residue_input(label, eta, &input)?;
        Ok(input)
    }

    #[cfg(test)]
    fn unverified_for_test(
        dealer: PartyId,
        label: SamplerLabel,
        eta: SmallSecretEta,
        residue: u8,
    ) -> Self {
        Self {
            dealer,
            label,
            eta,
            residue,
            verification: SmallResidueInputVerification::Unverified,
        }
    }
}

/// One scalar share of a sampled bounded coefficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedSmallScalarShare {
    /// Receiver that owns the share.
    pub receiver: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Share value at `point`.
    pub value: Coeff,
}

/// Secret-shared small coefficient encoded over the ML-DSA field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedSmallCoeff {
    /// Transcript label for this coefficient.
    pub label: SamplerLabel,
    /// ML-DSA eta distribution parameter.
    pub eta: SmallSecretEta,
    /// Receiver shares of `x = (sum_i u_i mod m) - eta`, encoded modulo `q`.
    pub shares: Vec<SharedSmallScalarShare>,
}

/// Secret-shared small ML-DSA vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedSmallPolyVec {
    /// Vector sampled.
    pub vector: SecretVectorKind,
    /// ML-DSA eta distribution parameter.
    pub eta: SmallSecretEta,
    /// Secret-shared coefficients in polynomial-major order.
    pub coefficients: Vec<SharedSmallCoeff>,
}

/// One party's shares for a sampled small ML-DSA vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedSmallVectorPartyShare {
    /// Receiver that owns this vector share.
    pub party: PartyId,
    /// Receiver interpolation point.
    pub point: u32,
    /// Field-valued coefficient shares in polynomial-major order.
    pub coeffs: Vec<Coeff>,
}

/// Shared `s1` and temporary `s2` material sampled during DKG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedMldsaSecretMaterial {
    /// Secret signing vector `s1`; this is retained for TALUS signing.
    pub s1: SharedSmallPolyVec,
    /// Temporary vector `s2`; used for public-key assembly and then erased.
    pub s2: SharedSmallPolyVec,
}

/// Production-facing sampler for exact ML-DSA bounded secret coefficients.
///
/// This boundary consumes only `VerifiedSmallResidueInput` values. Production
/// callers must obtain those inputs from production IT-VSS certificates; raw
/// `SmallResidueContribution` sampling is intentionally kept out of this
/// trait and exists only in test/scaffold extension helpers.
pub trait DistributedSmallSampler {
    /// Samples one coefficient from verified residue inputs.
    fn sample_verified_small_coeff<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: SamplerLabel,
        inputs: &[VerifiedSmallResidueInput],
    ) -> Result<SharedSmallCoeff, DkgError>;

    /// Samples one full ML-DSA secret vector from verified residue inputs.
    fn sample_verified_small_polyvec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        vector: SecretVectorKind,
        inputs: &[Vec<VerifiedSmallResidueInput>],
    ) -> Result<SharedSmallPolyVec, DkgError>;
}

/// Test/scaffold extension for sampling directly from raw residue broadcasts.
///
/// Production code must not depend on these methods because raw residue
/// broadcasts are not sufficient evidence. Use `sample_verified_small_*`
/// after IT-VSS certificate validation instead.
#[cfg(any(test, feature = "scaffold-dev"))]
pub trait DistributedSmallSamplerScaffoldExt: DistributedSmallSampler {
    /// Samples one coefficient from dealer residue contributions.
    fn sample_small_coeff<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: SamplerLabel,
        contributions: &[SmallResidueContribution],
    ) -> Result<SharedSmallCoeff, DkgError>;

    /// Samples one full ML-DSA secret vector from raw residue contributions.
    fn sample_small_polyvec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        vector: SecretVectorKind,
        contributions: &[Vec<SmallResidueContribution>],
    ) -> Result<SharedSmallPolyVec, DkgError>;
}

/// Exact verified `Z_m` bounded sampler.
///
/// For each coefficient, parties contribute `u_i in Z_m`, the sampler computes
/// `r = sum_i u_i mod m`, and shares `x = r - eta` over the ML-DSA field.
/// If at least one honest contribution is uniform in `Z_m`, then `r` is
/// uniform over `Z_m` for any fixed adversarial contribution sum. Production
/// callers provide verified IT-VSS-backed residues; test/scaffold builds may
/// additionally adapt raw contributions through `DistributedSmallSamplerScaffoldExt`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDistributedSmallSampler {
    seed: [u8; 32],
    counter: u64,
}

impl VerifiedDistributedSmallSampler {
    /// Creates a deterministic exact sampler.
    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

/// Backward-compatible test/dev name for the old in-process sampler.
#[cfg(any(test, feature = "scaffold-dev"))]
pub type InProcessDistributedSmallSampler = VerifiedDistributedSmallSampler;

impl DistributedSmallSampler for VerifiedDistributedSmallSampler {
    fn sample_verified_small_coeff<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: SamplerLabel,
        inputs: &[VerifiedSmallResidueInput],
    ) -> Result<SharedSmallCoeff, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        let residue = sum_verified_small_residues_mod(config, label, eta, inputs)?;
        let coefficient = reduce_mod_q::<P>(Coeff::from(residue) - eta.bound());
        let shares = self.share_sampled_coefficient::<P>(config, label, coefficient)?;

        Ok(SharedSmallCoeff { label, eta, shares })
    }

    fn sample_verified_small_polyvec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        vector: SecretVectorKind,
        inputs: &[Vec<VerifiedSmallResidueInput>],
    ) -> Result<SharedSmallPolyVec, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        let expected = vector.coefficient_count::<P>();
        if inputs.len() != expected {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected,
                got: inputs.len(),
            });
        }

        let mut coefficients = Vec::with_capacity(expected);
        for (index, coefficient_inputs) in inputs.iter().enumerate() {
            let label = SamplerLabel::new::<P>(config, vector, index)?;
            coefficients.push(self.sample_verified_small_coeff::<P>(
                config,
                label,
                coefficient_inputs,
            )?);
        }

        Ok(SharedSmallPolyVec {
            vector,
            eta,
            coefficients,
        })
    }
}

#[cfg(any(test, feature = "scaffold-dev"))]
impl DistributedSmallSamplerScaffoldExt for VerifiedDistributedSmallSampler {
    fn sample_small_coeff<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: SamplerLabel,
        contributions: &[SmallResidueContribution],
    ) -> Result<SharedSmallCoeff, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        let inputs =
            verified_small_residue_inputs_from_scaffold_contributions(label, eta, contributions)?;
        self.sample_verified_small_coeff::<P>(config, label, &inputs)
    }

    fn sample_small_polyvec<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        vector: SecretVectorKind,
        contributions: &[Vec<SmallResidueContribution>],
    ) -> Result<SharedSmallPolyVec, DkgError> {
        let eta = SmallSecretEta::for_params::<P>()?;
        let expected = vector.coefficient_count::<P>();
        if contributions.len() != expected {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected,
                got: contributions.len(),
            });
        }

        let inputs = contributions
            .iter()
            .enumerate()
            .map(|(index, coefficient_contributions)| {
                let label = SamplerLabel::new::<P>(config, vector, index)?;
                verified_small_residue_inputs_from_scaffold_contributions(
                    label,
                    eta,
                    coefficient_contributions,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.sample_verified_small_polyvec::<P>(config, vector, &inputs)
    }
}

impl VerifiedDistributedSmallSampler {
    fn share_sampled_coefficient<P: MlDsaParams>(
        &mut self,
        config: &DkgConfig,
        label: SamplerLabel,
        coefficient: Coeff,
    ) -> Result<Vec<SharedSmallScalarShare>, DkgError> {
        let share_index = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(DkgError::Backend("small sampler counter overflow"))?;

        let mut polynomial = Vec::with_capacity(usize::from(config.threshold));
        polynomial.push(coefficient);
        for degree in 1..usize::from(config.threshold) {
            polynomial.push(small_sampler_share_mask::<P>(
                self.seed,
                share_index,
                label,
                degree,
            ));
        }

        config
            .interpolation_points::<P>()?
            .into_iter()
            .map(|(receiver, point)| {
                Ok(SharedSmallScalarShare {
                    receiver,
                    point,
                    value: evaluate_shamir_polynomial::<P>(&polynomial, point)?,
                })
            })
            .collect()
    }
}

/// Computes `sum_i u_i mod m` after validating contribution shape, bitness,
/// range, and transcript label.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn sum_small_residues_mod(
    config: &DkgConfig,
    label: SamplerLabel,
    eta: SmallSecretEta,
    contributions: &[SmallResidueContribution],
) -> Result<u8, DkgError> {
    let inputs =
        verified_small_residue_inputs_from_scaffold_contributions(label, eta, contributions)?;
    sum_verified_small_residues_mod(config, label, eta, &inputs)
}

/// Adapts checked in-process scaffold residue contributions into verified
/// sampler inputs.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn verified_small_residue_inputs_from_scaffold_contributions(
    label: SamplerLabel,
    eta: SmallSecretEta,
    contributions: &[SmallResidueContribution],
) -> Result<Vec<VerifiedSmallResidueInput>, DkgError> {
    contributions
        .iter()
        .map(|contribution| {
            VerifiedSmallResidueInput::from_scaffold_contribution(label, eta, contribution)
        })
        .collect()
}

/// Computes `sum_i u_i mod m` from verified residue inputs.
pub fn sum_verified_small_residues_mod(
    config: &DkgConfig,
    label: SamplerLabel,
    eta: SmallSecretEta,
    inputs: &[VerifiedSmallResidueInput],
) -> Result<u8, DkgError> {
    config.validate()?;
    if label.config_hash != config.transcript_hash() {
        return Err(DkgError::SmallSamplerLabelMismatch);
    }
    if inputs.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: config.parties.len(),
            got: inputs.len(),
        });
    }

    let mut seen = Vec::with_capacity(inputs.len());
    let mut sum = 0u16;
    for input in inputs {
        if !config.parties.contains(&input.dealer) {
            return Err(DkgError::UnknownParty(input.dealer));
        }
        if seen.contains(&input.dealer) {
            return Err(DkgError::DuplicateRoundSender {
                round: DkgRound::Share,
                sender: input.dealer,
            });
        }
        seen.push(input.dealer);
        validate_verified_small_residue_input(label, eta, input)?;
        sum += u16::from(input.residue);
    }

    Ok((sum % u16::from(eta.modulus())) as u8)
}

/// Converts one sampled small vector into per-party field-share vectors.
pub fn shared_small_polyvec_party_shares<P: MlDsaParams>(
    config: &DkgConfig,
    shared: &SharedSmallPolyVec,
) -> Result<Vec<SharedSmallVectorPartyShare>, DkgError> {
    let expected = shared.vector.coefficient_count::<P>();
    if shared.coefficients.len() != expected {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected,
            got: shared.coefficients.len(),
        });
    }
    if shared.eta != SmallSecretEta::for_params::<P>()? {
        return Err(DkgError::Backend("small vector eta mismatch"));
    }

    let mut out = Vec::with_capacity(config.parties.len());
    for (party, point) in config.interpolation_points::<P>()? {
        let mut coeffs = Vec::with_capacity(expected);
        for (index, coefficient) in shared.coefficients.iter().enumerate() {
            let expected_label = SamplerLabel::new::<P>(config, shared.vector, index)?;
            if coefficient.label != expected_label {
                return Err(DkgError::SmallSamplerLabelMismatch);
            }
            let Some(share) = coefficient
                .shares
                .iter()
                .find(|share| share.receiver == party)
            else {
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: config.parties.len(),
                    got: coefficient.shares.len(),
                });
            };
            if share.point != point {
                return Err(DkgError::InvalidSharePoint {
                    party,
                    expected: point,
                    got: share.point,
                });
            }
            coeffs.push(reduce_mod_q::<P>(share.value));
        }
        out.push(SharedSmallVectorPartyShare {
            party,
            point,
            coeffs,
        });
    }

    Ok(out)
}

/// Converts sampled `s1` material into canonical DKG secret-share packages.
pub fn sampled_s1_to_dkg_secret_shares<P: MlDsaParams>(
    config: &DkgConfig,
    s1: &SharedSmallPolyVec,
) -> Result<Vec<DkgSecretShare>, DkgError> {
    if s1.vector != SecretVectorKind::S1 {
        return Err(DkgError::Backend("expected sampled s1 vector"));
    }

    shared_small_polyvec_party_shares::<P>(config, s1)?
        .into_iter()
        .map(|share| {
            let typed =
                BoundedSecretVectorShare::new::<P>(config, share.party, share.point, share.coeffs)?;
            Ok(DkgSecretShare {
                party: share.party,
                s1_share: typed.encode::<P>(config)?,
                s2_share: vec![0],
                t0_share: vec![0],
                pairwise_seed_shares: Vec::new(),
            })
        })
        .collect()
}

/// Rejects insecure Power2Round backends for production release paths.
pub fn ensure_power2round_backend_allowed_for_release(
    backend_id: Power2RoundBackendId,
) -> Result<(), DkgError> {
    match backend_id {
        Power2RoundBackendId::ProductionItMpc => Ok(()),
        #[cfg(test)]
        Power2RoundBackendId::InsecureClearSimulator
        | Power2RoundBackendId::LocalPrimeFieldSimulator
        | Power2RoundBackendId::InProcessShamirSimulator
        | Power2RoundBackendId::NetworkedShamirSimulator
        | Power2RoundBackendId::TransportBackedShamirSimulator
        | Power2RoundBackendId::RuntimeCoordinatedTransportShamirSimulator
        | Power2RoundBackendId::TransportBackedPerPartySkeleton
        | Power2RoundBackendId::TransportBackedPerPartyDriver => {
            Err(DkgError::InsecurePower2RoundBackend)
        }
    }
}

/// Ensures Power2Round public evidence is bound to the public `t1`, config,
/// rho, and selected backend identity.
pub fn ensure_power2round_evidence_matches_public_t1(
    config: &DkgConfig,
    rho: [u8; 32],
    t1: &PublicT1,
    evidence: &Power2RoundEvidence,
) -> Result<(), DkgError> {
    if t1.bytes.len() != config.suite.t1_len() {
        return Err(DkgError::InvalidT1Length {
            expected: config.suite.t1_len(),
            got: t1.bytes.len(),
        });
    }
    let expected = power2round_certify_public_t1_evidence(
        evidence.backend_id,
        config,
        PublicKeyAssemblyLabel::new(config, rho),
        t1,
    );
    if *evidence != expected {
        return Err(DkgError::Power2RoundEvidenceRequired);
    }
    Ok(())
}

/// Rejects DKG certificates that still depend on scaffold setup or explicit
/// release blockers.
pub fn ensure_dkg_certificate_allowed_for_release(
    certificate: &PublicKeyAssemblyCertificate,
) -> Result<(), DkgError> {
    ensure_power2round_backend_allowed_for_release(certificate.power2round.backend_id)?;
    let runtime_evidence = certificate
        .power2round_runtime
        .as_ref()
        .ok_or(DkgError::BlockedPendingReview)?;
    ensure_production_power2round_runtime_evidence_for_release(runtime_evidence)?;
    let setup = certificate
        .setup
        .as_ref()
        .ok_or(DkgError::MissingDkgSetupCertificate)?;
    if setup.setup_backend_id != DkgSetupBackendId::ProductionInformationTheoretic {
        return Err(DkgError::InsecureDkgSetupBackend);
    }
    if setup.it_vss_backend_id != ItVssBackendId::ProductionInformationChecking {
        return Err(DkgError::ItVssCertificateBackendMismatch);
    }
    if !setup.release_blockers.is_empty() {
        return Err(DkgError::DkgCertificateReleaseBlockers);
    }
    Ok(())
}

/// Scans persisted IT-VSS setup artifacts and rejects scaffold backend ids in
/// production release paths.
pub fn ensure_it_vss_artifact_log_allowed_for_release<L: DkgWireMessageLog>(
    log: &L,
) -> Result<(), DkgError> {
    for record in log.dkg_wire_records() {
        if record.message.header.payload_kind != PayloadKind::DkgItVssArtifact {
            continue;
        }
        match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?
        {
            DkgItVssArtifactPayload::PublicCommitment(commitment) => {
                if ItVssBackendId::from_u8(commitment.backend_id)
                    != Some(ItVssBackendId::ProductionInformationChecking)
                {
                    return Err(DkgError::ItVssCertificateBackendMismatch);
                }
            }
            DkgItVssArtifactPayload::PublicCommitmentBatch(commitments) => {
                for commitment in commitments {
                    if ItVssBackendId::from_u8(commitment.backend_id)
                        != Some(ItVssBackendId::ProductionInformationChecking)
                    {
                        return Err(DkgError::ItVssCertificateBackendMismatch);
                    }
                }
            }
            DkgItVssArtifactPayload::PublicPrecommitment(_) => {}
            DkgItVssArtifactPayload::PublicAuditRecords(_) => {}
            DkgItVssArtifactPayload::PublicConsistencyRecords(_) => {}
            DkgItVssArtifactPayload::ComplaintResolution(resolution) => {
                for certificate in resolution.certificates {
                    if ItVssBackendId::from_u8(certificate.backend_id)
                        != Some(ItVssBackendId::ProductionInformationChecking)
                    {
                        return Err(DkgError::ItVssCertificateBackendMismatch);
                    }
                }
            }
            DkgItVssArtifactPayload::PublicCoinShare(_) => {}
        }
    }
    Ok(())
}

/// Rejects release artifact logs that contain private setup payloads. Public
/// release bundles may carry IT-VSS public artifacts and certificates, but not
/// directed VSS/private-share payloads, raw information-checking deliveries, or
/// private transport records.
pub fn ensure_dkg_setup_log_excludes_forbidden_release_payloads<L: DkgWireMessageLog>(
    log: &L,
) -> Result<(), DkgError> {
    for record in log.dkg_wire_records() {
        ensure_public_payload_excludes_retained_receiver_tags(&record.message.payload)?;
        if matches!(
            record.direction,
            PrimeFieldMpcWireDirection::SentPrivate | PrimeFieldMpcWireDirection::AcceptedPrivate
        ) {
            return Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload);
        }
        if record.message.header.payload_kind == PayloadKind::DkgShare {
            return Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload);
        }
        if record
            .message
            .payload
            .starts_with(IT_VSS_PRIVATE_DELIVERY_MAGIC)
            || record
                .message
                .payload
                .starts_with(IT_VSS_PRIVATE_DELIVERY_BATCH_MAGIC)
            || record
                .message
                .payload
                .starts_with(RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC)
            || record
                .message
                .payload
                .starts_with(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_MAGIC)
            || record
                .message
                .payload
                .starts_with(IN_PROCESS_SCALAR_VSS_PRIVATE_SHARE_VECTOR_MAGIC)
        {
            return Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload);
        }
    }
    Ok(())
}

/// Rejects public payload bytes that carry retained receiver-side IC tag
/// material.
pub fn ensure_public_payload_excludes_retained_receiver_tags(
    payload: &[u8],
) -> Result<(), DkgError> {
    if payload
        .windows(RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC.len())
        .any(|window| window == RETAINED_RECEIVER_TAG_PUBLIC_ARTIFACT_MAGIC)
    {
        return Err(DkgError::DkgReleaseArtifactContainsPrivateSetupPayload);
    }
    Ok(())
}

fn recover_it_vss_artifacts_from_dkg_wire_records(
    records: &[DkgWireMessageRecord],
) -> Result<(Vec<ItVssPublicCommitment>, Option<ItVssComplaintResolution>), DkgError> {
    let mut public_commitments = Vec::new();
    let mut resolution = None;
    for record in records {
        if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
            || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
        {
            continue;
        }
        match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?
        {
            DkgItVssArtifactPayload::PublicCommitment(commitment) => {
                public_commitments.push(it_vss_public_commitment_from_wire(&commitment)?);
            }
            DkgItVssArtifactPayload::PublicCommitmentBatch(commitments) => {
                for commitment in commitments {
                    public_commitments.push(it_vss_public_commitment_from_wire(&commitment)?);
                }
            }
            DkgItVssArtifactPayload::PublicPrecommitment(_) => {}
            DkgItVssArtifactPayload::PublicAuditRecords(_) => {}
            DkgItVssArtifactPayload::PublicConsistencyRecords(_) => {}
            DkgItVssArtifactPayload::ComplaintResolution(next) => {
                if resolution.is_some() {
                    return Err(DkgError::PrimeFieldMpcReplayDetected);
                }
                resolution = Some(it_vss_resolution_from_wire(&next)?);
            }
            DkgItVssArtifactPayload::PublicCoinShare(_) => {}
        }
    }
    Ok((public_commitments, resolution))
}

fn recover_it_vss_public_precommitments_from_dkg_wire_records(
    records: &[DkgWireMessageRecord],
) -> Result<Vec<ItVssPublicPrecommitment>, DkgError> {
    let mut precommitments = Vec::new();
    for record in records {
        if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
            || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
        {
            continue;
        }
        match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?
        {
            DkgItVssArtifactPayload::PublicPrecommitment(precommitment) => {
                precommitments.push(it_vss_public_precommitment_from_wire(&precommitment)?);
            }
            DkgItVssArtifactPayload::PublicCommitment(_)
            | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
            | DkgItVssArtifactPayload::PublicAuditRecords(_)
            | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
            | DkgItVssArtifactPayload::ComplaintResolution(_)
            | DkgItVssArtifactPayload::PublicCoinShare(_) => {}
        }
    }
    Ok(precommitments)
}

fn recover_it_vss_public_coin_shares_from_dkg_wire_records(
    records: &[DkgWireMessageRecord],
) -> Result<Vec<ProductionItVssPublicCoinShare>, DkgError> {
    let mut shares = Vec::new();
    for record in records {
        if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
            || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
        {
            continue;
        }
        match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?
        {
            DkgItVssArtifactPayload::PublicCoinShare(share) => {
                shares.push(it_vss_public_coin_share_from_wire(&share));
            }
            DkgItVssArtifactPayload::PublicCommitment(_)
            | DkgItVssArtifactPayload::PublicPrecommitment(_)
            | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
            | DkgItVssArtifactPayload::PublicAuditRecords(_)
            | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
            | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
        }
    }
    Ok(shares)
}

fn recover_it_vss_public_audit_records_from_dkg_wire_records(
    records: &[DkgWireMessageRecord],
) -> Result<Vec<ProductionItVssAuditRecord>, DkgError> {
    let mut out = Vec::new();
    for record in records {
        if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
            || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
        {
            continue;
        }
        match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?
        {
            DkgItVssArtifactPayload::PublicAuditRecords(records) => {
                out.extend(records.iter().map(it_vss_audit_record_from_wire));
            }
            DkgItVssArtifactPayload::PublicCommitment(_)
            | DkgItVssArtifactPayload::PublicPrecommitment(_)
            | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
            | DkgItVssArtifactPayload::PublicCoinShare(_)
            | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
            | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
        }
    }
    Ok(out)
}

fn recover_it_vss_public_consistency_records_from_dkg_wire_records(
    records: &[DkgWireMessageRecord],
) -> Result<Vec<ProductionItVssConsistencyRecord>, DkgError> {
    let mut out = Vec::new();
    for record in records {
        if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
            || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
        {
            continue;
        }
        match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
            .map_err(|_| DkgError::PrimeFieldMpcTransport)?
        {
            DkgItVssArtifactPayload::PublicConsistencyRecords(records) => {
                out.extend(records.iter().map(it_vss_consistency_record_from_wire));
            }
            DkgItVssArtifactPayload::PublicCommitment(_)
            | DkgItVssArtifactPayload::PublicPrecommitment(_)
            | DkgItVssArtifactPayload::PublicCommitmentBatch(_)
            | DkgItVssArtifactPayload::PublicCoinShare(_)
            | DkgItVssArtifactPayload::PublicAuditRecords(_)
            | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
        }
    }
    Ok(out)
}

/// Ensures a production release certificate is matched by the encoded setup
/// log artifacts it claims. This is stricter than backend-id scanning: it
/// recomputes artifact hashes from the durable log and compares them with the
/// certificate fields.
pub fn ensure_dkg_setup_log_matches_certificate_for_release<L: DkgWireMessageLog>(
    log: &L,
    certificate: &PublicKeyAssemblyCertificate,
) -> Result<(), DkgError> {
    ensure_dkg_certificate_allowed_for_release(certificate)?;
    ensure_it_vss_artifact_log_allowed_for_release(log)?;
    ensure_dkg_setup_log_excludes_forbidden_release_payloads(log)?;
    let setup = certificate
        .setup
        .as_ref()
        .ok_or(DkgError::MissingDkgSetupCertificate)?;
    let (public_commitments, resolution) =
        recover_it_vss_artifacts_from_dkg_wire_records(log.dkg_wire_records())?;
    let resolution = resolution.ok_or(DkgError::MissingDkgSetupCertificate)?;
    let public_hash = hash_it_vss_public_artifacts(&public_commitments);
    if public_hash != setup.it_vss_public_artifact_hash {
        return Err(DkgError::TranscriptMismatch {
            expected: KeygenTranscriptHash(setup.it_vss_public_artifact_hash),
            got: KeygenTranscriptHash(public_hash),
        });
    }
    let resolution_hash = hash_it_vss_complaint_resolution(&resolution);
    if resolution_hash != setup.it_vss_resolution_hash {
        return Err(DkgError::TranscriptMismatch {
            expected: KeygenTranscriptHash(setup.it_vss_resolution_hash),
            got: KeygenTranscriptHash(resolution_hash),
        });
    }
    Ok(())
}

/// Ensures persisted IT-VSS public artifacts use only production batched
/// `s1`/`s2` vector labels for the configured DKG parties.
///
/// A production DKG setup must not contain scalar-per-coefficient IT-VSS
/// commitments. Those scalar labels have an index or an auxiliary domain and
/// are useful only for correctness scaffolds.
pub fn ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release<L: DkgWireMessageLog>(
    config: &DkgConfig,
    log: &L,
) -> Result<(), DkgError> {
    config.validate()?;
    let allowed = config
        .parties
        .iter()
        .flat_map(|&dealer| {
            [SecretVectorKind::S1, SecretVectorKind::S2]
                .into_iter()
                .map(move |vector| {
                    ItVssSharingLabel::new(
                        config,
                        dealer,
                        ItVssSharingDomain::for_secret_vector(vector),
                        None,
                    )
                    .map(|label| (dealer, label.label_hash))
                })
        })
        .collect::<Result<Vec<_>, DkgError>>()?;

    let (public_commitments, resolution) =
        recover_it_vss_artifacts_from_dkg_wire_records(log.dkg_wire_records())?;
    for commitment in &public_commitments {
        if !allowed.iter().any(|&(dealer, label_hash)| {
            dealer == commitment.dealer && label_hash == commitment.label_hash
        }) {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
    }
    if let Some(resolution) = resolution {
        for certificate in resolution.certificates {
            if !allowed.iter().any(|&(dealer, label_hash)| {
                dealer == certificate.dealer && label_hash == certificate.label_hash
            }) {
                return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
            }
        }
    }
    Ok(())
}

/// Ensures the public IT-VSS setup log contains the production vector flow for
/// every expected `s1`/`s2` sharing:
///
/// `public precommitment -> post-commitment public coins -> final metadata`.
///
/// Final commitments without the earlier public-coin phase are valid test
/// artifacts but are not a release-capable native DKG setup transcript.
pub fn ensure_it_vss_public_coin_flow_complete_for_release<L: DkgWireMessageLog>(
    config: &DkgConfig,
    log: &L,
) -> Result<(), DkgError> {
    config.validate()?;
    let labels = sampler_vector_it_vss_sharing_labels(
        config,
        &[SecretVectorKind::S1, SecretVectorKind::S2],
    )?;
    let expected_keys = labels
        .iter()
        .map(|label| (label.dealer, label.label_hash))
        .collect::<Vec<_>>();

    let precommitments =
        recover_it_vss_public_precommitments_from_dkg_wire_records(log.dkg_wire_records())?;
    for precommitment in &precommitments {
        if precommitment.backend_id != ItVssBackendId::ProductionInformationChecking {
            return Err(DkgError::ItVssCertificateBackendMismatch);
        }
        if !expected_keys.iter().any(|&(dealer, label_hash)| {
            dealer == precommitment.dealer && label_hash == precommitment.label_hash
        }) {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
    }
    let selected_precommitments =
        select_expected_it_vss_public_precommitments(&precommitments, &expected_keys)?;
    if selected_precommitments.len() != expected_keys.len() {
        return Err(DkgError::MissingDkgSetupCertificate);
    }

    let (public_commitments, _) =
        recover_it_vss_artifacts_from_dkg_wire_records(log.dkg_wire_records())?;
    let selected_commitments =
        select_expected_it_vss_public_commitments(&public_commitments, &expected_keys)?;
    if selected_commitments.len() != expected_keys.len() {
        return Err(DkgError::MissingDkgSetupCertificate);
    }

    ensure_it_vss_public_coin_flow_order_for_release(log.dkg_wire_records(), &expected_keys)?;

    let coin_shares =
        recover_it_vss_public_coin_shares_from_dkg_wire_records(log.dkg_wire_records())?;
    for share in &coin_shares {
        if !labels
            .iter()
            .any(|label| label.label_hash == share.label_hash)
        {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
    }
    for label in labels {
        let shares = coin_shares
            .iter()
            .filter(|share| share.label_hash == label.label_hash)
            .copied()
            .collect::<Vec<_>>();
        production_it_vss_public_coin_transcript(config, label.label_hash, &shares)?;
    }

    Ok(())
}

/// Ensures the public IT-VSS log contains replayable audit/discard and
/// vector-polynomial consistency transcripts for every release-capable
/// `s1`/`s2` vector sharing.
pub fn ensure_it_vss_public_audit_consistency_complete_for_release<L: DkgWireMessageLog>(
    config: &DkgConfig,
    log: &L,
) -> Result<(), DkgError> {
    config.validate()?;
    let labels = sampler_vector_it_vss_sharing_labels(
        config,
        &[SecretVectorKind::S1, SecretVectorKind::S2],
    )?;
    let expected_keys = labels
        .iter()
        .map(|label| (label.dealer, label.label_hash))
        .collect::<Vec<_>>();
    let audit_records =
        recover_it_vss_public_audit_records_from_dkg_wire_records(log.dkg_wire_records())?;
    let consistency_records =
        recover_it_vss_public_consistency_records_from_dkg_wire_records(log.dkg_wire_records())?;
    let (public_commitments, _) =
        recover_it_vss_artifacts_from_dkg_wire_records(log.dkg_wire_records())?;
    let selected_commitments =
        select_expected_it_vss_public_commitments(&public_commitments, &expected_keys)?;
    if selected_commitments.len() != expected_keys.len() {
        return Err(DkgError::MissingDkgSetupCertificate);
    }
    let coin_shares =
        recover_it_vss_public_coin_shares_from_dkg_wire_records(log.dkg_wire_records())?;
    let mut public_coin_hash_by_label = std::collections::BTreeMap::new();
    for &(_, label_hash) in &expected_keys {
        let shares = coin_shares
            .iter()
            .filter(|share| share.label_hash == label_hash)
            .copied()
            .collect::<Vec<_>>();
        let transcript = production_it_vss_public_coin_transcript(config, label_hash, &shares)?;
        public_coin_hash_by_label.insert(label_hash, transcript.coin_hash);
    }

    let mut audit_seen = std::collections::BTreeSet::new();
    for record in &audit_records {
        if !expected_keys
            .iter()
            .any(|&(dealer, label_hash)| dealer == record.dealer && label_hash == record.label_hash)
            || !config.parties.contains(&record.holder)
            || !config.parties.contains(&record.receiver)
        {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
        ensure_public_payload_excludes_retained_receiver_tags(&record.audited_receiver_tag)?;
        validate_opened_audited_vector_receiver_tag_payload(
            &record.audited_receiver_tag,
            record.holder,
            record.receiver,
            record.tag_index,
        )?;
        if hash_opened_audited_vector_receiver_tag_payload(&record.audited_receiver_tag)
            != record.audited_receiver_tag_hash
        {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
        if !audit_seen.insert((
            record.dealer.0,
            record.holder.0,
            record.receiver.0,
            record.label_hash,
            record.tag_index,
        )) {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
    }

    let mut consistency_seen = std::collections::BTreeSet::new();
    for record in &consistency_records {
        if !expected_keys
            .iter()
            .any(|&(dealer, label_hash)| dealer == record.dealer && label_hash == record.label_hash)
            || !config.parties.contains(&record.holder)
            || record.challenge_bit > 1
        {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
        ensure_public_payload_excludes_retained_receiver_tags(&record.masked_eval)?;
        validate_opened_vector_consistency_masked_eval_payload(
            &record.masked_eval,
            record.dealer,
            record.holder,
            record.label_hash,
            record.round,
            record.challenge_bit,
        )?;
        if hash_opened_vector_consistency_masked_eval_payload(&record.masked_eval)
            != record.masked_eval_hash
        {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
        let public_coin_hash = public_coin_hash_by_label
            .get(&record.label_hash)
            .copied()
            .ok_or(DkgError::MissingDkgSetupCertificate)?;
        let expected_challenge_bit = production_it_vss_consistency_challenge_bit_with_coin(
            record.label_hash,
            Some(public_coin_hash),
            record.round as usize,
        );
        if record.challenge_bit != expected_challenge_bit {
            return Err(DkgError::ItVssScalarPerCoefficientDkgReleaseBlocked);
        }
        if !consistency_seen.insert((
            record.dealer.0,
            record.holder.0,
            record.label_hash,
            record.round,
        )) {
            return Err(DkgError::PrimeFieldMpcReplayDetected);
        }
    }

    for &(dealer, label_hash) in &expected_keys {
        let mut expected_audit_tag_count = None;
        let mut expected_consistency_round_count = None;
        let mut expected_vector_len = None;
        for &holder in &config.parties {
            for &receiver in &config.parties {
                let mut tag_indices = audit_seen
                    .iter()
                    .filter_map(
                        |&(seen_dealer, seen_holder, seen_receiver, seen_label_hash, tag_index)| {
                            if seen_dealer == dealer.0
                                && seen_holder == holder.0
                                && seen_receiver == receiver.0
                                && seen_label_hash == label_hash
                            {
                                Some(tag_index)
                            } else {
                                None
                            }
                        },
                    )
                    .collect::<Vec<_>>();
                if tag_indices.is_empty() {
                    return Err(DkgError::MissingDkgSetupCertificate);
                }
                tag_indices.sort_unstable();
                for (expected, actual) in tag_indices.iter().copied().enumerate() {
                    if actual as usize != expected {
                        return Err(DkgError::MissingDkgSetupCertificate);
                    }
                }
                match expected_audit_tag_count {
                    Some(expected) if expected != tag_indices.len() => {
                        return Err(DkgError::MissingDkgSetupCertificate);
                    }
                    None => expected_audit_tag_count = Some(tag_indices.len()),
                    _ => {}
                }
            }
            let mut rounds = consistency_seen
                .iter()
                .filter_map(|&(seen_dealer, seen_holder, seen_label_hash, round)| {
                    if seen_dealer == dealer.0
                        && seen_holder == holder.0
                        && seen_label_hash == label_hash
                    {
                        Some(round)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if rounds.is_empty() {
                return Err(DkgError::MissingDkgSetupCertificate);
            }
            rounds.sort_unstable();
            for (expected, actual) in rounds.iter().copied().enumerate() {
                if actual as usize != expected {
                    return Err(DkgError::MissingDkgSetupCertificate);
                }
            }
            match expected_consistency_round_count {
                Some(expected) if expected != rounds.len() => {
                    return Err(DkgError::MissingDkgSetupCertificate);
                }
                None => expected_consistency_round_count = Some(rounds.len()),
                _ => {}
            }
            for record in consistency_records.iter().filter(|record| {
                record.dealer == dealer
                    && record.holder == holder
                    && record.label_hash == label_hash
            }) {
                let value_len = opened_vector_consistency_masked_eval_len(&record.masked_eval)?;
                match expected_vector_len {
                    Some(expected) if expected != value_len => {
                        return Err(DkgError::ItVssVectorLengthMismatch {
                            expected,
                            got: value_len,
                        });
                    }
                    None => expected_vector_len = Some(value_len),
                    _ => {}
                }
            }
        }
        let commitment = selected_commitments
            .iter()
            .find(|commitment| commitment.dealer == dealer && commitment.label_hash == label_hash)
            .ok_or(DkgError::MissingDkgSetupCertificate)?;
        let public_coin_hash = public_coin_hash_by_label
            .get(&label_hash)
            .copied()
            .ok_or(DkgError::MissingDkgSetupCertificate)?;
        let audit_for_key = audit_records
            .iter()
            .filter(|record| record.dealer == dealer && record.label_hash == label_hash)
            .cloned()
            .collect::<Vec<_>>();
        let consistency_for_key = consistency_records
            .iter()
            .filter(|record| record.dealer == dealer && record.label_hash == label_hash)
            .cloned()
            .collect::<Vec<_>>();
        verify_production_it_vss_public_metadata_hash(
            commitment,
            expected_vector_len.ok_or(DkgError::MissingDkgSetupCertificate)?,
            public_coin_hash,
            hash_production_it_vss_audit_records(&audit_for_key),
            hash_production_it_vss_consistency_records(&consistency_for_key),
            expected_audit_tag_count.ok_or(DkgError::MissingDkgSetupCertificate)?,
            expected_consistency_round_count.ok_or(DkgError::MissingDkgSetupCertificate)?,
        )?;
    }
    ensure_it_vss_public_audit_consistency_order_for_release(log.dkg_wire_records(), &expected_keys)
}

/// Public replay result for the durable vector IT-VSS setup transcript.
///
/// This is the observer-facing Phase 2 boundary: it reconstructs the public
/// `s1`/`s2` vector IT-VSS transcript from durable wire logs and reaches the
/// same accepted/rejected dealer decision as the persisted complaint
/// resolution. It does not inspect private deliveries or retained receiver
/// tags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayedItVssPublicLogDecision {
    /// Dealers accepted by the replayed complaint-resolution artifact.
    pub accepted_dealers: Vec<PartyId>,
    /// Dealers rejected by the replayed complaint-resolution artifact.
    pub rejected_dealers: Vec<PartyId>,
    /// Hash of replayed public IT-VSS commitments.
    pub public_artifact_hash: [u8; 32],
    /// Hash of the replayed complaint-resolution artifact.
    pub resolution_hash: [u8; 32],
    /// Hash of replayed public audit/discard records.
    pub public_audit_hash: [u8; 32],
    /// Hash of replayed public vector consistency records.
    pub public_consistency_hash: [u8; 32],
    /// Transcript hash binding the replay decision to the DKG config and all
    /// replayed public artifacts.
    pub replay_transcript_hash: [u8; 32],
}

/// Replays durable public vector IT-VSS logs and returns the accepted/rejected
/// dealer decision.
///
/// This is stricter than a presence scan: it validates the production vector
/// label set, public-coin flow, audit/consistency phase order, complaint
/// resolution shape, and one certificate for every accepted dealer/vector
/// sharing. Later Phase 2 hardening extends this boundary with hash-level
/// validation of opened audit tags and masked consistency evaluations.
pub fn replay_it_vss_public_log_for_release<L: DkgWireMessageLog>(
    config: &DkgConfig,
    log: &L,
) -> Result<ReplayedItVssPublicLogDecision, DkgError> {
    config.validate()?;
    ensure_it_vss_artifact_log_allowed_for_release(log)?;
    ensure_dkg_setup_log_excludes_forbidden_release_payloads(log)?;
    ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release(config, log)?;
    ensure_it_vss_public_coin_flow_complete_for_release(config, log)?;
    ensure_it_vss_public_audit_consistency_complete_for_release(config, log)?;

    let labels = sampler_vector_it_vss_sharing_labels(
        config,
        &[SecretVectorKind::S1, SecretVectorKind::S2],
    )?;
    let expected_keys = labels
        .iter()
        .map(|label| (label.dealer, label.label_hash))
        .collect::<Vec<_>>();

    let precommitments =
        recover_it_vss_public_precommitments_from_dkg_wire_records(log.dkg_wire_records())?;
    let selected_precommitments =
        select_expected_it_vss_public_precommitments(&precommitments, &expected_keys)?;
    if selected_precommitments.len() != expected_keys.len() {
        return Err(DkgError::MissingDkgSetupCertificate);
    }

    let coin_shares =
        recover_it_vss_public_coin_shares_from_dkg_wire_records(log.dkg_wire_records())?;
    for &(_, label_hash) in &expected_keys {
        let shares = coin_shares
            .iter()
            .filter(|share| share.label_hash == label_hash)
            .cloned()
            .collect::<Vec<_>>();
        production_it_vss_public_coin_transcript(config, label_hash, &shares)?;
    }

    let (public_commitments, resolution) =
        recover_it_vss_artifacts_from_dkg_wire_records(log.dkg_wire_records())?;
    let selected_commitments =
        select_expected_it_vss_public_commitments(&public_commitments, &expected_keys)?;
    let resolution = resolution.ok_or(DkgError::MissingDkgSetupCertificate)?;
    validate_it_vss_complaint_resolution_for_backend(
        config,
        &selected_commitments,
        &resolution,
        ItVssBackendId::ProductionInformationChecking,
    )?;
    ensure_replayed_it_vss_resolution_covers_expected_vector_commitments(
        &selected_commitments,
        &resolution,
    )?;

    let audit_records =
        recover_it_vss_public_audit_records_from_dkg_wire_records(log.dkg_wire_records())?;
    let consistency_records =
        recover_it_vss_public_consistency_records_from_dkg_wire_records(log.dkg_wire_records())?;
    let public_artifact_hash = hash_it_vss_public_artifacts(&selected_commitments);
    let resolution_hash = hash_it_vss_complaint_resolution(&resolution);
    let public_audit_hash = hash_production_it_vss_audit_records(&audit_records);
    let public_consistency_hash = hash_production_it_vss_consistency_records(&consistency_records);

    let mut hasher = Sha3_256::new();
    hasher.update(b"TALUS-DKG-IT-VSS-v1/public-log-replay");
    hasher.update(config.transcript_hash().0);
    hasher.update(public_artifact_hash);
    hasher.update(resolution_hash);
    hasher.update(public_audit_hash);
    hasher.update(public_consistency_hash);
    let replay_transcript_hash = hasher.finalize().into();

    Ok(ReplayedItVssPublicLogDecision {
        accepted_dealers: resolution.accepted_dealers,
        rejected_dealers: resolution.rejected_dealers,
        public_artifact_hash,
        resolution_hash,
        public_audit_hash,
        public_consistency_hash,
        replay_transcript_hash,
    })
}

fn ensure_replayed_it_vss_resolution_covers_expected_vector_commitments(
    commitments: &[ItVssPublicCommitment],
    resolution: &ItVssComplaintResolution,
) -> Result<(), DkgError> {
    for commitment in commitments {
        let has_certificate = resolution.certificates.iter().any(|certificate| {
            certificate.dealer == commitment.dealer
                && certificate.label_hash == commitment.label_hash
                && certificate.transcript_hash == hash_it_vss_public_commitment(commitment)
        });
        if resolution.accepted_dealers.contains(&commitment.dealer) {
            if !has_certificate {
                return Err(DkgError::ItVssResolutionMissingCertificate {
                    dealer: commitment.dealer,
                });
            }
        } else if has_certificate {
            return Err(DkgError::ItVssResolutionUnexpectedCertificate {
                dealer: commitment.dealer,
            });
        }
    }
    Ok(())
}

fn ensure_it_vss_public_coin_flow_order_for_release(
    records: &[DkgWireMessageRecord],
    expected_keys: &[(PartyId, [u8; 32])],
) -> Result<(), DkgError> {
    for &(expected_dealer, expected_label_hash) in expected_keys {
        let mut precommitment_index = None;
        let mut coin_indices = Vec::new();
        let mut final_commitment_index = None;

        for (index, record) in records.iter().enumerate() {
            if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
                || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
            {
                continue;
            }

            match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicPrecommitment(precommitment)
                    if PartyId(precommitment.dealer_party_id) == expected_dealer
                        && precommitment.label_hash == expected_label_hash =>
                {
                    precommitment_index.get_or_insert(index);
                }
                DkgItVssArtifactPayload::PublicCoinShare(share)
                    if share.label_hash == expected_label_hash =>
                {
                    coin_indices.push(index);
                }
                DkgItVssArtifactPayload::PublicCommitment(commitment)
                    if PartyId(commitment.dealer_party_id) == expected_dealer
                        && commitment.label_hash == expected_label_hash =>
                {
                    final_commitment_index.get_or_insert(index);
                }
                DkgItVssArtifactPayload::PublicCommitmentBatch(commitments) => {
                    if commitments.iter().any(|commitment| {
                        PartyId(commitment.dealer_party_id) == expected_dealer
                            && commitment.label_hash == expected_label_hash
                    }) {
                        final_commitment_index.get_or_insert(index);
                    }
                }
                DkgItVssArtifactPayload::PublicPrecommitment(_)
                | DkgItVssArtifactPayload::PublicCommitment(_)
                | DkgItVssArtifactPayload::PublicCoinShare(_)
                | DkgItVssArtifactPayload::PublicAuditRecords(_)
                | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
                | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
            }
        }

        let Some(precommitment_index) = precommitment_index else {
            return Err(DkgError::MissingDkgSetupCertificate);
        };
        if coin_indices.is_empty() {
            return Err(DkgError::MissingRoundMessages {
                round: DkgRound::Commit,
                expected: 1,
                got: 0,
            });
        }
        let Some(final_commitment_index) = final_commitment_index else {
            return Err(DkgError::MissingDkgSetupCertificate);
        };

        if coin_indices
            .iter()
            .any(|&coin_index| coin_index <= precommitment_index)
            || final_commitment_index <= *coin_indices.iter().max().expect("nonempty")
        {
            return Err(DkgError::DkgSetupIncompleteAfterRestart);
        }
    }

    Ok(())
}

fn ensure_it_vss_public_audit_consistency_order_for_release(
    records: &[DkgWireMessageRecord],
    expected_keys: &[(PartyId, [u8; 32])],
) -> Result<(), DkgError> {
    for &(expected_dealer, expected_label_hash) in expected_keys {
        let mut final_commitment_index = None;
        let mut audit_index = None;
        let mut consistency_index = None;
        for (index, record) in records.iter().enumerate() {
            if record.direction != PrimeFieldMpcWireDirection::AcceptedBroadcast
                || record.message.header.payload_kind != PayloadKind::DkgItVssArtifact
            {
                continue;
            }
            match wire_decode_dkg_it_vss_artifact_payload(&record.message.payload)
                .map_err(|_| DkgError::PrimeFieldMpcTransport)?
            {
                DkgItVssArtifactPayload::PublicCommitment(commitment)
                    if PartyId(commitment.dealer_party_id) == expected_dealer
                        && commitment.label_hash == expected_label_hash =>
                {
                    final_commitment_index.get_or_insert(index);
                }
                DkgItVssArtifactPayload::PublicCommitmentBatch(commitments) => {
                    if commitments.iter().any(|commitment| {
                        PartyId(commitment.dealer_party_id) == expected_dealer
                            && commitment.label_hash == expected_label_hash
                    }) {
                        final_commitment_index.get_or_insert(index);
                    }
                }
                DkgItVssArtifactPayload::PublicAuditRecords(records)
                    if records.iter().any(|record| {
                        PartyId(record.dealer_party_id) == expected_dealer
                            && record.label_hash == expected_label_hash
                    }) =>
                {
                    audit_index.get_or_insert(index);
                }
                DkgItVssArtifactPayload::PublicConsistencyRecords(records)
                    if records.iter().any(|record| {
                        PartyId(record.dealer_party_id) == expected_dealer
                            && record.label_hash == expected_label_hash
                    }) =>
                {
                    consistency_index.get_or_insert(index);
                }
                DkgItVssArtifactPayload::PublicCommitment(_)
                | DkgItVssArtifactPayload::PublicPrecommitment(_)
                | DkgItVssArtifactPayload::PublicCoinShare(_)
                | DkgItVssArtifactPayload::PublicAuditRecords(_)
                | DkgItVssArtifactPayload::PublicConsistencyRecords(_)
                | DkgItVssArtifactPayload::ComplaintResolution(_) => {}
            }
        }
        let final_commitment_index =
            final_commitment_index.ok_or(DkgError::MissingDkgSetupCertificate)?;
        let audit_index = audit_index.ok_or(DkgError::MissingDkgSetupCertificate)?;
        let consistency_index = consistency_index.ok_or(DkgError::MissingDkgSetupCertificate)?;
        if audit_index <= final_commitment_index || consistency_index <= final_commitment_index {
            return Err(DkgError::DkgSetupIncompleteAfterRestart);
        }
    }
    Ok(())
}

/// Ensures public setup cursors are complete enough for a release package.
pub fn ensure_dkg_setup_cursors_complete_for_release<C: DkgSetupPhaseCursorLog>(
    cursor_log: &C,
) -> Result<(), DkgError> {
    match classify_dkg_setup_restart(cursor_log.latest_setup_phase_cursor()) {
        DkgSetupRestartDecision::Complete => Ok(()),
        DkgSetupRestartDecision::Aborted => Err(DkgError::DkgSetupAbortedAfterRestart),
        _ => Err(DkgError::DkgSetupIncompleteAfterRestart),
    }
}

/// Ensures the durable setup cursor log contains the complete production
/// vector IT-VSS subphase sequence.
///
/// A final "complete" cursor alone is not enough for release: restart logic and
/// auditors need durable evidence that the app driver passed through the
/// precommitment, public-coin, final metadata, private delivery, verification,
/// complaint, resolution, and certification phases.
pub fn ensure_it_vss_phase_cursors_complete_for_release<C: DkgSetupPhaseCursorLog>(
    cursor_log: &C,
) -> Result<(), DkgError> {
    if cursor_log
        .setup_phase_cursors()
        .iter()
        .any(|cursor| cursor.state == DkgSetupPhaseCursorState::Aborted)
    {
        return Err(DkgError::DkgSetupAbortedAfterRestart);
    }
    const REQUIRED: &[(ProductionItVssComplaintPhase, DkgSetupPhaseCursorState)] = &[
        (
            ProductionItVssComplaintPhase::BroadcastPublicPrecommitments,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::BroadcastPublicCoins,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::BroadcastPublicCommitments,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::BroadcastPublicAudits,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::BroadcastConsistencyRecords,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::DeliverPrivateShares,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::VerifyPrivateDeliveries,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::BroadcastComplaints,
            DkgSetupPhaseCursorState::Sent,
        ),
        (
            ProductionItVssComplaintPhase::ResolveComplaints,
            DkgSetupPhaseCursorState::Collected,
        ),
        (
            ProductionItVssComplaintPhase::CertifyAcceptedSharings,
            DkgSetupPhaseCursorState::Collected,
        ),
    ];

    for &(phase, state) in REQUIRED {
        let complete = cursor_log.setup_phase_cursors().iter().any(|cursor| {
            cursor.it_vss_phase == Some(phase)
                && cursor.state == state
                && cursor.got >= cursor.expected
        });
        if !complete {
            if cursor_log.setup_phase_cursors().iter().any(|cursor| {
                cursor.it_vss_phase == Some(phase)
                    && cursor.state == DkgSetupPhaseCursorState::Aborted
            }) {
                return Err(DkgError::DkgSetupAbortedAfterRestart);
            }
            return Err(DkgError::DkgSetupIncompleteAfterRestart);
        }
    }
    Ok(())
}

/// Ensures application-supplied PQ transport evidence is bound to the same DKG
/// configuration as the package being released.
///
/// The crate still does not implement networking. This check verifies the
/// embedding application's evidence bundle derives a nonzero TALUS wire context
/// with the expected ML-DSA suite, keygen transcript, party set, and allowed
/// senders.
pub fn ensure_native_dkg_transport_evidence_matches_config(
    config: &DkgConfig,
    evidence: &NativeDkgTransportEvidence,
) -> Result<(), DkgError> {
    let expected = evidence
        .expected_context()
        .map_err(|_| DkgError::PrimeFieldMpcTransport)?;
    let allowed_parties = config
        .parties
        .iter()
        .map(|party| party.0)
        .collect::<Vec<_>>();
    let signing_set_hash = talus_wire::signing_set_hash(&allowed_parties);
    if expected.suite != wire_suite(config.suite)
        || expected.keygen_transcript_hash != config.transcript_hash().0
        || expected.signing_set_hash != signing_set_hash
        || expected.allowed_parties != allowed_parties
        || expected.session_id == [0; 32]
    {
        return Err(DkgError::PrimeFieldMpcContextMismatch);
    }
    Ok(())
}

/// Complete release gate for a native DKG package set plus the public setup
/// context that produced it.
///
/// This is the product-facing guard callers should use before treating a native
/// DKG output as release material. It composes package/certificate checks,
/// setup-artifact log checks, restart cursor completion, coordinator/backend
/// readiness, and application transport evidence binding.
pub fn ensure_native_dkg_release_context_allowed_for_release<L, C>(
    packages: &[DkgKeyPackage],
    setup_log: &L,
    cursor_log: &C,
    readiness: ProductionNativeDkgCoordinatorReadiness,
    transport_evidence: &NativeDkgTransportEvidence,
) -> Result<DkgConfig, DkgError>
where
    L: DkgWireMessageLog,
    C: DkgSetupPhaseCursorLog,
{
    let config = ensure_dkg_key_package_set_allowed_for_release(packages)?;
    ensure_production_native_dkg_coordinator_readiness(readiness)?;
    ensure_dkg_setup_cursors_complete_for_release(cursor_log)?;
    ensure_it_vss_phase_cursors_complete_for_release(cursor_log)?;
    let certificate = &packages[0].certificate;
    ensure_dkg_setup_log_matches_certificate_for_release(setup_log, certificate)?;
    ensure_it_vss_artifact_log_uses_batched_vector_labels_for_release(&config, setup_log)?;
    ensure_it_vss_public_coin_flow_complete_for_release(&config, setup_log)?;
    ensure_it_vss_public_audit_consistency_complete_for_release(&config, setup_log)?;
    ensure_native_dkg_transport_evidence_matches_config(&config, transport_evidence)?;
    Ok(config)
}

/// Complete release gate for a typed production native DKG output plus the
/// public setup context that produced it.
///
/// This is the narrow product-facing validator. The output must have been
/// constructed through `ProductionNativeDkgAssemblyOutput::new`, then this
/// composes package/certificate, setup-log, restart-cursor, coordinator
/// readiness, and PQ transport-evidence checks.
pub fn ensure_production_native_dkg_output_context_allowed_for_release<L, C>(
    output: &ProductionNativeDkgAssemblyOutput,
    setup_log: &L,
    cursor_log: &C,
    readiness: ProductionNativeDkgCoordinatorReadiness,
    transport_evidence: &NativeDkgTransportEvidence,
) -> Result<DkgConfig, DkgError>
where
    L: DkgWireMessageLog,
    C: DkgSetupPhaseCursorLog,
{
    ensure_native_dkg_assembly_parts_allowed_for_release(
        &output.certificate,
        &output.key_packages,
    )?;
    ensure_native_dkg_release_context_allowed_for_release(
        &output.key_packages,
        setup_log,
        cursor_log,
        readiness,
        transport_evidence,
    )
}

/// Recomputes every setup transcript hash that can be derived from the local
/// durable DKG log and compares it with the public assembly certificate.
///
/// This check is intentionally broader than the release public-artifact scan:
/// it is meant for the local package owner, whose setup log may include private
/// directed-share records that must not appear in release bundles.
pub fn ensure_logged_dkg_setup_matches_certificate<P, T, L>(
    config: &DkgConfig,
    runtime: &LoggedDkgTransportPartyRuntime<T, L>,
    certificate: &PublicKeyAssemblyCertificate,
) -> Result<(), DkgError>
where
    P: MlDsaParams,
    T: AuthenticatedP2pTransport + EquivocationResistantBroadcast,
    L: DkgWireMessageLog,
{
    let setup = certificate
        .setup
        .as_ref()
        .ok_or(DkgError::MissingDkgSetupCertificate)?;
    let checks = [
        (
            setup.sampler_s1_hash,
            hash_logged_small_sampler_vector::<P, _, _>(config, runtime, SecretVectorKind::S1)?,
        ),
        (
            setup.sampler_s2_hash,
            hash_logged_small_sampler_vector::<P, _, _>(config, runtime, SecretVectorKind::S2)?,
        ),
        (
            setup.vss_commit_hash,
            hash_dkg_commit_payloads(&runtime.recover_vss_commit_round_from_log()?),
        ),
        (
            setup.vss_share_hash,
            hash_dkg_share_payloads(
                &runtime.recover_vss_share_round_from_log(runtime.local_party())?,
            ),
        ),
        (
            setup.complaint_hash,
            hash_dkg_complaint_payloads(&runtime.recover_vss_complaint_round_from_log()?),
        ),
    ];
    for (expected, got) in checks {
        if expected != got {
            return Err(DkgError::TranscriptMismatch {
                expected: KeygenTranscriptHash(expected),
                got: KeygenTranscriptHash(got),
            });
        }
    }

    let (public_commitments, resolution) = runtime.recover_it_vss_artifacts_from_log()?;
    let resolution = resolution.ok_or(DkgError::MissingDkgSetupCertificate)?;
    let public_hash = hash_it_vss_public_artifacts(&public_commitments);
    if setup.it_vss_public_artifact_hash != public_hash {
        return Err(DkgError::TranscriptMismatch {
            expected: KeygenTranscriptHash(setup.it_vss_public_artifact_hash),
            got: KeygenTranscriptHash(public_hash),
        });
    }
    let resolution_hash = hash_it_vss_complaint_resolution(&resolution);
    if setup.it_vss_resolution_hash != resolution_hash {
        return Err(DkgError::TranscriptMismatch {
            expected: KeygenTranscriptHash(setup.it_vss_resolution_hash),
            got: KeygenTranscriptHash(resolution_hash),
        });
    }
    Ok(())
}

/// Implementation gates required before a backend may identify as
/// `ProductionItMpc`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionItMpcReadiness {
    /// Power2Round has been split into real per-party send/receive phases.
    pub per_party_power2round: bool,
    /// Batched/vector operations are implemented for openings, assertions,
    /// random bits, multiplications, comparisons, and private selection.
    pub vector_runtime_operations: bool,
    /// Transport adapter uses PQ-authenticated channels and broadcast.
    pub pq_authenticated_transport: bool,
    /// Durable public round logs reject replay/rollback.
    pub durable_round_log: bool,
    /// Durable local wire logs cover opened values and checked openings.
    pub durable_wire_log: bool,
    /// Runtime counters include rounds, messages, bytes, vector lanes, and
    /// multiplication layers.
    pub release_counters: bool,
    /// Release evidence rejects scalar-per-coefficient execution.
    pub no_scalarized_execution: bool,
    /// Multiplication by public constants is local and does not consume MPC
    /// multiplication gates.
    pub public_const_mul_local: bool,
    /// Abort/blame behavior is implemented and covered by tests.
    pub blame_abort_policy: bool,
    /// Optional post-implementation audit metadata. This is intentionally not
    /// a readiness requirement.
    pub external_review: bool,
}

/// Ensures a backend may claim the production IT-MPC identity.
pub fn ensure_production_it_mpc_readiness(
    backend_id: Power2RoundBackendId,
    readiness: ProductionItMpcReadiness,
) -> Result<(), DkgError> {
    ensure_power2round_backend_allowed_for_release(backend_id)?;
    if readiness.per_party_power2round
        && readiness.vector_runtime_operations
        && readiness.pq_authenticated_transport
        && readiness.durable_round_log
        && readiness.durable_wire_log
        && readiness.release_counters
        && readiness.no_scalarized_execution
        && readiness.public_const_mul_local
        && readiness.blame_abort_policy
    {
        Ok(())
    } else {
        Err(DkgError::BlockedPendingReview)
    }
}

/// Coordinator/scheduler shape selected for native DKG setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDkgCoordinatorKind {
    /// Embedding application supplies authenticated private transport,
    /// equivocation-resistant broadcast, scheduling, retry, and persistence.
    ApplicationSuppliedTransport,
    /// In-crate deterministic in-memory coordinator for tests and scaffolding.
    InMemoryScaffold,
}

impl NativeDkgCoordinatorKind {
    /// Returns true when this coordinator kind is a scaffold/test harness.
    pub const fn is_scaffold(self) -> bool {
        matches!(self, Self::InMemoryScaffold)
    }

    /// Returns true when this coordinator kind is the product-facing
    /// application transport boundary.
    pub const fn is_application_supplied_transport(self) -> bool {
        matches!(self, Self::ApplicationSuppliedTransport)
    }

    /// Stable human-readable label for policy errors, docs, and diagnostics.
    pub const fn release_label(self) -> &'static str {
        match self {
            Self::ApplicationSuppliedTransport => "application-supplied-transport",
            Self::InMemoryScaffold => "in-memory-scaffold",
        }
    }
}

impl Default for NativeDkgCoordinatorKind {
    fn default() -> Self {
        Self::InMemoryScaffold
    }
}

/// Release readiness gates for the native DKG coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionNativeDkgCoordinatorReadiness {
    /// Coordinator/scheduler implementation.
    pub coordinator: NativeDkgCoordinatorKind,
    /// Setup certificate backend that will be emitted.
    pub setup_backend_id: DkgSetupBackendId,
    /// IT-VSS backend selected for setup artifacts.
    pub it_vss_backend_id: ItVssBackendId,
    /// Power2Round backend selected for public-key assembly.
    pub power2round_backend_id: Power2RoundBackendId,
    /// IT-VSS backend readiness.
    pub it_vss_readiness: ProductionItVssReadiness,
    /// IT-MPC/Power2Round backend readiness.
    pub it_mpc_readiness: ProductionItMpcReadiness,
    /// Transport contract is implemented by the embedding application.
    pub application_transport_contract: bool,
    /// Reliable broadcast conformance tests have passed for the application
    /// transport adapter.
    pub reliable_broadcast_conformance: bool,
    /// Private channels are ML-KEM-derived for the selected deployment profile.
    pub ml_kem_private_channels: bool,
    /// Operational party identities and broadcast authentication use ML-DSA.
    pub ml_dsa_operational_identities: bool,
    /// Restart/replay policy is durable and reviewed for crash safety.
    pub durable_restart_policy: bool,
    /// The coordinator path contains no deterministic scaffold backends.
    pub no_scaffold_backends: bool,
    /// Optional post-implementation audit metadata. This is intentionally not
    /// a coordinator readiness requirement.
    pub external_review: bool,
}

impl Default for ProductionNativeDkgCoordinatorReadiness {
    fn default() -> Self {
        Self {
            coordinator: NativeDkgCoordinatorKind::InMemoryScaffold,
            setup_backend_id: DkgSetupBackendId::InProcessScaffold,
            it_vss_backend_id: ItVssBackendId::InProcessHashBindingScaffold,
            power2round_backend_id: {
                #[cfg(test)]
                {
                    Power2RoundBackendId::InsecureClearSimulator
                }
                #[cfg(not(test))]
                {
                    Power2RoundBackendId::ProductionItMpc
                }
            },
            it_vss_readiness: ProductionItVssReadiness::default(),
            it_mpc_readiness: ProductionItMpcReadiness::default(),
            application_transport_contract: false,
            reliable_broadcast_conformance: false,
            ml_kem_private_channels: false,
            ml_dsa_operational_identities: false,
            durable_restart_policy: false,
            no_scaffold_backends: false,
            external_review: false,
        }
    }
}

/// Release profile advertised by a native DKG coordinator/scheduler.
pub trait NativeDkgCoordinatorReleaseProfile {
    /// Coordinator implementation kind.
    fn coordinator_kind(&self) -> NativeDkgCoordinatorKind;

    /// Full release readiness claim for this coordinator composition.
    fn production_readiness_profile(&self) -> ProductionNativeDkgCoordinatorReadiness;

    /// Applies the production release gate to this coordinator profile.
    fn ensure_allowed_for_production_release(&self) -> Result<(), DkgError> {
        ensure_production_native_dkg_coordinator_readiness(self.production_readiness_profile())
    }
}

#[cfg(test)]
impl NativeDkgCoordinatorReleaseProfile for InMemoryNativeDkgScaffoldCoordinator {
    fn coordinator_kind(&self) -> NativeDkgCoordinatorKind {
        InMemoryNativeDkgScaffoldCoordinator::coordinator_kind(self)
    }

    fn production_readiness_profile(&self) -> ProductionNativeDkgCoordinatorReadiness {
        InMemoryNativeDkgScaffoldCoordinator::production_readiness_profile(self)
    }
}

/// Ensures the native DKG coordinator composition may be selected for a
/// production release path.
pub fn ensure_production_native_dkg_coordinator_readiness(
    readiness: ProductionNativeDkgCoordinatorReadiness,
) -> Result<(), DkgError> {
    if !readiness.coordinator.is_application_supplied_transport() {
        return Err(DkgError::InsecureNativeDkgCoordinator);
    }
    if readiness.setup_backend_id != DkgSetupBackendId::ProductionInformationTheoretic {
        return Err(DkgError::InsecureDkgSetupBackend);
    }
    ensure_production_it_vss_readiness(readiness.it_vss_backend_id, readiness.it_vss_readiness)?;
    ensure_production_it_mpc_readiness(
        readiness.power2round_backend_id,
        readiness.it_mpc_readiness,
    )?;
    if readiness.application_transport_contract
        && readiness.reliable_broadcast_conformance
        && readiness.ml_kem_private_channels
        && readiness.ml_dsa_operational_identities
        && readiness.durable_restart_policy
        && readiness.no_scaffold_backends
    {
        Ok(())
    } else {
        Err(DkgError::BlockedPendingReview)
    }
}

/// Assembles temporary shared `t = A*s1+s2`; consumes `s2`.
pub fn assemble_shared_t<P: MlDsaParams>(
    config: &DkgConfig,
    rho: [u8; 32],
    s1: &SharedSmallPolyVec,
    s2: SharedSmallPolyVec,
) -> Result<SharedT, DkgError> {
    if s1.vector != SecretVectorKind::S1 || s2.vector != SecretVectorKind::S2 {
        return Err(DkgError::Backend("bad ML-DSA secret material shape"));
    }
    let s1_shares = shared_small_polyvec_party_shares::<P>(config, s1)?;
    let s2_shares = shared_small_polyvec_party_shares::<P>(config, &s2)?;
    let mut shares = Vec::with_capacity(config.parties.len());
    for (s1_share, s2_share) in s1_shares.into_iter().zip(s2_shares) {
        if s1_share.party != s2_share.party || s1_share.point != s2_share.point {
            return Err(DkgError::PartyMismatch {
                expected: s1_share.party,
                got: s2_share.party,
            });
        }
        let s1_polyvec = coeffs_to_polyvec::<P>(&s1_share.coeffs, P::L)?;
        let s2_polyvec = coeffs_to_polyvec::<P>(&s2_share.coeffs, P::K)?;
        let as1 = az_from_rho::<P>(&rho, &s1_polyvec)
            .map_err(|_| DkgError::Backend("ExpandA/NTT public-key assembly failed"))?;
        shares.push(SharedTPartyShare {
            party: s1_share.party,
            point: s1_share.point,
            t_share: as1.add_mod_q::<P>(&s2_polyvec),
        });
    }

    Ok(SharedT {
        shares,
        assembly_label: PublicKeyAssemblyLabel::new(config, rho),
        origin: SharedTOrigin::DkgPublicKeyAssembly {
            epoch: config.epoch,
            party_set_hash: dkg_party_set_hash(config),
        },
    })
}

/// Extracts one local party's `t = A*s1+s2` share as a vector accepted by the
/// production prime-field Power2Round backend.
///
/// This does not reconstruct `t`: it copies only the local Shamir share into
/// backend-private share handles. The backend is responsible for checked
/// openings and MPC interaction during Power2Round.
pub fn shared_t_party_share_vec<P, B>(
    shared_t: &SharedT,
    party: PartyId,
    backend: &B,
) -> Result<ShareVec<B::Share>, DkgError>
where
    P: MlDsaParams,
    B: ItMpcPrimeFieldBackend<P>,
{
    let share = shared_t
        .shares
        .iter()
        .find(|share| share.party == party)
        .ok_or(DkgError::UnknownParty(party))?;
    if share.t_share.polys().len() != P::K {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: P::K * P::N,
            got: share.t_share.polys().len() * P::N,
        });
    }
    let mut lanes = Vec::with_capacity(P::K * P::N);
    for poly in share.t_share.polys() {
        if poly.coeffs().len() != P::N {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: P::K * P::N,
                got: lanes.len() + poly.coeffs().len(),
            });
        }
        lanes.extend(
            poly.coeffs()
                .iter()
                .copied()
                .map(|coeff| backend.secret_share(coeff)),
        );
    }
    if lanes.len() != P::K * P::N {
        return Err(DkgError::InvalidBoundedSecretVectorLength {
            expected: P::K * P::N,
            got: lanes.len(),
        });
    }
    Ok(backend.share_vec_from_lanes(lanes))
}

/// Assembles a transcript-bound DKG public output using a generic Power2Round
/// backend.
///
/// This is scaffold/dev-only. Production assembly must use
/// `assemble_public_output_from_production_power2round`, which requires a typed
/// `ProductionPower2RoundOutput`.
#[cfg(any(test, feature = "scaffold-dev"))]
#[doc(hidden)]
pub fn assemble_public_output_scaffold<P: MlDsaParams, B: MpcPower2RoundBackend>(
    config: &DkgConfig,
    rho: [u8; 32],
    material: SharedMldsaSecretMaterial,
    accepted_dealers: &[PartyId],
    backend: &mut B,
) -> Result<(DkgPublicOutput, PublicKeyAssemblyCertificate), DkgError>
where
    B::Evidence: Into<Power2RoundEvidence>,
{
    if material.s1.vector != SecretVectorKind::S1 || material.s2.vector != SecretVectorKind::S2 {
        return Err(DkgError::Backend("bad ML-DSA secret material shape"));
    }
    let shared_t = assemble_shared_t::<P>(config, rho, &material.s1, material.s2)?;
    let (t1, evidence) = backend.power2round_t1::<P>(config, shared_t)?;
    let evidence = evidence.into();
    if t1.bytes.len() != config.suite.t1_len() {
        return Err(DkgError::InvalidT1Length {
            expected: config.suite.t1_len(),
            got: t1.bytes.len(),
        });
    }
    ensure_power2round_evidence_matches_public_t1(config, rho, &t1, &evidence)?;

    assemble_public_output_from_t1_and_evidence(config, rho, t1, evidence, None, accepted_dealers)
}

/// Assembles a DKG public output from a validated production Power2Round result.
///
/// This is the production-oriented public-key assembly boundary: callers must
/// drive the per-party Power2Round phases first and provide a typed
/// `ProductionPower2RoundOutput`, rather than passing a generic backend through
/// the assembly path.
pub fn assemble_public_output_from_production_power2round(
    config: &DkgConfig,
    rho: [u8; 32],
    accepted_dealers: &[PartyId],
    power2round_output: ProductionPower2RoundOutput,
) -> Result<(DkgPublicOutput, PublicKeyAssemblyCertificate), DkgError> {
    let (t1, evidence, runtime_evidence) = power2round_output.into_parts();
    ensure_power2round_evidence_matches_public_t1(config, rho, &t1, &evidence)?;
    assemble_public_output_from_t1_and_evidence(
        config,
        rho,
        t1,
        evidence,
        runtime_evidence,
        accepted_dealers,
    )
}

fn assemble_public_output_from_t1_and_evidence(
    config: &DkgConfig,
    rho: [u8; 32],
    t1: PublicT1,
    evidence: Power2RoundEvidence,
    runtime_evidence: Option<ProductionVectorItMpcRuntimeEvidence>,
    accepted_dealers: &[PartyId],
) -> Result<(DkgPublicOutput, PublicKeyAssemblyCertificate), DkgError> {
    if t1.bytes.len() != config.suite.t1_len() {
        return Err(DkgError::InvalidT1Length {
            expected: config.suite.t1_len(),
            got: t1.bytes.len(),
        });
    }
    let mut public_key = Vec::with_capacity(config.suite.public_key_len());
    public_key.extend_from_slice(&rho);
    public_key.extend_from_slice(&t1.bytes);
    let mut output = DkgPublicOutput {
        public_key,
        t1: t1.bytes.clone(),
        pairwise_seed_commitments: config
            .parties
            .iter()
            .map(|&party| PairwiseSeedCommitment {
                party,
                commitment: scaffold_party_commitment(config, b"pairwise-seed", party),
            })
            .collect(),
        config: config.clone(),
        keygen_transcript_hash: KeygenTranscriptHash([0; 32]),
        rho,
        vss_commitments: accepted_dealers
            .iter()
            .map(|&party| VssCommitment {
                bytes: scaffold_party_commitment(config, b"accepted-vss", party).to_vec(),
            })
            .collect(),
    };
    output.keygen_transcript_hash = output.transcript_binding();
    output.validate_binding()?;
    Ok((
        output,
        PublicKeyAssemblyCertificate {
            power2round: evidence,
            power2round_runtime: runtime_evidence,
            setup: None,
            power2round_setup_input_hash: None,
        },
    ))
}

/// Builds per-party DKG key packages without including temporary `s2`, `t`, or `t0`.
pub fn dkg_key_packages_from_public_output(
    output: &DkgPublicOutput,
    s1_shares: Vec<DkgSecretShare>,
    certificate: PublicKeyAssemblyCertificate,
) -> Result<Vec<DkgKeyPackage>, DkgError> {
    output.validate_binding()?;
    if s1_shares.len() != output.config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Finalize,
            expected: output.config.parties.len(),
            got: s1_shares.len(),
        });
    }
    s1_shares
        .into_iter()
        .map(|share| {
            validate_secret_share_shape(&output.config, &share)?;
            let s1_share = DkgS1SecretShare {
                party: share.party,
                s1_share: share.s1_share,
                pairwise_seed_shares: share.pairwise_seed_shares,
            };
            validate_s1_secret_share_shape(&output.config, &s1_share)?;
            let as1_share = as1_share_from_s1_share(&output.config, &output.rho, &s1_share)?;
            validate_as1_secret_share_shape(&output.config, &as1_share)?;
            Ok(DkgKeyPackage {
                suite: output.config.suite,
                epoch: output.config.epoch,
                party: s1_share.party,
                threshold: output.config.threshold,
                rho: output.rho,
                t1: PublicT1 {
                    bytes: output.t1.clone(),
                    coeffs: Vec::new(),
                },
                public_key: output.public_key.clone(),
                s1_share,
                as1_share,
                certificate: certificate.clone(),
            })
        })
        .collect()
}

/// Ensures one DKG key package is release-acceptable.
pub fn ensure_dkg_key_package_allowed_for_release(package: &DkgKeyPackage) -> Result<(), DkgError> {
    if package.public_key.len() != package.suite.public_key_len() {
        return Err(DkgError::InvalidPublicKeyLength {
            expected: package.suite.public_key_len(),
            got: package.public_key.len(),
        });
    }
    if package.t1.bytes.len() != package.suite.t1_len() {
        return Err(DkgError::InvalidT1Length {
            expected: package.suite.t1_len(),
            got: package.t1.bytes.len(),
        });
    }
    if package.public_key[..32] != package.rho || package.public_key[32..] != package.t1.bytes {
        return Err(DkgError::DkgKeyPackagePublicMaterialMismatch);
    }
    if package.certificate.power2round.suite != package.suite
        || package.certificate.power2round.epoch != package.epoch
        || package.certificate.power2round.output_t1_hash != power2round_public_t1_hash(&package.t1)
    {
        return Err(DkgError::Power2RoundEvidenceRequired);
    }
    if package.s1_share.party != package.party {
        return Err(DkgError::PartyMismatch {
            expected: package.party,
            got: package.s1_share.party,
        });
    }
    if package.as1_share.party != package.party {
        return Err(DkgError::PartyMismatch {
            expected: package.party,
            got: package.as1_share.party,
        });
    }
    if package.as1_share.as1_share.is_empty() {
        return Err(DkgError::EmptySecretShareField {
            party: package.party,
            field: "as1_share",
        });
    }
    ensure_dkg_certificate_allowed_for_release(&package.certificate)
}

/// Ensures a complete DKG key-package set is release-acceptable and internally
/// consistent.
pub fn ensure_dkg_key_package_set_allowed_for_release(
    packages: &[DkgKeyPackage],
) -> Result<DkgConfig, DkgError> {
    let Some(first) = packages.first() else {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Finalize,
            expected: 1,
            got: 0,
        });
    };
    let mut parties = packages
        .iter()
        .map(|package| package.party)
        .collect::<Vec<_>>();
    parties.sort_by_key(|party| party.0);
    let config = DkgConfig::new_for_suite(first.suite, first.threshold, parties, first.epoch)?;
    validate_exact_party_set(
        &config,
        DkgRound::Finalize,
        packages.iter().map(|package| package.party),
    )?;

    for package in packages {
        ensure_dkg_key_package_allowed_for_release(package)?;
        ensure_power2round_evidence_matches_public_t1(
            &config,
            package.rho,
            &package.t1,
            &package.certificate.power2round,
        )?;
        if package.suite != first.suite
            || package.epoch != first.epoch
            || package.threshold != first.threshold
        {
            return Err(DkgError::FinalOutputConfigMismatch);
        }
        if package.rho != first.rho
            || package.t1.bytes != first.t1.bytes
            || package.public_key != first.public_key
        {
            return Err(DkgError::DkgKeyPackagePublicMaterialDisagreement);
        }
        if package.certificate != first.certificate {
            return Err(DkgError::DkgKeyPackageCertificateDisagreement);
        }
        ensure_power2round_setup_binding_matches_config(
            &config,
            package.rho,
            &package.certificate,
        )?;
        if package.s1_share.party != package.party {
            return Err(DkgError::PartyMismatch {
                expected: package.party,
                got: package.s1_share.party,
            });
        }
        if package.as1_share.party != package.party {
            return Err(DkgError::PartyMismatch {
                expected: package.party,
                got: package.as1_share.party,
            });
        }
        validate_s1_secret_share_shape(&config, &package.s1_share)?;
        validate_as1_secret_share_shape(&config, &package.as1_share)?;
        validate_as1_matches_s1_share(
            &config,
            &package.rho,
            &package.s1_share,
            &package.as1_share,
        )?;
    }

    Ok(config)
}

/// Ensures a native DKG assembly output is release-acceptable.
///
/// Scaffold assembly outputs intentionally fail this check because their setup
/// certificate carries scaffold backend ids and release blockers. Product code
/// should call this gate before treating any assembled output as release
/// material.
#[cfg(any(test, feature = "scaffold-dev"))]
pub fn ensure_native_dkg_assembly_output_allowed_for_release(
    output: &NativeDkgAssemblyScaffoldOutput,
) -> Result<DkgConfig, DkgError> {
    ensure_native_dkg_assembly_parts_allowed_for_release(&output.certificate, &output.key_packages)
}

fn ensure_native_dkg_assembly_parts_allowed_for_release(
    certificate: &PublicKeyAssemblyCertificate,
    key_packages: &[DkgKeyPackage],
) -> Result<DkgConfig, DkgError> {
    ensure_dkg_certificate_allowed_for_release(certificate)?;
    ensure_dkg_key_package_set_allowed_for_release(key_packages)
}

fn ensure_power2round_setup_binding_matches_config(
    config: &DkgConfig,
    rho: [u8; 32],
    certificate: &PublicKeyAssemblyCertificate,
) -> Result<(), DkgError> {
    let setup = certificate
        .setup
        .as_ref()
        .ok_or(DkgError::MissingDkgSetupCertificate)?;
    let expected = production_power2round_setup_input_hash(config, rho, setup);
    if certificate.power2round_setup_input_hash != Some(expected) {
        return Err(DkgError::Power2RoundEvidenceRequired);
    }
    Ok(())
}

/// Durable transcript store used to bind epoch output and prevent rollback.
pub trait DkgTranscriptStore {
    /// Persists a completed DKG public output.
    fn persist_output(&mut self, output: &DkgPublicOutput) -> Result<(), DkgError>;

    /// Returns whether an epoch has already been committed.
    fn contains_epoch(&self, epoch: KeygenEpoch) -> bool;
}

/// In-memory DKG transcript store for state-machine and restart tests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryDkgTranscriptStore {
    outputs: Vec<(KeygenEpoch, KeygenTranscriptHash)>,
}

impl InMemoryDkgTranscriptStore {
    /// Creates an empty in-memory store.
    pub const fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }
}

impl DkgTranscriptStore for InMemoryDkgTranscriptStore {
    fn persist_output(&mut self, output: &DkgPublicOutput) -> Result<(), DkgError> {
        output.validate_binding()?;
        if self.contains_epoch(output.config.epoch) {
            return Err(DkgError::EpochAlreadyCommitted(output.config.epoch));
        }
        self.outputs
            .push((output.config.epoch, output.keygen_transcript_hash));
        Ok(())
    }

    fn contains_epoch(&self, epoch: KeygenEpoch) -> bool {
        self.outputs
            .iter()
            .any(|&(stored_epoch, _)| stored_epoch == epoch)
    }
}

/// File-backed DKG transcript store for crash/reopen tests.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDkgTranscriptStore {
    path: std::path::PathBuf,
    inner: InMemoryDkgTranscriptStore,
}

#[cfg(feature = "std")]
impl FileDkgTranscriptStore {
    /// Opens or creates a transcript log.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, DkgError> {
        let path = path.into();
        let mut inner = InMemoryDkgTranscriptStore::new();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_index, line) in contents.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let Some((epoch, hash)) = parse_dkg_store_line(line) else {
                        return Err(DkgError::TranscriptStoreCorrupt {
                            line: line_index + 1,
                        });
                    };
                    if inner.contains_epoch(epoch) {
                        return Err(DkgError::EpochAlreadyCommitted(epoch));
                    }
                    inner.outputs.push((epoch, hash));
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
}

#[cfg(feature = "std")]
impl DkgTranscriptStore for FileDkgTranscriptStore {
    fn persist_output(&mut self, output: &DkgPublicOutput) -> Result<(), DkgError> {
        output.validate_binding()?;
        if self.inner.contains_epoch(output.config.epoch) {
            return Err(DkgError::EpochAlreadyCommitted(output.config.epoch));
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "open" })?;
        use std::io::Write;
        writeln!(
            file,
            "{} {}",
            output.config.epoch.0,
            Hex32(output.keygen_transcript_hash.0)
        )
        .map_err(|_| DkgError::TranscriptStoreIo { operation: "write" })?;
        file.sync_data()
            .map_err(|_| DkgError::TranscriptStoreIo { operation: "sync" })?;
        self.inner.persist_output(output)
    }

    fn contains_epoch(&self, epoch: KeygenEpoch) -> bool {
        self.inner.contains_epoch(epoch)
    }
}

/// Production DKG entrypoint.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionDkg;

impl ProductionDkg {
    /// Starts the production DKG state machine at the first application-driven
    /// setup phase.
    pub fn start(config: DkgConfig) -> Result<DkgState, DkgError> {
        Ok(DkgLocalStateMachine::new(config)?.state())
    }

    /// Starts the production DKG only after the caller has supplied the
    /// product-facing readiness claim. This does not run networking inside the
    /// crate; embedding applications still drive setup through
    /// `NativeDkgApplicationSetupDriver`.
    pub fn start_with_readiness(
        config: DkgConfig,
        readiness: ProductionNativeDkgCoordinatorReadiness,
    ) -> Result<DkgState, DkgError> {
        ensure_production_native_dkg_coordinator_readiness(readiness)?;
        Self::start(config)
    }
}

#[cfg(test)]
mod tests;
