use super::*;

/// Test-only clear Shamir VSS deal used to exercise DKG state-machine logic.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOnlyScalarVssDeal {
    /// Dealer that generated the polynomial.
    pub dealer: PartyId,
    /// Clear polynomial coefficients. This must never be used in production.
    pub clear_coefficients: Vec<Coeff>,
    /// Public check commitments for the clear polynomial.
    pub commitments: Vec<VssCommitment>,
    /// Directed receiver shares.
    pub shares: Vec<ScalarVssShare>,
}

/// Creates a deterministic clear Shamir VSS deal for tests.
///
/// This exposes the polynomial and is available only for tests or the explicit
/// unit tests. It is not a production VSS backend and is not compiled into
/// normal crate builds.
#[cfg(test)]
pub fn test_only_deal_scalar_vss<P: MlDsaParams>(
    dealer: PartyId,
    coefficients: &[Coeff],
    receivers: &[(PartyId, u32)],
) -> Result<TestOnlyScalarVssDeal, DkgError> {
    if coefficients.is_empty() {
        return Err(DkgError::EmptyShamirPolynomial);
    }
    if receivers.is_empty() {
        return Err(DkgError::EmptyShamirShareSet);
    }

    let points: Vec<u32> = receivers.iter().map(|&(_, point)| point).collect();
    validate_unique_points::<P>(&points)?;

    let commitments = coefficients
        .iter()
        .enumerate()
        .map(|(index, &coefficient)| VssCommitment {
            bytes: scalar_vss_coefficient_commitment::<P>(dealer, index, coefficient).to_vec(),
        })
        .collect();
    let shares = receivers
        .iter()
        .map(|&(receiver, point)| {
            Ok(ScalarVssShare {
                dealer,
                receiver,
                point,
                value: evaluate_shamir_polynomial::<P>(coefficients, point)?,
            })
        })
        .collect::<Result<Vec<_>, DkgError>>()?;

    Ok(TestOnlyScalarVssDeal {
        dealer,
        clear_coefficients: coefficients
            .iter()
            .map(|&coefficient| reduce_mod_q::<P>(coefficient))
            .collect(),
        commitments,
        shares,
    })
}

/// Creates a deterministic clear Shamir VSS deal for every configured party
/// using the DKG config's canonical interpolation points.
#[cfg(test)]
pub fn test_only_deal_scalar_vss_for_config<P: MlDsaParams>(
    config: &DkgConfig,
    dealer: PartyId,
    coefficients: &[Coeff],
) -> Result<TestOnlyScalarVssDeal, DkgError> {
    if !config.parties.contains(&dealer) {
        return Err(DkgError::UnknownParty(dealer));
    }
    test_only_deal_scalar_vss::<P>(dealer, coefficients, &config.interpolation_points::<P>()?)
}

/// Verifies one test-only clear Shamir VSS share and returns complaint evidence
/// on failure.
#[cfg(test)]
pub fn test_only_verify_scalar_vss_share<P: MlDsaParams>(
    deal: &TestOnlyScalarVssDeal,
    share: &ScalarVssShare,
) -> Result<(), ScalarVssComplaintEvidence> {
    let binding = scalar_vss_commitment_binding(&deal.commitments);
    if share.dealer != deal.dealer {
        return Err(ScalarVssComplaintEvidence {
            dealer: share.dealer,
            receiver: share.receiver,
            point: share.point,
            got: share.value,
            expected: share.value,
            commitment_binding: binding,
        });
    }

    let expected =
        evaluate_shamir_polynomial::<P>(&deal.clear_coefficients, share.point).unwrap_or(-1);
    if reduce_mod_q::<P>(share.value) == expected {
        Ok(())
    } else {
        Err(ScalarVssComplaintEvidence {
            dealer: share.dealer,
            receiver: share.receiver,
            point: share.point,
            got: reduce_mod_q::<P>(share.value),
            expected,
            commitment_binding: binding,
        })
    }
}

/// Verifies all receiver shares for one test-only scalar VSS deal.
#[cfg(test)]
pub fn test_only_verify_scalar_vss_round<P: MlDsaParams>(
    config: &DkgConfig,
    deal: &TestOnlyScalarVssDeal,
    shares: &[ScalarVssShare],
) -> Result<Vec<DkgComplaintPayload>, DkgError> {
    config.validate()?;
    if !config.parties.contains(&deal.dealer) {
        return Err(DkgError::UnknownParty(deal.dealer));
    }
    if shares.len() != config.parties.len() {
        return Err(DkgError::MissingRoundMessages {
            round: DkgRound::Share,
            expected: config.parties.len(),
            got: shares.len(),
        });
    }

    let mut seen = Vec::with_capacity(shares.len());
    let mut complaints = Vec::new();
    for share in shares {
        if share.dealer != deal.dealer {
            return Err(DkgError::PartyMismatch {
                expected: deal.dealer,
                got: share.dealer,
            });
        }
        if !config.parties.contains(&share.receiver) {
            return Err(DkgError::UnknownParty(share.receiver));
        }
        if seen.contains(&share.receiver) {
            return Err(DkgError::DuplicateShare {
                dealer: deal.dealer,
                receiver: share.receiver,
            });
        }
        seen.push(share.receiver);

        let expected_point = config.interpolation_point::<P>(share.receiver)?;
        if share.point != expected_point {
            return Err(DkgError::InvalidSharePoint {
                party: share.receiver,
                expected: expected_point,
                got: share.point,
            });
        }

        if let Err(evidence) = test_only_verify_scalar_vss_share::<P>(deal, share) {
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

/// Resolves test-only scalar VSS complaints into accepted/rejected dealers.
///
/// This is a deterministic scaffold for exercising DKG complaint wiring. It is
/// not Rabin-Ben-Or complaint resolution and is not a production VSS backend.
#[cfg(test)]
pub fn test_only_resolve_scalar_vss_complaints<P: MlDsaParams>(
    config: &DkgConfig,
    deals: &[TestOnlyScalarVssDeal],
    complaints: &[DkgComplaintPayload],
) -> Result<TestOnlyScalarVssResolution, DkgError> {
    config.validate()?;
    validate_exact_party_set(
        config,
        DkgRound::Commit,
        deals.iter().map(|deal| deal.dealer),
    )?;

    let mut rejected_dealers = Vec::new();
    for complaint in complaints {
        if complaint.reason != DkgComplaintReason::InvalidVssShare {
            return Err(DkgError::UnsupportedComplaintReason(complaint.reason));
        }
        if !config.parties.contains(&complaint.complainant) {
            return Err(DkgError::UnknownParty(complaint.complainant));
        }
        if complaint.receiver != complaint.complainant {
            return Err(DkgError::PartyMismatch {
                expected: complaint.complainant,
                got: complaint.receiver,
            });
        }

        let evidence = ScalarVssComplaintEvidence::from_canonical_bytes(&complaint.evidence)?;
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

        let Some(deal) = deals.iter().find(|deal| deal.dealer == evidence.dealer) else {
            return Err(DkgError::UnknownParty(evidence.dealer));
        };
        let expected_binding = scalar_vss_commitment_binding(&deal.commitments);
        if evidence.commitment_binding != expected_binding {
            return Err(DkgError::ComplaintEvidenceMismatch);
        }
        let expected = evaluate_shamir_polynomial::<P>(&deal.clear_coefficients, evidence.point)?;
        if evidence.expected != expected || evidence.got == expected {
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

    Ok(TestOnlyScalarVssResolution {
        accepted_dealers,
        rejected_dealers,
    })
}

/// Combines accepted test-only scalar VSS dealer contributions into one
/// Shamir-shared scalar.
///
/// This models the DKG "sum accepted dealer polynomials" step. It is a test
/// scaffold only: production DKG must use IT-VSS complaint resolution and never
/// expose clear dealer polynomials.
#[cfg(test)]
pub fn test_only_combine_accepted_scalar_vss_deals<P: MlDsaParams>(
    config: &DkgConfig,
    deals: &[TestOnlyScalarVssDeal],
    complaints: &[DkgComplaintPayload],
) -> Result<TestOnlyScalarDkgOutput, DkgError> {
    let resolution = test_only_resolve_scalar_vss_complaints::<P>(config, deals, complaints)?;
    if resolution.accepted_dealers.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: resolution.accepted_dealers.len(),
        });
    }

    let mut clear_secret = 0i64;
    let q = i64::from(P::Q);
    for deal in deals {
        if resolution.accepted_dealers.contains(&deal.dealer) {
            let Some(&constant) = deal.clear_coefficients.first() else {
                return Err(DkgError::EmptyShamirPolynomial);
            };
            clear_secret = (clear_secret + i64::from(constant)).rem_euclid(q);
        }
    }

    let mut shares = Vec::with_capacity(config.parties.len());
    for (receiver, point) in config.interpolation_points::<P>()? {
        let mut value = 0i64;
        for deal in deals {
            if !resolution.accepted_dealers.contains(&deal.dealer) {
                continue;
            }
            let Some(share) = deal.shares.iter().find(|share| share.receiver == receiver) else {
                return Err(DkgError::MissingRoundMessages {
                    round: DkgRound::Share,
                    expected: config.parties.len(),
                    got: deal.shares.len(),
                });
            };
            if share.point != point {
                return Err(DkgError::InvalidSharePoint {
                    party: receiver,
                    expected: point,
                    got: share.point,
                });
            }
            value = (value + i64::from(reduce_mod_q::<P>(share.value))).rem_euclid(q);
        }
        shares.push(TestOnlyCombinedScalarShare {
            receiver,
            point,
            value: value as Coeff,
        });
    }

    Ok(TestOnlyScalarDkgOutput {
        accepted_dealers: resolution.accepted_dealers,
        rejected_dealers: resolution.rejected_dealers,
        clear_secret: clear_secret as Coeff,
        shares,
    })
}

/// Creates test-only scalar VSS deals for every coefficient of a bounded
/// ML-DSA secret vector.
#[cfg(test)]
pub fn test_only_deal_bounded_secret_vector<P: MlDsaParams>(
    config: &DkgConfig,
    dealer: PartyId,
    secret_coeffs: &[Coeff],
) -> Result<TestOnlyBoundedSecretVectorDeal, DkgError> {
    validate_bounded_secret_vector::<P>(secret_coeffs)?;
    if !config.parties.contains(&dealer) {
        return Err(DkgError::UnknownParty(dealer));
    }

    let mut coefficient_deals = Vec::with_capacity(secret_coeffs.len());
    for (index, &secret) in secret_coeffs.iter().enumerate() {
        let mut polynomial = Vec::with_capacity(usize::from(config.threshold));
        polynomial.push(secret);
        for degree in 1..usize::from(config.threshold) {
            polynomial.push(test_only_deterministic_scalar_mask::<P>(
                dealer, index, degree,
            ));
        }
        coefficient_deals.push(test_only_deal_scalar_vss_for_config::<P>(
            config,
            dealer,
            &polynomial,
        )?);
    }

    Ok(TestOnlyBoundedSecretVectorDeal {
        dealer,
        clear_secret_coeffs: secret_coeffs.to_vec(),
        coefficient_deals,
    })
}

/// Combines accepted bounded-vector dealer contributions and rejects outputs
/// whose summed coefficients leave the ML-DSA `[-eta, eta]` range.
#[cfg(test)]
pub fn test_only_combine_bounded_secret_vector_deals<P: MlDsaParams>(
    config: &DkgConfig,
    deals: &[TestOnlyBoundedSecretVectorDeal],
    rejected_dealers: &[PartyId],
) -> Result<TestOnlyBoundedSecretVectorDkgOutput, DkgError> {
    config.validate()?;
    validate_exact_party_set(
        config,
        DkgRound::Commit,
        deals.iter().map(|deal| deal.dealer),
    )?;
    validate_rejected_dealer_set(config, rejected_dealers)?;

    let expected_len = P::L * P::N;
    for deal in deals {
        validate_bounded_secret_vector::<P>(&deal.clear_secret_coeffs)?;
        if deal.coefficient_deals.len() != expected_len {
            return Err(DkgError::InvalidBoundedSecretVectorLength {
                expected: expected_len,
                got: deal.coefficient_deals.len(),
            });
        }
    }

    let accepted_dealers: Vec<PartyId> = config
        .parties
        .iter()
        .copied()
        .filter(|party| !rejected_dealers.contains(party))
        .collect();
    if accepted_dealers.len() < usize::from(config.threshold) {
        return Err(DkgError::InsufficientAcceptedDealers {
            threshold: config.threshold,
            accepted: accepted_dealers.len(),
        });
    }

    let mut clear_secret_coeffs = vec![0; expected_len];
    for (index, out) in clear_secret_coeffs.iter_mut().enumerate() {
        let mut sum = 0;
        for deal in deals {
            if accepted_dealers.contains(&deal.dealer) {
                sum += deal.clear_secret_coeffs[index];
            }
        }
        if !(-P::ETA..=P::ETA).contains(&sum) {
            return Err(DkgError::CombinedBoundedCoefficientOutOfRange {
                index,
                coefficient: sum,
                bound: P::ETA,
            });
        }
        *out = sum;
    }

    let mut shares = Vec::with_capacity(config.parties.len());
    for (receiver, point) in config.interpolation_points::<P>()? {
        let mut coeffs = Vec::with_capacity(expected_len);
        for index in 0..expected_len {
            let mut value = 0i64;
            for deal in deals {
                if !accepted_dealers.contains(&deal.dealer) {
                    continue;
                }
                let scalar_deal = &deal.coefficient_deals[index];
                let Some(share) = scalar_deal
                    .shares
                    .iter()
                    .find(|share| share.receiver == receiver)
                else {
                    return Err(DkgError::MissingRoundMessages {
                        round: DkgRound::Share,
                        expected: config.parties.len(),
                        got: scalar_deal.shares.len(),
                    });
                };
                if share.point != point {
                    return Err(DkgError::InvalidSharePoint {
                        party: receiver,
                        expected: point,
                        got: share.point,
                    });
                }
                value =
                    (value + i64::from(reduce_mod_q::<P>(share.value))).rem_euclid(i64::from(P::Q));
            }
            coeffs.push(value as Coeff);
        }
        shares.push(TestOnlyBoundedSecretVectorShare {
            receiver,
            point,
            coeffs,
        });
    }

    Ok(TestOnlyBoundedSecretVectorDkgOutput {
        accepted_dealers,
        rejected_dealers: rejected_dealers.to_vec(),
        clear_secret_coeffs,
        shares,
    })
}

/// Converts a test-only bounded-vector DKG output into typed secret-share
/// packages with canonical `s1_share` bytes.
#[cfg(test)]
pub fn test_only_dkg_secret_shares_from_bounded_vector_output<P: MlDsaParams>(
    config: &DkgConfig,
    output: &TestOnlyBoundedSecretVectorDkgOutput,
) -> Result<Vec<DkgSecretShare>, DkgError> {
    let mut shares = Vec::with_capacity(output.shares.len());
    for share in &output.shares {
        let typed = BoundedSecretVectorShare::new::<P>(
            config,
            share.receiver,
            share.point,
            share.coeffs.clone(),
        )?;
        shares.push(DkgSecretShare {
            party: share.receiver,
            s1_share: typed.encode::<P>(config)?,
            s2_share: vec![0],
            t0_share: vec![0],
            pairwise_seed_shares: Vec::new(),
        });
    }
    Ok(shares)
}

/// Builds explicit provisioned key-share packages from a test-only bounded
/// vector DKG output.
#[cfg(test)]
pub fn test_only_provisioned_key_shares_from_bounded_vector_output<P: MlDsaParams>(
    public: DkgPublicOutput,
    output: &TestOnlyBoundedSecretVectorDkgOutput,
    ceremony_transcript_hash: [u8; 32],
) -> Result<Vec<ProvisionedKeyShare>, DkgError> {
    public.validate_binding()?;
    if public.config.suite != DkgSuite::for_params::<P>() {
        return Err(DkgError::FinalOutputConfigMismatch);
    }
    if ceremony_transcript_hash == [0u8; 32] {
        return Err(DkgError::EmptyProvisioningTranscript);
    }

    let secret_shares =
        test_only_dkg_secret_shares_from_bounded_vector_output::<P>(&public.config, output)?;
    Ok(secret_shares
        .into_iter()
        .map(|secret| ProvisionedKeyShare {
            party: secret.party,
            public: public.clone(),
            secret,
            ceremony_transcript_hash,
        })
        .collect())
}

#[cfg(test)]
pub(crate) fn test_only_deterministic_scalar_mask<P: MlDsaParams>(
    dealer: PartyId,
    index: usize,
    degree: usize,
) -> Coeff {
    let seed = i64::from(dealer.0) * 257 + index as i64 * 17 + degree as i64 * 13 + 1;
    seed.rem_euclid(i64::from(P::Q)) as Coeff
}

#[cfg(test)]
pub(crate) fn validate_rejected_dealer_set(
    config: &DkgConfig,
    rejected_dealers: &[PartyId],
) -> Result<(), DkgError> {
    let mut seen = Vec::with_capacity(rejected_dealers.len());
    for &dealer in rejected_dealers {
        if !config.parties.contains(&dealer) {
            return Err(DkgError::UnknownParty(dealer));
        }
        if seen.contains(&dealer) {
            return Err(DkgError::DuplicateRoundSender {
                round: DkgRound::Complaint,
                sender: dealer,
            });
        }
        seen.push(dealer);
    }
    Ok(())
}
