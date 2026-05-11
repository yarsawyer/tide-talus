use crate::dkg_signing_helpers::{
    dkg_to_talus_generated_nonce_signing_verifies_with_standard_fips_verifier,
    dkg_to_talus_nonzero_nonce_signing_verifies_with_standard_fips_verifier,
    dkg_to_talus_signing_verifies_with_standard_fips_verifier,
};
use talus_core::{MlDsa44, MlDsa65, MlDsa87};

#[test]
fn mldsa44_dkg_to_talus_signing_verifies_with_standard_fips_verifier() {
    dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x44);
}

#[test]
#[ignore = "slow all-suite DKG/signing integration; run explicitly before release"]
fn all_suites_dkg_to_talus_signing_verifies_with_standard_fips_verifier() {
    dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x44);
    dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa65>(0x65);
    dkg_to_talus_signing_verifies_with_standard_fips_verifier::<MlDsa87>(0x87);
}

#[test]
#[ignore = "slow generated-nonce DKG/signing integration; run explicitly before release"]
fn dkg_to_talus_signing_with_nonzero_nonce_verifies_with_standard_fips_verifier() {
    dkg_to_talus_nonzero_nonce_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x54);
}

#[test]
fn dkg_to_talus_signing_with_generated_distributed_nonce_verifies_with_standard_fips_verifier() {
    dkg_to_talus_generated_nonce_signing_verifies_with_standard_fips_verifier::<MlDsa44>(0x64);
}
