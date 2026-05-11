fn assert_absent(source_name: &str, source: &str, needle: &str) {
    assert!(
        !source.contains(needle),
        "`{needle}` must not appear in production source `{source_name}`"
    );
}

fn assert_cfg_gated(source_name: &str, source: &str, needle: &str, cfg: &str) {
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
            prefix.contains(cfg),
            "`{needle}` in `{source_name}` must be gated by `{cfg}`"
        );
        offset = index + needle.len();
    }
}

fn toml_section<'a>(source: &'a str, section: &str) -> &'a str {
    let header = format!("[{section}]");
    let start = source
        .find(&header)
        .unwrap_or_else(|| panic!("missing TOML section `{header}`"))
        + header.len();
    let rest = &source[start..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn crate_docs_define_one_normal_production_surface() {
    let mpc_lib = include_str!("../../talus-mpc/src/lib.rs");
    assert!(
        mpc_lib.contains("Normal builds expose only the strict production-facing TALUS-MPC API"),
        "talus-mpc crate docs must state that normal builds expose only strict production APIs"
    );
    assert!(
        mpc_lib.contains("production-release-checks"),
        "talus-mpc crate docs must mention the release-check feature"
    );

    let dkg_lib = include_str!("../../talus-dkg/src/lib.rs");
    assert!(
        dkg_lib.contains("Normal builds expose the production-oriented native DKG API"),
        "talus-dkg crate docs must state the production-oriented API surface"
    );
    assert!(
        dkg_lib.contains("Release checks reject scaffold/dev"),
        "talus-dkg crate docs must describe scaffold/dev release rejection"
    );

    let wire_lib = include_str!("../../talus-wire/src/lib.rs");
    assert!(
        wire_lib.contains("intentionally does not implement sockets"),
        "talus-wire crate docs must document that concrete transport is app-supplied"
    );
    assert!(
        wire_lib.contains("partial-signature payloads are test/dev only"),
        "talus-wire crate docs must document paper-fast payload gating"
    );
}

#[test]
fn normal_feature_graph_does_not_enable_dev_insecure_features() {
    let dkg_cargo = include_str!("../../talus-dkg/Cargo.toml");
    assert!(
        dkg_cargo.contains("scaffold-dev = [\"talus-wire/paper-fast-dev\"]"),
        "talus-dkg scaffold-dev feature must remain explicit"
    );
    let dkg_normal_deps = toml_section(dkg_cargo, "dependencies");
    assert!(
        dkg_normal_deps
            .contains("talus-wire = { path = \"../talus-wire\", default-features = false }"),
        "talus-dkg normal dependency must keep talus-wire dev features disabled"
    );
    assert!(
        !dkg_normal_deps.contains("paper-fast-dev"),
        "talus-dkg normal dependency must not enable talus-wire/paper-fast-dev"
    );

    let mpc_cargo = include_str!("../../talus-mpc/Cargo.toml");
    assert!(
        mpc_cargo.contains("paper-fast-dev = []"),
        "talus-mpc paper-fast-dev feature must remain explicit"
    );

    let tests_cargo = include_str!("../../talus-tests/Cargo.toml");
    assert!(
        tests_cargo.contains(
            "paper-fast-dev = [\"talus-mpc/paper-fast-dev\", \"talus-wire/paper-fast-dev\"]"
        ),
        "talus-tests paper-fast-dev must be the explicit opt-in for paper-fast integration tests"
    );
    let tests_normal_deps = toml_section(tests_cargo, "dependencies");
    for normal_dep in [
        "talus-dkg = { path = \"../talus-dkg\", default-features = false }",
        "talus-mpc = { path = \"../talus-mpc\", default-features = false }",
        "talus-wire = { path = \"../talus-wire\", default-features = false }",
    ] {
        assert!(
            tests_normal_deps.contains(normal_dep),
            "talus-tests normal dependency `{normal_dep}` must not enable dev features"
        );
    }
    assert!(
        !tests_normal_deps.contains("paper-fast-dev")
            && !tests_normal_deps.contains("scaffold-dev"),
        "talus-tests normal dependencies must not enable dev/scaffold features"
    );
}

#[test]
fn production_sources_do_not_expose_insecure_talus_paper_artifacts() {
    let mpc_online = include_str!("../../talus-mpc/src/online.rs");
    for needle in [
        "pub struct PartialSignature",
        "pub struct PolynomialPartialSignature",
        "pub struct CommitmentBackedPartialVerifier",
        "pub fn sign_with_token",
        "pub fn sign_polynomial_with_token",
        "as1_commitment",
        "ay_commitment",
    ] {
        assert_absent("talus-mpc/src/online.rs", mpc_online, needle);
    }

    let mpc_local = include_str!("../../talus-mpc/src/local.rs");
    for needle in [
        "pub ay_commitment: PolyVec",
        "pub struct MaskedBroadcastClearAudit",
        "pub struct ClearMaskedBroadcastConsistencyVerifier",
        "pub struct CutAndChooseAuditPlan",
    ] {
        assert_absent("talus-mpc/src/local.rs", mpc_local, needle);
    }

    let dkg_helpers = include_str!("dkg_signing_helpers.rs");
    for needle in [
        "CommitmentBackedPartialVerifier",
        "PolynomialPartialCommitment",
        "as1_commitment",
        "A*s1 commitment",
    ] {
        assert_absent(
            "talus-tests/src/dkg_signing_helpers.rs",
            dkg_helpers,
            needle,
        );
    }
}

#[test]
fn production_sources_do_not_expose_rejected_z_leakage_paths() {
    let mpc_online = include_str!("../../talus-mpc/src/online.rs");
    let mpc_online_production_prefix = mpc_online
        .split("#[cfg(test)]")
        .next()
        .expect("online source has production prefix before tests");
    for needle in [
        "PartialSignature",
        "PolynomialPartialSignature",
        "SignatureAssembler",
        "sign_with_token",
        "sign_with_retry",
        "z_share",
        "clear z",
        "candidate token",
        "rejected z",
    ] {
        assert_absent("talus-mpc/src/online.rs", mpc_online, needle);
    }
    for needle in [
        "Rc<RefCell",
        "StrictVectorBatchState",
        "bound_responses",
        "hint_responses",
        "selection_candidates",
    ] {
        assert_absent(
            "talus-mpc/src/online.rs production prefix",
            mpc_online_production_prefix,
            needle,
        );
    }
    let paper_cfg = "#[cfg(any(test, feature = \"paper-fast-dev\"))]";
    for needle in [
        "PartialSignerFailed",
        "PartialCountMismatch",
        "PartialMismatch",
        "Blame(PartyId)",
        "PublicCommitmentMissing",
        "PublicCommitmentLength",
        "RetryExhausted",
    ] {
        assert_cfg_gated("talus-mpc/src/online.rs", mpc_online, needle, paper_cfg);
    }

    let mpc_exports = include_str!("../../talus-mpc/src/lib.rs");
    let production_exports = mpc_exports
        .split("#[cfg(any(test, feature = \"paper-fast-dev\"))]")
        .next()
        .expect("source always has a production-prefix section");
    for needle in [
        "PartialSignature",
        "CommitmentBackedPartialVerifier",
        "sign_with_token",
        "sign_with_retry",
        "NoopStrictSigningDistributedRuntime",
    ] {
        assert_absent(
            "talus-mpc/src/lib.rs production exports",
            production_exports,
            needle,
        );
    }

    assert_absent(
        "talus-mpc/src/online.rs",
        mpc_online,
        "NoopStrictSigningDistributedRuntime",
    );

    let runtime_region = mpc_online
        .split("pub trait StrictSigningDistributedRuntime")
        .nth(1)
        .expect("distributed runtime trait exists")
        .split("/// Durable strict signing cursor persistence API.")
        .next()
        .expect("cursor API follows distributed runtime section");
    for needle in [
        "strict_response_polyvec",
        "strict_aggregate_response_lagrange",
        "z_bound_holds",
        "public_approx_from_az",
        "compute_talus_hint_polyvec",
        "signature_encode",
        ".select_candidate(",
        ".open_selected(",
    ] {
        assert_absent(
            "talus-mpc/src/online.rs distributed runtime boundary",
            runtime_region,
            needle,
        );
    }
    assert!(
        runtime_region.contains("DirectStrictSigningComponentRuntime"),
        "direct component-stack signing must use an explicit rejecting runtime adapter"
    );

    let wire = include_str!("../../talus-wire/src/lib.rs");
    let wire_production_prefix = wire
        .split("pub mod dev_backends")
        .next()
        .expect("wire source has a prefix before dev_backends");
    assert!(
        wire.contains("pub struct StrictSignMpcPayload"),
        "production wire API must expose the strict signing MPC runtime payload"
    );
    assert_absent(
        "talus-wire/src/lib.rs production prefix",
        wire_production_prefix,
        "z_share",
    );
    assert_absent(
        "talus-wire/src/lib.rs production prefix",
        wire_production_prefix,
        "PartialSignaturePayload",
    );
    for needle in [
        "\n    SignPartial = 4,",
        "\n    PartialSignature = 4,",
        "\npub struct PartialSignaturePayload",
        "\npub fn encode_partial_signature_payload",
        "\npub fn decode_partial_signature_payload",
    ] {
        assert_cfg_gated("talus-wire/src/lib.rs", wire, needle, paper_cfg);
    }
}

#[test]
fn normal_api_does_not_expose_test_execution_profiles_or_reveal_paths() {
    let mpc_lib = include_str!("../../talus-mpc/src/lib.rs");
    let mpc_production_prefix = mpc_lib
        .split("#[cfg(any(test, feature = \"paper-fast-dev\"))]")
        .next()
        .expect("talus-mpc lib has a normal-build prefix");
    for needle in [
        "TestPaperFastExperimental",
        "TestLocalSimulation",
        "SigningExecutionProfile",
        "RevealNonceAfterChallenge",
        "reveal_on_failure",
        "reveal_nonce_after_challenge",
        "CommitmentBackedPartialVerifier",
        "PartialSignaturePayload",
    ] {
        assert_absent(
            "talus-mpc/src/lib.rs normal API",
            mpc_production_prefix,
            needle,
        );
    }

    let dkg_lib = include_str!("../../talus-dkg/src/lib.rs");
    let dkg_production_prefix = dkg_lib
        .split("#[cfg(any(test, feature = \"scaffold-dev\"))]")
        .next()
        .unwrap_or(dkg_lib);
    for needle in [
        "TestPaperFastExperimental",
        "TestLocalSimulation",
        "SigningExecutionProfile",
        "As1Commitment",
        "as1_commitment",
        "reveal_on_failure",
    ] {
        assert_absent(
            "talus-dkg/src/lib.rs normal API",
            dkg_production_prefix,
            needle,
        );
    }

    let wire = include_str!("../../talus-wire/src/lib.rs");
    let wire_production_prefix = wire
        .split("#[cfg(any(test, feature = \"paper-fast-dev\"))]")
        .next()
        .expect("talus-wire source has a normal-build prefix");
    for needle in [
        "TestPaperFastExperimental",
        "TestLocalSimulation",
        "SigningExecutionProfile",
        "PartialSignaturePayload",
        "SignPartial = 4",
        "PartialSignature = 4",
        "reveal_on_failure",
    ] {
        assert_absent(
            "talus-wire/src/lib.rs normal API",
            wire_production_prefix,
            needle,
        );
    }
}

#[test]
fn remaining_dev_artifacts_are_feature_gated() {
    let dkg_types = include_str!("../../talus-dkg/src/types.rs");
    for needle in [
        "pub struct As1Commitment",
        "pub as1_commitments: Vec<As1Commitment>",
    ] {
        assert_absent("talus-dkg/src/types.rs", dkg_types, needle);
    }

    let dkg_lib = include_str!("../../talus-dkg/src/lib.rs");
    assert_absent(
        "talus-dkg/src/lib.rs",
        dkg_lib,
        "pub as1_commitment: As1Commitment",
    );

    let wire = include_str!("../../talus-wire/src/lib.rs");
    let paper_cfg = "#[cfg(any(test, feature = \"paper-fast-dev\"))]";
    for needle in [
        "\n    SignPartial = 4,",
        "\n    PartialSignature = 4,",
        "\npub struct PartialSignaturePayload",
        "\npub fn encode_partial_signature_payload",
        "\npub fn decode_partial_signature_payload",
        "\n    pub as1_commitment: Vec<u8>",
    ] {
        assert_cfg_gated("talus-wire/src/lib.rs", wire, needle, paper_cfg);
    }
}
