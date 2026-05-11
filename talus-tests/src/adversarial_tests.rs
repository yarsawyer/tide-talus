use super::*;

#[test]
fn deterministic_property_cases_pass() {
    let cases = run_deterministic_property_cases();
    assert!(cases.len() >= 5);
    for case in cases {
        assert!(case.passed, "case {} failed: {}", case.name, case.detail);
    }
}

#[test]
fn all_mpc_adversarial_cases_fail_as_expected() {
    let cases = run_mpc_adversarial_cases();
    assert!(cases.len() >= 6);
    for case in cases {
        assert!(
            case.passed(),
            "case {} got {:?}, expected {:?}",
            case.name,
            case.got,
            case.expected
        );
    }
}

#[test]
fn all_online_adversarial_cases_fail_as_expected() {
    let cases = run_online_adversarial_cases();
    assert!(cases.len() >= 8);
    for case in cases {
        assert!(
            case.passed(),
            "case {} got {:?}, expected {:?}",
            case.name,
            case.got,
            case.expected
        );
    }
}

#[test]
fn all_preprocessing_adversarial_cases_fail_as_expected() {
    let cases = run_preprocessing_adversarial_cases();
    assert!(cases.len() >= 11);
    for case in cases {
        assert!(
            case.passed(),
            "case {} got {:?}, expected {:?}",
            case.name,
            case.got,
            case.expected
        );
    }
}

#[test]
fn all_wire_adversarial_cases_fail_as_expected() {
    let cases = run_wire_adversarial_cases();
    assert!(cases.len() >= 14);
    for case in cases {
        assert!(
            case.passed(),
            "case {} got {:?}, expected {:?}",
            case.name,
            case.got,
            case.expected
        );
    }
}
