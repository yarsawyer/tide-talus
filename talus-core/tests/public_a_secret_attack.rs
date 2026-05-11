use talus_core::{
    az_from_expanded_a, expand_a, inv_ntt_poly, ntt_poly, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
    Poly, PolyVec,
};

const Q: i64 = 8_380_417;

fn mod_q(x: i64) -> i64 {
    x.rem_euclid(Q)
}

fn mod_pow(mut base: i64, mut exp: i64) -> i64 {
    let mut acc = 1i64;
    base = mod_q(base);
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mod_q(acc * base);
        }
        base = mod_q(base * base);
        exp >>= 1;
    }
    acc
}

fn mod_inv(x: i64) -> Option<i64> {
    (mod_q(x) != 0).then(|| mod_pow(x, Q - 2))
}

fn solve_full_column_rank(matrix: &[Vec<i64>], rhs: &[i64], vars: usize) -> Option<Vec<i64>> {
    let rows = matrix.len();
    let mut aug = vec![vec![0i64; vars + 1]; rows];
    for row in 0..rows {
        for col in 0..vars {
            aug[row][col] = mod_q(matrix[row][col]);
        }
        aug[row][vars] = mod_q(rhs[row]);
    }

    let mut pivot_row = 0usize;
    for col in 0..vars {
        let pivot = (pivot_row..rows).find(|&row| aug[row][col] != 0)?;
        aug.swap(pivot_row, pivot);

        let inv = mod_inv(aug[pivot_row][col])?;
        for entry in &mut aug[pivot_row][col..=vars] {
            *entry = mod_q(*entry * inv);
        }

        for row in 0..rows {
            if row == pivot_row {
                continue;
            }
            let factor = aug[row][col];
            if factor == 0 {
                continue;
            }
            for c in col..=vars {
                aug[row][c] = mod_q(aug[row][c] - factor * aug[pivot_row][c]);
            }
        }

        pivot_row += 1;
    }

    let solution: Vec<i64> = (0..vars).map(|col| aug[col][vars]).collect();
    for row in 0..rows {
        let actual = matrix[row]
            .iter()
            .zip(solution.iter())
            .fold(0i64, |acc, (&a, &x)| mod_q(acc + mod_q(a) * x));
        if actual != mod_q(rhs[row]) {
            return None;
        }
    }
    Some(solution)
}

fn deterministic_secret_polyvec<P: MlDsaParams>() -> PolyVec {
    PolyVec::new(
        (0..P::L)
            .map(|poly_idx| {
                Poly::from_coeffs(core::array::from_fn(|coeff_idx| {
                    let value = (17
                        + 4099 * (poly_idx as i32 + 1)
                        + 257 * coeff_idx as i32
                        + 31 * ((poly_idx * coeff_idx) as i32))
                        % P::Q;
                    value
                }))
            })
            .collect(),
    )
}

fn recover_secret_from_public_a_image<P: MlDsaParams>(
    rho: &[u8; 32],
    public_image: &PolyVec,
) -> Option<PolyVec> {
    let a_hat = expand_a::<P>(rho);
    let image_hat: Vec<Poly> = public_image.polys().iter().map(ntt_poly).collect();
    let mut recovered_hat = vec![[0i32; 256]; P::L];

    for coeff_idx in 0..P::N {
        let matrix: Vec<Vec<i64>> = (0..P::K)
            .map(|row| {
                (0..P::L)
                    .map(|col| i64::from(a_hat[row][col].coeffs()[coeff_idx]))
                    .collect()
            })
            .collect();
        let rhs: Vec<i64> = (0..P::K)
            .map(|row| i64::from(image_hat[row].coeffs()[coeff_idx]))
            .collect();
        let solution = solve_full_column_rank(&matrix, &rhs, P::L)?;
        for col in 0..P::L {
            recovered_hat[col][coeff_idx] = solution[col] as i32;
        }
    }

    Some(PolyVec::new(
        recovered_hat
            .into_iter()
            .map(|coeffs| inv_ntt_poly(&Poly::from_coeffs(coeffs)))
            .collect(),
    ))
}

fn rho_with_full_rank_slices<P: MlDsaParams>() -> [u8; 32] {
    for seed in 0u8..=64 {
        let rho = core::array::from_fn(|i| seed.wrapping_mul(17).wrapping_add(i as u8));
        let secret = deterministic_secret_polyvec::<P>();
        let image = az_from_expanded_a::<P>(&expand_a::<P>(&rho), &secret).expect("A*x");
        if recover_secret_from_public_a_image::<P>(&rho, &image).is_some() {
            return rho;
        }
    }
    panic!(
        "could not find full-rank ML-DSA matrix seed for {}",
        P::NAME
    );
}

fn assert_public_a_image_recovers_secret<P: MlDsaParams>() {
    let rho = rho_with_full_rank_slices::<P>();
    let secret = deterministic_secret_polyvec::<P>();
    let image = az_from_expanded_a::<P>(&expand_a::<P>(&rho), &secret).expect("A*x");

    let recovered = recover_secret_from_public_a_image::<P>(&rho, &image)
        .expect("public A*x should be invertible for this rho");

    assert_eq!(
        recovered,
        secret,
        "public exact A*x recovered the secret for {}",
        P::NAME
    );
}

#[test]
fn attack_recovers_secret_from_public_a_image_ml_dsa_44() {
    assert_public_a_image_recovers_secret::<MlDsa44>();
}

#[test]
fn attack_recovers_secret_from_public_a_image_ml_dsa_65() {
    assert_public_a_image_recovers_secret::<MlDsa65>();
}

#[test]
fn attack_recovers_secret_from_public_a_image_ml_dsa_87() {
    assert_public_a_image_recovers_secret::<MlDsa87>();
}

#[test]
fn attack_demonstrates_public_as1_share_compromise() {
    let rho = rho_with_full_rank_slices::<MlDsa65>();
    let signer_s1_share = deterministic_secret_polyvec::<MlDsa65>();
    let public_as1_share =
        az_from_expanded_a::<MlDsa65>(&expand_a::<MlDsa65>(&rho), &signer_s1_share)
            .expect("A*s1_i");

    let recovered_s1_share = recover_secret_from_public_a_image::<MlDsa65>(&rho, &public_as1_share)
        .expect("recover s1_i from public A*s1_i");

    assert_eq!(recovered_s1_share, signer_s1_share);
}

#[test]
fn attack_demonstrates_public_nonce_polynomial_commitment_compromise() {
    let rho = rho_with_full_rank_slices::<MlDsa65>();
    let nonce_polynomial_coefficient = deterministic_secret_polyvec::<MlDsa65>();
    let public_phi =
        az_from_expanded_a::<MlDsa65>(&expand_a::<MlDsa65>(&rho), &nonce_polynomial_coefficient)
            .expect("A*nonce coefficient");

    let recovered_nonce_coefficient =
        recover_secret_from_public_a_image::<MlDsa65>(&rho, &public_phi)
            .expect("recover nonce coefficient from public Phi=A*x");

    assert_eq!(recovered_nonce_coefficient, nonce_polynomial_coefficient);
}
