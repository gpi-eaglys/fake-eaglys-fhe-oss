#[cfg(test)]
use crate::low::torus::TorusParam;
use crate::low::{
    biguint::{BigUint, addmod, mulmod, submod},
    modulus::TwoPowerModulusPattern,
    torus::Torus,
    torus_polynomial::{TorusPolynomial, TorusPolynomialParameter},
};

// ntt/intt algorithms for test
// ntt algorithm without multiply_psi_power_list
fn ntt(
    poly: &TorusPolynomial<TwoPowerModulusPattern>,
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    // transform TorusPolynomial into a vector of BigUint
    let ctxt_vec: Vec<BigUint> = convert_torus_polynomial_to_biguint_vec(poly, param);

    let twiddle_list: Vec<Vec<BigUint>> = generate_bit_reversed_twiddle_list(param);

    ntt_butterfly_operation_cooley_tukey_type(&ctxt_vec, &twiddle_list, param)
}

// ntt algorithm without multiply_inverse_psi_power_list
fn intt(
    ntt_data_vec: &[BigUint],
    param: &TorusPolynomialParameter,
) -> TorusPolynomial<TwoPowerModulusPattern> {
    let inverse_twiddle_list: Vec<Vec<BigUint>> = generate_bit_reversed_inverse_twiddle_list(param);

    let intt_data_vec =
        intt_butterfly_operation_gentleman_sande_type(ntt_data_vec, &inverse_twiddle_list, param);

    convert_biguint_vec_to_torus_polynomial(&intt_data_vec, param)
}

// ntt/intt subroutines
pub fn multiply_psi_power_list(
    data_vec: &[BigUint],
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    let psi_power_list: Vec<BigUint> = generate_psi_power_list(param);
    biguint_vec_element_wise_multiplication(data_vec, &psi_power_list, param)
}

pub fn multiply_inverse_psi_power_list(
    intt_data_vec: &[BigUint],
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    let inverse_psi_power_list: Vec<BigUint> = generate_inverse_psi_power_list(param);

    let multiplied_data_list: Vec<BigUint> =
        biguint_vec_element_wise_multiplication(intt_data_vec, &inverse_psi_power_list, param);

    multiplied_data_list
}

// core algorithms for ntt/intt
pub fn generate_bit_reversed_twiddle_list(param: &TorusPolynomialParameter) -> Vec<Vec<BigUint>> {
    let mut twiddle_list: Vec<Vec<BigUint>> = Vec::new();
    let two_power_omega_list: Vec<BigUint> =
        generate_two_power_num_list(&param.ntt_prime_omega, param);

    for r in 0..param.log_polynomial_length {
        let mut rth_twiddle_list: Vec<BigUint> = Vec::with_capacity(2_usize.pow(r as u32));
        let mut rth_omega: BigUint = BigUint::from(1);
        let rth_two_power_omega: BigUint =
            two_power_omega_list[param.log_polynomial_length - 1 - r].clone();
        for _ in 0..((2_u32.pow(r as u32)) as usize) {
            rth_twiddle_list.push(rth_omega.clone());
            rth_omega = mulmod(&rth_omega, &rth_two_power_omega, &param.prime_modulus)
        }
        let bit_reversed_rth_twiddle_list: Vec<BigUint> = bit_reverse_list(&rth_twiddle_list, r);
        twiddle_list.push(bit_reversed_rth_twiddle_list.clone());
    }

    twiddle_list
}

fn generate_psi_power_list(param: &TorusPolynomialParameter) -> Vec<BigUint> {
    let mut psi_power_list: Vec<BigUint> = Vec::with_capacity(param.polynomial_length);
    let mut ith_psi = BigUint::from(1);

    for _ in 0..param.polynomial_length {
        psi_power_list.push(ith_psi.clone());
        ith_psi = mulmod(&ith_psi, &param.ntt_prime_psi, &param.prime_modulus);
    }

    psi_power_list
}

pub fn ntt_butterfly_operation_cooley_tukey_type(
    data_vec: &[BigUint],
    twiddle_list: &[Vec<BigUint>],
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    let mut data_vec_butterfly: Vec<BigUint> = data_vec.to_vec();
    for r in 0..param.log_polynomial_length {
        let m: usize = 2_usize.pow(r as u32);
        let k: usize = 2_usize.pow((param.log_polynomial_length - r - 1) as u32);
        for i in 0..m {
            let j1: usize = 2 * i * k;
            let j2: usize = j1 + k;
            for j in j1..j2 {
                let t: BigUint = std::mem::replace(&mut data_vec_butterfly[j], BigUint::from(0));
                let u: BigUint = mulmod(
                    &data_vec_butterfly[j + k],
                    &twiddle_list[r][i],
                    &param.prime_modulus,
                );
                data_vec_butterfly[j] = addmod(&t, &u, &param.prime_modulus);
                data_vec_butterfly[j + k] = submod(&t, &u, &param.prime_modulus);
            }
        }
    }
    data_vec_butterfly
}

pub fn generate_bit_reversed_inverse_twiddle_list(
    param: &TorusPolynomialParameter,
) -> Vec<Vec<BigUint>> {
    let mut twiddle_list: Vec<Vec<BigUint>> = Vec::new();
    let two_power_omega_list: Vec<BigUint> =
        generate_two_power_num_list(&param.inverse_ntt_prime_omega, param);

    for r in 0..param.log_polynomial_length {
        let mut rth_twiddle_list: Vec<BigUint> = Vec::with_capacity(2_usize.pow(r as u32));
        let mut rth_omega: BigUint = BigUint::from(1);
        let rth_two_power_omega: BigUint =
            two_power_omega_list[param.log_polynomial_length - 1 - r].clone();
        for _ in 0..((2_u32.pow(r as u32)) as usize) {
            rth_twiddle_list.push(rth_omega.clone());
            rth_omega = mulmod(&rth_omega, &rth_two_power_omega, &param.prime_modulus)
        }
        let bit_reversed_rth_twiddle_list: Vec<BigUint> = bit_reverse_list(&rth_twiddle_list, r);
        twiddle_list.push(bit_reversed_rth_twiddle_list.clone());
    }

    twiddle_list
}

fn generate_inverse_psi_power_list(param: &TorusPolynomialParameter) -> Vec<BigUint> {
    let mut psi_power_list: Vec<BigUint> = Vec::with_capacity(param.polynomial_length);
    let mut ith_psi = BigUint::from(1);

    for _ in 0..param.polynomial_length {
        psi_power_list.push(ith_psi.clone());
        ith_psi = mulmod(&ith_psi, &param.inverse_ntt_prime_psi, &param.prime_modulus);
    }

    psi_power_list
}

pub fn intt_butterfly_operation_gentleman_sande_type(
    ntt_data_vec: &[BigUint],
    inverse_twiddle_list: &[Vec<BigUint>],
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    let mut data_vec_butterfly: Vec<BigUint> = ntt_data_vec.to_vec();

    for r in 0..param.log_polynomial_length {
        let m: usize = 2_usize.pow((param.log_polynomial_length - r - 1) as u32);
        let k: usize = 2_usize.pow(r as u32);
        for i in 0..m {
            let j1: usize = 2 * i * k;
            let j2: usize = j1 + k;
            for j in j1..j2 {
                let t: BigUint = data_vec_butterfly[j].clone();
                let u: BigUint = data_vec_butterfly[j + k].clone();

                data_vec_butterfly[j] = addmod(&t, &u, &param.prime_modulus);
                data_vec_butterfly[j + k] = mulmod(
                    &submod(&t, &u, &param.prime_modulus),
                    &inverse_twiddle_list[param.log_polynomial_length - r - 1][i],
                    &param.prime_modulus,
                );
            }
        }
    }

    data_vec_butterfly
}

// basis algorithms for ntt/intt
pub fn convert_torus_polynomial_to_biguint_vec(
    poly: &TorusPolynomial<TwoPowerModulusPattern>,
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    let mut result: Vec<BigUint> = Vec::new();

    for i in 0..(param.polynomial_length) {
        result.push(BigUint::from(poly.coeffs[i].value));
    }

    result
}

fn convert_biguint_vec_to_torus_polynomial(
    biguint_vec: &[BigUint],
    param: &TorusPolynomialParameter,
) -> TorusPolynomial<TwoPowerModulusPattern> {
    let mut coeffs: Vec<Torus> = Vec::new();

    for i in 0..(param.polynomial_length) {
        // 64 bit Torus の範囲へ変換
        coeffs.push(Torus::from_biguint_checked(&rem_by_torus_parameter(
            &biguint_vec[i],
            param,
        )));
    }

    TorusPolynomial::new(coeffs)
}

fn rem_by_torus_parameter(biguint_num: &BigUint, param: &TorusPolynomialParameter) -> BigUint {
    let mut num = biguint_num.clone();

    assert!(
        param.torus_parameter.bitsize <= 64,
        "torus bitsize > 64 is unsupported for non-NTT storage"
    );

    // Reduce modulo 2^{bitsize} of the torus parameter.
    let modulus = BigUint::from(1u64) << param.torus_parameter.bitsize;

    num %= modulus;

    num
}

pub fn convert_biguint_vec_to_torus_polynomial_for_poly_mul(
    biguint_vec: &[BigUint],
    param: &TorusPolynomialParameter,
) -> TorusPolynomial<TwoPowerModulusPattern> {
    let mut coeffs: Vec<Torus> = Vec::new();

    // preprocess
    for i in 0..(param.polynomial_length) {
        // 多項式乗算用の後処理
        let mut ith_num = postprocess_for_poly_mul(&biguint_vec[i], param);

        // 64 bit Torus の範囲へ変換
        ith_num = rem_by_torus_parameter(&ith_num, param);

        coeffs.push(Torus::from_biguint_checked(&ith_num));
    }

    TorusPolynomial::new(coeffs)
}

fn postprocess_for_poly_mul(biguint_num: &BigUint, _param: &TorusPolynomialParameter) -> BigUint {
    let mut num: BigUint = biguint_num.clone();

    // TODO: param.torus_parameter とか param.prime_modulus を使う
    let threshold = BigUint::from(1u64) << 127;
    if num >= threshold {
        let adjustment = (BigUint::from(1u64) << 54) - BigUint::from(1u64);
        num += adjustment;
    }

    num
}

pub fn biguint_vec_element_wise_multiplication(
    ntt_data_vec1: &[BigUint],
    ntt_data_vec2: &[BigUint],
    param: &TorusPolynomialParameter,
) -> Vec<BigUint> {
    let mut ntt_data_vec: Vec<BigUint> = Vec::with_capacity(param.polynomial_length);

    for i in 0..param.polynomial_length {
        ntt_data_vec.push(mulmod(
            &ntt_data_vec1[i],
            &ntt_data_vec2[i],
            &param.prime_modulus,
        ));
    }

    ntt_data_vec
}

fn generate_two_power_num_list(num: &BigUint, param: &TorusPolynomialParameter) -> Vec<BigUint> {
    let mut two_power_num_list: Vec<BigUint> = Vec::with_capacity(param.log_polynomial_length);
    let mut two_power_num: BigUint = num.clone();

    for _ in 0..param.log_polynomial_length {
        two_power_num_list.push(two_power_num.clone());
        two_power_num = mulmod(&two_power_num, &two_power_num, &param.prime_modulus)
    }

    two_power_num_list
}

fn bit_reverse_list(rth_twiddle_list: &[BigUint], r: usize) -> Vec<BigUint> {
    let rth_twiddle_list_size = rth_twiddle_list.len();
    let mut rth_bit_reversed_twiddle_list: Vec<BigUint> = Vec::with_capacity(rth_twiddle_list_size);

    let rth_bit_reverse_index_list: Vec<usize> = bit_reverse_index_list(r);

    for i in 0..rth_twiddle_list_size {
        rth_bit_reversed_twiddle_list
            .push(rth_twiddle_list[(rth_bit_reverse_index_list[i]) as usize].clone());
    }

    rth_bit_reversed_twiddle_list
}

fn bit_reverse_index_list(r: usize) -> Vec<usize> {
    let two_power_r = 2_usize.pow(r as u32);
    let mut rth_bit_reverse_index_list: Vec<usize> = Vec::with_capacity(two_power_r);

    for i in 0..two_power_r {
        let mut bit_reverse_ith_num: usize = 0;
        for j in 0..r {
            if (i >> j) % 2 == 1 {
                bit_reverse_ith_num += 1 << (r - j - 1);
            }
        }
        rth_bit_reverse_index_list.push(bit_reverse_ith_num);
    }

    rth_bit_reverse_index_list
}

#[test]
fn test_ntt() {
    let mut input: Vec<Torus> = Vec::new();
    let mut expected: Vec<BigUint> = Vec::new();

    input.push(Torus::new(1));
    expected.push(BigUint::from(65536));

    for _ in 0..65535 {
        input.push(Torus::new(1));
        expected.push(BigUint::from(0));
    }

    let a: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(input);
    let param: TorusPolynomialParameter = TorusPolynomialParameter {
        polynomial_length: 65536,
        log_polynomial_length: 16,
        prime_modulus: BigUint::from(u128::MAX - ((1_u128) << 54) + 2),
        ntt_prime_psi: BigUint::from(15479278773488526269853478226682162690_u128),
        inverse_ntt_prime_psi: BigUint::from(149844963811214215698651536441648540446_u128),
        ntt_prime_omega: BigUint::from(274761496178149862042109796498575449673_u128),
        inverse_ntt_prime_omega: BigUint::from(276625252932050520471031159916991523792_u128),
        inverse_poly_size: BigUint::from(340277174624079928635728062811807416321_u128),
        torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^6 = 64bit
    };
    let result: Vec<BigUint> = ntt(&a, &param);
    for i in 0..param.polynomial_length {
        assert_eq!(result[i].clone(), expected[i]);
    }
}

#[test]
fn test_ntt_intt() {
    let mut input: Vec<Torus> = Vec::new();
    let mut expected: Vec<BigUint> = Vec::new();

    for _ in 0..65536 {
        input.push(Torus::new(1));
        expected.push(BigUint::from(1));
    }

    let a: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(input);
    let param: TorusPolynomialParameter = TorusPolynomialParameter {
        polynomial_length: 65536,
        log_polynomial_length: 16,
        prime_modulus: BigUint::from(u128::MAX - 2_u128.pow(54) + 2),
        ntt_prime_psi: BigUint::from(15479278773488526269853478226682162690_u128),
        inverse_ntt_prime_psi: BigUint::from(149844963811214215698651536441648540446_u128),
        ntt_prime_omega: BigUint::from(274761496178149862042109796498575449673_u128),
        inverse_ntt_prime_omega: BigUint::from(276625252932050520471031159916991523792_u128),
        inverse_poly_size: BigUint::from(340277174624079928635728062811807416321_u128),
        torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^6 = 64bit
    };
    let result: TorusPolynomial<TwoPowerModulusPattern> = intt(&ntt(&a, &param), &param);
    for i in 0..param.polynomial_length {
        let divisor = BigUint::from(param.polynomial_length as u64);
        assert_eq!(
            BigUint::from(result.coeffs[i].value) / divisor,
            expected[i].clone()
        );
    }
}
