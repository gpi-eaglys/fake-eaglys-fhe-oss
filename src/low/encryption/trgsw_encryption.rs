#[cfg(test)]
use crate::low::biguint::BigUint;
use crate::low::{
    encryption::trlwe_encryption::{trlwe_decrypt, trlwe_symmetric_encrypt},
    math::gadget_decomposition::generate_gadget_matrix,
    module::Module,
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    torus::Torus,
    torus_polynomial::{
        TorusPolynomial, TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat,
        torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn trgsw_encrypt<M: ModulusPattern>(
    plaintext: &[u64],
    seckey: &[Vec<u8>],
    poly_param: &TorusPolynomialParameter,
    encryption_sample_num: usize,
    trlwe_stddev: f32,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> TorusPolynomialMat<TwoPowerModulusPattern> {
    let mut ciphetext_vec: Vec<TorusPolynomialVec<TwoPowerModulusPattern>> = Vec::new();

    let zero_polynomial: TorusPolynomial<TwoPowerModulusPattern> =
        TorusPolynomial::new(vec![Torus::new(0); poly_param.polynomial_length]);

    for _ in 0..((encryption_sample_num + 1) * l) {
        ciphetext_vec.push(trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
            &zero_polynomial,
            seckey,
            poly_param,
            encryption_sample_num,
            trlwe_stddev,
        ));
    }

    let ciphertext_block: TorusPolynomialMat<TwoPowerModulusPattern> =
        TorusPolynomialMat::new(ciphetext_vec);

    let mut gadget_matrix: TorusPolynomialMat<TwoPowerModulusPattern> =
        generate_gadget_matrix(poly_param, encryption_sample_num, bg, l);

    gadget_matrix = gadget_matrix.scalar_mul(&plaintext[0], poly_param);

    let ciphertext: TorusPolynomialMat<TwoPowerModulusPattern> =
        ciphertext_block.add(&gadget_matrix, poly_param);

    ciphertext
}

pub fn trgsw_decrypt<M: ModulusPattern>(
    ciphertext: &TorusPolynomialMat<TwoPowerModulusPattern>,
    seckey: &[Vec<u8>],
    poly_param: &TorusPolynomialParameter,
    _bg: usize, // TODO: reconsider parameter name
    l: usize,   // TODO: reconsider parameter name
) -> TorusPolynomial<TwoPowerModulusPattern> {
    let lth_ciphertext: TorusPolynomialVec<TwoPowerModulusPattern> = ciphertext.poly_vec[l].clone();

    trlwe_decrypt::<TwoPowerModulusPattern>(&lth_ciphertext, seckey, poly_param)
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::low::{
        modulus::TwoPowerModulusPattern, secret_key::trlwe_secret_key::generate_trlwe_seckey,
        torus::TorusParam,
    };

    #[cfg(feature = "fixed_torus_rnd")]
    #[test]
    fn test_encrypt() {
        let plaintext: Vec<u64> = vec![1, 0];
        let trlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 1;
        let trlwe_stddev: f32 = 0.0;
        let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 0,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^8 = 64bit
        };
        let val: u64 = 1_u64 << 48;
        let bg: usize = 16;
        let l: usize = 1;

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let result: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &plaintext,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );

        assert_eq!(result.poly_vec[0].poly[0].coeffs[0].value, val);
        assert_eq!(result.poly_vec[1].poly[1].coeffs[0].value, val);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let trlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 1;
        let trlwe_stddev: f32 = 0.0;
        let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 0,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^8 = 64bit
        };
        let val: u64 = 1_u64 << 48;
        let bg: usize = 16;
        let l: usize = 1;

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let plaintext1: Vec<u64> = vec![0, 0];
        let plaintext2: Vec<u64> = vec![1, 0];

        let ciphertext1: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &plaintext1,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );
        let ciphertext2: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &plaintext2,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );

        let decrypted_ciphertext1: TorusPolynomial<TwoPowerModulusPattern> =
            trgsw_decrypt::<TwoPowerModulusPattern>(&ciphertext1, &seckey, &poly_param, bg, l);
        let decrypted_ciphertext2: TorusPolynomial<TwoPowerModulusPattern> =
            trgsw_decrypt::<TwoPowerModulusPattern>(&ciphertext2, &seckey, &poly_param, bg, l);

        assert_eq!(decrypted_ciphertext1.coeffs[0].value, 0);
        assert_eq!(decrypted_ciphertext2.coeffs[0].value, val);
    }
}
