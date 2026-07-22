use crate::low::{
    ciphertext_operation::{
        external_product::external_product,
        trlwe_ciphertext_operation::{trlwe_ciphertext_add, trlwe_ciphertext_sub},
    },
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    torus_polynomial::{
        TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat,
        torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn cmux<M: ModulusPattern>(
    trgsw_ciphertext: &TorusPolynomialMat<TwoPowerModulusPattern>,
    trlwe_ciphertext1: &TorusPolynomialVec<TwoPowerModulusPattern>,
    trlwe_ciphertext2: &TorusPolynomialVec<TwoPowerModulusPattern>,
    poly_param: &TorusPolynomialParameter,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> TorusPolynomialVec<TwoPowerModulusPattern> {
    let trlwe_ciphertext = trlwe_ciphertext_sub::<TwoPowerModulusPattern>(
        trlwe_ciphertext2,
        trlwe_ciphertext1,
        poly_param,
    );

    let result = external_product::<TwoPowerModulusPattern>(
        trgsw_ciphertext,
        &trlwe_ciphertext,
        poly_param,
        bg,
        l,
    );
    debug_assert!(result.poly.len() == trlwe_ciphertext.poly.len());

    trlwe_ciphertext_add::<TwoPowerModulusPattern>(&result, trlwe_ciphertext1, poly_param)
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::low::{
        biguint::BigUint,
        encryption::{
            trgsw_encryption::trgsw_encrypt,
            trlwe_encryption::{trlwe_decrypt, trlwe_symmetric_encrypt},
        },
        modulus::TwoPowerModulusPattern,
        secret_key::trlwe_secret_key::generate_trlwe_seckey,
        torus::{Torus, TorusParam},
        torus_polynomial::TorusPolynomial,
    };

    #[test]
    fn test_cmux() {
        let trlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 1;
        let trlwe_stddev: f32 = 0.0;
        let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^8 = 64bit
        };
        let val: u64 = 3 * (1_u64 << 48);
        let bg: usize = 63;
        let l: usize = 1;

        let trlwe_plaintext1: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(0); poly_param.polynomial_length]);
        let trlwe_plaintext2: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(val); poly_param.polynomial_length]);
        let trgsw_plaintext1: Vec<u64> = vec![0; poly_param.polynomial_length];
        let mut trgsw_plaintext2: Vec<u64> = vec![0; poly_param.polynomial_length];
        trgsw_plaintext2[0] = 1;

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let trlwe_ciphertext1: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &trlwe_plaintext1,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );
        let trlwe_ciphertext2: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &trlwe_plaintext2,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );

        let trgsw_ciphertext1: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &trgsw_plaintext1,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );
        let trgsw_ciphertext2: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &trgsw_plaintext2,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );

        let result1: TorusPolynomialVec<TwoPowerModulusPattern> = cmux::<TwoPowerModulusPattern>(
            &trgsw_ciphertext1,
            &trlwe_ciphertext1,
            &trlwe_ciphertext2,
            &poly_param,
            bg,
            l,
        );
        let result2: TorusPolynomialVec<TwoPowerModulusPattern> = cmux::<TwoPowerModulusPattern>(
            &trgsw_ciphertext2,
            &trlwe_ciphertext1,
            &trlwe_ciphertext2,
            &poly_param,
            bg,
            l,
        );

        let decrypted_ciphertext1: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&result1, &seckey, &poly_param);

        let decrypted_ciphertext2: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&result2, &seckey, &poly_param);

        assert_eq!(decrypted_ciphertext1.coeffs[0].value, 0);
        assert_eq!(decrypted_ciphertext2.coeffs[0].value, val);
    }

    #[cfg(feature = "ntt_test")]
    #[test]
    fn test_cmux_ntt() {
        let trlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 1;
        let trlwe_stddev: f32 = 0.0;
        let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
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
        let val: u64 = 3 * (1_u64 << 48);
        let bg: usize = 16;
        let l: usize = 2;

        let trlwe_plaintext1: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(0); poly_param.polynomial_length]);
        let trlwe_plaintext2: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(val); poly_param.polynomial_length]);
        let trgsw_plaintext1: Vec<u64> = vec![0; poly_param.polynomial_length];
        let mut trgsw_plaintext2: Vec<u64> = vec![0; poly_param.polynomial_length];
        trgsw_plaintext2[0] = 1;

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let trlwe_ciphertext1: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &trlwe_plaintext1,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );
        let trlwe_ciphertext2: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &trlwe_plaintext2,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );

        let trgsw_ciphertext1: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &trgsw_plaintext1,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );
        let trgsw_ciphertext2: TorusPolynomialMat<TwoPowerModulusPattern> =
            trgsw_encrypt::<TwoPowerModulusPattern>(
                &trgsw_plaintext2,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );

        let result1: TorusPolynomialVec<TwoPowerModulusPattern> = cmux::<TwoPowerModulusPattern>(
            &trgsw_ciphertext1,
            &trlwe_ciphertext1,
            &trlwe_ciphertext2,
            &poly_param,
            bg,
            l,
        );

        let result2: TorusPolynomialVec<TwoPowerModulusPattern> = cmux::<TwoPowerModulusPattern>(
            &trgsw_ciphertext2,
            &trlwe_ciphertext1,
            &trlwe_ciphertext2,
            &poly_param,
            bg,
            l,
        );

        let decrypted_ciphertext1: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&result1, &seckey, &poly_param);

        let decrypted_ciphertext2: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&result2, &seckey, &poly_param);

        assert_eq!(decrypted_ciphertext1.coeffs[0].value, 0);
        assert_eq!(decrypted_ciphertext2.coeffs[0].value, val);
    }
}
