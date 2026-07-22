use crate::low::{
    math::gadget_decomposition::gadget_decomposition_to_torus_polynomial_vec,
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    torus_polynomial::{
        TorusPolynomial, TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat,
        torus_polynomial_vec::TorusPolynomialVec,
    },
};

// TODO: Change to inner_product_ntt
pub fn external_product<M: ModulusPattern>(
    trgsw_ciphertext: &TorusPolynomialMat<TwoPowerModulusPattern>,
    trlwe_ciphertext: &TorusPolynomialVec<TwoPowerModulusPattern>,
    poly_param: &TorusPolynomialParameter,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> TorusPolynomialVec<TwoPowerModulusPattern> {
    debug_assert!(trgsw_ciphertext.poly_vec[0].poly.len() == trlwe_ciphertext.poly.len());
    let gadget_decomposed_trlwe_ciphertext: Vec<TorusPolynomialVec<TwoPowerModulusPattern>> =
        gadget_decomposition_to_torus_polynomial_vec(trlwe_ciphertext, poly_param, bg, l);

    let mut extended_gadget_decomposed_trlwe_ciphertext_vec: Vec<
        TorusPolynomial<TwoPowerModulusPattern>,
    > = Vec::new();

    for i in 0..gadget_decomposed_trlwe_ciphertext.len() {
        for j in 0..gadget_decomposed_trlwe_ciphertext[0].poly.len() {
            extended_gadget_decomposed_trlwe_ciphertext_vec
                .push(gadget_decomposed_trlwe_ciphertext[i].poly[j].clone());
        }
    }

    let gadget_decomposed_trlwe_ciphertext_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
        TorusPolynomialVec::new(extended_gadget_decomposed_trlwe_ciphertext_vec);

    let mut transposed_trgsw_ciphertext_vec: Vec<TorusPolynomialVec<TwoPowerModulusPattern>> =
        Vec::new();

    for j in 0..trgsw_ciphertext.poly_vec[0].poly.len() {
        let mut ith_transposed_trgsw_ciphertext_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> =
            Vec::new();
        for i in 0..trgsw_ciphertext.poly_vec.len() {
            ith_transposed_trgsw_ciphertext_vec.push(trgsw_ciphertext.poly_vec[i].poly[j].clone());
        }
        transposed_trgsw_ciphertext_vec
            .push(TorusPolynomialVec::new(ith_transposed_trgsw_ciphertext_vec));
    }

    let mut torus_poly_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> = Vec::new();

    // TODO: Later, will change to branching using parameters instead of magic numbers
    if poly_param.polynomial_length == 65536 {
        for trgsw_ciphertext_vec in transposed_trgsw_ciphertext_vec.iter() {
            let num = gadget_decomposed_trlwe_ciphertext_vec
                .inner_product_ntt(trgsw_ciphertext_vec, poly_param);
            torus_poly_vec.push(num);
        }
    } else {
        for trgsw_ciphertext_vec in transposed_trgsw_ciphertext_vec.iter() {
            let num = gadget_decomposed_trlwe_ciphertext_vec
                .inner_product(trgsw_ciphertext_vec, poly_param);
            torus_poly_vec.push(num);
        }
    }

    TorusPolynomialVec::new(torus_poly_vec)
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
    };

    #[test]
    fn test_external_product() {
        for _ in 0..100 {
            let trlwe_seckey_value: Range<u8> = 0u8..2u8;
            let encryption_sample_num: usize = 1;
            let trlwe_stddev: f32 = 0.0;
            let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
                polynomial_length: 4,
                log_polynomial_length: 2,
                prime_modulus: BigUint::from(1),
                ntt_prime_psi: BigUint::from(1),
                inverse_ntt_prime_psi: BigUint::from(1),
                ntt_prime_omega: BigUint::from(1),
                inverse_ntt_prime_omega: BigUint::from(1),
                inverse_poly_size: BigUint::from(1),
                torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^8 = 64bit
            };
            let val: u64 = 1_u64 << 48;
            let bg: usize = 63;
            let l: usize = 1;

            let trlwe_plaintext: TorusPolynomial<TwoPowerModulusPattern> =
                TorusPolynomial::new(vec![Torus::new(val); poly_param.polynomial_length]);

            let seckey: Vec<Vec<u8>> =
                generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

            let trlwe_ciphertext: TorusPolynomialVec<TwoPowerModulusPattern> =
                trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                    &trlwe_plaintext,
                    &seckey,
                    &poly_param,
                    encryption_sample_num,
                    trlwe_stddev,
                );

            let trgsw_plaintext1: Vec<u64> = vec![0; poly_param.polynomial_length];
            let mut trgsw_plaintext2: Vec<u64> = vec![0; poly_param.polynomial_length];
            trgsw_plaintext2[0] = 1;

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

            let result1: TorusPolynomialVec<TwoPowerModulusPattern> =
                external_product::<TwoPowerModulusPattern>(
                    &trgsw_ciphertext1,
                    &trlwe_ciphertext,
                    &poly_param,
                    bg,
                    l,
                );
            let result2: TorusPolynomialVec<TwoPowerModulusPattern> =
                external_product::<TwoPowerModulusPattern>(
                    &trgsw_ciphertext2,
                    &trlwe_ciphertext,
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

    // TODO: must accelerate external_product_ntt because the execution time for
    // test_external_product_ntt_time: 68.216671333s(test total time)
    // trlwe_symmetric_encrypt_time: 3.20902575s
    // trgsw_encrypt_time: 11.151605792s(one time)
    // external_product_time: 20.370664375s(one time)
    // trlwe_decrypt_time: 1.191466875s
    #[cfg(feature = "ntt_test")]
    #[test]
    fn test_external_product_ntt() {
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
        let val: u64 = 1_u64 << 48;
        let bg: usize = 63;
        let l: usize = 1;

        let trlwe_plaintext: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(val); poly_param.polynomial_length]);

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let trlwe_ciphertext: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &trlwe_plaintext,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );

        let trgsw_plaintext1: Vec<u64> = vec![0; poly_param.polynomial_length];
        let mut trgsw_plaintext2: Vec<u64> = vec![0; poly_param.polynomial_length];
        trgsw_plaintext2[0] = 1;

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

        let result1: TorusPolynomialVec<TwoPowerModulusPattern> =
            external_product::<TwoPowerModulusPattern>(
                &trgsw_ciphertext1,
                &trlwe_ciphertext,
                &poly_param,
                bg,
                l,
            );

        let result2: TorusPolynomialVec<TwoPowerModulusPattern> =
            external_product::<TwoPowerModulusPattern>(
                &trgsw_ciphertext2,
                &trlwe_ciphertext,
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
