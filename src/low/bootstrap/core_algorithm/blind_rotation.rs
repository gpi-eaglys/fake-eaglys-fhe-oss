use crate::low::{
    ciphertext_operation::cmux::cmux,
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    torus::{Torus, TorusParam},
    torus_polynomial::{
        TorusPolynomial, TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat,
        torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn blind_rotation<M: ModulusPattern>(
    tlwe_ciphertext: &[Torus],
    bootstrap_key: &[TorusPolynomialMat<TwoPowerModulusPattern>],
    lut: &[Torus],
    torus_param: &TorusParam,
    poly_param: &TorusPolynomialParameter,
    computational_accuracy_bit: usize,
    bg: usize,
    l: usize,
) -> TorusPolynomialVec<TwoPowerModulusPattern> {
    let rescaled_tlwe_ciphertext: Vec<Torus> =
        rescale_tlwe_ciphertext(tlwe_ciphertext, torus_param, computational_accuracy_bit);

    let mut accumulator: TorusPolynomialVec<TwoPowerModulusPattern> =
        generate_accumulator::<TwoPowerModulusPattern>(lut, poly_param.clone());

    accumulator = accumulator.rotate_left(
        (rescaled_tlwe_ciphertext[rescaled_tlwe_ciphertext.len() - 1]
            .clone()
            .value)
            .try_into()
            .unwrap(),
        poly_param,
    );

    for i in 0..(rescaled_tlwe_ciphertext.len() - 1) {
        let ith_rotated_accumulator: TorusPolynomialVec<TwoPowerModulusPattern> = accumulator
            .rotate_right(
                (rescaled_tlwe_ciphertext[i].clone().value)
                    .try_into()
                    .unwrap(),
                poly_param,
            );

        accumulator = cmux::<TwoPowerModulusPattern>(
            &bootstrap_key[i],
            &accumulator,
            &ith_rotated_accumulator,
            poly_param,
            bg,
            l,
        );
    }

    accumulator
}

pub fn rescale_tlwe_ciphertext(
    tlwe_ciphertext: &[Torus],
    torus_param: &TorusParam,
    computational_accuracy_bit: usize,
) -> Vec<Torus> {
    let mut rescaled_tlwe_ciphertext: Vec<Torus> = Vec::with_capacity(tlwe_ciphertext.len());

    let noise_bit: usize = torus_param.bitsize - computational_accuracy_bit - 1;

    for torus in tlwe_ciphertext.iter() {
        let val: u64 = 1 << (noise_bit);
        let half_val: u64 = 1 << (noise_bit - 1);
        rescaled_tlwe_ciphertext.push(Torus::new(
            u64::try_from((u128::from(torus.value) + u128::from(half_val)) / u128::from(val))
                .expect("rescaled TLWE coefficient must fit into u64"),
        ));
    }

    rescaled_tlwe_ciphertext
}

pub fn generate_accumulator<M: ModulusPattern>(
    lut: &[Torus],
    poly_param: TorusPolynomialParameter,
) -> TorusPolynomialVec<TwoPowerModulusPattern> {
    let initial_accumulator: Vec<Torus> = vec![Torus::new(0); poly_param.polynomial_length];

    let accumulator_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> = vec![
        TorusPolynomial::new(initial_accumulator.clone()),
        TorusPolynomial::new(lut.to_vec()),
    ];

    TorusPolynomialVec::new(accumulator_vec.clone())
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::low::{
        biguint::BigUint,
        bootstrap::{
            core_algorithm::{
                blind_rotation::blind_rotation, bootstrap_key_generation::generate_bootstrap_key,
            },
            pbs::lut_generation::generate_identity_lut,
        },
        encoder::{
            tlwe_encoder::{tlwe_decode, tlwe_encode},
            trlwe_encoder::trlwe_decode,
        },
        encryption::{tlwe_encryption::tlwe_public_encrypt, trlwe_encryption::trlwe_decrypt},
        modulus::TwoPowerModulusPattern,
        public_key::tlwe_public_key::generate_tlwe_public_key,
        secret_key::{
            tlwe_secret_key::generate_tlwe_seckey, trlwe_secret_key::generate_trlwe_seckey,
        },
        torus::{Torus, TorusParam},
        torus_polynomial::TorusPolynomial,
    };

    fn relative_equal(a: f32, b: f32, message_value_range: (f32, f32)) -> bool {
        let threas_hold: f32 = 1.0;
        if (a - b).abs() < threas_hold
            || (a - b).abs() > (message_value_range.1 - message_value_range.0) - threas_hold
        {
            true
        } else {
            println!("a: {:?}", a);
            println!("b: {:?}", b);
            false
        }
    }

    #[test]
    fn test_blind_rotation() {
        let computational_accuracy_bit: usize = 10;
        let message_value_range = (-10.0, 10.0);
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let tlwe_encryption_sample_num: usize = 3;
        let tlwe_stddev: f32 = 0.0;
        let tlwe_public_key_size: usize = 100;
        let tlwe_chosen_ctxt_from_public_key: usize = 5;
        let torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };

        let trlwe_seckey_value: Range<u8> = 0u8..2u8;
        let trlwe_encryption_sample_num: usize = 1;
        let trlwe_stddev: f32 = 0.0;
        let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 1024,
            log_polynomial_length: 10,
            prime_modulus: BigUint::from(1),
            ntt_prime_psi: BigUint::from(1),
            inverse_ntt_prime_psi: BigUint::from(1),
            ntt_prime_omega: BigUint::from(1),
            inverse_ntt_prime_omega: BigUint::from(1),
            inverse_poly_size: BigUint::from(1),
            torus_parameter: TorusParam { bitsize: 1 << 6 }, // 2^8 = 64bit
        };

        let bg: usize = 15;
        let l: usize = 4;

        let identity_lut: Vec<Torus> = generate_identity_lut(
            &torus_param,
            &poly_param.torus_parameter,
            computational_accuracy_bit,
            message_value_range,
        );

        let tlwe_seckey: Vec<u8> =
            generate_tlwe_seckey(tlwe_seckey_value, tlwe_encryption_sample_num);
        let tlwe_pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &tlwe_seckey,
            &torus_param,
            tlwe_encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        let trlwe_seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, trlwe_encryption_sample_num, &poly_param);

        let bootstrap_key: Vec<TorusPolynomialMat<TwoPowerModulusPattern>> =
            generate_bootstrap_key::<TwoPowerModulusPattern>(
                &tlwe_seckey,
                &trlwe_seckey,
                &poly_param,
                trlwe_encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );

        let tlwe_cleartext: f32 = 3.0;
        let tlwe_plaintext: Torus = tlwe_encode(
            tlwe_cleartext,
            &torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
        let tlwe_ciphertext: Vec<Torus> = tlwe_public_encrypt(
            &tlwe_plaintext,
            &tlwe_pubkey,
            &torus_param,
            tlwe_chosen_ctxt_from_public_key,
        );

        let result: TorusPolynomialVec<TwoPowerModulusPattern> =
            blind_rotation::<TwoPowerModulusPattern>(
                &tlwe_ciphertext,
                &bootstrap_key,
                &identity_lut,
                &torus_param,
                &poly_param,
                computational_accuracy_bit,
                bg,
                l,
            );

        let decrypted_result: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&result, &trlwe_seckey, &poly_param);

        let decoded_decrypted_result: f32 = trlwe_decode(
            &decrypted_result,
            &poly_param,
            computational_accuracy_bit,
            message_value_range,
        )[0];

        let expected: f32 = tlwe_decode(
            &tlwe_plaintext,
            &torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        assert!(relative_equal(
            decoded_decrypted_result,
            expected,
            message_value_range
        ));
    }

    #[cfg(feature = "ntt_test")]
    #[test]
    fn test_blind_rotation_ntt() {
        let computational_accuracy_bit: usize = 16;
        let message_value_range = (-10.0, 10.0);
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let tlwe_encryption_sample_num: usize = 3;
        let tlwe_stddev: f32 = 0.0;
        let tlwe_public_key_size: usize = 100;
        let tlwe_chosen_ctxt_from_public_key: usize = 5;
        let torus_param: TorusParam = TorusParam { bitsize: 1 << 6 };

        let trlwe_seckey_value: Range<u8> = 0u8..2u8;
        let trlwe_encryption_sample_num: usize = 1;
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

        let bg: usize = 16;
        let l: usize = 4;

        let identity_lut: Vec<Torus> = generate_identity_lut(
            &torus_param,
            &poly_param.torus_parameter,
            computational_accuracy_bit,
            message_value_range,
        );

        let tlwe_seckey: Vec<u8> =
            generate_tlwe_seckey(tlwe_seckey_value, tlwe_encryption_sample_num);
        let tlwe_pubkey: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &tlwe_seckey,
            &torus_param,
            tlwe_encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        let trlwe_seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, trlwe_encryption_sample_num, &poly_param);

        let bootstrap_key: Vec<TorusPolynomialMat<TwoPowerModulusPattern>> =
            generate_bootstrap_key::<TwoPowerModulusPattern>(
                &tlwe_seckey,
                &trlwe_seckey,
                &poly_param,
                trlwe_encryption_sample_num,
                trlwe_stddev,
                bg,
                l,
            );

        let tlwe_cleartext: f32 = 3.0;
        let tlwe_plaintext: Torus = tlwe_encode(
            tlwe_cleartext,
            &torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
        let tlwe_ciphertext: Vec<Torus> = tlwe_public_encrypt(
            &tlwe_plaintext,
            &tlwe_pubkey,
            &torus_param,
            tlwe_chosen_ctxt_from_public_key,
        );

        let result: TorusPolynomialVec<TwoPowerModulusPattern> =
            blind_rotation::<TwoPowerModulusPattern>(
                &tlwe_ciphertext,
                &bootstrap_key,
                &identity_lut,
                &torus_param,
                &poly_param,
                computational_accuracy_bit,
                bg,
                l,
            );

        let decrypted_result: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&result, &trlwe_seckey, &poly_param);

        let decoded_decrypted_result: f32 = trlwe_decode(
            &decrypted_result,
            &poly_param,
            computational_accuracy_bit,
            message_value_range,
        )[0];

        let expected: f32 = tlwe_decode(
            &tlwe_plaintext,
            &torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        assert!(relative_equal(
            decoded_decrypted_result,
            expected,
            message_value_range
        ));
    }
}
