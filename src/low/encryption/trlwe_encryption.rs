use crate::low::{
    module::Module,
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    rand::{noise_generation::generate_noise, torus_rnd_generation::generate_torus_rnd},
    torus::Torus,
    torus_polynomial::{
        TorusPolynomial, TorusPolynomialParameter, torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn trlwe_symmetric_encrypt<M: ModulusPattern>(
    plaintext: &TorusPolynomial<TwoPowerModulusPattern>,
    seckey: &[Vec<u8>],
    poly_param: &TorusPolynomialParameter,
    encryption_sample_num: usize,
    trlwe_stddev: f32,
) -> TorusPolynomialVec<TwoPowerModulusPattern> {
    // generate lwe_sample randomly
    // lwe_sample (1-dim) size is (lwe_encryption_sample_num)
    let mut rlwe_sample: Vec<TorusPolynomial<TwoPowerModulusPattern>> =
        Vec::with_capacity(encryption_sample_num);

    for _ in 0..encryption_sample_num {
        let mut kth_rlwe_sample: Vec<Torus> = Vec::with_capacity(poly_param.polynomial_length);
        for _ in 0..poly_param.polynomial_length {
            kth_rlwe_sample.push(generate_torus_rnd(&poly_param.torus_parameter));
        }
        rlwe_sample.push(TorusPolynomial::new(kth_rlwe_sample));
    }

    let mut noise_vec: Vec<Torus> = Vec::with_capacity(poly_param.polynomial_length);
    for _ in 0..poly_param.polynomial_length {
        noise_vec.push(generate_noise(&poly_param.torus_parameter, trlwe_stddev));
    }

    let noise: TorusPolynomial<TwoPowerModulusPattern> = TorusPolynomial::new(noise_vec);

    // compute the inner product <seckey, rlwe_sample>
    let rlwe_sample_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
        TorusPolynomialVec::new(rlwe_sample.clone());
    let mut seckey_poly_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> =
        Vec::with_capacity(seckey.len());
    for seckey_row in seckey.iter() {
        let mut ith_seckey_poly: Vec<Torus> = Vec::with_capacity(seckey_row.len());
        for &seckey_bit in seckey_row.iter() {
            ith_seckey_poly.push(Torus::new(seckey_bit as u64));
        }
        seckey_poly_vec.push(TorusPolynomial::new(ith_seckey_poly));
    }

    // TODO: Later, will change to branching using parameters instead of magic numbers
    let mut kth_ciphertext: TorusPolynomial<TwoPowerModulusPattern> =
        if poly_param.polynomial_length == 65536 {
            rlwe_sample_vec.inner_product_ntt(&TorusPolynomialVec::new(seckey_poly_vec), poly_param)
        } else {
            rlwe_sample_vec.inner_product(&TorusPolynomialVec::new(seckey_poly_vec), poly_param)
        };

    // compute <seckey, rlwe_sample> + plaintext + e
    kth_ciphertext = kth_ciphertext.add(plaintext, poly_param);
    kth_ciphertext = kth_ciphertext.add(&noise, poly_param);

    rlwe_sample.push(kth_ciphertext);
    let ciphertext: TorusPolynomialVec<TwoPowerModulusPattern> =
        TorusPolynomialVec::new(rlwe_sample);

    ciphertext
}

pub fn trlwe_decrypt<M: ModulusPattern>(
    ciphertext: &TorusPolynomialVec<TwoPowerModulusPattern>,
    seckey: &[Vec<u8>],
    poly_param: &TorusPolynomialParameter,
) -> TorusPolynomial<TwoPowerModulusPattern> {
    let encryption_sample_num: usize = seckey.len();
    let mut decrypted_ciphertext: TorusPolynomial<TwoPowerModulusPattern> =
        ciphertext.poly[encryption_sample_num].clone();

    // compute the phase
    // phase = ciphertext - <seckey, lwe_sample>
    let rlwe_sample_vec: TorusPolynomialVec<TwoPowerModulusPattern> =
        TorusPolynomialVec::new(ciphertext.poly[..seckey.len()].to_vec().clone());
    let mut seckey_poly_vec: Vec<TorusPolynomial<TwoPowerModulusPattern>> =
        Vec::with_capacity(seckey.len());
    for seckey_row in seckey.iter() {
        let mut ith_seckey_poly: Vec<Torus> = Vec::with_capacity(seckey_row.len());
        for &seckey_bit in seckey_row.iter() {
            ith_seckey_poly.push(Torus::new(seckey_bit as u64));
        }
        seckey_poly_vec.push(TorusPolynomial::new(ith_seckey_poly));
    }

    // TODO: Later, will change to branching using parameters instead of magic numbers
    let kth_ciphertext: TorusPolynomial<TwoPowerModulusPattern> =
        if poly_param.polynomial_length == 65536 {
            rlwe_sample_vec.inner_product_ntt(&TorusPolynomialVec::new(seckey_poly_vec), poly_param)
        } else {
            rlwe_sample_vec.inner_product(&TorusPolynomialVec::new(seckey_poly_vec), poly_param)
        };

    decrypted_ciphertext = decrypted_ciphertext.sub(&kth_ciphertext, poly_param);

    decrypted_ciphertext
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::low::{
        biguint::BigUint, modulus::TwoPowerModulusPattern,
        secret_key::trlwe_secret_key::generate_trlwe_seckey, torus::TorusParam,
    };

    #[cfg(feature = "fixed_torus_rnd")]
    #[test]
    fn test_encrypt() {
        let plaintext: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(10); 2]);
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

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let result: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &plaintext,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );

        for k in 0..result.poly.len() {
            if k < result.poly.len() - 1 {
                for i in 0..result.poly[k].coeffs.len() {
                    assert_eq!(result.poly[k].coeffs[i].value, 0);
                }
            } else {
                for i in 0..result.poly[k].coeffs.len() {
                    assert_eq!(result.poly[k].coeffs[i].value, 10);
                }
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(10); 2]);
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

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let ciphertext: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &plaintext,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );
        let decrypted_ciphertext: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&ciphertext, &seckey, &poly_param);

        for i in 0..poly_param.polynomial_length {
            assert_eq!(decrypted_ciphertext.coeffs[i].value, 10);
        }
    }

    #[test]
    fn test_encrypt_decrypt_ntt() {
        let plaintext: TorusPolynomial<TwoPowerModulusPattern> =
            TorusPolynomial::new(vec![Torus::new(10); 65536]);
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

        let seckey: Vec<Vec<u8>> =
            generate_trlwe_seckey(trlwe_seckey_value, encryption_sample_num, &poly_param);

        let ciphertext: TorusPolynomialVec<TwoPowerModulusPattern> =
            trlwe_symmetric_encrypt::<TwoPowerModulusPattern>(
                &plaintext,
                &seckey,
                &poly_param,
                encryption_sample_num,
                trlwe_stddev,
            );
        let decrypted_ciphertext: TorusPolynomial<TwoPowerModulusPattern> =
            trlwe_decrypt::<TwoPowerModulusPattern>(&ciphertext, &seckey, &poly_param);

        for i in 0..poly_param.polynomial_length {
            assert_eq!(decrypted_ciphertext.coeffs[i].value, 10);
        }
    }
}
