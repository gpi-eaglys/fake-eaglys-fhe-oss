use std::ops::Range;

use crate::low::{
    rand::secret_key_rnd_generation::generate_secret_key_rnd,
    torus_polynomial::TorusPolynomialParameter,
};

// COMMENT: this is not sensitive, so will be hosted by server-side
// generate the secret key used in LWE cryptosystem
pub fn generate_trlwe_seckey(
    tlwe_seckey_value: Range<u8>,
    encryption_sample_num: usize,
    param: &TorusPolynomialParameter,
) -> Vec<Vec<u8>> {
    #[cfg(feature = "fixed_trlwe_seckey_rnd")]
    {
        return vec![vec![0_u8; param.polynomial_length]; encryption_sample_num];
    }

    // Default: random secret key.
    let mut trlwe_secret_key: Vec<Vec<u8>> = Vec::with_capacity(encryption_sample_num);
    for _ in 0..encryption_sample_num {
        let mut ith_secret_key: Vec<u8> = Vec::with_capacity(param.polynomial_length);
        for _ in 0..param.polynomial_length {
            ith_secret_key.push(generate_secret_key_rnd(tlwe_seckey_value.clone()));
        }
        trlwe_secret_key.push(ith_secret_key);
    }
    trlwe_secret_key
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fixed_trlwe_seckey_rnd")]
    use std::ops::Range;

    #[cfg(feature = "fixed_trlwe_seckey_rnd")]
    use crate::low::{
        biguint::BigUint, secret_key::trlwe_secret_key::generate_trlwe_seckey, torus::TorusParam,
        torus_polynomial::TorusPolynomialParameter,
    };

    #[cfg(feature = "fixed_trlwe_seckey_rnd")]
    #[test]
    fn test_generate_tlwe_seckey() {
        let tlwe_seckey_value: Range<u8> = 0u8..2u8;
        let encryption_sample_num: usize = 1;
        let param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 0,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 }, // 2^8 = 64bit
        };

        let result: Vec<Vec<u8>> =
            generate_trlwe_seckey(tlwe_seckey_value, encryption_sample_num, &param);
        let mut expected: Vec<Vec<u8>> = vec![vec![0_u8; 2]];

        for (res, exp) in result.iter().zip(expected.iter()) {
            assert_eq!(res, exp);
        }
    }
}
