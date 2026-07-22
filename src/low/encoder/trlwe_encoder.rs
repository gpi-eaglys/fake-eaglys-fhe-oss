use crate::low::{
    encoder::tlwe_encoder::{tlwe_decode, tlwe_encode},
    modulus::ModulusPattern,
    torus::Torus,
    torus_polynomial::{TorusPolynomial, TorusPolynomialParameter},
};

pub fn trlwe_encode<M: ModulusPattern>(
    cleartext: &[f32],
    poly_param: &TorusPolynomialParameter,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> TorusPolynomial<M> {
    let plaintext_coeff: Vec<Torus> = cleartext
        .iter()
        .map(|c| {
            tlwe_encode(
                *c,
                &poly_param.torus_parameter,
                computational_accuracy_bit,
                message_value_range,
            )
        })
        .collect();

    TorusPolynomial::new(plaintext_coeff)
}

pub fn trlwe_decode<M: ModulusPattern>(
    plaintext: &TorusPolynomial<M>,
    poly_param: &TorusPolynomialParameter,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> Vec<f32> {
    let cleartext: Vec<f32> = plaintext
        .coeffs
        .iter()
        .map(|p| {
            tlwe_decode(
                p,
                &poly_param.torus_parameter,
                computational_accuracy_bit,
                message_value_range,
            )
        })
        .collect();

    cleartext
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low::{biguint::BigUint, modulus::TwoPowerModulusPattern, torus::TorusParam};

    #[test]
    fn test_trlwe_encode_decode() {
        let cleartext: Vec<f32> = vec![0.0, 0.0, 0.0];
        let poly_param: TorusPolynomialParameter = TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 64 },
        };
        let computational_accuracy_bit: usize = 16;
        let message_value_range = (-10.0, 10.0);

        let plaintext: TorusPolynomial<TwoPowerModulusPattern> = trlwe_encode(
            &cleartext,
            &poly_param,
            computational_accuracy_bit,
            message_value_range,
        );

        let decoded_plaintext = trlwe_decode(
            &plaintext,
            &poly_param,
            computational_accuracy_bit,
            message_value_range,
        );

        for res in plaintext.clone().coeffs.iter() {
            assert_eq!(res.value, 0);
        }
        assert_eq!(cleartext, decoded_plaintext);
    }
}
