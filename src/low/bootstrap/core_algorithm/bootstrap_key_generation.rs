use crate::low::{
    encryption::trgsw_encryption::trgsw_encrypt,
    modulus::{ModulusPattern, TwoPowerModulusPattern},
    torus_polynomial::{TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat},
};

pub fn generate_bootstrap_key<M: ModulusPattern>(
    tlwe_seckey: &[u8],
    trlwe_seckey: &[Vec<u8>],
    poly_param: &TorusPolynomialParameter,
    encryption_sample_num: usize,
    trlwe_stddev: f32,
    bg: usize, // TODO: reconsider parameter name
    l: usize,  // TODO: reconsider parameter name
) -> Vec<TorusPolynomialMat<TwoPowerModulusPattern>> {
    let mut bootstrap_key: Vec<TorusPolynomialMat<TwoPowerModulusPattern>> =
        Vec::with_capacity(tlwe_seckey.len());

    for &tlwe_seckey_num in tlwe_seckey.iter() {
        let mut trgsw_plaintext: Vec<u64> = vec![0; poly_param.polynomial_length];
        trgsw_plaintext[0] = tlwe_seckey_num as u64;

        bootstrap_key.push(trgsw_encrypt::<TwoPowerModulusPattern>(
            &trgsw_plaintext,
            trlwe_seckey,
            poly_param,
            encryption_sample_num,
            trlwe_stddev,
            bg, // TODO: reconsider parameter name
            l,  // TODO: reconsider parameter name
        ));
    }

    bootstrap_key
}
