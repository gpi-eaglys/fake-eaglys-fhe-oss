use crate::low::{
    bootstrap::core_algorithm::{
        blind_rotation::blind_rotation, key_switch::public_key_switch,
        sample_extraction::sample_extraction_to_ctxt,
    },
    modulus::TwoPowerModulusPattern,
    torus::{Torus, TorusParam},
    torus_polynomial::{
        TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat,
        torus_polynomial_vec::TorusPolynomialVec,
    },
};

pub fn general_pbs(
    tlwe_ciphertext: &[Torus],
    bootstrap_key: &[TorusPolynomialMat<TwoPowerModulusPattern>],
    lut: &[Torus],
    torus_param: &TorusParam,
    poly_param: &TorusPolynomialParameter,
    computational_accuracy_bit: usize,
    bg: usize,
    l: usize,
    ksk_precision: usize,
    key_switch_key: &[Vec<Vec<Torus>>],
) -> Vec<Torus> {
    let accumulator: TorusPolynomialVec<TwoPowerModulusPattern> =
        blind_rotation::<TwoPowerModulusPattern>(
            tlwe_ciphertext,
            bootstrap_key,
            lut,
            torus_param,
            poly_param,
            computational_accuracy_bit,
            bg,
            l,
        );

    let extracted_tlwe_ciphertext: Vec<Torus> = sample_extraction_to_ctxt(&accumulator, poly_param);

    let key_switched_tlwe_ciphertext: Vec<Torus> = public_key_switch(
        &extracted_tlwe_ciphertext,
        &poly_param.torus_parameter,
        torus_param,
        ksk_precision,
        key_switch_key,
    );

    key_switched_tlwe_ciphertext
}
