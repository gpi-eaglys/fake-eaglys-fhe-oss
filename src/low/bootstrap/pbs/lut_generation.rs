use crate::low::{
    bootstrap::pbs::lut_function::{div_square_function, identity_function, relu_function},
    encoder::tlwe_encoder::{tlwe_decode, tlwe_encode},
    torus::{Torus, TorusParam},
};

pub fn generate_arithmetic_cleartext_range_sequence(
    torus_param: &TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> Vec<f32> {
    let discretized_torus_step_width: usize = 2_u32.pow(computational_accuracy_bit as u32) as usize;
    let mut arithmetic_cleartext_range_sequence: Vec<f32> =
        Vec::with_capacity(discretized_torus_step_width);

    for i in 0..discretized_torus_step_width {
        let torus_num: u64 = 2_u64
            .pow(torus_param.bitsize as u32 - computational_accuracy_bit as u32 - 1)
            * i as u64;

        arithmetic_cleartext_range_sequence.push(tlwe_decode(
            &Torus::new(torus_num),
            torus_param,
            computational_accuracy_bit,
            message_value_range,
        ));
    }

    arithmetic_cleartext_range_sequence
}

pub fn generate_identity_lut(
    lvl0_torus_param: &TorusParam,
    lvl1_torus_param: &TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> Vec<Torus> {
    let arithmetic_cleartext_range_sequence: Vec<f32> =
        generate_arithmetic_cleartext_range_sequence(
            lvl0_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
    let mut identity_lut: Vec<Torus> =
        Vec::with_capacity(arithmetic_cleartext_range_sequence.len());

    for &cleartext in arithmetic_cleartext_range_sequence.iter() {
        let ith_lvl1_identity_num = tlwe_encode(
            identity_function(cleartext),
            lvl1_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        identity_lut.push(ith_lvl1_identity_num);
    }

    identity_lut
}

pub fn generate_div_square_lut(
    lvl0_torus_param: &TorusParam,
    lvl1_torus_param: &TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> Vec<Torus> {
    let arithmetic_cleartext_range_sequence: Vec<f32> =
        generate_arithmetic_cleartext_range_sequence(
            lvl0_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
    let mut div_square_lut: Vec<Torus> =
        Vec::with_capacity(arithmetic_cleartext_range_sequence.len());

    for &cleartext in arithmetic_cleartext_range_sequence.iter() {
        let ith_lvl1_div_square_num = tlwe_encode(
            div_square_function(cleartext, 4.0, message_value_range),
            lvl1_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        div_square_lut.push(ith_lvl1_div_square_num);
    }

    div_square_lut
}

pub fn generate_relu_lut(
    lvl0_torus_param: &TorusParam,
    lvl1_torus_param: &TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> Vec<Torus> {
    let arithmetic_cleartext_range_sequence: Vec<f32> =
        generate_arithmetic_cleartext_range_sequence(
            lvl0_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
    let mut identity_lut: Vec<Torus> =
        Vec::with_capacity(arithmetic_cleartext_range_sequence.len());

    for &cleartext in arithmetic_cleartext_range_sequence.iter() {
        let ith_lvl1_identity_num = tlwe_encode(
            relu_function(cleartext),
            lvl1_torus_param,
            computational_accuracy_bit,
            message_value_range,
        );

        identity_lut.push(ith_lvl1_identity_num);
    }

    identity_lut
}
