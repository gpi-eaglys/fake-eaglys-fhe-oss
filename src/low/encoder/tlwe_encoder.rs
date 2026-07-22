use crate::low::torus::{Torus, TorusParam};

pub fn tlwe_encode(
    cleartext: f32,
    torus_param: &TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> Torus {
    // TODO: message value range should follow message_value_range.0 < message_value_range.1,
    // consider to make specific type or, validate it in somewhere
    let cleartext_range: f32 = message_value_range.1 - message_value_range.0;

    let phase_shifted_cleartext: f32 = if cleartext > 0.0 {
        cleartext - message_value_range.1
    } else {
        cleartext + message_value_range.1
    };

    let torus_num: f32 = (phase_shifted_cleartext + message_value_range.1) / cleartext_range;

    let point_in_discretized_torus: f32 =
        torus_num * (2_u64.pow(computational_accuracy_bit as u32) as f32);

    let mut index_in_discretized_torus: u64 = point_in_discretized_torus.round() as u64;
    if index_in_discretized_torus == 2_u64.pow(computational_accuracy_bit as u32) {
        index_in_discretized_torus = 0;
    }

    let plaintext: u64 =
        index_in_discretized_torus << (torus_param.bitsize - computational_accuracy_bit - 1);

    Torus::new(plaintext)
}

pub fn tlwe_decode(
    plaintext: &Torus,
    torus_param: &TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
) -> f32 {
    // TODO: message value range should follow message_value_range.0 < message_value_range.1,
    // consider to make specific type or, validate it in somewhere
    let cleartext_range: f32 = message_value_range.1 - message_value_range.0;

    // TODO: Change `to_u64` to `to_u32` depending on the size of the torus
    let index_in_discretized_torus: u64 =
        plaintext.value / 2_u64.pow((torus_param.bitsize - computational_accuracy_bit - 1) as u32);

    let torus_num: f32 =
        (index_in_discretized_torus as f32) / (2_u64.pow(computational_accuracy_bit as u32) as f32);

    let mut cleartext: f32 = torus_num * cleartext_range - message_value_range.1;

    if cleartext > 0.0 {
        cleartext -= message_value_range.1
    } else {
        cleartext += message_value_range.1
    };

    cleartext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlwe_encode_decode() {
        let cleartext: f32 = 0.0;
        let torus_param = TorusParam { bitsize: 64 };
        let computational_accuracy_bit: usize = 16;
        let message_value_range = (-10.0, 10.0);

        let plaintext: Torus = tlwe_encode(
            cleartext,
            &torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
        assert_eq!(plaintext.value, 0);

        let decoded_plaintext: f32 = tlwe_decode(
            &plaintext,
            &torus_param,
            computational_accuracy_bit,
            message_value_range,
        );
        assert_eq!(cleartext, decoded_plaintext);
    }
}
