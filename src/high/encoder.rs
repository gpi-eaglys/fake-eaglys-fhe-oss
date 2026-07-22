// Note this function is duplicated by public_key.encode, and secret_key.decode will be deleted
use crate::{
    high::{parameter::Parameter, plaintext::Plaintext},
    low::{
        encoder::tlwe_encoder::{tlwe_decode, tlwe_encode},
        torus::TorusParam,
    },
};

pub struct Encoder {
    // original field
    message_value_range: (f32, f32),

    // copied filed from Parameter
    torus_param: TorusParam,
    computational_accuracy_bit: usize,
}

impl Encoder {
    pub fn new(parameter: &Parameter) -> Self {
        Self::new_with_extra_args(parameter, None)
    }

    pub fn new_with_extra_args(
        parameter: &Parameter,
        message_value_range: Option<(f32, f32)>,
    ) -> Self {
        let message_value_range =
            message_value_range.unwrap_or(parameter.default_message_value_range);
        Self {
            message_value_range,
            torus_param: parameter.torus_param,
            computational_accuracy_bit: parameter.computational_accuracy_bit,
        }
    }

    pub fn encode(&self, cleartext: f32) -> Plaintext {
        // TODO: must check cleartext range specify message_value_range
        tlwe_encode(
            cleartext,
            &self.torus_param,
            self.computational_accuracy_bit,
            self.message_value_range,
        )
    }

    pub fn decode(&self, plaintext: Plaintext) -> f32 {
        tlwe_decode(
            &plaintext,
            &self.torus_param,
            self.computational_accuracy_bit,
            self.message_value_range,
        )
    }
}

#[cfg(test)]
mod tests {
    use approx::assert_relative_eq;

    use crate::high::{
        encoder::Encoder,
        parameter::{Parameter, preset_for_test},
    };

    #[test]
    fn test_new() {
        Encoder::new(&Parameter::from_preset(preset_for_test()));
    }

    #[test]
    fn test_new_with_extra_args() {
        Encoder::new_with_extra_args(&Parameter::from_preset(preset_for_test()), None);
        Encoder::new_with_extra_args(
            &Parameter::from_preset(preset_for_test()),
            Some((-1.0, 1.0)),
        );
    }

    #[test]
    fn test_encode() {
        let cleartext: f32 = 0.0;
        let encoder = Encoder::new(&Parameter::from_preset(preset_for_test()));
        encoder.encode(cleartext);
    }

    #[test]
    fn test_decode() {
        let cleartext: f32 = 1.0;
        let encoder = Encoder::new(&Parameter::from_preset(preset_for_test()));
        let plaintext = encoder.encode(cleartext);
        let decoded_plaintext = encoder.decode(plaintext);
        assert_relative_eq!(cleartext, decoded_plaintext, epsilon = 1e-1);
    }
}
