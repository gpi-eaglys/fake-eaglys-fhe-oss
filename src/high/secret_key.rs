use std::ops::Range;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    high::{
        ciphertext::Ciphertext,
        error::HighError,
        parameter::{Parameter, ParameterOrigin},
        plaintext::Plaintext,
    },
    low::{
        encoder::tlwe_encoder::tlwe_decode,
        encryption::tlwe_encryption::tlwe_decrypt,
        secret_key::{
            tlwe_secret_key::generate_tlwe_seckey, trlwe_secret_key::generate_trlwe_seckey,
        },
        torus::TorusParam,
        torus_polynomial::TorusPolynomialParameter,
    },
};
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    // tlwe secret key
    // original field
    pub bytes: Vec<u8>,
    pub trlwe_bytes: Vec<Vec<u8>>,
    pub key_id: Uuid,

    // copied default value from Parameter
    tlwe_seckey_value: Range<u8>,
    encryption_sample_num: usize,
    trlwe_seckey_value: Range<u8>,
    trlwe_encryption_sample_num: usize,

    // copied field from Parameter
    origin: ParameterOrigin,
    torus_param: TorusParam,
    computational_accuracy_bit: usize,
    message_value_range: (f32, f32),
    torus_polynomial_param: TorusPolynomialParameter,
}

impl SecretKey {
    pub fn new(parameter: &Parameter) -> Self {
        Self::new_with_extra_args(parameter, None, None, None, None)
    }

    pub fn new_with_extra_args(
        parameter: &Parameter,
        tlwe_seckey_value: Option<Range<u8>>,
        sample_num: Option<usize>,
        trlwe_seckey_value: Option<Range<u8>>,
        trlwe_encryption_sample_num: Option<usize>,
    ) -> Self {
        let sample_num = sample_num.unwrap_or(parameter.default_encryption_sample_num);
        let tlwe_seckey_value =
            tlwe_seckey_value.unwrap_or(parameter.default_tlwe_seckey_value.clone());
        let bytes = generate_tlwe_seckey(tlwe_seckey_value.clone(), sample_num);

        let trlwe_seckey_value =
            trlwe_seckey_value.unwrap_or(parameter.default_trlwe_seckey_value.clone());
        let trlwe_encryption_sample_num =
            trlwe_encryption_sample_num.unwrap_or(parameter.default_trlwe_encryption_sample_num);

        let trlwe_bytes = generate_trlwe_seckey(
            trlwe_seckey_value.clone(),
            trlwe_encryption_sample_num,
            &parameter.torus_polynomial_parameter,
        );

        SecretKey {
            bytes,
            trlwe_bytes,
            key_id: Uuid::new_v4(),
            tlwe_seckey_value,
            encryption_sample_num: sample_num,
            trlwe_seckey_value,
            trlwe_encryption_sample_num,
            origin: parameter.origin,
            torus_param: parameter.torus_param,
            computational_accuracy_bit: parameter.computational_accuracy_bit,
            message_value_range: parameter.default_message_value_range,
            torus_polynomial_param: parameter.torus_polynomial_parameter.clone(),
        }
    }

    pub fn from_raw(
        bytes: Vec<u8>,
        trlwe_bytes: Vec<Vec<u8>>,
        key_id: Uuid,
        tlwe_seckey_value: Range<u8>,
        encryption_sample_num: usize,
        trlwe_seckey_value: Range<u8>,
        trlwe_encryption_sample_num: usize,
        torus_param: TorusParam,
        computational_accuracy_bit: usize,
        message_value_range: (f32, f32),
        torus_polynomial_param: TorusPolynomialParameter,
    ) -> Self {
        SecretKey {
            bytes,
            trlwe_bytes,
            key_id,
            tlwe_seckey_value,
            encryption_sample_num,
            trlwe_seckey_value,
            trlwe_encryption_sample_num,
            origin: ParameterOrigin::Custom,
            torus_param,
            computational_accuracy_bit,
            message_value_range,
            torus_polynomial_param,
        }
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Plaintext, HighError> {
        if ciphertext.key_id != self.key_id {
            return Err(HighError::KeyIdMismatch);
        }

        Ok(tlwe_decrypt(
            &ciphertext.vector_torus,
            &self.bytes,
            &self.torus_param,
        ))
    }

    pub fn decode(&self, plaintext: &Plaintext) -> f32 {
        tlwe_decode(
            plaintext,
            &self.torus_param,
            self.computational_accuracy_bit,
            self.message_value_range,
        )
    }

    pub fn decode_decrypt(&self, ciphertext: &Ciphertext) -> Result<f32, HighError> {
        let plaintext: Plaintext = self.decrypt(ciphertext)?;
        Ok(self.decode(&plaintext))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use approx::assert_relative_eq;
    use serde_json;

    use super::*;
    use crate::{
        high::{parameter::preset_for_test, public_key::PublicKey},
        low::{biguint::BigUint, torus::Torus},
    };

    fn sample_torus_polynomial_param() -> TorusPolynomialParameter {
        TorusPolynomialParameter {
            polynomial_length: 2,
            log_polynomial_length: 1,
            prime_modulus: BigUint::from(0),
            ntt_prime_psi: BigUint::from(0),
            inverse_ntt_prime_psi: BigUint::from(0),
            ntt_prime_omega: BigUint::from(0),
            inverse_ntt_prime_omega: BigUint::from(0),
            inverse_poly_size: BigUint::from(0),
            torus_parameter: TorusParam { bitsize: 1 },
        }
    }

    #[test]
    fn test_new() {
        SecretKey::new(&Parameter::from_preset(preset_for_test()));
    }

    #[test]
    fn test_new_with_extra_args() {
        let sk = SecretKey::new_with_extra_args(
            &Parameter::from_preset(preset_for_test()),
            Some(0u8..2u8),
            Some(16),
            Some(0u8..1u8),
            Some(1),
        );

        assert_eq!(sk.tlwe_seckey_value.start, 0);
        assert_eq!(sk.tlwe_seckey_value.end, 2);
        assert_eq!(sk.encryption_sample_num, 16);
        assert_eq!(sk.trlwe_seckey_value.start, 0);
        assert_eq!(sk.trlwe_seckey_value.end, 1);
        assert_eq!(sk.trlwe_encryption_sample_num, 1);
        assert_eq!(sk.trlwe_bytes.len(), 1);

        SecretKey::new_with_extra_args(
            &Parameter::from_preset(preset_for_test()),
            None,
            None,
            None,
            None,
        );
    }

    #[test]
    fn test_from_raw() {
        let bytes = vec![0u8; 16];
        let key_id = Uuid::new_v4();
        let tlwe_seckey_value = 0u8..10u8;
        let torus_param: TorusParam = TorusParam { bitsize: 6 };
        let computational_accuracy_bit = 32;
        let message_value_range = (-1.0, 1.0);
        let encryption_sample_num = 16;
        let trlwe_bytes = vec![vec![1u8, 0u8]];
        let trlwe_seckey_value = 0u8..2u8;
        let trlwe_encryption_sample_num = 1;
        let torus_polynomial_param = sample_torus_polynomial_param();
        let sk = SecretKey::from_raw(
            bytes.clone(),
            trlwe_bytes.clone(),
            key_id,
            tlwe_seckey_value.clone(),
            encryption_sample_num,
            trlwe_seckey_value.clone(),
            trlwe_encryption_sample_num,
            torus_param,
            computational_accuracy_bit,
            message_value_range,
            torus_polynomial_param.clone(),
        );

        assert_eq!(sk.tlwe_seckey_value.start, tlwe_seckey_value.start);
        assert_eq!(sk.tlwe_seckey_value.end, tlwe_seckey_value.end);
        assert_eq!(sk.encryption_sample_num, encryption_sample_num);
        assert_eq!(sk.trlwe_seckey_value.start, trlwe_seckey_value.start);
        assert_eq!(sk.trlwe_seckey_value.end, trlwe_seckey_value.end);
        assert_eq!(sk.trlwe_encryption_sample_num, trlwe_encryption_sample_num);
        assert_eq!(sk.trlwe_bytes.len(), trlwe_bytes.len());
        assert_eq!(sk.trlwe_bytes[0].len(), trlwe_bytes[0].len());
        assert_eq!(sk.key_id, key_id);
        assert_eq!(sk.computational_accuracy_bit, computational_accuracy_bit);
        assert_eq!(sk.message_value_range, message_value_range);
        assert_eq!(
            format!("{:?}", sk.torus_polynomial_param),
            format!("{:?}", torus_polynomial_param)
        );
    }

    #[test]
    fn test_decrypt() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let plaintext: Torus = Torus::new(10);
        let ciphertext: Ciphertext = pk.encrypt(&plaintext, BTreeMap::new(), None);

        let result = sk.decrypt(&ciphertext).expect("decrypt failed");

        let expected: u64 = 10;

        assert_eq!(result.value, expected);
    }

    #[test]
    fn test_decode() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let cleartext: f32 = 0.5;
        let plaintext: Plaintext = pk.encode(cleartext);

        let result = sk.decode(&plaintext);

        assert_relative_eq!(result, cleartext, epsilon = 1e-1);
    }

    #[test]
    fn test_decode_decrypt() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let cleartext: f32 = 0.5;

        let ciphertext = pk.encode_encrypt(cleartext, BTreeMap::new(), None);

        let decoded = sk
            .decode_decrypt(&ciphertext)
            .expect("decode_decrypt failed");

        assert_relative_eq!(cleartext, decoded, epsilon = 1e-1);
    }

    #[test]
    fn test_serialize_deserialize_json() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);

        // Serialize to JSON
        let serialized = serde_json::to_string(&sk).expect("Failed to serialize SecretKey");
        // Deserialize back
        let deserialized: SecretKey =
            serde_json::from_str(&serialized).expect("Failed to deserialize SecretKey");

        assert_eq!(
            deserialized.tlwe_seckey_value.start,
            sk.tlwe_seckey_value.start
        );
        assert_eq!(deserialized.tlwe_seckey_value.end, sk.tlwe_seckey_value.end);
        assert_eq!(deserialized.encryption_sample_num, sk.encryption_sample_num);
        assert_eq!(
            deserialized.trlwe_seckey_value.start,
            sk.trlwe_seckey_value.start
        );
        assert_eq!(
            deserialized.trlwe_seckey_value.end,
            sk.trlwe_seckey_value.end
        );
        assert_eq!(
            deserialized.trlwe_encryption_sample_num,
            sk.trlwe_encryption_sample_num
        );
        assert_eq!(
            deserialized.computational_accuracy_bit,
            sk.computational_accuracy_bit
        );
        assert_eq!(deserialized.message_value_range, sk.message_value_range);
        assert_eq!(
            format!("{:?}", deserialized.torus_polynomial_param),
            format!("{:?}", sk.torus_polynomial_param)
        );
        assert_eq!(deserialized.trlwe_bytes.len(), sk.trlwe_bytes.len());
        assert_eq!(deserialized.key_id, sk.key_id);
    }
}
