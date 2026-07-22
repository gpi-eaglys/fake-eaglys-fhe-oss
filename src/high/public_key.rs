use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    high::{
        ciphertext::{Ciphertext, OperationSide, OperationType},
        parameter::{Parameter, ParameterOrigin},
        plaintext::Plaintext,
        secret_key::SecretKey,
    },
    low::{
        encoder::tlwe_encoder::tlwe_encode,
        encryption::tlwe_encryption::tlwe_public_encrypt,
        public_key::tlwe_public_key::generate_tlwe_public_key,
        torus::{Torus, TorusParam},
    },
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    // original field
    pub ciphertexts: Vec<Vec<Torus>>,
    tlwe_stddev: f32,
    tlwe_public_key_size: usize,

    // copied field from SecretKey
    pub key_id: Uuid,

    // copied field from Parameter
    origin: ParameterOrigin,
    pub torus_param: TorusParam,
    computational_accuracy_bit: usize,
    encryption_sample_num: usize,
    pub message_value_range: (f32, f32),
    pub default_tlwe_chosen_ctxt_from_public_key: usize,
}

impl PublicKey {
    pub fn new(parameter: &Parameter, sk: &SecretKey) -> Self {
        Self::new_with_extra_args(parameter, sk, None, None)
    }

    pub fn new_with_extra_args(
        parameter: &Parameter,
        sk: &SecretKey,
        tlwe_stddev: Option<f32>,
        tlwe_public_key_size: Option<usize>,
    ) -> Self {
        let tlwe_stddev = tlwe_stddev.unwrap_or(parameter.default_tlwe_stddev);
        let tlwe_public_key_size =
            tlwe_public_key_size.unwrap_or(parameter.default_tlwe_public_key_size);

        let ciphertexts: Vec<Vec<Torus>> = generate_tlwe_public_key(
            &sk.bytes,
            &parameter.torus_param,
            parameter.encryption_sample_num,
            tlwe_stddev,
            tlwe_public_key_size,
        );

        Self {
            ciphertexts,
            tlwe_public_key_size,
            tlwe_stddev,
            key_id: sk.key_id,
            origin: parameter.origin,
            torus_param: parameter.torus_param,
            computational_accuracy_bit: parameter.computational_accuracy_bit,
            encryption_sample_num: parameter.encryption_sample_num,
            message_value_range: parameter.default_message_value_range,
            default_tlwe_chosen_ctxt_from_public_key: parameter
                .default_tlwe_chosen_ctxt_from_public_key,
        }
    }

    pub fn from_raw(
        ciphertexts: Vec<Vec<Torus>>,
        tlwe_stddev: f32,
        tlwe_public_key_size: usize,
        key_id: Uuid,
        origin: ParameterOrigin,
        torus_param: TorusParam,
        computational_accuracy_bit: usize,
        encryption_sample_num: usize,
        message_value_range: (f32, f32),
        default_tlwe_chosen_ctxt_from_public_key: usize,
    ) -> Self {
        Self {
            ciphertexts,
            tlwe_stddev,
            tlwe_public_key_size,
            key_id,
            origin,
            torus_param,
            computational_accuracy_bit,
            encryption_sample_num,
            message_value_range,
            default_tlwe_chosen_ctxt_from_public_key,
        }
    }

    // Note: tlwe_chosen_ctxt_from_public_key can be changed in one public key
    pub fn encrypt(
        &self,
        plaintext: &Plaintext,
        operation: BTreeMap<OperationType, OperationSide>,
        tlwe_chosen_ctxt_from_public_key: Option<usize>,
    ) -> Ciphertext {
        let tlwe_chosen_ctxt_from_public_key = tlwe_chosen_ctxt_from_public_key
            .unwrap_or(self.default_tlwe_chosen_ctxt_from_public_key);
        Ciphertext::new_with_extra_args(
            tlwe_public_encrypt(
                plaintext,
                &self.ciphertexts,
                &self.torus_param,
                tlwe_chosen_ctxt_from_public_key,
            ),
            self.key_id,
            operation,
        )
    }

    pub fn encode(&self, cleartext: f32) -> Plaintext {
        tlwe_encode(
            cleartext,
            &self.torus_param,
            self.computational_accuracy_bit,
            self.message_value_range,
        )
    }

    pub fn encode_encrypt(
        &self,
        cleartext: f32,
        operation: BTreeMap<OperationType, OperationSide>,
        tlwe_chosen_ctxt_from_public_key: Option<usize>,
    ) -> Ciphertext {
        self.encrypt(
            &self.encode(cleartext),
            operation,
            tlwe_chosen_ctxt_from_public_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;
    use crate::{
        high::{parameter::preset_for_test, secret_key::SecretKey},
        low::torus::Torus,
    };

    #[test]
    fn test_new() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        PublicKey::new(&parameter, &sk);
    }

    #[test]
    fn test_new_with_extra_args() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);

        PublicKey::new_with_extra_args(&parameter, &sk, None, None);
        PublicKey::new_with_extra_args(&parameter, &sk, Some(0.0), Some(2));
    }

    #[test]
    fn test_from_raw() {
        let ciphertexts = vec![];
        let tlwe_stddev = 0.01;
        let tlwe_public_key_size = 2;
        let key_id = Uuid::new_v4();
        let origin = ParameterOrigin::Custom;
        let torus_param = TorusParam::default();
        let computational_accuracy_bit = 64;
        let encryption_sample_num = 10;
        let message_value_range = (-1.0, 1.0);
        let default_tlwe_chosen_ctxt_from_public_key = 5;

        let pk = PublicKey::from_raw(
            ciphertexts.clone(),
            tlwe_stddev,
            tlwe_public_key_size,
            key_id,
            origin,
            torus_param,
            computational_accuracy_bit,
            encryption_sample_num,
            message_value_range,
            default_tlwe_chosen_ctxt_from_public_key,
        );

        assert_eq!(pk.ciphertexts.len(), ciphertexts.len());
        assert_eq!(pk.tlwe_stddev, tlwe_stddev);
        assert_eq!(pk.tlwe_public_key_size, tlwe_public_key_size);
        assert_eq!(pk.computational_accuracy_bit, computational_accuracy_bit);
        assert_eq!(pk.encryption_sample_num, encryption_sample_num);
        assert_eq!(pk.message_value_range, message_value_range);
        assert_eq!(pk.key_id, key_id);
        assert_eq!(pk.origin, origin);
        assert_eq!(
            format!("{:?}", pk.torus_param),
            format!("{:?}", torus_param)
        );
    }

    #[test]
    fn test_encrypt() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let plaintext: Torus = Torus::new(10);
        let _: Ciphertext = pk.encrypt(&plaintext, BTreeMap::new(), None);
    }

    #[test]
    fn test_encode() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let cleartext: f32 = 1.25;
        let _: Plaintext = pk.encode(cleartext);
    }

    #[test]
    fn test_encode_encrypt() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let cleartext: f32 = 1.25;
        let ciphertext = pk.encode_encrypt(cleartext, BTreeMap::new(), None);

        assert_eq!(ciphertext.key_id, sk.key_id);
    }

    #[test]
    fn test_serialize_deserialize_json() {
        let key_id = Uuid::new_v4();
        let origin = ParameterOrigin::Custom;
        let pk = PublicKey::from_raw(
            vec![],
            0.05,
            4,
            key_id,
            origin,
            TorusParam::default(),
            32,
            20,
            (-10.0, 10.0),
            5,
        );

        // Serialize to JSON
        let serialized = serde_json::to_string(&pk).expect("Failed to serialize");
        // Deserialize back
        let deserialized: PublicKey =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(deserialized.tlwe_stddev, pk.tlwe_stddev);
        assert_eq!(deserialized.tlwe_public_key_size, pk.tlwe_public_key_size);
        assert_eq!(
            deserialized.computational_accuracy_bit,
            pk.computational_accuracy_bit
        );
        assert_eq!(deserialized.encryption_sample_num, pk.encryption_sample_num);
        assert_eq!(deserialized.message_value_range, pk.message_value_range);
        assert_eq!(deserialized.key_id, pk.key_id);
        assert_eq!(deserialized.origin, pk.origin);
        assert_eq!(
            format!("{:?}", deserialized.torus_param),
            format!("{:?}", pk.torus_param)
        );
    }
}
