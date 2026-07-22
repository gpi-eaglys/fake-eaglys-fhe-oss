use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    high::{
        ciphertext::Ciphertext, parameter::Parameter, public_key::PublicKey, secret_key::SecretKey,
    },
    low::{
        bootstrap::core_algorithm::{
            key_switch::public_key_switch, key_switch_key_generation::generate_key_switch_key,
        },
        torus::{Torus, TorusParam},
    },
};
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct KeySwitchKey {
    pub key_id: Uuid,
    pub key_switch_key: Vec<Vec<Vec<Torus>>>,
    torus_param: TorusParam,
    ksk_precision: usize,
}

impl KeySwitchKey {
    pub fn new(parameter: &Parameter, original_sk: &SecretKey, target_pk: &PublicKey) -> Self {
        KeySwitchKey {
            key_id: target_pk.key_id,
            key_switch_key: generate_key_switch_key(
                &original_sk.bytes,
                &target_pk.ciphertexts,
                &parameter.torus_param,
                parameter.default_tlwe_chosen_ctxt_from_public_key,
                parameter.default_ksk_precision,
            ),
            torus_param: parameter.torus_param,
            ksk_precision: parameter.default_ksk_precision,
        }
    }

    pub fn key_switch(&self, original: &Ciphertext) -> Ciphertext {
        Ciphertext::new_with_extra_args(
            public_key_switch(
                &original.vector_torus,
                &self.torus_param,
                &self.torus_param,
                self.ksk_precision,
                &self.key_switch_key,
            ),
            self.key_id,
            original.operation_lock.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use approx::assert_relative_eq;
    use serde_json;

    use super::*;
    use crate::high::parameter::preset_for_test;

    #[test]
    fn test_new() {
        let parameter = Parameter::from_preset(preset_for_test());
        let original_sk = SecretKey::new(&parameter);
        let target_sk = SecretKey::new(&parameter);
        let target_pk = PublicKey::new(&parameter, &target_sk);

        let ksk = KeySwitchKey::new(&parameter, &original_sk, &target_pk);

        assert_eq!(ksk.key_id, target_pk.key_id);
        assert!(!ksk.key_switch_key.is_empty());
    }

    #[test]
    fn test_key_switch() {
        let parameter = Parameter::from_preset(preset_for_test());
        let original_sk = SecretKey::new(&parameter);
        let original_pk = PublicKey::new(&parameter, &original_sk);
        let target_sk = SecretKey::new(&parameter);
        let target_pk = PublicKey::new(&parameter, &target_sk);

        let ksk = KeySwitchKey::new(&parameter, &original_sk, &target_pk);
        let cleartext: f32 = 0.5;
        let ciphertext = original_pk.encode_encrypt(cleartext, BTreeMap::new(), None);

        let switched = ksk.key_switch(&ciphertext);
        let decoded = target_sk
            .decode_decrypt(&switched)
            .expect("decode_decrypt failed after key switch");

        assert_eq!(switched.key_id, target_pk.key_id);
        assert_relative_eq!(cleartext, decoded, epsilon = 1e-1);
    }

    #[test]
    fn test_serialize_deserialize_json() {
        let parameter = Parameter::from_preset(preset_for_test());
        let original_sk = SecretKey::new(&parameter);
        let target_sk = SecretKey::new(&parameter);
        let target_pk = PublicKey::new(&parameter, &target_sk);

        let ksk = KeySwitchKey::new(&parameter, &original_sk, &target_pk);

        let serialized = serde_json::to_string(&ksk).expect("serialize KeySwitchKey");
        let deserialized: KeySwitchKey =
            serde_json::from_str(&serialized).expect("deserialize KeySwitchKey");

        assert_eq!(deserialized.key_id, ksk.key_id);
        assert_eq!(deserialized.torus_param.bitsize, ksk.torus_param.bitsize);
        assert_eq!(deserialized.ksk_precision, ksk.ksk_precision);
        assert_eq!(deserialized.key_switch_key.len(), ksk.key_switch_key.len());
    }
}
