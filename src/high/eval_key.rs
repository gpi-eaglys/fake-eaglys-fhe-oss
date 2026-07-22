use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    high::{
        parameter::{Parameter, ParameterOrigin},
        public_key::PublicKey,
        secret_key::SecretKey,
    },
    low::{
        bootstrap::{
            core_algorithm::{
                bootstrap_key_generation::generate_bootstrap_key,
                key_switch_key_generation::generate_key_switch_key,
                sample_extraction::sample_extraction_to_key,
            },
            pbs::lut_generation::generate_div_square_lut,
        },
        modulus::TwoPowerModulusPattern,
        torus::{Torus, TorusParam},
        torus_polynomial::{TorusPolynomialParameter, torus_polynomial_mat::TorusPolynomialMat},
    },
};
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct EvalKey {
    pub key_id: Uuid,
    pub multiply_lut: Option<Vec<Torus>>,
    pub bootstrap_key: Vec<TorusPolynomialMat<TwoPowerModulusPattern>>,
    pub key_switch_key: Vec<Vec<Vec<Torus>>>,
    // copied from parameter
    origin: ParameterOrigin,
    pub torus_param: TorusParam,
    pub torus_polynomial_parameter: TorusPolynomialParameter,
    pub computational_accuracy_bit: usize,
    pub bg: usize,
    pub l: usize,
    pub ksk_precision: usize,
}

impl EvalKey {
    pub fn new(parameter: &Parameter, sk: &SecretKey) -> Self {
        let trlwe_to_tlwe_sk_bytes: Vec<u8> = sample_extraction_to_key(&sk.trlwe_bytes);
        let pk: PublicKey = PublicKey::new(parameter, sk);

        EvalKey {
            key_id: sk.key_id,
            multiply_lut: Some(generate_div_square_lut(
                &parameter.torus_param,
                &parameter.torus_polynomial_parameter.torus_parameter,
                parameter.computational_accuracy_bit,
                pk.message_value_range,
            )),
            bootstrap_key: generate_bootstrap_key::<TwoPowerModulusPattern>(
                &sk.bytes,
                &sk.trlwe_bytes,
                &parameter.torus_polynomial_parameter,
                parameter.default_trlwe_encryption_sample_num,
                parameter.default_trlwe_stddev,
                parameter.default_bg,
                parameter.default_l,
            ),
            key_switch_key: generate_key_switch_key(
                &trlwe_to_tlwe_sk_bytes,
                &pk.ciphertexts,
                &parameter.torus_param,
                parameter.default_tlwe_chosen_ctxt_from_public_key,
                parameter.default_ksk_precision,
            ),
            origin: parameter.origin,
            torus_param: parameter.torus_param,
            torus_polynomial_parameter: parameter.torus_polynomial_parameter.clone(),
            computational_accuracy_bit: parameter.computational_accuracy_bit,
            bg: parameter.default_bg,
            l: parameter.default_l,
            ksk_precision: parameter.default_ksk_precision,
        }
    }
    pub fn new_with_extra_args() -> Self {
        todo!();
    }
    pub fn from_raw() -> Self {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;
    use crate::high::parameter::preset_for_test;

    #[test]
    fn test_new() {
        let parameter = Parameter::from_preset(preset_for_test());

        let sk = SecretKey::new(&parameter);
        let eval_key = EvalKey::new(&parameter, &sk);

        assert_eq!(eval_key.key_id, sk.key_id);
        assert!(!eval_key.bootstrap_key.is_empty());
        assert!(!eval_key.key_switch_key.is_empty());
    }

    #[test]
    fn test_serialize_deserialize_json() {
        let parameter = Parameter::from_preset(preset_for_test());

        let sk = SecretKey::new(&parameter);
        let eval_key = EvalKey::new(&parameter, &sk);

        let serialized = serde_json::to_string(&eval_key).expect("serialize EvalKey");
        let deserialized: EvalKey = serde_json::from_str(&serialized).expect("deserialize EvalKey");

        assert_eq!(deserialized.key_id, eval_key.key_id);
        assert_eq!(
            deserialized.bootstrap_key.len(),
            eval_key.bootstrap_key.len()
        );
        assert_eq!(
            deserialized.key_switch_key.len(),
            eval_key.key_switch_key.len()
        );
    }
}
