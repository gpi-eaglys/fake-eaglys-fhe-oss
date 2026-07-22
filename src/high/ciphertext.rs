use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    high::{error::HighError, eval_key::EvalKey, parameter::Parameter},
    low::{bootstrap::pbs::multiply_pbs::multiply_pbs, module::Module, torus::Torus},
};
// // TODO: allow user to control modulus pattern by cargo.toml's features
// pub(crate) type Ciphertext = Vec<Torus>;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    // TODO: consider to check whose ciphertext, e.g. publickey serialization
    pub vector_torus: Vec<Torus>,
    pub key_id: Uuid,
    #[serde(default)]
    pub operation_lock: BTreeMap<OperationType, OperationSide>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum OperationType {
    Mul,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum OperationSide {
    Left,
    Right,
}

impl Ciphertext {
    pub fn new() -> Self {
        Self::new_with_extra_args(vec![], Uuid::nil(), BTreeMap::new())
    }

    pub fn new_with_extra_args(
        vector_torus: Vec<Torus>,
        key_id: Uuid,
        operation_lock: BTreeMap<OperationType, OperationSide>,
    ) -> Self {
        Self {
            vector_torus,
            key_id,
            operation_lock,
        }
    }

    pub fn add(&self, other: &Ciphertext, param: &Parameter) -> Result<Ciphertext, HighError> {
        if self.key_id != other.key_id {
            return Err(HighError::KeyIdMismatch);
        }
        if self.vector_torus.len() != other.vector_torus.len() {
            return Err(HighError::InvalidCiphertext);
        }
        let vector_torus = self
            .vector_torus
            .iter()
            .zip(other.vector_torus.iter())
            .map(|(lhs, rhs)| lhs.add(rhs, &param.torus_param))
            .collect();

        Ok(Ciphertext::new_with_extra_args(
            vector_torus,
            self.key_id,
            BTreeMap::new(),
        ))
    }

    pub fn sub(&self, other: &Ciphertext, param: &Parameter) -> Result<Ciphertext, HighError> {
        if self.key_id != other.key_id {
            return Err(HighError::KeyIdMismatch);
        }
        if self.vector_torus.len() != other.vector_torus.len() {
            return Err(HighError::InvalidCiphertext);
        }
        let vector_torus = self
            .vector_torus
            .iter()
            .zip(other.vector_torus.iter())
            .map(|(lhs, rhs)| lhs.sub(rhs, &param.torus_param))
            .collect();

        Ok(Ciphertext::new_with_extra_args(
            vector_torus,
            self.key_id,
            BTreeMap::new(),
        ))
    }

    pub fn mul(&self, other: &Ciphertext, eval_key: &EvalKey) -> Result<Ciphertext, HighError> {
        if self.key_id != other.key_id {
            return Err(HighError::KeyIdMismatch);
        }
        if self.vector_torus.len() != other.vector_torus.len() {
            return Err(HighError::InvalidCiphertext);
        }
        if self.key_id != eval_key.key_id {
            return Err(HighError::KeyIdMismatch);
        }
        if matches!(
            self.operation_lock.get(&OperationType::Mul),
            Some(OperationSide::Right)
        ) {
            return Err(HighError::InvalidMulSideLeft);
        }
        if matches!(
            other.operation_lock.get(&OperationType::Mul),
            Some(OperationSide::Left)
        ) {
            return Err(HighError::InvalidMulSideRight);
        }

        let div_square_lut = eval_key
            .multiply_lut
            .as_ref()
            .ok_or(HighError::ParameterMismatch)?;

        let vector_torus = multiply_pbs(
            &self.vector_torus,
            &other.vector_torus,
            &eval_key.bootstrap_key,
            div_square_lut,
            &eval_key.torus_param,
            &eval_key.torus_polynomial_parameter,
            eval_key.computational_accuracy_bit,
            eval_key.bg,
            eval_key.l,
            eval_key.ksk_precision,
            &eval_key.key_switch_key,
        );
        Ok(Ciphertext::new_with_extra_args(
            vector_torus,
            self.key_id,
            BTreeMap::new(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use approx::assert_relative_eq;

    use super::*;
    use crate::high::{parameter::preset_for_test, public_key::PublicKey, secret_key::SecretKey};

    #[test]
    fn test_new() {
        let ciphertext = Ciphertext::new();

        assert!(ciphertext.vector_torus.is_empty());
        assert_eq!(ciphertext.key_id, Uuid::nil());
    }

    #[test]
    fn test_add() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let lhs = 1.25_f32;
        let rhs = 0.5_f32;

        let lhs_ct = pk.encode_encrypt(lhs, BTreeMap::new(), None);
        let rhs_ct = pk.encode_encrypt(rhs, BTreeMap::new(), None);
        let summed = lhs_ct.add(&rhs_ct, &parameter).expect("add failed");
        let decoded = sk.decode_decrypt(&summed).expect("decode_decrypt failed");

        assert_relative_eq!(decoded, lhs + rhs, epsilon = 1e-1);
    }

    #[test]
    fn test_sub() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let lhs = 1.25_f32;
        let rhs = 0.5_f32;

        let lhs_ct = pk.encode_encrypt(lhs, BTreeMap::new(), None);
        let rhs_ct = pk.encode_encrypt(rhs, BTreeMap::new(), None);
        let diff = lhs_ct.sub(&rhs_ct, &parameter).expect("sub failed");
        let decoded = sk.decode_decrypt(&diff).expect("decode_decrypt failed");

        assert_relative_eq!(decoded, lhs - rhs, epsilon = 1e-1);
    }

    #[test]
    fn test_mul_key_id_mismatch() {
        let parameter = Parameter::from_preset(preset_for_test());
        let lhs_sk = SecretKey::new(&parameter);
        let rhs_sk = SecretKey::new(&parameter);
        let lhs_pk = PublicKey::new(&parameter, &lhs_sk);
        let rhs_pk = PublicKey::new(&parameter, &rhs_sk);
        let eval_key = EvalKey::new(&parameter, &lhs_sk);

        let lhs_ct = lhs_pk.encode_encrypt(
            1.0,
            BTreeMap::from([(OperationType::Mul, OperationSide::Left)]),
            None,
        );
        let rhs_ct = rhs_pk.encode_encrypt(
            2.0,
            BTreeMap::from([(OperationType::Mul, OperationSide::Right)]),
            None,
        );

        let err = lhs_ct
            .mul(&rhs_ct, &eval_key)
            .expect_err("expected key id mismatch");

        assert!(matches!(err, HighError::KeyIdMismatch));
    }

    #[test]
    fn test_mul_length_mismatch() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);

        let mut lhs_ct = pk.encode_encrypt(
            1.0,
            BTreeMap::from([(OperationType::Mul, OperationSide::Left)]),
            None,
        );
        let rhs_ct = pk.encode_encrypt(
            2.0,
            BTreeMap::from([(OperationType::Mul, OperationSide::Right)]),
            None,
        );
        lhs_ct.vector_torus.pop();

        let err = lhs_ct
            .mul(&rhs_ct, &eval_key)
            .expect_err("expected invalid ciphertext");

        assert!(matches!(err, HighError::InvalidCiphertext));
    }

    #[test]
    fn test_mul() {
        let parameter = Parameter::from_preset(preset_for_test());
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);
        let lhs = 1.25_f32;
        let rhs = 0.5_f32;

        let lhs_ct = pk.encode_encrypt(
            lhs,
            BTreeMap::from([(OperationType::Mul, OperationSide::Left)]),
            None,
        );
        let rhs_ct = pk.encode_encrypt(
            rhs,
            BTreeMap::from([(OperationType::Mul, OperationSide::Right)]),
            None,
        );
        let product = lhs_ct.mul(&rhs_ct, &eval_key).expect("mul failed");
        let decoded = sk.decode_decrypt(&product).expect("decode_decrypt failed");

        assert_relative_eq!(decoded, lhs * rhs, epsilon = 1e-1);
    }
}
