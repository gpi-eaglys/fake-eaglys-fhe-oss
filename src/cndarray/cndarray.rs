use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    cndarray::error::NdarrayError,
    high::{ciphertext::Ciphertext, eval_key::EvalKey, parameter::Parameter},
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Cndarray {
    ciphertexts: Vec<Ciphertext>,
    shape: Vec<usize>,
    pub key_id: Uuid,
}

impl Cndarray {
    pub fn new(ciphertexts: Vec<Ciphertext>, shape: Vec<usize>) -> Result<Self, NdarrayError> {
        let expected = validate_shape(&shape).ok_or(NdarrayError::ShapeMismatch)?;
        if expected != ciphertexts.len() {
            return Err(NdarrayError::ShapeMismatch);
        }

        let key_id = if let Some(first) = ciphertexts.first() {
            let key_id = first.key_id;
            if ciphertexts.iter().any(|ct| ct.key_id != key_id) {
                return Err(NdarrayError::KeyIdMismatch);
            }
            key_id
        } else {
            Uuid::nil()
        };

        Ok(Self {
            ciphertexts,
            shape,
            key_id,
        })
    }

    pub fn ndim(&self) -> usize {
        self.shape.len()
    }

    pub fn get_shape(&self) -> &[usize] {
        &self.shape
    }

    pub fn get_ciphertexts(&self) -> &[Ciphertext] {
        &self.ciphertexts
    }

    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn get_at(&self, indices: &[usize]) -> Result<&Ciphertext, NdarrayError> {
        if indices.len() != self.ndim() {
            return Err(NdarrayError::ShapeMismatch);
        }

        let mut offset = 0usize;
        for (&index, &extent) in indices.iter().zip(self.shape.iter()) {
            if index >= extent {
                return Err(NdarrayError::ShapeMismatch);
            }
            offset = offset
                .checked_mul(extent)
                .and_then(|value| value.checked_add(index))
                .ok_or(NdarrayError::ShapeMismatch)?;
        }

        self.ciphertexts
            .get(offset)
            .ok_or(NdarrayError::ShapeMismatch)
    }
    // TODO: here has ciphertext clone, discuss design in the fucture.
    pub fn reshape(&self, shape: &[usize]) -> Result<Self, NdarrayError> {
        let expected = validate_shape(shape).ok_or(NdarrayError::ShapeMismatch)?;
        if expected != self.ciphertexts.len() {
            return Err(NdarrayError::ShapeMismatch);
        }

        Self::new(self.ciphertexts.clone(), shape.to_vec())
    }

    pub fn add(&self, other: &Self, param: &Parameter) -> Result<Self, NdarrayError> {
        self.check_shape_invariant()?;
        other.check_shape_invariant()?;
        self.check_same_key_id(other)?;
        self.check_same_shape(other)?;

        let ciphertexts: Result<Vec<Ciphertext>, NdarrayError> = self
            .ciphertexts
            .iter()
            .zip(other.ciphertexts.iter())
            .map(|(lhs, rhs)| lhs.add(rhs, param).map_err(NdarrayError::from))
            .collect();

        Self::new(ciphertexts?, self.shape.clone())
    }

    pub fn sub(&self, other: &Self, param: &Parameter) -> Result<Self, NdarrayError> {
        self.check_shape_invariant()?;
        other.check_shape_invariant()?;
        self.check_same_key_id(other)?;
        self.check_same_shape(other)?;

        let ciphertexts: Result<Vec<Ciphertext>, NdarrayError> = self
            .ciphertexts
            .iter()
            .zip(other.ciphertexts.iter())
            .map(|(lhs, rhs)| lhs.sub(rhs, param).map_err(NdarrayError::from))
            .collect();

        Self::new(ciphertexts?, self.shape.clone())
    }

    pub fn mul(&self, other: &Self, eval_key: &EvalKey) -> Result<Self, NdarrayError> {
        self.check_shape_invariant()?;
        other.check_shape_invariant()?;
        self.check_same_key_id(other)?;
        self.check_same_shape(other)?;

        let ciphertexts: Result<Vec<Ciphertext>, NdarrayError> = self
            .ciphertexts
            .iter()
            .zip(other.ciphertexts.iter())
            .map(|(lhs, rhs)| lhs.mul(rhs, eval_key).map_err(NdarrayError::from))
            .collect();

        Self::new(ciphertexts?, self.shape.clone())
    }

    pub fn matmul(
        &self,
        other: &Self,
        param: &Parameter,
        eval_key: &EvalKey,
    ) -> Result<Self, NdarrayError> {
        self.check_shape_invariant()?;
        other.check_shape_invariant()?;
        self.check_same_key_id(other)?;
        if self.ndim() != 2 || other.ndim() != 2 {
            return Err(NdarrayError::ShapeMismatch);
        }

        let lhs_rows = self.shape[0];
        let lhs_cols = self.shape[1];
        let rhs_rows = other.shape[0];
        let rhs_cols = other.shape[1];

        if lhs_cols != rhs_rows {
            return Err(NdarrayError::ShapeMismatch);
        }
        let mut out: Vec<Ciphertext> = Vec::with_capacity(lhs_rows * rhs_cols);
        for row in 0..lhs_rows {
            for col in 0..rhs_cols {
                let mut acc: Option<Ciphertext> = None;
                for k in 0..lhs_cols {
                    let lhs = self.get_at(&[row, k])?;
                    let rhs = other.get_at(&[k, col])?;
                    let product = lhs.mul(rhs, eval_key).map_err(NdarrayError::from)?;
                    acc = match acc {
                        Some(current) => {
                            Some(current.add(&product, param).map_err(NdarrayError::from)?)
                        }
                        None => Some(product),
                    };
                }
                out.push(acc.ok_or(NdarrayError::ShapeMismatch)?);
            }
        }

        Self::new(out, vec![lhs_rows, rhs_cols])
    }

    fn check_same_key_id(&self, other: &Self) -> Result<(), NdarrayError> {
        if self.key_id != other.key_id {
            return Err(NdarrayError::KeyIdMismatch);
        }
        Ok(())
    }

    fn check_same_shape(&self, other: &Self) -> Result<(), NdarrayError> {
        if self.shape != other.shape {
            return Err(NdarrayError::ShapeMismatch);
        }
        Ok(())
    }

    fn check_shape_invariant(&self) -> Result<(), NdarrayError> {
        let expected = validate_shape(&self.shape).ok_or(NdarrayError::ShapeMismatch)?;
        if expected != self.ciphertexts.len() {
            return Err(NdarrayError::ShapeMismatch);
        }
        Ok(())
    }
}

fn validate_shape(shape: &[usize]) -> Option<usize> {
    if shape.is_empty() || shape.contains(&0) {
        return None;
    }

    let mut count = 1usize;
    for &extent in shape {
        count = count.checked_mul(extent)?;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use approx::assert_relative_eq;

    use super::*;
    use crate::{
        cndarray::{
            error::NdarrayError,
            utils::{decode_decrypt_ndarray, encode_encrypt_ndarray},
        },
        high::{
            ciphertext::{OperationSide, OperationType},
            parameter::ParameterPreset,
            public_key::PublicKey,
            secret_key::SecretKey,
        },
    };

    #[test]
    fn test_ndim() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let array = encode_encrypt_ndarray(&pk, &[1.0, 2.0], &[1, 2], BTreeMap::new(), None)
            .expect("encode_encrypt_ndarray failed");

        assert_eq!(array.ndim(), 2);
    }

    #[test]
    fn test_serialize_deserialize() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let array =
            encode_encrypt_ndarray(&pk, &[1.0, 2.0, 3.0, 4.0], &[2, 2], BTreeMap::new(), None)
                .expect("encode_encrypt_ndarray failed");

        let bytes = array.serialize().expect("serialize failed");
        let restored = Cndarray::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.get_shape(), array.get_shape());
        assert_eq!(restored.key_id, array.key_id);
        assert_eq!(
            restored.get_ciphertexts().len(),
            array.get_ciphertexts().len()
        );
    }

    #[test]
    fn test_get_at() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let array =
            encode_encrypt_ndarray(&pk, &[1.0, 2.0, 3.0, 4.0], &[2, 2], BTreeMap::new(), None)
                .expect("encode_encrypt_ndarray failed");

        let value = sk
            .decode_decrypt(array.get_at(&[1, 0]).expect("get_at failed"))
            .expect("decode failed");
        assert_relative_eq!(value, 3.0, epsilon = 1e-1);

        assert!(matches!(
            array.get_at(&[0]),
            Err(NdarrayError::ShapeMismatch)
        ));
        assert!(matches!(
            array.get_at(&[2, 0]),
            Err(NdarrayError::ShapeMismatch)
        ));
    }

    #[test]
    fn test_add() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let lhs =
            encode_encrypt_ndarray(&pk, &[1.0, 2.0, 3.0, 4.0], &[2, 2], BTreeMap::new(), None)
                .expect("encode_encrypt_ndarray failed");
        let rhs =
            encode_encrypt_ndarray(&pk, &[0.5, 1.5, 2.5, 3.5], &[2, 2], BTreeMap::new(), None)
                .expect("encode_encrypt_ndarray failed");

        let summed = lhs.add(&rhs, &parameter).expect("add failed");
        let decoded = decode_decrypt_ndarray(&sk, &summed).expect("decode_decrypt_ndarray failed");

        assert_relative_eq!(decoded[0], 1.5, epsilon = 1e-1);
        assert_relative_eq!(decoded[3], 7.5, epsilon = 1e-1);
    }

    #[test]
    fn test_reshape() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let original =
            encode_encrypt_ndarray(&pk, &[1.0, 2.0, 3.0, 4.0], &[2, 2], BTreeMap::new(), None)
                .expect("encode_encrypt_ndarray failed");
        let reshaped = original.reshape(&[4, 1]).expect("reshape failed");

        assert_eq!(reshaped.get_shape(), &[4, 1]);
        let decoded =
            decode_decrypt_ndarray(&sk, &reshaped).expect("decode_decrypt_ndarray failed");
        assert_relative_eq!(decoded[0], 1.0, epsilon = 1e-1);
        assert_relative_eq!(decoded[3], 4.0, epsilon = 1e-1);
    }

    #[test]
    fn test_reshape_shape_mismatch() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let original =
            encode_encrypt_ndarray(&pk, &[1.0, 2.0, 3.0, 4.0], &[2, 2], BTreeMap::new(), None)
                .expect("encode_encrypt_ndarray failed");
        let err = original.reshape(&[3]).expect_err("shape mismatch expected");

        assert!(matches!(err, NdarrayError::ShapeMismatch));
    }

    #[test]
    fn test_sub() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let lhs = encode_encrypt_ndarray(&pk, &[5.0, 7.0], &[1, 2], BTreeMap::new(), None)
            .expect("encode_encrypt_ndarray failed");
        let rhs = encode_encrypt_ndarray(&pk, &[1.5, 2.5], &[1, 2], BTreeMap::new(), None)
            .expect("encode_encrypt_ndarray failed");

        let diff = lhs.sub(&rhs, &parameter).expect("sub failed");

        assert_relative_eq!(
            sk.decode_decrypt(&diff.ciphertexts[0])
                .expect("decode failed"),
            3.5,
            epsilon = 1e-2
        );
        assert_relative_eq!(
            sk.decode_decrypt(&diff.ciphertexts[1])
                .expect("decode failed"),
            4.5,
            epsilon = 1e-2
        );
    }

    #[test]
    fn test_mul() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);
        let left_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Left)]);
        let right_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Right)]);

        let lhs = encode_encrypt_ndarray(&pk, &[0.6, 0.7], &[1, 2], left_lock, None)
            .expect("encode_encrypt_ndarray failed");
        let rhs = encode_encrypt_ndarray(&pk, &[0.2, 0.3], &[1, 2], right_lock, None)
            .expect("encode_encrypt_ndarray failed");

        let product = lhs.mul(&rhs, &eval_key).expect("mul failed");

        assert_relative_eq!(
            sk.decode_decrypt(&product.ciphertexts[0])
                .expect("decode failed"),
            0.12,
            epsilon = 1e-2
        );
        assert_relative_eq!(
            sk.decode_decrypt(&product.ciphertexts[1])
                .expect("decode failed"),
            0.21,
            epsilon = 1e-2
        );
    }

    #[test]
    fn test_matmul() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);
        let left_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Left)]);
        let right_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Right)]);

        let lhs = encode_encrypt_ndarray(&pk, &[0.6, 0.7], &[1, 2], left_lock, None)
            .expect("encode_encrypt_ndarray failed");
        let rhs = encode_encrypt_ndarray(&pk, &[0.2, 0.3], &[2, 1], right_lock, None)
            .expect("encode_encrypt_ndarray failed");

        let out = lhs
            .matmul(&rhs, &parameter, &eval_key)
            .expect("matmul failed");

        assert_eq!(out.get_shape(), &[1, 1]);
        assert_relative_eq!(
            sk.decode_decrypt(&out.ciphertexts[0])
                .expect("decode failed"),
            0.33,
            epsilon = 1e-1
        );
    }

    #[test]
    fn test_matmul_rejects_vector_other() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);
        let left_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Left)]);
        let right_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Right)]);

        let lhs = encode_encrypt_ndarray(&pk, &[0.6, 0.7], &[1, 2], left_lock, None)
            .expect("encode_encrypt_ndarray failed");
        let rhs = encode_encrypt_ndarray(&pk, &[0.2, 0.3], &[2], right_lock, None)
            .expect("encode_encrypt_ndarray failed");

        let err = lhs
            .matmul(&rhs, &parameter, &eval_key)
            .expect_err("shape mismatch expected");

        assert!(matches!(err, NdarrayError::ShapeMismatch));
    }

    #[test]
    fn test_matmul_reshaped_other() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);
        let left_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Left)]);
        let right_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Right)]);

        let lhs = encode_encrypt_ndarray(&pk, &[0.6, 0.7], &[1, 2], left_lock, None)
            .expect("encode_encrypt_ndarray failed");
        let rhs_1d = encode_encrypt_ndarray(&pk, &[0.2, 0.3], &[2], right_lock, None)
            .expect("encode_encrypt_ndarray failed");
        let rhs_2d = rhs_1d.reshape(&[2, 1]).expect("reshape failed");

        let out = lhs
            .matmul(&rhs_2d, &parameter, &eval_key)
            .expect("matmul failed");

        assert_eq!(out.get_shape(), &[1, 1]);
        assert_relative_eq!(
            sk.decode_decrypt(&out.ciphertexts[0])
                .expect("decode failed"),
            0.33,
            epsilon = 1e-1
        );
    }

    #[test]
    fn test_shape_mismatch() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let lhs = encode_encrypt_ndarray(&pk, &[1.0, 2.0], &[1, 2], BTreeMap::new(), None)
            .expect("encode_encrypt_ndarray failed");
        let rhs = encode_encrypt_ndarray(&pk, &[1.0, 2.0], &[2, 1], BTreeMap::new(), None)
            .expect("encode_encrypt_ndarray failed");
        let err = lhs
            .add(&rhs, &parameter)
            .expect_err("shape mismatch expected");

        assert!(matches!(err, NdarrayError::ShapeMismatch));
    }

    #[test]
    fn test_invalid_shape_invariant_rejected() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);
        let eval_key = EvalKey::new(&parameter, &sk);
        let left_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Left)]);
        let right_lock = BTreeMap::from([(OperationType::Mul, OperationSide::Right)]);

        let mut invalid = encode_encrypt_ndarray(&pk, &[0.6, 0.7], &[1, 2], left_lock, None)
            .expect("encode_encrypt_ndarray failed");
        invalid.shape = vec![2, 2];

        let other_same_shape =
            encode_encrypt_ndarray(&pk, &[0.2, 0.3], &[1, 2], right_lock.clone(), None)
                .expect("encode_encrypt_ndarray failed");
        let other_matmul = encode_encrypt_ndarray(&pk, &[0.2, 0.3], &[2, 1], right_lock, None)
            .expect("encode_encrypt_ndarray failed");

        assert!(matches!(
            invalid.add(&other_same_shape, &parameter),
            Err(NdarrayError::ShapeMismatch)
        ));
        assert!(matches!(
            invalid.sub(&other_same_shape, &parameter),
            Err(NdarrayError::ShapeMismatch)
        ));
        assert!(matches!(
            invalid.mul(&other_same_shape, &eval_key),
            Err(NdarrayError::ShapeMismatch)
        ));
        assert!(matches!(
            invalid.matmul(&other_matmul, &parameter, &eval_key),
            Err(NdarrayError::ShapeMismatch)
        ));
    }
}
