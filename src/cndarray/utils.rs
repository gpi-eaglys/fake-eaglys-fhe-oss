use std::collections::BTreeMap;

use crate::{
    cndarray::{cndarray::Cndarray, error::NdarrayError},
    high::{
        ciphertext::{OperationSide, OperationType},
        key_switch_key::KeySwitchKey,
        public_key::PublicKey,
        secret_key::SecretKey,
    },
};

// TODO: TFHE multiplication currently assumes an ordering constraint (`left < right`).
// For matrix multiplication, we enforce this through `VALUE_LIMITATION`:
// left values must be below the limit, and right values must be at or above it.
// Revisit this when we introduce a cleaner way to represent mul-side constraints.

pub const VALUE_LIMITATION: f32 = 0.5;

fn validate_mul_value_limitation(
    value: f32,
    operation: &BTreeMap<OperationType, OperationSide>,
) -> Result<(), NdarrayError> {
    match operation.get(&OperationType::Mul) {
        Some(OperationSide::Left) if value < VALUE_LIMITATION => {
            Err(NdarrayError::InvalidMulSideLeft)
        }
        Some(OperationSide::Right) if value >= VALUE_LIMITATION => {
            Err(NdarrayError::InvalidMulSideRight)
        }
        _ => Ok(()),
    }
}

pub fn encode_encrypt_ndarray(
    pk: &PublicKey,
    values: &[f32],
    shape: &[usize],
    operation: BTreeMap<OperationType, OperationSide>,
    tlwe_chosen_ctxt_from_public_key: Option<usize>,
) -> Result<Cndarray, NdarrayError> {
    let ciphertexts: Result<Vec<_>, NdarrayError> = values
        .iter()
        .map(|&value| {
            validate_mul_value_limitation(value, &operation)?;
            Ok(pk.encode_encrypt(value, operation.clone(), tlwe_chosen_ctxt_from_public_key))
        })
        .collect();

    Cndarray::new(ciphertexts?, shape.to_vec())
}

pub fn encode_encrypt_matrix(
    pk: &PublicKey,
    values: &[Vec<f32>],
    operation: BTreeMap<OperationType, OperationSide>,
    tlwe_chosen_ctxt_from_public_key: Option<usize>,
) -> Result<Cndarray, NdarrayError> {
    if values.is_empty() {
        return Err(NdarrayError::ShapeMismatch);
    }

    let cols = values[0].len();
    if cols == 0 || values.iter().any(|row| row.len() != cols) {
        return Err(NdarrayError::ShapeMismatch);
    }

    let rows = values.len();
    let mut flattened = Vec::with_capacity(rows * cols);
    for row in values {
        flattened.extend_from_slice(row);
    }

    encode_encrypt_ndarray(
        pk,
        &flattened,
        &[rows, cols],
        operation,
        tlwe_chosen_ctxt_from_public_key,
    )
}

pub fn decode_decrypt_ndarray(
    sk: &SecretKey,
    cndarray: &Cndarray,
) -> Result<Vec<f32>, NdarrayError> {
    cndarray
        .get_ciphertexts()
        .iter()
        .map(|ct| sk.decode_decrypt(ct).map_err(NdarrayError::from))
        .collect()
}

pub fn decode_decrypt_matrix(
    sk: &SecretKey,
    cndarray: &Cndarray,
) -> Result<Vec<Vec<f32>>, NdarrayError> {
    let shape = cndarray.get_shape();
    if shape.len() != 2 {
        return Err(NdarrayError::ShapeMismatch);
    }

    let rows = shape[0];
    let cols = shape[1];
    if rows == 0 || cols == 0 {
        return Err(NdarrayError::ShapeMismatch);
    }

    let decoded = decode_decrypt_ndarray(sk, cndarray)?;
    if decoded.len() != rows * cols {
        return Err(NdarrayError::ShapeMismatch);
    }

    Ok(decoded.chunks(cols).map(|row| row.to_vec()).collect())
}

pub fn key_switch_ndarray(
    ksk: &KeySwitchKey,
    cndarray: &Cndarray,
) -> Result<Cndarray, NdarrayError> {
    let switched = cndarray
        .get_ciphertexts()
        .iter()
        .map(|ciphertext| ksk.key_switch(ciphertext))
        .collect();

    Cndarray::new(switched, cndarray.get_shape().to_vec())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use approx::assert_relative_eq;

    use super::*;
    use crate::high::{
        ciphertext::{OperationSide, OperationType},
        parameter::{Parameter, ParameterPreset},
    };

    #[test]
    fn test_encode_encrypt_matrix_and_decode_decrypt_matrix() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let matrix = vec![vec![1.0, 2.0], vec![3.0, 4.0]];
        let ciphertext_matrix =
            encode_encrypt_matrix(&pk, &matrix, BTreeMap::new(), None).expect("encode failed");
        let decoded = decode_decrypt_matrix(&sk, &ciphertext_matrix).expect("decode failed");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].len(), 2);
        assert_relative_eq!(decoded[0][0], 1.0, epsilon = 1e-1);
        assert_relative_eq!(decoded[1][1], 4.0, epsilon = 1e-1);
    }

    #[test]
    fn test_encode_encrypt_matrix_shape_mismatch() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let matrix = vec![vec![1.0], vec![2.0, 3.0]];
        let err = encode_encrypt_matrix(&pk, &matrix, BTreeMap::new(), None)
            .expect_err("shape mismatch expected");

        assert!(matches!(err, NdarrayError::ShapeMismatch));
    }

    #[test]
    fn test_encode_encrypt_matrix_mul_value_limitation() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let left_matrix = vec![vec![0.3]];
        let left_err = encode_encrypt_matrix(
            &pk,
            &left_matrix,
            BTreeMap::from([(OperationType::Mul, OperationSide::Left)]),
            None,
        )
        .expect_err("left limitation expected");
        assert!(matches!(left_err, NdarrayError::InvalidMulSideLeft));

        let right_matrix = vec![vec![0.5]];
        let right_err = encode_encrypt_matrix(
            &pk,
            &right_matrix,
            BTreeMap::from([(OperationType::Mul, OperationSide::Right)]),
            None,
        )
        .expect_err("right limitation expected");
        assert!(matches!(right_err, NdarrayError::InvalidMulSideRight));
    }

    #[test]
    fn test_decode_decrypt_matrix_requires_2d_shape() {
        let parameter = Parameter::from_preset(ParameterPreset::Low);
        let sk = SecretKey::new(&parameter);
        let pk = PublicKey::new(&parameter, &sk);

        let array = encode_encrypt_ndarray(&pk, &[1.0, 2.0], &[2], BTreeMap::new(), None)
            .expect("encode failed");
        let err = decode_decrypt_matrix(&sk, &array).expect_err("shape mismatch expected");

        assert!(matches!(err, NdarrayError::ShapeMismatch));
    }
}
