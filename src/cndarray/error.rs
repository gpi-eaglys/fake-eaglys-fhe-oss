use crate::high::error::HighError;

#[derive(Debug)]
pub enum NdarrayError {
    ShapeMismatch,
    KeyIdMismatch,
    ParameterMismatch,
    InvalidCiphertext,
    InvalidMulSideLeft,
    InvalidMulSideRight,
}

impl From<HighError> for NdarrayError {
    fn from(value: HighError) -> Self {
        match value {
            HighError::KeyIdMismatch => NdarrayError::KeyIdMismatch,
            HighError::ParameterMismatch => NdarrayError::ParameterMismatch,
            HighError::InvalidCiphertext => NdarrayError::InvalidCiphertext,
            HighError::InvalidMulSideLeft => NdarrayError::InvalidMulSideLeft,
            HighError::InvalidMulSideRight => NdarrayError::InvalidMulSideRight,
        }
    }
}
