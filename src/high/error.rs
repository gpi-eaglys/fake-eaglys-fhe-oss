#[derive(Debug)]
pub enum HighError {
    KeyIdMismatch,
    ParameterMismatch,
    InvalidCiphertext,
    InvalidMulSideLeft,
    InvalidMulSideRight,
}
