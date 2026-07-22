pub mod cndarray;
pub mod high;
pub mod low;

#[cfg(feature = "wasm")]
mod wasm_bindings {
    use std::collections::BTreeMap;

    use wasm_bindgen::prelude::*;

    use crate::{
        cndarray::{
            cndarray::Cndarray as CoreCndarray,
            error::NdarrayError,
            utils::{
                decode_decrypt_matrix as core_decode_decrypt_matrix,
                encode_encrypt_matrix as core_encode_encrypt_matrix,
                key_switch_ndarray as core_key_switch_ndarray,
            },
        },
        high::{
            ciphertext::{
                Ciphertext as CoreCiphertext, OperationSide as CoreOperationSide,
                OperationType as CoreOperationType,
            },
            error::HighError,
            eval_key::EvalKey as CoreEvalKey,
            key_switch_key::KeySwitchKey as CoreKeySwitchKey,
            parameter::{Parameter as CoreParameter, ParameterPreset},
            public_key::PublicKey as CorePublicKey,
            secret_key::SecretKey as CoreSecretKey,
        },
    };

    #[wasm_bindgen]
    pub enum OperationType {
        Mul,
    }

    #[wasm_bindgen]
    pub enum OperationSide {
        Left,
        Right,
    }

    fn parse_operation_lock(
        operation_lock: &JsValue,
    ) -> Result<BTreeMap<CoreOperationType, CoreOperationSide>, JsValue> {
        if operation_lock.is_null() || operation_lock.is_undefined() {
            return Ok(BTreeMap::new());
        }
        let obj = js_sys::Object::from(operation_lock.clone());
        let keys = js_sys::Object::keys(&obj);
        let mut map = BTreeMap::new();
        for key in keys.iter() {
            let key_str = key
                .as_string()
                .ok_or_else(|| JsValue::from_str("operation_lock key must be a string"))?;
            let value = js_sys::Reflect::get(&obj, &key)?;
            let value_str = value
                .as_string()
                .ok_or_else(|| JsValue::from_str("operation_lock value must be a string"))?;
            let op_type = match key_str.as_str() {
                "Mul" => CoreOperationType::Mul,
                _ => {
                    return Err(JsValue::from_str(&format!(
                        "unsupported operation type: {}",
                        key_str
                    )));
                }
            };
            let op_side = match value_str.as_str() {
                "Left" => CoreOperationSide::Left,
                "Right" => CoreOperationSide::Right,
                _ => {
                    return Err(JsValue::from_str(&format!(
                        "unsupported operation side: {}",
                        value_str
                    )));
                }
            };
            map.insert(op_type, op_side);
        }
        Ok(map)
    }

    fn parse_matrix(values: &JsValue) -> Result<Vec<Vec<f32>>, JsValue> {
        if !js_sys::Array::is_array(values) {
            return Err(JsValue::from_str("values must be a 2D array"));
        }

        let rows = js_sys::Array::from(values);
        let mut matrix = Vec::with_capacity(rows.length() as usize);
        for row in rows.iter() {
            if !js_sys::Array::is_array(&row) {
                return Err(JsValue::from_str("each row must be an array"));
            }
            let row_array = js_sys::Array::from(&row);
            let mut out_row = Vec::with_capacity(row_array.length() as usize);
            for value in row_array.iter() {
                let number = value
                    .as_f64()
                    .ok_or_else(|| JsValue::from_str("matrix value must be a number"))?;
                out_row.push(number as f32);
            }
            matrix.push(out_row);
        }

        Ok(matrix)
    }

    fn matrix_to_js_array(matrix: &[Vec<f32>]) -> js_sys::Array {
        let out = js_sys::Array::new();
        for row in matrix {
            let row_array = js_sys::Array::new();
            for &value in row {
                row_array.push(&JsValue::from_f64(value as f64));
            }
            out.push(&row_array);
        }
        out
    }

    fn usize_slice_to_js_array(values: &[usize]) -> js_sys::Array {
        let out = js_sys::Array::new();
        for &value in values {
            out.push(&JsValue::from_f64(value as f64));
        }
        out
    }

    fn vec_to_uint8array(data: &[u8]) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(data)
    }

    fn parse_preset(preset: &str) -> Result<ParameterPreset, JsValue> {
        preset.parse::<ParameterPreset>().map_err(|_| {
            JsValue::from_str(&format!(
                "unsupported preset: {}. supported: {:?}",
                preset,
                ParameterPreset::supported()
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
            ))
        })
    }

    fn map_high_error(err: HighError) -> JsValue {
        let message = match err {
            HighError::KeyIdMismatch => "ciphertext key_id does not match secret key",
            HighError::ParameterMismatch => "ciphertext parameters do not match secret key",
            HighError::InvalidCiphertext => "ciphertext is invalid",
            HighError::InvalidMulSideLeft => "ciphertext operation_side must be Left for mul",
            HighError::InvalidMulSideRight => "ciphertext operation_side must be Right for mul",
        };
        JsValue::from_str(message)
    }

    fn map_ndarray_error(err: NdarrayError) -> JsValue {
        let message = match err {
            NdarrayError::ShapeMismatch => "cndarray shape mismatch",
            NdarrayError::KeyIdMismatch => "cndarray key_id mismatch",
            NdarrayError::ParameterMismatch => "cndarray parameter mismatch",
            NdarrayError::InvalidCiphertext => "cndarray contains invalid ciphertext",
            NdarrayError::InvalidMulSideLeft => {
                "cndarray left operand for mul must be below VALUE_LIMITATION"
            }
            NdarrayError::InvalidMulSideRight => {
                "cndarray right operand for mul must be at or above VALUE_LIMITATION"
            }
        };
        JsValue::from_str(message)
    }

    #[wasm_bindgen(js_name = "availablePresets")]
    pub fn available_presets() -> js_sys::Array {
        let arr = js_sys::Array::new();
        for p in ParameterPreset::supported() {
            arr.push(&JsValue::from_str(p.as_str()));
        }
        arr
    }

    #[wasm_bindgen(js_name = "encodeEncryptMatrix")]
    pub fn encode_encrypt_matrix(
        pk: &PublicKey,
        values: JsValue,
        operation_lock: JsValue,
    ) -> Result<Cndarray, JsValue> {
        let matrix = parse_matrix(&values)?;
        let operation = parse_operation_lock(&operation_lock)?;
        let encrypted = core_encode_encrypt_matrix(&pk.inner, &matrix, operation, None)
            .map_err(map_ndarray_error)?;
        Ok(Cndarray { inner: encrypted })
    }

    #[wasm_bindgen(js_name = "decodeDecryptMatrix")]
    pub fn decode_decrypt_matrix(
        sk: &SecretKey,
        cndarray: &Cndarray,
    ) -> Result<js_sys::Array, JsValue> {
        let decoded =
            core_decode_decrypt_matrix(&sk.inner, &cndarray.inner).map_err(map_ndarray_error)?;
        Ok(matrix_to_js_array(&decoded))
    }

    #[wasm_bindgen(js_name = "keySwitchCndarray")]
    pub fn key_switch_cndarray(
        ksk: &KeySwitchKey,
        original: &Cndarray,
    ) -> Result<Cndarray, JsValue> {
        let switched =
            core_key_switch_ndarray(&ksk.inner, &original.inner).map_err(map_ndarray_error)?;
        Ok(Cndarray { inner: switched })
    }

    // Expose preset identifiers as properties: wasm.ParameterPreset.low -> "low"
    #[wasm_bindgen(js_name = "ParameterPreset")]
    pub fn parameter_preset() -> js_sys::Object {
        // Build an object with properties like { low: "low", ... } so JS can use
        // ParameterPreset.low
        let obj = js_sys::Object::new();
        for p in ParameterPreset::supported() {
            let key = JsValue::from_str(p.as_str());
            let val = JsValue::from_str(p.as_str());
            let _ = js_sys::Reflect::set(&obj, &key, &val);
        }
        obj
    }

    #[wasm_bindgen(js_name = "Parameter")]
    pub struct Parameter {
        inner: CoreParameter,
    }

    #[wasm_bindgen]
    impl Parameter {
        #[wasm_bindgen(js_name = "fromPreset")]
        pub fn from_preset(preset: String) -> Result<Parameter, JsValue> {
            let preset = parse_preset(&preset)?;
            Ok(Parameter {
                inner: CoreParameter::from_preset(preset),
            })
        }
    }

    #[wasm_bindgen(js_name = "SecretKey")]
    pub struct SecretKey {
        inner: CoreSecretKey,
    }

    #[wasm_bindgen(js_name = "PublicKey")]
    pub struct PublicKey {
        inner: CorePublicKey,
    }

    #[wasm_bindgen(js_name = "Ciphertext")]
    pub struct Ciphertext {
        inner: CoreCiphertext,
    }

    #[wasm_bindgen(js_name = "Cndarray")]
    pub struct Cndarray {
        inner: CoreCndarray,
    }

    #[wasm_bindgen(js_name = "EvalKey")]
    pub struct EvalKey {
        inner: CoreEvalKey,
    }

    #[wasm_bindgen(js_name = "KeySwitchKey")]
    pub struct KeySwitchKey {
        inner: CoreKeySwitchKey,
    }

    #[wasm_bindgen]
    impl SecretKey {
        #[wasm_bindgen(constructor)]
        pub fn new(parameter: &Parameter) -> Result<SecretKey, JsValue> {
            Ok(SecretKey {
                inner: CoreSecretKey::new(&parameter.inner),
            })
        }

        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, JsValue> {
            let sk: CoreSecretKey =
                bincode::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(SecretKey { inner: sk })
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
            let bytes =
                bincode::serialize(&self.inner).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(vec_to_uint8array(&bytes))
        }

        #[wasm_bindgen(js_name = "toPublicKey")]
        pub fn to_public_key(&self, parameter: &Parameter) -> Result<PublicKey, JsValue> {
            let pk = CorePublicKey::new(&parameter.inner, &self.inner);
            Ok(PublicKey { inner: pk })
        }

        #[wasm_bindgen(js_name = "decodeDecrypt")]
        pub fn decode_decrypt(&self, ciphertext: &Ciphertext) -> Result<f64, JsValue> {
            let decoded = self
                .inner
                .decode_decrypt(&ciphertext.inner)
                .map_err(map_high_error)?;
            Ok(decoded as f64)
        }
    }

    #[wasm_bindgen]
    impl PublicKey {
        #[wasm_bindgen(constructor)]
        pub fn new(parameter: &Parameter, seckey: &SecretKey) -> PublicKey {
            let pk = CorePublicKey::new(&parameter.inner, &seckey.inner);
            PublicKey { inner: pk }
        }

        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, JsValue> {
            let pk: CorePublicKey =
                bincode::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(PublicKey { inner: pk })
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
            let bytes =
                bincode::serialize(&self.inner).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(vec_to_uint8array(&bytes))
        }

        #[wasm_bindgen(js_name = "encodeEncrypt")]
        pub fn encode_encrypt(
            &self,
            value: f64,
            operation_lock: JsValue,
        ) -> Result<Ciphertext, JsValue> {
            let operation = parse_operation_lock(&operation_lock)?;
            let ciphertext = self.inner.encode_encrypt(value as f32, operation, None);
            Ok(Ciphertext { inner: ciphertext })
        }
    }

    #[wasm_bindgen]
    impl Ciphertext {
        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(bytes: &[u8]) -> Result<Ciphertext, JsValue> {
            let ct: CoreCiphertext =
                bincode::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(Ciphertext { inner: ct })
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
            let bytes =
                bincode::serialize(&self.inner).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(vec_to_uint8array(&bytes))
        }

        #[wasm_bindgen(js_name = "add")]
        pub fn add(
            &self,
            other: &Ciphertext,
            parameter: &Parameter,
        ) -> Result<Ciphertext, JsValue> {
            let summed = self
                .inner
                .add(&other.inner, &parameter.inner)
                .map_err(map_high_error)?;
            Ok(Ciphertext { inner: summed })
        }

        #[wasm_bindgen(js_name = "mul")]
        pub fn mul(&self, other: &Ciphertext, eval_key: &EvalKey) -> Result<Ciphertext, JsValue> {
            let product = self
                .inner
                .mul(&other.inner, &eval_key.inner)
                .map_err(map_high_error)?;
            Ok(Ciphertext { inner: product })
        }
    }

    #[wasm_bindgen]
    impl Cndarray {
        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(bytes: &[u8]) -> Result<Cndarray, JsValue> {
            let cndarray =
                CoreCndarray::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(Cndarray { inner: cndarray })
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
            let bytes = self
                .inner
                .serialize()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(vec_to_uint8array(&bytes))
        }

        #[wasm_bindgen(js_name = "ndim")]
        pub fn ndim(&self) -> usize {
            self.inner.ndim()
        }

        #[wasm_bindgen(js_name = "getShape")]
        pub fn get_shape(&self) -> js_sys::Array {
            usize_slice_to_js_array(self.inner.get_shape())
        }

        #[wasm_bindgen(js_name = "add")]
        pub fn add(&self, other: &Cndarray, parameter: &Parameter) -> Result<Cndarray, JsValue> {
            let out = self
                .inner
                .add(&other.inner, &parameter.inner)
                .map_err(map_ndarray_error)?;
            Ok(Cndarray { inner: out })
        }

        #[wasm_bindgen(js_name = "sub")]
        pub fn sub(&self, other: &Cndarray, parameter: &Parameter) -> Result<Cndarray, JsValue> {
            let out = self
                .inner
                .sub(&other.inner, &parameter.inner)
                .map_err(map_ndarray_error)?;
            Ok(Cndarray { inner: out })
        }

        #[wasm_bindgen(js_name = "mul")]
        pub fn mul(&self, other: &Cndarray, eval_key: &EvalKey) -> Result<Cndarray, JsValue> {
            let out = self
                .inner
                .mul(&other.inner, &eval_key.inner)
                .map_err(map_ndarray_error)?;
            Ok(Cndarray { inner: out })
        }

        #[wasm_bindgen(js_name = "matmul")]
        pub fn matmul(
            &self,
            other: &Cndarray,
            parameter: &Parameter,
            eval_key: &EvalKey,
        ) -> Result<Cndarray, JsValue> {
            let out = self
                .inner
                .matmul(&other.inner, &parameter.inner, &eval_key.inner)
                .map_err(map_ndarray_error)?;
            Ok(Cndarray { inner: out })
        }
    }

    #[wasm_bindgen]
    impl EvalKey {
        #[wasm_bindgen(constructor)]
        pub fn new(parameter: &Parameter, seckey: &SecretKey) -> EvalKey {
            let ek = CoreEvalKey::new(&parameter.inner, &seckey.inner);
            EvalKey { inner: ek }
        }
    }

    #[wasm_bindgen]
    impl KeySwitchKey {
        #[wasm_bindgen(constructor)]
        pub fn new(
            parameter: &Parameter,
            original_sk: &SecretKey,
            target_pk: &PublicKey,
        ) -> KeySwitchKey {
            let ksk = CoreKeySwitchKey::new(&parameter.inner, &original_sk.inner, &target_pk.inner);
            KeySwitchKey { inner: ksk }
        }

        #[wasm_bindgen(js_name = "keySwitch")]
        pub fn key_switch(&self, original: &Ciphertext) -> Ciphertext {
            let switched = self.inner.key_switch(&original.inner);
            Ciphertext { inner: switched }
        }
    }
}
