pub fn check_cleartext_range(clear_num: f32, message_value_range: (f32, f32)) -> f32 {
    // assume a < b
    let cleartext_range: f32 = message_value_range.1 - message_value_range.0;

    let cleartext: f32 = if clear_num >= message_value_range.1 {
        ((clear_num - message_value_range.0) % cleartext_range) + message_value_range.0
    } else if clear_num < message_value_range.0 {
        message_value_range.1 - ((message_value_range.0 - clear_num) % cleartext_range)
    } else {
        clear_num
    };

    cleartext
}

pub fn identity_function(num: f32) -> f32 {
    num
}

pub fn div_square_function(num1: f32, num2: f32, message_value_range: (f32, f32)) -> f32 {
    check_cleartext_range(num1 * num1 / num2, message_value_range)
}

pub fn relu_function(num: f32) -> f32 {
    if num > 0.0 { num } else { 0.0 }
}
