use crate::*;

pub fn prettify_signature(signature: &Vec<BigUint>) -> String {
    let mut sig_str = String::new();
    for sig_i in signature {
        sig_str.push_str(&format!("{:x} ", sig_i));
    }
    sig_str
}