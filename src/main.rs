use rand::Rng;
// use std::io;
// use modular::*;
use num_bigint::{BigUint, ToBigUint};

use gong_rsa_25::rsa::plain_rsa;
use gong_rsa_25::rsa::fdh_rsa;
use gong_rsa_25::rsa::*;

// use sha2::{Digest, Sha256};

const EZ_SECURE_PARAM: u8 = 8;

fn main() {
    test_plain_rsa();

    test_fdh_rsa();
}

fn test_plain_rsa() {
    println!("\n\n--- RSA plain: Original Message and Signature ---");
    let rsa_key_pair = plain_rsa::gen_rsa(EZ_SECURE_PARAM);

    println!(
        "The RSA key pair is: n = {}, e = {}, d = {}",
        &rsa_key_pair.n, &rsa_key_pair.e, &rsa_key_pair.d
    );

    // assert_eq!((&rsa_key_pair.e * &rsa_key_pair.d) % &rsa_key_pair.n, BigUint::one());

    let public_key = RSAPublicKey {
        n: rsa_key_pair.n.clone(),
        e: rsa_key_pair.e.clone(),
    };
    let private_key = RSAPrivateKey {
        n: rsa_key_pair.n.clone(),
        d: rsa_key_pair.d.clone(),
    };

    let message: u8 = rand::rng().random_range(0..255);
    // let message: u8 = 42;
    println!("The original message is: {}", message);

    let signature: BigUint = plain_rsa::sign_rsa(&message.to_biguint().unwrap(), &private_key);
    println!("The signature is: {}", &signature);

    if plain_rsa::verify_rsa(&message.to_biguint().unwrap(), &signature, &public_key) {
        println!("The message and the signature are valid!");
    } else {
        println!("The message and the signature are invalid!");
    }

    println!("\n\n--- RSA plain Forgery Attack: Message Forgery ---");
    let forged_message: u8 = rand::rng().random_range(0..255);
    println!("The forged message is: {}", forged_message);

    if plain_rsa::verify_rsa(
        &forged_message.to_biguint().unwrap(),
        &signature,
        &public_key,
    ) {
        println!("The forged message is valid!");
    } else {
        println!("The forged message is invalid!");
    }

    println!("\n\n--- RSA plain Forgery Attack: Signature Forgery ---");
    let forged_signature: u16 = rand::rng().random_range(0..u16::MAX);
    println!("The forged signature is: {}", forged_signature);
    if plain_rsa::verify_rsa(
        &message.to_biguint().unwrap(),
        &forged_signature.to_biguint().unwrap(),
        &public_key,
    ) {
        println!("The forged signature is valid!");
    } else {
        println!("The forged signature is invalid!");
    }
}

fn test_fdh_rsa() {
    println!("\n\n--- RSA-FDH: Original Message and Signature ---");
    // let message: u8 = rand::rng().random_range(0..255);
    let message: u8 = 84;
    println!("The original message is: {}", message);

    let rsa_fdh = fdh_rsa::RSAFDH::new(EZ_SECURE_PARAM);

    let signature: Vec<BigUint> = rsa_fdh.sign_rsa(message);
    println!(
        "The signature is: {}",
        prettify_signature(&signature)
    );

    if rsa_fdh.verify_rsa(message, &signature) {
        println!("The message and the signature are valid!");
    } else {
        println!("The message and the signature are invalid!");
    }

    println!("\n\n--- RSA-FDH Forgery Attack: Message Forgery ---");
    let forged_message: u8 = rand::rng().random_range(0..255);
    println!("The forged message is: {}", forged_message);

    if rsa_fdh.verify_rsa(forged_message, &signature) {
        println!("The forged message is valid!");
    } else {
        println!("The forged message is invalid!");
    }
}

fn prettify_signature(signature: &Vec<BigUint>) -> String {
    let mut sig_str = String::new();
    for sig_i in signature {
        sig_str.push_str(&format!("{:x} ", sig_i));
    }
    sig_str
}