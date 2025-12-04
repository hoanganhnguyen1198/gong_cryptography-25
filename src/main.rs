use rand::Rng;
// use std::io;
// use modular::*;
use num_bigint::{BigUint, ToBigUint};

use gong_rsa_25::rsa::fdh_rsa;
use gong_rsa_25::rsa::plain_rsa;
use gong_rsa_25::rsa::*;
use gong_rsa_25::utils::*;

// use sha2::Sha256;
use schnorr_rs;

const EZ_SECURE_PARAM: u8 = 8;

fn main() {
    // Test Plain RSA
    // test_plain_rsa();

    // Test RSA-FDH
    // test_fdh_rsa();

    // Schnorr Signature Scheme
    // test_lib_schnorr_signature();

    // Schnorr Identification Protocol
    // test_lib_schnorr_identification_protocol();
}

fn _test_plain_rsa() {
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

    let message: u8 = rand::thread_rng().gen_range(0..255);
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
    let forged_message: u8 = rand::thread_rng().gen_range(0..255);
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
    let forged_signature: u16 = rand::thread_rng().gen_range(0..u16::MAX);
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
fn _test_fdh_rsa() {
    println!("\n\n--- RSA-FDH: Original Message and Signature ---");
    // let message: u8 = rand::rng().random_range(0..255);
    let message: u8 = 84;
    println!("The original message is: {}", message);

    let rsa_fdh = fdh_rsa::RSAFDH::new(EZ_SECURE_PARAM);

    let signature: Vec<BigUint> = rsa_fdh.sign_rsa(message);
    println!("The signature is: {}", prettify_signature(&signature));

    if rsa_fdh.verify_rsa(message, &signature) {
        println!("The message and the signature are valid!");
    } else {
        println!("The message and the signature are invalid!");
    }

    println!("\n\n--- RSA-FDH Forgery Attack: Message Forgery ---");
    let forged_message: u8 = rand::thread_rng().gen_range(0..255);
    println!("The forged message is: {}", forged_message);

    if rsa_fdh.verify_rsa(forged_message, &signature) {
        println!("The forged message is valid!");
    } else {
        println!("The forged message is invalid!");
    }
}

fn _test_lib_schnorr_signature() {
    println!("\n\n--- Schnorr Signature Scheme ---");
    // Specify the common parameters from Integer field elements.
    let scheme =
        schnorr_rs::signature_scheme::<sha2::Sha256>("1623299", "811649", "1109409").unwrap();

    let rng = &mut rand::thread_rng();

    let (key, public_key) = scheme.generate_key(rng);
    let message = "hello world".as_bytes();
    let signature = scheme.sign(rng, &key, &public_key, message);

    let serialized_signature: Vec<u8> = signature.clone().into();
    println!("Signature: {:?}", &hex::encode(&serialized_signature));

    let serialised_key: Vec<u8> = key.clone().into();
    println!("Private Key: {:?}", &hex::encode(&serialised_key));

    let serialised_public_key: Vec<u8> = (&public_key).into();
    println!("Public Key: {:?}", &hex::encode(&serialised_public_key));

    assert!(scheme.verify(&public_key, message, &signature));
    println!("The Schnorr Signature is valid!");
}
fn _test_lib_schnorr_identification_protocol() {
    println!("\n\n--- Schnorr Identification Protocol ---");
    // Specify the common parameters from Integer field elements.
    let protocol = schnorr_rs::identification_protocol("1623299", "811649", "1109409").unwrap();

    let rng = &mut rand::thread_rng();

    // Specify the signature scheme used in the protocol. It is not a must to use the scheme provided
    // by this crate, as long as the signer and verifier implements the trait `signature::RandomizedDigestSigner`
    // and `signature::DigestVerifier` respectively.
    let signature_scheme =
        schnorr_rs::signature_scheme::<sha2::Sha256>("1623299", "811649", "1109409").unwrap();
    let (signing_key, public_key) = signature_scheme.generate_key(rng);
    let signer = schnorr_rs::Signer {
        scheme: &signature_scheme,
        key: &signing_key,
        pub_key: &public_key,
    };
    let verifier = schnorr_rs::Verifier {
        scheme: &signature_scheme,
        key: &public_key,
    };

    // An identity represented by BigUint
    let i = num_bigint::BigUint::from(123u32);

    // User interacts with issuer to get a certificate
    let (iss_secret, iss_params) = protocol.issue_params(rng, i.clone());
    let cert = protocol.issue_certificate(rng, &signer, iss_params);

    // User presents the certificate to the verifier
    let (ver_secret, ver_req) = protocol.verification_request(rng, cert);

    // Verifier challenges the user's knowledge of the secret
    let challenge = protocol
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();

    // User responds to the challenge
    let ver_res = protocol.verification_response(challenge.clone(), iss_secret, ver_secret);

    // Verifier verifies the response
    assert!(protocol.verification(ver_req, challenge, ver_res));
    println!("Schnorr Identification Protocol executed successfully!");
}


