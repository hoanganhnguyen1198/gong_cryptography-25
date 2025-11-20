
pub use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
pub use num_primes::Generator;
pub use num_traits::{One, Zero};

pub use crate::rsa::*;
pub use crate::{extended_gcd, gcd};

pub fn gen_rsa(sec_param: u8) -> RSAKeyPair {
    let p1 = BigUint::from_bytes_be(&Generator::new_prime(sec_param as usize).to_bytes_be());
    let p2 = BigUint::from_bytes_be(&Generator::new_prime(sec_param as usize).to_bytes_be());

    let n: num_bigint::BigUint = &p1 * &p2;

    let phi_n = (&p1 - BigUint::one()) * (&p2 - BigUint::one());

    let d = p1; // p1 is moved here and can no longer be used as p1

    assert_eq!(
        gcd(&d, &phi_n),
        BigUint::one(),
        "d and φ(n) are not coprime!"
    );

    let egcd = extended_gcd(&d, &phi_n);
    let e = if egcd.x < BigInt::zero() {
        (egcd.x + &phi_n.to_bigint().unwrap()).to_biguint().unwrap()
    } else {
        egcd.x.to_biguint().unwrap()
    };

    assert_eq!(
        (&e * &d) % &phi_n,
        BigUint::one(),
        "e and d are not multiplicative inverses modulo φ(n)!"
    );

    RSAKeyPair { n, e, d }
}

pub fn sign_rsa(message: &BigUint, private_key: &RSAPrivateKey) -> BigUint {
    message.modpow(&private_key.d, &private_key.n)
}

pub fn verify_rsa(message: &BigUint, signature: &BigUint, public_key: &RSAPublicKey) -> bool {
    signature.modpow(&public_key.e, &public_key.n) == *message
}
