use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Zero, One};


pub struct ExtendedGCD {
    pub gcd: BigUint,
    pub x: BigInt,
    pub y: BigInt,
}

/// Euclidean Algorithm
/// ### Description:
/// Returns gcd(a, b)
pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while b != BigUint::ZERO {
        let tmp = b;
        b = a % &tmp;
        a = tmp;
    }
    a
}

/// Extended Euclidean Algorithm
/// ### Description:
/// Given a and b, returns (gcd, x, y) such that: a * x + b * y = gcd(a, b)
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> ExtendedGCD {
    if *a == BigUint::ZERO {
        return ExtendedGCD { gcd: b.clone(), x: BigInt::zero(), y: BigInt::one() };
    }

    let mut old_remainder = a.clone();
    let mut remainder = b.clone();

    let mut old_x: BigInt = BigInt::one();
    let mut x: BigInt = BigInt::zero();

    let mut old_y: BigInt = BigInt::zero();
    let mut y: BigInt = BigInt::one();

    let mut quotient: BigUint;
    
    while remainder != BigUint::ZERO {
        quotient = &old_remainder / &remainder;

        let tmp_remainder = remainder.clone();
        remainder = old_remainder - &quotient * remainder;
        old_remainder = tmp_remainder;

        let tmp_x = x.clone();
        x = old_x - quotient.to_bigint().unwrap() * x;
        old_x = tmp_x;

        let tmp_y = y.clone();
        y = old_y - quotient.to_bigint().unwrap() * y;
        old_y = tmp_y;
    }

    ExtendedGCD {
        gcd: old_remainder,
        x: old_x,
        y: old_y,
    }
}

pub mod rsa {
    pub use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
    pub use num_primes::Generator;
    pub use num_traits::{One, Zero};

    pub struct RSAKeyPair {
        pub n: BigUint,
        pub e: BigUint,
        pub d: BigUint,
    }

    pub struct RSAPublicKey {
        pub n: BigUint,
        pub e: BigUint,
    }

    pub struct RSAPrivateKey {
        pub n: BigUint,
        pub d: BigUint,
    }

    pub mod plain_rsa;
}