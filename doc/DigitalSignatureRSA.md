# PQC: Digital Signature - RSA

**Hemingway Bridge:**

- [ ]  Provide more detailed Theory for RSA

---

# Theory:
## Plain RSA
Let GenRSA be a algorithm that, on input $1^n$, outputs a modulus N that is the product of two n-bit primes (except with negligible probability), along with integers e, d satisfying $e.d = 1 \textnormal{mod} φ(N)$. Key generation in plain RSA involves simply running GenRSA, and outputting ⟨N, e⟩ as the public key and ⟨N, d⟩ as the private key. To sign a message $m ∈Z^*_N$, the signer computes $σ := [m^d \textnormal{mod} N ]$. Verification of a signature σ on a message m with respect to the public key ⟨N, e⟩ is carried out by checking whether $m = σ^e \textnormal{mod} N$.

## RSA-FDH
Specify as part of the public key a (deterministic) function H with certain cryptographic properties mapping messages to $Z^*_N$; the signature on a message m will be $σ := [H(m)^d \textnormal{mod} N ]$, and verification of the signature σ on the message m will be done by checking whether $σ^e = H(m) \textnormal{mod} N$.

# Code:

## Mathematical Functions:

### Extended Euclidean Algorithm:

Given $a$ and $b$, returns $(gcd, x, y)$ such that: $a * x + b * y = gcd(a, b)$

```rust
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
```

## Plain RSA:

The algorithm is used for testing only.

### Key generation:

Generate the value of $N$ based on two random primes

```rust
let p1 = BigUint::from_bytes_be(&Generator::new_prime(sec_param as usize).to_bytes_be());
let p2 = BigUint::from_bytes_be(&Generator::new_prime(sec_param as usize).to_bytes_be());

let n: num_bigint::BigUint = &p1 * &p2;
```

Calculate $\phi(N) = (p_1 - 1)(p_2 - 1)$

```rust
let phi_n = (&p1 - BigUint::one()) * (&p2 - BigUint::one());
```

Calculate two integer $e$ and $d$ such that $e.d = 1 mod(\phi(N))$

The lazy way is to assign $d$ to one of the prime number generated (called $p_1$). Since $p_1$ is a prime number, it and $\phi(N)$will very likely be co-prime with one another (except when $p_2 = 3$ and $p_1 =2$).

```rust
let d = p1; // p1 is moved here and can no longer be used as p1
```

Using the Extended Euclidean Algorithm to calculate $e$ based on $d$ and $\phi(N)$. Since the result can be a negative number, wrap it in $Z_N$

```rust
let egcd = extended_gcd(&d, &phi_n);
let e = if egcd.x < BigInt::zero() {
		(egcd.x + &phi_n.to_bigint().unwrap()).to_biguint().unwrap(
} else {
		egcd.x.to_biguint().unwrap()
};
```

Return the RSA key set

```rust
RSAKeyPair { n, e, d }
```

### Sign a message:

Calculate and return the signature $\sigma = m^d mod(N)$

```rust
message.modpow(&private_key.d, &private_key.n)
```

### Verify a message:

Return `true` iff $m == \sigma^e mod(N)$. This means the signature is valid. 

```rust
signature.modpow(&public_key.e, &public_key.n) == *message
```

### Test:

This simple RSA inputs a 8-bit unsigned integer (from 0 to 255).

It also uses a very simple secure parameter `const EZ_SECURE_PARAM: u8 = 8` 

The program showcases two attempts of forgery attacks: Message Forgery and Signature Forgery

```rust
fn test_plain_rsa() {
    println!("\n\n--- RSA plain: Original Message and Signature ---");
    let rsa_key_pair = plain_rsa::gen_rsa(EZ_SECURE_PARAM);

    let public_key = RSAPublicKey {
        n: rsa_key_pair.n.clone(),
        e: rsa_key_pair.e.clone(),
    };
    let private_key = RSAPrivateKey {
        n: rsa_key_pair.n.clone(),
        d: rsa_key_pair.d.clone(),
    };

    let message: u8 = rand::rng().random_range(0..255);
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
```

## RSA-FDH:

The algorithm is used for testing only.

This algorithm is proved to be more secure than the plain one. However, some parts of the latter can be re-used to develop it.

### Construction:

Create a `struct` for the RSAFDH. Here, the public key is accessible by everyone (there will be a getter function for it). In contrast, the private key is strictly hidden.

```rust
pub struct RSAFDH {
    pub rsa_pk: RSAPublicKey,
    rsa_sk: RSAPrivateKey,
}
```

The methods for this struct will be written in the `impl` block.

```rust
impl RSAFDH {

}
```

### Key generation:

Inputs the security parameter to create the key.

The fundamental is identical to the plain RSA algorithm.

We will use the SHA-256 for the hash function $H$.

```rust
pub fn new(secure_param: u8) -> Self {
    let rsa_key_pair = rsa::plain_rsa::gen_rsa(secure_param);
    let rsa_pk = RSAPublicKey {
        n: rsa_key_pair.n.clone(),
        e: rsa_key_pair.e.clone(),
    };
    let rsa_sk = RSAPrivateKey {
        n: rsa_key_pair.n.clone(),
        d: rsa_key_pair.d.clone(),
    };
    RSAFDH { rsa_pk, rsa_sk }
}
```

### Sign a message:

The message is hashed before getting signed.

The hash contains blocks of 8-bit unsigned integers; thus, it is signed block-by-block.

```rust
pub fn sign_rsa(&self, message: u8) -> Vec<BigUint> {
    let hash = Sha256::digest(message.to_le_bytes());
    let h_msg: Vec<u8> = hash.to_vec();

    let mut signed_h_msg: Vec<BigUint> = Vec::new();
    for i in 0..h_msg.len() {
        let sig_i = crate::rsa::plain_rsa::sign_rsa(&h_msg[i].to_biguint().unwrap(), &self.rsa_sk);
        signed_h_msg.push(sig_i);
    }
    signed_h_msg
}
```

### Verify a message:

Input a message $m$ and the signature $\sigma$, return `true` iff the signature and message are valid.

The quickest check is length-check. If the two lengths do not match, either one or both of them are forged.

Since the hashed message are signed block-by-block, the code also compare them block-by-block. For each block, calculate if $H(m) == \sigma^e mod (N)$.

```rust
pub fn verify_rsa(&self, message: u8, signature: &Vec<BigUint>) -> bool {
    let v_h_msg = Sha256::digest(message.to_le_bytes()).to_vec();

    if v_h_msg.len() != signature.len() {
        println!("Signature length does not match");
        return false;
    }

    for i in 0..signature.len() {
        if
            signature[i].modpow(&self.rsa_pk.e, &self.rsa_pk.n) !=
            v_h_msg[i].to_biguint().unwrap() % &self.rsa_pk.n
        {
            println!("The signature does not match");
            return false;
        }
    }
    true
}
```

### Utilities:

Since the public key is “public”. There is a getter function allowing users to get it.

```rust
pub fn get_public_key(&self) -> RSAPublicKey {
    RSAPublicKey {
        n: self.rsa_pk.n.clone(),
        e: self.rsa_pk.e.clone(),
    }
}
```

The users can also query the hash message as much as they want. 

However, this is a very plain SHA256 hash scheme, which can be improved later on (i.e., changing to the HMAC scheme)

```rust
pub fn query_hash(&self, message: u8) -> Vec<u8> {
    let hash = Sha256::digest(message.to_le_bytes());
    hash.to_vec()
}
```

### Test:

This simple RSA inputs a 8-bit unsigned integer (from 0 to 255).

It also uses a very simple secure parameter `const EZ_SECURE_PARAM: u8 = 8` 

The program showcases an attempt of forgery attacks: Message Forgery.

```rust
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
```

Since the message is hashed before signed, the target of the signing algorithm remains to be a `Vec` of 8-bit unsigned integers regardless of the message. Thus, the algorithm can be modified to inputs different types of data (ideally `String`).