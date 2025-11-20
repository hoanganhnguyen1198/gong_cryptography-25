pub use crate::rsa::*;
use sha2::{Digest, Sha256};

pub struct RSAFDH {
    pub rsa_pk: RSAPublicKey,
    rsa_sk: RSAPrivateKey,
}

impl RSAFDH {
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

    pub fn sign_rsa(&self, message: u8) -> Vec<BigUint> {
        let hash = Sha256::digest(message.to_le_bytes());
        let h_msg: Vec<u8> = hash.to_vec();

        let mut signed_h_msg: Vec<BigUint> = Vec::new();
        for i in 0..h_msg.len() {
            let sig_i =
                crate::rsa::plain_rsa::sign_rsa(&h_msg[i].to_biguint().unwrap(), &self.rsa_sk);
            signed_h_msg.push(sig_i);
        }
        signed_h_msg
    }

    pub fn verify_rsa(&self, message: u8, signature: &Vec<BigUint>) -> bool {
        let v_h_msg = Sha256::digest(message.to_le_bytes()).to_vec();

        if v_h_msg.len() != signature.len() {
            println!("Signature length does not match");
            return false;
        }

        for i in 0..signature.len() {
            if signature[i].modpow(&self.rsa_pk.e, &self.rsa_pk.n)
                != v_h_msg[i].to_biguint().unwrap() % &self.rsa_pk.n
            {
                println!("The signature does not match");
                return false;
            }
        }
        true
    }

    pub fn query_hash(&self, message: u8) -> Vec<u8> {
        let hash = Sha256::digest(message.to_le_bytes());
        hash.to_vec()
    }

    pub fn get_public_key(&self) -> RSAPublicKey {
        RSAPublicKey {
            n: self.rsa_pk.n.clone(),
            e: self.rsa_pk.e.clone(),
        }
    }
}
