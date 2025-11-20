# gong_rsa-25

Reference: _Jonathan Katz and Yehuda Lindell. 2014. Introduction to Modern Cryptography, Second Edition (2nd. ed.). Chapman & Hall/CRC_.

## Plain RSA
Let GenRSA be a algorithm that, on input 1n, outputs a modulus N that is the product of two n-bit primes (except with negligible probability), along with integers e, d satisfying $e.d = 1 mod φ(N)$. Key generation in plain RSA involves simply running GenRSA, and outputting ⟨N, e⟩ as the public key and ⟨N, d⟩ as the private key. To sign a message $m ∈Z^*_N$, the signer computes $σ := [m^d mod N ]$. Verification of a signature σ on a message m with respect to the public key ⟨N, e⟩ is carried out by checking whether $m = σ^e mod N$.

## RSA-FDH
Specify as part of the public key a (deterministic) function H with certain cryptographic properties mapping messages to $Z^*_N$; the signature on a message m will be $σ := [H(m)^d mod N ]$, and verification of the signature σ on the message m will be done by checking whether $σ^e = H(m) mod N$ .