use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use lazy_static::lazy_static;

// Define the prime p and base g as global values using lazy_static
lazy_static! {
    pub static ref P: BigUint = BigUint::parse_bytes(
        b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327fffffffffffffffff", 16).unwrap();
    pub static ref G: BigUint = BigUint::from(2u32);
}

pub fn diffie_hellman() -> (BigUint, BigUint){
    let mut rng = thread_rng();    
    let a = rng.gen_biguint_below(&P);// Generate random integers modulo P
    let result_a = G.modpow(&a, &P);// Calculate g^a mod p
    return (a,result_a);
}

// Function to test random integers and modpow calculation
pub fn test33() {
    let (secret_a, public_a) = diffie_hellman();
    let (secret_b, public_b) = diffie_hellman();
    
    // Calculate g^ab mod p (Shared secret)
    let result_ab = public_a.modpow(&secret_a, &P);
    let result_ba = public_b.modpow(&secret_b, &P);

    // Assertions to check if the values are valid
    assert!(result_ab == result_ba,"Shared secret generation failure");
    println!("Shared Secret: {}", result_ab);
}
