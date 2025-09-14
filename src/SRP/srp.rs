use num_bigint::{BigUint, RandBigInt};
use sha2::{Digest, Sha256};
use rand::Rng;
use std::str;

// SRP parameters
const N: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327fffffffffffffffff";
const G: &str = "2";
const K: &str = "3";
const I: &str = "bibekghosh2015@gmail.com";
const P: &str = "BIBEKgho16@";
  
// Function to convert a hex string to a big integer
fn hex_to_bigint(hex: &str) -> num_bigint::BigUint {
    num_bigint::BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()
}

// Function to compute the SHA256 hash and convert the output to a big integer
fn sha256_to_bigint(data: &[u8]) -> num_bigint::BigUint {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    num_bigint::BigUint::from_bytes_be(&result)
}

// Server: Generate salt, v
fn server_setup() -> (u64, num_bigint::BigUint) {
    let mut rng = rand::thread_rng();

    // Generate a random salt
    let salt: u64 = rng.gen();
    
    // Generate xH=SHA256(salt|password)
    let xh = sha256_to_bigint(format!("{}{}", salt, P).as_bytes());

    // Generate v=g**x % N
    let v = hex_to_bigint(G).modpow(&xh, &hex_to_bigint(N));

    (salt, v)
}

// Client -> Server: Send I, A
fn client_compute_A() -> num_bigint::BigUint {
    let mut rng = rand::thread_rng();
    let a = rng.gen_biguint_below(&hex_to_bigint(N));

    // Compute A = g**a % N
    hex_to_bigint(G).modpow(&num_bigint::BigUint::from(a), &hex_to_bigint(N))
}

// Server -> Client: Send salt, B
fn server_compute_B(v: &num_bigint::BigUint) -> num_bigint::BigUint {
    let mut rng = rand::thread_rng();
    let b = rng.gen_biguint_below(&hex_to_bigint(N));
    
    // Compute B=kv + g**b % N
    let kv = &hex_to_bigint(K) * v;
    let gb = hex_to_bigint(G).modpow(&num_bigint::BigUint::from(b), &hex_to_bigint(N));
    (kv + gb) % &hex_to_bigint(N)
}

// Compute u = SHA256(A|B)
fn compute_hash(A: &num_bigint::BigUint, B: &num_bigint::BigUint) -> num_bigint::BigUint {
    sha256_to_bigint(format!("{}{}", A, B).as_bytes())
}

// Client: Generate S and K
fn client_compute_S(A: &num_bigint::BigUint, B: &num_bigint::BigUint, salt: u64) -> num_bigint::BigUint {
    // Generate xH=SHA256(salt|password)
    let xh = sha256_to_bigint(format!("{}{}", salt, P).as_bytes());
    let u = compute_hash(A, B);

    // Generate S = (B - k * g**x)**(a + u * x) % N
    let k_gx = hex_to_bigint(G).modpow(&xh, &hex_to_bigint(N)) * &hex_to_bigint(K);
    let exp = (&a + &u * &xh) % &hex_to_bigint(N);
    let S = (B - &k_gx).modpow(&exp, &hex_to_bigint(N));

    S
}

// Server: Generate S and K
fn server_compute_S(A: &num_bigint::BigUint, v: &num_bigint::BigUint, b: u64) -> num_bigint::BigUint {
    let u = compute_hash(A, &v);
    let S = A * v.modpow(&u, &hex_to_bigint(N_HEX));
    S
}

fn main() {
    
    // Server setup: Generate salt and verifier v
    let (salt, v) = server_setup();

    // Client computes A
    let A = client_compute_A();
    
    // Server computes B
    let B = server_compute_B(&v);
    
    // Client computes S
    let S_client = client_compute_S(&A, &B, salt);

    // Server computes S
    let S_server = server_compute_S(&A, &v, 3); // Replace with actual `b`
    
    // Both parties generate K (session key)
    let K_client = sha256_to_bigint(S_client.to_str_radix(10).as_bytes());
    let K_server = sha256_to_bigint(S_server.to_str_radix(10).as_bytes());

    println!("Client Key: {:?}", K_client);
    println!("Server Key: {:?}", K_server);
}