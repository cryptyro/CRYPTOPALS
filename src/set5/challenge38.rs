use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use rand::Rng;
use num_bigint::BigUint;
use num_traits::Num;

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// MITM attack
fn mitm_attack(
    intercepted_a: BigUint, 
    intercepted_hmac: Vec<u8>, 
    dictionary: Vec<&str>, 
    salt: BigUint, 
    b: BigUint, 
    g: BigUint, 
    n: BigUint, 
    u: BigUint
) -> Option<String> {
    for password in dictionary {
        // Compute x = SHA256(salt|password)
        let xh = sha256(&[&salt.to_bytes_be(), password.as_bytes()].concat());
        let x = BigUint::from_bytes_be(&xh);

        // Compute S = B**(a + u*x) % n
        let s = intercepted_a.modpow(&(b + u * x), &n);

        // Compute K = SHA256(S)
        let k = sha256(&s.to_bytes_be());

        // Compute HMAC-SHA256(K, salt)
        let computed_hmac = hmac_sha256(&k, &salt.to_bytes_be());

        // Compare with intercepted HMAC
        if computed_hmac == intercepted_hmac {
            return Some(password.to_string());
        }
    }

    None
}

fn main() {
    // Example values (normally these would be intercepted during the attack)
    let g = BigUint::from(2u32);
    let n = BigUint::from_str_radix("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813B57647AA7E5BCF21B4C1E78F0D1B5E45D5DC2A94E4531B14F78F30CF018BBF75DDA1BDDC7D5B04D8EFBBB064C46A8E9B8AE9E3AE4DDCDA625A37C4216FBD6E841D9452BDACF29E4EEA7E611B4B47D6D69C9215DA03327BC1DF1F", 16).unwrap();
    let intercepted_a = g.modpow(&BigUint::from(5u32), &n); // g^a mod n
    let b = BigUint::from(3u32); // Arbitrary b
    let intercepted_hmac = vec![/* Intercepted HMAC value */];
    let u = BigUint::from(1u32); // Arbitrary u
    let salt = BigUint::from(12345u32); // Arbitrary salt

    // Dictionary of possible passwords
    let dictionary = vec!["password123", "123456", "qwerty", "letmein", "password"];

    // Perform MITM attack
    match mitm_attack(intercepted_a, intercepted_hmac, dictionary, salt, b, g, n, u) {
        Some(password) => println!("Password cracked: {}", password),
        None => println!("Password not found in dictionary."),
    }
}
