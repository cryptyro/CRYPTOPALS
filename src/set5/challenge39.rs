fn egcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        return (b, 0, 1);
    } else {
        let (g, x, y) = egcd(b % a, a);
        return (g, y - (b / a) * x, x);
    }
}

fn invmod(a: i64, m: i64) -> i64 {
    let (g, x, _) = egcd(a, m);
    if g != 1 {
        panic!("No modular inverse exists!");
    } else {
        (x % m + m) % m
    }
}

fn generate_rsa_keys(p: i64, q: i64) -> (i64, i64, i64) {
    let n = p * q;
    let et = (p - 1) * (q - 1);
    let e = 3;
    let d = invmod(e, et);
    (e, d, n)
}

fn encrypt(m: i64, e: i64, n: i64) -> i64 {
    mod_exp(m, e, n)
}

fn decrypt(c: i64, d: i64, n: i64) -> i64 {
    mod_exp(c, d, n)
}

// Modular exponentiation function
fn mod_exp(base: i64, exp: i64, modulus: i64) -> i64 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp = exp >> 1;
        base = (base * base) % modulus;
    }
    result
}
fn string_to_number(s: &str) -> i64 {
    let hex_string = format!("0x{}", hex::encode(s));
    i64::from_str_radix(&hex_string[2..], 16).unwrap()
}

fn number_to_string(n: i64) -> String {
    let hex_string = format!("{:x}", n);
    let bytes = hex::decode(hex_string).unwrap();
    String::from_utf8(bytes).unwrap()
}

fn main() {
    let p = 104729; // larger prime
    let q = 104723; // larger prime
    let (e, d, n) = generate_rsa_keys(p, q);

    println!("Public Key: (e: {}, n: {})", e, n);
    println!("Private Key: (d: {}, n: {})", d, n);

    let message = "Hello, RSA!";
    let message_number = string_to_number(message);
    let encrypted_message = encrypt(message_number, e, n);
    println!("Encrypted message (as number): {}", encrypted_message);

    let decrypted_message_number = decrypt(encrypted_message, d, n);
    let decrypted_message = number_to_string(decrypted_message_number);
    println!("Decrypted message: {}", decrypted_message);
}
