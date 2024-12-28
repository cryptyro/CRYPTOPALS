use rand::Rng;
use crate::AES::moops::{ecb_encipher, ecb_decipher};
use super::challenge9::pkcs7_pad;
use super::challenge15::pkcs7_unpad;

struct Profile {
    email: String,
    uid: u32,
    role: String,
}

fn parse_query_string(query: &str) -> Profile {
    let mut email = String::new();
    let mut uid = 0;
    let mut role = String::new();

    for pair in query.split('&') {
        let mut parts = pair.split('=');
        let key = parts.next().unwrap();
        let value = parts.next().unwrap();

        match key {
            "email" => email = value.to_string(),
            "uid" => uid = value.parse().unwrap(),
            "role" => role = value.to_string(),
            _ => (),
        }
    }

    Profile {
        email: email,
        uid: uid,
        role: role,
    }
}

fn sanitize(input: &str) -> String {
    input.chars()
        .filter(|&c| c != '&' && c != '=')
        .collect()
}

fn profile_for(email: &str) -> String {
    let sanitized_email = sanitize(email);
    let suffix = String::from("&uid=10&role=user");
    let prefix = String::from("email=");
    let profile = prefix + &sanitized_email + &suffix;
    return profile;
}

pub fn test13() {
    let profile = b"email=foooo@bar.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bcom&uid=10&role=user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
    let mut key = [0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill(&mut key);
    let mut cipher = ecb_encipher(profile, &key);
    //Now modify this cipher to get the admin profile
    let mut admin_profile = [0u8; 48];
    for i in 0..16 {
        admin_profile[i] = cipher[i];
        admin_profile[i + 16] = cipher[i + 32];
        admin_profile[i + 32] = cipher[i + 16];
    }
    ecb_decipher(&mut admin_profile, &key);
    let profile = pkcs7_unpad(&admin_profile, 16).unwrap();
    let profile = String::from_utf8(profile).unwrap();
    let admin_profile = parse_query_string(&profile);
    println!("Email: {}, UID: {}, Role: {}", admin_profile.email, admin_profile.uid, admin_profile.role);
}