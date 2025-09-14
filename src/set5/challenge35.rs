/*If a is even, (p−1)^a mod p = 1.
If a is odd, (p−1)^a mod  p = p−1 
This means that the attacker can guess the shared secret with 
high accuracy if they can determine the parity (even or odd) of 
one of the private keys, making it much easier to break the 
encryption compared to a standard Diffie-Hellman exchange with a 
random generator g.*/

use rand::{Rng, thread_rng};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use crate::AES::moops::{cbc_encipher, cbc_decipher};
use crate::set2::challenge15::pkcs7_unpad;
use crate::set5::challenge33::P;
use crate::set5::challenge34::sha1_key;


pub fn test35() {
    //A->M->B Send "P", "g"(g=1, g=P, g=P-1)
    let g1 = BigUint::from(1u32);
    let gp = P.clone();
    let gp1 = P.clone()-1u64;

    //B->M->A Send ACK

    //A->M->B Send "A=g^a"
    let mut rng = thread_rng();
    let a1 = rng.gen_biguint_below(&P);
    let ap = rng.gen_biguint_below(&P);
    let ap1 = rng.gen_biguint_below(&P);

    let A1 = g1.modpow(&a1, &P);
    let Ap = gp.modpow(&ap, &P);
    let Ap1 = gp1.modpow(&ap1, &P);
    
    //B->M->A Send "B=g^b"
    let mut rng = thread_rng();
    let b1 = rng.gen_biguint_below(&P);
    let bp = rng.gen_biguint_below(&P);
    let bp1 = rng.gen_biguint_below(&P);

    let B1 = g1.modpow(&b1, &P);
    let Bp = gp.modpow(&bp, &P);
    let Bp1 = gp1.modpow(&bp1, &P);

    // AES key for A{sha1(B^a mod P)} and B{sha1(A^b mod P)}
    let key1 = sha1_key(&B1.modpow(&a1, &P));
    let keyp = sha1_key(&Bp.modpow(&ap, &P));
    let keyp1 = sha1_key(&Bp1.modpow(&ap1, &P));
   
    //A->M->B Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    // Don't bother with appending and extracting iv
    let mut iv: [u8; 16] = [0; 16];
    rand::thread_rng().fill(&mut iv);
    let enc_message1 = cbc_encipher("From A1 with love!!".as_bytes(), &key1, &iv);
    let enc_messagep = cbc_encipher("From A1 with love!!".as_bytes(), &keyp, &iv);
    let enc_messagep1 = cbc_encipher("From A1 with love!!".as_bytes(), &keyp1, &iv);

    //M intercepts and relay to B, meanwhile decrypt it
    let keym1 = sha1_key(&BigUint::from(1u32));
    let keymp = sha1_key(&BigUint::zero());
    let keymp1;

    if Ap1 == gp1 && Bp1 == gp1{
        keymp1 = sha1_key(&(P.clone()-1u64));
    } else {
        keymp1 = sha1_key(&(BigUint::from(1u32)));
    }

    let message1 = cbc_decipher(&enc_message1, &keym1, &iv);
    let messagep = cbc_decipher(&enc_messagep, &keymp, &iv);
    let messagep1 = cbc_decipher(&enc_messagep1, &keymp1, &iv);

    let unpad_message1 = pkcs7_unpad(&message1, 16).unwrap();
    let unpad_messagep = pkcs7_unpad(&messagep, 16).unwrap();
    let unpad_messagep1 = pkcs7_unpad(&messagep1, 16).unwrap();

    println!("Decrypted message1: {:?}", String::from_utf8(unpad_message1));
    println!("Decrypted messagep: {:?}", String::from_utf8(unpad_messagep));
    println!("Decrypted messagep1: {:?}", String::from_utf8(unpad_messagep1));
}