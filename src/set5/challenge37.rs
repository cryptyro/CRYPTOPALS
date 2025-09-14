fn client_compute_S_with_A(A: &num_bigint::BigUint, B: &num_bigint::BigUint, salt: u64, password: &str) -> num_bigint::BigUint {
    let xh = sha256_to_bigint(format!("{}{}", salt, password).as_bytes());
    let u = compute_u(A, B);

    let k_gx = hex_to_bigint(N_HEX).modpow(&xh, &hex_to_bigint(N_HEX)) * num_bigint::BigUint::from(K);
    let exp = &u * &xh;

    // S = (B - k * g**x)**(a + u * x) % N
    let S = (B - &k_gx).modpow(&exp, &hex_to_bigint(N_HEX));
    S
}

let A = num_bigint::BigUint::from(0u64); // Client sends A = 0

let A = hex_to_bigint(N_HEX); // Client sends A = N

let A = &hex_to_bigint(N_HEX) * 2u64; // Client sends A = 2N
