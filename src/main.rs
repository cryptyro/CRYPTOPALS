#![allow(unused)]
#![allow(non_snake_case)]

mod set1;
mod set2;
mod set3;
mod set4;
mod set5;
mod AES;
mod DH;

use set1::challenge1::test1;
use set1::challenge2::test2;
use set1::challenge3::test3;
use set1::challenge4::test4;
use set1::challenge5::test5;
use set1::challenge6::test6;
use set1::challenge7::test7;
use set1::challenge8::test8;

use set2::challenge9::test9;
use set2::challenge10::test10;
use set2::challenge11::test11;
use set2::challenge12::test12;
use set2::challenge13::test13;
use set2::challenge14::test14;
use set2::challenge15::test15;
use set2::challenge16::test16;

use set3::challenge17::test17;
use set3::challenge18::test18;
use set3::challenge19::test19;
// use set3::challenge20::test20;
// use set3::challenge21::test21;
// use set3::challenge22::test22;
// use set3::challenge23::test23;
// use set3::challenge24::test24;

// use set4::challenge25::test25;
// use set4::challenge26::test26;
// use set4::challenge27::test27;
// use set4::challenge28::test28;
// use set4::challenge29::test29;
// use set4::challenge30::test30;
// use set4::challenge31::test31;
// use set4::challenge32::test32;

// use set5::challenge33::test33;
// use set5::challenge34::test34;
// use set5::challenge35::test35;
// use set5::challenge36::test36;
// use set5::challenge37::test37;
// use set5::challenge38::test38;
// use set5::challenge39::test39;
// use set5::challenge40::test40;

// use DH::client::client;
// use DH::server::server;



fn main () {
    test19();
}

/*use std::collections::HashMap;
use std::env;

mod module1;
mod module2;

fn main() {
    // Create a function registry
    let mut function_map: HashMap<&str, fn()> = HashMap::new();

    // Register functions
    function_map.insert("hello", module1::hello);
    function_map.insert("greet", module1::greet);
    function_map.insert("bye", module2::bye);

    // Get function name from CLI args
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <function_name>", args[0]);
        return;
    }

    let function_name = args[1].as_str();

    // Execute the function if found
    if let Some(&function) = function_map.get(function_name) {
        function();
    } else {
        eprintln!("Error: Function '{}' not found!", function_name);
    }
}
 */