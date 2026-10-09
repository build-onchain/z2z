//! Public synthetic regression guest; never consumes real owner/wallet material.
#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    let (mode, sentinel) = input.split_first().expect("missing public fixture mode");
    // Lossy formatting also permits non-UTF-8 bytes; regression inputs are ASCII.
    let sentinel = String::from_utf8_lossy(sentinel);
    println!("fixture stdout: {sentinel}");
    eprintln!("fixture stderr: {sentinel}");
    println!("cycle-tracker-start: {sentinel}");
    println!("cycle-tracker-end: {sentinel}");
    println!("cycle-tracker-report-start: {sentinel}");
    println!("cycle-tracker-report-end: {sentinel}");
    match mode {
        0 => sp1_zkvm::io::commit_slice(b"private-output-fixture-public-journal-v1"),
        1 => panic!("fixture panic: {sentinel}"),
        _ => panic!("unsupported public fixture mode"),
    }
}
