use std::process::Command;

#[test]
fn allocation_command_exercises_checked_native_core() {
    let output = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["allocation", "6000000", "30000000", "2000000"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let values: Vec<_> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|field| field.split_once('=').unwrap())
        .collect();
    assert!(values.contains(&("user_wei", "10000000")));
    assert!(values.contains(&("solver_wei", "20000000")));

    for args in [
        ["allocation", "0", "10", "0"],
        ["allocation", "3", "10", "4"],
        ["allocation", "3", "0", "1"],
        ["allocation", "-1", "10", "0"],
        ["allocation", "+3", "10", "1"],
        ["allocation", "3", "10", "+1"],
        ["allocation", "3", "+10", "1"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
