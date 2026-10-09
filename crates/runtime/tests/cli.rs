use std::process::Command;

#[test]
fn rejects_unknown_and_extra_arguments() {
    for arguments in [
        &["solver"][..],
        &["--unknown"][..],
        &["--help", "extra"][..],
        &["-h", "extra"][..],
        &["--version", "extra"][..],
        &["-V", "extra"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .args(arguments)
            .output()
            .expect("ziquid binary should run");

        assert_eq!(output.status.code(), Some(2), "arguments: {arguments:?}");
    }
}
