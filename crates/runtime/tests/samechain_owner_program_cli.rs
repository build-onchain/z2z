//! Public-only program derivation; fast regressions never initialize a valid guest.
//! The ignored positive requires an explicitly caller-selected real ELF and SHA pin.
use std::{ffi::OsString, process::{Command, Output, Stdio}, time::{Duration, Instant}};

fn invoke(args: &[OsString], setup: Option<&std::path::Path>) -> Output {
    invoke_with_budget(args, setup, Duration::from_secs(60))
}

fn invoke_with_budget(args: &[OsString], setup: Option<&std::path::Path>, budget: Duration) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.arg("samechain").args(args).env_clear()
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for name in ["HOME", "PATH"] {
        if let Some(value) = std::env::var_os(name) { command.env(name, value); }
    }
    if let Some(setup) = setup { command.env("SP1_GROTH16_CIRCUIT_PATH", setup); }
    let mut child = command.spawn().unwrap();
    // Retain an open pipe without sending bytes: public dispatch must never read it.
    let stdin = child.stdin.take().unwrap();
    let deadline = Instant::now() + budget;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("public owner-program did not finish without private stdin");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    for stream in [&output.stdout, &output.stderr] {
        for argument in args {
            if let Some(value) = argument.to_str().filter(|value| value.starts_with('/') || value.contains("sentinel")) {
                assert!(!stream.windows(value.len()).any(|window| window == value.as_bytes()),
                    "owner-program disclosed a supplied path or private selector");
            }
        }
        if let Some(setup) = setup {
            let value = setup.to_str().unwrap();
            assert!(!stream.windows(value.len()).any(|window| window == value.as_bytes()),
                "owner-program disclosed artifact path");
        }
    }
    output
}

fn rejected(output: &Output, code: i32, category: &[u8]) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty(), "rejection exported public readiness");
    assert_eq!(output.stderr, category);
}

#[cfg(not(feature = "sp1-local"))]
#[test]
fn owner_program_without_local_feature_refuses_without_output() {
    rejected(&invoke(&["owner-program".into(), "--elf".into(),
        "/tmp/private-owner-program-path-sentinel".into(), "--elf-sha256".into(),
        format!("0x{}", "11".repeat(32)).into()], None), 2,
        b"invalid samechain command arguments\n");
}

#[cfg(feature = "sp1-local")]
mod enabled {
    use super::*;
    use std::{fs, io::Write, path::Path};
    use sha2::{Digest, Sha256};

    const NON_ELF: &[u8] = b"public owner-program mismatch fixture, never supplied for setup";

    fn args(elf: &Path, hash: impl Into<OsString>) -> Vec<OsString> {
        vec!["owner-program".into(), "--elf".into(), elf.into(), "--elf-sha256".into(), hash.into()]
    }

    #[test]
    fn owner_program_wrong_hash_rejects_before_setup_without_reading_stdin() {
        let mut elf = tempfile::NamedTempFile::new().unwrap();
        elf.write_all(NON_ELF).unwrap();
        let setup = tempfile::tempdir().unwrap();
        let output = invoke(&args(elf.path(), format!("0x{}", "11".repeat(32))), Some(setup.path()));
        rejected(&output, 1, b"samechain owner ELF hash mismatch\n");
        assert!(fs::read_dir(setup.path()).unwrap().next().is_none(), "public setup downloaded artifacts");
    }

    #[test]
    fn owner_program_invalid_pin_rejects_before_opening_elf_or_setup() {
        let elf = Path::new("/tmp/missing-owner-program-path-sentinel");
        for pin in ["0x01".to_owned(), format!("0x{}", "00".repeat(32)),
            format!("0x{}", "gg".repeat(32)), "private-pin-sentinel".to_owned()]
        {
            rejected(&invoke(&args(elf, pin), None), 1, b"invalid samechain owner ELF hash pin\n");
        }
    }

    #[test]
    fn owner_program_rejects_private_selectors_and_requires_both_public_pins() {
        let base = args(Path::new("/tmp/missing-owner-program-path-sentinel"),
            format!("0x{}", "11".repeat(32)));
        for extra in [vec!["--witness-stdin"], vec!["--witness", "private-witness-sentinel"],
            vec!["--deployment", "private-deployment-sentinel"],
            vec!["--program-vkey", "private-program-sentinel"]]
        {
            let mut args = base.clone();
            args.extend(extra.into_iter().map(OsString::from));
            rejected(&invoke(&args, None), 2, b"invalid samechain command arguments\n");
        }
        for flag in ["--elf", "--elf-sha256"] {
            let mut args = base.clone();
            let index = args.iter().position(|arg| arg == flag).unwrap();
            args.drain(index..index + 2);
            rejected(&invoke(&args, None), 2, b"invalid samechain command arguments\n");
        }
    }

    #[test]
    fn owner_program_bounds_elf_reads_and_sanitizes_missing_paths() {
        let oversized = tempfile::NamedTempFile::new().unwrap();
        oversized.as_file().set_len(16 * 1024 * 1024 + 1).unwrap();
        let pin = format!("0x{}", "11".repeat(32));
        rejected(&invoke(&args(oversized.path(), &pin), None), 1,
            b"samechain public owner ELF exceeds size limit\n");
        rejected(&invoke(&args(Path::new("/tmp/missing-owner-program-path-sentinel"), pin), None), 1,
            b"samechain public owner ELF unavailable\n");
    }

    #[test]
    #[ignore = "parent-controlled real light setup; requires Z2Z_OWNER_PROGRAM_ELF, Z2Z_OWNER_PROGRAM_SHA256 and Z2Z_OWNER_PROGRAM_TIMEOUT_SECONDS"]
    fn owner_program_real_light_setup_exports_exact_identity_without_qualification() {
        let elf = std::env::var_os("Z2Z_OWNER_PROGRAM_ELF").expect("explicit real public ELF required");
        let pin = std::env::var("Z2Z_OWNER_PROGRAM_SHA256").expect("explicit public SHA pin required");
        let seconds = std::env::var("Z2Z_OWNER_PROGRAM_TIMEOUT_SECONDS")
            .expect("explicit public setup timeout required").parse::<u64>().unwrap();
        assert!((1..=86400).contains(&seconds), "public setup timeout outside reviewed bound");
        let bytes = fs::read(&elf).unwrap();
        assert!(!bytes.is_empty() && bytes.len() <= 16 * 1024 * 1024);
        let hash = Sha256::digest(&bytes);
        let actual = format!("0x{}", hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        assert_eq!(pin, actual, "parent public ELF pin mismatch");
        let setup = tempfile::tempdir().unwrap();
        let output = invoke_with_budget(&args(Path::new(&elf), pin.as_str()), Some(setup.path()), Duration::from_secs(seconds));
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["kind"], "samechain_owner_program");
        assert_eq!(value["elf_sha256"], actual);
        assert_eq!(value["evidence"], "actual_local_light_program_setup");
        let program = value["program_vkey"].as_str().unwrap();
        assert_eq!(program.len(), 66);
        assert!(program.starts_with("0x") && program[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(program, format!("0x{}", "00".repeat(32)));
        for flag in ["source_qualification", "setup_qualification", "program_identity", "root_eligibility",
            "global_unspentness", "asset_backing", "finality", "deployment_profile_qualification"]
        { assert_eq!(value[flag], "UNVERIFIED", "derived program falsely qualified {flag}"); }
        for flag in ["proof_certificate", "financial_execution", "strict_matching_privacy"] {
            assert_eq!(value[flag], false, "derived program falsely asserted {flag}");
        }
        for forbidden in ["journal", "proof", "witness", "private_temp_dir", "elf"] {
            assert!(value.get(forbidden).is_none(), "public program export included {forbidden}");
        }
        assert!(fs::read_dir(setup.path()).unwrap().next().is_none(), "public light setup downloaded artifacts");
    }
}
