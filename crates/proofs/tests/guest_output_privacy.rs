//! Real guest fd 1/2 and panic diagnostics must stay inside the private executor.
//! The retained ELF is built only from the adjacent public synthetic fixture source.
#![cfg(feature = "sp1-execute")]

use sp1_primitives::Elf;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};
use tracing_subscriber::{Layer, layer::Context, prelude::*};
use ziquid_proofs::artifacts::execution::execute_private;

const CHILD_FLAG: &str = "ZIQUID_PRIVATE_OUTPUT_TEST_CHILD";
const SENTINEL: &[u8] = b"public-synthetic-private-output-sentinel-6c41e9";
const FINISHED: &[u8] = b"private-output-execution-checked";
const ELF: &[u8] = include_bytes!("fixtures/private-output.elf");

// No runtime filter or fmt feature: accept programmatic DEBUG/INFO diagnostics,
// including cycle-tracker names, and expose their actual fields to the subprocess
// capture. Span fields are captured as well as events.
struct DiagnosticOutput;
struct DiagnosticFields;

impl tracing::field::Visit for DiagnosticFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        eprintln!("tracing {} = {value:?}", field.name());
    }
}

impl<S: tracing::Subscriber> Layer<S> for DiagnosticOutput {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        event.record(&mut DiagnosticFields);
    }

    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: Context<'_, S>,
    ) {
        attributes.record(&mut DiagnosticFields);
    }

    fn on_record(
        &self,
        _: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: Context<'_, S>,
    ) {
        values.record(&mut DiagnosticFields);
    }
}

#[test]
fn private_output_child() {
    if std::env::var_os(CHILD_FLAG).is_none() {
        return;
    }
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(DiagnosticOutput),
    ).expect("install fixture diagnostic subscriber");
    tracing::debug!("public-debug-subscriber-control");
    tracing::info!("public-info-subscriber-control");

    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("read public synthetic fixture input");
    let mode = *input.first().expect("fixture mode required");
    let result = match execute_private(Elf::Static(ELF), &input) {
        Ok(result) => result,
        Err(_) => panic!("fixture execution failed before returning a guest result"),
    };
    assert!(result.instructions > 0, "actual guest must execute instructions");
    match mode {
        0 => {
            assert_eq!(result.exit_code, 0, "positive guest must halt successfully");
            assert_eq!(result.journal, b"private-output-fixture-public-journal-v1",
                "positive guest must commit its full nonsecret journal");
        }
        1 => {
            assert_eq!(result.exit_code, 1, "negative guest must actually panic");
            assert!(result.journal.is_empty(), "panicking guest must not commit a journal");
        }
        _ => panic!("unsupported public fixture mode"),
    }
    println!("private-output-execution-checked");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn assert_private_output(mode: u8) {
    let mut child = Command::new(std::env::current_exe().expect("current regression binary"))
        .args(["--exact", "private_output_child", "--nocapture"])
        .env(CHILD_FLAG, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn actual executor subprocess");
    {
        let mut stdin = child.stdin.take().expect("fixture stdin pipe");
        stdin.write_all(&[mode]).expect("write fixture mode");
        stdin.write_all(SENTINEL).expect("write public synthetic sentinel");
    }
    let output = child.wait_with_output().expect("capture actual executor subprocess");
    assert!(output.status.success(), "fixture child failed before result qualification");
    assert!(contains(&output.stdout, FINISHED), "child must check the actual exit and journal");
    assert!(contains(&output.stderr, b"public-debug-subscriber-control"),
        "DEBUG diagnostics must reach the programmatic subscriber");
    assert!(contains(&output.stderr, b"public-info-subscriber-control"),
        "INFO diagnostics must reach the programmatic subscriber");
    assert!(!contains(&output.stdout, SENTINEL), "private guest bytes escaped to host stdout");
    assert!(!contains(&output.stderr, SENTINEL),
        "private guest bytes escaped to host stderr or programmatic diagnostics");
}

#[test]
fn successful_private_guest_output_never_reaches_host_streams_or_diagnostics() {
    assert_private_output(0);
}

#[test]
fn panicking_private_guest_output_never_reaches_host_streams_or_diagnostics() {
    assert_private_output(1);
}
