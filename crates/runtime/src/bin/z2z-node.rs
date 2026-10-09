//! Transport-only node: wallet keys, proving and trading are not wired here.
fn main() -> std::process::ExitCode {
    ziquid_runtime::node::run_cli(std::env::args_os().skip(1))
}
