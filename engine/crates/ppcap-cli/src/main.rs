//! `ppcap` binary entrypoint. The command structure and dispatch live in [`cli`]; `main`
//! is a one-line shell that returns the process exit code.

mod cli;
mod mcp;
mod push;

fn main() -> std::process::ExitCode {
    cli::run()
}
