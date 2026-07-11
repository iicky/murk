//! Dev-only tool: render the CLI command reference (`docs/cli-reference.md`)
//! from the clap model so the documented surface cannot drift from the binary.
//!
//! Regenerate:  `cargo run --features doc-gen --bin gen-docs`
//! Check (CI):  `cargo run --features doc-gen --bin gen-docs -- --check`
//!
//! Gated behind the `doc-gen` feature; the shipped `murk` binary never links it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::CommandFactory;
use murk_cli::cli::Cli;

fn reference_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/cli-reference.md")
}

fn render() -> String {
    // Strip the version so the reference stays stable across release bumps: the
    // version lives in Cargo.toml and is already guarded by check-versions.cjs.
    // Coupling the CLI reference to it would fire this guard on every bump.
    let cmd = Cli::command().version(None::<&'static str>);
    let options = clap_markdown::MarkdownOptions::new()
        .title("murk command reference".to_string())
        .show_footer(false)
        .show_table_of_contents(true);
    let body = clap_markdown::help_markdown_command_custom(&cmd, &options);
    format!("{BANNER}{body}")
}

/// Prepended so readers know the file is generated and CI enforces it.
const BANNER: &str = "<!-- Generated from the clap model by \
`cargo run --features doc-gen --bin gen-docs`. Do not edit by hand; CI checks it. -->\n\n";

fn main() -> ExitCode {
    let generated = render();
    let path = reference_path();

    if std::env::args().any(|a| a == "--check") {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current == generated {
            eprintln!("docs/cli-reference.md is up to date.");
            return ExitCode::SUCCESS;
        }
        eprintln!(
            "docs/cli-reference.md is out of date.\n\
             Regenerate with: cargo run --features doc-gen --bin gen-docs"
        );
        return ExitCode::FAILURE;
    }

    std::fs::write(&path, generated).expect("write docs/cli-reference.md");
    eprintln!("wrote {}", path.display());
    ExitCode::SUCCESS
}
