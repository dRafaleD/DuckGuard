mod discovery;
mod model;
mod runtime;
mod scan;
use clap::{Parser, Subcommand, ValueEnum};
use model::{Report, Severity};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "DuckGuard",
    version,
    about = "Container configuration security scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Scan a Dockerfile or Compose file, or discover files in a directory
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
        #[arg(long, value_enum, default_value = "low")]
        severity: Severity,
        #[arg(long)]
        fail_on_findings: bool,
    },
    /// List available checks
    Rules,
    /// Inspect running containers using the current Docker context
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
}
#[derive(Subcommand)]
enum RuntimeCommand {
    /// Read configuration of running containers
    Scan {
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
        #[arg(long, value_enum, default_value = "low")]
        severity: Severity,
        #[arg(long)]
        fail_on_findings: bool,
    },
}
#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}
fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Rules => {
            for (id, name) in scan::RULES {
                println!("{id}  {name}");
            }
            for (id, name) in runtime::RULES {
                println!("{id}  {name}");
            }
            ExitCode::SUCCESS
        }
        Command::Runtime {
            command:
                RuntimeCommand::Scan {
                    format,
                    severity,
                    fail_on_findings,
                },
        } => {
            let mut report = runtime::scan();
            report.findings.retain(|f| f.severity >= severity);
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("serialize report")
                ),
                Format::Text => {
                    println!("DuckGuard — Running Container Configuration\n");
                    for f in &report.findings {
                        println!(
                            "[{}] {}  {}\n  {}\n  {}\n  Fix: {}\n",
                            f.severity, f.rule_id, f.title, f.file, f.detail, f.recommendation
                        );
                    }
                    for e in &report.errors {
                        eprintln!("Error: {e}");
                    }
                    println!(
                        "{} container(s), {} finding(s), {} error(s)",
                        report.scanned_containers,
                        report.findings.len(),
                        report.errors.len()
                    );
                }
            }
            if !report.errors.is_empty() {
                ExitCode::from(2)
            } else if fail_on_findings && !report.findings.is_empty() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Command::Scan {
            path,
            format,
            severity,
            fail_on_findings,
        } => {
            let (files, mut errors) = discovery::discover(&path);
            if files.is_empty() && errors.is_empty() {
                errors.push("No supported Dockerfile or Compose files found.".into());
            }
            let mut findings = Vec::new();
            for file in &files {
                if let Err(e) = scan::scan_file(file, &mut findings) {
                    errors.push(format!("{}: {e}", file.display()));
                }
            }
            findings.retain(|f| f.severity >= severity);
            let report = Report {
                scanned_files: files.len(),
                findings,
                errors,
            };
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("serialize report")
                ),
                Format::Text => {
                    println!("DuckGuard — Container Security Scanner\n");
                    for f in &report.findings {
                        println!(
                            "[{}] {}  {}\n  {}{}\n  {}\n  Fix: {}\n",
                            f.severity,
                            f.rule_id,
                            f.title,
                            f.file,
                            f.location
                                .as_ref()
                                .map(|s| format!(" · {s}"))
                                .unwrap_or_default(),
                            f.detail,
                            f.recommendation
                        );
                    }
                    for e in &report.errors {
                        eprintln!("Error: {e}");
                    }
                    println!(
                        "{} file(s), {} finding(s), {} error(s)",
                        report.scanned_files,
                        report.findings.len(),
                        report.errors.len()
                    );
                }
            }
            if !report.errors.is_empty() {
                ExitCode::from(2)
            } else if fail_on_findings && !report.findings.is_empty() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}
