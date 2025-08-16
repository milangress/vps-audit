mod model;
mod engine;
mod collectors;
mod checks;
mod report;

use crate::engine::AuditEngine;
use crate::report::{OutputFormat, Reporter};
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "vps-audit", version, about = "Self-contained VPS security and health audit CLI")]
struct Cli {
    /// Output format
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,

    /// Only run checks in these categories (comma separated). Known: security, performance, config, linux
    #[arg(long)]
    categories: Option<String>,

    /// Show PASS and SKIP results too
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Fail the process if any check FAILs (exit code 2) or WARNs (exit code 1)
    #[arg(long, default_value_t = false)]
    strict: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum FormatArg {
    Text,
    Json,
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Text => OutputFormat::Text,
            FormatArg::Json => OutputFormat::Json,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let categories: Option<Vec<String>> = cli
        .categories
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());

    let mut engine = AuditEngine::new(categories);
    engine.register_default_checks();

    let results = engine.run_all();

    let reporter = Reporter::new(cli.verbose, cli.format.into());
    reporter.print(&results);

    if cli.strict {
        let has_fail = results.iter().any(|r| r.status.is_fail());
        let has_warn = results.iter().any(|r| r.status.is_warn());
        if has_fail {
            std::process::exit(2);
        } else if has_warn {
            std::process::exit(1);
        }
    }
}
