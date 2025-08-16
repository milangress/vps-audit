mod model;
mod engine;
mod collectors;
mod checks;
mod report;

use crate::engine::AuditEngine;
use crate::report::{OutputFormat, Reporter};
use clap::{Parser, ValueEnum};
use dialoguer::{theme::ColorfulTheme, Confirm, MultiSelect, Select};

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

    /// Interactive wizard mode
    #[arg(long, default_value_t = false)]
    interactive: bool,
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

    let mut categories: Option<Vec<String>> = cli
        .categories
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());

    if cli.interactive {
        categories = interactive_select_categories(categories);
    }

    let mut engine = AuditEngine::new(categories.clone());
    engine.register_default_checks();

    let results = engine.run_all();

    let reporter = Reporter::new(cli.verbose, cli.format.into());
    reporter.print(&results);

    if cli.interactive {
        interactive_post_actions(&results);
    }

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

fn interactive_select_categories(preset: Option<Vec<String>>) -> Option<Vec<String>> {
    let theme = ColorfulTheme::default();
    let all = vec!["security", "performance", "config", "linux", "network"];
    let mut initial = vec![false; all.len()];
    if let Some(pre) = preset {
        for (idx, name) in all.iter().enumerate() {
            if pre.iter().any(|c| c.eq_ignore_ascii_case(name)) { initial[idx] = true; }
        }
    }
    let selections = MultiSelect::with_theme(&theme)
        .with_prompt("Select categories to run (space to toggle, enter to confirm)")
        .items(&all)
        .defaults(&initial)
        .interact()
        .unwrap_or_default();
    if selections.is_empty() { None } else { Some(selections.into_iter().map(|i| all[i].to_string()).collect()) }
}

fn interactive_post_actions(results: &[crate::model::CheckResult]) {
    let theme = ColorfulTheme::default();
    let fail_count = results.iter().filter(|r| r.status.is_fail()).count();
    let warn_count = results.iter().filter(|r| r.status.is_warn()).count();
    if fail_count == 0 && warn_count == 0 { return; }
    let choices = vec!["Show remediation for failed", "Show remediation for warn", "Exit"];
    loop {
        let idx = Select::with_theme(&theme)
            .with_prompt("Next action")
            .items(&choices)
            .default(0)
            .interact()
            .unwrap_or(2);
        match idx {
            0 => {
                for r in results.iter().filter(|r| r.status.is_fail()) {
                    if let Some(rem) = &r.remediation { println!("- {}: {}", r.id, rem); }
                }
            }
            1 => {
                for r in results.iter().filter(|r| r.status.is_warn()) {
                    if let Some(rem) = &r.remediation { println!("- {}: {}", r.id, rem); }
                }
            }
            _ => break,
        }
        let again = Confirm::with_theme(&theme).with_prompt("Anything else?").default(false).interact().unwrap_or(false);
        if !again { break; }
    }
}
