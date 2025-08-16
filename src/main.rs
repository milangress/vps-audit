mod model;
mod engine;
mod collectors;
mod checks;
mod report;

use crate::engine::AuditEngine;
use crate::report::{OutputFormat, Reporter};
use clap::{Parser, ValueEnum};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};

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

    /// Run non-interactively (disables wizard)
    #[arg(long, default_value_t = false)]
    non_interactive: bool,
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

    if !cli.non_interactive {
        categories = interactive_select_categories(categories);
    }

    let mut engine = AuditEngine::new(categories.clone());
    engine.register_default_checks();

    let results = engine.run_all();

    let reporter = Reporter::new(cli.verbose, cli.format.into());
    reporter.print(&results);

    if !cli.non_interactive {
        interactive_wizard(&results, &reporter, &mut engine);
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

fn interactive_wizard(results: &[crate::model::CheckResult], reporter: &Reporter, engine: &mut AuditEngine) {
    let theme = ColorfulTheme::default();
    let mut current_results = results.to_vec();
    loop {
        let (pass, warn, fail, skip) = crate::report::Reporter::counts(&current_results);
        println!("Score: {} / 100", crate::report::Reporter::score(&current_results));
        println!("PASS={}, WARN={}, FAIL={}, SKIP={}", pass, warn, fail, skip);
        let options = vec![
            "View failures",
            "View warnings",
            "Save report",
            "Rerun checks",
            "Choose categories",
            "Exit",
        ];
        let choice = Select::with_theme(&theme)
            .with_prompt("Wizard")
            .items(&options)
            .default(0)
            .interact()
            .unwrap_or(options.len() - 1);
        match choice {
            0 => {
                for r in current_results.iter().filter(|r| r.status.is_fail()) {
                    println!("[FAIL] {}\n  {}\n  remediation: {}\n", r.title, r.reason, r.remediation.clone().unwrap_or_default());
                }
            }
            1 => {
                for r in current_results.iter().filter(|r| r.status.is_warn()) {
                    println!("[WARN] {}\n  {}\n  remediation: {}\n", r.title, r.reason, r.remediation.clone().unwrap_or_default());
                }
            }
            2 => {
                let path: String = Input::with_theme(&theme).with_prompt("Save report to path").default("vps-audit-report.txt".into()).interact_text().unwrap_or_else(|_| "vps-audit-report.txt".into());
                let contents = reporter.render(&current_results);
                if std::fs::write(&path, contents).is_ok() { println!("Saved to {}", path); } else { println!("Failed to save to {}", path); }
            }
            3 => {
                current_results = engine.run_all();
                reporter.print(&current_results);
            }
            4 => {
                let new_categories = interactive_select_categories(None);
                *engine = crate::engine::AuditEngine::new(new_categories);
                engine.register_default_checks();
            }
            _ => break,
        }
        let again = Confirm::with_theme(&theme).with_prompt("Continue?").default(true).interact().unwrap_or(true);
        if !again { break; }
    }
}
