mod capture;
mod ast_chunker;
mod models;
mod scanner;
mod cache;
mod llm_client;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use crate::{
    models::{LlmConfig, Severity},
    scanner::Scanner,
};
use std::process;

#[derive(Parser)]
#[command(
    name = "codeshield",
    about = "🛡️  CodeShield — Local AI Security Scanner",
    version = "2.2.0",
    author = "Mohammed Emad AL-Mekhlafi"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project directory for vulnerabilities
    Scan {
        /// Path to project root
        #[arg(short, long)]
        path: String,

        /// Ollama model to use
        #[arg(short, long, default_value = "qwen2.5-coder:7b")]
        model: String,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Fail with exit code 1 if severity >= threshold
        #[arg(long, default_value = "CRITICAL")]
        fail_on: String,

        /// SQLite cache path
        #[arg(long, default_value = "~/.codeshield/cache.db")]
        db: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("codeshield=info")
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, model, json, fail_on, db } => {
            let config = LlmConfig {
                model,
                ..Default::default()
            };

            let db_path = shellexpand::tilde(&db).to_string();
            let scanner = Scanner::new(config, &db_path).await?;
            let result = scanner.scan_project(&path).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_report(&result);
            }

            // Exit code for CI/CD integration
            let fail_severity = parse_severity(&fail_on);
            let should_fail = result.vulnerabilities.iter()
                .any(|v| v.severity >= fail_severity);

            if should_fail {
                eprintln!("\n{}", "🚫 Scan failed: vulnerabilities at or above threshold found.".red().bold());
                process::exit(1);
            }
        }
    }

    Ok(())
}

fn print_report(result: &crate::models::ScanResult) {
    println!("\n{}", "═".repeat(60).cyan());
    println!("{}", "  🛡️  CodeShield Scan Report".bold());
    println!("{}", "═".repeat(60).cyan());
    println!("  📂  Project:   {}", result.project_path);
    println!("  📄  Files:     {}", result.files_scanned);
    println!("  ⏱️   Duration:  {}ms", result.duration_ms);
    println!("  🔴  CRITICAL:  {}", result.critical_count.to_string().red().bold());
    println!("  🟠  HIGH:      {}", result.high_count.to_string().yellow().bold());
    println!("  🟡  MEDIUM:    {}", result.medium_count);
    println!("  🟢  LOW:       {}", result.low_count);
    println!("{}", "─".repeat(60).cyan());

    for vuln in &result.vulnerabilities {
        let sev_str = format!("{}", vuln.severity);
        println!("\n  {} │ {}:{}-{}",
                 sev_str.bold(),
                 vuln.file_path,
                 vuln.line_start,
                 vuln.line_end
        );
        println!("  Type: {} {}",
                 vuln.vuln_type,
                 vuln.cwe_id.as_deref().unwrap_or("")
        );
        println!("  {}", vuln.description.italic());
        println!("  Fix: {}", vuln.recommendation.green());
    }

    println!("\n{}", "═".repeat(60).cyan());
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH"     => Severity::High,
        "MEDIUM"   => Severity::Medium,
        "LOW"      => Severity::Low,
        _          => Severity::Critical,
    }
}