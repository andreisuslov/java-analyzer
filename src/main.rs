//! Java Analyzer CLI
//!
//! A fast static code analyzer for Java based on SonarSource rules.

use std::path::PathBuf;
use std::process::ExitCode;
use std::fs;
use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;

use java_analyzer::{Analyzer, AnalyzerConfig, Severity, AnalysisResult};
use java_analyzer::reports::{Report, ReportFormat, ReportConfig};

#[derive(Parser)]
#[command(name = "java-analyzer")]
#[command(author = "Java Analyzer Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Fast static code analyzer for Java based on SonarSource rules")]
#[command(long_about = r#"
Java Analyzer - A lightning-fast static code analyzer for Java

This tool analyzes Java source code for:
  - Naming convention violations
  - Security vulnerabilities
  - Potential bugs
  - Code smells
  - Cognitive complexity issues

Based on SonarSource rules with 80+ checks implemented.
"#)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to analyze (file or directory)
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Output file (defaults to stdout)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Minimum severity level to report
    #[arg(short = 's', long, value_enum, default_value = "info")]
    min_severity: SeverityLevel,

    /// Maximum cognitive complexity threshold
    #[arg(long, default_value = "15")]
    max_complexity: usize,

    /// Only enable specific rules (comma-separated)
    #[arg(long, value_delimiter = ',')]
    rules: Option<Vec<String>>,

    /// Disable specific rules (comma-separated)
    #[arg(long, value_delimiter = ',')]
    exclude_rules: Option<Vec<String>>,

    /// Exclude paths matching patterns (comma-separated)
    #[arg(long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Show only summary, no individual issues
    #[arg(long)]
    summary_only: bool,

    /// Fail with exit code 1 if issues are found
    #[arg(long)]
    fail_on_issues: bool,

    /// Fail if issues of this severity or higher are found
    #[arg(long, value_enum)]
    fail_on_severity: Option<SeverityLevel>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze Java source code
    Analyze {
        /// Path to analyze
        path: PathBuf,
    },

    /// List all available rules
    Rules {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Show detailed descriptions
        #[arg(short, long)]
        details: bool,
    },

    /// Show version and build information
    Version,

    /// Generate a sample configuration file
    Init {
        /// Output file
        #[arg(short, long, default_value = "java-analyzer.toml")]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Html,
    Sarif,
    Csv,
    Markdown,
}

impl From<OutputFormat> for ReportFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Text => ReportFormat::Text,
            OutputFormat::Json => ReportFormat::Json,
            OutputFormat::Html => ReportFormat::Html,
            OutputFormat::Sarif => ReportFormat::Sarif,
            OutputFormat::Csv => ReportFormat::Csv,
            OutputFormat::Markdown => ReportFormat::Markdown,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SeverityLevel {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

impl From<SeverityLevel> for Severity {
    fn from(s: SeverityLevel) -> Self {
        match s {
            SeverityLevel::Info => Severity::Info,
            SeverityLevel::Minor => Severity::Minor,
            SeverityLevel::Major => Severity::Major,
            SeverityLevel::Critical => Severity::Critical,
            SeverityLevel::Blocker => Severity::Blocker,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle no-color flag
    if cli.no_color {
        colored::control::set_override(false);
    }

    match cli.command {
        Some(Commands::Rules { category, details }) => {
            list_rules(category, details);
            ExitCode::SUCCESS
        }
        Some(Commands::Version) => {
            print_version();
            ExitCode::SUCCESS
        }
        Some(Commands::Init { output }) => {
            generate_config(&output)
        }
        Some(Commands::Analyze { ref path }) => {
            run_analysis(&cli, path)
        }
        None => {
            match &cli.path {
                Some(p) => run_analysis(&cli, p),
                None => {
                    eprintln!("{}: No path specified. Use --help for usage.", "Error".red().bold());
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn run_analysis(cli: &Cli, path: &PathBuf) -> ExitCode {
    if !path.exists() {
        eprintln!("{}: Path does not exist: {}", "Error".red().bold(), path.display());
        return ExitCode::FAILURE;
    }

    // Build configuration
    let mut config = AnalyzerConfig::default();
    config.min_severity = cli.min_severity.into();
    config.max_complexity = cli.max_complexity;

    if let Some(ref rules) = cli.rules {
        config.enabled_rules = Some(rules.clone());
    }

    if let Some(ref exclude_rules) = cli.exclude_rules {
        config.disabled_rules = exclude_rules.clone();
    }

    if let Some(ref exclude) = cli.exclude {
        config.exclude_patterns.extend(exclude.clone());
    }

    // Create analyzer and run
    let analyzer = Analyzer::with_config(config);

    if cli.verbose {
        eprintln!("{} Analyzing {}...", "Info:".blue().bold(), path.display());
        eprintln!("{} {} rules active", "Info:".blue().bold(), analyzer.available_rules().len());
    }

    let result = analyzer.analyze(path);

    // Generate report
    if cli.summary_only {
        print_summary(&result, cli.no_color);
    } else {
        let report_config = ReportConfig {
            format: cli.format.into(),
            include_snippets: true,
            group_by: java_analyzer::reports::GroupBy::File,
            color_output: !cli.no_color,
        };

        let report = Report::with_config(report_config).generate(&result);

        if let Some(ref output_path) = cli.output {
            match fs::write(output_path, &report) {
                Ok(_) => {
                    if cli.verbose {
                        eprintln!("{} Report written to {}", "Success:".green().bold(), output_path.display());
                    }
                }
                Err(e) => {
                    eprintln!("{}: Failed to write report: {}", "Error".red().bold(), e);
                    return ExitCode::FAILURE;
                }
            }
        } else {
            print!("{}", report);
        }
    }

    // Determine exit code
    let has_issues = !result.issues.is_empty();

    if cli.fail_on_issues && has_issues {
        return ExitCode::FAILURE;
    }

    if let Some(fail_severity) = cli.fail_on_severity {
        let fail_severity: Severity = fail_severity.into();
        if result.issues.iter().any(|i| i.severity >= fail_severity) {
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

fn print_summary(result: &AnalysisResult, no_color: bool) {
    if no_color {
        println!("Java Analyzer Summary");
        println!("=====================");
    } else {
        println!("{}", "Java Analyzer Summary".bold().cyan());
        println!("{}", "=====================".cyan());
    }

    println!("Files analyzed: {}", result.files_analyzed);
    println!("Total issues:   {}", result.issues.len());
    println!("Analysis time:  {}ms", result.duration_ms);
    println!();

    let counts = result.severity_counts();

    let blocker = counts.get(&Severity::Blocker).unwrap_or(&0);
    let critical = counts.get(&Severity::Critical).unwrap_or(&0);
    let major = counts.get(&Severity::Major).unwrap_or(&0);
    let minor = counts.get(&Severity::Minor).unwrap_or(&0);
    let info = counts.get(&Severity::Info).unwrap_or(&0);

    if no_color {
        println!("Issues by severity:");
        println!("  BLOCKER:  {}", blocker);
        println!("  CRITICAL: {}", critical);
        println!("  MAJOR:    {}", major);
        println!("  MINOR:    {}", minor);
        println!("  INFO:     {}", info);
    } else {
        println!("Issues by severity:");
        println!("  {}: {}", "BLOCKER ".red().bold(), blocker);
        println!("  {}: {}", "CRITICAL".red(), critical);
        println!("  {}: {}", "MAJOR   ".yellow(), major);
        println!("  {}: {}", "MINOR   ".blue(), minor);
        println!("  {}: {}", "INFO    ".white(), info);
    }
}

fn list_rules(category: Option<String>, details: bool) {
    let analyzer = Analyzer::new();
    let rules = analyzer.available_rules();

    println!("{}", "Available Rules".bold().cyan());
    println!("{}", "===============".cyan());
    println!();
    println!("Total: {} rules", rules.len());
    println!();

    let category_filter = category.map(|c| c.to_lowercase());

    for rule in rules {
        let cat_str = format!("{:?}", rule.category()).to_lowercase();

        if let Some(ref filter) = category_filter {
            if !cat_str.contains(filter) {
                continue;
            }
        }

        let severity_str = match rule.severity() {
            Severity::Blocker => "BLOCKER ".red().bold(),
            Severity::Critical => "CRITICAL".red(),
            Severity::Major => "MAJOR   ".yellow(),
            Severity::Minor => "MINOR   ".blue(),
            Severity::Info => "INFO    ".white(),
        };

        println!("{} [{}] {} - {}",
                 rule.id().cyan(),
                 severity_str,
                 format!("{:?}", rule.category()).dimmed(),
                 rule.title()
        );

        if details && !rule.description().is_empty() {
            println!("         {}", rule.description().dimmed());
        }
    }
}

fn print_version() {
    println!("{} {}", "Java Analyzer".bold().cyan(), env!("CARGO_PKG_VERSION"));
    println!();
    println!("A fast static code analyzer for Java based on SonarSource rules.");
    println!();
    println!("Built with:");
    println!("  - tree-sitter for parsing");
    println!("  - rayon for parallel analysis");
    println!();
    println!("Features:");
    println!("  - 80+ rules implemented");
    println!("  - Multiple output formats (text, JSON, HTML, SARIF, CSV, Markdown)");
    println!("  - Configurable severity thresholds");
    println!("  - Cognitive complexity analysis");
}

fn generate_config(output: &PathBuf) -> ExitCode {
    let config = r#"# Java Analyzer Configuration
# Generated configuration file

# Minimum severity level to report
# Options: info, minor, major, critical, blocker
min_severity = "info"

# Maximum cognitive complexity threshold
max_complexity = 15

# Rules to enable (if specified, only these rules will run)
# enabled_rules = ["S100", "S101", "S2068"]

# Rules to disable
disabled_rules = []

# Path patterns to exclude from analysis
exclude_patterns = [
    "target/",
    "build/",
    "node_modules/",
    ".git/",
    "**/generated/**",
    "**/test/**"
]

# Output format
# Options: text, json, html, sarif, csv, markdown
output_format = "text"

# Fail if issues of this severity or higher are found
# Options: info, minor, major, critical, blocker
# fail_on_severity = "major"
"#;

    match fs::write(output, config) {
        Ok(_) => {
            println!("{} Configuration written to {}", "Success:".green().bold(), output.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: Failed to write configuration: {}", "Error".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_conversion() {
        assert_eq!(Severity::from(SeverityLevel::Info), Severity::Info);
        assert_eq!(Severity::from(SeverityLevel::Blocker), Severity::Blocker);
    }

    #[test]
    fn test_format_conversion() {
        assert_eq!(ReportFormat::from(OutputFormat::Json), ReportFormat::Json);
        assert_eq!(ReportFormat::from(OutputFormat::Html), ReportFormat::Html);
    }
}
