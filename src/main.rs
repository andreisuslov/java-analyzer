//! Java Analyzer CLI
//!
//! A fast static code analyzer for Java based on SonarSource rules.

#![allow(clippy::ptr_arg)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::manual_map)]

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;

use java_analyzer::coverage::load_coverage;
use java_analyzer::hotspots::HotspotResult;
use java_analyzer::reports::{Report, ReportConfig, ReportFormat};
use java_analyzer::{compare_with_baseline, Baseline};
use java_analyzer::{AnalysisResult, Analyzer, AnalyzerConfig, QualityGate, Severity};
use java_analyzer::{DebtRating, DebtSummary};
use java_analyzer::{DuplicationConfig, DuplicationDetector};

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

    /// Apply a quality gate (strict, standard, lenient)
    #[arg(long, value_enum)]
    quality_gate: Option<QualityGatePreset>,

    /// Load quality gate from a JSON or TOML file
    #[arg(long, value_name = "FILE")]
    quality_gate_file: Option<PathBuf>,
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

    /// Detect code duplication
    Duplication {
        /// Path to analyze
        path: PathBuf,

        /// Minimum lines to consider a duplicate
        #[arg(long, default_value = "6")]
        min_lines: usize,

        /// Ignore whitespace differences
        #[arg(long, default_value = "true")]
        ignore_whitespace: bool,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Create a baseline from current analysis
    Baseline {
        /// Path to analyze
        path: PathBuf,

        /// Output baseline file
        #[arg(short, long, default_value = "java-analyzer-baseline.json")]
        output: PathBuf,

        /// Description for the baseline
        #[arg(long)]
        description: Option<String>,
    },

    /// Compare against a baseline (differential analysis)
    Diff {
        /// Path to analyze
        path: PathBuf,

        /// Baseline file to compare against
        #[arg(short, long)]
        baseline: PathBuf,

        /// Only show new issues
        #[arg(long)]
        new_only: bool,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Show technical debt summary
    Debt {
        /// Path to analyze
        path: PathBuf,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Show security hotspots
    Hotspots {
        /// Path to analyze
        path: PathBuf,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Import and display test coverage
    Coverage {
        /// Coverage report file (JaCoCo XML or LCOV format)
        report: PathBuf,

        /// Minimum coverage threshold (%)
        #[arg(long, default_value = "80")]
        threshold: f64,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
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

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum QualityGatePreset {
    /// Strict: No blockers or criticals, max 10 major issues, max 60 min debt
    Strict,
    /// Standard: No blockers, max 5 criticals, max 120 min debt
    Standard,
    /// Lenient: Only fails on blocker issues
    Lenient,
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
        Some(Commands::Init { output }) => generate_config(&output),
        Some(Commands::Duplication {
            path,
            min_lines,
            ignore_whitespace,
            format,
        }) => run_duplication_check(&path, min_lines, ignore_whitespace, &format),
        Some(Commands::Baseline {
            path,
            output,
            description,
        }) => create_baseline(&path, &output, description),
        Some(Commands::Diff {
            path,
            baseline,
            new_only,
            format,
        }) => run_diff_analysis(&path, &baseline, new_only, &format),
        Some(Commands::Debt { path, format }) => show_debt_summary(&path, &format),
        Some(Commands::Hotspots { path, format }) => show_hotspots(&path, &format),
        Some(Commands::Coverage {
            report,
            threshold,
            format,
        }) => show_coverage(&report, threshold, &format),
        Some(Commands::Analyze { ref path }) => run_analysis(&cli, path),
        None => match &cli.path {
            Some(p) => run_analysis(&cli, p),
            None => {
                eprintln!(
                    "{}: No path specified. Use --help for usage.",
                    "Error".red().bold()
                );
                ExitCode::FAILURE
            }
        },
    }
}

fn run_analysis(cli: &Cli, path: &PathBuf) -> ExitCode {
    if !path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            path.display()
        );
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
        eprintln!(
            "{} {} rules active",
            "Info:".blue().bold(),
            analyzer.available_rules().len()
        );
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
                        eprintln!(
                            "{} Report written to {}",
                            "Success:".green().bold(),
                            output_path.display()
                        );
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

    // Evaluate quality gate if specified
    let gate_passed = evaluate_quality_gate(cli, &result);

    // Determine exit code
    let has_issues = !result.issues.is_empty();

    if !gate_passed {
        return ExitCode::FAILURE;
    }

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

fn evaluate_quality_gate(cli: &Cli, result: &AnalysisResult) -> bool {
    // Determine which quality gate to use
    let gate = if let Some(ref gate_file) = cli.quality_gate_file {
        // Load from file
        let loaded = if gate_file.extension().map_or(false, |e| e == "toml") {
            QualityGate::from_toml_file(gate_file)
        } else {
            QualityGate::from_file(gate_file)
        };

        match loaded {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!(
                    "{}: Failed to load quality gate: {}",
                    "Error".red().bold(),
                    e
                );
                return true; // Don't fail on gate load error
            }
        }
    } else if let Some(preset) = cli.quality_gate {
        Some(match preset {
            QualityGatePreset::Strict => QualityGate::strict(),
            QualityGatePreset::Standard => QualityGate::standard(),
            QualityGatePreset::Lenient => QualityGate::lenient(),
        })
    } else {
        None
    };

    // Evaluate if a gate is configured
    if let Some(gate) = gate {
        let gate_result = gate.evaluate(result);

        // Print quality gate result
        println!();
        if cli.no_color {
            println!("{}", gate_result.summary());
        } else {
            let status = if gate_result.passed {
                "PASSED".green().bold()
            } else {
                "FAILED".red().bold()
            };
            println!(
                "{} Quality Gate: {} - {}",
                "━━━".dimmed(),
                gate_result.gate_name.cyan(),
                status
            );
            for cond in &gate_result.conditions {
                println!("    {}", cond.message);
            }
        }

        gate_result.passed
    } else {
        true // No gate configured, pass by default
    }
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

        println!(
            "{} [{}] {} - {}",
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
    println!(
        "{} {}",
        "Java Analyzer".bold().cyan(),
        env!("CARGO_PKG_VERSION")
    );
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
            println!(
                "{} Configuration written to {}",
                "Success:".green().bold(),
                output.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "{}: Failed to write configuration: {}",
                "Error".red().bold(),
                e
            );
            ExitCode::FAILURE
        }
    }
}

fn run_duplication_check(
    path: &PathBuf,
    min_lines: usize,
    ignore_whitespace: bool,
    format: &str,
) -> ExitCode {
    use walkdir::WalkDir;

    if !path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            path.display()
        );
        return ExitCode::FAILURE;
    }

    let config = DuplicationConfig {
        min_lines,
        ignore_whitespace,
        ..Default::default()
    };

    let detector = DuplicationDetector::with_config(config);

    // Collect Java files
    let files: Vec<(String, String)> = if path.is_file() {
        match fs::read_to_string(path) {
            Ok(content) => vec![(path.to_string_lossy().to_string(), content)],
            Err(e) => {
                eprintln!("{}: Failed to read file: {}", "Error".red().bold(), e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "java"))
            .filter_map(|e| {
                let path_str = e.path().to_string_lossy().to_string();
                fs::read_to_string(e.path())
                    .ok()
                    .map(|content| (path_str, content))
            })
            .collect()
    };

    if files.is_empty() {
        eprintln!("{}: No Java files found", "Warning".yellow().bold());
        return ExitCode::SUCCESS;
    }

    let result = detector.analyze_files(&files);

    if format == "json" {
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!(
                    "{}: Failed to serialize result: {}",
                    "Error".red().bold(),
                    e
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        // Text format
        println!("{}", "Code Duplication Analysis".bold().cyan());
        println!("{}", "=========================".cyan());
        println!();
        println!("Files analyzed:    {}", result.files_analyzed);
        println!("Total lines:       {}", result.total_lines);
        println!("Duplicated lines:  {}", result.duplicated_lines);
        println!("Duplication rate:  {:.1}%", result.duplication_percentage);
        println!();

        if result.duplicates.is_empty() {
            println!("{}", "No significant code duplication found.".green());
        } else {
            println!("{} duplicate blocks found:", result.duplicates.len());
            println!();

            for (i, dup) in result.duplicates.iter().enumerate() {
                if i >= 10 {
                    println!(
                        "... and {} more duplicate blocks",
                        result.duplicates.len() - 10
                    );
                    break;
                }

                println!(
                    "{}. {} occurrences ({} lines):",
                    i + 1,
                    dup.duplicate_count(),
                    dup.line_count
                );

                for loc in &dup.locations {
                    println!(
                        "   {} (lines {}-{})",
                        loc.file.dimmed(),
                        loc.start_line,
                        loc.end_line
                    );
                }

                if let Some(ref sample) = dup.code_sample {
                    println!("   {}", "Sample:".dimmed());
                    for line in sample.lines().take(3) {
                        println!("   │ {}", line.dimmed());
                    }
                }
                println!();
            }
        }
    }

    ExitCode::SUCCESS
}

fn create_baseline(path: &PathBuf, output: &PathBuf, description: Option<String>) -> ExitCode {
    if !path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            path.display()
        );
        return ExitCode::FAILURE;
    }

    let analyzer = Analyzer::new();
    let result = analyzer.analyze(path);

    let mut baseline = Baseline::from_analysis(&result);
    if let Some(desc) = description {
        baseline = baseline.with_description(desc);
    }

    match baseline.save(output) {
        Ok(_) => {
            println!(
                "{} Baseline created with {} issues",
                "Success:".green().bold(),
                baseline.issue_count()
            );
            println!("Saved to: {}", output.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

fn run_diff_analysis(
    path: &PathBuf,
    baseline_path: &PathBuf,
    new_only: bool,
    format: &str,
) -> ExitCode {
    if !path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            path.display()
        );
        return ExitCode::FAILURE;
    }

    if !baseline_path.exists() {
        eprintln!(
            "{}: Baseline file does not exist: {}",
            "Error".red().bold(),
            baseline_path.display()
        );
        return ExitCode::FAILURE;
    }

    // Load baseline
    let baseline = match Baseline::load(baseline_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            return ExitCode::FAILURE;
        }
    };

    // Run current analysis
    let analyzer = Analyzer::new();
    let current_result = analyzer.analyze(path);

    // Compare with baseline
    let diff = compare_with_baseline(&current_result, &baseline);

    if format == "json" {
        match serde_json::to_string_pretty(&diff) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!(
                    "{}: Failed to serialize result: {}",
                    "Error".red().bold(),
                    e
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        // Text format
        println!("{}", "Differential Analysis".bold().cyan());
        println!("{}", "=====================".cyan());
        println!();
        println!(
            "Baseline: {} (created: {})",
            baseline_path.display(),
            baseline.created_at
        );
        if let Some(ref desc) = baseline.description {
            println!("Description: {}", desc);
        }
        println!();

        let net = diff.net_change();
        let trend = if net > 0 {
            format!("+{}", net).red().to_string()
        } else if net < 0 {
            format!("{}", net).green().to_string()
        } else {
            "0".to_string()
        };

        println!(
            "{} new | {} fixed | {} unchanged | Net: {}",
            diff.new_count.to_string().red(),
            diff.fixed_count.to_string().green(),
            diff.unchanged_count.to_string().dimmed(),
            trend
        );
        println!();

        if !diff.new_issues.is_empty() {
            println!("{}", "New Issues:".red().bold());
            for issue in &diff.new_issues {
                println!(
                    "  [{}] {}:{} - {} ({})",
                    format!("{:?}", issue.severity).yellow(),
                    issue.file,
                    issue.line,
                    issue.message,
                    issue.rule_id.dimmed()
                );
            }
            println!();
        }

        if !new_only && !diff.fixed_issues.is_empty() {
            println!("{}", "Fixed Issues:".green().bold());
            for fp in &diff.fixed_issues {
                println!(
                    "  [{}] {}:{} - {}",
                    "FIXED".green(),
                    fp.file,
                    fp.line,
                    fp.rule_id.dimmed()
                );
            }
            println!();
        }

        if diff.new_issues.is_empty() && diff.fixed_issues.is_empty() {
            println!("{}", "No changes from baseline.".dimmed());
        }
    }

    // Return failure if there are new issues
    if diff.has_new_issues() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn show_debt_summary(path: &PathBuf, format: &str) -> ExitCode {
    if !path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            path.display()
        );
        return ExitCode::FAILURE;
    }

    let analyzer = Analyzer::new();
    let result = analyzer.analyze(path);
    let debt = DebtSummary::from_analysis(&result);

    if format == "json" {
        match serde_json::to_string_pretty(&debt) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("{}: Failed to serialize: {}", "Error".red().bold(), e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("{}", "Technical Debt Summary".bold().cyan());
        println!("{}", "======================".cyan());
        println!();

        let rating = debt.rating();
        let rating_color = match rating {
            DebtRating::A => "A".green(),
            DebtRating::B => "B".green(),
            DebtRating::C => "C".yellow(),
            DebtRating::D => "D".red(),
            DebtRating::E => "E".red().bold(),
        };

        println!(
            "Total Debt:  {} ({})",
            debt.formatted_total.bold(),
            rating.description()
        );
        println!("Rating:      {}", rating_color.bold());
        println!();

        println!("{}", "By Severity:".dimmed());
        for (sev, mins) in &debt.by_severity {
            println!("  {}: {}", sev, java_analyzer::format_debt(*mins));
        }
        println!();

        println!("{}", "By Category:".dimmed());
        for (cat, mins) in &debt.by_category {
            println!("  {}: {}", cat, java_analyzer::format_debt(*mins));
        }
        println!();

        if !debt.by_file.is_empty() {
            println!("{}", "Top Files by Debt:".dimmed());
            for (file, mins) in debt.by_file.iter().take(5) {
                println!("  {} - {}", java_analyzer::format_debt(*mins), file);
            }
            println!();
        }

        if !debt.by_rule.is_empty() {
            println!("{}", "Top Rules by Debt:".dimmed());
            for (rule, mins) in debt.by_rule.iter().take(5) {
                println!("  {} - {}", java_analyzer::format_debt(*mins), rule);
            }
        }
    }

    ExitCode::SUCCESS
}

fn show_hotspots(path: &PathBuf, format: &str) -> ExitCode {
    if !path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            path.display()
        );
        return ExitCode::FAILURE;
    }

    let analyzer = Analyzer::new();
    let result = analyzer.analyze(path);
    let hotspots = HotspotResult::from_analysis(&result);

    if format == "json" {
        match serde_json::to_string_pretty(&hotspots) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("{}: Failed to serialize: {}", "Error".red().bold(), e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("{}", "Security Hotspots".bold().cyan());
        println!("{}", "=================".cyan());
        println!();

        println!("Total Hotspots: {}", hotspots.total_hotspots);
        println!(
            "  High Priority:   {}",
            hotspots.high_priority.len().to_string().red()
        );
        println!(
            "  Medium Priority: {}",
            hotspots.medium_priority.len().to_string().yellow()
        );
        println!("  Low Priority:    {}", hotspots.low_priority.len());
        println!();

        if !hotspots.high_priority.is_empty() {
            println!("{}", "High Priority Hotspots:".red().bold());
            for h in &hotspots.high_priority {
                println!(
                    "  [{}] {}:{} - {}",
                    h.category.as_str().red(),
                    h.issue.file,
                    h.issue.line,
                    h.issue.message
                );
            }
            println!();
        }

        if !hotspots.medium_priority.is_empty() {
            println!("{}", "Medium Priority Hotspots:".yellow().bold());
            for h in hotspots.medium_priority.iter().take(10) {
                println!(
                    "  [{}] {}:{} - {}",
                    h.category.as_str().yellow(),
                    h.issue.file,
                    h.issue.line,
                    h.issue.message
                );
            }
            if hotspots.medium_priority.len() > 10 {
                println!("  ... and {} more", hotspots.medium_priority.len() - 10);
            }
        }
    }

    if hotspots.high_priority.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn show_coverage(report_path: &PathBuf, threshold: f64, format: &str) -> ExitCode {
    let coverage = match load_coverage(report_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: Failed to load coverage: {}", "Error".red().bold(), e);
            return ExitCode::FAILURE;
        }
    };

    if format == "json" {
        match serde_json::to_string_pretty(&coverage) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("{}: Failed to serialize: {}", "Error".red().bold(), e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("{}", "Test Coverage Report".bold().cyan());
        println!("{}", "====================".cyan());
        println!();

        let cov_str = format!("{:.1}%", coverage.overall_line_coverage);
        let cov_colored = if coverage.overall_line_coverage >= threshold {
            cov_str.green()
        } else {
            cov_str.red()
        };

        println!(
            "Overall Coverage: {} (threshold: {:.1}%)",
            cov_colored.bold(),
            threshold
        );
        println!("Files with coverage: {}", coverage.files_with_coverage);
        println!("Lines covered:   {}", coverage.total_covered);
        println!("Lines uncovered: {}", coverage.total_uncovered);
        println!();

        let below = coverage.files_below_threshold(threshold);
        if !below.is_empty() {
            println!(
                "{}",
                format!("Files Below {}% Threshold:", threshold)
                    .red()
                    .bold()
            );
            for f in below.iter().take(10) {
                println!("  {:.1}% - {}", f.line_coverage, f.file);
            }
            if below.len() > 10 {
                println!("  ... and {} more files", below.len() - 10);
            }
        } else {
            println!("{}", "All files meet the coverage threshold!".green());
        }
    }

    if coverage.meets_threshold(threshold) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
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
