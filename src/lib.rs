//! Java Analyzer - A fast static code analyzer for Java based on SonarSource rules
//!
//! This library provides comprehensive Java code analysis with support for:
//! - Naming conventions
//! - Security vulnerabilities
//! - Bug detection
//! - Code smell identification
//! - Cognitive complexity analysis

// Allow pre-existing clippy lints that would require significant refactoring
#![allow(clippy::borrowed_box)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::map_entry)]
#![allow(clippy::manual_find)]
#![allow(clippy::single_char_add_str)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::manual_saturating_arithmetic)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::regex_creation_in_loops)]
#![allow(clippy::implicit_saturating_sub)]
#![allow(clippy::unused_enumerate_index)]
#![allow(clippy::trim_split_whitespace)]
#![allow(dead_code)]

pub mod baseline;
pub mod cache;
pub mod coverage;
pub mod debt;
pub mod duplication;
pub mod hotspots;
pub mod module;
pub mod parser;
pub mod quality_gate;
pub mod reports;
pub mod rules;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

pub use baseline::{compare_with_baseline, Baseline, DifferentialResult, IssueFingerprint};
pub use cache::{hash_config, AnalysisCache, CacheEntry, CacheStats};
pub use coverage::{load_coverage, parse_jacoco_xml, parse_lcov, CoverageReport, FileCoverage};
pub use debt::{format_debt, DebtBreakdown, DebtRating, DebtSummary};
pub use duplication::{
    CodeLocation, DuplicateBlock, DuplicationConfig, DuplicationDetector, DuplicationResult,
};
pub use hotspots::{
    HotspotCategory, HotspotPriority, HotspotResult, HotspotStatus, SecurityHotspot,
};
pub use module::{detect_gradle, detect_maven, BuildSystem, Module, ModuleStructure};
pub use quality_gate::{ConditionResult, QualityCondition, QualityGate, QualityGateResult};
pub use reports::{Report, ReportFormat};
pub use rules::custom::{
    load_custom_rules, CustomRule, CustomRuleConfig, CustomRuleError, CustomRulesConfig,
};
pub use rules::{AnalysisContext, Issue, OwaspCategory, Rule, RuleCategory, Severity};

/// Configuration for the analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalyzerConfig {
    /// Minimum severity to report
    pub min_severity: Severity,
    /// Specific rules to enable (None = all)
    pub enabled_rules: Option<Vec<String>>,
    /// Specific rules to disable
    pub disabled_rules: Vec<String>,
    /// Patterns to exclude
    pub exclude_patterns: Vec<String>,
    /// Maximum cognitive complexity threshold
    pub max_complexity: usize,
    /// Maximum number of parameters per method
    pub max_params: Option<usize>,
    /// Maximum nesting depth
    pub max_nesting: Option<usize>,
    /// Fail on severity level (for CI)
    pub fail_on_severity: Option<Severity>,
    /// Output format
    pub output_format: Option<String>,
    /// Path to custom rules YAML file
    pub custom_rules_file: Option<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Info,
            enabled_rules: None,
            disabled_rules: vec![],
            exclude_patterns: vec![
                "target/".to_string(),
                "build/".to_string(),
                "node_modules/".to_string(),
                ".git/".to_string(),
            ],
            max_complexity: 15,
            max_params: Some(7),
            max_nesting: Some(4),
            fail_on_severity: None,
            output_format: None,
            custom_rules_file: None,
        }
    }
}

impl AnalyzerConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;

        toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Try to find and load config from standard locations
    pub fn discover(start_path: &Path) -> Option<Self> {
        let config_names = [
            ".java-analyzer.toml",
            "java-analyzer.toml",
            ".java-analyzer.json",
        ];

        // Search from start_path up to root
        let mut current = if start_path.is_file() {
            start_path.parent()
        } else {
            Some(start_path)
        };

        while let Some(dir) = current {
            for name in &config_names {
                let config_path = dir.join(name);
                if config_path.exists() {
                    if name.ends_with(".toml") {
                        if let Ok(config) = Self::from_file(&config_path) {
                            return Some(config);
                        }
                    } else if name.ends_with(".json") {
                        if let Ok(content) = fs::read_to_string(&config_path) {
                            if let Ok(config) = serde_json::from_str(&content) {
                                return Some(config);
                            }
                        }
                    }
                }
            }
            current = dir.parent();
        }

        None
    }

    /// Merge another config into this one (other takes precedence)
    pub fn merge(&mut self, other: Self) {
        if other.min_severity != Severity::Info {
            self.min_severity = other.min_severity;
        }
        if other.enabled_rules.is_some() {
            self.enabled_rules = other.enabled_rules;
        }
        if !other.disabled_rules.is_empty() {
            self.disabled_rules.extend(other.disabled_rules);
        }
        if !other.exclude_patterns.is_empty() {
            self.exclude_patterns.extend(other.exclude_patterns);
        }
        if other.max_complexity != 15 {
            self.max_complexity = other.max_complexity;
        }
        if other.max_params.is_some() {
            self.max_params = other.max_params;
        }
        if other.max_nesting.is_some() {
            self.max_nesting = other.max_nesting;
        }
        if other.fail_on_severity.is_some() {
            self.fail_on_severity = other.fail_on_severity;
        }
        if other.output_format.is_some() {
            self.output_format = other.output_format;
        }
        if other.custom_rules_file.is_some() {
            self.custom_rules_file = other.custom_rules_file;
        }
    }
}

/// Configuration loading errors
#[derive(Debug, Clone)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
}

/// Main analyzer engine
pub struct Analyzer {
    rules: Vec<Box<dyn Rule>>,
    config: AnalyzerConfig,
    custom_rules_error: Option<String>,
}

impl Analyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(AnalyzerConfig::default())
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalyzerConfig) -> Self {
        let mut rules = rules::create_all_rules();
        let mut custom_rules_error = None;

        // Load custom rules if configured
        if let Some(ref custom_rules_path) = config.custom_rules_file {
            match rules::custom::load_custom_rules(Path::new(custom_rules_path)) {
                Ok(custom_rules) => {
                    rules.extend(custom_rules);
                }
                Err(e) => {
                    custom_rules_error = Some(format!("{}", e));
                }
            }
        }

        Self {
            rules,
            config,
            custom_rules_error,
        }
    }

    /// Get the error that occurred when loading custom rules (if any)
    pub fn custom_rules_error(&self) -> Option<&str> {
        self.custom_rules_error.as_deref()
    }

    /// Get all available rules
    pub fn available_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    /// Get rules filtered by configuration
    fn active_rules(&self) -> Vec<&Box<dyn Rule>> {
        self.rules
            .iter()
            .filter(|rule| {
                // Check severity
                if rule.severity() < self.config.min_severity {
                    return false;
                }

                // Check if explicitly disabled
                if self.config.disabled_rules.iter().any(|r| r == rule.id()) {
                    return false;
                }

                // Check if only specific rules are enabled
                if let Some(ref enabled) = self.config.enabled_rules {
                    if !enabled.iter().any(|r| r == rule.id()) {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    /// Analyze a single file
    pub fn analyze_file(&self, path: &Path) -> Vec<Issue> {
        let source = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let ctx = AnalysisContext {
            source: &source,
            file_path: path.to_str().unwrap_or(""),
            tree: &tree,
            config: &self.config,
        };

        let active_rules = self.active_rules();
        let mut issues = Vec::new();

        for rule in active_rules {
            issues.extend(rule.check(&ctx));
        }

        issues
    }

    /// Analyze a directory recursively
    pub fn analyze_directory(&self, path: &Path) -> AnalysisResult {
        let start = Instant::now();
        let files_count = AtomicUsize::new(0);
        let issues_count = AtomicUsize::new(0);

        // Collect Java files
        let java_files: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "java"))
            .filter(|e| {
                let path_str = e.path().to_string_lossy();
                !self
                    .config
                    .exclude_patterns
                    .iter()
                    .any(|p| path_str.contains(p))
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        // Analyze in parallel
        let all_issues: Vec<Issue> = java_files
            .par_iter()
            .flat_map(|path| {
                files_count.fetch_add(1, Ordering::Relaxed);
                let issues = self.analyze_file(path);
                issues_count.fetch_add(issues.len(), Ordering::Relaxed);
                issues
            })
            .collect();

        let duration = start.elapsed();

        // Detect module structure
        let module_structure = ModuleStructure::detect(path);

        // Assign modules to issues if module structure was detected
        let all_issues = if let Some(ref modules) = module_structure {
            all_issues
                .into_iter()
                .map(|mut issue| {
                    let file_path = Path::new(&issue.file);
                    if let Some(module_name) = modules.module_name_for_file(file_path) {
                        issue.module = Some(module_name.to_string());
                    }
                    issue
                })
                .collect()
        } else {
            all_issues
        };

        AnalysisResult {
            files_analyzed: files_count.load(Ordering::Relaxed),
            issues: all_issues,
            duration_ms: duration.as_millis() as u64,
            modules: module_structure,
        }
    }

    /// Analyze a path (file or directory)
    pub fn analyze(&self, path: &Path) -> AnalysisResult {
        if path.is_file() {
            let start = Instant::now();
            let issues = self.analyze_file(path);
            let duration = start.elapsed();

            AnalysisResult {
                files_analyzed: 1,
                issues,
                duration_ms: duration.as_millis() as u64,
                modules: None,
            }
        } else {
            self.analyze_directory(path)
        }
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of an analysis run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub files_analyzed: usize,
    pub issues: Vec<Issue>,
    pub duration_ms: u64,
    /// Module structure (for multi-module projects)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules: Option<ModuleStructure>,
}

impl AnalysisResult {
    /// Get issues grouped by file
    pub fn issues_by_file(&self) -> HashMap<String, Vec<&Issue>> {
        let mut map: HashMap<String, Vec<&Issue>> = HashMap::new();
        for issue in &self.issues {
            map.entry(issue.file.clone()).or_default().push(issue);
        }
        map
    }

    /// Get issues grouped by severity
    pub fn issues_by_severity(&self) -> HashMap<Severity, Vec<&Issue>> {
        let mut map: HashMap<Severity, Vec<&Issue>> = HashMap::new();
        for issue in &self.issues {
            map.entry(issue.severity).or_default().push(issue);
        }
        map
    }

    /// Get issues grouped by rule
    pub fn issues_by_rule(&self) -> HashMap<String, Vec<&Issue>> {
        let mut map: HashMap<String, Vec<&Issue>> = HashMap::new();
        for issue in &self.issues {
            map.entry(issue.rule_id.clone()).or_default().push(issue);
        }
        map
    }

    /// Count issues by severity
    pub fn severity_counts(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for issue in &self.issues {
            *counts.entry(issue.severity).or_default() += 1;
        }
        counts
    }

    /// Get issues grouped by module
    pub fn issues_by_module(&self) -> HashMap<String, Vec<&Issue>> {
        let mut map: HashMap<String, Vec<&Issue>> = HashMap::new();
        for issue in &self.issues {
            let module_name = issue.module.clone().unwrap_or_else(|| "(root)".to_string());
            map.entry(module_name).or_default().push(issue);
        }
        map
    }

    /// Check if this is a multi-module project analysis
    pub fn is_multi_module(&self) -> bool {
        self.modules.as_ref().map_or(false, |m| m.is_multi_module())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = Analyzer::new();
        assert!(!analyzer.available_rules().is_empty());
    }

    #[test]
    fn test_analyzer_with_config() {
        let config = AnalyzerConfig {
            min_severity: Severity::Major,
            ..Default::default()
        };
        let analyzer = Analyzer::with_config(config);
        assert!(!analyzer.available_rules().is_empty());
    }

    // ===== Config File Tests =====

    #[test]
    fn test_config_from_toml_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("java-analyzer.toml");

        let config_content = r#"
min_severity = "major"
max_complexity = 20
disabled_rules = ["S100", "S101"]
exclude_patterns = ["**/test/**"]
"#;
        fs::write(&config_path, config_content).unwrap();

        let config = AnalyzerConfig::from_file(&config_path).unwrap();

        assert_eq!(config.min_severity, Severity::Major);
        assert_eq!(config.max_complexity, 20);
        assert!(config.disabled_rules.contains(&"S100".to_string()));
        assert!(config.exclude_patterns.contains(&"**/test/**".to_string()));
    }

    #[test]
    fn test_config_discover() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".java-analyzer.toml");

        let config_content = r#"
min_severity = "critical"
max_complexity = 10
"#;
        fs::write(&config_path, config_content).unwrap();

        let config = AnalyzerConfig::discover(temp_dir.path());
        assert!(config.is_some());

        let config = config.unwrap();
        assert_eq!(config.min_severity, Severity::Critical);
        assert_eq!(config.max_complexity, 10);
    }

    #[test]
    fn test_config_discover_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let config = AnalyzerConfig::discover(temp_dir.path());
        assert!(config.is_none());
    }

    #[test]
    fn test_config_merge() {
        let mut base = AnalyzerConfig::default();
        let override_config = AnalyzerConfig {
            min_severity: Severity::Critical,
            disabled_rules: vec!["S100".to_string()],
            max_complexity: 25,
            ..Default::default()
        };

        base.merge(override_config);

        assert_eq!(base.min_severity, Severity::Critical);
        assert!(base.disabled_rules.contains(&"S100".to_string()));
        assert_eq!(base.max_complexity, 25);
    }

    #[test]
    fn test_config_default_values() {
        let config = AnalyzerConfig::default();

        assert_eq!(config.min_severity, Severity::Info);
        assert_eq!(config.max_complexity, 15);
        assert!(config.enabled_rules.is_none());
        assert!(config.disabled_rules.is_empty());
        assert!(!config.exclude_patterns.is_empty());
    }
}
