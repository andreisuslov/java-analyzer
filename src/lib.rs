//! Java Analyzer - A fast static code analyzer for Java based on SonarSource rules
//!
//! This library provides comprehensive Java code analysis with support for:
//! - Naming conventions
//! - Security vulnerabilities
//! - Bug detection
//! - Code smell identification
//! - Cognitive complexity analysis

pub mod rules;
pub mod reports;
pub mod parser;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

pub use rules::{Rule, RuleCategory, Severity, Issue, AnalysisContext};
pub use reports::{Report, ReportFormat};

/// Configuration for the analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        }
    }
}

/// Main analyzer engine
pub struct Analyzer {
    rules: Vec<Box<dyn Rule>>,
    config: AnalyzerConfig,
}

impl Analyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(AnalyzerConfig::default())
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalyzerConfig) -> Self {
        let rules = rules::create_all_rules();
        Self { rules, config }
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
            .filter(|e| {
                e.path().extension().map_or(false, |ext| ext == "java")
            })
            .filter(|e| {
                let path_str = e.path().to_string_lossy();
                !self.config.exclude_patterns.iter().any(|p| path_str.contains(p))
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

        AnalysisResult {
            files_analyzed: files_count.load(Ordering::Relaxed),
            issues: all_issues,
            duration_ms: duration.as_millis() as u64,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
