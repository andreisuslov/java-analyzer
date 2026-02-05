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

pub mod autofix;
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
pub mod suppression;
pub mod watch;

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
pub use autofix::{apply_fix, to_camel_case, to_pascal_case, to_upper_snake_case, Fix, TextEdit};
pub use rules::{AnalysisContext, Issue, OwaspCategory, Rule, RuleCategory, Severity};
pub use suppression::{Suppression, SuppressionIndex};
pub use watch::{DebounceState, FileWatcher, WatchConfig, WatchEvent};

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
    /// Optional cache for incremental analysis
    cache: Option<std::sync::Arc<std::sync::Mutex<AnalysisCache>>>,
    /// Path to cache file (for persistence)
    cache_path: Option<PathBuf>,
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
            cache: None,
            cache_path: None,
        }
    }

    /// Create an analyzer with caching enabled
    pub fn with_cache(config: AnalyzerConfig, cache_path: PathBuf) -> Self {
        let mut analyzer = Self::with_config(config.clone());

        // Calculate config hash for cache invalidation
        let config_hash = hash_config(&config);

        // Try to load existing cache, or create new one
        let cache = if cache_path.exists() {
            match AnalysisCache::load(&cache_path) {
                Ok(loaded) => {
                    if loaded.is_compatible(env!("CARGO_PKG_VERSION"), config_hash) {
                        loaded
                    } else {
                        // Cache is incompatible, create new one
                        AnalysisCache::new(env!("CARGO_PKG_VERSION"), config_hash)
                    }
                }
                Err(_) => AnalysisCache::new(env!("CARGO_PKG_VERSION"), config_hash),
            }
        } else {
            AnalysisCache::new(env!("CARGO_PKG_VERSION"), config_hash)
        };

        analyzer.cache = Some(std::sync::Arc::new(std::sync::Mutex::new(cache)));
        analyzer.cache_path = Some(cache_path);
        analyzer
    }

    /// Enable caching with default cache path
    pub fn enable_cache(&mut self) {
        let config_hash = hash_config(&self.config);
        let cache_path = cache::default_cache_path();

        let cache = if cache_path.exists() {
            match AnalysisCache::load(&cache_path) {
                Ok(loaded) => {
                    if loaded.is_compatible(env!("CARGO_PKG_VERSION"), config_hash) {
                        loaded
                    } else {
                        AnalysisCache::new(env!("CARGO_PKG_VERSION"), config_hash)
                    }
                }
                Err(_) => AnalysisCache::new(env!("CARGO_PKG_VERSION"), config_hash),
            }
        } else {
            AnalysisCache::new(env!("CARGO_PKG_VERSION"), config_hash)
        };

        self.cache = Some(std::sync::Arc::new(std::sync::Mutex::new(cache)));
        self.cache_path = Some(cache_path);
    }

    /// Save cache to disk
    pub fn save_cache(&self) -> Result<(), cache::CacheError> {
        if let (Some(cache), Some(path)) = (&self.cache, &self.cache_path) {
            let cache = cache.lock().unwrap();
            cache.save(path)?;
        }
        Ok(())
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> Option<CacheStats> {
        self.cache.as_ref().map(|c| c.lock().unwrap().stats())
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
        self.analyze_file_with_cache_info(path).0
    }

    /// Analyze a single file and return (issues, was_cache_hit)
    fn analyze_file_with_cache_info(&self, path: &Path) -> (Vec<Issue>, bool) {
        // Check cache first
        if let Some(ref cache) = self.cache {
            let cache_guard = cache.lock().unwrap();
            if let Some(entry) = cache_guard.get(path) {
                return (entry.issues.clone(), true);
            }
        }

        // Cache miss - perform full analysis
        let source = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), false),
        };

        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => return (Vec::new(), false),
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

        // Filter out suppressed issues (NOSONAR comments, @SuppressWarnings)
        let suppressions = suppression::SuppressionIndex::parse(&source);
        let issues = suppressions.filter_issues(issues);

        // Update cache
        if let Some(ref cache) = self.cache {
            let mut cache_guard = cache.lock().unwrap();
            cache_guard.update(path, issues.clone());
        }

        (issues, false)
    }

    /// Analyze a directory recursively
    pub fn analyze_directory(&self, path: &Path) -> AnalysisResult {
        let start = Instant::now();
        let files_count = AtomicUsize::new(0);
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);

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
                let (issues, was_hit) = self.analyze_file_with_cache_info(path);
                if was_hit {
                    cache_hits.fetch_add(1, Ordering::Relaxed);
                } else {
                    cache_misses.fetch_add(1, Ordering::Relaxed);
                }
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
            cache_hits: cache_hits.load(Ordering::Relaxed),
            cache_misses: cache_misses.load(Ordering::Relaxed),
        }
    }

    /// Analyze a path (file or directory)
    pub fn analyze(&self, path: &Path) -> AnalysisResult {
        if path.is_file() {
            let start = Instant::now();
            let (issues, was_hit) = self.analyze_file_with_cache_info(path);
            let duration = start.elapsed();

            AnalysisResult {
                files_analyzed: 1,
                issues,
                duration_ms: duration.as_millis() as u64,
                modules: None,
                cache_hits: if was_hit { 1 } else { 0 },
                cache_misses: if was_hit { 0 } else { 1 },
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
    /// Number of files served from cache (cache hits)
    #[serde(default)]
    pub cache_hits: usize,
    /// Number of files that required fresh analysis (cache misses)
    #[serde(default)]
    pub cache_misses: usize,
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

    // ===== Suppression Integration Tests =====

    #[test]
    fn test_nosonar_suppresses_issues() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");

        // This code has a class naming violation (lowercase 'test')
        // but it's suppressed with NOSONAR
        let code = r#"public class test {} // NOSONAR"#;
        fs::write(&file_path, code).unwrap();

        let analyzer = Analyzer::new();
        let issues = analyzer.analyze_file(&file_path);

        // S101 (class naming) should be suppressed
        assert!(
            !issues.iter().any(|i| i.rule_id == "S101"),
            "S101 should be suppressed by NOSONAR"
        );
    }

    #[test]
    fn test_nosonar_specific_rule_suppression() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");

        // Suppress only S101, not other rules on the same line
        let code = r#"public class test {} // NOSONAR S101"#;
        fs::write(&file_path, code).unwrap();

        let analyzer = Analyzer::new();
        let issues = analyzer.analyze_file(&file_path);

        // S101 should be suppressed
        assert!(
            !issues.iter().any(|i| i.rule_id == "S101"),
            "S101 should be suppressed by NOSONAR S101"
        );
    }

    #[test]
    fn test_without_nosonar_issues_reported() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");

        // This code has a class naming violation without suppression
        let code = r#"public class test {}"#;
        fs::write(&file_path, code).unwrap();

        let analyzer = Analyzer::new();
        let issues = analyzer.analyze_file(&file_path);

        // S101 should be reported
        assert!(
            issues.iter().any(|i| i.rule_id == "S101"),
            "S101 should be reported without NOSONAR"
        );
    }

    // ===== Incremental Cache Integration Tests =====

    #[test]
    fn test_cache_miss_on_first_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");
        let cache_path = temp_dir.path().join(".cache.json");

        fs::write(&file_path, "public class test {}").unwrap();

        let config = AnalyzerConfig::default();
        let analyzer = Analyzer::with_cache(config, cache_path);
        let result = analyzer.analyze(&file_path);

        assert_eq!(result.files_analyzed, 1);
        assert_eq!(result.cache_hits, 0, "First analysis should be a cache miss");
        assert_eq!(result.cache_misses, 1, "First analysis should be a cache miss");
    }

    #[test]
    fn test_cache_hit_on_second_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");
        let cache_path = temp_dir.path().join(".cache.json");

        fs::write(&file_path, "public class test {}").unwrap();

        let config = AnalyzerConfig::default();
        let analyzer = Analyzer::with_cache(config, cache_path);

        // First analysis - cache miss
        let r1 = analyzer.analyze(&file_path);
        assert_eq!(r1.cache_misses, 1);

        // Second analysis - should be cache hit
        let r2 = analyzer.analyze(&file_path);
        assert_eq!(r2.cache_hits, 1, "Second analysis should be a cache hit");
        assert_eq!(r2.cache_misses, 0);

        // Issues should be the same
        assert_eq!(r1.issues.len(), r2.issues.len());
    }

    #[test]
    fn test_cache_miss_after_file_modification() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");
        let cache_path = temp_dir.path().join(".cache.json");

        fs::write(&file_path, "public class test {}").unwrap();

        let config = AnalyzerConfig::default();
        let analyzer = Analyzer::with_cache(config, cache_path);

        // First analysis
        let _r1 = analyzer.analyze(&file_path);

        // Modify file (add small delay to ensure mtime changes)
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&file_path, "public class Test {}").unwrap();

        // Second analysis should be cache miss due to file change
        let r2 = analyzer.analyze(&file_path);
        assert_eq!(r2.cache_misses, 1, "Modified file should cause cache miss");
    }

    #[test]
    fn test_cache_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");
        let cache_path = temp_dir.path().join(".cache.json");

        fs::write(&file_path, "public class test {}").unwrap();

        // First analyzer instance - analyze and save cache
        {
            let config = AnalyzerConfig::default();
            let analyzer = Analyzer::with_cache(config, cache_path.clone());
            let _r1 = analyzer.analyze(&file_path);
            analyzer.save_cache().unwrap();
        }

        // Second analyzer instance - should load cache and get hit
        {
            let config = AnalyzerConfig::default();
            let analyzer = Analyzer::with_cache(config, cache_path);
            let r2 = analyzer.analyze(&file_path);
            assert_eq!(r2.cache_hits, 1, "Loaded cache should provide cache hit");
        }
    }

    #[test]
    fn test_no_cache_without_enable() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Test.java");

        fs::write(&file_path, "public class test {}").unwrap();

        let analyzer = Analyzer::new(); // No cache enabled
        let result = analyzer.analyze(&file_path);

        // Without cache, always shows as miss
        assert_eq!(result.cache_hits, 0);
        assert_eq!(result.cache_misses, 1);
    }

    #[test]
    fn test_cache_stats() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join(".cache.json");

        // Create multiple files
        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("Test{}.java", i));
            fs::write(&file_path, format!("public class Test{} {{}}", i)).unwrap();
        }

        let config = AnalyzerConfig::default();
        let analyzer = Analyzer::with_cache(config, cache_path);

        // Analyze directory
        let _result = analyzer.analyze(temp_dir.path());

        // Check cache stats
        let stats = analyzer.cache_stats();
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_entries, 3);
    }
}
