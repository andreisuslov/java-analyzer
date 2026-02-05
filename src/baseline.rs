//! Baseline and Differential Analysis
//!
//! Compares current analysis against a stored baseline to identify:
//! - New issues (not in baseline)
//! - Fixed issues (in baseline but not in current)
//! - Unchanged issues (in both)

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::rules::Issue;
use crate::AnalysisResult;

/// A fingerprint uniquely identifying an issue
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IssueFingerprint {
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    /// Hash of surrounding code context for location-independent matching
    pub context_hash: Option<u64>,
}

impl IssueFingerprint {
    pub fn from_issue(issue: &Issue) -> Self {
        Self {
            rule_id: issue.rule_id.clone(),
            file: issue.file.clone(),
            line: issue.line,
            context_hash: None,
        }
    }

    /// Create a fingerprint that ignores line numbers (for moved code detection)
    pub fn from_issue_with_context(issue: &Issue, context_hash: u64) -> Self {
        Self {
            rule_id: issue.rule_id.clone(),
            file: issue.file.clone(),
            line: issue.line,
            context_hash: Some(context_hash),
        }
    }
}

/// Stored baseline data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Version of the baseline format
    pub version: String,
    /// Timestamp when baseline was created
    pub created_at: String,
    /// Optional description
    pub description: Option<String>,
    /// Issue fingerprints in the baseline
    pub fingerprints: Vec<IssueFingerprint>,
}

impl Baseline {
    /// Create a new baseline from analysis results
    pub fn from_analysis(result: &AnalysisResult) -> Self {
        let fingerprints: Vec<IssueFingerprint> = result
            .issues
            .iter()
            .map(IssueFingerprint::from_issue)
            .collect();

        Self {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            description: None,
            fingerprints,
        }
    }

    /// Create a baseline with a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Save baseline to a JSON file
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize baseline: {}", e))?;

        fs::write(path, json).map_err(|e| format!("Failed to write baseline file: {}", e))
    }

    /// Load baseline from a JSON file
    pub fn load(path: &Path) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read baseline file: {}", e))?;

        serde_json::from_str(&content).map_err(|e| format!("Failed to parse baseline: {}", e))
    }

    /// Get the set of fingerprints for fast lookup
    pub fn fingerprint_set(&self) -> HashSet<IssueFingerprint> {
        self.fingerprints.iter().cloned().collect()
    }

    /// Number of issues in the baseline
    pub fn issue_count(&self) -> usize {
        self.fingerprints.len()
    }
}

/// Result of comparing current analysis against a baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResult {
    /// Issues that are new (not in baseline)
    pub new_issues: Vec<Issue>,
    /// Fingerprints of issues that were fixed (in baseline but not current)
    pub fixed_issues: Vec<IssueFingerprint>,
    /// Issues that are unchanged (in both baseline and current)
    pub unchanged_issues: Vec<Issue>,
    /// Total new issue count
    pub new_count: usize,
    /// Total fixed issue count
    pub fixed_count: usize,
    /// Total unchanged count
    pub unchanged_count: usize,
}

impl DifferentialResult {
    /// Create a summary string
    pub fn summary(&self) -> String {
        format!(
            "New: {} | Fixed: {} | Unchanged: {}",
            self.new_count, self.fixed_count, self.unchanged_count
        )
    }

    /// Check if there are any new issues
    pub fn has_new_issues(&self) -> bool {
        !self.new_issues.is_empty()
    }

    /// Get the net change in issues (positive = more issues, negative = fewer)
    pub fn net_change(&self) -> i64 {
        self.new_count as i64 - self.fixed_count as i64
    }
}

/// Compare current analysis against a baseline
pub fn compare_with_baseline(current: &AnalysisResult, baseline: &Baseline) -> DifferentialResult {
    let baseline_set = baseline.fingerprint_set();

    let mut new_issues = Vec::new();
    let mut unchanged_issues = Vec::new();
    let mut current_fingerprints = HashSet::new();

    // Categorize current issues
    for issue in &current.issues {
        let fingerprint = IssueFingerprint::from_issue(issue);
        current_fingerprints.insert(fingerprint.clone());

        if baseline_set.contains(&fingerprint) {
            unchanged_issues.push(issue.clone());
        } else {
            new_issues.push(issue.clone());
        }
    }

    // Find fixed issues (in baseline but not in current)
    let fixed_issues: Vec<IssueFingerprint> = baseline
        .fingerprints
        .iter()
        .filter(|fp| !current_fingerprints.contains(fp))
        .cloned()
        .collect();

    let new_count = new_issues.len();
    let fixed_count = fixed_issues.len();
    let unchanged_count = unchanged_issues.len();

    DifferentialResult {
        new_issues,
        fixed_issues,
        unchanged_issues,
        new_count,
        fixed_count,
        unchanged_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleCategory, Severity};

    fn create_test_issue(rule_id: &str, file: &str, line: usize) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            title: "Test Issue".to_string(),
            severity: Severity::Major,
            category: RuleCategory::Bug,
            file: file.to_string(),
            line,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Test message".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: 5,
            module: None,
            fix: None,
        }
    }

    fn create_test_result(issues: Vec<Issue>) -> AnalysisResult {
        AnalysisResult {
            files_analyzed: 1,
            issues,
            duration_ms: 100,
            modules: None,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    // ===== Fingerprint Tests =====

    #[test]
    fn test_fingerprint_from_issue() {
        let issue = create_test_issue("S100", "Test.java", 10);
        let fp = IssueFingerprint::from_issue(&issue);

        assert_eq!(fp.rule_id, "S100");
        assert_eq!(fp.file, "Test.java");
        assert_eq!(fp.line, 10);
        assert!(fp.context_hash.is_none());
    }

    #[test]
    fn test_fingerprint_equality() {
        let issue1 = create_test_issue("S100", "Test.java", 10);
        let issue2 = create_test_issue("S100", "Test.java", 10);

        let fp1 = IssueFingerprint::from_issue(&issue1);
        let fp2 = IssueFingerprint::from_issue(&issue2);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_line() {
        let issue1 = create_test_issue("S100", "Test.java", 10);
        let issue2 = create_test_issue("S100", "Test.java", 20);

        let fp1 = IssueFingerprint::from_issue(&issue1);
        let fp2 = IssueFingerprint::from_issue(&issue2);

        assert_ne!(fp1, fp2);
    }

    // ===== Baseline Tests =====

    #[test]
    fn test_baseline_from_analysis() {
        let result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);

        let baseline = Baseline::from_analysis(&result);

        assert_eq!(baseline.version, "1.0");
        assert_eq!(baseline.issue_count(), 2);
        assert!(baseline.description.is_none());
    }

    #[test]
    fn test_baseline_with_description() {
        let result = create_test_result(vec![]);
        let baseline = Baseline::from_analysis(&result).with_description("Initial baseline");

        assert_eq!(baseline.description, Some("Initial baseline".to_string()));
    }

    #[test]
    fn test_baseline_fingerprint_set() {
        let result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);

        let baseline = Baseline::from_analysis(&result);
        let fp_set = baseline.fingerprint_set();

        assert_eq!(fp_set.len(), 2);
    }

    // ===== Differential Analysis Tests =====

    #[test]
    fn test_no_changes() {
        let issues = vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ];

        let baseline_result = create_test_result(issues.clone());
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(issues);
        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.fixed_count, 0);
        assert_eq!(diff.unchanged_count, 2);
        assert!(!diff.has_new_issues());
        assert_eq!(diff.net_change(), 0);
    }

    #[test]
    fn test_new_issues_detected() {
        let baseline_result = create_test_result(vec![create_test_issue("S100", "Test.java", 10)]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20), // New issue
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 1);
        assert_eq!(diff.fixed_count, 0);
        assert_eq!(diff.unchanged_count, 1);
        assert!(diff.has_new_issues());
        assert_eq!(diff.net_change(), 1);
    }

    #[test]
    fn test_fixed_issues_detected() {
        let baseline_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            // S101 was fixed
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.fixed_count, 1);
        assert_eq!(diff.unchanged_count, 1);
        assert!(!diff.has_new_issues());
        assert_eq!(diff.net_change(), -1);
    }

    #[test]
    fn test_mixed_changes() {
        let baseline_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10), // Unchanged
            // S101 was fixed
            create_test_issue("S102", "Test.java", 30), // New
            create_test_issue("S103", "Test.java", 40), // New
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 2);
        assert_eq!(diff.fixed_count, 1);
        assert_eq!(diff.unchanged_count, 1);
        assert!(diff.has_new_issues());
        assert_eq!(diff.net_change(), 1); // 2 new - 1 fixed = +1
    }

    #[test]
    fn test_empty_baseline() {
        let baseline_result = create_test_result(vec![]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 2);
        assert_eq!(diff.fixed_count, 0);
        assert_eq!(diff.unchanged_count, 0);
    }

    #[test]
    fn test_all_issues_fixed() {
        let baseline_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.fixed_count, 2);
        assert_eq!(diff.unchanged_count, 0);
        assert_eq!(diff.net_change(), -2);
    }

    #[test]
    fn test_differential_summary() {
        let baseline_result = create_test_result(vec![create_test_issue("S100", "Test.java", 10)]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S100", "Test.java", 10),
            create_test_issue("S101", "Test.java", 20),
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);
        let summary = diff.summary();

        assert!(summary.contains("New: 1"));
        assert!(summary.contains("Fixed: 0"));
        assert!(summary.contains("Unchanged: 1"));
    }

    // ===== Edge Cases =====

    #[test]
    fn test_same_rule_different_files() {
        let baseline_result = create_test_result(vec![create_test_issue("S100", "File1.java", 10)]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S100", "File2.java", 10), // Different file
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 1);
        assert_eq!(diff.fixed_count, 1);
    }

    #[test]
    fn test_same_location_different_rules() {
        let baseline_result = create_test_result(vec![create_test_issue("S100", "Test.java", 10)]);
        let baseline = Baseline::from_analysis(&baseline_result);

        let current_result = create_test_result(vec![
            create_test_issue("S101", "Test.java", 10), // Different rule
        ]);

        let diff = compare_with_baseline(&current_result, &baseline);

        assert_eq!(diff.new_count, 1);
        assert_eq!(diff.fixed_count, 1);
    }
}
