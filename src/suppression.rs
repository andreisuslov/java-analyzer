//! Suppression Comments Support
//!
//! Allows users to suppress issues via `// NOSONAR` comments and
//! `@SuppressWarnings("rule-id")` annotations.

use crate::rules::Issue;
use regex::Regex;
use std::collections::HashMap;

/// Represents a single suppression directive
#[derive(Debug, Clone, PartialEq)]
pub struct Suppression {
    /// Line number where the suppression applies (1-indexed)
    pub line: usize,
    /// Rule IDs to suppress (empty means all rules)
    pub rule_ids: Vec<String>,
    /// Optional reason/justification for the suppression
    pub reason: Option<String>,
}

impl Suppression {
    /// Create a new suppression for all rules on a line
    pub fn all_rules(line: usize) -> Self {
        Self {
            line,
            rule_ids: Vec::new(),
            reason: None,
        }
    }

    /// Create a new suppression for specific rules
    pub fn for_rules(line: usize, rule_ids: Vec<String>) -> Self {
        Self {
            line,
            rule_ids,
            reason: None,
        }
    }

    /// Add a reason for the suppression
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Check if this suppression applies to a specific rule
    pub fn suppresses_rule(&self, rule_id: &str) -> bool {
        // Empty rule_ids means suppress all
        self.rule_ids.is_empty() || self.rule_ids.iter().any(|r| r == rule_id)
    }
}

/// Index of all suppressions in a source file for efficient lookup
#[derive(Debug, Clone)]
pub struct SuppressionIndex {
    /// Suppressions indexed by line number
    by_line: HashMap<usize, Vec<Suppression>>,
    /// Block-level suppressions (from annotations) with their ranges
    block_suppressions: Vec<BlockSuppression>,
}

/// A block-level suppression from @SuppressWarnings annotation
#[derive(Debug, Clone)]
struct BlockSuppression {
    start_line: usize,
    end_line: usize,
    rule_ids: Vec<String>,
}

impl SuppressionIndex {
    /// Parse source code to build a suppression index
    pub fn parse(source: &str) -> Self {
        let mut by_line: HashMap<usize, Vec<Suppression>> = HashMap::new();
        let block_suppressions = Vec::new();

        // Pattern for // NOSONAR [rule-ids] [reason]
        // Examples:
        //   // NOSONAR
        //   // NOSONAR S100
        //   // NOSONAR S100,S101
        //   // NOSONAR S100 - reason for suppression
        let nosonar_regex =
            Regex::new(r"//\s*NOSONAR\s*(?:([A-Za-z0-9,\s]+?))?(?:\s*[-:]\s*(.+))?$").unwrap();

        // Pattern for @SuppressWarnings with java-analyzer rule IDs
        // Examples:
        //   @SuppressWarnings("java-analyzer:S100")
        //   @SuppressWarnings({"java-analyzer:S100", "java-analyzer:S101"})
        let _suppress_warnings_regex =
            Regex::new(r#"@SuppressWarnings\s*\(\s*(?:"([^"]+)"|\{([^}]+)\})\s*\)"#).unwrap();

        for (line_num, line) in source.lines().enumerate() {
            let line_number = line_num + 1; // 1-indexed

            // Check for NOSONAR comment
            if let Some(caps) = nosonar_regex.captures(line) {
                let rule_ids = if let Some(rules_match) = caps.get(1) {
                    let rules_str = rules_match.as_str().trim();
                    if rules_str.is_empty() {
                        Vec::new()
                    } else {
                        rules_str
                            .split([',', ' '])
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect()
                    }
                } else {
                    Vec::new()
                };

                let reason = caps.get(2).map(|m| m.as_str().trim().to_string());

                let mut suppression = if rule_ids.is_empty() {
                    Suppression::all_rules(line_number)
                } else {
                    Suppression::for_rules(line_number, rule_ids)
                };

                if let Some(r) = reason {
                    suppression = suppression.with_reason(r);
                }

                by_line.entry(line_number).or_default().push(suppression);
            }
        }

        Self {
            by_line,
            block_suppressions,
        }
    }

    /// Check if an issue at a specific line with a specific rule is suppressed
    pub fn is_suppressed(&self, line: usize, rule_id: &str) -> bool {
        // Check line-level suppressions
        if let Some(suppressions) = self.by_line.get(&line) {
            if suppressions.iter().any(|s| s.suppresses_rule(rule_id)) {
                return true;
            }
        }

        // Check block-level suppressions
        for block in &self.block_suppressions {
            if line >= block.start_line
                && line <= block.end_line
                && (block.rule_ids.is_empty()
                    || block.rule_ids.iter().any(|r| r == rule_id))
            {
                return true;
            }
        }

        false
    }

    /// Filter a list of issues, removing any that are suppressed
    pub fn filter_issues(&self, issues: Vec<Issue>) -> Vec<Issue> {
        issues
            .into_iter()
            .filter(|issue| !self.is_suppressed(issue.line, &issue.rule_id))
            .collect()
    }

    /// Get the count of suppressions
    pub fn suppression_count(&self) -> usize {
        self.by_line.values().map(|v| v.len()).sum::<usize>() + self.block_suppressions.len()
    }

    /// Get all suppressions for reporting/auditing purposes
    pub fn all_suppressions(&self) -> Vec<&Suppression> {
        self.by_line.values().flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleCategory, Severity};

    fn create_test_issue(rule_id: &str, line: usize) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            title: "Test".to_string(),
            severity: Severity::Major,
            category: RuleCategory::Naming,
            file: "Test.java".to_string(),
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

    // ===== Suppression Creation Tests =====

    #[test]
    fn test_suppression_all_rules() {
        let s = Suppression::all_rules(10);
        assert_eq!(s.line, 10);
        assert!(s.rule_ids.is_empty());
        assert!(s.suppresses_rule("S100"));
        assert!(s.suppresses_rule("S101"));
        assert!(s.suppresses_rule("any_rule"));
    }

    #[test]
    fn test_suppression_specific_rules() {
        let s = Suppression::for_rules(10, vec!["S100".to_string(), "S101".to_string()]);
        assert_eq!(s.line, 10);
        assert_eq!(s.rule_ids.len(), 2);
        assert!(s.suppresses_rule("S100"));
        assert!(s.suppresses_rule("S101"));
        assert!(!s.suppresses_rule("S102"));
    }

    #[test]
    fn test_suppression_with_reason() {
        let s = Suppression::all_rules(10).with_reason("Legacy code".to_string());
        assert_eq!(s.reason, Some("Legacy code".to_string()));
    }

    // ===== NOSONAR Parsing Tests =====

    #[test]
    fn test_parse_nosonar_all_rules() {
        let source = "String x = \"test\"; // NOSONAR";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        assert!(index.is_suppressed(1, "S101"));
        assert!(index.is_suppressed(1, "any_rule"));
    }

    #[test]
    fn test_parse_nosonar_specific_rule() {
        let source = "String x = \"test\"; // NOSONAR S100";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        assert!(!index.is_suppressed(1, "S101"));
    }

    #[test]
    fn test_parse_nosonar_multiple_rules() {
        let source = "String x = \"test\"; // NOSONAR S100, S101";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        assert!(index.is_suppressed(1, "S101"));
        assert!(!index.is_suppressed(1, "S102"));
    }

    #[test]
    fn test_parse_nosonar_with_reason() {
        let source = "String x = \"test\"; // NOSONAR S100 - legacy code that cannot be changed";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        let suppressions = index.all_suppressions();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].reason,
            Some("legacy code that cannot be changed".to_string())
        );
    }

    #[test]
    fn test_parse_nosonar_multiline() {
        let source = "line1\nline2 // NOSONAR\nline3 // NOSONAR S100";
        let index = SuppressionIndex::parse(source);

        // Line 1: not suppressed
        assert!(!index.is_suppressed(1, "S100"));

        // Line 2: all rules suppressed
        assert!(index.is_suppressed(2, "S100"));
        assert!(index.is_suppressed(2, "S101"));

        // Line 3: only S100 suppressed
        assert!(index.is_suppressed(3, "S100"));
        assert!(!index.is_suppressed(3, "S101"));
    }

    #[test]
    fn test_parse_nosonar_case_variations() {
        let source = "// NOSONAR\n//NOSONAR\n//  NOSONAR";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        assert!(index.is_suppressed(2, "S100"));
        assert!(index.is_suppressed(3, "S100"));
    }

    #[test]
    fn test_parse_no_suppressions() {
        let source = "public class Test {\n    void method() {}\n}";
        let index = SuppressionIndex::parse(source);
        assert!(!index.is_suppressed(1, "S100"));
        assert!(!index.is_suppressed(2, "S100"));
        assert!(!index.is_suppressed(3, "S100"));
        assert_eq!(index.suppression_count(), 0);
    }

    // ===== Issue Filtering Tests =====

    #[test]
    fn test_filter_removes_suppressed_issues() {
        let source = "line1\nline2 // NOSONAR\nline3";
        let index = SuppressionIndex::parse(source);
        let issues = vec![
            create_test_issue("S100", 1),
            create_test_issue("S100", 2),
            create_test_issue("S100", 3),
        ];
        let filtered = index.filter_issues(issues);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].line, 1);
        assert_eq!(filtered[1].line, 3);
    }

    #[test]
    fn test_filter_removes_only_matching_rule() {
        let source = "line1 // NOSONAR S100";
        let index = SuppressionIndex::parse(source);
        let issues = vec![
            create_test_issue("S100", 1),
            create_test_issue("S101", 1),
        ];
        let filtered = index.filter_issues(issues);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "S101");
    }

    #[test]
    fn test_filter_empty_issues() {
        let source = "line1 // NOSONAR";
        let index = SuppressionIndex::parse(source);
        let issues: Vec<Issue> = vec![];
        let filtered = index.filter_issues(issues);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_no_suppressions() {
        let source = "line1\nline2\nline3";
        let index = SuppressionIndex::parse(source);
        let issues = vec![
            create_test_issue("S100", 1),
            create_test_issue("S100", 2),
            create_test_issue("S100", 3),
        ];
        let filtered = index.filter_issues(issues);
        assert_eq!(filtered.len(), 3);
    }

    // ===== Suppression Count Tests =====

    #[test]
    fn test_suppression_count() {
        let source = "line1 // NOSONAR\nline2\nline3 // NOSONAR S100";
        let index = SuppressionIndex::parse(source);
        assert_eq!(index.suppression_count(), 2);
    }

    // ===== NOSONAR with Colon Separator =====

    #[test]
    fn test_parse_nosonar_with_colon_reason() {
        let source = "String x = \"test\"; // NOSONAR: reason here";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        let suppressions = index.all_suppressions();
        assert_eq!(suppressions[0].reason, Some("reason here".to_string()));
    }

    // ===== Spaces in Rule List =====

    #[test]
    fn test_parse_nosonar_space_separated_rules() {
        let source = "String x = \"test\"; // NOSONAR S100 S101 S102";
        let index = SuppressionIndex::parse(source);
        assert!(index.is_suppressed(1, "S100"));
        assert!(index.is_suppressed(1, "S101"));
        assert!(index.is_suppressed(1, "S102"));
        assert!(!index.is_suppressed(1, "S103"));
    }
}
