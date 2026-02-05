//! Rule definitions and implementations
//!
//! This module contains all the static analysis rules organized by category.

mod naming;
mod security;
mod bugs;
mod code_smells;
mod complexity;

use serde::{Deserialize, Serialize};

use crate::AnalyzerConfig;

/// Severity levels for issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "blocker" => Severity::Blocker,
            "critical" => Severity::Critical,
            "major" => Severity::Major,
            "minor" => Severity::Minor,
            _ => Severity::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Blocker => "blocker",
            Severity::Critical => "critical",
            Severity::Major => "major",
            Severity::Minor => "minor",
            Severity::Info => "info",
        }
    }
}

/// Rule categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleCategory {
    Naming,
    Security,
    Bug,
    CodeSmell,
    Complexity,
    Documentation,
    Performance,
}

/// An issue found during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: RuleCategory,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub message: String,
    pub code_snippet: Option<String>,
}

/// Context for rule analysis
pub struct AnalysisContext<'a> {
    pub source: &'a str,
    pub file_path: &'a str,
    pub tree: &'a tree_sitter::Tree,
    pub config: &'a AnalyzerConfig,
}

/// Trait that all rules must implement
pub trait Rule: Send + Sync {
    /// Unique identifier (e.g., "S100")
    fn id(&self) -> &str;

    /// Human-readable title
    fn title(&self) -> &str;

    /// Severity level
    fn severity(&self) -> Severity;

    /// Category
    fn category(&self) -> RuleCategory;

    /// Detailed description
    fn description(&self) -> &str { "" }

    /// Check the code and return any issues found
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue>;
}

/// Create all available rules
pub fn create_all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();

    // Naming rules
    rules.extend(naming::create_rules());

    // Security rules
    rules.extend(security::create_rules());

    // Bug detection rules
    rules.extend(bugs::create_rules());

    // Code smell rules
    rules.extend(code_smells::create_rules());

    // Complexity rules
    rules.extend(complexity::create_rules());

    rules
}

/// Helper to create an issue
pub fn create_issue(
    rule: &dyn Rule,
    file: &str,
    line: usize,
    column: usize,
    message: String,
    snippet: Option<String>,
) -> Issue {
    Issue {
        rule_id: rule.id().to_string(),
        title: rule.title().to_string(),
        severity: rule.severity(),
        category: rule.category(),
        file: file.to_string(),
        line,
        column,
        end_line: None,
        end_column: None,
        message,
        code_snippet: snippet,
    }
}

// Re-export Lazy and Regex for submodules
pub use once_cell::sync::Lazy;
pub use regex::Regex;

// Note: Individual rules are accessed via create_all_rules()

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_all_rules() {
        let rules = create_all_rules();
        assert!(!rules.is_empty(), "Should have at least some rules");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Minor);
        assert!(Severity::Minor < Severity::Major);
        assert!(Severity::Major < Severity::Critical);
        assert!(Severity::Critical < Severity::Blocker);
    }
}
