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

/// OWASP Top 10 (2021) categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspCategory {
    A01BrokenAccessControl,
    A02CryptographicFailures,
    A03Injection,
    A04InsecureDesign,
    A05SecurityMisconfiguration,
    A06VulnerableComponents,
    A07AuthenticationFailures,
    A08SoftwareDataIntegrityFailures,
    A09SecurityLoggingFailures,
    A10ServerSideRequestForgery,
    None,
}

impl OwaspCategory {
    pub fn code(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2021",
            Self::A02CryptographicFailures => "A02:2021",
            Self::A03Injection => "A03:2021",
            Self::A04InsecureDesign => "A04:2021",
            Self::A05SecurityMisconfiguration => "A05:2021",
            Self::A06VulnerableComponents => "A06:2021",
            Self::A07AuthenticationFailures => "A07:2021",
            Self::A08SoftwareDataIntegrityFailures => "A08:2021",
            Self::A09SecurityLoggingFailures => "A09:2021",
            Self::A10ServerSideRequestForgery => "A10:2021",
            Self::None => "",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02CryptographicFailures => "Cryptographic Failures",
            Self::A03Injection => "Injection",
            Self::A04InsecureDesign => "Insecure Design",
            Self::A05SecurityMisconfiguration => "Security Misconfiguration",
            Self::A06VulnerableComponents => "Vulnerable and Outdated Components",
            Self::A07AuthenticationFailures => "Identification and Authentication Failures",
            Self::A08SoftwareDataIntegrityFailures => "Software and Data Integrity Failures",
            Self::A09SecurityLoggingFailures => "Security Logging and Monitoring Failures",
            Self::A10ServerSideRequestForgery => "Server-Side Request Forgery",
            Self::None => "",
        }
    }
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
    /// OWASP Top 10 category (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<OwaspCategory>,
    /// CWE identifier (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    /// Estimated remediation time in minutes
    pub debt_minutes: u32,
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

    /// OWASP Top 10 category (for security rules)
    fn owasp(&self) -> Option<OwaspCategory> { None }

    /// CWE identifier (Common Weakness Enumeration)
    fn cwe(&self) -> Option<u32> { None }

    /// Estimated remediation time in minutes (technical debt)
    fn debt_minutes(&self) -> u32 { 5 }

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
        owasp: rule.owasp(),
        cwe: rule.cwe(),
        debt_minutes: rule.debt_minutes(),
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

    // ===== OWASP/CWE Mapping Tests =====

    #[test]
    fn test_owasp_category_code() {
        assert_eq!(OwaspCategory::A01BrokenAccessControl.code(), "A01:2021");
        assert_eq!(OwaspCategory::A03Injection.code(), "A03:2021");
        assert_eq!(OwaspCategory::None.code(), "");
    }

    #[test]
    fn test_owasp_category_name() {
        assert_eq!(OwaspCategory::A01BrokenAccessControl.name(), "Broken Access Control");
        assert_eq!(OwaspCategory::A03Injection.name(), "Injection");
    }

    #[test]
    fn test_security_rules_have_owasp_mapping() {
        let rules = create_all_rules();
        let security_rules: Vec<_> = rules.iter()
            .filter(|r| r.category() == RuleCategory::Security)
            .collect();

        // At least some security rules should have OWASP mappings
        let rules_with_owasp = security_rules.iter()
            .filter(|r| r.owasp().is_some())
            .count();

        assert!(rules_with_owasp > 0, "Security rules should have OWASP mappings");
    }

    #[test]
    fn test_security_rules_have_cwe_mapping() {
        let rules = create_all_rules();
        let security_rules: Vec<_> = rules.iter()
            .filter(|r| r.category() == RuleCategory::Security)
            .collect();

        // At least some security rules should have CWE mappings
        let rules_with_cwe = security_rules.iter()
            .filter(|r| r.cwe().is_some())
            .count();

        assert!(rules_with_cwe > 0, "Security rules should have CWE mappings");
    }

    // ===== Technical Debt Tests =====

    #[test]
    fn test_rules_have_debt_estimates() {
        let rules = create_all_rules();

        // All rules should have a debt estimate > 0
        for rule in &rules {
            assert!(rule.debt_minutes() > 0,
                "Rule {} should have debt estimate > 0", rule.id());
        }
    }

    #[test]
    fn test_debt_varies_by_severity() {
        let rules = create_all_rules();

        // Find average debt for different severities
        let blocker_debt: Vec<u32> = rules.iter()
            .filter(|r| r.severity() == Severity::Blocker)
            .map(|r| r.debt_minutes())
            .collect();

        let minor_debt: Vec<u32> = rules.iter()
            .filter(|r| r.severity() == Severity::Minor)
            .map(|r| r.debt_minutes())
            .collect();

        if !blocker_debt.is_empty() && !minor_debt.is_empty() {
            let avg_blocker: u32 = blocker_debt.iter().sum::<u32>() / blocker_debt.len() as u32;
            let avg_minor: u32 = minor_debt.iter().sum::<u32>() / minor_debt.len() as u32;

            // Blocker issues should generally take longer to fix
            assert!(avg_blocker >= avg_minor,
                "Blocker issues should have equal or higher debt than minor issues");
        }
    }

    #[test]
    fn test_issue_includes_debt() {
        struct TestRule;
        impl Rule for TestRule {
            fn id(&self) -> &str { "TEST001" }
            fn title(&self) -> &str { "Test Rule" }
            fn severity(&self) -> Severity { Severity::Major }
            fn category(&self) -> RuleCategory { RuleCategory::Bug }
            fn debt_minutes(&self) -> u32 { 15 }
            fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> { vec![] }
        }

        let rule = TestRule;
        let issue = create_issue(&rule, "test.java", 1, 1, "Test".to_string(), None);

        assert_eq!(issue.debt_minutes, 15);
    }

    #[test]
    fn test_issue_includes_owasp_and_cwe() {
        struct SecurityTestRule;
        impl Rule for SecurityTestRule {
            fn id(&self) -> &str { "SEC001" }
            fn title(&self) -> &str { "Security Test Rule" }
            fn severity(&self) -> Severity { Severity::Critical }
            fn category(&self) -> RuleCategory { RuleCategory::Security }
            fn owasp(&self) -> Option<OwaspCategory> { Some(OwaspCategory::A03Injection) }
            fn cwe(&self) -> Option<u32> { Some(89) } // SQL Injection
            fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> { vec![] }
        }

        let rule = SecurityTestRule;
        let issue = create_issue(&rule, "test.java", 1, 1, "Test".to_string(), None);

        assert_eq!(issue.owasp, Some(OwaspCategory::A03Injection));
        assert_eq!(issue.cwe, Some(89));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Minor);
        assert!(Severity::Minor < Severity::Major);
        assert!(Severity::Major < Severity::Critical);
        assert!(Severity::Critical < Severity::Blocker);
    }
}
