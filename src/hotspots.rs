//! Security Hotspots System
//!
//! Distinguishes between confirmed vulnerabilities and security-sensitive code
//! that requires human review (hotspots).

use serde::{Deserialize, Serialize};

use crate::rules::Issue;
use crate::AnalysisResult;

/// Security hotspot review status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HotspotStatus {
    /// Needs review - initial state
    ToReview,
    /// Reviewed and confirmed as safe
    Safe,
    /// Reviewed and confirmed as vulnerability
    Vulnerability,
    /// Acknowledged but accepted risk
    Acknowledged,
}

impl HotspotStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            HotspotStatus::ToReview => "To Review",
            HotspotStatus::Safe => "Safe",
            HotspotStatus::Vulnerability => "Vulnerability",
            HotspotStatus::Acknowledged => "Acknowledged",
        }
    }
}

/// Security hotspot priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HotspotPriority {
    Low,
    Medium,
    High,
}

impl HotspotPriority {
    pub fn from_probability_and_impact(probability: &str, impact: &str) -> Self {
        match (probability.to_lowercase().as_str(), impact.to_lowercase().as_str()) {
            ("high", "high") => HotspotPriority::High,
            ("high", "medium") | ("medium", "high") => HotspotPriority::High,
            ("high", "low") | ("low", "high") | ("medium", "medium") => HotspotPriority::Medium,
            _ => HotspotPriority::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HotspotPriority::Low => "Low",
            HotspotPriority::Medium => "Medium",
            HotspotPriority::High => "High",
        }
    }
}

/// A security hotspot requiring review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHotspot {
    /// The underlying issue
    pub issue: Issue,
    /// Review status
    pub status: HotspotStatus,
    /// Priority based on likelihood and impact
    pub priority: HotspotPriority,
    /// Security category
    pub category: HotspotCategory,
    /// Vulnerability probability (low, medium, high)
    pub vulnerability_probability: String,
    /// Review comment (if any)
    pub review_comment: Option<String>,
}

/// Categories of security hotspots
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HotspotCategory {
    /// Authentication-related code
    Authentication,
    /// Authorization and access control
    Authorization,
    /// Cryptography usage
    Cryptography,
    /// Input validation
    InputValidation,
    /// Injection prevention
    Injection,
    /// Insecure configuration
    InsecureConfiguration,
    /// Sensitive data exposure
    SensitiveData,
    /// Cross-site scripting prevention
    XSS,
    /// Denial of service prevention
    DoS,
    /// Logging and monitoring
    Logging,
    /// Other security concerns
    Other,
}

impl HotspotCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            HotspotCategory::Authentication => "Authentication",
            HotspotCategory::Authorization => "Authorization",
            HotspotCategory::Cryptography => "Cryptography",
            HotspotCategory::InputValidation => "Input Validation",
            HotspotCategory::Injection => "Injection",
            HotspotCategory::InsecureConfiguration => "Insecure Configuration",
            HotspotCategory::SensitiveData => "Sensitive Data",
            HotspotCategory::XSS => "Cross-Site Scripting",
            HotspotCategory::DoS => "Denial of Service",
            HotspotCategory::Logging => "Logging & Monitoring",
            HotspotCategory::Other => "Other",
        }
    }

    /// Determine category from rule ID
    pub fn from_rule_id(rule_id: &str) -> Self {
        match rule_id {
            // Authentication rules
            "S2068" | "S1421" | "S2078" => HotspotCategory::Authentication,
            // Cryptography rules
            "S4790" | "S2277" | "S5547" => HotspotCategory::Cryptography,
            // Injection rules
            "S3649" | "S2076" | "S2631" => HotspotCategory::Injection,
            // XSS rules
            "S5131" | "S5247" => HotspotCategory::XSS,
            // Configuration rules
            "S4507" | "S5693" => HotspotCategory::InsecureConfiguration,
            // Sensitive data rules
            "S2162B" | "S1350" => HotspotCategory::SensitiveData,
            // Default
            _ => HotspotCategory::Other,
        }
    }
}

/// Result of security hotspot analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotResult {
    /// Total number of hotspots
    pub total_hotspots: usize,
    /// Hotspots by priority
    pub high_priority: Vec<SecurityHotspot>,
    pub medium_priority: Vec<SecurityHotspot>,
    pub low_priority: Vec<SecurityHotspot>,
    /// Hotspots by category
    pub by_category: Vec<(HotspotCategory, usize)>,
    /// Review statistics
    pub to_review_count: usize,
    pub reviewed_count: usize,
}

impl HotspotResult {
    /// Create hotspot result from analysis
    pub fn from_analysis(result: &AnalysisResult) -> Self {
        let mut high_priority = Vec::new();
        let mut medium_priority = Vec::new();
        let mut low_priority = Vec::new();

        // Convert security issues to hotspots
        for issue in &result.issues {
            if is_security_hotspot(issue) {
                let hotspot = SecurityHotspot::from_issue(issue.clone());
                match hotspot.priority {
                    HotspotPriority::High => high_priority.push(hotspot),
                    HotspotPriority::Medium => medium_priority.push(hotspot),
                    HotspotPriority::Low => low_priority.push(hotspot),
                }
            }
        }

        let total_hotspots = high_priority.len() + medium_priority.len() + low_priority.len();

        // Count by category
        let mut category_counts = std::collections::HashMap::new();
        for h in high_priority.iter().chain(medium_priority.iter()).chain(low_priority.iter()) {
            *category_counts.entry(h.category).or_insert(0) += 1;
        }
        let by_category: Vec<_> = category_counts.into_iter().collect();

        HotspotResult {
            total_hotspots,
            high_priority,
            medium_priority,
            low_priority,
            by_category,
            to_review_count: total_hotspots, // All start as ToReview
            reviewed_count: 0,
        }
    }

    /// Get all hotspots as a flat list
    pub fn all_hotspots(&self) -> Vec<&SecurityHotspot> {
        self.high_priority.iter()
            .chain(self.medium_priority.iter())
            .chain(self.low_priority.iter())
            .collect()
    }
}

impl SecurityHotspot {
    /// Create a hotspot from an issue
    pub fn from_issue(issue: Issue) -> Self {
        let category = HotspotCategory::from_rule_id(&issue.rule_id);
        let probability = probability_from_severity(&issue.severity);
        let priority = HotspotPriority::from_probability_and_impact(&probability, "medium");

        Self {
            issue,
            status: HotspotStatus::ToReview,
            priority,
            category,
            vulnerability_probability: probability,
            review_comment: None,
        }
    }

    /// Mark hotspot as reviewed with a status
    pub fn review(mut self, status: HotspotStatus, comment: Option<String>) -> Self {
        self.status = status;
        self.review_comment = comment;
        self
    }
}

/// Check if an issue should be treated as a security hotspot
fn is_security_hotspot(issue: &Issue) -> bool {
    use crate::rules::RuleCategory;

    // Security issues are hotspots
    if matches!(issue.category, RuleCategory::Security) {
        return true;
    }

    // Certain rules are always hotspots
    let hotspot_rules = [
        "S2068", "S1421", "S3649", "S4790", "S2162B", "S1350",
        "S2078", "S2076", "S2631", "S5131", "S5247", "S2277",
        "S5547", "S4507", "S5693",
    ];

    hotspot_rules.contains(&issue.rule_id.as_str())
}

/// Determine vulnerability probability from severity
fn probability_from_severity(severity: &crate::Severity) -> String {
    use crate::Severity;
    match severity {
        Severity::Blocker | Severity::Critical => "high".to_string(),
        Severity::Major => "medium".to_string(),
        _ => "low".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleCategory, Severity};

    fn create_security_issue(rule_id: &str, severity: Severity) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            title: "Security Issue".to_string(),
            severity,
            category: RuleCategory::Security,
            file: "Test.java".to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Security concern".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: 30,
        }
    }

    fn create_result(issues: Vec<Issue>) -> AnalysisResult {
        AnalysisResult {
            files_analyzed: 1,
            issues,
            duration_ms: 100,
        }
    }

    // ===== Hotspot Status Tests =====

    #[test]
    fn test_hotspot_status_strings() {
        assert_eq!(HotspotStatus::ToReview.as_str(), "To Review");
        assert_eq!(HotspotStatus::Safe.as_str(), "Safe");
        assert_eq!(HotspotStatus::Vulnerability.as_str(), "Vulnerability");
        assert_eq!(HotspotStatus::Acknowledged.as_str(), "Acknowledged");
    }

    // ===== Hotspot Priority Tests =====

    #[test]
    fn test_priority_high() {
        assert_eq!(
            HotspotPriority::from_probability_and_impact("high", "high"),
            HotspotPriority::High
        );
        assert_eq!(
            HotspotPriority::from_probability_and_impact("high", "medium"),
            HotspotPriority::High
        );
    }

    #[test]
    fn test_priority_medium() {
        assert_eq!(
            HotspotPriority::from_probability_and_impact("medium", "medium"),
            HotspotPriority::Medium
        );
        assert_eq!(
            HotspotPriority::from_probability_and_impact("high", "low"),
            HotspotPriority::Medium
        );
    }

    #[test]
    fn test_priority_low() {
        assert_eq!(
            HotspotPriority::from_probability_and_impact("low", "low"),
            HotspotPriority::Low
        );
    }

    // ===== Hotspot Category Tests =====

    #[test]
    fn test_category_from_rule_id() {
        assert_eq!(HotspotCategory::from_rule_id("S2068"), HotspotCategory::Authentication);
        assert_eq!(HotspotCategory::from_rule_id("S4790"), HotspotCategory::Cryptography);
        assert_eq!(HotspotCategory::from_rule_id("S3649"), HotspotCategory::Injection);
        assert_eq!(HotspotCategory::from_rule_id("S9999"), HotspotCategory::Other);
    }

    #[test]
    fn test_category_strings() {
        assert_eq!(HotspotCategory::Authentication.as_str(), "Authentication");
        assert_eq!(HotspotCategory::Cryptography.as_str(), "Cryptography");
    }

    // ===== Security Hotspot Tests =====

    #[test]
    fn test_hotspot_from_issue() {
        let issue = create_security_issue("S2068", Severity::Critical);
        let hotspot = SecurityHotspot::from_issue(issue);

        assert_eq!(hotspot.status, HotspotStatus::ToReview);
        assert_eq!(hotspot.category, HotspotCategory::Authentication);
        assert_eq!(hotspot.priority, HotspotPriority::High);
    }

    #[test]
    fn test_hotspot_review() {
        let issue = create_security_issue("S2068", Severity::Critical);
        let hotspot = SecurityHotspot::from_issue(issue)
            .review(HotspotStatus::Safe, Some("Reviewed and safe".to_string()));

        assert_eq!(hotspot.status, HotspotStatus::Safe);
        assert_eq!(hotspot.review_comment, Some("Reviewed and safe".to_string()));
    }

    // ===== Hotspot Result Tests =====

    #[test]
    fn test_empty_result() {
        let result = create_result(vec![]);
        let hotspot_result = HotspotResult::from_analysis(&result);

        assert_eq!(hotspot_result.total_hotspots, 0);
        assert!(hotspot_result.high_priority.is_empty());
    }

    #[test]
    fn test_result_with_hotspots() {
        let result = create_result(vec![
            create_security_issue("S2068", Severity::Critical),  // High priority
            create_security_issue("S3649", Severity::Major),     // Medium priority
        ]);
        let hotspot_result = HotspotResult::from_analysis(&result);

        assert_eq!(hotspot_result.total_hotspots, 2);
        assert_eq!(hotspot_result.high_priority.len(), 1);
        assert_eq!(hotspot_result.medium_priority.len(), 1);
    }

    #[test]
    fn test_result_all_hotspots() {
        let result = create_result(vec![
            create_security_issue("S2068", Severity::Critical),
            create_security_issue("S3649", Severity::Major),
            create_security_issue("S4790", Severity::Minor),
        ]);
        let hotspot_result = HotspotResult::from_analysis(&result);

        assert_eq!(hotspot_result.all_hotspots().len(), 3);
    }

    #[test]
    fn test_result_by_category() {
        let result = create_result(vec![
            create_security_issue("S2068", Severity::Critical),  // Authentication
            create_security_issue("S1421", Severity::Critical),  // Authentication
            create_security_issue("S3649", Severity::Major),     // Injection
        ]);
        let hotspot_result = HotspotResult::from_analysis(&result);

        assert!(!hotspot_result.by_category.is_empty());
    }

    #[test]
    fn test_to_review_count() {
        let result = create_result(vec![
            create_security_issue("S2068", Severity::Critical),
            create_security_issue("S3649", Severity::Major),
        ]);
        let hotspot_result = HotspotResult::from_analysis(&result);

        assert_eq!(hotspot_result.to_review_count, 2);
        assert_eq!(hotspot_result.reviewed_count, 0);
    }

    // ===== is_security_hotspot Tests =====

    #[test]
    fn test_is_security_hotspot_vulnerability() {
        let issue = create_security_issue("S9999", Severity::Major);
        assert!(is_security_hotspot(&issue));
    }

    #[test]
    fn test_is_security_hotspot_known_rule() {
        let mut issue = create_security_issue("S2068", Severity::Major);
        issue.category = RuleCategory::Bug; // Not vulnerability category
        assert!(is_security_hotspot(&issue)); // But rule is in hotspot list
    }

    #[test]
    fn test_not_security_hotspot() {
        let issue = Issue {
            rule_id: "S100".to_string(),
            title: "Naming".to_string(),
            severity: Severity::Minor,
            category: RuleCategory::CodeSmell,
            file: "Test.java".to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Naming issue".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: 5,
        };
        assert!(!is_security_hotspot(&issue));
    }
}
