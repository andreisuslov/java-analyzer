//! Technical Debt Calculation and Reporting
//!
//! Calculates and summarizes technical debt from analysis results.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::AnalysisResult;

/// Technical debt summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebtSummary {
    /// Total debt in minutes
    pub total_minutes: u32,
    /// Debt by severity
    pub by_severity: HashMap<String, u32>,
    /// Debt by category
    pub by_category: HashMap<String, u32>,
    /// Debt by file (top files)
    pub by_file: Vec<(String, u32)>,
    /// Debt by rule (top rules)
    pub by_rule: Vec<(String, u32)>,
    /// Debt by module (for multi-module projects)
    pub by_module: Vec<(String, u32)>,
    /// Human-readable total debt
    pub formatted_total: String,
}

impl DebtSummary {
    /// Calculate debt summary from analysis results
    pub fn from_analysis(result: &AnalysisResult) -> Self {
        let mut total_minutes: u32 = 0;
        let mut by_severity: HashMap<String, u32> = HashMap::new();
        let mut by_category: HashMap<String, u32> = HashMap::new();
        let mut by_file: HashMap<String, u32> = HashMap::new();
        let mut by_rule: HashMap<String, u32> = HashMap::new();
        let mut by_module_map: HashMap<String, u32> = HashMap::new();

        for issue in &result.issues {
            let debt = issue.debt_minutes;
            total_minutes += debt;

            *by_severity
                .entry(format!("{:?}", issue.severity))
                .or_default() += debt;
            *by_category
                .entry(format!("{:?}", issue.category))
                .or_default() += debt;
            *by_file.entry(issue.file.clone()).or_default() += debt;
            *by_rule.entry(issue.rule_id.clone()).or_default() += debt;

            // Track debt by module
            let module_name = issue.module.clone().unwrap_or_else(|| "(root)".to_string());
            *by_module_map.entry(module_name).or_default() += debt;
        }

        // Sort and take top 10 files
        let mut file_vec: Vec<_> = by_file.into_iter().collect();
        file_vec.sort_by(|a, b| b.1.cmp(&a.1));
        file_vec.truncate(10);

        // Sort and take top 10 rules
        let mut rule_vec: Vec<_> = by_rule.into_iter().collect();
        rule_vec.sort_by(|a, b| b.1.cmp(&a.1));
        rule_vec.truncate(10);

        // Sort modules by debt
        let mut module_vec: Vec<_> = by_module_map.into_iter().collect();
        module_vec.sort_by(|a, b| b.1.cmp(&a.1));

        let formatted_total = format_debt(total_minutes);

        Self {
            total_minutes,
            by_severity,
            by_category,
            by_file: file_vec,
            by_rule: rule_vec,
            by_module: module_vec,
            formatted_total,
        }
    }

    /// Get debt rating (A-E scale like SonarQube)
    pub fn rating(&self) -> DebtRating {
        // Based on debt ratio (debt minutes / estimated code volume)
        // Simplified: based on absolute debt
        match self.total_minutes {
            0..=30 => DebtRating::A,
            31..=120 => DebtRating::B,
            121..=480 => DebtRating::C,
            481..=1440 => DebtRating::D,
            _ => DebtRating::E,
        }
    }

    /// Check if debt is within acceptable limit
    pub fn is_acceptable(&self, max_minutes: u32) -> bool {
        self.total_minutes <= max_minutes
    }
}

/// Debt rating scale (A = best, E = worst)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebtRating {
    A, // 0-30 min
    B, // 31-120 min (up to 2 hours)
    C, // 121-480 min (up to 8 hours / 1 day)
    D, // 481-1440 min (up to 24 hours / 3 days)
    E, // More than 1440 min
}

impl DebtRating {
    pub fn description(&self) -> &'static str {
        match self {
            DebtRating::A => "Excellent - minimal technical debt",
            DebtRating::B => "Good - manageable debt",
            DebtRating::C => "Fair - moderate debt needs attention",
            DebtRating::D => "Poor - significant debt accumulation",
            DebtRating::E => "Critical - urgent debt reduction needed",
        }
    }

    pub fn as_char(&self) -> char {
        match self {
            DebtRating::A => 'A',
            DebtRating::B => 'B',
            DebtRating::C => 'C',
            DebtRating::D => 'D',
            DebtRating::E => 'E',
        }
    }
}

/// Format debt in human-readable form
pub fn format_debt(minutes: u32) -> String {
    if minutes == 0 {
        return "0min".to_string();
    }

    let days = minutes / (8 * 60); // 8-hour work days
    let remaining = minutes % (8 * 60);
    let hours = remaining / 60;
    let mins = remaining % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if mins > 0 {
        parts.push(format!("{}min", mins));
    }

    parts.join(" ")
}

/// Debt breakdown by a specific dimension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebtBreakdown {
    pub dimension: String,
    pub items: Vec<DebtItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebtItem {
    pub name: String,
    pub minutes: u32,
    pub percentage: f64,
    pub formatted: String,
}

impl DebtSummary {
    /// Get detailed breakdown by severity
    pub fn severity_breakdown(&self) -> DebtBreakdown {
        let items: Vec<DebtItem> = self
            .by_severity
            .iter()
            .map(|(name, &minutes)| {
                let percentage = if self.total_minutes > 0 {
                    (minutes as f64 / self.total_minutes as f64) * 100.0
                } else {
                    0.0
                };
                DebtItem {
                    name: name.clone(),
                    minutes,
                    percentage,
                    formatted: format_debt(minutes),
                }
            })
            .collect();

        DebtBreakdown {
            dimension: "Severity".to_string(),
            items,
        }
    }

    /// Get detailed breakdown by category
    pub fn category_breakdown(&self) -> DebtBreakdown {
        let items: Vec<DebtItem> = self
            .by_category
            .iter()
            .map(|(name, &minutes)| {
                let percentage = if self.total_minutes > 0 {
                    (minutes as f64 / self.total_minutes as f64) * 100.0
                } else {
                    0.0
                };
                DebtItem {
                    name: name.clone(),
                    minutes,
                    percentage,
                    formatted: format_debt(minutes),
                }
            })
            .collect();

        DebtBreakdown {
            dimension: "Category".to_string(),
            items,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Issue, RuleCategory};
    use crate::Severity;

    fn create_issue(
        rule_id: &str,
        file: &str,
        severity: Severity,
        category: RuleCategory,
        debt: u32,
    ) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            title: "Test".to_string(),
            severity,
            category,
            file: file.to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Test".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: debt,
            module: None,
        }
    }

    fn create_result(issues: Vec<Issue>) -> AnalysisResult {
        AnalysisResult {
            files_analyzed: 1,
            issues,
            duration_ms: 100,
            modules: None,
        }
    }

    // ===== Format Debt Tests =====

    #[test]
    fn test_format_debt_zero() {
        assert_eq!(format_debt(0), "0min");
    }

    #[test]
    fn test_format_debt_minutes_only() {
        assert_eq!(format_debt(45), "45min");
    }

    #[test]
    fn test_format_debt_hours_and_minutes() {
        assert_eq!(format_debt(90), "1h 30min");
    }

    #[test]
    fn test_format_debt_days() {
        assert_eq!(format_debt(480), "1d"); // 8 hours = 1 work day
    }

    #[test]
    fn test_format_debt_complex() {
        assert_eq!(format_debt(615), "1d 2h 15min"); // 1 day + 2 hours + 15 min
    }

    // ===== Debt Rating Tests =====

    #[test]
    fn test_rating_a() {
        let result = create_result(vec![create_issue(
            "S1",
            "f.java",
            Severity::Minor,
            RuleCategory::CodeSmell,
            10,
        )]);
        let summary = DebtSummary::from_analysis(&result);
        assert_eq!(summary.rating(), DebtRating::A);
    }

    #[test]
    fn test_rating_b() {
        let result = create_result(vec![create_issue(
            "S1",
            "f.java",
            Severity::Minor,
            RuleCategory::CodeSmell,
            60,
        )]);
        let summary = DebtSummary::from_analysis(&result);
        assert_eq!(summary.rating(), DebtRating::B);
    }

    #[test]
    fn test_rating_c() {
        let result = create_result(vec![create_issue(
            "S1",
            "f.java",
            Severity::Major,
            RuleCategory::Bug,
            300,
        )]);
        let summary = DebtSummary::from_analysis(&result);
        assert_eq!(summary.rating(), DebtRating::C);
    }

    #[test]
    fn test_rating_d() {
        let result = create_result(vec![create_issue(
            "S1",
            "f.java",
            Severity::Critical,
            RuleCategory::Bug,
            600,
        )]);
        let summary = DebtSummary::from_analysis(&result);
        assert_eq!(summary.rating(), DebtRating::D);
    }

    #[test]
    fn test_rating_e() {
        let result = create_result(vec![create_issue(
            "S1",
            "f.java",
            Severity::Blocker,
            RuleCategory::Security,
            2000,
        )]);
        let summary = DebtSummary::from_analysis(&result);
        assert_eq!(summary.rating(), DebtRating::E);
    }

    // ===== Debt Summary Tests =====

    #[test]
    fn test_empty_result() {
        let result = create_result(vec![]);
        let summary = DebtSummary::from_analysis(&result);

        assert_eq!(summary.total_minutes, 0);
        assert_eq!(summary.formatted_total, "0min");
        assert!(summary.by_file.is_empty());
    }

    #[test]
    fn test_total_calculation() {
        let result = create_result(vec![
            create_issue(
                "S1",
                "f1.java",
                Severity::Minor,
                RuleCategory::CodeSmell,
                10,
            ),
            create_issue("S2", "f2.java", Severity::Major, RuleCategory::Bug, 20),
            create_issue(
                "S3",
                "f1.java",
                Severity::Critical,
                RuleCategory::Security,
                30,
            ),
        ]);
        let summary = DebtSummary::from_analysis(&result);

        assert_eq!(summary.total_minutes, 60);
    }

    #[test]
    fn test_by_severity() {
        let result = create_result(vec![
            create_issue("S1", "f.java", Severity::Minor, RuleCategory::CodeSmell, 10),
            create_issue("S2", "f.java", Severity::Minor, RuleCategory::CodeSmell, 15),
            create_issue("S3", "f.java", Severity::Major, RuleCategory::Bug, 30),
        ]);
        let summary = DebtSummary::from_analysis(&result);

        assert_eq!(summary.by_severity.get("Minor"), Some(&25));
        assert_eq!(summary.by_severity.get("Major"), Some(&30));
    }

    #[test]
    fn test_by_category() {
        let result = create_result(vec![
            create_issue("S1", "f.java", Severity::Minor, RuleCategory::CodeSmell, 10),
            create_issue("S2", "f.java", Severity::Major, RuleCategory::Bug, 20),
            create_issue("S3", "f.java", Severity::Critical, RuleCategory::Bug, 30),
        ]);
        let summary = DebtSummary::from_analysis(&result);

        assert_eq!(summary.by_category.get("CodeSmell"), Some(&10));
        assert_eq!(summary.by_category.get("Bug"), Some(&50));
    }

    #[test]
    fn test_by_file_sorted() {
        let result = create_result(vec![
            create_issue(
                "S1",
                "low.java",
                Severity::Minor,
                RuleCategory::CodeSmell,
                5,
            ),
            create_issue("S2", "high.java", Severity::Major, RuleCategory::Bug, 100),
            create_issue("S3", "medium.java", Severity::Major, RuleCategory::Bug, 50),
        ]);
        let summary = DebtSummary::from_analysis(&result);

        assert_eq!(summary.by_file[0].0, "high.java");
        assert_eq!(summary.by_file[0].1, 100);
    }

    #[test]
    fn test_by_rule_sorted() {
        let result = create_result(vec![
            create_issue(
                "S100",
                "f.java",
                Severity::Minor,
                RuleCategory::CodeSmell,
                5,
            ),
            create_issue("S200", "f.java", Severity::Major, RuleCategory::Bug, 100),
            create_issue("S200", "g.java", Severity::Major, RuleCategory::Bug, 50),
        ]);
        let summary = DebtSummary::from_analysis(&result);

        assert_eq!(summary.by_rule[0].0, "S200");
        assert_eq!(summary.by_rule[0].1, 150);
    }

    #[test]
    fn test_is_acceptable() {
        let result = create_result(vec![create_issue(
            "S1",
            "f.java",
            Severity::Minor,
            RuleCategory::CodeSmell,
            50,
        )]);
        let summary = DebtSummary::from_analysis(&result);

        assert!(summary.is_acceptable(60));
        assert!(!summary.is_acceptable(40));
    }

    // ===== Breakdown Tests =====

    #[test]
    fn test_severity_breakdown() {
        let result = create_result(vec![
            create_issue("S1", "f.java", Severity::Minor, RuleCategory::CodeSmell, 25),
            create_issue("S2", "f.java", Severity::Major, RuleCategory::Bug, 75),
        ]);
        let summary = DebtSummary::from_analysis(&result);
        let breakdown = summary.severity_breakdown();

        assert_eq!(breakdown.dimension, "Severity");
        assert_eq!(breakdown.items.len(), 2);
    }

    #[test]
    fn test_category_breakdown() {
        let result = create_result(vec![
            create_issue("S1", "f.java", Severity::Minor, RuleCategory::CodeSmell, 40),
            create_issue("S2", "f.java", Severity::Major, RuleCategory::Bug, 60),
        ]);
        let summary = DebtSummary::from_analysis(&result);
        let breakdown = summary.category_breakdown();

        assert_eq!(breakdown.dimension, "Category");
        assert_eq!(breakdown.items.len(), 2);
    }

    // ===== Rating Description Tests =====

    #[test]
    fn test_rating_descriptions() {
        assert!(DebtRating::A.description().contains("Excellent"));
        assert!(DebtRating::B.description().contains("Good"));
        assert!(DebtRating::C.description().contains("Fair"));
        assert!(DebtRating::D.description().contains("Poor"));
        assert!(DebtRating::E.description().contains("Critical"));
    }

    #[test]
    fn test_rating_as_char() {
        assert_eq!(DebtRating::A.as_char(), 'A');
        assert_eq!(DebtRating::E.as_char(), 'E');
    }
}
