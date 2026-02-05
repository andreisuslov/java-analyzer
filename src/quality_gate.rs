//! Quality Gates - Configurable quality thresholds for CI/CD
//!
//! Quality gates define pass/fail criteria based on analysis metrics.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::{AnalysisResult, Severity};

/// A condition that must be met for the quality gate to pass
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum QualityCondition {
    /// Maximum number of issues of a given severity
    #[serde(rename = "max_issues")]
    MaxIssues {
        severity: Severity,
        threshold: usize,
    },
    /// Maximum total number of issues
    #[serde(rename = "max_total_issues")]
    MaxTotalIssues { threshold: usize },
    /// No issues of a given severity or higher
    #[serde(rename = "no_issues_above")]
    NoIssuesAbove { severity: Severity },
    /// Maximum technical debt in minutes
    #[serde(rename = "max_debt_minutes")]
    MaxDebtMinutes { threshold: u32 },
    /// Maximum number of new issues (for differential analysis)
    #[serde(rename = "max_new_issues")]
    MaxNewIssues { threshold: usize },
    /// Minimum percentage of issues resolved (for tracking)
    #[serde(rename = "min_issues_resolved_percent")]
    MinIssuesResolvedPercent { threshold: f64 },
}

/// Result of evaluating a single condition
#[derive(Debug, Clone)]
pub struct ConditionResult {
    pub condition: QualityCondition,
    pub passed: bool,
    pub actual_value: String,
    pub threshold_value: String,
    pub message: String,
}

/// Quality gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGate {
    /// Name of the quality gate
    pub name: String,
    /// Description
    #[serde(default)]
    pub description: String,
    /// Conditions that must all pass
    pub conditions: Vec<QualityCondition>,
}

impl QualityGate {
    /// Create a new quality gate with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            conditions: Vec::new(),
        }
    }

    /// Add a condition to the quality gate
    pub fn add_condition(mut self, condition: QualityCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Load quality gate from a JSON file
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read quality gate file: {}", e))?;

        serde_json::from_str(&content).map_err(|e| format!("Failed to parse quality gate: {}", e))
    }

    /// Load quality gate from a TOML file
    pub fn from_toml_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read quality gate file: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("Failed to parse quality gate: {}", e))
    }

    /// Evaluate the quality gate against analysis results
    pub fn evaluate(&self, result: &AnalysisResult) -> QualityGateResult {
        let mut condition_results = Vec::new();
        let mut all_passed = true;

        for condition in &self.conditions {
            let cond_result = self.evaluate_condition(condition, result);
            if !cond_result.passed {
                all_passed = false;
            }
            condition_results.push(cond_result);
        }

        QualityGateResult {
            gate_name: self.name.clone(),
            passed: all_passed,
            conditions: condition_results,
        }
    }

    fn evaluate_condition(
        &self,
        condition: &QualityCondition,
        result: &AnalysisResult,
    ) -> ConditionResult {
        match condition {
            QualityCondition::MaxIssues {
                severity,
                threshold,
            } => {
                let count = result
                    .issues
                    .iter()
                    .filter(|i| i.severity == *severity)
                    .count();
                ConditionResult {
                    condition: condition.clone(),
                    passed: count <= *threshold,
                    actual_value: count.to_string(),
                    threshold_value: threshold.to_string(),
                    message: format!(
                        "{} issues with severity {:?}: {} (max: {})",
                        if count <= *threshold { "✓" } else { "✗" },
                        severity,
                        count,
                        threshold
                    ),
                }
            }
            QualityCondition::MaxTotalIssues { threshold } => {
                let count = result.issues.len();
                ConditionResult {
                    condition: condition.clone(),
                    passed: count <= *threshold,
                    actual_value: count.to_string(),
                    threshold_value: threshold.to_string(),
                    message: format!(
                        "{} Total issues: {} (max: {})",
                        if count <= *threshold { "✓" } else { "✗" },
                        count,
                        threshold
                    ),
                }
            }
            QualityCondition::NoIssuesAbove { severity } => {
                let count = result
                    .issues
                    .iter()
                    .filter(|i| i.severity >= *severity)
                    .count();
                ConditionResult {
                    condition: condition.clone(),
                    passed: count == 0,
                    actual_value: count.to_string(),
                    threshold_value: "0".to_string(),
                    message: format!(
                        "{} Issues with severity {:?} or higher: {}",
                        if count == 0 { "✓" } else { "✗" },
                        severity,
                        count
                    ),
                }
            }
            QualityCondition::MaxDebtMinutes { threshold } => {
                let total_debt: u32 = result.issues.iter().map(|i| i.debt_minutes).sum();
                ConditionResult {
                    condition: condition.clone(),
                    passed: total_debt <= *threshold,
                    actual_value: total_debt.to_string(),
                    threshold_value: threshold.to_string(),
                    message: format!(
                        "{} Technical debt: {} min (max: {} min)",
                        if total_debt <= *threshold {
                            "✓"
                        } else {
                            "✗"
                        },
                        total_debt,
                        threshold
                    ),
                }
            }
            QualityCondition::MaxNewIssues { threshold } => {
                // For now, treat all issues as "new" - baseline comparison will be added later
                let count = result.issues.len();
                ConditionResult {
                    condition: condition.clone(),
                    passed: count <= *threshold,
                    actual_value: count.to_string(),
                    threshold_value: threshold.to_string(),
                    message: format!(
                        "{} New issues: {} (max: {})",
                        if count <= *threshold { "✓" } else { "✗" },
                        count,
                        threshold
                    ),
                }
            }
            QualityCondition::MinIssuesResolvedPercent { threshold } => {
                // Placeholder - requires historical data
                ConditionResult {
                    condition: condition.clone(),
                    passed: true,
                    actual_value: "N/A".to_string(),
                    threshold_value: format!("{}%", threshold),
                    message: "⚠ Issue resolution tracking not yet implemented".to_string(),
                }
            }
        }
    }
}

/// Result of evaluating a quality gate
#[derive(Debug, Clone)]
pub struct QualityGateResult {
    pub gate_name: String,
    pub passed: bool,
    pub conditions: Vec<ConditionResult>,
}

impl QualityGateResult {
    /// Generate a summary report
    pub fn summary(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Quality Gate: {}\n", self.gate_name));
        output.push_str(&format!(
            "Status: {}\n\n",
            if self.passed {
                "PASSED ✓"
            } else {
                "FAILED ✗"
            }
        ));

        output.push_str("Conditions:\n");
        for cond in &self.conditions {
            output.push_str(&format!("  {}\n", cond.message));
        }

        output
    }
}

/// Default quality gates for common use cases
impl QualityGate {
    /// Strict quality gate - no blockers or criticals
    pub fn strict() -> Self {
        Self::new("Strict")
            .add_condition(QualityCondition::NoIssuesAbove {
                severity: Severity::Critical,
            })
            .add_condition(QualityCondition::MaxIssues {
                severity: Severity::Major,
                threshold: 10,
            })
            .add_condition(QualityCondition::MaxDebtMinutes { threshold: 60 })
    }

    /// Standard quality gate - no blockers, limited criticals
    pub fn standard() -> Self {
        Self::new("Standard")
            .add_condition(QualityCondition::NoIssuesAbove {
                severity: Severity::Blocker,
            })
            .add_condition(QualityCondition::MaxIssues {
                severity: Severity::Critical,
                threshold: 5,
            })
            .add_condition(QualityCondition::MaxDebtMinutes { threshold: 120 })
    }

    /// Lenient quality gate - only blocks on blockers
    pub fn lenient() -> Self {
        Self::new("Lenient").add_condition(QualityCondition::NoIssuesAbove {
            severity: Severity::Blocker,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Issue, OwaspCategory, RuleCategory};

    fn create_test_issue(severity: Severity, debt: u32) -> Issue {
        Issue {
            rule_id: "TEST".to_string(),
            title: "Test Issue".to_string(),
            severity,
            category: RuleCategory::Bug,
            file: "test.java".to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Test message".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: debt,
            module: None,
        }
    }

    fn create_test_result(issues: Vec<Issue>) -> AnalysisResult {
        AnalysisResult {
            files_analyzed: 1,
            issues,
            duration_ms: 100,
            modules: None,
        }
    }

    #[test]
    fn test_quality_gate_passes_when_no_issues() {
        let gate = QualityGate::strict();
        let result = create_test_result(vec![]);

        let gate_result = gate.evaluate(&result);
        assert!(gate_result.passed);
    }

    #[test]
    fn test_quality_gate_fails_on_blocker() {
        let gate = QualityGate::strict();
        let result = create_test_result(vec![create_test_issue(Severity::Blocker, 30)]);

        let gate_result = gate.evaluate(&result);
        assert!(!gate_result.passed);
    }

    #[test]
    fn test_quality_gate_fails_on_critical() {
        let gate = QualityGate::strict();
        let result = create_test_result(vec![create_test_issue(Severity::Critical, 20)]);

        let gate_result = gate.evaluate(&result);
        assert!(!gate_result.passed);
    }

    #[test]
    fn test_quality_gate_passes_with_minor_issues() {
        let gate = QualityGate::strict();
        let result = create_test_result(vec![
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
        ]);

        let gate_result = gate.evaluate(&result);
        assert!(gate_result.passed);
    }

    #[test]
    fn test_max_issues_condition() {
        let gate = QualityGate::new("Test").add_condition(QualityCondition::MaxIssues {
            severity: Severity::Major,
            threshold: 2,
        });

        // Should pass with 2 major issues
        let result = create_test_result(vec![
            create_test_issue(Severity::Major, 10),
            create_test_issue(Severity::Major, 10),
        ]);
        assert!(gate.evaluate(&result).passed);

        // Should fail with 3 major issues
        let result = create_test_result(vec![
            create_test_issue(Severity::Major, 10),
            create_test_issue(Severity::Major, 10),
            create_test_issue(Severity::Major, 10),
        ]);
        assert!(!gate.evaluate(&result).passed);
    }

    #[test]
    fn test_max_total_issues_condition() {
        let gate = QualityGate::new("Test")
            .add_condition(QualityCondition::MaxTotalIssues { threshold: 5 });

        let result = create_test_result(vec![
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
        ]);
        assert!(gate.evaluate(&result).passed);

        let result = create_test_result(vec![
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
            create_test_issue(Severity::Minor, 5),
        ]);
        assert!(!gate.evaluate(&result).passed);
    }

    #[test]
    fn test_max_debt_condition() {
        let gate = QualityGate::new("Test")
            .add_condition(QualityCondition::MaxDebtMinutes { threshold: 30 });

        // Total debt = 25 min, should pass
        let result = create_test_result(vec![
            create_test_issue(Severity::Minor, 10),
            create_test_issue(Severity::Minor, 15),
        ]);
        assert!(gate.evaluate(&result).passed);

        // Total debt = 40 min, should fail
        let result = create_test_result(vec![
            create_test_issue(Severity::Minor, 20),
            create_test_issue(Severity::Minor, 20),
        ]);
        assert!(!gate.evaluate(&result).passed);
    }

    #[test]
    fn test_standard_gate() {
        let gate = QualityGate::standard();

        // Should pass with criticals below threshold
        let result = create_test_result(vec![
            create_test_issue(Severity::Critical, 20),
            create_test_issue(Severity::Critical, 20),
        ]);
        assert!(gate.evaluate(&result).passed);
    }

    #[test]
    fn test_lenient_gate() {
        let gate = QualityGate::lenient();

        // Should pass even with many criticals
        let result = create_test_result(vec![
            create_test_issue(Severity::Critical, 20),
            create_test_issue(Severity::Critical, 20),
            create_test_issue(Severity::Critical, 20),
        ]);
        assert!(gate.evaluate(&result).passed);

        // Should fail on blocker
        let result = create_test_result(vec![create_test_issue(Severity::Blocker, 30)]);
        assert!(!gate.evaluate(&result).passed);
    }

    #[test]
    fn test_quality_gate_summary() {
        let gate = QualityGate::strict();
        let result = create_test_result(vec![]);

        let gate_result = gate.evaluate(&result);
        let summary = gate_result.summary();

        assert!(summary.contains("Quality Gate: Strict"));
        assert!(summary.contains("PASSED"));
    }

    #[test]
    fn test_quality_gate_serialization() {
        let gate = QualityGate::standard();
        let json = serde_json::to_string_pretty(&gate).unwrap();

        assert!(json.contains("Standard"));
        assert!(json.contains("no_issues_above"));
    }
}
