//! Custom Rule Support
//!
//! Allows users to define custom rules via YAML configuration.

use once_cell::sync::OnceCell;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use super::{AnalysisContext, Issue, Rule, RuleCategory, Severity};

/// Error type for custom rule loading
#[derive(Debug, Clone)]
pub enum CustomRuleError {
    /// Failed to read the file
    IoError(String),
    /// Failed to parse YAML
    ParseError(String),
    /// Invalid regex pattern
    InvalidRegex { rule_id: String, pattern: String, error: String },
    /// Invalid rule ID (must start with CUSTOM-)
    InvalidRuleId(String),
    /// Invalid severity value
    InvalidSeverity(String),
    /// Invalid category value
    InvalidCategory(String),
}

impl std::fmt::Display for CustomRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomRuleError::IoError(e) => write!(f, "Failed to read file: {}", e),
            CustomRuleError::ParseError(e) => write!(f, "Failed to parse YAML: {}", e),
            CustomRuleError::InvalidRegex { rule_id, pattern, error } => {
                write!(f, "Invalid regex in rule {}: '{}' - {}", rule_id, pattern, error)
            }
            CustomRuleError::InvalidRuleId(id) => {
                write!(f, "Invalid rule ID '{}': must start with 'CUSTOM-'", id)
            }
            CustomRuleError::InvalidSeverity(s) => {
                write!(f, "Invalid severity '{}': must be info, minor, major, critical, or blocker", s)
            }
            CustomRuleError::InvalidCategory(c) => {
                write!(f, "Invalid category '{}': must be naming, security, bug, code_smell, complexity, documentation, or performance", c)
            }
        }
    }
}

/// Configuration for custom rules loaded from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRulesConfig {
    pub rules: Vec<CustomRuleConfig>,
}

/// Configuration for a single custom rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleConfig {
    /// Unique rule ID (must start with "CUSTOM-")
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Severity level (info, minor, major, critical, blocker)
    pub severity: String,
    /// Category (naming, security, bug, code_smell, complexity, documentation, performance)
    pub category: String,
    /// Regex pattern to match
    pub pattern: String,
    /// Message to display when rule matches
    pub message: String,
    /// Optional: if this pattern matches, skip the rule (e.g., "@Test")
    #[serde(default)]
    pub negative_pattern: Option<String>,
    /// Technical debt in minutes
    #[serde(default = "default_debt_minutes")]
    pub debt_minutes: u32,
    /// Optional detailed description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_debt_minutes() -> u32 {
    5
}

/// A custom rule that matches regex patterns
pub struct CustomRule {
    id: String,
    title: String,
    severity: Severity,
    category: RuleCategory,
    message: String,
    debt: u32,
    description: String,
    pattern: OnceCell<Regex>,
    pattern_str: String,
    negative_pattern: OnceCell<Option<Regex>>,
    negative_pattern_str: Option<String>,
}

impl CustomRule {
    /// Create a new custom rule from configuration
    pub fn from_config(config: CustomRuleConfig) -> Result<Self, CustomRuleError> {
        // Validate rule ID
        if !config.id.starts_with("CUSTOM-") {
            return Err(CustomRuleError::InvalidRuleId(config.id));
        }

        // Parse severity
        let severity = parse_severity(&config.severity)
            .ok_or_else(|| CustomRuleError::InvalidSeverity(config.severity.clone()))?;

        // Parse category
        let category = parse_category(&config.category)
            .ok_or_else(|| CustomRuleError::InvalidCategory(config.category.clone()))?;

        // Validate main pattern (compile to check for errors)
        Regex::new(&config.pattern).map_err(|e| CustomRuleError::InvalidRegex {
            rule_id: config.id.clone(),
            pattern: config.pattern.clone(),
            error: e.to_string(),
        })?;

        // Validate negative pattern if provided
        if let Some(ref neg_pattern) = config.negative_pattern {
            Regex::new(neg_pattern).map_err(|e| CustomRuleError::InvalidRegex {
                rule_id: config.id.clone(),
                pattern: neg_pattern.clone(),
                error: e.to_string(),
            })?;
        }

        Ok(Self {
            id: config.id,
            title: config.title,
            severity,
            category,
            message: config.message,
            debt: config.debt_minutes,
            description: config.description.unwrap_or_default(),
            pattern: OnceCell::new(),
            pattern_str: config.pattern,
            negative_pattern: OnceCell::new(),
            negative_pattern_str: config.negative_pattern,
        })
    }

    /// Get the compiled regex pattern (lazy initialization)
    fn get_pattern(&self) -> &Regex {
        self.pattern.get_or_init(|| {
            // Safe to unwrap because we validated in from_config
            Regex::new(&self.pattern_str).unwrap()
        })
    }

    /// Get the compiled negative pattern (lazy initialization)
    fn get_negative_pattern(&self) -> &Option<Regex> {
        self.negative_pattern.get_or_init(|| {
            self.negative_pattern_str.as_ref().map(|p| {
                // Safe to unwrap because we validated in from_config
                Regex::new(p).unwrap()
            })
        })
    }
}

impl Rule for CustomRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn title(&self) -> &str {
        &self.title
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn category(&self) -> RuleCategory {
        self.category
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn debt_minutes(&self) -> u32 {
        self.debt
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let pattern = self.get_pattern();
        let negative_pattern = self.get_negative_pattern();

        for (line_idx, line) in ctx.source.lines().enumerate() {
            // Check if negative pattern matches this line - if so, skip
            if let Some(ref neg) = negative_pattern {
                if neg.is_match(line) {
                    continue;
                }
            }

            // Check for matches
            for mat in pattern.find_iter(line) {
                issues.push(Issue {
                    rule_id: self.id.clone(),
                    title: self.title.clone(),
                    severity: self.severity,
                    category: self.category,
                    file: ctx.file_path.to_string(),
                    line: line_idx + 1,
                    column: mat.start() + 1,
                    end_line: None,
                    end_column: Some(mat.end() + 1),
                    message: self.message.clone(),
                    code_snippet: Some(line.trim().to_string()),
                    owasp: None,
                    cwe: None,
                    debt_minutes: self.debt,
                    module: None,
                });
            }
        }

        issues
    }
}

/// Parse severity string to enum
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "minor" => Some(Severity::Minor),
        "major" => Some(Severity::Major),
        "critical" => Some(Severity::Critical),
        "blocker" => Some(Severity::Blocker),
        _ => None,
    }
}

/// Parse category string to enum
fn parse_category(s: &str) -> Option<RuleCategory> {
    match s.to_lowercase().as_str() {
        "naming" => Some(RuleCategory::Naming),
        "security" => Some(RuleCategory::Security),
        "bug" => Some(RuleCategory::Bug),
        "code_smell" | "codesmell" => Some(RuleCategory::CodeSmell),
        "complexity" => Some(RuleCategory::Complexity),
        "documentation" => Some(RuleCategory::Documentation),
        "performance" => Some(RuleCategory::Performance),
        _ => None,
    }
}

/// Load custom rules from a YAML file
pub fn load_custom_rules(path: &Path) -> Result<Vec<Box<dyn Rule>>, CustomRuleError> {
    let content = fs::read_to_string(path)
        .map_err(|e| CustomRuleError::IoError(e.to_string()))?;

    let config: CustomRulesConfig = serde_yaml::from_str(&content)
        .map_err(|e| CustomRuleError::ParseError(e.to_string()))?;

    let mut rules: Vec<Box<dyn Rule>> = Vec::new();

    for rule_config in config.rules {
        let rule = CustomRule::from_config(rule_config)?;
        rules.push(Box::new(rule));
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn create_test_context(source: &str) -> (String, tree_sitter::Tree, crate::AnalyzerConfig) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let config = crate::AnalyzerConfig::default();
        (source.to_string(), tree, config)
    }

    // ===== YAML Parsing Tests =====

    #[test]
    fn test_parse_valid_yaml() {
        let yaml = r#"
rules:
  - id: "CUSTOM-001"
    title: "Avoid System.out"
    severity: major
    category: code_smell
    pattern: "System\\.out\\.println"
    message: "Use logging framework instead"
    debt_minutes: 5
"#;
        let config: CustomRulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "CUSTOM-001");
        assert_eq!(config.rules[0].severity, "major");
    }

    #[test]
    fn test_parse_yaml_with_negative_pattern() {
        let yaml = r#"
rules:
  - id: "CUSTOM-002"
    title: "No System.out except tests"
    severity: minor
    category: code_smell
    pattern: "System\\.out"
    message: "Use logger"
    negative_pattern: "@Test"
"#;
        let config: CustomRulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.rules[0].negative_pattern, Some("@Test".to_string()));
    }

    #[test]
    fn test_parse_yaml_default_debt() {
        let yaml = r#"
rules:
  - id: "CUSTOM-003"
    title: "Test rule"
    severity: info
    category: naming
    pattern: "test"
    message: "Found test"
"#;
        let config: CustomRulesConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.rules[0].debt_minutes, 5); // Default value
    }

    // ===== Rule Validation Tests =====

    #[test]
    fn test_invalid_rule_id() {
        let config = CustomRuleConfig {
            id: "BAD-001".to_string(), // Should start with CUSTOM-
            title: "Test".to_string(),
            severity: "major".to_string(),
            category: "bug".to_string(),
            pattern: "test".to_string(),
            message: "Test".to_string(),
            negative_pattern: None,
            debt_minutes: 5,
            description: None,
        };

        let result = CustomRule::from_config(config);
        assert!(matches!(result, Err(CustomRuleError::InvalidRuleId(_))));
    }

    #[test]
    fn test_invalid_severity() {
        let config = CustomRuleConfig {
            id: "CUSTOM-001".to_string(),
            title: "Test".to_string(),
            severity: "super-critical".to_string(), // Invalid
            category: "bug".to_string(),
            pattern: "test".to_string(),
            message: "Test".to_string(),
            negative_pattern: None,
            debt_minutes: 5,
            description: None,
        };

        let result = CustomRule::from_config(config);
        assert!(matches!(result, Err(CustomRuleError::InvalidSeverity(_))));
    }

    #[test]
    fn test_invalid_category() {
        let config = CustomRuleConfig {
            id: "CUSTOM-001".to_string(),
            title: "Test".to_string(),
            severity: "major".to_string(),
            category: "unknown-category".to_string(), // Invalid
            pattern: "test".to_string(),
            message: "Test".to_string(),
            negative_pattern: None,
            debt_minutes: 5,
            description: None,
        };

        let result = CustomRule::from_config(config);
        assert!(matches!(result, Err(CustomRuleError::InvalidCategory(_))));
    }

    #[test]
    fn test_invalid_regex() {
        let config = CustomRuleConfig {
            id: "CUSTOM-001".to_string(),
            title: "Test".to_string(),
            severity: "major".to_string(),
            category: "bug".to_string(),
            pattern: "[invalid".to_string(), // Invalid regex
            message: "Test".to_string(),
            negative_pattern: None,
            debt_minutes: 5,
            description: None,
        };

        let result = CustomRule::from_config(config);
        assert!(matches!(result, Err(CustomRuleError::InvalidRegex { .. })));
    }

    #[test]
    fn test_invalid_negative_regex() {
        let config = CustomRuleConfig {
            id: "CUSTOM-001".to_string(),
            title: "Test".to_string(),
            severity: "major".to_string(),
            category: "bug".to_string(),
            pattern: "test".to_string(),
            message: "Test".to_string(),
            negative_pattern: Some("(unclosed".to_string()), // Invalid regex
            debt_minutes: 5,
            description: None,
        };

        let result = CustomRule::from_config(config);
        assert!(matches!(result, Err(CustomRuleError::InvalidRegex { .. })));
    }

    // ===== Rule Check Tests =====

    #[test]
    fn test_custom_rule_matches() {
        let config = CustomRuleConfig {
            id: "CUSTOM-001".to_string(),
            title: "Avoid System.out".to_string(),
            severity: "major".to_string(),
            category: "code_smell".to_string(),
            pattern: r"System\.out\.println".to_string(),
            message: "Use logging instead".to_string(),
            negative_pattern: None,
            debt_minutes: 10,
            description: None,
        };

        let rule = CustomRule::from_config(config).unwrap();

        let source = r#"
public class Test {
    public void foo() {
        System.out.println("Hello");
    }
}
"#;
        let (src, tree, analyzer_config) = create_test_context(source);
        let ctx = AnalysisContext {
            source: &src,
            file_path: "Test.java",
            tree: &tree,
            config: &analyzer_config,
        };

        let issues = rule.check(&ctx);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule_id, "CUSTOM-001");
        assert_eq!(issues[0].line, 4);
        assert_eq!(issues[0].message, "Use logging instead");
    }

    #[test]
    fn test_custom_rule_negative_pattern() {
        let config = CustomRuleConfig {
            id: "CUSTOM-002".to_string(),
            title: "No System.out except tests".to_string(),
            severity: "minor".to_string(),
            category: "code_smell".to_string(),
            pattern: r"System\.out".to_string(),
            message: "Use logger".to_string(),
            negative_pattern: Some("@Test".to_string()),
            debt_minutes: 5,
            description: None,
        };

        let rule = CustomRule::from_config(config).unwrap();

        // The negative pattern skips lines where the negative pattern matches anywhere on the line
        let source = r#"@Test System.out.println("skipped");
System.out.println("matched");
"#;
        let (src, tree, analyzer_config) = create_test_context(source);
        let ctx = AnalysisContext {
            source: &src,
            file_path: "Test.java",
            tree: &tree,
            config: &analyzer_config,
        };

        let issues = rule.check(&ctx);
        // Line 1 has @Test, so it's skipped even though it has System.out
        // Line 2 has System.out with no @Test, so it matches
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].line, 2);
    }

    #[test]
    fn test_custom_rule_no_match() {
        let config = CustomRuleConfig {
            id: "CUSTOM-003".to_string(),
            title: "Find TODO".to_string(),
            severity: "info".to_string(),
            category: "documentation".to_string(),
            pattern: r"TODO".to_string(),
            message: "Found TODO comment".to_string(),
            negative_pattern: None,
            debt_minutes: 5,
            description: None,
        };

        let rule = CustomRule::from_config(config).unwrap();

        let source = r#"
public class Clean {
    public void method() {
        // This code is clean
    }
}
"#;
        let (src, tree, analyzer_config) = create_test_context(source);
        let ctx = AnalysisContext {
            source: &src,
            file_path: "Clean.java",
            tree: &tree,
            config: &analyzer_config,
        };

        let issues = rule.check(&ctx);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_custom_rule_multiple_matches_per_line() {
        let config = CustomRuleConfig {
            id: "CUSTOM-004".to_string(),
            title: "Find foo".to_string(),
            severity: "info".to_string(),
            category: "naming".to_string(),
            pattern: r"foo".to_string(),
            message: "Found foo".to_string(),
            negative_pattern: None,
            debt_minutes: 2,
            description: None,
        };

        let rule = CustomRule::from_config(config).unwrap();

        let source = "String x = foo + foo + foo;";
        let (src, tree, analyzer_config) = create_test_context(source);
        let ctx = AnalysisContext {
            source: &src,
            file_path: "Test.java",
            tree: &tree,
            config: &analyzer_config,
        };

        let issues = rule.check(&ctx);
        assert_eq!(issues.len(), 3); // Three occurrences of "foo"
    }

    // ===== Rule Trait Implementation Tests =====

    #[test]
    fn test_rule_trait_methods() {
        let config = CustomRuleConfig {
            id: "CUSTOM-005".to_string(),
            title: "Test Title".to_string(),
            severity: "critical".to_string(),
            category: "security".to_string(),
            pattern: "secret".to_string(),
            message: "Found secret".to_string(),
            negative_pattern: None,
            debt_minutes: 30,
            description: Some("Detailed description".to_string()),
        };

        let rule = CustomRule::from_config(config).unwrap();

        assert_eq!(rule.id(), "CUSTOM-005");
        assert_eq!(rule.title(), "Test Title");
        assert_eq!(rule.severity(), Severity::Critical);
        assert_eq!(rule.category(), RuleCategory::Security);
        assert_eq!(rule.debt_minutes(), 30);
        assert_eq!(rule.description(), "Detailed description");
    }

    // ===== File Loading Tests =====

    #[test]
    fn test_load_custom_rules_from_file() {
        let yaml = r#"
rules:
  - id: "CUSTOM-001"
    title: "Rule 1"
    severity: major
    category: bug
    pattern: "pattern1"
    message: "Message 1"
  - id: "CUSTOM-002"
    title: "Rule 2"
    severity: minor
    category: code_smell
    pattern: "pattern2"
    message: "Message 2"
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let rules = load_custom_rules(file.path()).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id(), "CUSTOM-001");
        assert_eq!(rules[1].id(), "CUSTOM-002");
    }

    #[test]
    fn test_load_custom_rules_invalid_file() {
        let result = load_custom_rules(Path::new("/nonexistent/path.yaml"));
        assert!(matches!(result, Err(CustomRuleError::IoError(_))));
    }

    #[test]
    fn test_load_custom_rules_invalid_yaml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not: valid: yaml: [").unwrap();

        let result = load_custom_rules(file.path());
        assert!(matches!(result, Err(CustomRuleError::ParseError(_))));
    }

    // ===== Severity and Category Parsing Tests =====

    #[test]
    fn test_parse_all_severities() {
        assert_eq!(parse_severity("info"), Some(Severity::Info));
        assert_eq!(parse_severity("INFO"), Some(Severity::Info));
        assert_eq!(parse_severity("minor"), Some(Severity::Minor));
        assert_eq!(parse_severity("major"), Some(Severity::Major));
        assert_eq!(parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("blocker"), Some(Severity::Blocker));
        assert_eq!(parse_severity("invalid"), None);
    }

    #[test]
    fn test_parse_all_categories() {
        assert_eq!(parse_category("naming"), Some(RuleCategory::Naming));
        assert_eq!(parse_category("security"), Some(RuleCategory::Security));
        assert_eq!(parse_category("bug"), Some(RuleCategory::Bug));
        assert_eq!(parse_category("code_smell"), Some(RuleCategory::CodeSmell));
        assert_eq!(parse_category("codesmell"), Some(RuleCategory::CodeSmell));
        assert_eq!(parse_category("complexity"), Some(RuleCategory::Complexity));
        assert_eq!(parse_category("documentation"), Some(RuleCategory::Documentation));
        assert_eq!(parse_category("performance"), Some(RuleCategory::Performance));
        assert_eq!(parse_category("invalid"), None);
    }
}
