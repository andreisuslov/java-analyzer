//! Report generation module
//!
//! Generates analysis reports in various formats (text, JSON, HTML, SARIF, GitLab Code Quality).

#[cfg(test)]
use crate::rules::RuleCategory;
use crate::{AnalysisResult, Issue, Severity};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Write;

/// Available report formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Text,
    Json,
    Html,
    Sarif,
    Csv,
    Markdown,
    GitLabCodeQuality,
}

impl ReportFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Some(ReportFormat::Text),
            "json" => Some(ReportFormat::Json),
            "html" => Some(ReportFormat::Html),
            "sarif" => Some(ReportFormat::Sarif),
            "csv" => Some(ReportFormat::Csv),
            "md" | "markdown" => Some(ReportFormat::Markdown),
            "gitlab" | "codequality" | "gitlab-code-quality" => {
                Some(ReportFormat::GitLabCodeQuality)
            }
            _ => None,
        }
    }
}

/// Report configuration
#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub include_snippets: bool,
    pub group_by: GroupBy,
    pub color_output: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Text,
            include_snippets: true,
            group_by: GroupBy::File,
            color_output: true,
        }
    }
}

/// How to group issues in the report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    File,
    Rule,
    Severity,
    Category,
}

/// Report generator
pub struct Report {
    config: ReportConfig,
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

impl Report {
    pub fn new() -> Self {
        Self {
            config: ReportConfig::default(),
        }
    }

    pub fn with_config(config: ReportConfig) -> Self {
        Self { config }
    }

    pub fn with_format(mut self, format: ReportFormat) -> Self {
        self.config.format = format;
        self
    }

    /// Generate report for the analysis result
    pub fn generate(&self, result: &AnalysisResult) -> String {
        match self.config.format {
            ReportFormat::Text => self.generate_text(result),
            ReportFormat::Json => self.generate_json(result),
            ReportFormat::Html => self.generate_html(result),
            ReportFormat::Sarif => self.generate_sarif(result),
            ReportFormat::Csv => self.generate_csv(result),
            ReportFormat::Markdown => self.generate_markdown(result),
            ReportFormat::GitLabCodeQuality => self.generate_gitlab_code_quality(result),
        }
    }

    /// Write report to a writer
    pub fn write_to<W: Write>(
        &self,
        result: &AnalysisResult,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let report = self.generate(result);
        writer.write_all(report.as_bytes())
    }

    fn generate_text(&self, result: &AnalysisResult) -> String {
        let mut output = String::new();

        // Header
        output.push_str("=".repeat(70).as_str());
        output.push_str("\n");
        output.push_str("                     JAVA ANALYZER REPORT\n");
        output.push_str("=".repeat(70).as_str());
        output.push_str("\n\n");

        // Summary
        output.push_str(&format!("Files analyzed: {}\n", result.files_analyzed));
        output.push_str(&format!("Total issues: {}\n", result.issues.len()));
        output.push_str(&format!("Analysis time: {}ms\n\n", result.duration_ms));

        // Severity summary
        let severity_counts = result.severity_counts();
        output.push_str("Issues by Severity:\n");
        for severity in &[
            Severity::Blocker,
            Severity::Critical,
            Severity::Major,
            Severity::Minor,
            Severity::Info,
        ] {
            let count = severity_counts.get(severity).unwrap_or(&0);
            let label = format!("  {:10}", severity.as_str().to_uppercase());
            output.push_str(&format!("{}: {}\n", label, count));
        }
        output.push('\n');

        // Issues grouped by file
        output.push_str("-".repeat(70).as_str());
        output.push_str("\n");
        output.push_str("ISSUES BY FILE\n");
        output.push_str("-".repeat(70).as_str());
        output.push_str("\n\n");

        let issues_by_file = result.issues_by_file();
        let mut files: Vec<_> = issues_by_file.keys().collect();
        files.sort();

        for file in files {
            let issues = &issues_by_file[file];
            output.push_str(&format!("File: {}\n", file));
            output.push_str(&format!("Issues: {}\n\n", issues.len()));

            for issue in issues {
                output.push_str(&format!(
                    "  [{:8}] {}:{} - {} ({})\n",
                    issue.severity.as_str().to_uppercase(),
                    issue.line,
                    issue.column,
                    issue.message,
                    issue.rule_id
                ));

                if self.config.include_snippets {
                    if let Some(ref snippet) = issue.code_snippet {
                        output.push_str(&format!("             > {}\n", snippet));
                    }
                }
            }
            output.push('\n');
        }

        output
    }

    fn generate_json(&self, result: &AnalysisResult) -> String {
        #[derive(Serialize)]
        struct JsonReport<'a> {
            summary: Summary,
            issues: &'a [Issue],
            issues_by_file: HashMap<String, Vec<&'a Issue>>,
            issues_by_severity: HashMap<String, usize>,
            issues_by_rule: HashMap<String, usize>,
        }

        #[derive(Serialize)]
        struct Summary {
            files_analyzed: usize,
            total_issues: usize,
            duration_ms: u64,
        }

        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for (sev, count) in result.severity_counts() {
            severity_counts.insert(sev.as_str().to_string(), count);
        }

        let mut rule_counts: HashMap<String, usize> = HashMap::new();
        for (rule, issues) in result.issues_by_rule() {
            rule_counts.insert(rule, issues.len());
        }

        let report = JsonReport {
            summary: Summary {
                files_analyzed: result.files_analyzed,
                total_issues: result.issues.len(),
                duration_ms: result.duration_ms,
            },
            issues: &result.issues,
            issues_by_file: result.issues_by_file(),
            issues_by_severity: severity_counts,
            issues_by_rule: rule_counts,
        };

        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }

    fn generate_html(&self, result: &AnalysisResult) -> String {
        let severity_counts = result.severity_counts();
        let issues_by_file = result.issues_by_file();

        let mut html = String::from(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Java Analyzer Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { color: #7f8c8d; font-size: 14px; text-transform: uppercase; margin-bottom: 10px; }
        .card .value { font-size: 32px; font-weight: bold; color: #2c3e50; }
        .severity-badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .severity-blocker { background: #e74c3c; color: white; }
        .severity-critical { background: #e67e22; color: white; }
        .severity-major { background: #f39c12; color: white; }
        .severity-minor { background: #3498db; color: white; }
        .severity-info { background: #95a5a6; color: white; }
        .file-section { background: white; margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .file-header { background: #34495e; color: white; padding: 15px 20px; font-family: monospace; }
        .issue { padding: 15px 20px; border-bottom: 1px solid #eee; }
        .issue:last-child { border-bottom: none; }
        .issue-location { font-family: monospace; color: #7f8c8d; font-size: 14px; }
        .issue-message { margin-top: 5px; }
        .issue-rule { color: #95a5a6; font-size: 13px; margin-top: 5px; }
        .snippet { background: #f8f8f8; padding: 10px; border-left: 3px solid #3498db; margin-top: 10px; font-family: monospace; font-size: 13px; overflow-x: auto; }
        .severity-counts { display: flex; gap: 10px; flex-wrap: wrap; }
        .severity-count { display: flex; align-items: center; gap: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Java Static Analysis Report</h1>

        <div class="summary">
            <div class="card">
                <h3>Files Analyzed</h3>
                <div class="value">"#,
        );

        html.push_str(&result.files_analyzed.to_string());
        html.push_str(
            r#"</div>
            </div>
            <div class="card">
                <h3>Total Issues</h3>
                <div class="value">"#,
        );

        html.push_str(&result.issues.len().to_string());
        html.push_str(
            r#"</div>
            </div>
            <div class="card">
                <h3>Analysis Time</h3>
                <div class="value">"#,
        );

        html.push_str(&format!("{}ms", result.duration_ms));
        html.push_str(
            r#"</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 30px;">
            <h3>Issues by Severity</h3>
            <div class="severity-counts">"#,
        );

        for severity in &[
            Severity::Blocker,
            Severity::Critical,
            Severity::Major,
            Severity::Minor,
            Severity::Info,
        ] {
            let count = severity_counts.get(severity).unwrap_or(&0);
            let class = format!("severity-{}", severity.as_str());
            html.push_str(&format!(
                r#"<div class="severity-count"><span class="severity-badge {}">{}</span> {}</div>"#,
                class,
                severity.as_str().to_uppercase(),
                count
            ));
        }

        html.push_str(
            r#"</div>
        </div>

        <h2 style="margin-bottom: 20px;">Issues by File</h2>"#,
        );

        let mut files: Vec<_> = issues_by_file.keys().collect();
        files.sort();

        for file in files {
            let issues = &issues_by_file[file];
            html.push_str(&format!(
                r#"
        <div class="file-section">
            <div class="file-header">{} ({} issues)</div>"#,
                Self::html_escape(file),
                issues.len()
            ));

            for issue in issues {
                let severity_class = format!("severity-{}", issue.severity.as_str());
                html.push_str(&format!(
                    r#"
            <div class="issue">
                <div class="issue-location">
                    <span class="severity-badge {}">{}  </span>
                    Line {}, Column {}
                </div>
                <div class="issue-message">{}</div>
                <div class="issue-rule">{} - {}</div>"#,
                    severity_class,
                    issue.severity.as_str().to_uppercase(),
                    issue.line,
                    issue.column,
                    Self::html_escape(&issue.message),
                    issue.rule_id,
                    Self::html_escape(&issue.title)
                ));

                if let Some(ref snippet) = issue.code_snippet {
                    html.push_str(&format!(
                        r#"
                <div class="snippet">{}</div>"#,
                        Self::html_escape(snippet)
                    ));
                }

                html.push_str("\n            </div>");
            }

            html.push_str("\n        </div>");
        }

        html.push_str(
            r#"
    </div>
</body>
</html>"#,
        );

        html
    }

    fn generate_sarif(&self, result: &AnalysisResult) -> String {
        #[derive(Serialize)]
        struct SarifReport {
            #[serde(rename = "$schema")]
            schema: String,
            version: String,
            runs: Vec<SarifRun>,
        }

        #[derive(Serialize)]
        struct SarifRun {
            tool: SarifTool,
            results: Vec<SarifResult>,
        }

        #[derive(Serialize)]
        struct SarifTool {
            driver: SarifDriver,
        }

        #[derive(Serialize)]
        struct SarifDriver {
            name: String,
            version: String,
            #[serde(rename = "informationUri")]
            information_uri: String,
        }

        #[derive(Serialize)]
        struct SarifResult {
            #[serde(rename = "ruleId")]
            rule_id: String,
            level: String,
            message: SarifMessage,
            locations: Vec<SarifLocation>,
        }

        #[derive(Serialize)]
        struct SarifMessage {
            text: String,
        }

        #[derive(Serialize)]
        struct SarifLocation {
            #[serde(rename = "physicalLocation")]
            physical_location: SarifPhysicalLocation,
        }

        #[derive(Serialize)]
        struct SarifPhysicalLocation {
            #[serde(rename = "artifactLocation")]
            artifact_location: SarifArtifactLocation,
            region: SarifRegion,
        }

        #[derive(Serialize)]
        struct SarifArtifactLocation {
            uri: String,
        }

        #[derive(Serialize)]
        struct SarifRegion {
            #[serde(rename = "startLine")]
            start_line: usize,
            #[serde(rename = "startColumn")]
            start_column: usize,
        }

        fn severity_to_sarif_level(severity: Severity) -> &'static str {
            match severity {
                Severity::Blocker | Severity::Critical => "error",
                Severity::Major => "warning",
                Severity::Minor | Severity::Info => "note",
            }
        }

        let results: Vec<SarifResult> = result
            .issues
            .iter()
            .map(|issue| SarifResult {
                rule_id: issue.rule_id.clone(),
                level: severity_to_sarif_level(issue.severity).to_string(),
                message: SarifMessage {
                    text: issue.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: issue.file.clone(),
                        },
                        region: SarifRegion {
                            start_line: issue.line,
                            start_column: issue.column,
                        },
                    },
                }],
            })
            .collect();

        let report = SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "java-analyzer".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/java-analyzer".to_string(),
                    },
                },
                results,
            }],
        };

        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }

    fn generate_csv(&self, result: &AnalysisResult) -> String {
        let mut csv = String::from("file,line,column,severity,rule_id,title,message\n");

        for issue in &result.issues {
            csv.push_str(&format!(
                "\"{}\",{},{},{},{},\"{}\",\"{}\"\n",
                issue.file.replace('"', "\"\""),
                issue.line,
                issue.column,
                issue.severity.as_str(),
                issue.rule_id,
                issue.title.replace('"', "\"\""),
                issue.message.replace('"', "\"\"")
            ));
        }

        csv
    }

    fn generate_markdown(&self, result: &AnalysisResult) -> String {
        let mut md = String::new();
        let severity_counts = result.severity_counts();

        md.push_str("# Java Static Analysis Report\n\n");
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "- **Files analyzed:** {}\n",
            result.files_analyzed
        ));
        md.push_str(&format!("- **Total issues:** {}\n", result.issues.len()));
        md.push_str(&format!(
            "- **Analysis time:** {}ms\n\n",
            result.duration_ms
        ));

        md.push_str("## Issues by Severity\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        for severity in &[
            Severity::Blocker,
            Severity::Critical,
            Severity::Major,
            Severity::Minor,
            Severity::Info,
        ] {
            let count = severity_counts.get(severity).unwrap_or(&0);
            md.push_str(&format!(
                "| {} | {} |\n",
                severity.as_str().to_uppercase(),
                count
            ));
        }
        md.push('\n');

        md.push_str("## Issues by File\n\n");
        let issues_by_file = result.issues_by_file();
        let mut files: Vec<_> = issues_by_file.keys().collect();
        files.sort();

        for file in files {
            let issues = &issues_by_file[file];
            md.push_str(&format!("### `{}`\n\n", file));

            md.push_str("| Line | Severity | Rule | Message |\n");
            md.push_str("|------|----------|------|--------|\n");

            for issue in issues {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    issue.line,
                    issue.severity.as_str(),
                    issue.rule_id,
                    issue.message.replace('|', "\\|")
                ));
            }
            md.push('\n');
        }

        md
    }

    /// Generate GitLab Code Quality report format
    /// See: https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool
    fn generate_gitlab_code_quality(&self, result: &AnalysisResult) -> String {
        #[derive(Serialize)]
        struct GitLabIssue {
            description: String,
            check_name: String,
            fingerprint: String,
            severity: String,
            location: GitLabLocation,
        }

        #[derive(Serialize)]
        struct GitLabLocation {
            path: String,
            lines: GitLabLines,
        }

        #[derive(Serialize)]
        struct GitLabLines {
            begin: usize,
        }

        let issues: Vec<GitLabIssue> = result
            .issues
            .iter()
            .map(|issue| {
                let severity = Self::severity_to_gitlab(issue.severity);
                let fingerprint = Self::generate_fingerprint(issue);
                let path = Self::normalize_path(&issue.file);

                GitLabIssue {
                    description: format!("{}: {}", issue.rule_id, issue.message),
                    check_name: issue.rule_id.clone(),
                    fingerprint,
                    severity,
                    location: GitLabLocation {
                        path,
                        lines: GitLabLines { begin: issue.line },
                    },
                }
            })
            .collect();

        serde_json::to_string_pretty(&issues).unwrap_or_else(|_| "[]".to_string())
    }

    /// Map severity to GitLab Code Quality severity levels
    fn severity_to_gitlab(severity: Severity) -> String {
        match severity {
            Severity::Blocker => "blocker".to_string(),
            Severity::Critical => "critical".to_string(),
            Severity::Major => "major".to_string(),
            Severity::Minor => "minor".to_string(),
            Severity::Info => "info".to_string(),
        }
    }

    /// Generate a unique fingerprint for an issue using hash of key attributes
    fn generate_fingerprint(issue: &Issue) -> String {
        let mut hasher = DefaultHasher::new();
        issue.rule_id.hash(&mut hasher);
        issue.file.hash(&mut hasher);
        issue.line.hash(&mut hasher);
        issue.message.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Normalize file path to relative path (strip common absolute prefixes)
    fn normalize_path(path: &str) -> String {
        // If path starts with common absolute prefixes, try to make it relative
        if let Some(stripped) = path.strip_prefix('/') {
            // Check for common project root indicators
            if let Some(pos) = stripped.find("/src/") {
                return stripped[pos + 1..].to_string();
            }
            // Return as-is if we can't find a good relative path
            return path.to_string();
        }
        path.to_string()
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
}

use crate::rules::OwaspCategory;
use std::collections::BTreeMap;

/// Group issues by OWASP Top 10 category
pub fn group_by_owasp(issues: &[Issue]) -> BTreeMap<OwaspCategory, Vec<&Issue>> {
    let mut grouped: BTreeMap<OwaspCategory, Vec<&Issue>> = BTreeMap::new();
    for issue in issues {
        if let Some(owasp) = issue.owasp {
            grouped.entry(owasp).or_default().push(issue);
        }
    }
    grouped
}

/// Group issues by CWE identifier
pub fn group_by_cwe(issues: &[Issue]) -> BTreeMap<u32, Vec<&Issue>> {
    let mut grouped: BTreeMap<u32, Vec<&Issue>> = BTreeMap::new();
    for issue in issues {
        if let Some(cwe) = issue.cwe {
            grouped.entry(cwe).or_default().push(issue);
        }
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_result() -> AnalysisResult {

        AnalysisResult {
            files_analyzed: 5,
            duration_ms: 100,
            issues: vec![
                Issue {
                    rule_id: "S100".to_string(),
                    title: "Method naming".to_string(),
                    severity: Severity::Minor,
                    category: RuleCategory::Naming,
                    file: "Test.java".to_string(),
                    line: 10,
                    column: 5,
                    end_line: None,
                    end_column: None,
                    message: "Rename method".to_string(),
                    code_snippet: Some("void BadMethod() {}".to_string()),
                    owasp: None,
                    cwe: None,
                    debt_minutes: 5,
                    module: None,
                },
                Issue {
                    rule_id: "S2068".to_string(),
                    title: "Hardcoded credentials".to_string(),
                    severity: Severity::Blocker,
                    category: RuleCategory::Security,
                    file: "Config.java".to_string(),
                    line: 25,
                    column: 1,
                    end_line: None,
                    end_column: None,
                    message: "Remove hardcoded password".to_string(),
                    code_snippet: Some("String password = \"secret\"".to_string()),
                    owasp: Some(OwaspCategory::A07AuthenticationFailures),
                    cwe: Some(798),
                    debt_minutes: 30,
                    module: None,
                },
            ],
            modules: None,
        }
    }

    #[test]
    fn test_text_report() {
        let result = create_test_result();
        let report = Report::new().generate(&result);
        assert!(report.contains("Files analyzed: 5"));
        assert!(report.contains("Total issues: 2"));
        assert!(report.contains("S100"));
        assert!(report.contains("S2068"));
    }

    #[test]
    fn test_json_report() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::Json)
            .generate(&result);
        let json: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert_eq!(json["summary"]["files_analyzed"], 5);
        assert_eq!(json["summary"]["total_issues"], 2);
    }

    #[test]
    fn test_html_report() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::Html)
            .generate(&result);
        assert!(report.contains("<!DOCTYPE html>"));
        assert!(report.contains("Java Static Analysis Report"));
        assert!(report.contains("Test.java"));
    }

    #[test]
    fn test_csv_report() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::Csv)
            .generate(&result);
        assert!(report.contains("file,line,column"));
        assert!(report.contains("\"Test.java\",10,5"));
    }

    #[test]
    fn test_markdown_report() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::Markdown)
            .generate(&result);
        assert!(report.contains("# Java Static Analysis Report"));
        assert!(report.contains("| Severity | Count |"));
    }

    #[test]
    fn test_sarif_report() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::Sarif)
            .generate(&result);
        let json: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert_eq!(json["version"], "2.1.0");
        assert!(json["runs"][0]["tool"]["driver"]["name"] == "java-analyzer");
    }

    // ===== GitLab Code Quality Tests =====

    #[test]
    fn test_gitlab_code_quality_report_structure() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::GitLabCodeQuality)
            .generate(&result);

        // Should be a valid JSON array
        let json: Vec<serde_json::Value> = serde_json::from_str(&report).unwrap();
        assert_eq!(json.len(), 2); // Two issues in test result

        // Check required fields exist
        let first = &json[0];
        assert!(first.get("description").is_some());
        assert!(first.get("check_name").is_some());
        assert!(first.get("fingerprint").is_some());
        assert!(first.get("severity").is_some());
        assert!(first.get("location").is_some());
        assert!(first["location"].get("path").is_some());
        assert!(first["location"]["lines"].get("begin").is_some());
    }

    #[test]
    fn test_gitlab_severity_mapping() {
        assert_eq!(Report::severity_to_gitlab(Severity::Blocker), "blocker");
        assert_eq!(Report::severity_to_gitlab(Severity::Critical), "critical");
        assert_eq!(Report::severity_to_gitlab(Severity::Major), "major");
        assert_eq!(Report::severity_to_gitlab(Severity::Minor), "minor");
        assert_eq!(Report::severity_to_gitlab(Severity::Info), "info");
    }

    #[test]
    fn test_gitlab_fingerprint_generation() {
        let issue1 = Issue {
            rule_id: "S100".to_string(),
            title: "Test".to_string(),
            severity: Severity::Minor,
            category: RuleCategory::Naming,
            file: "Test.java".to_string(),
            line: 10,
            column: 5,
            end_line: None,
            end_column: None,
            message: "Test message".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: 5,
            module: None,
        };

        let issue2 = Issue {
            rule_id: "S100".to_string(),
            title: "Test".to_string(),
            severity: Severity::Minor,
            category: RuleCategory::Naming,
            file: "Test.java".to_string(),
            line: 20, // Different line
            column: 5,
            end_line: None,
            end_column: None,
            message: "Test message".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: 5,
            module: None,
        };

        let fp1 = Report::generate_fingerprint(&issue1);
        let fp2 = Report::generate_fingerprint(&issue2);

        // Fingerprints should be 16 hex characters
        assert_eq!(fp1.len(), 16);
        assert_eq!(fp2.len(), 16);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));

        // Same issue should give same fingerprint
        let fp1_again = Report::generate_fingerprint(&issue1);
        assert_eq!(fp1, fp1_again);

        // Different issues should give different fingerprints
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_gitlab_code_quality_content() {
        let result = create_test_result();
        let report = Report::new()
            .with_format(ReportFormat::GitLabCodeQuality)
            .generate(&result);

        let json: Vec<serde_json::Value> = serde_json::from_str(&report).unwrap();

        // Find the S100 issue
        let s100_issue = json
            .iter()
            .find(|i| i["check_name"] == "S100")
            .expect("Should have S100 issue");

        assert!(s100_issue["description"].as_str().unwrap().contains("S100"));
        assert_eq!(s100_issue["severity"], "minor");
        assert_eq!(s100_issue["location"]["lines"]["begin"], 10);

        // Find the S2068 issue (blocker severity)
        let s2068_issue = json
            .iter()
            .find(|i| i["check_name"] == "S2068")
            .expect("Should have S2068 issue");

        assert_eq!(s2068_issue["severity"], "blocker");
    }

    #[test]
    fn test_gitlab_format_aliases() {
        assert_eq!(
            ReportFormat::from_str("gitlab"),
            Some(ReportFormat::GitLabCodeQuality)
        );
        assert_eq!(
            ReportFormat::from_str("codequality"),
            Some(ReportFormat::GitLabCodeQuality)
        );
        assert_eq!(
            ReportFormat::from_str("gitlab-code-quality"),
            Some(ReportFormat::GitLabCodeQuality)
        );
        assert_eq!(
            ReportFormat::from_str("GITLAB"),
            Some(ReportFormat::GitLabCodeQuality)
        );
    }

    #[test]
    fn test_gitlab_empty_result() {
        let result = AnalysisResult {
            files_analyzed: 0,
            issues: vec![],
            duration_ms: 0,
            modules: None,
        };
        let report = Report::new()
            .with_format(ReportFormat::GitLabCodeQuality)
            .generate(&result);

        let json: Vec<serde_json::Value> = serde_json::from_str(&report).unwrap();
        assert!(json.is_empty());
    }

    #[test]
    fn test_gitlab_path_normalization() {
        // Absolute path with src
        assert_eq!(
            Report::normalize_path("/home/user/project/src/main/java/Test.java"),
            "src/main/java/Test.java"
        );

        // Already relative
        assert_eq!(
            Report::normalize_path("src/main/java/Test.java"),
            "src/main/java/Test.java"
        );

        // No src directory
        assert_eq!(
            Report::normalize_path("/home/user/Test.java"),
            "/home/user/Test.java"
        );
    }

    // ===== Compliance Report Tests (OWASP/CWE Grouping) =====

    fn create_issue_with_owasp(
        rule_id: &str,
        owasp: OwaspCategory,
        cwe: Option<u32>,
    ) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            title: format!("Rule {}", rule_id),
            severity: Severity::Critical,
            category: RuleCategory::Security,
            file: "Test.java".to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Test message".to_string(),
            code_snippet: None,
            owasp: Some(owasp),
            cwe,
            debt_minutes: 10,
            module: None,
        }
    }

    #[test]
    fn test_group_issues_by_owasp() {
        let issues = vec![
            create_issue_with_owasp("S3649", OwaspCategory::A03Injection, Some(89)),
            create_issue_with_owasp("S2068", OwaspCategory::A07AuthenticationFailures, Some(798)),
            create_issue_with_owasp("S2076", OwaspCategory::A03Injection, Some(78)),
            create_issue_with_owasp("S4423", OwaspCategory::A02CryptographicFailures, Some(326)),
        ];
        let grouped = group_by_owasp(&issues);

        assert_eq!(
            grouped.get(&OwaspCategory::A03Injection).unwrap().len(),
            2,
            "A03 Injection should have 2 issues"
        );
        assert_eq!(
            grouped.get(&OwaspCategory::A07AuthenticationFailures).unwrap().len(),
            1,
            "A07 Auth Failures should have 1 issue"
        );
        assert_eq!(
            grouped.get(&OwaspCategory::A02CryptographicFailures).unwrap().len(),
            1,
            "A02 Crypto Failures should have 1 issue"
        );
    }

    #[test]
    fn test_group_issues_by_cwe() {
        let issues = vec![
            create_issue_with_owasp("S3649", OwaspCategory::A03Injection, Some(89)),
            create_issue_with_owasp("S5247", OwaspCategory::A03Injection, Some(89)),
            create_issue_with_owasp("S2076", OwaspCategory::A03Injection, Some(78)),
            create_issue_with_owasp("S2068", OwaspCategory::A07AuthenticationFailures, Some(798)),
        ];
        let grouped = group_by_cwe(&issues);

        assert_eq!(
            grouped.get(&89).unwrap().len(),
            2,
            "CWE-89 (SQL Injection) should have 2 issues"
        );
        assert_eq!(
            grouped.get(&78).unwrap().len(),
            1,
            "CWE-78 (OS Command Injection) should have 1 issue"
        );
        assert_eq!(
            grouped.get(&798).unwrap().len(),
            1,
            "CWE-798 (Hardcoded Credentials) should have 1 issue"
        );
    }

    #[test]
    fn test_group_by_owasp_ignores_none() {
        let issues = vec![
            create_issue_with_owasp("S3649", OwaspCategory::A03Injection, Some(89)),
            Issue {
                rule_id: "S100".to_string(),
                title: "Naming rule".to_string(),
                severity: Severity::Minor,
                category: RuleCategory::Naming,
                file: "Test.java".to_string(),
                line: 1,
                column: 1,
                end_line: None,
                end_column: None,
                message: "Rename method".to_string(),
                code_snippet: None,
                owasp: None, // No OWASP mapping
                cwe: None,
                debt_minutes: 5,
                module: None,
            },
        ];
        let grouped = group_by_owasp(&issues);

        // Should only have 1 entry (the one with OWASP mapping)
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped.get(&OwaspCategory::A03Injection).unwrap().len(), 1);
    }

    #[test]
    fn test_group_by_cwe_ignores_none() {
        let issues = vec![
            create_issue_with_owasp("S3649", OwaspCategory::A03Injection, Some(89)),
            Issue {
                rule_id: "S100".to_string(),
                title: "Naming rule".to_string(),
                severity: Severity::Minor,
                category: RuleCategory::Naming,
                file: "Test.java".to_string(),
                line: 1,
                column: 1,
                end_line: None,
                end_column: None,
                message: "Rename method".to_string(),
                code_snippet: None,
                owasp: None,
                cwe: None, // No CWE mapping
                debt_minutes: 5,
                module: None,
            },
        ];
        let grouped = group_by_cwe(&issues);

        // Should only have 1 entry (the one with CWE mapping)
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped.get(&89).unwrap().len(), 1);
    }

    #[test]
    fn test_group_by_owasp_empty() {
        let issues: Vec<Issue> = vec![];
        let grouped = group_by_owasp(&issues);
        assert!(grouped.is_empty());
    }

    #[test]
    fn test_group_by_cwe_empty() {
        let issues: Vec<Issue> = vec![];
        let grouped = group_by_cwe(&issues);
        assert!(grouped.is_empty());
    }
}
