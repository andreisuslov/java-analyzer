//! Report generation module
//!
//! Generates analysis reports in various formats (text, JSON, HTML, SARIF).

use crate::{AnalysisResult, Issue, RuleCategory, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_result() -> AnalysisResult {
        use crate::rules::OwaspCategory;

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
                },
            ],
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
}
