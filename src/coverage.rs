//! Test Coverage Integration
//!
//! Import and analyze test coverage from JaCoCo and LCOV formats.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Coverage data for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverage {
    /// File path
    pub file: String,
    /// Lines covered
    pub covered_lines: Vec<usize>,
    /// Lines not covered
    pub uncovered_lines: Vec<usize>,
    /// Total executable lines
    pub total_lines: usize,
    /// Line coverage percentage
    pub line_coverage: f64,
    /// Branch coverage (if available)
    pub branch_coverage: Option<f64>,
}

impl FileCoverage {
    pub fn new(file: String) -> Self {
        Self {
            file,
            covered_lines: Vec::new(),
            uncovered_lines: Vec::new(),
            total_lines: 0,
            line_coverage: 0.0,
            branch_coverage: None,
        }
    }

    pub fn calculate_coverage(&mut self) {
        self.total_lines = self.covered_lines.len() + self.uncovered_lines.len();
        if self.total_lines > 0 {
            self.line_coverage = (self.covered_lines.len() as f64 / self.total_lines as f64) * 100.0;
        }
    }
}

/// Aggregated coverage report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Coverage by file
    pub files: HashMap<String, FileCoverage>,
    /// Overall line coverage percentage
    pub overall_line_coverage: f64,
    /// Overall branch coverage percentage (if available)
    pub overall_branch_coverage: Option<f64>,
    /// Total lines covered
    pub total_covered: usize,
    /// Total lines uncovered
    pub total_uncovered: usize,
    /// Number of files with coverage data
    pub files_with_coverage: usize,
}

impl CoverageReport {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            overall_line_coverage: 0.0,
            overall_branch_coverage: None,
            total_covered: 0,
            total_uncovered: 0,
            files_with_coverage: 0,
        }
    }

    /// Calculate overall coverage from file data
    pub fn calculate_overall(&mut self) {
        self.total_covered = self.files.values().map(|f| f.covered_lines.len()).sum();
        self.total_uncovered = self.files.values().map(|f| f.uncovered_lines.len()).sum();
        self.files_with_coverage = self.files.len();

        let total = self.total_covered + self.total_uncovered;
        if total > 0 {
            self.overall_line_coverage = (self.total_covered as f64 / total as f64) * 100.0;
        }
    }

    /// Check if coverage meets threshold
    pub fn meets_threshold(&self, min_coverage: f64) -> bool {
        self.overall_line_coverage >= min_coverage
    }

    /// Get files below coverage threshold
    pub fn files_below_threshold(&self, min_coverage: f64) -> Vec<&FileCoverage> {
        self.files.values()
            .filter(|f| f.line_coverage < min_coverage)
            .collect()
    }

    /// Get uncovered lines for a specific file
    pub fn uncovered_lines(&self, file: &str) -> Option<&Vec<usize>> {
        self.files.get(file).map(|f| &f.uncovered_lines)
    }
}

impl Default for CoverageReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse LCOV format coverage report
pub fn parse_lcov(content: &str) -> Result<CoverageReport, CoverageError> {
    let mut report = CoverageReport::new();
    let mut current_file: Option<FileCoverage> = None;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("SF:") {
            // Source file
            if let Some(file) = current_file.take() {
                let mut file = file;
                file.calculate_coverage();
                report.files.insert(file.file.clone(), file);
            }
            let file_path = line.strip_prefix("SF:").unwrap_or("").to_string();
            current_file = Some(FileCoverage::new(file_path));
        } else if line.starts_with("DA:") {
            // Line data: DA:line_number,hit_count
            if let Some(ref mut file) = current_file {
                let parts: Vec<&str> = line.strip_prefix("DA:").unwrap_or("")
                    .split(',')
                    .collect();
                if parts.len() >= 2 {
                    if let Ok(line_num) = parts[0].parse::<usize>() {
                        if let Ok(hits) = parts[1].parse::<usize>() {
                            if hits > 0 {
                                file.covered_lines.push(line_num);
                            } else {
                                file.uncovered_lines.push(line_num);
                            }
                        }
                    }
                }
            }
        } else if line.starts_with("BRDA:") {
            // Branch data (simplified handling)
            // BRDA:line,block,branch,taken
        } else if line == "end_of_record" {
            if let Some(file) = current_file.take() {
                let mut file = file;
                file.calculate_coverage();
                report.files.insert(file.file.clone(), file);
            }
        }
    }

    // Handle last file if no end_of_record
    if let Some(file) = current_file {
        let mut file = file;
        file.calculate_coverage();
        report.files.insert(file.file.clone(), file);
    }

    report.calculate_overall();
    Ok(report)
}

/// Parse JaCoCo XML format coverage report
pub fn parse_jacoco_xml(content: &str) -> Result<CoverageReport, CoverageError> {
    let mut report = CoverageReport::new();

    // Simple XML parsing (for production, use a proper XML parser)
    // This handles the basic structure of JaCoCo XML

    // Find all sourcefile elements
    let mut current_file = String::new();
    let mut covered_lines = Vec::new();
    let mut uncovered_lines = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Match sourcefile start
        if line.contains("<sourcefile") && line.contains("name=") {
            // Save previous file if any
            if !current_file.is_empty() {
                let mut file_cov = FileCoverage::new(current_file.clone());
                file_cov.covered_lines = covered_lines.clone();
                file_cov.uncovered_lines = uncovered_lines.clone();
                file_cov.calculate_coverage();
                report.files.insert(current_file.clone(), file_cov);
            }

            // Extract filename
            if let Some(start) = line.find("name=\"") {
                let rest = &line[start + 6..];
                if let Some(end) = rest.find('"') {
                    current_file = rest[..end].to_string();
                }
            }
            covered_lines.clear();
            uncovered_lines.clear();
        }

        // Match line elements
        // <line nr="10" mi="0" ci="1" mb="0" cb="0"/>
        if line.contains("<line") && line.contains("nr=") {
            let mut line_num = 0;
            let mut covered = false;

            // Extract line number
            if let Some(start) = line.find("nr=\"") {
                let rest = &line[start + 4..];
                if let Some(end) = rest.find('"') {
                    line_num = rest[..end].parse().unwrap_or(0);
                }
            }

            // Check if covered (ci > 0)
            if let Some(start) = line.find("ci=\"") {
                let rest = &line[start + 4..];
                if let Some(end) = rest.find('"') {
                    let ci: usize = rest[..end].parse().unwrap_or(0);
                    covered = ci > 0;
                }
            }

            if line_num > 0 {
                if covered {
                    covered_lines.push(line_num);
                } else {
                    uncovered_lines.push(line_num);
                }
            }
        }
    }

    // Save last file
    if !current_file.is_empty() {
        let mut file_cov = FileCoverage::new(current_file.clone());
        file_cov.covered_lines = covered_lines;
        file_cov.uncovered_lines = uncovered_lines;
        file_cov.calculate_coverage();
        report.files.insert(current_file, file_cov);
    }

    report.calculate_overall();
    Ok(report)
}

/// Load coverage from file, auto-detecting format
pub fn load_coverage(path: &Path) -> Result<CoverageReport, CoverageError> {
    let content = fs::read_to_string(path)
        .map_err(|e| CoverageError::IoError(e.to_string()))?;

    let extension = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match extension.to_lowercase().as_str() {
        "xml" => parse_jacoco_xml(&content),
        "info" | "lcov" => parse_lcov(&content),
        _ => {
            // Try to auto-detect
            if content.trim_start().starts_with("<?xml") || content.contains("<report") {
                parse_jacoco_xml(&content)
            } else if content.contains("SF:") {
                parse_lcov(&content)
            } else {
                Err(CoverageError::UnknownFormat)
            }
        }
    }
}

/// Coverage parsing errors
#[derive(Debug, Clone)]
pub enum CoverageError {
    IoError(String),
    ParseError(String),
    UnknownFormat,
}

impl std::fmt::Display for CoverageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverageError::IoError(e) => write!(f, "I/O error: {}", e),
            CoverageError::ParseError(e) => write!(f, "Parse error: {}", e),
            CoverageError::UnknownFormat => write!(f, "Unknown coverage format"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== LCOV Parsing Tests =====

    #[test]
    fn test_parse_lcov_basic() {
        let lcov = r#"
SF:/path/to/File.java
DA:1,1
DA:2,1
DA:3,0
DA:4,1
end_of_record
"#;
        let report = parse_lcov(lcov).unwrap();

        assert_eq!(report.files.len(), 1);
        let file = report.files.get("/path/to/File.java").unwrap();
        assert_eq!(file.covered_lines.len(), 3);
        assert_eq!(file.uncovered_lines.len(), 1);
        assert_eq!(file.line_coverage, 75.0);
    }

    #[test]
    fn test_parse_lcov_multiple_files() {
        let lcov = r#"
SF:File1.java
DA:1,1
DA:2,1
end_of_record
SF:File2.java
DA:1,0
DA:2,0
end_of_record
"#;
        let report = parse_lcov(lcov).unwrap();

        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files.get("File1.java").unwrap().line_coverage, 100.0);
        assert_eq!(report.files.get("File2.java").unwrap().line_coverage, 0.0);
    }

    #[test]
    fn test_parse_lcov_empty() {
        let lcov = "";
        let report = parse_lcov(lcov).unwrap();
        assert!(report.files.is_empty());
    }

    // ===== JaCoCo XML Parsing Tests =====

    #[test]
    fn test_parse_jacoco_basic() {
        let xml = r#"
<?xml version="1.0" encoding="UTF-8"?>
<report>
  <package name="com/example">
    <sourcefile name="Test.java">
      <line nr="1" mi="0" ci="1" mb="0" cb="0"/>
      <line nr="2" mi="0" ci="1" mb="0" cb="0"/>
      <line nr="3" mi="1" ci="0" mb="0" cb="0"/>
    </sourcefile>
  </package>
</report>
"#;
        let report = parse_jacoco_xml(xml).unwrap();

        assert_eq!(report.files.len(), 1);
        let file = report.files.get("Test.java").unwrap();
        assert_eq!(file.covered_lines.len(), 2);
        assert_eq!(file.uncovered_lines.len(), 1);
    }

    // ===== Coverage Report Tests =====

    #[test]
    fn test_coverage_report_overall() {
        let mut report = CoverageReport::new();

        let mut file1 = FileCoverage::new("File1.java".to_string());
        file1.covered_lines = vec![1, 2, 3, 4];
        file1.uncovered_lines = vec![];
        file1.calculate_coverage();

        let mut file2 = FileCoverage::new("File2.java".to_string());
        file2.covered_lines = vec![1, 2];
        file2.uncovered_lines = vec![3, 4];
        file2.calculate_coverage();

        report.files.insert("File1.java".to_string(), file1);
        report.files.insert("File2.java".to_string(), file2);
        report.calculate_overall();

        assert_eq!(report.total_covered, 6);
        assert_eq!(report.total_uncovered, 2);
        assert_eq!(report.overall_line_coverage, 75.0);
    }

    #[test]
    fn test_meets_threshold() {
        let mut report = CoverageReport::new();

        let mut file = FileCoverage::new("File.java".to_string());
        file.covered_lines = vec![1, 2, 3, 4, 5, 6, 7, 8];
        file.uncovered_lines = vec![9, 10];
        file.calculate_coverage();

        report.files.insert("File.java".to_string(), file);
        report.calculate_overall();

        assert!(report.meets_threshold(80.0));
        assert!(!report.meets_threshold(85.0));
    }

    #[test]
    fn test_files_below_threshold() {
        let mut report = CoverageReport::new();

        let mut file1 = FileCoverage::new("Good.java".to_string());
        file1.covered_lines = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        file1.uncovered_lines = vec![10];
        file1.calculate_coverage();

        let mut file2 = FileCoverage::new("Bad.java".to_string());
        file2.covered_lines = vec![1, 2];
        file2.uncovered_lines = vec![3, 4, 5, 6, 7, 8, 9, 10];
        file2.calculate_coverage();

        report.files.insert("Good.java".to_string(), file1);
        report.files.insert("Bad.java".to_string(), file2);

        let below = report.files_below_threshold(80.0);
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].file, "Bad.java");
    }

    #[test]
    fn test_uncovered_lines() {
        let mut report = CoverageReport::new();

        let mut file = FileCoverage::new("File.java".to_string());
        file.uncovered_lines = vec![5, 10, 15];
        report.files.insert("File.java".to_string(), file);

        let uncovered = report.uncovered_lines("File.java");
        assert!(uncovered.is_some());
        assert_eq!(uncovered.unwrap(), &vec![5, 10, 15]);
    }

    // ===== File Coverage Tests =====

    #[test]
    fn test_file_coverage_calculation() {
        let mut file = FileCoverage::new("Test.java".to_string());
        file.covered_lines = vec![1, 2, 3];
        file.uncovered_lines = vec![4, 5];
        file.calculate_coverage();

        assert_eq!(file.total_lines, 5);
        assert_eq!(file.line_coverage, 60.0);
    }

    #[test]
    fn test_file_coverage_zero_lines() {
        let mut file = FileCoverage::new("Empty.java".to_string());
        file.calculate_coverage();

        assert_eq!(file.total_lines, 0);
        assert_eq!(file.line_coverage, 0.0);
    }

    #[test]
    fn test_file_coverage_full() {
        let mut file = FileCoverage::new("Full.java".to_string());
        file.covered_lines = vec![1, 2, 3, 4, 5];
        file.calculate_coverage();

        assert_eq!(file.line_coverage, 100.0);
    }
}
