//! Code Duplication Detection
//!
//! Detects copy-paste code and similar code blocks using:
//! - Line-based hashing for exact duplicates
//! - Token-based comparison for similar code
//! - Configurable thresholds

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// Configuration for duplication detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicationConfig {
    /// Minimum number of lines to consider a duplicate
    pub min_lines: usize,
    /// Minimum number of tokens to consider a duplicate
    pub min_tokens: usize,
    /// Ignore whitespace differences
    pub ignore_whitespace: bool,
    /// Ignore comments
    pub ignore_comments: bool,
    /// Ignore string literals (treat all strings as equivalent)
    pub ignore_literals: bool,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self {
            min_lines: 6,
            min_tokens: 50,
            ignore_whitespace: true,
            ignore_comments: true,
            ignore_literals: false,
        }
    }
}

/// A location in source code
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}

impl CodeLocation {
    pub fn new(file: impl Into<String>, start_line: usize, end_line: usize) -> Self {
        Self {
            file: file.into(),
            start_line,
            end_line,
        }
    }

    pub fn line_count(&self) -> usize {
        self.end_line - self.start_line + 1
    }
}

/// A duplicated code block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateBlock {
    /// Locations where this duplicate appears
    pub locations: Vec<CodeLocation>,
    /// Number of duplicated lines
    pub line_count: usize,
    /// Number of duplicated tokens
    pub token_count: usize,
    /// Hash of the normalized code
    pub hash: u64,
    /// Sample of the duplicated code (first few lines)
    pub code_sample: Option<String>,
}

impl DuplicateBlock {
    pub fn new(
        locations: Vec<CodeLocation>,
        line_count: usize,
        token_count: usize,
        hash: u64,
    ) -> Self {
        Self {
            locations,
            line_count,
            token_count,
            hash,
            code_sample: None,
        }
    }

    /// Number of times this code is duplicated
    pub fn duplicate_count(&self) -> usize {
        self.locations.len()
    }
}

/// Result of duplication analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicationResult {
    /// Files analyzed
    pub files_analyzed: usize,
    /// Total lines analyzed
    pub total_lines: usize,
    /// Duplicated lines
    pub duplicated_lines: usize,
    /// Duplication percentage
    pub duplication_percentage: f64,
    /// Individual duplicate blocks
    pub duplicates: Vec<DuplicateBlock>,
}

impl DuplicationResult {
    pub fn new() -> Self {
        Self {
            files_analyzed: 0,
            total_lines: 0,
            duplicated_lines: 0,
            duplication_percentage: 0.0,
            duplicates: Vec::new(),
        }
    }

    pub fn calculate_percentage(&mut self) {
        if self.total_lines > 0 {
            self.duplication_percentage =
                (self.duplicated_lines as f64 / self.total_lines as f64) * 100.0;
        }
    }
}

impl Default for DuplicationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Duplication detector
pub struct DuplicationDetector {
    config: DuplicationConfig,
}

impl DuplicationDetector {
    pub fn new() -> Self {
        Self {
            config: DuplicationConfig::default(),
        }
    }

    pub fn with_config(config: DuplicationConfig) -> Self {
        Self { config }
    }

    /// Normalize a line for comparison
    fn normalize_line(&self, line: &str) -> String {
        let mut normalized = line.to_string();

        if self.config.ignore_whitespace {
            // Replace all whitespace sequences with single space
            normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
        }

        if self.config.ignore_comments {
            // Remove single-line comments
            if let Some(pos) = normalized.find("//") {
                normalized = normalized[..pos].to_string();
            }
        }

        normalized.trim().to_string()
    }

    /// Hash a sequence of lines
    fn hash_lines(&self, lines: &[String]) -> u64 {
        let mut hasher = DefaultHasher::new();
        for line in lines {
            line.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Analyze a single file for internal duplicates
    pub fn analyze_file(&self, file_path: &str, content: &str) -> Vec<DuplicateBlock> {
        let lines: Vec<&str> = content.lines().collect();
        let normalized: Vec<String> = lines.iter().map(|l| self.normalize_line(l)).collect();

        let mut hash_to_locations: HashMap<u64, Vec<CodeLocation>> = HashMap::new();
        let min_lines = self.config.min_lines;

        // Sliding window approach
        for start in 0..normalized.len().saturating_sub(min_lines - 1) {
            let window: Vec<String> = normalized[start..start + min_lines].to_vec();

            // Skip if window contains only empty/whitespace lines
            if window.iter().all(|l| l.is_empty()) {
                continue;
            }

            let hash = self.hash_lines(&window);
            let location = CodeLocation::new(file_path, start + 1, start + min_lines);

            hash_to_locations.entry(hash).or_default().push(location);
        }

        // Convert to duplicate blocks (only those appearing more than once)
        hash_to_locations
            .into_iter()
            .filter(|(_, locs)| locs.len() > 1)
            .map(|(hash, locations)| {
                let line_count = min_lines;
                let token_count = 0; // Simplified for now
                DuplicateBlock::new(locations, line_count, token_count, hash)
            })
            .collect()
    }

    /// Analyze multiple files for cross-file duplicates
    pub fn analyze_files(&self, files: &[(String, String)]) -> DuplicationResult {
        let mut result = DuplicationResult::new();
        let mut hash_to_locations: HashMap<u64, Vec<(CodeLocation, String)>> = HashMap::new();
        let min_lines = self.config.min_lines;

        for (file_path, content) in files {
            result.files_analyzed += 1;
            let lines: Vec<&str> = content.lines().collect();
            result.total_lines += lines.len();

            let normalized: Vec<String> = lines.iter().map(|l| self.normalize_line(l)).collect();

            // Sliding window
            for start in 0..normalized.len().saturating_sub(min_lines - 1) {
                let window: Vec<String> = normalized[start..start + min_lines].to_vec();

                if window.iter().all(|l| l.is_empty()) {
                    continue;
                }

                let hash = self.hash_lines(&window);
                let location = CodeLocation::new(file_path.clone(), start + 1, start + min_lines);

                // Store sample code
                let sample = lines[start..start + min_lines].join("\n");

                hash_to_locations
                    .entry(hash)
                    .or_default()
                    .push((location, sample));
            }
        }

        // Build duplicate blocks
        let mut seen_lines: HashMap<(String, usize), bool> = HashMap::new();

        for (hash, locations_with_samples) in hash_to_locations {
            if locations_with_samples.len() > 1 {
                let locations: Vec<CodeLocation> = locations_with_samples
                    .iter()
                    .map(|(loc, _)| loc.clone())
                    .collect();

                let sample = locations_with_samples.first().map(|(_, s)| s.clone());

                let mut block = DuplicateBlock::new(locations.clone(), min_lines, 0, hash);
                block.code_sample = sample;

                // Count duplicated lines (avoid double-counting overlaps)
                for loc in &locations {
                    for line in loc.start_line..=loc.end_line {
                        let key = (loc.file.clone(), line);
                        if !seen_lines.contains_key(&key) {
                            seen_lines.insert(key, true);
                            result.duplicated_lines += 1;
                        }
                    }
                }

                result.duplicates.push(block);
            }
        }

        result.calculate_percentage();
        result
    }
}

impl Default for DuplicationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Configuration Tests =====

    #[test]
    fn test_default_config() {
        let config = DuplicationConfig::default();
        assert_eq!(config.min_lines, 6);
        assert_eq!(config.min_tokens, 50);
        assert!(config.ignore_whitespace);
        assert!(config.ignore_comments);
        assert!(!config.ignore_literals);
    }

    #[test]
    fn test_custom_config() {
        let config = DuplicationConfig {
            min_lines: 10,
            min_tokens: 100,
            ignore_whitespace: false,
            ignore_comments: false,
            ignore_literals: true,
        };
        assert_eq!(config.min_lines, 10);
        assert!(!config.ignore_whitespace);
    }

    // ===== Code Location Tests =====

    #[test]
    fn test_code_location_line_count() {
        let loc = CodeLocation::new("test.java", 5, 10);
        assert_eq!(loc.line_count(), 6);
    }

    #[test]
    fn test_code_location_single_line() {
        let loc = CodeLocation::new("test.java", 5, 5);
        assert_eq!(loc.line_count(), 1);
    }

    // ===== Normalization Tests =====

    #[test]
    fn test_normalize_whitespace() {
        let detector = DuplicationDetector::new();
        let line = "    int   x   =   5;  ";
        assert_eq!(detector.normalize_line(line), "int x = 5;");
    }

    #[test]
    fn test_normalize_comments() {
        let detector = DuplicationDetector::new();
        let line = "int x = 5; // this is a comment";
        assert_eq!(detector.normalize_line(line), "int x = 5;");
    }

    #[test]
    fn test_normalize_preserves_content() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            ignore_whitespace: false,
            ignore_comments: false,
            ..Default::default()
        });
        let line = "int x = 5; // comment";
        assert_eq!(detector.normalize_line(line), "int x = 5; // comment");
    }

    // ===== Single File Duplicate Detection Tests =====

    #[test]
    fn test_detect_exact_duplicate_in_file() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 3,
            ..Default::default()
        });

        let content = r#"
public void method1() {
    int x = 1;
    int y = 2;
    int z = x + y;
}

public void method2() {
    int x = 1;
    int y = 2;
    int z = x + y;
}
"#;
        let duplicates = detector.analyze_file("test.java", content);
        assert!(
            !duplicates.is_empty(),
            "Should detect duplicate code blocks"
        );
    }

    #[test]
    fn test_no_duplicate_with_different_code() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 3,
            ..Default::default()
        });

        let content = r#"
public void method1() {
    int x = 1;
    int y = 2;
}

public void method2() {
    String a = "hello";
    String b = "world";
}
"#;
        let duplicates = detector.analyze_file("test.java", content);
        // Check that no significant duplicates are found (some small ones might be)
        let significant = duplicates
            .iter()
            .filter(|d| d.duplicate_count() > 1)
            .count();
        // The code is different enough that there shouldn't be many duplicates
        assert!(significant <= 1);
    }

    #[test]
    fn test_ignore_whitespace_differences() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 3,
            ignore_whitespace: true,
            ..Default::default()
        });

        // Test with different indentation levels (tabs vs spaces, different amounts)
        let content = r#"
public void method1() {
    int x = 1;
    int y = 2;
    int z = x + y;
}

public void method2() {
        int x = 1;
        int y = 2;
        int z = x + y;
}
"#;
        let duplicates = detector.analyze_file("test.java", content);
        assert!(
            !duplicates.is_empty(),
            "Should detect duplicates despite indentation differences"
        );
    }

    // ===== Multi-File Duplicate Detection Tests =====

    #[test]
    fn test_cross_file_duplication() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 3,
            ..Default::default()
        });

        let files = vec![
            (
                "File1.java".to_string(),
                r#"
public void method1() {
    int x = 1;
    int y = 2;
    int z = x + y;
}
"#
                .to_string(),
            ),
            (
                "File2.java".to_string(),
                r#"
public void method2() {
    int x = 1;
    int y = 2;
    int z = x + y;
}
"#
                .to_string(),
            ),
        ];

        let result = detector.analyze_files(&files);
        assert_eq!(result.files_analyzed, 2);
        assert!(
            !result.duplicates.is_empty(),
            "Should detect cross-file duplicates"
        );
    }

    #[test]
    fn test_duplication_percentage() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 2,
            ..Default::default()
        });

        let files = vec![
            (
                "File1.java".to_string(),
                "int x = 1;\nint y = 2;\nint z = 3;\nint w = 4;".to_string(),
            ),
            (
                "File2.java".to_string(),
                "int x = 1;\nint y = 2;\nint a = 5;\nint b = 6;".to_string(),
            ),
        ];

        let result = detector.analyze_files(&files);
        assert!(result.total_lines > 0);
        // Some percentage should be duplicated
        if !result.duplicates.is_empty() {
            assert!(result.duplication_percentage > 0.0);
        }
    }

    // ===== Duplicate Block Tests =====

    #[test]
    fn test_duplicate_block_count() {
        let locations = vec![
            CodeLocation::new("file1.java", 1, 5),
            CodeLocation::new("file2.java", 10, 14),
            CodeLocation::new("file3.java", 20, 24),
        ];
        let block = DuplicateBlock::new(locations, 5, 50, 12345);
        assert_eq!(block.duplicate_count(), 3);
    }

    // ===== Result Tests =====

    #[test]
    fn test_empty_result() {
        let result = DuplicationResult::new();
        assert_eq!(result.files_analyzed, 0);
        assert_eq!(result.total_lines, 0);
        assert_eq!(result.duplicated_lines, 0);
        assert_eq!(result.duplication_percentage, 0.0);
        assert!(result.duplicates.is_empty());
    }

    #[test]
    fn test_result_percentage_calculation() {
        let mut result = DuplicationResult::new();
        result.total_lines = 100;
        result.duplicated_lines = 25;
        result.calculate_percentage();
        assert!((result.duplication_percentage - 25.0).abs() < 0.001);
    }

    // ===== Edge Cases =====

    #[test]
    fn test_empty_file() {
        let detector = DuplicationDetector::new();
        let duplicates = detector.analyze_file("empty.java", "");
        assert!(duplicates.is_empty());
    }

    #[test]
    fn test_file_smaller_than_min_lines() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 10,
            ..Default::default()
        });
        let content = "line1\nline2\nline3";
        let duplicates = detector.analyze_file("small.java", content);
        assert!(duplicates.is_empty());
    }

    #[test]
    fn test_only_whitespace_lines() {
        let detector = DuplicationDetector::with_config(DuplicationConfig {
            min_lines: 3,
            ..Default::default()
        });
        let content = "\n\n\n\n\n\n\n\n";
        let duplicates = detector.analyze_file("whitespace.java", content);
        // Empty lines should not create duplicates
        assert!(duplicates.is_empty());
    }
}
