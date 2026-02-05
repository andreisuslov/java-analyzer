//! Auto-fix Suggestions
//!
//! Provides code fixes for common issues, starting with naming convention violations.

use serde::{Deserialize, Serialize};

/// A suggested fix for an issue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fix {
    /// Human-readable description of the fix
    pub message: String,
    /// The edits to apply
    pub edits: Vec<TextEdit>,
}

impl Fix {
    /// Create a new fix with a message
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            edits: Vec::new(),
        }
    }

    /// Add an edit to the fix
    pub fn with_edit(mut self, edit: TextEdit) -> Self {
        self.edits.push(edit);
        self
    }

    /// Add multiple edits to the fix
    pub fn with_edits(mut self, edits: Vec<TextEdit>) -> Self {
        self.edits.extend(edits);
        self
    }
}

/// A single text edit (replacement)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TextEdit {
    /// Start line (1-indexed)
    pub start_line: usize,
    /// Start column (1-indexed)
    pub start_column: usize,
    /// End line (1-indexed)
    pub end_line: usize,
    /// End column (1-indexed)
    pub end_column: usize,
    /// Text to replace with
    pub replacement: String,
}

impl TextEdit {
    /// Create a new text edit
    pub fn new(
        start_line: usize,
        start_column: usize,
        end_line: usize,
        end_column: usize,
        replacement: impl Into<String>,
    ) -> Self {
        Self {
            start_line,
            start_column,
            end_line,
            end_column,
            replacement: replacement.into(),
        }
    }

    /// Create a single-line replacement
    pub fn replace_range(line: usize, start_col: usize, end_col: usize, replacement: impl Into<String>) -> Self {
        Self::new(line, start_col, line, end_col, replacement)
    }
}

/// Convert a string to camelCase (first letter lowercase)
///
/// Examples:
/// - "BadMethod" -> "badMethod"
/// - "UPPER_CASE" -> "upperCase"
/// - "already_camel" -> "alreadyCamel"
pub fn to_camel_case(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    // Handle UPPER_SNAKE_CASE
    if s.contains('_') {
        let parts: Vec<&str> = s.split('_').collect();
        let mut result = String::new();
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if i == 0 {
                result.push_str(&part.to_lowercase());
            } else {
                // Capitalize first letter, lowercase rest
                let mut chars = part.chars();
                if let Some(first) = chars.next() {
                    result.push(first.to_ascii_uppercase());
                    result.push_str(&chars.as_str().to_lowercase());
                }
            }
        }
        return result;
    }

    // Handle PascalCase -> camelCase
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    let rest: String = chars.collect();

    format!("{}{}", first.to_ascii_lowercase(), rest)
}

/// Convert a string to PascalCase (first letter uppercase)
///
/// Examples:
/// - "badMethod" -> "BadMethod"
/// - "lower_snake" -> "LowerSnake"
/// - "already" -> "Already"
pub fn to_pascal_case(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    // Handle snake_case
    if s.contains('_') {
        let parts: Vec<&str> = s.split('_').collect();
        let mut result = String::new();
        for part in parts {
            if part.is_empty() {
                continue;
            }
            // Capitalize first letter, lowercase rest
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                result.push(first.to_ascii_uppercase());
                result.push_str(&chars.as_str().to_lowercase());
            }
        }
        return result;
    }

    // Handle camelCase -> PascalCase
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    let rest: String = chars.collect();

    format!("{}{}", first.to_ascii_uppercase(), rest)
}

/// Convert a string to UPPER_SNAKE_CASE
///
/// Examples:
/// - "maxValue" -> "MAX_VALUE"
/// - "someConstant" -> "SOME_CONSTANT"
/// - "APIKey" -> "API_KEY"
pub fn to_upper_snake_case(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    // Already UPPER_SNAKE_CASE?
    if s.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()) {
        return s.to_string();
    }

    let mut result = String::new();
    let mut prev_lower = false;

    for (i, c) in s.chars().enumerate() {
        if c == '_' {
            result.push('_');
            prev_lower = false;
        } else if c.is_ascii_uppercase() {
            // Add underscore before uppercase if:
            // 1. Not at start
            // 2. Previous char was lowercase
            // 3. Or next char is lowercase (handles "APIKey" -> "API_KEY")
            if i > 0 && prev_lower {
                result.push('_');
            }
            result.push(c);
            prev_lower = false;
        } else {
            result.push(c.to_ascii_uppercase());
            prev_lower = true;
        }
    }

    result
}

/// Apply a fix to source code and return the modified source
pub fn apply_fix(source: &str, fix: &Fix) -> String {
    let mut result = source.to_string();

    // Sort edits by position (reverse order to preserve positions)
    let mut edits = fix.edits.clone();
    edits.sort_by(|a, b| {
        if a.start_line != b.start_line {
            b.start_line.cmp(&a.start_line)
        } else {
            b.start_column.cmp(&a.start_column)
        }
    });

    for edit in edits {
        result = apply_single_edit(&result, &edit);
    }

    result
}

fn apply_single_edit(source: &str, edit: &TextEdit) -> String {
    let lines: Vec<&str> = source.lines().collect();

    if edit.start_line == 0 || edit.start_line > lines.len() {
        return source.to_string();
    }

    let start_line_idx = edit.start_line - 1;
    let end_line_idx = edit.end_line - 1;

    if edit.start_line == edit.end_line {
        // Single line edit
        let line = lines[start_line_idx];
        let start_col = edit.start_column.saturating_sub(1);
        let end_col = edit.end_column.saturating_sub(1).min(line.len());

        let new_line = format!(
            "{}{}{}",
            &line[..start_col.min(line.len())],
            &edit.replacement,
            &line[end_col..]
        );

        let mut new_lines = lines.clone();
        new_lines[start_line_idx] = Box::leak(new_line.into_boxed_str());
        new_lines.join("\n")
    } else {
        // Multi-line edit
        let start_line = lines[start_line_idx];
        let end_line = lines[end_line_idx];

        let start_col = edit.start_column.saturating_sub(1);
        let end_col = edit.end_column.saturating_sub(1).min(end_line.len());

        let new_content = format!(
            "{}{}{}",
            &start_line[..start_col.min(start_line.len())],
            &edit.replacement,
            &end_line[end_col..]
        );

        let mut new_lines = Vec::new();
        new_lines.extend_from_slice(&lines[..start_line_idx]);
        new_lines.push(Box::leak(new_content.into_boxed_str()));
        new_lines.extend_from_slice(&lines[(end_line_idx + 1)..]);
        new_lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Case Conversion Tests =====

    #[test]
    fn test_to_camel_case_from_pascal() {
        assert_eq!(to_camel_case("BadMethod"), "badMethod");
        assert_eq!(to_camel_case("CalculateTotal"), "calculateTotal");
        assert_eq!(to_camel_case("X"), "x");
    }

    #[test]
    fn test_to_camel_case_from_upper_snake() {
        assert_eq!(to_camel_case("UPPER_CASE"), "upperCase");
        assert_eq!(to_camel_case("MAX_VALUE"), "maxValue");
        assert_eq!(to_camel_case("API_KEY_VALUE"), "apiKeyValue");
    }

    #[test]
    fn test_to_camel_case_already_camel() {
        assert_eq!(to_camel_case("alreadyCamel"), "alreadyCamel");
        assert_eq!(to_camel_case("x"), "x");
    }

    #[test]
    fn test_to_camel_case_empty() {
        assert_eq!(to_camel_case(""), "");
    }

    #[test]
    fn test_to_pascal_case_from_camel() {
        assert_eq!(to_pascal_case("badMethod"), "BadMethod");
        assert_eq!(to_pascal_case("calculateTotal"), "CalculateTotal");
    }

    #[test]
    fn test_to_pascal_case_from_snake() {
        assert_eq!(to_pascal_case("lower_snake"), "LowerSnake");
        assert_eq!(to_pascal_case("my_class_name"), "MyClassName");
    }

    #[test]
    fn test_to_pascal_case_already_pascal() {
        assert_eq!(to_pascal_case("AlreadyPascal"), "AlreadyPascal");
    }

    #[test]
    fn test_to_pascal_case_empty() {
        assert_eq!(to_pascal_case(""), "");
    }

    #[test]
    fn test_to_upper_snake_case_from_camel() {
        assert_eq!(to_upper_snake_case("maxValue"), "MAX_VALUE");
        assert_eq!(to_upper_snake_case("someConstant"), "SOME_CONSTANT");
        assert_eq!(to_upper_snake_case("apiKey"), "API_KEY");
    }

    #[test]
    fn test_to_upper_snake_case_from_pascal() {
        assert_eq!(to_upper_snake_case("MaxValue"), "MAX_VALUE");
        assert_eq!(to_upper_snake_case("SomeConstant"), "SOME_CONSTANT");
    }

    #[test]
    fn test_to_upper_snake_case_already_upper() {
        assert_eq!(to_upper_snake_case("ALREADY_UPPER"), "ALREADY_UPPER");
        assert_eq!(to_upper_snake_case("MAX"), "MAX");
    }

    #[test]
    fn test_to_upper_snake_case_empty() {
        assert_eq!(to_upper_snake_case(""), "");
    }

    // ===== Fix Creation Tests =====

    #[test]
    fn test_fix_creation() {
        let fix = Fix::new("Rename to camelCase")
            .with_edit(TextEdit::new(1, 10, 1, 20, "newName"));

        assert_eq!(fix.message, "Rename to camelCase");
        assert_eq!(fix.edits.len(), 1);
        assert_eq!(fix.edits[0].replacement, "newName");
    }

    #[test]
    fn test_text_edit_replace_range() {
        let edit = TextEdit::replace_range(5, 10, 15, "replacement");

        assert_eq!(edit.start_line, 5);
        assert_eq!(edit.start_column, 10);
        assert_eq!(edit.end_line, 5);
        assert_eq!(edit.end_column, 15);
        assert_eq!(edit.replacement, "replacement");
    }

    // ===== Apply Fix Tests =====

    #[test]
    fn test_apply_fix_single_line() {
        let source = "public void BadMethod() {}";
        let fix = Fix::new("Rename")
            .with_edit(TextEdit::new(1, 13, 1, 22, "badMethod"));

        let result = apply_fix(source, &fix);
        assert_eq!(result, "public void badMethod() {}");
    }

    #[test]
    fn test_apply_fix_multiple_edits() {
        let source = "int X = Y;";
        let fix = Fix::new("Rename variables")
            .with_edit(TextEdit::new(1, 5, 1, 6, "x"))
            .with_edit(TextEdit::new(1, 9, 1, 10, "y"));

        let result = apply_fix(source, &fix);
        assert_eq!(result, "int x = y;");
    }

    #[test]
    fn test_apply_fix_preserves_other_lines() {
        let source = "line1\npublic void BadMethod() {}\nline3";
        let fix = Fix::new("Rename")
            .with_edit(TextEdit::new(2, 13, 2, 22, "badMethod"));

        let result = apply_fix(source, &fix);
        assert_eq!(result, "line1\npublic void badMethod() {}\nline3");
    }

    #[test]
    fn test_apply_fix_at_line_start() {
        let source = "BadClass {}";
        let fix = Fix::new("Rename")
            .with_edit(TextEdit::new(1, 1, 1, 9, "GoodClass"));

        let result = apply_fix(source, &fix);
        assert_eq!(result, "GoodClass {}");
    }

    #[test]
    fn test_apply_fix_at_line_end() {
        let source = "class Test";
        let fix = Fix::new("Rename")
            .with_edit(TextEdit::new(1, 7, 1, 11, "Example"));

        let result = apply_fix(source, &fix);
        assert_eq!(result, "class Example");
    }

    // ===== Edge Cases =====

    #[test]
    fn test_apply_fix_empty_replacement() {
        let source = "int unused = 0;";
        let fix = Fix::new("Remove")
            .with_edit(TextEdit::new(1, 5, 1, 12, ""));

        let result = apply_fix(source, &fix);
        // Columns 5-12 is "unused " (including space), removal gives "int = 0;"
        assert_eq!(result, "int = 0;");
    }

    #[test]
    fn test_apply_fix_no_edits() {
        let source = "unchanged";
        let fix = Fix::new("No changes");

        let result = apply_fix(source, &fix);
        assert_eq!(result, "unchanged");
    }
}
