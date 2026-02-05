//! Java parsing utilities
//!
//! Helper functions for working with tree-sitter parsed Java AST.

use once_cell::sync::Lazy;
use regex::Regex;
use tree_sitter::{Node, Tree};

/// Get Java parser
pub fn get_parser() -> tree_sitter::Parser {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_java::language())
        .expect("Failed to load Java grammar");
    parser
}

/// Parse Java source code
pub fn parse_java(source: &str) -> Option<Tree> {
    let mut parser = get_parser();
    parser.parse(source, None)
}

/// Helper trait for Node traversal
pub trait NodeExt<'a> {
    /// Get the text content of this node
    fn text<'b>(&self, source: &'b str) -> &'b str;

    /// Find first child by kind
    fn find_child(&self, kind: &str) -> Option<Node<'a>>;

    /// Find all children by kind
    fn find_children(&self, kind: &str) -> Vec<Node<'a>>;

    /// Find all descendants by kind (recursive)
    fn find_descendants(&self, kind: &str) -> Vec<Node<'a>>;

    /// Check if node has a child of given kind
    fn has_child(&self, kind: &str) -> bool;

    /// Get parent node
    fn get_parent(&self) -> Option<Node<'a>>;

    /// Get line number (1-indexed)
    fn line(&self) -> usize;

    /// Get column number (1-indexed)
    fn column(&self) -> usize;
}

impl<'a> NodeExt<'a> for Node<'a> {
    fn text<'b>(&self, source: &'b str) -> &'b str {
        &source[self.start_byte()..self.end_byte()]
    }

    fn find_child(&self, kind: &str) -> Option<Node<'a>> {
        let mut cursor = self.walk();
        for child in self.children(&mut cursor) {
            if child.kind() == kind {
                return Some(child);
            }
        }
        None
    }

    fn find_children(&self, kind: &str) -> Vec<Node<'a>> {
        let mut cursor = self.walk();
        self.children(&mut cursor)
            .filter(|c| c.kind() == kind)
            .collect()
    }

    fn find_descendants(&self, kind: &str) -> Vec<Node<'a>> {
        let mut results = Vec::new();
        let mut stack = vec![*self];

        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                results.push(node);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push(child);
            }
        }
        results
    }

    fn has_child(&self, kind: &str) -> bool {
        self.find_child(kind).is_some()
    }

    fn get_parent(&self) -> Option<Node<'a>> {
        self.parent()
    }

    fn line(&self) -> usize {
        self.start_position().row + 1
    }

    fn column(&self) -> usize {
        self.start_position().column + 1
    }
}

/// Java AST node kinds
pub mod kinds {
    pub const PROGRAM: &str = "program";
    pub const CLASS_DECLARATION: &str = "class_declaration";
    pub const INTERFACE_DECLARATION: &str = "interface_declaration";
    pub const ENUM_DECLARATION: &str = "enum_declaration";
    pub const METHOD_DECLARATION: &str = "method_declaration";
    pub const CONSTRUCTOR_DECLARATION: &str = "constructor_declaration";
    pub const FIELD_DECLARATION: &str = "field_declaration";
    pub const LOCAL_VARIABLE_DECLARATION: &str = "local_variable_declaration";
    pub const FORMAL_PARAMETER: &str = "formal_parameter";
    pub const IF_STATEMENT: &str = "if_statement";
    pub const FOR_STATEMENT: &str = "for_statement";
    pub const ENHANCED_FOR_STATEMENT: &str = "enhanced_for_statement";
    pub const WHILE_STATEMENT: &str = "while_statement";
    pub const DO_STATEMENT: &str = "do_statement";
    pub const SWITCH_EXPRESSION: &str = "switch_expression";
    pub const TRY_STATEMENT: &str = "try_statement";
    pub const CATCH_CLAUSE: &str = "catch_clause";
    pub const FINALLY_CLAUSE: &str = "finally_clause";
    pub const THROW_STATEMENT: &str = "throw_statement";
    pub const RETURN_STATEMENT: &str = "return_statement";
    pub const BLOCK: &str = "block";
    pub const EXPRESSION_STATEMENT: &str = "expression_statement";
    pub const METHOD_INVOCATION: &str = "method_invocation";
    pub const OBJECT_CREATION_EXPRESSION: &str = "object_creation_expression";
    pub const ASSIGNMENT_EXPRESSION: &str = "assignment_expression";
    pub const BINARY_EXPRESSION: &str = "binary_expression";
    pub const UNARY_EXPRESSION: &str = "unary_expression";
    pub const TERNARY_EXPRESSION: &str = "ternary_expression";
    pub const IDENTIFIER: &str = "identifier";
    pub const STRING_LITERAL: &str = "string_literal";
    pub const NUMBER_LITERAL: &str = "decimal_integer_literal";
    pub const MODIFIERS: &str = "modifiers";
    pub const ANNOTATION: &str = "annotation";
    pub const MARKER_ANNOTATION: &str = "marker_annotation";
    pub const IMPORT_DECLARATION: &str = "import_declaration";
    pub const PACKAGE_DECLARATION: &str = "package_declaration";
}

/// Extract class information from AST
pub fn extract_class_info<'a>(node: Node<'a>, source: &str) -> Option<ClassInfo> {
    if node.kind() != kinds::CLASS_DECLARATION {
        return None;
    }

    let name = node
        .find_child(kinds::IDENTIFIER)
        .map(|n| n.text(source).to_string())?;

    let modifiers = node
        .find_child(kinds::MODIFIERS)
        .map(|n| extract_modifiers(n, source))
        .unwrap_or_default();

    let methods: Vec<MethodInfo> = node
        .find_descendants(kinds::METHOD_DECLARATION)
        .iter()
        .filter_map(|m| extract_method_info(*m, source))
        .collect();

    let fields: Vec<FieldInfo> = node
        .find_descendants(kinds::FIELD_DECLARATION)
        .iter()
        .filter_map(|f| extract_field_info(*f, source))
        .collect();

    Some(ClassInfo {
        name,
        modifiers,
        methods,
        fields,
        line: node.line(),
    })
}

/// Extract method information from AST
pub fn extract_method_info<'a>(node: Node<'a>, source: &str) -> Option<MethodInfo> {
    if node.kind() != kinds::METHOD_DECLARATION {
        return None;
    }

    let name = node
        .find_child(kinds::IDENTIFIER)
        .map(|n| n.text(source).to_string())?;

    let modifiers = node
        .find_child(kinds::MODIFIERS)
        .map(|n| extract_modifiers(n, source))
        .unwrap_or_default();

    let parameters: Vec<String> = node
        .find_descendants(kinds::FORMAL_PARAMETER)
        .iter()
        .filter_map(|p| {
            p.find_child(kinds::IDENTIFIER)
                .map(|i| i.text(source).to_string())
        })
        .collect();

    Some(MethodInfo {
        name,
        modifiers,
        parameters,
        line: node.line(),
    })
}

/// Extract field information from AST
pub fn extract_field_info<'a>(node: Node<'a>, source: &str) -> Option<FieldInfo> {
    if node.kind() != kinds::FIELD_DECLARATION {
        return None;
    }

    let modifiers = node
        .find_child(kinds::MODIFIERS)
        .map(|n| extract_modifiers(n, source))
        .unwrap_or_default();

    // Get variable declarator
    let name = node
        .find_descendants(kinds::IDENTIFIER)
        .first()
        .map(|n| n.text(source).to_string())?;

    Some(FieldInfo {
        name,
        modifiers,
        line: node.line(),
    })
}

/// Extract modifiers from a modifiers node
fn extract_modifiers<'a>(node: Node<'a>, source: &str) -> Vec<String> {
    let text = node.text(source);
    let mut modifiers = Vec::new();

    for modifier in &[
        "public",
        "private",
        "protected",
        "static",
        "final",
        "abstract",
        "synchronized",
        "volatile",
        "transient",
        "native",
    ] {
        if text.contains(modifier) {
            modifiers.push(modifier.to_string());
        }
    }

    modifiers
}

/// Information about a Java class
#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub name: String,
    pub modifiers: Vec<String>,
    pub methods: Vec<MethodInfo>,
    pub fields: Vec<FieldInfo>,
    pub line: usize,
}

/// Information about a Java method
#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub name: String,
    pub modifiers: Vec<String>,
    pub parameters: Vec<String>,
    pub line: usize,
}

/// Information about a Java field
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub modifiers: Vec<String>,
    pub line: usize,
}

/// Get the enclosing method for a node
pub fn get_enclosing_method<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut current = Some(node);
    while let Some(n) = current {
        if n.kind() == kinds::METHOD_DECLARATION || n.kind() == kinds::CONSTRUCTOR_DECLARATION {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// Get the enclosing class for a node
pub fn get_enclosing_class<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut current = Some(node);
    while let Some(n) = current {
        if n.kind() == kinds::CLASS_DECLARATION {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// Check if a node is inside a method body
pub fn is_in_method_body<'a>(node: Node<'a>) -> bool {
    get_enclosing_method(node).is_some()
}

/// Calculate simple metrics for Java source
pub fn calculate_metrics(source: &str) -> SourceMetrics {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len();

    let code_lines = lines
        .iter()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("/*")
                && !trimmed.starts_with("*")
        })
        .count();

    let comment_lines = lines
        .iter()
        .filter(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*")
        })
        .count();

    let blank_lines = lines.iter().filter(|l| l.trim().is_empty()).count();

    // Count classes (simplified)
    let class_count = Regex::new(r"\bclass\s+\w+")
        .unwrap()
        .find_iter(source)
        .count();

    // Count methods (simplified)
    let method_count =
        Regex::new(r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+)\s+\w+\s*\([^)]*\)\s*\{")
            .unwrap()
            .find_iter(source)
            .count();

    SourceMetrics {
        total_lines,
        code_lines,
        comment_lines,
        blank_lines,
        class_count,
        method_count,
    }
}

/// Source code metrics
#[derive(Debug, Clone)]
pub struct SourceMetrics {
    pub total_lines: usize,
    pub code_lines: usize,
    pub comment_lines: usize,
    pub blank_lines: usize,
    pub class_count: usize,
    pub method_count: usize,
}

/// Extract all string literals from source
pub fn extract_string_literals(source: &str) -> Vec<(usize, String)> {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"\\]|\\.)*""#).unwrap());

    let mut results = Vec::new();
    for (line_num, line) in source.lines().enumerate() {
        for m in RE.find_iter(line) {
            results.push((line_num + 1, m.as_str().to_string()));
        }
    }
    results
}

/// Extract all imports from source
pub fn extract_imports(source: &str) -> Vec<String> {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"import\s+([\w.]+(?:\.\*)?)\s*;").unwrap());

    RE.captures_iter(source)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Check if source uses a specific class/package
pub fn uses_import(source: &str, pattern: &str) -> bool {
    let imports = extract_imports(source);
    imports.iter().any(|i| i.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_java() {
        let source = r#"
            public class Test {
                public void hello() {
                    System.out.println("Hello");
                }
            }
        "#;

        let tree = parse_java(source);
        assert!(tree.is_some());

        let tree = tree.unwrap();
        let root = tree.root_node();
        assert_eq!(root.kind(), kinds::PROGRAM);
    }

    #[test]
    fn test_extract_class_info() {
        let source = r#"
            public class MyClass {
                private int count;
                public void doSomething(String arg) {}
            }
        "#;

        let tree = parse_java(source).unwrap();
        let root = tree.root_node();

        let class_node = root
            .find_descendants(kinds::CLASS_DECLARATION)
            .into_iter()
            .next()
            .unwrap();

        let info = extract_class_info(class_node, source).unwrap();
        assert_eq!(info.name, "MyClass");
        assert!(info.modifiers.contains(&"public".to_string()));
        assert_eq!(info.methods.len(), 1);
        assert_eq!(info.fields.len(), 1);
    }

    #[test]
    fn test_calculate_metrics() {
        let source = r#"
            // Comment
            public class Test {
                private int x;

                public void test() {
                    // inline comment
                    doSomething();
                }
            }
        "#;

        let metrics = calculate_metrics(source);
        assert!(metrics.total_lines > 0);
        assert!(metrics.code_lines > 0);
        assert!(metrics.comment_lines > 0);
        assert!(metrics.blank_lines > 0);
        assert_eq!(metrics.class_count, 1);
    }

    #[test]
    fn test_extract_string_literals() {
        let source = r#"
            String a = "hello";
            String b = "world";
        "#;

        let literals = extract_string_literals(source);
        assert_eq!(literals.len(), 2);
    }

    #[test]
    fn test_extract_imports() {
        let source = r#"
            import java.util.List;
            import java.util.*;
            import com.example.MyClass;
        "#;

        let imports = extract_imports(source);
        assert_eq!(imports.len(), 3);
        assert!(imports.contains(&"java.util.List".to_string()));
        assert!(imports.contains(&"java.util.*".to_string()));
    }
}
