//! Builds a Control Flow Graph from a tree-sitter AST

use super::{BlockId, Condition, ControlFlowGraph, Expression, Statement, Terminator};
use tree_sitter::Node;

/// Builds a CFG from a method's AST
pub struct CfgBuilder<'a> {
    source: &'a str,
    cfg: ControlFlowGraph,
    current_block: BlockId,
}

impl<'a> CfgBuilder<'a> {
    /// Create a new CFG builder
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            cfg: ControlFlowGraph::new(),
            current_block: 0,
        }
    }

    /// Build CFG for a method body
    pub fn build_method(mut self, method_node: Node<'a>) -> ControlFlowGraph {
        // Extract parameters
        if let Some(params) = method_node.child_by_field_name("parameters") {
            self.extract_parameters(params);
        }

        // Process method body
        if let Some(body) = method_node.child_by_field_name("body") {
            self.process_block(body);
        }

        // Connect last block to exit if not already terminated
        let exit_block = self.cfg.exit;
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            if matches!(block.terminator, Terminator::Unreachable) {
                block.terminator = Terminator::Goto(exit_block);
            }
        }

        self.cfg
    }

    /// Extract parameter names from formal parameters
    fn extract_parameters(&mut self, params_node: Node<'a>) {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "formal_parameter" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = self.node_text(name_node);
                    self.cfg.parameters.push(name);
                }
            }
        }
    }

    /// Process a block (compound statement)
    fn process_block(&mut self, block_node: Node<'a>) {
        let mut cursor = block_node.walk();
        for child in block_node.children(&mut cursor) {
            self.process_statement(child);
        }
    }

    /// Process a single statement
    fn process_statement(&mut self, node: Node<'a>) {
        match node.kind() {
            "local_variable_declaration" => self.process_variable_declaration(node),
            "expression_statement" => self.process_expression_statement(node),
            "if_statement" => self.process_if_statement(node),
            "return_statement" => self.process_return_statement(node),
            "block" => self.process_block(node),
            "while_statement" => self.process_while_statement(node),
            "for_statement" => self.process_for_statement(node),
            "try_statement" => self.process_try_statement(node),
            _ => {}
        }
    }

    /// Process variable declaration
    fn process_variable_declaration(&mut self, node: Node<'a>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let var_name = self.node_text(name_node);
                    let line = name_node.start_position().row + 1;
                    let column = name_node.start_position().column + 1;

                    let expr = if let Some(value_node) = child.child_by_field_name("value") {
                        self.analyze_expression(value_node)
                    } else {
                        Expression::Unknown
                    };

                    let stmt = Statement::Assignment {
                        var: var_name,
                        expr,
                        line,
                        column,
                    };

                    self.add_statement(stmt);
                }
            }
        }
    }

    /// Process expression statement
    fn process_expression_statement(&mut self, node: Node<'a>) {
        if let Some(expr_node) = node.child(0) {
            match expr_node.kind() {
                "assignment_expression" => {
                    if let Some(left) = expr_node.child_by_field_name("left") {
                        if left.kind() == "identifier" {
                            let var_name = self.node_text(left);
                            let line = left.start_position().row + 1;
                            let column = left.start_position().column + 1;

                            let expr = if let Some(right) = expr_node.child_by_field_name("right") {
                                self.analyze_expression(right)
                            } else {
                                Expression::Unknown
                            };

                            let stmt = Statement::Assignment {
                                var: var_name,
                                expr,
                                line,
                                column,
                            };
                            self.add_statement(stmt);
                        }
                    }
                }
                "method_invocation" => {
                    self.process_method_invocation(expr_node);
                }
                _ => {}
            }
        }
    }

    /// Process method invocation (potential dereference)
    fn process_method_invocation(&mut self, node: Node<'a>) {
        let line = node.start_position().row + 1;
        let column = node.start_position().column + 1;

        let receiver = node.child_by_field_name("object").map(|n| self.node_text(n));
        let method = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n))
            .unwrap_or_default();

        let stmt = Statement::MethodCall {
            receiver,
            method,
            line,
            column,
        };
        self.add_statement(stmt);
    }

    /// Process if statement - creates branching CFG
    fn process_if_statement(&mut self, node: Node<'a>) {
        let condition = node
            .child_by_field_name("condition")
            .map(|n| self.analyze_condition(n))
            .unwrap_or(Condition::Other);

        // Create then and merge blocks
        let then_block = self.cfg.add_block();
        let merge_block = self.cfg.add_block();

        // Check for else branch
        let else_block = if node.child_by_field_name("alternative").is_some() {
            self.cfg.add_block()
        } else {
            merge_block
        };

        // Set branch terminator on current block
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            block.terminator = Terminator::Branch {
                condition,
                then_block,
                else_block,
            };
        }

        // Process then branch
        self.current_block = then_block;
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.process_statement(consequence);
        }
        // Connect to merge only if the then-block itself hasn't been terminated
        // (current_block may differ if return/throw created new blocks)
        if let Some(block) = self.cfg.get_block_mut(then_block) {
            if matches!(block.terminator, Terminator::Unreachable) {
                block.terminator = Terminator::Goto(merge_block);
            }
        }

        // Process else branch if exists
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.current_block = else_block;
            self.process_statement(alternative);
            if let Some(block) = self.cfg.get_block_mut(else_block) {
                if matches!(block.terminator, Terminator::Unreachable) {
                    block.terminator = Terminator::Goto(merge_block);
                }
            }
        }

        self.current_block = merge_block;
    }

    /// Process return statement
    fn process_return_statement(&mut self, _node: Node<'a>) {
        let exit_block = self.cfg.exit;
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            block.terminator = Terminator::Goto(exit_block);
        }
        // Create new unreachable block for any code after return
        self.current_block = self.cfg.add_block();
    }

    /// Process while statement
    fn process_while_statement(&mut self, node: Node<'a>) {
        let header_block = self.cfg.add_block();
        let body_block = self.cfg.add_block();
        let exit_block = self.cfg.add_block();

        // Connect current block to header
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            block.terminator = Terminator::Goto(header_block);
        }

        // Header: condition check
        self.current_block = header_block;
        let condition = node
            .child_by_field_name("condition")
            .map(|n| self.analyze_condition(n))
            .unwrap_or(Condition::Other);

        if let Some(block) = self.cfg.get_block_mut(header_block) {
            block.terminator = Terminator::Branch {
                condition,
                then_block: body_block,
                else_block: exit_block,
            };
        }

        // Process body
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(body);
        }
        // Loop back to header
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            if matches!(block.terminator, Terminator::Unreachable) {
                block.terminator = Terminator::Goto(header_block);
            }
        }

        self.current_block = exit_block;
    }

    /// Process for statement (simplified - treat like while)
    fn process_for_statement(&mut self, node: Node<'a>) {
        // Process init
        if let Some(init) = node.child_by_field_name("init") {
            self.process_statement(init);
        }

        let header_block = self.cfg.add_block();
        let body_block = self.cfg.add_block();
        let exit_block = self.cfg.add_block();

        // Connect to header
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            block.terminator = Terminator::Goto(header_block);
        }

        // Header with condition
        self.current_block = header_block;
        if let Some(block) = self.cfg.get_block_mut(header_block) {
            block.terminator = Terminator::Branch {
                condition: Condition::Other,
                then_block: body_block,
                else_block: exit_block,
            };
        }

        // Body
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(body);
        }
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            if matches!(block.terminator, Terminator::Unreachable) {
                block.terminator = Terminator::Goto(header_block);
            }
        }

        self.current_block = exit_block;
    }

    /// Process try statement (simplified)
    fn process_try_statement(&mut self, node: Node<'a>) {
        // Just process the body for now
        if let Some(body) = node.child_by_field_name("body") {
            self.process_block(body);
        }
    }

    /// Analyze an expression to determine its null state
    fn analyze_expression(&self, node: Node<'a>) -> Expression {
        match node.kind() {
            "null_literal" => Expression::Null,
            "string_literal" | "decimal_integer_literal" | "decimal_floating_point_literal"
            | "true" | "false" | "character_literal" => Expression::Literal,
            "object_creation_expression" => Expression::NewObject,
            "method_invocation" => Expression::MethodCall,
            "identifier" => Expression::Variable(self.node_text(node)),
            "ternary_expression" => {
                let then_expr = node
                    .child_by_field_name("consequence")
                    .map(|n| self.analyze_expression(n))
                    .unwrap_or(Expression::Unknown);
                let else_expr = node
                    .child_by_field_name("alternative")
                    .map(|n| self.analyze_expression(n))
                    .unwrap_or(Expression::Unknown);
                Expression::Ternary {
                    then_expr: Box::new(then_expr),
                    else_expr: Box::new(else_expr),
                }
            }
            "parenthesized_expression" => {
                if let Some(inner) = node.child(1) {
                    self.analyze_expression(inner)
                } else {
                    Expression::Unknown
                }
            }
            _ => Expression::Unknown,
        }
    }

    /// Analyze a condition for null checks
    fn analyze_condition(&self, node: Node<'a>) -> Condition {
        // Handle condition wrapper (tree-sitter-java) or parenthesized expression
        let node = if node.kind() == "condition" || node.kind() == "parenthesized_expression" {
            // Get the inner expression (skip parentheses)
            node.named_child(0).unwrap_or(node)
        } else {
            node
        };

        if node.kind() == "binary_expression" {
            let operator = node
                .child_by_field_name("operator")
                .map(|n| self.node_text(n))
                .unwrap_or_default();

            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");

            match (left, right, operator.as_str()) {
                (Some(l), Some(r), "==") => {
                    if r.kind() == "null_literal" && l.kind() == "identifier" {
                        return Condition::IsNull(self.node_text(l));
                    }
                    if l.kind() == "null_literal" && r.kind() == "identifier" {
                        return Condition::IsNull(self.node_text(r));
                    }
                }
                (Some(l), Some(r), "!=") => {
                    if r.kind() == "null_literal" && l.kind() == "identifier" {
                        return Condition::IsNotNull(self.node_text(l));
                    }
                    if l.kind() == "null_literal" && r.kind() == "identifier" {
                        return Condition::IsNotNull(self.node_text(r));
                    }
                }
                _ => {}
            }
        }

        Condition::Other
    }

    /// Add a statement to the current block
    fn add_statement(&mut self, stmt: Statement) {
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            block.statements.push(stmt);
        }
    }

    /// Get text for a node
    fn node_text(&self, node: Node<'a>) -> String {
        node.utf8_text(self.source.as_bytes())
            .unwrap_or("")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_get_method(source: &str) -> (tree_sitter::Tree, String) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        (tree, source.to_string())
    }

    fn find_method<'a>(node: Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "method_declaration" {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(method) = find_method(child) {
                return Some(method);
            }
        }
        None
    }

    #[test]
    fn test_build_simple_method() {
        let source = r#"
            class Test {
                void foo() {
                    String s = null;
                }
            }
        "#;
        let (tree, src) = parse_and_get_method(source);
        let method = find_method(tree.root_node()).unwrap();

        let cfg = CfgBuilder::new(&src).build_method(method);

        assert!(cfg.blocks.len() >= 2); // entry + exit at minimum
        // Should have an assignment statement
        let entry = cfg.get_block(cfg.entry).unwrap();
        assert!(!entry.statements.is_empty() || cfg.blocks.len() > 2);
    }

    #[test]
    fn test_build_if_statement() {
        let source = r#"
            class Test {
                void foo(String s) {
                    if (s != null) {
                        s.length();
                    }
                }
            }
        "#;
        let (tree, src) = parse_and_get_method(source);
        let method = find_method(tree.root_node()).unwrap();

        let cfg = CfgBuilder::new(&src).build_method(method);

        // Should have multiple blocks due to branching
        assert!(cfg.blocks.len() >= 4); // entry, then, merge, exit
    }

    #[test]
    fn test_extract_parameters() {
        let source = r#"
            class Test {
                void foo(String a, int b) {
                }
            }
        "#;
        let (tree, src) = parse_and_get_method(source);
        let method = find_method(tree.root_node()).unwrap();

        let cfg = CfgBuilder::new(&src).build_method(method);

        assert_eq!(cfg.parameters.len(), 2);
        assert!(cfg.parameters.contains(&"a".to_string()));
        assert!(cfg.parameters.contains(&"b".to_string()));
    }

    #[test]
    fn test_null_check_condition() {
        let source = r#"
            class Test {
                void foo(String s) {
                    if (s == null) {
                        return;
                    }
                }
            }
        "#;
        let (tree, src) = parse_and_get_method(source);
        let method = find_method(tree.root_node()).unwrap();

        let cfg = CfgBuilder::new(&src).build_method(method);

        // Find a branch with IsNull condition
        let has_null_check = cfg.blocks.values().any(|block| {
            matches!(
                &block.terminator,
                Terminator::Branch { condition: Condition::IsNull(_), .. }
            )
        });
        assert!(has_null_check, "Should detect null check condition");
    }
}
