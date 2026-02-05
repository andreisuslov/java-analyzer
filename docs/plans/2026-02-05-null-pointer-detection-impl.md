# Null Pointer Detection (S2259) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect potential NullPointerException via intra-method control-flow-sensitive data flow analysis.

**Architecture:** Build a Control Flow Graph (CFG) for each method, then run forward dataflow analysis tracking null states (Null, NonNull, MaybeNull) through branches. Report issues at dereference points where state is Null or MaybeNull.

**Tech Stack:** Rust, tree-sitter-java for AST, standard library HashMap for state tracking.

---

## Task 1: Create dataflow module with NullState lattice

**Files:**
- Create: `src/dataflow/mod.rs`
- Create: `src/dataflow/lattice.rs`
- Modify: `src/lib.rs:31` (add module declaration)

**Step 1: Write the failing test for NullState and join**

Create `src/dataflow/lattice.rs`:

```rust
//! Null state lattice for data flow analysis

use std::fmt;

/// Represents the null state of a variable at a program point
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NullState {
    /// Definitely null (assigned null literal)
    Null,
    /// Definitely not null (assigned non-null value or after null check)
    NonNull,
    /// Could be either (conditional, method return, parameter)
    MaybeNull,
}

impl NullState {
    /// Join two states at control flow merge points
    /// Returns the least upper bound in the lattice
    pub fn join(self, other: NullState) -> NullState {
        match (self, other) {
            (NullState::Null, NullState::Null) => NullState::Null,
            (NullState::NonNull, NullState::NonNull) => NullState::NonNull,
            _ => NullState::MaybeNull,
        }
    }

    /// Check if this state could be null
    pub fn could_be_null(&self) -> bool {
        matches!(self, NullState::Null | NullState::MaybeNull)
    }

    /// Check if this state is definitely null
    pub fn is_definitely_null(&self) -> bool {
        matches!(self, NullState::Null)
    }
}

impl fmt::Display for NullState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NullState::Null => write!(f, "null"),
            NullState::NonNull => write!(f, "non-null"),
            NullState::MaybeNull => write!(f, "maybe-null"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_same_states() {
        assert_eq!(NullState::Null.join(NullState::Null), NullState::Null);
        assert_eq!(NullState::NonNull.join(NullState::NonNull), NullState::NonNull);
        assert_eq!(NullState::MaybeNull.join(NullState::MaybeNull), NullState::MaybeNull);
    }

    #[test]
    fn test_join_different_states() {
        assert_eq!(NullState::Null.join(NullState::NonNull), NullState::MaybeNull);
        assert_eq!(NullState::NonNull.join(NullState::Null), NullState::MaybeNull);
        assert_eq!(NullState::Null.join(NullState::MaybeNull), NullState::MaybeNull);
        assert_eq!(NullState::NonNull.join(NullState::MaybeNull), NullState::MaybeNull);
    }

    #[test]
    fn test_could_be_null() {
        assert!(NullState::Null.could_be_null());
        assert!(NullState::MaybeNull.could_be_null());
        assert!(!NullState::NonNull.could_be_null());
    }

    #[test]
    fn test_is_definitely_null() {
        assert!(NullState::Null.is_definitely_null());
        assert!(!NullState::NonNull.is_definitely_null());
        assert!(!NullState::MaybeNull.is_definitely_null());
    }
}
```

**Step 2: Create module file**

Create `src/dataflow/mod.rs`:

```rust
//! Data flow analysis infrastructure
//!
//! Provides control flow graph construction and data flow analysis
//! for detecting issues like null pointer dereferences.

mod lattice;

pub use lattice::NullState;
```

**Step 3: Add module to lib.rs**

In `src/lib.rs`, after line 30 (after existing module declarations), add:

```rust
pub mod dataflow;
```

**Step 4: Run tests to verify**

Run: `cargo test dataflow::lattice --  --nocapture`
Expected: 4 tests pass

**Step 5: Commit**

```bash
git add src/dataflow/ src/lib.rs
git commit -m "feat(dataflow): add NullState lattice for null analysis"
```

---

## Task 2: Create CFG data structures

**Files:**
- Create: `src/dataflow/cfg.rs`
- Modify: `src/dataflow/mod.rs`

**Step 1: Create CFG types**

Create `src/dataflow/cfg.rs`:

```rust
//! Control Flow Graph (CFG) for methods
//!
//! Represents the control flow structure of a method as a graph of basic blocks.

use std::collections::HashMap;

/// Unique identifier for a basic block
pub type BlockId = usize;

/// A statement in the CFG (simplified representation)
#[derive(Debug, Clone)]
pub enum Statement {
    /// Variable assignment: var = expr
    Assignment {
        var: String,
        expr: Expression,
        line: usize,
        column: usize,
    },
    /// Method call on a receiver: receiver.method(args)
    MethodCall {
        receiver: Option<String>,
        method: String,
        line: usize,
        column: usize,
    },
    /// Field access: receiver.field
    FieldAccess {
        receiver: String,
        field: String,
        line: usize,
        column: usize,
    },
    /// Array access: array[index]
    ArrayAccess {
        array: String,
        line: usize,
        column: usize,
    },
    /// Other statement (not relevant for null analysis)
    Other,
}

/// Expression types for null analysis
#[derive(Debug, Clone)]
pub enum Expression {
    /// null literal
    Null,
    /// Non-null literal (string, number, etc.)
    Literal,
    /// new ClassName()
    NewObject,
    /// Method call result (could be null)
    MethodCall,
    /// Variable reference
    Variable(String),
    /// Ternary: cond ? then : else
    Ternary {
        then_expr: Box<Expression>,
        else_expr: Box<Expression>,
    },
    /// Unknown/complex expression
    Unknown,
}

/// Condition for branch decisions
#[derive(Debug, Clone)]
pub enum Condition {
    /// x == null
    IsNull(String),
    /// x != null
    IsNotNull(String),
    /// Other condition
    Other,
}

/// How a basic block terminates
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Return from method
    Return,
    /// Unconditional jump to another block
    Goto(BlockId),
    /// Conditional branch
    Branch {
        condition: Condition,
        then_block: BlockId,
        else_block: BlockId,
    },
    /// Unreachable (e.g., after throw)
    Unreachable,
}

/// A basic block in the CFG
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique identifier
    pub id: BlockId,
    /// Statements in this block (executed sequentially)
    pub statements: Vec<Statement>,
    /// How this block ends
    pub terminator: Terminator,
}

impl BasicBlock {
    /// Create a new empty block
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            statements: Vec::new(),
            terminator: Terminator::Unreachable,
        }
    }
}

/// Control Flow Graph for a method
#[derive(Debug)]
pub struct ControlFlowGraph {
    /// Entry block ID
    pub entry: BlockId,
    /// All blocks in the CFG
    pub blocks: HashMap<BlockId, BasicBlock>,
    /// Exit block ID (virtual block for method exit)
    pub exit: BlockId,
    /// Method parameters (treated as MaybeNull)
    pub parameters: Vec<String>,
}

impl ControlFlowGraph {
    /// Create a new CFG with entry and exit blocks
    pub fn new() -> Self {
        let mut blocks = HashMap::new();

        // Block 0: entry
        let entry_block = BasicBlock::new(0);
        blocks.insert(0, entry_block);

        // Block 1: exit (virtual)
        let exit_block = BasicBlock {
            id: 1,
            statements: Vec::new(),
            terminator: Terminator::Return,
        };
        blocks.insert(1, exit_block);

        Self {
            entry: 0,
            blocks,
            exit: 1,
            parameters: Vec::new(),
        }
    }

    /// Get a block by ID
    pub fn get_block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// Get a mutable block by ID
    pub fn get_block_mut(&mut self, id: BlockId) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&id)
    }

    /// Add a new block and return its ID
    pub fn add_block(&mut self) -> BlockId {
        let id = self.blocks.len();
        self.blocks.insert(id, BasicBlock::new(id));
        id
    }

    /// Get all block IDs in order
    pub fn block_ids(&self) -> Vec<BlockId> {
        let mut ids: Vec<_> = self.blocks.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Get predecessor blocks for a given block
    pub fn predecessors(&self, block_id: BlockId) -> Vec<BlockId> {
        let mut preds = Vec::new();
        for (id, block) in &self.blocks {
            match &block.terminator {
                Terminator::Goto(target) if *target == block_id => {
                    preds.push(*id);
                }
                Terminator::Branch { then_block, else_block, .. } => {
                    if *then_block == block_id || *else_block == block_id {
                        preds.push(*id);
                    }
                }
                _ => {}
            }
        }
        preds
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_new() {
        let cfg = ControlFlowGraph::new();
        assert_eq!(cfg.entry, 0);
        assert_eq!(cfg.exit, 1);
        assert_eq!(cfg.blocks.len(), 2);
    }

    #[test]
    fn test_add_block() {
        let mut cfg = ControlFlowGraph::new();
        let id = cfg.add_block();
        assert_eq!(id, 2);
        assert_eq!(cfg.blocks.len(), 3);
    }

    #[test]
    fn test_predecessors() {
        let mut cfg = ControlFlowGraph::new();
        let block2 = cfg.add_block();

        // Set entry block to jump to block2
        cfg.get_block_mut(0).unwrap().terminator = Terminator::Goto(block2);

        let preds = cfg.predecessors(block2);
        assert_eq!(preds, vec![0]);
    }

    #[test]
    fn test_expression_null() {
        let expr = Expression::Null;
        assert!(matches!(expr, Expression::Null));
    }

    #[test]
    fn test_condition_is_null() {
        let cond = Condition::IsNull("x".to_string());
        assert!(matches!(cond, Condition::IsNull(_)));
    }
}
```

**Step 2: Export from mod.rs**

Update `src/dataflow/mod.rs`:

```rust
//! Data flow analysis infrastructure
//!
//! Provides control flow graph construction and data flow analysis
//! for detecting issues like null pointer dereferences.

mod cfg;
mod lattice;

pub use cfg::{
    BasicBlock, BlockId, Condition, ControlFlowGraph, Expression, Statement, Terminator,
};
pub use lattice::NullState;
```

**Step 3: Run tests**

Run: `cargo test dataflow::cfg --  --nocapture`
Expected: 5 tests pass

**Step 4: Commit**

```bash
git add src/dataflow/
git commit -m "feat(dataflow): add CFG data structures"
```

---

## Task 3: Build CFG from tree-sitter AST

**Files:**
- Create: `src/dataflow/cfg_builder.rs`
- Modify: `src/dataflow/mod.rs`

**Step 1: Create CFG builder**

Create `src/dataflow/cfg_builder.rs`:

```rust
//! Builds a Control Flow Graph from a tree-sitter AST

use super::{
    BasicBlock, BlockId, Condition, ControlFlowGraph, Expression, Statement, Terminator,
};
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
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            if matches!(block.terminator, Terminator::Unreachable) {
                block.terminator = Terminator::Goto(self.cfg.exit);
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
        // Connect to merge
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            if matches!(block.terminator, Terminator::Unreachable) {
                block.terminator = Terminator::Goto(merge_block);
            }
        }

        // Process else branch if exists
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.current_block = else_block;
            self.process_statement(alternative);
            if let Some(block) = self.cfg.get_block_mut(self.current_block) {
                if matches!(block.terminator, Terminator::Unreachable) {
                    block.terminator = Terminator::Goto(merge_block);
                }
            }
        }

        self.current_block = merge_block;
    }

    /// Process return statement
    fn process_return_statement(&mut self, _node: Node<'a>) {
        if let Some(block) = self.cfg.get_block_mut(self.current_block) {
            block.terminator = Terminator::Goto(self.cfg.exit);
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
        // Handle parenthesized expression
        let node = if node.kind() == "parenthesized_expression" {
            node.child(1).unwrap_or(node)
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
```

**Step 2: Export from mod.rs**

Update `src/dataflow/mod.rs`:

```rust
//! Data flow analysis infrastructure
//!
//! Provides control flow graph construction and data flow analysis
//! for detecting issues like null pointer dereferences.

mod cfg;
mod cfg_builder;
mod lattice;

pub use cfg::{
    BasicBlock, BlockId, Condition, ControlFlowGraph, Expression, Statement, Terminator,
};
pub use cfg_builder::CfgBuilder;
pub use lattice::NullState;
```

**Step 3: Run tests**

Run: `cargo test dataflow::cfg_builder --  --nocapture`
Expected: 4 tests pass

**Step 4: Commit**

```bash
git add src/dataflow/
git commit -m "feat(dataflow): add CFG builder from tree-sitter AST"
```

---

## Task 4: Implement nullability analysis

**Files:**
- Create: `src/dataflow/nullability.rs`
- Modify: `src/dataflow/mod.rs`

**Step 1: Create nullability analysis**

Create `src/dataflow/nullability.rs`:

```rust
//! Nullability analysis - tracks null state of variables through CFG

use super::{BlockId, Condition, ControlFlowGraph, Expression, NullState, Statement, Terminator};
use std::collections::HashMap;

/// State of all variables at a program point
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullabilityState {
    /// Variable name -> null state
    pub variables: HashMap<String, NullState>,
}

impl NullabilityState {
    /// Create empty state
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// Get state for a variable
    pub fn get(&self, var: &str) -> NullState {
        self.variables
            .get(var)
            .copied()
            .unwrap_or(NullState::MaybeNull)
    }

    /// Set state for a variable
    pub fn set(&mut self, var: String, state: NullState) {
        self.variables.insert(var, state);
    }

    /// Join with another state (for merge points)
    pub fn join(&self, other: &NullabilityState) -> NullabilityState {
        let mut result = self.clone();
        for (var, other_state) in &other.variables {
            let self_state = self.get(var);
            result.set(var.clone(), self_state.join(*other_state));
        }
        // Also include vars only in self
        for var in self.variables.keys() {
            if !other.variables.contains_key(var) {
                let state = self.get(var).join(NullState::MaybeNull);
                result.set(var.clone(), state);
            }
        }
        result
    }

    /// Refine state based on a condition being true
    pub fn refine_true(&mut self, condition: &Condition) {
        match condition {
            Condition::IsNotNull(var) => {
                self.set(var.clone(), NullState::NonNull);
            }
            Condition::IsNull(var) => {
                self.set(var.clone(), NullState::Null);
            }
            Condition::Other => {}
        }
    }

    /// Refine state based on a condition being false
    pub fn refine_false(&mut self, condition: &Condition) {
        match condition {
            Condition::IsNotNull(var) => {
                self.set(var.clone(), NullState::Null);
            }
            Condition::IsNull(var) => {
                self.set(var.clone(), NullState::NonNull);
            }
            Condition::Other => {}
        }
    }
}

impl Default for NullabilityState {
    fn default() -> Self {
        Self::new()
    }
}

/// A potential null dereference found during analysis
#[derive(Debug, Clone)]
pub struct NullDereference {
    /// Variable being dereferenced
    pub variable: String,
    /// Line number
    pub line: usize,
    /// Column number
    pub column: usize,
    /// The null state at this point
    pub state: NullState,
    /// Description of the dereference type
    pub dereference_type: String,
}

/// Result of nullability analysis
#[derive(Debug)]
pub struct NullabilityAnalysisResult {
    /// State at entry of each block
    pub block_entry_states: HashMap<BlockId, NullabilityState>,
    /// State at exit of each block
    pub block_exit_states: HashMap<BlockId, NullabilityState>,
    /// Detected null dereferences
    pub dereferences: Vec<NullDereference>,
}

/// Perform nullability analysis on a CFG
pub fn analyze_nullability(cfg: &ControlFlowGraph) -> NullabilityAnalysisResult {
    let mut entry_states: HashMap<BlockId, NullabilityState> = HashMap::new();
    let mut exit_states: HashMap<BlockId, NullabilityState> = HashMap::new();
    let mut dereferences = Vec::new();

    // Initialize entry state with parameters as MaybeNull
    let mut initial_state = NullabilityState::new();
    for param in &cfg.parameters {
        initial_state.set(param.clone(), NullState::MaybeNull);
    }
    entry_states.insert(cfg.entry, initial_state);

    // Worklist algorithm
    let mut worklist: Vec<BlockId> = cfg.block_ids();
    let mut iterations = 0;
    let max_iterations = 1000; // Prevent infinite loops

    while !worklist.is_empty() && iterations < max_iterations {
        iterations += 1;
        let block_id = worklist.remove(0);

        // Compute entry state from predecessors
        let preds = cfg.predecessors(block_id);
        let entry_state = if block_id == cfg.entry {
            entry_states.get(&cfg.entry).cloned().unwrap_or_default()
        } else if preds.is_empty() {
            NullabilityState::new()
        } else {
            // Join states from all predecessors
            let mut state = NullabilityState::new();
            let mut first = true;
            for pred_id in &preds {
                if let Some(pred_exit) = exit_states.get(pred_id) {
                    // Apply condition refinement based on how we reached this block
                    let mut refined_state = pred_exit.clone();
                    if let Some(pred_block) = cfg.get_block(*pred_id) {
                        if let Terminator::Branch {
                            condition,
                            then_block,
                            else_block,
                        } = &pred_block.terminator
                        {
                            if *then_block == block_id {
                                refined_state.refine_true(condition);
                            } else if *else_block == block_id {
                                refined_state.refine_false(condition);
                            }
                        }
                    }

                    if first {
                        state = refined_state;
                        first = false;
                    } else {
                        state = state.join(&refined_state);
                    }
                }
            }
            state
        };

        // Check if state changed
        let old_entry = entry_states.get(&block_id);
        if old_entry.map(|s| s != &entry_state).unwrap_or(true) {
            entry_states.insert(block_id, entry_state.clone());

            // Process block statements
            if let Some(block) = cfg.get_block(block_id) {
                let exit_state = process_block_statements(block, entry_state, &mut dereferences);
                exit_states.insert(block_id, exit_state);

                // Add successors to worklist
                match &block.terminator {
                    Terminator::Goto(target) => {
                        if !worklist.contains(target) {
                            worklist.push(*target);
                        }
                    }
                    Terminator::Branch {
                        then_block,
                        else_block,
                        ..
                    } => {
                        if !worklist.contains(then_block) {
                            worklist.push(*then_block);
                        }
                        if !worklist.contains(else_block) {
                            worklist.push(*else_block);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    NullabilityAnalysisResult {
        block_entry_states: entry_states,
        block_exit_states: exit_states,
        dereferences,
    }
}

/// Process statements in a block, updating state and recording dereferences
fn process_block_statements(
    block: &super::BasicBlock,
    mut state: NullabilityState,
    dereferences: &mut Vec<NullDereference>,
) -> NullabilityState {
    for stmt in &block.statements {
        match stmt {
            Statement::Assignment { var, expr, .. } => {
                let new_state = evaluate_expression(expr, &state);
                state.set(var.clone(), new_state);
            }
            Statement::MethodCall {
                receiver: Some(recv),
                line,
                column,
                ..
            } => {
                let recv_state = state.get(recv);
                if recv_state.could_be_null() {
                    dereferences.push(NullDereference {
                        variable: recv.clone(),
                        line: *line,
                        column: *column,
                        state: recv_state,
                        dereference_type: "method call".to_string(),
                    });
                }
            }
            Statement::FieldAccess {
                receiver,
                line,
                column,
                ..
            } => {
                let recv_state = state.get(receiver);
                if recv_state.could_be_null() {
                    dereferences.push(NullDereference {
                        variable: receiver.clone(),
                        line: *line,
                        column: *column,
                        state: recv_state,
                        dereference_type: "field access".to_string(),
                    });
                }
            }
            Statement::ArrayAccess { array, line, column } => {
                let arr_state = state.get(array);
                if arr_state.could_be_null() {
                    dereferences.push(NullDereference {
                        variable: array.clone(),
                        line: *line,
                        column: *column,
                        state: arr_state,
                        dereference_type: "array access".to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    state
}

/// Evaluate an expression to determine its null state
fn evaluate_expression(expr: &Expression, state: &NullabilityState) -> NullState {
    match expr {
        Expression::Null => NullState::Null,
        Expression::Literal | Expression::NewObject => NullState::NonNull,
        Expression::MethodCall => NullState::MaybeNull,
        Expression::Variable(name) => state.get(name),
        Expression::Ternary {
            then_expr,
            else_expr,
        } => {
            let then_state = evaluate_expression(then_expr, state);
            let else_state = evaluate_expression(else_expr, state);
            then_state.join(else_state)
        }
        Expression::Unknown => NullState::MaybeNull,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullability_state_get_default() {
        let state = NullabilityState::new();
        assert_eq!(state.get("unknown"), NullState::MaybeNull);
    }

    #[test]
    fn test_nullability_state_set_get() {
        let mut state = NullabilityState::new();
        state.set("x".to_string(), NullState::Null);
        assert_eq!(state.get("x"), NullState::Null);
    }

    #[test]
    fn test_nullability_state_join() {
        let mut s1 = NullabilityState::new();
        s1.set("x".to_string(), NullState::Null);

        let mut s2 = NullabilityState::new();
        s2.set("x".to_string(), NullState::NonNull);

        let joined = s1.join(&s2);
        assert_eq!(joined.get("x"), NullState::MaybeNull);
    }

    #[test]
    fn test_refine_true_not_null() {
        let mut state = NullabilityState::new();
        state.set("x".to_string(), NullState::MaybeNull);
        state.refine_true(&Condition::IsNotNull("x".to_string()));
        assert_eq!(state.get("x"), NullState::NonNull);
    }

    #[test]
    fn test_refine_false_not_null() {
        let mut state = NullabilityState::new();
        state.set("x".to_string(), NullState::MaybeNull);
        state.refine_false(&Condition::IsNotNull("x".to_string()));
        assert_eq!(state.get("x"), NullState::Null);
    }

    #[test]
    fn test_evaluate_expression_null() {
        let state = NullabilityState::new();
        assert_eq!(evaluate_expression(&Expression::Null, &state), NullState::Null);
    }

    #[test]
    fn test_evaluate_expression_literal() {
        let state = NullabilityState::new();
        assert_eq!(evaluate_expression(&Expression::Literal, &state), NullState::NonNull);
    }

    #[test]
    fn test_evaluate_expression_ternary() {
        let state = NullabilityState::new();
        let expr = Expression::Ternary {
            then_expr: Box::new(Expression::Literal),
            else_expr: Box::new(Expression::Null),
        };
        assert_eq!(evaluate_expression(&expr, &state), NullState::MaybeNull);
    }
}
```

**Step 2: Export from mod.rs**

Update `src/dataflow/mod.rs`:

```rust
//! Data flow analysis infrastructure
//!
//! Provides control flow graph construction and data flow analysis
//! for detecting issues like null pointer dereferences.

mod cfg;
mod cfg_builder;
mod lattice;
mod nullability;

pub use cfg::{
    BasicBlock, BlockId, Condition, ControlFlowGraph, Expression, Statement, Terminator,
};
pub use cfg_builder::CfgBuilder;
pub use lattice::NullState;
pub use nullability::{analyze_nullability, NullabilityAnalysisResult, NullabilityState, NullDereference};
```

**Step 3: Run tests**

Run: `cargo test dataflow::nullability --  --nocapture`
Expected: 7 tests pass

**Step 4: Commit**

```bash
git add src/dataflow/
git commit -m "feat(dataflow): add nullability analysis algorithm"
```

---

## Task 5: Create S2259 rule

**Files:**
- Modify: `src/rules/bugs.rs`

**Step 1: Add S2259 rule implementation**

At the end of `src/rules/bugs.rs` (before `create_rules()` function around line 4993), add:

```rust
// S2259: Null pointer dereference
pub struct S2259NullPointerDereference;

impl Rule for S2259NullPointerDereference {
    fn id(&self) -> &str {
        "S2259"
    }

    fn title(&self) -> &str {
        "Null pointers should not be dereferenced"
    }

    fn severity(&self) -> Severity {
        Severity::Major // Will be Blocker for definite null
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }

    fn description(&self) -> &str {
        "A reference to null should never be dereferenced. Doing so will cause a NullPointerException."
    }

    fn cwe(&self) -> Option<u32> {
        Some(476) // CWE-476: NULL Pointer Dereference
    }

    fn debt_minutes(&self) -> u32 {
        10
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        use crate::dataflow::{analyze_nullability, CfgBuilder, NullState};

        let mut issues = Vec::new();

        // Find all method declarations
        let root = ctx.tree.root_node();
        let mut cursor = root.walk();

        fn find_methods<'a>(node: tree_sitter::Node<'a>, methods: &mut Vec<tree_sitter::Node<'a>>) {
            if node.kind() == "method_declaration" || node.kind() == "constructor_declaration" {
                methods.push(node);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                find_methods(child, methods);
            }
        }

        let mut methods = Vec::new();
        for child in root.children(&mut cursor) {
            find_methods(child, &mut methods);
        }

        // Analyze each method
        for method in methods {
            let cfg = CfgBuilder::new(ctx.source).build_method(method);
            let result = analyze_nullability(&cfg);

            for deref in result.dereferences {
                let severity = if deref.state.is_definitely_null() {
                    Severity::Blocker
                } else {
                    Severity::Major
                };

                let message = if deref.state.is_definitely_null() {
                    format!(
                        "Null pointer dereference: '{}' is always null here ({})",
                        deref.variable, deref.dereference_type
                    )
                } else {
                    format!(
                        "Potential null pointer dereference: '{}' may be null ({})",
                        deref.variable, deref.dereference_type
                    )
                };

                // Get code snippet
                let snippet = ctx
                    .source
                    .lines()
                    .nth(deref.line.saturating_sub(1))
                    .map(|l| l.trim().to_string());

                let mut issue = create_issue(
                    self,
                    ctx.file_path,
                    deref.line,
                    deref.column,
                    message,
                    snippet,
                );
                issue.severity = severity;
                issue.cwe = Some(476);
                issues.push(issue);
            }
        }

        issues
    }
}
```

**Step 2: Register in create_rules()**

In `src/rules/bugs.rs`, add to the `create_rules()` vector (around line 5235, before the closing `]`):

```rust
        Box::new(S2259NullPointerDereference),
```

**Step 3: Add tests for S2259**

At the end of the `tests` module in `src/rules/bugs.rs`, add:

```rust
    // ===== S2259 Null Pointer Dereference Tests =====

    #[test]
    fn test_s2259_explicit_null_dereference() {
        let source = r#"
            public class Test {
                void foo() {
                    String s = null;
                    s.length();
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(!issues.is_empty(), "Should detect null dereference");
        assert_eq!(issues[0].severity, Severity::Blocker);
    }

    #[test]
    fn test_s2259_null_after_reassignment() {
        let source = r#"
            public class Test {
                void foo() {
                    String s = "hello";
                    s = null;
                    s.length();
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(!issues.is_empty(), "Should detect null after reassignment");
    }

    #[test]
    fn test_s2259_parameter_could_be_null() {
        let source = r#"
            public class Test {
                void foo(String s) {
                    s.length();
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(!issues.is_empty(), "Should warn about parameter possibly being null");
        assert_eq!(issues[0].severity, Severity::Major);
    }

    #[test]
    fn test_s2259_null_check_guards_access() {
        let source = r#"
            public class Test {
                void foo(String s) {
                    if (s != null) {
                        s.length();
                    }
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(issues.is_empty(), "Should not warn when null check guards access");
    }

    #[test]
    fn test_s2259_assignment_after_null() {
        let source = r#"
            public class Test {
                void foo() {
                    String s = null;
                    s = "safe";
                    s.length();
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(issues.is_empty(), "Should not warn when reassigned to non-null");
    }

    #[test]
    fn test_s2259_conditional_null() {
        let source = r#"
            public class Test {
                void foo(boolean cond) {
                    String s = cond ? "hi" : null;
                    s.length();
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(!issues.is_empty(), "Should warn about conditional null");
        assert_eq!(issues[0].severity, Severity::Major);
    }

    #[test]
    fn test_s2259_early_return_pattern() {
        let source = r#"
            public class Test {
                void foo(String s) {
                    if (s == null) {
                        return;
                    }
                    s.length();
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let rule = S2259NullPointerDereference;
        let issues = rule.check(&ctx);
        assert!(issues.is_empty(), "Should not warn after early return on null");
    }
```

**Step 4: Run tests**

Run: `cargo test s2259 --  --nocapture`
Expected: 7 tests pass

**Step 5: Commit**

```bash
git add src/rules/bugs.rs
git commit -m "feat(rules): add S2259 null pointer dereference detection"
```

---

## Task 6: Integration test and final verification

**Files:**
- None (verification only)

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (280+ tests)

**Step 2: Test with real Java code**

Create test file `/tmp/NullTest.java`:

```java
public class NullTest {
    void definiteNull() {
        String s = null;
        s.length(); // Should warn: Blocker
    }

    void possibleNull(String s) {
        s.length(); // Should warn: Major
    }

    void safeWithCheck(String s) {
        if (s != null) {
            s.length(); // Should NOT warn
        }
    }

    void safeWithEarlyReturn(String s) {
        if (s == null) return;
        s.length(); // Should NOT warn
    }
}
```

Run: `cargo run -- /tmp/NullTest.java`
Expected: 2 issues (lines 4 and 8)

**Step 3: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete S2259 null pointer detection with CFG-based analysis"
```

---

## Summary

| Task | Files | Tests |
|------|-------|-------|
| 1. NullState lattice | `src/dataflow/lattice.rs`, `src/dataflow/mod.rs`, `src/lib.rs` | 4 |
| 2. CFG data structures | `src/dataflow/cfg.rs` | 5 |
| 3. CFG builder | `src/dataflow/cfg_builder.rs` | 4 |
| 4. Nullability analysis | `src/dataflow/nullability.rs` | 7 |
| 5. S2259 rule | `src/rules/bugs.rs` | 7 |
| 6. Integration | - | - |

**Total new tests:** ~27
**Estimated commits:** 6
