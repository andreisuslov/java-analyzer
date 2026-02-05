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
