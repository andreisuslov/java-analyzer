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
