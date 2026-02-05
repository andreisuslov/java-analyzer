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
