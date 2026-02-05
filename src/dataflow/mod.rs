//! Data flow analysis infrastructure
//!
//! Provides control flow graph construction and data flow analysis
//! for detecting issues like null pointer dereferences.

mod lattice;

pub use lattice::NullState;
