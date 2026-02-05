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
