# Null Pointer Detection Design (S2259)

## Overview

Intra-method null pointer detection via control-flow-sensitive data flow analysis.

**Scope**: Single method analysis (no cross-method tracking)
**Rule ID**: S2259 (matches SonarQube)
**CWE**: 476 (NULL Pointer Dereference)
**Severity**: Blocker (definite null), Major (possible null)

## Null State Lattice

```
       Unknown
          |
      +---+---+
      |       |
   NonNull  Null
      |       |
      +---+---+
          |
       MaybeNull
```

- `Null` - Definitely null (assigned `null` literal)
- `NonNull` - Definitely not null (assigned non-null value, or after null check)
- `MaybeNull` - Could be either (conditional assignment, method return, parameter)

## Control Flow Graph (CFG)

```rust
pub struct BasicBlock {
    pub id: usize,
    pub statements: Vec<Statement>,
    pub terminator: Terminator,
}

pub enum Terminator {
    Return,
    Goto(BlockId),
    Branch { condition: Expr, then_: BlockId, else_: BlockId },
    Switch { value: Expr, cases: Vec<(Value, BlockId)>, default: BlockId },
}

pub struct ControlFlowGraph {
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub exit: BlockId,
}
```

CFG built by walking tree-sitter AST, splitting at control flow points.

## Null State Tracking

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NullState {
    Null,
    NonNull,
    MaybeNull,
}

pub struct NullabilityState {
    pub variables: HashMap<String, NullState>,
}
```

### State Transfer Functions

| Statement | Effect |
|-----------|--------|
| `x = null` | `x → Null` |
| `x = "literal"` | `x → NonNull` |
| `x = new Foo()` | `x → NonNull` |
| `x = someMethod()` | `x → MaybeNull` |
| `x = y` | `x → state(y)` |
| `x = cond ? a : b` | `x → join(state(a), state(b))` |

### Join Operation

```
join(Null, Null) = Null
join(NonNull, NonNull) = NonNull
join(Null, NonNull) = MaybeNull
join(_, MaybeNull) = MaybeNull
```

### Null Check Refinement

At `if (x != null)`:
- In `then` branch: `x → NonNull`
- In `else` branch: `x → Null`

## Dereference Detection

```rust
pub enum Dereference {
    MethodCall { receiver: String, method: String, line: usize, column: usize },
    FieldAccess { receiver: String, field: String, line: usize, column: usize },
    ArrayAccess { array: String, line: usize, column: usize },
    Synchronized { monitor: String, line: usize, column: usize },
}
```

### Issue Severity

| State | Severity | Message |
|-------|----------|---------|
| `Null` | Blocker | "Null pointer dereference: 'x' is always null here" |
| `MaybeNull` | Major | "Potential null pointer dereference: 'x' may be null" |

## File Structure

```
src/
├── dataflow/
│   ├── mod.rs          # Module exports
│   ├── cfg.rs          # Control Flow Graph builder
│   ├── nullability.rs  # Null state analysis
│   └── lattice.rs      # NullState enum and join operations
└── rules/
    └── bugs.rs         # Add S2259 rule
```

## Integration

1. `src/lib.rs` - Add `pub mod dataflow;`
2. `src/rules/bugs.rs` - Add `NullPointerDereferenceRule`
3. `src/rules/bugs.rs:create_rules()` - Register S2259

## Test Cases

### Should Warn (Blocker - Definite Null)

```java
// Explicit null dereference
String s = null;
s.length();

// Null after reassignment
String s = "hi";
s = null;
s.length();
```

### Should Warn (Major - Possible Null)

```java
// Conditional null
String s = cond ? "hi" : null;
s.length();

// Parameter could be null
void foo(String s) {
    s.length();
}
```

### Should NOT Warn (Safe)

```java
// Null check guards access
if (s != null) {
    s.length();
}

// Assignment after null
String s = null;
s = "safe";
s.length();

// Early return pattern
if (s == null) return;
s.length();
```

### Edge Cases

- Nested if null checks
- Loop null assignment
- Try-catch with null assignment
- Switch statement branches

## Implementation Order

1. RED: Write failing tests for all scenarios
2. GREEN:
   - `lattice.rs` - NullState enum and join
   - `cfg.rs` - CFG builder from tree-sitter AST
   - `nullability.rs` - Forward analysis algorithm
   - `bugs.rs` - S2259 rule integration
3. REFACTOR: Optimize CFG building, reduce allocations
