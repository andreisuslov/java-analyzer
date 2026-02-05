# rules

List all available analysis rules.

## Usage

```bash
java-analyzer rules [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --category` | Filter by category |
| `-d, --details` | Show detailed descriptions |

## Examples

### List All Rules

```bash
java-analyzer rules
```

Output:
```
Available Rules
===============

Total: 87 rules

S100  [MINOR   ] Naming - Method names should comply with naming convention
S101  [MINOR   ] Naming - Class names should comply with naming convention
S106  [MAJOR   ] CodeSmell - Replace System.out with logger
S2068 [BLOCKER ] Security - Credentials should not be hardcoded
...
```

### Filter by Category

```bash
java-analyzer rules --category security
```

### Show Details

```bash
java-analyzer rules --details
```

## Rule Categories

| Category | Description |
|----------|-------------|
| Naming | Naming convention violations |
| Security | Security vulnerabilities |
| Bug | Potential bugs |
| CodeSmell | Code quality issues |
| Complexity | Cognitive complexity |
| Documentation | Missing documentation |
| Performance | Performance issues |
