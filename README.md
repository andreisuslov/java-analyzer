# Java Analyzer

A lightning-fast static code analyzer for Java, implementing 987 rules based on SonarSource's Java analysis rules. Built in Rust for maximum performance.

## Features

- **987 Rules** covering:
  - 494 Code Smell detection rules
  - 239 Bug detection rules
  - 136 Security vulnerability rules
  - 65 Complexity analysis rules
  - 53 Naming convention rules

- **Multiple Output Formats**:
  - Text (default, colored terminal output)
  - JSON (for CI/CD integration)
  - HTML (interactive reports)
  - SARIF (for IDE integration)
  - CSV (for spreadsheet analysis)
  - Markdown (for documentation)

- **Fast Performance**: Analyzes thousands of files in seconds using parallel processing with Rayon

- **Configurable**: Filter by severity, exclude rules, set complexity thresholds

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/andreisuslov/java-analyzer.git
cd java-analyzer

# Build in release mode
cargo build --release

# The binary will be at target/release/java-analyzer
```

### Requirements

- Rust 1.70 or later
- Cargo package manager

## Usage

### Basic Analysis

```bash
# Analyze a single file
java-analyzer path/to/File.java

# Analyze a directory (recursive)
java-analyzer path/to/project

# Analyze with specific output format
java-analyzer path/to/project --format json
```

### Output Formats

```bash
# Text output (default)
java-analyzer src/

# JSON output
java-analyzer src/ --format json

# HTML report
java-analyzer src/ --format html --output report.html

# SARIF for IDE integration
java-analyzer src/ --format sarif --output results.sarif

# CSV for spreadsheets
java-analyzer src/ --format csv --output issues.csv

# Markdown
java-analyzer src/ --format markdown --output report.md
```

### Filtering Options

```bash
# Only show major issues and above
java-analyzer src/ --min-severity major

# Show only summary (no individual issues)
java-analyzer src/ --summary-only

# Enable specific rules only
java-analyzer src/ --rules S100,S101,S106

# Exclude specific rules
java-analyzer src/ --exclude-rules S105,S109

# Exclude paths
java-analyzer src/ --exclude "*/test/*,*/generated/*"
```

### Complexity Thresholds

```bash
# Set maximum cognitive complexity (default: 15)
java-analyzer src/ --max-complexity 20
```

### CI/CD Integration

```bash
# Fail if any issues are found
java-analyzer src/ --fail-on-issues

# Fail only on critical or blocker issues
java-analyzer src/ --fail-on-severity critical
```

### List Available Rules

```bash
# Show all 987 rules
java-analyzer rules

# Filter rules by keyword
java-analyzer rules | grep -i security
```

## Severity Levels

| Level | Description |
|-------|-------------|
| **Blocker** | Must be fixed immediately - blocks release |
| **Critical** | High priority - security issues, likely bugs |
| **Major** | Should be fixed - code quality issues |
| **Minor** | Nice to fix - style and convention issues |
| **Info** | Informational - suggestions for improvement |

## Rule Categories

### Naming (53 rules)
Checks for naming convention violations:
- Method names (camelCase)
- Class names (PascalCase)
- Constants (UPPER_SNAKE_CASE)
- Package names (lowercase)

### Security (136 rules)
Detects security vulnerabilities:
- Hardcoded credentials
- SQL injection risks
- Insecure cryptography
- Path traversal vulnerabilities

### Bugs (239 rules)
Identifies potential bugs:
- Null pointer dereferences
- Resource leaks
- Infinite loops
- Dead code

### Code Smells (494 rules)
Finds maintainability issues:
- Long methods
- Duplicate code patterns
- Unused variables
- Complex conditionals

### Complexity (65 rules)
Measures code complexity:
- Cognitive complexity
- Cyclomatic complexity
- Nesting depth
- Method length

## Example Output

### Text Format
```
======================================================================
                     JAVA ANALYZER REPORT
======================================================================

Files analyzed: 42
Total issues: 156
Analysis time: 234ms

Issues by Severity:
  BLOCKER   : 0
  CRITICAL  : 3
  MAJOR     : 28
  MINOR     : 125
  INFO      : 0

----------------------------------------------------------------------
ISSUES BY FILE
----------------------------------------------------------------------

File: src/main/java/Example.java
Issues: 5

  [MAJOR   ] 15:1 - Replace this with proper logging. (S106)
             > System.out.println("debug");
  [MINOR   ] 8:17 - Rename method 'BadName' to match camelCase convention (S100)
             > BadName
```

### JSON Format
```json
{
  "summary": {
    "files_analyzed": 42,
    "total_issues": 156,
    "duration_ms": 234
  },
  "issues": [
    {
      "rule_id": "S106",
      "severity": "major",
      "file": "src/main/java/Example.java",
      "line": 15,
      "message": "Replace this with proper logging."
    }
  ]
}
```

## Performance

Benchmarks on a MacBook Pro M1:

| Project Size | Files | Time |
|-------------|-------|------|
| Small | 50 files | ~0.5s |
| Medium | 500 files | ~5s |
| Large | 1,000+ files | ~4 min |

## Development

### Running Tests

```bash
cargo test
```

### Building for Release

```bash
cargo build --release
```

### Project Structure

```
java-analyzer/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library exports
│   ├── parser/          # Java parsing with tree-sitter
│   ├── rules/           # Rule implementations
│   │   ├── naming.rs    # Naming convention rules
│   │   ├── security.rs  # Security rules
│   │   ├── bugs.rs      # Bug detection rules
│   │   ├── code_smells.rs # Code smell rules
│   │   └── complexity.rs  # Complexity rules
│   └── reports/         # Output formatters
├── tests/               # Integration tests
├── Cargo.toml          # Dependencies
└── README.md           # This file
```

## License

MIT License

## Acknowledgments

- Rule definitions based on [SonarSource Java Rules](https://rules.sonarsource.com/java/)
- Built with [tree-sitter](https://tree-sitter.github.io/) for parsing
- Parallel processing with [Rayon](https://github.com/rayon-rs/rayon)
