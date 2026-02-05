# analyze

Analyze Java source code for issues.

## Usage

```bash
java-analyzer [OPTIONS] <PATH>
java-analyzer analyze <PATH>
```

## Arguments

| Argument | Description |
|----------|-------------|
| `PATH` | File or directory to analyze |

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format` | Output format (text, json, html, sarif, csv, markdown) | `text` |
| `-o, --output` | Output file path | stdout |
| `-s, --min-severity` | Minimum severity to report | `info` |
| `--max-complexity` | Cognitive complexity threshold | `15` |
| `--rules` | Enable only specific rules (comma-separated) | all |
| `--exclude-rules` | Disable specific rules (comma-separated) | none |
| `--exclude` | Exclude path patterns (comma-separated) | none |
| `--no-color` | Disable colored output | false |
| `--summary-only` | Show only summary, no details | false |
| `--fail-on-issues` | Exit code 1 if any issues found | false |
| `--fail-on-severity` | Exit code 1 if severity threshold exceeded | none |
| `--quality-gate` | Apply quality gate (strict, standard, lenient) | none |
| `--quality-gate-file` | Load quality gate from file | none |
| `-v, --verbose` | Enable verbose output | false |

## Examples

### Basic Analysis

```bash
java-analyzer ./src/main/java
```

### Generate HTML Report

```bash
java-analyzer ./src --format html -o report.html
```

### CI Pipeline

```bash
java-analyzer ./src --fail-on-severity critical --format sarif -o results.sarif
```

### Enable Specific Rules Only

```bash
java-analyzer ./src --rules S2068,S3649,S106
```

### Exclude Test Files

```bash
java-analyzer ./src --exclude "**/test/**,**/*Test.java"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no issues or below threshold) |
| 1 | Issues found exceeding threshold |
