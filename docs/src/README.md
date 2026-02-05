# Java Analyzer

A lightning-fast static code analyzer for Java built in Rust, implementing SonarSource-based rules.

## Features

- **Fast Analysis** - Parallel file processing using Rayon
- **80+ Rules** - Based on SonarSource Java rules
- **Multiple Output Formats** - Text, JSON, HTML, SARIF, CSV, Markdown
- **Quality Gates** - Pass/fail criteria for CI/CD pipelines
- **Code Duplication** - Detect copy-paste code
- **Technical Debt** - Calculate and track debt with A-E ratings
- **Security Hotspots** - Identify security-sensitive code
- **Baseline Comparison** - Track new vs. fixed issues
- **Test Coverage** - Import JaCoCo/LCOV reports

## Quick Example

```bash
# Analyze a Java project
java-analyzer ./src

# Apply strict quality gate
java-analyzer ./src --quality-gate strict

# Generate JSON report
java-analyzer ./src --format json -o report.json

# Show only critical issues
java-analyzer ./src --min-severity critical
```

## Why Java Analyzer?

| Feature | Java Analyzer | SonarQube |
|---------|--------------|-----------|
| Speed | Milliseconds | Seconds-Minutes |
| Setup | Single binary | Server + Database |
| CI Integration | Native exit codes | Requires webhook |
| Cost | Free | Enterprise pricing |

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Parser    │────▶│   Rules      │────▶│   Reports   │
│ (tree-sitter)│    │ (80+ checks) │     │ (6 formats) │
└─────────────┘     └──────────────┘     └─────────────┘
```

## Getting Started

1. [Install Java Analyzer](./getting-started/installation.md)
2. [Run your first analysis](./getting-started/quickstart.md)
3. [Configure for your project](./getting-started/configuration.md)
