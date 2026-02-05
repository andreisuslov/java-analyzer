# Quick Start

## Analyze a File

```bash
java-analyzer MyClass.java
```

## Analyze a Directory

```bash
java-analyzer ./src
```

## Example Output

```
======================================================================
                     JAVA ANALYZER REPORT
======================================================================

Files analyzed: 15
Total issues: 23
Analysis time: 45ms

Issues by Severity:
  BLOCKER   : 0
  CRITICAL  : 2
  MAJOR     : 8
  MINOR     : 10
  INFO      : 3

----------------------------------------------------------------------
ISSUES BY FILE
----------------------------------------------------------------------

File: src/Main.java
Issues: 5

  [CRITICAL] 15:1 - Hard-coded credential detected (S2068)
  [MAJOR   ] 23:5 - Replace System.out with proper logging (S106)
  [MINOR   ] 8:12 - Rename field 'URL' to match camelCase (S116)
```

## Filter by Severity

```bash
# Only show major issues and above
java-analyzer ./src --min-severity major

# Fail CI if critical issues found
java-analyzer ./src --fail-on-severity critical
```

## Generate Reports

```bash
# JSON report
java-analyzer ./src --format json -o report.json

# HTML report
java-analyzer ./src --format html -o report.html

# SARIF for GitHub Code Scanning
java-analyzer ./src --format sarif -o results.sarif
```

## Apply Quality Gate

```bash
# Use built-in strict gate
java-analyzer ./src --quality-gate strict

# Use custom gate from file
java-analyzer ./src --quality-gate-file my-gate.json
```

## Show Summary Only

```bash
java-analyzer ./src --summary-only
```

## Next Steps

- [Configure your project](./configuration.md)
- [Explore all commands](../commands/analyze.md)
- [Set up CI/CD](../reference/cicd.md)
