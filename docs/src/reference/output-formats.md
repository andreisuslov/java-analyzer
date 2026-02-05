# Output Formats

Java Analyzer supports multiple output formats for different use cases.

## Text (Default)

Human-readable console output with colors.

```bash
java-analyzer ./src --format text
```

## JSON

Machine-readable format for automation.

```bash
java-analyzer ./src --format json -o report.json
```

```json
{
  "files_analyzed": 15,
  "issues": [
    {
      "rule_id": "S106",
      "title": "Replace System.out with logger",
      "severity": "Major",
      "category": "CodeSmell",
      "file": "src/Main.java",
      "line": 25,
      "column": 9,
      "message": "Replace this with proper logging",
      "debt_minutes": 5
    }
  ],
  "duration_ms": 45
}
```

## HTML

Interactive report for browsers.

```bash
java-analyzer ./src --format html -o report.html
```

Features:
- Sortable issue table
- Severity filtering
- Code snippets
- Summary statistics

## SARIF

Static Analysis Results Interchange Format for GitHub Code Scanning.

```bash
java-analyzer ./src --format sarif -o results.sarif
```

### GitHub Integration

```yaml
- name: Run Java Analyzer
  run: java-analyzer ./src --format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## CSV

Spreadsheet-compatible format.

```bash
java-analyzer ./src --format csv -o report.csv
```

Columns:
- File, Line, Column
- Rule ID, Title
- Severity, Category
- Message

## Markdown

Documentation-friendly format.

```bash
java-analyzer ./src --format markdown -o report.md
```

Output:
```markdown
# Java Analyzer Report

**Files analyzed:** 15
**Total issues:** 23

## Issues by Severity

| Severity | Count |
|----------|-------|
| Critical | 2 |
| Major | 8 |
| Minor | 13 |

## Issues

### src/Main.java

| Line | Severity | Rule | Message |
|------|----------|------|---------|
| 25 | Major | S106 | Replace System.out with logger |
```
