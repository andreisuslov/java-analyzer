# Quality Gates

Quality gates define pass/fail criteria for CI/CD pipelines.

## Built-in Gates

### Strict

```bash
java-analyzer ./src --quality-gate strict
```

Conditions:
- No blocker or critical issues
- Max 10 major issues
- Max 60 minutes technical debt

### Standard

```bash
java-analyzer ./src --quality-gate standard
```

Conditions:
- No blocker issues
- Max 5 critical issues
- Max 120 minutes technical debt

### Lenient

```bash
java-analyzer ./src --quality-gate lenient
```

Conditions:
- No blocker issues only

## Custom Quality Gates

### JSON Format

Create `quality-gate.json`:

```json
{
  "name": "My Custom Gate",
  "description": "Custom quality requirements",
  "conditions": [
    {
      "type": "no_issues_above",
      "severity": "Critical"
    },
    {
      "type": "max_issues",
      "severity": "Major",
      "threshold": 20
    },
    {
      "type": "max_total_issues",
      "threshold": 50
    },
    {
      "type": "max_debt_minutes",
      "threshold": 240
    }
  ]
}
```

### TOML Format

Create `quality-gate.toml`:

```toml
name = "My Custom Gate"
description = "Custom quality requirements"

[[conditions]]
type = "no_issues_above"
severity = "Critical"

[[conditions]]
type = "max_issues"
severity = "Major"
threshold = 20

[[conditions]]
type = "max_debt_minutes"
threshold = 240
```

### Use Custom Gate

```bash
java-analyzer ./src --quality-gate-file quality-gate.json
```

## Condition Types

| Type | Description | Parameters |
|------|-------------|------------|
| `max_issues` | Max issues of severity | `severity`, `threshold` |
| `max_total_issues` | Max total issues | `threshold` |
| `no_issues_above` | No issues at or above severity | `severity` |
| `max_debt_minutes` | Max technical debt | `threshold` |
| `max_new_issues` | Max new issues (vs baseline) | `threshold` |

## Output

```
━━━ Quality Gate: Strict - FAILED
    ✗ Issues with severity Critical or higher: 3
    ✓ issues with severity Major: 8 (max: 10)
    ✗ Technical debt: 75 min (max: 60 min)
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Quality gate passed |
| 1 | Quality gate failed |
