# diff

Compare current analysis against a baseline (differential analysis).

## Usage

```bash
java-analyzer diff <PATH> --baseline <BASELINE_FILE> [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-b, --baseline` | Baseline file to compare against | required |
| `--new-only` | Only show new issues | false |
| `-f, --format` | Output format (text, json) | `text` |

## Examples

### Compare Against Baseline

```bash
java-analyzer diff ./src --baseline baseline.json
```

Output:
```
Differential Analysis
=====================

Baseline: baseline.json (created: 2024-01-15T10:30:00Z)
Description: Release 1.0 baseline

2 new | 1 fixed | 42 unchanged | Net: +1

New Issues:
  [Critical] src/Auth.java:45 - Hard-coded credential detected (S2068)
  [Major] src/Utils.java:12 - Replace System.out with logger (S106)

Fixed Issues:
  [FIXED] src/Main.java:25 - S101
```

### Show Only New Issues

```bash
java-analyzer diff ./src --baseline baseline.json --new-only
```

### JSON Output for CI

```bash
java-analyzer diff ./src --baseline baseline.json --format json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No new issues |
| 1 | New issues detected |

## CI Integration

```yaml
- name: Check for new issues
  run: |
    java-analyzer diff ./src --baseline baseline.json
  continue-on-error: false
```
