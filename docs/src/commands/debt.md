# debt

Show technical debt summary with A-E rating.

## Usage

```bash
java-analyzer debt <PATH> [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format` | Output format (text, json) | `text` |

## Example

```bash
java-analyzer debt ./src
```

Output:
```
Technical Debt Summary
======================

Total Debt:  2d 4h 30min (Fair - moderate debt needs attention)
Rating:      C

By Severity:
  Blocker: 2h
  Critical: 4h
  Major: 1d 2h
  Minor: 6h 30min

By Category:
  Security: 6h
  Bug: 8h
  CodeSmell: 1d 6h 30min

Top Files by Debt:
  4h 15min - src/LegacyService.java
  2h 30min - src/DataProcessor.java
  1h 45min - src/Utils.java

Top Rules by Debt:
  3h 30min - S106 (System.out usage)
  2h - S2068 (Hardcoded credentials)
  1h 45min - S3776 (Cognitive complexity)
```

## Debt Rating Scale

| Rating | Debt Range | Description |
|--------|-----------|-------------|
| **A** | 0-30 min | Excellent - minimal debt |
| **B** | 31-120 min | Good - manageable debt |
| **C** | 2-8 hours | Fair - moderate debt |
| **D** | 8-24 hours | Poor - significant debt |
| **E** | >24 hours | Critical - urgent action needed |

## JSON Output

```bash
java-analyzer debt ./src --format json
```

```json
{
  "total_minutes": 1710,
  "formatted_total": "2d 4h 30min",
  "by_severity": {"Major": 740, "Minor": 390},
  "by_category": {"CodeSmell": 990, "Bug": 480},
  "by_file": [["src/LegacyService.java", 255]],
  "by_rule": [["S106", 210]]
}
```
