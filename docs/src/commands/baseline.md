# baseline

Create a baseline from current analysis results for differential comparison.

## Usage

```bash
java-analyzer baseline <PATH> [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output baseline file | `java-analyzer-baseline.json` |
| `--description` | Description for the baseline | none |

## Examples

### Create Baseline

```bash
java-analyzer baseline ./src -o baseline.json
```

Output:
```
Success: Baseline created with 45 issues
Saved to: baseline.json
```

### With Description

```bash
java-analyzer baseline ./src -o baseline.json --description "Release 1.0 baseline"
```

## Baseline File Format

```json
{
  "version": "1.0",
  "created_at": "2024-01-15T10:30:00Z",
  "description": "Release 1.0 baseline",
  "fingerprints": [
    {
      "rule_id": "S106",
      "file": "src/Main.java",
      "line": 25,
      "context_hash": null
    }
  ]
}
```

## Use Cases

1. **Track New Issues in PRs** - Compare PR against main branch baseline
2. **Release Validation** - Ensure no new issues since last release
3. **Technical Debt Tracking** - Monitor issue count over time

## See Also

- [diff](./diff.md) - Compare against baseline
