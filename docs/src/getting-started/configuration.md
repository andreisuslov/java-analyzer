# Configuration

## Configuration File

Create `.java-analyzer.toml` in your project root:

```toml
# Minimum severity to report
min_severity = "major"

# Maximum cognitive complexity threshold
max_complexity = 15

# Rules to disable
disabled_rules = ["S100", "S101"]

# Path patterns to exclude
exclude_patterns = [
    "target/",
    "build/",
    "**/generated/**",
    "**/test/**"
]

# Fail on severity (for CI)
fail_on_severity = "critical"
```

## Generate Config Template

```bash
java-analyzer init
# Creates java-analyzer.toml with default settings
```

## Configuration Options

### Severity Levels

| Level | Description |
|-------|-------------|
| `info` | Informational suggestions |
| `minor` | Minor code improvements |
| `major` | Important issues to fix |
| `critical` | Bugs or security issues |
| `blocker` | Must fix before release |

### Complexity Threshold

```toml
# Default is 15, increase for complex codebases
max_complexity = 20
```

### Rule Management

```toml
# Enable only specific rules
enabled_rules = ["S2068", "S3649", "S106"]

# Disable specific rules
disabled_rules = ["S1451"]  # Skip copyright header check
```

### Exclude Patterns

```toml
exclude_patterns = [
    "target/",
    "build/",
    "node_modules/",
    ".git/",
    "**/generated/**",
    "**/test/**",
    "**/*Test.java"
]
```

## JSON Configuration

Alternatively use `.java-analyzer.json`:

```json
{
  "min_severity": "major",
  "max_complexity": 15,
  "disabled_rules": ["S100"],
  "exclude_patterns": ["target/", "build/"]
}
```

## Config Discovery

The analyzer searches for config files in this order:
1. `.java-analyzer.toml` in current directory
2. `java-analyzer.toml` in current directory
3. `.java-analyzer.json` in current directory
4. Search parent directories up to root

## CLI Override

CLI flags override config file settings:

```bash
# Override min-severity from config
java-analyzer ./src --min-severity critical
```
