# init

Generate a sample configuration file.

## Usage

```bash
java-analyzer init [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output file path | `java-analyzer.toml` |

## Example

```bash
java-analyzer init
```

Output:
```
Success: Configuration written to java-analyzer.toml
```

## Generated Config

```toml
# Java Analyzer Configuration
# Generated configuration file

# Minimum severity level to report
# Options: info, minor, major, critical, blocker
min_severity = "info"

# Maximum cognitive complexity threshold
max_complexity = 15

# Rules to enable (if specified, only these rules will run)
# enabled_rules = ["S100", "S101", "S2068"]

# Rules to disable
disabled_rules = []

# Path patterns to exclude from analysis
exclude_patterns = [
    "target/",
    "build/",
    "node_modules/",
    ".git/",
    "**/generated/**",
    "**/test/**"
]

# Output format
# Options: text, json, html, sarif, csv, markdown
output_format = "text"

# Fail if issues of this severity or higher are found
# Options: info, minor, major, critical, blocker
# fail_on_severity = "major"
```

## Custom Output Path

```bash
java-analyzer init -o .java-analyzer.toml
```
