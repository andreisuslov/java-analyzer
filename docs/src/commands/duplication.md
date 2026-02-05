# duplication

Detect code duplication in Java files.

## Usage

```bash
java-analyzer duplication <PATH> [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--min-lines` | Minimum lines to consider a duplicate | `6` |
| `--ignore-whitespace` | Ignore whitespace differences | `true` |
| `-f, --format` | Output format (text, json) | `text` |

## Examples

### Basic Duplication Check

```bash
java-analyzer duplication ./src
```

Output:
```
Code Duplication Analysis
=========================

Files analyzed:    15
Total lines:       2500
Duplicated lines:  150
Duplication rate:  6.0%

4 duplicate blocks found:

1. 2 occurrences (8 lines):
   src/UserService.java (lines 45-52)
   src/AdminService.java (lines 23-30)
   Sample:
   │ public void validateInput(String input) {
   │     if (input == null || input.isEmpty()) {
   │         throw new IllegalArgumentException("Input cannot be null");
```

### Custom Threshold

```bash
java-analyzer duplication ./src --min-lines 10
```

### JSON Output

```bash
java-analyzer duplication ./src --format json
```

## How It Works

1. Normalizes code (removes whitespace, comments)
2. Uses sliding window with configurable size
3. Hashes normalized code blocks
4. Identifies blocks with matching hashes
5. Reports duplicate locations
