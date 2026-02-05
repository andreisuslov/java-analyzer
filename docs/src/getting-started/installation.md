# Installation

## From Source (Recommended)

```bash
# Clone and build
git clone https://github.com/andreisuslov/java-analyzer.git
cd java-analyzer
cargo build --release

# Install to path
cargo install --path .
```

## Using Cargo

```bash
cargo install --git https://github.com/andreisuslov/java-analyzer.git
```

## Pre-built Binaries

Download from [GitHub Releases](https://github.com/andreisuslov/java-analyzer/releases):

| Platform | Download |
|----------|----------|
| Linux x64 | `java-analyzer-linux` |
| macOS x64 | `java-analyzer-macos` |
| Windows | `java-analyzer.exe` |

## GitHub Action

Add to your workflow:

```yaml
- name: Run Java Analyzer
  uses: andreisuslov/java-analyzer@v1
  with:
    path: './src'
    min-severity: 'major'
    fail-on-severity: 'critical'
```

## Verify Installation

```bash
java-analyzer --version
# Java Analyzer 1.0.0
```

## Requirements

- Rust 1.70+ (for building from source)
- No runtime dependencies
