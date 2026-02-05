# coverage

Import and display test coverage from JaCoCo or LCOV reports.

## Usage

```bash
java-analyzer coverage <REPORT_FILE> [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--threshold` | Minimum coverage percentage | `80` |
| `-f, --format` | Output format (text, json) | `text` |

## Supported Formats

- **JaCoCo XML** - `jacoco.xml`
- **LCOV** - `coverage.info`, `lcov.info`

## Examples

### Import JaCoCo Report

```bash
java-analyzer coverage target/site/jacoco/jacoco.xml
```

Output:
```
Test Coverage Report
====================

Overall Coverage: 78.5% (threshold: 80.0%)
Files with coverage: 25
Lines covered:   1850
Lines uncovered: 505

Files Below 80% Threshold:
  45.2% - src/LegacyService.java
  62.1% - src/DataProcessor.java
  71.8% - src/Utils.java
```

### Custom Threshold

```bash
java-analyzer coverage jacoco.xml --threshold 70
```

### JSON Output

```bash
java-analyzer coverage jacoco.xml --format json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Coverage meets threshold |
| 1 | Coverage below threshold |

## CI Integration

```yaml
- name: Run tests with coverage
  run: mvn test jacoco:report

- name: Check coverage
  run: java-analyzer coverage target/site/jacoco/jacoco.xml --threshold 80
```

## Generating Coverage Reports

### Maven (JaCoCo)

```xml
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>0.8.8</version>
  <executions>
    <execution>
      <goals><goal>report</goal></goals>
    </execution>
  </executions>
</plugin>
```

### Gradle (JaCoCo)

```groovy
plugins {
    id 'jacoco'
}

jacocoTestReport {
    reports {
        xml.required = true
    }
}
```
