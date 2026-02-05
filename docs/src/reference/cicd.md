# CI/CD Integration

## GitHub Actions

### Basic Workflow

```yaml
name: Code Analysis

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Java Analyzer
        run: |
          cargo install --git https://github.com/andreisuslov/java-analyzer.git

      - name: Run Analysis
        run: java-analyzer ./src --fail-on-severity critical
```

### Using GitHub Action

```yaml
- name: Java Analyzer
  uses: andreisuslov/java-analyzer@v1
  with:
    path: './src'
    min-severity: 'major'
    fail-on-severity: 'critical'
    format: 'sarif'
```

### With SARIF Upload

```yaml
- name: Run Analysis
  run: java-analyzer ./src --format sarif -o results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### PR Quality Gate

```yaml
- name: Create Baseline (main branch only)
  if: github.ref == 'refs/heads/main'
  run: |
    java-analyzer baseline ./src -o baseline.json
    # Upload as artifact for PR comparison

- name: Compare Against Baseline (PR only)
  if: github.event_name == 'pull_request'
  run: |
    # Download baseline artifact
    java-analyzer diff ./src --baseline baseline.json
```

## GitLab CI

```yaml
code-analysis:
  stage: test
  script:
    - cargo install --git https://github.com/andreisuslov/java-analyzer.git
    - java-analyzer ./src --format json -o gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

## Jenkins

### Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Analysis') {
            steps {
                sh 'java-analyzer ./src --format json -o report.json'
                archiveArtifacts artifacts: 'report.json'
            }
        }
    }
    post {
        always {
            recordIssues tools: [java()]
        }
    }
}
```

## Azure DevOps

```yaml
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      cargo install --git https://github.com/andreisuslov/java-analyzer.git
      java-analyzer ./src --format sarif -o $(Build.ArtifactStagingDirectory)/results.sarif

- task: PublishBuildArtifacts@1
  inputs:
    pathtoPublish: '$(Build.ArtifactStagingDirectory)'
    artifactName: 'CodeAnalysis'
```

## Exit Codes

Use exit codes for pipeline decisions:

| Code | Meaning | Suggested Action |
|------|---------|------------------|
| 0 | Pass | Continue pipeline |
| 1 | Fail | Block merge/deploy |

```yaml
- name: Analysis
  run: java-analyzer ./src --quality-gate strict
  # Pipeline fails if quality gate fails
```
