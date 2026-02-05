# Rules Reference

Java Analyzer implements 80+ rules based on SonarSource Java rules.

## Categories

### Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| S2068 | Blocker | Credentials should not be hardcoded |
| S3649 | Critical | SQL queries should not be vulnerable to injection |
| S4790 | Major | Cryptographic hash functions should be secure |
| S2078 | Critical | LDAP queries should not be vulnerable to injection |

### Bug Rules

| Rule | Severity | Description |
|------|----------|-------------|
| S1144 | Major | Unused private methods should be removed |
| S1481 | Minor | Unused local variables should be removed |
| S2259 | Critical | Null pointers should not be dereferenced |
| S2583 | Major | Conditionally executed code should be reachable |

### Code Smell Rules

| Rule | Severity | Description |
|------|----------|-------------|
| S106 | Major | Standard outputs should not be used for logging |
| S1192 | Minor | String literals should not be duplicated |
| S1450 | Minor | Private fields only used in one method |
| S3776 | Critical | Cognitive complexity of methods should not be too high |

### Naming Rules

| Rule | Severity | Description |
|------|----------|-------------|
| S100 | Minor | Method names should comply with convention |
| S101 | Minor | Class names should comply with convention |
| S115 | Minor | Constant names should comply with convention |
| S116 | Minor | Field names should comply with convention |

## OWASP Mapping

Rules are mapped to OWASP Top 10 (2021):

| OWASP Category | Rules |
|----------------|-------|
| A01 Broken Access Control | S2068, S4790 |
| A02 Cryptographic Failures | S4790, S2277 |
| A03 Injection | S3649, S2078, S2076 |
| A07 Authentication Failures | S2068, S1421 |

## CWE Mapping

| Rule | CWE ID | CWE Name |
|------|--------|----------|
| S2068 | CWE-798 | Use of Hard-coded Credentials |
| S3649 | CWE-89 | SQL Injection |
| S4790 | CWE-328 | Weak Hash |

## Technical Debt

Each rule has an estimated remediation time:

| Rule | Debt (minutes) |
|------|----------------|
| S2068 | 30 |
| S106 | 5 |
| S100 | 2 |
| S3776 | 15 |

## Disable Rules

```bash
# Via CLI
java-analyzer ./src --exclude-rules S100,S101

# Via config
disabled_rules = ["S100", "S101"]
```

## Enable Specific Rules

```bash
# Via CLI
java-analyzer ./src --rules S2068,S3649

# Via config
enabled_rules = ["S2068", "S3649"]
```
