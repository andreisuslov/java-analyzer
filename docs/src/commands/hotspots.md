# hotspots

Show security hotspots requiring review.

## Usage

```bash
java-analyzer hotspots <PATH> [OPTIONS]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format` | Output format (text, json) | `text` |

## Example

```bash
java-analyzer hotspots ./src
```

Output:
```
Security Hotspots
=================

Total Hotspots: 5
  High Priority:   2
  Medium Priority: 2
  Low Priority:    1

High Priority Hotspots:
  [Authentication] src/Auth.java:45 - Hard-coded credential detected
  [Injection] src/Query.java:23 - SQL query built from user input

Medium Priority Hotspots:
  [Cryptography] src/Crypto.java:12 - Weak hash algorithm (MD5)
  [Sensitive Data] src/Config.java:8 - API key in source code
```

## Hotspot Categories

| Category | Description |
|----------|-------------|
| Authentication | Login, password, session handling |
| Authorization | Access control, permissions |
| Cryptography | Encryption, hashing, keys |
| Input Validation | User input handling |
| Injection | SQL, command, LDAP injection |
| Insecure Configuration | Debug mode, weak settings |
| Sensitive Data | Credentials, PII exposure |
| XSS | Cross-site scripting |
| DoS | Denial of service |
| Logging | Security event logging |

## Priority Levels

| Priority | Criteria |
|----------|----------|
| High | High probability + High impact |
| Medium | Mixed probability/impact |
| Low | Low probability or impact |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No high-priority hotspots |
| 1 | High-priority hotspots found |
