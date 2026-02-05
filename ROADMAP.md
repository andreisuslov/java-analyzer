# Java Analyzer Roadmap

## Feature Gap Analysis: SonarQube vs Java Analyzer

This document outlines 25 features from SonarQube that could enhance our Java Analyzer, organized into implementation phases.

---

## Phase 1: Foundation Improvements (Weeks 1-4)

### 1. Technical Debt Quantification
**Priority:** High | **Complexity:** Medium
- Add remediation time estimates to each rule
- Calculate aggregate technical debt in minutes/hours/days
- Display debt summary in reports
- **Implementation:**
  - Add `remediation_time_minutes` field to Rule struct
  - Create debt calculation module
  - Update all report formats to show debt

### 2. Code Duplication Detection
**Priority:** High | **Complexity:** Medium
- Implement token-based duplicate detection
- Identify identical/similar code blocks (10+ lines)
- Report duplication percentage
- **Implementation:**
  - Add rolling hash algorithm for token sequences
  - Create DuplicationDetector module
  - Add `--detect-duplicates` CLI flag

### 3. Quality Gates System
**Priority:** High | **Complexity:** Medium
- Define configurable quality thresholds
- Pass/fail based on metrics (issue counts, severity, coverage)
- Exit code integration for CI/CD
- **Implementation:**
  - Create QualityGate struct with conditions
  - Add `quality-gates.json` config file support
  - Implement `--quality-gate` CLI option

### 4. OWASP/CWE Mapping
**Priority:** High | **Complexity:** Low
- Map existing security rules to OWASP Top 10
- Map rules to CWE identifiers
- Generate compliance reports
- **Implementation:**
  - Add `owasp_category` and `cwe_id` fields to rules
  - Create compliance report format
  - Add `--compliance owasp|cwe` flag

### 5. Configuration File Support
**Priority:** High | **Complexity:** Low
- Support `.java-analyzer.toml` or `.java-analyzer.json`
- Project-level rule configuration
- Severity overrides and rule exclusions
- **Implementation:**
  - Add config file discovery and parsing
  - Merge CLI args with config file settings
  - Document config file format

---

## Phase 2: Analysis Enhancements (Weeks 5-10)

### 6. Cross-File Symbol Resolution
**Priority:** High | **Complexity:** High
- Build symbol table across all files
- Resolve imports and class references
- Track method calls between files
- **Implementation:**
  - Create SymbolTable with file-to-symbol mappings
  - Two-pass analysis: collect symbols, then analyze
  - Cache symbol tables for incremental analysis

### 7. Basic Data Flow Analysis
**Priority:** High | **Complexity:** High
- Track variable assignments and usages
- Detect uninitialized variable usage
- Find unused assignments (dead stores)
- **Implementation:**
  - Build Control Flow Graph (CFG) per method
  - Implement reaching definitions analysis
  - Add data flow rules module

### 8. Taint Analysis (Basic)
**Priority:** Medium | **Complexity:** High
- Mark user input sources (HttpServletRequest, etc.)
- Track tainted data through assignments
- Flag when tainted data reaches sinks (SQL, exec)
- **Implementation:**
  - Define source/sink/sanitizer annotations
  - Implement intra-procedural taint propagation
  - Add taint-specific security rules

### 9. Test Coverage Integration
**Priority:** Medium | **Complexity:** Medium
- Import LCOV/JaCoCo coverage reports
- Correlate coverage with analyzed code
- Include coverage metrics in quality gates
- **Implementation:**
  - Add coverage report parsers (LCOV, JaCoCo XML)
  - Merge coverage data with analysis results
  - Add coverage conditions to quality gates

### 10. Incremental Analysis
**Priority:** Medium | **Complexity:** Medium
- Cache previous analysis results
- Only re-analyze changed files
- Invalidate dependents when signatures change
- **Implementation:**
  - Create analysis cache with file hashes
  - Track file dependencies for invalidation
  - Add `--cache-dir` option

---

## Phase 3: Integration Features (Weeks 11-16)

### 11. GitHub Actions Integration
**Priority:** High | **Complexity:** Low
- Create GitHub Action for marketplace
- Automatic PR annotations
- Quality gate status checks
- **Implementation:**
  - Create `action.yml` with Docker container
  - Use GitHub API for PR comments
  - Publish to GitHub Marketplace

### 12. GitLab CI Integration
**Priority:** Medium | **Complexity:** Low
- Create `.gitlab-ci.yml` template
- Code Quality report artifact format
- MR widget integration
- **Implementation:**
  - Create GitLab Code Quality JSON format
  - Document pipeline configuration
  - Add merge request notes via API

### 13. Jenkins Plugin
**Priority:** Medium | **Complexity:** Medium
- Create Jenkins pipeline step
- Build status integration
- Trend graphs in Jenkins UI
- **Implementation:**
  - Create Jenkins shared library
  - Or full Java plugin with UI components
  - Document Jenkinsfile usage

### 14. VS Code Extension
**Priority:** High | **Complexity:** Medium
- Real-time analysis as you type
- Inline issue highlighting
- Quick-fix suggestions
- **Implementation:**
  - Create VS Code extension (TypeScript)
  - Use Language Server Protocol (LSP)
  - Bundle analyzer binary

### 15. IntelliJ Plugin
**Priority:** Medium | **Complexity:** Medium
- Background analysis on file save
- Inspection integration
- Tool window for issue list
- **Implementation:**
  - Create IntelliJ plugin (Kotlin/Java)
  - Use External Annotator API
  - Publish to JetBrains Marketplace

---

## Phase 4: Advanced Analysis (Weeks 17-24)

### 16. Inter-procedural Analysis
**Priority:** Medium | **Complexity:** High
- Track data flow across method calls
- Build call graph
- Detect issues spanning multiple methods
- **Implementation:**
  - Build call graph from symbol table
  - Implement context-sensitive analysis
  - Add inter-procedural rules

### 17. Security Hotspots System
**Priority:** Medium | **Complexity:** Medium
- Distinguish vulnerabilities from hotspots
- Hotspot review workflow states
- Priority-based categorization
- **Implementation:**
  - Add `is_hotspot` field to security rules
  - Create review status tracking
  - Add hotspot-specific report section

### 18. Custom Rule Templates
**Priority:** Medium | **Complexity:** Medium
- Allow user-defined regex rules
- XPath-like rule definitions
- Rule template system
- **Implementation:**
  - Create rule definition YAML/JSON format
  - Add custom rule loader
  - Document rule authoring

### 19. Multi-Module Project Support
**Priority:** Medium | **Complexity:** Medium
- Detect Maven/Gradle multi-module projects
- Aggregate results per module
- Cross-module analysis
- **Implementation:**
  - Parse pom.xml/build.gradle for modules
  - Organize results by module
  - Add module-level quality gates

### 20. Baseline/Differential Analysis
**Priority:** High | **Complexity:** Medium
- Compare against baseline (main branch)
- Report only new issues in PRs
- Track issue introduction date
- **Implementation:**
  - Store baseline analysis results
  - Compute issue diff between runs
  - Add `--baseline` option

---

## Phase 5: Enterprise Features (Weeks 25-32)

### 21. Web Dashboard (Basic)
**Priority:** Low | **Complexity:** High
- Project overview page
- Issue browsing and filtering
- Trend charts over time
- **Implementation:**
  - Create web server (Rust/Actix or separate service)
  - SQLite/PostgreSQL for persistence
  - React/Vue frontend

### 22. Historical Trend Tracking
**Priority:** Medium | **Complexity:** Medium
- Store analysis results over time
- Generate trend graphs
- Track metrics improvement/regression
- **Implementation:**
  - Database schema for historical data
  - Time-series metrics storage
  - Trend visualization in reports

### 23. Issue Management Workflow
**Priority:** Low | **Complexity:** Medium
- Mark issues as false positive/won't fix
- Assign issues to users
- Track issue resolution
- **Implementation:**
  - Persistent issue database
  - Issue state machine
  - API for issue management

### 24. AI-Powered Fix Suggestions
**Priority:** Low | **Complexity:** High
- Integrate with OpenAI/Claude API
- Generate context-aware fixes
- Provide one-click fix application
- **Implementation:**
  - Add LLM API integration
  - Create fix suggestion prompts
  - Implement fix application logic

### 25. Additional Language Support
**Priority:** Low | **Complexity:** High
- Add Kotlin analyzer
- Add Scala analyzer
- Shared infrastructure for JVM languages
- **Implementation:**
  - Add tree-sitter grammars for each language
  - Create language-specific rule modules
  - Unified JVM analysis framework

---

## Implementation Priority Matrix

| Feature | Business Value | Complexity | Priority Score |
|---------|---------------|------------|----------------|
| Quality Gates | High | Medium | **P1** |
| Technical Debt | High | Medium | **P1** |
| OWASP/CWE Mapping | High | Low | **P1** |
| Config File Support | High | Low | **P1** |
| GitHub Actions | High | Low | **P1** |
| Cross-File Analysis | High | High | **P2** |
| VS Code Extension | High | Medium | **P2** |
| Duplication Detection | High | Medium | **P2** |
| Baseline/Diff Analysis | High | Medium | **P2** |
| Data Flow Analysis | Medium | High | **P3** |
| Taint Analysis | Medium | High | **P3** |
| Test Coverage | Medium | Medium | **P3** |

---

## Quick Wins (Can implement in 1-2 days each)

1. **OWASP/CWE Mapping** - Add metadata to existing rules
2. **Config File Support** - TOML parsing already available in Rust
3. **GitHub Actions** - Simple Docker-based action
4. **Exit Codes for CI** - Already partially implemented
5. **Technical Debt Fields** - Add time estimates to rule definitions

---

## Architecture Considerations

### For Cross-File Analysis
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Parser    │────▶│ Symbol Table │────▶│  Analyzer   │
│ (per file)  │     │  (global)    │     │(with context)│
└─────────────┘     └──────────────┘     └─────────────┘
```

### For Data Flow Analysis
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    AST      │────▶│    CFG      │────▶│  DFA Pass   │
│             │     │  Builder    │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
```

### For Web Dashboard
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   CLI Tool  │────▶│  Database   │────▶│ Web Server  │
│  (analyzer) │     │ (SQLite/PG) │     │  (API+UI)   │
└─────────────┘     └──────────────┘    └─────────────┘
```

---

## Success Metrics

- **Phase 1:** Quality gates blocking 80% of critical issues in CI
- **Phase 2:** 50% reduction in false positives with data flow
- **Phase 3:** 1000+ GitHub stars, 100+ daily active IDE users
- **Phase 4:** Detection of complex vulnerabilities (SQLi, XSS chains)
- **Phase 5:** Production deployment at 3+ organizations

---

## Next Steps

1. Create GitHub Issues for Phase 1 features
2. Set up project board for tracking
3. Begin with Quick Wins to show immediate progress
4. Gather user feedback after each phase
