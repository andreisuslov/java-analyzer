//! Complexity analysis rules
//!
//! Rules that detect overly complex code that is hard to understand and maintain.

use crate::rules::{Rule, Severity, RuleCategory, Issue, AnalysisContext, create_issue};
use once_cell::sync::Lazy;
use regex::Regex;

/// S3776: Cognitive Complexity of methods should not be too high
pub struct S3776CognitiveComplexity;

impl S3776CognitiveComplexity {
    /// Calculate cognitive complexity for a method
    fn calculate_complexity(&self, method_body: &str) -> usize {
        let mut complexity = 0;
        let mut nesting_level = 0;

        let lines: Vec<&str> = method_body.lines().collect();

        for line in &lines {
            let trimmed = line.trim();

            // Track nesting
            let opens = line.matches('{').count();
            let closes = line.matches('}').count();

            // Control flow structures add to complexity
            // They also increase nesting penalty for nested structures
            if trimmed.starts_with("if") && trimmed.contains("(") {
                complexity += 1 + nesting_level;
                nesting_level += 1;
            } else if trimmed.starts_with("else if") {
                complexity += 1; // No nesting penalty for else if
            } else if trimmed.starts_with("else") && !trimmed.starts_with("else if") {
                complexity += 1;
            } else if trimmed.starts_with("for") && trimmed.contains("(") {
                complexity += 1 + nesting_level;
                nesting_level += 1;
            } else if trimmed.starts_with("while") && trimmed.contains("(") {
                complexity += 1 + nesting_level;
                nesting_level += 1;
            } else if trimmed.starts_with("do") {
                complexity += 1 + nesting_level;
                nesting_level += 1;
            } else if trimmed.starts_with("switch") {
                complexity += 1 + nesting_level;
                nesting_level += 1;
            } else if trimmed.starts_with("try") {
                complexity += 1 + nesting_level;
                nesting_level += 1;
            } else if trimmed.starts_with("catch") {
                complexity += 1;
            } else if trimmed.starts_with("finally") {
                complexity += 1;
            }

            // Logical operators add complexity
            complexity += line.matches("&&").count();
            complexity += line.matches("||").count();

            // Ternary operators
            complexity += line.matches('?').count();

            // Handle closing braces for nesting
            if closes > opens && nesting_level > 0 {
                nesting_level = nesting_level.saturating_sub(closes - opens);
            }
        }

        complexity
    }
}

impl Rule for S3776CognitiveComplexity {
    fn id(&self) -> &str { "S3776" }
    fn title(&self) -> &str { "Cognitive Complexity should not be too high" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }
    fn description(&self) -> &str {
        "Methods with high cognitive complexity are hard to understand and maintain."
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{").unwrap()
        });

        let max_complexity = ctx.config.max_complexity;
        let mut issues = Vec::new();

        for cap in METHOD_RE.captures_iter(ctx.source) {
            let method_name = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let match_start = cap.get(0).unwrap().start();
            let line_num = ctx.source[..match_start].lines().count() + 1;

            // Extract method body
            let rest = &ctx.source[match_start..];
            let mut brace_count = 0;
            let mut body_start = None;
            let mut body_end = None;

            for (i, c) in rest.char_indices() {
                if c == '{' {
                    if body_start.is_none() {
                        body_start = Some(i);
                    }
                    brace_count += 1;
                } else if c == '}' {
                    brace_count -= 1;
                    if brace_count == 0 {
                        body_end = Some(i);
                        break;
                    }
                }
            }

            if let (Some(start), Some(end)) = (body_start, body_end) {
                let method_body = &rest[start..=end];
                let complexity = self.calculate_complexity(method_body);

                if complexity > max_complexity {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Method '{}' has cognitive complexity of {} (max: {}). Refactor to reduce complexity.",
                            method_name, complexity, max_complexity
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S1541: Cyclomatic Complexity should not be too high
pub struct S1541CyclomaticComplexity;

impl S1541CyclomaticComplexity {
    fn calculate_cyclomatic(&self, method_body: &str) -> usize {
        let mut complexity = 1; // Base complexity

        // Count decision points
        static DECISION_POINTS: Lazy<Vec<Regex>> = Lazy::new(|| {
            vec![
                Regex::new(r"\bif\s*\(").unwrap(),
                Regex::new(r"\belse\s+if\s*\(").unwrap(),
                Regex::new(r"\bfor\s*\(").unwrap(),
                Regex::new(r"\bwhile\s*\(").unwrap(),
                Regex::new(r"\bdo\s*\{").unwrap(),
                Regex::new(r"\bcase\s+").unwrap(),
                Regex::new(r"\bcatch\s*\(").unwrap(),
                Regex::new(r"\?").unwrap(),
                Regex::new(r"&&").unwrap(),
                Regex::new(r"\|\|").unwrap(),
            ]
        });

        for re in DECISION_POINTS.iter() {
            complexity += re.find_iter(method_body).count();
        }

        complexity
    }
}

impl Rule for S1541CyclomaticComplexity {
    fn id(&self) -> &str { "S1541" }
    fn title(&self) -> &str { "Cyclomatic Complexity should not be too high" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }
    fn description(&self) -> &str {
        "Methods with high cyclomatic complexity have many execution paths and are hard to test."
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{").unwrap()
        });

        const MAX_CYCLOMATIC: usize = 10;
        let mut issues = Vec::new();

        for cap in METHOD_RE.captures_iter(ctx.source) {
            let method_name = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let match_start = cap.get(0).unwrap().start();
            let line_num = ctx.source[..match_start].lines().count() + 1;

            // Extract method body
            let rest = &ctx.source[match_start..];
            let mut brace_count = 0;
            let mut body_start = None;
            let mut body_end = None;

            for (i, c) in rest.char_indices() {
                if c == '{' {
                    if body_start.is_none() {
                        body_start = Some(i);
                    }
                    brace_count += 1;
                } else if c == '}' {
                    brace_count -= 1;
                    if brace_count == 0 {
                        body_end = Some(i);
                        break;
                    }
                }
            }

            if let (Some(start), Some(end)) = (body_start, body_end) {
                let method_body = &rest[start..=end];
                let complexity = self.calculate_cyclomatic(method_body);

                if complexity > MAX_CYCLOMATIC {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Method '{}' has cyclomatic complexity of {} (max: {}). Split into smaller methods.",
                            method_name, complexity, MAX_CYCLOMATIC
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S138: Methods should not have too many lines
pub struct S138MethodTooLong;

impl Rule for S138MethodTooLong {
    fn id(&self) -> &str { "S138" }
    fn title(&self) -> &str { "Methods should not be too long" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }
    fn description(&self) -> &str {
        "Long methods are hard to understand. Split them into smaller methods."
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{").unwrap()
        });

        const MAX_LINES: usize = 100;
        let mut issues = Vec::new();

        for cap in METHOD_RE.captures_iter(ctx.source) {
            let method_name = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let match_start = cap.get(0).unwrap().start();
            let line_num = ctx.source[..match_start].lines().count() + 1;

            // Extract method body
            let rest = &ctx.source[match_start..];
            let mut brace_count = 0;
            let mut body_start = None;
            let mut body_end = None;

            for (i, c) in rest.char_indices() {
                if c == '{' {
                    if body_start.is_none() {
                        body_start = Some(i);
                    }
                    brace_count += 1;
                } else if c == '}' {
                    brace_count -= 1;
                    if brace_count == 0 {
                        body_end = Some(i);
                        break;
                    }
                }
            }

            if let (Some(start), Some(end)) = (body_start, body_end) {
                let method_body = &rest[start..=end];
                let line_count = method_body.lines().count();

                if line_count > MAX_LINES {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Method '{}' has {} lines (max: {}). Split into smaller methods.",
                            method_name, line_count, MAX_LINES
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S1200: Classes should not be coupled to too many other classes
pub struct S1200ClassCoupling;

impl Rule for S1200ClassCoupling {
    fn id(&self) -> &str { "S1200" }
    fn title(&self) -> &str { "Classes should not be coupled to too many classes" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }
    fn description(&self) -> &str {
        "High coupling makes classes hard to reuse and maintain independently."
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        use std::collections::HashSet;

        static IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"import\s+[\w.]+\.(\w+)\s*;").unwrap()
        });
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"class\s+(\w+)").unwrap()
        });

        const MAX_COUPLING: usize = 20;
        let mut issues = Vec::new();

        // Collect imported classes
        let mut coupled_classes: HashSet<String> = HashSet::new();
        for cap in IMPORT_RE.captures_iter(ctx.source) {
            if let Some(class) = cap.get(1) {
                coupled_classes.insert(class.as_str().to_string());
            }
        }

        // Get class name
        if let Some(cap) = CLASS_RE.captures(ctx.source) {
            if let Some(class_name) = cap.get(1) {
                let coupling_count = coupled_classes.len();
                if coupling_count > MAX_COUPLING {
                    let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Class '{}' is coupled to {} other classes (max: {}). Consider reducing dependencies.",
                            class_name.as_str(), coupling_count, MAX_COUPLING
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S1448: Classes should not have too many methods
pub struct S1448TooManyMethods;

impl Rule for S1448TooManyMethods {
    fn id(&self) -> &str { "S1448" }
    fn title(&self) -> &str { "Classes should not have too many methods" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+(?:static\s+)?(?:\w+)\s+\w+\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{").unwrap()
        });
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"class\s+(\w+)").unwrap()
        });

        const MAX_METHODS: usize = 35;
        let mut issues = Vec::new();

        let method_count = METHOD_RE.find_iter(ctx.source).count();

        if method_count > MAX_METHODS {
            if let Some(cap) = CLASS_RE.captures(ctx.source) {
                if let Some(class_name) = cap.get(1) {
                    let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Class '{}' has {} methods (max: {}). Split into smaller classes.",
                            class_name.as_str(), method_count, MAX_METHODS
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S1820: Classes should not have too many fields
pub struct S1820TooManyFields;

impl Rule for S1820TooManyFields {
    fn id(&self) -> &str { "S1820" }
    fn title(&self) -> &str { "Classes should not have too many fields" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static FIELD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?(?:\w+)\s+\w+\s*[=;]").unwrap()
        });
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"class\s+(\w+)").unwrap()
        });

        const MAX_FIELDS: usize = 20;
        let mut issues = Vec::new();

        let field_count = FIELD_RE.find_iter(ctx.source).count();

        if field_count > MAX_FIELDS {
            if let Some(cap) = CLASS_RE.captures(ctx.source) {
                if let Some(class_name) = cap.get(1) {
                    let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Class '{}' has {} fields (max: {}). Consider splitting or using composition.",
                            class_name.as_str(), field_count, MAX_FIELDS
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S104: Files should not have too many lines of code
pub struct S104FileTooLong;

impl Rule for S104FileTooLong {
    fn id(&self) -> &str { "S104" }
    fn title(&self) -> &str { "Files should not have too many lines" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        const MAX_LINES: usize = 1000;
        let mut issues = Vec::new();

        let line_count = ctx.source.lines().count();

        if line_count > MAX_LINES {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                format!(
                    "File has {} lines (max: {}). Split into multiple files.",
                    line_count, MAX_LINES
                ),
                None,
            ));
        }
        issues
    }
}

/// S1151: Switch cases should not have too many lines
pub struct S1151SwitchCaseTooLong;

impl Rule for S1151SwitchCaseTooLong {
    fn id(&self) -> &str { "S1151" }
    fn title(&self) -> &str { "Switch cases should not have too many lines" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        const MAX_CASE_LINES: usize = 5;
        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();
        let mut case_start: Option<usize> = None;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("case ") || trimmed.starts_with("default:") {
                // Check previous case
                if let Some(start) = case_start {
                    let case_lines = line_num - start;
                    if case_lines > MAX_CASE_LINES {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            start + 1,
                            1,
                            format!("Case has {} lines (max: {}). Extract to a method.", case_lines, MAX_CASE_LINES),
                            None,
                        ));
                    }
                }
                case_start = Some(line_num);
            }
        }
        issues
    }
}

/// S1067: Expressions should not be too complex
pub struct S1067ExpressionComplexity;

impl Rule for S1067ExpressionComplexity {
    fn id(&self) -> &str { "S1067" }
    fn title(&self) -> &str { "Expressions should not be too complex" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Complexity }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        const MAX_OPERATORS: usize = 3;
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            // Count logical operators in the line
            let and_count = line.matches("&&").count();
            let or_count = line.matches("||").count();
            let total = and_count + or_count;

            if total > MAX_OPERATORS {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    format!("Expression has {} logical operators (max: {}). Extract to variables.", total, MAX_OPERATORS),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// ============================================================================
// Additional complexity rules
// ============================================================================

macro_rules! complexity_rule {
    ($struct_name:ident, $id:expr, $title:expr, $severity:expr, $pattern:expr, $message:expr) => {
        pub struct $struct_name;
        impl Rule for $struct_name {
            fn id(&self) -> &str { $id }
            fn title(&self) -> &str { $title }
            fn severity(&self) -> Severity { $severity }
            fn category(&self) -> RuleCategory { RuleCategory::Complexity }
            fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
                static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pattern).unwrap());
                let mut issues = Vec::new();
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if RE.is_match(line) && !line.trim().starts_with("//") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            $message.to_string(), Some(line.trim().to_string())));
                    }
                }
                issues
            }
        }
    };
}

// S1068B: Deep inheritance hierarchy
complexity_rule!(S1068BDeepInherit, "S1068B", "Deep inheritance hierarchy",
    Severity::Major, r"extends\s+\w+\s+extends",
    "Consider using composition over inheritance.");

// S1069: Constructor chain complexity
complexity_rule!(S1069CtorChain, "S1069", "Constructor chain is too long",
    Severity::Major, r"this\s*\([^)]+\)[^}]*this\s*\(",
    "Simplify constructor chain.");

// S1070: Too many constructors
complexity_rule!(S1070ManyCtors, "S1070", "Class has too many constructors",
    Severity::Major, r"public\s+\w+\s*\([^)]*\)\s*\{[^}]+public\s+\w+\s*\(",
    "Consider using builder pattern.");

// S1071: Deep lambda nesting
complexity_rule!(S1071DeepLambda, "S1071", "Lambda nesting is too deep",
    Severity::Major, r"->\s*\{[^}]*->\s*\{[^}]*->",
    "Extract nested lambdas to methods.");

// S1072: Complex ternary expression
complexity_rule!(S1072ComplexTernary, "S1072", "Complex ternary expression",
    Severity::Major, r"\?\s*[^:]+\?\s*[^:]+:",
    "Replace nested ternary with if-else.");

// S1073: Too many parameters in lambda
complexity_rule!(S1073LambdaParams, "S1073", "Lambda has too many parameters",
    Severity::Major, r"\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*->",
    "Lambda has too many parameters.");

// S1074: Method chain too long
complexity_rule!(S1074LongChain, "S1074", "Method chain is too long",
    Severity::Major, r"\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\(",
    "Break long method chains into variables.");

// S1075B: Too many local variables
complexity_rule!(S1075BLocalVars, "S1075B", "Method has too many local variables",
    Severity::Major, r"(?:int|String|boolean|double|long)\s+\w+\s*[=;].*(?:int|String|boolean)\s+\w+\s*[=;].*(?:int|String|boolean)",
    "Reduce number of local variables.");

// S1076: Deeply nested stream operations
complexity_rule!(S1076DeepStream, "S1076", "Deeply nested stream operations",
    Severity::Major, r"\.stream\(\)[^;]*\.flatMap[^;]*\.flatMap",
    "Simplify nested stream operations.");

// S1077: Too many catch clauses
complexity_rule!(S1077ManyCatch, "S1077", "Too many catch clauses",
    Severity::Major, r"catch\s*\([^}]+catch\s*\([^}]+catch\s*\([^}]+catch\s*\(",
    "Consider multi-catch or restructuring.");

// S1078: Complex boolean assignment
complexity_rule!(S1078ComplexBoolAssign, "S1078", "Complex boolean assignment",
    Severity::Major, r"boolean\s+\w+\s*=\s*[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)",
    "Simplify boolean expression.");

// S1079: Too many type parameters
complexity_rule!(S1079ManyTypeParams, "S1079", "Too many type parameters",
    Severity::Major, r"<\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*>",
    "Consider reducing type parameters.");

// S1080: Complex generic type
complexity_rule!(S1080ComplexGeneric, "S1080", "Complex generic type",
    Severity::Major, r"<[^>]+<[^>]+<[^>]+>",
    "Simplify nested generic types.");

// S1081: Deep if nesting
complexity_rule!(S1081DeepIf, "S1081", "Deep if nesting",
    Severity::Major, r"if\s*\([^{]+\{[^}]*if\s*\([^{]+\{[^}]*if\s*\([^{]+\{[^}]*if\s*\(",
    "Reduce if nesting depth.");

// S1082: Complex annotation usage
complexity_rule!(S1082ComplexAnnotation, "S1082", "Complex annotation usage",
    Severity::Minor, r"@\w+\s*\([^)]{100,}\)",
    "Consider simplifying annotation configuration.");

// S1083: Too many return statements
complexity_rule!(S1083ManyReturns, "S1083", "Too many return statements",
    Severity::Major, r"return\s+[^;]+;[^}]+return\s+[^;]+;[^}]+return\s+[^;]+;[^}]+return\s+[^;]+;[^}]+return",
    "Reduce number of return statements.");

// S1084: Too many break/continue
complexity_rule!(S1084ManyBreaks, "S1084", "Too many break or continue statements",
    Severity::Major, r"(?:break|continue)\s*;[^}]*(?:break|continue)\s*;[^}]*(?:break|continue)\s*;",
    "Simplify control flow.");

// S1085: Complex initialization
complexity_rule!(S1085ComplexInit, "S1085", "Complex field initialization",
    Severity::Major, r"private\s+\w+\s+\w+\s*=\s*[^;]{100,};",
    "Extract complex initialization to method.");

// S1086: Complex import structure
complexity_rule!(S1086ComplexImport, "S1086", "Complex import structure",
    Severity::Minor, r"import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;\s*import\s+[\w.]+\s*;",
    "Too many imports, consider organizing.");

// S1087: Complex enum
complexity_rule!(S1087ComplexEnum, "S1087", "Complex enum with too many members",
    Severity::Major, r"enum\s+\w+\s*\{[^}]{500,}\}",
    "Consider splitting large enum.");

// S1088: Complex interface
complexity_rule!(S1088ComplexInterface, "S1088", "Interface is too complex",
    Severity::Major, r"interface\s+\w+[^{]*\{[^}]{1000,}\}",
    "Split large interface.");

// S1089: Too many annotations
complexity_rule!(S1089ManyAnnotations, "S1089", "Too many annotations on element",
    Severity::Minor, r"@\w+[^@]*@\w+[^@]*@\w+[^@]*@\w+[^@]*@\w+",
    "Consider reducing annotation count.");

// S1090: Complex exception handling
complexity_rule!(S1090ComplexException, "S1090", "Complex exception handling",
    Severity::Major, r"throws\s+\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+",
    "Reduce number of thrown exceptions.");

// S1091: Deep anonymous class
complexity_rule!(S1091DeepAnonymous, "S1091", "Deeply nested anonymous class",
    Severity::Major, r"new\s+\w+\s*\(\s*\)\s*\{[^}]*new\s+\w+\s*\(\s*\)\s*\{",
    "Extract anonymous class to named class.");

// S1092: Complex condition
complexity_rule!(S1092ComplexCondition, "S1092", "Complex condition expression",
    Severity::Major, r"if\s*\([^)]{80,}\)",
    "Extract complex condition to method.");

// S1093: Too many static imports
complexity_rule!(S1093ManyStaticImport, "S1093", "Too many static imports",
    Severity::Minor, r"import\s+static[^;]+;\s*import\s+static[^;]+;\s*import\s+static[^;]+;\s*import\s+static[^;]+;\s*import\s+static",
    "Reduce static imports.");

// S1094: Complex string operation
complexity_rule!(S1094ComplexString, "S1094", "Complex string operation",
    Severity::Minor, r"\.replace[^;]+\.replace[^;]+\.replace[^;]+\.replace",
    "Consider using regex for complex replacements.");

// S1095: Too many inner classes
complexity_rule!(S1095ManyInner, "S1095", "Too many inner classes",
    Severity::Major, r"class\s+\w+[^}]*class\s+\w+[^}]*class\s+\w+[^}]*class\s+\w+",
    "Move inner classes to separate files.");

// S1096: Complex array initialization
complexity_rule!(S1096ComplexArray, "S1096", "Complex array initialization",
    Severity::Minor, r"new\s+\w+\[\]\s*\{[^}]{200,}\}",
    "Move large array initialization to separate method.");

// S1097: Complex map initialization
complexity_rule!(S1097ComplexMap, "S1097", "Complex map initialization",
    Severity::Minor, r"Map\.of\s*\([^)]{100,}\)|Map\.ofEntries\s*\([^)]{100,}\)",
    "Consider using builder pattern for complex maps.");

// S1098: Too many type casts
complexity_rule!(S1098ManyTypeCast, "S1098", "Too many type casts in expression",
    Severity::Major, r"\(\s*\w+\s*\)[^;]*\(\s*\w+\s*\)[^;]*\(\s*\w+\s*\)",
    "Consider redesigning to avoid casts.");

// S1099: Complex regex
complexity_rule!(S1099ComplexRegex, "S1099", "Complex regular expression",
    Severity::Major, r#"Pattern\.compile\s*\(\s*"[^"]{50,}""#,
    "Consider breaking complex regex into parts.");

// S1100: Deep class nesting
complexity_rule!(S1100DeepClass, "S1100", "Deep class nesting",
    Severity::Major, r"class\s+\w+[^}]*\{[^}]*class\s+\w+[^}]*\{[^}]*class\s+\w+",
    "Reduce class nesting depth.");

// ============================================================================
// Batch 3 - Additional complexity rules
// ============================================================================

// S1101: Complex constructor
complexity_rule!(S1101ComplexCtor, "S1101", "Complex constructor",
    Severity::Major, r"public\s+\w+\s*\([^)]{100,}\)",
    "Simplify constructor or use builder pattern.");

// S1102: Too many method calls in expression
complexity_rule!(S1102ManyMethodCalls, "S1102", "Too many method calls in expression",
    Severity::Minor, r"\.\w+\(\)[^;]*\.\w+\(\)[^;]*\.\w+\(\)[^;]*\.\w+\(\)[^;]*\.\w+\(\)",
    "Break expression into separate statements.");

// S1103B: Complex ternary chain
complexity_rule!(S1103BTernaryChain, "S1103B", "Complex ternary chain",
    Severity::Major, r"\?\s*[^:]+:\s*[^?]+\?\s*[^:]+:\s*[^?]+\?\s*[^:]+:",
    "Replace ternary chain with if-else or map.");

// S1104B: Too many arguments
complexity_rule!(S1104BManyArgs, "S1104B", "Too many arguments in method call",
    Severity::Major, r"\.\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*,",
    "Consider using builder or parameter object.");

// S1105: Complex stream pipeline
complexity_rule!(S1105ComplexStream, "S1105", "Complex stream pipeline",
    Severity::Major, r"\.stream\(\)[^;]*\.filter[^;]*\.map[^;]*\.filter[^;]*\.map",
    "Simplify stream pipeline.");

// S1106B: Deep switch
complexity_rule!(S1106BDeepSwitch, "S1106B", "Deep switch nesting",
    Severity::Major, r"switch\s*\([^{]+\{[^}]*switch\s*\(",
    "Avoid nested switch statements.");

// S1107B: Too many variables in scope
complexity_rule!(S1107BScopeVars, "S1107B", "Too many variables in scope",
    Severity::Major, r"void\s+\w+\s*\([^)]*\)\s*\{[^}]*(?:int|String|boolean)[^}]*(?:int|String|boolean)[^}]*(?:int|String|boolean)[^}]*(?:int|String|boolean)[^}]*(?:int|String|boolean)[^}]*(?:int|String|boolean)[^}]*(?:int|String|boolean)",
    "Reduce scope size or extract method.");

// S1108: Complex for loop
complexity_rule!(S1108ComplexFor, "S1108", "Complex for loop",
    Severity::Major, r"for\s*\([^;]+;[^;]{40,};[^)]+\)",
    "Simplify for loop conditions.");

// S1109: Complex while condition
complexity_rule!(S1109ComplexWhile, "S1109", "Complex while condition",
    Severity::Major, r"while\s*\([^)]{60,}\)",
    "Extract complex condition to variable.");

// S1110: Complex catch block
complexity_rule!(S1110ComplexCatch, "S1110", "Complex catch block",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{[^}]{200,}\}",
    "Simplify catch block logic.");

// S1111B: Too many statements in method
complexity_rule!(S1111BManyStatements, "S1111B", "Too many statements in method",
    Severity::Major, r"void\s+\w+\s*\([^)]*\)\s*\{[^}]{1500,}\}",
    "Method has too many statements.");

// S1112: Complex object creation
complexity_rule!(S1112ComplexObject, "S1112", "Complex object creation",
    Severity::Minor, r"new\s+\w+\s*\([^)]*new\s+\w+\s*\([^)]*new\s+\w+",
    "Simplify nested object creation.");

// S1113: Too many parameters in generic
complexity_rule!(S1113ManyGenericParams, "S1113", "Too many parameters in generic",
    Severity::Minor, r"<\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*>",
    "Consider reducing generic parameters.");

// S1114B: Complex static initializer
complexity_rule!(S1114BComplexStaticInit, "S1114B", "Complex static initializer",
    Severity::Major, r"static\s*\{[^}]{200,}\}",
    "Simplify static initializer block.");

// S1115: Too many string operations
complexity_rule!(S1115ManyStringOps, "S1115", "Too many string operations",
    Severity::Minor, r"\.substring[^;]+\.substring[^;]+\.substring",
    "Simplify string operations.");

// S1116B: Complex collection operation
complexity_rule!(S1116BComplexCollection, "S1116B", "Complex collection operation",
    Severity::Major, r"\.addAll[^;]+\.removeAll[^;]+\.retainAll",
    "Simplify collection operations.");

// S1117B: Too many loop variables
complexity_rule!(S1117BLoopVars, "S1117B", "Too many loop variables",
    Severity::Minor, r"for\s*\(\s*\w+\s+\w+\s*,\s*\w+\s*,\s*\w+\s*;",
    "Reduce loop variable count.");

// S1118B: Complex lambda expression
complexity_rule!(S1118BComplexLambda, "S1118B", "Complex lambda expression",
    Severity::Major, r"->\s*\{[^}]{100,}\}",
    "Extract complex lambda to method.");

// S1119B: Too many boolean operators
complexity_rule!(S1119BManyBoolOps, "S1119B", "Too many boolean operators",
    Severity::Major, r"(?:&&|\|\|)[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)",
    "Simplify boolean expression.");

// S1120B: Complex assignment
complexity_rule!(S1120BComplexAssign, "S1120B", "Complex assignment expression",
    Severity::Major, r"=\s*[^;]{80,};",
    "Break complex assignment into steps.");

// S1121B: Too many casts in expression
complexity_rule!(S1121BManyTypes, "S1121B", "Too many type operations",
    Severity::Minor, r"instanceof[^;]*instanceof[^;]*instanceof",
    "Consider redesigning type checks.");

// S1122B: Complex error handling
complexity_rule!(S1122BComplexError, "S1122B", "Complex error handling",
    Severity::Major, r"catch\s*\([^)]+\)[^}]*catch\s*\([^)]+\)[^}]*finally",
    "Simplify error handling structure.");

// S1123B: Too many comparisons
complexity_rule!(S1123BManyCompare, "S1123B", "Too many comparisons",
    Severity::Major, r"(?:==|!=|<=|>=|<|>)[^;]*(?:==|!=|<=|>=|<|>)[^;]*(?:==|!=|<=|>=|<|>)[^;]*(?:==|!=|<=|>=|<|>)",
    "Simplify comparison logic.");

/// Create all complexity rules
pub fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(S3776CognitiveComplexity),
        Box::new(S1541CyclomaticComplexity),
        Box::new(S138MethodTooLong),
        Box::new(S1200ClassCoupling),
        Box::new(S1448TooManyMethods),
        Box::new(S1820TooManyFields),
        Box::new(S104FileTooLong),
        Box::new(S1151SwitchCaseTooLong),
        Box::new(S1067ExpressionComplexity),
        // Additional complexity rules
        Box::new(S1068BDeepInherit),
        Box::new(S1069CtorChain),
        Box::new(S1070ManyCtors),
        Box::new(S1071DeepLambda),
        Box::new(S1072ComplexTernary),
        Box::new(S1073LambdaParams),
        Box::new(S1074LongChain),
        Box::new(S1075BLocalVars),
        Box::new(S1076DeepStream),
        Box::new(S1077ManyCatch),
        Box::new(S1078ComplexBoolAssign),
        Box::new(S1079ManyTypeParams),
        Box::new(S1080ComplexGeneric),
        Box::new(S1081DeepIf),
        Box::new(S1082ComplexAnnotation),
        Box::new(S1083ManyReturns),
        Box::new(S1084ManyBreaks),
        Box::new(S1085ComplexInit),
        Box::new(S1086ComplexImport),
        Box::new(S1087ComplexEnum),
        Box::new(S1088ComplexInterface),
        Box::new(S1089ManyAnnotations),
        Box::new(S1090ComplexException),
        Box::new(S1091DeepAnonymous),
        Box::new(S1092ComplexCondition),
        Box::new(S1093ManyStaticImport),
        Box::new(S1094ComplexString),
        Box::new(S1095ManyInner),
        Box::new(S1096ComplexArray),
        Box::new(S1097ComplexMap),
        Box::new(S1098ManyTypeCast),
        Box::new(S1099ComplexRegex),
        Box::new(S1100DeepClass),
        // Batch 3 - additional complexity rules
        Box::new(S1101ComplexCtor),
        Box::new(S1102ManyMethodCalls),
        Box::new(S1103BTernaryChain),
        Box::new(S1104BManyArgs),
        Box::new(S1105ComplexStream),
        Box::new(S1106BDeepSwitch),
        Box::new(S1107BScopeVars),
        Box::new(S1108ComplexFor),
        Box::new(S1109ComplexWhile),
        Box::new(S1110ComplexCatch),
        Box::new(S1111BManyStatements),
        Box::new(S1112ComplexObject),
        Box::new(S1113ManyGenericParams),
        Box::new(S1114BComplexStaticInit),
        Box::new(S1115ManyStringOps),
        Box::new(S1116BComplexCollection),
        Box::new(S1117BLoopVars),
        Box::new(S1118BComplexLambda),
        Box::new(S1119BManyBoolOps),
        Box::new(S1120BComplexAssign),
        Box::new(S1121BManyTypes),
        Box::new(S1122BComplexError),
        Box::new(S1123BManyCompare),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalyzerConfig;

    fn create_test_context(source: &str) -> (tree_sitter::Tree, AnalyzerConfig) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let config = AnalyzerConfig::default();
        (tree, config)
    }

    #[test]
    fn test_s3776_cognitive_complexity() {
        let source = r#"
            public class Test {
                public void complex() {
                    if (a) {
                        if (b) {
                            if (c) {
                                while (d) {
                                    for (int i = 0; i < 10; i++) {
                                        if (e && f || g) {
                                            try {
                                                doSomething();
                                            } catch (Exception ex) {
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        let issues = S3776CognitiveComplexity.check(&ctx);
        assert!(!issues.is_empty(), "Should detect high cognitive complexity");
    }

    #[test]
    fn test_s3776_simple_method() {
        let source = r#"
            public class Test {
                public void simple() {
                    if (a) {
                        doSomething();
                    }
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        let issues = S3776CognitiveComplexity.check(&ctx);
        assert!(issues.is_empty(), "Simple method should not trigger complexity warning");
    }

    #[test]
    fn test_s1067_expression_complexity() {
        let source = r#"
            public class Test {
                void test() {
                    if (a && b && c && d && e) {}  // too complex
                    if (a && b) {}                  // ok
                }
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        let issues = S1067ExpressionComplexity.check(&ctx);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_s104_file_too_long() {
        // Generate a source with more than 1000 lines
        let mut source = String::from("public class Test {\n");
        for i in 0..1005 {
            source.push_str(&format!("    int field{} = {};\n", i, i));
        }
        source.push_str("}\n");

        let (tree, config) = create_test_context(&source);
        let ctx = AnalysisContext {
            source: &source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        let issues = S104FileTooLong.check(&ctx);
        assert_eq!(issues.len(), 1);
    }
}
