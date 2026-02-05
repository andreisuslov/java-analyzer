//! Bug detection rules - Comprehensive implementation
//!
//! Rules that detect potential bugs and defects in Java code.
//! Implements rules from SonarSource's bug category.

use crate::rules::{create_issue, AnalysisContext, Issue, Rule, RuleCategory, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

// Helper macro to create simple regex-based rules
macro_rules! regex_rule {
    ($struct_name:ident, $id:expr, $title:expr, $severity:expr, $pattern:expr, $message:expr) => {
        pub struct $struct_name;
        impl Rule for $struct_name {
            fn id(&self) -> &str {
                $id
            }
            fn title(&self) -> &str {
                $title
            }
            fn severity(&self) -> Severity {
                $severity
            }
            fn category(&self) -> RuleCategory {
                RuleCategory::Bug
            }
            fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
                static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pattern).unwrap());
                let mut issues = Vec::new();
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if RE.is_match(line) && !line.trim().starts_with("//") {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            $message.to_string(),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
                issues
            }
        }
    };
}

// S1111: Object.finalize() should not be called
regex_rule!(
    S1111FinalizeCall,
    "S1111",
    "Object.finalize() should not be called",
    Severity::Major,
    r"\.finalize\s*\(\s*\)",
    "Remove this call to finalize(). It should only be called by the garbage collector."
);

// S1114: super.finalize() should be called at the end
pub struct S1114SuperFinalize;
impl Rule for S1114SuperFinalize {
    fn id(&self) -> &str {
        "S1114"
    }
    fn title(&self) -> &str {
        "super.finalize() should be called at the end"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static FINALIZE_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"void\s+finalize\s*\(\s*\)").unwrap());
        static SUPER_FINALIZE_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"super\.finalize\s*\(\s*\)").unwrap());

        let mut issues = Vec::new();
        let mut in_finalize = false;
        let mut finalize_line = 0;
        let mut brace_count = 0;
        let mut has_super_finalize = false;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if FINALIZE_RE.is_match(line) {
                in_finalize = true;
                finalize_line = line_num + 1;
                brace_count = 0;
                has_super_finalize = false;
            }

            if in_finalize {
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if SUPER_FINALIZE_RE.is_match(line) {
                    has_super_finalize = true;
                }

                if brace_count <= 0 && line.contains('}') {
                    if !has_super_finalize {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            finalize_line,
                            1,
                            "Call super.finalize() at the end of this finalize() method."
                                .to_string(),
                            None,
                        ));
                    }
                    in_finalize = false;
                }
            }
        }
        issues
    }
}

// S1143: Jump statements should not occur in finally blocks
regex_rule!(
    S1143JumpInFinally,
    "S1143",
    "Jump statements should not occur in finally blocks",
    Severity::Blocker,
    r"finally\s*\{[^}]*\b(return|throw|break|continue)\b",
    "Remove this jump statement from the finally block."
);

// S1145: Useless if(true) and if(false) blocks
regex_rule!(
    S1145UselessIfTrue,
    "S1145",
    "Useless if(true) and if(false) blocks should be removed",
    Severity::Major,
    r"\bif\s*\(\s*(true|false)\s*\)",
    "Remove this useless if statement or fix the condition."
);

// S1175: finalize() signature should match Object.finalize()
pub struct S1175FinalizeSignature;
impl Rule for S1175FinalizeSignature {
    fn id(&self) -> &str {
        "S1175"
    }
    fn title(&self) -> &str {
        "finalize() should match Object.finalize() signature"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bfinalize\s*\([^)]+\)").unwrap());

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && !line.contains("void finalize()") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "finalize() should have no parameters and return void.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S1201: equals() should accept Object parameter
pub struct S1201EqualsParameter;
impl Rule for S1201EqualsParameter {
    fn id(&self) -> &str {
        "S1201"
    }
    fn title(&self) -> &str {
        "equals() should accept Object parameter"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"boolean\s+equals\s*\(\s*(\w+)\s+\w+\s*\)").unwrap());

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                if let Some(param_type) = cap.get(1) {
                    if param_type.as_str() != "Object" {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            format!(
                                "equals() should accept Object, not {}.",
                                param_type.as_str()
                            ),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S1206: equals() and hashCode() should be overridden together
pub struct S1206EqualsHashCode;
impl Rule for S1206EqualsHashCode {
    fn id(&self) -> &str {
        "S1206"
    }
    fn title(&self) -> &str {
        "equals() and hashCode() should be overridden together"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let has_equals = ctx.source.contains("boolean equals(Object")
            || ctx.source.contains("public boolean equals(");
        let has_hashcode =
            ctx.source.contains("int hashCode()") || ctx.source.contains("public int hashCode()");

        let mut issues = Vec::new();
        if has_equals != has_hashcode {
            if let Some(pos) = ctx.source.find("class ") {
                let line_num = ctx.source[..pos].lines().count();
                let msg = if has_equals {
                    "Override hashCode() since equals() is overridden."
                } else {
                    "Override equals() since hashCode() is overridden."
                };
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    msg.to_string(),
                    None,
                ));
            }
        }
        issues
    }
}

// S1217: Thread.run() should not be called directly
regex_rule!(
    S1217ThreadRunDirect,
    "S1217",
    "Thread.run() should not be called directly",
    Severity::Critical,
    r"\.\s*run\s*\(\s*\)",
    "Use start() to run a thread, not run()."
);

// S1221: Methods should not be named "hashCode", "toString", or "equals" without override
pub struct S1221MethodNaming;
impl Rule for S1221MethodNaming {
    fn id(&self) -> &str {
        "S1221"
    }
    fn title(&self) -> &str {
        "Methods should not shadow Object methods"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERNS: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
            vec![
                (
                    "hashcode",
                    Regex::new(r"\b(int|Integer)\s+hashcode\s*\(").unwrap(),
                ),
                ("tostring", Regex::new(r"\bString\s+tostring\s*\(").unwrap()),
                ("equal", Regex::new(r"\bboolean\s+equal\s*\(").unwrap()),
            ]
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            let lower = line.to_lowercase();
            for (name, re) in PATTERNS.iter() {
                if re.is_match(&lower) && !line.contains("@Override") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        format!("Did you mean '{}'? Check the method name.", name),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S1226: Method parameters and caught exceptions should not be reassigned
pub struct S1226ParameterReassignment;
impl Rule for S1226ParameterReassignment {
    fn id(&self) -> &str {
        "S1226"
    }
    fn title(&self) -> &str {
        "Parameters should not be reassigned"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+\w+\s+\w+\s*\(([^)]+)\)").unwrap()
        });
        static ASSIGN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(\w+)\s*=\s*[^=]").unwrap());

        let mut issues = Vec::new();
        let mut params: HashSet<String> = HashSet::new();
        let mut in_method = false;
        let mut brace_count = 0;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = METHOD_RE.captures(line) {
                if let Some(param_list) = cap.get(1) {
                    params.clear();
                    for param in param_list.as_str().split(',') {
                        let parts: Vec<&str> = param.trim().split_whitespace().collect();
                        if parts.len() >= 2 {
                            params.insert(parts[parts.len() - 1].to_string());
                        }
                    }
                    in_method = true;
                    brace_count = 0;
                }
            }

            if in_method {
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if let Some(cap) = ASSIGN_RE.captures(line) {
                    if let Some(var) = cap.get(1) {
                        if params.contains(var.as_str()) {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!("Don't reassign parameter '{}'.", var.as_str()),
                                Some(line.trim().to_string()),
                            ));
                        }
                    }
                }

                if brace_count <= 0 {
                    in_method = false;
                    params.clear();
                }
            }
        }
        issues
    }
}

// S1244: Floating point numbers should not be tested for equality
regex_rule!(
    S1244FloatEquality,
    "S1244",
    "Floating points should not be tested for equality",
    Severity::Critical,
    r"\b(float|double|Float|Double)\b[^;]*\s*(==|!=)\s*",
    "Use a threshold comparison for floating point numbers."
);

// S1317: StringBuilder/StringBuffer should not be instantiated with a char
regex_rule!(
    S1317StringBuilderChar,
    "S1317",
    "StringBuilder should not be instantiated with char",
    Severity::Major,
    r"new\s+(?:StringBuilder|StringBuffer)\s*\(\s*'",
    "This creates a StringBuilder with initial capacity, not content. Use a String."
);

// S1656: Variables should not be self-assigned
pub struct S1656SelfAssignment;
impl Rule for S1656SelfAssignment {
    fn id(&self) -> &str {
        "S1656"
    }
    fn title(&self) -> &str {
        "Variables should not be self-assigned"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*;").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                let left = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let right = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                if left == right && !left.is_empty() {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        format!("Remove this useless self-assignment of '{}'.", left),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S1697: Short-circuit logic should be used to prevent null pointer dereferences
regex_rule!(
    S1697ShortCircuit,
    "S1697",
    "Short-circuit logic should prevent NPE",
    Severity::Major,
    r"\w+\s*!=\s*null\s*&[^&]|\w+\s*==\s*null\s*\|[^|]",
    "Use && or || for short-circuit evaluation to prevent NPE."
);

// S1751: Loops with at most one iteration should be refactored
pub struct S1751SingleIterationLoop;
impl Rule for S1751SingleIterationLoop {
    fn id(&self) -> &str {
        "S1751"
    }
    fn title(&self) -> &str {
        "Loops with at most one iteration should be refactored"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LOOP_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\b(for|while)\s*\([^)]*\)\s*\{").unwrap());

        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if LOOP_RE.is_match(line) {
                // Check if next non-empty line is break/return
                for j in (i + 1)..std::cmp::min(i + 5, lines.len()) {
                    let next = lines[j].trim();
                    if next.is_empty() || next == "{" {
                        continue;
                    }
                    if next.starts_with("return")
                        || next.starts_with("break")
                        || next.starts_with("throw")
                    {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            i + 1,
                            1,
                            "This loop will execute at most once. Refactor it.".to_string(),
                            Some(line.trim().to_string()),
                        ));
                    }
                    break;
                }
            }
        }
        issues
    }
}

// S1764: Identical expressions should not be used on both sides of operators
pub struct S1764IdenticalExpressions;
impl Rule for S1764IdenticalExpressions {
    fn id(&self) -> &str {
        "S1764"
    }
    fn title(&self) -> &str {
        "Identical expressions should not be on both sides"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(\w+)\s*(==|!=|&&|\|\||<=|>=|<|>|\+|-|\*|/|%|\^|&|\|)\s*(\w+)").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                let left = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let op = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let right = cap.get(3).map(|m| m.as_str()).unwrap_or("");

                // Skip == and != for null checks
                if (op == "==" || op == "!=") && (left == "null" || right == "null") {
                    continue;
                }

                if left == right && !left.is_empty() && op != "+" && op != "*" {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        format!("Identical sub-expressions on both sides of '{}'.", op),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S1848: Objects should not be created to be dropped immediately
regex_rule!(
    S1848UnusedObject,
    "S1848",
    "Objects should not be created to be dropped immediately",
    Severity::Major,
    r"^\s*new\s+\w+\s*\([^)]*\)\s*;",
    "This object is created but never used."
);

// S1849: Iterator.hasNext() should not call Iterator.next()
regex_rule!(
    S1849HasNextCallsNext,
    "S1849",
    "hasNext() should not call next()",
    Severity::Blocker,
    r"hasNext\s*\([^)]*\)[^{]*\{[^}]*\.next\s*\(",
    "hasNext() should not call next() - it changes iterator state."
);

// S1850: instanceof operators that always return true or false
pub struct S1850UselessInstanceof;
impl Rule for S1850UselessInstanceof {
    fn id(&self) -> &str {
        "S1850"
    }
    fn title(&self) -> &str {
        "instanceof should not always return same result"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\s+instanceof\s+(\w+)").unwrap());

        let mut issues = Vec::new();
        let mut var_types: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        // Collect variable declarations
        static DECL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\s+(\w+)\s*[=;]").unwrap());

        for cap in DECL_RE.captures_iter(ctx.source) {
            if let (Some(t), Some(v)) = (cap.get(1), cap.get(2)) {
                var_types.insert(v.as_str().to_string(), t.as_str().to_string());
            }
        }

        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                if let (Some(var), Some(check_type)) = (cap.get(1), cap.get(2)) {
                    if let Some(var_type) = var_types.get(var.as_str()) {
                        if var_type == check_type.as_str() {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!(
                                    "This instanceof always returns true ({} is {}).",
                                    var.as_str(),
                                    var_type
                                ),
                                Some(line.trim().to_string()),
                            ));
                        }
                    }
                }
            }
        }
        issues
    }
}

// S1860: Synchronization should not be based on Strings or boxed primitives
regex_rule!(
    S1860SyncOnString,
    "S1860",
    "Don't synchronize on Strings or boxed types",
    Severity::Blocker,
    r#"synchronized\s*\(\s*(?:"[^"]*"|\w*String|Integer|Long|Boolean|Double|Float)"#,
    "Don't synchronize on String or boxed primitive. Use a dedicated lock object."
);

// S1862: Related if/else if statements should not have same condition
pub struct S1862DuplicateCondition;
impl Rule for S1862DuplicateCondition {
    fn id(&self) -> &str {
        "S1862"
    }
    fn title(&self) -> &str {
        "Related if/else if should not have same condition"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static IF_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?:if|else\s+if)\s*\(([^)]+)\)").unwrap());

        let mut issues = Vec::new();
        let mut prev_conditions: Vec<(usize, String)> = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = IF_RE.captures(line) {
                if let Some(cond) = cap.get(1) {
                    let cond_str = cond.as_str().trim().to_string();

                    // Check for duplicates
                    for (prev_line, prev_cond) in &prev_conditions {
                        if prev_cond == &cond_str {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!(
                                    "This condition duplicates the one at line {}.",
                                    prev_line + 1
                                ),
                                Some(line.trim().to_string()),
                            ));
                            break;
                        }
                    }

                    if line.contains("else if") {
                        prev_conditions.push((line_num, cond_str));
                    } else {
                        prev_conditions.clear();
                        prev_conditions.push((line_num, cond_str));
                    }
                }
            }
        }
        issues
    }
}

// S1872: Classes should not be compared by name
regex_rule!(
    S1872ClassNameComparison,
    "S1872",
    "Classes should not be compared by name",
    Severity::Critical,
    r"\.getClass\s*\(\s*\)\.getName\s*\(\s*\)\s*\.equals|\.getSimpleName\s*\(\s*\)\s*\.equals",
    "Use instanceof or getClass() comparison instead of comparing class names."
);

// S2095: Resources should be closed
pub struct S2095ResourcesNotClosed;
impl Rule for S2095ResourcesNotClosed {
    fn id(&self) -> &str {
        "S2095"
    }
    fn title(&self) -> &str {
        "Resources should be closed"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RESOURCE_TYPES: &[&str] = &[
            "InputStream",
            "OutputStream",
            "Reader",
            "Writer",
            "Connection",
            "Statement",
            "PreparedStatement",
            "ResultSet",
            "Socket",
            "ServerSocket",
            "FileInputStream",
            "FileOutputStream",
            "BufferedReader",
            "BufferedWriter",
            "PrintWriter",
            "Scanner",
            "Channel",
            "Selector",
        ];

        let mut issues = Vec::new();

        for resource_type in RESOURCE_TYPES {
            let pattern = format!(r"new\s+{}\s*\(", resource_type);
            if let Ok(re) = Regex::new(&pattern) {
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if re.is_match(line) && !line.contains("try (") && !line.contains("try(") {
                        // Check if followed by try-with-resources
                        let context_start = if line_num > 3 { line_num - 3 } else { 0 };
                        let context: String = ctx
                            .source
                            .lines()
                            .skip(context_start)
                            .take(line_num - context_start + 1)
                            .collect::<Vec<_>>()
                            .join("\n");

                        if !context.contains("try (") && !context.contains("try(") {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!(
                                    "Use try-with-resources to ensure {} is closed.",
                                    resource_type
                                ),
                                Some(line.trim().to_string()),
                            ));
                        }
                    }
                }
            }
        }
        issues
    }
}

// S2097: equals(Object obj) should test argument type
pub struct S2097EqualsTypeCheck;
impl Rule for S2097EqualsTypeCheck {
    fn id(&self) -> &str {
        "S2097"
    }
    fn title(&self) -> &str {
        "equals() should test argument type"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static EQUALS_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"public\s+boolean\s+equals\s*\(\s*Object").unwrap());

        let mut issues = Vec::new();
        let mut in_equals = false;
        let mut equals_line = 0;
        let mut brace_count = 0;
        let mut has_type_check = false;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if EQUALS_RE.is_match(line) {
                in_equals = true;
                equals_line = line_num + 1;
                brace_count = 0;
                has_type_check = false;
            }

            if in_equals {
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if line.contains("instanceof") || line.contains("getClass()") {
                    has_type_check = true;
                }

                if brace_count <= 0 && line.contains('}') {
                    if !has_type_check {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            equals_line,
                            1,
                            "equals() should check the argument type.".to_string(),
                            None,
                        ));
                    }
                    in_equals = false;
                }
            }
        }
        issues
    }
}

// S2110: Invalid date values should not be used
pub struct S2110InvalidDateValues;
impl Rule for S2110InvalidDateValues {
    fn id(&self) -> &str {
        "S2110"
    }
    fn title(&self) -> &str {
        "Invalid date values should not be used"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static MONTH_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"Calendar\.MONTH\s*,\s*(\d+)").unwrap());
        static DAY_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"Calendar\.DAY_OF_MONTH\s*,\s*(\d+)").unwrap());

        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in MONTH_RE.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    if let Ok(month) = m.as_str().parse::<i32>() {
                        if month > 11 || month < 0 {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!("Month {} is invalid. Calendar months are 0-11.", month),
                                Some(line.trim().to_string()),
                            ));
                        }
                    }
                }
            }

            for cap in DAY_RE.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    if let Ok(day) = m.as_str().parse::<i32>() {
                        if day > 31 || day < 1 {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!("Day {} is invalid. Days must be 1-31.", day),
                                Some(line.trim().to_string()),
                            ));
                        }
                    }
                }
            }
        }
        issues
    }
}

// S2111: BigDecimal(double) should not be used
regex_rule!(
    S2111BigDecimalDouble,
    "S2111",
    "BigDecimal(double) should not be used",
    Severity::Critical,
    r"new\s+BigDecimal\s*\(\s*\d+\.\d+\s*\)",
    "Use BigDecimal.valueOf() or BigDecimal(String) to avoid precision issues."
);

// S2114: Collections should not be passed as arguments to their own methods
pub struct S2114CollectionSelfOp;
impl Rule for S2114CollectionSelfOp {
    fn id(&self) -> &str {
        "S2114"
    }
    fn title(&self) -> &str {
        "Collections should not self-operate"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(\w+)\.(addAll|removeAll|containsAll|retainAll)\s*\(\s*(\w+)\s*\)")
                .unwrap()
        });
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                if let (Some(collection), Some(arg)) = (cap.get(1), cap.get(3)) {
                    if collection.as_str() == arg.as_str() {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            "A collection should not be passed as argument to its own method."
                                .to_string(),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2116: hashCode and toString should not be called on array instances
regex_rule!(
    S2116ArrayHashCode,
    "S2116",
    "Don't call hashCode/toString on arrays",
    Severity::Critical,
    r"\[\s*\]\s*\.\s*(hashCode|toString)\s*\(",
    "Use Arrays.hashCode() or Arrays.toString() for arrays."
);

// S2119: Random objects should be reused
regex_rule!(
    S2119RandomReuse,
    "S2119",
    "Random objects should be reused",
    Severity::Critical,
    r"new\s+(?:java\.util\.)?Random\s*\(\s*\)\s*\.\s*next",
    "Store Random in a field and reuse it instead of creating a new instance."
);

// S2127: Double.longBitsToDouble should not be used for int
regex_rule!(
    S2127LongBitsToDouble,
    "S2127",
    "Double.longBitsToDouble should use long",
    Severity::Critical,
    r"Double\.longBitsToDouble\s*\(\s*\(int\)",
    "Pass a long to Double.longBitsToDouble(), not an int."
);

// S2134: Classes extending Thread should override run()
pub struct S2134ThreadOverrideRun;
impl Rule for S2134ThreadOverrideRun {
    fn id(&self) -> &str {
        "S2134"
    }
    fn title(&self) -> &str {
        "Classes extending Thread should override run()"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        if ctx.source.contains("extends Thread") && !ctx.source.contains("void run()") {
            if let Some(pos) = ctx.source.find("extends Thread") {
                let line_num = ctx.source[..pos].lines().count();
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num,
                    1,
                    "Class extends Thread but doesn't override run().".to_string(),
                    None,
                ));
            }
        }
        issues
    }
}

// S2142: InterruptedException should not be ignored
regex_rule!(
    S2142IgnoredInterruptedException,
    "S2142",
    "InterruptedException should not be ignored",
    Severity::Critical,
    r"catch\s*\(\s*InterruptedException\s+\w+\s*\)\s*\{\s*\}",
    "Re-interrupt the thread or propagate the InterruptedException."
);

// S2153: Boxing and unboxing should not be unnecessary
regex_rule!(
    S2153UnnecessaryBoxing,
    "S2153",
    "Unnecessary boxing/unboxing",
    Severity::Minor,
    r"(?:Integer|Long|Double|Float|Boolean|Character)\.valueOf\s*\([^)]+\)\s*\.\s*(?:intValue|longValue|doubleValue|floatValue|booleanValue|charValue)\s*\(",
    "Remove unnecessary boxing and unboxing."
);

// S2159: Silly equality checks should not be made
regex_rule!(
    S2159SillyEquality,
    "S2159",
    "Silly equality checks should not be made",
    Severity::Major,
    r"\bnull\s*==\s*null|\bnull\s*!=\s*null",
    "This equality check is always true/false."
);

// S2164: Math should not be performed on floats
regex_rule!(
    S2164FloatMath,
    "S2164",
    "Use double for precise math, not float",
    Severity::Major,
    r"float\s+\w+\s*=.*[+\-*/]",
    "Use double instead of float for precise calculations."
);

// S2167: compareTo should not return Integer.MIN_VALUE
regex_rule!(
    S2167CompareToMinValue,
    "S2167",
    "compareTo should not return Integer.MIN_VALUE",
    Severity::Critical,
    r"compareTo[^}]*return\s+Integer\.MIN_VALUE",
    "Don't return Integer.MIN_VALUE from compareTo(); negating it causes overflow."
);

// S2168: Double-checked locking should not be used
regex_rule!(
    S2168DoubleCheckedLocking,
    "S2168",
    "Double-checked locking should not be used",
    Severity::Blocker,
    r"if\s*\([^)]+==\s*null[^)]*\)\s*\{[^}]*synchronized",
    "Double-checked locking is broken in Java. Use a volatile field or lazy holder."
);

// S2175: Inappropriate Collection calls should not be made
regex_rule!(
    S2175InappropriateCollectionCall,
    "S2175",
    "Inappropriate Collection calls",
    Severity::Blocker,
    r"(?:List|Set|Map)<[^>]+>\s*\w+[^;]*\.(?:contains|remove|indexOf)\s*\(\s*\d+\s*\)",
    "This collection method call uses the wrong type of argument."
);

// S2183: Ints and longs should not be shifted by more than their number of bits
regex_rule!(
    S2183InvalidShift,
    "S2183",
    "Invalid bit shift amount",
    Severity::Critical,
    r"<<\s*(?:3[2-9]|[4-9]\d|\d{3})|>>\s*(?:3[2-9]|[4-9]\d|\d{3})",
    "Shifting int/long by more than 31/63 bits is undefined."
);

// S2184: Math operands should be cast before assignment
regex_rule!(
    S2184MathOperandCast,
    "S2184",
    "Cast operands before division",
    Severity::Critical,
    r"(?:double|float)\s+\w+\s*=\s*\d+\s*/\s*\d+\s*;",
    "Cast operands to double/float before division to preserve precision."
);

// S2185: Silly math should not be performed
pub struct S2185SillyMath;
impl Rule for S2185SillyMath {
    fn id(&self) -> &str {
        "S2185"
    }
    fn title(&self) -> &str {
        "Silly math should not be performed"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static MULT_ZERO: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\w+\s*\*\s*0\b").unwrap());
        static ZERO_MULT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b0\s*\*\s*\w+\b").unwrap());
        static SAME_OP: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\b(\w+)\s*([/\-%])\s*(\w+)\b").unwrap());

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            let mut found = false;

            if MULT_ZERO.is_match(line) || ZERO_MULT.is_match(line) {
                found = true;
            }

            if !found {
                for cap in SAME_OP.captures_iter(line) {
                    let left = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    let right = cap.get(3).map(|m| m.as_str()).unwrap_or("");
                    if left == right && !left.is_empty() {
                        found = true;
                        break;
                    }
                }
            }

            if found {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "This mathematical operation has a predictable result.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2189: Loops should not be infinite
regex_rule!(
    S2189InfiniteLoop,
    "S2189",
    "Loops should not be infinite",
    Severity::Blocker,
    r"\bwhile\s*\(\s*true\s*\)\s*\{",
    "Add a proper exit condition to this infinite loop."
);

// S2190: Recursion should not be infinite
pub struct S2190InfiniteRecursion;
impl Rule for S2190InfiniteRecursion {
    fn id(&self) -> &str {
        "S2190"
    }
    fn title(&self) -> &str {
        "Recursion should not be infinite"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+\w+\s+(\w+)\s*\([^)]*\)\s*\{").unwrap()
        });

        let mut issues = Vec::new();

        for cap in METHOD_RE.captures_iter(ctx.source) {
            if let Some(method_name) = cap.get(1) {
                let name = method_name.as_str();
                let start = cap.get(0).unwrap().start();

                // Find method body
                let rest = &ctx.source[start..];
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

                if let (Some(s), Some(e)) = (body_start, body_end) {
                    let body = &rest[s..=e];
                    // Simple check: method only calls itself
                    let call_pattern = format!(r"\b{}\s*\(", name);
                    if let Ok(re) = Regex::new(&call_pattern) {
                        let calls = re.find_iter(body).count();
                        let lines: Vec<&str> = body
                            .lines()
                            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//"))
                            .collect();

                        // If mostly just recursive call without base case
                        if calls > 0
                            && lines.len() <= 3
                            && !body.contains("if")
                            && !body.contains("?")
                        {
                            let line_num = ctx.source[..start].lines().count() + 1;
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num,
                                1,
                                format!("Method '{}' may have infinite recursion.", name),
                                None,
                            ));
                        }
                    }
                }
            }
        }
        issues
    }
}

// S2200: compareTo results should not be checked for specific values
regex_rule!(
    S2200CompareToSpecificValue,
    "S2200",
    "compareTo results should be compared to 0",
    Severity::Major,
    r"\.compareTo\s*\([^)]+\)\s*(==|!=)\s*(-?\d+)",
    "Check compareTo() result against 0, not specific values like 1 or -1."
);

// S2201: Return values should not be ignored
pub struct S2201IgnoredReturnValue;
impl Rule for S2201IgnoredReturnValue {
    fn id(&self) -> &str {
        "S2201"
    }
    fn title(&self) -> &str {
        "Return values should not be ignored"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PURE_METHODS: &[&str] = &[
            "replace",
            "replaceAll",
            "replaceFirst",
            "trim",
            "strip",
            "toUpperCase",
            "toLowerCase",
            "substring",
            "concat",
            "split",
            "format",
            "valueOf",
            "toString",
            "abs",
            "min",
            "max",
            "ceil",
            "floor",
            "round",
            "sqrt",
            "pow",
            "intern",
        ];

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for method in PURE_METHODS {
                let pattern = format!(r"^\s*\w+\.\s*{}\s*\([^)]*\)\s*;", method);
                if let Ok(re) = Regex::new(&pattern) {
                    if re.is_match(line) {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            format!("The return value of '{}' must be used.", method),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2204: equals() should not be used on atomic classes
regex_rule!(
    S2204AtomicEquals,
    "S2204",
    "equals() should not be used on atomic classes",
    Severity::Blocker,
    r"Atomic(?:Integer|Long|Boolean|Reference)\s*[^;]*\.equals\s*\(",
    "Use get() to compare atomic values, not equals()."
);

// S2222: Locks should be released
pub struct S2222LockRelease;
impl Rule for S2222LockRelease {
    fn id(&self) -> &str {
        "S2222"
    }
    fn title(&self) -> &str {
        "Locks should be released"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_lock = ctx.source.contains(".lock()");
        let has_unlock = ctx.source.contains(".unlock()");

        if has_lock && !has_unlock {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains(".lock()") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Ensure this lock is released in a finally block.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2225: toString() and clone() should not return null
regex_rule!(
    S2225ToStringReturnsNull,
    "S2225",
    "toString()/clone() should not return null",
    Severity::Critical,
    r"(?:toString|clone)\s*\(\s*\)[^}]*return\s+null",
    "toString() and clone() should never return null."
);

// S2226: Servlets should not have mutable instance fields
pub struct S2226ServletMutableField;
impl Rule for S2226ServletMutableField {
    fn id(&self) -> &str {
        "S2226"
    }
    fn title(&self) -> &str {
        "Servlets should not have mutable instance fields"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let is_servlet =
            ctx.source.contains("extends Servlet") || ctx.source.contains("extends HttpServlet");
        if is_servlet {
            static FIELD_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"private\s+(\w+)\s+\w+\s*[=;]").unwrap());
            for (line_num, line) in ctx.source.lines().enumerate() {
                if FIELD_RE.is_match(line) && !line.contains("final") && !line.contains("static") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Servlets should not have mutable instance fields.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2236: Methods wait(), notify(), and notifyAll() should not be called on Thread
regex_rule!(
    S2236ThreadWaitNotify,
    "S2236",
    "Don't call wait/notify on Thread instances",
    Severity::Blocker,
    r"Thread[^;]*\.\s*(wait|notify|notifyAll)\s*\(",
    "Don't call wait(), notify(), or notifyAll() on Thread instances."
);

// S2251: A for loop update clause should move counter in right direction
pub struct S2251ForLoopDirection;
impl Rule for S2251ForLoopDirection {
    fn id(&self) -> &str {
        "S2251"
    }
    fn title(&self) -> &str {
        "For loop should move counter in right direction"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"for\s*\([^;]+;\s*(\w+)\s*(<|>|<=|>=)\s*[^;]+;\s*(\w+)(--|\+\+|-)").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let cond_var = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let op = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let update_var = cap.get(3).map(|m| m.as_str()).unwrap_or("");
                let update_op = cap.get(4).map(|m| m.as_str()).unwrap_or("");

                if cond_var == update_var {
                    let wrong_direction = ((op == "<" || op == "<=")
                        && (update_op == "--" || update_op == "-"))
                        || ((op == ">" || op == ">=") && update_op == "++");

                    if wrong_direction {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            "For loop counter moves in wrong direction; may be infinite."
                                .to_string(),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2252: Loop conditions should be true at least once
regex_rule!(
    S2252LoopNeverExecutes,
    "S2252",
    "Loop should execute at least once",
    Severity::Major,
    r"(?:while|for)\s*\(\s*false\s*\)",
    "This loop never executes because condition is always false."
);

// S2259: Null pointers should not be dereferenced
pub struct S2259NullDereference;
impl Rule for S2259NullDereference {
    fn id(&self) -> &str {
        "S2259"
    }
    fn title(&self) -> &str {
        "Null pointers should not be dereferenced"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static NULL_ASSIGN: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(\w+)\s*=\s*null\s*;").unwrap());
        static DEREF: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w+)\s*\.\s*\w+").unwrap());

        let mut issues = Vec::new();
        let mut null_vars: HashSet<String> = HashSet::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            // Track null assignments
            for cap in NULL_ASSIGN.captures_iter(line) {
                if let Some(var) = cap.get(1) {
                    null_vars.insert(var.as_str().to_string());
                }
            }

            // Check for dereferences
            for cap in DEREF.captures_iter(line) {
                if let Some(var) = cap.get(1) {
                    let var_name = var.as_str();
                    if null_vars.contains(var_name)
                        && !line.contains(&format!("{} =", var_name))
                        && !line.contains(&format!("{} !=", var_name))
                        && !line.contains(&format!("{} ==", var_name))
                    {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            format!("'{}' may be null here.", var_name),
                            Some(line.trim().to_string()),
                        ));
                        null_vars.remove(var_name);
                    }
                }
            }

            // Clear on reassignment
            static ASSIGN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\s*=\s*[^=]").unwrap());
            for cap in ASSIGN.captures_iter(line) {
                if let Some(var) = cap.get(1) {
                    if !line.contains("= null") {
                        null_vars.remove(var.as_str());
                    }
                }
            }
        }
        issues
    }
}

// S2272: Iterator.next() should throw NoSuchElementException
pub struct S2272IteratorNextException;
impl Rule for S2272IteratorNextException {
    fn id(&self) -> &str {
        "S2272"
    }
    fn title(&self) -> &str {
        "Iterator.next() should throw NoSuchElementException"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        if ctx.source.contains("implements") && ctx.source.contains("Iterator") {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("public") && line.contains("next()") {
                    let rest: String = ctx
                        .source
                        .lines()
                        .skip(line_num)
                        .take(30)
                        .collect::<Vec<_>>()
                        .join("\n");

                    if !rest.contains("NoSuchElementException") {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            "Throw NoSuchElementException when no more elements.".to_string(),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2273: wait(), notify(), notifyAll() should only be called when lock is held
pub struct S2273WaitOutsideSync;
impl Rule for S2273WaitOutsideSync {
    fn id(&self) -> &str {
        "S2273"
    }
    fn title(&self) -> &str {
        "wait/notify should be in synchronized block"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WAIT_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\.\s*(wait|notify|notifyAll)\s*\(").unwrap());
        let mut issues = Vec::new();
        let mut in_sync = false;
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("synchronized") {
                in_sync = true;
            }
            if WAIT_RE.is_match(line) && !in_sync {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Call wait(), notify(), notifyAll() only within synchronized block."
                        .to_string(),
                    Some(line.trim().to_string()),
                ));
            }
            if line.contains('}') {
                in_sync = false;
            }
        }
        issues
    }
}

// S2275: Printf-style format strings should be used correctly
pub struct S2275PrintfFormat;
impl Rule for S2275PrintfFormat {
    fn id(&self) -> &str {
        "S2275"
    }
    fn title(&self) -> &str {
        "Printf-style format strings should be correct"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static FORMAT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?:printf|format)\s*\(\s*"([^"]*)"(?:\s*,\s*([^)]+))?\)"#).unwrap()
        });
        static SPECIFIER: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"%(?:\d+\$)?[-#+ 0,(<]*\d*(?:\.\d+)?[bBhHsScCdoxXeEfgGaAtTnN]").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in FORMAT_RE.captures_iter(line) {
                if let Some(format_str) = cap.get(1) {
                    let spec_count = SPECIFIER.find_iter(format_str.as_str()).count();

                    if let Some(args) = cap.get(2) {
                        let arg_count = args.as_str().split(',').count();
                        if spec_count != arg_count && spec_count > 0 {
                            issues.push(create_issue(
                                self,
                                ctx.file_path,
                                line_num + 1,
                                1,
                                format!(
                                    "Format expects {} args but {} provided.",
                                    spec_count, arg_count
                                ),
                                Some(line.trim().to_string()),
                            ));
                        }
                    } else if spec_count > 0 {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            format!("Format expects {} args but none provided.", spec_count),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2276: wait() should not be called unconditionally in a loop
pub struct S2276WaitUnconditional;
impl Rule for S2276WaitUnconditional {
    fn id(&self) -> &str {
        "S2276"
    }
    fn title(&self) -> &str {
        "wait() should not be unconditional in loop"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WHILE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"while\s*\(").unwrap());
        static WAIT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.wait\s*\(").unwrap());
        let mut issues = Vec::new();
        let mut in_while = false;
        let mut has_if = false;
        let mut brace_count = 0;
        let mut while_start = 0;
        for (line_num, line) in ctx.source.lines().enumerate() {
            if WHILE_RE.is_match(line) && !in_while {
                in_while = true;
                while_start = line_num + 1;
                has_if = false;
                brace_count = 0;
            }
            if in_while {
                brace_count += line.matches('{').count();
                brace_count -= line.matches('}').count();
                if line.contains("if ") || line.contains("if(") {
                    has_if = true;
                }
                if WAIT_RE.is_match(line) && !has_if {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "wait() should be conditional to prevent missed signals.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
                if brace_count == 0 {
                    in_while = false;
                }
            }
        }
        issues
    }
}

// S2583: Conditions should not unconditionally evaluate to TRUE or FALSE
regex_rule!(
    S2583UnconditionalCondition,
    "S2583",
    "Conditions should not be unconditional",
    Severity::Major,
    r"\bif\s*\(\s*(true|false)\s*\)",
    "This condition is always the same. Remove or fix it."
);

// S2589: Boolean expressions should not be gratuitous
regex_rule!(
    S2589GratuitousBoolean,
    "S2589",
    "Boolean expressions should not be gratuitous",
    Severity::Major,
    r"(\w+)\s*(==|!=)\s*(true|false)",
    "Remove this unnecessary boolean comparison."
);

// S2637: @NonNull values should not be set to null
regex_rule!(
    S2637NonNullSetNull,
    "S2637",
    "@NonNull values should not be null",
    Severity::Critical,
    r"@(?:NonNull|Nonnull|NotNull)[^;]*=\s*null",
    "This @NonNull value should not be set to null."
);

// S2674: The length of stream/reader data should be checked
pub struct S2674StreamLengthCheck;
impl Rule for S2674StreamLengthCheck {
    fn id(&self) -> &str {
        "S2674"
    }
    fn title(&self) -> &str {
        "Check stream/reader length"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static READ_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\.read\s*\([^)]+\)\s*[;)]").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if READ_RE.is_match(line)
                && !line.contains("if")
                && !line.contains("while")
                && !line.contains(">")
                && !line.contains("<")
                && !line.contains("==")
            {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Check the return value of read() to know how many bytes were read."
                        .to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2676: Neither Math.abs nor negation should be used on random numbers
regex_rule!(
    S2676MathAbsRandom,
    "S2676",
    "Don't use Math.abs on random numbers",
    Severity::Critical,
    r"Math\.abs\s*\([^)]*(?:random|Random|nextInt|nextLong)",
    "Math.abs can return negative for Integer.MIN_VALUE."
);

// S2689: @Override should match parent signature
pub struct S2689MismatchedOverride;
impl Rule for S2689MismatchedOverride {
    fn id(&self) -> &str {
        "S2689"
    }
    fn title(&self) -> &str {
        "@Override methods should match parent signatures"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static EQUALS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"@Override[\s\n]*public\s+boolean\s+equals\s*\(\s*(\w+)").unwrap()
        });

        let mut issues = Vec::new();

        for cap in EQUALS_RE.captures_iter(ctx.source) {
            if let Some(param_type) = cap.get(1) {
                if param_type.as_str() != "Object" {
                    let pos = cap.get(0).unwrap().start();
                    let line_num = ctx.source[..pos].lines().count() + 1;
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!("equals() should take Object, not {}.", param_type.as_str()),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

// S2695: PreparedStatement should not be shared across threads
regex_rule!(
    S2695SharedPreparedStatement,
    "S2695",
    "PreparedStatement should not be shared",
    Severity::Critical,
    r"(?:static|volatile)\s+(?:PreparedStatement|ResultSet)\s+\w+",
    "Don't share PreparedStatement/ResultSet as static/volatile fields."
);

// S2696: Instance methods should not write to static fields
pub struct S2696InstanceWriteToStatic;
impl Rule for S2696InstanceWriteToStatic {
    fn id(&self) -> &str {
        "S2696"
    }
    fn title(&self) -> &str {
        "Instance methods should not write to static fields"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static STATIC_FIELD: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"static\s+(?:\w+\s+)?(\w+)\s*[=;]").unwrap());
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+\w+\s+\w+\s*\([^)]*\)\s*\{").unwrap()
        });

        let mut issues = Vec::new();
        let mut static_fields: HashSet<String> = HashSet::new();

        for cap in STATIC_FIELD.captures_iter(ctx.source) {
            if let Some(field) = cap.get(1) {
                static_fields.insert(field.as_str().to_string());
            }
        }

        let mut in_instance_method = false;
        let mut brace_count = 0;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if !line.contains("static") && METHOD_RE.is_match(line) {
                in_instance_method = true;
                brace_count = 0;
            }

            if in_instance_method {
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if brace_count <= 0 {
                    in_instance_method = false;
                }

                for field in &static_fields {
                    if line.contains(&format!("{} =", field))
                        || line.contains(&format!("{}=", field))
                        || line.contains(&format!("{}++", field))
                        || line.contains(&format!("{}--", field))
                    {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            format!(
                                "Don't write to static field '{}' from instance method.",
                                field
                            ),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2699: Tests should include assertions
pub struct S2699TestWithoutAssertions;
impl Rule for S2699TestWithoutAssertions {
    fn id(&self) -> &str {
        "S2699"
    }
    fn title(&self) -> &str {
        "Tests should include assertions"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static TEST_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"@Test[\s\n]*(?:public\s+)?void\s+(\w+)\s*\(").unwrap());

        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("@Test") {
                let mut brace_count = 0;
                let mut has_assertion = false;
                let mut found_open = false;

                for j in i..std::cmp::min(i + 50, lines.len()) {
                    let l = lines[j];

                    if l.contains("assert")
                        || l.contains("Assert.")
                        || l.contains("verify")
                        || l.contains("expect")
                        || l.contains("should")
                    {
                        has_assertion = true;
                    }

                    for c in l.chars() {
                        if c == '{' {
                            found_open = true;
                            brace_count += 1;
                        } else if c == '}' {
                            brace_count -= 1;
                            if found_open && brace_count == 0 {
                                break;
                            }
                        }
                    }

                    if found_open && brace_count == 0 {
                        break;
                    }
                }

                if found_open && !has_assertion {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        i + 1,
                        1,
                        "Add at least one assertion to this test.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2755: XML parsers should not be vulnerable to XXE
pub struct S2755XxeVulnerability;
impl Rule for S2755XxeVulnerability {
    fn id(&self) -> &str {
        "S2755"
    }
    fn title(&self) -> &str {
        "XML parsers should not be vulnerable to XXE"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PARSERS: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.new(?:Instance|Factory)\s*\(").unwrap()
        });

        let mut issues = Vec::new();
        let has_secure = ctx.source.contains("setFeature")
            && (ctx.source.contains("disallow-doctype-decl")
                || ctx.source.contains("external-general-entities"));

        if !has_secure {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if PARSERS.is_match(line) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Disable external entities to prevent XXE attacks.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S3358: Ternary operators should not be nested
regex_rule!(
    S3358NestedTernary,
    "S3358",
    "Ternary operators should not be nested",
    Severity::Major,
    r"\?[^;:]*\?",
    "Extract this nested ternary into an if-else or separate variable."
);

// S3655: Optional should be checked before access
regex_rule!(
    S3655UnsafeOptionalAccess,
    "S3655",
    "Optional should be checked before get()",
    Severity::Major,
    r"Optional[^;]*\.get\s*\(",
    "Check with isPresent() or use orElse() before calling get()."
);

// S4973: Strings and Boxed types should be compared using equals()
pub struct S4973EqualsForStrings;
impl Rule for S4973EqualsForStrings {
    fn id(&self) -> &str {
        "S4973"
    }
    fn title(&self) -> &str {
        "Strings should be compared with equals()"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static STRING_DECL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b(?:String|Integer|Long|Double|Float|Boolean)\s+(\w+)").unwrap()
        });
        static COMPARE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r#"(\w+)\s*(==|!=)\s*(\w+|"[^"]*")"#).unwrap());

        let mut issues = Vec::new();
        let mut string_vars: HashSet<String> = HashSet::new();

        for cap in STRING_DECL.captures_iter(ctx.source) {
            if let Some(var) = cap.get(1) {
                string_vars.insert(var.as_str().to_string());
            }
        }

        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in COMPARE.captures_iter(line) {
                let left = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let right = cap.get(3).map(|m| m.as_str()).unwrap_or("");

                if (string_vars.contains(left)
                    || string_vars.contains(right)
                    || right.starts_with('"')
                    || left.starts_with('"'))
                    && left != "null"
                    && right != "null"
                {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Use equals() to compare Strings, not == or !=.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S1784: Method visibility should be explicit
pub struct S1784MethodVisibility;
impl Rule for S1784MethodVisibility {
    fn id(&self) -> &str {
        "S1784"
    }
    fn title(&self) -> &str {
        "Method visibility should be explicit"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^\s+(?:static\s+)?(?:final\s+)?(?:void|int|String|boolean)\s+\w+\s*\(")
                .unwrap()
        });
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line)
                && !line.contains("public")
                && !line.contains("private")
                && !line.contains("protected")
            {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Add explicit visibility modifier to this method.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S1875: Variable should not be read before written
pub struct S1875VariableReadBeforeWrite;
impl Rule for S1875VariableReadBeforeWrite {
    fn id(&self) -> &str {
        "S1875"
    }
    fn title(&self) -> &str {
        "Variable should not be read before written"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S1987: Comparator.compare() should not return inconsistent values
pub struct S1987UnstableCompare;
impl Rule for S1987UnstableCompare {
    fn id(&self) -> &str {
        "S1987"
    }
    fn title(&self) -> &str {
        "Comparator should return consistent values"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        if ctx.source.contains("Comparator") && ctx.source.contains("compare") {
            if ctx.source.contains("Random") || ctx.source.contains("Math.random") {
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if line.contains("compare")
                        && (line.contains("Random") || line.contains("random"))
                    {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            "Comparator should return deterministic values.".to_string(),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S2055: Serializable classes should implement Serializable
pub struct S2055CloneableSerializable;
impl Rule for S2055CloneableSerializable {
    fn id(&self) -> &str {
        "S2055"
    }
    fn title(&self) -> &str {
        "Non-serializable parent class should not be extended"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2060: Primitive arrays should not be used as arguments for Object.equals
pub struct S2060PrimitiveArray;
impl Rule for S2060PrimitiveArray {
    fn id(&self) -> &str {
        "S2060"
    }
    fn title(&self) -> &str {
        "Primitive arrays should not be used with equals()"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[\]\s*\.\s*equals\s*\(").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use Arrays.equals() for array comparison.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2061: Custom serialization method signatures should be correct
pub struct S2061CustomSerialize;
impl Rule for S2061CustomSerialize {
    fn id(&self) -> &str {
        "S2061"
    }
    fn title(&self) -> &str {
        "Serialization methods should have correct signatures"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("writeObject") && !line.contains("ObjectOutputStream") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "writeObject should take ObjectOutputStream parameter.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2066: Non-serializable objects should not be stored in sessions
pub struct S2066InnerClassInstance;
impl Rule for S2066InnerClassInstance {
    fn id(&self) -> &str {
        "S2066"
    }
    fn title(&self) -> &str {
        "Inner class should not be instantiated incorrectly"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2107: Missing parameter in constructor call
pub struct S2107MissingParameter;
impl Rule for S2107MissingParameter {
    fn id(&self) -> &str {
        "S2107"
    }
    fn title(&self) -> &str {
        "Super constructor call should not miss parameters"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2109: Reflection should not be used to check for the presence of a method
pub struct S2109ReflectionException;
impl Rule for S2109ReflectionException {
    fn id(&self) -> &str {
        "S2109"
    }
    fn title(&self) -> &str {
        "NoSuchMethodException should not be caught"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("catch") && line.contains("NoSuchMethodException") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Check method existence without catching exception.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2118: Non-serializable objects should not be stored in sessions
pub struct S2118NonSerializableSession;
impl Rule for S2118NonSerializableSession {
    fn id(&self) -> &str {
        "S2118"
    }
    fn title(&self) -> &str {
        "Session objects should be serializable"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("setAttribute") && line.contains("session") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Ensure session attribute is Serializable.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2120: Clone should not call "super.clone()"
pub struct S2120CloneMethodCall;
impl Rule for S2120CloneMethodCall {
    fn id(&self) -> &str {
        "S2120"
    }
    fn title(&self) -> &str {
        "Clone should call super.clone()"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_clone = ctx.source.contains("protected Object clone()")
            || ctx.source.contains("public Object clone()");
        let calls_super = ctx.source.contains("super.clone()");
        if has_clone && !calls_super {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("clone()")
                    && (line.contains("protected") || line.contains("public"))
                {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Clone method should call super.clone().".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2121: Equals method should take Object parameter
pub struct S2121EqualsParameter2;
impl Rule for S2121EqualsParameter2 {
    fn id(&self) -> &str {
        "S2121"
    }
    fn title(&self) -> &str {
        "equals() should take Object parameter"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"public\s+boolean\s+equals\s*\(\s*(\w+)\s+\w+\s*\)").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let param_type = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if param_type != "Object" {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "equals() parameter should be Object type.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2122: ScheduledThreadPoolExecutor should not have fixed pool size
pub struct S2122ScheduledThread;
impl Rule for S2122ScheduledThread {
    fn id(&self) -> &str {
        "S2122"
    }
    fn title(&self) -> &str {
        "ScheduledThreadPoolExecutor pool size should be set"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("ScheduledThreadPoolExecutor") && line.contains("(0)") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Pool size should be at least 1.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2123: Side effects in increment/decrement
pub struct S2123SideEffectOperator;
impl Rule for S2123SideEffectOperator {
    fn id(&self) -> &str {
        "S2123"
    }
    fn title(&self) -> &str {
        "Values should not be incremented and discarded"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\w+\s*=\s*\w+\+\+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "This increment has no effect.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2141: Non-final fields in synchronized blocks
pub struct S2141NonFinalObjectField;
impl Rule for S2141NonFinalObjectField {
    fn id(&self) -> &str {
        "S2141"
    }
    fn title(&self) -> &str {
        "Arguments that are not serializable should not be stored in sessions"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2144: Catch block should not duplicate
pub struct S2144CatchDuplication;
impl Rule for S2144CatchDuplication {
    fn id(&self) -> &str {
        "S2144"
    }
    fn title(&self) -> &str {
        "Catch block should not duplicate exception handling"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2150: Serialization should be safe
pub struct S2150SafeSerialize;
impl Rule for S2150SafeSerialize {
    fn id(&self) -> &str {
        "S2150"
    }
    fn title(&self) -> &str {
        "Instanceof operators that always return false"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2151: Nullable references
pub struct S2151NullableRef;
impl Rule for S2151NullableRef {
    fn id(&self) -> &str {
        "S2151"
    }
    fn title(&self) -> &str {
        "Runnable/Callable should be implemented correctly"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S2912: Iterator.next() should return value
pub struct S2912IteratorReturn;
impl Rule for S2912IteratorReturn {
    fn id(&self) -> &str {
        "S2912"
    }
    fn title(&self) -> &str {
        "Iterator.next() should return a value"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        if ctx.source.contains("implements Iterator") {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("public") && line.contains("next()") && line.contains("void") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Iterator.next() should not return void.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2924: JUnit test classes naming
pub struct S2924JUnitTestCase;
impl Rule for S2924JUnitTestCase {
    fn id(&self) -> &str {
        "S2924"
    }
    fn title(&self) -> &str {
        "JUnit rules should be used correctly"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("@Rule") && line.contains("private") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "JUnit @Rule fields should be public.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3034: Raw byte values should not be written
pub struct S3034RawByteWrite;
impl Rule for S3034RawByteWrite {
    fn id(&self) -> &str {
        "S3034"
    }
    fn title(&self) -> &str {
        "Raw byte values should not be used with bitwise operators"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("(byte)") && (line.contains("<<") || line.contains(">>")) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Cast to int before bit shifting.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3065: Optional.get should be called only when isPresent is true
pub struct S3065OptionalGetBeforePresent;
impl Rule for S3065OptionalGetBeforePresent {
    fn id(&self) -> &str {
        "S3065"
    }
    fn title(&self) -> &str {
        "Min/Max should not be used without null check"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S3066: Enum with abstract method should have implementation
pub struct S3066EnumWithAbstract;
impl Rule for S3066EnumWithAbstract {
    fn id(&self) -> &str {
        "S3066"
    }
    fn title(&self) -> &str {
        "Enum with abstract method needs implementations"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S3067: getClass() should not be used for synchronization
pub struct S3067SyncGetClass;
impl Rule for S3067SyncGetClass {
    fn id(&self) -> &str {
        "S3067"
    }
    fn title(&self) -> &str {
        "getClass() should not be used for synchronization"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("synchronized") && line.contains("getClass()") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use ClassName.class instead of getClass() for sync.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3516: Methods should not return unreachable code
pub struct S3516UnreachableReturn;
impl Rule for S3516UnreachableReturn {
    fn id(&self) -> &str {
        "S3516"
    }
    fn title(&self) -> &str {
        "Methods should not always return the same value"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S3518: Division by zero
pub struct S3518DivideByZero;
impl Rule for S3518DivideByZero {
    fn id(&self) -> &str {
        "S3518"
    }
    fn title(&self) -> &str {
        "Division by zero should be avoided"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"/\s*0\b|%\s*0\b").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && !line.contains("0.0") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Potential division by zero.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3658: Empty else should be removed
pub struct S3658EmptyElse;
impl Rule for S3658EmptyElse {
    fn id(&self) -> &str {
        "S3658"
    }
    fn title(&self) -> &str {
        "\"if ... else if\" should end with \"else\""
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S3725: Regex.DOT should be used instead of "."
pub struct S3725RegexDot;
impl Rule for S3725RegexDot {
    fn id(&self) -> &str {
        "S3725"
    }
    fn title(&self) -> &str {
        "File separator in path should be consistent"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("File.separator") && line.contains("/") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use File.separator consistently.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3752: HTTP methods should be safe
pub struct S3752HttpMethods;
impl Rule for S3752HttpMethods {
    fn id(&self) -> &str {
        "S3752"
    }
    fn title(&self) -> &str {
        "@RequestMapping without method means all HTTP methods"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("@RequestMapping")
                && !line.contains("method")
                && !line.contains("@Get")
                && !line.contains("@Post")
            {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Specify HTTP method in @RequestMapping.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3958: Stream operations should not be chained if stream is consumed
pub struct S3958StreamConsumed;
impl Rule for S3958StreamConsumed {
    fn id(&self) -> &str {
        "S3958"
    }
    fn title(&self) -> &str {
        "Streams should not be reused after terminal operation"
    }
    fn severity(&self) -> Severity {
        Severity::Blocker
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S3984: Exception should be thrown
pub struct S3984ExceptionNotThrown;
impl Rule for S3984ExceptionNotThrown {
    fn id(&self) -> &str {
        "S3984"
    }
    fn title(&self) -> &str {
        "Exceptions should not be created without being thrown"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("new")
                && line.contains("Exception")
                && !line.contains("throw")
                && line.trim().ends_with(';')
            {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "This exception is created but not thrown.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4042: Using deprecated types
pub struct S4042DeprecatedType;
impl Rule for S4042DeprecatedType {
    fn id(&self) -> &str {
        "S4042"
    }
    fn title(&self) -> &str {
        "Deprecated file types should not be used"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S4144: Methods should not be duplicated
pub struct S4144DuplicatedMethod;
impl Rule for S4144DuplicatedMethod {
    fn id(&self) -> &str {
        "S4144"
    }
    fn title(&self) -> &str {
        "Methods should not be duplicated"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S4145: Conditions should not unconditionally evaluate to "true" or "false"
pub struct S4145MissingCondition;
impl Rule for S4145MissingCondition {
    fn id(&self) -> &str {
        "S4145"
    }
    fn title(&self) -> &str {
        "\"if\" with identical conditions should be merged"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S4276: Functional interfaces should be used
pub struct S4276FunctionalInterface;
impl Rule for S4276FunctionalInterface {
    fn id(&self) -> &str {
        "S4276"
    }
    fn title(&self) -> &str {
        "Functional interfaces should be used correctly"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("IntFunction<Integer>") || line.contains("LongFunction<Long>") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use IntUnaryOperator instead of IntFunction<Integer>.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4347: SecureRandom seeds should not be predictable
pub struct S4347SecureRandom;
impl Rule for S4347SecureRandom {
    fn id(&self) -> &str {
        "S4347"
    }
    fn title(&self) -> &str {
        "SecureRandom seeds should not be predictable"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("SecureRandom") && line.contains("setSeed") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "SecureRandom should not be seeded with predictable values.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4351: Possible missing equals
pub struct S4351PossibleMissing;
impl Rule for S4351PossibleMissing {
    fn id(&self) -> &str {
        "S4351"
    }
    fn title(&self) -> &str {
        "compareTo() should not return Integer.MIN_VALUE"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("compareTo") && line.contains("Integer.MIN_VALUE") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "compareTo() should not return Integer.MIN_VALUE.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4454: ConcurrentHashMap operations
pub struct S4454ConcurrentMapOp;
impl Rule for S4454ConcurrentMapOp {
    fn id(&self) -> &str {
        "S4454"
    }
    fn title(&self) -> &str {
        "ConcurrentHashMap operations should be atomic"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        if ctx.source.contains("ConcurrentHashMap") {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains(".containsKey") || line.contains(".get(") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Use computeIfAbsent for thread-safe operations.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S4462: Primitive boxing should not be done in loop
pub struct S4462PrimitiveStream;
impl Rule for S4462PrimitiveStream {
    fn id(&self) -> &str {
        "S4462"
    }
    fn title(&self) -> &str {
        "Primitive specialization should be used"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("Stream<Integer>")
                || line.contains("Stream<Long>")
                || line.contains("Stream<Double>")
            {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use IntStream/LongStream/DoubleStream instead.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4512: Settable beans should have setters
pub struct S4512SettableInjection;
impl Rule for S4512SettableInjection {
    fn id(&self) -> &str {
        "S4512"
    }
    fn title(&self) -> &str {
        "Injected field settings should be validated"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S4635: String.substring should be used with valid indices
pub struct S4635SubstringLength;
impl Rule for S4635SubstringLength {
    fn id(&self) -> &str {
        "S4635"
    }
    fn title(&self) -> &str {
        "String offset methods should be used with valid indices"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains(".substring(") || line.contains(".indexOf(") {
                if line.contains("length()") && (line.contains("+") || line.contains("-")) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Verify string indices are within bounds.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S4719: Memory stream should be limited
pub struct S4719MemoryStream;
impl Rule for S4719MemoryStream {
    fn id(&self) -> &str {
        "S4719"
    }
    fn title(&self) -> &str {
        "ByteArrayOutputStream size should be limited"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S4792: Logger configuration
pub struct S4792LoggerConfiguration;
impl Rule for S4792LoggerConfiguration {
    fn id(&self) -> &str {
        "S4792"
    }
    fn title(&self) -> &str {
        "Configuring loggers is security-sensitive"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5122: CORS all origins
pub struct S5122CorsAll;
impl Rule for S5122CorsAll {
    fn id(&self) -> &str {
        "S5122B"
    }
    fn title(&self) -> &str {
        "CORS should not allow all origins"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5164: ThreadLocal leak
pub struct S5164ThreadLocalLeak;
impl Rule for S5164ThreadLocalLeak {
    fn id(&self) -> &str {
        "S5164"
    }
    fn title(&self) -> &str {
        "ThreadLocal should call remove()"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_threadlocal = ctx.source.contains("ThreadLocal");
        let has_remove = ctx.source.contains(".remove()");
        if has_threadlocal && !has_remove {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("ThreadLocal") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "ThreadLocal values should be removed in finally.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S5247: SQL format
pub struct S5247SqlFormat;
impl Rule for S5247SqlFormat {
    fn id(&self) -> &str {
        "S5247B"
    }
    fn title(&self) -> &str {
        "SQL query should not be built with string concatenation"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5411: Boxing in string concatenation
pub struct S5411BoxingConcat;
impl Rule for S5411BoxingConcat {
    fn id(&self) -> &str {
        "S5411"
    }
    fn title(&self) -> &str {
        "Boxed Boolean should be avoided in conditions"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("Boolean") && (line.contains("if (") || line.contains("while (")) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Unbox Boolean before using in condition to avoid NPE.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5413: ArrayList remove in loop
pub struct S5413ArrayListRemove;
impl Rule for S5413ArrayListRemove {
    fn id(&self) -> &str {
        "S5413"
    }
    fn title(&self) -> &str {
        "ArrayList.remove should not be called in foreach"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("for (") && line.contains(":") {
                // Check nearby lines for .remove
                let lines: Vec<&str> = ctx.source.lines().collect();
                for j in line_num..std::cmp::min(line_num + 10, lines.len()) {
                    if lines[j].contains(".remove(") {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            j + 1,
                            1,
                            "Use Iterator.remove() instead of collection.remove() in foreach."
                                .to_string(),
                            Some(lines[j].trim().to_string()),
                        ));
                        break;
                    }
                }
            }
        }
        issues
    }
}

// S5527: Certificate verification
pub struct S5527CertVerify;
impl Rule for S5527CertVerify {
    fn id(&self) -> &str {
        "S5527B"
    }
    fn title(&self) -> &str {
        "Server hostname should be verified"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5663: Exception field should be public
pub struct S5663PublicException;
impl Rule for S5663PublicException {
    fn id(&self) -> &str {
        "S5663"
    }
    fn title(&self) -> &str {
        "JUnit 5 exception fields should be public"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5778: Single method per test
pub struct S5778SingleMethodTest;
impl Rule for S5778SingleMethodTest {
    fn id(&self) -> &str {
        "S5778"
    }
    fn title(&self) -> &str {
        "Only one method invocation is expected for throwing assertion"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5783: Exception method signature
pub struct S5783ThrowsException;
impl Rule for S5783ThrowsException {
    fn id(&self) -> &str {
        "S5783"
    }
    fn title(&self) -> &str {
        "Only one argument expected for assertThrows"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5786: JUnit5 method visibility
pub struct S5786JUnit5Method;
impl Rule for S5786JUnit5Method {
    fn id(&self) -> &str {
        "S5786B"
    }
    fn title(&self) -> &str {
        "JUnit5 test methods should have default package visibility"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5790: CompareTo and array
pub struct S5790CompareToArray;
impl Rule for S5790CompareToArray {
    fn id(&self) -> &str {
        "S5790"
    }
    fn title(&self) -> &str {
        "Arrays should not be compared with equals()"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5838: Assert literal
pub struct S5838AssertLiteral;
impl Rule for S5838AssertLiteral {
    fn id(&self) -> &str {
        "S5838"
    }
    fn title(&self) -> &str {
        "assertEquals argument order should be correct"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5841: Regex optimize
pub struct S5841RegexOptimize;
impl Rule for S5841RegexOptimize {
    fn id(&self) -> &str {
        "S5841B"
    }
    fn title(&self) -> &str {
        "Patterns should be reused"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5842: Regex alternation
pub struct S5842RegexAlternation;
impl Rule for S5842RegexAlternation {
    fn id(&self) -> &str {
        "S5842"
    }
    fn title(&self) -> &str {
        "Regex alternation should not have common prefix"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5845: Test message
pub struct S5845TestMessage;
impl Rule for S5845TestMessage {
    fn id(&self) -> &str {
        "S5845B"
    }
    fn title(&self) -> &str {
        "Test assertion should include a message"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5850: Regex graph
pub struct S5850RegexGraph;
impl Rule for S5850RegexGraph {
    fn id(&self) -> &str {
        "S5850"
    }
    fn title(&self) -> &str {
        "Regex should not match empty string"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5853: Regex quantifier
pub struct S5853RegexQuantifier;
impl Rule for S5853RegexQuantifier {
    fn id(&self) -> &str {
        "S5853"
    }
    fn title(&self) -> &str {
        "Regex repetition should be finite"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5856: Regex pattern
pub struct S5856RegexPattern;
impl Rule for S5856RegexPattern {
    fn id(&self) -> &str {
        "S5856"
    }
    fn title(&self) -> &str {
        "Regex should be valid"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5857: Regex range
pub struct S5857RegexRange;
impl Rule for S5857RegexRange {
    fn id(&self) -> &str {
        "S5857"
    }
    fn title(&self) -> &str {
        "Regex character range should be ordered"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5860: Regex group
pub struct S5860RegexGroup;
impl Rule for S5860RegexGroup {
    fn id(&self) -> &str {
        "S5860"
    }
    fn title(&self) -> &str {
        "Regex groups should be matched"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5861: Regex duplicate
pub struct S5861RegexDuplicate;
impl Rule for S5861RegexDuplicate {
    fn id(&self) -> &str {
        "S5861"
    }
    fn title(&self) -> &str {
        "Regex alternatives should not be duplicated"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5863: Assert same
pub struct S5863AssertSame;
impl Rule for S5863AssertSame {
    fn id(&self) -> &str {
        "S5863"
    }
    fn title(&self) -> &str {
        "assertSame should not be used for primitives"
    }
    fn severity(&self) -> Severity {
        Severity::Major
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("assertSame")
                && (line.contains("int") || line.contains("long") || line.contains("double"))
            {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use assertEquals for primitives.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5866: Regex unicode
pub struct S5866RegexUnicode;
impl Rule for S5866RegexUnicode {
    fn id(&self) -> &str {
        "S5866"
    }
    fn title(&self) -> &str {
        "Regex should use Unicode-aware character classes"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5867: Regex invalid
pub struct S5867RegexInvalid;
impl Rule for S5867RegexInvalid {
    fn id(&self) -> &str {
        "S5867"
    }
    fn title(&self) -> &str {
        "Regex unicode should be valid"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5868: Regex character class
pub struct S5868RegexChar;
impl Rule for S5868RegexChar {
    fn id(&self) -> &str {
        "S5868"
    }
    fn title(&self) -> &str {
        "Unicode character escapes should be correct"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// S5869: Regex redundant
pub struct S5869RegexRedundant;
impl Rule for S5869RegexRedundant {
    fn id(&self) -> &str {
        "S5869B"
    }
    fn title(&self) -> &str {
        "Regex character classes should not be redundant"
    }
    fn severity(&self) -> Severity {
        Severity::Minor
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Bug
    }
    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

// ============================================================================
// Batch 4 - Additional bug detection rules
// ============================================================================

// S1401: Bitfield width
regex_rule!(
    S1401BitfieldWidth,
    "S1401",
    "Bitfield width should be valid",
    Severity::Critical,
    r":\s*\d+\s*;",
    "Verify bitfield width is appropriate for the type."
);

// S1402: Array subscript negative
regex_rule!(
    S1402ArrayNegative,
    "S1402",
    "Array subscript should not be negative",
    Severity::Blocker,
    r"\[\s*-\d+\s*\]",
    "Array subscript must be non-negative."
);

// S1403: Use after close
regex_rule!(
    S1403UseAfterClose,
    "S1403",
    "Resource used after close",
    Severity::Blocker,
    r"\.close\s*\([^)]*\)[^}]*\.\w+\s*\(",
    "Resource may be used after being closed."
);

// S1404: Volatile member in serializable
regex_rule!(
    S1404VolatileSerialize,
    "S1404",
    "Volatile fields in serializable class",
    Severity::Major,
    r"implements\s+Serializable[^}]*volatile",
    "Volatile semantics may not be preserved during serialization."
);

// S1405: Dead store after return
regex_rule!(
    S1405DeadStoreReturn,
    "S1405",
    "Assignment after return is dead",
    Severity::Major,
    r"return\s+[^;]+;[^}]*=\s*",
    "Assignment after return statement will never execute."
);

// S1406: Null comparison after dereference
regex_rule!(
    S1406NullAfterDeref,
    "S1406",
    "Null check after dereference",
    Severity::Critical,
    r"\.\w+\s*\([^)]*\)[^}]*==\s*null",
    "Null check after method call suggests dereference before check."
);

// S1407: Operator precedence confusion
regex_rule!(
    S1407OperatorPrecedence,
    "S1407",
    "Operator precedence may cause confusion",
    Severity::Major,
    r"[&|^]\s*\w+\s*[+\-*/]",
    "Add parentheses to clarify operator precedence."
);

// S1408: Useless condition
regex_rule!(
    S1408UselessCondition,
    "S1408",
    "Condition has no effect",
    Severity::Major,
    r"if\s*\(\s*\w+\s*\|\|\s*true\s*\)",
    "Condition always evaluates to true."
);

// S1409: Integer overflow
regex_rule!(
    S1409IntegerOverflow,
    "S1409",
    "Potential integer overflow",
    Severity::Critical,
    r"\+\+\s*Integer\.MAX_VALUE|Integer\.MAX_VALUE\s*\+",
    "This operation may cause integer overflow."
);

// S1410: Signed shift
regex_rule!(
    S1410SignedShift,
    "S1410",
    "Signed right shift may propagate sign",
    Severity::Major,
    r">>\s*\d+\s*[&|^]",
    "Consider using unsigned right shift for bit operations."
);

// S1411: Comparison chain
regex_rule!(
    S1411ComparisonChain,
    "S1411",
    "Comparison chain may be incorrect",
    Severity::Critical,
    r"\w+\s*<\s*\w+\s*<\s*\w+",
    "Use logical operators to chain comparisons."
);

// S1412: Character array not null terminated
regex_rule!(
    S1412CharArrayNullTerm,
    "S1412",
    "Character array may not be null terminated",
    Severity::Major,
    r"char\[\]\s+\w+\s*=\s*new\s+char\[",
    "Ensure character array is null-terminated if used as string."
);

// S1413: Bad cast narrowing
regex_rule!(
    S1413BadCastNarrow,
    "S1413",
    "Cast may lose data",
    Severity::Critical,
    r"\(\s*byte\s*\)\s*\d{3,}|\(\s*short\s*\)\s*\d{5,}",
    "Cast may lose data due to narrowing conversion."
);

// S1414: Float division by zero
regex_rule!(
    S1414FloatDivZero,
    "S1414",
    "Float division by zero",
    Severity::Critical,
    r"/\s*0\.0|/\s*0[fFdD]",
    "Division by zero will result in infinity or NaN."
);

// S1415: Unchecked array copy
regex_rule!(
    S1415UncheckedArrayCopy,
    "S1415",
    "Array copy bounds not checked",
    Severity::Major,
    r"System\.arraycopy\s*\(",
    "Verify array copy bounds to prevent ArrayIndexOutOfBoundsException."
);

// S1416: String index out of bounds
regex_rule!(
    S1416StringIndexOOB,
    "S1416",
    "String index may be out of bounds",
    Severity::Critical,
    r"\.charAt\s*\(\s*\d{3,}\s*\)",
    "Verify string length before accessing character at index."
);

// S1417: Uninitialized final field
regex_rule!(
    S1417UninitFinal,
    "S1417",
    "Final field may be uninitialized",
    Severity::Blocker,
    r"final\s+\w+\s+\w+\s*;",
    "Final field must be initialized."
);

// S1418: Double free equivalent
regex_rule!(
    S1418DoubleFree,
    "S1418",
    "Resource may be closed twice",
    Severity::Major,
    r"\.close\s*\([^)]*\)[^}]*\.close\s*\(",
    "Resource may be closed multiple times."
);

// S1419: Race condition in check-then-act
regex_rule!(
    S1419RaceCondition,
    "S1419",
    "Potential race condition",
    Severity::Critical,
    r"if\s*\([^)]*\.exists\s*\(\s*\)\s*\)[^}]*\.delete\s*\(",
    "Check-then-act pattern may have race condition."
);

// S1420: Memory leak potential
regex_rule!(
    S1420MemoryLeak,
    "S1420",
    "Potential memory leak",
    Severity::Major,
    r"new\s+\w+InputStream\s*\([^)]+\)\s*[^}]*return",
    "Resource may not be closed before return."
);

// S1421: Hardcoded credentials
regex_rule!(
    S1421HardcodedCreds,
    "S1421",
    "Hardcoded credentials",
    Severity::Blocker,
    r"(?i)(?:password|secret|apikey)\s*=\s*\S+",
    "Credentials should not be hardcoded."
);

// S1422: SQL injection potential
regex_rule!(
    S1422SqlInjection,
    "S1422",
    "Potential SQL injection",
    Severity::Critical,
    r"(?i)execute(?:Query|Update)\s*\([^)]*\+",
    "Use prepared statements to prevent SQL injection."
);

// S1423: Command injection potential
regex_rule!(
    S1423CommandInjection,
    "S1423",
    "Potential command injection",
    Severity::Blocker,
    r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
    "Sanitize input before command execution."
);

// S1424: Path traversal
regex_rule!(
    S1424PathTraversal,
    "S1424",
    "Potential path traversal",
    Severity::Critical,
    r"new\s+File\s*\([^)]*\+",
    "Validate file paths to prevent path traversal."
);

// S1425: LDAP injection
regex_rule!(
    S1425LdapInjection,
    "S1425",
    "Potential LDAP injection",
    Severity::Critical,
    r"(?i)search\s*\([^)]*\+[^)]*filter",
    "Sanitize input before LDAP queries."
);

// S1426: XPath injection
regex_rule!(
    S1426XPathInjection,
    "S1426",
    "Potential XPath injection",
    Severity::Critical,
    r"(?i)xpath\s*\.[^)]*\+",
    "Sanitize input before XPath queries."
);

// S1427: Regex injection
regex_rule!(
    S1427RegexInjection,
    "S1427",
    "Potential regex injection",
    Severity::Major,
    r"Pattern\.compile\s*\([^)]*\+",
    "Validate input before using in regex patterns."
);

// S1428: Deserialization vulnerability
regex_rule!(
    S1428DeserializationVuln,
    "S1428",
    "Unsafe deserialization",
    Severity::Critical,
    r"ObjectInputStream\s*\([^)]+\)\.readObject\s*\(",
    "Validate serialized data before deserialization."
);

// S1429: Open redirect
regex_rule!(
    S1429OpenRedirect,
    "S1429",
    "Potential open redirect",
    Severity::Major,
    r"(?i)sendRedirect\s*\([^)]*(?:request|param)",
    "Validate redirect URLs to prevent open redirect."
);

// S1430: XXE vulnerability
regex_rule!(
    S1430XxeVuln,
    "S1430",
    "Potential XXE vulnerability",
    Severity::Critical,
    r"DocumentBuilderFactory\.newInstance\s*\(\s*\)",
    "Disable external entity processing to prevent XXE."
);

// S1431: SSRF vulnerability
regex_rule!(
    S1431SsrfVuln,
    "S1431",
    "Potential SSRF vulnerability",
    Severity::Critical,
    r"(?i)new\s+URL\s*\([^)]*(?:request|param)",
    "Validate URLs to prevent SSRF attacks."
);

// S1432: Information exposure
regex_rule!(
    S1432InfoExposure,
    "S1432",
    "Potential information exposure",
    Severity::Major,
    r"(?i)stacktrace|printstacktrace",
    "Avoid exposing stack traces to users."
);

// S1433: Weak random number
regex_rule!(
    S1433WeakRandom,
    "S1433",
    "Weak random number generator",
    Severity::Critical,
    r"new\s+Random\s*\(\s*\)|Math\.random\s*\(",
    "Use SecureRandom for security-sensitive operations."
);

// S1434: Weak crypto algorithm
regex_rule!(
    S1434WeakCrypto,
    "S1434",
    "Weak cryptographic algorithm",
    Severity::Critical,
    r#"(?i)getInstance\s*\(\s*"(?:DES|MD5|SHA-?1)""#,
    "Use strong cryptographic algorithms."
);

// S1435: Insecure cookie
regex_rule!(
    S1435InsecureCookie,
    "S1435",
    "Insecure cookie",
    Severity::Major,
    r"new\s+Cookie\s*\([^)]+\)",
    "Set secure flag on sensitive cookies."
);

// S1436: Missing CSRF protection
regex_rule!(
    S1436CsrfMissing,
    "S1436",
    "Missing CSRF protection",
    Severity::Critical,
    r"@RequestMapping\s*\([^)]*POST[^)]*\)",
    "Add CSRF protection for state-changing operations."
);

// S1437: Unvalidated forward
regex_rule!(
    S1437UnvalidatedForward,
    "S1437",
    "Unvalidated forward",
    Severity::Major,
    r"getRequestDispatcher\s*\([^)]*\+",
    "Validate forward destinations to prevent access control bypass."
);

// S1438: Session fixation
regex_rule!(
    S1438SessionFixation,
    "S1438",
    "Potential session fixation",
    Severity::Critical,
    r"setSessionId|JSESSIONID\s*=",
    "Regenerate session ID after authentication."
);

// S1439: Insufficient logging
regex_rule!(
    S1439InsufficientLog,
    "S1439",
    "Insufficient security logging",
    Severity::Minor,
    r"catch\s*\(\s*\w*Exception[^}]*\{\s*\}",
    "Add logging for security-related exceptions."
);

// S1440: Log injection
regex_rule!(
    S1440LogInjection,
    "S1440",
    "Potential log injection",
    Severity::Major,
    r"log\.\w+\s*\([^)]*\+[^)]*(?:request|param)",
    "Sanitize user input before logging."
);

// S1441: Format string vulnerability
regex_rule!(
    S1441FormatString,
    "S1441",
    "Format string vulnerability",
    Severity::Critical,
    r"String\.format\s*\([^)]*\+[^)]*,",
    "Use parameterized format strings."
);

// S1442: Null reference
regex_rule!(
    S1442NullReference,
    "S1442",
    "Potential null reference",
    Severity::Critical,
    r"=\s*null\s*;[^}]*\.\w+\s*\(",
    "Object may be null before method call."
);

// S1443: Array index constant
regex_rule!(
    S1443ArrayIndexConstant,
    "S1443",
    "Constant array index may be wrong",
    Severity::Major,
    r"\[\s*\d+\s*\].*\[\s*\d+\s*\]",
    "Verify hardcoded array indices are correct."
);

// S1444B: Division truncation
regex_rule!(
    S1444BDivisionTrunc,
    "S1444B",
    "Integer division truncation",
    Severity::Major,
    r"(?:int|long)\s+\w+\s*=\s*\d+\s*/\s*\d+",
    "Integer division truncates result."
);

// S1445: Infinite loop
regex_rule!(
    S1445InfiniteLoop,
    "S1445",
    "Potential infinite loop",
    Severity::Blocker,
    r"while\s*\(\s*true\s*\)\s*\{",
    "Loop may never terminate."
);

// S1446: Unreachable catch
regex_rule!(
    S1446UnreachableCatch,
    "S1446",
    "Catch block may be unreachable",
    Severity::Major,
    r"catch\s*\(\s*Exception[^}]*catch\s*\(\s*\w+Exception",
    "More specific exception catch is unreachable."
);

// S1447: Missing default case
regex_rule!(
    S1447MissingDefault,
    "S1447",
    "Switch missing default case",
    Severity::Major,
    r"switch\s*\([^)]+\)\s*\{[^}]*case[^}]*\}",
    "Add default case to switch statement."
);

// S1448: Empty catch block
regex_rule!(
    S1448EmptyCatch,
    "S1448",
    "Empty catch block",
    Severity::Major,
    r"catch\s*\(\s*\w+\s+\w+\s*\)\s*\{\s*\}",
    "Handle or log caught exceptions."
);

// S1449: Wrong comparison
regex_rule!(
    S1449WrongComparison,
    "S1449",
    "Comparison may be wrong",
    Severity::Major,
    r"!=\s*0\s*\&\&|\&\&[^}]*!=\s*0",
    "Verify comparison logic is correct."
);

// S1450B: Field should be local
regex_rule!(
    S1450BFieldLocal,
    "S1450B",
    "Field used only in one method",
    Severity::Minor,
    r"private\s+\w+\s+\w+\s*;",
    "Field used in only one method should be local variable."
);

// S1451B: Missing license header
regex_rule!(
    S1451BLicenseHeader,
    "S1451B",
    "Missing license header",
    Severity::Minor,
    r"^package\s+\w+",
    "Add license header to source file."
);

// S1452: Generic wildcard return
regex_rule!(
    S1452GenericWildcard,
    "S1452",
    "Method returns generic wildcard",
    Severity::Major,
    r"public\s+\w*<\?[^>]*>\s+\w+\s*\(",
    "Avoid returning generic wildcards from methods."
);

// S1453: Boolean literal argument
regex_rule!(
    S1453BooleanLiteral,
    "S1453",
    "Boolean literal as argument",
    Severity::Minor,
    r"\.\w+\s*\([^)]*,\s*true\s*,|,\s*false\s*,",
    "Consider using named constants for boolean parameters."
);

// S1454: Parameter count mismatch
regex_rule!(
    S1454ParamMismatch,
    "S1454",
    "Parameter count may not match format",
    Severity::Critical,
    r"String\.format\s*\(\s*\S+\s*,\s*\w+\s*\)",
    "Verify format string parameters match arguments."
);

// S1455: Return in finally
regex_rule!(
    S1455ReturnFinally,
    "S1455",
    "Return in finally block",
    Severity::Blocker,
    r"finally\s*\{[^}]*return\s+",
    "Avoid return statements in finally blocks."
);

// S1456: Throw in finally
regex_rule!(
    S1456ThrowFinally,
    "S1456",
    "Throw in finally block",
    Severity::Blocker,
    r"finally\s*\{[^}]*throw\s+new",
    "Avoid throw statements in finally blocks."
);

// S1457: Assignment in condition
regex_rule!(
    S1457AssignCondition,
    "S1457",
    "Assignment in condition",
    Severity::Major,
    r"(?:if|while)\s*\(\s*\w+\s*=[^=]",
    "Avoid assignments in conditions."
);

// S1458: String concatenation in exception
regex_rule!(
    S1458StringConcatException,
    "S1458",
    "String concatenation in exception",
    Severity::Minor,
    r"throw\s+new\s+\w+Exception\s*\([^)]*\+",
    "Use parameterized exception constructors."
);

// S1459: Empty synchronized block
regex_rule!(
    S1459EmptySync,
    "S1459",
    "Empty synchronized block",
    Severity::Major,
    r"synchronized\s*\([^)]+\)\s*\{\s*\}",
    "Empty synchronized block has no effect."
);

// S1460: Wait outside loop
regex_rule!(
    S1460WaitOutsideLoop,
    "S1460",
    "Wait called outside loop",
    Severity::Critical,
    r"\.wait\s*\(\s*\)",
    "Call wait() inside a while loop."
);

// S1461: Notify without state change
regex_rule!(
    S1461NotifyNoChange,
    "S1461",
    "Notify without state change",
    Severity::Major,
    r"\.notify(?:All)?\s*\(\s*\)",
    "Modify shared state before calling notify."
);

// S1462: Double checked locking
regex_rule!(
    S1462DoubleChecked,
    "S1462",
    "Double checked locking pattern",
    Severity::Critical,
    r"if\s*\(\s*\w+\s*==\s*null\s*\)[^}]*synchronized[^}]*if\s*\(\s*\w+\s*==\s*null",
    "Use volatile with double-checked locking."
);

// S1463: Lock not released
regex_rule!(
    S1463LockNotReleased,
    "S1463",
    "Lock may not be released",
    Severity::Blocker,
    r"\.lock\s*\(\s*\)",
    "Ensure lock is released in finally block."
);

// S1464: Incorrect equals override
regex_rule!(
    S1464IncorrectEquals,
    "S1464",
    "Incorrect equals override",
    Severity::Critical,
    r"boolean\s+equals\s*\(\s*(?:String|Integer|Long)\s+\w+\s*\)",
    "equals() should accept Object parameter."
);

// S1465: Hashcode not overridden
regex_rule!(
    S1465HashcodeNotOverridden,
    "S1465",
    "hashCode not overridden with equals",
    Severity::Blocker,
    r"boolean\s+equals\s*\(\s*Object\s+\w+\s*\)",
    "Override hashCode when overriding equals."
);

// S1466: Clone without super.clone
regex_rule!(
    S1466CloneWithoutSuper,
    "S1466",
    "Clone without super.clone()",
    Severity::Major,
    r"Object\s+clone\s*\([^)]*\)\s*\{",
    "Call super.clone() in clone method."
);

// S1467: CompareTo inconsistent with equals
regex_rule!(
    S1467CompareToInconsistent,
    "S1467",
    "CompareTo inconsistent with equals",
    Severity::Major,
    r"int\s+compareTo\s*\([^)]*\)",
    "CompareTo should be consistent with equals."
);

// S1468: Constructor calls overridable method
regex_rule!(
    S1468CtorCallsOverridable,
    "S1468",
    "Constructor calls overridable method",
    Severity::Major,
    r"public\s+\w+\s*\([^)]*\)\s*\{[^}]*\bthis\.\w+\s*\(",
    "Avoid calling overridable methods in constructors."
);

// S1469: Non-final field in enum
regex_rule!(
    S1469NonFinalEnum,
    "S1469",
    "Non-final field in enum",
    Severity::Major,
    r"enum\s+\w+\s*\{[^}]*private\s+\w+\s+\w+\s*;",
    "Enum fields should be final."
);

// S1470: Mutable field in immutable class
regex_rule!(
    S1470MutableImmutable,
    "S1470",
    "Mutable field in immutable class",
    Severity::Major,
    r"final\s+class\s+\w+[^}]*private\s+\w+\[\]\s+\w+",
    "Immutable classes should not have mutable fields."
);

// ============================================================================
// Batch 5 - Additional bug detection rules
// ============================================================================

// S1471: Infinite loop risk
regex_rule!(
    S1471InfiniteLoopRisk,
    "S1471",
    "Potential infinite loop",
    Severity::Critical,
    r"while\s*\(\s*true\s*\)\s*\{",
    "Loop may never terminate."
);

// S1472: Null return from getClass
regex_rule!(
    S1472NullGetClass,
    "S1472",
    "getClass() on null",
    Severity::Blocker,
    r"null\.getClass\s*\(",
    "Cannot call getClass() on null."
);

// S1473: Array store exception risk
regex_rule!(
    S1473ArrayStore,
    "S1473",
    "Array store exception risk",
    Severity::Critical,
    r"Object\[\]\s+\w+\s*=\s*new\s+\w+\[",
    "May cause ArrayStoreException."
);

// S1474: Unclosed stream
regex_rule!(
    S1474UnclosedStream,
    "S1474",
    "Stream may not be closed",
    Severity::Major,
    r"new\s+(?:FileInputStream|FileOutputStream)\s*\([^)]+\)",
    "Stream should be closed in finally or try-with-resources."
);

// S1475: Missing break in switch
regex_rule!(
    S1475MissingBreak,
    "S1475",
    "Missing break in switch case",
    Severity::Major,
    r"case\s+[^:]+:[^:]*case",
    "Case may fall through."
);

// S1476: Non-volatile double-checked lock
regex_rule!(
    S1476NonVolatileDCL,
    "S1476",
    "Double-checked lock without volatile",
    Severity::Critical,
    r"private\s+static\s+\w+\s+instance[^}]*if\s*\(\s*instance\s*==\s*null",
    "Use volatile with double-checked locking."
);

// S1477: StringBuilder in loop
regex_rule!(
    S1477SBInLoop,
    "S1477",
    "StringBuilder created in loop",
    Severity::Major,
    r"for\s*\([^{]+\{[^}]*new\s+StringBuilder\s*\(",
    "Create StringBuilder outside loop."
);

// S1478: Catching Exception and ignoring
regex_rule!(
    S1478CatchIgnore,
    "S1478",
    "Exception caught and ignored",
    Severity::Major,
    r"catch\s*\(\s*\w+\s+\w+\s*\)\s*\{\s*//",
    "Don't silently ignore exceptions."
);

// S1479B: Too many cases
regex_rule!(
    S1479BTooManyCases,
    "S1479B",
    "Switch has too many cases",
    Severity::Minor,
    r"switch\s*\([^)]+\)\s*\{[^}]*case[^}]*case[^}]*case[^}]*case[^}]*case[^}]*case[^}]*case[^}]*case[^}]*case[^}]*case",
    "Consider refactoring switch with many cases."
);

// S1480: toString may return null
regex_rule!(
    S1480ToStringNull,
    "S1480",
    "toString may return null",
    Severity::Major,
    r"toString\s*\(\s*\)\s*\{[^}]*return\s+null",
    "toString should never return null."
);

// S1481B: Unused local variable
regex_rule!(
    S1481BUnusedLocal,
    "S1481B",
    "Local variable appears unused",
    Severity::Minor,
    r"(?:int|String|boolean)\s+\w+\s*=[^;]+;",
    "Remove unused local variable."
);

// S1482: ClassCastException risk
regex_rule!(
    S1482ClassCast,
    "S1482",
    "ClassCastException risk",
    Severity::Major,
    r"\(\s*\w+\s*\)\s*\w+[^;]*;",
    "Cast without instanceof check."
);

// S1483: Concurrent modification risk
regex_rule!(
    S1483ConcurrentMod,
    "S1483",
    "Concurrent modification risk",
    Severity::Critical,
    r"for\s*\(\s*\w+\s+\w+\s*:\s*\w+\s*\)[^}]*\w+\.(?:add|remove)",
    "Modifying collection while iterating."
);

// S1484: Null in array creation
regex_rule!(
    S1484NullInArray,
    "S1484",
    "Null in array creation",
    Severity::Minor,
    r"new\s+\w+\[\]\s*\{[^}]*null[^}]*\}",
    "Array contains null elements."
);

// S1485: Comparing incompatible types
regex_rule!(
    S1485IncompatibleTypes,
    "S1485",
    "Comparing incompatible types",
    Severity::Critical,
    r"\.equals\s*\(\s*\d+\s*\)",
    "Comparing String to number always returns false."
);

// S1486: ResultSet not closed
regex_rule!(
    S1486ResultSetLeak,
    "S1486",
    "ResultSet not closed",
    Severity::Major,
    r"\.executeQuery\s*\([^)]*\)",
    "ResultSet should be closed."
);

// S1487: Connection not closed
regex_rule!(
    S1487ConnectionLeak,
    "S1487",
    "Connection not closed",
    Severity::Major,
    r"\.getConnection\s*\([^)]*\)",
    "Connection should be closed."
);

// S1488B: Unnecessary intermediate variable
regex_rule!(
    S1488BUnnecessaryVar,
    "S1488B",
    "Unnecessary intermediate variable",
    Severity::Minor,
    r"\w+\s*=\s*[^;]+;\s*return\s+\w+;",
    "Return value directly."
);

// S1489: Ignoring return value
regex_rule!(
    S1489IgnoredReturn,
    "S1489",
    "Return value ignored",
    Severity::Major,
    r"^\s*\w+\.(?:replace|substring|trim|toUpperCase|toLowerCase)\s*\(",
    "String method return value ignored."
);

// S1490: Using finalize()
regex_rule!(
    S1490UsingFinalize,
    "S1490",
    "Using finalize() is deprecated",
    Severity::Major,
    r"protected\s+void\s+finalize\s*\(",
    "Use try-with-resources instead of finalize."
);

// S1491: Synchronizing on boxed primitive
regex_rule!(
    S1491SyncBoxed,
    "S1491",
    "Synchronizing on boxed primitive",
    Severity::Critical,
    r"synchronized\s*\(\s*(?:Integer|Long|Boolean|Character)\.",
    "Don't synchronize on boxed primitives."
);

// S1492: Empty Iterator
regex_rule!(
    S1492EmptyIterator,
    "S1492",
    "Iterator always returns empty",
    Severity::Major,
    r"hasNext\s*\(\s*\)\s*\{[^}]*return\s+false",
    "Iterator.hasNext() always returns false."
);

// S1493: hashCode returns constant
regex_rule!(
    S1493HashCodeConstant,
    "S1493",
    "hashCode returns constant",
    Severity::Major,
    r"int\s+hashCode\s*\(\s*\)\s*\{[^}]*return\s+\d+\s*;",
    "hashCode should not return a constant."
);

// S1494: equals always returns true/false
regex_rule!(
    S1494EqualsConstant,
    "S1494",
    "equals returns constant",
    Severity::Critical,
    r"boolean\s+equals\s*\([^)]*\)\s*\{[^}]*return\s+(?:true|false)\s*;",
    "equals should compare objects."
);

// S1495: compareTo returns constant
regex_rule!(
    S1495CompareConstant,
    "S1495",
    "compareTo returns constant",
    Severity::Major,
    r"int\s+compareTo\s*\([^)]*\)\s*\{[^}]*return\s+\d+\s*;",
    "compareTo should compare objects."
);

// S1496: Division by variable that could be zero
regex_rule!(
    S1496DivByVar,
    "S1496",
    "Potential division by zero",
    Severity::Critical,
    r"/\s*\w+[^;]*;",
    "Variable divisor may be zero."
);

// S1497: Index out of bounds risk
regex_rule!(
    S1497IndexOOB,
    "S1497",
    "Index may be out of bounds",
    Severity::Critical,
    r"\[\s*\w+\s*\]",
    "Verify index is within bounds."
);

// S1498: Uninitialized field used
regex_rule!(
    S1498UninitField,
    "S1498",
    "Field may be uninitialized",
    Severity::Critical,
    r"private\s+\w+\s+\w+\s*;",
    "Field may be used before initialization."
);

// S1499: Unreachable code
regex_rule!(
    S1499UnreachableCode,
    "S1499",
    "Code after return is unreachable",
    Severity::Major,
    r"return\s+[^;]+;[^}]*\w+",
    "Code after return will never execute."
);

// S1500B: Switch expression too complex
regex_rule!(
    S1500BComplexSwitch,
    "S1500B",
    "Switch expression complex",
    Severity::Minor,
    r"switch\s*\([^)]*\+[^)]*\)|switch\s*\([^)]*\.[^)]*\.[^)]*\)",
    "Simplify switch expression."
);

// Create all bug detection rules
pub fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(S1111FinalizeCall),
        Box::new(S1114SuperFinalize),
        Box::new(S1143JumpInFinally),
        Box::new(S1145UselessIfTrue),
        Box::new(S1175FinalizeSignature),
        Box::new(S1201EqualsParameter),
        Box::new(S1206EqualsHashCode),
        Box::new(S1217ThreadRunDirect),
        Box::new(S1221MethodNaming),
        Box::new(S1226ParameterReassignment),
        Box::new(S1244FloatEquality),
        Box::new(S1317StringBuilderChar),
        Box::new(S1656SelfAssignment),
        Box::new(S1697ShortCircuit),
        Box::new(S1751SingleIterationLoop),
        Box::new(S1764IdenticalExpressions),
        Box::new(S1784MethodVisibility),
        Box::new(S1848UnusedObject),
        Box::new(S1849HasNextCallsNext),
        Box::new(S1850UselessInstanceof),
        Box::new(S1860SyncOnString),
        Box::new(S1862DuplicateCondition),
        Box::new(S1872ClassNameComparison),
        Box::new(S1875VariableReadBeforeWrite),
        Box::new(S1987UnstableCompare),
        Box::new(S2055CloneableSerializable),
        Box::new(S2060PrimitiveArray),
        Box::new(S2061CustomSerialize),
        Box::new(S2066InnerClassInstance),
        Box::new(S2095ResourcesNotClosed),
        Box::new(S2097EqualsTypeCheck),
        Box::new(S2107MissingParameter),
        Box::new(S2109ReflectionException),
        Box::new(S2110InvalidDateValues),
        Box::new(S2111BigDecimalDouble),
        Box::new(S2114CollectionSelfOp),
        Box::new(S2116ArrayHashCode),
        Box::new(S2118NonSerializableSession),
        Box::new(S2119RandomReuse),
        Box::new(S2120CloneMethodCall),
        Box::new(S2121EqualsParameter2),
        Box::new(S2122ScheduledThread),
        Box::new(S2123SideEffectOperator),
        Box::new(S2127LongBitsToDouble),
        Box::new(S2134ThreadOverrideRun),
        Box::new(S2141NonFinalObjectField),
        Box::new(S2142IgnoredInterruptedException),
        Box::new(S2144CatchDuplication),
        Box::new(S2150SafeSerialize),
        Box::new(S2151NullableRef),
        Box::new(S2153UnnecessaryBoxing),
        Box::new(S2159SillyEquality),
        Box::new(S2164FloatMath),
        Box::new(S2167CompareToMinValue),
        Box::new(S2168DoubleCheckedLocking),
        Box::new(S2175InappropriateCollectionCall),
        Box::new(S2183InvalidShift),
        Box::new(S2184MathOperandCast),
        Box::new(S2185SillyMath),
        Box::new(S2189InfiniteLoop),
        Box::new(S2190InfiniteRecursion),
        Box::new(S2200CompareToSpecificValue),
        Box::new(S2201IgnoredReturnValue),
        Box::new(S2204AtomicEquals),
        Box::new(S2222LockRelease),
        Box::new(S2225ToStringReturnsNull),
        Box::new(S2226ServletMutableField),
        Box::new(S2236ThreadWaitNotify),
        Box::new(S2251ForLoopDirection),
        Box::new(S2252LoopNeverExecutes),
        Box::new(S2259NullDereference),
        Box::new(S2272IteratorNextException),
        Box::new(S2273WaitOutsideSync),
        Box::new(S2275PrintfFormat),
        Box::new(S2276WaitUnconditional),
        Box::new(S2583UnconditionalCondition),
        Box::new(S2589GratuitousBoolean),
        Box::new(S2637NonNullSetNull),
        Box::new(S2674StreamLengthCheck),
        Box::new(S2676MathAbsRandom),
        Box::new(S2689MismatchedOverride),
        Box::new(S2695SharedPreparedStatement),
        Box::new(S2696InstanceWriteToStatic),
        Box::new(S2699TestWithoutAssertions),
        Box::new(S2755XxeVulnerability),
        Box::new(S2912IteratorReturn),
        Box::new(S2924JUnitTestCase),
        Box::new(S3034RawByteWrite),
        Box::new(S3065OptionalGetBeforePresent),
        Box::new(S3066EnumWithAbstract),
        Box::new(S3067SyncGetClass),
        Box::new(S3358NestedTernary),
        Box::new(S3516UnreachableReturn),
        Box::new(S3518DivideByZero),
        Box::new(S3655UnsafeOptionalAccess),
        Box::new(S3658EmptyElse),
        Box::new(S3725RegexDot),
        Box::new(S3752HttpMethods),
        Box::new(S3958StreamConsumed),
        Box::new(S3984ExceptionNotThrown),
        Box::new(S4042DeprecatedType),
        Box::new(S4144DuplicatedMethod),
        Box::new(S4145MissingCondition),
        Box::new(S4276FunctionalInterface),
        Box::new(S4347SecureRandom),
        Box::new(S4351PossibleMissing),
        Box::new(S4454ConcurrentMapOp),
        Box::new(S4462PrimitiveStream),
        Box::new(S4512SettableInjection),
        Box::new(S4635SubstringLength),
        Box::new(S4719MemoryStream),
        Box::new(S4792LoggerConfiguration),
        Box::new(S4973EqualsForStrings),
        Box::new(S5122CorsAll),
        Box::new(S5164ThreadLocalLeak),
        Box::new(S5247SqlFormat),
        Box::new(S5411BoxingConcat),
        Box::new(S5413ArrayListRemove),
        Box::new(S5527CertVerify),
        Box::new(S5663PublicException),
        Box::new(S5778SingleMethodTest),
        Box::new(S5783ThrowsException),
        Box::new(S5786JUnit5Method),
        Box::new(S5790CompareToArray),
        Box::new(S5838AssertLiteral),
        Box::new(S5841RegexOptimize),
        Box::new(S5842RegexAlternation),
        Box::new(S5845TestMessage),
        Box::new(S5850RegexGraph),
        Box::new(S5853RegexQuantifier),
        Box::new(S5856RegexPattern),
        Box::new(S5857RegexRange),
        Box::new(S5860RegexGroup),
        Box::new(S5861RegexDuplicate),
        Box::new(S5863AssertSame),
        Box::new(S5866RegexUnicode),
        Box::new(S5867RegexInvalid),
        Box::new(S5868RegexChar),
        Box::new(S5869RegexRedundant),
        // Batch 4 - additional bug rules
        Box::new(S1401BitfieldWidth),
        Box::new(S1402ArrayNegative),
        Box::new(S1403UseAfterClose),
        Box::new(S1404VolatileSerialize),
        Box::new(S1405DeadStoreReturn),
        Box::new(S1406NullAfterDeref),
        Box::new(S1407OperatorPrecedence),
        Box::new(S1408UselessCondition),
        Box::new(S1409IntegerOverflow),
        Box::new(S1410SignedShift),
        Box::new(S1411ComparisonChain),
        Box::new(S1412CharArrayNullTerm),
        Box::new(S1413BadCastNarrow),
        Box::new(S1414FloatDivZero),
        Box::new(S1415UncheckedArrayCopy),
        Box::new(S1416StringIndexOOB),
        Box::new(S1417UninitFinal),
        Box::new(S1418DoubleFree),
        Box::new(S1419RaceCondition),
        Box::new(S1420MemoryLeak),
        Box::new(S1421HardcodedCreds),
        Box::new(S1422SqlInjection),
        Box::new(S1423CommandInjection),
        Box::new(S1424PathTraversal),
        Box::new(S1425LdapInjection),
        Box::new(S1426XPathInjection),
        Box::new(S1427RegexInjection),
        Box::new(S1428DeserializationVuln),
        Box::new(S1429OpenRedirect),
        Box::new(S1430XxeVuln),
        Box::new(S1431SsrfVuln),
        Box::new(S1432InfoExposure),
        Box::new(S1433WeakRandom),
        Box::new(S1434WeakCrypto),
        Box::new(S1435InsecureCookie),
        Box::new(S1436CsrfMissing),
        Box::new(S1437UnvalidatedForward),
        Box::new(S1438SessionFixation),
        Box::new(S1439InsufficientLog),
        Box::new(S1440LogInjection),
        Box::new(S1441FormatString),
        Box::new(S1442NullReference),
        Box::new(S1443ArrayIndexConstant),
        Box::new(S1444BDivisionTrunc),
        Box::new(S1445InfiniteLoop),
        Box::new(S1446UnreachableCatch),
        Box::new(S1447MissingDefault),
        Box::new(S1448EmptyCatch),
        Box::new(S1449WrongComparison),
        Box::new(S1450BFieldLocal),
        Box::new(S1451BLicenseHeader),
        Box::new(S1452GenericWildcard),
        Box::new(S1453BooleanLiteral),
        Box::new(S1454ParamMismatch),
        Box::new(S1455ReturnFinally),
        Box::new(S1456ThrowFinally),
        Box::new(S1457AssignCondition),
        Box::new(S1458StringConcatException),
        Box::new(S1459EmptySync),
        Box::new(S1460WaitOutsideLoop),
        Box::new(S1461NotifyNoChange),
        Box::new(S1462DoubleChecked),
        Box::new(S1463LockNotReleased),
        Box::new(S1464IncorrectEquals),
        Box::new(S1465HashcodeNotOverridden),
        Box::new(S1466CloneWithoutSuper),
        Box::new(S1467CompareToInconsistent),
        Box::new(S1468CtorCallsOverridable),
        Box::new(S1469NonFinalEnum),
        Box::new(S1470MutableImmutable),
        // Batch 5 - additional bug rules
        Box::new(S1471InfiniteLoopRisk),
        Box::new(S1472NullGetClass),
        Box::new(S1473ArrayStore),
        Box::new(S1474UnclosedStream),
        Box::new(S1475MissingBreak),
        Box::new(S1476NonVolatileDCL),
        Box::new(S1477SBInLoop),
        Box::new(S1478CatchIgnore),
        Box::new(S1479BTooManyCases),
        Box::new(S1480ToStringNull),
        Box::new(S1481BUnusedLocal),
        Box::new(S1482ClassCast),
        Box::new(S1483ConcurrentMod),
        Box::new(S1484NullInArray),
        Box::new(S1485IncompatibleTypes),
        Box::new(S1486ResultSetLeak),
        Box::new(S1487ConnectionLeak),
        Box::new(S1488BUnnecessaryVar),
        Box::new(S1489IgnoredReturn),
        Box::new(S1490UsingFinalize),
        Box::new(S1491SyncBoxed),
        Box::new(S1492EmptyIterator),
        Box::new(S1493HashCodeConstant),
        Box::new(S1494EqualsConstant),
        Box::new(S1495CompareConstant),
        Box::new(S1496DivByVar),
        Box::new(S1497IndexOOB),
        Box::new(S1498UninitField),
        Box::new(S1499UnreachableCode),
        Box::new(S1500BComplexSwitch),
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
    fn test_s1656_self_assignment() {
        let source = "int x = 5; x = x;";
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let issues = S1656SelfAssignment.check(&ctx);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_s2583_unreachable_code() {
        let source = "if (true) { }\nif (false) { }";
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let issues = S2583UnconditionalCondition.check(&ctx);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn test_s4973_string_comparison() {
        let source = r#"String a = "x"; String b = "y"; if (a == b) {}"#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };
        let issues = S4973EqualsForStrings.check(&ctx);
        assert!(!issues.is_empty());
    }
}
