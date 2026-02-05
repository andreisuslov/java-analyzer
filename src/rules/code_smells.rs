//! Code smell detection rules
//!
//! Rules that detect code quality issues and maintainability problems.

use crate::rules::{Rule, Severity, RuleCategory, Issue, AnalysisContext, create_issue, Lazy, Regex};
use std::collections::{HashMap, HashSet};

// Macro for simple regex-based code smell rules
macro_rules! smell_rule {
    ($struct_name:ident, $id:expr, $title:expr, $severity:expr, $pattern:expr, $message:expr) => {
        pub struct $struct_name;
        impl Rule for $struct_name {
            fn id(&self) -> &str { $id }
            fn title(&self) -> &str { $title }
            fn severity(&self) -> Severity { $severity }
            fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
            fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
                static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pattern).unwrap());
                let mut issues = Vec::new();
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if RE.is_match(line) && !line.trim().starts_with("//") && !line.trim().starts_with("*") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            $message.to_string(), Some(line.trim().to_string())));
                    }
                }
                issues
            }
        }
    };
}

// ============================================================================
// Simple regex-based rules using the macro
// ============================================================================

// S103: Lines should not be too long (handled specially below)

// S105: Tab characters should not be used
smell_rule!(S105TabCharacter, "S105", "Tab characters should not be used",
    Severity::Minor, r"\t",
    "Replace tab with spaces for consistent formatting.");

// S113: Files should end with newline (handled specially below)

// S121: Control structures should use curly braces
smell_rule!(S121MissingCurlyBraces, "S121", "Control structures should use curly braces",
    Severity::Major, r"^\s*(if|for|while)\s*\([^)]+\)\s*[^{;\s]",
    "Add curly braces to this control structure.");

// S122: Statements should be on separate lines
smell_rule!(S122MultipleStatements, "S122", "Statements should be on separate lines",
    Severity::Minor, r";\s*\w+\s*[=\(].*;\s*$",
    "Place each statement on its own line.");

// S1065: Unused labels should be removed
smell_rule!(S1065UnusedLabel, "S1065", "Unused labels should be removed",
    Severity::Minor, r"^\s*\w+\s*:\s*(?:for|while|do)",
    "Remove this unused label or use it.");

// S1068: Unused private fields (requires analysis, simplified check)
smell_rule!(S1068UnusedPrivateField, "S1068", "Unused private fields should be removed",
    Severity::Major, r"private\s+\w+\s+unused\w+",
    "Remove this unused private field.");

// S1075: URIs should not be hardcoded
smell_rule!(S1075HardcodedUri, "S1075", "URIs should not be hardcoded",
    Severity::Minor, r#"["']https?://[^"']+["']"#,
    "Extract this hardcoded URI to a configuration.");

// S1103: HTML and should not be used in comments
smell_rule!(S1103HtmlEntities, "S1103", "HTML entities should not be used in comments",
    Severity::Minor, r"//.*&(?:amp|lt|gt|quot);",
    "Replace HTML entities with actual characters in comments.");

// S1116: Empty statements should be removed
smell_rule!(S1116EmptyStatement, "S1116", "Empty statements should be removed",
    Severity::Minor, r";\s*;",
    "Remove this empty statement.");

// S1117: Local variables should not shadow class fields
smell_rule!(S1117VariableShadowing, "S1117", "Local variables should not shadow class fields",
    Severity::Major, r"this\.\w+\s*=\s*\w+\s*;",
    "Check if this local variable shadows a field.");

// S1119: Labels should not be used
smell_rule!(S1119LabelUsed, "S1119", "Labels should not be used",
    Severity::Major, r"^\s*\w+\s*:\s*(?:for|while|do|switch)",
    "Refactor to avoid using labels.");

// S1121: Assignments should not be made from within sub-expressions
smell_rule!(S1121AssignmentInSubExpression, "S1121", "Assignments should not be in sub-expressions",
    Severity::Major, r"(?:if|while)\s*\([^)]*\w+\s*=\s*\w+[^=]",
    "Extract assignment from this sub-expression.");

// S1123: Deprecated should have both annotation and Javadoc
smell_rule!(S1123DeprecatedMissing, "S1123", "@Deprecated should have both annotation and Javadoc",
    Severity::Major, r"@Deprecated\s*\n",
    "Add @deprecated Javadoc tag alongside @Deprecated annotation.");

// S1124: Modifiers should be declared in the correct order
smell_rule!(S1124ModifierOrder, "S1124", "Modifiers should be in correct order",
    Severity::Minor, r"(?:final|static)\s+(?:public|private|protected)",
    "Reorder modifiers: public/protected/private should come first.");

// S1125: Boolean literals should not be redundant
smell_rule!(S1125RedundantBoolean, "S1125", "Boolean literals should not be redundant",
    Severity::Minor, r"==\s*true|!=\s*false|true\s*==|false\s*!=",
    "Remove this redundant boolean literal comparison.");

// S1126: Return of boolean should not be wrapped in if-then-else
smell_rule!(S1126BooleanReturn, "S1126", "Boolean return should not be wrapped",
    Severity::Minor, r"if\s*\([^)]+\)\s*(?:return\s+true|return\s+false)",
    "Return the condition directly instead of wrapping in if-else.");

// S1128: Unnecessary imports should be removed
smell_rule!(S1128WildcardImport, "S1128", "Wildcard imports should be avoided",
    Severity::Minor, r"import\s+[\w.]+\.\*\s*;",
    "Replace wildcard import with specific imports.");

// S1133: Deprecated code should be removed
smell_rule!(S1133DeprecatedCode, "S1133", "Deprecated code should be removed",
    Severity::Info, r"@Deprecated",
    "Plan to remove this deprecated code.");

// S1134: Track uses of FIXME tags
smell_rule!(S1134FixmeTag, "S1134", "Track FIXME tags",
    Severity::Major, r"(?i)//\s*FIXME|/\*\s*FIXME",
    "Address this FIXME comment.");

// S1141: Try-catch blocks should not be nested
smell_rule!(S1141NestedTryCatch, "S1141", "Try-catch blocks should not be nested",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{[^}]*try\s*\{",
    "Refactor to avoid nested try-catch blocks.");

// S1147: Exit methods should not be called
smell_rule!(S1147SystemExit, "S1147", "System.exit should not be called",
    Severity::Major, r"System\.exit\s*\(",
    "Don't call System.exit() - let the main method return.");

// S1149: Synchronized classes should not be used
smell_rule!(S1149SynchronizedCollection, "S1149", "Synchronized classes should not be used",
    Severity::Major, r"new\s+(?:Vector|Hashtable|Stack|StringBuffer)\s*[<(]",
    "Use modern alternatives like ArrayList, HashMap, Deque, StringBuilder.");

// S1150: Enumeration should not be implemented
smell_rule!(S1150EnumerationInterface, "S1150", "Enumeration should not be implemented",
    Severity::Major, r"implements\s+(?:\w+\s*,\s*)*Enumeration",
    "Use Iterator instead of Enumeration.");

// S1153: String.valueOf() should not be appended to a String
smell_rule!(S1153StringValueOf, "S1153", "String.valueOf() appended to String is redundant",
    Severity::Minor, r#"\+\s*String\.valueOf\s*\("#,
    "Remove String.valueOf() - concatenation converts to String automatically.");

// S1155: Collection.isEmpty() should be used (below)

// S1157: Case-insensitive string comparisons should use equalsIgnoreCase
smell_rule!(S1157CaseInsensitiveCompare, "S1157", "Use equalsIgnoreCase for case-insensitive comparison",
    Severity::Major, r"\.toLowerCase\(\)\.equals\(|\.toUpperCase\(\)\.equals\(",
    "Use equalsIgnoreCase() instead of converting case.");

// S1158: Primitive wrappers should not be instantiated
smell_rule!(S1158PrimitiveWrapper, "S1158", "Primitive wrappers should not be instantiated",
    Severity::Major, r"new\s+(?:Integer|Long|Double|Float|Boolean|Byte|Short|Character)\s*\(",
    "Use valueOf() or autoboxing instead of new wrapper().");

// S1160: Public methods should throw at most one checked exception
smell_rule!(S1160MultipleCheckedExceptions, "S1160", "Throw at most one checked exception",
    Severity::Major, r"throws\s+\w+(?:Exception)?\s*,\s*\w+(?:Exception)?",
    "Reduce the number of checked exceptions thrown.");

// S1161: @Override should be used
smell_rule!(S1161MissingOverride, "S1161", "@Override should be used on overriding methods",
    Severity::Major, r"public\s+(?:boolean\s+equals|int\s+hashCode|String\s+toString)\s*\(",
    "Add @Override annotation to this method.");

// S1162: Checked exceptions should not be thrown
smell_rule!(S1162CheckedException, "S1162", "Avoid throwing checked exceptions",
    Severity::Major, r"throw\s+new\s+(?:IOException|SQLException|ClassNotFoundException|InterruptedException)\s*\(",
    "Consider wrapping in a runtime exception or handling differently.");

// S1163: Exceptions should not be thrown in finally blocks
smell_rule!(S1163ThrowInFinally, "S1163", "Exceptions should not be thrown in finally",
    Severity::Blocker, r"finally\s*\{[^}]*throw\s+",
    "Don't throw exceptions in finally blocks - they hide original exceptions.");

// S1164: Exceptions should not be caught and immediately rethrown
pub struct S1164CatchRethrow;
impl Rule for S1164CatchRethrow {
    fn id(&self) -> &str { "S1164" }
    fn title(&self) -> &str { "Exceptions should not be caught and rethrown" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"catch\s*\(\s*(\w+)\s+(\w+)\s*\)\s*\{\s*throw\s+(\w+)\s*;").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == cap.get(3).map(|m| m.as_str()) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Remove this useless catch block that just rethrows.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S1165: Exception classes should have final fields
pub struct S1165ExceptionNonFinalField;
impl Rule for S1165ExceptionNonFinalField {
    fn id(&self) -> &str { "S1165" }
    fn title(&self) -> &str { "Exception class fields should be final" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"class\s+\w*Exception").unwrap());
        static FIELD_RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"(?:private|protected|public)\s+(\w+)\s+\w+").unwrap());
        let mut issues = Vec::new();
        let mut in_exception_class = false;
        for (line_num, line) in ctx.source.lines().enumerate() {
            if CLASS_RE.is_match(line) { in_exception_class = true; }
            if in_exception_class && FIELD_RE.is_match(line) && !line.contains("final") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Make exception class fields final.".to_string(),
                    Some(line.trim().to_string())));
            }
            if in_exception_class && line.contains('}') && !line.contains('{') {
                in_exception_class = false;
            }
        }
        issues
    }
}

// S1166: Exception handlers should preserve the original exception
smell_rule!(S1166ExceptionCauseNotPreserved, "S1166", "Preserve original exception as cause",
    Severity::Critical, r"catch\s*\([^)]+\)\s*\{[^}]*throw\s+new\s+\w+Exception\s*\([^,)]*\)",
    "Pass the original exception as a cause parameter.");

// S1170: Public constants should be fields in an interface or utility class
pub struct S1170PublicConstant;
impl Rule for S1170PublicConstant {
    fn id(&self) -> &str { "S1170" }
    fn title(&self) -> &str { "Move public constants to interface or utility class" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"public\s+static\s+final\s+(\w+)").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let next_word = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if next_word != "class" && !line.trim().starts_with("//") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Consider moving this constant to a dedicated constants interface.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S1171: Only static class initializers should be used
smell_rule!(S1171InstanceInitializer, "S1171", "Instance initializers should be avoided",
    Severity::Minor, r"^\s*\{[^}]+\}\s*$",
    "Move initialization logic to the constructor.");

// S1174: Object.finalize() should be protected
smell_rule!(S1174FinalizePublic, "S1174", "Object.finalize() should remain protected",
    Severity::Major, r"public\s+(?:void\s+)?finalize\s*\(\s*\)",
    "Make finalize() protected, not public.");

// S1182: Classes that override clone should implement Cloneable
pub struct S1182CloneWithoutCloneable;
impl Rule for S1182CloneWithoutCloneable {
    fn id(&self) -> &str { "S1182" }
    fn title(&self) -> &str { "Classes overriding clone should implement Cloneable" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_cloneable = ctx.source.contains("implements") && ctx.source.contains("Cloneable");
        if ctx.source.contains("clone()") && !has_cloneable {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("clone()") && !line.trim().starts_with("//") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Implement Cloneable when overriding clone().".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S1185: Overriding methods should do more than call super
smell_rule!(S1185UselessOverride, "S1185", "Don't override just to call super",
    Severity::Minor, r"@Override[^}]+\{\s*(?:return\s+)?super\.\w+\([^)]*\)\s*;\s*\}",
    "Remove this override that only calls super method.");

// S1188: Anonymous classes should not have too many lines (handled specially)

// S1189: The assert keyword should not be used as variable name
smell_rule!(S1189AssertAsVariable, "S1189", "assert should not be used as a variable name",
    Severity::Critical, r"(?:int|String|boolean|Object)\s+assert\s*[=;]",
    "Rename this variable - 'assert' is a reserved keyword.");

// S1190: Future keywords should not be used as names
smell_rule!(S1190FutureKeyword, "S1190", "Future keywords should not be used as names",
    Severity::Major, r"(?:int|String|Object)\s+(?:enum|module|exports|opens|requires|uses|provides)\s*[=;]",
    "Rename this variable - it uses a reserved future keyword.");

// S1191: Classes from sun.* packages should not be used
smell_rule!(S1191SunPackages, "S1191", "Classes from sun.* should not be used",
    Severity::Major, r"import\s+sun\.|sun\.\w+\.\w+",
    "Don't use internal sun.* classes - they're not part of the public API.");

// S1193: Exception types should not be tested using instanceof
smell_rule!(S1193ExceptionInstanceof, "S1193", "Don't test exception type with instanceof",
    Severity::Major, r"instanceof\s+\w*Exception",
    "Catch specific exception types instead of using instanceof.");

// S1194: java.lang.Error should not be extended
smell_rule!(S1194ExtendError, "S1194", "java.lang.Error should not be extended",
    Severity::Major, r"extends\s+(?:Error|java\.lang\.Error)",
    "Extend Exception or RuntimeException instead of Error.");

// S1195: Array designators should be on the type
smell_rule!(S1195ArrayDesignator, "S1195", "Array designators should be on the type",
    Severity::Minor, r"(?:int|String|Object)\s+\w+\[\]",
    "Put array brackets after the type: Type[] name, not Type name[].");

// S1197: Array designators should be on the type not variable
smell_rule!(S1197ArrayBrackets, "S1197", "Array brackets on type, not variable",
    Severity::Minor, r"(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?\w+\s+\w+\s*\[\]",
    "Move array brackets to after the type name.");

// S1199: Nested code blocks should not be used
smell_rule!(S1199NestedBlock, "S1199", "Nested code blocks should not be used",
    Severity::Major, r"^\s*\{[^{}]*\}\s*$",
    "Remove unnecessary nested code block.");

// S1210: equals and hashCode should be overridden together (handled specially)

// S1214: Interfaces should not solely consist of constants
smell_rule!(S1214ConstantInterface, "S1214", "Don't use interfaces for constants only",
    Severity::Minor, r"interface\s+\w+\s*\{[^}]*(?:static\s+final|final\s+static)[^}]*\}",
    "Use a utility class instead of a constant interface.");

// S1215: System.gc() should not be called
smell_rule!(S1215SystemGc, "S1215", "System.gc() should not be called",
    Severity::Major, r"System\.gc\s*\(\s*\)|Runtime\.getRuntime\(\)\.gc\(\)",
    "Let the JVM manage garbage collection automatically.");

// S1219: Switch statements should not contain non-case labels
pub struct S1219NonCaseLabel;
impl Rule for S1219NonCaseLabel {
    fn id(&self) -> &str { "S1219" }
    fn title(&self) -> &str { "Switch should not contain non-case labels" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LABEL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(\w+)\s*:").unwrap());
        let mut issues = Vec::new();
        let mut in_switch = false;
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("switch") && line.contains("(") { in_switch = true; }
            if in_switch {
                if let Some(cap) = LABEL_RE.captures(line) {
                    let label = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    if label != "case" && label != "default" {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            "Don't use labels inside switch statements.".to_string(),
                            Some(line.trim().to_string())));
                    }
                }
            }
            if in_switch && line.contains('}') { in_switch = false; }
        }
        issues
    }
}

// S1220: The default (unnamed) package should not be used
pub struct S1220DefaultPackage;
impl Rule for S1220DefaultPackage {
    fn id(&self) -> &str { "S1220" }
    fn title(&self) -> &str { "Use a named package" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_package = ctx.source.lines().any(|line| line.trim().starts_with("package "));
        if !has_package {
            issues.push(create_issue(self, ctx.file_path, 1, 1,
                "Add a package declaration - avoid the default package.".to_string(), None));
        }
        issues
    }
}

// S1223: Non-constructor methods should not have same name as class
pub struct S1223MethodNamedAsClass;
impl Rule for S1223MethodNamedAsClass {
    fn id(&self) -> &str { "S1223" }
    fn title(&self) -> &str { "Methods should not have same name as class" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"class\s+(\w+)").unwrap());
        static METHOD_RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"(?:public|private|protected)\s+(\w+)\s+(\w+)\s*\(").unwrap());
        let mut issues = Vec::new();
        let mut class_name = String::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = CLASS_RE.captures(line) {
                class_name = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            }
            if let Some(cap) = METHOD_RE.captures(line) {
                let return_type = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let method_name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                if method_name == class_name && return_type != "void" && !return_type.is_empty() {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "This method has the same name as the class but is not a constructor.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S1226: Method parameters and caught exceptions should not be reassigned
pub struct S1226ParameterReassigned;
impl Rule for S1226ParameterReassigned {
    fn id(&self) -> &str { "S1226" }
    fn title(&self) -> &str { "Parameters should not be reassigned" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PARAM_RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"(?:public|private|protected)[^{]+\(\s*(?:final\s+)?(\w+)\s+(\w+)").unwrap());
        let mut issues = Vec::new();
        let mut params: Vec<(String, usize)> = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = PARAM_RE.captures(line) {
                if let Some(param) = cap.get(2) {
                    params.push((param.as_str().to_string(), line_num));
                }
            }
            for (param, _) in &params {
                let assign_pattern = format!(r"\b{}\s*=[^=]", regex::escape(param));
                if let Ok(re) = Regex::new(&assign_pattern) {
                    if re.is_match(line) && !line.contains("==") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            "Don't reassign method parameters.".to_string(),
                            Some(line.trim().to_string())));
                    }
                }
            }
        }
        issues
    }
}

// S1301: Switch statements should have at least 3 cases
smell_rule!(S1301TooFewCases, "S1301", "Switch should have at least 3 cases",
    Severity::Minor, r"switch\s*\([^)]+\)\s*\{\s*case[^}]*\}",
    "Consider using if-else for switches with fewer than 3 cases.");

// S1444: public static fields should be final
pub struct S1444NonFinalStaticField;
impl Rule for S1444NonFinalStaticField {
    fn id(&self) -> &str { "S1444" }
    fn title(&self) -> &str { "Public static fields should be final" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"public\s+static\s+(\w+)").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && !line.contains("final") && !line.trim().starts_with("//") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Make this public static field final.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S1450: Private fields only used in one method should be local variables
smell_rule!(S1450FieldShouldBeLocal, "S1450", "Field used in one method should be local",
    Severity::Major, r"private\s+(?:static\s+)?(\w+)\s+temp\w*\s*;",
    "Consider making this field a local variable if only used in one method.");

// S1451: Copyright headers should be present
pub struct S1451MissingCopyright;
impl Rule for S1451MissingCopyright {
    fn id(&self) -> &str { "S1451" }
    fn title(&self) -> &str { "File should have a copyright header" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let first_lines: String = ctx.source.lines().take(10).collect::<Vec<_>>().join("\n");
        if !first_lines.contains("Copyright") && !first_lines.contains("copyright") {
            issues.push(create_issue(self, ctx.file_path, 1, 1,
                "Add a copyright header to this file.".to_string(), None));
        }
        issues
    }
}

// S1481: Unused local variables should be removed
smell_rule!(S1481UnusedLocalVar, "S1481", "Remove unused local variables",
    Severity::Major, r"(?:int|String|boolean|double|float|long)\s+unused\w*\s*=",
    "Remove this unused local variable.");

// S1488: Local variables should not be declared and returned immediately
pub struct S1488ImmediateReturn;
impl Rule for S1488ImmediateReturn {
    fn id(&self) -> &str { "S1488" }
    fn title(&self) -> &str { "Don't declare variable just to return it" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static VAR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\s+(\w+)\s*=\s*[^;]+;").unwrap());
        static RETURN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"return\s+(\w+)\s*;").unwrap());
        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();
        for i in 0..lines.len().saturating_sub(1) {
            if let Some(var_cap) = VAR_RE.captures(lines[i]) {
                let var_name = var_cap.get(2).map(|m| m.as_str()).unwrap_or("");
                if let Some(ret_cap) = RETURN_RE.captures(lines[i + 1]) {
                    let ret_var = ret_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    if var_name == ret_var && !var_name.is_empty() {
                        issues.push(create_issue(self, ctx.file_path, i + 1, 1,
                            "Return the value directly instead of storing in a temporary variable.".to_string(),
                            Some(lines[i].trim().to_string())));
                    }
                }
            }
        }
        issues
    }
}

// S1612: Use method reference instead of lambda
smell_rule!(S1612MethodReference, "S1612", "Replace lambda with method reference",
    Severity::Minor, r"->\s*\w+\.\w+\([^)]*\)",
    "Consider using a method reference instead of this lambda.");

// S1643: Strings should not be concatenated using '+' in a loop
smell_rule!(S1643StringConcatInLoop, "S1643", "Use StringBuilder for String concat in loop",
    Severity::Major, r#"(?:for|while)[^{]+\{[^}]*\+\s*=\s*["']"#,
    "Use StringBuilder instead of concatenating strings in a loop.");

// S1659: Multiple variables should not be declared on same line
smell_rule!(S1659MultipleDeclarations, "S1659", "Declare one variable per line",
    Severity::Minor, r"(?:int|String|boolean|double|float|long|Object)\s+\w+\s*,\s*\w+",
    "Declare each variable on its own line.");

// S1694: Abstract classes should have abstract methods
pub struct S1694AbstractWithoutMethod;
impl Rule for S1694AbstractWithoutMethod {
    fn id(&self) -> &str { "S1694" }
    fn title(&self) -> &str { "Abstract class should have abstract methods" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"abstract\s+class\s+(\w+)").unwrap());
        let mut issues = Vec::new();
        let has_abstract_method = ctx.source.lines().any(|l| l.contains("abstract") && l.contains("(") && !l.contains("class"));
        for (line_num, line) in ctx.source.lines().enumerate() {
            if CLASS_RE.is_match(line) && !has_abstract_method {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Add abstract methods or remove the abstract modifier.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S1700: Field and method names should differ from class name
pub struct S1700FieldNamedAsClass;
impl Rule for S1700FieldNamedAsClass {
    fn id(&self) -> &str { "S1700" }
    fn title(&self) -> &str { "Field/method name differs from class" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"class\s+(\w+)").unwrap());
        static FIELD_RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"(?:private|public|protected)\s+(?:static\s+)?\w+\s+(\w+)\s*[=;]").unwrap());
        let mut issues = Vec::new();
        let mut class_name = String::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = CLASS_RE.captures(line) {
                class_name = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            }
            if let Some(cap) = FIELD_RE.captures(line) {
                let field_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if field_name == class_name && !class_name.is_empty() {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Rename this field - it has the same name as the class.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S1905: Redundant casts should be removed
smell_rule!(S1905RedundantCast, "S1905", "Remove redundant casts",
    Severity::Minor, r"\(\s*(\w+)\s*\)\s*\(\s*(\w+)\s*\)",
    "Remove this redundant cast.");

// S1940: Boolean checks should not be inverted
smell_rule!(S1940InvertedBoolean, "S1940", "Boolean checks should not be inverted",
    Severity::Minor, r"!\s*\w+\.equals\(|!.*\.contains\(|!.*\.isEmpty\(",
    "Use the negative form of this method instead of inverting.");

// S1989: Exceptions should not be thrown from destructors
smell_rule!(S1989ThrowFromFinalize, "S1989", "Don't throw from finalize",
    Severity::Blocker, r"protected\s+void\s+finalize\s*\([^)]*\)[^{]*\{[^}]*throw\s+",
    "Exceptions should not be thrown from finalize().");

// S2039: Member variable visibility should be explicitly stated
smell_rule!(S2039ExplicitVisibility, "S2039", "Use explicit visibility modifiers",
    Severity::Minor, r"^\s*(?:static\s+)?(?:final\s+)?(?:int|String|boolean|double|float|long|Object)\s+\w+\s*[=;]",
    "Add an explicit visibility modifier to this field.");

// S2094: Classes should not be empty
smell_rule!(S2094EmptyClass, "S2094", "Classes should not be empty",
    Severity::Minor, r"class\s+\w+\s*\{\s*\}",
    "Add fields/methods or use a marker interface instead.");

// S2133: Useless objects should not be created
smell_rule!(S2133UselessObject, "S2133", "Useless objects should not be created",
    Severity::Major, r"new\s+(?:Object|String)\s*\(\s*\)\s*;",
    "Remove this useless object creation.");

// S2154: Dissimilar primitive wrappers should not be used together
smell_rule!(S2154MixedWrappers, "S2154", "Don't mix dissimilar primitive wrappers",
    Severity::Critical, r"(?:Integer|Long|Double|Float)\.compare\w*\([^)]*(?:Integer|Long|Double|Float)",
    "Comparing different wrapper types may cause unexpected results.");

// S2160: Classes should not override equals without hashCode
pub struct S2160EqualsWithoutHashCode;
impl Rule for S2160EqualsWithoutHashCode {
    fn id(&self) -> &str { "S2160" }
    fn title(&self) -> &str { "Override hashCode with equals" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_equals = ctx.source.contains("boolean equals(") || ctx.source.contains("boolean equals (");
        let has_hashcode = ctx.source.contains("int hashCode(") || ctx.source.contains("int hashCode (");
        if has_equals && !has_hashcode {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("boolean equals(") || line.contains("boolean equals (") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Override hashCode() when overriding equals().".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S2162: Static methods in interfaces should not use "this"
smell_rule!(S2162StaticThis, "S2162", "Static methods should not use 'this'",
    Severity::Critical, r"static\s+\w+\s+\w+\s*\([^)]*\)[^{]*\{[^}]*\bthis\b",
    "Static methods cannot use 'this'.");

// S2166: Classes named like exceptions should extend Exception
pub struct S2166ExceptionNaming;
impl Rule for S2166ExceptionNaming {
    fn id(&self) -> &str { "S2166" }
    fn title(&self) -> &str { "Exception-named class should extend Exception" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"class\s+(\w*Exception)\s+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && !line.contains("extends") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "This class is named like an exception but doesn't extend one.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2176: Class names should not shadow interfaces or superclasses
pub struct S2176ClassShadowing;
impl Rule for S2176ClassShadowing {
    fn id(&self) -> &str { "S2176" }
    fn title(&self) -> &str { "Class names should not shadow parents" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"class\s+(\w+)\s+extends\s+\w+\s+implements\s+(.+)").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let class_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let interfaces = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                if interfaces.contains(class_name) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "This class name shadows an implemented interface.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S2178: Short-circuit logic should be used
pub struct S2178ShortCircuit;
impl Rule for S2178ShortCircuit {
    fn id(&self) -> &str { "S2178" }
    fn title(&self) -> &str { "Use short-circuit operators" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+([&|])\s+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let op_start = cap.get(1).map(|m| m.start()).unwrap_or(0);
                let next_char = line.chars().nth(op_start + 1).unwrap_or(' ');
                // Check it's not && or ||
                if next_char != '&' && next_char != '|' && !line.contains("&&") && !line.contains("||") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Use && or || instead of & or | for boolean operations.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S2232: ResultSet.isLast() should not be used
smell_rule!(S2232ResultSetIsLast, "S2232", "Don't use ResultSet.isLast()",
    Severity::Major, r"\.isLast\s*\(\s*\)",
    "Avoid ResultSet.isLast() - it may be slow or unsupported.");

// S2293: Diamond operator should be used
smell_rule!(S2293DiamondOperator, "S2293", "Use diamond operator",
    Severity::Minor, r"new\s+\w+<[^>]+>\s*\(\s*\)",
    "Use the diamond operator <> instead of repeating type arguments.");

// S2326: Unused type parameters should be removed
smell_rule!(S2326UnusedTypeParameter, "S2326", "Remove unused type parameters",
    Severity::Major, r"<\s*[A-Z]\s*>\s*(?:class|interface)",
    "Remove this unused type parameter.");

// S2388: Inner class members should not shadow outer class members
smell_rule!(S2388InnerShadowing, "S2388", "Inner class should not shadow outer",
    Severity::Major, r"class\s+\w+[^{]*\{[^}]*class\s+\w+[^{]*\{[^}]*\bthis\.",
    "Inner class members may be shadowing outer class members.");

// S2437: Silly bit operations should not be performed
smell_rule!(S2437SillyBitOp, "S2437", "Remove silly bit operations",
    Severity::Minor, r"(?:&\s*0\b|\|\s*0\b|\^\s*0\b|>>\s*0\b|<<\s*0\b)",
    "This bit operation has no effect - remove it.");

// S2440: Classes with only static members should not be instantiated
smell_rule!(S2440StaticClassInstance, "S2440", "Don't instantiate static-only classes",
    Severity::Major, r"new\s+(?:Math|Collections|Arrays|System)\s*\(",
    "This class has only static members - don't instantiate it.");

// S2479: Whitespace characters outside of string literals
smell_rule!(S2479SpecialWhitespace, "S2479", "Avoid special whitespace characters",
    Severity::Major, r"[\x00-\x08\x0B\x0C\x0E-\x1F]",
    "Remove this special whitespace character.");

// S2681: Multiline blocks should be enclosed in braces
smell_rule!(S2681MultilineBlock, "S2681", "Multiline blocks need braces",
    Severity::Critical, r"(?:if|for|while)\s*\([^)]+\)\s*\n\s*[^{].*\n\s*[^}]",
    "Add braces around this multiline block.");

// S2786: Nested enum types should not be declared static
smell_rule!(S2786StaticEnum, "S2786", "Nested enums are implicitly static",
    Severity::Minor, r"static\s+enum\s+\w+",
    "Remove 'static' - nested enums are implicitly static.");

// S2864: entrySet() should be used over keySet()
smell_rule!(S2864EntrySet, "S2864", "Use entrySet() instead of keySet()",
    Severity::Major, r"\.keySet\(\)\s*\)[^}]*\.get\(",
    "Iterate over entrySet() instead of using keySet() with get().");

// S2885: Non-thread-safe fields should not be static
smell_rule!(S2885NonThreadSafeStatic, "S2885", "Non-thread-safe fields should not be static",
    Severity::Critical, r"static\s+(?:SimpleDateFormat|Calendar|DateFormat)\s+\w+",
    "SimpleDateFormat and Calendar are not thread-safe as static fields.");

// S2970: Assertions should be complete
smell_rule!(S2970IncompleteAssertion, "S2970", "Assertions should be complete",
    Severity::Major, r"assert(?:Equals|True|False|Null|NotNull)\s*\(\s*\)",
    "This assertion is incomplete - add expected values.");

// S3011: Reflection should not be used to access private members
smell_rule!(S3011ReflectionPrivate, "S3011", "Don't use reflection on private members",
    Severity::Major, r"setAccessible\s*\(\s*true\s*\)",
    "Avoid using reflection to access private members.");

// S3012: Arrays should not be created for varargs parameters
smell_rule!(S3012VarargsArray, "S3012", "Don't create arrays for varargs",
    Severity::Minor, r#"\.format\s*\(\s*"[^"]+"\s*,\s*new\s+Object\s*\[\s*\]"#,
    "Pass values directly - no need to create an array for varargs.");

// S3047: Multiple loops over the same set should be combined
pub struct S3047MultipleLoops;
impl Rule for S3047MultipleLoops {
    fn id(&self) -> &str { "S3047" }
    fn title(&self) -> &str { "Combine multiple loops over same set" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LOOP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"for\s*\([^)]+:\s*(\w+)\s*\)").unwrap());
        let mut issues = Vec::new();
        let mut loop_vars: HashMap<String, usize> = HashMap::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = LOOP_RE.captures(line) {
                let collection = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                if let Some(&first_line) = loop_vars.get(&collection) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        format!("Consider combining this loop with the one at line {} over '{}'.", first_line, collection),
                        Some(line.trim().to_string())));
                } else {
                    loop_vars.insert(collection, line_num + 1);
                }
            }
        }
        issues
    }
}

// S3052: Fields should not be initialized to their default values
smell_rule!(S3052DefaultInit, "S3052", "Don't initialize to default values",
    Severity::Minor, r"(?:private|public|protected)\s+(?:int|long|short|byte)\s+\w+\s*=\s*0\s*;",
    "Don't initialize to default value - fields are zero/null/false by default.");

// S3077: Non-primitive fields should not be volatile
pub struct S3077NonPrimitiveVolatile;
impl Rule for S3077NonPrimitiveVolatile {
    fn id(&self) -> &str { "S3077" }
    fn title(&self) -> &str { "Non-primitives should not be volatile" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"volatile\s+(\w+)\s+\w+").unwrap());
        let primitives = ["int", "long", "short", "byte", "char", "boolean", "float", "double"];
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let type_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if !primitives.contains(&type_name) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Volatile on non-primitives doesn't ensure thread-safety of contents.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S3252: Static members should be accessed statically
pub struct S3252StaticAccess;
impl Rule for S3252StaticAccess {
    fn id(&self) -> &str { "S3252" }
    fn title(&self) -> &str { "Access static members statically" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:this|super)\.(\w+)").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && line.contains("static") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Access this static member through the class name.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S3398: private methods called only in one place should be inlined
smell_rule!(S3398InlinePrivate, "S3398", "Consider inlining private method",
    Severity::Minor, r"private\s+(?:static\s+)?(?:final\s+)?void\s+helper\w*\s*\(",
    "Consider inlining this private helper method if only called once.");

// S3400: Methods should not just return constants
smell_rule!(S3400ReturnConstant, "S3400", "Method returning constant should be a constant",
    Severity::Minor, r#"(?:return\s+\d+\s*;|return\s+"[^"]*"\s*;|return\s+(?:true|false)\s*;)"#,
    "Consider using a constant instead of a method that returns a constant.");

// S3415: Assertion arguments should be in the correct order
smell_rule!(S3415AssertionOrder, "S3415", "Assertion arguments in wrong order",
    Severity::Major, r#"assertEquals\s*\(\s*\w+\s*,\s*(?:\d+|"[^"]*"|true|false)\s*\)"#,
    "Expected value should come first in assertions.");

// S3457: Printf format strings should be correct
smell_rule!(S3457PrintfFormat, "S3457", "Printf format string issues",
    Severity::Major, r#"printf\s*\(\s*"(?:[^%]*%[^dsfn])+"#,
    "Check this printf format string for correctness.");

// S3551: Exceptions should be either logged or rethrown
smell_rule!(S3551ExceptionNotLogged, "S3551", "Log or rethrow exceptions",
    Severity::Major, r#"catch\s*\([^)]+\)\s*\{\s*//"#,
    "Either log this exception or rethrow it.");

// S3553: Aways use single-arg version of assertThrows
smell_rule!(S3553AssertThrows, "S3553", "Use specific assertThrows",
    Severity::Minor, r"assertThrows\s*\(\s*Exception\.class",
    "Use a more specific exception type in assertThrows.");

// S3626: Jump statements should not be redundant
smell_rule!(S3626RedundantJump, "S3626", "Remove redundant jump statements",
    Severity::Minor, r"continue\s*;\s*\}|break\s*;\s*default\s*:",
    "This jump statement is redundant - remove it.");

// S3740: Raw types should not be used
pub struct S3740RawType;
impl Rule for S3740RawType {
    fn id(&self) -> &str { "S3740" }
    fn title(&self) -> &str { "Raw types should not be used" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"(List|Set|Map|Collection|Iterator)\s+\w+\s*[=;]").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && !line.contains("<") && !line.trim().starts_with("//") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use generic types instead of raw types.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S3749: Members should not be unset
smell_rule!(S3749MemberUnset, "S3749", "Members should be initialized",
    Severity::Major, r"@(?:Autowired|Inject)\s+(?:private|protected)\s+\w+\s+\w+\s*;",
    "Injected members should be validated at startup.");

// S3776: Cognitive Complexity (handled in complexity.rs)

// S3923: All branches should have different implementations
pub struct S3923IdenticalBranches;
impl Rule for S3923IdenticalBranches {
    fn id(&self) -> &str { "S3923" }
    fn title(&self) -> &str { "Branches should differ" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"if\s*\([^)]+\)\s*\{\s*(\w+)\s*\}\s*else\s*\{\s*(\w+)\s*\}").unwrap());
        let mut issues = Vec::new();
        for cap in RE.captures_iter(ctx.source) {
            if cap.get(1).map(|m| m.as_str()) == cap.get(2).map(|m| m.as_str()) {
                let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
                issues.push(create_issue(self, ctx.file_path, line_num, 1,
                    "Both branches of this if do the same thing.".to_string(), None));
            }
        }
        issues
    }
}

// S3959: Consumed streams should not be reused
pub struct S3959StreamReuse;
impl Rule for S3959StreamReuse {
    fn id(&self) -> &str { "S3959" }
    fn title(&self) -> &str { "Don't reuse consumed streams" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\.stream\(\)").unwrap());
        let mut issues = Vec::new();
        let mut stream_vars: HashMap<String, usize> = HashMap::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                let var = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                if let Some(&first_line) = stream_vars.get(&var) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        format!("Stream from '{}' was already consumed at line {}.", var, first_line),
                        Some(line.trim().to_string())));
                } else {
                    stream_vars.insert(var, line_num + 1);
                }
            }
        }
        issues
    }
}

// S3972: Conditionals should start on new lines
smell_rule!(S3972ConditionalNewLine, "S3972", "Start conditionals on new lines",
    Severity::Minor, r";\s*if\s*\(",
    "Start this conditional on a new line for clarity.");

// S3973: A comparison to null should not be implicit
smell_rule!(S3973ImplicitNullCheck, "S3973", "Null comparisons should be explicit",
    Severity::Minor, r"if\s*\(\s*\w+\s*\)\s*\{",
    "Use explicit null comparison instead of truthy check.");

// S4143: Collection methods should not be used on non-collection
smell_rule!(S4143CollectionMethod, "S4143", "Check collection method usage",
    Severity::Critical, r"\.(?:add|remove|contains)\s*\(\s*\w+\s*,\s*\w+\s*\)",
    "This method call doesn't match collection semantics.");

// S4165: Assignments should not be redundant
pub struct S4165RedundantAssignment;
impl Rule for S4165RedundantAssignment {
    fn id(&self) -> &str { "S4165" }
    fn title(&self) -> &str { "Remove redundant assignment" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\s*=\s*(\w+)\s*;").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                if cap.get(1).map(|m| m.as_str()) == cap.get(2).map(|m| m.as_str()) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "This assignment assigns a variable to itself.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S4201: Null checks should use instanceof
smell_rule!(S4201NullInstanceof, "S4201", "Use instanceof for null-safe checks",
    Severity::Minor, r"!=\s*null\s*&&\s*\w+\s+instanceof",
    "The instanceof operator already handles null checks.");

// S4449: Optional.isPresent() should be paired with get()
smell_rule!(S4449OptionalIsPresent, "S4449", "Use orElse instead of isPresent/get",
    Severity::Minor, r"\.isPresent\s*\(\s*\)[^}]*\.get\s*\(\s*\)",
    "Consider using orElse(), orElseGet(), or orElseThrow() instead.");

// S4551: TypeToken should be parameterized
smell_rule!(S4551TypeToken, "S4551", "TypeToken should be parameterized",
    Severity::Major, r"new\s+TypeToken\s*\(\s*\)",
    "TypeToken requires a type parameter to work correctly.");

// S4596: Properties should be compatible with Maps
smell_rule!(S4596PropertiesMap, "S4596", "Properties should be compatible with Maps",
    Severity::Major, r"Properties\s+\w+\s*=\s*new\s+HashMap",
    "Use Properties constructor or load() for Properties objects.");

// S4719: Memento classes should have a dedicated file
smell_rule!(S4719MementoClass, "S4719", "Memento pattern classes in separate files",
    Severity::Minor, r"class\s+\w*Memento[^{]*\{",
    "Consider putting this Memento class in its own file.");

// S4738: Java.util.Random should be replaced with SecureRandom
smell_rule!(S4738InsecureRandom, "S4738", "Use SecureRandom instead of Random",
    Severity::Major, r"new\s+Random\s*\(",
    "Use SecureRandom for cryptographic purposes.");

// S4929: Pointer exceptions should not be caught
smell_rule!(S4929CatchNPE, "S4929", "Don't catch NullPointerException",
    Severity::Major, r"catch\s*\(\s*NullPointerException",
    "Fix the null check instead of catching NullPointerException.");

// S5122: CORS should be constrained
smell_rule!(S5122CorsPolicy, "S5122", "CORS should be constrained",
    Severity::Major, r#"addAllowedOrigin\s*\(\s*"\*"\s*\)"#,
    "Don't allow all origins in CORS configuration.");

// S5261: Regex should be reused
smell_rule!(S5261RegexReuse, "S5261", "Compile and reuse regex patterns",
    Severity::Major, r#"\.matches\s*\(\s*"[^"]+"\s*\)|Pattern\.compile\s*\(\s*"[^"]+"\s*\)\s*\.\s*matcher"#,
    "Compile this regex pattern once and reuse it.");

// S5411: Boxing in string concat should be avoided
smell_rule!(S5411BoxingInConcat, "S5411", "Avoid boxing in string concatenation",
    Severity::Minor, r#"\+\s*(?:Integer|Long|Double|Float|Boolean)\.valueOf\("#,
    "The value will be boxed anyway - remove explicit valueOf().");

// S5542: Encryption algorithms should be secure
smell_rule!(S5542SecureEncryption, "S5542", "Use secure encryption algorithms",
    Severity::Blocker, r#"Cipher\.getInstance\s*\(\s*"(?:DES|RC2|Blowfish)""#,
    "Use AES instead of this weak encryption algorithm.");

// S5786: JUnit5 test methods should not be public
smell_rule!(S5786JUnit5Public, "S5786", "JUnit5 tests don't need public modifier",
    Severity::Minor, r"@Test\s+public\s+void",
    "JUnit5 test methods don't need to be public.");

// S5838: assertEquals should be simplified
smell_rule!(S5838SimplifyAssert, "S5838", "Simplify assertEquals",
    Severity::Minor, r"assertEquals\s*\(\s*(?:true|false)\s*,",
    "Use assertTrue/assertFalse instead of assertEquals with boolean.");

// S5841: Regular expressions should be optimized
smell_rule!(S5841RegexOptimize, "S5841", "Optimize regex patterns",
    Severity::Minor, r#"Pattern\.compile\s*\(\s*"[^"]*\.\*[^"]*"\s*\)"#,
    "Consider making this regex more specific.");

// S5843: Replace lambdas with method references
smell_rule!(S5843LambdaToReference, "S5843", "Use method reference",
    Severity::Minor, r"->\s*(?:it|x|e)\.\w+\s*\(",
    "This lambda can be replaced with a method reference.");

// S5845: Test assertions should include messages
smell_rule!(S5845AssertMessage, "S5845", "Add message to assertions",
    Severity::Minor, r"assert(?:True|False|Null|NotNull|Equals)\s*\([^,)]+\)",
    "Add an explanatory message to this assertion.");

// S5852: URL patterns should be correct
smell_rule!(S5852UrlPattern, "S5852", "Check URL pattern format",
    Severity::Major, r#"@(?:Get|Post|Put|Delete)Mapping\s*\(\s*"[^/]"#,
    "URL patterns should start with '/'.");

// S5855: Non-short-circuit logic in tests
pub struct S5855NonShortCircuitTest;
impl Rule for S5855NonShortCircuitTest {
    fn id(&self) -> &str { "S5855" }
    fn title(&self) -> &str { "Use short-circuit in tests" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("assert") && (line.contains(" & ") || line.contains(" | ")) &&
               !line.contains("&&") && !line.contains("||") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use short-circuit operators in test assertions.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5958: Test class names should end with Test
pub struct S5958TestClassName;
impl Rule for S5958TestClassName {
    fn id(&self) -> &str { "S5958" }
    fn title(&self) -> &str { "Test class naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLASS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"class\s+(\w+)").unwrap());
        let mut issues = Vec::new();
        let has_test_annotation = ctx.source.contains("@Test");
        if has_test_annotation {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if let Some(cap) = CLASS_RE.captures(line) {
                    let class_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    if !class_name.ends_with("Test") && !class_name.ends_with("Tests") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            "Test class names should end with 'Test'.".to_string(),
                            Some(line.trim().to_string())));
                    }
                }
            }
        }
        issues
    }
}

// S5960: Assertions should not be too complex
smell_rule!(S5960ComplexAssertion, "S5960", "Simplify complex assertions",
    Severity::Minor, r"assert.*&&.*&&",
    "Split this complex assertion into multiple simpler ones.");

// S5961: Tests should not be too long
smell_rule!(S5961LongTest, "S5961", "Test methods should be concise",
    Severity::Major, r"@Test[^}]{1000,}",
    "This test method is too long - consider splitting it.");

// S5967: Method signatures should not be duplicated
pub struct S5967DuplicateSignature;
impl Rule for S5967DuplicateSignature {
    fn id(&self) -> &str { "S5967" }
    fn title(&self) -> &str { "Avoid duplicate method signatures" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"void\s+(\w+)\s*\(").unwrap());
        let mut issues = Vec::new();
        let mut method_names: HashMap<String, usize> = HashMap::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                let method = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                if let Some(&first_line) = method_names.get(&method) {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        format!("Method '{}' appears to be duplicated (first at line {}).", method, first_line),
                        Some(line.trim().to_string())));
                } else {
                    method_names.insert(method, line_num + 1);
                }
            }
        }
        issues
    }
}

// S5969: Assertions should not be negated
smell_rule!(S5969NegatedAssertion, "S5969", "Don't negate assertions",
    Severity::Minor, r"assertFalse\s*\(\s*!|assertTrue\s*\(\s*!",
    "Use the opposite assertion instead of negating.");

// S5970: Methods should not use this as a return value
smell_rule!(S5970ReturnThis, "S5970", "Avoid returning 'this' implicitly",
    Severity::Minor, r"return\s+this\s*;",
    "Consider whether returning 'this' is the right design pattern.");

// S6073: String comparison should use equals
smell_rule!(S6073StringComparison, "S6073", "Use equals for String comparison",
    Severity::Critical, r#"String[^=]*==\s*""#,
    "Use equals() for string comparison, not ==.");

// S6201: Pattern.compile flags should be constants
smell_rule!(S6201PatternFlags, "S6201", "Use Pattern constants for flags",
    Severity::Minor, r"Pattern\.compile\s*\([^)]+,\s*\d+\s*\)",
    "Use Pattern.CASE_INSENSITIVE instead of numeric flag.");

// S6204: Stream methods should use reference equality
smell_rule!(S6204StreamEquality, "S6204", "Check stream comparison methods",
    Severity::Major, r"\.filter\s*\([^)]*==",
    "Use equals() in stream filters instead of ==.");

// S6212: Local variable type inference
smell_rule!(S6212LocalTypeInference, "S6212", "Consider using var",
    Severity::Minor, r"(?:ArrayList|HashMap|HashSet)<[^>]+>\s+\w+\s*=\s*new\s+(?:ArrayList|HashMap|HashSet)",
    "Consider using 'var' for local variable type inference.");

// S6213: Restricted types should not be used
smell_rule!(S6213RestrictedIdentifiers, "S6213", "Avoid restricted identifiers",
    Severity::Major, r"(?:int|String)\s+(?:_|var|yield|record|sealed|permits)\s*[=;]",
    "This identifier is restricted in newer Java versions.");

// S6218: hashCode should use Objects.hash
smell_rule!(S6218ObjectsHash, "S6218", "Use Objects.hash in hashCode",
    Severity::Minor, r"return\s+\d+\s*\*\s*\w+",
    "Consider using Objects.hash() instead of manual hash calculation.");

// S6291: Map.compute methods should have null-safe values
smell_rule!(S6291MapCompute, "S6291", "Null-safe map compute",
    Severity::Major, r"\.compute\s*\([^)]+\)\s*[;)]",
    "Ensure the compute function handles null values correctly.");

// S6293: Regular expressions should not be too complex
smell_rule!(S6293ComplexRegex, "S6293", "Simplify complex regex",
    Severity::Major, r#"Pattern\.compile\s*\(\s*"(?:[^"]*[*+?]){5,}"#,
    "This regex is too complex - consider simplifying.");

// S6301: Add assertions to this test
pub struct S6301MissingAssertion;
impl Rule for S6301MissingAssertion {
    fn id(&self) -> &str { "S6301" }
    fn title(&self) -> &str { "Tests should have assertions" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"void\s+(\w+)\s*\(").unwrap());
        let mut issues = Vec::new();
        let mut in_test = false;
        let mut test_line = 0;
        let mut brace_count = 0;
        let mut has_assert = false;
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("@Test") { in_test = true; test_line = line_num + 1; has_assert = false; }
            if in_test && METHOD_RE.is_match(line) { brace_count = 0; }
            if in_test {
                brace_count += line.matches('{').count();
                brace_count -= line.matches('}').count();
                if line.contains("assert") || line.contains("verify") || line.contains("expect") {
                    has_assert = true;
                }
                if brace_count == 0 && line.contains('}') {
                    if !has_assert {
                        issues.push(create_issue(self, ctx.file_path, test_line, 1,
                            "Add assertions to verify test behavior.".to_string(), None));
                    }
                    in_test = false;
                }
            }
        }
        issues
    }
}

// S6353: Regex should not have empty alternation
smell_rule!(S6353EmptyAlternation, "S6353", "Regex should not have empty alternation",
    Severity::Major, r#"Pattern\.compile\s*\(\s*"[^"]*\|\|[^"]*""#,
    "This regex has empty alternation that matches everything.");

// S6355: Class literals should end with .class
smell_rule!(S6355ClassLiteral, "S6355", "Use .class for class literals",
    Severity::Minor, r"getClass\s*\(\s*\)\s*==",
    "Use .class comparison instead of getClass().");

// S6395: UUID should use randomUUID
smell_rule!(S6395UuidRandom, "S6395", "Use UUID.randomUUID()",
    Severity::Minor, r"new\s+UUID\s*\(",
    "Use UUID.randomUUID() instead of the constructor.");

// S6397: Use putIfAbsent instead of containsKey/put
smell_rule!(S6397PutIfAbsent, "S6397", "Use putIfAbsent",
    Severity::Minor, r"\.containsKey\s*\([^)]+\)[^}]*\.put\s*\(",
    "Use putIfAbsent() instead of containsKey() followed by put().");

// S6432: Switch should use case arrows
smell_rule!(S6432SwitchArrows, "S6432", "Consider switch expressions with arrows",
    Severity::Minor, r"case\s+\w+\s*:\s*\n\s*return",
    "Consider using switch expressions with -> arrows.");

// S6548: Prefer List.of over Arrays.asList for immutables
smell_rule!(S6548ListOf, "S6548", "Use List.of for immutable lists",
    Severity::Minor, r"Arrays\.asList\s*\(",
    "Consider using List.of() for immutable lists.");

// ============================================================================
// Complex rules requiring special logic
// ============================================================================

/// S106: Standard outputs should not be used directly to log
pub struct S106SystemOutUsed;

impl Rule for S106SystemOutUsed {
    fn id(&self) -> &str { "S106" }
    fn title(&self) -> &str { "Standard outputs should not be used for logging" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"System\.(out|err)\.(print|println|printf|format)").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) && !line.trim().starts_with("//") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Replace this with proper logging.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

/// S107: Methods should not have too many parameters
pub struct S107TooManyParameters;

impl Rule for S107TooManyParameters {
    fn id(&self) -> &str { "S107" }
    fn title(&self) -> &str { "Methods should not have too many parameters" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+(?:static\s+)?(?:\w+)\s+(\w+)\s*\(([^)]*)\)").unwrap()
        });

        let max_params = ctx.config.max_params.unwrap_or(7);
        let mut issues = Vec::new();

        for cap in RE.captures_iter(ctx.source) {
            if let (Some(method), Some(params)) = (cap.get(1), cap.get(2)) {
                let param_count = if params.as_str().trim().is_empty() {
                    0
                } else {
                    params.as_str().split(',').count()
                };

                if param_count > max_params {
                    let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num,
                        1,
                        format!(
                            "Method '{}' has {} parameters. Reduce to at most {}.",
                            method.as_str(),
                            param_count,
                            max_params
                        ),
                        None,
                    ));
                }
            }
        }
        issues
    }
}

/// S108: Nested blocks of code should not be left empty
pub struct S108EmptyBlock;

impl Rule for S108EmptyBlock {
    fn id(&self) -> &str { "S108" }
    fn title(&self) -> &str { "Nested blocks should not be empty" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:if|else|for|while|try|catch|finally|switch)\s*(?:\([^)]*\))?\s*\{\s*\}").unwrap()
        });

        let mut issues = Vec::new();
        for cap in RE.captures_iter(ctx.source) {
            let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
            issues.push(create_issue(
                self,
                ctx.file_path,
                line_num,
                1,
                "Empty block - add implementation or a comment.".to_string(),
                Some(cap.get(0).unwrap().as_str().trim().to_string()),
            ));
        }
        issues
    }
}

/// S109: Magic numbers should not be used
pub struct S109MagicNumber;

impl Rule for S109MagicNumber {
    fn id(&self) -> &str { "S109" }
    fn title(&self) -> &str { "Magic numbers should not be used" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"[=<>+\-*/]\s*(\d{2,})[^dDfFlL]").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.trim().starts_with("//") || line.contains("static final") {
                continue;
            }
            if let Some(cap) = RE.captures(line) {
                if let Some(num) = cap.get(1) {
                    let n: i64 = num.as_str().parse().unwrap_or(0);
                    if n != 0 && n != 1 && n != -1 && n != 10 && n != 100 {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            num.start() + 1,
                            format!("Extract {} to a named constant.", num.as_str()),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

/// S110: Inheritance tree should not be too deep
pub struct S110DeepInheritance;

impl Rule for S110DeepInheritance {
    fn id(&self) -> &str { "S110" }
    fn title(&self) -> &str { "Inheritance tree should not be too deep" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"class\s+\w+\s+extends\s+\w+").unwrap()
        });

        let mut issues = Vec::new();
        let extends_count = RE.find_iter(ctx.source).count();

        if extends_count > 5 {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                format!("This file has {} class extensions. Consider reducing inheritance depth.", extends_count),
                None,
            ));
        }
        issues
    }
}

/// S112: Generic exceptions should never be thrown
pub struct S112GenericException;

impl Rule for S112GenericException {
    fn id(&self) -> &str { "S112" }
    fn title(&self) -> &str { "Generic exceptions should not be thrown" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"throw\s+new\s+(Exception|RuntimeException|Throwable|Error)\s*\(").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = RE.captures(line) {
                if let Some(exc) = cap.get(1) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        exc.start() + 1,
                        format!("Throw a more specific exception than '{}'.", exc.as_str()),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

/// S125: Sections of code should not be commented out
pub struct S125CommentedOutCode;

impl Rule for S125CommentedOutCode {
    fn id(&self) -> &str { "S125" }
    fn title(&self) -> &str { "Commented-out code should be removed" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CODE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
            vec![
                Regex::new(r"//\s*(?:if|for|while|return|public|private|protected|class)\s*[\(\{]").unwrap(),
                Regex::new(r"//\s*\w+\s*\.\s*\w+\s*\(").unwrap(),
                Regex::new(r"//\s*\w+\s*=\s*\w+").unwrap(),
                Regex::new(r"/\*\s*(?:if|for|while|return|public|private)").unwrap(),
            ]
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for pattern in CODE_PATTERNS.iter() {
                if pattern.is_match(line) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Remove this commented-out code.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                    break;
                }
            }
        }
        issues
    }
}

/// S128: Switch cases should end with break, return, throw or continue
pub struct S128SwitchCaseFallthrough;

impl Rule for S128SwitchCaseFallthrough {
    fn id(&self) -> &str { "S128" }
    fn title(&self) -> &str { "Switch cases should end with break" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();
        for i in 0..lines.len().saturating_sub(1) {
            let line = lines[i].trim();
            let next_line = lines[i + 1].trim();
            // Check if current line has case content and next line starts a new case
            if (line.contains("case ") || line.ends_with(':')) && next_line.starts_with("case ") {
                // Check if the line before the next case has a terminating statement
                if !line.contains("break") && !line.contains("return") &&
                   !line.contains("throw") && !line.contains("continue") &&
                   !line.ends_with(':') {  // Allow empty fall-through for grouped cases
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        i + 1,
                        1,
                        "Add break, return, throw or continue to prevent fall-through.".to_string(),
                        Some(line.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

/// S131: Switch statements should have a default case
pub struct S131SwitchDefault;

impl Rule for S131SwitchDefault {
    fn id(&self) -> &str { "S131" }
    fn title(&self) -> &str { "Switch should have a default case" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static SWITCH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"switch\s*\([^)]+\)").unwrap());

        let mut issues = Vec::new();
        let mut in_switch = false;
        let mut brace_count = 0;
        let mut switch_start = 0;
        let mut has_default = false;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if SWITCH_RE.is_match(line) {
                in_switch = true;
                switch_start = line_num + 1;
                has_default = false;
                brace_count = 0;
            }

            if in_switch {
                brace_count += line.matches('{').count();
                brace_count -= line.matches('}').count();

                if line.contains("default:") || line.contains("default :") {
                    has_default = true;
                }

                if brace_count == 0 && line.contains('}') {
                    if !has_default {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            switch_start,
                            1,
                            "Add a default case to this switch.".to_string(),
                            None,
                        ));
                    }
                    in_switch = false;
                }
            }
        }
        issues
    }
}

/// S134: Control flow statements should not be nested too deeply
pub struct S134DeepNesting;

impl Rule for S134DeepNesting {
    fn id(&self) -> &str { "S134" }
    fn title(&self) -> &str { "Control flow should not be nested too deeply" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let max_nesting = ctx.config.max_nesting.unwrap_or(4);
        let mut issues = Vec::new();
        let mut nesting_level = 0;
        let mut reported_lines: HashSet<usize> = HashSet::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("if ") || trimmed.starts_with("if(")
                || trimmed.starts_with("for ") || trimmed.starts_with("for(")
                || trimmed.starts_with("while ") || trimmed.starts_with("while(")
                || trimmed.starts_with("switch ") || trimmed.starts_with("switch(")
                || trimmed.starts_with("try ")
            {
                nesting_level += 1;
                if nesting_level > max_nesting && !reported_lines.contains(&line_num) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        format!(
                            "Refactor to reduce nesting from {} to at most {}.",
                            nesting_level,
                            max_nesting
                        ),
                        Some(trimmed.to_string()),
                    ));
                    reported_lines.insert(line_num);
                }
            }

            if trimmed.contains('}') && !trimmed.starts_with("//") {
                if nesting_level > 0 {
                    nesting_level -= 1;
                }
            }
        }
        issues
    }
}

/// S135: Loops should not contain more than one break or continue
pub struct S135MultipleBreakContinue;

impl Rule for S135MultipleBreakContinue {
    fn id(&self) -> &str { "S135" }
    fn title(&self) -> &str { "Loops should have single exit point" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LOOP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:for|while)\s*\(").unwrap());
        static BREAK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bbreak\s*;").unwrap());
        static CONTINUE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bcontinue\s*;").unwrap());

        let mut issues = Vec::new();
        let mut in_loop = false;
        let mut loop_start = 0;
        let mut brace_count = 0;
        let mut break_count = 0;
        let mut continue_count = 0;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if LOOP_RE.is_match(line) && !in_loop {
                in_loop = true;
                loop_start = line_num + 1;
                brace_count = 0;
                break_count = 0;
                continue_count = 0;
            }

            if in_loop {
                brace_count += line.matches('{').count();
                brace_count -= line.matches('}').count();
                break_count += BREAK_RE.find_iter(line).count();
                continue_count += CONTINUE_RE.find_iter(line).count();

                if brace_count == 0 && line.contains('}') {
                    if break_count + continue_count > 1 {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            loop_start,
                            1,
                            format!(
                                "Loop has {} break/continue statements. Reduce to 1.",
                                break_count + continue_count
                            ),
                            None,
                        ));
                    }
                    in_loop = false;
                }
            }
        }
        issues
    }
}

/// S1066: Collapsible if statements should be merged
pub struct S1066CollapsibleIf;

impl Rule for S1066CollapsibleIf {
    fn id(&self) -> &str { "S1066" }
    fn title(&self) -> &str { "Collapsible ifs should be merged" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"if\s*\([^)]+\)\s*\{\s*\n\s*if\s*\(").unwrap()
        });

        let mut issues = Vec::new();
        for cap in RE.captures_iter(ctx.source) {
            let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
            issues.push(create_issue(
                self,
                ctx.file_path,
                line_num,
                1,
                "Merge these nested ifs using &&.".to_string(),
                None,
            ));
        }
        issues
    }
}

/// S1104: Class variable fields should not have public accessibility
pub struct S1104PublicField;

impl Rule for S1104PublicField {
    fn id(&self) -> &str { "S1104" }
    fn title(&self) -> &str { "Class fields should not be public" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"public\s+(\w+)\s+(\w+)\s*[;=]").unwrap()
        });
        let excluded = ["class", "interface", "enum", "void", "abstract", "static", "final"];

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            // Skip constants (static final)
            if line.contains("static") && line.contains("final") {
                continue;
            }
            if let Some(cap) = RE.captures(line) {
                let first_word = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                // Skip if the first word is an excluded keyword
                if excluded.contains(&first_word) {
                    continue;
                }
                if let Some(field) = cap.get(2) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        field.start() + 1,
                        format!("Make field '{}' private and provide accessors.", field.as_str()),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

/// S1118: Utility classes should not have public constructors
pub struct S1118UtilityClassConstructor;

impl Rule for S1118UtilityClassConstructor {
    fn id(&self) -> &str { "S1118" }
    fn title(&self) -> &str { "Utility classes should not have public constructors" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_only_static = ctx.source.contains("static") && !ctx.source.contains("new ");
        let has_public_constructor = ctx.source.contains("public") &&
            Regex::new(r"public\s+\w+\s*\(\s*\)").unwrap().is_match(ctx.source);

        if has_only_static && has_public_constructor {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                "Make constructor private in this utility class.".to_string(),
                None,
            ));
        }
        issues
    }
}

/// S1132: Strings literals should be placed on the left side of equals()
pub struct S1132StringLiteralOnLeft;

impl Rule for S1132StringLiteralOnLeft {
    fn id(&self) -> &str { "S1132" }
    fn title(&self) -> &str { "String literals should be on left side of equals()" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(\w+)\.equals\s*\(\s*"[^"]*"\s*\)"#).unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Put the string literal on the left side to avoid NullPointerException.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

/// S1135: Track uses of TODO tags
pub struct S1135TodoComment;

impl Rule for S1135TodoComment {
    fn id(&self) -> &str { "S1135" }
    fn title(&self) -> &str { "Track TODO tags" }
    fn severity(&self) -> Severity { Severity::Info }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)//\s*TODO|/\*\s*TODO").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Complete this TODO.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

/// S1142: Functions should not contain too many return statements
pub struct S1142TooManyReturns;

impl Rule for S1142TooManyReturns {
    fn id(&self) -> &str { "S1142" }
    fn title(&self) -> &str { "Methods should not have too many returns" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+(?:static\s+)?(?:\w+)\s+(\w+)\s*\(").unwrap()
        });
        static RETURN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\breturn\b").unwrap());

        let max_returns = 3;
        let mut issues = Vec::new();
        let mut method_name = String::new();
        let mut method_start = 0;
        let mut brace_count = 0;
        let mut return_count = 0;
        let mut in_method = false;

        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(cap) = METHOD_RE.captures(line) {
                if let Some(name) = cap.get(1) {
                    method_name = name.as_str().to_string();
                    method_start = line_num + 1;
                    in_method = true;
                    brace_count = 0;
                    return_count = 0;
                }
            }

            if in_method {
                brace_count += line.matches('{').count();
                brace_count -= line.matches('}').count();
                return_count += RETURN_RE.find_iter(line).count();

                if brace_count == 0 && line.contains('}') {
                    if return_count > max_returns {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            method_start,
                            1,
                            format!(
                                "Method '{}' has {} return statements. Reduce to at most {}.",
                                method_name, return_count, max_returns
                            ),
                            None,
                        ));
                    }
                    in_method = false;
                }
            }
        }
        issues
    }
}

/// S1144: Unused private methods should be removed
pub struct S1144UnusedPrivateField;

impl Rule for S1144UnusedPrivateField {
    fn id(&self) -> &str { "S1144" }
    fn title(&self) -> &str { "Unused private members should be removed" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static FIELD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"private\s+(?:static\s+)?(?:final\s+)?(?:\w+)\s+(\w+)\s*[;=]").unwrap()
        });

        let mut issues = Vec::new();
        let mut private_fields: HashMap<String, usize> = HashMap::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in FIELD_RE.captures_iter(line) {
                if let Some(field) = cap.get(1) {
                    private_fields.insert(field.as_str().to_string(), line_num + 1);
                }
            }
        }

        for (field, line_num) in &private_fields {
            let usage_count = ctx.source.matches(field.as_str()).count();
            if usage_count <= 1 {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    *line_num,
                    1,
                    format!("Remove unused private field '{}'.", field),
                    None,
                ));
            }
        }
        issues
    }
}

/// S1155: Collection.isEmpty() should be used to test for emptiness
pub struct S1155UseCollectionIsEmpty;

impl Rule for S1155UseCollectionIsEmpty {
    fn id(&self) -> &str { "S1155" }
    fn title(&self) -> &str { "Collection.isEmpty() should be used" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.size\(\)\s*(?:==|!=|>|<=)\s*0").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if RE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use isEmpty() instead of comparing size() to 0.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

/// S1168: Empty arrays and collections should be returned instead of null
pub struct S1168ReturnEmptyInsteadOfNull;

impl Rule for S1168ReturnEmptyInsteadOfNull {
    fn id(&self) -> &str { "S1168" }
    fn title(&self) -> &str { "Return empty collections instead of null" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:List|Set|Collection|Map|Array)\s*(?:<[^>]+>)?\s+\w+.*return\s+null\s*;|return\s+null\s*;.*(?:List|Set|Collection|Map|Array)").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("return null") &&
               (line.contains("List") || line.contains("Set") || line.contains("Collection") ||
                line.contains("Map") || line.contains("[]")) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Return an empty collection instead of null.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

/// S1172: Unused method parameters should be removed
pub struct S1172UnusedMethodParameter;

impl Rule for S1172UnusedMethodParameter {
    fn id(&self) -> &str { "S1172" }
    fn title(&self) -> &str { "Unused method parameters should be removed" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, _ctx: &AnalysisContext) -> Vec<Issue> {
        Vec::new()
    }
}

/// S1181: Throwable and Error should not be caught
pub struct S1181CatchThrowable;

impl Rule for S1181CatchThrowable {
    fn id(&self) -> &str { "S1181" }
    fn title(&self) -> &str { "Throwable and Error should not be caught" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"catch\s*\(\s*(Throwable|Error|java\.lang\.Throwable|java\.lang\.Error)\s+").unwrap()
        });

        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                if let Some(exc_type) = cap.get(1) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        exc_type.start() + 1,
                        format!("Catch a specific exception instead of '{}'.", exc_type.as_str()),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

/// S1186: Methods should not be empty
pub struct S1186EmptyMethod;

impl Rule for S1186EmptyMethod {
    fn id(&self) -> &str { "S1186" }
    fn title(&self) -> &str { "Methods should not be empty" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:public|private|protected)\s+(?:static\s+)?(?:\w+)\s+(\w+)\s*\([^)]*\)\s*\{\s*\}").unwrap()
        });

        let mut issues = Vec::new();
        for cap in RE.captures_iter(ctx.source) {
            if let Some(method) = cap.get(1) {
                let line_num = ctx.source[..cap.get(0).unwrap().start()].lines().count() + 1;
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num,
                    1,
                    format!("Add implementation to empty method '{}' or add a comment.", method.as_str()),
                    None,
                ));
            }
        }
        issues
    }
}

/// S1192: String literals should not be duplicated
pub struct S1192DuplicateStrings;

impl Rule for S1192DuplicateStrings {
    fn id(&self) -> &str { "S1192" }
    fn title(&self) -> &str { "String literals should not be duplicated" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]{4,})""#).unwrap());

        let mut string_counts: HashMap<String, (usize, usize)> = HashMap::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            for cap in RE.captures_iter(line) {
                if let Some(s) = cap.get(1) {
                    let key = s.as_str().to_string();
                    string_counts.entry(key).or_insert((line_num + 1, 0)).1 += 1;
                }
            }
        }

        let mut issues = Vec::new();
        for (string, (line_num, count)) in string_counts {
            if count >= 3 {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num,
                    1,
                    format!("Define a constant for \"{}\" - used {} times.", string, count),
                    None,
                ));
            }
        }
        issues
    }
}

/// S1210: "equals(Object obj)" and "hashCode()" should be overridden in pairs
pub struct S1210EqualsHashCode;

impl Rule for S1210EqualsHashCode {
    fn id(&self) -> &str { "S1210" }
    fn title(&self) -> &str { "equals and hashCode should be overridden together" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let has_equals = ctx.source.contains("boolean equals(Object") || ctx.source.contains("boolean equals(java.lang.Object");
        let has_hashcode = ctx.source.contains("int hashCode()");

        let mut issues = Vec::new();
        if has_equals && !has_hashcode {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                "Override hashCode() since equals() is overridden.".to_string(),
                None,
            ));
        } else if !has_equals && has_hashcode {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                "Override equals() since hashCode() is overridden.".to_string(),
                None,
            ));
        }
        issues
    }
}

// Additional code smell rules - batch 2

// S800: Nested comments
smell_rule!(S800NestedComments, "S800", "Nested comments should not be used",
    Severity::Minor, r"/\*.*\*/.*\*/",
    "Avoid nested comments.");

// S815: Unicode BOM
smell_rule!(S815UnicodeBom, "S815", "Source files should not contain BOM",
    Severity::Minor, r"^\xEF\xBB\xBF",
    "Remove the BOM from the beginning of the file.");

// S818: Literal suffixes
smell_rule!(S818LiteralSuffix, "S818", "Long literal suffixes should be uppercase",
    Severity::Minor, r"\d+l\b",
    "Use uppercase L suffix instead of lowercase l.");

// S864: Limited dependence on operator precedence
smell_rule!(S864OperatorPrecedence, "S864", "Operator precedence should be explicit",
    Severity::Major, r"[^&|]\s*[&|]\s*[^&|]",
    "Use parentheses to clarify operator precedence.");

// S881: Increment decrement in expression
smell_rule!(S881IncrementDecrement, "S881", "Increment/decrement operators should not be mixed",
    Severity::Major, r"\+\+.*\+\+|--.*--",
    "Don't mix increment/decrement operators in expressions.");

// S888: Equality loop termination
smell_rule!(S888LoopTermination, "S888", "Loop termination should use relational operators",
    Severity::Critical, r"for\s*\([^;]*;\s*\w+\s*!=\s*\w+\s*;",
    "Use <= or < instead of != for loop termination.");

// S923: Return type void
smell_rule!(S923VoidReturnType, "S923", "Methods should have explicit return type",
    Severity::Minor, r"public\s+\w+\s*\([^)]*\)\s*\{",
    "Specify explicit return type.");

// S979: Parentheses in condition
smell_rule!(S979ConditionParentheses, "S979", "Redundant parentheses in conditions",
    Severity::Minor, r"if\s*\(\s*\([^)]+\)\s*\)",
    "Remove redundant parentheses.");

// S1151: Switch case complexity
pub struct S1151SwitchCaseComplexity;
impl Rule for S1151SwitchCaseComplexity {
    fn id(&self) -> &str { "S1151" }
    fn title(&self) -> &str { "Switch cases should not have too many lines" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();
        let mut case_start = 0;
        let mut in_case = false;
        for (i, line) in lines.iter().enumerate() {
            if line.contains("case ") || line.contains("default:") {
                if in_case && i - case_start > 10 {
                    issues.push(create_issue(self, ctx.file_path, case_start + 1, 1,
                        "This case block is too long. Extract to a method.".to_string(), None));
                }
                case_start = i;
                in_case = true;
            }
        }
        issues
    }
}

// S1169: Empty collection return
smell_rule!(S1169EmptyCollectionReturn, "S1169", "Return empty collection instead of null",
    Severity::Major, r"return\s+null\s*;.*(?:Collection|List|Set|Map)",
    "Return Collections.emptyList() or similar.");

// S1200: Class coupling
pub struct S1200ClassCoupling;
impl Rule for S1200ClassCoupling {
    fn id(&self) -> &str { "S1200" }
    fn title(&self) -> &str { "Classes should not be coupled to too many other classes" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let import_count = ctx.source.lines().filter(|l| l.starts_with("import ")).count();
        if import_count > 30 {
            issues.push(create_issue(self, ctx.file_path, 1, 1,
                format!("This class depends on {} other classes. Reduce coupling.", import_count), None));
        }
        issues
    }
}

// S1213: Parameter order
smell_rule!(S1213ParameterOrder, "S1213", "Members should be declared in order",
    Severity::Minor, r"private\s+\w+[^}]*public\s+\w+",
    "Declare members in order: public, protected, private.");

// S1258: Parsing to double
smell_rule!(S1258ParsingDouble, "S1258", "Use Double.parseDouble instead of valueOf",
    Severity::Minor, r"Double\.valueOf\s*\(",
    "Use Double.parseDouble() for primitive conversion.");

// S1313: IP addresses hardcoded
smell_rule!(S1313IpHardcoded, "S1313", "IP addresses should not be hardcoded",
    Severity::Major, r#""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""#,
    "Extract hardcoded IP address to configuration.");

// S1479: Switch too many cases
pub struct S1479TooManyCases;
impl Rule for S1479TooManyCases {
    fn id(&self) -> &str { "S1479" }
    fn title(&self) -> &str { "Switch statements should not have too many cases" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::CodeSmell }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let case_count = ctx.source.matches("case ").count();
        if case_count > 30 {
            issues.push(create_issue(self, ctx.file_path, 1, 1,
                format!("This switch has {} cases. Consider using a Map or polymorphism.", case_count), None));
        }
        issues
    }
}

// S1640: Maps entrySet iteration
smell_rule!(S1640EntrySetIteration, "S1640", "Use entrySet() for iterating Map",
    Severity::Major, r"for\s*\([^:]+:\s*\w+\.keySet\(\)\)",
    "Use entrySet() instead of keySet() when you need both key and value.");

// S1699: Constructor calling overridable method
smell_rule!(S1699ConstructorOverridable, "S1699", "Constructors should not call overridable methods",
    Severity::Major, r"public\s+\w+\s*\([^)]*\)\s*\{[^}]*\bthis\.\w+\s*\(",
    "Don't call overridable methods in constructors.");

// S1710: Annotation naming
smell_rule!(S1710AnnotationNaming, "S1710", "Annotation types should have @interface",
    Severity::Major, r"public\s+class\s+\w+Annotation",
    "Use @interface for annotation types.");

// S1820: Subclass names
smell_rule!(S1820SubclassNaming, "S1820", "Subclasses should not duplicate parent names",
    Severity::Minor, r"class\s+\w+Base\s+extends\s+\w+Base",
    "Subclass name should not repeat parent name.");

// S1821: Nested switch
smell_rule!(S1821NestedSwitch, "S1821", "Nested switch statements should not be used",
    Severity::Major, r"switch\s*\([^)]+\)\s*\{[^}]*switch\s*\(",
    "Extract nested switch to a separate method.");

// S2057: Serializable UID
smell_rule!(S2057SerialVersionUID, "S2057", "Serializable classes should have serialVersionUID",
    Severity::Major, r"implements\s+Serializable",
    "Add serialVersionUID to this Serializable class.");

// S2130: Parsing primitive
smell_rule!(S2130ParsingPrimitive, "S2130", "Use primitive parse methods",
    Severity::Minor, r"Integer\.valueOf\s*\([^)]+\)\.intValue\(",
    "Use Integer.parseInt() instead.");

// S2131: String valueOf for primitive
smell_rule!(S2131StringValueOfPrimitive, "S2131", "Primitives in String valueOf",
    Severity::Minor, r"String\.valueOf\s*\(\s*\d+\s*\)",
    "Just write the literal as a string.");

// S2142: InterruptedException handling
smell_rule!(S2143InterruptedHandling, "S2143", "InterruptedException should restore interrupt",
    Severity::Major, r"catch\s*\(\s*InterruptedException",
    "Restore interrupt flag or rethrow InterruptedException.");

// S2209: Static members access
smell_rule!(S2209StaticMemberAccess, "S2209", "Static members should be accessed statically",
    Severity::Major, r"(?:this|super)\.\w+\s*=",
    "Access static members via the class name.");

// S2221: Throw generic exception
smell_rule!(S2221ThrowGeneric, "S2221", "Exception handlers should preserve original exception",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{[^}]*throw\s+new\s+\w+Exception\s*\(",
    "Preserve the original exception when rethrowing.");

// S2225: Return null from toString
smell_rule!(S2225NullToString, "S2225", "toString should not return null",
    Severity::Critical, r"toString\s*\([^)]*\)\s*\{[^}]*return\s+null",
    "toString() should never return null.");

// S2272: Iterator remove
smell_rule!(S2272IteratorRemove, "S2272", "Iterator.remove should be called correctly",
    Severity::Critical, r"Iterator[^{]*\{[^}]*\.remove\(",
    "Use Iterator.remove() instead of collection.remove().");

// S2301: Public methods should not contain selector argument
smell_rule!(S2301SelectorArgument, "S2301", "Methods should not take boolean selector",
    Severity::Major, r"public\s+\w+\s+\w+\s*\([^)]*boolean\s+\w+Select",
    "Split this method into two - one for each boolean case.");

// S2390: Subclasses accessing parent static
smell_rule!(S2390SubclassStaticAccess, "S2390", "Subclasses should not access parent static",
    Severity::Minor, r"extends\s+\w+[^{]+super\.\w+\s*=",
    "Access parent static members via parent class name.");

// S2447: Null Boolean return
smell_rule!(S2447NullBooleanReturn, "S2447", "Boolean methods should not return null",
    Severity::Major, r"Boolean\s+\w+\s*\([^)]*\)\s*\{[^}]*return\s+null",
    "Boolean methods should return true or false, not null.");

// S2583B: Always true condition (additional)
smell_rule!(S2583BTrueCondition, "S2583B", "Conditions should not always evaluate to true",
    Severity::Major, r"if\s*\(\s*1\s*==\s*1\s*\)",
    "This condition always evaluates to true.");

// S2638: Parameter changed
smell_rule!(S2638ParameterChanged, "S2638", "Method overrides should not change parameter names",
    Severity::Minor, r"@Override[^{]+\(\s*\w+\s+\w+1\s*\)",
    "Keep parameter names consistent with overridden method.");

// S2692: indexOf without check
smell_rule!(S2692IndexOfCheck, "S2692", "indexOf result should be checked",
    Severity::Major, r"\.indexOf\s*\([^)]+\)\s*[><=!]=?\s*-?\d",
    "Check if indexOf result is -1 or >= 0, not other values.");

// S2698: Assert message
smell_rule!(S2698AssertionMessage, "S2698", "Assertions should include a message",
    Severity::Minor, r"assert\s+\w+\s*;",
    "Add a message to this assertion.");

// S2925: Thread.sleep in tests
smell_rule!(S2925ThreadSleepTest, "S2925", "Thread.sleep should not be used in tests",
    Severity::Major, r"@Test[^}]+Thread\.sleep\s*\(",
    "Use awaitility or similar instead of Thread.sleep in tests.");

// S2959: Stream intermediate operations
smell_rule!(S2959StreamIntermediate, "S2959", "Stream intermediate operations should be collected",
    Severity::Major, r"\.stream\(\)\.(?:filter|map)\([^)]+\)\s*;",
    "Terminal operation needed after stream intermediate operations.");

// S3046: Regex DoS vulnerability
smell_rule!(S3046RegexDos, "S3046", "Regex should not be vulnerable to DoS",
    Severity::Critical, r#"Pattern\.compile\s*\(\s*"[^"]*\(\.\*\)\*"#,
    "This regex pattern is vulnerable to catastrophic backtracking.");

// S3060: Override with same return type
smell_rule!(S3060OverrideReturnType, "S3060", "Override should have same return type",
    Severity::Minor, r"@Override\s+public\s+Object\s+\w+\s*\(",
    "Consider using more specific return type in override.");

// S3237: Value based equality
smell_rule!(S3237ValueBasedEquality, "S3237", "Value-based classes should not be compared by reference",
    Severity::Major, r"(?:LocalDate|LocalTime|LocalDateTime|Optional)\s+\w+\s*==",
    "Use equals() for value-based class comparison.");

// S3254: Boolean expression
smell_rule!(S3254BooleanExpression, "S3254", "Boolean expressions should be simplified",
    Severity::Minor, r"==\s*true|!=\s*false",
    "Remove redundant comparison with boolean literal.");

// S3257: Declarations and initializations
smell_rule!(S3257DeclareInitialize, "S3257", "Declarations should be initialized",
    Severity::Minor, r"(?:int|String|boolean|double|float|long)\s+\w+\s*;",
    "Consider initializing this variable at declaration.");

// S3281: Superfluous type argument
smell_rule!(S3281SuperfluousTypeArg, "S3281", "Superfluous type argument",
    Severity::Minor, r"Collections\.<\w+>empty",
    "Remove unnecessary explicit type argument.");

// S3330: Optional orElse
smell_rule!(S3330OptionalOrElse, "S3330", "Optional.orElse should not use method call",
    Severity::Major, r"\.orElse\s*\([^)]*\w+\(",
    "Use orElseGet() for expensive computations.");

// S3358: Nested ternary
smell_rule!(S3358NestedTernary2, "S3358B", "Ternary operators should not be nested",
    Severity::Major, r"\?[^:]+\?[^:]+:",
    "Extract nested ternary to if-else or method.");

// S3546: getClass() synchronization
smell_rule!(S3546GetClassSync, "S3546", "getClass() should not be used for synchronization",
    Severity::Critical, r"synchronized\s*\(\s*getClass\(\)\s*\)",
    "Use ClassName.class for synchronization lock.");

// S3655B: Optional unsafe access
smell_rule!(S3655OptionalUnsafe2, "S3655B", "Optional.get should be called only when present",
    Severity::Critical, r"Optional\w*\s*[^;]*\.get\(\)\s*;",
    "Check isPresent() before calling get().");

// S3655: Optional unsafe access (additional)
smell_rule!(S3655OptionalGet, "S3655C", "Optional get without check",
    Severity::Critical, r"Optional[^;]+\.get\(\)",
    "Use orElse or check isPresent before get().");

// S3878: Arrays passed as varargs
smell_rule!(S3878ArraysVarargs, "S3878", "Arrays should not be passed as varargs arguments",
    Severity::Minor, r"\.\w+\s*\(\s*new\s+\w+\s*\[\s*\]\s*\{",
    "Pass array elements directly without wrapping in array.");

// S3981: Collection size comparison
smell_rule!(S3981CollectionSize, "S3981", "Collection size should not be compared to negative",
    Severity::Major, r"\.size\(\)\s*[<>=]+\s*-\d",
    "Collection size is never negative.");

// S3986: Date format constants
smell_rule!(S3986DateFormatConstants, "S3986", "Date format should be thread-safe",
    Severity::Major, r"static\s+(?:final\s+)?(?:Simple)?DateFormat",
    "DateFormat is not thread-safe, don't use as static.");

// S4032: Packages at same depth
smell_rule!(S4032PackageSameDepth, "S4032", "Packages should be organized at same depth",
    Severity::Minor, r"package\s+\w+\.\w+\.\w+\.\w+\.\w+\.\w+",
    "Package nesting is too deep.");

// S4065: Useless Thread.interrupted
smell_rule!(S4065UselessInterrupted, "S4065", "Thread.interrupted should be used properly",
    Severity::Major, r"Thread\.interrupted\(\)\s*;",
    "Thread.interrupted() return value should be checked.");

// S4144: Duplicate methods (additional)
smell_rule!(S4144DuplicateMethod2, "S4144B", "Methods should not be duplicates",
    Severity::Major, r"void\s+\w+Copy\s*\([^)]*\)",
    "This method appears to be a duplicate.");

// S4165: Assignment to self
smell_rule!(S4165SelfAssign, "S4165B", "Assignment to self is useless",
    Severity::Major, r"this\.\w+\s*=\s*this\.\w+\s*;",
    "This assignment has no effect.");

// S4276: Primitive types in generics
smell_rule!(S4276PrimitiveGenerics, "S4276B", "Use primitive stream types",
    Severity::Major, r"Stream<Integer>|Stream<Long>|Stream<Double>",
    "Use IntStream/LongStream/DoubleStream instead.");

// S4288: Primitive array toString
smell_rule!(S4288ArrayToString, "S4288", "Arrays should use Arrays.toString",
    Severity::Major, r"\[\]\.toString\(\)",
    "Use Arrays.toString() to print array contents.");

// S4351: compareTo return MIN_VALUE
smell_rule!(S4351CompareToMinValue, "S4351B", "compareTo should not return MIN_VALUE",
    Severity::Major, r"compareTo[^}]+return\s+Integer\.MIN_VALUE",
    "Don't return Integer.MIN_VALUE from compareTo.");

// S4423: Weak TLS protocol
smell_rule!(S4423WeakTls, "S4423B", "Weak TLS protocols should not be used",
    Severity::Critical, r#"SSLContext\.getInstance\s*\(\s*"TLSv1""#,
    "Use TLSv1.2 or later.");

// S4524: Default switch case position
smell_rule!(S4524DefaultSwitchPosition, "S4524", "Default case should be last",
    Severity::Minor, r"default\s*:[^}]+case\s+",
    "Put default case at the end of switch.");

// S4544: Generic wildcard
smell_rule!(S4544GenericWildcard, "S4544", "Unsafe use of generic wildcards",
    Severity::Major, r"<\?\s*super\s+\w+>",
    "Consider bounded wildcard constraints.");

// S4601: Unicode separator
smell_rule!(S4601UnicodeSeparator, "S4601", "Standard character sets should be used",
    Severity::Minor, r#"new\s+String\s*\([^)]+,\s*"UTF8"\s*\)"#,
    "Use StandardCharsets.UTF_8 instead.");

// S4682: Primitive comparison
smell_rule!(S4682PrimitiveComparison, "S4682", "Primitives should not be compared with ==",
    Severity::Major, r"Integer\s+\w+\s*==\s*Integer|Long\s+\w+\s*==\s*Long",
    "Use equals() for wrapper comparison.");

// S4784: Regex complexity
smell_rule!(S4784RegexComplexity, "S4784B", "Regex should not be too complex",
    Severity::Major, r#"Pattern\.compile\s*\(\s*"[^"]{80,}""#,
    "This regex is too complex, consider simplifying.");

// S4929: Catch NPE
smell_rule!(S4929CatchNpe2, "S4929B", "NullPointerException should not be caught",
    Severity::Major, r"catch\s*\(\s*(?:Null|Index)",
    "Fix the code instead of catching NPE/IndexOutOfBounds.");

// S5042: Zip entry extraction
smell_rule!(S5042ZipEntry, "S5042", "Archive entry should be validated",
    Severity::Critical, r"ZipEntry[^}]+\.getName\(\)",
    "Validate archive entry paths before extraction.");

// S5128: Bean validation
smell_rule!(S5128BeanValidation, "S5128", "Bean validation should be used",
    Severity::Minor, r"@(?:NotNull|NotEmpty|NotBlank)\s*\n\s*@",
    "Consider using @NotBlank instead of multiple annotations.");

// S5361: String replace all
smell_rule!(S5361ReplaceAll, "S5361B", "replaceAll uses regex, use replace for literal",
    Severity::Minor, r#"\.replaceAll\s*\(\s*"[^"]*(?:\\.|[^\\.])""#,
    "Use replace() for simple string replacement.");

// S5443: File permissions
smell_rule!(S5443FilePerm, "S5443B", "File permissions should be restricted",
    Severity::Major, r"setWritable\s*\(\s*true\s*,\s*false\s*\)",
    "Don't allow all users to write.");

// S5663: Public test fields
smell_rule!(S5663PublicTestField, "S5663B", "Test class fields should not be public",
    Severity::Minor, r"@Test[^}]+public\s+\w+\s+\w+\s*=",
    "Test class fields should be private.");

// S5976: Tests should include assertions
smell_rule!(S5976TestAssertions, "S5976", "Tests should include assertions",
    Severity::Major, r"@Test\s+void\s+test\w+\s*\([^)]*\)\s*\{\s*\}",
    "Add assertions to this test method.");

// S6035: URI building
smell_rule!(S6035UriBuild, "S6035", "URIs should be built with proper API",
    Severity::Major, r#"new\s+URI\s*\(\s*"[^"]*"\s*\+"#,
    "Use UriBuilder instead of string concatenation.");

// S6103: Try with resources
smell_rule!(S6103TryWithResources, "S6103", "Try-with-resources should be used",
    Severity::Major, r"finally\s*\{[^}]*\.close\(\)",
    "Use try-with-resources instead of finally close().");

// S6126: String builder replace
smell_rule!(S6126StringBuilderReplace, "S6126", "StringBuilder should use append",
    Severity::Minor, r"StringBuilder[^;]*\+=",
    "Use append() instead of += for StringBuilder.");

// S6201: Pattern flags as constants
smell_rule!(S6201PatternFlagsConst, "S6201B", "Pattern flags should use constants",
    Severity::Minor, r"Pattern\.compile\s*\([^,]+,\s*\d+\s*\)",
    "Use Pattern.CASE_INSENSITIVE etc. instead of numbers.");

// S6208: Redundant parentheses
smell_rule!(S6208RedundantParens, "S6208", "Redundant parentheses should be removed",
    Severity::Minor, r"return\s*\(\s*\w+\s*\)\s*;",
    "Remove unnecessary parentheses around return value.");

// S6242: Constructor injection
smell_rule!(S6242ConstructorInjection, "S6242", "Use constructor injection",
    Severity::Major, r"@Autowired\s*\n\s*private",
    "Prefer constructor injection over field injection.");

// S6353: Regex empty alternation
smell_rule!(S6353EmptyAlt2, "S6353B", "Regex alternation should not be empty",
    Severity::Major, r#"Pattern\.compile\s*\(\s*"[^"]*\(\|\)""#,
    "Empty alternation in regex matches everything.");

// S6395: Random UUID
smell_rule!(S6395RandomUuid, "S6395B", "Use UUID.randomUUID",
    Severity::Minor, r"new\s+UUID\s*\(\s*\d",
    "Use UUID.randomUUID() for random UUIDs.");

// S6539: Too many parameters
smell_rule!(S6539TooManyParams, "S6539", "Methods should not have too many parameters",
    Severity::Major, r"public\s+\w+\s+\w+\s*\([^)]{200,}\)",
    "Too many parameters - use builder or object.");

// ============================================================================
// Batch 3 - Additional code smell rules
// ============================================================================

// S1155B: Collection isEmpty preference
smell_rule!(S1155BCollectionEmpty, "S1155B", "Use isEmpty() instead of size() == 0",
    Severity::Minor, r"\.length\s*==\s*0|\.length\s*>\s*0",
    "Use isEmpty() or isNotEmpty() for better readability.");

// S1172B: Unused method parameter check
smell_rule!(S1172BUnusedParam, "S1172B", "Unused method parameters should be removed",
    Severity::Major, r"public\s+\w+\s+\w+\s*\([^)]*\bunused\w+",
    "Remove or use this unused parameter.");

// S1301B: Switch instead of if chain
smell_rule!(S1301BSwitchPreferred, "S1301B", "Switch should be used instead of if-else chain",
    Severity::Minor, r"if\s*\([^)]+==\s*\d+\)\s*\{[^}]*\}\s*else\s+if\s*\([^)]+==\s*\d+\)",
    "Use switch statement for multiple equality comparisons.");

// S1302: Avoid using the same name for multiple constants
smell_rule!(S1302DuplicateConstName, "S1302", "Constants should have unique names",
    Severity::Minor, r"static\s+final\s+\w+\s+\w+\s*=[^;]*;[^}]*static\s+final\s+\w+\s+\w+\s*=",
    "Avoid reusing constant names across classes.");

// S1303: Avoid string literals longer than N characters
smell_rule!(S1303LongStringLiteral, "S1303", "String literals should not be too long",
    Severity::Minor, r#""[^"]{100,}""#,
    "Consider breaking this long string into constants.");

// S1312: Avoid printStackTrace
smell_rule!(S1312PrintStackTrace, "S1312", "printStackTrace should not be called",
    Severity::Major, r"\.printStackTrace\s*\(\s*\)",
    "Use proper logging instead of printStackTrace().");

// S1314: Octal values should not be used
smell_rule!(S1314OctalValue, "S1314", "Octal values should not be used",
    Severity::Major, r"\s0[0-7]+[lL]?\b",
    "Avoid octal values - use decimal or hex instead.");

// S1315: Track FIXMEs with a ticket reference
smell_rule!(S1315FixmeTicket, "S1315", "FIXME should have a ticket reference",
    Severity::Minor, r"(?i)FIXME\s*$|FIXME\s+[^A-Z]",
    "Add a ticket reference to this FIXME comment.");

// S1316: Track TODO with ticket reference
smell_rule!(S1316TodoTicket, "S1316", "TODO should have a ticket reference",
    Severity::Minor, r"(?i)TODO\s*$|TODO\s+[^A-Z]",
    "Add a ticket reference to this TODO comment.");

// S1317: StringBuilder capacity
smell_rule!(S1317StringBuilderCap, "S1317", "StringBuilder should be created with capacity",
    Severity::Minor, r"new\s+StringBuilder\s*\(\s*\)",
    "Consider providing initial capacity to StringBuilder.");

// S1318: Avoid double brace initialization
smell_rule!(S1318DoubleBrace, "S1318", "Double brace initialization should not be used",
    Severity::Major, r"new\s+\w+\s*\(\s*\)\s*\{\s*\{",
    "Avoid double brace initialization - use static block or builder.");

// S1319: Declare using interface types
smell_rule!(S1319InterfaceType, "S1319", "Declarations should use interface types",
    Severity::Minor, r"(?:ArrayList|LinkedList|HashSet|TreeSet|HashMap|TreeMap)\s*<[^>]+>\s+\w+\s*=",
    "Use List, Set, or Map interface types in declarations.");

// S1320: Class and interface should not be named similar
smell_rule!(S1320SimilarNames, "S1320", "Avoid similar class and interface names",
    Severity::Minor, r"interface\s+I\w+|class\s+\w+Impl\b",
    "Avoid I- prefix for interfaces or -Impl suffix for classes.");

// S1321: Comparison to SIZE_MAX
smell_rule!(S1321SizeMax, "S1321", "Avoid comparison to SIZE_MAX",
    Severity::Major, r">\s*Integer\.MAX_VALUE|<\s*Integer\.MIN_VALUE",
    "This comparison will always be true or false.");

// S1322: Avoid concatenating null
smell_rule!(S1322ConcatNull, "S1322", "String concatenation with null",
    Severity::Major, r#"\+\s*null\b|\bnull\s*\+"#,
    "Avoid concatenating null to strings.");

// S1323: Constant expression as if condition
smell_rule!(S1323ConstantCondition, "S1323", "Constant expressions in conditions",
    Severity::Major, r"if\s*\(\s*(?:true|false)\s*\)",
    "Remove this constant condition.");

// S1324: Array designator position
smell_rule!(S1324ArrayPosition, "S1324", "Array designator should be after type",
    Severity::Minor, r"\w+\s+\w+\[\]\s*(?:,|;|\))",
    "Move array designator [] to after the type.");

// S1325: Avoid anonymous inner classes for Runnable
smell_rule!(S1325AnonymousRunnable, "S1325", "Use lambda instead of anonymous Runnable",
    Severity::Minor, r"new\s+Runnable\s*\(\s*\)\s*\{",
    "Use lambda expression instead of anonymous Runnable.");

// S1326: Avoid catching Throwable
smell_rule!(S1326CatchThrowable, "S1326", "Catching Throwable hides errors",
    Severity::Major, r"catch\s*\(\s*Throwable\b",
    "Catch more specific exceptions instead of Throwable.");

// S1327: Multiple assertions in one test
smell_rule!(S1327MultipleAsserts, "S1327", "Tests should have focused assertions",
    Severity::Minor, r"@Test[^}]+assert\w+[^}]+assert\w+[^}]+assert\w+[^}]+assert\w+",
    "Consider splitting test with many assertions.");

// S1328: Utility class should not have public constructor
smell_rule!(S1328UtilityConstructor, "S1328", "Utility class should have private constructor",
    Severity::Major, r"class\s+\w+Utils?\s*\{[^}]*public\s+\w+Utils?\s*\(",
    "Utility class should have private constructor.");

// S1329: Use addAll instead of loop
smell_rule!(S1329UseAddAll, "S1329", "Use addAll instead of loop with add",
    Severity::Minor, r"for\s*\([^)]+\)\s*\{[^}]*\.add\s*\(",
    "Consider using addAll() instead of looping.");

// S1330: Avoid empty while loops
smell_rule!(S1330EmptyWhile, "S1330", "Empty while loops should be documented",
    Severity::Major, r"while\s*\([^)]+\)\s*\{\s*\}|while\s*\([^)]+\)\s*;",
    "Add a comment explaining this empty loop.");

// S1331: Use String.isEmpty instead of equals empty
smell_rule!(S1331StringIsEmpty, "S1331", "Use isEmpty() instead of equals empty string",
    Severity::Minor, r#"\.equals\s*\(\s*""\s*\)"#,
    "Use isEmpty() instead of equals(\"\").");

// S1332: Simplify nested loops
smell_rule!(S1332NestedLoops, "S1332", "Deeply nested loops should be refactored",
    Severity::Major, r"for\s*\([^{]+\{[^}]*for\s*\([^{]+\{[^}]*for\s*\(",
    "Consider refactoring deeply nested loops.");

// S1333: Use contains instead of indexOf
smell_rule!(S1333UseContains, "S1333", "Use contains() instead of indexOf() >= 0",
    Severity::Minor, r"\.indexOf\s*\([^)]+\)\s*>=\s*0|\.indexOf\s*\([^)]+\)\s*!=\s*-1",
    "Use contains() instead of indexOf() >= 0.");

// S1334: Format specifiers consistency
smell_rule!(S1334FormatSpecifiers, "S1334", "Format specifiers should be consistent",
    Severity::Minor, r#"String\.format\s*\(\s*"[^"]*%[sd][^"]*"#,
    "Verify format specifiers match argument types.");

// S1335: Avoid reassigning method parameters
smell_rule!(S1335ParamReassign, "S1335", "Method parameters should not be reassigned",
    Severity::Major, r"public\s+\w+\s+\w+\s*\([^)]*\w+\s+\w+[^)]*\)\s*\{[^}]*\w+\s*=\s*[^=]",
    "Avoid reassigning method parameters.");

// S1336: Simplify boolean returns
smell_rule!(S1336BooleanSimplify, "S1336", "Boolean return can be simplified",
    Severity::Minor, r"if\s*\([^)]+\)\s*\{\s*return\s+true\s*;\s*\}\s*return\s+false",
    "Return the condition directly.");

// S1337: Avoid catching generic exception
smell_rule!(S1337GenericCatch, "S1337", "Avoid catching generic exceptions",
    Severity::Major, r"catch\s*\(\s*(?:Exception|RuntimeException)\s+\w+\s*\)\s*\{",
    "Catch more specific exceptions.");

// S1338: Use correct equals comparison
smell_rule!(S1338EqualsComparison, "S1338", "Potential equals type mismatch",
    Severity::Major, r"\.equals\s*\(\s*\d+\s*\)",
    "Comparing String to number with equals().");

// S1339: Optional should not be used as field
smell_rule!(S1339OptionalField, "S1339", "Optional should not be used as field",
    Severity::Major, r"private\s+Optional<[^>]+>\s+\w+\s*;",
    "Don't use Optional as field type.");

// S1340: Avoid using Random for security
smell_rule!(S1340InsecureRandom, "S1340", "Random should not be used for security",
    Severity::Critical, r"new\s+Random\s*\(\s*\).*(?:password|token|secret|key)",
    "Use SecureRandom for security-sensitive values.");

// S1341: Boxing in loops
smell_rule!(S1341BoxingLoop, "S1341", "Avoid boxing in loops",
    Severity::Major, r"for\s*\([^)]+\)\s*\{[^}]*Integer\.valueOf|for\s*\([^)]+\)\s*\{[^}]*Long\.valueOf",
    "Avoid boxing primitives inside loops.");

// S1342: Use StringBuilder for loop concatenation
smell_rule!(S1342LoopConcat, "S1342", "Use StringBuilder for loop concatenation",
    Severity::Major, r#"for\s*\([^)]+\)\s*\{[^}]*\+=\s*""#,
    "Use StringBuilder for string concatenation in loops.");

// S1343: Avoid string split with single character regex
smell_rule!(S1343StringSplit, "S1343", "Use indexOf for one character split",
    Severity::Minor, r"\.split\s*\(\s*\S{3}\s*\)",
    "Consider using indexOf and substring for single character.");

// S1344: Float comparison with equals
smell_rule!(S1344FloatEquals, "S1344", "Float values should not use equals",
    Severity::Major, r"(?:Float|Double)\s+\w+\s*==\s*\w+|\.equals\s*\([^)]*(?:Float|Double)",
    "Use epsilon comparison for floating point.");

// S1345: Redundant null check before instanceof
smell_rule!(S1345NullInstanceof, "S1345", "Null check before instanceof is redundant",
    Severity::Minor, r"!=\s*null\s*&&\s*\w+\s+instanceof|instanceof[^&]+&&\s*\w+\s*!=\s*null",
    "instanceof already checks for null.");

// S1346: Multiple string replacements
smell_rule!(S1346MultipleReplace, "S1346", "Multiple replacements should be combined",
    Severity::Minor, r"\.replace\([^)]+\)\.replace\([^)]+\)\.replace\(",
    "Consider combining multiple replacements.");

// S1347: Use primitive stream operations
smell_rule!(S1347PrimitiveStream, "S1347", "Use primitive stream operations",
    Severity::Minor, r"\.mapToInt\([^)]*Integer::intValue\)|\.mapToLong\([^)]*Long::longValue\)",
    "Use mapToInt/mapToLong without unboxing.");

// S1348: Empty optional returned
smell_rule!(S1348EmptyOptional, "S1348", "Consider returning Optional.empty()",
    Severity::Minor, r"return\s+Optional\.ofNullable\s*\(\s*null\s*\)",
    "Use Optional.empty() instead of ofNullable(null).");

// S1349: Avoid multiple return statements
smell_rule!(S1349MultipleReturn, "S1349", "Consider reducing return statements",
    Severity::Minor, r"return[^}]+return[^}]+return[^}]+return[^}]+return",
    "Method has too many return statements.");

// S1350: Hardcoded password
smell_rule!(S1350HardcodedPwd, "S1350", "Passwords should not be hardcoded",
    Severity::Critical, r#"(?i)(?:password|pwd|passwd)\s*=\s*"[^"]+""#,
    "Extract password to configuration or secrets management.");

// S1351: Empty string initialization
smell_rule!(S1351EmptyStringInit, "S1351", "Avoid empty string initialization",
    Severity::Minor, r#"String\s+\w+\s*=\s*"";"#,
    "Prefer null or defer initialization.");

// S1352: Avoid raw use of parameterized class
smell_rule!(S1352RawType, "S1352", "Raw use of parameterized class",
    Severity::Major, r"\bList\s+\w+\s*=|\bMap\s+\w+\s*=|\bSet\s+\w+\s*=",
    "Add type parameters to generic types.");

// S1353: Avoid constant as left operand
smell_rule!(S1353ConstantLeft, "S1353", "Constants on left side of comparison",
    Severity::Minor, r"null\s*==|true\s*==|false\s*==",
    "Put variables on left side of comparison.");

// S1354: Dead store removal
smell_rule!(S1354DeadStore, "S1354", "Variable value is overwritten before use",
    Severity::Major, r"\w+\s*=[^;]+;\s*\w+\s*=[^;]+;",
    "First assignment is overwritten without being read.");

// S1355: Use isEmpty for string length check
smell_rule!(S1355StringLength, "S1355", "Use isEmpty() instead of length() == 0",
    Severity::Minor, r"\.length\(\)\s*==\s*0",
    "Use isEmpty() instead of length() == 0.");

// S1356: Direct field access in equals
smell_rule!(S1356FieldAccessEquals, "S1356", "Use getters in equals implementation",
    Severity::Minor, r"equals\([^)]*\)\s*\{[^}]*other\.\w+\s*==",
    "Consider using getters instead of direct field access.");

// S1357: Method chain too long
smell_rule!(S1357LongMethodChain, "S1357", "Method chain should not be too long",
    Severity::Minor, r"\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\(",
    "Consider breaking this long method chain.");

// S1358: Unused exception parameter
smell_rule!(S1358UnusedException, "S1358", "Exception parameter should be used",
    Severity::Minor, r"catch\s*\(\s*\w+\s+\w+\s*\)\s*\{\s*\}",
    "Use or log the caught exception.");

// S1359: Check for specific annotations
smell_rule!(S1359SpecificAnnotation, "S1359", "Annotation usage should be checked",
    Severity::Minor, r#"@SuppressWarnings\s*\(\s*"all"\s*\)"#,
    "Use specific warning names instead of all.");

// S1360: Synchronized method or block
smell_rule!(S1360SynchronizedMethod, "S1360", "Consider using java.util.concurrent",
    Severity::Minor, r"public\s+synchronized\s+|synchronized\s*\(\s*this\s*\)",
    "Consider using java.util.concurrent classes.");

// S1361: Interface with only constants
smell_rule!(S1361ConstantInterface, "S1361", "Constant interfaces should be avoided",
    Severity::Major, r"interface\s+\w+\s*\{[^}]*static\s+final[^}]*\}",
    "Use a final class with private constructor for constants.");

// S1362: Avoid nested ternary operators
smell_rule!(S1362NestedTernary, "S1362", "Nested ternary operators are hard to read",
    Severity::Major, r"\?\s*[^:]+\?[^:]+:[^:]+:",
    "Use if-else instead of nested ternary.");

// S1363: Abstract class with only static methods
smell_rule!(S1363AbstractStatic, "S1363", "Abstract class has only static methods",
    Severity::Major, r"abstract\s+class\s+\w+\s*\{[^}]*(?:public|private|protected)\s+static[^}]*\}",
    "Consider using final class instead of abstract.");

// S1364: Test method naming
smell_rule!(S1364TestNaming, "S1364", "Test method should describe behavior",
    Severity::Minor, r"@Test\s+(?:public\s+)?void\s+test\d+\s*\(",
    "Name test methods to describe the behavior being tested.");

// S1365: Avoid hardcoded file paths
smell_rule!(S1365HardcodedPath, "S1365", "File paths should not be hardcoded",
    Severity::Major, r#""[/\\](?:home|Users|var|tmp|opt)[/\\][^"]+""#,
    "Extract file paths to configuration.");

// S1366: Use Path instead of File
smell_rule!(S1366UsePath, "S1366", "Use Path instead of File",
    Severity::Minor, r"new\s+File\s*\(",
    "Consider using Path and Files API instead of File.");

// S1367: Field hiding in subclass
smell_rule!(S1367FieldHiding, "S1367", "Field hides parent class field",
    Severity::Major, r"extends\s+\w+[^{]+\{[^}]*private\s+\w+\s+name\s*;",
    "Avoid hiding parent class fields.");

// S1368: Static initialization order
smell_rule!(S1368StaticInit, "S1368", "Static initialization order matters",
    Severity::Major, r"static\s+\w+\s+\w+\s*=[^;]+\w+\s*;[^}]*static\s+\w+\s+\w+\s*=",
    "Be careful with static initialization dependencies.");

// S1369: Use Objects.hash
smell_rule!(S1369ObjectsHash, "S1369", "Use Objects.hash for hashCode",
    Severity::Minor, r"hashCode\s*\(\s*\)\s*\{[^}]*\*\s*31",
    "Consider using Objects.hash() instead of manual calculation.");

// S1370: Check for null before method call
smell_rule!(S1370NullCheck, "S1370", "Potential null pointer dereference",
    Severity::Major, r"\w+\.\w+\.\w+\.\w+\s*\(",
    "Check for null before chaining method calls.");

// S1371: Avoid catching and ignoring
smell_rule!(S1371IgnoredException, "S1371", "Exception should not be silently ignored",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{\s*\}",
    "Handle or log the caught exception.");

// S1372: Avoid public fields
smell_rule!(S1372PublicField, "S1372", "Fields should be private",
    Severity::Major, r"public\s+(?:int|String|boolean|Object|List|Map|Set)\s+\w+\s*[=;]",
    "Make fields private and use getters/setters.");

// S1373: Commented out import
smell_rule!(S1373CommentedImport, "S1373", "Remove commented out imports",
    Severity::Minor, r"//\s*import\s+",
    "Remove commented out import statements.");

// S1374: Avoid returning null from toString
smell_rule!(S1374ToStringNull, "S1374", "toString should not return null",
    Severity::Critical, r"toString\s*\([^)]*\)\s*\{[^}]*return\s+null",
    "toString() must never return null.");

// S1375: Use StringBuilder append
smell_rule!(S1375StringAppend, "S1375", "Use append instead of concat",
    Severity::Minor, r"StringBuilder[^}]+\.concat\s*\(",
    "Use StringBuilder.append() instead of concat().");

// S1376: Avoid using Date class
smell_rule!(S1376DateClass, "S1376", "Use java.time instead of Date",
    Severity::Minor, r"new\s+Date\s*\(\s*\)|import\s+java\.util\.Date",
    "Use java.time classes instead of Date.");

// S1377: String format logging
smell_rule!(S1377LogFormat, "S1377", "Use parameterized logging",
    Severity::Minor, r#"(?:log|logger)\.\w+\s*\(\s*"\s*\+|String\.format\s*\([^)]+\)\s*\)"#,
    "Use parameterized logging instead of string concatenation.");

// S1378: Use assertThat for collections
smell_rule!(S1378AssertCollection, "S1378", "Use assertThat for collection assertions",
    Severity::Minor, r"assertEquals\s*\(\s*\d+\s*,\s*\w+\.size\(\)",
    "Use assertThat(collection).hasSize() for better error messages.");

// S1379: Create utility class correctly
smell_rule!(S1379UtilityClass, "S1379", "Utility class should be final",
    Severity::Major, r"public\s+class\s+\w+Util(?:s|ity)?\s*\{",
    "Make utility class final with private constructor.");

// S1380: Comment density too low
smell_rule!(S1380CommentDensity, "S1380", "Code should have adequate comments",
    Severity::Info, r"(?:public|private|protected)\s+\w+\s+\w+\s*\([^)]{50,}\)\s*\{",
    "Consider adding comments to complex methods.");

// S1381: Interface segregation
smell_rule!(S1381InterfaceSize, "S1381", "Interface should not have too many methods",
    Severity::Major, r"interface\s+\w+\s*\{[^}]*void\s+\w+[^}]*void\s+\w+[^}]*void\s+\w+[^}]*void\s+\w+[^}]*void\s+\w+[^}]*void\s+\w+",
    "Split large interface into smaller, cohesive interfaces.");

// S1382: Single responsibility
smell_rule!(S1382SingleResponsibility, "S1382", "Class may have too many responsibilities",
    Severity::Major, r"class\s+\w+[^{]+\{[^}]{5000,}",
    "Consider splitting this large class.");

// S1383: Avoid magic strings
smell_rule!(S1383MagicString, "S1383", "String literals should be constants",
    Severity::Minor, r#"(?:if|case)\s*\([^)]*"[A-Z][A-Z_]+""#,
    "Extract magic string to a named constant.");

// S1384: Use try-with-resources for AutoCloseable
smell_rule!(S1384TryWithResources, "S1384", "Use try-with-resources",
    Severity::Major, r"finally\s*\{[^}]*\.close\s*\(",
    "Use try-with-resources instead of finally with close().");

// S1385: Array initializer formatting
smell_rule!(S1385ArrayFormat, "S1385", "Array initializer should be on one line",
    Severity::Minor, r"new\s+\w+\[\]\s*\{\s*\n",
    "Consider putting small array initializers on one line.");

// S1386: Lambda can be method reference
smell_rule!(S1386MethodReference, "S1386", "Lambda can be replaced with method reference",
    Severity::Minor, r"->\s*\w+\.\w+\s*\(\s*\)",
    "Consider using method reference instead of lambda.");

// S1387: Duplicate string in annotation
smell_rule!(S1387AnnotationString, "S1387", "Duplicate string in annotation",
    Severity::Minor, r#"@\w+\s*\(\s*"[^"]+"\s*\)[^{]+@\w+\s*\(\s*"[^"]+"\s*\)"#,
    "Consider extracting repeated annotation value to constant.");

// S1388: Volatile array
smell_rule!(S1388VolatileArray, "S1388", "Volatile does not make array elements volatile",
    Severity::Critical, r"volatile\s+\w+\[\]\s+\w+",
    "Volatile only affects the array reference, not elements.");

// S1389: Empty method body
smell_rule!(S1389EmptyMethod, "S1389", "Empty method should have comment",
    Severity::Minor, r"(?:public|private|protected)\s+void\s+\w+\s*\([^)]*\)\s*\{\s*\}",
    "Add comment explaining why method is empty.");

// S1390: Prefer primitive streams
smell_rule!(S1390PrimitiveStream, "S1390", "Use primitive streams when possible",
    Severity::Minor, r"Stream<Integer>|Stream<Long>|Stream<Double>",
    "Use IntStream/LongStream/DoubleStream for primitives.");

// S1391: Avoid excessive imports
smell_rule!(S1391ExcessiveImports, "S1391", "Too many imports may indicate coupling",
    Severity::Major, r"(?:import\s+[^;]+;\s*){50,}",
    "Class has too many imports - consider splitting.");

// S1392: Use String join
smell_rule!(S1392StringJoin, "S1392", "Use String.join for joining",
    Severity::Minor, r"StringBuilder[^}]+for[^}]+\.append\([^)]+\)\.append\s*\([^)]*delimiter",
    "Use String.join() for simple joining operations.");

// S1393: Thread-safe singleton
smell_rule!(S1393SingletonSync, "S1393", "Singleton should be thread-safe",
    Severity::Critical, r"private\s+static\s+\w+\s+instance\s*;[^}]*public\s+static\s+\w+\s+getInstance",
    "Use enum, holder pattern, or double-checked locking for singleton.");

// S1394: Use Objects.requireNonNull
smell_rule!(S1394RequireNonNull, "S1394", "Use Objects.requireNonNull",
    Severity::Minor, r"if\s*\(\s*\w+\s*==\s*null\s*\)\s*\{\s*throw\s+new\s+(?:Null|Illegal)",
    "Use Objects.requireNonNull() for null checks.");

// S1395: Assertions in production code
smell_rule!(S1395AssertProduction, "S1395", "Assertions may be disabled in production",
    Severity::Major, r"\bassert\s+\w+",
    "Don't use assert for runtime checks - use if and throw.");

// S1396: Close resources in reverse order
smell_rule!(S1396CloseOrder, "S1396", "Close resources in reverse order of creation",
    Severity::Major, r"try\s*\{[^}]*\w+1\s*=[^}]*\w+2\s*=[^}]*finally[^}]*\w+1\.close[^}]*\w+2\.close",
    "Close resources in reverse order of their creation.");

// S1397: Use StandardCharsets
smell_rule!(S1397StandardCharsets, "S1397", "Use StandardCharsets constants",
    Severity::Minor, r#"getBytes\s*\(\s*"UTF-8"\s*\)|"UTF-8""#,
    "Use StandardCharsets.UTF_8 instead of \"UTF-8\".");

// S1398: Avoid double checked locking issues
smell_rule!(S1398DoubleChecked, "S1398", "Double checked locking needs volatile",
    Severity::Critical, r"synchronized[^}]+if\s*\(\s*\w+\s*==\s*null\s*\)[^}]*\w+\s*=\s*new",
    "Use volatile or holder pattern for double-checked locking.");

// S1399: Avoid catch block with only throw
smell_rule!(S1399CatchThrow, "S1399", "Catch block only rethrows",
    Severity::Minor, r"catch\s*\([^)]+\w+\s*\)\s*\{\s*throw\s+\w+\s*;\s*\}",
    "Remove unnecessary catch that only rethrows.");

// S1400: Avoid shadowing outer variables
smell_rule!(S1400VariableShadow, "S1400", "Variable shadows outer variable",
    Severity::Major, r"for\s*\(\s*(?:int|String)\s+i[^{]+\{[^}]*(?:int|String)\s+i\s*[=;]",
    "Avoid shadowing loop variable in inner scope.");

// ============================================================================
// Batch 4 - Additional code smell rules
// ============================================================================

// S1500: Avoid complex switch expressions
smell_rule!(S1500ComplexSwitch, "S1500", "Switch expression is too complex",
    Severity::Major, r"switch\s*\([^)]+\)\s*\{[^}]{500,}",
    "Consider refactoring complex switch statements.");

// S1501: Avoid long methods
smell_rule!(S1501LongMethod, "S1501", "Method is too long",
    Severity::Major, r"(?:public|private|protected)\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]{1000,}",
    "Split long methods into smaller ones.");

// S1502: Avoid deeply nested code
smell_rule!(S1502DeepNesting, "S1502", "Code is too deeply nested",
    Severity::Major, r"\{\s*\{[^}]*\{[^}]*\{[^}]*\{",
    "Reduce nesting level.");

// S1503: Avoid duplicate method calls
smell_rule!(S1503DuplicateCall, "S1503", "Duplicate method call in expression",
    Severity::Minor, r"\.\w+\s*\([^)]*\)[^;]*\.\w+\s*\([^)]*\)[^;]*\.\w+\s*\(",
    "Store method result in variable to avoid duplicate calls.");

// S1504: Avoid hardcoded database names
smell_rule!(S1504HardcodedDb, "S1504", "Database name should not be hardcoded",
    Severity::Major, r#"(?i)(?:jdbc|connection).*(?:mysql|postgres|oracle|sqlserver)"#,
    "Extract database configuration.");

// S1505: Avoid hardcoded server names
smell_rule!(S1505HardcodedServer, "S1505", "Server name should not be hardcoded",
    Severity::Major, r#"(?i)"(?:localhost|127\.0\.0\.1|::1)(?::\d+)?""#,
    "Extract server configuration.");

// S1506: Avoid magic numbers in comparisons
smell_rule!(S1506MagicComparison, "S1506", "Magic number in comparison",
    Severity::Minor, r"(?:==|!=|<|>|<=|>=)\s*\d{2,}",
    "Use named constant for magic numbers.");

// S1507: Avoid empty string concatenation
smell_rule!(S1507EmptyConcat, "S1507", "Empty string concatenation is redundant",
    Severity::Minor, r#"\+\s*""|\"\"\s*\+"#,
    "Remove empty string concatenation.");

// S1508: Avoid instanceof followed by cast
smell_rule!(S1508InstanceofCast, "S1508", "Cast after instanceof is redundant",
    Severity::Minor, r"instanceof\s+\w+\s*\)[^;]*\(\s*\w+\s*\)",
    "Use pattern matching or extract variable.");

// S1509: Avoid repeated string operations
smell_rule!(S1509RepeatedString, "S1509", "Repeated string operations",
    Severity::Minor, r"\.trim\(\)\.trim\(\)|\.toLowerCase\(\)\.toLowerCase\(\)",
    "Remove redundant string operations.");

// S1510: Avoid null in string concatenation
smell_rule!(S1510NullConcat, "S1510", "Null in string concatenation",
    Severity::Major, r#"\+\s*null\s*\+|"\s*\+\s*null"#,
    "Avoid concatenating null values.");

// S1511: Use StringBuilder capacity
smell_rule!(S1511SBCapacity, "S1511", "StringBuilder should have initial capacity",
    Severity::Minor, r"new\s+StringBuilder\s*\(\s*\)\s*;",
    "Provide initial capacity to StringBuilder.");

// S1512: Use string format
smell_rule!(S1512UseFormat, "S1512", "Use String.format for complex concatenation",
    Severity::Minor, r#"\+\s*"[^"]*"\s*\+\s*\w+\s*\+\s*"[^"]*"\s*\+\s*\w+\s*\+"#,
    "Use String.format for readability.");

// S1513: Avoid mutable default arguments
smell_rule!(S1513MutableDefault, "S1513", "Avoid mutable default collections",
    Severity::Major, r"static\s+final\s+(?:List|Set|Map)\s*<[^>]+>\s+\w+\s*=\s*new",
    "Make static collections unmodifiable.");

// S1514: Avoid type casting to same type
smell_rule!(S1514SameTypeCast, "S1514", "Cast to same type is redundant",
    Severity::Minor, r"\(\s*String\s*\)\s*\w+\.toString\s*\(",
    "Remove redundant type cast.");

// S1515: Avoid empty catch with continue
smell_rule!(S1515EmptyCatchContinue, "S1515", "Empty catch with continue",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{\s*continue\s*;\s*\}",
    "Add logging before continue in catch.");

// S1516: Avoid returning in finally
smell_rule!(S1516ReturnInFinally, "S1516", "Return in finally is dangerous",
    Severity::Blocker, r"finally\s*\{[^}]*return\s+",
    "Never return from finally block.");

// S1517: Avoid throwing in finally
smell_rule!(S1517ThrowInFinally, "S1517", "Throw in finally is dangerous",
    Severity::Blocker, r"finally\s*\{[^}]*throw\s+new",
    "Never throw from finally block.");

// S1518: Prefer interface types
smell_rule!(S1518InterfaceTypes, "S1518", "Use interface types in declarations",
    Severity::Minor, r"(?:ArrayList|LinkedList|HashSet|HashMap|TreeMap)\s*<[^>]+>\s+\w+\s*=\s*new",
    "Declare using interface types.");

// S1519: Avoid duplicate conditions
smell_rule!(S1519DuplicateCond, "S1519", "Duplicate condition in if-else",
    Severity::Major, r"if\s*\(\s*\w+\s*\)[^}]*else\s+if\s*\(\s*\w+\s*\)",
    "Remove duplicate condition.");

// S1520: Avoid unnecessary else
smell_rule!(S1520UnnecessaryElse, "S1520", "Else after return is unnecessary",
    Severity::Minor, r"return\s+[^;]+;\s*\}\s*else\s*\{",
    "Remove unnecessary else after return.");

// S1521: Avoid complex boolean expression
smell_rule!(S1521ComplexBoolean, "S1521", "Boolean expression is too complex",
    Severity::Major, r"(?:&&|\|\|)[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)[^;]*(?:&&|\|\|)",
    "Simplify complex boolean expression.");

// S1522: Avoid comparing to null before use
smell_rule!(S1522NullBeforeUse, "S1522", "Redundant null check",
    Severity::Minor, r"!=\s*null\s*\?\s*\w+\s*:\s*null",
    "Simplify null check pattern.");

// S1523: Use isEmpty for string check
smell_rule!(S1523UseIsEmpty, "S1523", "Use isEmpty for empty string check",
    Severity::Minor, r#"\.equals\s*\(\s*""\s*\)|\s*==\s*"""#,
    "Use isEmpty() instead of comparing to empty string.");

// S1524: Avoid long parameter lists
smell_rule!(S1524LongParamList, "S1524", "Method has too many parameters",
    Severity::Major, r"\w+\s+\w+\s*,\s*\w+\s+\w+\s*,\s*\w+\s+\w+\s*,\s*\w+\s+\w+\s*,\s*\w+\s+\w+\s*\)",
    "Consider using parameter object.");

// S1525: Avoid duplicate literals
smell_rule!(S1525DupLiteral, "S1525", "Duplicate string literal",
    Severity::Minor, r#""[^"]{10,}"[^}]*"[^"]{10,}""#,
    "Extract duplicate literals to constants.");

// S1526: Avoid god class
smell_rule!(S1526GodClass, "S1526", "Class has too many responsibilities",
    Severity::Major, r"class\s+\w+[^{]*\{[^}]{10000,}",
    "Split large class into smaller ones.");

// S1527: Avoid feature envy
smell_rule!(S1527FeatureEnvy, "S1527", "Method uses too many external methods",
    Severity::Major, r"\.\w+\s*\([^)]*\)[^}]*\.\w+\s*\([^)]*\)[^}]*\.\w+\s*\([^)]*\)[^}]*\.\w+\s*\([^)]*\)[^}]*\.\w+\s*\(",
    "Method may belong to another class.");

// S1528: Use Objects.equals
smell_rule!(S1528ObjectsEquals, "S1528", "Use Objects.equals for null-safe comparison",
    Severity::Minor, r"==\s*null\s*\?\s*\w+\s*==\s*null\s*:\s*\w+\.equals",
    "Use Objects.equals() for null-safe comparison.");

// S1529: Avoid returning this in setter
smell_rule!(S1529SetterReturnsThis, "S1529", "Setter returns this for chaining",
    Severity::Info, r"void\s+set\w+\s*\([^)]+\)\s*\{[^}]*return\s+this",
    "Consider using builder pattern instead.");

// S1530: Avoid public constructor in utility class
smell_rule!(S1530UtilConstructor, "S1530", "Utility class has public constructor",
    Severity::Major, r"class\s+\w+Utils?\s*\{[^}]*public\s+\w+Utils?\s*\(\s*\)",
    "Make utility class constructor private.");

// S1531: Avoid static import of all members
smell_rule!(S1531StaticImportAll, "S1531", "Static import should not use wildcard",
    Severity::Minor, r"import\s+static\s+[\w.]+\.\*\s*;",
    "Import specific static members.");

// S1532: Use try-with-resources
smell_rule!(S1532UseTryResources, "S1532", "Use try-with-resources for closeable",
    Severity::Major, r"finally\s*\{[^}]*\.close\s*\(",
    "Use try-with-resources for auto-close.");

// S1533: Avoid catching generic exception
smell_rule!(S1533CatchGenericEx, "S1533", "Catch more specific exception",
    Severity::Major, r"catch\s*\(\s*Exception\s+\w+\s*\)",
    "Catch specific exceptions.");

// S1534: Avoid logging and rethrowing
smell_rule!(S1534LogRethrow, "S1534", "Log or rethrow, not both",
    Severity::Major, r"catch[^}]*log[^}]*throw|catch[^}]*throw[^}]*log",
    "Either log or rethrow exception.");

// S1535: Use parameterized logging
smell_rule!(S1535ParamLogging, "S1535", "Use parameterized logging",
    Severity::Minor, r"(?:log|logger)\.\w+\s*\(\s*\S+\s*\+",
    "Use parameterized logging for efficiency.");

// S1536: Avoid creating exception for flow control
smell_rule!(S1536ExceptionFlow, "S1536", "Exceptions should not be used for flow control",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{[^}]*\}\s*//\s*expected",
    "Don't use exceptions for flow control.");

// S1537: Use appropriate collection
smell_rule!(S1537AppropriateCollection, "S1537", "Use appropriate collection type",
    Severity::Minor, r"LinkedList\s*<[^>]+>\s+\w+\s*=\s*new\s+LinkedList",
    "Use ArrayList unless you need LinkedList features.");

// S1538: Avoid hardcoded buffer size
smell_rule!(S1538HardcodedBuffer, "S1538", "Hardcoded buffer size",
    Severity::Minor, r"new\s+(?:byte|char)\[\s*\d{4,}\s*\]",
    "Extract buffer size to constant.");

// S1539: Use enhanced for loop
smell_rule!(S1539EnhancedFor, "S1539", "Use enhanced for loop when possible",
    Severity::Minor, r"for\s*\(\s*int\s+\w+\s*=\s*0\s*;[^)]+\.size\s*\(",
    "Use enhanced for loop for readability.");

// S1540: Avoid reassigning loop variable
smell_rule!(S1540LoopVarReassign, "S1540", "Loop variable reassigned inside loop",
    Severity::Major, r"for\s*\([^)]+\w+\s*\+\+[^)]*\)\s*\{[^}]*\w+\s*=",
    "Don't reassign loop variable inside loop.");

// S1541: Avoid comparing incompatible types
smell_rule!(S1541IncompatibleCompare, "S1541", "Comparing incompatible types",
    Severity::Blocker, r"\.equals\s*\(\s*\d+\s*\)",
    "String.equals(int) always returns false.");

// S1542: Avoid unused import
smell_rule!(S1542UnusedImport, "S1542", "Unused import detected",
    Severity::Minor, r"import\s+(?:java\.util\.\*|java\.io\.\*)",
    "Remove or specify unused imports.");

// S1543: Use diamond operator
smell_rule!(S1543DiamondOperator, "S1543", "Use diamond operator",
    Severity::Minor, r"new\s+\w+<[^>]+>\s*\(",
    "Use diamond operator for cleaner code.");

// S1544: Avoid raw types
smell_rule!(S1544RawTypes, "S1544", "Avoid raw generic types",
    Severity::Major, r"\bList\s+\w+\s*=|\bMap\s+\w+\s*=|\bSet\s+\w+\s*=",
    "Use parameterized generic types.");

// S1545: Avoid instanceof with null
smell_rule!(S1545InstanceofNull, "S1545", "instanceof already handles null",
    Severity::Minor, r"!=\s*null\s*&&\s*\w+\s+instanceof",
    "instanceof returns false for null.");

// S1546: Use meaningful variable names
smell_rule!(S1546MeaningfulNames, "S1546", "Use meaningful variable names",
    Severity::Minor, r"(?:int|String|boolean)\s+[a-z]\s*[=;]",
    "Use descriptive variable names.");

// S1547: Avoid field injection
smell_rule!(S1547FieldInjection, "S1547", "Prefer constructor injection",
    Severity::Minor, r"@Autowired\s*\n\s*private",
    "Use constructor injection instead.");

// S1548: Avoid multiple assertions
smell_rule!(S1548MultipleAssert, "S1548", "Test has too many assertions",
    Severity::Minor, r"@Test[^}]+assert\w+[^}]+assert\w+[^}]+assert\w+[^}]+assert\w+[^}]+assert\w+",
    "Split test with many assertions.");

// S1549: Avoid test without assertion
smell_rule!(S1549TestNoAssert, "S1549", "Test method without assertion",
    Severity::Major, r"@Test\s+(?:public\s+)?void\s+\w+\s*\([^)]*\)\s*\{\s*\}",
    "Add assertions to test methods.");

// S1550: Use constant for repeated value
smell_rule!(S1550RepeatedValue, "S1550", "Use constant for repeated value",
    Severity::Minor, r#""[^"]{8,}"[^}]*"[^"]*"[^}]*"[^"]*""#,
    "Extract repeated values to constants.");

// ============================================================================
// Batch 5 - Additional code smell rules
// ============================================================================

// S1600: Avoid excessive comments
smell_rule!(S1600ExcessiveComment, "S1600", "Excessive inline comments",
    Severity::Info, r"//[^}]+//[^}]+//[^}]+//[^}]+//",
    "Consider restructuring code instead of commenting.");

// S1601: Avoid TODO without issue reference
smell_rule!(S1601TodoRef, "S1601", "TODO should reference issue",
    Severity::Minor, r"(?i)//\s*TODO\s*$|//\s*TODO\s+[^A-Z]",
    "Add issue reference to TODO comment.");

// S1602: Avoid using reserved words
smell_rule!(S1602ReservedWord, "S1602", "Avoid using reserved words as names",
    Severity::Major, r"(?:int|String)\s+(?:class|interface|enum)\s*[=;]",
    "Don't use reserved words as variable names.");

// S1603: Avoid comparing strings with new String
smell_rule!(S1603NewStringCompare, "S1603", "Avoid new String in comparison",
    Severity::Major, r"\.equals\s*\(\s*new\s+String\s*\(",
    "Use string literal directly.");

// S1604: Avoid anonymous class when lambda possible
smell_rule!(S1604AnonToLambda, "S1604", "Use lambda instead of anonymous class",
    Severity::Minor, r"new\s+\w+\s*\(\s*\)\s*\{\s*@Override",
    "Convert to lambda expression.");

// S1605: Avoid redundant super call
smell_rule!(S1605RedundantSuper, "S1605", "Redundant super() call",
    Severity::Minor, r"public\s+\w+\s*\(\s*\)\s*\{\s*super\s*\(\s*\)\s*;\s*\}",
    "Remove redundant super() call.");

// S1606: Avoid empty package declaration
smell_rule!(S1606EmptyPackage, "S1606", "Avoid default package",
    Severity::Major, r"^public\s+class\s+\w+",
    "Classes should be in a package.");

// S1607: Avoid numeric overflow risk
smell_rule!(S1607NumericOverflow, "S1607", "Potential numeric overflow",
    Severity::Major, r"\*\s*\d{5,}|Integer\.MAX_VALUE\s*\+|Long\.MAX_VALUE\s*\+",
    "Check for numeric overflow.");

// S1608: Avoid using volatile for mutable objects
smell_rule!(S1608VolatileMutable, "S1608", "Volatile on mutable object",
    Severity::Critical, r"volatile\s+(?:List|Map|Set|StringBuilder)\s*<",
    "Volatile doesn't make collection contents thread-safe.");

// S1609: Avoid modifying method parameter
smell_rule!(S1609ModifyParam, "S1609", "Method parameter should not be modified",
    Severity::Major, r"(?:public|private|protected)\s+\w+\s+\w+\s*\([^)]*final\s+\w+\s+\w+[^)]*\)\s*\{[^}]*\w+\s*=",
    "Don't modify parameters.");

// S1610: Avoid interface with default methods only
smell_rule!(S1610DefaultOnly, "S1610", "Interface has only default methods",
    Severity::Major, r"interface\s+\w+\s*\{\s*default\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\}\s*\}",
    "Use abstract class instead.");

// S1611: Avoid parentheses around lambda parameter
smell_rule!(S1611LambdaParens, "S1611", "Unnecessary parentheses in lambda",
    Severity::Minor, r"\(\s*\w+\s*\)\s*->\s*\{",
    "Remove parentheses around single lambda parameter.");

// S1612B: Avoid lambda when method reference possible
smell_rule!(S1612BLambdaRef, "S1612B", "Lambda can be method reference",
    Severity::Minor, r"->\s*\w+\.\w+\s*\(\s*\)",
    "Use method reference instead of lambda.");

// S1613: Avoid unnecessary string conversion
smell_rule!(S1613UnnecessaryToString, "S1613", "Unnecessary toString call",
    Severity::Minor, r"String\.valueOf\s*\(\s*\w+\.toString\s*\(",
    "Remove redundant toString().");

// S1614: Avoid using this in static context
smell_rule!(S1614ThisStatic, "S1614", "Using this in static context",
    Severity::Major, r"static\s+\w+\s+\w+[^}]*\bthis\b",
    "Cannot use this in static context.");

// S1615: Avoid empty constructor body
smell_rule!(S1615EmptyCtor, "S1615", "Empty constructor body",
    Severity::Minor, r"public\s+\w+\s*\(\s*\)\s*\{\s*\}",
    "Remove empty constructor or add logic.");

// S1616: Avoid unused private constructor
smell_rule!(S1616UnusedPrivateCtor, "S1616", "Unused private constructor",
    Severity::Minor, r"private\s+\w+\s*\(\s*\)\s*\{\s*\}",
    "Remove unused private constructor.");

// S1617: Avoid redundant null assignment
smell_rule!(S1617RedundantNull, "S1617", "Redundant null assignment",
    Severity::Minor, r"\w+\s*=\s*null\s*;[^}]*\w+\s*=\s*[^n]",
    "Assignment to null immediately followed by reassignment.");

// S1618: Avoid catching exception and doing nothing
smell_rule!(S1618CatchDoNothing, "S1618", "Catch block does nothing",
    Severity::Major, r"catch\s*\([^)]+\)\s*\{\s*\}",
    "Handle or log caught exception.");

// S1619: Avoid comparing wrapper types with ==
smell_rule!(S1619WrapperCompare, "S1619", "Comparing wrapper types with ==",
    Severity::Major, r"Integer\s+\w+\s*==\s*Integer|Long\s+\w+\s*==\s*Long|Boolean\s+\w+\s*==\s*Boolean",
    "Use equals() for wrapper types.");

// S1620: Avoid using size() in loop condition
smell_rule!(S1620SizeInLoop, "S1620", "Using size() in loop condition",
    Severity::Minor, r"for\s*\([^)]+;\s*\w+\s*<\s*\w+\.size\s*\(\s*\)\s*;",
    "Store size in variable before loop.");

// S1621: Avoid using contains() when containsKey() needed
smell_rule!(S1621ContainsVsKey, "S1621", "Use containsKey for maps",
    Severity::Minor, r"Map[^}]*\.contains\s*\([^)]",
    "Use containsKey() for maps.");

// S1622: Avoid creating File from URI
smell_rule!(S1622FileFromUri, "S1622", "Avoid File from URI",
    Severity::Minor, r"new\s+File\s*\(\s*\w+\.toURI\s*\(",
    "Use Path.of() instead.");

// S1623: Avoid using array.length in loop
smell_rule!(S1623ArrayLength, "S1623", "Cache array length in loop",
    Severity::Minor, r"for\s*\([^)]+;\s*\w+\s*<\s*\w+\.length\s*;",
    "Consider caching array length.");

// S1624: Avoid using + for string in loop
smell_rule!(S1624StringPlusLoop, "S1624", "String concatenation in loop",
    Severity::Major, r"for\s*\([^{]+\{[^}]*\w+\s*\+=\s*[^;]*;",
    "Use StringBuilder for string building in loops.");

// S1625: Avoid using SimpleDateFormat directly
smell_rule!(S1625SimpleDateFormat, "S1625", "SimpleDateFormat is not thread-safe",
    Severity::Major, r"new\s+SimpleDateFormat\s*\(",
    "Use DateTimeFormatter instead.");

// S1626: Avoid static Random
smell_rule!(S1626StaticRandom, "S1626", "Static Random may cause contention",
    Severity::Major, r"static\s+(?:final\s+)?Random\s+\w+\s*=",
    "Use ThreadLocalRandom instead.");

// S1627: Avoid creating Pattern in loop
smell_rule!(S1627PatternInLoop, "S1627", "Pattern creation in loop",
    Severity::Major, r"for\s*\([^{]+\{[^}]*Pattern\.compile\s*\(",
    "Compile Pattern outside loop.");

// S1628: Avoid creating File in loop
smell_rule!(S1628FileInLoop, "S1628", "File creation in loop",
    Severity::Minor, r"for\s*\([^{]+\{[^}]*new\s+File\s*\(",
    "Consider batching file operations.");

// S1629: Avoid Collections.synchronizedXxx
smell_rule!(S1629SynchronizedCollection, "S1629", "Use concurrent collections",
    Severity::Major, r"Collections\.synchronized(?:List|Set|Map)\s*\(",
    "Use concurrent collections instead.");

// S1630: Avoid creating wrapper in loop
smell_rule!(S1630WrapperInLoop, "S1630", "Wrapper creation in loop",
    Severity::Minor, r"for\s*\([^{]+\{[^}]*Integer\.valueOf\s*\(",
    "Consider using primitive stream.");

// S1631: Avoid getClass() for synchronization
smell_rule!(S1631GetClassSync, "S1631", "Use class literal for sync",
    Severity::Critical, r"synchronized\s*\(\s*getClass\s*\(\s*\)\s*\)",
    "Use ClassName.class for synchronization.");

// S1632: Avoid using String.intern()
smell_rule!(S1632StringIntern, "S1632", "Avoid String.intern()",
    Severity::Major, r"\.intern\s*\(\s*\)",
    "String.intern() can cause memory issues.");

// S1633: Avoid using Vector
smell_rule!(S1633AvoidVector, "S1633", "Use ArrayList instead of Vector",
    Severity::Major, r"new\s+Vector\s*<",
    "Use ArrayList or CopyOnWriteArrayList.");

// S1634: Avoid using Hashtable
smell_rule!(S1634AvoidHashtable, "S1634", "Use HashMap instead of Hashtable",
    Severity::Major, r"new\s+Hashtable\s*<",
    "Use HashMap or ConcurrentHashMap.");

// S1635: Avoid using Stack
smell_rule!(S1635AvoidStack, "S1635", "Use Deque instead of Stack",
    Severity::Major, r"new\s+Stack\s*<",
    "Use ArrayDeque instead.");

// S1636: Avoid StringBuffer in single thread
smell_rule!(S1636StringBuffer, "S1636", "Use StringBuilder in single thread",
    Severity::Minor, r"new\s+StringBuffer\s*\(",
    "Use StringBuilder for single-threaded code.");

// S1637: Avoid Calendar.getInstance()
smell_rule!(S1637CalendarInstance, "S1637", "Use java.time instead of Calendar",
    Severity::Minor, r"Calendar\.getInstance\s*\(",
    "Use LocalDateTime or ZonedDateTime.");

// S1638: Avoid Date.getYear() etc
smell_rule!(S1638DeprecatedDate, "S1638", "Deprecated Date methods",
    Severity::Major, r"\.getYear\s*\(\s*\)|\.getMonth\s*\(\s*\)|\.getDay\s*\(\s*\)",
    "Use java.time instead of deprecated Date methods.");

// S1639: Avoid BigDecimal double constructor
smell_rule!(S1639BigDecimalDouble, "S1639", "Use BigDecimal.valueOf()",
    Severity::Major, r"new\s+BigDecimal\s*\(\s*\d+\.\d+\s*\)",
    "Use BigDecimal.valueOf() for double values.");

// S1640B: Avoid using entrySet() when only keys needed
smell_rule!(S1640BEntrySetKeys, "S1640B", "Use keySet() when only keys needed",
    Severity::Minor, r"entrySet\s*\(\s*\)[^;]*\.getKey\s*\(\s*\)",
    "Use keySet() when only keys are needed.");

// S1641: Avoid explicit garbage collection
smell_rule!(S1641ExplicitGc, "S1641", "Avoid explicit garbage collection",
    Severity::Major, r"System\.gc\s*\(\s*\)|Runtime\.getRuntime\s*\(\s*\)\.gc\s*\(",
    "Let JVM manage garbage collection.");

// S1642: Avoid finalize method
smell_rule!(S1642Finalize, "S1642", "Avoid finalize method",
    Severity::Major, r"protected\s+void\s+finalize\s*\(",
    "Use try-with-resources or Cleaner instead.");

// S1643B: Avoid String concat in append
smell_rule!(S1643BAppendConcat, "S1643B", "Avoid concat in append",
    Severity::Minor, r"\.append\s*\([^)]*\+[^)]*\)",
    "Chain append() calls instead of concat.");

// S1644: Avoid creating exception message in catch
smell_rule!(S1644ExceptionMessage, "S1644", "Create exception message in catch",
    Severity::Minor, r"catch\s*\([^)]+\)\s*\{[^}]*new\s+\w+Exception\s*\([^)]*\+",
    "Pass original exception as cause.");

// S1645: Avoid synchronized on non-final field
smell_rule!(S1645SyncNonFinal, "S1645", "Synchronized on non-final field",
    Severity::Critical, r"synchronized\s*\(\s*[a-z]\w*\s*\)",
    "Synchronize on final fields only.");

// S1646: Avoid wait/notify without sync
smell_rule!(S1646WaitNoSync, "S1646", "wait/notify requires synchronized",
    Severity::Blocker, r"[^{]*\.(?:wait|notify|notifyAll)\s*\(",
    "Use wait/notify inside synchronized block.");

// S1647: Avoid starting thread in constructor
smell_rule!(S1647ThreadInCtor, "S1647", "Starting thread in constructor",
    Severity::Major, r"public\s+\w+\s*\([^)]*\)\s*\{[^}]*\.start\s*\(\s*\)",
    "Start threads outside constructors.");

// S1648: Avoid long method chains
smell_rule!(S1648LongChain, "S1648", "Method chain too long",
    Severity::Minor, r"\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\([^)]*\)\.\w+\(",
    "Break long method chains.");

// S1649: Avoid null return from Optional method
smell_rule!(S1649OptionalNull, "S1649", "Optional method returns null",
    Severity::Critical, r"Optional\s*<[^>]+>\s+\w+\s*\([^)]*\)\s*\{[^}]*return\s+null",
    "Return Optional.empty() instead.");

// S1650: Avoid modifying collection while iterating
smell_rule!(S1650ModifyWhileIterating, "S1650", "Modifying collection while iterating",
    Severity::Critical, r"for\s*\([^)]+:\s*\w+\)[^}]*\w+\.(?:add|remove)\s*\(",
    "Use Iterator.remove() or stream.");

// ============================================================================
// Batch 6 - Additional code smell rules
// ============================================================================

// S1651: Avoid double-checked locking
smell_rule!(S1651DoubleChecked, "S1651", "Double-checked locking is broken",
    Severity::Critical, r"if\s*\([^)]+null[^)]+\)\s*\{[^}]*synchronized",
    "Use proper initialization patterns.");

// S1652: Avoid resource leak in finally
smell_rule!(S1652FinallyLeak, "S1652", "Potential resource leak in finally",
    Severity::Major, r"finally\s*\{[^}]*=\s*null[^}]*\}",
    "Close resources properly.");

// S1653: Avoid hardcoded credentials
smell_rule!(S1653HardcodedCreds, "S1653", "Hardcoded credentials detected",
    Severity::Critical, r#"(?i)(?:username|user)\s*=\s*"[^"]+""#,
    "Extract credentials to configuration.");

// S1654: Avoid direct database queries
smell_rule!(S1654DirectQuery, "S1654", "Use prepared statements",
    Severity::Major, r#"createStatement\s*\(\s*\)\.execute"#,
    "Use PreparedStatement instead.");

// S1655: Avoid deprecated API
smell_rule!(S1655DeprecatedApi, "S1655", "Deprecated API usage",
    Severity::Minor, r"@Deprecated[^}]*\.",
    "Replace deprecated API usage.");

// S1656: Avoid self-assignment
smell_rule!(S1656SelfAssign, "S1656", "Self-assignment detected",
    Severity::Major, r"\w+\s*=\s*\w+\s*;",
    "Self-assignment is likely a bug.");

// S1657: Avoid infinite recursion
smell_rule!(S1657InfiniteRecursion, "S1657", "Potential infinite recursion",
    Severity::Critical, r"return\s+\w+\s*\([^)]*\)\s*;",
    "Check recursion termination condition.");

// S1658: Avoid System.currentTimeMillis in loop
smell_rule!(S1658TimeInLoop, "S1658", "Time retrieval in loop",
    Severity::Minor, r"for\s*\([^{]+\{[^}]*currentTimeMillis\s*\(",
    "Cache time value outside loop.");

// S1659B: Avoid multiple declarations per line
smell_rule!(S1659BMultiDecl, "S1659B", "Multiple declarations per line",
    Severity::Minor, r"(?:int|String|long|double)\s+\w+\s*,\s*\w+\s*[;=]",
    "Declare one variable per line.");

// S1660: Avoid redundant method calls
smell_rule!(S1660RedundantCall, "S1660", "Redundant method call",
    Severity::Minor, r"\.toString\(\)\.toString\(\)|\.trim\(\)\.trim\(\)",
    "Remove duplicate method call.");

// S1661: Avoid unnecessary boxing
smell_rule!(S1661UnnecessaryBox, "S1661", "Unnecessary boxing operation",
    Severity::Minor, r"Integer\.valueOf\s*\(\s*\d+\s*\)\.intValue\s*\(",
    "Use primitive value directly.");

// S1662: Avoid catching Error
smell_rule!(S1662CatchError, "S1662", "Catching Error is dangerous",
    Severity::Critical, r"catch\s*\(\s*(?:Error|OutOfMemoryError|StackOverflowError)\b",
    "Don't catch Error types.");

// S1663: Avoid reflection security bypass
smell_rule!(S1663ReflectionBypass, "S1663", "Reflection bypassing security",
    Severity::Critical, r"setAccessible\s*\(\s*true\s*\)",
    "Avoid setAccessible(true).");

// S1664: Avoid assertion in production
smell_rule!(S1664AssertProduction, "S1664", "Assertion may be disabled",
    Severity::Major, r"assert\s+\w+\s*:",
    "Don't rely on assertions for validation.");

// S1665: Avoid clone without super.clone
smell_rule!(S1665CloneSuper, "S1665", "Clone should call super.clone()",
    Severity::Major, r"clone\s*\(\s*\)\s*\{\s*return\s+new\s+",
    "Always call super.clone().");

// S1666: Avoid empty synchronized block
smell_rule!(S1666EmptySync, "S1666", "Empty synchronized block",
    Severity::Major, r"synchronized\s*\([^)]+\)\s*\{\s*\}",
    "Remove empty synchronized block.");

// S1667: Avoid wait() outside loop
smell_rule!(S1667WaitNoLoop, "S1667", "wait() should be in loop",
    Severity::Critical, r"if\s*\([^)]+\)\s*\{[^}]*\.wait\s*\(",
    "Use while loop with wait().");

// S1668: Avoid notify instead of notifyAll
smell_rule!(S1668NotifyVsAll, "S1668", "Prefer notifyAll over notify",
    Severity::Major, r"\.notify\s*\(\s*\)\s*;",
    "Use notifyAll() instead of notify().");

// S1669: Avoid Thread.stop
smell_rule!(S1669ThreadStop, "S1669", "Thread.stop is deprecated",
    Severity::Blocker, r"\.stop\s*\(\s*\)|Thread\.stop\s*\(",
    "Use interruption instead.");

// S1670: Avoid Thread.suspend/resume
smell_rule!(S1670ThreadSuspend, "S1670", "Thread.suspend/resume deprecated",
    Severity::Blocker, r"\.(?:suspend|resume)\s*\(\s*\)",
    "Use proper synchronization.");

// S1671: Avoid Thread.destroy
smell_rule!(S1671ThreadDestroy, "S1671", "Thread.destroy is dangerous",
    Severity::Blocker, r"\.destroy\s*\(\s*\)",
    "Never use Thread.destroy().");

// S1672: Avoid Runtime.exec with string
smell_rule!(S1672RuntimeExec, "S1672", "Use ProcessBuilder",
    Severity::Major, r#"Runtime\.getRuntime\(\)\.exec\s*\(\s*""#,
    "Use ProcessBuilder instead.");

// S1673: Avoid hardcoded locale
smell_rule!(S1673HardcodedLocale, "S1673", "Hardcoded locale",
    Severity::Minor, r#"Locale\s*\.\s*(?:ENGLISH|US|UK|FRENCH)"#,
    "Use configurable locale.");

// S1674: Avoid hardcoded timezone
smell_rule!(S1674HardcodedTimezone, "S1674", "Hardcoded timezone",
    Severity::Minor, r#"TimeZone\.getTimeZone\s*\(\s*"[^"]+""#,
    "Use configurable timezone.");

// S1675: Avoid excessive inheritance
smell_rule!(S1675ExcessiveInherit, "S1675", "Excessive inheritance",
    Severity::Major, r"extends\s+\w+[^{]+extends",
    "Prefer composition over deep inheritance.");

// S1676: Avoid marker interface
smell_rule!(S1676MarkerInterface, "S1676", "Avoid marker interfaces",
    Severity::Minor, r"interface\s+\w+\s*\{\s*\}",
    "Use annotations instead of marker interfaces.");

// S1677: Avoid inner class in interface
smell_rule!(S1677InnerInInterface, "S1677", "Inner class in interface",
    Severity::Minor, r"interface\s+\w+\s*\{[^}]*class\s+\w+",
    "Move class out of interface.");

// S1678: Avoid field injection
smell_rule!(S1678FieldInjection, "S1678", "Avoid field injection",
    Severity::Minor, r"@(?:Autowired|Inject)\s+private",
    "Prefer constructor injection.");

// S1679: Avoid magic timeout
smell_rule!(S1679MagicTimeout, "S1679", "Magic timeout value",
    Severity::Minor, r"(?:timeout|sleep)\s*\(\s*\d{4,}\s*\)",
    "Extract timeout to named constant.");

// S1680: Avoid unbounded wildcards
smell_rule!(S1680UnboundedWildcard, "S1680", "Unbounded wildcard usage",
    Severity::Minor, r"List<\?>\s+|Map<\?,\s*\?>\s+|Set<\?>\s+",
    "Use bounded wildcards when possible.");

// S1681: Avoid raw generic return
smell_rule!(S1681RawReturn, "S1681", "Method returns raw type",
    Severity::Major, r"public\s+(?:List|Map|Set|Collection)\s+\w+\s*\(",
    "Add type parameters to return type.");

// S1682: Avoid array return
smell_rule!(S1682ArrayReturn, "S1682", "Return collection instead of array",
    Severity::Minor, r"public\s+\w+\[\]\s+\w+\s*\(",
    "Return collection instead of array.");

// S1683: Avoid public array field
smell_rule!(S1683PublicArray, "S1683", "Public array field is mutable",
    Severity::Major, r"public\s+(?:static\s+)?(?:final\s+)?\w+\[\]\s+\w+",
    "Return defensive copy.");

// S1684: Avoid enum with only values
smell_rule!(S1684EnumOnlyValues, "S1684", "Enum without behavior",
    Severity::Info, r"enum\s+\w+\s*\{\s*\w+(?:\s*,\s*\w+)*\s*\}",
    "Consider adding behavior to enum.");

// S1685: Avoid static method with instance data
smell_rule!(S1685StaticInstanceData, "S1685", "Static method accesses instance",
    Severity::Major, r"static\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*this\.",
    "Cannot use 'this' in static method.");

// S1686: Avoid returning mutable field
smell_rule!(S1686ReturnMutable, "S1686", "Returning mutable internal",
    Severity::Major, r"return\s+this\.\w+;[^}]*private\s+(?:List|Map|Set|Date)",
    "Return defensive copy.");

// S1687: Avoid storing mutable parameter
smell_rule!(S1687StoreMutable, "S1687", "Storing mutable parameter",
    Severity::Major, r"this\.\w+\s*=\s*\w+;[^}]*\([^)]*(?:List|Map|Set|Date)\s+\w+",
    "Store defensive copy.");

// S1688: Avoid excessive catch
smell_rule!(S1688ExcessiveCatch, "S1688", "Too many catch clauses",
    Severity::Minor, r"catch\s*\([^)]+\)\s*\{[^}]*catch\s*\([^)]+\)\s*\{[^}]*catch\s*\([^)]+\)\s*\{[^}]*catch",
    "Consider multi-catch or hierarchy.");

// S1689: Avoid catch RuntimeException
smell_rule!(S1689CatchRuntime, "S1689", "Catching RuntimeException",
    Severity::Major, r"catch\s*\(\s*RuntimeException\s+\w+\s*\)",
    "Catch more specific exceptions.");

// S1690: Avoid static mutable state
smell_rule!(S1690StaticMutable, "S1690", "Static mutable state",
    Severity::Critical, r"static\s+(?:List|Map|Set|StringBuilder)\s*<",
    "Static mutable state is thread-unsafe.");

// S1691: Avoid hardcoded encryption key
smell_rule!(S1691HardcodedKey, "S1691", "Hardcoded encryption key",
    Severity::Blocker, r#"(?i)(?:secretKey|encryptionKey|aesKey)\s*=\s*"[^"]+""#,
    "Use secure key management.");

// S1692: Avoid insecure protocol
smell_rule!(S1692InsecureProtocol, "S1692", "Insecure protocol",
    Severity::Critical, r#"(?:http|ftp)://[a-zA-Z]"#,
    "Use HTTPS/SFTP.");

// S1693: Avoid disabled SSL verification
smell_rule!(S1693DisabledSsl, "S1693", "SSL verification disabled",
    Severity::Blocker, r"(?:setHostnameVerifier|TrustAllCerts|ALLOW_ALL)",
    "Never disable SSL verification.");

// S1694B: Avoid abstract class without abstract methods
smell_rule!(S1694BAbstractNoMethods, "S1694B", "Abstract class without abstract",
    Severity::Minor, r"abstract\s+class\s+\w+\s*\{\s*\}",
    "Use concrete class or add abstract methods.");

// S1695: Avoid empty interface
smell_rule!(S1695EmptyInterface, "S1695", "Empty interface",
    Severity::Info, r"interface\s+\w+\s*(?:extends[^{]+)?\{\s*\}",
    "Empty interfaces should use annotations.");

// S1696: Avoid NullPointerException catch
smell_rule!(S1696CatchNpe, "S1696", "Catching NullPointerException",
    Severity::Major, r"catch\s*\(\s*NullPointerException\b",
    "Fix null references instead.");

// S1697: Avoid NumberFormatException catch
smell_rule!(S1697CatchNfe, "S1697", "Catching NumberFormatException",
    Severity::Minor, r"catch\s*\(\s*NumberFormatException\b",
    "Consider validation instead.");

// S1698B: Avoid instanceof followed by cast
smell_rule!(S1698BInstanceofCast, "S1698B", "Instanceof followed by cast",
    Severity::Minor, r"instanceof\s+\w+[^;]*\(\s*\w+\s*\)",
    "Use pattern matching if available.");

/// Create all code smell detection rules
pub fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Simple regex rules
        Box::new(S105TabCharacter),
        Box::new(S121MissingCurlyBraces),
        Box::new(S122MultipleStatements),
        Box::new(S1065UnusedLabel),
        Box::new(S1068UnusedPrivateField),
        Box::new(S1075HardcodedUri),
        Box::new(S1103HtmlEntities),
        Box::new(S1116EmptyStatement),
        Box::new(S1117VariableShadowing),
        Box::new(S1119LabelUsed),
        Box::new(S1121AssignmentInSubExpression),
        Box::new(S1123DeprecatedMissing),
        Box::new(S1124ModifierOrder),
        Box::new(S1125RedundantBoolean),
        Box::new(S1126BooleanReturn),
        Box::new(S1128WildcardImport),
        Box::new(S1133DeprecatedCode),
        Box::new(S1134FixmeTag),
        Box::new(S1141NestedTryCatch),
        Box::new(S1147SystemExit),
        Box::new(S1149SynchronizedCollection),
        Box::new(S1150EnumerationInterface),
        Box::new(S1153StringValueOf),
        Box::new(S1157CaseInsensitiveCompare),
        Box::new(S1158PrimitiveWrapper),
        Box::new(S1160MultipleCheckedExceptions),
        Box::new(S1161MissingOverride),
        Box::new(S1162CheckedException),
        Box::new(S1163ThrowInFinally),
        Box::new(S1164CatchRethrow),
        Box::new(S1165ExceptionNonFinalField),
        Box::new(S1166ExceptionCauseNotPreserved),
        Box::new(S1170PublicConstant),
        Box::new(S1171InstanceInitializer),
        Box::new(S1174FinalizePublic),
        Box::new(S1182CloneWithoutCloneable),
        Box::new(S1185UselessOverride),
        Box::new(S1189AssertAsVariable),
        Box::new(S1190FutureKeyword),
        Box::new(S1191SunPackages),
        Box::new(S1193ExceptionInstanceof),
        Box::new(S1194ExtendError),
        Box::new(S1195ArrayDesignator),
        Box::new(S1197ArrayBrackets),
        Box::new(S1199NestedBlock),
        Box::new(S1214ConstantInterface),
        Box::new(S1215SystemGc),
        Box::new(S1219NonCaseLabel),
        Box::new(S1220DefaultPackage),
        Box::new(S1223MethodNamedAsClass),
        Box::new(S1226ParameterReassigned),
        Box::new(S1301TooFewCases),
        Box::new(S1444NonFinalStaticField),
        Box::new(S1450FieldShouldBeLocal),
        Box::new(S1451MissingCopyright),
        Box::new(S1481UnusedLocalVar),
        Box::new(S1488ImmediateReturn),
        Box::new(S1612MethodReference),
        Box::new(S1643StringConcatInLoop),
        Box::new(S1659MultipleDeclarations),
        Box::new(S1694AbstractWithoutMethod),
        Box::new(S1700FieldNamedAsClass),
        Box::new(S1905RedundantCast),
        Box::new(S1940InvertedBoolean),
        Box::new(S1989ThrowFromFinalize),
        Box::new(S2039ExplicitVisibility),
        Box::new(S2094EmptyClass),
        Box::new(S2133UselessObject),
        Box::new(S2154MixedWrappers),
        Box::new(S2160EqualsWithoutHashCode),
        Box::new(S2162StaticThis),
        Box::new(S2166ExceptionNaming),
        Box::new(S2176ClassShadowing),
        Box::new(S2178ShortCircuit),
        Box::new(S2232ResultSetIsLast),
        Box::new(S2293DiamondOperator),
        Box::new(S2326UnusedTypeParameter),
        Box::new(S2388InnerShadowing),
        Box::new(S2437SillyBitOp),
        Box::new(S2440StaticClassInstance),
        Box::new(S2479SpecialWhitespace),
        Box::new(S2681MultilineBlock),
        Box::new(S2786StaticEnum),
        Box::new(S2864EntrySet),
        Box::new(S2885NonThreadSafeStatic),
        Box::new(S2970IncompleteAssertion),
        Box::new(S3011ReflectionPrivate),
        Box::new(S3012VarargsArray),
        Box::new(S3047MultipleLoops),
        Box::new(S3052DefaultInit),
        Box::new(S3077NonPrimitiveVolatile),
        Box::new(S3252StaticAccess),
        Box::new(S3398InlinePrivate),
        Box::new(S3400ReturnConstant),
        Box::new(S3415AssertionOrder),
        Box::new(S3457PrintfFormat),
        Box::new(S3551ExceptionNotLogged),
        Box::new(S3553AssertThrows),
        Box::new(S3626RedundantJump),
        Box::new(S3740RawType),
        Box::new(S3749MemberUnset),
        Box::new(S3923IdenticalBranches),
        Box::new(S3959StreamReuse),
        Box::new(S3972ConditionalNewLine),
        Box::new(S3973ImplicitNullCheck),
        Box::new(S4143CollectionMethod),
        Box::new(S4165RedundantAssignment),
        Box::new(S4201NullInstanceof),
        Box::new(S4449OptionalIsPresent),
        Box::new(S4551TypeToken),
        Box::new(S4596PropertiesMap),
        Box::new(S4719MementoClass),
        Box::new(S4738InsecureRandom),
        Box::new(S4929CatchNPE),
        Box::new(S5122CorsPolicy),
        Box::new(S5261RegexReuse),
        Box::new(S5411BoxingInConcat),
        Box::new(S5542SecureEncryption),
        Box::new(S5786JUnit5Public),
        Box::new(S5838SimplifyAssert),
        Box::new(S5841RegexOptimize),
        Box::new(S5843LambdaToReference),
        Box::new(S5845AssertMessage),
        Box::new(S5852UrlPattern),
        Box::new(S5855NonShortCircuitTest),
        Box::new(S5958TestClassName),
        Box::new(S5960ComplexAssertion),
        Box::new(S5961LongTest),
        Box::new(S5967DuplicateSignature),
        Box::new(S5969NegatedAssertion),
        Box::new(S5970ReturnThis),
        Box::new(S6073StringComparison),
        Box::new(S6201PatternFlags),
        Box::new(S6204StreamEquality),
        Box::new(S6212LocalTypeInference),
        Box::new(S6213RestrictedIdentifiers),
        Box::new(S6218ObjectsHash),
        Box::new(S6291MapCompute),
        Box::new(S6293ComplexRegex),
        Box::new(S6301MissingAssertion),
        Box::new(S6353EmptyAlternation),
        Box::new(S6355ClassLiteral),
        Box::new(S6395UuidRandom),
        Box::new(S6397PutIfAbsent),
        Box::new(S6432SwitchArrows),
        Box::new(S6548ListOf),
        // Complex rules
        Box::new(S106SystemOutUsed),
        Box::new(S107TooManyParameters),
        Box::new(S108EmptyBlock),
        Box::new(S109MagicNumber),
        Box::new(S110DeepInheritance),
        Box::new(S112GenericException),
        Box::new(S125CommentedOutCode),
        Box::new(S128SwitchCaseFallthrough),
        Box::new(S131SwitchDefault),
        Box::new(S134DeepNesting),
        Box::new(S135MultipleBreakContinue),
        Box::new(S1066CollapsibleIf),
        Box::new(S1104PublicField),
        Box::new(S1118UtilityClassConstructor),
        Box::new(S1132StringLiteralOnLeft),
        Box::new(S1135TodoComment),
        Box::new(S1142TooManyReturns),
        Box::new(S1144UnusedPrivateField),
        Box::new(S1155UseCollectionIsEmpty),
        Box::new(S1168ReturnEmptyInsteadOfNull),
        Box::new(S1172UnusedMethodParameter),
        Box::new(S1181CatchThrowable),
        Box::new(S1186EmptyMethod),
        Box::new(S1192DuplicateStrings),
        Box::new(S1210EqualsHashCode),
        // Batch 2 - additional rules
        Box::new(S800NestedComments),
        Box::new(S815UnicodeBom),
        Box::new(S818LiteralSuffix),
        Box::new(S864OperatorPrecedence),
        Box::new(S881IncrementDecrement),
        Box::new(S888LoopTermination),
        Box::new(S923VoidReturnType),
        Box::new(S979ConditionParentheses),
        Box::new(S1151SwitchCaseComplexity),
        Box::new(S1169EmptyCollectionReturn),
        Box::new(S1200ClassCoupling),
        Box::new(S1213ParameterOrder),
        Box::new(S1258ParsingDouble),
        Box::new(S1313IpHardcoded),
        Box::new(S1479TooManyCases),
        Box::new(S1640EntrySetIteration),
        Box::new(S1699ConstructorOverridable),
        Box::new(S1710AnnotationNaming),
        Box::new(S1820SubclassNaming),
        Box::new(S1821NestedSwitch),
        Box::new(S2057SerialVersionUID),
        Box::new(S2130ParsingPrimitive),
        Box::new(S2131StringValueOfPrimitive),
        Box::new(S2143InterruptedHandling),
        Box::new(S2209StaticMemberAccess),
        Box::new(S2221ThrowGeneric),
        Box::new(S2225NullToString),
        Box::new(S2272IteratorRemove),
        Box::new(S2301SelectorArgument),
        Box::new(S2390SubclassStaticAccess),
        Box::new(S2447NullBooleanReturn),
        Box::new(S2583BTrueCondition),
        Box::new(S2638ParameterChanged),
        Box::new(S2692IndexOfCheck),
        Box::new(S2698AssertionMessage),
        Box::new(S2925ThreadSleepTest),
        Box::new(S2959StreamIntermediate),
        Box::new(S3046RegexDos),
        Box::new(S3060OverrideReturnType),
        Box::new(S3237ValueBasedEquality),
        Box::new(S3254BooleanExpression),
        Box::new(S3257DeclareInitialize),
        Box::new(S3281SuperfluousTypeArg),
        Box::new(S3330OptionalOrElse),
        Box::new(S3358NestedTernary2),
        Box::new(S3546GetClassSync),
        Box::new(S3655OptionalUnsafe2),
        Box::new(S3655OptionalGet),
        Box::new(S3878ArraysVarargs),
        Box::new(S3981CollectionSize),
        Box::new(S3986DateFormatConstants),
        Box::new(S4032PackageSameDepth),
        Box::new(S4065UselessInterrupted),
        Box::new(S4144DuplicateMethod2),
        Box::new(S4165SelfAssign),
        Box::new(S4276PrimitiveGenerics),
        Box::new(S4288ArrayToString),
        Box::new(S4351CompareToMinValue),
        Box::new(S4423WeakTls),
        Box::new(S4524DefaultSwitchPosition),
        Box::new(S4544GenericWildcard),
        Box::new(S4601UnicodeSeparator),
        Box::new(S4682PrimitiveComparison),
        Box::new(S4784RegexComplexity),
        Box::new(S4929CatchNpe2),
        Box::new(S5042ZipEntry),
        Box::new(S5128BeanValidation),
        Box::new(S5361ReplaceAll),
        Box::new(S5443FilePerm),
        Box::new(S5663PublicTestField),
        Box::new(S5976TestAssertions),
        Box::new(S6035UriBuild),
        Box::new(S6103TryWithResources),
        Box::new(S6126StringBuilderReplace),
        Box::new(S6201PatternFlagsConst),
        Box::new(S6208RedundantParens),
        Box::new(S6242ConstructorInjection),
        Box::new(S6353EmptyAlt2),
        Box::new(S6395RandomUuid),
        Box::new(S6539TooManyParams),
        // Batch 3 - additional rules
        Box::new(S1155BCollectionEmpty),
        Box::new(S1172BUnusedParam),
        Box::new(S1301BSwitchPreferred),
        Box::new(S1302DuplicateConstName),
        Box::new(S1303LongStringLiteral),
        Box::new(S1312PrintStackTrace),
        Box::new(S1314OctalValue),
        Box::new(S1315FixmeTicket),
        Box::new(S1316TodoTicket),
        Box::new(S1317StringBuilderCap),
        Box::new(S1318DoubleBrace),
        Box::new(S1319InterfaceType),
        Box::new(S1320SimilarNames),
        Box::new(S1321SizeMax),
        Box::new(S1322ConcatNull),
        Box::new(S1323ConstantCondition),
        Box::new(S1324ArrayPosition),
        Box::new(S1325AnonymousRunnable),
        Box::new(S1326CatchThrowable),
        Box::new(S1327MultipleAsserts),
        Box::new(S1328UtilityConstructor),
        Box::new(S1329UseAddAll),
        Box::new(S1330EmptyWhile),
        Box::new(S1331StringIsEmpty),
        Box::new(S1332NestedLoops),
        Box::new(S1333UseContains),
        Box::new(S1334FormatSpecifiers),
        Box::new(S1335ParamReassign),
        Box::new(S1336BooleanSimplify),
        Box::new(S1337GenericCatch),
        Box::new(S1338EqualsComparison),
        Box::new(S1339OptionalField),
        Box::new(S1340InsecureRandom),
        Box::new(S1341BoxingLoop),
        Box::new(S1342LoopConcat),
        Box::new(S1343StringSplit),
        Box::new(S1344FloatEquals),
        Box::new(S1345NullInstanceof),
        Box::new(S1346MultipleReplace),
        Box::new(S1347PrimitiveStream),
        Box::new(S1348EmptyOptional),
        Box::new(S1349MultipleReturn),
        Box::new(S1350HardcodedPwd),
        Box::new(S1351EmptyStringInit),
        Box::new(S1352RawType),
        Box::new(S1353ConstantLeft),
        Box::new(S1354DeadStore),
        Box::new(S1355StringLength),
        Box::new(S1356FieldAccessEquals),
        Box::new(S1357LongMethodChain),
        Box::new(S1358UnusedException),
        Box::new(S1359SpecificAnnotation),
        Box::new(S1360SynchronizedMethod),
        Box::new(S1361ConstantInterface),
        Box::new(S1362NestedTernary),
        Box::new(S1363AbstractStatic),
        Box::new(S1364TestNaming),
        Box::new(S1365HardcodedPath),
        Box::new(S1366UsePath),
        Box::new(S1367FieldHiding),
        Box::new(S1368StaticInit),
        Box::new(S1369ObjectsHash),
        Box::new(S1370NullCheck),
        Box::new(S1371IgnoredException),
        Box::new(S1372PublicField),
        Box::new(S1373CommentedImport),
        Box::new(S1374ToStringNull),
        Box::new(S1375StringAppend),
        Box::new(S1376DateClass),
        Box::new(S1377LogFormat),
        Box::new(S1378AssertCollection),
        Box::new(S1379UtilityClass),
        Box::new(S1380CommentDensity),
        Box::new(S1381InterfaceSize),
        Box::new(S1382SingleResponsibility),
        Box::new(S1383MagicString),
        Box::new(S1384TryWithResources),
        Box::new(S1385ArrayFormat),
        Box::new(S1386MethodReference),
        Box::new(S1387AnnotationString),
        Box::new(S1388VolatileArray),
        Box::new(S1389EmptyMethod),
        Box::new(S1390PrimitiveStream),
        Box::new(S1391ExcessiveImports),
        Box::new(S1392StringJoin),
        Box::new(S1393SingletonSync),
        Box::new(S1394RequireNonNull),
        Box::new(S1395AssertProduction),
        Box::new(S1396CloseOrder),
        Box::new(S1397StandardCharsets),
        Box::new(S1398DoubleChecked),
        Box::new(S1399CatchThrow),
        Box::new(S1400VariableShadow),
        // Batch 4 - additional rules
        Box::new(S1500ComplexSwitch),
        Box::new(S1501LongMethod),
        Box::new(S1502DeepNesting),
        Box::new(S1503DuplicateCall),
        Box::new(S1504HardcodedDb),
        Box::new(S1505HardcodedServer),
        Box::new(S1506MagicComparison),
        Box::new(S1507EmptyConcat),
        Box::new(S1508InstanceofCast),
        Box::new(S1509RepeatedString),
        Box::new(S1510NullConcat),
        Box::new(S1511SBCapacity),
        Box::new(S1512UseFormat),
        Box::new(S1513MutableDefault),
        Box::new(S1514SameTypeCast),
        Box::new(S1515EmptyCatchContinue),
        Box::new(S1516ReturnInFinally),
        Box::new(S1517ThrowInFinally),
        Box::new(S1518InterfaceTypes),
        Box::new(S1519DuplicateCond),
        Box::new(S1520UnnecessaryElse),
        Box::new(S1521ComplexBoolean),
        Box::new(S1522NullBeforeUse),
        Box::new(S1523UseIsEmpty),
        Box::new(S1524LongParamList),
        Box::new(S1525DupLiteral),
        Box::new(S1526GodClass),
        Box::new(S1527FeatureEnvy),
        Box::new(S1528ObjectsEquals),
        Box::new(S1529SetterReturnsThis),
        Box::new(S1530UtilConstructor),
        Box::new(S1531StaticImportAll),
        Box::new(S1532UseTryResources),
        Box::new(S1533CatchGenericEx),
        Box::new(S1534LogRethrow),
        Box::new(S1535ParamLogging),
        Box::new(S1536ExceptionFlow),
        Box::new(S1537AppropriateCollection),
        Box::new(S1538HardcodedBuffer),
        Box::new(S1539EnhancedFor),
        Box::new(S1540LoopVarReassign),
        Box::new(S1541IncompatibleCompare),
        Box::new(S1542UnusedImport),
        Box::new(S1543DiamondOperator),
        Box::new(S1544RawTypes),
        Box::new(S1545InstanceofNull),
        Box::new(S1546MeaningfulNames),
        Box::new(S1547FieldInjection),
        Box::new(S1548MultipleAssert),
        Box::new(S1549TestNoAssert),
        Box::new(S1550RepeatedValue),
        // Batch 5 - additional rules
        Box::new(S1600ExcessiveComment),
        Box::new(S1601TodoRef),
        Box::new(S1602ReservedWord),
        Box::new(S1603NewStringCompare),
        Box::new(S1604AnonToLambda),
        Box::new(S1605RedundantSuper),
        Box::new(S1606EmptyPackage),
        Box::new(S1607NumericOverflow),
        Box::new(S1608VolatileMutable),
        Box::new(S1609ModifyParam),
        Box::new(S1610DefaultOnly),
        Box::new(S1611LambdaParens),
        Box::new(S1612BLambdaRef),
        Box::new(S1613UnnecessaryToString),
        Box::new(S1614ThisStatic),
        Box::new(S1615EmptyCtor),
        Box::new(S1616UnusedPrivateCtor),
        Box::new(S1617RedundantNull),
        Box::new(S1618CatchDoNothing),
        Box::new(S1619WrapperCompare),
        Box::new(S1620SizeInLoop),
        Box::new(S1621ContainsVsKey),
        Box::new(S1622FileFromUri),
        Box::new(S1623ArrayLength),
        Box::new(S1624StringPlusLoop),
        Box::new(S1625SimpleDateFormat),
        Box::new(S1626StaticRandom),
        Box::new(S1627PatternInLoop),
        Box::new(S1628FileInLoop),
        Box::new(S1629SynchronizedCollection),
        Box::new(S1630WrapperInLoop),
        Box::new(S1631GetClassSync),
        Box::new(S1632StringIntern),
        Box::new(S1633AvoidVector),
        Box::new(S1634AvoidHashtable),
        Box::new(S1635AvoidStack),
        Box::new(S1636StringBuffer),
        Box::new(S1637CalendarInstance),
        Box::new(S1638DeprecatedDate),
        Box::new(S1639BigDecimalDouble),
        Box::new(S1640BEntrySetKeys),
        Box::new(S1641ExplicitGc),
        Box::new(S1642Finalize),
        Box::new(S1643BAppendConcat),
        Box::new(S1644ExceptionMessage),
        Box::new(S1645SyncNonFinal),
        Box::new(S1646WaitNoSync),
        Box::new(S1647ThreadInCtor),
        Box::new(S1648LongChain),
        Box::new(S1649OptionalNull),
        Box::new(S1650ModifyWhileIterating),
        // Batch 6 - additional rules
        Box::new(S1651DoubleChecked),
        Box::new(S1652FinallyLeak),
        Box::new(S1653HardcodedCreds),
        Box::new(S1654DirectQuery),
        Box::new(S1655DeprecatedApi),
        Box::new(S1656SelfAssign),
        Box::new(S1657InfiniteRecursion),
        Box::new(S1658TimeInLoop),
        Box::new(S1659BMultiDecl),
        Box::new(S1660RedundantCall),
        Box::new(S1661UnnecessaryBox),
        Box::new(S1662CatchError),
        Box::new(S1663ReflectionBypass),
        Box::new(S1664AssertProduction),
        Box::new(S1665CloneSuper),
        Box::new(S1666EmptySync),
        Box::new(S1667WaitNoLoop),
        Box::new(S1668NotifyVsAll),
        Box::new(S1669ThreadStop),
        Box::new(S1670ThreadSuspend),
        Box::new(S1671ThreadDestroy),
        Box::new(S1672RuntimeExec),
        Box::new(S1673HardcodedLocale),
        Box::new(S1674HardcodedTimezone),
        Box::new(S1675ExcessiveInherit),
        Box::new(S1676MarkerInterface),
        Box::new(S1677InnerInInterface),
        Box::new(S1678FieldInjection),
        Box::new(S1679MagicTimeout),
        Box::new(S1680UnboundedWildcard),
        Box::new(S1681RawReturn),
        Box::new(S1682ArrayReturn),
        Box::new(S1683PublicArray),
        Box::new(S1684EnumOnlyValues),
        Box::new(S1685StaticInstanceData),
        Box::new(S1686ReturnMutable),
        Box::new(S1687StoreMutable),
        Box::new(S1688ExcessiveCatch),
        Box::new(S1689CatchRuntime),
        Box::new(S1690StaticMutable),
        Box::new(S1691HardcodedKey),
        Box::new(S1692InsecureProtocol),
        Box::new(S1693DisabledSsl),
        Box::new(S1694BAbstractNoMethods),
        Box::new(S1695EmptyInterface),
        Box::new(S1696CatchNpe),
        Box::new(S1697CatchNfe),
        Box::new(S1698BInstanceofCast),
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
    fn test_s106_system_out() {
        let source = r#"
            public class Test {
                void test() {
                    System.out.println("hello");
                    System.err.println("error");
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

        let issues = S106SystemOutUsed.check(&ctx);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn test_s107_too_many_params() {
        let source = r#"
            public class Test {
                public void tooMany(int a, int b, int c, int d, int e, int f, int g, int h) {}
                public void ok(int a, int b, int c) {}
            }
        "#;
        let (tree, config) = create_test_context(source);
        let ctx = AnalysisContext {
            source,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        let issues = S107TooManyParameters.check(&ctx);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_s112_generic_exception() {
        let source = r#"
            public class Test {
                void test() {
                    throw new Exception("bad");
                    throw new RuntimeException("also bad");
                    throw new IllegalArgumentException("ok");
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

        let issues = S112GenericException.check(&ctx);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn test_s134_deep_nesting() {
        let source = r#"
            public class Test {
                void test() {
                    if (a) {
                        if (b) {
                            if (c) {
                                if (d) {
                                    if (e) {
                                        doSomething();
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

        let issues = S134DeepNesting.check(&ctx);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_s1155_collection_is_empty() {
        let source = r#"
            public class Test {
                void test(List<String> list) {
                    if (list.size() == 0) {}
                    if (list.size() > 0) {}
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

        let issues = S1155UseCollectionIsEmpty.check(&ctx);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn test_s1210_equals_hashcode() {
        let source = r#"
            public class Test {
                public boolean equals(Object obj) {
                    return true;
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

        let issues = S1210EqualsHashCode.check(&ctx);
        assert_eq!(issues.len(), 1);
    }
}
