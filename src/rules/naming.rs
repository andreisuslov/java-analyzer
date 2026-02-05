//! Naming convention rules (S100-S120, etc.)

use super::*;
use tree_sitter::{Query, QueryCursor};

pub fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(S100MethodNaming),
        Box::new(S101ClassNaming),
        Box::new(S114InterfaceNaming),
        Box::new(S115ConstantNaming),
        Box::new(S116FieldNaming),
        Box::new(S117LocalVariableNaming),
        Box::new(S118AbstractClassNaming),
        Box::new(S119TypeParameterNaming),
        Box::new(S120PackageNaming),
        Box::new(S1312LoggerNaming),
        // Additional naming rules
        Box::new(S1700BFieldClassName),
        Box::new(S1701BooleanGetter),
        Box::new(S1702SetterReturn),
        Box::new(S1703ParameterNaming),
        Box::new(S1704TestMethodNaming),
        Box::new(S1705FactoryNaming),
        Box::new(S1706ExceptionNaming),
        Box::new(S1707EnumNaming),
        Box::new(S1708EnumConstantNaming),
        Box::new(S1709BuilderNaming),
        Box::new(S1711AnnotationElement),
        Box::new(S1712TestClassNaming),
        Box::new(S1713LambdaNaming),
        Box::new(S1714GenericNaming),
        Box::new(S1715AnnotationConstant),
        Box::new(S1716PackageLong),
        Box::new(S1717ClassNameLong),
        Box::new(S1718MethodNameLong),
        Box::new(S1719VarNameLong),
        Box::new(S1720Abbreviation),
        Box::new(S1721BooleanField),
        Box::new(S1722CollectionNaming),
        Box::new(S1723MapNaming),
        Box::new(S1724OptionalNaming),
        Box::new(S1725StreamNaming),
        Box::new(S1726FutureNaming),
        Box::new(S1727ImplNaming),
        Box::new(S1728AbstractNaming),
        Box::new(S1729UtilNaming),
        Box::new(S1730ConstantCollection),
        Box::new(S1731CounterNaming),
        Box::new(S1732IndexNaming),
        Box::new(S1733TempNaming),
        Box::new(S1734DataFieldNaming),
        Box::new(S1735ServiceNaming),
        Box::new(S1736RepositoryNaming),
        Box::new(S1737ControllerNaming),
        Box::new(S1738ConfigNaming),
        Box::new(S1739TestFixtureNaming),
        Box::new(S1740AsyncNaming),
        Box::new(S1741EventHandlerNaming),
        Box::new(S1742CallbackNaming),
        Box::new(S1743PredicateNaming),
    ]
}

// S100: Method names should comply with a naming convention
pub struct S100MethodNaming;
impl Rule for S100MethodNaming {
    fn id(&self) -> &str { "S100" }
    fn title(&self) -> &str { "Method names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }
    fn description(&self) -> &str {
        "Method names should start with a lowercase letter and use camelCase."
    }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-zA-Z0-9]*$").unwrap());
        let mut issues = Vec::new();

        let query = Query::new(
            tree_sitter_java::language(),
            "(method_declaration name: (identifier) @name)"
        ).unwrap();

        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&query, ctx.tree.root_node(), ctx.source.as_bytes()) {
            for cap in m.captures {
                let name = &ctx.source[cap.node.byte_range()];
                // Skip common exceptions
                if !PATTERN.is_match(name) && !is_method_exception(name) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        cap.node.start_position().row + 1,
                        cap.node.start_position().column + 1,
                        format!("Rename method '{}' to match camelCase convention", name),
                        Some(name.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

fn is_method_exception(name: &str) -> bool {
    // Allow main, setUp, tearDown, and JUnit test methods
    matches!(name, "main" | "setUp" | "tearDown") || name.starts_with("test")
}

// S101: Class names should comply with a naming convention
pub struct S101ClassNaming;
impl Rule for S101ClassNaming {
    fn id(&self) -> &str { "S101" }
    fn title(&self) -> &str { "Class names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z][a-zA-Z0-9]*$").unwrap());
        let mut issues = Vec::new();

        let query = Query::new(
            tree_sitter_java::language(),
            "(class_declaration name: (identifier) @name)"
        ).unwrap();

        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&query, ctx.tree.root_node(), ctx.source.as_bytes()) {
            for cap in m.captures {
                let name = &ctx.source[cap.node.byte_range()];
                if !PATTERN.is_match(name) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        cap.node.start_position().row + 1,
                        cap.node.start_position().column + 1,
                        format!("Rename class '{}' to match PascalCase convention", name),
                        Some(name.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S114: Interface names should comply with a naming convention
pub struct S114InterfaceNaming;
impl Rule for S114InterfaceNaming {
    fn id(&self) -> &str { "S114" }
    fn title(&self) -> &str { "Interface names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z][a-zA-Z0-9]*$").unwrap());
        let mut issues = Vec::new();

        let query = Query::new(
            tree_sitter_java::language(),
            "(interface_declaration name: (identifier) @name)"
        ).unwrap();

        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&query, ctx.tree.root_node(), ctx.source.as_bytes()) {
            for cap in m.captures {
                let name = &ctx.source[cap.node.byte_range()];
                // Don't flag interfaces starting with 'I' as that's a valid convention
                if !PATTERN.is_match(name) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        cap.node.start_position().row + 1,
                        cap.node.start_position().column + 1,
                        format!("Rename interface '{}' to match PascalCase convention", name),
                        Some(name.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S115: Constant names should comply with a naming convention
pub struct S115ConstantNaming;
impl Rule for S115ConstantNaming {
    fn id(&self) -> &str { "S115" }
    fn title(&self) -> &str { "Constant names should comply with UPPER_SNAKE_CASE" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CONST_PATTERN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$").unwrap()
        });
        static CONST_DECL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(static\s+final|final\s+static)\s+\w+\s+(\w+)").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(caps) = CONST_DECL.captures(line) {
                if let Some(name) = caps.get(2) {
                    let name_str = name.as_str();
                    // Skip loggers and serialVersionUID
                    if !CONST_PATTERN.is_match(name_str)
                        && !name_str.starts_with("log")
                        && name_str != "serialVersionUID"
                    {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            name.start() + 1,
                            format!("Rename constant '{}' to UPPER_SNAKE_CASE", name_str),
                            Some(name_str.to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S116: Field names should comply with a naming convention
pub struct S116FieldNaming;
impl Rule for S116FieldNaming {
    fn id(&self) -> &str { "S116" }
    fn title(&self) -> &str { "Field names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-zA-Z0-9]*$").unwrap());
        static FIELD_DECL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"private\s+(\w+)\s+(\w+)\s*[;=]").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            // Skip constants (static final)
            if line.contains("static") && line.contains("final") {
                continue;
            }

            if let Some(caps) = FIELD_DECL.captures(line) {
                if let Some(name) = caps.get(2) {
                    let name_str = name.as_str();
                    if !PATTERN.is_match(name_str) {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            name.start() + 1,
                            format!("Rename field '{}' to match camelCase convention", name_str),
                            Some(name_str.to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// S117: Local variable names should comply with a naming convention
pub struct S117LocalVariableNaming;
impl Rule for S117LocalVariableNaming {
    fn id(&self) -> &str { "S117" }
    fn title(&self) -> &str { "Local variable names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-zA-Z0-9]*$").unwrap());
        let mut issues = Vec::new();

        let query = Query::new(
            tree_sitter_java::language(),
            "(local_variable_declaration declarator: (variable_declarator name: (identifier) @name))"
        ).unwrap();

        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&query, ctx.tree.root_node(), ctx.source.as_bytes()) {
            for cap in m.captures {
                let name = &ctx.source[cap.node.byte_range()];
                // Allow single character names for loop counters
                if name.len() > 1 && !PATTERN.is_match(name) && name != "_" {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        cap.node.start_position().row + 1,
                        cap.node.start_position().column + 1,
                        format!("Rename variable '{}' to match camelCase convention", name),
                        Some(name.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S118: Abstract class names should comply with a naming convention
pub struct S118AbstractClassNaming;
impl Rule for S118AbstractClassNaming {
    fn id(&self) -> &str { "S118" }
    fn title(&self) -> &str { "Abstract class names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^Abstract[A-Z][a-zA-Z0-9]*$|^[A-Z][a-zA-Z0-9]*Base$").unwrap()
        });
        let mut issues = Vec::new();

        // Find abstract classes
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("abstract") && line.contains("class") {
                static CLASS_NAME: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r"abstract\s+class\s+(\w+)").unwrap()
                });
                if let Some(caps) = CLASS_NAME.captures(line) {
                    if let Some(name) = caps.get(1) {
                        let name_str = name.as_str();
                        if !PATTERN.is_match(name_str) && !name_str.starts_with("Abstract") {
                            // This is a style suggestion, not strictly enforced
                            // Uncomment to enable:
                            // issues.push(create_issue(...));
                        }
                    }
                }
            }
        }
        issues
    }
}

// S119: Type parameter names should comply with a naming convention
pub struct S119TypeParameterNaming;
impl Rule for S119TypeParameterNaming {
    fn id(&self) -> &str { "S119" }
    fn title(&self) -> &str { "Type parameter names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        // Type parameters should be single uppercase letters or end with T
        static PATTERN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^[A-Z]$|^[A-Z][a-zA-Z0-9]*T$").unwrap()
        });
        let mut issues = Vec::new();

        let query = Query::new(
            tree_sitter_java::language(),
            "(type_parameter (type_identifier) @name)"
        ).unwrap();

        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&query, ctx.tree.root_node(), ctx.source.as_bytes()) {
            for cap in m.captures {
                let name = &ctx.source[cap.node.byte_range()];
                if !PATTERN.is_match(name) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        cap.node.start_position().row + 1,
                        cap.node.start_position().column + 1,
                        format!("Rename type parameter '{}' to single letter or end with 'T'", name),
                        Some(name.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S120: Package names should comply with a naming convention
pub struct S120PackageNaming;
impl Rule for S120PackageNaming {
    fn id(&self) -> &str { "S120" }
    fn title(&self) -> &str { "Package names should comply with a naming convention" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PATTERN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$").unwrap()
        });
        let mut issues = Vec::new();

        let query = Query::new(
            tree_sitter_java::language(),
            "(package_declaration (scoped_identifier) @name)"
        ).unwrap();

        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&query, ctx.tree.root_node(), ctx.source.as_bytes()) {
            for cap in m.captures {
                let name = &ctx.source[cap.node.byte_range()];
                if !PATTERN.is_match(name) {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        cap.node.start_position().row + 1,
                        cap.node.start_position().column + 1,
                        format!("Rename package '{}' to use lowercase letters only", name),
                        Some(name.to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S1312: Logger fields should follow naming convention
pub struct S1312LoggerNaming;
impl Rule for S1312LoggerNaming {
    fn id(&self) -> &str { "S1312" }
    fn title(&self) -> &str { "Loggers should be named LOG or LOGGER" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Naming }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LOGGER_DECL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(Logger|Log)\s+(\w+)\s*=").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if let Some(caps) = LOGGER_DECL.captures(line) {
                if let Some(name) = caps.get(2) {
                    let name_str = name.as_str();
                    if !matches!(name_str, "LOG" | "LOGGER" | "log" | "logger") {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            name.start() + 1,
                            format!("Rename logger '{}' to 'LOG', 'LOGGER', 'log', or 'logger'", name_str),
                            Some(name_str.to_string()),
                        ));
                    }
                }
            }
        }
        issues
    }
}

// ============================================================================
// Additional naming rules
// ============================================================================

macro_rules! naming_rule {
    ($struct_name:ident, $id:expr, $title:expr, $severity:expr, $pattern:expr, $message:expr) => {
        pub struct $struct_name;
        impl Rule for $struct_name {
            fn id(&self) -> &str { $id }
            fn title(&self) -> &str { $title }
            fn severity(&self) -> Severity { $severity }
            fn category(&self) -> RuleCategory { RuleCategory::Naming }
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

// S1700B: Field should not have same name as enclosing class
naming_rule!(S1700BFieldClassName, "S1700B", "Field should not share class name",
    Severity::Major, r"class\s+\w+[^{]+\{[^}]*(?:private|public|protected)\s+\w+\s+\w+\s*[;=]",
    "Field has same name as class.");

// S1701: Boolean getter should start with is
naming_rule!(S1701BooleanGetter, "S1701", "Boolean getter should start with is",
    Severity::Minor, r"(?:public|protected)\s+boolean\s+get\w+\s*\(\s*\)",
    "Boolean getter should start with 'is' not 'get'.");

// S1702: Setter should not return value
naming_rule!(S1702SetterReturn, "S1702", "Setter should not return value",
    Severity::Minor, r"(?:public|protected)\s+(?:int|String|boolean|Object|this)\s+set[A-Z]\w*\s*\(",
    "Setter methods should return void.");

// S1703: Parameter names should be meaningful
naming_rule!(S1703ParameterNaming, "S1703", "Parameter names should be meaningful",
    Severity::Minor, r"\(\s*\w+\s+[a-z]\s*,|\(\s*\w+\s+[a-z]\s*\)",
    "Use meaningful parameter names instead of single letters.");

// S1704: Test methods should have meaningful names
naming_rule!(S1704TestMethodNaming, "S1704", "Test methods should have meaningful names",
    Severity::Minor, r"@Test\s+(?:public\s+)?void\s+test\d+\s*\(",
    "Test methods should describe the behavior being tested.");

// S1705: Factory method naming
naming_rule!(S1705FactoryNaming, "S1705", "Factory methods should be named consistently",
    Severity::Minor, r"public\s+static\s+\w+\s+(?:make|build|produce)\w+\s*\(",
    "Consider using 'create', 'of', or 'from' for factory methods.");

// S1706: Exception class naming
naming_rule!(S1706ExceptionNaming, "S1706", "Exception classes should end with Exception",
    Severity::Major, r"class\s+\w+[a-z]\s+extends\s+\w*Exception",
    "Exception class should end with 'Exception'.");

// S1707: Enum naming
naming_rule!(S1707EnumNaming, "S1707", "Enum type names should be singular",
    Severity::Minor, r"enum\s+\w+s\s*\{",
    "Enum names should be singular nouns.");

// S1708: Enum constant naming
naming_rule!(S1708EnumConstantNaming, "S1708", "Enum constants should be uppercase",
    Severity::Minor, r"enum\s+\w+\s*\{[^}]*[a-z]\w*\s*[,}]",
    "Enum constants should be UPPER_CASE.");

// S1709: Builder method naming
naming_rule!(S1709BuilderNaming, "S1709", "Builder methods should follow pattern",
    Severity::Minor, r"class\s+\w+Builder\s*\{[^}]*\}",
    "Builder class should have a build() method.");

// S1711: Annotation element naming
naming_rule!(S1711AnnotationElement, "S1711", "Annotation elements should be camelCase",
    Severity::Minor, r"@interface\s+\w+\s*\{[^}]*\w+_\w+\s*\(\s*\)",
    "Annotation elements should use camelCase.");

// S1712: Test class naming
naming_rule!(S1712TestClassNaming, "S1712", "Test class should end with Test",
    Severity::Minor, r"class\s+\w+[a-z]\s*\{[^}]*@Test",
    "Test classes should end with 'Test'.");

// S1713: Lambda parameter naming
naming_rule!(S1713LambdaNaming, "S1713", "Lambda parameters should be meaningful",
    Severity::Minor, r"->\s*\{[^}]{50,}.*[a-z]\s*->",
    "Use meaningful names for lambda parameters in complex lambdas.");

// S1714: Generic type naming
naming_rule!(S1714GenericNaming, "S1714", "Generic types should follow convention",
    Severity::Minor, r"<\s*[a-z][a-z0-9]+\s*>",
    "Type parameters should be single uppercase letters.");

// S1715: Constant naming in annotation
naming_rule!(S1715AnnotationConstant, "S1715", "Annotation constants should be uppercase",
    Severity::Minor, r"@interface\s+\w+\s*\{[^}]*static\s+final\s+\w+\s+[a-z]\w*",
    "Annotation constants should be UPPER_CASE.");

// S1716: Package name too long
naming_rule!(S1716PackageLong, "S1716", "Package name is too long",
    Severity::Minor, r"package\s+\w+\.\w+\.\w+\.\w+\.\w+\.\w+\.\w+",
    "Package name has too many segments.");

// S1717: Class name too long
naming_rule!(S1717ClassNameLong, "S1717", "Class name is too long",
    Severity::Minor, r"class\s+\w{40,}\s",
    "Class name is excessively long.");

// S1718: Method name too long
naming_rule!(S1718MethodNameLong, "S1718", "Method name is too long",
    Severity::Minor, r"(?:public|private|protected)\s+\w+\s+\w{35,}\s*\(",
    "Method name is excessively long.");

// S1719: Variable name too long
naming_rule!(S1719VarNameLong, "S1719", "Variable name is too long",
    Severity::Minor, r"(?:int|String|boolean|double|long)\s+\w{30,}\s*[;=]",
    "Variable name is excessively long.");

// S1720: Avoid abbreviations in names
naming_rule!(S1720Abbreviation, "S1720", "Avoid abbreviations in names",
    Severity::Minor, r"(?:public|private|protected)\s+\w+\s+(?:\w*(?:impl|mgr|util|cfg|ctx|svc|repo)\w*)\s*[;=(]",
    "Avoid common abbreviations in names.");

// S1721: Boolean field naming
naming_rule!(S1721BooleanField, "S1721", "Boolean field should start with is/has/can",
    Severity::Minor, r"(?:private|protected)\s+boolean\s+[a-z]\w*\s*[;=]",
    "Boolean fields should start with is, has, can, etc.");

// S1722: Collection naming
naming_rule!(S1722CollectionNaming, "S1722", "Collection variable should be plural",
    Severity::Minor, r"(?:List|Set|Collection)<[^>]+>\s+[a-z]+[a-rt-z]\s*[;=]",
    "Collection variables should have plural names.");

// S1723: Map naming
naming_rule!(S1723MapNaming, "S1723", "Map variable naming convention",
    Severity::Minor, r"Map<[^>]+>\s+[a-z][a-z0-9]*\s*[;=]",
    "Map variables should indicate key-value relationship.");

// S1724: Optional naming
naming_rule!(S1724OptionalNaming, "S1724", "Optional variable naming",
    Severity::Minor, r"Optional<[^>]+>\s+(?:maybe|opt|possible)\w*\s*[;=]",
    "Don't prefix Optional variables with maybe/opt.");

// S1725: Stream naming
naming_rule!(S1725StreamNaming, "S1725", "Stream variable naming",
    Severity::Minor, r"Stream<[^>]+>\s+\w+Stream\s*[;=]",
    "Avoid 'Stream' suffix for stream variables.");

// S1726: Future naming
naming_rule!(S1726FutureNaming, "S1726", "Future variable naming",
    Severity::Minor, r"(?:Future|CompletableFuture)<[^>]+>\s+\w+Future\s*[;=]",
    "Avoid 'Future' suffix for future variables.");

// S1727: Interface implementation naming
naming_rule!(S1727ImplNaming, "S1727", "Avoid Impl suffix for implementations",
    Severity::Minor, r"class\s+\w+Impl\s+implements",
    "Consider more descriptive names than 'Impl' suffix.");

// S1728: Abstract class naming
naming_rule!(S1728AbstractNaming, "S1728", "Abstract class naming convention",
    Severity::Minor, r"abstract\s+class\s+[A-Z][a-z]\w*\s*[{<]",
    "Consider 'Abstract' prefix or 'Base' suffix for abstract classes.");

// S1729: Utility class naming
naming_rule!(S1729UtilNaming, "S1729", "Utility class naming convention",
    Severity::Minor, r"(?:final\s+)?class\s+\w+(?:Helper|Helpers)\s*\{",
    "Prefer 'Utils' suffix over 'Helper'.");

// S1730: Constant collection naming
naming_rule!(S1730ConstantCollection, "S1730", "Constant collection naming",
    Severity::Minor, r"static\s+final\s+(?:List|Set|Map)\s+[A-Z_]+\s*=",
    "Constant collections should have uppercase names.");

// S1731: Counter variable naming
naming_rule!(S1731CounterNaming, "S1731", "Counter variable naming",
    Severity::Minor, r"int\s+(?:cnt|num|no)\s*[;=]",
    "Use 'count' instead of 'cnt', 'num', or 'no'.");

// S1732: Index variable naming
naming_rule!(S1732IndexNaming, "S1732", "Index variable naming",
    Severity::Minor, r"for\s*\(\s*int\s+(?:idx|ind)\s*=",
    "Use 'index' or 'i' instead of 'idx' or 'ind'.");

// S1733: Temporary variable naming
naming_rule!(S1733TempNaming, "S1733", "Temporary variable naming",
    Severity::Minor, r"(?:int|String|Object)\s+(?:temp|tmp|t)\s*[;=]",
    "Avoid 'temp', 'tmp', or 't' for variable names.");

// S1734: Data class field naming
naming_rule!(S1734DataFieldNaming, "S1734", "Data class field naming",
    Severity::Minor, r"(?:private|protected)\s+\w+\s+m[A-Z]\w*\s*[;=]",
    "Avoid Hungarian notation (m prefix) for fields.");

// S1735: Service class naming
naming_rule!(S1735ServiceNaming, "S1735", "Service class naming convention",
    Severity::Minor, r"class\s+\w*(?:Srvc|Svc)\s",
    "Use 'Service' instead of 'Srvc' or 'Svc'.");

// S1736: Repository naming
naming_rule!(S1736RepositoryNaming, "S1736", "Repository class naming",
    Severity::Minor, r"interface\s+\w+(?:Repo|DAO)\s+extends",
    "Consider using 'Repository' suffix.");

// S1737: Controller naming
naming_rule!(S1737ControllerNaming, "S1737", "Controller class naming",
    Severity::Minor, r"@(?:RestController|Controller)\s+class\s+\w+[a-z]\s*\{",
    "Controller classes should end with 'Controller'.");

// S1738: Config class naming
naming_rule!(S1738ConfigNaming, "S1738", "Configuration class naming",
    Severity::Minor, r"@Configuration\s+class\s+\w+[a-z]\s*\{",
    "Configuration classes should end with 'Config'.");

// S1739: Test fixture naming
naming_rule!(S1739TestFixtureNaming, "S1739", "Test fixture naming convention",
    Severity::Minor, r"@BeforeEach\s+(?:public\s+)?void\s+(?:init|prepare|before)\w*\s*\(",
    "BeforeEach methods should be named 'setup' or 'setUp'.");

// S1740: Async method naming
naming_rule!(S1740AsyncNaming, "S1740", "Async method naming convention",
    Severity::Minor, r"(?:CompletableFuture|Future)<[^>]+>\s+[a-z]\w*\s*\(",
    "Consider 'Async' suffix for async methods.");

// S1741: Event handler naming
naming_rule!(S1741EventHandlerNaming, "S1741", "Event handler naming convention",
    Severity::Minor, r"void\s+(?:on|handle)[a-z]\w*\s*\(",
    "Event handlers should start with 'on' or 'handle' followed by uppercase.");

// S1742: Callback naming
naming_rule!(S1742CallbackNaming, "S1742", "Callback parameter naming",
    Severity::Minor, r"\(\s*(?:Consumer|Function|Supplier|Runnable)\s*<[^>]*>\s+cb\s*\)",
    "Use descriptive names for callback parameters.");

// S1743: Predicate naming
naming_rule!(S1743PredicateNaming, "S1743", "Predicate variable naming",
    Severity::Minor, r"Predicate<[^>]+>\s+[a-z]\w*\s*[;=]",
    "Predicate variables should start with is, has, can, etc.");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalyzerConfig;

    fn analyze_code(code: &str, rule: &dyn Rule) -> Vec<Issue> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let config = AnalyzerConfig::default();

        let ctx = AnalysisContext {
            source: code,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        rule.check(&ctx)
    }

    #[test]
    fn test_s100_good_method_names() {
        let code = r#"
            public class Test {
                public void doSomething() {}
                public void calculateTotal() {}
                public void main(String[] args) {}
            }
        "#;
        let issues = analyze_code(code, &S100MethodNaming);
        assert!(issues.is_empty(), "Good method names should not be flagged");
    }

    #[test]
    fn test_s100_bad_method_names() {
        let code = r#"
            public class Test {
                public void Do_Something() {}
                public void CalculateTotal() {}
            }
        "#;
        let issues = analyze_code(code, &S100MethodNaming);
        assert_eq!(issues.len(), 2, "Bad method names should be flagged");
    }

    #[test]
    fn test_s101_good_class_names() {
        let code = r#"
            public class MyClass {}
            class AnotherClass {}
        "#;
        let issues = analyze_code(code, &S101ClassNaming);
        assert!(issues.is_empty(), "Good class names should not be flagged");
    }

    #[test]
    fn test_s101_bad_class_names() {
        let code = r#"
            public class myClass {}
            class another_class {}
        "#;
        let issues = analyze_code(code, &S101ClassNaming);
        assert_eq!(issues.len(), 2, "Bad class names should be flagged");
    }

    #[test]
    fn test_s115_good_constant_names() {
        let code = r#"
            public class Test {
                public static final int MAX_VALUE = 100;
                public static final String API_KEY = "key";
            }
        "#;
        let issues = analyze_code(code, &S115ConstantNaming);
        assert!(issues.is_empty(), "Good constant names should not be flagged");
    }

    #[test]
    fn test_s115_bad_constant_names() {
        let code = r#"
            public class Test {
                public static final int maxValue = 100;
                public static final String apiKey = "key";
            }
        "#;
        let issues = analyze_code(code, &S115ConstantNaming);
        assert_eq!(issues.len(), 2, "Bad constant names should be flagged");
    }
}
