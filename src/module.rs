//! Multi-Module Project Support
//!
//! Detects and analyzes Maven and Gradle multi-module projects.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

/// Build system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildSystem {
    Maven,
    Gradle,
    Unknown,
}

impl BuildSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            BuildSystem::Maven => "Maven",
            BuildSystem::Gradle => "Gradle",
            BuildSystem::Unknown => "Unknown",
        }
    }
}

/// A single module in a multi-module project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    /// Module name/identifier
    pub name: String,
    /// Path to the module root directory
    pub path: PathBuf,
    /// Build system used
    pub build_system: BuildSystem,
    /// Parent module name (if this is a submodule)
    pub parent: Option<String>,
    /// Child module names
    pub children: Vec<String>,
}

impl Module {
    /// Create a new module
    pub fn new(name: String, path: PathBuf, build_system: BuildSystem) -> Self {
        Self {
            name,
            path,
            build_system,
            parent: None,
            children: Vec::new(),
        }
    }

    /// Check if a file path belongs to this module
    pub fn contains_file(&self, file_path: &Path) -> bool {
        file_path.starts_with(&self.path)
    }
}

/// Structure representing a multi-module project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStructure {
    /// Root module (or single module for non-multi-module projects)
    pub root: Module,
    /// All modules indexed by name
    pub modules: HashMap<String, Module>,
    /// Build system detected
    pub build_system: BuildSystem,
}

impl ModuleStructure {
    /// Detect module structure from a project root
    pub fn detect(project_root: &Path) -> Option<Self> {
        // Try Maven first
        if let Some(structure) = detect_maven(project_root) {
            return Some(structure);
        }

        // Try Gradle
        if let Some(structure) = detect_gradle(project_root) {
            return Some(structure);
        }

        None
    }

    /// Get the module that contains a given file path
    pub fn module_for_file(&self, file_path: &Path) -> Option<&Module> {
        // Find the module with the longest matching path (most specific)
        self.modules
            .values()
            .filter(|m| m.contains_file(file_path))
            .max_by_key(|m| m.path.components().count())
    }

    /// Get module name for a file path
    pub fn module_name_for_file(&self, file_path: &Path) -> Option<&str> {
        self.module_for_file(file_path).map(|m| m.name.as_str())
    }

    /// Get all module names
    pub fn module_names(&self) -> Vec<&str> {
        self.modules.keys().map(|s| s.as_str()).collect()
    }

    /// Check if this is a multi-module project
    pub fn is_multi_module(&self) -> bool {
        self.modules.len() > 1
    }
}

/// Detect Maven multi-module project structure
pub fn detect_maven(project_root: &Path) -> Option<ModuleStructure> {
    let pom_path = project_root.join("pom.xml");
    if !pom_path.exists() {
        return None;
    }

    let content = fs::read_to_string(&pom_path).ok()?;
    let (artifact_id, module_names) = parse_pom_xml(&content)?;

    let root_name = artifact_id.unwrap_or_else(|| "root".to_string());
    let mut root = Module::new(
        root_name.clone(),
        project_root.to_path_buf(),
        BuildSystem::Maven,
    );
    let mut modules = HashMap::new();

    // Process child modules
    for module_name in &module_names {
        let module_path = project_root.join(module_name);
        if module_path.exists() {
            // Recursively detect submodules
            if let Some(sub_structure) = detect_maven(&module_path) {
                for (name, mut sub_module) in sub_structure.modules {
                    if sub_module.parent.is_none() {
                        sub_module.parent = Some(root_name.clone());
                    }
                    modules.insert(name, sub_module);
                }
            } else {
                // Simple module without submodules
                let mut module = Module::new(module_name.clone(), module_path, BuildSystem::Maven);
                module.parent = Some(root_name.clone());
                root.children.push(module_name.clone());
                modules.insert(module_name.clone(), module);
            }
        }
    }

    // Add root module
    modules.insert(root_name.clone(), root.clone());

    Some(ModuleStructure {
        root,
        modules,
        build_system: BuildSystem::Maven,
    })
}

/// Parse pom.xml to extract artifact ID and module names
fn parse_pom_xml(content: &str) -> Option<(Option<String>, Vec<String>)> {
    let mut reader = Reader::from_str(content);
    reader.trim_text(true);

    let mut artifact_id = None;
    let mut modules = Vec::new();
    let mut in_modules = false;
    let mut in_module = false;
    let mut in_artifact_id = false;
    let mut depth = 0;
    let mut project_depth = 0;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                let name = e.name();
                let local_name = std::str::from_utf8(name.as_ref()).unwrap_or("");

                if local_name == "project" {
                    project_depth = depth;
                } else if local_name == "modules" && depth == project_depth + 1 {
                    in_modules = true;
                } else if local_name == "module" && in_modules {
                    in_module = true;
                } else if local_name == "artifactId"
                    && depth == project_depth + 1
                    && artifact_id.is_none()
                {
                    in_artifact_id = true;
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let local_name = std::str::from_utf8(name.as_ref()).unwrap_or("");

                if local_name == "modules" {
                    in_modules = false;
                } else if local_name == "module" {
                    in_module = false;
                } else if local_name == "artifactId" {
                    in_artifact_id = false;
                }
                depth -= 1;
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().ok()?.into_owned();
                if in_module {
                    modules.push(text.trim().to_string());
                } else if in_artifact_id {
                    artifact_id = Some(text.trim().to_string());
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    Some((artifact_id, modules))
}

/// Detect Gradle multi-module project structure
pub fn detect_gradle(project_root: &Path) -> Option<ModuleStructure> {
    // Check for settings.gradle or settings.gradle.kts
    let settings_path = project_root.join("settings.gradle");
    let settings_kts_path = project_root.join("settings.gradle.kts");

    let settings_content = if settings_path.exists() {
        fs::read_to_string(&settings_path).ok()
    } else if settings_kts_path.exists() {
        fs::read_to_string(&settings_kts_path).ok()
    } else {
        // Check if there's at least a build.gradle
        let build_path = project_root.join("build.gradle");
        let build_kts_path = project_root.join("build.gradle.kts");
        if !build_path.exists() && !build_kts_path.exists() {
            return None;
        }
        // Single module project
        let name = project_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("root")
            .to_string();
        let root = Module::new(
            name.clone(),
            project_root.to_path_buf(),
            BuildSystem::Gradle,
        );
        let mut modules = HashMap::new();
        modules.insert(name.clone(), root.clone());
        return Some(ModuleStructure {
            root,
            modules,
            build_system: BuildSystem::Gradle,
        });
    };

    let content = settings_content?;
    let module_paths = parse_settings_gradle(&content);

    // Get root project name from settings file or directory name
    let root_name = parse_gradle_root_name(&content).unwrap_or_else(|| {
        project_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("root")
            .to_string()
    });

    let mut root = Module::new(
        root_name.clone(),
        project_root.to_path_buf(),
        BuildSystem::Gradle,
    );
    let mut modules = HashMap::new();

    for module_path in &module_paths {
        // Convert Gradle path notation (e.g., ":app" or ":parent:child") to file path
        let path_parts: Vec<&str> = module_path.trim_start_matches(':').split(':').collect();
        let module_name = path_parts.last().unwrap_or(&"").to_string();
        let relative_path: PathBuf = path_parts.iter().collect();
        let full_path = project_root.join(&relative_path);

        if full_path.exists() {
            let mut module = Module::new(module_name.clone(), full_path, BuildSystem::Gradle);

            // Set parent relationship
            if path_parts.len() > 1 {
                // Has a parent module
                let parent_name = path_parts[path_parts.len() - 2].to_string();
                module.parent = Some(parent_name);
            } else {
                module.parent = Some(root_name.clone());
                root.children.push(module_name.clone());
            }

            modules.insert(module_name, module);
        }
    }

    // Add root module
    modules.insert(root_name.clone(), root.clone());

    Some(ModuleStructure {
        root,
        modules,
        build_system: BuildSystem::Gradle,
    })
}

/// Parse settings.gradle to extract module paths
fn parse_settings_gradle(content: &str) -> Vec<String> {
    let mut modules = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Match include statements: include 'module-a', 'module-b' or include ':app'
        if trimmed.starts_with("include") {
            // Extract quoted strings
            let mut in_quote = false;
            let mut quote_char = ' ';
            let mut current = String::new();

            for ch in trimmed.chars() {
                if !in_quote && (ch == '\'' || ch == '"') {
                    in_quote = true;
                    quote_char = ch;
                } else if in_quote && ch == quote_char {
                    in_quote = false;
                    if !current.is_empty() {
                        modules.push(current.clone());
                        current.clear();
                    }
                } else if in_quote {
                    current.push(ch);
                }
            }
        }

        // Also handle includeBuild for composite builds (less common)
        // We don't process these as they're typically external projects
    }

    modules
}

/// Parse root project name from settings.gradle
fn parse_gradle_root_name(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();

        // Match: rootProject.name = 'project-name' or rootProject.name = "project-name"
        if trimmed.starts_with("rootProject.name") {
            // Extract the quoted value
            let mut in_quote = false;
            let mut quote_char = ' ';
            let mut name = String::new();

            for ch in trimmed.chars() {
                if !in_quote && (ch == '\'' || ch == '"') {
                    in_quote = true;
                    quote_char = ch;
                } else if in_quote && ch == quote_char {
                    return Some(name);
                } else if in_quote {
                    name.push(ch);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ===== BuildSystem Tests =====

    #[test]
    fn test_build_system_as_str() {
        assert_eq!(BuildSystem::Maven.as_str(), "Maven");
        assert_eq!(BuildSystem::Gradle.as_str(), "Gradle");
        assert_eq!(BuildSystem::Unknown.as_str(), "Unknown");
    }

    // ===== Module Tests =====

    #[test]
    fn test_module_contains_file() {
        let module = Module::new(
            "app".to_string(),
            PathBuf::from("/project/app"),
            BuildSystem::Maven,
        );

        assert!(module.contains_file(Path::new("/project/app/src/Main.java")));
        assert!(module.contains_file(Path::new("/project/app/pom.xml")));
        assert!(!module.contains_file(Path::new("/project/other/Main.java")));
    }

    // ===== Maven Detection Tests =====

    #[test]
    fn test_parse_simple_pom() {
        let pom = r#"<?xml version="1.0"?>
<project>
    <artifactId>my-project</artifactId>
</project>
"#;
        let (artifact_id, modules) = parse_pom_xml(pom).unwrap();
        assert_eq!(artifact_id, Some("my-project".to_string()));
        assert!(modules.is_empty());
    }

    #[test]
    fn test_parse_multi_module_pom() {
        let pom = r#"<?xml version="1.0"?>
<project>
    <artifactId>parent-project</artifactId>
    <modules>
        <module>module-a</module>
        <module>module-b</module>
        <module>module-c</module>
    </modules>
</project>
"#;
        let (artifact_id, modules) = parse_pom_xml(pom).unwrap();
        assert_eq!(artifact_id, Some("parent-project".to_string()));
        assert_eq!(modules, vec!["module-a", "module-b", "module-c"]);
    }

    #[test]
    fn test_detect_maven_project() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create root pom.xml
        let pom = r#"<?xml version="1.0"?>
<project>
    <artifactId>test-parent</artifactId>
    <modules>
        <module>module-a</module>
        <module>module-b</module>
    </modules>
</project>
"#;
        fs::write(root.join("pom.xml"), pom).unwrap();

        // Create module directories with pom.xml
        fs::create_dir(root.join("module-a")).unwrap();
        fs::write(
            root.join("module-a/pom.xml"),
            r#"<project><artifactId>module-a</artifactId></project>"#,
        )
        .unwrap();

        fs::create_dir(root.join("module-b")).unwrap();
        fs::write(
            root.join("module-b/pom.xml"),
            r#"<project><artifactId>module-b</artifactId></project>"#,
        )
        .unwrap();

        let structure = detect_maven(root).unwrap();
        assert_eq!(structure.build_system, BuildSystem::Maven);
        assert_eq!(structure.root.name, "test-parent");
        assert!(structure.modules.contains_key("module-a"));
        assert!(structure.modules.contains_key("module-b"));
        assert!(structure.is_multi_module());
    }

    #[test]
    fn test_detect_maven_single_module() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let pom = r#"<?xml version="1.0"?>
<project>
    <artifactId>simple-project</artifactId>
</project>
"#;
        fs::write(root.join("pom.xml"), pom).unwrap();

        let structure = detect_maven(root).unwrap();
        assert_eq!(structure.build_system, BuildSystem::Maven);
        assert_eq!(structure.root.name, "simple-project");
        assert_eq!(structure.modules.len(), 1);
        assert!(!structure.is_multi_module());
    }

    // ===== Gradle Detection Tests =====

    #[test]
    fn test_parse_settings_gradle_simple() {
        let settings = r#"
include 'app'
include 'lib'
"#;
        let modules = parse_settings_gradle(settings);
        assert_eq!(modules, vec!["app", "lib"]);
    }

    #[test]
    fn test_parse_settings_gradle_multi_include() {
        let settings = r#"
include 'module-a', 'module-b', 'module-c'
"#;
        let modules = parse_settings_gradle(settings);
        assert_eq!(modules, vec!["module-a", "module-b", "module-c"]);
    }

    #[test]
    fn test_parse_settings_gradle_colon_prefix() {
        let settings = r#"
include ':app'
include ':lib:core'
"#;
        let modules = parse_settings_gradle(settings);
        assert_eq!(modules, vec![":app", ":lib:core"]);
    }

    #[test]
    fn test_parse_gradle_root_name() {
        let settings = r#"
rootProject.name = 'my-gradle-project'
include 'app'
"#;
        let name = parse_gradle_root_name(settings);
        assert_eq!(name, Some("my-gradle-project".to_string()));
    }

    #[test]
    fn test_parse_gradle_root_name_double_quotes() {
        let settings = r#"
rootProject.name = "another-project"
"#;
        let name = parse_gradle_root_name(settings);
        assert_eq!(name, Some("another-project".to_string()));
    }

    #[test]
    fn test_detect_gradle_project() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create settings.gradle
        let settings = r#"
rootProject.name = 'test-gradle'
include 'app', 'lib'
"#;
        fs::write(root.join("settings.gradle"), settings).unwrap();

        // Create module directories
        fs::create_dir(root.join("app")).unwrap();
        fs::write(root.join("app/build.gradle"), "").unwrap();

        fs::create_dir(root.join("lib")).unwrap();
        fs::write(root.join("lib/build.gradle"), "").unwrap();

        let structure = detect_gradle(root).unwrap();
        assert_eq!(structure.build_system, BuildSystem::Gradle);
        assert_eq!(structure.root.name, "test-gradle");
        assert!(structure.modules.contains_key("app"));
        assert!(structure.modules.contains_key("lib"));
        assert!(structure.is_multi_module());
    }

    #[test]
    fn test_detect_gradle_single_module() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Only build.gradle, no settings.gradle
        fs::write(root.join("build.gradle"), "").unwrap();

        let structure = detect_gradle(root).unwrap();
        assert_eq!(structure.build_system, BuildSystem::Gradle);
        assert_eq!(structure.modules.len(), 1);
        assert!(!structure.is_multi_module());
    }

    // ===== Module Structure Tests =====

    #[test]
    fn test_module_for_file() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a multi-module Maven project
        let pom = r#"<?xml version="1.0"?>
<project>
    <artifactId>parent</artifactId>
    <modules>
        <module>api</module>
        <module>core</module>
    </modules>
</project>
"#;
        fs::write(root.join("pom.xml"), pom).unwrap();

        fs::create_dir(root.join("api")).unwrap();
        fs::write(
            root.join("api/pom.xml"),
            "<project><artifactId>api</artifactId></project>",
        )
        .unwrap();

        fs::create_dir(root.join("core")).unwrap();
        fs::write(
            root.join("core/pom.xml"),
            "<project><artifactId>core</artifactId></project>",
        )
        .unwrap();

        let structure = detect_maven(root).unwrap();

        // Test file-to-module mapping
        let api_file = root.join("api/src/main/java/Api.java");
        let core_file = root.join("core/src/main/java/Core.java");
        let root_file = root.join("pom.xml");

        assert_eq!(structure.module_name_for_file(&api_file), Some("api"));
        assert_eq!(structure.module_name_for_file(&core_file), Some("core"));
        // Root file could match parent module
        assert!(structure.module_for_file(&root_file).is_some());
    }

    #[test]
    fn test_module_structure_detect_auto() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create Maven project
        fs::write(
            root.join("pom.xml"),
            "<project><artifactId>auto-detect</artifactId></project>",
        )
        .unwrap();

        let structure = ModuleStructure::detect(root).unwrap();
        assert_eq!(structure.build_system, BuildSystem::Maven);
    }

    #[test]
    fn test_module_structure_detect_no_build() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // No build files
        let structure = ModuleStructure::detect(root);
        assert!(structure.is_none());
    }

    // ===== Nested Module Tests =====

    #[test]
    fn test_gradle_nested_modules() {
        let settings = r#"
include ':parent:child'
"#;
        let modules = parse_settings_gradle(settings);
        assert_eq!(modules, vec![":parent:child"]);
    }

    #[test]
    fn test_module_names() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let pom = r#"<?xml version="1.0"?>
<project>
    <artifactId>parent</artifactId>
    <modules>
        <module>a</module>
        <module>b</module>
    </modules>
</project>
"#;
        fs::write(root.join("pom.xml"), pom).unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::write(
            root.join("a/pom.xml"),
            "<project><artifactId>a</artifactId></project>",
        )
        .unwrap();
        fs::create_dir(root.join("b")).unwrap();
        fs::write(
            root.join("b/pom.xml"),
            "<project><artifactId>b</artifactId></project>",
        )
        .unwrap();

        let structure = detect_maven(root).unwrap();
        let names = structure.module_names();
        assert!(names.contains(&"parent"));
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }
}
