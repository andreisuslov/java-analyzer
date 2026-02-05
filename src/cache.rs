//! Incremental Analysis Cache
//!
//! Caches analysis results to avoid re-analyzing unchanged files.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::rules::Issue;

/// Cache entry for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Hash of file content
    pub content_hash: u64,
    /// Last modified time (as seconds since epoch)
    pub modified_time: u64,
    /// File size in bytes
    pub file_size: u64,
    /// Cached issues for this file
    pub issues: Vec<Issue>,
    /// Timestamp when this entry was created
    pub cached_at: u64,
}

impl CacheEntry {
    /// Check if the cache entry is still valid for the given file
    pub fn is_valid(&self, path: &Path) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            let modified = metadata.modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let size = metadata.len();

            // Check if file hasn't changed
            self.modified_time == modified && self.file_size == size
        } else {
            false
        }
    }
}

/// Analysis cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCache {
    /// Version of the cache format
    pub version: String,
    /// Analyzer version that created this cache
    pub analyzer_version: String,
    /// Cached entries by file path
    pub entries: HashMap<String, CacheEntry>,
    /// Configuration hash (invalidates cache if config changes)
    pub config_hash: u64,
}

impl AnalysisCache {
    /// Create a new empty cache
    pub fn new(analyzer_version: &str, config_hash: u64) -> Self {
        Self {
            version: "1.0".to_string(),
            analyzer_version: analyzer_version.to_string(),
            entries: HashMap::new(),
            config_hash,
        }
    }

    /// Load cache from file
    pub fn load(path: &Path) -> Result<Self, CacheError> {
        let content = fs::read_to_string(path)
            .map_err(|e| CacheError::IoError(e.to_string()))?;

        serde_json::from_str(&content)
            .map_err(|e| CacheError::ParseError(e.to_string()))
    }

    /// Save cache to file
    pub fn save(&self, path: &Path) -> Result<(), CacheError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| CacheError::IoError(e.to_string()))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CacheError::ParseError(e.to_string()))?;

        fs::write(path, json)
            .map_err(|e| CacheError::IoError(e.to_string()))
    }

    /// Get cached issues for a file if valid
    pub fn get(&self, path: &Path) -> Option<&CacheEntry> {
        let path_str = path.to_string_lossy().to_string();
        self.entries.get(&path_str).filter(|entry| entry.is_valid(path))
    }

    /// Update cache entry for a file
    pub fn update(&mut self, path: &Path, issues: Vec<Issue>) {
        let path_str = path.to_string_lossy().to_string();

        let (modified_time, file_size, content_hash) = if let Ok(metadata) = fs::metadata(path) {
            let modified = metadata.modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let size = metadata.len();

            // Simple content hash based on path, size, and modified time
            let hash = hash_file_metadata(&path_str, size, modified);

            (modified, size, hash)
        } else {
            (0, 0, 0)
        };

        let cached_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.entries.insert(path_str, CacheEntry {
            content_hash,
            modified_time,
            file_size,
            issues,
            cached_at,
        });
    }

    /// Remove entry for a file
    pub fn invalidate(&mut self, path: &Path) {
        let path_str = path.to_string_lossy().to_string();
        self.entries.remove(&path_str);
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total_entries = self.entries.len();
        let total_issues: usize = self.entries.values().map(|e| e.issues.len()).sum();

        CacheStats {
            total_entries,
            total_issues,
        }
    }

    /// Check if cache is compatible with current version
    pub fn is_compatible(&self, analyzer_version: &str, config_hash: u64) -> bool {
        self.analyzer_version == analyzer_version && self.config_hash == config_hash
    }

    /// Prune entries for files that no longer exist
    pub fn prune(&mut self) {
        let to_remove: Vec<String> = self.entries
            .keys()
            .filter(|path| !Path::new(path).exists())
            .cloned()
            .collect();

        for path in to_remove {
            self.entries.remove(&path);
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_issues: usize,
}

/// Cache errors
#[derive(Debug, Clone)]
pub enum CacheError {
    IoError(String),
    ParseError(String),
    VersionMismatch,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::IoError(e) => write!(f, "Cache I/O error: {}", e),
            CacheError::ParseError(e) => write!(f, "Cache parse error: {}", e),
            CacheError::VersionMismatch => write!(f, "Cache version mismatch"),
        }
    }
}

/// Simple hash function for file metadata
fn hash_file_metadata(path: &str, size: u64, modified: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    size.hash(&mut hasher);
    modified.hash(&mut hasher);
    hasher.finish()
}

/// Hash configuration for cache invalidation
pub fn hash_config(config: &crate::AnalyzerConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();

    // Hash key configuration fields
    format!("{:?}", config.min_severity).hash(&mut hasher);
    config.max_complexity.hash(&mut hasher);
    config.disabled_rules.hash(&mut hasher);
    if let Some(ref enabled) = config.enabled_rules {
        enabled.hash(&mut hasher);
    }

    hasher.finish()
}

/// Default cache file path
pub fn default_cache_path() -> PathBuf {
    // Try to use standard cache directories
    let base = if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join("Library/Caches"))
            .unwrap_or_else(|_| PathBuf::from("."))
    } else if cfg!(target_os = "linux") {
        std::env::var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    };

    base.join("java-analyzer").join("cache.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleCategory, Severity};
    use tempfile::TempDir;

    fn create_test_issue(rule_id: &str) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            title: "Test".to_string(),
            severity: Severity::Major,
            category: RuleCategory::Bug,
            file: "test.java".to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "Test".to_string(),
            code_snippet: None,
            owasp: None,
            cwe: None,
            debt_minutes: 5,
        }
    }

    // ===== Cache Creation Tests =====

    #[test]
    fn test_new_cache() {
        let cache = AnalysisCache::new("1.0.0", 12345);

        assert_eq!(cache.version, "1.0");
        assert_eq!(cache.analyzer_version, "1.0.0");
        assert_eq!(cache.config_hash, 12345);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn test_cache_compatibility() {
        let cache = AnalysisCache::new("1.0.0", 12345);

        assert!(cache.is_compatible("1.0.0", 12345));
        assert!(!cache.is_compatible("2.0.0", 12345));
        assert!(!cache.is_compatible("1.0.0", 99999));
    }

    // ===== Cache Entry Tests =====

    #[test]
    fn test_cache_update_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();

        let mut cache = AnalysisCache::new("1.0.0", 12345);
        let issues = vec![create_test_issue("S100")];

        cache.update(&file_path, issues.clone());

        let entry = cache.get(&file_path);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().issues.len(), 1);
    }

    #[test]
    fn test_cache_invalidate() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();

        let mut cache = AnalysisCache::new("1.0.0", 12345);
        cache.update(&file_path, vec![create_test_issue("S100")]);

        cache.invalidate(&file_path);

        assert!(cache.get(&file_path).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();

        let mut cache = AnalysisCache::new("1.0.0", 12345);
        cache.update(&file_path, vec![create_test_issue("S100")]);

        cache.clear();

        assert!(cache.entries.is_empty());
    }

    // ===== Cache Persistence Tests =====

    #[test]
    fn test_cache_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("cache.json");

        let mut cache = AnalysisCache::new("1.0.0", 12345);
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();
        cache.update(&file_path, vec![create_test_issue("S100")]);

        cache.save(&cache_path).unwrap();

        let loaded = AnalysisCache::load(&cache_path).unwrap();
        assert_eq!(loaded.analyzer_version, "1.0.0");
        assert_eq!(loaded.entries.len(), 1);
    }

    #[test]
    fn test_cache_load_nonexistent() {
        let result = AnalysisCache::load(Path::new("/nonexistent/cache.json"));
        assert!(result.is_err());
    }

    // ===== Cache Stats Tests =====

    #[test]
    fn test_cache_stats() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = AnalysisCache::new("1.0.0", 12345);

        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("test{}.java", i));
            fs::write(&file_path, format!("public class Test{} {{}}", i)).unwrap();
            cache.update(&file_path, vec![
                create_test_issue("S100"),
                create_test_issue("S101"),
            ]);
        }

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_issues, 6);
    }

    // ===== Cache Pruning Tests =====

    #[test]
    fn test_cache_prune() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = AnalysisCache::new("1.0.0", 12345);

        // Create and cache a file
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();
        cache.update(&file_path, vec![create_test_issue("S100")]);

        // Add a fake entry for a non-existent file
        cache.entries.insert("/nonexistent/file.java".to_string(), CacheEntry {
            content_hash: 0,
            modified_time: 0,
            file_size: 0,
            issues: vec![],
            cached_at: 0,
        });

        assert_eq!(cache.entries.len(), 2);

        cache.prune();

        assert_eq!(cache.entries.len(), 1);
    }

    // ===== Cache Entry Validity Tests =====

    #[test]
    fn test_cache_entry_valid() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();

        let mut cache = AnalysisCache::new("1.0.0", 12345);
        cache.update(&file_path, vec![create_test_issue("S100")]);

        // Entry should be valid for unchanged file
        let entry = cache.entries.get(&file_path.to_string_lossy().to_string()).unwrap();
        assert!(entry.is_valid(&file_path));
    }

    #[test]
    fn test_cache_entry_invalid_after_modification() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.java");
        fs::write(&file_path, "public class Test {}").unwrap();

        let mut cache = AnalysisCache::new("1.0.0", 12345);
        cache.update(&file_path, vec![create_test_issue("S100")]);

        // Modify the file
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&file_path, "public class Test { void foo() {} }").unwrap();

        // Entry should be invalid now
        let entry = cache.entries.get(&file_path.to_string_lossy().to_string()).unwrap();
        assert!(!entry.is_valid(&file_path));
    }

    // ===== Hash Config Tests =====

    #[test]
    fn test_hash_config_consistency() {
        let config = crate::AnalyzerConfig::default();
        let hash1 = hash_config(&config);
        let hash2 = hash_config(&config);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_config_changes() {
        let config1 = crate::AnalyzerConfig::default();
        let mut config2 = crate::AnalyzerConfig::default();
        config2.max_complexity = 99;

        let hash1 = hash_config(&config1);
        let hash2 = hash_config(&config2);
        assert_ne!(hash1, hash2);
    }
}
