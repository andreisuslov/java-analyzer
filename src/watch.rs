//! Watch Mode for Continuous Analysis
//!
//! Monitors files for changes and re-analyzes them automatically.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::rules::Issue;

/// Events emitted by the file watcher
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// Analysis completed for a file
    Analyzed {
        path: PathBuf,
        issues: Vec<Issue>,
        duration_ms: u64,
    },
    /// An error occurred
    Error(String),
    /// Initial analysis started
    InitialAnalysisStarted { file_count: usize },
    /// Initial analysis completed
    InitialAnalysisCompleted {
        file_count: usize,
        issue_count: usize,
        duration_ms: u64,
    },
    /// A file was modified (before re-analysis)
    FileModified { path: PathBuf },
}

/// Configuration for the file watcher
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Debounce delay in milliseconds
    pub debounce_ms: u64,
    /// Whether to run initial analysis on startup
    pub initial_analysis: bool,
    /// File extensions to watch (default: ["java"])
    pub extensions: Vec<String>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 300,
            initial_analysis: true,
            extensions: vec!["java".to_string()],
        }
    }
}

/// State for debouncing file change events
#[derive(Debug)]
pub struct DebounceState {
    /// Pending file changes with their timestamps
    pending: HashMap<PathBuf, Instant>,
    /// Debounce delay
    delay: Duration,
}

impl DebounceState {
    /// Create a new debounce state
    pub fn new(delay_ms: u64) -> Self {
        Self {
            pending: HashMap::new(),
            delay: Duration::from_millis(delay_ms),
        }
    }

    /// Record a file change
    pub fn record_change(&mut self, path: PathBuf) {
        self.pending.insert(path, Instant::now());
    }

    /// Get files that are ready to be processed (past debounce delay)
    pub fn get_ready_files(&mut self) -> Vec<PathBuf> {
        let now = Instant::now();
        let ready: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, &time)| now.duration_since(time) >= self.delay)
            .map(|(path, _)| path.clone())
            .collect();

        for path in &ready {
            self.pending.remove(path);
        }

        ready
    }

    /// Check if any files are pending
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Clear all pending changes
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

/// File watcher for continuous analysis
pub struct FileWatcher {
    /// The underlying notify watcher
    _watcher: RecommendedWatcher,
    /// Receiver for file system events
    fs_rx: Receiver<Result<Event, notify::Error>>,
    /// Sender for watch events
    event_tx: Sender<WatchEvent>,
    /// Receiver for watch events (public interface)
    event_rx: Receiver<WatchEvent>,
    /// Debounce state
    debounce: DebounceState,
    /// Watch configuration
    config: WatchConfig,
    /// Root path being watched
    root_path: PathBuf,
}

impl FileWatcher {
    /// Create a new file watcher
    pub fn new(path: &Path, config: WatchConfig) -> Result<Self, String> {
        let (fs_tx, fs_rx) = channel();
        let (event_tx, event_rx) = channel();

        // Create the watcher
        let watcher_config = Config::default()
            .with_poll_interval(Duration::from_millis(config.debounce_ms));

        let watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                let _ = fs_tx.send(res);
            },
            watcher_config,
        )
        .map_err(|e| format!("Failed to create watcher: {}", e))?;

        let mut file_watcher = Self {
            _watcher: watcher,
            fs_rx,
            event_tx,
            event_rx,
            debounce: DebounceState::new(config.debounce_ms),
            config,
            root_path: path.to_path_buf(),
        };

        // Start watching
        file_watcher
            ._watcher
            .watch(path, RecursiveMode::Recursive)
            .map_err(|e| format!("Failed to watch path: {}", e))?;

        Ok(file_watcher)
    }

    /// Get the receiver for watch events
    pub fn events(&self) -> &Receiver<WatchEvent> {
        &self.event_rx
    }

    /// Get the event sender (for sending analysis results)
    pub fn event_sender(&self) -> Sender<WatchEvent> {
        self.event_tx.clone()
    }

    /// Check if a path should be watched based on extension
    fn should_watch(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|ext| self.config.extensions.iter().any(|e| e == ext))
            .unwrap_or(false)
    }

    /// Process pending file system events and return ready files
    pub fn poll(&mut self) -> Vec<PathBuf> {
        // Process all available file system events
        while let Ok(result) = self.fs_rx.try_recv() {
            match result {
                Ok(event) => {
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        for path in event.paths {
                            if self.should_watch(&path) && path.exists() {
                                self.debounce.record_change(path.clone());
                                let _ = self.event_tx.send(WatchEvent::FileModified { path });
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = self
                        .event_tx
                        .send(WatchEvent::Error(format!("Watch error: {}", e)));
                }
            }
        }

        // Return files that have passed debounce delay
        self.debounce.get_ready_files()
    }

    /// Get the root path being watched
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Get the watch configuration
    pub fn config(&self) -> &WatchConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ===== DebounceState Tests =====

    #[test]
    fn test_debounce_new() {
        let debounce = DebounceState::new(100);
        assert!(debounce.pending.is_empty());
        assert_eq!(debounce.delay, Duration::from_millis(100));
    }

    #[test]
    fn test_debounce_record_change() {
        let mut debounce = DebounceState::new(100);
        debounce.record_change(PathBuf::from("test.java"));

        assert!(debounce.has_pending());
        assert!(debounce.pending.contains_key(&PathBuf::from("test.java")));
    }

    #[test]
    fn test_debounce_not_ready_immediately() {
        let mut debounce = DebounceState::new(100);
        debounce.record_change(PathBuf::from("test.java"));

        // Should not be ready immediately
        let ready = debounce.get_ready_files();
        assert!(ready.is_empty(), "Files should not be ready before debounce delay");
    }

    #[test]
    fn test_debounce_ready_after_delay() {
        let mut debounce = DebounceState::new(50);
        debounce.record_change(PathBuf::from("test.java"));

        // Wait for debounce delay
        thread::sleep(Duration::from_millis(100));

        let ready = debounce.get_ready_files();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], PathBuf::from("test.java"));

        // Should be removed from pending
        assert!(!debounce.has_pending());
    }

    #[test]
    fn test_debounce_multiple_files() {
        let mut debounce = DebounceState::new(50);
        debounce.record_change(PathBuf::from("file1.java"));
        debounce.record_change(PathBuf::from("file2.java"));

        thread::sleep(Duration::from_millis(100));

        let ready = debounce.get_ready_files();
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_debounce_deduplicates_rapid_changes() {
        let mut debounce = DebounceState::new(100);

        // Multiple rapid changes to the same file
        debounce.record_change(PathBuf::from("test.java"));
        thread::sleep(Duration::from_millis(10));
        debounce.record_change(PathBuf::from("test.java")); // Resets timestamp
        thread::sleep(Duration::from_millis(10));
        debounce.record_change(PathBuf::from("test.java")); // Resets timestamp again

        // Check immediately - should not be ready
        let ready = debounce.get_ready_files();
        assert!(ready.is_empty(), "Rapid changes should reset debounce timer");
    }

    #[test]
    fn test_debounce_clear() {
        let mut debounce = DebounceState::new(100);
        debounce.record_change(PathBuf::from("test.java"));

        debounce.clear();
        assert!(!debounce.has_pending());
    }

    // ===== WatchConfig Tests =====

    #[test]
    fn test_watch_config_default() {
        let config = WatchConfig::default();
        assert_eq!(config.debounce_ms, 300);
        assert!(config.initial_analysis);
        assert!(config.extensions.contains(&"java".to_string()));
    }

    // ===== WatchEvent Tests =====

    #[test]
    fn test_watch_event_variants() {
        let analyzed = WatchEvent::Analyzed {
            path: PathBuf::from("test.java"),
            issues: vec![],
            duration_ms: 100,
        };
        assert!(matches!(analyzed, WatchEvent::Analyzed { .. }));

        let error = WatchEvent::Error("test error".to_string());
        assert!(matches!(error, WatchEvent::Error(_)));

        let modified = WatchEvent::FileModified {
            path: PathBuf::from("test.java"),
        };
        assert!(matches!(modified, WatchEvent::FileModified { .. }));
    }

    // ===== Extension Filtering Tests =====

    #[test]
    fn test_should_watch_java_files() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("test.java"), "").unwrap();

        let config = WatchConfig::default();
        let watcher = FileWatcher::new(temp_dir.path(), config).unwrap();

        assert!(watcher.should_watch(&PathBuf::from("test.java")));
        assert!(watcher.should_watch(&PathBuf::from("/path/to/file.java")));
    }

    #[test]
    fn test_should_not_watch_non_java_files() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();

        let config = WatchConfig::default();
        let watcher = FileWatcher::new(temp_dir.path(), config).unwrap();

        assert!(!watcher.should_watch(&PathBuf::from("test.txt")));
        assert!(!watcher.should_watch(&PathBuf::from("test.py")));
        assert!(!watcher.should_watch(&PathBuf::from("test"))); // No extension
    }
}
