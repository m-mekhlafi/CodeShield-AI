use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use serde_json::Value;

/// Severity levels — ordered for comparison
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// Custom default for Severity
impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

// 🛡️ Bulletproof Deserializer for Severity
// This prevents Rust from crashing if the LLM hallucinates the case, adds spaces, or returns null/numbers.
impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Parse into a flexible JSON Value first to catch ANY weird type
        if let Ok(value) = Value::deserialize(deserializer) {
            if let Some(s) = value.as_str() {
                let upper = s.to_uppercase();
                if upper.contains("CRITICAL") { return Ok(Severity::Critical); }
                if upper.contains("HIGH") { return Ok(Severity::High); }
                if upper.contains("MEDIUM") { return Ok(Severity::Medium); }
                if upper.contains("LOW") { return Ok(Severity::Low); }
            }
        }
        Ok(Severity::Info) // Fallback for invalid formats
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "🔴 CRITICAL"),
            Severity::High     => write!(f, "🟠 HIGH"),
            Severity::Medium   => write!(f, "🟡 MEDIUM"),
            Severity::Low      => write!(f, "🟢 LOW"),
            Severity::Info     => write!(f, "🔵 INFO"),
        }
    }
}

/// A single detected vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)] // 🛡️ Instructs Serde to use our safe Default implementation for any missing fields!
pub struct Vulnerability {
    pub id: Uuid,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub vuln_type: String, // Changed to String to prevent enum crashes!
    pub severity: Severity,
    pub description: String,
    pub code_snippet: String,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub confidence: f32,
}

// 🛡️ Bulletproof defaults. If LLM forgets a field, it gets these instead of crashing.
impl Default for Vulnerability {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(), // Always generates a fresh UUID safely
            file_path: String::new(),
            line_start: 0,
            line_end: 0,
            vuln_type: "Unknown".to_string(),
            severity: Severity::default(),
            description: String::new(),
            code_snippet: String::new(),
            recommendation: String::new(),
            cwe_id: None,
            confidence: 0.0,
        }
    }
}

/// LLM raw response wrapper — handles partial/malformed JSON
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct LlmResponse {
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Full scan result
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub project_path: String,
    pub files_scanned: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub duration_ms: u64,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl ScanResult {
    pub fn from_vulns(project_path: String, files: usize, vulns: Vec<Vulnerability>, duration_ms: u64) -> Self {
        let critical_count = vulns.iter().filter(|v| v.severity == Severity::Critical).count();
        let high_count     = vulns.iter().filter(|v| v.severity == Severity::High).count();
        let medium_count   = vulns.iter().filter(|v| v.severity == Severity::Medium).count();
        let low_count      = vulns.iter().filter(|v| v.severity == Severity::Low).count();

        Self {
            scan_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            project_path,
            files_scanned: files,
            vulnerabilities: vulns,
            duration_ms,
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }
}

/// Ollama model configuration
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    pub temperature: f32,
    pub top_p: f32,
    pub num_ctx: u32,
    pub max_retries: u8,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434".into(),
            model: "qwen2.5-coder:7b".into(),
            temperature: 0.2,
            top_p: 0.7,
            num_ctx: 8192,
            max_retries: 3,
        }
    }
}