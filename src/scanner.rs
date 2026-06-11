use crate::{
    ast_chunker::chunk_file,
    cache::{ScanCache, file_hash},
    llm_client::OllamaClient,
    models::{LlmConfig, ScanResult, Vulnerability},
};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::{path::{Path, PathBuf}, sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use walkdir::WalkDir;

const SCANNABLE_EXTENSIONS: &[&str] = &[
    "py", "js", "ts", "jsx", "tsx", "php",
    "java", "go", "rb", "cs", "cpp", "c", "rs", "sh",
];

const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", "__pycache__", ".venv",
    "venv", "dist", "build", ".pytest_cache", "target",
];

const MAX_FILE_SIZE_BYTES: u64 = 150_000; // 150KB
const MAX_CONCURRENT_SCANS: usize = 4;   // parallel file scans

pub struct Scanner {
    client: Arc<OllamaClient>,
    cache: Arc<ScanCache>,
    semaphore: Arc<Semaphore>,
}

impl Scanner {
    pub async fn new(config: LlmConfig, db_path: &str) -> Result<Self> {
        let cache = ScanCache::new(db_path).await?;
        Ok(Self {
            client: Arc::new(OllamaClient::new(config)),
            cache: Arc::new(cache),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
        })
    }

    /// Walk project directory and collect scannable files
    fn collect_files(&self, project_path: &Path) -> Vec<PathBuf> {
        WalkDir::new(project_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                // Skip ignored directories
                !e.path().components().any(|c| {
                    SKIP_DIRS.contains(&c.as_os_str().to_str().unwrap_or(""))
                })
            })
            .filter(|e| {
                // Check extension
                e.path().extension()
                    .and_then(|x| x.to_str())
                    .map(|x| SCANNABLE_EXTENSIONS.contains(&x))
                    .unwrap_or(false)
            })
            .filter(|e| {
                // Skip large files
                e.metadata().map(|m| m.len() < MAX_FILE_SIZE_BYTES).unwrap_or(false)
            })
            .map(|e| e.into_path())
            .collect()
    }

    /// Scan a single file — uses cache, then LLM
    async fn scan_file(
        client: Arc<OllamaClient>,
        cache: Arc<ScanCache>,
        semaphore: Arc<Semaphore>,
        file_path: PathBuf,
    ) -> Result<Vec<Vulnerability>> {
        let _permit = semaphore.acquire().await?; // rate limiting

        let content = tokio::fs::read(&file_path).await?;
        let hash = file_hash(&content);

        // Cache hit?
        if let Some(cached) = cache.get(&hash).await? {
            return Ok(cached);
        }

        let text = String::from_utf8_lossy(&content).to_string();
        let chunks = chunk_file(&file_path, &text);
        let file_str = file_path.to_string_lossy().to_string();

        let mut all_vulns = Vec::new();

        for chunk in &chunks {
            let vulns = client
                .scan_chunk(&chunk.content, &file_str, chunk.chunk_index, chunk.total_chunks)
                .await
                .unwrap_or_default();
            all_vulns.extend(vulns);
        }

        // Deduplicate: remove duplicate vulns (same line + type)
        all_vulns.dedup_by(|a, b| {
            a.line_start == b.line_start && a.vuln_type == b.vuln_type
        });

        cache.store(&hash, &all_vulns).await?;
        Ok(all_vulns)
    }

    /// Full project scan — parallel execution
    pub async fn scan_project(&self, project_path: &str) -> Result<ScanResult> {
        if !self.client.is_available().await {
            anyhow::bail!(
                "Ollama is not running.\nStart it with: ollama serve\nThen pull a model: ollama pull qwen2.5-coder:7b"
            );
        }

        let path = Path::new(project_path);
        let files = self.collect_files(path);
        let total = files.len();

        info!("🛡️  CodeShield Rust Engine");
        info!("📂  Found {} files", total);

        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("=>-")
        );

        let start = Instant::now();

        // Spawn concurrent tasks
        let mut handles = Vec::new();
        for file_path in files {
            let client = self.client.clone();
            let cache = self.cache.clone();
            let sem = self.semaphore.clone();
            let pb_clone = pb.clone();
            let path_str = file_path.to_string_lossy().to_string();

            handles.push(tokio::spawn(async move {
                let result = Self::scan_file(client, cache, sem, file_path).await;
                pb_clone.set_message(path_str);
                pb_clone.inc(1);
                result
            }));
        }

        let mut all_vulns = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(vulns)) => all_vulns.extend(vulns),
                Ok(Err(e))   => warn!("File scan error: {}", e),
                Err(e)       => warn!("Task panic: {}", e),
            }
        }

        pb.finish_with_message("✅ Scan complete");

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ScanResult::from_vulns(project_path.to_string(), total, all_vulns, duration_ms))
    }
}