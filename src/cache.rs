use crate::models::Vulnerability;
use anyhow::Result;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::path::Path;

pub struct ScanCache {
    pool: SqlitePool,
}

impl ScanCache {
    /// Initialize with async pool — solves SQLite concurrency
    pub async fn new(db_path: &str) -> Result<Self> {
        // Create parent directories
        if let Some(parent) = Path::new(db_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect(&format!("sqlite://{}?mode=rwc", db_path))
            .await?;

        // 1. قمنا بحذف أو تعليق السطر القديم المسبب للخطأ:
        // sqlx::migrate!().run(&pool).await?;

        // 2. واستبدلناه بهذا الكود لإنشاء الجدول برمجياً بدون الحاجة لمجلدات خارجية:
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS scan_cache (
                file_hash TEXT PRIMARY KEY,
                vulnerabilities TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            );"
        )
            .execute(&pool)
            .await?;

        Ok(Self { pool })
    }

    /// Check cache by SHA256 hash of file content
    pub async fn get(&self, file_hash: &str) -> Result<Option<Vec<Vulnerability>>> {
        // استخدام query البسيط بدلاً من query! الصارم لحل مشكلة وقت الترجمة
        let row: Option<(String,)> = sqlx::query_as("SELECT vulnerabilities FROM scan_cache WHERE file_hash = ?")
            .bind(file_hash)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let vulns: Vec<Vulnerability> = serde_json::from_str(&r.0)?;
                Ok(Some(vulns))
            }
            None => Ok(None),
        }
    }

    /// Store scan result — UPSERT for idempotency
    pub async fn store(&self, file_hash: &str, vulns: &[Vulnerability]) -> Result<()> {
        let json = serde_json::to_string(vulns)?;

        // استخدام query البسيط هنا أيضاً لتخطي فحص DATABASE_URL المزعج
        sqlx::query("INSERT OR REPLACE INTO scan_cache (file_hash, vulnerabilities, scanned_at) VALUES (?, ?, datetime('now'))")
            .bind(file_hash)
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// تأكد أن هذه الدالة مكتوبة في نهاية الملف تماماً وخارج أي impl ScanCache { ... }
    /// Compute SHA256 of file bytes
    pub fn file_hash(content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }