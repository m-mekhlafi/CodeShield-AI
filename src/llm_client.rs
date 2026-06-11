use crate::models::{LlmConfig, LlmResponse, Vulnerability};
use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde_json::{json, Value};
use tracing::{debug, warn};

pub struct OllamaClient {
    client: Client,
    config: LlmConfig,
}

impl OllamaClient {
    pub fn new(config: LlmConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()
            .expect("Failed to build HTTP client");
        Self { client, config }
    }

    pub async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/api/tags", self.config.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Scan code chunk with retry on JSON parse failure
    pub async fn scan_chunk(
        &self,
        code: &str,
        file_path: &str,
        chunk_idx: usize,
        total_chunks: usize,
    ) -> Result<Vec<Vulnerability>> {
        let system_prompt = SYSTEM_PROMPT;
        let user_prompt = format!(
            "File: {}\nChunk: {}/{}\n\nCode:\n```\n{}\n```",
            file_path, chunk_idx + 1, total_chunks, code
        );

        let mut last_error = String::new();

        for attempt in 0..self.config.max_retries {
            if attempt > 0 {
                warn!("Retry {}/{} for {}", attempt, self.config.max_retries - 1, file_path);
            }

            let payload = json!({
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt}
                ],
                "stream": false,
                "format": "json",
                "options": {
                    "temperature": self.config.temperature,
                    "top_p":       self.config.top_p,
                    "num_ctx":     self.config.num_ctx,
                    "seed": 42
                }
            });

            let resp = self.client
                .post(format!("{}/api/chat", self.config.base_url))
                .json(&payload)
                .send()
                .await
                .context("Failed to reach Ollama")?;

            let resp_json: Value = resp.json().await
                .context("Failed to parse Ollama HTTP response")?;

            let content = resp_json["message"]["content"]
                .as_str()
                .unwrap_or("{}")
                .trim()
                .to_string();

            debug!("LLM raw output (attempt {}): {}", attempt, &content[..content.len().min(200)]);

            match self.parse_llm_response(&content) {
                Ok(vulns) => return Ok(vulns),
                Err(e) => {
                    last_error = e.to_string();
                    warn!("JSON parse failed (attempt {}): {}", attempt, last_error);
                }
            }
        }

        warn!("All {} retries failed for chunk in {}. Error: {}", self.config.max_retries, file_path, last_error);
        Ok(vec![])
    }

    /// Multi-strategy JSON parser — handles malformed LLM output
    fn parse_llm_response(&self, raw: &str) -> Result<Vec<Vulnerability>> {
        if let Ok(parsed) = serde_json::from_str::<LlmResponse>(raw) {
            return Ok(parsed.vulnerabilities);
        }

        let stripped = raw
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        if let Ok(parsed) = serde_json::from_str::<LlmResponse>(stripped) {
            return Ok(parsed.vulnerabilities);
        }

        if let Some(start) = raw.find('{') {
            if let Some(end) = raw.rfind('}') {
                let candidate = &raw[start..=end];
                if let Ok(parsed) = serde_json::from_str::<LlmResponse>(candidate) {
                    return Ok(parsed.vulnerabilities);
                }
            }
        }

        // تم تنظيف رسالة الخطأ هنا لتكون مختصرة ولا تملأ التيرمنال
        Err(anyhow!("Model output is missing required JSON fields or malformed."))
    }
}

const SYSTEM_PROMPT: &str = r#"You are a senior application security engineer.
Analyze the provided code chunk for security vulnerabilities.
You MUST respond with ONLY valid JSON. No markdown, no explanation.

JSON schema:
{
  "vulnerabilities": [
    {
      "line_start": <integer>,
      "line_end": <integer>,
      "vuln_type": "<string>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "description": "<string>",
      "code_snippet": "<string>",
      "recommendation": "<string>",
      "cwe_id": "<string>",
      "confidence": <float>
    }
  ]
}

Rules:
- Only report real vulnerabilities with confidence > 0.6
- If no vulnerabilities found, return {"vulnerabilities": []}"#;