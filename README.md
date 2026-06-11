# 🛡️ CodeShield — Local AI Security Scanner

**CodeShield** is a blazing-fast, 100% local, AI-powered Static Application Security Testing (SAST) tool built in Rust. It utilizes local Large Language Models (LLMs) via Ollama to scan your source code for vulnerabilities without ever sending your sensitive data to the cloud.

Built with performance and privacy in mind, CodeShield smartly chunks your code, processes files concurrently, and caches results to deliver near-instant rescans.

👤 **Author:** Mohammed Emad AL-Mekhlafi

---

## ✨ Key Features

* 🔒 **100% Privacy:** All code scanning happens locally on your machine via Ollama. No data leaves your computer.
* ⚡ **Blazing Fast (Rust):** Uses `tokio` for parallel async processing and a local SQLite cache database to skip unchanged files.
* 🧠 **Smart Code Chunker:** Doesn't just slice text randomly. It respects function and class boundaries across 10+ programming languages to give the LLM full context.
* 🛡️ **Bulletproof Parsing:** Designed with resilient JSON deserializers that never crash, even if the LLM hallucinates formatting.
* 📊 **Beautiful CLI Reports:** Categorizes findings by severity (CRITICAL, HIGH, MEDIUM, LOW) with specific line numbers and CWE-mapped remediation advice.
* ⚙️ **CI/CD Ready:** Can be configured to break the build (`exit code 1`) if a specific severity threshold is met.

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed:
1. [Rust & Cargo](https://rustup.rs/) (v1.70+)
2. [Ollama](https://ollama.ai/) (Running locally)

Make sure to pull at least one coding model in Ollama:
```bash
# Recommended models:
ollama pull qwen2.5-coder:7b
ollama pull hermes3
🚀 Installation & Build
Clone the repository and build the release version:

Bash
git clone [https://github.com/YOUR_USERNAME/CodeShield-AI.git](https://github.com/YOUR_USERNAME/CodeShield-AI.git)
cd CodeShield-AI
cargo build --release
💻 Usage
Run the scanner against any project directory.

Basic Scan
Bash
./target/release/codeshield scan --path /path/to/your/project
Advanced Scan (Custom Model & CI/CD Threshold)
Specify an exact model and set the tool to fail the pipeline if a HIGH severity bug is found:

Bash
./target/release/codeshield scan --path . --model hermes3 --fail-on HIGH
Output as JSON
Useful for piping results into other security dashboards:

Bash
./target/release/codeshield scan --path . --json
📂 Supported Languages
The Smart Chunker currently supports automatic language detection and boundary splitting for:
Python (.py), JavaScript/TypeScript (.js, .jsx, .ts, .tsx), Rust (.rs), Go (.go), Java (.java), PHP (.php), Ruby (.rb), and C/C++ (.c, .cpp).

🧠 How it works under the hood
Discovery: Scans the directory, filtering out non-code assets and heavy folders (node_modules, target, etc.).

Caching: Hashes each file (SHA256). If it hasn't changed since the last scan, it fetches the result from SQLite instantly.

Chunking: Large files are split into overlapping chunks at safe programmatic boundaries.

Analysis: Prompts the local LLM with strict JSON schemas.

Sanitization: Cleans malformed LLM outputs and prints actionable security reports.

📜 License
This project is licensed under the Apache 2.0 License.
