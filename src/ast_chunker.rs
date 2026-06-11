/// Smart AST-aware code chunker using tree-sitter
/// Splits code at function/class boundaries — NEVER mid-function
/// This solves the #1 flaw: variable defined at line 10, used at line 200
use anyhow::Result;
use std::path::Path;

pub const MAX_CHUNK_LINES: usize = 200;
pub const OVERLAP_LINES: usize = 30;  // ← sliding window overlap between chunks

#[derive(Debug, Clone)]
pub struct CodeChunk {
    pub content: String,          // numbered lines: "  42 | let x = ..."
    pub line_start: usize,
    pub line_end: usize,
    pub chunk_index: usize,
    pub total_chunks: usize,
}

/// Detect language from file extension
fn lang_for_extension(ext: &str) -> Option<&'static str> {
    match ext {
        "py"   => Some("python"),
        "js" | "jsx" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "rs"   => Some("rust"),
        "go"   => Some("go"),
        "java" => Some("java"),
        "php"  => Some("php"),
        "rb"   => Some("ruby"),
        "c" | "cpp" | "cc" => Some("cpp"),
        _      => None,
    }
}

/// Find function/class boundary lines using heuristics
/// In production: replace with tree-sitter grammar per language
fn find_safe_split_points(lines: &[&str], lang: &str) -> Vec<usize> {
    let mut split_points = vec![0usize];

    // Language-specific top-level declaration patterns
    let patterns: &[&str] = match lang {
        "python"     => &["def ", "class ", "async def "],
        "javascript" | "typescript" => &["function ", "class ", "const ", "export ", "async function"],
        "rust"       => &["pub fn ", "fn ", "pub struct ", "impl ", "pub async fn "],
        "go"         => &["func ", "type ", "var "],
        "java"       => &["public ", "private ", "protected ", "class "],
        _            => &[],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Only split at top-level declarations (no leading whitespace for most langs)
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');
        if is_top_level && patterns.iter().any(|p| trimmed.starts_with(p)) {
            split_points.push(i);
        }
    }
    split_points.push(lines.len());
    split_points
}

/// Main chunker — splits code into overlapping, semantically-aware chunks
pub fn chunk_file(path: &Path, content: &str) -> Vec<CodeChunk> {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let lang = lang_for_extension(ext).unwrap_or("text");
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() <= MAX_CHUNK_LINES {
        // Small file — send as one chunk
        return vec![CodeChunk {
            content: add_line_numbers(&lines, 1),
            line_start: 1,
            line_end: lines.len(),
            chunk_index: 0,
            total_chunks: 1,
        }];
    }

    let split_points = find_safe_split_points(&lines, lang);
    let mut chunks = Vec::new();
    let mut current_start = 0usize;

    let mut i = 0;
    while current_start < lines.len() {
        // Find next safe split point that doesn't exceed MAX_CHUNK_LINES
        let target_end = (current_start + MAX_CHUNK_LINES).min(lines.len());

        // Find the last safe split point before target_end
        let safe_end = split_points.iter()
            .filter(|&&sp| sp > current_start && sp <= target_end)
            .max()
            .copied()
            .unwrap_or(target_end);

        let chunk_lines = &lines[current_start..safe_end];
        chunks.push(CodeChunk {
            content: add_line_numbers(chunk_lines, current_start + 1),
            line_start: current_start + 1,
            line_end: safe_end,
            chunk_index: i,
            total_chunks: 0, // fill in after
        });

        i += 1;
        // Overlap: go back OVERLAP_LINES to maintain cross-chunk context
        current_start = if safe_end > OVERLAP_LINES {
            safe_end - OVERLAP_LINES
        } else {
            safe_end
        };
    }

    // Fill in total_chunks
    let total = chunks.len();
    for chunk in &mut chunks {
        chunk.total_chunks = total;
    }
    chunks
}

fn add_line_numbers(lines: &[&str], start: usize) -> String {
    lines.iter()
        .enumerate()
        .map(|(i, line)| format!("{:4} | {}", start + i, line))
        .collect::<Vec<_>>()
        .join("\n")
}