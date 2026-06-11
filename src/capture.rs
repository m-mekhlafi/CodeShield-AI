/// Quantum-IDS — Network packet capture and feature extraction
/// Uses pcap crate (wraps libpcap/WinPcap)
/// Run with sudo/root for raw socket access
use anyhow::{Result, Context};
use pcap::{Capture, Device};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::{Duration, SystemTime}};

/// Network flow features for ML classifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub duration_ms: u64,
    pub packet_count: u32,
    pub byte_count: u64,
    pub avg_packet_size: f64,
    pub packets_per_second: f64,
    pub syn_count: u32,
    pub ack_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub urg_count: u32,
    /// Payload entropy — high entropy = possible encryption/exfil
    pub payload_entropy: f64,
}

/// Alert from IDS engine
#[derive(Debug, Serialize)]
pub struct IdsAlert {
    pub timestamp: String,
    pub severity: String,
    pub alert_type: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub description: String,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub confidence: f64,
}

/// Simple rule-based detection (before ML model integration)
/// In production: feed features into trained Random Forest / XGBoost
pub fn detect_anomaly(flow: &FlowFeatures) -> Option<IdsAlert> {
    // Rule 1: Port scan detection (many ports, few packets each)
    // Maps to: MITRE T1046 — Network Service Discovery
    if flow.packet_count < 3 && flow.syn_count >= 1 {
        return Some(IdsAlert {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: "MEDIUM".into(),
            alert_type: "PortScan".into(),
            src_ip: flow.src_ip.clone(),
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
            description: format!("Possible port scan from {} — low packet count with SYN", flow.src_ip),
            mitre_tactic: "Discovery".into(),
            mitre_technique: "T1046".into(),
            confidence: 0.7,
        });
    }

    // Rule 2: High-rate traffic = DoS/DDoS
    // Maps to: MITRE T1498 — Network Denial of Service
    if flow.packets_per_second > 10_000.0 {
        return Some(IdsAlert {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: "HIGH".into(),
            alert_type: "DoS".into(),
            src_ip: flow.src_ip.clone(),
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
            description: format!("High packet rate from {} ({:.0} pps)", flow.src_ip, flow.packets_per_second),
            mitre_tactic: "Impact".into(),
            mitre_technique: "T1498".into(),
            confidence: 0.85,
        });
    }

    // Rule 3: Data exfiltration — large outbound + high entropy
    // Maps to: MITRE T1048 — Exfiltration Over Alternative Protocol
    if flow.byte_count > 10_000_000 && flow.payload_entropy > 7.5 {
        return Some(IdsAlert {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: "CRITICAL".into(),
            alert_type: "DataExfiltration".into(),
            src_ip: flow.src_ip.clone(),
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
            description: format!(
                "Possible data exfiltration: {:.1}MB transferred, high entropy ({:.2})",
                flow.byte_count as f64 / 1_000_000.0,
                flow.payload_entropy
            ),
            mitre_tactic: "Exfiltration".into(),
            mitre_technique: "T1048".into(),
            confidence: 0.82,
        });
    }

    None
}

/// Shannon entropy of byte slice — detects encryption/compression
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}