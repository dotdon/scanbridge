//! Custom backend example demonstrating how to implement a new scanner.
//!
//! This example shows how to:
//! - Implement the Scanner trait for a custom backend
//! - Handle different scan outcomes
//! - Integrate with the ScanManager
//!
//! Run with: cargo run --example custom_backend

use async_trait::async_trait;
use scanbridge::prelude::*;

/// A simple hash-based scanner that checks file hashes against a blocklist.
/// 
/// This demonstrates how to implement a custom scanning backend.
#[derive(Debug)]
struct HashBlocklistScanner {
    name: String,
    blocklist: std::collections::HashSet<String>,
    hasher: FileHasher,
}

impl HashBlocklistScanner {
    /// Creates a new scanner with an empty blocklist.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            blocklist: std::collections::HashSet::new(),
            hasher: FileHasher::new(),
        }
    }

    /// Adds a hash to the blocklist.
    pub fn with_blocked_hash(mut self, hash: impl Into<String>) -> Self {
        self.blocklist.insert(hash.into());
        self
    }

    /// Adds multiple hashes to the blocklist.
    #[allow(dead_code)]
    pub fn with_blocked_hashes(mut self, hashes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.blocklist.extend(hashes.into_iter().map(|h| h.into()));
        self
    }
}

#[async_trait]
impl Scanner for HashBlocklistScanner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        let start = std::time::Instant::now();

        // Compute the file hash
        let hash = self.hasher.hash_input(input)?;
        
        tracing::debug!(
            scanner = self.name(),
            hash = %hash.blake3,
            "Checking hash against blocklist"
        );

        // Check if the hash is in our blocklist
        let outcome = if self.blocklist.contains(&hash.blake3) {
            tracing::warn!(
                scanner = self.name(),
                hash = %hash.blake3,
                "Hash found in blocklist!"
            );
            ScanOutcome::Infected {
                threats: vec![
                    ThreatInfo::new("Blocklist.Match", ThreatSeverity::High, &self.name)
                        .with_signature_id(&hash.blake3)
                        .with_category("blocklist")
                        .with_description("File hash matches known malicious hash"),
                ],
            }
        } else {
            ScanOutcome::Clean
        };

        let duration = start.elapsed();
        let size = input.size_hint().unwrap_or(0);
        let metadata = FileMetadata::new(size, hash);

        Ok(ScanResult::new(
            outcome,
            metadata,
            self.name(),
            duration,
            ScanContext::new(),
        ))
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        // Our scanner is always healthy (it's just an in-memory lookup)
        Ok(())
    }

    fn max_file_size(&self) -> Option<u64> {
        Some(1024 * 1024 * 1024) // 1 GB - we only hash the file
    }

    fn supports_streaming(&self) -> bool {
        true // Hash computation can be streamed
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== Custom Backend Example ===\n");

    // First, let's compute the hash of our "malicious" file
    let malicious_content = b"This content is known to be malicious!";
    let hasher = FileHasher::new();
    let malicious_hash = hasher.hash_bytes(malicious_content);
    
    println!("Malicious file hash: {}", malicious_hash.blake3);

    // Create our custom scanner with the known-bad hash in its blocklist
    let scanner = HashBlocklistScanner::new("hash-blocklist")
        .with_blocked_hash(&malicious_hash.blake3);

    println!("Created HashBlocklistScanner with 1 blocked hash\n");

    // Build the scan manager
    let manager = ScanManager::builder()
        .add_scanner(scanner)
        .build()?;

    // Test 1: Scan a clean file
    println!("=== Test 1: Scanning a clean file ===");
    let clean_input = FileInput::from_bytes(b"This is a perfectly safe file.".to_vec())
        .with_filename("safe.txt");

    let context = ScanContext::new().with_tenant_id("demo");
    let report = manager.scan(clean_input, context.clone()).await?;

    println!("Result: {}", if report.is_clean() { "✅ CLEAN" } else { "❌ INFECTED" });
    println!("Duration: {:?}", report.total_duration);

    // Test 2: Scan the malicious file
    println!("\n=== Test 2: Scanning the malicious file ===");
    let malicious_input = FileInput::from_bytes(malicious_content.to_vec())
        .with_filename("malware.bin");

    let report = manager.scan(malicious_input, context.clone()).await?;

    if report.is_infected() {
        println!("Result: ❌ INFECTED");
        for threat in report.all_threats() {
            println!("  Threat: {}", threat.name);
            println!("  Category: {:?}", threat.category);
            println!("  Description: {:?}", threat.description);
            println!("  Signature: {:?}", threat.signature_id);
        }
    } else {
        println!("Result: ✅ CLEAN (unexpected!)");
    }
    println!("Duration: {:?}", report.total_duration);

    // Test 3: Use with policy engine
    println!("\n=== Test 3: Integrating with policy engine ===");
    
    use scanbridge::policy::PolicyEngine;

    // Create a policy that blocks infected files
    let policy = PolicyEngine::default_policy();

    // Create a new scanner for this test
    let scanner2 = HashBlocklistScanner::new("blocklist-v2")
        .with_blocked_hash(&malicious_hash.blake3);

    let manager2 = ScanManager::builder()
        .add_scanner(scanner2)
        .with_policy_engine(policy)
        .build()?;

    let malicious_input = FileInput::from_bytes(malicious_content.to_vec())
        .with_filename("unknown.exe");

    let decision = manager2.scan_with_policy(malicious_input, context).await?;

    println!("Policy decision: {:?}", decision.action);
    println!("Matched rule: {:?}", decision.matched_rule_name);

    println!("\n=== Example Complete ===");
    Ok(())
}
