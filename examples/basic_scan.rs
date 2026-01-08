//! Basic scan example demonstrating simple file scanning.
//!
//! This example shows how to:
//! - Create a scanner
//! - Build a ScanManager
//! - Scan a file and handle the result
//!
//! Run with: cargo run --example basic_scan

use scanbridge::backends::MockScanner;
use scanbridge::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== Scanbridge Basic Scan Example ===\n");

    // Create a mock scanner that reports files as clean
    let scanner = MockScanner::new_clean().with_name("example-scanner");

    // Build the scan manager with the scanner
    let manager = ScanManager::builder()
        .add_scanner(scanner)
        .build()?;

    // Create file input from bytes (in practice, this would be an uploaded file)
    let file_content = b"This is the content of a clean file.";
    let input = FileInput::from_bytes(file_content.to_vec()).with_filename("document.txt");

    // Create a scan context with metadata
    let context = ScanContext::new()
        .with_tenant_id("example-tenant")
        .with_user_id("user-123")
        .with_request_id("req-456")
        .with_source("upload");

    println!("Scanning file: {:?}", input.filename());
    println!("File size: {} bytes", input.size_hint().unwrap_or(0));

    // Perform the scan
    let report = manager.scan(input, context).await?;

    // Handle the result
    println!("\n=== Scan Results ===");
    println!("Report ID: {}", report.id);
    println!("File Hash (BLAKE3): {}", report.file_hash.blake3);
    println!("Engines used: {}", report.engine_count());
    println!("Total duration: {:?}", report.total_duration);

    match &report.aggregated_outcome {
        ScanOutcome::Clean => {
            println!("\n✅ File is CLEAN - no threats detected");
        }
        ScanOutcome::Infected { threats } => {
            println!("\n❌ File is INFECTED!");
            for threat in threats {
                println!("  - {} (severity: {}, engine: {})", 
                    threat.name, threat.severity, threat.engine);
            }
        }
        ScanOutcome::Suspicious { reason, confidence } => {
            println!("\n⚠️ File is SUSPICIOUS");
            println!("  Reason: {}", reason);
            println!("  Confidence: {:.1}%", confidence * 100.0);
        }
        ScanOutcome::Error { recoverable } => {
            println!("\n💥 Scan ERROR occurred");
            println!("  Recoverable: {}", recoverable);
        }
    }

    // Demonstrate scanning an "infected" file
    println!("\n\n=== Scanning an Infected File ===\n");

    let infected_scanner = MockScanner::new_infected(vec![
        ThreatInfo::new("Trojan.GenericKD.12345", ThreatSeverity::High, "example-scanner")
            .with_category("trojan")
            .with_signature_id("SIG-001"),
    ]).with_name("infected-scanner");

    let infected_manager = ScanManager::builder()
        .add_scanner(infected_scanner)
        .build()?;

    let malicious_input = FileInput::from_bytes(b"malicious content".to_vec())
        .with_filename("malware.exe");

    let context = ScanContext::new().with_tenant_id("example-tenant");
    let report = infected_manager.scan(malicious_input, context).await?;

    if report.is_infected() {
        println!("❌ File is INFECTED!");
        for threat in report.all_threats() {
            println!("  Threat: {} ({})", threat.name, threat.severity);
        }
    }

    println!("\n=== Example Complete ===");
    Ok(())
}
