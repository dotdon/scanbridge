//! Circuit breaker example demonstrating resilience patterns.
//!
//! This example shows how to:
//! - Wrap a scanner with a circuit breaker
//! - Configure failure thresholds and timeouts
//! - Handle open circuit states
//! - Monitor circuit breaker metrics
//!
//! Run with: cargo run --example with_circuit_breaker

use scanbridge::backends::MockScanner;
use scanbridge::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, FallbackBehavior};
use scanbridge::prelude::*;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== Circuit Breaker Example ===\n");

    // Create a mock scanner that will fail frequently
    let failing_scanner = MockScanner::new()
        .with_name("unreliable-scanner")
        .with_fail_rate(0.8); // 80% failure rate

    // Configure the circuit breaker
    let cb_config = CircuitBreakerConfig::default()
        .with_failure_threshold(3)          // Open after 3 failures
        .with_success_threshold(2)          // Close after 2 successes in half-open
        .with_open_duration(Duration::from_secs(5)) // Stay open for 5 seconds
        .with_fallback_behavior(FallbackBehavior::FailClosed);

    println!("Circuit Breaker Configuration:");
    println!("  Failure threshold: {}", cb_config.failure_threshold);
    println!("  Success threshold: {}", cb_config.success_threshold);
    println!("  Open duration: {:?}", cb_config.open_duration);
    println!();

    // Wrap the scanner with a circuit breaker
    let protected_scanner = CircuitBreaker::new(failing_scanner, cb_config);

    // Create test input
    let input = FileInput::from_bytes(b"test content".to_vec());

    println!("Sending requests to trigger circuit breaker...\n");

    // Send multiple requests to trigger the circuit breaker
    for i in 1..=10 {
        let state = protected_scanner.state();
        let metrics = protected_scanner.metrics();
        
        println!("Request #{}: Circuit state = {:?}", i, state.name());
        
        match protected_scanner.scan(&input).await {
            Ok(result) => {
                println!("  ✅ Success! Outcome: {:?}", 
                    if result.is_clean() { "Clean" } else { "Infected" });
            }
            Err(ScanError::CircuitOpen { engine, .. }) => {
                println!("  🔴 Circuit OPEN for '{}' - request rejected", engine);
            }
            Err(e) => {
                println!("  ❌ Failed: {}", e);
            }
        }

        println!("  Metrics: {} total, {} success, {} failed, {} rejected",
            metrics.total_requests,
            metrics.successful_requests,
            metrics.failed_requests,
            metrics.rejected_requests);

        // Small delay between requests
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for circuit to transition to half-open
    println!("\nWaiting for circuit to transition to half-open...");
    tokio::time::sleep(Duration::from_secs(6)).await;

    println!("\nCircuit should now be in half-open state.");
    println!("Current state: {:?}", protected_scanner.state().name());

    // Demonstrate recovery with a healthy scanner
    println!("\n=== Demonstrating Recovery ===\n");

    let healthy_scanner = MockScanner::new_clean().with_name("healthy-scanner");
    let cb_config = CircuitBreakerConfig::default()
        .with_failure_threshold(3)
        .with_success_threshold(2)
        .with_open_duration(Duration::from_secs(2));

    let healthy_cb = CircuitBreaker::new(healthy_scanner, cb_config);

    // Force open the circuit
    healthy_cb.force_open();
    println!("Forced circuit to OPEN state");

    // Wait for transition to half-open
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("State after wait: {:?}", healthy_cb.state().name());

    // Send successful requests to close the circuit
    for i in 1..=3 {
        let state = healthy_cb.state();
        println!("\nRequest #{}: State = {:?}", i, state.name());
        
        match healthy_cb.scan(&input).await {
            Ok(_) => println!("  ✅ Success!"),
            Err(e) => println!("  ❌ Failed: {}", e),
        }
    }

    println!("\nFinal state: {:?}", healthy_cb.state().name());
    println!("Final metrics: {:?}", healthy_cb.metrics());

    // Demonstrate fallback scanner
    println!("\n=== Demonstrating Fallback Scanner ===\n");

    let primary_scanner = MockScanner::new()
        .with_name("primary")
        .with_fail_rate(1.0); // Always fails

    let fallback_scanner: Arc<dyn Scanner> = Arc::new(
        MockScanner::new_clean().with_name("fallback")
    );

    let cb_config = CircuitBreakerConfig::default()
        .with_failure_threshold(2)
        .with_fallback_behavior(FallbackBehavior::Fallback(fallback_scanner));

    let scanner_with_fallback = CircuitBreaker::new(primary_scanner, cb_config);

    // Trigger circuit to open
    for _ in 0..3 {
        let _ = scanner_with_fallback.scan(&input).await;
    }

    println!("Circuit is now: {:?}", scanner_with_fallback.state().name());
    
    // This request should use the fallback
    match scanner_with_fallback.scan(&input).await {
        Ok(result) => {
            println!("✅ Request succeeded using fallback scanner!");
            println!("   Engine: {}", result.engine);
        }
        Err(e) => println!("❌ Failed: {}", e),
    }

    println!("\n=== Example Complete ===");
    Ok(())
}
