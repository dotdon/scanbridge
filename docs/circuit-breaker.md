# Circuit Breaker Guide

The circuit breaker is a resilience pattern that prevents your application from repeatedly calling a failing service. When a scanner becomes unhealthy, the circuit breaker temporarily stops sending requests, allowing the service to recover.

## Why Use Circuit Breakers?

Without circuit breakers:

1. Scanner goes down
2. Every request tries to connect
3. Requests pile up waiting for timeouts
4. Your application becomes slow/unresponsive
5. Users experience degraded service

With circuit breakers:

1. Scanner goes down
2. After a few failures, circuit opens
3. Requests fail immediately (fast failure)
4. Your application remains responsive
5. Circuit periodically probes for recovery

## Basic Usage

```rust
use scanbridge::backends::MockScanner;
use scanbridge::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use std::time::Duration;

// Create a scanner
let scanner = MockScanner::new_clean();

// Configure the circuit breaker
let config = CircuitBreakerConfig::default()
    .with_failure_threshold(5)
    .with_open_duration(Duration::from_secs(30))
    .with_success_threshold(3);

// Wrap the scanner
let protected = CircuitBreaker::new(scanner, config);

// Use protected just like a regular scanner
let result = protected.scan(&input).await;
```

## Configuration Options

### Failure Threshold

How many failures before opening the circuit.

```rust
.with_failure_threshold(5)  // Default: 5
```

**Recommendations:**
- Low (2-3): Strict, opens quickly. Good for critical paths.
- Medium (5): Balanced default.
- High (10+): Tolerant, for flaky services.

### Open Duration

How long the circuit stays open before transitioning to half-open.

```rust
.with_open_duration(Duration::from_secs(30))  // Default: 30s
```

**Recommendations:**
- Short (5-10s): Quick recovery detection. More probing traffic.
- Medium (30s): Balanced default.
- Long (60s+): Give slow services time to recover.

### Success Threshold

How many successful probes needed to close the circuit.

```rust
.with_success_threshold(3)  // Default: 3
```

**Recommendations:**
- Low (1): Fast recovery, but might close too soon.
- Medium (3): Balanced default.
- High (5+): Conservative, ensures service is truly healthy.

### Half-Open Max Probes

How many concurrent probe requests allowed in half-open state.

```rust
.with_half_open_max_probes(1)  // Default: 1
```

Limits traffic to the recovering service to prevent overwhelming it.

## Failure Policy

Configure what types of errors count as failures.

```rust
use scanbridge::circuit_breaker::FailurePolicy;

let policy = FailurePolicy {
    count_timeouts: true,              // Connection/scan timeouts
    count_connection_failures: true,   // Network errors
    count_engine_unavailable: true,    // Service down
    count_rate_limited: false,         // Rate limiting (expected)
    count_all_errors: false,           // Everything else
};

let config = CircuitBreakerConfig::default()
    .with_failure_policy(policy);
```

### Built-in Policies

```rust
// Default: timeouts, connections, unavailable
let policy = FailurePolicy::default();

// Count all errors as failures
let policy = FailurePolicy::all_errors();

// Only connection-related failures
let policy = FailurePolicy::connection_only();
```

## Fallback Behaviors

What to do when the circuit is open.

### Fail Closed (Default)

Reject all scans when circuit is open. **Safest option.**

```rust
use scanbridge::circuit_breaker::FallbackBehavior;

let config = CircuitBreakerConfig::default()
    .with_fallback_behavior(FallbackBehavior::FailClosed);
```

When circuit is open:
```rust
Err(ScanError::CircuitOpen { engine: "clamav", .. })
```

### Fail Open

Allow files through when circuit is open. **Use with caution!**

```rust
.with_fallback_behavior(FallbackBehavior::FailOpen)
```

Returns a "clean" result with a warning in the details. This means **potentially infected files may pass through** when the scanner is down.

Use this only when availability is more important than security.

### Fallback Scanner

Use an alternate scanner when the primary fails.

```rust
use std::sync::Arc;

let primary = ClamAvScanner::new(config)?;
let fallback: Arc<dyn Scanner> = Arc::new(MockScanner::new_clean());

let config = CircuitBreakerConfig::default()
    .with_fallback_behavior(FallbackBehavior::Fallback(fallback));

let protected = CircuitBreaker::new(primary, config);
```

When primary circuit opens, scans go to the fallback.

## Monitoring

### State Inspection

```rust
let state = protected.state();
println!("Current state: {:?}", state.name());
// "closed", "open", or "half_open"

match state {
    BreakerState::Closed { failure_count } => {
        println!("Failures so far: {}", failure_count);
    }
    BreakerState::Open { opened_at, until } => {
        println!("Opened at: {:?}", opened_at);
        println!("Will transition at: {:?}", until);
    }
    BreakerState::HalfOpen { success_count, probe_count } => {
        println!("Successes: {}/{}", success_count, config.success_threshold);
    }
}
```

### Metrics

```rust
let metrics = protected.metrics();

println!("Total requests: {}", metrics.total_requests);
println!("Successful: {}", metrics.successful_requests);
println!("Failed: {}", metrics.failed_requests);
println!("Rejected (circuit open): {}", metrics.rejected_requests);
println!("Times opened: {}", metrics.times_opened);
println!("Times closed: {}", metrics.times_closed);
println!("Success rate: {:.1}%", metrics.success_rate() * 100.0);
```

### Manual Control

```rust
// Force circuit open (e.g., during maintenance)
protected.force_open();

// Force circuit closed
protected.force_close();

// Reset state and metrics
protected.reset();
```

## Integration with ScanManager

Use circuit-breaker-wrapped scanners with ScanManager:

```rust
use std::sync::Arc;

let clamav = ClamAvScanner::new(clamav_config)?;
let clamav_cb = CircuitBreaker::new(clamav, CircuitBreakerConfig::strict());

let vt = VirusTotalScanner::new(vt_config)?;
let vt_cb = CircuitBreaker::new(vt, CircuitBreakerConfig::high_availability());

let manager = ScanManager::builder()
    .add_arc_scanner(Arc::new(clamav_cb))
    .add_arc_scanner(Arc::new(vt_cb))
    .build()?;
```

Each scanner has independent circuit breaker state.

## Preset Configurations

### Strict (Security-focused)

```rust
let config = CircuitBreakerConfig::strict();
// failure_threshold: 3
// success_threshold: 5
// open_duration: 60s
// fallback: FailClosed
```

Opens quickly, recovers slowly. Best for security-critical paths.

### High Availability

```rust
let config = CircuitBreakerConfig::high_availability();
// failure_threshold: 10
// success_threshold: 2
// open_duration: 10s
// fallback: FailClosed
```

Tolerant of failures, quick recovery. Best for non-critical scans.

## Interaction with Policies

When circuit is open with `FailClosed`:

1. Scan fails with `ScanError::CircuitOpen`
2. No `ScanResult` is produced
3. Policy engine not invoked

When circuit is open with `FailOpen`:

1. Synthetic "clean" result created with warning
2. Policy engine evaluates as normal
3. Consider adding a policy rule that blocks files scanned during circuit-open

```rust
PolicyRule::new("block-fallback", PolicyAction::require_review())
    .with_condition(Condition::SourceEquals { source: "failopen".into() })
```

## Best Practices

1. **Always use circuit breakers for network-based scanners** (ClamAV TCP, VirusTotal)

2. **Configure based on expected failure patterns**:
   - Intermittent network issues: higher threshold
   - Service outages: shorter open duration for quick recovery detection

3. **Monitor circuit breaker metrics** in production:
   - Alert on `times_opened` increases
   - Track `rejected_requests` for capacity planning

4. **Test circuit breaker behavior** before deployment:
   - Simulate scanner failures
   - Verify fallback behavior
   - Check recovery time

5. **Document fallback behavior** for operations:
   - What happens when each scanner's circuit opens?
   - What's the impact on file processing?
