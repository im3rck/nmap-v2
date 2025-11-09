//! Asynchronous DNS resolver for ApexScan
//!
//! Provides non-blocking hostname resolution with graceful error handling.

use std::net::{IpAddr, ToSocketAddrs};
use tokio::task;
use tracing::warn;

/// Resolve a hostname to a list of IP addresses
///
/// This function accepts either a hostname or an IP address string.
/// If the input is already a valid IP, it returns that IP immediately.
/// Otherwise, it performs async DNS resolution.
///
/// # Arguments
/// * `target` - Hostname or IP address string
///
/// # Returns
/// * `Ok(Vec<String>)` - List of resolved IP addresses
/// * `Err(String)` - Descriptive error message on failure
///
/// # Examples
/// ```
/// let ips = resolve_hostname("example.com").await?;
/// ```
pub async fn resolve_hostname(target: &str) -> Result<Vec<String>, String> {
    // First, check if the target is already a valid IP address
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip.to_string()]);
    }

    // Clone target for the blocking task
    let target_owned = target.to_string();

    // Perform DNS resolution in a blocking task to avoid blocking the async runtime
    let result = task::spawn_blocking(move || {
        // Use ToSocketAddrs for DNS resolution
        // We need to append a port for the resolution to work
        let addr_string = format!("{}:0", target_owned);

        match addr_string.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs
                    .map(|addr| addr.ip().to_string())
                    .collect();

                if ips.is_empty() {
                    Err(format!("No IP addresses found for hostname: {}", target_owned))
                } else {
                    Ok(ips)
                }
            }
            Err(e) => Err(format!("DNS resolution failed for '{}': {}", target_owned, e)),
        }
    })
    .await
    .map_err(|e| format!("DNS resolver task panicked: {}", e))?;

    result
}

/// Resolve multiple targets concurrently
///
/// # Arguments
/// * `targets` - List of hostnames or IP addresses
///
/// # Returns
/// * Vector of tuples: (original_target, resolved_ips_or_error)
pub async fn resolve_multiple(targets: &[String]) -> Vec<(String, Result<Vec<String>, String>)> {
    let mut results = Vec::new();

    for target in targets {
        let resolved = resolve_hostname(target).await;

        if let Err(ref err) = resolved {
            warn!("DNS resolution warning for '{}': {}", target, err);
        }

        results.push((target.clone(), resolved));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ip_address() {
        // IP addresses should be returned immediately
        let result = resolve_hostname("192.168.1.1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["192.168.1.1"]);
    }

    #[tokio::test]
    async fn test_resolve_ipv6_address() {
        // IPv6 addresses should also work
        let result = resolve_hostname("::1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["::1"]);
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        // Localhost should resolve
        let result = resolve_hostname("localhost").await;
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
        // Should contain 127.0.0.1 or ::1
        assert!(ips.contains(&"127.0.0.1".to_string()) || ips.contains(&"::1".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_invalid_hostname() {
        // Invalid hostnames should return an error
        let result = resolve_hostname("this-hostname-definitely-does-not-exist-12345.invalid").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_multiple_targets() {
        let targets = vec![
            "127.0.0.1".to_string(),
            "localhost".to_string(),
            "invalid-host-xyz.invalid".to_string(),
        ];

        let results = resolve_multiple(&targets).await;

        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_ok()); // 127.0.0.1 should succeed
        assert!(results[1].1.is_ok()); // localhost should succeed
        assert!(results[2].1.is_err()); // invalid host should fail
    }
}
