//! Service version detection

use crate::{banner::BannerGrabber, ServiceInfo};
use apexscan_core::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::debug;

/// Service detector
pub struct ServiceDetector {
    banner_grabber: BannerGrabber,
}

impl ServiceDetector {
    pub fn new(timeout: Duration) -> Self {
        Self {
            banner_grabber: BannerGrabber::new(timeout),
        }
    }

    /// Detect service on a specific port
    pub async fn detect_service(&self, target: IpAddr, port: u16) -> Result<ServiceInfo> {
        debug!("Detecting service on {}:{}", target, port);

        let addr = SocketAddr::new(target, port);

        // Try to grab banner
        let banner_result = self.banner_grabber.grab_banner(addr).await;

        let (banner_str, service_name, version, product, extra_info) = if let Ok(banner) = banner_result {
            let (svc, ver, prod, extra) = self.analyze_banner(&banner, port);
            (banner, svc, ver, prod, extra)
        } else {
            // Fallback to port-based guess
            (String::new(), self.guess_service_by_port(port), None, None, None)
        };

        let confidence = if version.is_some() {
            0.9 // High confidence with version
        } else if service_name.is_some() {
            0.5 // Medium confidence without version
        } else {
            0.1 // Low confidence (pure guess)
        };

        Ok(ServiceInfo {
            port,
            protocol: "tcp".to_string(),
            service_name,
            version,
            product,
            extra_info,
            banner: banner_str,
            confidence,
        })
    }

    /// Analyze banner to extract service info
    fn analyze_banner(
        &self,
        banner: &str,
        port: u16,
    ) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
        // Extract service name
        let service = crate::banner::extract_service_from_banner(banner, port);

        // Extract version if service identified
        let version = if let Some(ref svc) = service {
            crate::banner::extract_version_from_banner(banner, svc)
        } else {
            None
        };

        // Extract product and extra info
        let (product, extra_info) = self.extract_product_info(banner, &service);

        (service, version, product, extra_info)
    }

    /// Extract product information from banner
    fn extract_product_info(
        &self,
        banner: &str,
        service: &Option<String>,
    ) -> (Option<String>, Option<String>) {
        match service.as_deref() {
            Some("http") => {
                // Extract server software
                if let Some(start) = banner.find("Server:") {
                    let line = &banner[start + 7..];
                    if let Some(end) = line.find('\r') {
                        let server = line[..end].trim();

                        // Split product from extra info
                        if let Some(slash) = server.find('/') {
                            let product = &server[..slash];
                            let rest = &server[slash + 1..];

                            if let Some(space) = rest.find(' ') {
                                return (
                                    Some(product.to_string()),
                                    Some(rest[space + 1..].to_string()),
                                );
                            } else {
                                return (Some(product.to_string()), Some(rest.to_string()));
                            }
                        }
                    }
                }
            }
            Some("ssh") => {
                // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
                if let Some(openssh_pos) = banner.find("OpenSSH") {
                    let rest = &banner[openssh_pos..];
                    if let Some(space) = rest.find(' ') {
                        return (
                            Some("OpenSSH".to_string()),
                            Some(rest[space + 1..].trim().to_string()),
                        );
                    }
                }
            }
            _ => {}
        }

        (None, None)
    }

    /// Guess service by well-known port
    fn guess_service_by_port(&self, port: u16) -> Option<String> {
        match port {
            21 => Some("ftp".to_string()),
            22 => Some("ssh".to_string()),
            23 => Some("telnet".to_string()),
            25 => Some("smtp".to_string()),
            53 => Some("dns".to_string()),
            80 => Some("http".to_string()),
            110 => Some("pop3".to_string()),
            143 => Some("imap".to_string()),
            443 => Some("https".to_string()),
            445 => Some("microsoft-ds".to_string()),
            3306 => Some("mysql".to_string()),
            3389 => Some("ms-wbt-server".to_string()),
            5432 => Some("postgresql".to_string()),
            6379 => Some("redis".to_string()),
            8080 => Some("http-proxy".to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_service() {
        let detector = ServiceDetector::new(Duration::from_secs(5));
        assert_eq!(
            detector.guess_service_by_port(22),
            Some("ssh".to_string())
        );
        assert_eq!(
            detector.guess_service_by_port(80),
            Some("http".to_string())
        );
    }
}
