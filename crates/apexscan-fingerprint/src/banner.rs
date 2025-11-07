//! Banner grabbing for service detection

use apexscan_core::{Error, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

/// Banner grabber
pub struct BannerGrabber {
    timeout: Duration,
}

impl BannerGrabber {
    pub fn new(timeout_duration: Duration) -> Self {
        Self {
            timeout: timeout_duration,
        }
    }

    /// Grab banner from a TCP port
    pub async fn grab_banner(&self, addr: SocketAddr) -> Result<String> {
        debug!("Grabbing banner from {}", addr);

        let stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Network(format!("Failed to connect: {}", e)))?;

        self.read_banner(stream, addr.port()).await
    }

    /// Read banner from connected stream
    async fn read_banner(&self, mut stream: TcpStream, port: u16) -> Result<String> {
        let mut buffer = vec![0u8; 4096];

        // For some services, we need to send a probe first
        if let Some(probe) = self.get_probe_for_port(port) {
            trace!("Sending probe for port {}", port);
            stream
                .write_all(&probe)
                .await
                .map_err(|e| Error::Network(format!("Failed to send probe: {}", e)))?;
        }

        // Read response
        let size = timeout(self.timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Network(format!("Failed to read: {}", e)))?;

        if size == 0 {
            return Err(Error::Network("No banner received".to_string()));
        }

        // Convert to string (best effort)
        let banner = String::from_utf8_lossy(&buffer[..size]).to_string();
        trace!("Received banner: {}", banner.trim());

        Ok(banner)
    }

    /// Get protocol-specific probe for a port
    fn get_probe_for_port(&self, port: u16) -> Option<Vec<u8>> {
        match port {
            80 | 8080 | 8000 => {
                // HTTP GET request
                Some(b"GET / HTTP/1.0\r\n\r\n".to_vec())
            }
            443 | 8443 => {
                // HTTPS would need TLS handshake (simplified here)
                None
            }
            22 => {
                // SSH - just read banner, no probe needed
                None
            }
            21 => {
                // FTP - server sends banner first
                None
            }
            25 | 587 => {
                // SMTP - server sends banner first
                None
            }
            110 => {
                // POP3 - server sends banner first
                None
            }
            143 => {
                // IMAP - server sends banner first
                None
            }
            3306 => {
                // MySQL - server sends handshake first
                None
            }
            5432 => {
                // PostgreSQL - need startup packet
                None
            }
            _ => None,
        }
    }
}

/// Extract service name from banner
pub fn extract_service_from_banner(banner: &str, port: u16) -> Option<String> {
    // HTTP
    if banner.contains("HTTP/") {
        return Some("http".to_string());
    }

    // SSH
    if banner.starts_with("SSH-") {
        return Some("ssh".to_string());
    }

    // FTP
    if banner.contains("FTP") || banner.contains("220") {
        return Some("ftp".to_string());
    }

    // SMTP
    if banner.contains("SMTP") || (port == 25 && banner.contains("220")) {
        return Some("smtp".to_string());
    }

    // MySQL
    if banner.contains("mysql") || banner.as_bytes().get(0) == Some(&0x0a) {
        return Some("mysql".to_string());
    }

    // PostgreSQL
    if banner.contains("PostgreSQL") {
        return Some("postgresql".to_string());
    }

    None
}

/// Extract version from banner
pub fn extract_version_from_banner(banner: &str, service: &str) -> Option<String> {
    match service {
        "ssh" => {
            // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            if let Some(start) = banner.find("OpenSSH_") {
                let version_str = &banner[start + 8..];
                if let Some(end) = version_str.find(' ') {
                    return Some(version_str[..end].to_string());
                }
            }
        }
        "http" => {
            // Server: Apache/2.4.52 (Ubuntu)
            if let Some(start) = banner.find("Server:") {
                let server_line = &banner[start + 7..];
                if let Some(end) = server_line.find('\r') {
                    return Some(server_line[..end].trim().to_string());
                }
            }
        }
        "ftp" => {
            // 220 ProFTPD 1.3.5 Server
            if let Some(start) = banner.find("ProFTPD") {
                let version_str = &banner[start + 8..];
                if let Some(end) = version_str.find(' ') {
                    return Some(format!("ProFTPD {}", &version_str[..end]));
                }
            }
        }
        _ => {}
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_service() {
        assert_eq!(
            extract_service_from_banner("SSH-2.0-OpenSSH_8.2p1", 22),
            Some("ssh".to_string())
        );
        assert_eq!(
            extract_service_from_banner("HTTP/1.1 200 OK\r\nServer: nginx", 80),
            Some("http".to_string())
        );
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(
            extract_version_from_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu", "ssh"),
            Some("8.2p1".to_string())
        );
    }
}
