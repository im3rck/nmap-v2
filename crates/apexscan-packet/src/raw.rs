//! Raw socket interface

use apexscan_core::{Error, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::SocketAddr;

/// Raw socket wrapper for packet transmission
pub struct RawSocket {
    socket: Socket,
}

impl RawSocket {
    /// Create a new raw socket for IPv4
    pub fn new_ipv4(protocol: Protocol) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(protocol))
            .map_err(|e| Error::Network(format!("Failed to create raw socket: {}", e)))?;

        // Set IP_HDRINCL to include IP header in packet
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    return Err(Error::Network(
                        "Failed to set IP_HDRINCL".to_string(),
                    ));
                }
            }
        }

        Ok(Self { socket })
    }

    /// Send a raw packet to the specified address
    pub fn send_to(&self, packet: &[u8], addr: &SocketAddr) -> Result<usize> {
        let sent = self
            .socket
            .send_to(packet, &(*addr).into())
            .map_err(|e| Error::Network(format!("Failed to send packet: {}", e)))?;

        Ok(sent)
    }

    /// Receive a raw packet
    pub fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (size, addr) = self
            .socket
            .recv_from(buffer)
            .map_err(|e| Error::Network(format!("Failed to receive packet: {}", e)))?;

        let socket_addr = addr
            .as_socket()
            .ok_or_else(|| Error::Network("Invalid socket address".to_string()))?;

        Ok((size, socket_addr))
    }

    /// Set socket timeout
    pub fn set_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::Network(format!("Failed to set timeout: {}", e)))?;

        Ok(())
    }
}

/// Check if the process has CAP_NET_RAW capability (Linux only)
#[cfg(target_os = "linux")]
pub fn check_raw_socket_permission() -> Result<()> {
    use std::process::Command;

    let output = Command::new("getcap")
        .arg("/proc/self/exe")
        .output()
        .map_err(|e| Error::Permission(format!("Failed to check capabilities: {}", e)))?;

    if !output.status.success() {
        // Try creating a test socket
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::Permission(
                "CAP_NET_RAW capability required. Run with sudo or set capabilities.".to_string(),
            )),
        }
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check_raw_socket_permission() -> Result<()> {
    // On non-Linux systems, try creating a test socket
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::Permission(
            "Administrative privileges required for raw sockets".to_string(),
        )),
    }
}
