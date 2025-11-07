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
    /// protocol_num: libc protocol constant (e.g., libc::IPPROTO_TCP, libc::IPPROTO_ICMP)
    pub fn new_ipv4(protocol_num: i32) -> Result<Self> {
        // Create raw socket using SOCK_RAW type
        #[cfg(unix)]
        let socket = unsafe {
            use std::os::unix::io::FromRawFd;
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol_num);
            if fd < 0 {
                return Err(Error::Network("Failed to create raw socket".to_string()));
            }
            Socket::from_raw_fd(fd)
        };

        #[cfg(windows)]
        let socket = unsafe {
            use std::os::windows::io::FromRawSocket;
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol_num);
            if fd < 0 {
                return Err(Error::Network("Failed to create raw socket".to_string()));
            }
            Socket::from_raw_socket(fd as _)
        };

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
        use std::mem::MaybeUninit;

        // Convert buffer to MaybeUninit for socket2 API
        let uninit_buf = unsafe {
            std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut MaybeUninit<u8>, buffer.len())
        };

        let (size, addr) = self
            .socket
            .recv_from(uninit_buf)
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
    use std::os::unix::io::FromRawFd;
    use std::process::Command;

    let output = Command::new("getcap")
        .arg("/proc/self/exe")
        .output()
        .map_err(|e| Error::Permission(format!("Failed to check capabilities: {}", e)))?;

    if !output.status.success() {
        // Try creating a test socket (ICMP protocol = 1)
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
            if fd < 0 {
                return Err(Error::Permission(
                    "CAP_NET_RAW capability required. Run with sudo or set capabilities.".to_string(),
                ));
            }
            libc::close(fd);
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_raw_socket_permission() -> Result<()> {
    use std::os::unix::io::FromRawFd;

    // On non-Linux systems, try creating a test socket (ICMP protocol = 1)
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, 1);
        if fd < 0 {
            return Err(Error::Permission(
                "Administrative privileges required for raw sockets".to_string(),
            ));
        }
        libc::close(fd);
    }

    Ok(())
}
