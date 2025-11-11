#!/usr/bin/env python3
"""
ApexScan ASE Script: ssh-hostkey.py
Category: discovery, safe
Description: Enumerate SSH host keys and key exchange algorithms
Author: ApexScan Team

Retrieves SSH host keys (RSA, ECDSA, ED25519) and identifies weak algorithms.
"""

import socket
import struct

def main(context):
    """
    Main entry point for ASE script.

    Args:
        context: Dictionary with target, port, service, version, os, banner

    Returns:
        Dictionary with output, success, data, error
    """
    target = context.get('target')
    port = context.get('port', 22)

    try:
        # Enumerate SSH host keys
        ssh_info = enumerate_ssh_hostkeys(target, port)

        if not ssh_info:
            return {
                "output": "Unable to enumerate SSH host keys (connection failed)",
                "success": False,
                "data": {},
                "error": "No SSH response"
            }

        # Extract information
        banner = ssh_info.get('banner', 'Unknown')
        kex_algorithms = ssh_info.get('kex_algorithms', [])
        host_key_algorithms = ssh_info.get('host_key_algorithms', [])
        encryption_algorithms = ssh_info.get('encryption_algorithms', [])

        # Identify weak algorithms
        weak_kex = []
        weak_hostkey = []
        weak_encryption = []

        # Check for weak key exchange algorithms
        weak_kex_patterns = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1']
        for alg in kex_algorithms:
            if any(weak in alg for weak in weak_kex_patterns):
                weak_kex.append(alg)

        # Check for weak host key algorithms
        weak_hostkey_patterns = ['ssh-dss', 'ssh-rsa']  # DSA is weak, RSA without SHA2 is deprecated
        for alg in host_key_algorithms:
            if alg == 'ssh-dss':
                weak_hostkey.append(alg)

        # Check for weak encryption
        weak_encryption_patterns = ['arcfour', '3des', 'blowfish', 'cast128']
        for alg in encryption_algorithms:
            if any(weak in alg for weak in weak_encryption_patterns):
                weak_encryption.append(alg)

        # Determine security level
        issues = len(weak_kex) + len(weak_hostkey) + len(weak_encryption)
        if issues >= 3:
            security_level = "WEAK"
        elif issues > 0:
            security_level = "MODERATE"
        else:
            security_level = "STRONG"

        # Build output
        output_lines = [
            f"SSH Host Key Analysis:",
            f"  Server Banner: {banner}",
            f"  Security Level: {security_level}",
        ]

        if host_key_algorithms:
            output_lines.append(f"\nHost Key Algorithms ({len(host_key_algorithms)}):")
            for alg in host_key_algorithms[:5]:
                marker = "⚠️ " if alg in weak_hostkey else "✓ "
                output_lines.append(f"  {marker}{alg}")

        if kex_algorithms:
            output_lines.append(f"\nKey Exchange Algorithms ({len(kex_algorithms)}):")
            for alg in kex_algorithms[:3]:
                marker = "⚠️ " if alg in weak_kex else "✓ "
                output_lines.append(f"  {marker}{alg}")

        if encryption_algorithms:
            output_lines.append(f"\nEncryption Algorithms ({len(encryption_algorithms)}):")
            for alg in encryption_algorithms[:3]:
                marker = "⚠️ " if alg in weak_encryption else "✓ "
                output_lines.append(f"  {marker}{alg}")

        if weak_kex or weak_hostkey or weak_encryption:
            output_lines.append(f"\n⚠️  Weak Algorithms Detected:")
            if weak_kex:
                output_lines.append(f"  • Weak Key Exchange: {', '.join(weak_kex)}")
            if weak_hostkey:
                output_lines.append(f"  • Weak Host Keys: {', '.join(weak_hostkey)}")
            if weak_encryption:
                output_lines.append(f"  • Weak Encryption: {', '.join(weak_encryption)}")

            output_lines.append(f"\nRecommendations:")
            output_lines.append("  → Disable weak algorithms in sshd_config")
            output_lines.append("  → Use only modern ciphers (AES-GCM, ChaCha20)")
            output_lines.append("  → Prefer ECDSA or ED25519 host keys")
            output_lines.append("  → Use strong key exchange (curve25519, ecdh-sha2)")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "banner": banner,
                "host_key_algorithms": host_key_algorithms,
                "kex_algorithms": kex_algorithms,
                "encryption_algorithms": encryption_algorithms,
                "weak_kex": weak_kex,
                "weak_hostkey": weak_hostkey,
                "weak_encryption": weak_encryption,
                "security_level": security_level
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while enumerating SSH host keys",
            "success": False,
            "data": {},
            "error": "Timeout"
        }
    except ConnectionRefusedError:
        return {
            "output": f"Connection refused to {target}:{port}",
            "success": False,
            "data": {},
            "error": "Connection refused"
        }
    except Exception as e:
        return {
            "output": f"SSH enumeration failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def enumerate_ssh_hostkeys(target, port):
    """
    Enumerate SSH host keys by initiating SSH handshake.

    Args:
        target: Target IP address
        port: SSH port (usually 22)

    Returns:
        Dictionary with SSH information
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Receive SSH banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

        # Send client banner
        client_banner = "SSH-2.0-ApexScan_1.0\r\n"
        sock.sendall(client_banner.encode())

        # Send SSH_MSG_KEXINIT to get supported algorithms
        kexinit = build_kexinit_packet()
        sock.sendall(kexinit)

        # Receive server's KEXINIT
        response = sock.recv(8192)

        sock.close()

        # Parse KEXINIT response
        algorithms = parse_kexinit(response)

        return {
            'banner': banner,
            'kex_algorithms': algorithms.get('kex', []),
            'host_key_algorithms': algorithms.get('server_host_key', []),
            'encryption_algorithms': algorithms.get('encryption_client_to_server', [])
        }

    except Exception as e:
        return None


def build_kexinit_packet():
    """Build SSH KEXINIT packet."""
    # Simplified KEXINIT packet
    packet = b''

    # Random cookie (16 bytes)
    import os
    cookie = os.urandom(16)

    # Message type: SSH_MSG_KEXINIT (20)
    payload = b'\x14' + cookie

    # Algorithm lists (using common modern algorithms)
    algorithms = [
        b'curve25519-sha256',  # kex_algorithms
        b'ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-256',  # server_host_key_algorithms
        b'aes128-gcm@openssh.com,aes256-gcm@openssh.com',  # encryption_algorithms_client_to_server
        b'aes128-gcm@openssh.com,aes256-gcm@openssh.com',  # encryption_algorithms_server_to_client
        b'hmac-sha2-256',  # mac_algorithms_client_to_server
        b'hmac-sha2-256',  # mac_algorithms_server_to_client
        b'none',  # compression_algorithms_client_to_server
        b'none',  # compression_algorithms_server_to_client
        b'',  # languages_client_to_server
        b'',  # languages_server_to_client
    ]

    for alg_list in algorithms:
        payload += struct.pack('>I', len(alg_list)) + alg_list

    # First packet follows (boolean): false
    payload += b'\x00'

    # Reserved
    payload += b'\x00\x00\x00\x00'

    # Packet length
    packet_len = len(payload) + 1  # +1 for padding length
    padding_len = 8 - (packet_len % 8)
    if padding_len < 4:
        padding_len += 8

    packet = struct.pack('>I', packet_len + padding_len)
    packet += struct.pack('B', padding_len)
    packet += payload
    packet += b'\x00' * padding_len

    return packet


def parse_kexinit(data):
    """Parse SSH KEXINIT response packet."""
    try:
        if len(data) < 20:
            return {}

        # Skip packet length (4 bytes) and padding length (1 byte)
        pos = 5

        # Check message type (should be 20 for KEXINIT)
        if data[pos] != 20:
            return {}

        pos += 1

        # Skip cookie (16 bytes)
        pos += 16

        # Read algorithm lists
        algorithms = {}
        algorithm_names = [
            'kex',
            'server_host_key',
            'encryption_client_to_server',
            'encryption_server_to_client',
            'mac_client_to_server',
            'mac_server_to_client',
            'compression_client_to_server',
            'compression_server_to_client',
            'languages_client_to_server',
            'languages_server_to_client'
        ]

        for name in algorithm_names:
            if pos + 4 > len(data):
                break

            list_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4

            if pos + list_len > len(data):
                break

            alg_string = data[pos:pos+list_len].decode('utf-8', errors='ignore')
            algorithms[name] = alg_string.split(',') if alg_string else []
            pos += list_len

        return algorithms

    except Exception as e:
        return {}
