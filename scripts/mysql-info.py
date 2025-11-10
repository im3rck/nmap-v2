#!/usr/bin/env python3
"""
ApexScan ASE Script: mysql-info.py
Category: discovery, safe
Description: Enumerate MySQL/MariaDB server information and configuration
Author: ApexScan Team

Retrieves vital system information from MySQL/MariaDB servers including
version, configuration details, and security-relevant settings.
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
    port = context.get('port', 3306)

    try:
        # Attempt to gather MySQL server information
        db_info = enumerate_mysql_info(target, port)

        if not db_info:
            return {
                "output": "Unable to enumerate MySQL information (connection failed or authentication required)",
                "success": False,
                "data": {},
                "error": "No database information retrieved"
            }

        # Extract information
        version = db_info.get('version', 'Unknown')
        protocol_version = db_info.get('protocol_version', 'Unknown')
        server_capabilities = db_info.get('capabilities', [])
        charset = db_info.get('charset', 'Unknown')
        thread_id = db_info.get('thread_id', 'Unknown')

        # Analyze version for known vulnerabilities
        security_issues = []
        version_lower = version.lower()

        # Check for old MySQL versions
        if 'mysql' in version_lower:
            if any(v in version_lower for v in ['5.0', '5.1', '5.5']):
                security_issues.append("Outdated MySQL version (EOL, no security updates)")

        # Check for old MariaDB versions
        if 'mariadb' in version_lower:
            if any(v in version_lower for v in ['5.5', '10.0', '10.1']):
                security_issues.append("Outdated MariaDB version (EOL, no security updates)")

        # Check for insecure capabilities
        insecure_caps = []
        if 'no_schema' in server_capabilities:
            insecure_caps.append("Schema information exposed")
        if 'connect_with_db' in server_capabilities:
            insecure_caps.append("Direct database selection allowed")

        # Determine security level
        if len(security_issues) >= 2:
            security_level = "WEAK"
        elif len(security_issues) == 1:
            security_level = "MODERATE"
        else:
            security_level = "NORMAL"

        # Build output message
        output_lines = [
            f"MySQL/MariaDB Information:",
            f"  Version: {version}",
            f"  Protocol: {protocol_version}",
            f"  Character Set: {charset}",
            f"  Thread ID: {thread_id}",
        ]

        if server_capabilities:
            output_lines.append(f"\nServer Capabilities:")
            for cap in server_capabilities[:5]:  # Show first 5
                output_lines.append(f"  • {cap}")

        if security_issues:
            output_lines.append(f"\n⚠️  Security Issues:")
            for issue in security_issues:
                output_lines.append(f"  • {issue}")

            output_lines.append(f"\nRecommendations:")
            if any('outdated' in issue.lower() for issue in security_issues):
                output_lines.append("  → Upgrade to latest stable version")
            output_lines.append("  → Review user privileges and access controls")
            output_lines.append("  → Enable SSL/TLS for encrypted connections")
            output_lines.append("  → Disable anonymous access")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "version": version,
                "protocol_version": protocol_version,
                "capabilities": server_capabilities,
                "charset": charset,
                "thread_id": thread_id,
                "security_level": security_level,
                "security_issues": security_issues
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while enumerating MySQL information",
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
            "output": f"MySQL enumeration failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def enumerate_mysql_info(target, port):
    """
    Enumerate MySQL server information by parsing the handshake packet.

    MySQL sends a greeting packet upon connection that contains:
    - Protocol version
    - Server version string
    - Thread ID
    - Authentication plugin data
    - Server capabilities
    - Character set

    Args:
        target: Target IP address
        port: MySQL port (usually 3306)

    Returns:
        Dictionary with server information
    """
    try:
        # Connect to MySQL server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # MySQL sends an initial handshake packet immediately upon connection
        # Read the handshake packet
        data = sock.recv(4096)

        if len(data) < 10:
            sock.close()
            return None

        # Parse MySQL handshake packet (simplified)
        # Format:
        # 3 bytes: packet length
        # 1 byte: packet number
        # 1 byte: protocol version
        # null-terminated string: server version
        # 4 bytes: thread id
        # ... (additional fields)

        pos = 0

        # Read packet header (4 bytes)
        packet_length = struct.unpack('<I', data[pos:pos+3] + b'\x00')[0]
        packet_number = data[pos+3]
        pos += 4

        # Read protocol version
        protocol_version = data[pos]
        pos += 1

        # Read server version (null-terminated string)
        version_end = data.find(b'\x00', pos)
        if version_end == -1:
            sock.close()
            return None

        version = data[pos:version_end].decode('utf-8', errors='ignore')
        pos = version_end + 1

        # Read thread ID (4 bytes)
        if pos + 4 <= len(data):
            thread_id = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
        else:
            thread_id = 0

        # Skip auth plugin data part 1 (8 bytes)
        pos += 8

        # Skip filler (1 byte)
        pos += 1

        # Read server capabilities (2 bytes, lower)
        if pos + 2 <= len(data):
            capabilities_lower = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
        else:
            capabilities_lower = 0

        # Read character set (1 byte)
        if pos + 1 <= len(data):
            charset = data[pos]
            pos += 1
        else:
            charset = 0

        # Parse capabilities into human-readable list
        capability_flags = {
            0x0001: 'long_password',
            0x0002: 'found_rows',
            0x0004: 'long_flag',
            0x0008: 'connect_with_db',
            0x0010: 'no_schema',
            0x0020: 'compress',
            0x0040: 'odbc',
            0x0080: 'local_files',
            0x0100: 'ignore_space',
            0x0200: 'protocol_41',
            0x0400: 'interactive',
            0x0800: 'ssl',
            0x1000: 'ignore_sigpipe',
            0x2000: 'transactions',
            0x4000: 'reserved',
            0x8000: 'secure_connection'
        }

        capabilities = []
        for flag, name in capability_flags.items():
            if capabilities_lower & flag:
                capabilities.append(name)

        # Charset mapping (simplified)
        charset_map = {
            8: 'latin1_swedish_ci',
            33: 'utf8_general_ci',
            45: 'utf8mb4_general_ci',
            63: 'binary'
        }
        charset_name = charset_map.get(charset, f'charset_{charset}')

        sock.close()

        return {
            'version': version,
            'protocol_version': protocol_version,
            'thread_id': thread_id,
            'capabilities': capabilities,
            'charset': charset_name
        }

    except Exception as e:
        return None
