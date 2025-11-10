#!/usr/bin/env python3
"""
ApexScan ASE Script: mysql-empty-password.py
Category: auth, intrusive, vuln
Description: Check for MySQL/MariaDB accounts with empty passwords
Author: ApexScan Team

Tests if the MySQL/MariaDB server allows authentication with common
administrative usernames using blank/empty passwords - a critical
security vulnerability.
"""

import socket
import struct
import hashlib

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
        # Test common usernames with empty password
        usernames_to_test = ['root', 'admin', 'mysql', 'test', 'user', 'dba']

        vulnerable_accounts = []

        for username in usernames_to_test:
            result = test_empty_password(target, port, username)

            if result.get('success'):
                vulnerable_accounts.append({
                    'username': username,
                    'details': result.get('details', '')
                })

        # Build output
        if vulnerable_accounts:
            output_lines = [
                f"MySQL Empty Password Check:",
                f"  Status: 🚨 VULNERABLE",
                f"\n⚠️  CRITICAL SECURITY VULNERABILITY DETECTED!",
                f"   {len(vulnerable_accounts)} account(s) with empty passwords found:",
            ]

            for account in vulnerable_accounts:
                output_lines.append(f"   • Username: '{account['username']}' - {account['details']}")

            output_lines.append(f"\n   Impact:")
            output_lines.append(f"   • Complete database access without authentication")
            output_lines.append(f"   • Data theft and modification")
            output_lines.append(f"   • Potential server compromise")
            output_lines.append(f"   • Privilege escalation vector")

            output_lines.append(f"\n   Remediation (URGENT):")
            output_lines.append(f"   → Set strong passwords for all accounts immediately")
            output_lines.append(f"   → Remove or disable unused accounts")
            output_lines.append(f"   → Review and restrict user privileges")
            output_lines.append(f"   → Enable audit logging")
            output_lines.append(f"   → Consider network-level access restrictions")

            security_level = "CRITICAL"
            vulnerable = True

        else:
            output_lines = [
                f"MySQL Empty Password Check:",
                f"  Status: ✓ SECURE",
                f"\n   No accounts with empty passwords detected.",
                f"   Tested usernames: {', '.join(usernames_to_test)}",
            ]

            security_level = "SECURE"
            vulnerable = False

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "vulnerable": vulnerable,
                "vulnerable_accounts": vulnerable_accounts,
                "tested_usernames": usernames_to_test,
                "security_level": security_level
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while testing MySQL empty passwords",
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
            "output": f"MySQL empty password test failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def test_empty_password(target, port, username):
    """
    Test if a MySQL account accepts empty password authentication.

    This function attempts to authenticate with the MySQL server using
    the specified username and an empty password.

    Args:
        target: Target IP address
        port: MySQL port (usually 3306)
        username: Username to test

    Returns:
        Dictionary with test results
    """
    try:
        # Connect to MySQL server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        # Receive initial handshake packet
        handshake_data = sock.recv(4096)

        if len(handshake_data) < 10:
            sock.close()
            return {'success': False, 'details': 'Invalid handshake'}

        # Parse handshake to get authentication details
        handshake = parse_handshake(handshake_data)

        if not handshake:
            sock.close()
            return {'success': False, 'details': 'Failed to parse handshake'}

        # Send authentication packet with empty password
        auth_packet = build_auth_packet(
            username=username,
            password='',  # Empty password
            database='',
            auth_plugin_data=handshake.get('auth_plugin_data', b''),
            capabilities=handshake.get('capabilities', 0),
            charset=handshake.get('charset', 33)
        )

        sock.sendall(auth_packet)

        # Receive authentication response
        response = sock.recv(4096)

        if len(response) < 5:
            sock.close()
            return {'success': False, 'details': 'No auth response'}

        # Parse response packet
        # Packet format: 3 bytes length, 1 byte sequence, 1 byte type
        packet_length = struct.unpack('<I', response[0:3] + b'\x00')[0]
        packet_sequence = response[3]
        packet_type = response[4]

        sock.close()

        # 0x00 = OK packet (authentication successful)
        # 0xFF = ERR packet (authentication failed)
        if packet_type == 0x00:
            return {
                'success': True,
                'details': 'Empty password accepted'
            }
        else:
            return {
                'success': False,
                'details': 'Empty password rejected'
            }

    except Exception as e:
        return {
            'success': False,
            'details': f'Test error: {str(e)}'
        }


def parse_handshake(data):
    """
    Parse MySQL handshake packet.

    Args:
        data: Raw handshake packet data

    Returns:
        Dictionary with handshake information
    """
    try:
        pos = 4  # Skip packet header

        # Protocol version
        protocol_version = data[pos]
        pos += 1

        # Server version (null-terminated)
        version_end = data.find(b'\x00', pos)
        if version_end == -1:
            return None
        version = data[pos:version_end].decode('utf-8', errors='ignore')
        pos = version_end + 1

        # Thread ID
        thread_id = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4

        # Auth plugin data part 1 (8 bytes)
        auth_plugin_data_part1 = data[pos:pos+8]
        pos += 8

        # Filler
        pos += 1

        # Capabilities (lower 2 bytes)
        capabilities_lower = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2

        # Charset
        charset = data[pos]
        pos += 1

        # Status flags
        pos += 2

        # Capabilities (upper 2 bytes)
        if pos + 2 <= len(data):
            capabilities_upper = struct.unpack('<H', data[pos:pos+2])[0]
            capabilities = (capabilities_upper << 16) | capabilities_lower
            pos += 2
        else:
            capabilities = capabilities_lower

        # Auth plugin data length
        auth_plugin_data_len = data[pos] if pos < len(data) else 0
        pos += 1

        # Reserved (10 bytes)
        pos += 10

        # Auth plugin data part 2
        if auth_plugin_data_len > 8:
            auth_data_len = max(13, auth_plugin_data_len - 8)
            auth_plugin_data_part2 = data[pos:pos+auth_data_len]
            # Remove trailing null
            if auth_plugin_data_part2 and auth_plugin_data_part2[-1] == 0:
                auth_plugin_data_part2 = auth_plugin_data_part2[:-1]
        else:
            auth_plugin_data_part2 = b''

        auth_plugin_data = auth_plugin_data_part1 + auth_plugin_data_part2

        return {
            'protocol_version': protocol_version,
            'version': version,
            'thread_id': thread_id,
            'auth_plugin_data': auth_plugin_data,
            'capabilities': capabilities,
            'charset': charset
        }

    except Exception as e:
        return None


def build_auth_packet(username, password, database, auth_plugin_data, capabilities, charset):
    """
    Build MySQL authentication packet.

    Args:
        username: Username string
        password: Password string (empty for this test)
        database: Database name
        auth_plugin_data: Challenge from server
        capabilities: Server capabilities
        charset: Character set

    Returns:
        Bytes representing the authentication packet
    """
    # Client capabilities
    client_capabilities = 0x000FA685  # Standard client flags

    # Max packet size
    max_packet_size = 0x01000000

    # Build packet payload
    payload = b''

    # Client capabilities (4 bytes)
    payload += struct.pack('<I', client_capabilities)

    # Max packet size (4 bytes)
    payload += struct.pack('<I', max_packet_size)

    # Charset (1 byte)
    payload += struct.pack('<B', charset)

    # Reserved (23 bytes of zeros)
    payload += b'\x00' * 23

    # Username (null-terminated)
    payload += username.encode('utf-8') + b'\x00'

    # Password authentication
    if password:
        # For non-empty password, we'd use mysql_native_password
        # But for empty password, auth response is just 0x00
        payload += b'\x00'
    else:
        # Empty password = 0x00 length byte
        payload += b'\x00'

    # Database (null-terminated) - optional
    if database:
        payload += database.encode('utf-8') + b'\x00'

    # Build packet with header
    packet_length = len(payload)
    packet = struct.pack('<I', packet_length)[0:3]  # 3 bytes length
    packet += b'\x01'  # Sequence number
    packet += payload

    return packet
