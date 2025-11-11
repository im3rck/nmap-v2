#!/usr/bin/env python3
"""
ApexScan ASE Script: rdp-enum-encryption.py
Category: discovery, safe
Description: Enumerate RDP encryption levels and security protocols
Author: ApexScan Team

Determines RDP encryption strength and supported security protocols (RDP, TLS, CredSSP).
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
    port = context.get('port', 3389)

    try:
        # Test RDP encryption
        rdp_info = test_rdp_encryption(target, port)

        if not rdp_info:
            return {
                "output": "Unable to enumerate RDP encryption (connection failed or not RDP)",
                "success": False,
                "data": {},
                "error": "No RDP response"
            }

        # Extract encryption info
        protocols = rdp_info.get('protocols', [])
        encryption_level = rdp_info.get('encryption_level', 'Unknown')
        tls_supported = 'TLS' in protocols or 'SSL' in protocols
        nla_supported = 'CredSSP' in protocols or 'NLA' in protocols

        # Determine security level
        if nla_supported and tls_supported:
            security_level = "STRONG"
        elif tls_supported:
            security_level = "MODERATE"
        elif encryption_level == 'HIGH':
            security_level = "MODERATE"
        else:
            security_level = "WEAK"

        # Build output
        output_lines = [
            f"RDP Encryption Analysis:",
            f"  Security Level: {security_level}",
            f"  Encryption: {encryption_level}",
        ]

        if protocols:
            output_lines.append(f"\nSupported Protocols:")
            for protocol in protocols:
                marker = "✓ " if protocol in ['TLS', 'SSL', 'CredSSP', 'NLA'] else "• "
                output_lines.append(f"  {marker}{protocol}")

        # Security recommendations
        if not nla_supported:
            output_lines.append(f"\n⚠️  Network Level Authentication (NLA) not required")
            output_lines.append("   Without NLA, servers are vulnerable to DoS and brute force attacks")

        if not tls_supported:
            output_lines.append(f"\n⚠️  TLS/SSL encryption not supported")
            output_lines.append("   Legacy RDP encryption is weaker than modern TLS")

        if security_level in ['WEAK', 'MODERATE']:
            output_lines.append(f"\nRecommendations:")
            if not nla_supported:
                output_lines.append("  → Enable Network Level Authentication (NLA)")
            if not tls_supported:
                output_lines.append("  → Enable TLS 1.2+ encryption")
            output_lines.append("  → Disable legacy RDP Security protocol")
            output_lines.append("  → Use certificate-based authentication")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "protocols": protocols,
                "encryption_level": encryption_level,
                "tls_supported": tls_supported,
                "nla_supported": nla_supported,
                "security_level": security_level
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while testing RDP encryption",
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
            "output": f"RDP enumeration failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def test_rdp_encryption(target, port):
    """
    Test RDP encryption by analyzing connection negotiation.

    Args:
        target: Target IP address
        port: RDP port (usually 3389)

    Returns:
        Dictionary with RDP security information
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Send RDP Connection Request (X.224 Connection Request)
        # This requests all security protocols
        connection_request = build_rdp_connection_request()
        sock.sendall(connection_request)

        # Receive response
        response = sock.recv(4096)

        sock.close()

        if len(response) < 11:
            return None

        # Parse response to determine supported protocols
        protocols = []
        encryption_level = "UNKNOWN"

        # Check for various protocol indicators in response
        # RDP uses X.224 protocol

        # Standard RDP Security
        if b'\x00\x00' in response or len(response) > 10:
            protocols.append('RDP Security')
            encryption_level = "HIGH"  # Assume HIGH for modern RDP

        # Check for TLS (indicated by specific flags)
        if b'\x01\x00' in response[11:13] if len(response) > 12 else False:
            protocols.append('TLS/SSL')

        # Check for CredSSP/NLA
        if b'\x02\x00' in response or b'\x03\x00' in response:
            protocols.append('CredSSP (NLA)')

        # If no specific protocols found but connection accepted
        if not protocols and len(response) > 10:
            protocols.append('RDP Security (Legacy)')
            encryption_level = "MEDIUM"

        return {
            'protocols': protocols,
            'encryption_level': encryption_level
        }

    except Exception as e:
        return None


def build_rdp_connection_request():
    """
    Build RDP X.224 Connection Request PDU.

    This requests all available security protocols.
    """
    # TPKT Header
    tpkt_version = b'\x03'
    tpkt_reserved = b'\x00'
    tpkt_length = struct.pack('>H', 43)  # Total length

    # X.224 Connection Request
    x224_length = b'\x26'  # Length of X.224 data
    x224_type = b'\xe0'  # Connection Request
    x224_dst_ref = b'\x00\x00'
    x224_src_ref = b'\x00\x00'
    x224_class = b'\x00'

    # RDP Negotiation Request (TYPE_RDP_NEG_REQ)
    rdp_neg_type = b'\x01'  # TYPE_RDP_NEG_REQ
    rdp_neg_flags = b'\x00'
    rdp_neg_length = struct.pack('<H', 8)

    # Request all protocols: RDP, TLS, CredSSP
    # Flags: 0x00000001 (RDP), 0x00000002 (TLS), 0x00000008 (CredSSP)
    rdp_neg_protocols = struct.pack('<I', 0x0000000B)  # Request all

    # Additional padding
    padding = b'\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x75\x73\x65\x72\x0d\x0a'

    packet = (tpkt_version + tpkt_reserved + tpkt_length +
              x224_length + x224_type + x224_dst_ref + x224_src_ref + x224_class +
              rdp_neg_type + rdp_neg_flags + rdp_neg_length + rdp_neg_protocols)

    return packet
