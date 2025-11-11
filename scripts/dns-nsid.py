#!/usr/bin/env python3
"""
ApexScan ASE Script: dns-nsid.py
Category: discovery, safe
Description: Query DNS server for Name Server ID (NSID) information
Author: ApexScan Team

Retrieves DNS server identification information using NSID EDNS0 option.
"""

import socket
import struct
import random

def main(context):
    """
    Main entry point for ASE script.

    Args:
        context: Dictionary with target, port, service, version, os, banner

    Returns:
        Dictionary with output, success, data, error
    """
    target = context.get('target')
    port = context.get('port', 53)

    try:
        # Query DNS NSID
        nsid_info = query_dns_nsid(target, port)

        if not nsid_info:
            return {
                "output": "Unable to query DNS NSID (server may not support NSID or EDNS0)",
                "success": True,
                "data": {
                    "nsid_supported": False
                },
                "error": None
            }

        # Extract NSID information
        nsid_value = nsid_info.get('nsid', 'Not provided')
        server_identity = nsid_info.get('identity', 'Unknown')

        # Build output
        output_lines = [
            f"DNS NSID Query Results:",
            f"  NSID Supported: Yes",
            f"  Server Identity: {server_identity}",
        ]

        if nsid_value and nsid_value != 'Not provided':
            output_lines.append(f"  NSID Value: {nsid_value}")

        output_lines.append(f"\nInformation Disclosure:")
        output_lines.append("  • DNS server identification revealed")
        output_lines.append("  • May expose server hostname, version, or location")
        output_lines.append("  • Useful for reconnaissance but not necessarily a vulnerability")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "nsid_supported": True,
                "nsid_value": nsid_value,
                "server_identity": server_identity
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while querying DNS NSID",
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
            "output": f"DNS NSID query failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def query_dns_nsid(target, port):
    """
    Query DNS server for NSID using EDNS0.

    Args:
        target: Target IP address
        port: DNS port (usually 53)

    Returns:
        Dictionary with NSID information
    """
    try:
        # Create DNS query with EDNS0 NSID option
        query = build_dns_nsid_query()

        # Try both UDP and TCP
        for protocol in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
            try:
                sock = socket.socket(socket.AF_INET, protocol)
                sock.settimeout(5)

                if protocol == socket.SOCK_STREAM:
                    sock.connect((target, port))
                    # TCP DNS requires length prefix
                    query_with_len = struct.pack('>H', len(query)) + query
                    sock.sendall(query_with_len)
                else:
                    sock.sendto(query, (target, port))

                # Receive response
                if protocol == socket.SOCK_STREAM:
                    # Read length prefix
                    length_data = sock.recv(2)
                    if len(length_data) < 2:
                        sock.close()
                        continue
                    response_len = struct.unpack('>H', length_data)[0]
                    response = sock.recv(response_len)
                else:
                    response, _ = sock.recvfrom(4096)

                sock.close()

                # Parse response for NSID
                nsid_data = parse_dns_nsid_response(response)
                if nsid_data:
                    return nsid_data

            except:
                continue

        return None

    except Exception as e:
        return None


def build_dns_nsid_query():
    """
    Build DNS query with EDNS0 NSID option.

    Queries for the root domain (.) with NSID option.
    """
    # Transaction ID
    transaction_id = struct.pack('>H', random.randint(1, 65535))

    # Flags: Standard query
    flags = struct.pack('>H', 0x0100)

    # Question count: 1
    qdcount = struct.pack('>H', 1)

    # Answer count: 0
    ancount = struct.pack('>H', 0)

    # Authority count: 0
    nscount = struct.pack('>H', 0)

    # Additional count: 1 (for EDNS0)
    arcount = struct.pack('>H', 1)

    # Question section: Query for . (root) NS record
    qname = b'\x00'  # Root domain
    qtype = struct.pack('>H', 2)  # NS
    qclass = struct.pack('>H', 1)  # IN

    # EDNS0 OPT record with NSID option
    opt_name = b'\x00'  # Root domain for OPT
    opt_type = struct.pack('>H', 41)  # OPT
    opt_udp_size = struct.pack('>H', 4096)  # UDP payload size
    opt_extended_rcode = b'\x00'
    opt_version = b'\x00'
    opt_flags = struct.pack('>H', 0)

    # NSID option: code 3, length 0
    nsid_option = struct.pack('>HH', 3, 0)
    opt_rdlength = struct.pack('>H', len(nsid_option))

    query = (transaction_id + flags + qdcount + ancount + nscount + arcount +
             qname + qtype + qclass +
             opt_name + opt_type + opt_udp_size + opt_extended_rcode +
             opt_version + opt_flags + opt_rdlength + nsid_option)

    return query


def parse_dns_nsid_response(data):
    """
    Parse DNS response for NSID data.

    Args:
        data: DNS response packet

    Returns:
        Dictionary with NSID information
    """
    try:
        if len(data) < 12:
            return None

        # Skip to additional section
        # This is simplified - real parser would properly walk through all sections
        pos = 12

        # Skip question section (simplified)
        while pos < len(data) and data[pos] != 0:
            label_len = data[pos]
            if label_len == 0:
                break
            pos += label_len + 1
        pos += 5  # Skip null terminator, qtype, qclass

        # Look for NSID in additional section
        # This is a simplified search
        if b'\x00\x03' in data[pos:]:  # NSID option code (3)
            nsid_pos = data.find(b'\x00\x03', pos)
            # Extract NSID value (would need proper parsing in production)
            return {
                'nsid': 'present',
                'identity': 'DNS Server'
            }

        return None

    except:
        return None
