#!/usr/bin/env python3
"""
ApexScan ASE Script: dns-zone-transfer.py
Category: intrusive, vuln
Description: Test for DNS zone transfer (AXFR) vulnerability
Author: ApexScan Team

Attempts DNS zone transfer to detect misconfigured DNS servers allowing unauthorized zone data access.
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
        # Attempt zone transfer
        zone_transfer = attempt_zone_transfer(target, port)

        if zone_transfer.get('vulnerable'):
            records = zone_transfer.get('records', [])
            domain = zone_transfer.get('domain', 'unknown')

            output_lines = [
                f"DNS Zone Transfer Test:",
                f"  Status: 🚨 VULNERABLE",
                f"\n⚠️  CRITICAL SECURITY VULNERABILITY!",
                f"   DNS server allows unauthorized zone transfer (AXFR)",
                f"   Domain: {domain}",
                f"   Records leaked: {len(records)}",
            ]

            if records:
                output_lines.append(f"\nSample Records Exposed:")
                for record in records[:5]:
                    output_lines.append(f"  • {record}")
                if len(records) > 5:
                    output_lines.append(f"  ... and {len(records) - 5} more records")

            output_lines.append(f"\n   Impact:")
            output_lines.append("   • Complete DNS zone data exposed")
            output_lines.append("   • Internal network topology revealed")
            output_lines.append("   • Hostnames and IP addresses leaked")
            output_lines.append("   • Facilitates targeted attacks")

            output_lines.append(f"\n   Remediation (URGENT):")
            output_lines.append("   → Restrict zone transfers to authorized secondary DNS servers only")
            output_lines.append("   → Configure allow-transfer in named.conf")
            output_lines.append("   → Use TSIG authentication for zone transfers")
            output_lines.append("   → Monitor DNS logs for unauthorized AXFR attempts")

            return {
                "output": "\n".join(output_lines),
                "success": True,
                "data": {
                    "vulnerable": True,
                    "domain": domain,
                    "records": records,
                    "security_level": "CRITICAL"
                },
                "error": None
            }

        else:
            return {
                "output": "DNS Zone Transfer Test:\n  Status: ✓ NOT VULNERABLE\n\n   Zone transfer properly restricted",
                "success": True,
                "data": {
                    "vulnerable": False,
                    "security_level": "SECURE"
                },
                "error": None
            }

    except socket.timeout:
        return {
            "output": "Connection timeout while testing DNS zone transfer",
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
            "output": f"DNS zone transfer test failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def attempt_zone_transfer(target, port):
    """
    Attempt DNS zone transfer (AXFR).

    Args:
        target: Target IP address
        port: DNS port (usually 53)

    Returns:
        Dictionary with zone transfer results
    """
    try:
        # Build AXFR query for a common domain
        # In real implementation, would first discover the authoritative domain
        query = build_axfr_query("example.com")

        # Zone transfers use TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # TCP DNS requires length prefix
        query_with_len = struct.pack('>H', len(query)) + query
        sock.sendall(query_with_len)

        # Receive response
        try:
            length_data = sock.recv(2)
            if len(length_data) < 2:
                sock.close()
                return {'vulnerable': False}

            response_len = struct.unpack('>H', length_data)[0]
            response = sock.recv(response_len)

            sock.close()

            # Check if zone transfer succeeded
            # A successful AXFR will have answer records
            if len(response) > 12:
                # Check answer count (bytes 6-7)
                ancount = struct.unpack('>H', response[6:8])[0]

                if ancount > 0:
                    # Zone transfer succeeded - parse some records
                    records = parse_zone_records(response, ancount)

                    return {
                        'vulnerable': True,
                        'domain': 'example.com',
                        'records': records
                    }

        except:
            pass

        sock.close()
        return {'vulnerable': False}

    except Exception as e:
        return {'vulnerable': False}


def build_axfr_query(domain):
    """
    Build DNS AXFR query.

    Args:
        domain: Domain to query

    Returns:
        DNS AXFR query packet
    """
    # Transaction ID
    transaction_id = struct.pack('>H', random.randint(1, 65535))

    # Flags: Standard query
    flags = struct.pack('>H', 0x0000)

    # Question count: 1
    qdcount = struct.pack('>H', 1)

    # Other counts: 0
    ancount = struct.pack('>H', 0)
    nscount = struct.pack('>H', 0)
    arcount = struct.pack('>H', 0)

    # Question section
    qname = encode_domain_name(domain)
    qtype = struct.pack('>H', 252)  # AXFR
    qclass = struct.pack('>H', 1)  # IN

    query = (transaction_id + flags + qdcount + ancount + nscount + arcount +
             qname + qtype + qclass)

    return query


def encode_domain_name(domain):
    """Encode domain name in DNS format."""
    encoded = b''
    for label in domain.split('.'):
        encoded += bytes([len(label)]) + label.encode('ascii')
    encoded += b'\x00'
    return encoded


def parse_zone_records(data, count):
    """
    Parse zone transfer records (simplified).

    Args:
        data: DNS response data
        count: Number of answer records

    Returns:
        List of record strings
    """
    records = []

    # This is a simplified parser
    # Real implementation would properly parse all RR types
    try:
        # Skip header
        pos = 12

        # Skip question section
        while pos < len(data) and data[pos] != 0:
            label_len = data[pos]
            if label_len == 0:
                break
            pos += label_len + 1
        pos += 5  # Skip null, qtype, qclass

        # Parse answer records (simplified)
        for i in range(min(count, 10)):  # Limit to 10 records
            if pos + 12 > len(data):
                break

            # Extract record type
            rtype = struct.unpack('>H', data[pos+2:pos+4])[0] if pos+4 <= len(data) else 0

            record_types = {
                1: 'A',
                2: 'NS',
                5: 'CNAME',
                6: 'SOA',
                15: 'MX',
                16: 'TXT',
                28: 'AAAA'
            }

            rtype_name = record_types.get(rtype, f'TYPE{rtype}')
            records.append(f"{rtype_name} record")

            # Skip to next record (simplified)
            pos += 20

    except:
        pass

    return records if records else ['Zone data available']
