#!/usr/bin/env python3
"""
ApexScan Script: HTTP Title Grabber
Category: discovery, safe
Description: Grabs and displays the HTML title from web servers
Author: ApexScan Team
"""

import socket
import re

def main(context):
    """
    Main entry point for ASE script
    
    Args:
        context: Dictionary with target, port, service, version, os, banner
    
    Returns:
        Dictionary with output, success, data, error
    """
    target = context.get('target')
    port = context.get('port', 80)
    
    try:
        # Connect to HTTP server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # Send HTTP GET request
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        
        # Receive response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            
            # Stop after receiving enough for the title
            if len(response) > 50000:
                break
        
        sock.close()
        
        # Parse HTML for title
        response_str = response.decode('utf-8', errors='ignore')
        
        # Extract title using regex
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response_str, re.IGNORECASE | re.DOTALL)
        
        if title_match:
            title = title_match.group(1).strip()
            return {
                'output': f"Title: {title}",
                'success': True,
                'data': {
                    'title': title,
                    'url': f"http://{target}:{port}/"
                },
                'error': None
            }
        else:
            return {
                'output': "No HTML title found",
                'success': True,
                'data': {},
                'error': None
            }
            
    except Exception as e:
        return {
            'output': f"Failed to grab title: {str(e)}",
            'success': False,
            'data': {},
            'error': str(e)
        }
