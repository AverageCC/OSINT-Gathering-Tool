#!/usr/bin/env python3
"""
Basic OSINT Tool - Open Source Intelligence Gathering Tool
A simple tool for gathering information about IP addresses, domains, and emails.
"""

import argparse
import sys
import json
from typing import Dict, Any
import requests
import socket
import whois
import dns.resolver

class OSINTTool:
    """Main OSINT Tool class for gathering intelligence."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """
        Get geolocation information for an IP address.
        Uses ip-api.com free API.
        """
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}')
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'fail':
                return {'error': data.get('message', 'Failed to get IP information')}
            
            return {
                'ip': data.get('query'),
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'zip': data.get('zip'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'as': data.get('as'),
                'is_mobile': data.get('mobile'),
                'is_proxy': data.get('proxy'),
                'is_vpn': data.get('hosting')
            }
        except Exception as e:
            return {'error': str(e)}
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for a domain.
        """
        try:
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            w = whois.whois(domain)
            
            result = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
            
            # Filter out None values
            return {k: v for k, v in result.items() if v is not None}
        except Exception as e:
            return {'error': str(e)}
    
    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """
        Perform DNS enumeration for a domain.
        """
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        results = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results[record_type] = []
            except dns.resolver.NXDOMAIN:
                results[record_type] = ['Domain does not exist']
            except Exception as e:
                results[record_type] = [f'Error: {str(e)}']
        
        # Get IP address
        try:
            ip = socket.gethostbyname(domain)
            results['ip_address'] = ip
        except Exception as e:
            results['ip_address'] = f'Error: {str(e)}'
        
        return results
    
    def email_validation(self, email: str) -> Dict[str, Any]:
        """
        Basic email validation and information gathering.
        """
        result = {}
        
        # Basic format validation
        if '@' not in email or '.' not in email.split('@')[1]:
            result['valid_format'] = False
            result['error'] = 'Invalid email format'
            return result
        
        result['valid_format'] = True
        
        # Extract domain
        domain = email.split('@')[1]
        result['domain'] = domain
        
        # Check if domain has MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(rdata) for rdata in mx_records]
            result['domain_has_mail'] = True
        except:
            result['mx_records'] = []
            result['domain_has_mail'] = False
        
        # Check domain existence
        try:
            socket.gethostbyname(domain)
            result['domain_exists'] = True
        except:
            result['domain_exists'] = False
        
        return result
    
    def reverse_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup on an IP address.
        """
        try:
            hostname = socket.gethostbyaddr(ip)
            return {
                'ip': ip,
                'hostname': hostname[0],
                'aliases': hostname[1],
                'ip_addresses': hostname[2]
            }
        except Exception as e:
            return {'error': str(e)}


def print_results(data: Dict[str, Any], format: str = 'pretty'):
    """Print results in specified format."""
    if format == 'json':
        print(json.dumps(data, indent=2, default=str))
    else:
        print_pretty(data)


def print_pretty(data: Dict[str, Any], indent: int = 0):
    """Print results in a pretty format."""
    prefix = '  ' * indent
    for key, value in data.items():
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            print_pretty(value, indent + 1)
        elif isinstance(value, list):
            print(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    print_pretty(item, indent + 1)
                else:
                    print(f"{prefix}  - {item}")
        else:
            print(f"{prefix}{key}: {value}")


def main():
    parser = argparse.ArgumentParser(
        description='Basic OSINT Tool - Open Source Intelligence Gathering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_tool.py --ip 8.8.8.8
  python osint_tool.py --domain example.com --whois
  python osint_tool.py --domain example.com --dns
  python osint_tool.py --email test@example.com
  python osint_tool.py --ip 8.8.8.8 --reverse
        """
    )
    
    parser.add_argument('--ip', help='IP address to investigate')
    parser.add_argument('--domain', help='Domain to investigate')
    parser.add_argument('--email', help='Email address to validate')
    parser.add_argument('--geo', action='store_true', help='IP geolocation lookup')
    parser.add_argument('--whois', action='store_true', help='WHOIS domain lookup')
    parser.add_argument('--dns', action='store_true', help='DNS enumeration')
    parser.add_argument('--validate', action='store_true', help='Email validation')
    parser.add_argument('--reverse', action='store_true', help='Reverse IP lookup')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    args = parser.parse_args()
    
    if not any([args.ip, args.domain, args.email]):
        parser.print_help()
        sys.exit(1)
    
    tool = OSINTTool()
    
    if args.ip:
        if args.geo or not any([args.whois, args.dns, args.validate, args.reverse]):
            print("IP Geolocation:")
            results = tool.ip_geolocation(args.ip)
            print_results(results, 'json' if args.json else 'pretty')
            print()
        
        if args.reverse:
            print("Reverse IP Lookup:")
            results = tool.reverse_ip_lookup(args.ip)
            print_results(results, 'json' if args.json else 'pretty')
    
    if args.domain:
        if args.whois:
            print("WHOIS Lookup:")
            results = tool.whois_lookup(args.domain)
            print_results(results, 'json' if args.json else 'pretty')
            print()
        
        if args.dns:
            print("DNS Enumeration:")
            results = tool.dns_enumeration(args.domain)
            print_results(results, 'json' if args.json else 'pretty')
    
    if args.email:
        if args.validate or True:
            print("Email Validation:")
            results = tool.email_validation(args.email)
            print_results(results, 'json' if args.json else 'pretty')


if __name__ == '__main__':
    main()
