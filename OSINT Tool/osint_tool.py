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
import os
from pathlib import Path

class OSINTTool:
    """Main OSINT Tool class for gathering intelligence."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.api_keys = self.load_api_keys()
    
    def load_api_keys(self):
        """Load API keys from config file."""
        config_path = Path.home() / '.osint_tool' / 'api_keys.json'
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def save_api_keys(self, api_keys):
        """Save API keys to config file."""
        config_path = Path.home() / '.osint_tool'
        config_path.mkdir(parents=True, exist_ok=True)
        with open(config_path / 'api_keys.json', 'w') as f:
            json.dump(api_keys, f, indent=2)
        self.api_keys = api_keys
    
    def set_api_key(self, service, key):
        """Set an API key for a service."""
        self.api_keys[service] = key
        self.save_api_keys(self.api_keys)
    
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
    
    def hibp_breach_check(self, email: str) -> Dict[str, Any]:
        """
        Check if email has been in any data breaches using Have I Been Pwned API.
        """
        try:
            # Use HIBP API (requires API key for rate limit increase)
            api_key = self.api_keys.get('hibp', '')
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
            headers = {
                'User-Agent': 'OSINT Tool',
                'hibp-api-key': api_key
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {
                    'email': email,
                    'found': False,
                    'breaches': [],
                    'message': 'No breaches found'
                }
            elif response.status_code == 401:
                return {'error': 'Invalid HIBP API key'}
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded. Please add your HIBP API key.'}
            
            response.raise_for_status()
            breaches = response.json()
            
            breach_list = []
            for breach in breaches:
                breach_list.append({
                    'name': breach.get('Name'),
                    'title': breach.get('Title'),
                    'domain': breach.get('Domain'),
                    'breach_date': breach.get('BreachDate'),
                    'added_date': breach.get('AddedDate'),
                    'pwn_count': breach.get('PwnCount'),
                    'description': breach.get('Description'),
                    'data_classes': breach.get('DataClasses', []),
                    'is_verified': breach.get('IsVerified'),
                    'is_fabricated': breach.get('IsFabricated'),
                    'is_sensitive': breach.get('IsSensitive'),
                    'is_retired': breach.get('IsRetired'),
                    'is_spam_list': breach.get('IsSpamList')
                })
            
            return {
                'email': email,
                'found': True,
                'breach_count': len(breach_list),
                'breaches': breach_list
            }
        except Exception as e:
            return {'error': str(e)}
    
    def virustotal_ip_scan(self, ip: str) -> Dict[str, Any]:
        """
        Scan IP address using VirusTotal API.
        """
        try:
            api_key = self.api_keys.get('virustotal', '')
            if not api_key:
                return {'error': 'VirusTotal API key required'}
            
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': api_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif response.status_code == 404:
                return {'error': 'IP not found in VirusTotal database'}
            
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get('data', {}).get('attributes', {})
            
            # Extract reputation and analysis
            return {
                'ip': ip,
                'reputation': attributes.get('reputation', 0),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'country': attributes.get('country'),
                'continent': attributes.get('continent'),
                'network': attributes.get('network'),
                'asn': attributes.get('asn'),
                'as_owner': attributes.get('as_owner'),
                'total_votes': attributes.get('total_votes', {}),
                'last_https_certificate': attributes.get('last_https_certificate', {}),
                'last_modification_date': attributes.get('last_modification_date'),
                'creation_date': attributes.get('creation_date')
            }
        except Exception as e:
            return {'error': str(e)}
    
    def virustotal_domain_scan(self, domain: str) -> Dict[str, Any]:
        """
        Scan domain using VirusTotal API.
        """
        try:
            api_key = self.api_keys.get('virustotal', '')
            if not api_key:
                return {'error': 'VirusTotal API key required'}
            
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': api_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif response.status_code == 404:
                return {'error': 'Domain not found in VirusTotal database'}
            
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get('data', {}).get('attributes', {})
            
            return {
                'domain': domain,
                'reputation': attributes.get('reputation', 0),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'last_dns_records': attributes.get('last_dns_records', []),
                'categories': attributes.get('categories', {}),
                'whois': attributes.get('whois', ''),
                'creation_date': attributes.get('creation_date'),
                'last_modification_date': attributes.get('last_modification_date'),
                'last_update_date': attributes.get('last_update_date'),
                'total_votes': attributes.get('total_votes', {})
            }
        except Exception as e:
            return {'error': str(e)}
    
    def spokeo_search(self, query: str, search_type: str = 'email') -> Dict[str, Any]:
        """
        Search Spokeo API (requires API key).
        Note: Spokeo API requires commercial subscription.
        """
        try:
            api_key = self.api_keys.get('spokeo', '')
            if not api_key:
                return {'error': 'Spokeo API key required'}
            
            # Spokeo API endpoint (this is a placeholder - actual endpoint may vary)
            # Spokeo's API is not publicly documented and requires business partnership
            url = 'https://api.spokeo.com/v1/search'
            
            params = {
                'key': api_key,
                'query': query,
                'type': search_type
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid Spokeo API key'}
            elif response.status_code == 403:
                return {'error': 'Spokeo API access forbidden. Check subscription.'}
            
            response.raise_for_status()
            data = response.json()
            
            return {
                'query': query,
                'search_type': search_type,
                'results': data.get('results', []),
                'total_results': data.get('total', 0)
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
