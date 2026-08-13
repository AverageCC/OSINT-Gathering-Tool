"""
Utility functions for OSINT Tool
Contains shared functions for entity extraction, result formatting, and data processing.
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Set


def extract_ips_from_text(text: str) -> List[str]:
    """Extract IP addresses from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, str(text))


def extract_domains_from_text(text: str) -> List[str]:
    """Extract domain names from text."""
    domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'
    return re.findall(domain_pattern, str(text))


def format_results(data: Dict[str, Any], result_type: str) -> str:
    """Format results for better readability."""
    if 'error' in data:
        return f"❌ Error: {data['error']}"
    
    output = []
    output.append("=" * 60)
    output.append(f"📊 OSINT Results - {result_type.upper()} LOOKUP")
    output.append(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("=" * 60)
    output.append("")
    
    if result_type == 'ip':
        output.append("🌍 GEOLOCATION INFORMATION")
        output.append("-" * 40)
        if 'ip' in data:
            output.append(f"IP Address: {data['ip']}")
        if 'country' in data:
            output.append(f"Country: {data['country']} ({data.get('country_code', 'N/A')})")
        if 'region' in data:
            output.append(f"Region: {data['region']}")
        if 'city' in data:
            output.append(f"City: {data['city']}")
        if 'zip' in data:
            output.append(f"Postal Code: {data['zip']}")
        if 'lat' in data and 'lon' in data:
            output.append(f"Coordinates: {data['lat']}, {data['lon']}")
        if 'timezone' in data:
            output.append(f"Timezone: {data['timezone']}")
        output.append("")
        output.append("🏢 NETWORK INFORMATION")
        output.append("-" * 40)
        if 'isp' in data:
            output.append(f"ISP: {data['isp']}")
        if 'org' in data:
            output.append(f"Organization: {data['org']}")
        if 'as' in data:
            output.append(f"AS Number: {data['as']}")
        output.append("")
        output.append("🔒 SECURITY FLAGS")
        output.append("-" * 40)
        output.append(f"Mobile: {'Yes' if data.get('is_mobile') else 'No'}")
        output.append(f"Proxy: {'Yes' if data.get('is_proxy') else 'No'}")
        output.append(f"VPN/Hosting: {'Yes' if data.get('is_vpn') else 'No'}")
        
    elif result_type == 'domain':
        if 'domain_name' in data or 'registrar' in data:
            output.append("📋 WHOIS INFORMATION")
            output.append("-" * 40)
            if 'domain_name' in data:
                output.append(f"Domain Name: {data['domain_name']}")
            if 'registrar' in data:
                output.append(f"Registrar: {data['registrar']}")
            if 'creation_date' in data:
                output.append(f"Created: {data['creation_date']}")
            if 'expiration_date' in data:
                output.append(f"Expires: {data['expiration_date']}")
            if 'name_servers' in data:
                output.append(f"Name Servers: {', '.join(str(ns) for ns in data['name_servers']) if isinstance(data['name_servers'], list) else data['name_servers']}")
            if 'status' in data:
                output.append(f"Status: {data['status']}")
            output.append("")
        
        if 'A' in data or 'MX' in data:
            output.append("🌐 DNS RECORDS")
            output.append("-" * 40)
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for rt in record_types:
                if rt in data and data[rt]:
                    output.append(f"{rt} Records:")
                    if isinstance(data[rt], list):
                        for record in data[rt]:
                            output.append(f"  • {record}")
                    else:
                        output.append(f"  • {data[rt]}")
            if 'ip_address' in data:
                output.append(f"\nIP Address: {data['ip_address']}")
                
    elif result_type == 'email':
        output.append("📧 EMAIL VALIDATION")
        output.append("-" * 40)
        output.append(f"Valid Format: {'✅ Yes' if data.get('valid_format') else '❌ No'}")
        if 'domain' in data:
            output.append(f"Domain: {data['domain']}")
        output.append(f"Domain Exists: {'✅ Yes' if data.get('domain_exists') else '❌ No'}")
        output.append(f"Domain Has Mail: {'✅ Yes' if data.get('domain_has_mail') else '❌ No'}")
        if 'mx_records' in data and data['mx_records']:
            output.append("\nMX Records:")
            for mx in data['mx_records']:
                output.append(f"  • {mx}")
    
    elif result_type == 'reverse':
        output.append("🔄 REVERSE DNS LOOKUP")
        output.append("-" * 40)
        if 'ip' in data:
            output.append(f"IP Address: {data['ip']}")
        if 'hostname' in data:
            output.append(f"Hostname: {data['hostname']}")
        if 'aliases' in data and data['aliases']:
            output.append(f"Aliases: {', '.join(data['aliases'])}")
        if 'ip_addresses' in data and data['ip_addresses']:
            output.append(f"IP Addresses: {', '.join(data['ip_addresses'])}")
    
    elif result_type == 'security':
        if 'email' in data and 'breaches' in data:
            # HIBP results
            output.append("🔓 HAVE I BEEN PWNED - BREACH CHECK")
            output.append("-" * 40)
            output.append(f"Email: {data['email']}")
            output.append(f"Breaches Found: {'Yes' if data.get('found') else 'No'}")
            if data.get('breach_count'):
                output.append(f"Total Breaches: {data['breach_count']}")
            if data.get('breaches'):
                output.append("")
                output.append("BREACH DETAILS:")
                for i, breach in enumerate(data['breaches'], 1):
                    output.append(f"\n{i}. {breach.get('name', 'Unknown')}")
                    output.append(f"   Title: {breach.get('title', 'N/A')}")
                    output.append(f"   Domain: {breach.get('domain', 'N/A')}")
                    output.append(f"   Breach Date: {breach.get('breach_date', 'N/A')}")
                    output.append(f"   Pwn Count: {breach.get('pwn_count', 'N/A')}")
                    output.append(f"   Data Classes: {', '.join(breach.get('data_classes', []))}")
                    output.append(f"   Verified: {'Yes' if breach.get('is_verified') else 'No'}")
                    output.append(f"   Sensitive: {'Yes' if breach.get('is_sensitive') else 'No'}")
        
        elif 'ip' in data and 'reputation' in data:
            # VirusTotal IP results
            output.append("🦠 VIRUSTOTAL - IP SCAN")
            output.append("-" * 40)
            output.append(f"IP: {data['ip']}")
            output.append(f"Reputation Score: {data['reputation']}")
            if data.get('country'):
                output.append(f"Country: {data['country']}")
            if data.get('asn'):
                output.append(f"ASN: {data['asn']}")
            if data.get('as_owner'):
                output.append(f"AS Owner: {data['as_owner']}")
            if data.get('last_analysis_stats'):
                output.append("")
                output.append("ANALYSIS STATS:")
                for engine, count in data['last_analysis_stats'].items():
                    output.append(f"  {engine}: {count}")
        
        elif 'domain' in data and 'reputation' in data:
            # VirusTotal Domain results
            output.append("🦠 VIRUSTOTAL - DOMAIN SCAN")
            output.append("-" * 40)
            output.append(f"Domain: {data['domain']}")
            output.append(f"Reputation Score: {data['reputation']}")
            if data.get('categories'):
                output.append(f"Categories: {data['categories']}")
            if data.get('creation_date'):
                output.append(f"Creation Date: {data['creation_date']}")
            if data.get('last_analysis_stats'):
                output.append("")
                output.append("ANALYSIS STATS:")
                for engine, count in data['last_analysis_stats'].items():
                    output.append(f"  {engine}: {count}")
        
        elif 'query' in data and 'search_type' in data:
            # Spokeo results
            output.append("👤 SPOKEO SEARCH")
            output.append("-" * 40)
            output.append(f"Query: {data['query']}")
            output.append(f"Search Type: {data['search_type']}")
            output.append(f"Total Results: {data.get('total_results', 0)}")
            if data.get('results'):
                output.append("")
                output.append("RESULTS:")
                for i, result in enumerate(data['results'][:10], 1):
                    output.append(f"\n{i}. {str(result)[:200]}...")
            
        elif 'person' in data and 'query' in data:
            # WhitePages results
            output.append("👤 WHITEPAGES PERSON SEARCH")
            output.append("-" * 40)
            output.append(f"Query: {data['query']}")
            output.append(f"Search Type: {data['search_type']}")
            output.append(f"Valid: {'✅ Yes' if data.get('is_valid') else '❌ No'}")
            output.append(f"Confidence Score: {data.get('confidence_score', 0)}")
            
            person = data.get('person', {})
            
            if person.get('name'):
                output.append("")
                output.append("NAME:")
                name = person['name']
                if isinstance(name, dict):
                    output.append(f"  Full Name: {name.get('full_name', 'N/A')}")
                    output.append(f"  First Name: {name.get('first_name', 'N/A')}")
                    output.append(f"  Middle Name: {name.get('middle_name', 'N/A')}")
                    output.append(f"  Last Name: {name.get('last_name', 'N/A')}")
                else:
                    output.append(f"  {name}")
            
            if person.get('age_range'):
                output.append("")
                output.append(f"Age Range: {person['age_range']}")
            
            if person.get('gender'):
                output.append(f"Gender: {person['gender']}")
            
            if person.get('location'):
                output.append("")
                output.append("LOCATION:")
                loc = person['location']
                if isinstance(loc, dict):
                    output.append(f"  City: {loc.get('city', 'N/A')}")
                    output.append(f"  State: {loc.get('state', 'N/A')}")
                    output.append(f"  Country: {loc.get('country', 'N/A')}")
                    output.append(f"  ZIP: {loc.get('postal_code', 'N/A')}")
            
            if person.get('emails'):
                output.append("")
                output.append("EMAILS:")
                for i, email in enumerate(person['emails'][:5], 1):
                    if isinstance(email, dict):
                        output.append(f"  {i}. {email.get('email_address', 'N/A')} (Type: {email.get('type', 'N/A')})")
                    else:
                        output.append(f"  {i}. {email}")
            
            if person.get('phones'):
                output.append("")
                output.append("PHONES:")
                for i, phone in enumerate(person['phones'][:5], 1):
                    if isinstance(phone, dict):
                        output.append(f"  {i}. {phone.get('phone_number', 'N/A')} (Type: {phone.get('type', 'N/A')})")
                    else:
                        output.append(f"  {i}. {phone}")
            
            if person.get('addresses'):
                output.append("")
                output.append("ADDRESSES:")
                for i, addr in enumerate(person['addresses'][:3], 1):
                    if isinstance(addr, dict):
                        output.append(f"  {i}. {addr.get('full_street_address', 'N/A')}")
                        output.append(f"     {addr.get('city', 'N/A')}, {addr.get('state', 'N/A')} {addr.get('postal_code', 'N/A')}")
                    else:
                        output.append(f"  {i}. {addr}")
            
            if person.get('associates'):
                output.append("")
                output.append(f"ASSOCIATES: {len(person['associates'])} found")
                for i, assoc in enumerate(person['associates'][:5], 1):
                    if isinstance(assoc, dict):
                        output.append(f"  {i}. {assoc.get('name', {}).get('full_name', 'N/A')}")
                    else:
                        output.append(f"  {i}. {assoc}")
            
            if person.get('criminal_records'):
                output.append("")
                output.append(f"CRIMINAL RECORDS: {len(person['criminal_records'])} found")
                for i, record in enumerate(person['criminal_records'][:3], 1):
                    if isinstance(record, dict):
                        output.append(f"  {i}. {record.get('type', 'N/A')} - {record.get('date', 'N/A')}")
                    else:
                        output.append(f"  {i}. {record}")
    
    output.append("")
    output.append("=" * 60)
    
    return "\n".join(output)


class EntityExtractor:
    """Extract and track entities from OSINT results."""
    
    def __init__(self):
        self.discovered_entities = {
            'ips': set(),
            'domains': set(),
            'emails': set()
        }
        self.entity_history = []
    
    def extract_entities(self, data: Dict[str, Any], result_type: str):
        """Extract entities from lookup results."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if result_type == 'ip':
            self._extract_from_ip(data, result_type, timestamp)
        elif result_type == 'domain':
            self._extract_from_domain(data, result_type, timestamp)
        elif result_type == 'email':
            self._extract_from_email(data, result_type, timestamp)
        elif result_type == 'reverse':
            self._extract_from_reverse(data, result_type, timestamp)
        elif result_type == 'security':
            self._extract_from_security(data, result_type, timestamp)
    
    def _extract_from_ip(self, data: Dict[str, Any], result_type: str, timestamp: str):
        """Extract entities from IP lookup results."""
        if 'ip' in data:
            self.discovered_entities['ips'].add(data['ip'])
            self.entity_history.append({'type': 'ip', 'value': data['ip'], 'source': result_type, 'timestamp': timestamp})
        
        for field in ['org', 'isp']:
            if field in data and data[field]:
                domains = extract_domains_from_text(str(data[field]))
                for domain in domains:
                    if domain not in self.discovered_entities['domains']:
                        self.discovered_entities['domains'].add(domain)
                        self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_{field}", 'timestamp': timestamp})
    
    def _extract_from_domain(self, data: Dict[str, Any], result_type: str, timestamp: str):
        """Extract entities from domain lookup results."""
        if 'domain_name' in data:
            domain = data['domain_name']
            if isinstance(domain, list):
                domain = domain[0] if domain else None
            if domain:
                self.discovered_entities['domains'].add(str(domain))
                self.entity_history.append({'type': 'domain', 'value': str(domain), 'source': result_type, 'timestamp': timestamp})
        
        if 'ip_address' in data and data['ip_address'] and not data['ip_address'].startswith('Error'):
            self.discovered_entities['ips'].add(data['ip_address'])
            self.entity_history.append({'type': 'ip', 'value': data['ip_address'], 'source': f"{result_type}_dns", 'timestamp': timestamp})
        
        if 'A' in data and data['A']:
            for record in data['A']:
                ips = extract_ips_from_text(record)
                for ip in ips:
                    if ip not in self.discovered_entities['ips']:
                        self.discovered_entities['ips'].add(ip)
                        self.entity_history.append({'type': 'ip', 'value': ip, 'source': f"{result_type}_A", 'timestamp': timestamp})
        
        if 'name_servers' in data and data['name_servers']:
            for ns in data['name_servers']:
                domains = extract_domains_from_text(str(ns))
                for domain in domains:
                    if domain not in self.discovered_entities['domains']:
                        self.discovered_entities['domains'].add(domain)
                        self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_ns", 'timestamp': timestamp})
        
        if 'emails' in data and data['emails']:
            for email in data['emails']:
                if email and '@' in str(email):
                    email_str = str(email).strip()
                    if email_str not in self.discovered_entities['emails']:
                        self.discovered_entities['emails'].add(email_str)
                        self.entity_history.append({'type': 'email', 'value': email_str, 'source': f"{result_type}_whois", 'timestamp': timestamp})
    
    def _extract_from_email(self, data: Dict[str, Any], result_type: str, timestamp: str, email_input: str = None):
        """Extract entities from email lookup results."""
        if email_input and '@' in email_input:
            if email_input not in self.discovered_entities['emails']:
                self.discovered_entities['emails'].add(email_input)
                self.entity_history.append({'type': 'email', 'value': email_input, 'source': result_type, 'timestamp': timestamp})
        
        if 'domain' in data:
            if data['domain'] not in self.discovered_entities['domains']:
                self.discovered_entities['domains'].add(data['domain'])
                self.entity_history.append({'type': 'domain', 'value': data['domain'], 'source': f"{result_type}_domain", 'timestamp': timestamp})
        
        if 'mx_records' in data and data['mx_records']:
            for mx in data['mx_records']:
                domains = extract_domains_from_text(mx)
                for domain in domains:
                    if domain not in self.discovered_entities['domains']:
                        self.discovered_entities['domains'].add(domain)
                        self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_mx", 'timestamp': timestamp})
    
    def _extract_from_reverse(self, data: Dict[str, Any], result_type: str, timestamp: str):
        """Extract entities from reverse DNS lookup results."""
        if 'ip' in data:
            self.discovered_entities['ips'].add(data['ip'])
            self.entity_history.append({'type': 'ip', 'value': data['ip'], 'source': result_type, 'timestamp': timestamp})
        
        if 'hostname' in data:
            domains = extract_domains_from_text(data['hostname'])
            for domain in domains:
                if domain not in self.discovered_entities['domains']:
                    self.discovered_entities['domains'].add(domain)
                    self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_hostname", 'timestamp': timestamp})
    
    def _extract_from_security(self, data: Dict[str, Any], result_type: str, timestamp: str):
        """Extract entities from security API results."""
        if 'email' in data:
            if data.get('email') and '@' in data['email']:
                email = data['email']
                if email not in self.discovered_entities['emails']:
                    self.discovered_entities['emails'].add(email)
                    self.entity_history.append({'type': 'email', 'value': email, 'source': 'hibp', 'timestamp': timestamp})
            
            if data.get('breaches'):
                for breach in data['breaches']:
                    if breach.get('domain'):
                        domain = breach['domain']
                        if domain not in self.discovered_entities['domains']:
                            self.discovered_entities['domains'].add(domain)
                            self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'hibp_breach', 'timestamp': timestamp})
        
        elif 'ip' in data and 'reputation' in data:
            ip = data['ip']
            if ip not in self.discovered_entities['ips']:
                self.discovered_entities['ips'].add(ip)
                self.entity_history.append({'type': 'ip', 'value': ip, 'source': 'virustotal_ip', 'timestamp': timestamp})
            
            if data.get('as_owner'):
                domains = extract_domains_from_text(data['as_owner'])
                for domain in domains:
                    if domain not in self.discovered_entities['domains']:
                        self.discovered_entities['domains'].add(domain)
                        self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'virustotal_as_owner', 'timestamp': timestamp})
        
        elif 'domain' in data and 'reputation' in data:
            domain = data['domain']
            if domain not in self.discovered_entities['domains']:
                self.discovered_entities['domains'].add(domain)
                self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'virustotal_domain', 'timestamp': timestamp})
        
        elif 'query' in data and 'search_type' in data:
            query = data['query']
            if '@' in query:
                if query not in self.discovered_entities['emails']:
                    self.discovered_entities['emails'].add(query)
                    self.entity_history.append({'type': 'email', 'value': query, 'source': 'spokeo', 'timestamp': timestamp})
            else:
                domains = extract_domains_from_text(query)
                for domain in domains:
                    if domain not in self.discovered_entities['domains']:
                        self.discovered_entities['domains'].add(domain)
                        self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'spokeo', 'timestamp': timestamp})
    
    def clear_all(self):
        """Clear all discovered entities."""
        self.discovered_entities = {'ips': set(), 'domains': set(), 'emails': set()}
        self.entity_history = []
    
    def get_entities_dict(self) -> Dict[str, List[str]]:
        """Get discovered entities as dictionary with lists."""
        return {
            'ips': list(self.discovered_entities['ips']),
            'domains': list(self.discovered_entities['domains']),
            'emails': list(self.discovered_entities['emails'])
        }
