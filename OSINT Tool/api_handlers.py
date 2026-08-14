"""
Security API handlers for OSINT Tool
Handles integration with Have I Been Pwned, VirusTotal, Spokeo, and WhitePages APIs.
"""

import os
import time
from typing import Dict, Any
import requests
from dotenv import load_dotenv


# Load environment variables at module level
load_dotenv()


class SecurityAPIHandler:
    """Handler for security API integrations."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _get_api_key(self, service: str) -> str:
        """
        Get API key from environment variables.
        Returns empty string if key is missing or is a placeholder.
        """
        key_map = {
            'hibp': 'HIBP_API_KEY',
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'spokeo': 'SPOKEO_API_KEY',
            'whitepages': 'WHITEPAGES_API_KEY',
            'osintly': 'OSINTLY_API_KEY'
        }
        
        env_key = key_map.get(service)
        if not env_key:
            return ''
        
        api_key = os.getenv(env_key, '')
        
        # Check if key is missing or placeholder
        if not api_key or api_key.startswith('your_') or api_key == '':
            return ''
        
        return api_key
    
    def hibp_breach_check(self, email: str) -> Dict[str, Any]:
        """
        Check if email has been in any data breaches using Have I Been Pwned API.
        """
        try:
            api_key = self._get_api_key('hibp')
            if not api_key:
                return {'error': 'HIBP API key required. Add HIBP_API_KEY to your .env file.'}
            
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
            headers = {
                'hibp-api-key': api_key,
                'User-Agent': 'OSINT Tool'
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid HIBP API key'}
            elif response.status_code == 404:
                return {'breaches': [], 'message': 'No breaches found for this email'}
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded. Please try again later.'}
            
            response.raise_for_status()
            breaches = response.json()
            
            return {
                'email': email,
                'breaches': breaches,
                'total_breaches': len(breaches)
            }
            
        except Exception as e:
            return {'error': f'HIBP API error: {str(e)}'}
    
    def virustotal_ip_scan(self, ip: str) -> Dict[str, Any]:
        """
        Scan IP address using VirusTotal API.
        """
        try:
            api_key = self._get_api_key('virustotal')
            if not api_key:
                return {'error': 'VirusTotal API key required. Add VIRUSTOTAL_API_KEY to your .env file.'}
            
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {
                'x-apikey': api_key
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif response.status_code == 403:
                return {'error': 'VirusTotal API access forbidden. Check your API key permissions.'}
            elif response.status_code == 404:
                return {'error': 'IP not found in VirusTotal database'}
            
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get('data', {}).get('attributes', {})
            
            return {
                'ip': ip,
                'reputation': attributes.get('reputation', 0),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'country': attributes.get('country', 'Unknown'),
                'asn': attributes.get('asn', 0),
                'as_owner': attributes.get('as_owner', 'Unknown')
            }
            
        except Exception as e:
            return {'error': f'VirusTotal API error: {str(e)}'}
    
    def virustotal_domain_scan(self, domain: str) -> Dict[str, Any]:
        """
        Scan domain using VirusTotal API.
        """
        try:
            api_key = self._get_api_key('virustotal')
            if not api_key:
                return {'error': 'VirusTotal API key required. Add VIRUSTOTAL_API_KEY to your .env file.'}
            
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {
                'x-apikey': api_key
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif response.status_code == 403:
                return {'error': 'VirusTotal API access forbidden. Check your API key permissions.'}
            elif response.status_code == 404:
                return {'error': 'Domain not found in VirusTotal database'}
            
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get('data', {}).get('attributes', {})
            
            return {
                'domain': domain,
                'reputation': attributes.get('reputation', 0),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'creation_date': attributes.get('creation_date', 'Unknown'),
                'last_dns_records': attributes.get('last_dns_records', [])[:5]
            }
            
        except Exception as e:
            return {'error': f'VirusTotal API error: {str(e)}'}
    
    def spokeo_search(self, query: str) -> Dict[str, Any]:
        """
        Search Spokeo API for person information.
        Note: Spokeo requires commercial subscription.
        """
        try:
            api_key = self._get_api_key('spokeo')
            if not api_key:
                return {'error': 'Spokeo API key required. Add SPOKEO_API_KEY to your .env file. Note: Spokeo requires commercial subscription.'}
            
            # Spokeo API endpoint (placeholder - actual endpoint depends on subscription)
            url = 'https://api.spokeo.com/v1/search'
            
            params = {
                'api_key': api_key,
                'query': query
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 401:
                return {'error': 'Invalid Spokeo API key'}
            elif response.status_code == 403:
                return {'error': 'Spokeo API access forbidden. Check your subscription.'}
            
            response.raise_for_status()
            data = response.json()
            
            return {
                'query': query,
                'results': data.get('results', []),
                'total_results': len(data.get('results', []))
            }
            
        except Exception as e:
            return {'error': f'Spokeo API error: {str(e)}'}
    
    def whitepages_person_search(self, query: str, search_type: str = 'email') -> Dict[str, Any]:
        """
        Search WhitePages API for person information.
        Supports email, phone, and name/address searches.
        """
        try:
            api_key = self._get_api_key('whitepages')
            if not api_key:
                return {'error': 'WhitePages API key required. Add WHITEPAGES_API_KEY to your .env file.'}
            
            # WhitePages API v2 endpoint for person search
            url = 'https://api.whitepages.com/v2/person'
            
            headers = {
                'X-Api-Key': api_key
            }
            
            params = {}
            
            # Add query parameter based on search type
            if search_type == 'email':
                params['email'] = query
            elif search_type == 'phone':
                params['phone'] = query
            elif search_type == 'name':
                params['name'] = query
            elif search_type == 'address':
                params['address'] = query
            
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 401:
                return {'error': 'Invalid WhitePages API key'}
            elif response.status_code == 403:
                return {'error': 'WhitePages API access forbidden. Check your subscription.'}
            elif response.status_code == 404:
                return {'error': 'No results found for this query'}
            
            response.raise_for_status()
            data = response.json()
            
            # Extract relevant person information
            person_data = {}
            
            if data.get('results'):
                for person in data['results'][:1]:  # Get first result
                    person_data['name'] = person.get('best_name', {})
                    person_data['age_range'] = person.get('age_range')
                    person_data['gender'] = person.get('gender')
                    person_data['location'] = person.get('location', {})
                    person_data['phones'] = person.get('phones', [])
                    person_data['emails'] = person.get('emails', [])
                    person_data['addresses'] = person.get('addresses', [])
                    person_data['associates'] = person.get('associates', [])
                    person_data['criminal_records'] = person.get('criminal_records', [])
                    person_data['properties'] = person.get('properties', [])
            
            return {
                'query': query,
                'search_type': search_type,
                'person': person_data,
                'is_valid': data.get('is_valid', False),
                'confidence_score': data.get('confidence_score', 0),
                'total_results': len(data.get('results', []))
            }
            
        except Exception as e:
            return {'error': f'WhitePages API error: {str(e)}'}

    def osintly_search(self, query: str, query_type: str = None) -> Dict[str, Any]:
        """
        Search Osint.ly for an email address or phone number.
        The API creates an asynchronous search and this method polls for results.
        """
        api_key = self._get_api_key('osintly')
        if not api_key:
            return {'error': 'Osint.ly API key required. Add OSINTLY_API_KEY to your .env file.'}

        normalized = query.strip().lower()

        # Determine query type if not provided
        if not query_type:
            if '@' in normalized:
                query_type = 'Email Address'
            else:
                digits = ''.join(char for char in query if char.isdigit())
                if len(digits) >= 10:
                    query_type = 'Phone Number'

        if not query_type:
            return {'error': 'Osint.ly requires an email address or phone number.'}

        base_url = 'https://api.osint.ly'
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        try:
            # Create the search
            payload = {
                'query': {
                    'type': query_type,
                    'value': query.strip()
                },
                'features': {
                    'breached_accounts': True,
                    'registered_accounts': 'include'
                },
                'cache': {
                    'mode': 'prefer'
                }
            }

            response = self.session.post(f'{base_url}/search', headers=headers, json=payload, timeout=30)
            if response.status_code == 401:
                return {'error': 'Invalid Osint.ly API key'}
            elif response.status_code == 403:
                return {'error': 'Osint.ly API access forbidden. Check your subscription plan.'}

            response.raise_for_status()
            data = response.json()

            # Extract search ID from possible response shapes
            search_id = data.get('search', {}).get('id') or data.get('id')
            if not search_id:
                return {'error': 'Failed to create Osint.ly search', 'response': data}

            # Poll for results
            result_url = f'{base_url}/search/{search_id}/results'
            partial_data = None

            for _ in range(20):
                time.sleep(3)
                result_response = self.session.get(result_url, headers=headers, timeout=30)

                if result_response.status_code == 200:
                    result_data = result_response.json()
                    partial_data = result_data

                    status = result_data.get('status', '').lower()
                    if result_data.get('ok') and (status in ('completed', 'done') or result_data.get('result') is not None):
                        return {
                            'query': query,
                            'query_type': query_type,
                            'search_id': search_id,
                            'results': result_data.get('result', {}),
                            'status': status
                        }

            return {
                'query': query,
                'query_type': query_type,
                'search_id': search_id,
                'status': partial_data.get('status', 'pending') if partial_data else 'pending',
                'message': 'Osint.ly search is still running. Retrieve it later with the search ID.',
                'partial_results': partial_data.get('result') if partial_data else None
            }

        except Exception as e:
            return {'error': f'Osint.ly API error: {str(e)}'}