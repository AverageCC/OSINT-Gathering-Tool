# Basic OSINT Tool

A Python-based Open Source Intelligence (OSINT) gathering tool for investigating IP addresses, domains, and email addresses. Features both command-line and graphical user interfaces.

## Features

- **IP Geolocation**: Get geographical information about an IP address with interactive map visualization
- **WHOIS Lookup**: Retrieve domain registration information
- **DNS Enumeration**: Gather DNS records for a domain
- **Email Validation**: Validate email addresses and check domain mail configuration
- **Reverse IP Lookup**: Perform reverse DNS lookup on IP addresses
- **Security API Integrations**: Premium security intelligence via APIs:
  - **Have I Been Pwned**: Check if emails have been in data breaches
  - **VirusTotal**: Scan IPs and domains for malware and reputation
  - **Spokeo**: People search and background checks (requires commercial subscription)
- **API Key Management**: Secure local storage for API keys in `~/.osint_tool/api_keys.json`
- **Intelligent Entity Discovery**: Automatically extract and track related entities:
  - Extract domains from IP lookups (ISP, organization info)
  - Extract IPs from domain DNS records
  - Extract emails from WHOIS data
  - Extract domains from email validation
  - Extract entities from security API results (breach domains, AS owners, etc.)
- **Auto-Propagation**: Optional automatic investigation of discovered entities
- **Modern GUI**: Professional dark-themed graphical interface with:
  - Formatted, easy-to-read results with emojis and sections
  - Interactive map visualization for IP geolocation
  - Collected Intelligence tab to track all discovered entities
  - One-click investigation buttons for discovered entities
  - API Configuration tab for managing service credentials
  - Security APIs tab for premium lookups
  - Save results to JSON files with timestamps
  - Save complete intelligence reports
  - Responsive design with background threading

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

### API Key Setup (Optional)

For premium security API features, you'll need to obtain API keys:

- **Have I Been Pwned**: Get a free API key at https://haveibeenpwned.com/API/Key
- **VirusTotal**: Get a free API key at https://www.virustotal.com/ (requires account registration)
- **Spokeo**: Requires commercial subscription - contact Spokeo for API access

Once you have your API keys:
1. Launch the GUI: `python gui.py`
2. Go to the "API Configuration" tab
3. Enter your API keys in the respective fields
4. Click the save button for each service

Keys are stored locally in `~/.osint_tool/api_keys.json`

## Usage

### Graphical User Interface (Recommended)

Launch the modern GUI application:

```bash
python gui.py
```

The GUI provides a professional dark-themed interface with six tabs:

- **IP Lookup**: Enter an IP address and perform geolocation or reverse DNS lookups
  - Click "Show Map" to visualize IP location on an interactive map
  - Click "Save Results" to export data to JSON
- **Domain Lookup**: Enter a domain and perform WHOIS or DNS enumeration
  - Click "Save Results" to export data to JSON
- **Email Validation**: Enter an email address to validate and check domain mail configuration
  - Click "Save Results" to export data to JSON
- **Collected Intelligence**: View and manage all discovered entities
  - Automatically extracts IPs, domains, and emails from lookups
  - Click "Geo" or "Reverse" buttons to investigate discovered IPs
  - Click "WHOIS" or "DNS" buttons to investigate discovered domains
  - Click "Validate" button to investigate discovered emails
  - Enable "Auto-propagate" to automatically investigate new entities
  - Click "Clear All" to reset collected intelligence
  - Click "Save Intelligence" to export complete intelligence report
- **API Configuration**: Manage API keys for premium services
  - Enter and save API keys for Have I Been Pwned, VirusTotal, and Spokeo
  - Keys are stored securely in `~/.osint_tool/api_keys.json`
  - Free API keys available for HIBP and VirusTotal
- **Security APIs**: Perform premium security lookups
  - **HIBP Breach Check**: Check if an email has been in data breaches
  - **VT IP Scan**: Scan IP addresses with VirusTotal for malware and reputation
  - **VT Domain Scan**: Scan domains with VirusTotal for malware and reputation
  - **Spokeo Search**: People search and background checks (requires commercial subscription)
  - Click "Save Results" to export security API data to JSON

All operations run in background threads to keep the interface responsive. Results are displayed with professional formatting including emojis, sections, and timestamps for easy reading.

### Command Line Interface

#### Basic Syntax

```bash
python osint_tool.py [OPTIONS]
```

### IP Address Investigation

**Geolocation lookup:**
```bash
python osint_tool.py --ip 8.8.8.8
python osint_tool.py --ip 8.8.8.8 --geo
```

**Reverse DNS lookup:**
```bash
python osint_tool.py --ip 8.8.8.8 --reverse
```

### Domain Investigation

**WHOIS lookup:**
```bash
python osint_tool.py --domain example.com --whois
```

**DNS enumeration:**
```bash
python osint_tool.py --domain example.com --dns
```

**Combined domain lookup:**
```bash
python osint_tool.py --domain example.com --whois --dns
```

### Email Validation

```bash
python osint_tool.py --email test@example.com
```

### Output Formats

**Pretty print (default):**
```bash
python osint_tool.py --ip 8.8.8.8
```

**JSON output:**
```bash
python osint_tool.py --ip 8.8.8.8 --json
```

## Examples

### Investigate an IP address
```bash
python osint_tool.py --ip 1.1.1.1
```

### Full domain investigation
```bash
python osint_tool.py --domain example.com --whois --dns
```

### Validate an email
```bash
python osint_tool.py --email user@example.com
```

### Get JSON output for scripting
```bash
python osint_tool.py --domain example.com --dns --json
```

## Requirements

- Python 3.7+
- requests
- python-whois
- dnspython
- customtkinter (for GUI)
- folium (for map visualization)
- pillow (for image handling)
- pyhibp (for Have I Been Pwned API)

## Disclaimer

This tool is for educational and legitimate OSINT purposes only. Always ensure you have proper authorization before investigating any targets. Respect privacy laws and terms of service of the APIs used.

## License

This tool is provided as-is for educational purposes.
