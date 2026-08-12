# Basic OSINT Tool

A Python-based Open Source Intelligence (OSINT) gathering tool for investigating IP addresses, domains, and email addresses. Features both command-line and graphical user interfaces.

## Features

- **IP Geolocation**: Get geographical information about an IP address with interactive map visualization
- **WHOIS Lookup**: Retrieve domain registration information
- **DNS Enumeration**: Gather DNS records for a domain
- **Email Validation**: Validate email addresses and check domain mail configuration
- **Reverse IP Lookup**: Perform reverse DNS lookup on IP addresses
- **Modern GUI**: Professional dark-themed graphical interface with:
  - Formatted, easy-to-read results with emojis and sections
  - Interactive map visualization for IP geolocation
  - Save results to JSON files with timestamps
  - Responsive design with background threading

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Graphical User Interface (Recommended)

Launch the modern GUI application:

```bash
python gui.py
```

The GUI provides a professional dark-themed interface with three tabs:

- **IP Lookup**: Enter an IP address and perform geolocation or reverse DNS lookups
  - Click "Show Map" to visualize IP location on an interactive map
  - Click "Save Results" to export data to JSON
- **Domain Lookup**: Enter a domain and perform WHOIS or DNS enumeration
  - Click "Save Results" to export data to JSON
- **Email Validation**: Enter an email address to validate and check domain mail configuration
  - Click "Save Results" to export data to JSON

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

## Disclaimer

This tool is for educational and legitimate OSINT purposes only. Always ensure you have proper authorization before investigating any targets. Respect privacy laws and terms of service of the APIs used.

## License

This tool is provided as-is for educational purposes.
