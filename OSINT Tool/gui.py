#!/usr/bin/env python3
"""
OSINT Tool GUI - Modern Graphical User Interface
A professional interface for the OSINT gathering tool using CustomTkinter.
"""

import customtkinter as ctk
from tkinter import messagebox, scrolledtext, filedialog
import threading
import json
import os
import tempfile
import webbrowser
import re
from datetime import datetime
from osint_tool import OSINTTool
import folium


class OSINTGUI:
    """Main GUI class for OSINT Tool."""
    
    def __init__(self):
        # Set appearance mode and default color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("OSINT Tool - Open Source Intelligence")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize OSINT tool
        self.tool = OSINTTool()
        
        # Store last results for saving
        self.last_ip_results = None
        self.last_domain_results = None
        self.last_email_results = None
        
        # Store discovered entities for propagation
        self.discovered_entities = {
            'ips': set(),
            'domains': set(),
            'emails': set()
        }
        self.entity_history = []  # Track discovery order and relationships
        
        # Auto-propagation setting
        self.auto_propagate = False
        
        # Create GUI components
        self.create_widgets()
        
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container with padding
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(
            main_frame, 
            text="OSINT Tool",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(pady=(0, 10))
        
        subtitle_label = ctk.CTkLabel(
            main_frame,
            text="Open Source Intelligence Gathering Tool",
            font=ctk.CTkFont(size=14)
        )
        subtitle_label.pack(pady=(0, 20))
        
        # Tabview for different tools
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.pack(fill="both", expand=True)
        
        # Create tabs
        self.tab_ip = self.tabview.add("IP Lookup")
        self.tab_domain = self.tabview.add("Domain Lookup")
        self.tab_email = self.tabview.add("Email Validation")
        self.tab_intel = self.tabview.add("Collected Intelligence")
        self.tab_api = self.tabview.add("API Configuration")
        self.tab_security = self.tabview.add("Security APIs")
        
        # Setup each tab
        self.setup_ip_tab()
        self.setup_domain_tab()
        self.setup_email_tab()
        self.setup_intel_tab()
        self.setup_api_tab()
        self.setup_security_tab()
        
    def setup_ip_tab(self):
        """Setup IP lookup tab."""
        # Input frame
        input_frame = ctk.CTkFrame(self.tab_ip)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Label
        ctk.CTkLabel(input_frame, text="IP Address:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Entry
        self.ip_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter IP address (e.g., 8.8.8.8)")
        self.ip_entry.pack(fill="x", padx=10, pady=(0, 10))
        
        # Buttons frame
        button_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        # Geolocation button
        self.geo_btn = ctk.CTkButton(
            button_frame,
            text="Geolocation Lookup",
            command=self.run_ip_geolocation,
            height=40
        )
        self.geo_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # Reverse lookup button
        self.reverse_btn = ctk.CTkButton(
            button_frame,
            text="Reverse DNS Lookup",
            command=self.run_reverse_ip,
            height=40
        )
        self.reverse_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Action buttons frame
        action_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        # Show Map button
        self.map_btn = ctk.CTkButton(
            action_frame,
            text="Show Map",
            command=self.show_ip_map,
            height=40,
            fg_color="#2d8659"
        )
        self.map_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # Save button
        self.save_ip_btn = ctk.CTkButton(
            action_frame,
            text="Save Results",
            command=lambda: self.save_results('ip'),
            height=40,
            fg_color="#7c2d12"
        )
        self.save_ip_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Results area
        ctk.CTkLabel(self.tab_ip, text="Results:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.ip_results = scrolledtext.ScrolledText(
            self.tab_ip,
            wrap="word",
            font=("Consolas", 10),
            bg="#1a1a1a",
            fg="#ffffff"
        )
        self.ip_results.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def setup_domain_tab(self):
        """Setup domain lookup tab."""
        # Input frame
        input_frame = ctk.CTkFrame(self.tab_domain)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Label
        ctk.CTkLabel(input_frame, text="Domain:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Entry
        self.domain_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter domain (e.g., example.com)")
        self.domain_entry.pack(fill="x", padx=10, pady=(0, 10))
        
        # Buttons frame
        button_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        # WHOIS button
        self.whois_btn = ctk.CTkButton(
            button_frame,
            text="WHOIS Lookup",
            command=self.run_whois,
            height=40
        )
        self.whois_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # DNS button
        self.dns_btn = ctk.CTkButton(
            button_frame,
            text="DNS Enumeration",
            command=self.run_dns,
            height=40
        )
        self.dns_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Save button
        self.save_domain_btn = ctk.CTkButton(
            input_frame,
            text="Save Results",
            command=lambda: self.save_results('domain'),
            height=40,
            fg_color="#7c2d12"
        )
        self.save_domain_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        # Results area
        ctk.CTkLabel(self.tab_domain, text="Results:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.domain_results = scrolledtext.ScrolledText(
            self.tab_domain,
            wrap="word",
            font=("Consolas", 10),
            bg="#1a1a1a",
            fg="#ffffff"
        )
        self.domain_results.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def setup_email_tab(self):
        """Setup email validation tab."""
        # Input frame
        input_frame = ctk.CTkFrame(self.tab_email)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Label
        ctk.CTkLabel(input_frame, text="Email Address:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Entry
        self.email_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter email (e.g., test@example.com)")
        self.email_entry.pack(fill="x", padx=10, pady=(0, 10))
        
        # Validate button
        self.validate_btn = ctk.CTkButton(
            input_frame,
            text="Validate Email",
            command=self.run_email_validation,
            height=40
        )
        self.validate_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        # Save button
        self.save_email_btn = ctk.CTkButton(
            input_frame,
            text="Save Results",
            command=lambda: self.save_results('email'),
            height=40,
            fg_color="#7c2d12"
        )
        self.save_email_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        # Results area
        ctk.CTkLabel(self.tab_email, text="Results:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.email_results = scrolledtext.ScrolledText(
            self.tab_email,
            wrap="word",
            font=("Consolas", 10),
            bg="#1a1a1a",
            fg="#ffffff"
        )
        self.email_results.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def setup_intel_tab(self):
        """Setup collected intelligence tab."""
        # Control frame
        control_frame = ctk.CTkFrame(self.tab_intel)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        # Title
        ctk.CTkLabel(control_frame, text="Discovered Entities", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Auto-propagate checkbox
        self.auto_prop_var = ctk.BooleanVar(value=False)
        self.auto_prop_check = ctk.CTkCheckBox(
            control_frame,
            text="Auto-propagate (automatically investigate discovered entities)",
            variable=self.auto_prop_var,
            command=self.toggle_auto_propagate
        )
        self.auto_prop_check.pack(anchor="w", padx=10, pady=(0, 10))
        
        # Buttons frame
        button_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        # Clear all button
        ctk.CTkButton(
            button_frame,
            text="Clear All",
            command=self.clear_intelligence,
            height=40,
            fg_color="#7c2d12"
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # Save intelligence button
        ctk.CTkButton(
            button_frame,
            text="Save Intelligence",
            command=self.save_intelligence,
            height=40,
            fg_color="#2d8659"
        ).pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Entity display frame
        entity_frame = ctk.CTkFrame(self.tab_intel)
        entity_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Create scrollable frame for entities
        self.intel_scroll = ctk.CTkScrollableFrame(entity_frame)
        self.intel_scroll.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Initialize entity displays
        self.ip_entities_frame = None
        self.domain_entities_frame = None
        self.email_entities_frame = None
        
        self.update_intel_display()
        
        # Store security results for saving
        self.last_security_results = None
        
    def setup_api_tab(self):
        """Setup API configuration tab."""
        # Main frame
        main_frame = ctk.CTkFrame(self.tab_api)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Title
        ctk.CTkLabel(main_frame, text="API Key Configuration", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        ctk.CTkLabel(main_frame, text="Configure your API keys for premium services. Keys are stored locally in ~/.osint_tool/api_keys.json", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=10, pady=(0, 10))
        
        # Scrollable frame for API keys
        scroll_frame = ctk.CTkScrollableFrame(main_frame)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # HIBP API Key
        hibp_frame = ctk.CTkFrame(scroll_frame)
        hibp_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(hibp_frame, text="Have I Been Pwned API Key", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        ctk.CTkLabel(hibp_frame, text="Get your free API key at: https://haveibeenpwned.com/API/Key", font=ctk.CTkFont(size=10)).pack(anchor="w", padx=10, pady=(0, 5))
        
        self.hibp_key_entry = ctk.CTkEntry(hibp_frame, placeholder_text="Enter HIBP API key")
        self.hibp_key_entry.pack(fill="x", padx=10, pady=(0, 5))
        
        # Load existing key
        if 'hibp' in self.tool.api_keys:
            self.hibp_key_entry.insert(0, self.tool.api_keys['hibp'])
        
        ctk.CTkButton(hibp_frame, text="Save HIBP Key", command=lambda: self.save_api_key('hibp', self.hibp_key_entry)).pack(fill="x", padx=10, pady=(0, 10))
        
        # VirusTotal API Key
        vt_frame = ctk.CTkFrame(scroll_frame)
        vt_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(vt_frame, text="VirusTotal API Key", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        ctk.CTkLabel(vt_frame, text="Get your free API key at: https://www.virustotal.com/", font=ctk.CTkFont(size=10)).pack(anchor="w", padx=10, pady=(0, 5))
        
        self.vt_key_entry = ctk.CTkEntry(vt_frame, placeholder_text="Enter VirusTotal API key")
        self.vt_key_entry.pack(fill="x", padx=10, pady=(0, 5))
        
        # Load existing key
        if 'virustotal' in self.tool.api_keys:
            self.vt_key_entry.insert(0, self.tool.api_keys['virustotal'])
        
        ctk.CTkButton(vt_frame, text="Save VirusTotal Key", command=lambda: self.save_api_key('virustotal', self.vt_key_entry)).pack(fill="x", padx=10, pady=(0, 10))
        
        # Spokeo API Key
        spokeo_frame = ctk.CTkFrame(scroll_frame)
        spokeo_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(spokeo_frame, text="Spokeo API Key", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        ctk.CTkLabel(spokeo_frame, text="Requires commercial subscription. Contact Spokeo for API access.", font=ctk.CTkFont(size=10)).pack(anchor="w", padx=10, pady=(0, 5))
        
        self.spokeo_key_entry = ctk.CTkEntry(spokeo_frame, placeholder_text="Enter Spokeo API key")
        self.spokeo_key_entry.pack(fill="x", padx=10, pady=(0, 5))
        
        # Load existing key
        if 'spokeo' in self.tool.api_keys:
            self.spokeo_key_entry.insert(0, self.tool.api_keys['spokeo'])
        
        ctk.CTkButton(spokeo_frame, text="Save Spokeo Key", command=lambda: self.save_api_key('spokeo', self.spokeo_key_entry)).pack(fill="x", padx=10, pady=(0, 10))
    
    def setup_security_tab(self):
        """Setup security APIs tab."""
        # Input frame
        input_frame = ctk.CTkFrame(self.tab_security)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Title
        ctk.CTkLabel(input_frame, text="Security API Lookups", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Query entry
        ctk.CTkLabel(input_frame, text="Query (IP, Domain, or Email):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=10, pady=(5, 2))
        self.security_query_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter IP, domain, or email")
        self.security_query_entry.pack(fill="x", padx=10, pady=(0, 10))
        
        # Buttons frame
        button_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        # HIBP button
        self.hibp_btn = ctk.CTkButton(
            button_frame,
            text="HIBP Breach Check",
            command=self.run_hibp_check,
            height=40
        )
        self.hibp_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # VirusTotal IP button
        self.vt_ip_btn = ctk.CTkButton(
            button_frame,
            text="VT IP Scan",
            command=self.run_vt_ip_scan,
            height=40
        )
        self.vt_ip_btn.pack(side="left", fill="x", expand=True, padx=(5, 5))
        
        # VirusTotal Domain button
        self.vt_domain_btn = ctk.CTkButton(
            button_frame,
            text="VT Domain Scan",
            command=self.run_vt_domain_scan,
            height=40
        )
        self.vt_domain_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Spokeo button
        self.spokeo_btn = ctk.CTkButton(
            input_frame,
            text="Spokeo Search",
            command=self.run_spokeo_search,
            height=40
        )
        self.spokeo_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        # Save button
        self.save_security_btn = ctk.CTkButton(
            input_frame,
            text="Save Results",
            command=lambda: self.save_results('security'),
            height=40,
            fg_color="#7c2d12"
        )
        self.save_security_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        # Results area
        ctk.CTkLabel(self.tab_security, text="Results:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.security_results = scrolledtext.ScrolledText(
            self.tab_security,
            wrap="word",
            font=("Consolas", 10),
            bg="#1a1a1a",
            fg="#ffffff"
        )
        self.security_results.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def save_api_key(self, service, entry_widget):
        """Save an API key for a service."""
        key = entry_widget.get().strip()
        if key:
            self.tool.set_api_key(service, key)
            messagebox.showinfo("Success", f"{service.capitalize()} API key saved successfully.")
        else:
            messagebox.showerror("Error", "Please enter an API key.")
    
    def run_hibp_check(self):
        """Run HIBP breach check in a separate thread."""
        query = self.security_query_entry.get().strip()
        if not query or '@' not in query:
            messagebox.showerror("Error", "Please enter a valid email address")
            return
        
        self.hibp_btn.configure(state="disabled", text="Checking...")
        
        def lookup():
            try:
                results = self.tool.hibp_breach_check(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.hibp_btn.configure(state="normal", text="HIBP Breach Check"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_vt_ip_scan(self):
        """Run VirusTotal IP scan in a separate thread."""
        query = self.security_query_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        self.vt_ip_btn.configure(state="disabled", text="Scanning...")
        
        def lookup():
            try:
                results = self.tool.virustotal_ip_scan(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.vt_ip_btn.configure(state="normal", text="VT IP Scan"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_vt_domain_scan(self):
        """Run VirusTotal domain scan in a separate thread."""
        query = self.security_query_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.vt_domain_btn.configure(state="disabled", text="Scanning...")
        
        def lookup():
            try:
                results = self.tool.virustotal_domain_scan(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.vt_domain_btn.configure(state="normal", text="VT Domain Scan"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_spokeo_search(self):
        """Run Spokeo search in a separate thread."""
        query = self.security_query_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a search query")
            return
        
        self.spokeo_btn.configure(state="disabled", text="Searching...")
        
        def lookup():
            try:
                results = self.tool.spokeo_search(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.spokeo_btn.configure(state="normal", text="Spokeo Search"))
        
        threading.Thread(target=lookup, daemon=True).start()
        
    def display_results(self, text_widget, data, result_type='ip'):
        """Display results in the specified text widget with formatting."""
        text_widget.delete(1.0, "end")
        
        # Store results for saving
        if result_type == 'ip':
            self.last_ip_results = data
        elif result_type == 'domain':
            self.last_domain_results = data
        elif result_type == 'email':
            self.last_email_results = data
        elif result_type == 'security':
            self.last_security_results = data
        
        # Extract and store discovered entities
        if 'error' not in data:
            self.extract_entities(data, result_type)
        
        # Format and display results
        formatted = self.format_results(data, result_type)
        text_widget.insert("end", formatted)
        
        # Update intelligence display
        self.update_intel_display()
        
        # Auto-propagate if enabled
        if self.auto_propagate and 'error' not in data:
            self.auto_propagate_entities(data, result_type)
    
    def format_results(self, data, result_type):
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
                    for i, result in enumerate(data['results'][:10], 1):  # Limit to first 10
                        output.append(f"\n{i}. {str(result)[:200]}...")  # Truncate long results
        
        output.append("")
        output.append("=" * 60)
        
        return "\n".join(output)
        
    def run_ip_geolocation(self):
        """Run IP geolocation lookup in a separate thread."""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        self.geo_btn.configure(state="disabled", text="Looking up...")
        
        def lookup():
            try:
                results = self.tool.ip_geolocation(ip)
                self.root.after(0, lambda: self.display_results(self.ip_results, results, 'ip'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.ip_results, {"error": str(e)}, 'ip'))
            finally:
                self.root.after(0, lambda: self.geo_btn.configure(state="normal", text="Geolocation Lookup"))
        
        threading.Thread(target=lookup, daemon=True).start()
        
    def run_reverse_ip(self):
        """Run reverse IP lookup in a separate thread."""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        self.reverse_btn.configure(state="disabled", text="Looking up...")
        
        def lookup():
            try:
                results = self.tool.reverse_ip_lookup(ip)
                self.root.after(0, lambda: self.display_results(self.ip_results, results, 'reverse'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.ip_results, {"error": str(e)}, 'reverse'))
            finally:
                self.root.after(0, lambda: self.reverse_btn.configure(state="normal", text="Reverse DNS Lookup"))
        
        threading.Thread(target=lookup, daemon=True).start()
        
    def run_whois(self):
        """Run WHOIS lookup in a separate thread."""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.whois_btn.configure(state="disabled", text="Looking up...")
        
        def lookup():
            try:
                results = self.tool.whois_lookup(domain)
                self.root.after(0, lambda: self.display_results(self.domain_results, results, 'domain'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.domain_results, {"error": str(e)}, 'domain'))
            finally:
                self.root.after(0, lambda: self.whois_btn.configure(state="normal", text="WHOIS Lookup"))
        
        threading.Thread(target=lookup, daemon=True).start()
        
    def run_dns(self):
        """Run DNS enumeration in a separate thread."""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.dns_btn.configure(state="disabled", text="Looking up...")
        
        def lookup():
            try:
                results = self.tool.dns_enumeration(domain)
                self.root.after(0, lambda: self.display_results(self.domain_results, results, 'domain'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.domain_results, {"error": str(e)}, 'domain'))
            finally:
                self.root.after(0, lambda: self.dns_btn.configure(state="normal", text="DNS Enumeration"))
        
        threading.Thread(target=lookup, daemon=True).start()
        
    def run_email_validation(self):
        """Run email validation in a separate thread."""
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Error", "Please enter an email address")
            return
        
        self.validate_btn.configure(state="disabled", text="Validating...")
        
        def lookup():
            try:
                results = self.tool.email_validation(email)
                self.root.after(0, lambda: self.display_results(self.email_results, results, 'email'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.email_results, {"error": str(e)}, 'email'))
            finally:
                self.root.after(0, lambda: self.validate_btn.configure(state="normal", text="Validate Email"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def show_ip_map(self):
        """Show IP location on a map using folium."""
        if not self.last_ip_results or 'error' in self.last_ip_results:
            messagebox.showerror("Error", "Please perform a geolocation lookup first")
            return
        
        data = self.last_ip_results
        if 'lat' not in data or 'lon' not in data:
            messagebox.showerror("Error", "No coordinates available for this IP")
            return
        
        try:
            # Create map centered on IP location
            m = folium.Map(
                location=[data['lat'], data['lon']],
                zoom_start=10,
                tiles='OpenStreetMap'
            )
            
            # Add marker with popup
            popup_content = f"""
            <b>IP:</b> {data.get('ip', 'N/A')}<br>
            <b>Location:</b> {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}<br>
            <b>ISP:</b> {data.get('isp', 'N/A')}<br>
            <b>Coordinates:</b> {data['lat']}, {data['lon']}
            """
            
            folium.Marker(
                [data['lat'], data['lon']],
                popup=folium.Popup(popup_content, max_width=300),
                tooltip=f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
            ).add_to(m)
            
            # Save to temporary file and open in browser
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                m.save(f.name)
                temp_path = f.name
            
            webbrowser.open(f'file://{temp_path}')
            messagebox.showinfo("Map", "Map opened in your default browser")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate map: {str(e)}")
    
    def save_results(self, result_type):
        """Save results to a file."""
        data = None
        default_name = ""
        
        if result_type == 'ip':
            data = self.last_ip_results
            default_name = "ip_results"
        elif result_type == 'domain':
            data = self.last_domain_results
            default_name = "domain_results"
        elif result_type == 'email':
            data = self.last_email_results
            default_name = "email_results"
        elif result_type == 'security':
            data = self.last_security_results
            default_name = "security_results"
        
        if not data:
            messagebox.showerror("Error", "No results to save. Please perform a lookup first.")
            return
        
        if 'error' in data:
            messagebox.showerror("Error", "Cannot save error results")
            return
        
        # Ask for file location
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"{default_name}_{timestamp}.json"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=default_filename,
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # Save as JSON
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            messagebox.showinfo("Success", f"Results saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")
    
    def extract_entities(self, data, result_type):
        """Extract entities from lookup results."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if result_type == 'ip':
            # Extract IP
            if 'ip' in data:
                self.discovered_entities['ips'].add(data['ip'])
                self.entity_history.append({'type': 'ip', 'value': data['ip'], 'source': result_type, 'timestamp': timestamp})
            
            # Extract domain from org/isp if present
            for field in ['org', 'isp']:
                if field in data and data[field]:
                    domains = self.extract_domains_from_text(str(data[field]))
                    for domain in domains:
                        if domain not in self.discovered_entities['domains']:
                            self.discovered_entities['domains'].add(domain)
                            self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_{field}", 'timestamp': timestamp})
        
        elif result_type == 'domain':
            # Extract domain
            if 'domain_name' in data:
                domain = data['domain_name']
                if isinstance(domain, list):
                    domain = domain[0] if domain else None
                if domain:
                    self.discovered_entities['domains'].add(str(domain))
                    self.entity_history.append({'type': 'domain', 'value': str(domain), 'source': result_type, 'timestamp': timestamp})
            
            # Extract IPs from DNS records
            if 'ip_address' in data and data['ip_address'] and not data['ip_address'].startswith('Error'):
                self.discovered_entities['ips'].add(data['ip_address'])
                self.entity_history.append({'type': 'ip', 'value': data['ip_address'], 'source': f"{result_type}_dns", 'timestamp': timestamp})
            
            # Extract IPs from A records
            if 'A' in data and data['A']:
                for record in data['A']:
                    ips = self.extract_ips_from_text(record)
                    for ip in ips:
                        if ip not in self.discovered_entities['ips']:
                            self.discovered_entities['ips'].add(ip)
                            self.entity_history.append({'type': 'ip', 'value': ip, 'source': f"{result_type}_A", 'timestamp': timestamp})
            
            # Extract domains from name servers
            if 'name_servers' in data and data['name_servers']:
                for ns in data['name_servers']:
                    domains = self.extract_domains_from_text(str(ns))
                    for domain in domains:
                        if domain not in self.discovered_entities['domains']:
                            self.discovered_entities['domains'].add(domain)
                            self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_ns", 'timestamp': timestamp})
            
            # Extract emails from WHOIS
            if 'emails' in data and data['emails']:
                for email in data['emails']:
                    if email and '@' in str(email):
                        email_str = str(email).strip()
                        if email_str not in self.discovered_entities['emails']:
                            self.discovered_entities['emails'].add(email_str)
                            self.entity_history.append({'type': 'email', 'value': email_str, 'source': f"{result_type}_whois", 'timestamp': timestamp})
        
        elif result_type == 'email':
            # Extract email
            if 'valid_format' in data and data['valid_format']:
                # Reconstruct email from entry
                email = self.email_entry.get().strip()
                if email not in self.discovered_entities['emails']:
                    self.discovered_entities['emails'].add(email)
                    self.entity_history.append({'type': 'email', 'value': email, 'source': result_type, 'timestamp': timestamp})
            
            # Extract domain
            if 'domain' in data:
                if data['domain'] not in self.discovered_entities['domains']:
                    self.discovered_entities['domains'].add(data['domain'])
                    self.entity_history.append({'type': 'domain', 'value': data['domain'], 'source': f"{result_type}_domain", 'timestamp': timestamp})
            
            # Extract domains from MX records
            if 'mx_records' in data and data['mx_records']:
                for mx in data['mx_records']:
                    domains = self.extract_domains_from_text(mx)
                    for domain in domains:
                        if domain not in self.discovered_entities['domains']:
                            self.discovered_entities['domains'].add(domain)
                            self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_mx", 'timestamp': timestamp})
        
        elif result_type == 'reverse':
            # Extract IP
            if 'ip' in data:
                self.discovered_entities['ips'].add(data['ip'])
                self.entity_history.append({'type': 'ip', 'value': data['ip'], 'source': result_type, 'timestamp': timestamp})
            
            # Extract domain from hostname
            if 'hostname' in data:
                domains = self.extract_domains_from_text(data['hostname'])
                for domain in domains:
                    if domain not in self.discovered_entities['domains']:
                        self.discovered_entities['domains'].add(domain)
                        self.entity_history.append({'type': 'domain', 'value': domain, 'source': f"{result_type}_hostname", 'timestamp': timestamp})
        
        elif result_type == 'security':
            # Extract entities from security API results
            if 'email' in data:
                # HIBP results
                if data.get('email') and '@' in data['email']:
                    email = data['email']
                    if email not in self.discovered_entities['emails']:
                        self.discovered_entities['emails'].add(email)
                        self.entity_history.append({'type': 'email', 'value': email, 'source': 'hibp', 'timestamp': timestamp})
                
                # Extract domains from breach data
                if data.get('breaches'):
                    for breach in data['breaches']:
                        if breach.get('domain'):
                            domain = breach['domain']
                            if domain not in self.discovered_entities['domains']:
                                self.discovered_entities['domains'].add(domain)
                                self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'hibp_breach', 'timestamp': timestamp})
            
            elif 'ip' in data and 'reputation' in data:
                # VirusTotal IP results
                ip = data['ip']
                if ip not in self.discovered_entities['ips']:
                    self.discovered_entities['ips'].add(ip)
                    self.entity_history.append({'type': 'ip', 'value': ip, 'source': 'virustotal_ip', 'timestamp': timestamp})
                
                # Extract domain from AS owner
                if data.get('as_owner'):
                    domains = self.extract_domains_from_text(data['as_owner'])
                    for domain in domains:
                        if domain not in self.discovered_entities['domains']:
                            self.discovered_entities['domains'].add(domain)
                            self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'virustotal_as_owner', 'timestamp': timestamp})
            
            elif 'domain' in data and 'reputation' in data:
                # VirusTotal Domain results
                domain = data['domain']
                if domain not in self.discovered_entities['domains']:
                    self.discovered_entities['domains'].add(domain)
                    self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'virustotal_domain', 'timestamp': timestamp})
            
            elif 'query' in data and 'search_type' in data:
                # Spokeo results
                query = data['query']
                if '@' in query:
                    # Email query
                    if query not in self.discovered_entities['emails']:
                        self.discovered_entities['emails'].add(query)
                        self.entity_history.append({'type': 'email', 'value': query, 'source': 'spokeo', 'timestamp': timestamp})
                else:
                    # Could be domain or other
                    domains = self.extract_domains_from_text(query)
                    for domain in domains:
                        if domain not in self.discovered_entities['domains']:
                            self.discovered_entities['domains'].add(domain)
                            self.entity_history.append({'type': 'domain', 'value': domain, 'source': 'spokeo', 'timestamp': timestamp})
    
    def extract_ips_from_text(self, text):
        """Extract IP addresses from text."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, str(text))
    
    def extract_domains_from_text(self, text):
        """Extract domain names from text."""
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'
        return re.findall(domain_pattern, str(text))
    
    def update_intel_display(self):
        """Update the collected intelligence display."""
        # Clear existing widgets
        for widget in self.intel_scroll.winfo_children():
            widget.destroy()
        
        # IPs section
        if self.discovered_entities['ips']:
            ip_frame = ctk.CTkFrame(self.intel_scroll)
            ip_frame.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(ip_frame, text=f"🌐 IP Addresses ({len(self.discovered_entities['ips'])})", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for ip in sorted(self.discovered_entities['ips']):
                ip_item = ctk.CTkFrame(ip_frame, fg_color="transparent")
                ip_item.pack(fill="x", padx=10, pady=2)
                
                ctk.CTkLabel(ip_item, text=ip, width=150).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    ip_item,
                    text="Geo",
                    width=50,
                    command=lambda i=ip: self.investigate_ip(i, 'geo')
                ).pack(side="left", padx=2)
                
                ctk.CTkButton(
                    ip_item,
                    text="Reverse",
                    width=50,
                    command=lambda i=ip: self.investigate_ip(i, 'reverse')
                ).pack(side="left", padx=2)
        
        # Domains section
        if self.discovered_entities['domains']:
            domain_frame = ctk.CTkFrame(self.intel_scroll)
            domain_frame.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(domain_frame, text=f"🔗 Domains ({len(self.discovered_entities['domains'])})", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for domain in sorted(self.discovered_entities['domains']):
                domain_item = ctk.CTkFrame(domain_frame, fg_color="transparent")
                domain_item.pack(fill="x", padx=10, pady=2)
                
                ctk.CTkLabel(domain_item, text=domain, width=200).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    domain_item,
                    text="WHOIS",
                    width=60,
                    command=lambda d=domain: self.investigate_domain(d, 'whois')
                ).pack(side="left", padx=2)
                
                ctk.CTkButton(
                    domain_item,
                    text="DNS",
                    width=60,
                    command=lambda d=domain: self.investigate_domain(d, 'dns')
                ).pack(side="left", padx=2)
        
        # Emails section
        if self.discovered_entities['emails']:
            email_frame = ctk.CTkFrame(self.intel_scroll)
            email_frame.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(email_frame, text=f"📧 Emails ({len(self.discovered_entities['emails'])})", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for email in sorted(self.discovered_entities['emails']):
                email_item = ctk.CTkFrame(email_frame, fg_color="transparent")
                email_item.pack(fill="x", padx=10, pady=2)
                
                ctk.CTkLabel(email_item, text=email, width=250).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    email_item,
                    text="Validate",
                    width=60,
                    command=lambda e=email: self.investigate_email(e)
                ).pack(side="left", padx=2)
        
        # Show empty state if no entities
        if not any(self.discovered_entities.values()):
            ctk.CTkLabel(self.intel_scroll, text="No entities discovered yet. Perform lookups to populate this tab.", font=ctk.CTkFont(size=12)).pack(pady=20)
    
    def investigate_ip(self, ip, lookup_type):
        """Investigate a discovered IP address."""
        self.tabview.set("IP Lookup")
        self.ip_entry.delete(0, "end")
        self.ip_entry.insert(0, ip)
        if lookup_type == 'geo':
            self.run_ip_geolocation()
        else:
            self.run_reverse_ip()
    
    def investigate_domain(self, domain, lookup_type):
        """Investigate a discovered domain."""
        self.tabview.set("Domain Lookup")
        self.domain_entry.delete(0, "end")
        self.domain_entry.insert(0, domain)
        if lookup_type == 'whois':
            self.run_whois()
        else:
            self.run_dns()
    
    def investigate_email(self, email):
        """Investigate a discovered email."""
        self.tabview.set("Email Validation")
        self.email_entry.delete(0, "end")
        self.email_entry.insert(0, email)
        self.run_email_validation()
    
    def toggle_auto_propagate(self):
        """Toggle auto-propagation setting."""
        self.auto_propagate = self.auto_prop_var.get()
    
    def auto_propagate_entities(self, data, result_type):
        """Automatically investigate newly discovered entities."""
        # Get newly discovered entities (last few entries in history)
        new_entities = self.entity_history[-5:] if len(self.entity_history) > 5 else self.entity_history
        
        for entity in new_entities:
            # Skip the original entity we just looked up
            if entity['source'] == result_type:
                continue
            
            # Investigate with delay to avoid overwhelming
            if entity['type'] == 'ip':
                self.root.after(500, lambda i=entity['value']: self.investigate_ip(i, 'geo'))
            elif entity['type'] == 'domain':
                self.root.after(500, lambda d=entity['value']: self.investigate_domain(d, 'whois'))
            elif entity['type'] == 'email':
                self.root.after(500, lambda e=entity['value']: self.investigate_email(e))
    
    def clear_intelligence(self):
        """Clear all collected intelligence."""
        self.discovered_entities = {'ips': set(), 'domains': set(), 'emails': set()}
        self.entity_history = []
        self.update_intel_display()
        messagebox.showinfo("Cleared", "All collected intelligence has been cleared.")
    
    def save_intelligence(self):
        """Save collected intelligence to a file."""
        if not any(self.discovered_entities.values()):
            messagebox.showerror("Error", "No intelligence to save.")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"intelligence_{timestamp}.json"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=default_filename,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            intelligence_data = {
                'timestamp': timestamp,
                'entities': {
                    'ips': list(self.discovered_entities['ips']),
                    'domains': list(self.discovered_entities['domains']),
                    'emails': list(self.discovered_entities['emails'])
                },
                'history': self.entity_history
            }
            
            with open(file_path, 'w') as f:
                json.dump(intelligence_data, f, indent=2, default=str)
            
            messagebox.showinfo("Success", f"Intelligence saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save intelligence: {str(e)}")
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point for GUI application."""
    app = OSINTGUI()
    app.run()


if __name__ == '__main__':
    main()
