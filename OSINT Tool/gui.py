#!/usr/bin/env python3
"""
OSINT Tool GUI - Modern Graphical User Interface
A professional interface for the OSINT gathering tool using CustomTkinter.
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, scrolledtext, filedialog
import threading
import json
import os
import tempfile
import webbrowser
from datetime import datetime
from osint_tool import OSINTTool
from functions import format_results, EntityExtractor
from api_handlers import SecurityAPIHandler
import folium


class OSINTGUI:
    """Main GUI class for OSINT Tool."""
    
    def __init__(self):
        # Set appearance mode and default color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("OSINT Tool - Open Source Intelligence")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)
        
        # Configure grid weights for responsive layout
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Initialize OSINT tool
        self.tool = OSINTTool()
        self.security_handler = SecurityAPIHandler()
        
        # Store last results for saving
        self.last_ip_results = None
        self.last_domain_results = None
        self.last_email_results = None
        self.last_security_results = None
        
        # Initialize entity extractor
        self.entity_extractor = EntityExtractor()
        
        # Auto-propagation setting
        self.auto_propagate = False
        
        # Create GUI components
        self.create_widgets()
        
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container with padding
        main_frame = ctk.CTkFrame(self.root, fg_color="#0d1117")
        main_frame.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Header with gradient effect
        header_frame = ctk.CTkFrame(main_frame, fg_color="#161b22", height=80)
        header_frame.pack(fill="x", padx=0, pady=(0, 0))
        header_frame.pack_propagate(False)
        
        # Logo/title section
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.pack(side="left", padx=30, pady=15)
        
        ctk.CTkLabel(
            title_container,
            text="",
            font=ctk.CTkFont(size=32)
        ).pack(side="left", padx=(0, 10))
        
        title_text = ctk.CTkFrame(title_container, fg_color="transparent")
        title_text.pack(side="left")
        
        ctk.CTkLabel(
            title_text,
            text="OSINT Tool",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            title_text,
            text="Open Source Intelligence Platform",
            font=ctk.CTkFont(size=12),
            text_color="#8b949e"
        ).pack(anchor="w")
        
        # Tabview for different tools
        self.tabview = ctk.CTkTabview(main_frame, fg_color="#0d1117")
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)
        
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
        
    def setup_api_tab(self):
        """Setup API configuration tab."""
        # Main frame
        main_frame = ctk.CTkFrame(self.tab_api)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Title
        ctk.CTkLabel(main_frame, text="API Key Configuration", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        ctk.CTkLabel(main_frame, text="Configure your API keys for premium services. Keys are stored in .env file for security.", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=10, pady=(0, 10))
        
        # Instructions
        info_frame = ctk.CTkFrame(main_frame)
        info_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        instructions = (
            "To configure API keys:\n"
            "1. Copy .env.example to .env\n"
            "2. Add your API keys to the .env file\n"
            "3. Restart the application\n\n"
            "API keys are loaded from environment variables for security."
        )
        ctk.CTkLabel(info_frame, text=instructions, font=ctk.CTkFont(size=10)).pack(anchor="w", padx=10, pady=10)
        
        # Check if .env exists
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        if os.path.exists(env_path):
            ctk.CTkLabel(main_frame, text="✅ .env file detected - API keys will be loaded from environment", font=ctk.CTkFont(size=10), text_color="#2d8659").pack(anchor="w", padx=10, pady=(0, 10))
        else:
            ctk.CTkLabel(main_frame, text="⚠️ .env file not found - Copy .env.example to .env and add your keys", font=ctk.CTkFont(size=10), text_color="#d4a017").pack(anchor="w", padx=10, pady=(0, 10))
        
    def setup_security_tab(self):
        """Setup security tab."""
        # Input frame
        input_frame = ctk.CTkFrame(self.tab_security)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Label
        ctk.CTkLabel(input_frame, text="Query:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Entry with StringVar for reliable text tracking
        self.security_query_var = tk.StringVar()
        self.security_query_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter email, phone, or name",
            textvariable=self.security_query_var
        )
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
        
        # VT IP button
        self.vt_ip_btn = ctk.CTkButton(
            button_frame,
            text="VT IP Scan",
            command=self.run_vt_ip_scan,
            height=40
        )
        self.vt_ip_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # VT domain button
        self.vt_domain_btn = ctk.CTkButton(
            button_frame,
            text="VT Domain Scan",
            command=self.run_vt_domain_scan,
            height=40
        )
        self.vt_domain_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Spokeo button
        self.spokeo_btn = ctk.CTkButton(
            button_frame,
            text="Spokeo Search",
            command=self.run_spokeo_search,
            height=40,
            fg_color="#1a5fb4"
        )
        self.spokeo_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        # Whitepages button
        self.whitepages_btn = ctk.CTkButton(
            button_frame,
            text="WhitePages Person Search",
            command=self.run_whitepages_search,
            height=40,
            fg_color="#1a5fb4"
        )
        self.whitepages_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
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
    
    def run_hibp_check(self):
        """Run HIBP breach check in a separate thread."""
        query = self.security_query_var.get().strip()
        if not query or '@' not in query:
            messagebox.showerror("Error", "Please enter a valid email address")
            return
        
        self.hibp_btn.configure(state="disabled", text="Checking...")
        
        def lookup():
            try:
                results = self.security_handler.hibp_breach_check(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.hibp_btn.configure(state="normal", text="HIBP Breach Check"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_vt_ip_scan(self):
        """Run VirusTotal IP scan in a separate thread."""
        query = self.security_query_var.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        self.vt_ip_btn.configure(state="disabled", text="Scanning...")
        
        def lookup():
            try:
                results = self.security_handler.virustotal_ip_scan(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.vt_ip_btn.configure(state="normal", text="VT IP Scan"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_vt_domain_scan(self):
        """Run VirusTotal domain scan in a separate thread."""
        query = self.security_query_var.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.vt_domain_btn.configure(state="disabled", text="Scanning...")
        
        def lookup():
            try:
                results = self.security_handler.virustotal_domain_scan(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.vt_domain_btn.configure(state="normal", text="VT Domain Scan"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_spokeo_search(self):
        """Run Spokeo search in a separate thread."""
        query = self.security_query_var.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a search query")
            return
        
        self.spokeo_btn.configure(state="disabled", text="Searching...")
        
        def lookup():
            try:
                results = self.security_handler.spokeo_search(query)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.spokeo_btn.configure(state="normal", text="Spokeo Search"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def run_whitepages_search(self):
        """Run WhitePages person search in a separate thread."""
        query = self.security_query_var.get().strip()
        
        if not query:
            messagebox.showerror("Error", "Please enter a valid search query (email, phone, or name)")
            return
        
        # Determine search type based on query content
        search_type = self._determine_whitepages_search_type(query)
        
        # Show user what type was detected
        type_labels = {
            'email': 'Email',
            'phone': 'Phone',
            'name': 'Name'
        }
        self.whitepages_btn.configure(state="disabled", text=f"Searching as {type_labels[search_type]}...")
        
        def lookup():
            try:
                results = self.security_handler.whitepages_person_search(query, search_type)
                self.root.after(0, lambda: self.display_results(self.security_results, results, 'security'))
            except Exception as e:
                self.root.after(0, lambda: self.display_results(self.security_results, {"error": str(e)}, 'security'))
            finally:
                self.root.after(0, lambda: self.whitepages_btn.configure(state="normal", text="WhitePages Person Search"))
        
        threading.Thread(target=lookup, daemon=True).start()
    
    def _determine_whitepages_search_type(self, query: str) -> str:
        """
        Determine the type of WhitePages search based on query content.
        
        This method uses pattern matching to identify:
        - Email addresses (contains @ and domain)
        - Phone numbers (digits with optional formatting)
        - Names (default fallback)
        
        Args:
            query: The search query string from the user
            
        Returns:
            str: The search type ('email', 'phone', or 'name')
        """
        # Normalize query for analysis
        normalized = query.strip().lower()
        
        # Email pattern: contains @ and has a domain with at least one dot
        if '@' in normalized:
            parts = normalized.split('@')
            if len(parts) == 2 and '.' in parts[1] and len(parts[1]) > 3:
                return 'email'
        
        # Phone pattern: extract digits and check length
        # Remove all non-digit characters
        digits_only = ''.join(char for char in query if char.isdigit())
        
        # Phone numbers are typically 10-15 digits (with country code)
        if len(digits_only) >= 10 and len(digits_only) <= 15:
            # Additional check: ensure it's not just random numbers
            # Phone numbers usually have some pattern
            if len(digits_only) >= 10:
                return 'phone'
        
        # Default to name search for anything else
        return 'name'
    
    def display_results(self, text_widget, data, result_type='ip', email_input=None):
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
            if result_type == 'email' and email_input:
                self.entity_extractor._extract_from_email(data, result_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), email_input)
            else:
                self.entity_extractor.extract_entities(data, result_type)
        
        # Format and display results
        formatted = format_results(data, result_type)
        text_widget.insert("end", formatted)
        
        # Update intelligence display
        self.update_intel_display()
        
        # Auto-propagate if enabled
        if self.auto_propagate and 'error' not in data:
            self.auto_propagate_entities(data, result_type)
        
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
                self.root.after(0, lambda: self.display_results(self.email_results, results, 'email', email))
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
    
    def update_intel_display(self):
        """Update the collected intelligence display."""
        # Clear existing widgets
        for widget in self.intel_scroll.winfo_children():
            widget.destroy()
        
        entities = self.entity_extractor.discovered_entities
        
        # IPs section
        if entities['ips']:
            ip_frame = ctk.CTkFrame(self.intel_scroll)
            ip_frame.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(ip_frame, text=f"🌐 IP Addresses ({len(entities['ips'])})", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for ip in sorted(entities['ips']):
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
        if entities['domains']:
            domain_frame = ctk.CTkFrame(self.intel_scroll)
            domain_frame.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(domain_frame, text=f"🔗 Domains ({len(entities['domains'])})", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for domain in sorted(entities['domains']):
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
        if entities['emails']:
            email_frame = ctk.CTkFrame(self.intel_scroll)
            email_frame.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(email_frame, text=f"📧 Emails ({len(entities['emails'])})", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for email in sorted(entities['emails']):
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
        if not any(entities.values()):
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
        new_entities = self.entity_extractor.entity_history[-5:] if len(self.entity_extractor.entity_history) > 5 else self.entity_extractor.entity_history
        
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
        self.entity_extractor.clear_all()
        self.update_intel_display()
        messagebox.showinfo("Cleared", "All collected intelligence has been cleared.")
    
    def save_intelligence(self):
        """Save collected intelligence to a file."""
        entities = self.entity_extractor.get_entities_dict()
        if not any(entities.values()):
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
                'entities': entities,
                'history': self.entity_extractor.entity_history
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
