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
        
        # Setup each tab
        self.setup_ip_tab()
        self.setup_domain_tab()
        self.setup_email_tab()
        
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
        
        # Format and display results
        formatted = self.format_results(data, result_type)
        text_widget.insert("end", formatted)
    
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
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point for GUI application."""
    app = OSINTGUI()
    app.run()


if __name__ == '__main__':
    main()
