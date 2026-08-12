"""
====================================================================================
AGILE PROJECT MANAGEMENT & DOCUMENTATION
====================================================================================
EPIC: Develop an automated data propagation and visualization dashboard.

CURRENT PHASE: Sprint 1 - UI/UX Minimum Viable Product (MVP)
Sprint Goal: Deliver a purely visual, structural skeleton for stakeholder approval 
before committing resources to complex backend data pipelines.

PRODUCT BACKLOG (Future Sprints):
- Sprint 2: Wire the 'Initialize' button to a backend Python controller (Controller Pattern).
- Sprint 3: Integrate first OSINT API (e.g., HaveIBeenPwned or a dummy internal database).
- Sprint 4: Implement Matplotlib/NetworkX in the "Relationship Graph" tab.
- Sprint 5: Implement CI/CD pipeline for automated testing of backend data parsers.
====================================================================================
"""

import customtkinter as ctk

class IntelligenceDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Window Configuration ---
        self.title("Data Propagation & Analysis Engine - MVP v0.1")
        self.geometry("1100x700")
        
        # Grid layout: 1 row, 2 columns (Sidebar + Main Area)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # SIDEBAR PANEL (Controls & Input)
        # AGILE USER STORY: "As an analyst, I need a static control panel on the left side so I can easily input target identifiers."

        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="OSINT\nDashboard", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        self.seed_label = ctk.CTkLabel(self.sidebar_frame, text="Target Identifier (Seed):")
        self.seed_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.seed_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="e.g., Phone, Email")
        self.seed_entry.grid(row=2, column=0, padx=20, pady=(5, 20), sticky="ew")

        # AGILE NOTE: In Sprint 1, this button does nothing (Mocked). 
        # In Sprint 2, we will bind this to a command: `command=self.start_propagation`

        self.start_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Initialize Propagation", 
            fg_color="#2B7A0B", 
            hover_color="#3A9A11"
        )
        self.start_button.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.export_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Export Target Profile", 
            fg_color="#333333"
        )
        self.export_button.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: IDLE", text_color="gray")
        self.status_label.grid(row=6, column=0, padx=20, pady=20, sticky="sw")

        # MAIN CONTENT AREA (Tabs)
        # AGILE USER STORY: "As a user, I want my data views separated into distinct tabs to avoid cognitive overload on a single screen."

        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tabview.add("Compiled Profile")
        self.tabview.add("Relationship Graph")
        self.tabview.add("Execution Logs")

        # --- Tab 1: Compiled Profile ---
        self.tabview.tab("Compiled Profile").grid_columnconfigure(0, weight=1)
        self.tabview.tab("Compiled Profile").grid_rowconfigure(0, weight=1)
        
        self.profile_text = ctk.CTkTextbox(
            self.tabview.tab("Compiled Profile"), 
            font=ctk.CTkFont(family="Consolas", size=14)
        )
        self.profile_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.profile_text.insert("0.0", "=== TARGET PROFILE ===\n\nAwaiting propagation data...\n")
        self.profile_text.configure(state="disabled")

        # --- Tab 2: Relationship Graph ---
        # AGILE NOTE: "Stubbing" or "Mocking". 
        # Agile encourages putting a placeholder here so the UI is 'done', and pushing the complex graph logic to the Sprint 4 backlog.

        self.tabview.tab("Relationship Graph").grid_columnconfigure(0, weight=1)
        self.tabview.tab("Relationship Graph").grid_rowconfigure(0, weight=1)
        
        self.graph_label = ctk.CTkLabel(
            self.tabview.tab("Relationship Graph"), 
            text="[ Network Graph Canvas Visualization Area ]\n\n(Backlog: Slated for Sprint 4 Integration)",
            text_color="gray"
        )
        self.graph_label.grid(row=0, column=0, sticky="nsew")

        # --- Tab 3: Execution Logs ---

        self.tabview.tab("Execution Logs").grid_columnconfigure(0, weight=1)
        self.tabview.tab("Execution Logs").grid_rowconfigure(0, weight=1)
        
        self.log_text = ctk.CTkTextbox(
            self.tabview.tab("Execution Logs"), 
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # AGILE NOTE: Logging is crucial for iterative testing. 
        # In future sprints, the backend classes will append directly to this textbox.

        self.log_text.insert("0.0", "[*] System initialized.\n[*] UI Skeleton Loaded (Sprint 1 Complete).\n[*] Ready for backend integration...")
        self.log_text.configure(state="disabled")

# AGILE SCRUM MASTER / DEVOPS NOTE:
# This block ensures the file can be executed locally for manual UI testing, but can also be imported securely as a module in larger test suites.

if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue") 
    
    app = IntelligenceDashboard()
    app.mainloop()