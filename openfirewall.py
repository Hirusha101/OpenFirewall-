#!/usr/bin/env python3

import socket
import struct
import logging
import json
import os
import subprocess
import time
import psutil
import ipaddress
from typing import Dict, List, Tuple, Optional
from threading import Thread, Event
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from queue import Queue

class FirewallGUI:
    def __init__(self):
        self.log_queue = Queue()
        self.firewall = Firewall()
        self.firewall.set_log_queue(self.log_queue)
        self.running = False
        self.root = tk.Tk()
        self.root.title("Open Firewall")
        self.root.geometry("1400x900")
        self.root.configure(bg="#e6f3ff")
        self.root.minsize(1200, 800)
        
        # UI Configuration
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", background="#e6f3ff", font=("Helvetica", 10))
        self.style.configure("TButton", font=("Helvetica", 10), background="#cce5ff")
        self.style.configure("TLabelframe.Label", font=("Helvetica", 12, "bold"), foreground="#004080")
        self.style.configure("Treeview", rowheight=30)
        
        # Custom styles
        self.style.configure("Accent.TButton", background="#80bfff", foreground="#004080")
        self.style.configure("Green.TButton", background="#80ff80", foreground="#006600")
        self.style.configure("Red.TButton", background="#ff8080", foreground="#660000")
        self.style.map("Treeview", background=[('selected', '#0078d7')], foreground=[('selected', 'white')])
        
        # Main frame configuration
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill="both", expand=True)
        
        # Configure grid weights - make all columns expand
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # Rules Treeview
        rules_frame = ttk.LabelFrame(self.main_frame, text="Firewall Rules", padding="10")
        rules_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        rules_frame.grid_columnconfigure(0, weight=1)
        rules_frame.grid_rowconfigure(0, weight=1)

        self.rules_tree = ttk.Treeview(rules_frame, 
                                    columns=("Action", "Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port", "Enabled"),
                                    show="headings", height=10)

        # Treeview column configuration - use pixel values initially
        col_widths = {
            "Action": 100,
            "Src IP": 180,
            "Dst IP": 180,
            "Protocol": 100,
            "Src Port": 100,
            "Dst Port": 100,
            "Enabled": 80
        }

        for col, width in col_widths.items():
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=width, anchor="center", stretch=True)
                    
        self.rules_tree.tag_configure('oddrow', background='#f0f0f0')
        self.rules_tree.tag_configure('evenrow', background='#ffffff')
        
        #Scrollbars
        tree_scroll_y = ttk.Scrollbar(rules_frame, orient="vertical", command=self.rules_tree.yview)
        tree_scroll_x = ttk.Scrollbar(rules_frame, orient="horizontal", command=self.rules_tree.xview)
        self.rules_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        self.rules_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x.grid(row=1, column=0, sticky="ew")
        
        rules_frame.grid_rowconfigure(0, weight=1)
        rules_frame.grid_columnconfigure(0, weight=1)
        
        # Rule management buttons
        rules_btn_frame = ttk.Frame(rules_frame)
        rules_btn_frame.grid(row=2, column=0, columnspan=2, pady=(5, 0), sticky="ew")
        
        btn_config = {
            "Add Rule": ("Accent.TButton", self.show_add_rule),
            "Edit Rule": ("Accent.TButton", self.edit_rule),
            "Delete Rule": ("Accent.TButton", self.delete_rule),
            "Toggle": ("Accent.TButton", self.toggle_rule)
        }
        
        for i, (text, (style, cmd)) in enumerate(btn_config.items()):
            ttk.Button(rules_btn_frame, text=text, command=cmd, style=style).grid(
                row=0, column=i, padx=5, pady=5, sticky="ew")
            rules_btn_frame.grid_columnconfigure(i, weight=1)
        
        # Control buttons
        control_frame = ttk.Frame(self.main_frame)
        control_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Button(control_frame, text="Start Firewall", command=self.start_firewall, 
                  style="Green.TButton").pack(side="left", padx=5)
        ttk.Button(control_frame, text="Stop Firewall", command=self.stop_firewall, 
                  style="Red.TButton").pack(side="left", padx=5)
        
        # Middle frame for logs and status
        middle_frame = ttk.Frame(self.main_frame)
        middle_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=5)
        
        # Configure weights for log and status frames
        middle_frame.grid_columnconfigure(0, weight=3)  # 75% width for logs
        middle_frame.grid_columnconfigure(1, weight=1)  # 25% width for status
        middle_frame.grid_rowconfigure(0, weight=1)
        
        # Log frame
        log_frame = ttk.LabelFrame(middle_frame, text="Real-time Packet Log", padding="10")
        log_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        
        
        self.log_text = tk.Text(log_frame, height=15, width=60, font=("Courier", 10), 
                               bg="#fff0f5", wrap=tk.WORD)
        log_scroll_y = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        log_scroll_x = ttk.Scrollbar(log_frame, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)
        
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll_y.grid(row=0, column=1, sticky="ns")
        log_scroll_x.grid(row=1, column=0, sticky="ew")
        
        
        # Status frame
        status_frame = ttk.LabelFrame(middle_frame, text="System Status", padding="10")
        status_frame.grid(row=0, column=1, sticky="nsew")
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_rowconfigure(0, weight=1)
        
        self.status_text = tk.Text(status_frame, height=15, width=40, font=("Helvetica", 10), 
                                 bg="#f0fff0", wrap=tk.WORD)
        status_scroll = ttk.Scrollbar(status_frame, command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=status_scroll.set)
        
        self.status_text.grid(row=0, column=0, sticky="nsew")
        status_scroll.grid(row=0, column=1, sticky="ns")
        
        
        # Bottom buttons
        bottom_frame = ttk.Frame(self.main_frame)
        bottom_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        
        ttk.Button(bottom_frame, text="Clear Logs", command=self.clear_logs, 
                  style="Accent.TButton").pack(side="left", padx=5)
        ttk.Button(bottom_frame, text="Save Config", command=self.save_config, 
                  style="Accent.TButton").pack(side="left", padx=5)
        ttk.Button(bottom_frame, text="Load Config", command=self.load_config, 
                  style="Accent.TButton").pack(side="left", padx=5)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Firewall Stopped", relief="sunken", 
                                  anchor="w", padding=5, background="#cce5ff")
        self.status_bar.pack(fill="x", side="bottom")
        
        # Initialize
        self.refresh_rules()
        self.update_status()
        self.root.after(1000, self.update_logs)
        self.root.after(5000, self.update_status)
        
        self.root.bind('<Configure>', self.on_window_resize)

    def on_window_resize(self, event):
        if event.widget == self.root:
            window_width = self.root.winfo_width()
            if window_width > 100:
                # Calculate column widths based on percentage of window width
                col_widths = {
                    "Action": int(window_width * 0.10),
                    "Src IP": int(window_width * 0.20),
                    "Dst IP": int(window_width * 0.20),
                    "Protocol": int(window_width * 0.10),
                    "Src Port": int(window_width * 0.10),
                    "Dst Port": int(window_width * 0.10),
                    "Enabled": int(window_width * 0.05)
                }
                
                for col, width in col_widths.items():
                    self.rules_tree.column(col, width=width)

    def validate_rule_inputs(self, rule: Dict) -> bool:
        try:
            if rule.get('src_ip', 'any') != 'any':
                ipaddress.ip_network(rule['src_ip'], strict=False)
            if rule.get('dst_ip', 'any') != 'any':
                ipaddress.ip_network(rule['dst_ip'], strict=False)
            
            if rule.get('src_port', 'any') != 'any':
                if '-' in rule['src_port']:
                    start, end = map(int, rule['src_port'].split('-'))
                    if not (0 <= start <= 65535 and 0 <= end <= 65535 and start <= end):
                        return False
                else:
                    port = int(rule['src_port'])
                    if not 0 <= port <= 65535:
                        return False
            
            if rule.get('dst_port', 'any') != 'any':
                if '-' in rule['dst_port']:
                    start, end = map(int, rule['dst_port'].split('-'))
                    if not (0 <= start <= 65535 and 0 <= end <= 65535 and start <= end):
                        return False
                else:
                    port = int(rule['dst_port'])
                    if not 0 <= port <= 65535:
                        return False
            
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False

    def get_common_ips(self) -> List[str]:
        return [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "0.0.0.0/0"
        ]

    def get_common_ports(self) -> List[str]:
        return [
            "22", "80", "443", "53", 
            "20-21", "3389", "5900", "1-1024"
        ]

    def start_firewall(self):
        if not self.running:
            try:
                self.log_queue.put("Initializing firewall...")
                result = subprocess.run(["sudo", "iptables", "-L"], 
                                      check=True, 
                                      capture_output=True, 
                                      text=True)
                self.log_queue.put("iptables access verified")
                
                self.firewall.stop_event.clear()
                self.firewall_thread = Thread(target=self.firewall.run, daemon=True)
                self.firewall_thread.start()
                
                self.running = True
                self.status_bar.config(text="Firewall Started", background="#80ff80")
                self.log_queue.put("Firewall started successfully")
                self.firewall.sync_iptables_rules()
                
            except subprocess.CalledProcessError as e:
                error_msg = f"Permission Error: {e.stderr}"
                self.log_queue.put(f"ERROR: {error_msg}")
                messagebox.showerror("Permission Error", 
                    "Firewall requires root privileges to modify iptables rules.\n"
                    "Please ensure you have sudo access configured.")
                if self.firewall:
                    self.firewall.stop_event.set()

    def stop_firewall(self):
        if self.running and self.firewall:
            self.log_queue.put("Stopping firewall...")
            self.firewall.stop_event.set()
            self.firewall.clear_iptables()
            self.firewall_thread.join(timeout=2)
            self.running = False
            self.status_bar.config(text="Firewall Stopped", background="#ff8080")
            self.log_queue.put("Firewall stopped successfully")

    def show_add_rule(self):
        self.show_rule_dialog("Add Rule")

    def edit_rule(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        self.show_rule_dialog("Edit Rule", self.rules_tree.item(selected[0])["values"])

    def toggle_rule(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to toggle")
            return
            
        index = self.rules_tree.index(selected[0])
        rule = self.firewall.rules[index]
        rule['enabled'] = not rule.get('enabled', True)
        
        self.firewall.save_rules()
        if self.running:
            self.firewall.sync_iptables_rules()
        self.refresh_rules()
        
        status = "enabled" if rule['enabled'] else "disabled"
        self.log_queue.put(f"Rule {index} {status}")

    def show_rule_dialog(self, title, values=None):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.configure(bg="#e6f3ff")
        
        fields = [
            ("Action", ["allow", "block"]),
            ("Source IP", ["any"] + self.get_common_ips()),
            ("Dest IP", ["any"] + self.get_common_ips()),
            ("Protocol", ["any", "tcp", "udp", "icmp"]),
            ("Source Port", ["any"] + self.get_common_ports()),
            ("Dest Port", ["any"] + self.get_common_ports()),
            ("Enabled", ["yes", "no"])
        ]
        
        entries = {}
        for i, (label, options) in enumerate(fields):
            ttk.Label(dialog, text=f"{label}:", anchor="e").grid(row=i, column=0, padx=10, pady=10, sticky="e")
            var = tk.StringVar(value=values[i] if values and i < len(values) else options[0])
            entries[label] = ttk.Combobox(dialog, textvariable=var, values=options, width=40)
            entries[label].grid(row=i, column=1, padx=10, pady=10)
        
        save_button = ttk.Button(dialog, text="Save", command=lambda: self.save_rule(dialog, title, entries), style="Accent.TButton")
        save_button.grid(row=len(fields), column=0, columnspan=2, pady=20)

    def save_rule(self, dialog, title, entries):
        rule = {
            'action': entries['Action'].get(),
            'src_ip': entries['Source IP'].get(),
            'dst_ip': entries['Dest IP'].get(),
            'protocol': entries['Protocol'].get(),
            'src_port': entries['Source Port'].get(),
            'dst_port': entries['Dest Port'].get(),
            'enabled': entries['Enabled'].get() == "yes"
        }
        
        if not self.validate_rule_inputs(rule):
            messagebox.showerror("Error", "Invalid rule parameters")
            return
            
        if title == "Add Rule":
            self.firewall.rules.append(rule)
            self.log_queue.put(f"Added new rule: {rule}")
        else:
            selected = self.rules_tree.selection()[0]
            old_rule = self.firewall.rules[self.rules_tree.index(selected)]
            self.firewall.rules[self.rules_tree.index(selected)] = rule
            self.log_queue.put(f"Updated rule from {old_rule} to {rule}")
            
        self.firewall.save_rules()
        if self.running:
            self.firewall.sync_iptables_rules()
        self.refresh_rules()
        dialog.destroy()

    def delete_rule(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
        if messagebox.askyesno("Confirm", "Delete selected rule?"):
            index = self.rules_tree.index(selected[0])
            deleted_rule = self.firewall.rules[index]
            del self.firewall.rules[index]
            self.firewall.save_rules()
            if self.running:
                self.firewall.sync_iptables_rules()
            self.refresh_rules()
            self.log_queue.put(f"Deleted rule: {deleted_rule}")

    def refresh_rules(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        for i, rule in enumerate(self.firewall.rules):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            self.rules_tree.insert("", "end", values=(
                rule.get("action", "unknown"),
                rule.get("src_ip", "any"),
                rule.get("dst_ip", "any"),
                rule.get("protocol", "any"),
                rule.get("src_port", "any"),
                rule.get("dst_port", "any"),
                "Yes" if rule.get('enabled', True) else "No"
            ), tags=(tag,))

    def update_logs(self):
        self.log_text.tag_config("allow", foreground="green", font=('Courier', 10, 'bold'))
        self.log_text.tag_config("block", foreground="red", font=('Courier', 10, 'bold'))
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("info", foreground="blue")
        
        while not self.log_queue.empty():
            log = self.log_queue.get()
            timestamp = time.strftime("%H:%M:%S")
            full_msg = f"{timestamp} - {log}"
            
            if "ALLOW" in log:
                self.log_text.insert(tk.END, full_msg + "\n", "allow")
            elif "BLOCK" in log:
                self.log_text.insert(tk.END, full_msg + "\n", "block")
            elif "ERROR" in log:
                self.log_text.insert(tk.END, full_msg + "\n", "error")
            else:
                self.log_text.insert(tk.END, full_msg + "\n", "info")
            
            self.log_text.see(tk.END)
        
        self.root.after(100, self.update_logs)

    def clear_logs(self):
        if messagebox.askyesno("Confirm", "Clear all logs?"):
            open('firewall.log', 'w').close()
            self.log_text.delete(1.0, tk.END)
            self.status_bar.config(text="Logs cleared", background="#cce5ff")

    def update_status(self):
        self.status_text.delete(1.0, tk.END)
        status = (
            f"CPU Usage: {psutil.cpu_percent()}%\n"
            f"Memory Usage: {psutil.virtual_memory().percent}%\n"
            f"Active Connections: {len(self.firewall.connections) if hasattr(self.firewall, 'connections') else 0}\n"
            f"Rules Loaded: {len(self.firewall.rules)}\n"
            f"Network Interfaces: {len(psutil.net_if_addrs())}\n"
            f"Firewall Status: {'Running' if self.running else 'Stopped'}\n\n"
            f"Last Update: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.status_text.insert(tk.END, status)
        self.status_bar.config(text=f"Firewall {'Running' if self.running else 'Stopped'}")
        self.root.after(1000, self.update_status)

    def save_config(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json", title="Save Configuration")
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.firewall.rules, f, indent=4)
                message = f"Configuration saved to {filename}"
                messagebox.showinfo("Success", message)
                self.status_bar.config(text=message, background="#cce5ff")
                self.log_queue.put(message)
            except Exception as e:
                error_msg = f"Failed to save config: {e}"
                messagebox.showerror("Error", error_msg)
                self.status_bar.config(text=error_msg, background="#ff8080")
                self.log_queue.put(f"ERROR: {error_msg}")

    def load_config(self):
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")], title="Load Configuration")
        if filename:
            try:
                with open(filename, 'r') as f:
                    self.firewall.rules = json.load(f)
                self.firewall.save_rules()
                if self.running:
                    self.firewall.sync_iptables_rules()
                self.refresh_rules()
                message = f"Configuration loaded from {filename}"
                messagebox.showinfo("Success", message)
                self.status_bar.config(text=message, background="#cce5ff")
                self.log_queue.put(message)
            except Exception as e:
                error_msg = f"Failed to load config: {e}"
                messagebox.showerror("Error", error_msg)
                self.status_bar.config(text=error_msg, background="#ff8080")
                self.log_queue.put(f"ERROR: {error_msg}")

    def run(self):
        self.root.mainloop()

class Firewall:
    def __init__(self, config_file: str = "firewall_config.json"):
        self.log_queue = None
        self.config_file = config_file
        self.rules = self.load_rules()
        self.connections: Dict[Tuple, dict] = {}
        self.stop_event = Event()
        self.initialize_socket()
        self.initialize_iptables_chains()
        self.setup_logging()

    def initialize_socket(self):
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.log_queue:
                self.log_queue.put("Raw socket initialized successfully")
        except PermissionError:
            error_msg = "Run with sudo for raw socket access"
            if self.log_queue:
                self.log_queue.put(f"ERROR: {error_msg}")
            raise Exception(error_msg)
        except Exception as e:
            if self.log_queue:
                self.log_queue.put(f"ERROR initializing socket: {e}")
            raise

    def set_log_queue(self, queue):
        self.log_queue = queue
        if queue:
            queue.put("Logging queue connected to firewall")

    def setup_logging(self):
        logging.basicConfig(
            filename='firewall.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('Firewall')
        if self.log_queue:
            self.log_queue.put("Logging system initialized")

    def load_rules(self) -> List[Dict]:
        default_rules = [
            {"action": "allow", "src_ip": "any", "dst_ip": "any", 
             "protocol": "tcp", "src_port": "any", "dst_port": "80", "enabled": True},
            {"action": "block", "src_ip": "any", "dst_ip": "any", 
             "protocol": "icmp", "src_port": "any", "dst_port": "any", "enabled": True}
        ]
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    rules = json.load(f)
                if self.log_queue:
                    self.log_queue.put(f"Loaded {len(rules)} rules from config file")
                return rules
        except Exception as e:
            if self.log_queue:
                self.log_queue.put(f"WARNING: Failed to load config: {e}. Using default rules")
        return default_rules

    def save_rules(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.rules, f, indent=4)
        if self.log_queue:
            self.log_queue.put(f"Saved {len(self.rules)} rules to config file")

    def run_command(self, cmd):
        try:
            if self.log_queue:
                self.log_queue.put(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(['sudo'] + cmd, check=True, capture_output=True, text=True)
            if self.log_queue:
                self.log_queue.put(f"Command succeeded: {' '.join(cmd)}")
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: {' '.join(cmd)}\nError: {e.stderr}"
            if self.log_queue:
                self.log_queue.put(f"ERROR: {error_msg}")
            return False

    def initialize_iptables_chains(self):
        try:
            if self.log_queue:
                self.log_queue.put("Initializing iptables chains...")
            
            self.run_command(["iptables", "-N", "PYFIREWALL_IN"])
            self.run_command(["iptables", "-N", "PYFIREWALL_OUT"])
            
            self.run_command(["iptables", "-F", "PYFIREWALL_IN"])
            self.run_command(["iptables", "-F", "PYFIREWALL_OUT"])
            
            if not self.run_command(["iptables", "-C", "INPUT", "-j", "PYFIREWALL_IN"]):
                self.run_command(["iptables", "-A", "INPUT", "-j", "PYFIREWALL_IN"])
            if not self.run_command(["iptables", "-C", "OUTPUT", "-j", "PYFIREWALL_OUT"]):
                self.run_command(["iptables", "-A", "OUTPUT", "-j", "PYFIREWALL_OUT"])
            
            if self.log_queue:
                self.log_queue.put("iptables chains initialized successfully")
        except Exception as e:
            if self.log_queue:
                self.log_queue.put(f"ERROR initializing iptables chains: {e}")

    def parse_packet(self, packet: bytes) -> Dict:
        try:
            eth_header = packet[:14]
            eth = struct.unpack('!6s6sH', eth_header)
            ip_header = packet[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            transport_header = packet[14 + iph_length:]
            ports = {"src_port": "any", "dst_port": "any"}
            
            if protocol == 6:  # TCP
                tcp_header = struct.unpack('!HHLLBBHHH', transport_header[:20])
                ports["src_port"] = str(tcp_header[0])
                ports["dst_port"] = str(tcp_header[1])
            elif protocol == 17:  # UDP
                udp_header = struct.unpack('!HHHH', transport_header[:8])
                ports["src_port"] = str(udp_header[0])
                ports["dst_port"] = str(udp_header[1])
                
            protocol_map = {6: "tcp", 17: "udp", 1: "icmp"}
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol_map.get(protocol, "all"),
                **ports
            }
        except Exception as e:
            if self.log_queue:
                self.log_queue.put(f"ERROR parsing packet: {e}")
            raise

    def match_rule(self, packet_info: Dict) -> Optional[Dict]:
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            if not self._rule_matches(rule, packet_info):
                continue
            
            if packet_info['protocol'] == 'tcp':
                conn_key = self._get_connection_key(packet_info)
                if conn_key in self.connections:
                    return self.connections[conn_key]
                
                self.connections[conn_key] = rule
                if len(self.connections) > 10000:
                    self._cleanup_old_connections()
            
            return rule
        
        return None

    def _rule_matches(self, rule: Dict, packet_info: Dict) -> bool:
        if rule['protocol'] != 'any' and rule['protocol'] != packet_info['protocol']:
            return False
        
        if rule['src_ip'] != 'any' and not self._ip_matches(rule['src_ip'], packet_info['src_ip']):
            return False
        
        if rule['dst_ip'] != 'any' and not self._ip_matches(rule['dst_ip'], packet_info['dst_ip']):
            return False
        
        if rule['src_port'] != 'any' and not self._port_matches(rule['src_port'], packet_info['src_port']):
            return False
        
        if rule['dst_port'] != 'any' and not self._port_matches(rule['dst_port'], packet_info['dst_port']):
            return False
            
        return True

    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        try:
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                ip = ipaddress.ip_address(packet_ip)
                return ip in network
            return rule_ip == packet_ip
        except ValueError:
            return False

    def _port_matches(self, rule_port: str, packet_port: str) -> bool:
        try:
            if '-' in rule_port:
                start, end = map(int, rule_port.split('-'))
                port = int(packet_port)
                return start <= port <= end
            return rule_port == packet_port
        except ValueError:
            return False

    def _get_connection_key(self, packet_info: Dict) -> Tuple:
        return (
            packet_info['src_ip'], 
            packet_info['dst_ip'],
            packet_info['src_port'],
            packet_info['dst_port'],
            packet_info['protocol']
        )

    def _cleanup_old_connections(self):
        cutoff = time.time() - 3600
        self.connections = {
            k: v for k, v in self.connections.items() 
            if v['timestamp'] > cutoff
        }

    def apply_iptables_rule(self, rule: Dict) -> bool:
        if not rule.get('enabled', True):
            return True
            
        chain = "PYFIREWALL_IN"
        
        cmd = ["iptables", "-A", chain]
        
        if rule['protocol'] != 'any':
            cmd.extend(["-p", rule['protocol']])
        
        if rule['src_ip'] != 'any':
            cmd.extend(["-s", rule['src_ip']])
        
        if rule['dst_ip'] != 'any':
            cmd.extend(["-d", rule['dst_ip']])
        
        if rule['protocol'] in ['tcp', 'udp']:
            if rule['src_port'] != 'any':
                if '-' in rule['src_port']:
                    cmd.extend(["-m", "multiport", "--sports", rule['src_port']])
                else:
                    cmd.extend(["--sport", rule['src_port']])
            
            if rule['dst_port'] != 'any':
                if '-' in rule['dst_port']:
                    cmd.extend(["-m", "multiport", "--dports", rule['dst_port']])
                else:
                    cmd.extend(["--dport", rule['dst_port']])
        
        action = "DROP" if rule['action'] == "block" else "ACCEPT"
        cmd.extend(["-j", action])
        
        return self.run_command(cmd)

    def sync_iptables_rules(self):
        if self.log_queue:
            self.log_queue.put("Synchronizing iptables rules...")
        
        self.clear_iptables()
        self.initialize_iptables_chains()
        
        for rule in self.rules:
            if not self.apply_iptables_rule(rule):
                if self.log_queue:
                    self.log_queue.put(f"Failed to sync rule: {rule}")
        
        if self.log_queue:
            self.log_queue.put(f"Successfully synchronized {len(self.rules)} rules to iptables")

    def clear_iptables(self):
        try:
            if self.log_queue:
                self.log_queue.put("Cleaning up iptables rules...")

            # 1. FLUSH custom chains to remove rules
            self.run_command(["iptables", "-F", "PYFIREWALL_IN"])
            self.run_command(["iptables", "-F", "PYFIREWALL_OUT"])

            # 2. REMOVE references to custom chains in INPUT and OUTPUT
            self.run_command(["iptables", "-D", "INPUT", "-j", "PYFIREWALL_IN"])
            self.run_command(["iptables", "-D", "OUTPUT", "-j", "PYFIREWALL_OUT"])

            # 3. ENSURE no references exist before deleting
            self.run_command(["iptables", "-L"])  # Check if chains are still in use

            # 4. DELETE the custom chains
            self.run_command(["iptables", "-X", "PYFIREWALL_IN"])
            self.run_command(["iptables", "-X", "PYFIREWALL_OUT"])

            if self.log_queue:
                self.log_queue.put("iptables rules cleaned up successfully")

        except Exception as e:
            if self.log_queue:
                self.log_queue.put(f"ERROR cleaning iptables: {e}")


    def process_packet(self, packet: bytes):
        try:
            packet_info = self.parse_packet(packet)
            
            matched_rule = self.match_rule(packet_info)
            
            if matched_rule:
                action = matched_rule['action'].upper()
                log_msg = (
                    f"{action} - {packet_info['protocol'].upper()} "
                    f"from {packet_info['src_ip']}:{packet_info['src_port']} "
                    f"to {packet_info['dst_ip']}:{packet_info['dst_port']}"
                )
            else:
                action = "BLOCK"
                log_msg = (
                    f"{action} - {packet_info['protocol'].upper()} "
                    f"from {packet_info['src_ip']}:{packet_info['src_port']} "
                    f"to {packet_info['dst_ip']}:{packet_info['dst_port']} "
                    "(No matching rule)"
                )
            
            if self.log_queue:
                self.log_queue.put(log_msg)
            
            return action == "ALLOW"
            
        except Exception as e:
            error_msg = f"ERROR processing packet: {str(e)}"
            if self.log_queue:
                self.log_queue.put(error_msg)
            return False

    def run(self):
        if self.log_queue:
            self.log_queue.put("Starting firewall packet processing...")
    
        self.sync_iptables_rules()
    
        try:
            while not self.stop_event.is_set():
                try:
                    self.socket.settimeout(1.0)
                    packet, addr = self.socket.recvfrom(65535)
                    self.process_packet(packet)
                
                except socket.timeout:
                    continue
                
                except Exception as e:
                    error_msg = f"Error receiving packet: {str(e)}"
                    if self.log_queue:
                        self.log_queue.put(error_msg)
                    time.sleep(1)
                
        finally:
            self.socket.close()
            if self.log_queue:
                self.log_queue.put("Firewall stopped")

if __name__ == "__main__":
    if 'DISPLAY' not in os.environ:
        print("Error: No graphical display available.")
        print("To run with GUI, use: sudo apt-get install xvfb; xvfb-run python3 firewall.py")
        exit(1)

    subprocess.run(["sudo", "iptables", "-F"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "iptables", "-X"], stderr=subprocess.DEVNULL)
    
    gui = FirewallGUI()
    gui.run()
