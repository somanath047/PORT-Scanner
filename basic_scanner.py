# basic_scanner.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic Port Scanner - Ethical Hacking Lab 1
Learn: TCP connections, socket programming, scanning basics
"""

import socket
import sys
import time
from datetime import datetime
import colorama
from colorama import Fore, Style

# Initialize colorama for Windows compatibility
colorama.init(autoreset=True)

class BasicScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_duration = 0
    
    def banner(self):
        """Display tool banner"""
        print(Fore.CYAN + """
╔══════════════════════════════════════════╗
║      BASIC PORT SCANNER v1.0             ║
║      Ethical Hacking Learning Tool       ║
╚══════════════════════════════════════════╝
        """)
    
    def scan_port(self, target, port):
        """Scan a single port"""
        try:
            # Create socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            
            # Attempt connection
            result = sock.connect_ex((target, port))
            
            if result == 0:
                print(Fore.GREEN + f"[+] Port {port}: OPEN")
                self.open_ports.append(port)
                
                # Try to get banner
                try:
                    sock.send(b"Hello\r\n")
                    banner = sock.recv(1024).decode().strip()
                    if banner:
                        print(Fore.YELLOW + f"    Banner: {banner[:50]}")
                except:
                    pass
            else:
                print(Fore.RED + f"[-] Port {port}: CLOSED")
            
            sock.close()
            
        except socket.error:
            print(Fore.MAGENTA + f"[!] Error scanning port {port}")
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by user")
            sys.exit()
    
    def scan_range(self, target, start_port, end_port):
        """Scan a range of ports"""
        print(f"\n🎯 Target: {target}")
        print(f"📊 Port Range: {start_port} - {end_port}")
        print(f"⏰ Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        start_time = time.time()
        
        for port in range(start_port, end_port + 1):
            self.scan_port(target, port)
        
        self.scan_duration = time.time() - start_time
        
        self.display_results()
    
    def scan_common_ports(self, target):
        """Scan common ports"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389,
            5900, 8080
        ]
        
        print(f"\n🎯 Target: {target}")
        print("📊 Scanning 20 common ports")
        print(f"⏰ Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        start_time = time.time()
        
        for port in common_ports:
            self.scan_port(target, port)
        
        self.scan_duration = time.time() - start_time
        
        self.display_results()
    
    def display_results(self):
        """Display scan results"""
        print("\n" + "=" * 50)
        print(Fore.CYAN + "📋 SCAN RESULTS")
        print("=" * 50)
        
        if self.open_ports:
            print(Fore.GREEN + f"✅ Open Ports Found: {len(self.open_ports)}")
            print(Fore.YELLOW + "📌 List of open ports:")
            for port in sorted(self.open_ports):
                print(f"   - Port {port}")
        else:
            print(Fore.RED + "❌ No open ports found")
        
        print(f"\n⏱️  Scan Duration: {self.scan_duration:.2f} seconds")
        print(f"🕐 End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Security reminder
        print("\n" + Fore.MAGENTA + "⚠️  ETHICAL REMINDER:")
        print("• Only scan systems you own or have permission to scan")
        print("• Unauthorized scanning may be illegal")
        print("• Use this knowledge responsibly")

def main():
    scanner = BasicScanner()
    scanner.banner()
    
    print(Fore.YELLOW + "Please read:")
    print("1. This is for EDUCATIONAL purposes only")
    print("2. Only scan your own systems or lab environments")
    print("3. Enter 'localhost' or '127.0.0.1' for practice\n")
    
    try:
        # Get target
        target = input(Fore.CYAN + "[?] Enter target IP or hostname: ").strip()
        
        if not target:
            target = "127.0.0.1"  # Default to localhost for safety
        
        print(Fore.CYAN + "\n[?] Select scan type:")
        print("1. Scan common ports (Recommended for beginners)")
        print("2. Scan custom port range")
        
        choice = input(Fore.YELLOW + "\n[?] Enter choice (1 or 2): ").strip()
        
        if choice == "1":
            scanner.scan_common_ports(target)
        elif choice == "2":
            try:
                start = int(input(Fore.CYAN + "[?] Start port: ").strip())
                end = int(input(Fore.CYAN + "[?] End port: ").strip())
                
                if start > end:
                    print(Fore.RED + "[!] Start port must be less than end port")
                    return
                if end > 65535:
                    print(Fore.RED + "[!] Port cannot exceed 65535")
                    return
                
                scanner.scan_range(target, start, end)
            except ValueError:
                print(Fore.RED + "[!] Please enter valid numbers")
        else:
            print(Fore.RED + "[!] Invalid choice")
    
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Program terminated by user")
        sys.exit()
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

if __name__ == "__main__":
    main()
    print(Fore.GREEN + "\n✅ Scan complete! Lab saved to logs/")
    
    # Save results to log file
    try:
        with open('logs/scan_results.txt', 'a') as f:
            f.write(f"Scan at {datetime.now()}\n")
            f.write(f"Open ports: {scanner.open_ports}\n")
            f.write("-" * 30 + "\n")
    except:
        pass