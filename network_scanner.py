# network_scanner.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner - Ethical Hacking Lab 2
Learn: ARP, network discovery, device fingerprinting
"""

import scapy.all as scapy
import socket
import netifaces
import platform
import subprocess
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.local_ip = self.get_local_ip()
        self.network_info = {}
    
    def banner(self):
        """Display banner"""
        print(Fore.CYAN + """
╔══════════════════════════════════════════╗
║      NETWORK DISCOVERY TOOL v1.0         ║
║      Find devices on your network        ║
╚══════════════════════════════════════════╝
        """)
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Create a socket connection to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_network_info(self):
        """Get network interface information"""
        print(Fore.YELLOW + "\n🔍 Analyzing your network...")
        
        try:
            # Get default gateway
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            
            # Get network interfaces
            interfaces = netifaces.interfaces()
            
            self.network_info = {
                'local_ip': self.local_ip,
                'gateway': default_gateway,
                'interfaces': interfaces,
                'platform': platform.system(),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            print(Fore.GREEN + f"✅ Local IP: {self.local_ip}")
            print(Fore.GREEN + f"✅ Gateway: {default_gateway}")
            print(Fore.GREEN + f"✅ System: {platform.system()}")
            
            return True
        except Exception as e:
            print(Fore.RED + f"❌ Error getting network info: {e}")
            return False
    
    def scan_network(self, ip_range=None):
        """Scan network using ARP requests"""
        print(Fore.CYAN + "\n📡 Scanning network...")
        print("This may take a moment. Please wait...\n")
        
        try:
            if not ip_range:
                # Create IP range from local IP
                base_ip = ".".join(self.local_ip.split(".")[:3]) + ".1/24"
                ip_range = base_ip
            
            # Create ARP request
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send packet and get response
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            print(Fore.GREEN + f"✅ Found {len(answered_list)} devices\n")
            
            # Process results
            print(Fore.YELLOW + "IP Address\t\tMAC Address\t\tVendor")
            print("-" * 60)
            
            for element in answered_list:
                device = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc,
                    'vendor': self.get_vendor(element[1].hwsrc)
                }
                self.devices.append(device)
                
                # Display device
                vendor_short = device['vendor'][:20] + "..." if len(device['vendor']) > 20 else device['vendor']
                print(f"{device['ip']}\t\t{device['mac']}\t{vendor_short}")
            
            return True
            
        except PermissionError:
            print(Fore.RED + "\n❌ Permission denied!")
            print(Fore.YELLOW + "   Try: Run as administrator (Windows) or use sudo (Linux)")
            return False
        except Exception as e:
            print(Fore.RED + f"\n❌ Scan error: {e}")
            return False
    
    def get_vendor(self, mac_address):
        """Get vendor from MAC address (simplified)"""
        # In real tool, you'd use OUI database
        vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1A:11': 'Google',
            '00:1D:0F': 'Microsoft',
            '00:24:1D': 'Cisco',
            '00:26:BB': 'Apple',
            '28:16:2E': 'Apple',
            'A4:83:E7': 'Apple',
            'BC:54:2F': 'Samsung',
            'F0:79:60': 'Apple'
        }
        
        prefix = mac_address[:8].upper()
        return vendors.get(prefix, "Unknown Vendor")
    
    def port_scan_device(self, ip):
        """Quick port scan on a discovered device"""
        print(Fore.CYAN + f"\n🔎 Quick port scan on {ip}...")
        
        common_ports = [21, 22, 23, 80, 443, 3389]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    print(Fore.GREEN + f"   [+] Port {port}: OPEN")
                else:
                    print(Fore.RED + f"   [-] Port {port}: CLOSED")
                
                sock.close()
            except:
                print(Fore.MAGENTA + f"   [!] Port {port}: ERROR")
    
    def save_results(self):
        """Save scan results to file"""
        try:
            results = {
                'scan_info': self.network_info,
                'devices': self.devices,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            with open('logs/network_scan.json', 'w') as f:
                json.dump(results, f, indent=4)
            
            print(Fore.GREEN + "\n💾 Results saved to: logs/network_scan.json")
            
        except Exception as e:
            print(Fore.RED + f"\n❌ Error saving results: {e}")
    
    def display_menu(self):
        """Display interactive menu"""
        while True:
            print(Fore.CYAN + "\n" + "=" * 50)
            print("NETWORK SCANNER MENU")
            print("=" * 50)
            print("1. Show network information")
            print("2. Scan local network")
            print("3. Scan custom IP range")
            print("4. Quick port scan on device")
            print("5. Save results")
            print("6. Exit")
            
            choice = input(Fore.YELLOW + "\n[?] Enter choice (1-6): ").strip()
            
            if choice == "1":
                self.get_network_info()
            
            elif choice == "2":
                self.scan_network()
            
            elif choice == "3":
                ip_range = input(Fore.CYAN + "[?] Enter IP range (e.g., 192.168.1.1/24): ").strip()
                if ip_range:
                    self.scan_network(ip_range)
            
            elif choice == "4":
                if not self.devices:
                    print(Fore.RED + "❌ No devices found. Run scan first!")
                else:
                    print(Fore.YELLOW + "\nDiscovered devices:")
                    for i, device in enumerate(self.devices, 1):
                        print(f"{i}. {device['ip']} ({device['vendor']})")
                    
                    try:
                        device_num = int(input(Fore.CYAN + "\n[?] Select device number: ").strip())
                        if 1 <= device_num <= len(self.devices):
                            self.port_scan_device(self.devices[device_num-1]['ip'])
                        else:
                            print(Fore.RED + "❌ Invalid device number")
                    except ValueError:
                        print(Fore.RED + "❌ Please enter a number")
            
            elif choice == "5":
                self.save_results()
            
            elif choice == "6":
                print(Fore.GREEN + "\n👋 Goodbye! Stay ethical!")
                break
            
            else:
                print(Fore.RED + "❌ Invalid choice")

def main():
    scanner = NetworkScanner()
    scanner.banner()
    
    print(Fore.YELLOW + "⚠️  IMPORTANT:")
    print("• Only scan YOUR OWN network")
    print("• Get permission before scanning any network")
    print("• Unauthorized scanning may violate laws\n")
    
    try:
        # Get network info first
        scanner.get_network_info()
        
        # Start interactive menu
        scanner.display_menu()
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Program terminated by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")

if __name__ == "__main__":
    # Check if running with admin privileges (for ARP scan)
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(Fore.YELLOW + "⚠️  Note: Some features may require Administrator privileges")
        except:
            pass
    
    main()