# password_checker.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Password Security Checker - Ethical Hacking Lab 3
Learn: Password strength, hashing, security principles
"""

import hashlib
import re
import string
import secrets
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class PasswordChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
    
    def banner(self):
        """Display banner"""
        print(Fore.CYAN + """
╔══════════════════════════════════════════╗
║      PASSWORD SECURITY ANALYZER v1.0     ║
║      Check and improve your passwords    ║
╚══════════════════════════════════════════╝
        """)
    
    def load_common_passwords(self):
        """Load list of common passwords"""
        common = [
            'password', '123456', '12345678', '1234', 'qwerty',
            '12345', 'dragon', 'baseball', 'football', 'letmein',
            'monkey', 'abc123', '111111', 'mustang', 'access',
            'shadow', 'master', 'michael', 'superman', '696969',
            '123123', 'batman', 'trustno1', 'admin', 'welcome'
        ]
        return set(common)
    
    def check_strength(self, password):
        """Check password strength"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
            feedback.append(Fore.GREEN + "✅ Length: Good (12+ characters)")
        elif len(password) >= 8:
            score += 1
            feedback.append(Fore.YELLOW + "⚠️  Length: Okay (8+ characters)")
        else:
            feedback.append(Fore.RED + "❌ Length: Too short (<8 characters)")
        
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append(Fore.GREEN + "✅ Contains uppercase letters")
        else:
            feedback.append(Fore.YELLOW + "⚠️  Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append(Fore.GREEN + "✅ Contains lowercase letters")
        else:
            feedback.append(Fore.YELLOW + "⚠️  Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
            feedback.append(Fore.GREEN + "✅ Contains numbers")
        else:
            feedback.append(Fore.YELLOW + "⚠️  Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            feedback.append(Fore.GREEN + "✅ Contains special characters")
        else:
            feedback.append(Fore.YELLOW + "⚠️  Add special characters")
        
        # Check for common patterns
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append(Fore.RED + "❌ VERY WEAK: Common password")
        
        # Sequential characters
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            score -= 1
            feedback.append(Fore.RED + "❌ Avoid sequential letters")
        
        # Repeated characters
        if re.search(r'(.)\1\1', password):
            score -= 1
            feedback.append(Fore.RED + "❌ Avoid repeated characters")
        
        return score, feedback
    
    def estimate_crack_time(self, password):
        """Estimate time to crack password (simplified)"""
        # Very simplified calculation for educational purposes
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        
        if charset_size == 0:
            return "instantly"
        
        # Calculate combinations
        combinations = charset_size ** len(password)
        
        # Assume 1 billion guesses per second
        guesses_per_second = 1_000_000_000
        seconds = combinations / guesses_per_second
        
        # Convert to human readable
        if seconds < 1:
            return "less than a second"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:  # 365 days
            return f"{seconds/86400:.0f} days"
        else:
            years = seconds / 31536000
            if years > 1000000:
                return "millions of years"
            return f"{years:.0f} years"
    
    def generate_strong_password(self, length=16):
        """Generate a strong password"""
        if length < 12:
            length = 12
        
        alphabet = string.ascii_letters + string.digits + string.punctuation
        
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            score, _ = self.check_strength(password)
            
            if score >= 5:  # Strong enough
                return password
    
    def hash_password(self, password, algorithm='sha256'):
        """Show password hash (for educational purposes)"""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            return "Invalid algorithm"
        
        hash_func = algorithms[algorithm]
        hashed = hash_func(password.encode()).hexdigest()
        
        return hashed
    
    def check_common_hash(self, password):
        """Check if password matches common hashes (educational)"""
        print(Fore.YELLOW + "\n🔍 Checking against common password hashes...")
        
        # Common passwords with their SHA256 hashes
        common_hashes = {
            '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
            '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92': '123456',
            'ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f': '12345678'
        }
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if password_hash in common_hashes:
            print(Fore.RED + f"❌ WARNING: Password matches common password '{common_hashes[password_hash]}'")
            print(Fore.RED + f"   Hash: {password_hash}")
            return False
        else:
            print(Fore.GREEN + f"✅ Password not found in common hashes")
            print(Fore.CYAN + f"   Your hash: {password_hash}")
            return True
    
    def display_menu(self):
        """Display interactive menu"""
        while True:
            print(Fore.CYAN + "\n" + "=" * 50)
            print("PASSWORD SECURITY MENU")
            print("=" * 50)
            print("1. Check password strength")
            print("2. Generate strong password")
            print("3. Show password hashes")
            print("4. Password security tips")
            print("5. Exit")
            
            choice = input(Fore.YELLOW + "\n[?] Enter choice (1-5): ").strip()
            
            if choice == "1":
                password = input(Fore.CYAN + "[?] Enter password to check: ").strip()
                
                if not password:
                    print(Fore.RED + "❌ Please enter a password")
                    continue
                
                print(Fore.CYAN + "\n" + "=" * 50)
                print("ANALYSIS RESULTS")
                print("=" * 50)
                
                # Check strength
                score, feedback = self.check_strength(password)
                
                for item in feedback:
                    print(item)
                
                # Show score
                print(Fore.CYAN + "\n📊 Strength Score:", end=" ")
                if score <= 1:
                    print(Fore.RED + f"VERY WEAK ({score}/7)")
                elif score <= 3:
                    print(Fore.YELLOW + f"WEAK ({score}/7)")
                elif score <= 5:
                    print(Fore.BLUE + f"GOOD ({score}/7)")
                else:
                    print(Fore.GREEN + f"STRONG ({score}/7)")
                
                # Estimate crack time
                crack_time = self.estimate_crack_time(password)
                print(Fore.CYAN + f"⏱️  Estimated crack time: {crack_time}")
                
                # Check against common hashes
                self.check_common_hash(password)
                
                # Security recommendations
                if score < 5:
                    print(Fore.YELLOW + "\n💡 Recommendations:")
                    if len(password) < 12:
                        print("   • Use at least 12 characters")
                    if not re.search(r'[A-Z]', password):
                        print("   • Add uppercase letters")
                    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                        print("   • Add special characters")
                
                # Save to log
                self.save_check(password, score)
            
            elif choice == "2":
                try:
                    length = int(input(Fore.CYAN + "[?] Password length (default 16): ").strip() or "16")
                    password = self.generate_strong_password(length)
                    
                    print(Fore.GREEN + "\n✅ Generated strong password:")
                    print(Fore.CYAN + f"   {password}")
                    
                    # Show hashes
                    print(Fore.YELLOW + "\n🔐 Hashes (for comparison):")
                    print(Fore.CYAN + f"   MD5:    {self.hash_password(password, 'md5')}")
                    print(Fore.CYAN + f"   SHA256: {self.hash_password(password, 'sha256')}")
                    
                except ValueError:
                    print(Fore.RED + "❌ Please enter a valid number")
            
            elif choice == "3":
                password = input(Fore.CYAN + "[?] Enter password to hash: ").strip()
                
                if not password:
                    print(Fore.RED + "❌ Please enter a password")
                    continue
                
                print(Fore.YELLOW + "\n🔐 Password Hashes:")
                print(Fore.CYAN + f"   Original: {password}")
                print(Fore.RED + f"   MD5:      {self.hash_password(password, 'md5')}")
                print(Fore.YELLOW + f"   SHA1:     {self.hash_password(password, 'sha1')}")
                print(Fore.GREEN + f"   SHA256:   {self.hash_password(password, 'sha256')}")
                print(Fore.BLUE + f"   SHA512:   {self.hash_password(password, 'sha512')}")
                
                print(Fore.MAGENTA + "\n⚠️  Note: MD5 and SHA1 are cryptographically broken!")
                print("   Use SHA256 or SHA512 for security")
            
            elif choice == "4":
                self.show_security_tips()
            
            elif choice == "5":
                print(Fore.GREEN + "\n🔒 Stay secure! Goodbye!")
                break
            
            else:
                print(Fore.RED + "❌ Invalid choice")
    
    def show_security_tips(self):
        """Display password security tips"""
        print(Fore.CYAN + "\n" + "=" * 50)
        print("PASSWORD SECURITY TIPS")
        print("=" * 50)
        
        tips = [
            "✅ Use at least 12 characters",
            "✅ Mix uppercase, lowercase, numbers, symbols",
            "✅ Avoid common words and patterns",
            "✅ Don't use personal information",
            "✅ Use unique passwords for each account",
            "✅ Consider using a password manager",
            "✅ Enable two-factor authentication (2FA)",
            "✅ Change passwords if a service is breached",
            "❌ Don't write passwords on paper",
            "❌ Don't share passwords via email/text",
            "❌ Avoid 'password', '123456', etc.",
            "❌ Don't use dictionary words alone"
        ]
        
        for tip in tips:
            if tip.startswith("✅"):
                print(Fore.GREEN + tip)
            else:
                print(Fore.RED + tip)
    
    def save_check(self, password, score):
        """Save password check to log (hash only, not plaintext)"""
        try:
            # Only save hash for security
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'password_hash': password_hash,
                'score': score,
                'length': len(password)
            }
            
            with open('logs/password_checks.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
        except Exception as e:
            print(Fore.RED + f"❌ Error saving log: {e}")

def main():
    checker = PasswordChecker()
    checker.banner()
    
    print(Fore.YELLOW + "🔒 IMPORTANT SECURITY NOTES:")
    print("• This tool runs locally on your computer")
    print("• Passwords are NOT sent over the internet")
    print("• Still, be careful with sensitive passwords\n")
    
    try:
        checker.display_menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Program terminated by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()