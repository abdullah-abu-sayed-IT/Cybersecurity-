#!/usr/bin/env python3
"""
Real-Time Security Monitor
===========================
Linux system logs থেকে সরাসরি পড়ে real-time monitoring করে
"""

import re
import os
from collections import defaultdict
from datetime import datetime
import subprocess


class RealtimeSecurityMonitor:
    def __init__(self):
        self.alerts = []
        self.ip_blacklist = set()
        self.suspicious_ips = defaultdict(int)
    
    def read_system_logs(self, log_file='/var/log/auth.log', lines=100):
        """System authentication logs পড়ে"""
        try:
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]  # Last 100 lines
        except PermissionError:
            print("⚠️ Need sudo access to read /var/log/auth.log")
            return []
    
    def parse_ssh_attempt(self, line):
        """SSH authentication attempt parse করে"""
        
        # Invalid user attempt
        if 'Invalid user' in line:
            match = re.search(r'Invalid user (\S+) from (\S+)', line)
            if match:
                return {
                    'type': 'INVALID_USER',
                    'username': match.group(1),
                    'ip': match.group(2),
                    'status': 'FAILED'
                }
        
        # Authentication failed
        if 'authentication failure' in line.lower():
            match = re.search(r'authentication failure.*rhost=(\S+)', line)
            if match:
                return {
                    'type': 'AUTH_FAILURE',
                    'ip': match.group(1),
                    'status': 'FAILED'
                }
        
        # Accepted password
        if 'Accepted password' in line:
            match = re.search(r'Accepted password for (\S+) from (\S+)', line)
            if match:
                return {
                    'type': 'LOGIN_SUCCESS',
                    'username': match.group(1),
                    'ip': match.group(2),
                    'status': 'SUCCESS'
                }
        
        return None
    
    def detect_ssh_brute_force(self, logs):
        """SSH brute force attempts detect করে"""
        ip_attempts = defaultdict(list)
        
        for log in logs:
            parsed = self.parse_ssh_attempt(log)
            if parsed and parsed['status'] == 'FAILED':
                ip_attempts[parsed['ip']].append(parsed)
        
        threats = []
        for ip, attempts in ip_attempts.items():
            if len(attempts) >= 3:  # 3 failed attempts
                threat = {
                    'type': 'SSH_BRUTE_FORCE',
                    'severity': 'HIGH' if len(attempts) > 5 else 'MEDIUM',
                    'ip': ip,
                    'failed_attempts': len(attempts),
                    'users_tried': list(set([a.get('username', 'unknown') for a in attempts]))
                }
                threats.append(threat)
                self.ip_blacklist.add(ip)
        
        return threats
    
    def get_network_connections(self):
        """Current network connections দেখায়"""
        try:
            result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
            connections = result.stdout.split('\n')
            return connections[:10]  # Top 10
        except:
            return []
    
    def check_open_ports(self):
        """Open ports check করে"""
        try:
            result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
            ports = []
            
            for line in result.stdout.split('\n')[2:]:
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ports.append(parts[3])
            
            return ports
        except:
            return []
    
    def scan_for_rootkits(self):
        """সন্দেহজনক processes check করে"""
        suspicious = []
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            suspicious_patterns = [
                r'\.sh\s', r'curl.*\|.*bash',
                r'wget.*\|.*bash', r'\$\(.*\)'
            ]
            
            for line in result.stdout.split('\n'):
                for pattern in suspicious_patterns:
                    if re.search(pattern, line):
                        suspicious.append({
                            'type': 'SUSPICIOUS_PROCESS',
                            'severity': 'HIGH',
                            'process': line.strip(),
                            'timestamp': datetime.now().isoformat()
                        })
        except:
            pass
        
        return suspicious
    
    def check_file_integrity(self, critical_files):
        """Important files modification check করে"""
        
        changes = []
        for file_path in critical_files:
            if os.path.exists(file_path):
                mod_time = os.path.getmtime(file_path)
                mod_datetime = datetime.fromtimestamp(mod_time)
                
                # Last 24 hours এ modified?
                if (datetime.now() - mod_datetime).days == 0:
                    changes.append({
                        'type': 'FILE_MODIFIED',
                        'severity': 'HIGH',
                        'file': file_path,
                        'modified_time': mod_datetime.isoformat()
                    })
        
        return changes
    
    def generate_security_report(self):
        """সম্পূর্ণ security report তৈরি করে"""
        
        print("\n" + "="*70)
        print("🛡️  REAL-TIME SECURITY MONITOR REPORT")
        print("="*70 + "\n")
        
        # Check for threats
        critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/root/.ssh/authorized_keys']
        
        print("📋 System Status:\n")
        
        # Open ports
        ports = self.check_open_ports()
        print(f"🔌 Open Ports: {', '.join(ports) if ports else 'None'}")
        
        # Suspicious processes
        print("\n🔍 Scanning for Suspicious Processes...")
        suspicious = self.scan_for_rootkits()
        if suspicious:
            print(f"⚠️  Found {len(suspicious)} suspicious processes!")
            for proc in suspicious:
                print(f"   • {proc['process'][:60]}...")
        else:
            print("✅ No suspicious processes detected")
        
        # File integrity
        print("\n📄 Checking Critical Files...")
        changes = self.check_file_integrity(critical_files)
        if changes:
            print(f"⚠️  {len(changes)} critical files were recently modified!")
            for change in changes:
                print(f"   • {change['file']} - {change['modified_time']}")
        else:
            print("✅ All critical files integrity verified")
        
        print("\n" + "="*70 + "\n")


class PasswordSecurityChecker:
    """Password strength এবং policy check করে"""
    
    @staticmethod
    def check_password_strength(password):
        """Password strength analyze করে"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Password অন্তত 8 characters হওয়া উচিত")
        
        # Uppercase
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("❌ Uppercase letter যোগ করুন")
        
        # Lowercase
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("❌ Lowercase letter যোগ করুন")
        
        # Numbers
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("❌ Number যোগ করুন")
        
        # Special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("❌ Special character যোগ করুন")
        
        # Strength assessment
        if score >= 5:
            strength = "🟢 STRONG"
        elif score >= 3:
            strength = "🟡 MEDIUM"
        else:
            strength = "🔴 WEAK"
        
        return {
            'strength': strength,
            'score': score,
            'feedback': feedback
        }
    
    @staticmethod
    def check_common_passwords(password):
        """Common/weak passwords check করে"""
        common = ['password', '123456', '12345678', 'qwerty', 'abc123', 'admin', 'pass']
        return password.lower() not in common


def demo_password_checker():
    """Password checking demo চালায়"""
    print("\n" + "="*50)
    print("🔐 PASSWORD SECURITY CHECKER")
    print("="*50 + "\n")
    
    test_passwords = [
        "password",
        "MyP@ssw0rd",
        "Test123!@#",
    ]
    
    for pwd in test_passwords:
        result = PasswordSecurityChecker.check_password_strength(pwd)
        common_check = PasswordSecurityChecker.check_common_passwords(pwd)
        
        print(f"Password: {'*' * len(pwd)}")
        print(f"Strength: {result['strength']}")
        print(f"Score: {result['score']}/5")
        print(f"Is Common: {'❌ Yes' if not common_check else '✅ No'}")
        
        if result['feedback']:
            print("Suggestions:")
            for feedback in result['feedback']:
                print(f"  {feedback}")
        print()


if __name__ == "__main__":
    # Demo চালাও
    print("\n🚀 Starting Security Monitoring System...\n")
    
    # Monitor তৈরি করো
    monitor = RealtimeSecurityMonitor()
    
    # Password checker demo
    demo_password_checker()
    
    # System security report generate করো
    monitor.generate_security_report()
    
    print("✅ Security monitoring complete!")
