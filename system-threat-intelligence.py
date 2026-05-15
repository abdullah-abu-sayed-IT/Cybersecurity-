#!/usr/bin/env python3
"""
IP Reputation & Threat Intelligence System
===========================================
IP addresses check করে malicious activity এর জন্য
"""

import re
import json
from datetime import datetime
from collections import defaultdict


class IPReputationChecker:
    def __init__(self):
        # Known malicious IP ranges (demo purposes)
        self.blacklist = {
            '192.168.100.50': {'threat': 'botnet', 'severity': 'HIGH'},
            '10.0.0.99': {'threat': 'ransomware', 'severity': 'CRITICAL'},
            '172.16.0.5': {'threat': 'credential_theft', 'severity': 'HIGH'},
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'port_scanning': {'ports_checked': 10, 'time_window': 60},
            'syn_flood': {'packets': 1000, 'time_window': 5},
            'dns_spoofing': {'requests': 100, 'time_window': 10}
        }
        
        self.threat_log = []
    
    def check_ip_reputation(self, ip):
        """IP এর reputation check করে"""
        
        if ip in self.blacklist:
            threat_info = self.blacklist[ip]
            return {
                'ip': ip,
                'status': '🔴 MALICIOUS',
                'threat_type': threat_info['threat'],
                'severity': threat_info['severity'],
                'recommendation': 'Block this IP immediately'
            }
        
        # Check IP format validity
        if not self.validate_ip(ip):
            return {
                'ip': ip,
                'status': 'INVALID',
                'error': 'Invalid IP format'
            }
        
        # Private IP range check
        if self.is_private_ip(ip):
            return {
                'ip': ip,
                'status': '🟢 PRIVATE',
                'category': 'Internal network',
                'threat_level': 'LOW'
            }
        
        # Public IP
        return {
            'ip': ip,
            'status': '🟡 MONITOR',
            'category': 'Public IP',
            'threat_level': 'UNKNOWN',
            'recommendation': 'Monitor for suspicious activity'
        }
    
    @staticmethod
    def validate_ip(ip):
        """IP address validation"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    @staticmethod
    def is_private_ip(ip):
        """Private IP range check করে"""
        parts = [int(x) for x in ip.split('.')]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8 (localhost)
        if parts[0] == 127:
            return True
        
        return False
    
    def analyze_ip_pattern(self, ip, activity_count, time_window_seconds):
        """IP র activity pattern analyze করে"""
        
        threat_score = 0
        threats = []
        
        # High activity in short time
        if activity_count > 100 and time_window_seconds < 60:
            threat_score += 30
            threats.append('High frequency activity detected')
        
        # Port scanning signature
        if activity_count > 50 and time_window_seconds < 120:
            threat_score += 25
            threats.append('Possible port scanning activity')
        
        # DDoS pattern
        if activity_count > 500 and time_window_seconds < 10:
            threat_score += 40
            threats.append('Possible DDoS attack pattern')
        
        severity = 'CRITICAL' if threat_score >= 70 else 'HIGH' if threat_score >= 40 else 'MEDIUM' if threat_score >= 20 else 'LOW'
        
        return {
            'ip': ip,
            'threat_score': threat_score,
            'severity': severity,
            'threats': threats,
            'activities': activity_count,
            'time_window': time_window_seconds
        }
    
    def geolocate_ip(self, ip):
        """IP র geographical location estimate করে (demo)"""
        
        first_octet = int(ip.split('.')[0])
        
        geo_ranges = {
            range(1, 50): 'USA/North America',
            range(51, 100): 'Europe',
            range(101, 150): 'Asia',
            range(151, 200): 'South America',
            range(201, 240): 'Africa/Middle East',
        }
        
        for octet_range, region in geo_ranges.items():
            if first_octet in octet_range:
                return region
        
        return 'Unknown'
    
    def generate_threat_intelligence_report(self, ips):
        """IP র threat intelligence report তৈরি করে"""
        
        print("\n" + "="*70)
        print("🕵️  IP THREAT INTELLIGENCE REPORT")
        print("="*70 + "\n")
        
        report_data = []
        
        for ip in ips:
            reputation = self.check_ip_reputation(ip)
            
            if 'error' not in reputation:
                geolocation = self.geolocate_ip(ip)
                reputation['geolocation'] = geolocation
                report_data.append(reputation)
                
                print(f"IP Address: {ip}")
                print(f"Status: {reputation['status']}")
                print(f"Threat Level: {reputation.get('threat_level', reputation.get('severity', 'N/A'))}")
                print(f"Location: {geolocation}")
                
                if 'recommendation' in reputation:
                    print(f"Action: {reputation['recommendation']}")
                
                print()
        
        return report_data


class NetworkAnomalyDetector:
    def __init__(self):
        self.traffic_patterns = defaultdict(list)
        self.baseline = {}
    
    def establish_baseline(self, traffic_data):
        """Normal network behavior র baseline establish করে"""
        
        for ip, bytes_transferred in traffic_data:
            self.traffic_patterns[ip].append(bytes_transferred)
        
        # Calculate average traffic per IP
        for ip, values in self.traffic_patterns.items():
            self.baseline[ip] = {
                'avg': sum(values) / len(values),
                'max': max(values),
                'min': min(values)
            }
        
        return self.baseline
    
    def detect_anomalies(self, current_traffic):
        """Current traffic থেকে anomalies detect করে"""
        
        anomalies = []
        
        for ip, bytes_now in current_traffic:
            if ip in self.baseline:
                baseline_avg = self.baseline[ip]['avg']
                
                # 500% এর বেশি বৃদ্ধি
                if bytes_now > baseline_avg * 5:
                    anomalies.append({
                        'ip': ip,
                        'type': 'TRAFFIC_SPIKE',
                        'severity': 'HIGH',
                        'baseline': int(baseline_avg),
                        'current': bytes_now,
                        'increase_percent': int((bytes_now / baseline_avg - 1) * 100)
                    })
        
        return anomalies


class DNSSecurityChecker:
    """DNS security threats detect করে"""
    
    @staticmethod
    def check_dns_requests(requests):
        """DNS requests analyze করে malicious domains খোঁজে"""
        
        suspicious_domains = {
            'evil.com': 'Known C2 server',
            'malware-host.net': 'Malware distribution',
            'phishing-bank.org': 'Phishing site',
        }
        
        threats = []
        
        for request in requests:
            if request in suspicious_domains:
                threats.append({
                    'type': 'MALICIOUS_DNS_LOOKUP',
                    'severity': 'HIGH',
                    'domain': request,
                    'threat_description': suspicious_domains[request]
                })
        
        return threats
    
    @staticmethod
    def detect_dns_tunneling(requests, threshold=100):
        """DNS tunneling attack detect করে"""
        
        subdomain_count = defaultdict(int)
        for request in requests:
            # Count subdomains
            if request.count('.') > 2:
                base_domain = '.'.join(request.split('.')[-2:])
                subdomain_count[base_domain] += 1
        
        tunneling_detected = []
        for domain, count in subdomain_count.items():
            if count > threshold:
                tunneling_detected.append({
                    'type': 'DNS_TUNNELING',
                    'severity': 'MEDIUM',
                    'domain': domain,
                    'subdomain_count': count,
                    'description': 'Abnormally high number of DNS queries to subdomains'
                })
        
        return tunneling_detected


def demo_reputation_checker():
    """IP reputation checker র demo চালায়"""
    
    checker = IPReputationChecker()
    
    # Test IPs
    test_ips = [
        '192.168.1.100',      # Private
        '192.168.100.50',     # Blacklisted
        '8.8.8.8',            # Public (Google)
        '1.1.1.1',            # Public (Cloudflare)
        '10.0.0.99',          # Blacklisted
        'invalid.ip',         # Invalid
    ]
    
    report = checker.generate_threat_intelligence_report(test_ips)


def demo_network_anomaly():
    """Network anomaly detection demo চালায়"""
    
    print("\n" + "="*70)
    print("📊 NETWORK ANOMALY DETECTION")
    print("="*70 + "\n")
    
    detector = NetworkAnomalyDetector()
    
    # Baseline traffic (normal behavior)
    baseline_traffic = [
        ('192.168.1.100', 1000),  # 1KB
        ('192.168.1.101', 2000),  # 2KB
        ('192.168.1.102', 1500),  # 1.5KB
    ]
    
    detector.establish_baseline(baseline_traffic)
    print("✅ Baseline established from normal traffic\n")
    
    # Current traffic (with anomaly)
    current_traffic = [
        ('192.168.1.100', 5000),   # Normal
        ('192.168.1.101', 15000),  # Spike! (7.5x increase)
        ('192.168.1.102', 1600),   # Normal
    ]
    
    anomalies = detector.detect_anomalies(current_traffic)
    
    if anomalies:
        print(f"🚨 {len(anomalies)} Anomalies detected!\n")
        for anomaly in anomalies:
            print(f"IP: {anomaly['ip']}")
            print(f"Type: {anomaly['type']}")
            print(f"Baseline: {anomaly['baseline']} bytes")
            print(f"Current: {anomaly['current']} bytes")
            print(f"Increase: {anomaly['increase_percent']}%\n")
    else:
        print("✅ No anomalies detected\n")


def demo_dns_security():
    """DNS security threats detection demo"""
    
    print("\n" + "="*70)
    print("🔒 DNS SECURITY ANALYSIS")
    print("="*70 + "\n")
    
    checker = DNSSecurityChecker()
    
    # Sample DNS requests
    dns_requests = [
        'google.com',
        'evil.com',
        'facebook.com',
        'malware-host.net',
        'a1.subdomain.example.com',
        'a2.subdomain.example.com',
        'a3.subdomain.example.com',
    ]
    
    # Check for malicious domains
    print("Checking for malicious domains...")
    threats = checker.check_dns_requests(dns_requests)
    
    if threats:
        for threat in threats:
            print(f"🚨 {threat['type']}: {threat['domain']}")
            print(f"   Reason: {threat['threat_description']}\n")
    else:
        print("✅ No malicious domains detected\n")
    
    # Check DNS tunneling
    print("Checking for DNS tunneling...")
    tunneling_requests = ['a.b.c.example.com'] * 150
    dns_requests.extend(tunneling_requests)
    
    tunneling = checker.detect_dns_tunneling(dns_requests)
    if tunneling:
        for alert in tunneling:
            print(f"⚠️  {alert['type']}: {alert['domain']}")
            print(f"   Subdomain queries: {alert['subdomain_count']}\n")


if __name__ == "__main__":
    print("\n🛡️  THREAT INTELLIGENCE SYSTEM DEMO\n")
    
    # IP reputation checker
    demo_reputation_checker()
    
    # Network anomaly detector
    demo_network_anomaly()
    
    # DNS security
    demo_dns_security()
    
    print("✅ All security checks complete!")
