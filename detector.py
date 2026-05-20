import re
from collections import defaultdict
from datetime import datetime
from dateutil import parser as date_parser

class SecurityDetector:
    def __init__(self, config: dict):
        self.config = config['detection']
        self.sqli_regex = [re.compile(p, re.IGNORECASE) for p in self.config['sqli_patterns']]
        self.failed_logins = defaultdict(list) # IP -> list of timestamps

    def check_sqli(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in self.sqli_regex)

    def check_brute_force(self, ip: str, timestamp_str: str, status: int) -> bool:
        if status not in self.config['brute_force']['failed_status_codes']:
            return False
        
        # Parse timestamp and maintain sliding window
        current_time = date_parser.parse(timestamp_str, fuzzy=True)
        self.failed_logins[ip].append(current_time)
        
        # Clean up old attempts outside the window
        window = self.config['brute_force']['window_seconds']
        self.failed_logins[ip] = [
            t for t in self.failed_logins[ip] 
            if (current_time - t).total_seconds() <= window
        ]
        
        return len(self.failed_logins[ip]) >= self.config['brute_force']['threshold_count']

    def analyze(self, entry):
        alerts = []
        if self.check_sqli(entry.path):
            alerts.append(f"[ALERT] SQL Injection attempt from {entry.ip} in path: {entry.path}")
        
        if self.check_brute_force(entry.ip, entry.timestamp, entry.status):
            count = len(self.failed_logins[entry.ip])
            alerts.append(f"[ALERT] Potential Brute Force: {count} failed attempts from {entry.ip}")
            
        return alerts