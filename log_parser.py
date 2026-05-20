import re
from dataclasses import dataclass
from typing import Optional, Iterator

@dataclass
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int
    raw: str

class LogParser:
    # Access Log Pattern (CLF)
    CLF_PATTERN = r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<path>\S+) .*?" (?P<status>\d+) (?P<size>\d+)'
    
    # Error Log Pattern (handles Apache_2k.log.csv format)
    ERROR_PATTERN = r'\[(?P<timestamp>.*?)\] \[(?P<level>\w+)\] (?:\[client (?P<ip>[\d\.]+)\] )?(?P<message>.*)'

    def __init__(self):
        self.clf_regex = re.compile(self.CLF_PATTERN)
        self.error_regex = re.compile(self.ERROR_PATTERN)

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        # Try Access Log format
        match = self.clf_regex.match(line)
        if match:
            data = match.groupdict()
            return LogEntry(data['ip'], data['timestamp'], data['method'], data['path'], int(data['status']), int(data['size']), line)
        
        # Try Error Log format (fallback)
        match = self.error_regex.match(line)
        if match and match.group('ip'): # We only care about lines with an IP for security analysis
            data = match.groupdict()
            # Map "forbidden" errors to status 403 so the brute force detector picks them up
            status = 403 if 'forbidden' in data['message'].lower() else 500
            return LogEntry(
                ip=data['ip'], timestamp=data['timestamp'], method="ERROR",
                path=data['message'], status=status, size=0, raw=line
            )
        
        return None

    def stream_logs(self, file_path: str) -> Iterator[LogEntry]:
        with open(file_path, 'r') as f:
            for line in f:
                entry = self.parse_line(line)
                if entry:
                    yield entry