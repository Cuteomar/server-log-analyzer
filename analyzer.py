import argparse
import yaml
import pandas as pd
import time
from log_parser import LogParser
from detector import SecurityDetector

def main():
    parser = argparse.ArgumentParser(description="Log Analyzer Tool")
    parser.add_argument("--input", required=True, help="Path to log file")
    parser.add_argument("--output", help="Path to export CSV report")
    parser.add_argument("--rules", default="rules.yaml", help="Path to rules config")
    parser.add_argument("--watch", action="store_true", help="Monitor file in real-time")
    args = parser.parse_args()

    # Load configuration
    with open(args.rules, 'r') as f:
        config = yaml.safe_load(f)

    log_parser = LogParser()
    detector = SecurityDetector(config)
    results = []

    def process_entry(entry):
        alerts = detector.analyze(entry)
        for alert in alerts:
            print(alert)
            results.append({
                "timestamp": entry.timestamp,
                "ip": entry.ip,
                "alert": alert,
                "raw": entry.raw
            })

    if args.watch:
        print(f"[*] Monitoring {args.input} in real-time...")
        with open(args.input, 'r') as f:
            f.seek(0, 2) # Move to end of file
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    entry = log_parser.parse_line(line)
                    if entry:
                        process_entry(entry)
            except KeyboardInterrupt:
                print("\n[*] Stopping monitor.")
    else:
        print(f"[*] Analyzing {args.input}...")
        for entry in log_parser.stream_logs(args.input):
            process_entry(entry)

    if args.output and results:
        df = pd.DataFrame(results)
        if args.output.endswith('.csv'):
            df.to_csv(args.output, index=False)
        elif args.output.endswith('.json'):
            df.to_json(args.output, orient='records', indent=4)
        print(f"[!] Report saved to {args.output}")
    elif not results:
        print("[+] No suspicious activity detected.")

if __name__ == "__main__":
    main()