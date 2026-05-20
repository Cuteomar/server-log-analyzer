# 🛡️ Sentinel Log Analyzer

A high-performance Security Information and Event Management (SIEM) lite tool designed to parse, analyze, and monitor server logs for malicious activity in real-time or batch modes.

## 🚀 Overview
The Sentinel Log Analyzer automates the detection of common web attacks by scanning server logs (Apache/Nginx). It utilizes stateful analysis to track brute-force attempts over time and regex-based pattern matching to identify injection attacks.

## ✨ Key Features
- **Multi-Format Support**: Intelligently handles both Common Log Format (Access logs) and Apache Error logs.
- **Stateful Brute Force Detection**: Tracks failed login attempts (401/403 errors) within a sliding time window to reduce false positives.
- **Signature-Based SQLi Detection**: Uses configurable regex patterns to flag SQL injection attempts in request paths.
- **Real-Time Monitoring**: Includes a `--watch` mode that tails active log files, providing live security alerts.
- **Memory Efficient**: Built with Python generators to process multi-gigabyte log files without exhausting system RAM.
- **Structured Reporting**: Exports findings to CSV or JSON for integration with other security workflows.

## 🛠️ Architecture & Engineering
- **Modular Design**: Separates concerns between the `LogParser` (data extraction), `SecurityDetector` (logic/analysis), and the CLI entry point.
- **Regex Named Groups**: Utilizes named capture groups for robust and readable log parsing.
- **External Configuration**: Detection rules and thresholds are decoupled from the code via `rules.yaml`.

## 📂 Project Structure
```text
├── analyzer.py          # CLI Entry point & Main logic
├── log_parser.py        # Regex-based parsing engine
├── detector.py          # Security analysis & state tracking
├── rules.yaml           # Configurable attack signatures
├── requirements.txt     # Dependency list
└── reports/             # Generated security audits
```

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone <https://github.com/Cuteomar/log-analyzer.git>
   cd log-analyzer
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## ▶️ Usage

### Batch Analysis
Scan an existing log file and export a security report:
```bash
python analyzer.py --input samples/access.log --output reports/audit.csv
```

### Real-Time Monitoring
Tail a log file and receive live alerts as events occur:
```bash
python analyzer.py --input access.log --watch
```

## 🔧 Configuration
Adjust thresholds and attack signatures in `rules.yaml`:
```yaml
detection:
  brute_force:
    threshold_count: 5      # Max failed attempts
    window_seconds: 60      # Within this timeframe
  sqli_patterns:
    - "UNION SELECT"        # Attack signatures
```

## 🧪 Technologies Used
- **Python 3.10+**
- **Pandas**: Structured data manipulation and report generation.
- **PyYAML**: Clean configuration management.
- **Regular Expressions (re)**: High-speed pattern matching.
- **Python-Dateutil**: Robust timestamp normalization across formats.

## 📖 Portfolio Highlights
During the development of this tool, I focused on:
- **High-Volume Data Processing**: Implementing line-by-line streaming to ensure the tool remains performant on production-scale logs.
- **Sliding Window Algorithms**: Maintaining a dictionary-based state to track IP behavior over specific time intervals.
- **Regex Optimization**: Crafting patterns that handle the variations between Access and Error log syntaxes.

## 📜 License
This project is licensed under the MIT License.
