# CallTrace
Call Trap and Trace System

A comprehensive VoIP security monitoring and analysis system designed for security analysts and managed service providers. This system captures extensive metadata from SIP traffic, performs advanced threat analysis, and generates detailed forensic reports for incident response and security investigations.

## Features

### 🔍 **Comprehensive Metadata Capture**
- **SIP Protocol Analysis**: Complete header parsing, call flow tracking, authentication analysis
- **Media Intelligence**: Codec identification, SDP parsing, quality metrics (jitter, packet loss, MOS)
- **Device Fingerprinting**: User-Agent analysis, OS detection, SIP stack identification
- **Network Forensics**: Packet analysis, fragmentation detection, protocol inspection
- **Geographic Intelligence**: Country/city identification, ISP tracking, ASN analysis
- **Security Metadata**: TLS detection, certificate analysis, encryption tracking

### 🛡️ **Advanced Threat Detection**
- Real-time risk scoring with 15+ detection algorithms
- Pattern matching for known attack vectors (toll-free abuse, premium rate fraud)
- Authentication failure tracking and brute-force detection
- Rapid call pattern analysis
- Geographic anomaly detection
- Header manipulation and spoofing detection
- Device inconsistency analysis

### 📊 **Forensic Reporting**
- Comprehensive security reports with 60+ metadata fields
- Threat intelligence generation with IOC extraction
- Call-specific forensic analysis
- Temporal pattern analysis
- Export capabilities (JSON, CSV) for SIEM integration

### 🚨 **Real-time Alerting**
- Automated alert generation for high-risk calls
- Severity-based classification (HIGH/MEDIUM/LOW)
- Integration-ready alert format for security orchestration

## Installation

### Prerequisites
```bash
# Python 3.8 or higher
python3 --version

# Required packages
pip install sqlite3 ipaddress hashlib
```

### Setup
```bash
# Clone or download the call trace system
wget call_trap_trace.py

# Make executable
chmod +x call_trap_trace.py

# Initialize database (automatic on first run)
python3 call_trap_trace.py --help
```

## Quick Start

### 1. Start Real-time Monitoring
```bash
# Monitor SIP traffic on default port 5060
python3 call_trap_trace.py --monitor

# Monitor on specific interface/port
python3 call_trap_trace.py --monitor --host 192.168.1.100 --port 5060
```

### 2. Generate Security Report
```bash
# Generate 24-hour summary report
python3 call_trap_trace.py --report

# Generate report for specific time period
python3 call_trap_trace.py --report --hours 168
```

### 3. Export Data for Analysis
```bash
# Export to JSON
python3 call_trap_trace.py --export security_report.json

# Export to CSV for spreadsheet analysis
python3 call_trap_trace.py --export call_data.csv --export-format csv
```

## Command-Line Reference

### Monitoring Commands
```bash
# Start SIP monitoring
--monitor                    # Start real-time SIP traffic monitoring
--host <ip>                 # Bind to specific IP (default: 0.0.0.0)
--port <port>               # Listen on specific port (default: 5060)
```

### Reporting Commands
```bash
--report                    # Generate comprehensive summary report
--threat-intel              # Generate threat intelligence report
--forensic <call_id>        # Detailed forensic analysis of specific call
--hours <n>                 # Time period for reports (default: 24)
```

### Analysis Commands
```bash
--analyze-ip <ip>           # Analyze all calls from specific IP
--search-caller <number>    # Search call history for specific caller
--list-alerts               # Show recent security alerts
```

### Export Commands
```bash
--export <filename>         # Export report to file
--export-format <format>    # Export format: json or csv (default: json)
```

### Testing Commands
```bash
--test <caller,dest,duration>  # Add test call for system validation
```

## Interactive Mode

Launch interactive mode for dynamic analysis:

```bash
python3 call_trap_trace.py
```

**Available Commands:**
- `monitor` - Start enhanced monitoring
- `report` - Generate comprehensive report
- `threat-intel` - Generate threat intelligence
- `forensic <call_id>` - Detailed call analysis
- `export` - Export data
- `analyze-ip <ip>` - Analyze IP address
- `search <caller>` - Search caller history
- `alerts` - Show recent alerts
- `test <caller,dest>` - Add test call
- `quit` - Exit

## Configuration

### Database Configuration
The system uses SQLite for data storage. Database files are created automatically:
- `call_trace.db` - Main call records
- `call_trace.log` - System logs

### Security Configuration
```python
# Modify trusted networks in ThreatAnalyzer class
self.trusted_networks = [
    '192.168.', '10.', '172.16.'  # Add your trusted IP ranges
]

# Customize high-risk countries
self.high_risk_countries = [
    '+234', '+91', '+86', '+7'  # Add country codes to monitor
]
```

## Use Cases

### 🔒 **Security Analysis**
- **Fraud Detection**: Identify premium rate fraud, toll-free abuse
- **Intrusion Detection**: Detect SIP scanning, brute-force attacks
- **Anomaly Detection**: Identify unusual call patterns, geographic anomalies

### 🕵️ **Incident Response**
- **Forensic Analysis**: Detailed call-by-call investigation
- **Threat Hunting**: Proactive search for IOCs and attack patterns
- **Timeline Analysis**: Reconstruct attack sequences

### 📈 **Compliance & Monitoring**
- **Regulatory Compliance**: Maintain detailed call records
- **Quality Monitoring**: Track call quality metrics
- **Capacity Planning**: Analyze traffic patterns

## Advanced Features

### Threat Intelligence Integration
```bash
# Generate 7-day threat intelligence report
python3 call_trap_trace.py --threat-intel --hours 168

# Extract IOCs for external systems
python3 call_trap_trace.py --export iocs.json --threat-intel
```

### Forensic Analysis
```bash
# Analyze specific suspicious call
python3 call_trap_trace.py --forensic abc123def456

# Investigate IP address activity
python3 call_trap_trace.py --analyze-ip 203.0.113.42
```

### SIEM Integration
Export data in formats compatible with security tools:
```bash
# Splunk-ready JSON export
python3 call_trap_trace.py --export splunk_data.json

# ELK Stack CSV import
python3 call_trap_trace.py --export elk_data.csv --export-format csv
```

## Metadata Captured

### SIP Protocol Metadata
- Via headers, Contact headers, Route/Record-Route
- CSeq tracking, Branch analysis, Max-Forwards
- Content-Type, Content-Length, Expires

### Authentication & Security
- Authorization methods, WWW-Authenticate
- Realm and nonce analysis, TLS version detection
- Certificate information, Encryption status

### Media Analysis
- SDP body parsing, Audio/video codecs
- Media IP and ports, Quality metrics
- Jitter, packet loss, latency, MOS scores

### Device Intelligence
- User-Agent parsing, Device type classification
- OS fingerprinting, SIP stack identification
- Hardware vendor detection

### Network Forensics
- Source/destination analysis, Protocol detection
- Packet size analysis, Fragmentation detection
- TTL analysis, TCP flags

### Geographic Intelligence
- Country and city identification, ISP information
- ASN tracking, Geographic anomaly detection

## Troubleshooting

### Common Issues

**Permission Denied on Port 5060**
```bash
# Run with appropriate privileges
sudo python3 call_trap_trace.py --monitor

# Or use non-privileged port
python3 call_trap_trace.py --monitor --port 15060
```

**Database Lock Errors**
```bash
# Check for running instances
ps aux | grep call_trap_trace

# Kill existing processes if needed
pkill -f call_trap_trace.py
```

**Missing Dependencies**
```bash
# Install required packages
pip3 install ipaddress sqlite3
```

### Log Analysis
```bash
# View system logs
tail -f call_trace.log

# Search for specific errors
grep ERROR call_trace.log
```

## Security Considerations

### Network Security
- Monitor from dedicated security segment
- Use network taps or mirror ports for passive monitoring
- Implement proper access controls for database files

### Data Protection
- Encrypt database files containing call records
- Implement log rotation for long-term storage
- Follow data retention policies

### Performance
- Monitor system resources during high-volume periods
- Implement database maintenance routines
- Consider distributed deployment for large networks

## Integration Examples

### Splunk Integration
```bash
# Daily export for Splunk ingestion
0 0 * * * /usr/bin/python3 /opt/call_trace/call_trap_trace.py --export /var/log/splunk/call_trace_$(date +\%Y\%m\%d).json --hours 24
```

### ELK Stack Integration
```bash
# Logstash-compatible CSV export
python3 call_trap_trace.py --export elk_import.csv --export-format csv --hours 24
```

### SIEM Alert Integration
```python
# Custom alert handler
def send_to_siem(alert):
    # Integrate with your SIEM platform
    pass
```

## Support and Maintenance

### Database Maintenance
```bash
# Vacuum database for performance
sqlite3 call_trace.db "VACUUM;"

# Clean old records (optional)
sqlite3 call_trace.db "DELETE FROM calls WHERE timestamp < datetime('now', '-30 days');"
```

### Backup Procedures
```bash
# Backup database
cp call_trace.db call_trace_backup_$(date +%Y%m%d).db

# Export all data
python3 call_trap_trace.py --export full_backup.json --hours 8760
```

## Contributing

This system is designed for security professionals and can be extended with:
- Additional threat detection algorithms
- Integration with threat intelligence feeds
- Custom export formats
- Enhanced geographic databases
- Machine learning-based anomaly detection

## License

This tool is provided for security analysis and monitoring purposes. Ensure compliance with local telecommunications monitoring regulations and privacy laws.

## Changelog

### Version 2.0 (Enhanced)
- Added comprehensive metadata capture (60+ fields)
- Enhanced threat detection with 15+ algorithms
- Geographic intelligence integration
- Device fingerprinting capabilities
- Forensic analysis features
- Threat intelligence reporting
- Multiple export formats

### Version 1.0 (Basic)
- Basic SIP monitoring
- Simple risk scoring
- JSON reporting
- SQLite storage

---

**For MSP Security Teams**: This tool provides enterprise-grade VoIP security monitoring with the detailed metadata capture needed for compliance, forensic analysis, and threat hunting in managed service environments.
