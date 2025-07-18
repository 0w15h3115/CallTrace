# Extract display name from From header
        from_header = headers.get('from', '')
        metadata['from_header'] = from_header
        if from_header:
            display_match = re.search(r'"([^"]+)"', from_header)
            if display_match:
                metadata['from_display_name'] = display_match.group(1)
        
        # Store To header for analysis
        metadata['to_header'] = headers.get('to', '')
    
    def generate_enhanced_alerts(self, call: 'CallRecord'):
        """Generate enhanced alerts based on routing, addressing, and origination analysis"""
        alerts = []
        
        # Standard threat alerts
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        # Routing-based alerts
        if hasattr(call, 'routing_analysis'):
            if call.routing_analysis.routing_loops:
                alerts.append({
                    'type': 'ROUTING_LOOP',
                    'severity': 'HIGH',
                    'message': f"Routing loop detected: {', '.join(call.routing_analysis.routing_loops)}",
                    'details': call.routing_analysis.routing_loops
                })
            
            if call.routing_analysis.hop_count > 10:
                alerts.append({
                    'type': 'EXCESSIVE_HOPS',
                    'severity': 'MEDIUM',
                    'message': f"Excessive routing hops: {call.routing_analysis.hop_count}",
                    'details': {'hop_count': call.routing_analysis.hop_count}
                })
        
        # Addressing-based alerts
        if hasattr(call, 'addressing_analysis'):
            if call.addressing_analysis.address_manipulations:
                alerts.append({
                    'type': 'ADDRESS_MANIPULATION',
                    'severity': 'HIGH',
                    'message': f"Address manipulation detected: {', '.join(call.addressing_analysis.address_manipulations)}",
                    'details': call.addressing_analysis.address_manipulations
                })
            
            if 'anonymous_from' in call.addressing_analysis.privacy_flags:
                alerts.append({
                    'type': 'ANONYMOUS_CALLER',
                    'severity': 'MEDIUM',
                    'message': "Anonymous caller detected",
                    'details': {'privacy_flags': call.addressing_analysis.privacy_flags}
                })
        
        # Origination-based alerts
        if hasattr(call, 'origination_analysis'):
            if call.origination_analysis.spoofing_indicators:
                alerts.append({
                    'type': 'SPOOFING_DETECTED',
                    'severity': 'HIGH',
                    'message': f"Potential caller ID spoofing: {'; '.join(call.origination_analysis.spoofing_indicators)}",
                    'details': call.origination_analysis.spoofing_indicators
                })
            
            if call.origination_analysis.origination_confidence < 30:
                alerts.append({
                    'type': 'LOW_ORIGINATION_CONFIDENCE',
                    'severity': 'HIGH',
                    'message': f"Low confidence in call origination: {call.origination_analysis.origination_confidence}%",
                    'details': {
                        'confidence': call.origination_analysis.origination_confidence,
                        'type': call.origination_analysis.origination_type
                    }
                })
        
        # Store alerts in database
        for alert in alerts:
            self.db.insert_enhanced_alert(call.call_id, alert)
        
        # Log critical alerts
        for alert in alerts:
            if alert['severity'] == 'HIGH':
                logger.warning(f"HIGH SEVERITY ALERT: {alert['message']} for call {call.call_id}")
    
    def log_enhanced_forensics(self, call: 'CallRecord'):
        """Log enhanced forensic data for investigation"""
        forensic_data = {
            'call_id': call.call_id,
            'timestamp': str(call.timestamp),
            'risk_score': call.risk_score,
            'forensic_summary': {}
        }
        
        # Add routing forensics
        if hasattr(call, 'routing_analysis'):
            forensic_data['forensic_summary']['routing'] = {
                'total_hops': call.routing_analysis.hop_count,
                'has_loops': len(call.routing_analysis.routing_loops) > 0,
                'anomaly_count': len(call.routing_analysis.routing_anomalies),
                'estimated_latency_ms': call.routing_analysis.estimated_latency
            }
        
        # Add addressing forensics
        if hasattr(call, 'addressing_analysis'):
            forensic_data['forensic_summary']['addressing'] = {
                'manipulation_detected': len(call.addressing_analysis.address_manipulations) > 0,
                'is_anonymous': 'anonymous_from' in call.addressing_analysis.privacy_flags,
                'suspicious_domains': len(call.addressing_analysis.domain_analysis.get('suspicious_domains', [])) > 0
            }
        
        # Add origination forensics
        if hasattr(call, 'origination_analysis'):
            forensic_data['forensic_summary']['origination'] = {
                'confidence_score': call.origination_analysis.origination_confidence,
                'spoofing_indicators_count': len(call.origination_analysis.spoofing_indicators),
                'origination_type': call.origination_analysis.origination_type,
                'carrier_identified': call.origination_analysis.carrier_identification is not None
            }
        
        # Log high-risk calls to separate forensic log
        if call.risk_score >= 70:
            with open('high_risk_forensics.jsonl', 'a') as f:
                f.write(json.dumps(forensic_data) + '\n')


class EnhancedCallDatabase(CallDatabase):
    """Extended database handler with enhanced analysis storage"""
    
    def init_database(self):
        """Initialize database with enhanced tables"""
        # Call parent init
        super().init_database()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Add enhanced analysis tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS routing_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT NOT NULL,
                hop_count INTEGER,
                routing_loops TEXT,
                routing_anomalies TEXT,
                estimated_latency REAL,
                geographic_path TEXT,
                routing_path TEXT,
                FOREIGN KEY (call_id) REFERENCES calls (call_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS addressing_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT NOT NULL,
                original_caller TEXT,
                displayed_caller TEXT,
                asserted_identity TEXT,
                privacy_flags TEXT,
                address_manipulations TEXT,
                domain_analysis TEXT,
                FOREIGN KEY (call_id) REFERENCES calls (call_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS origination_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT NOT NULL,
                true_origin TEXT,
                claimed_origin TEXT,
                origination_confidence REAL,
                spoofing_indicators TEXT,
                origination_type TEXT,
                carrier_identification TEXT,
                network_path TEXT,
                FOREIGN KEY (call_id) REFERENCES calls (call_id)
            )
        ''')
        
        # Enhanced alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enhanced_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (call_id) REFERENCES calls (call_id)
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_routing_call_id ON routing_analysis(call_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_addressing_call_id ON addressing_analysis(call_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_origination_call_id ON origination_analysis(call_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_enhanced_alerts_call_id ON enhanced_alerts(call_id)')
        
        conn.commit()
        conn.close()
    
    def insert_enhanced_call(self, call: 'CallRecord'):
        """Insert call record with enhanced analysis data"""
        # Insert base call record
        self.insert_call(call)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insert routing analysis
            if hasattr(call, 'routing_analysis'):
                cursor.execute('''
                    INSERT INTO routing_analysis 
                    (call_id, hop_count, routing_loops, routing_anomalies, 
                     estimated_latency, geographic_path, routing_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    call.call_id,
                    call.routing_analysis.hop_count,
                    json.dumps(call.routing_analysis.routing_loops),
                    json.dumps(call.routing_analysis.routing_anomalies),
                    call.routing_analysis.estimated_latency,
                    json.dumps(call.routing_analysis.geographic_path),
                    json.dumps([asdict(hop) for hop in call.routing_analysis.routing_path])
                ))
            
            # Insert addressing analysis
            if hasattr(call, 'addressing_analysis'):
                cursor.execute('''
                    INSERT INTO addressing_analysis 
                    (call_id, original_caller, displayed_caller, asserted_identity,
                     privacy_flags, address_manipulations, domain_analysis)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    call.call_id,
                    call.addressing_analysis.original_caller,
                    call.addressing_analysis.displayed_caller,
                    call.addressing_analysis.asserted_identity,
                    json.dumps(call.addressing_analysis.privacy_flags),
                    json.dumps(call.addressing_analysis.address_manipulations),
                    json.dumps(call.addressing_analysis.domain_analysis)
                ))
            
            # Insert origination analysis
            if hasattr(call, 'origination_analysis'):
                cursor.execute('''
                    INSERT INTO origination_analysis 
                    (call_id, true_origin, claimed_origin, origination_confidence,
                     spoofing_indicators, origination_type, carrier_identification, network_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    call.call_id,
                    json.dumps(call.origination_analysis.true_origin),
                    json.dumps(call.origination_analysis.claimed_origin),
                    call.origination_analysis.origination_confidence,
                    json.dumps(call.origination_analysis.spoofing_indicators),
                    call.origination_analysis.origination_type,
                    json.dumps(call.origination_analysis.carrier_identification),
                    json.dumps(call.origination_analysis.network_path)
                ))
            
            conn.commit()
            
        except sqlite3.Error as e:
            logger.error(f"Database error inserting enhanced analysis: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def insert_enhanced_alert(self, call_id: str, alert: Dict):
        """Insert enhanced alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO enhanced_alerts 
                (call_id, alert_type, severity, message, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                call_id,
                alert['type'],
                alert['severity'],
                alert['message'],
                json.dumps(alert.get('details', {})),
                datetime.datetime.now().isoformat()
            ))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error inserting enhanced alert: {e}")
        finally:
            conn.close()
    
    def get_enhanced_call_analysis(self, call_id: str) -> Dict:
        """Retrieve complete enhanced analysis for a call"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        analysis = {'call_id': call_id}
        
        # Get routing analysis
        cursor.execute('SELECT * FROM routing_analysis WHERE call_id = ?', (call_id,))
        routing = cursor.fetchone()
        if routing:
            analysis['routing'] = {
                'hop_count': routing[2],
                'routing_loops': json.loads(routing[3]),
                'routing_anomalies': json.loads(routing[4]),
                'estimated_latency': routing[5],
                'geographic_path': json.loads(routing[6]),
                'routing_path': json.loads(routing[7])
            }
        
        # Get addressing analysis
        cursor.execute('SELECT * FROM addressing_analysis WHERE call_id = ?', (call_id,))
        addressing = cursor.fetchone()
        if addressing:
            analysis['addressing'] = {
                'original_caller': addressing[2],
                'displayed_caller': addressing[3],
                'asserted_identity': addressing[4],
                'privacy_flags': json.loads(addressing[5]),
                'address_manipulations': json.loads(addressing[6]),
                'domain_analysis': json.loads(addressing[7])
            }
        
        # Get origination analysis
        cursor.execute('SELECT * FROM origination_analysis WHERE call_id = ?', (call_id,))
        origination = cursor.fetchone()
        if origination:
            analysis['origination'] = {
                'true_origin': json.loads(origination[2]),
                'claimed_origin': json.loads(origination[3]),
                'origination_confidence': origination[4],
                'spoofing_indicators': json.loads(origination[5]),
                'origination_type': origination[6],
                'carrier_identification': json.loads(origination[7]),
                'network_path': json.loads(origination[8])
            }
        
        conn.close()
        return analysis


class EnhancedCallTraceReporter(CallTraceReporter):
    """Enhanced reporter with routing, addressing, and origination insights"""
    
    def generate_enhanced_summary_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report with enhanced analysis"""
        # Get base report
        base_report = self.generate_summary_report(hours)
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Routing statistics
        cursor.execute('''
            SELECT AVG(hop_count) as avg_hops,
                   MAX(hop_count) as max_hops,
                   COUNT(CASE WHEN routing_loops != '[]' THEN 1 END) as calls_with_loops
            FROM routing_analysis r
            JOIN calls c ON r.call_id = c.call_id
            WHERE c.timestamp > ?
        ''', (threshold.isoformat(),))
        
        routing_stats = cursor.fetchone()
        
        # Addressing statistics
        cursor.execute('''
            SELECT COUNT(CASE WHEN address_manipulations != '[]' THEN 1 END) as manipulated_calls,
                   COUNT(CASE WHEN privacy_flags LIKE '%anonymous%' THEN 1 END) as anonymous_calls
            FROM addressing_analysis a
            JOIN calls c ON a.call_id = c.call_id
            WHERE c.timestamp > ?
        ''', (threshold.isoformat(),))
        
        addressing_stats = cursor.fetchone()
        
        # Origination statistics
        cursor.execute('''
            SELECT AVG(origination_confidence) as avg_confidence,
                   COUNT(CASE WHEN spoofing_indicators != '[]' THEN 1 END) as potential_spoofs,
                   COUNT(CASE WHEN origination_type = 'Potentially-Spoofed' THEN 1 END) as confirmed_spoofs
            FROM origination_analysis o
            JOIN calls c ON o.call_id = c.call_id
            WHERE c.timestamp > ?
        ''', (threshold.isoformat(),))
        
        origination_stats = cursor.fetchone()
        
        # Most common spoofing indicators
        cursor.execute('''
            SELECT spoofing_indicators, COUNT(*) as count
            FROM origination_analysis o
            JOIN calls c ON o.call_id = c.call_id
            WHERE c.timestamp > ? AND spoofing_indicators != '[]'
            GROUP BY spoofing_indicators
            ORDER BY count DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        spoofing_patterns = cursor.fetchall()
        
        # Carrier statistics
        cursor.execute('''
            SELECT carrier_identification, COUNT(*) as count
            FROM origination_analysis o
            JOIN calls c ON o.call_id = c.call_id
            WHERE c.timestamp > ? AND carrier_identification IS NOT NULL
            GROUP BY carrier_identification
            ORDER BY count DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        carrier_stats = cursor.fetchall()
        
        conn.close()
        
        # Add enhanced statistics to report
        base_report['enhanced_analysis'] = {
            'routing_statistics': {
                'average_hops': round(routing_stats[0] or 0, 2),
                'maximum_hops': routing_stats[1] or 0,
                'calls_with_routing_loops': routing_stats[2] or 0
            },
            'addressing_statistics': {
                'calls_with_manipulation': addressing_stats[0] or 0,
                'anonymous_calls': addressing_stats[1] or 0
            },
            'origination_statistics': {
                'average_confidence': round(origination_stats[0] or 0, 2),
                'potential_spoofing_attempts': origination_stats[1] or 0,
                'confirmed_spoofed_calls': origination_stats[2] or 0
            },
            'top_spoofing_patterns': [
                {
                    'indicators': json.loads(row[0]),
                    'occurrences': row[1]
                }
                for row in spoofing_patterns
            ],
            'carrier_distribution': [
                {
                    'carrier': json.loads(row[0]) if row[0] else {'name': 'Unknown'},
                    'call_count': row[1]
                }
                for row in carrier_stats
            ]
        }
        
        return base_report
    
    def generate_routing_path_report(self, call_id: str) -> Dict:
        """Generate detailed routing path visualization data"""
        analysis = self.db.get_enhanced_call_analysis(call_id)
        
        if 'routing' not in analysis:
            return {'error': 'No routing analysis available for this call'}
        
        routing_data = analysis['routing']
        
        # Format for visualization
        path_visualization = {
            'call_id': call_id,
            'total_hops': routing_data['hop_count'],
            'estimated_latency_ms': routing_data['estimated_latency'],
            'has_loops': len(routing_data['routing_loops']) > 0,
            'anomalies': routing_data['routing_anomalies'],
            'path': []
        }
        
        # Build path with geographic info
        for i, hop in enumerate(routing_data['routing_path']):
            hop_info = {
                'sequence': i,
                'host': hop.get('host', 'Unknown'),
                'ip': hop.get('resolved_ip', hop.get('host', 'Unknown')),
                'port': hop.get('port', '5060'),
                'type': hop.get('type', 'unknown'),
                'nat_detected': hop.get('nat_detected', False)
            }
            
            # Add geographic info if available
            if i < len(routing_data['geographic_path']):
                hop_info['location'] = routing_data['geographic_path'][i]
            
            path_visualization['path'].append(hop_info)
        
        return path_visualization
    
    def generate_origination_verification_report(self, hours: int = 24) -> Dict:
        """Generate report on call origination verification"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get calls with low origination confidence
        cursor.execute('''
            SELECT c.call_id, c.caller_id, c.source_ip, 
                   o.origination_confidence, o.origination_type,
                   o.spoofing_indicators, o.carrier_identification
            FROM calls c
            JOIN origination_analysis o ON c.call_id = o.call_id
            WHERE c.timestamp > ? AND o.origination_confidence < 50
            ORDER BY o.origination_confidence ASC
            LIMIT 50
        ''', (threshold.isoformat(),))
        
        low_confidence_calls = cursor.fetchall()
        
        # Get origination type distribution
        cursor.execute('''
            SELECT origination_type, COUNT(*) as count,
                   AVG(origination_confidence) as avg_confidence
            FROM origination_analysis o
            JOIN calls c ON o.call_id = c.call_id
            WHERE c.timestamp > ?
            GROUP BY origination_type
            ORDER BY count DESC
        ''', (threshold.isoformat(),))
        
        type_distribution = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_type': 'Origination Verification',
            'time_period_hours': hours,
            'low_confidence_calls': [
                {
                    'call_id': row[0],
                    'caller_id': row[1],
                    'source_ip': row[2],
                    'confidence': row[3],
                    'type': row[4],
                    'spoofing_indicators': json.loads(row[5]) if row[5] else [],
                    'carrier': json.loads(row[6]) if row[6] else None
                }
                for row in low_confidence_calls
            ],
            'origination_type_distribution': [
                {
                    'type': row[0],
                    'count': row[1],
                    'average_confidence': round(row[2], 2)
                }
                for row in type_distribution
            ],
            'recommendations': self.generate_origination_recommendations(low_confidence_calls)
        }
    
    def generate_origination_recommendations(self, low_confidence_calls: List) -> List[str]:
        """Generate recommendations based on origination analysis"""
        recommendations = []
        
        # Count spoofing indicators
        spoofing_count = sum(1 for call in low_confidence_calls if json.loads(call[5] or '[]'))
        
        if spoofing_count > len(low_confidence_calls) * 0.3:
            recommendations.append(
                f"High spoofing activity detected ({spoofing_count} potential spoofs). "
                "Consider implementing stricter caller ID verification."
            )
        
        # Check for unidentified carriers
        unknown_carriers = sum(1 for call in low_confidence_calls if not call[6])
        
        if unknown_carriers > len(low_confidence_calls) * 0.5:
            recommendations.append(
                "Many calls from unidentified carriers. "
                "Update carrier identification database."
            )
        
        # Check for specific origination types
        types = [call[4] for call in low_confidence_calls]
        if types.count('Potentially-Spoofed') > 5:
            recommendations.append(
                "Multiple potentially spoofed calls detected. "
                "Review authentication mechanisms and consider implementing STIR/SHAKEN."
            )
        
        return recommendations


# CLI Extension for enhanced features
def add_enhanced_cli_commands(parser):
    """Add enhanced command-line arguments"""
    parser.add_argument('--routing-analysis', metavar='CALL_ID', 
                      help='Analyze routing path for specific call')
    parser.add_argument('--origination-report', action='store_true',
                      help='Generate origination verification report')
    parser.add_argument('--address-analysis', metavar='CALL_ID',
                      help='Analyze addressing for specific call')
    parser.add_argument('--enhanced-report', action='store_true',
                      help='Generate enhanced summary report with routing/origination data')
    parser.add_argument('--visualize-path', metavar='CALL_ID',
                      help='Generate routing path visualization data')
    
    return parser


def handle_enhanced_commands(args, manager):
    """Handle enhanced CLI commands"""
    if args.routing_analysis:
        analysis = manager.db.get_enhanced_call_analysis(args.routing_analysis)
        if 'routing' in analysis:
            print("=== ROUTING ANALYSIS ===")
            print(json.dumps(analysis['routing'], indent=2))
        else:
            print("No routing analysis available for this call")
    
    elif args.origination_report:
        reporter = EnhancedCallTraceReporter(manager.db)
        report = reporter.generate_origination_verification_report(args.hours)
        print("=== ORIGINATION VERIFICATION REPORT ===")
        print(json.dumps(report, indent=2))
    
    elif args.address_analysis:
        analysis = manager.db.get_enhanced_call_analysis(args.address_analysis)
        if 'addressing' in analysis:
            print("=== ADDRESSING ANALYSIS ===")
            print(json.dumps(analysis['addressing'], indent=2))
        else:
            print("No addressing analysis available for this call")
    
    elif args.enhanced_report:
        reporter = EnhancedCallTraceReporter(manager.db)
        report = reporter.generate_enhanced_summary_report(args.hours)
        print("=== ENHANCED SUMMARY REPORT ===")
        print(json.dumps(report, indent=2))
    
    elif args.visualize_path:
        reporter = EnhancedCallTraceReporter(manager.db)
        path_data = reporter.generate_routing_path_report(args.visualize_path)
        print("=== ROUTING PATH VISUALIZATION ===")
        print(json.dumps(path_data, indent=2))
        
        # Generate ASCII visualization
        if 'path' in path_data:
            print("\nPath Visualization:")
            for i, hop in enumerate(path_data['path']):
                prefix = "└──>" if i == len(path_data['path']) - 1 else "├──>"
                nat_indicator = " [NAT]" if hop.get('nat_detected') else ""
                location = f" ({hop.get('location', 'Unknown')})" if 'location' in hop else ""
                print(f"{prefix} Hop {i}: {hop['host']}:{hop['port']}{nat_indicator}{location}")


# Example integration into main()
"""
def enhanced_main():
    parser = argparse.ArgumentParser(description="Enhanced Call Trap and Trace System")
    # ... existing arguments ...
    
    # Add enhanced commands
    parser = add_enhanced_cli_commands(parser)
    
    args = parser.parse_args()
    
    # Use enhanced manager with new database
    manager = CallTraceManager()
    manager.db = EnhancedCallDatabase()  # Use enhanced database
    
    # Handle enhanced commands
    if any([args.routing_analysis, args.origination_report, args.address_analysis, 
            args.enhanced_report, args.visualize_path]):
        handle_enhanced_commands(args, manager)
    else:
        # Handle existing commands
        # ... existing command handling ...
"""#!/usr/bin/env python3
"""
CallTrace Integration Module
Integrates the enhanced routing, addressing, and origination features
into the existing CallTrace system.
"""

import sys
import json
from typing import Dict, List, Optional
import logging

# Import the enhanced modules
from calltrace_routing_enhancement import (
    EnhancedRoutingAnalyzer,
    EnhancedAddressingAnalyzer,
    EnhancedOriginationAnalyzer,
    enhance_call_record_with_routing_analysis,
    generate_enhanced_forensic_report
)

logger = logging.getLogger(__name__)


class EnhancedSIPMonitor:
    """Enhanced SIP Monitor with routing, addressing, and origination analysis"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        # Initialize base components
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        
        # Initialize enhanced analyzers
        self.routing_analyzer = EnhancedRoutingAnalyzer()
        self.addressing_analyzer = EnhancedAddressingAnalyzer()
        self.origination_analyzer = EnhancedOriginationAnalyzer()
        
        # Cache for performance
        self.analysis_cache = {}
        
    def process_sip_message(self, data: bytes, addr: Tuple[str, int]):
        """Enhanced SIP message processing with comprehensive analysis"""
        try:
            message = data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            logger.warning(f"Failed to decode SIP message from {addr}")
            return
        
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Extract comprehensive metadata (using existing method)
        metadata = self.extract_comprehensive_metadata(lines, data, addr)
        
        # Extract additional headers for enhanced analysis
        self.extract_enhanced_headers(lines, metadata)
        
        # Calculate packet hash for forensics
        packet_hash = hashlib.sha256(data).hexdigest()
        
        # Create enhanced call record with additional fields
        call = CallRecord(
            # ... existing fields ...
            call_id=metadata.get('call_id', 'unknown'),
            timestamp=datetime.datetime.now(),
            caller_id=metadata.get('caller_id', 'Unknown'),
            destination=metadata.get('destination', 'Unknown'),
            # ... other existing fields ...
            
            # Additional fields for enhanced analysis
            p_asserted_identity=metadata.get('p_asserted_identity'),
            p_preferred_identity=metadata.get('p_preferred_identity'),
            remote_party_id=metadata.get('remote_party_id'),
            privacy_header=metadata.get('privacy_header'),
            from_display_name=metadata.get('from_display_name'),
            from_header=metadata.get('from_header'),
            to_header=metadata.get('to_header'),
            history_info=metadata.get('history_info'),
            reason_header=metadata.get('reason_header'),
            priority_header=metadata.get('priority_header')
        )
        
        # Perform standard threat analysis
        call = self.analyzer.analyze_call(call)
        
        # Perform enhanced analysis
        call = enhance_call_record_with_routing_analysis(
            call,
            self.routing_analyzer,
            self.addressing_analyzer,
            self.origination_analyzer
        )
        
        # Store enhanced call record
        self.db.insert_enhanced_call(call)
        
        # Generate enhanced alerts
        self.generate_enhanced_alerts(call)
        
        # Log enhanced forensic data
        self.log_enhanced_forensics(call)
    
    def extract_enhanced_headers(self, lines: List[str], metadata: Dict):
        """Extract additional headers for enhanced analysis"""
        headers = {}
        
        # Parse all headers
        for line in lines[1:]:
            if line.strip() == '':
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Extract identity headers
        metadata['p_asserted_identity'] = headers.get('p-asserted-identity')
        metadata['p_preferred_identity'] = headers.get('p-preferred-identity')
        metadata['remote_party_id'] = headers.get('remote-party-id')
        
        # Extract privacy headers
        metadata['privacy_header'] = headers.get('privacy')
        
        # Extract additional routing headers
        metadata['history_info'] = headers.get('history-info')
        metadata['reason_header'] = headers.get('reason')
        metadata['priority_header'] = headers.get('priority')
        
        # Extract display name from From header
        from_header = headers.get('from', '')
        metadata['from_header'] = from_header
        if from_header:
            display_match = re.search(r'"([^"]+)"', from_header)
            if display_match:
                metadata['from_display_name'] = display_match.group(1)
        
        # Store To header for analysis
        metadata['to_header'] = headers.get('to', '')
