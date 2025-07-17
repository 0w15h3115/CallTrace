class CallTraceReporter:
    """Generate comprehensive reports and statistics from enhanced call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive summary report with enhanced metadata analysis"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Basic statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls,
                   COUNT(CASE WHEN risk_score >= 40 AND risk_score < 70 THEN 1 END) as medium_risk_calls,
                   COUNT(DISTINCT source_ip) as unique_ips,
                   COUNT(DISTINCT caller_id) as unique_callers
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Geographic analysis
        cursor.execute('''
            SELECT caller_country, COUNT(*) as call_count,
                   AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND caller_country IS NOT NULL
            GROUP BY caller_country
            ORDER BY call_count DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        geographic_stats = cursor.fetchall()
        
        # Device type analysis
        cursor.execute('''
            SELECT device_type, COUNT(*) as call_count,
                   AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND device_type IS NOT NULL
            GROUP BY device_type
            ORDER BY call_count DESC
        ''', (threshold.isoformat(),))
        
        device_stats = cursor.fetchall()
        
        # SIP method analysis
        # SIP method analysis
        cursor.execute('''
            SELECT sip_method, COUNT(*) as call_count,
                   AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND sip_method IS NOT NULL
            GROUP BY sip_method
            ORDER BY call_count DESC
        ''', (threshold.isoformat(),))
        
        sip_method_stats = cursor.fetchall()
        
        # Top suspicious numbers with enhanced metadata
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, 
                   AVG(risk_score) as avg_risk,
                   caller_country, caller_city, device_type,
                   GROUP_CONCAT(DISTINCT flags) as common_flags
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 15
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Network analysis
        cursor.execute('''
            SELECT source_ip, COUNT(*) as call_count,
                   AVG(risk_score) as avg_risk,
                   caller_country, caller_isp
            FROM calls 
            WHERE timestamp > ? AND source_ip IS NOT NULL
            GROUP BY source_ip
            HAVING call_count > 5
            ORDER BY call_count DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        network_stats = cursor.fetchall()
        
        # Authentication failure analysis
        cursor.execute('''
            SELECT COUNT(*) as auth_failures,
                   COUNT(DISTINCT source_ip) as failed_ips,
                   COUNT(DISTINCT caller_id) as failed_numbers
            FROM calls 
            WHERE timestamp > ? AND response_code IN (401, 403, 407)
        ''', (threshold.isoformat(),))
        
        auth_stats = cursor.fetchone()
        
        # Media analysis
        cursor.execute('''
            SELECT audio_codecs, COUNT(*) as usage_count
            FROM calls 
            WHERE timestamp > ? AND audio_codecs IS NOT NULL AND audio_codecs != '[]'
            GROUP BY audio_codecs
            ORDER BY usage_count DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        codec_stats = cursor.fetchall()
        
        # User-Agent analysis
        cursor.execute('''
            SELECT user_agent, COUNT(*) as call_count,
                   AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND user_agent IS NOT NULL
            GROUP BY user_agent
            ORDER BY call_count DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        user_agent_stats = cursor.fetchall()
        
        # Quality metrics analysis
        cursor.execute('''
            SELECT AVG(jitter) as avg_jitter,
                   AVG(packet_loss) as avg_packet_loss,
                   AVG(latency) as avg_latency,
                   AVG(mos_score) as avg_mos
            FROM calls 
            WHERE timestamp > ? AND jitter IS NOT NULL
        ''', (threshold.isoformat(),))
        
        quality_stats = cursor.fetchone()
        
        # Recent high-risk alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp,
                   calls.caller_id, calls.source_ip, calls.caller_country
            FROM alerts 
            JOIN calls ON alerts.call_id = calls.call_id
            WHERE alerts.timestamp > ?
            ORDER BY alerts.timestamp DESC
            LIMIT 25
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        # Protocol distribution
        cursor.execute('''
            SELECT protocol, COUNT(*) as call_count,
                   AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND protocol IS NOT NULL
            GROUP BY protocol
        ''', (threshold.isoformat(),))
        
        protocol_stats = cursor.fetchall()
        
        # Encryption usage
        cursor.execute('''
            SELECT encryption_used, COUNT(*) as call_count
            FROM calls 
            WHERE timestamp > ?
            GROUP BY encryption_used
        ''', (threshold.isoformat(),))
        
        encryption_stats = cursor.fetchall()
        
        # Flag frequency analysis
        cursor.execute('''
            SELECT flags, COUNT(*) as occurrence_count
            FROM calls 
            WHERE timestamp > ? AND flags IS NOT NULL AND flags != '[]'
            GROUP BY flags
            ORDER BY occurrence_count DESC
            LIMIT 15
        ''', (threshold.isoformat(),))
        
        flag_stats = cursor.fetchall()
        
        conn.close()
        
        # Build comprehensive report
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'summary_statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0,
                'medium_risk_calls': stats[4] or 0,
                'unique_source_ips': stats[5] or 0,
                'unique_caller_ids': stats[6] or 0
            },
            'geographic_analysis': [
                {
                    'country': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in geographic_stats
            ],
            'device_analysis': [
                {
                    'device_type': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in device_stats
            ],
            'sip_method_analysis': [
                {
                    'method': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in sip_method_stats
            ],
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2),
                    'country': row[3],
                    'city': row[4],
                    'device_type': row[5],
                    'common_flags': row[6].split(',') if row[6] else []
                }
                for row in suspicious_numbers
            ],
            'network_analysis': [
                {
                    'source_ip': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2),
                    'country': row[3],
                    'isp': row[4]
                }
                for row in network_stats
            ],
            'authentication_analysis': {
                'total_failures': auth_stats[0] or 0,
                'unique_failed_ips': auth_stats[1] or 0,
                'unique_failed_numbers': auth_stats[2] or 0
            },
            'codec_analysis': [
                {
                    'codecs': json.loads(row[0]) if row[0] else [],
                    'usage_count': row[1]
                }
                for row in codec_stats
            ],
            'user_agent_analysis': [
                {
                    'user_agent': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in user_agent_stats
            ],
            'quality_metrics': {
                'average_jitter': round(quality_stats[0] or 0, 3),
                'average_packet_loss': round(quality_stats[1] or 0, 3),
                'average_latency': round(quality_stats[2] or 0, 3),
                'average_mos_score': round(quality_stats[3] or 0, 2)
            } if quality_stats[0] else None,
            'protocol_distribution': [
                {
                    'protocol': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in protocol_stats
            ],
            'encryption_usage': [
                {
                    'encrypted': bool(row[0]),
                    'call_count': row[1]
                }
                for row in encryption_stats
            ],
            'threat_flag_analysis': [
                {
                    'flags': json.loads(row[0]) if row[0] else [],
                    'occurrence_count': row[1]
                }
                for row in flag_stats
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3],
                    'caller_id': row[4],
                    'source_ip': row[5],
                    'country': row[6]
                }
                for row in alerts
            ]
        }
    
    def generate_forensic_report(self, call_id: str) -> Dict:
        """Generate detailed forensic report for a specific call"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Get complete call record
        cursor.execute('SELECT * FROM calls WHERE call_id = ?', (call_id,))
        row = cursor.fetchone()
        
        if not row:
            return {'error': 'Call not found'}
        
        # Column names for mapping
        columns = [desc[0] for desc in cursor.description]
        call_data = dict(zip(columns, row))
        
        # Get related calls from same source IP
        cursor.execute('''
            SELECT call_id, timestamp, caller_id, risk_score 
            FROM calls 
            WHERE source_ip = ? AND call_id != ?
            ORDER BY timestamp DESC
            LIMIT 10
        ''', (call_data['source_ip'], call_id))
        
        related_calls = cursor.fetchall()
        
        # Get alerts for this call
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts 
            WHERE call_id = ?
            ORDER BY timestamp DESC
        ''', (call_id,))
        
        call_alerts = cursor.fetchall()
        
        conn.close()
        
        # Parse JSON fields
        for field in ['flags', 'via_headers', 'route_headers', 'record_route_headers', 
                     'audio_codecs', 'video_codecs', 'media_ports', 'diversion_headers', 'custom_headers']:
            if call_data.get(field):
                try:
                    call_data[field] = json.loads(call_data[field])
                except json.JSONDecodeError:
                    pass
        
        return {
            'call_id': call_id,
            'forensic_timestamp': datetime.datetime.now().isoformat(),
            'call_data': call_data,
            'related_calls': [
                {
                    'call_id': row[0],
                    'timestamp': row[1],
                    'caller_id': row[2],
                    'risk_score': row[3]
                }
                for row in related_calls
            ],
            'alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in call_alerts
            ]
        }
    
    def generate_threat_intelligence_report(self, hours: int = 168) -> Dict:
        """Generate threat intelligence report (7 days default)"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # IOC (Indicators of Compromise) extraction
        cursor.execute('''
            SELECT DISTINCT source_ip, caller_id, user_agent, caller_country
            FROM calls 
            WHERE timestamp > ? AND risk_score >= 70
            ORDER BY risk_score DESC
        ''', (threshold.isoformat(),))
        
        iocs = cursor.fetchall()
        
        # Attack pattern analysis
        cursor.execute('''
            SELECT flags, COUNT(*) as frequency,
                   GROUP_CONCAT(DISTINCT source_ip) as source_ips
            FROM calls 
            WHERE timestamp > ? AND flags IS NOT NULL AND flags != '[]'
            GROUP BY flags
            ORDER BY frequency DESC
        ''', (threshold.isoformat(),))
        
        attack_patterns = cursor.fetchall()
        
        # Temporal analysis
        cursor.execute('''
            SELECT DATE(timestamp) as date, 
                   COUNT(*) as total_calls,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls,
                   AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ?
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        ''', (threshold.isoformat(),))
        
        temporal_data = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_type': 'Threat Intelligence',
            'generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'indicators_of_compromise': [
                {
                    'source_ip': row[0],
                    'caller_id': row[1],
                    'user_agent': row[2],
                    'country': row[3]
                }
                for row in iocs
            ],
            'attack_patterns': [
                {
                    'flags': json.loads(row[0]) if row[0] else [],
                    'frequency': row[1],
                    'source_ips': row[2].split(',') if row[2] else []
                }
                for row in attack_patterns
            ],
            'temporal_analysis': [
                {
                    'date': row[0],
                    'total_calls': row[1],
                    'high_risk_calls': row[2],
                    'average_risk': round(row[3], 2)
                }
                for row in temporal_data
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24, report_type: str = 'summary'):
        """Export comprehensive report to JSON file"""
        if not filename:
            filename = f"call_trace_{report_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        if report_type == 'summary':
            report = self.generate_summary_report(hours)
        elif report_type == 'threat_intelligence':
            report = self.generate_threat_intelligence_report(hours)
        else:
            report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename
    
    def export_to_csv(self, filename: str = None, hours: int = 24):
        """Export call data to CSV for analysis tools"""
        if not filename:
            filename = f"call_trace_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        conn = sqlite3.connect(self.db.db_path)
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        query = '''
            SELECT call_id, timestamp, caller_id, destination, duration, call_type,
                   source_ip, source_port, user_agent, sip_method, response_code,
                   risk_score, caller_country, caller_city, device_type, 
                   protocol, encryption_used, flags
            FROM calls 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        '''
        
        import csv
        
        cursor = conn.cursor()
        cursor.execute(query, (threshold.isoformat(),))
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # Write header
            writer.writerow([
                'Call ID', 'Timestamp', 'Caller ID', 'Destination', 'Duration',
                'Call Type', 'Source IP', 'Source Port', 'User Agent', 'SIP Method',
                'Response Code', 'Risk Score', 'Country', 'City', 'Device Type',
                'Protocol', 'Encrypted', 'Flags'
            ])
            
            # Write data
            for row in cursor.fetchall():
                writer.writerow(row)
        
        conn.close()
        logger.info(f"CSV data exported to {filename}")
        return filenameclass SIPMonitor:
    """Monitor SIP traffic for call events with enhanced metadata extraction"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.call_states = {}  # Track call states for timing analysis
        self.geo_cache = {}  # Cache for geographic lookups
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(8192)  # Increased buffer size
                self.process_sip_message(data, addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, data: bytes, addr: Tuple[str, int]):
        """Process incoming SIP message and extract comprehensive metadata"""
        try:
            message = data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            logger.warning(f"Failed to decode SIP message from {addr}")
            return
        
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract comprehensive metadata
        metadata = self.extract_comprehensive_metadata(lines, data, addr)
        
        # Calculate packet hash for forensics
        packet_hash = hashlib.sha256(data).hexdigest()
        
        # Create enhanced call record
        call = CallRecord(
            call_id=metadata.get('call_id', 'unknown'),
            timestamp=datetime.datetime.now(),
            caller_id=metadata.get('caller_id', 'Unknown'),
            destination=metadata.get('destination', 'Unknown'),
            duration=metadata.get('duration', 0),
            call_type=metadata.get('call_type', 'UNKNOWN'),
            source_ip=addr[0],
            source_port=addr[1],
            destination_ip=metadata.get('destination_ip'),
            destination_port=metadata.get('destination_port'),
            protocol=metadata.get('protocol', 'UDP'),
            user_agent=metadata.get('user_agent'),
            sip_method=metadata.get('sip_method'),
            response_code=metadata.get('response_code'),
            
            # SIP Headers
            via_headers=metadata.get('via_headers', []),
            contact_header=metadata.get('contact_header'),
            route_headers=metadata.get('route_headers', []),
            record_route_headers=metadata.get('record_route_headers', []),
            max_forwards=metadata.get('max_forwards'),
            content_type=metadata.get('content_type'),
            content_length=metadata.get('content_length'),
            expires=metadata.get('expires'),
            
            # Call flow metadata
            cseq=metadata.get('cseq'),
            branch=metadata.get('branch'),
            tag_from=metadata.get('tag_from'),
            tag_to=metadata.get('tag_to'),
            
            # Authentication metadata
            authorization=metadata.get('authorization'),
            www_authenticate=metadata.get('www_authenticate'),
            proxy_authenticate=metadata.get('proxy_authenticate'),
            realm=metadata.get('realm'),
            nonce=metadata.get('nonce'),
            
            # Media metadata
            sdp_body=metadata.get('sdp_body'),
            audio_codecs=metadata.get('audio_codecs', []),
            video_codecs=metadata.get('video_codecs', []),
            media_ip=metadata.get('media_ip'),
            media_ports=metadata.get('media_ports', []),
            
            # Network metadata
            ttl=metadata.get('ttl'),
            packet_size=len(data),
            fragmented=metadata.get('fragmented', False),
            tcp_flags=metadata.get('tcp_flags'),
            
            # Timing metadata
            setup_time=metadata.get('setup_time'),
            ring_time=metadata.get('ring_time'),
            answer_time=metadata.get('answer_time'),
            hangup_time=metadata.get('hangup_time'),
            
            # Geographic metadata
            caller_country=metadata.get('caller_country'),
            caller_city=metadata.get('caller_city'),
            caller_isp=metadata.get('caller_isp'),
            source_asn=metadata.get('source_asn'),
            
            # Device fingerprinting
            device_type=metadata.get('device_type'),
            os_fingerprint=metadata.get('os_fingerprint'),
            sip_stack=metadata.get('sip_stack'),
            
            # Quality metrics
            jitter=metadata.get('jitter'),
            packet_loss=metadata.get('packet_loss'),
            latency=metadata.get('latency'),
            mos_score=metadata.get('mos_score'),
            
            # Security metadata
            encryption_used=metadata.get('encryption_used', False),
            tls_version=metadata.get('tls_version'),
            certificate_info=metadata.get('certificate_info'),
            
            # Call chain metadata
            diversion_headers=metadata.get('diversion_headers', []),
            referred_by=metadata.get('referred_by'),
            replaces=metadata.get('replaces'),
            
            # Custom headers
            custom_headers=metadata.get('custom_headers', {}),
            packet_hash=packet_hash
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_comprehensive_metadata(self, lines: List[str], raw_data: bytes, addr: Tuple[str, int]) -> Dict:
        """Extract comprehensive metadata from SIP message"""
        metadata = {}
        
        # Parse request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER', 'OPTIONS', 'ACK', 'SUBSCRIBE', 'NOTIFY']:
            metadata['sip_method'] = parts[0]
            metadata['call_type'] = self.determine_call_type(parts[0])
        elif parts[0] == 'SIP/2.0':
            metadata['response_code'] = int(parts[1]) if len(parts) > 1 else None
            metadata['call_type'] = 'RESPONSE'
        
        # Extract all headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Extract SIP headers
        metadata['call_id'] = headers.get('call-id')
        metadata['user_agent'] = headers.get('user-agent')
        metadata['content_type'] = headers.get('content-type')
        metadata['content_length'] = self.safe_int(headers.get('content-length'))
        metadata['expires'] = self.safe_int(headers.get('expires'))
        metadata['max_forwards'] = self.safe_int(headers.get('max-forwards'))
        metadata['contact_header'] = headers.get('contact')
        metadata['cseq'] = headers.get('cseq')
        
        # Extract Via headers (can be multiple)
        via_headers = []
        for key, value in headers.items():
            if key == 'via':
                via_headers.append(value)
        metadata['via_headers'] = via_headers
        
        # Extract branch from Via header
        if via_headers:
            branch_match = re.search(r'branch=([^;]+)', via_headers[0])
            metadata['branch'] = branch_match.group(1) if branch_match else None
        
        # Extract Route headers
        route_headers = []
        record_route_headers = []
        for key, value in headers.items():
            if key == 'route':
                route_headers.append(value)
            elif key == 'record-route':
                record_route_headers.append(value)
        metadata['route_headers'] = route_headers
        metadata['record_route_headers'] = record_route_headers
        
        # Extract From and To headers with tags
        from_header = headers.get('from')
        to_header = headers.get('to')
        
        if from_header:
            metadata['caller_id'] = self.extract_phone_number(from_header)
            tag_match = re.search(r'tag=([^;]+)', from_header)
            metadata['tag_from'] = tag_match.group(1) if tag_match else None
        
        if to_header:
            metadata['destination'] = self.extract_phone_number(to_header)
            tag_match = re.search(r'tag=([^;]+)', to_header)
            metadata['tag_to'] = tag_match.group(1) if tag_match else None
        
        # Extract authentication headers
        metadata['authorization'] = headers.get('authorization')
        metadata['www_authenticate'] = headers.get('www-authenticate')
        metadata['proxy_authenticate'] = headers.get('proxy-authenticate')
        
        # Extract realm and nonce from auth headers
        auth_header = metadata.get('authorization') or metadata.get('www_authenticate')
        if auth_header:
            realm_match = re.search(r'realm="([^"]+)"', auth_header)
            nonce_match = re.search(r'nonce="([^"]+)"', auth_header)
            metadata['realm'] = realm_match.group(1) if realm_match else None
            metadata['nonce'] = nonce_match.group(1) if nonce_match else None
        
        # Extract call chain headers
        diversion_headers = []
        for key, value in headers.items():
            if key == 'diversion':
                diversion_headers.append(value)
        metadata['diversion_headers'] = diversion_headers
        metadata['referred_by'] = headers.get('referred-by')
        metadata['replaces'] = headers.get('replaces')
        
        # Extract custom headers (X- headers)
        custom_headers = {}
        for key, value in headers.items():
            if key.startswith('x-'):
                custom_headers[key] = value
        metadata['custom_headers'] = custom_headers
        
        # Extract SDP body for media analysis
        if body_start < len(lines):
            sdp_body = '\r\n'.join(lines[body_start:])
            if sdp_body.strip():
                metadata['sdp_body'] = sdp_body
                media_info = self.parse_sdp(sdp_body)
                metadata.update(media_info)
        
        # Device fingerprinting based on User-Agent
        if metadata.get('user_agent'):
            device_info = self.fingerprint_device(metadata['user_agent'])
            metadata.update(device_info)
        
        # Geographic analysis
        if addr[0]:
            geo_info = self.get_geographic_info(addr[0])
            metadata.update(geo_info)
        
        # Protocol detection
        metadata['protocol'] = 'TCP' if 'tcp' in str(headers.get('via', '')).lower() else 'UDP'
        
        # Encryption detection
        if 'sips:' in request_line or 'TLS' in str(headers.get('via', '')):
            metadata['encryption_used'] = True
            metadata['tls_version'] = self.extract_tls_version(headers)
        
        return metadata
    
    def parse_sdp(self, sdp_body: str) -> Dict:
        """Parse SDP body to extract media information"""
        media_info = {
            'audio_codecs': [],
            'video_codecs': [],
            'media_ports': [],
            'media_ip': None
        }
        
        lines = sdp_body.split('\r\n')
        
        for line in lines:
            if line.startswith('c='):
                # Connection information
                parts = line.split(' ')
                if len(parts) >= 3:
                    media_info['media_ip'] = parts[2]
            
            elif line.startswith('m='):
                # Media description
                parts = line.split(' ')
                if len(parts) >= 2:
                    media_type = parts[0][2:]  # Remove 'm='
                    port = self.safe_int(parts[1])
                    if port:
                        media_info['media_ports'].append(port)
                    
                    # Extract codec information
                    if len(parts) > 3:
                        for codec_num in parts[3:]:
                            if codec_num.isdigit():
                                codec_name = self.get_codec_name(int(codec_num))
                                if media_type == 'audio':
                                    media_info['audio_codecs'].append(codec_name)
                                elif media_type == 'video':
                                    media_info['video_codecs'].append(codec_name)
            
            elif line.startswith('a=rtpmap:'):
                # RTP payload type mapping
                parts = line.split(' ')
                if len(parts) >= 2:
                    codec_info = parts[1]
                    if '/' in codec_info:
                        codec_name = codec_info.split('/')[0]
                        if codec_name not in media_info['audio_codecs'] + media_info['video_codecs']:
                            # Determine if audio or video based on common codecs
                            if codec_name.upper() in ['PCMU', 'PCMA', 'G729', 'G722', 'OPUS', 'AMR']:
                                media_info['audio_codecs'].append(codec_name)
                            elif codec_name.upper() in ['H264', 'H265', 'VP8', 'VP9']:
                                media_info['video_codecs'].append(codec_name)
        
        return media_info
    
    def get_codec_name(self, payload_type: int) -> str:
        """Map RTP payload type to codec name"""
        codec_map = {
            0: 'PCMU',
            3: 'GSM',
            4: 'G723',
            5: 'DVI4',
            6: 'DVI4',
            7: 'LPC',
            8: 'PCMA',
            9: 'G722',
            10: 'L16',
            11: 'L16',
            12: 'QCELP',
            13: 'CN',
            14: 'MPA',
            15: 'G728',
            16: 'DVI4',
            17: 'DVI4',
            18: 'G729',
            25: 'CelB',
            26: 'JPEG',
            28: 'nv',
            31: 'H261',
            32: 'MPV',
            33: 'MP2T',
            34: 'H263'
        }
        return codec_map.get(payload_type, f'Unknown({payload_type})')
    
    def fingerprint_device(self, user_agent: str) -> Dict:
        """Fingerprint device based on User-Agent string"""
        device_info = {
            'device_type': 'Unknown',
            'os_fingerprint': 'Unknown',
            'sip_stack': 'Unknown'
        }
        
        ua_lower = user_agent.lower()
        
        # Device type detection
        if any(term in ua_lower for term in ['android', 'iphone', 'mobile']):
            device_info['device_type'] = 'Mobile'
        elif any(term in ua_lower for term in ['windows', 'linux', 'macos', 'darwin']):
            device_info['device_type'] = 'Desktop'
        elif any(term in ua_lower for term in ['cisco', 'polycom', 'yealink', 'grandstream']):
            device_info['device_type'] = 'IP Phone'
        elif any(term in ua_lower for term in ['asterisk', 'freeswitch', 'opensips']):
            device_info['device_type'] = 'PBX/Server'
        
        # OS fingerprinting
        if 'windows' in ua_lower:
            device_info['os_fingerprint'] = 'Windows'
        elif 'android' in ua_lower:
            device_info['os_fingerprint'] = 'Android'
        elif 'iphone' in ua_lower or 'ios' in ua_lower:
            device_info['os_fingerprint'] = 'iOS'
        elif 'linux' in ua_lower:
            device_info['os_fingerprint'] = 'Linux'
        elif 'darwin' in ua_lower or 'macos' in ua_lower:
            device_info['os_fingerprint'] = 'macOS'
        
        # SIP stack detection
        if 'asterisk' in ua_lower:
            device_info['sip_stack'] = 'Asterisk'
        elif 'freeswitch' in ua_lower:
            device_info['sip_stack'] = 'FreeSWITCH'
        elif 'opensips' in ua_lower:
            device_info['sip_stack'] = 'OpenSIPS'
        elif 'kamailio' in ua_lower:
            device_info['sip_stack'] = 'Kamailio'
        elif 'pjsip' in ua_lower or 'pjsua' in ua_lower:
            device_info['sip_stack'] = 'PJSIP'
        elif 'linphone' in ua_lower:
            device_info['sip_stack'] = 'Linphone'
        elif 'x-lite' in ua_lower:
            device_info['sip_stack'] = 'X-Lite'
        elif 'zoiper' in ua_lower:
            device_info['sip_stack'] = 'Zoiper'
        
        return device_info
    
    def get_geographic_info(self, ip_address: str) -> Dict:
        """Get geographic information for IP address"""
        geo_info = {
            'caller_country': None,
            'caller_city': None,
            'caller_isp': None,
            'source_asn': None
        }
        
        # Check cache first
        if ip_address in self.geo_cache:
            return self.geo_cache[ip_address]
        
        try:
            # Check if it's a private IP
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                geo_info['caller_country'] = 'Private Network'
                geo_info['caller_city'] = 'Local'
                self.geo_cache[ip_address] = geo_info
                return geo_info
            
            # For production use, integrate with IP geolocation API
            # This is a placeholder for demonstration
            if ip_address.startswith('192.168.'):
                geo_info['caller_country'] = 'Private Network'
                geo_info['caller_city'] = 'Local'
            elif ip_address.startswith('10.'):
                geo_info['caller_country'] = 'Private Network'
                geo_info['caller_city'] = 'Local'
            else:
                # Placeholder logic - in production, use MaxMind GeoIP2 or similar
                geo_info['caller_country'] = 'Unknown'
                geo_info['caller_city'] = 'Unknown'
                geo_info['caller_isp'] = 'Unknown'
                geo_info['source_asn'] = 'Unknown'
        
        except Exception as e:
            logger.warning(f"Geographic lookup failed for {ip_address}: {e}")
        
        # Cache the result
        self.geo_cache[ip_address] = geo_info
        return geo_info
    
    def extract_tls_version(self, headers: Dict) -> Optional[str]:
        """Extract TLS version from headers"""
        via_header = headers.get('via', '')
        if 'TLS' in via_header:
            # Try to extract TLS version
            tls_match = re.search(r'TLS\s*([0-9.]+)', via_header)
            if tls_match:
                return f"TLS {tls_match.group(1)}"
            return "TLS"
        return None
    
    def determine_call_type(self, method: str) -> str:
        """Determine call type based on SIP method"""
        if method == 'INVITE':
            return 'INBOUND'
        elif method in ['BYE', 'CANCEL']:
            return 'HANGUP'
        elif method == 'REGISTER':
            return 'REGISTRATION'
        elif method in ['OPTIONS', 'SUBSCRIBE', 'NOTIFY']:
            return 'CONTROL'
        else:
            return 'OTHER'
    
    def safe_int(self, value: str) -> Optional[int]:
        """Safely convert string to integer"""
        try:
            return int(value) if value else None
        except (ValueError, TypeError):
            return None#!/usr/bin/env python3
"""
Call Trap and Trace System
A comprehensive system for monitoring, logging, and analyzing incoming calls
for security analysis and incident response.
"""

import json
import sqlite3
import datetime
import re
import socket
import threading
import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('call_trace.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CallRecord:
    """Data structure for call records with comprehensive metadata"""
    call_id: str
    timestamp: datetime.datetime
    caller_id: str
    destination: str
    duration: int
    call_type: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    sip_method: Optional[str] = None
    response_code: Optional[int] = None
    risk_score: int = 0
    flags: List[str] = None
    
    # Enhanced metadata fields
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: str = "UDP"
    
    # SIP Headers
    via_headers: List[str] = None
    contact_header: Optional[str] = None
    route_headers: List[str] = None
    record_route_headers: List[str] = None
    max_forwards: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    expires: Optional[int] = None
    
    # Call flow metadata
    cseq: Optional[str] = None
    branch: Optional[str] = None
    tag_from: Optional[str] = None
    tag_to: Optional[str] = None
    
    # Authentication metadata
    authorization: Optional[str] = None
    www_authenticate: Optional[str] = None
    proxy_authenticate: Optional[str] = None
    realm: Optional[str] = None
    nonce: Optional[str] = None
    
    # Codec and media metadata
    sdp_body: Optional[str] = None
    audio_codecs: List[str] = None
    video_codecs: List[str] = None
    media_ip: Optional[str] = None
    media_ports: List[int] = None
    
    # Network metadata
    ttl: Optional[int] = None
    packet_size: Optional[int] = None
    fragmented: bool = False
    tcp_flags: Optional[str] = None
    
    # Timing metadata
    setup_time: Optional[float] = None
    ring_time: Optional[float] = None
    answer_time: Optional[float] = None
    hangup_time: Optional[float] = None
    
    # Geographic metadata
    caller_country: Optional[str] = None
    caller_city: Optional[str] = None
    caller_isp: Optional[str] = None
    source_asn: Optional[str] = None
    
    # Device fingerprinting
    device_type: Optional[str] = None
    os_fingerprint: Optional[str] = None
    sip_stack: Optional[str] = None
    
    # Quality metrics
    jitter: Optional[float] = None
    packet_loss: Optional[float] = None
    latency: Optional[float] = None
    mos_score: Optional[float] = None
    
    # Security metadata
    encryption_used: bool = False
    tls_version: Optional[str] = None
    certificate_info: Optional[str] = None
    
    # Call chain metadata
    diversion_headers: List[str] = None
    referred_by: Optional[str] = None
    replaces: Optional[str] = None
    
    # Custom headers
    custom_headers: Dict[str, str] = None
    
    # Raw data for forensics
    raw_packet: Optional[bytes] = None
    packet_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.flags is None:
            self.flags = []
        if self.via_headers is None:
            self.via_headers = []
        if self.route_headers is None:
            self.route_headers = []
        if self.record_route_headers is None:
            self.record_route_headers = []
        if self.audio_codecs is None:
            self.audio_codecs = []
        if self.video_codecs is None:
            self.video_codecs = []
        if self.media_ports is None:
            self.media_ports = []
        if self.diversion_headers is None:
            self.diversion_headers = []
        if self.custom_headers is None:
            self.custom_headers = {}

class CallDatabase:
    """Database handler for call records"""
    
    def __init__(self, db_path: str = "call_trace.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                caller_id TEXT NOT NULL,
                destination TEXT NOT NULL,
                duration INTEGER,
                call_type TEXT,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                user_agent TEXT,
                sip_method TEXT,
                response_code INTEGER,
                risk_score INTEGER DEFAULT 0,
                flags TEXT,
                
                -- SIP Headers
                via_headers TEXT,
                contact_header TEXT,
                route_headers TEXT,
                record_route_headers TEXT,
                max_forwards INTEGER,
                content_type TEXT,
                content_length INTEGER,
                expires INTEGER,
                
                -- Call flow metadata
                cseq TEXT,
                branch TEXT,
                tag_from TEXT,
                tag_to TEXT,
                
                -- Authentication metadata
                authorization TEXT,
                www_authenticate TEXT,
                proxy_authenticate TEXT,
                realm TEXT,
                nonce TEXT,
                
                -- Codec and media metadata
                sdp_body TEXT,
                audio_codecs TEXT,
                video_codecs TEXT,
                media_ip TEXT,
                media_ports TEXT,
                
                -- Network metadata
                ttl INTEGER,
                packet_size INTEGER,
                fragmented BOOLEAN,
                tcp_flags TEXT,
                
                -- Timing metadata
                setup_time REAL,
                ring_time REAL,
                answer_time REAL,
                hangup_time REAL,
                
                -- Geographic metadata
                caller_country TEXT,
                caller_city TEXT,
                caller_isp TEXT,
                source_asn TEXT,
                
                -- Device fingerprinting
                device_type TEXT,
                os_fingerprint TEXT,
                sip_stack TEXT,
                
                -- Quality metrics
                jitter REAL,
                packet_loss REAL,
                latency REAL,
                mos_score REAL,
                
                -- Security metadata
                encryption_used BOOLEAN,
                tls_version TEXT,
                certificate_info TEXT,
                
                -- Call chain metadata
                diversion_headers TEXT,
                referred_by TEXT,
                replaces TEXT,
                
                -- Custom headers and forensics
                custom_headers TEXT,
                packet_hash TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                number TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_date TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_call(self, call: CallRecord):
        """Insert a call record into the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO calls 
                (call_id, timestamp, caller_id, destination, duration, call_type,
                 source_ip, source_port, destination_ip, destination_port, protocol,
                 user_agent, sip_method, response_code, risk_score, flags,
                 via_headers, contact_header, route_headers, record_route_headers,
                 max_forwards, content_type, content_length, expires, cseq, branch,
                 tag_from, tag_to, authorization, www_authenticate, proxy_authenticate,
                 realm, nonce, sdp_body, audio_codecs, video_codecs, media_ip,
                 media_ports, ttl, packet_size, fragmented, tcp_flags, setup_time,
                 ring_time, answer_time, hangup_time, caller_country, caller_city,
                 caller_isp, source_asn, device_type, os_fingerprint, sip_stack,
                 jitter, packet_loss, latency, mos_score, encryption_used,
                 tls_version, certificate_info, diversion_headers, referred_by,
                 replaces, custom_headers, packet_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                call.call_id,
                call.timestamp.isoformat(),
                call.caller_id,
                call.destination,
                call.duration,
                call.call_type,
                call.source_ip,
                call.source_port,
                call.destination_ip,
                call.destination_port,
                call.protocol,
                call.user_agent,
                call.sip_method,
                call.response_code,
                call.risk_score,
                json.dumps(call.flags),
                json.dumps(call.via_headers),
                call.contact_header,
                json.dumps(call.route_headers),
                json.dumps(call.record_route_headers),
                call.max_forwards,
                call.content_type,
                call.content_length,
                call.expires,
                call.cseq,
                call.branch,
                call.tag_from,
                call.tag_to,
                call.authorization,
                call.www_authenticate,
                call.proxy_authenticate,
                call.realm,
                call.nonce,
                call.sdp_body,
                json.dumps(call.audio_codecs),
                json.dumps(call.video_codecs),
                call.media_ip,
                json.dumps(call.media_ports),
                call.ttl,
                call.packet_size,
                call.fragmented,
                call.tcp_flags,
                call.setup_time,
                call.ring_time,
                call.answer_time,
                call.hangup_time,
                call.caller_country,
                call.caller_city,
                call.caller_isp,
                call.source_asn,
                call.device_type,
                call.os_fingerprint,
                call.sip_stack,
                call.jitter,
                call.packet_loss,
                call.latency,
                call.mos_score,
                call.encryption_used,
                call.tls_version,
                call.certificate_info,
                json.dumps(call.diversion_headers),
                call.referred_by,
                call.replaces,
                json.dumps(call.custom_headers),
                call.packet_hash
            ))
            conn.commit()
            logger.info(f"Call record inserted: {call.call_id}")
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
        finally:
            conn.close()
    
    def get_calls(self, limit: int = 100, caller_id: str = None) -> List[CallRecord]:
        """Retrieve call records from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM calls"
        params = []
        
        if caller_id:
            query += " WHERE caller_id = ?"
            params.append(caller_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        calls = []
        for row in rows:
            call = CallRecord(
                call_id=row[1],
                timestamp=datetime.datetime.fromisoformat(row[2]),
                caller_id=row[3],
                destination=row[4],
                duration=row[5],
                call_type=row[6],
                source_ip=row[7],
                user_agent=row[8],
                sip_method=row[9],
                response_code=row[10],
                risk_score=row[11],
                flags=json.loads(row[12]) if row[12] else []
            )
            calls.append(call)
        
        return calls

class ThreatAnalyzer:
    """Enhanced threat analyzer utilizing comprehensive metadata"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
        self.suspicious_patterns = [
            r'^\+?1?8(00|88|77|66|55|44|33|22)\d{7}
    
    def generate_alert(self, call: CallRecord):
        """Generate security alert for high-risk calls"""
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            return
        
        alert_message = f"Suspicious call detected from {call.caller_id} (Risk: {call.risk_score})"
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (call_id, alert_type, message, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            call.call_id,
            "THREAT_DETECTION",
            alert_message,
            severity,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}]: {alert_message}")

class SIPMonitor:
    """Monitor SIP traffic for call events"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.process_sip_message(data.decode('utf-8'), addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, message: str, addr: Tuple[str, int]):
        """Process incoming SIP message and extract call information"""
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract call information
        call_id = self.extract_header(lines, 'Call-ID')
        from_header = self.extract_header(lines, 'From')
        to_header = self.extract_header(lines, 'To')
        user_agent = self.extract_header(lines, 'User-Agent')
        
        if not call_id:
            return
        
        # Extract caller ID from From header
        caller_id = self.extract_phone_number(from_header) if from_header else "Unknown"
        destination = self.extract_phone_number(to_header) if to_header else "Unknown"
        
        # Determine call type and method
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER']:
            sip_method = parts[0]
            call_type = "INBOUND" if sip_method == "INVITE" else "CONTROL"
        else:
            # This is a response
            sip_method = None
            call_type = "RESPONSE"
        
        # Create call record
        call = CallRecord(
            call_id=call_id,
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=0,  # Will be updated on BYE
            call_type=call_type,
            source_ip=addr[0],
            user_agent=user_agent,
            sip_method=sip_method,
            response_code=int(parts[1]) if parts[0] == 'SIP/2.0' else None
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_header(self, lines: List[str], header_name: str) -> Optional[str]:
        """Extract header value from SIP message"""
        for line in lines:
            if line.startswith(f"{header_name}:"):
                return line.split(":", 1)[1].strip()
        return None
    
    def extract_phone_number(self, header: str) -> str:
        """Extract phone number from SIP header"""
        # Simple regex to extract phone number from SIP URI
        match = re.search(r'sip:([^@]+)@', header)
        if match:
            return match.group(1)
        return "Unknown"
    
    def stop_monitoring(self):
        """Stop SIP monitoring"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("SIP Monitor stopped")

class CallTraceReporter:
    """Generate reports and statistics from call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate summary report for the last N hours"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get call statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Get top suspicious numbers
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Get recent alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0
            },
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in suspicious_numbers
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in alerts
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24):
        """Export call data to JSON file"""
        if not filename:
            filename = f"call_trace_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename

class CallTraceManager:
    """Enhanced main manager class for the call trace system"""
    
    def __init__(self):
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.reporter = CallTraceReporter(self.db)
        self.monitor = None
        self.monitor_thread = None
    
    def start_monitoring(self, host: str = "0.0.0.0", port: int = 5060):
        """Start enhanced call monitoring"""
        self.monitor = SIPMonitor(host, port)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Enhanced call trace monitoring started")
    
    def stop_monitoring(self):
        """Stop call monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
        logger.info("Call trace monitoring stopped")
    
    def add_manual_call(self, caller_id: str, destination: str, duration: int = 0):
        """Manually add a call record for testing with enhanced metadata"""
        call = CallRecord(
            call_id=hashlib.md5(f"{caller_id}{time.time()}".encode()).hexdigest(),
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=duration,
            call_type="MANUAL",
            source_ip="127.0.0.1",
            device_type="Test Device",
            caller_country="Test",
            protocol="UDP"
        )
        
        call = self.analyzer.analyze_call(call)
        self.db.insert_call(call)
        self.analyzer.generate_alert(call)
        
        return call
    
    def get_recent_calls(self, limit: int = 50) -> List[CallRecord]:
        """Get recent call records"""
        return self.db.get_calls(limit)
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report"""
        return self.reporter.generate_summary_report(hours)
    
    def export_report(self, filename: str = None, hours: int = 24) -> str:
        """Export report to file"""
        return self.reporter.export_to_json(filename, hours)
    
    def analyze_ip_address(self, ip_address: str, hours: int = 24) -> List[CallRecord]:
        """Analyze all calls from a specific IP address"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        cursor.execute('''
            SELECT call_id FROM calls 
            WHERE source_ip = ? AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (ip_address, threshold.isoformat()))
        
        call_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        calls = []
        for call_id in call_ids:
            call_records = self.db.get_calls(limit=1, caller_id=None)
            # This is a simplified approach - in production you'd want a more efficient query
            for call in call_records:
                if call.call_id == call_id:
                    calls.append(call)
                    break
        
        return calls
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent security alerts"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (threshold.isoformat(),))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'type': row[0],
                'message': row[1],
                'severity': row[2],
                'timestamp': row[3]
            })
        
        conn.close()
        return alerts

def main():
    """Enhanced main function for CLI usage with comprehensive metadata features"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Call Trap and Trace System")
    parser.add_argument('--monitor', action='store_true', help='Start SIP monitoring')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5060, help='Port to bind to')
    parser.add_argument('--report', action='store_true', help='Generate summary report')
    parser.add_argument('--threat-intel', action='store_true', help='Generate threat intelligence report')
    parser.add_argument('--forensic', help='Generate forensic report for specific call ID')
    parser.add_argument('--hours', type=int, default=24, help='Hours to include in report')
    parser.add_argument('--export', help='Export report to file (json/csv)')
    parser.add_argument('--export-format', choices=['json', 'csv'], default='json', help='Export format')
    parser.add_argument('--test', help='Add test call (format: caller_id,destination,duration)')
    parser.add_argument('--analyze-ip', help='Analyze all calls from specific IP address')
    parser.add_argument('--search-caller', help='Search for calls from specific caller ID')
    parser.add_argument('--list-alerts', action='store_true', help='List recent security alerts')
    
    args = parser.parse_args()
    
    manager = CallTraceManager()
    
    if args.monitor:
        try:
            manager.start_monitoring(args.host, args.port)
            print(f"Enhanced monitoring started on {args.host}:{args.port}")
            print("Capturing comprehensive metadata including:")
            print("- SIP headers and authentication")
            print("- Media codecs and quality metrics")
            print("- Device fingerprinting")
            print("- Geographic analysis")
            print("- Network-level metadata")
            print("Press Ctrl+C to stop...")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop_monitoring()
            print("\nMonitoring stopped")
    
    elif args.report:
        report = manager.generate_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.threat_intel:
        report = manager.reporter.generate_threat_intelligence_report(args.hours)
        print("=== THREAT INTELLIGENCE REPORT ===")
        print(json.dumps(report, indent=2))
    
    elif args.forensic:
        report = manager.reporter.generate_forensic_report(args.forensic)
        print(f"=== FORENSIC REPORT FOR CALL {args.forensic} ===")
        print(json.dumps(report, indent=2))
    
    elif args.export:
        if args.export_format == 'csv':
            filename = manager.reporter.export_to_csv(args.export, args.hours)
        else:
            report_type = 'threat_intelligence' if args.threat_intel else 'summary'
            filename = manager.reporter.export_to_json(args.export, args.hours, report_type)
        print(f"Report exported to {filename}")
    
    elif args.analyze_ip:
        calls = manager.analyze_ip_address(args.analyze_ip, args.hours)
        print(f"=== ANALYSIS FOR IP {args.analyze_ip} ===")
        for call in calls:
            print(f"Call: {call.call_id} | Risk: {call.risk_score} | Flags: {call.flags}")
    
    elif args.search_caller:
        calls = manager.db.get_calls(limit=50, caller_id=args.search_caller)
        print(f"=== CALLS FROM {args.search_caller} ===")
        for call in calls:
            print(f"Time: {call.timestamp} | Risk: {call.risk_score} | Country: {call.caller_country}")
    
    elif args.list_alerts:
        alerts = manager.get_recent_alerts(args.hours)
        print("=== RECENT SECURITY ALERTS ===")
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['timestamp']}: {alert['message']}")
    
    elif args.test:
        parts = args.test.split(',')
        if len(parts) >= 2:
            caller_id = parts[0]
            destination = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 0
            
            call = manager.add_manual_call(caller_id, destination, duration)
            print(f"Test call added: {call.call_id}")
            print(f"Risk Score: {call.risk_score}")
            print(f"Flags: {call.flags}")
            print(f"Metadata captured: Device={call.device_type}, Country={call.caller_country}")
        else:
            print("Invalid test format. Use: caller_id,destination,duration")
    
    else:
        # Enhanced interactive mode
        print("Enhanced Call Trap and Trace System - Interactive Mode")
        print("Commands: monitor, report, threat-intel, forensic <call_id>, export, analyze-ip <ip>, search <caller_id>, alerts, test, quit")
        
        while True:
            try:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'monitor':
                    print("Starting enhanced monitor... (Press Ctrl+C to stop)")
                    manager.start_monitoring()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("\nMonitoring stopped")
                
                elif cmd == 'report':
                    report = manager.generate_report(24)
                    print("=== COMPREHENSIVE SECURITY REPORT ===")
                    print(f"Total Calls: {report['summary_statistics']['total_calls']}")
                    print(f"High Risk Calls: {report['summary_statistics']['high_risk_calls']}")
                    print(f"Unique IPs: {report['summary_statistics']['unique_source_ips']}")
                    print(f"Countries: {len(report['geographic_analysis'])}")
                    if report['recent_alerts']:
                        print(f"Recent Alerts: {len(report['recent_alerts'])}")
                
                elif cmd == 'threat-intel':
                    report = manager.reporter.generate_threat_intelligence_report(168)
                    print("=== THREAT INTELLIGENCE SUMMARY ===")
                    print(f"IOCs Found: {len(report['indicators_of_compromise'])}")
                    print(f"Attack Patterns: {len(report['attack_patterns'])}")
                
                elif cmd.startswith('forensic'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        call_id = parts[1]
                        report = manager.reporter.generate_forensic_report(call_id)
                        if 'error' not in report:
                            print(f"=== FORENSIC ANALYSIS: {call_id} ===")
                            print(f"Risk Score: {report['call_data']['risk_score']}")
                            print(f"Source IP: {report['call_data']['source_ip']}")
                            print(f"Country: {report['call_data']['caller_country']}")
                            print(f"Device: {report['call_data']['device_type']}")
                            print(f"Related Calls: {len(report['related_calls'])}")
                        else:
                            print(report['error'])
                    else:
                        print("Usage: forensic <call_id>")
                
                elif cmd == 'export':
                    filename = manager.export_report()
                    print(f"Enhanced report exported to {filename}")
                
                elif cmd.startswith('analyze-ip'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        ip = parts[1]
                        calls = manager.analyze_ip_address(ip)
                        print(f"=== IP ANALYSIS: {ip} ===")
                        print(f"Total calls: {len(calls)}")
                        if calls:
                            avg_risk = sum(c.risk_score for c in calls) / len(calls)
                            print(f"Average risk: {avg_risk:.1f}")
                    else:
                        print("Usage: analyze-ip <ip_address>")
                
                elif cmd.startswith('search'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        caller = parts[1]
                        calls = manager.db.get_calls(limit=20, caller_id=caller)
                        print(f"=== CALLER SEARCH: {caller} ===")
                        for call in calls[:5]:  # Show first 5
                            print(f"{call.timestamp}: Risk {call.risk_score} from {call.source_ip}")
                    else:
                        print("Usage: search <caller_id>")
                
                elif cmd == 'alerts':
                    alerts = manager.get_recent_alerts(24)
                    print("=== RECENT ALERTS ===")
                    for alert in alerts[:10]:  # Show first 10
                        print(f"[{alert['severity']}] {alert['message']}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call: Risk {call.risk_score}, Flags: {call.flags}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Available commands:")
                    print("  monitor - Start enhanced monitoring")
                    print("  report - Generate comprehensive report")
                    print("  threat-intel - Generate threat intelligence")
                    print("  forensic <call_id> - Detailed call analysis")
                    print("  export - Export data")
                    print("  analyze-ip <ip> - Analyze IP address")
                    print("  search <caller> - Search caller history")
                    print("  alerts - Show recent alerts")
                    print("  test <caller,dest> - Add test call")
                    print("  quit - Exit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()"Report exported to {filename}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call added: Risk score {call.risk_score}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Unknown command. Available: monitor, report, export, test, quit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
,  # Toll-free abuse
            r'^\+?1?900\d{7}
    
    def generate_alert(self, call: CallRecord):
        """Generate security alert for high-risk calls"""
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            return
        
        alert_message = f"Suspicious call detected from {call.caller_id} (Risk: {call.risk_score})"
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (call_id, alert_type, message, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            call.call_id,
            "THREAT_DETECTION",
            alert_message,
            severity,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}]: {alert_message}")

class SIPMonitor:
    """Monitor SIP traffic for call events"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.process_sip_message(data.decode('utf-8'), addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, message: str, addr: Tuple[str, int]):
        """Process incoming SIP message and extract call information"""
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract call information
        call_id = self.extract_header(lines, 'Call-ID')
        from_header = self.extract_header(lines, 'From')
        to_header = self.extract_header(lines, 'To')
        user_agent = self.extract_header(lines, 'User-Agent')
        
        if not call_id:
            return
        
        # Extract caller ID from From header
        caller_id = self.extract_phone_number(from_header) if from_header else "Unknown"
        destination = self.extract_phone_number(to_header) if to_header else "Unknown"
        
        # Determine call type and method
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER']:
            sip_method = parts[0]
            call_type = "INBOUND" if sip_method == "INVITE" else "CONTROL"
        else:
            # This is a response
            sip_method = None
            call_type = "RESPONSE"
        
        # Create call record
        call = CallRecord(
            call_id=call_id,
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=0,  # Will be updated on BYE
            call_type=call_type,
            source_ip=addr[0],
            user_agent=user_agent,
            sip_method=sip_method,
            response_code=int(parts[1]) if parts[0] == 'SIP/2.0' else None
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_header(self, lines: List[str], header_name: str) -> Optional[str]:
        """Extract header value from SIP message"""
        for line in lines:
            if line.startswith(f"{header_name}:"):
                return line.split(":", 1)[1].strip()
        return None
    
    def extract_phone_number(self, header: str) -> str:
        """Extract phone number from SIP header"""
        # Simple regex to extract phone number from SIP URI
        match = re.search(r'sip:([^@]+)@', header)
        if match:
            return match.group(1)
        return "Unknown"
    
    def stop_monitoring(self):
        """Stop SIP monitoring"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("SIP Monitor stopped")

class CallTraceReporter:
    """Generate reports and statistics from call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate summary report for the last N hours"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get call statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Get top suspicious numbers
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Get recent alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0
            },
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in suspicious_numbers
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in alerts
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24):
        """Export call data to JSON file"""
        if not filename:
            filename = f"call_trace_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename

class CallTraceManager:
    """Main manager class for the call trace system"""
    
    def __init__(self):
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.reporter = CallTraceReporter(self.db)
        self.monitor = None
        self.monitor_thread = None
    
    def start_monitoring(self, host: str = "0.0.0.0", port: int = 5060):
        """Start call monitoring"""
        self.monitor = SIPMonitor(host, port)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Call trace monitoring started")
    
    def stop_monitoring(self):
        """Stop call monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
        logger.info("Call trace monitoring stopped")
    
    def add_manual_call(self, caller_id: str, destination: str, duration: int = 0):
        """Manually add a call record for testing"""
        call = CallRecord(
            call_id=hashlib.md5(f"{caller_id}{time.time()}".encode()).hexdigest(),
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=duration,
            call_type="MANUAL"
        )
        
        call = self.analyzer.analyze_call(call)
        self.db.insert_call(call)
        self.analyzer.generate_alert(call)
        
        return call
    
    def get_recent_calls(self, limit: int = 50) -> List[CallRecord]:
        """Get recent call records"""
        return self.db.get_calls(limit)
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report"""
        return self.reporter.generate_summary_report(hours)
    
    def export_report(self, filename: str = None, hours: int = 24) -> str:
        """Export report to file"""
        return self.reporter.export_to_json(filename, hours)

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Call Trap and Trace System")
    parser.add_argument('--monitor', action='store_true', help='Start SIP monitoring')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5060, help='Port to bind to')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours to include in report')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--test', help='Add test call (format: caller_id,destination,duration)')
    
    args = parser.parse_args()
    
    manager = CallTraceManager()
    
    if args.monitor:
        try:
            manager.start_monitoring(args.host, args.port)
            print(f"Monitoring started on {args.host}:{args.port}")
            print("Press Ctrl+C to stop...")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop_monitoring()
            print("\nMonitoring stopped")
    
    elif args.report:
        report = manager.generate_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.export:
        filename = manager.export_report(args.export, args.hours)
        print(f"Report exported to {filename}")
    
    elif args.test:
        parts = args.test.split(',')
        if len(parts) >= 2:
            caller_id = parts[0]
            destination = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 0
            
            call = manager.add_manual_call(caller_id, destination, duration)
            print(f"Test call added: {call.call_id} (Risk: {call.risk_score})")
        else:
            print("Invalid test format. Use: caller_id,destination,duration")
    
    else:
        # Interactive mode
        print("Call Trap and Trace System - Interactive Mode")
        print("Commands: monitor, report, export, test, quit")
        
        while True:
            try:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'monitor':
                    print("Starting monitor... (Press Ctrl+C to stop)")
                    manager.start_monitoring()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("\nMonitoring stopped")
                
                elif cmd == 'report':
                    report = manager.generate_report()
                    print(json.dumps(report, indent=2))
                
                elif cmd == 'export':
                    filename = manager.export_report()
                    print(f"Report exported to {filename}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call added: Risk score {call.risk_score}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Unknown command. Available: monitor, report, export, test, quit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
,  # Premium rate
            r'^\d{1,3}
    
    def generate_alert(self, call: CallRecord):
        """Generate security alert for high-risk calls"""
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            return
        
        alert_message = f"Suspicious call detected from {call.caller_id} (Risk: {call.risk_score})"
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (call_id, alert_type, message, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            call.call_id,
            "THREAT_DETECTION",
            alert_message,
            severity,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}]: {alert_message}")

class SIPMonitor:
    """Monitor SIP traffic for call events"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.process_sip_message(data.decode('utf-8'), addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, message: str, addr: Tuple[str, int]):
        """Process incoming SIP message and extract call information"""
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract call information
        call_id = self.extract_header(lines, 'Call-ID')
        from_header = self.extract_header(lines, 'From')
        to_header = self.extract_header(lines, 'To')
        user_agent = self.extract_header(lines, 'User-Agent')
        
        if not call_id:
            return
        
        # Extract caller ID from From header
        caller_id = self.extract_phone_number(from_header) if from_header else "Unknown"
        destination = self.extract_phone_number(to_header) if to_header else "Unknown"
        
        # Determine call type and method
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER']:
            sip_method = parts[0]
            call_type = "INBOUND" if sip_method == "INVITE" else "CONTROL"
        else:
            # This is a response
            sip_method = None
            call_type = "RESPONSE"
        
        # Create call record
        call = CallRecord(
            call_id=call_id,
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=0,  # Will be updated on BYE
            call_type=call_type,
            source_ip=addr[0],
            user_agent=user_agent,
            sip_method=sip_method,
            response_code=int(parts[1]) if parts[0] == 'SIP/2.0' else None
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_header(self, lines: List[str], header_name: str) -> Optional[str]:
        """Extract header value from SIP message"""
        for line in lines:
            if line.startswith(f"{header_name}:"):
                return line.split(":", 1)[1].strip()
        return None
    
    def extract_phone_number(self, header: str) -> str:
        """Extract phone number from SIP header"""
        # Simple regex to extract phone number from SIP URI
        match = re.search(r'sip:([^@]+)@', header)
        if match:
            return match.group(1)
        return "Unknown"
    
    def stop_monitoring(self):
        """Stop SIP monitoring"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("SIP Monitor stopped")

class CallTraceReporter:
    """Generate reports and statistics from call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate summary report for the last N hours"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get call statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Get top suspicious numbers
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Get recent alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0
            },
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in suspicious_numbers
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in alerts
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24):
        """Export call data to JSON file"""
        if not filename:
            filename = f"call_trace_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename

class CallTraceManager:
    """Main manager class for the call trace system"""
    
    def __init__(self):
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.reporter = CallTraceReporter(self.db)
        self.monitor = None
        self.monitor_thread = None
    
    def start_monitoring(self, host: str = "0.0.0.0", port: int = 5060):
        """Start call monitoring"""
        self.monitor = SIPMonitor(host, port)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Call trace monitoring started")
    
    def stop_monitoring(self):
        """Stop call monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
        logger.info("Call trace monitoring stopped")
    
    def add_manual_call(self, caller_id: str, destination: str, duration: int = 0):
        """Manually add a call record for testing"""
        call = CallRecord(
            call_id=hashlib.md5(f"{caller_id}{time.time()}".encode()).hexdigest(),
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=duration,
            call_type="MANUAL"
        )
        
        call = self.analyzer.analyze_call(call)
        self.db.insert_call(call)
        self.analyzer.generate_alert(call)
        
        return call
    
    def get_recent_calls(self, limit: int = 50) -> List[CallRecord]:
        """Get recent call records"""
        return self.db.get_calls(limit)
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report"""
        return self.reporter.generate_summary_report(hours)
    
    def export_report(self, filename: str = None, hours: int = 24) -> str:
        """Export report to file"""
        return self.reporter.export_to_json(filename, hours)

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Call Trap and Trace System")
    parser.add_argument('--monitor', action='store_true', help='Start SIP monitoring')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5060, help='Port to bind to')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours to include in report')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--test', help='Add test call (format: caller_id,destination,duration)')
    
    args = parser.parse_args()
    
    manager = CallTraceManager()
    
    if args.monitor:
        try:
            manager.start_monitoring(args.host, args.port)
            print(f"Monitoring started on {args.host}:{args.port}")
            print("Press Ctrl+C to stop...")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop_monitoring()
            print("\nMonitoring stopped")
    
    elif args.report:
        report = manager.generate_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.export:
        filename = manager.export_report(args.export, args.hours)
        print(f"Report exported to {filename}")
    
    elif args.test:
        parts = args.test.split(',')
        if len(parts) >= 2:
            caller_id = parts[0]
            destination = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 0
            
            call = manager.add_manual_call(caller_id, destination, duration)
            print(f"Test call added: {call.call_id} (Risk: {call.risk_score})")
        else:
            print("Invalid test format. Use: caller_id,destination,duration")
    
    else:
        # Interactive mode
        print("Call Trap and Trace System - Interactive Mode")
        print("Commands: monitor, report, export, test, quit")
        
        while True:
            try:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'monitor':
                    print("Starting monitor... (Press Ctrl+C to stop)")
                    manager.start_monitoring()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("\nMonitoring stopped")
                
                elif cmd == 'report':
                    report = manager.generate_report()
                    print(json.dumps(report, indent=2))
                
                elif cmd == 'export':
                    filename = manager.export_report()
                    print(f"Report exported to {filename}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call added: Risk score {call.risk_score}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Unknown command. Available: monitor, report, export, test, quit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
,  # Short codes
            r'^\+?1?(\d)\1{9}
    
    def generate_alert(self, call: CallRecord):
        """Generate security alert for high-risk calls"""
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            return
        
        alert_message = f"Suspicious call detected from {call.caller_id} (Risk: {call.risk_score})"
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (call_id, alert_type, message, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            call.call_id,
            "THREAT_DETECTION",
            alert_message,
            severity,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}]: {alert_message}")

class SIPMonitor:
    """Monitor SIP traffic for call events"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.process_sip_message(data.decode('utf-8'), addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, message: str, addr: Tuple[str, int]):
        """Process incoming SIP message and extract call information"""
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract call information
        call_id = self.extract_header(lines, 'Call-ID')
        from_header = self.extract_header(lines, 'From')
        to_header = self.extract_header(lines, 'To')
        user_agent = self.extract_header(lines, 'User-Agent')
        
        if not call_id:
            return
        
        # Extract caller ID from From header
        caller_id = self.extract_phone_number(from_header) if from_header else "Unknown"
        destination = self.extract_phone_number(to_header) if to_header else "Unknown"
        
        # Determine call type and method
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER']:
            sip_method = parts[0]
            call_type = "INBOUND" if sip_method == "INVITE" else "CONTROL"
        else:
            # This is a response
            sip_method = None
            call_type = "RESPONSE"
        
        # Create call record
        call = CallRecord(
            call_id=call_id,
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=0,  # Will be updated on BYE
            call_type=call_type,
            source_ip=addr[0],
            user_agent=user_agent,
            sip_method=sip_method,
            response_code=int(parts[1]) if parts[0] == 'SIP/2.0' else None
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_header(self, lines: List[str], header_name: str) -> Optional[str]:
        """Extract header value from SIP message"""
        for line in lines:
            if line.startswith(f"{header_name}:"):
                return line.split(":", 1)[1].strip()
        return None
    
    def extract_phone_number(self, header: str) -> str:
        """Extract phone number from SIP header"""
        # Simple regex to extract phone number from SIP URI
        match = re.search(r'sip:([^@]+)@', header)
        if match:
            return match.group(1)
        return "Unknown"
    
    def stop_monitoring(self):
        """Stop SIP monitoring"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("SIP Monitor stopped")

class CallTraceReporter:
    """Generate reports and statistics from call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate summary report for the last N hours"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get call statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Get top suspicious numbers
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Get recent alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0
            },
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in suspicious_numbers
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in alerts
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24):
        """Export call data to JSON file"""
        if not filename:
            filename = f"call_trace_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename

class CallTraceManager:
    """Main manager class for the call trace system"""
    
    def __init__(self):
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.reporter = CallTraceReporter(self.db)
        self.monitor = None
        self.monitor_thread = None
    
    def start_monitoring(self, host: str = "0.0.0.0", port: int = 5060):
        """Start call monitoring"""
        self.monitor = SIPMonitor(host, port)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Call trace monitoring started")
    
    def stop_monitoring(self):
        """Stop call monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
        logger.info("Call trace monitoring stopped")
    
    def add_manual_call(self, caller_id: str, destination: str, duration: int = 0):
        """Manually add a call record for testing"""
        call = CallRecord(
            call_id=hashlib.md5(f"{caller_id}{time.time()}".encode()).hexdigest(),
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=duration,
            call_type="MANUAL"
        )
        
        call = self.analyzer.analyze_call(call)
        self.db.insert_call(call)
        self.analyzer.generate_alert(call)
        
        return call
    
    def get_recent_calls(self, limit: int = 50) -> List[CallRecord]:
        """Get recent call records"""
        return self.db.get_calls(limit)
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report"""
        return self.reporter.generate_summary_report(hours)
    
    def export_report(self, filename: str = None, hours: int = 24) -> str:
        """Export report to file"""
        return self.reporter.export_to_json(filename, hours)

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Call Trap and Trace System")
    parser.add_argument('--monitor', action='store_true', help='Start SIP monitoring')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5060, help='Port to bind to')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours to include in report')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--test', help='Add test call (format: caller_id,destination,duration)')
    
    args = parser.parse_args()
    
    manager = CallTraceManager()
    
    if args.monitor:
        try:
            manager.start_monitoring(args.host, args.port)
            print(f"Monitoring started on {args.host}:{args.port}")
            print("Press Ctrl+C to stop...")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop_monitoring()
            print("\nMonitoring stopped")
    
    elif args.report:
        report = manager.generate_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.export:
        filename = manager.export_report(args.export, args.hours)
        print(f"Report exported to {filename}")
    
    elif args.test:
        parts = args.test.split(',')
        if len(parts) >= 2:
            caller_id = parts[0]
            destination = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 0
            
            call = manager.add_manual_call(caller_id, destination, duration)
            print(f"Test call added: {call.call_id} (Risk: {call.risk_score})")
        else:
            print("Invalid test format. Use: caller_id,destination,duration")
    
    else:
        # Interactive mode
        print("Call Trap and Trace System - Interactive Mode")
        print("Commands: monitor, report, export, test, quit")
        
        while True:
            try:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'monitor':
                    print("Starting monitor... (Press Ctrl+C to stop)")
                    manager.start_monitoring()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("\nMonitoring stopped")
                
                elif cmd == 'report':
                    report = manager.generate_report()
                    print(json.dumps(report, indent=2))
                
                elif cmd == 'export':
                    filename = manager.export_report()
                    print(f"Report exported to {filename}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call added: Risk score {call.risk_score}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Unknown command. Available: monitor, report, export, test, quit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
,  # Repeated digits
            r'^(\d)\1+
    
    def generate_alert(self, call: CallRecord):
        """Generate security alert for high-risk calls"""
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            return
        
        alert_message = f"Suspicious call detected from {call.caller_id} (Risk: {call.risk_score})"
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (call_id, alert_type, message, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            call.call_id,
            "THREAT_DETECTION",
            alert_message,
            severity,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}]: {alert_message}")

class SIPMonitor:
    """Monitor SIP traffic for call events"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.process_sip_message(data.decode('utf-8'), addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, message: str, addr: Tuple[str, int]):
        """Process incoming SIP message and extract call information"""
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract call information
        call_id = self.extract_header(lines, 'Call-ID')
        from_header = self.extract_header(lines, 'From')
        to_header = self.extract_header(lines, 'To')
        user_agent = self.extract_header(lines, 'User-Agent')
        
        if not call_id:
            return
        
        # Extract caller ID from From header
        caller_id = self.extract_phone_number(from_header) if from_header else "Unknown"
        destination = self.extract_phone_number(to_header) if to_header else "Unknown"
        
        # Determine call type and method
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER']:
            sip_method = parts[0]
            call_type = "INBOUND" if sip_method == "INVITE" else "CONTROL"
        else:
            # This is a response
            sip_method = None
            call_type = "RESPONSE"
        
        # Create call record
        call = CallRecord(
            call_id=call_id,
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=0,  # Will be updated on BYE
            call_type=call_type,
            source_ip=addr[0],
            user_agent=user_agent,
            sip_method=sip_method,
            response_code=int(parts[1]) if parts[0] == 'SIP/2.0' else None
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_header(self, lines: List[str], header_name: str) -> Optional[str]:
        """Extract header value from SIP message"""
        for line in lines:
            if line.startswith(f"{header_name}:"):
                return line.split(":", 1)[1].strip()
        return None
    
    def extract_phone_number(self, header: str) -> str:
        """Extract phone number from SIP header"""
        # Simple regex to extract phone number from SIP URI
        match = re.search(r'sip:([^@]+)@', header)
        if match:
            return match.group(1)
        return "Unknown"
    
    def stop_monitoring(self):
        """Stop SIP monitoring"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("SIP Monitor stopped")

class CallTraceReporter:
    """Generate reports and statistics from call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate summary report for the last N hours"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get call statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Get top suspicious numbers
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Get recent alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0
            },
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in suspicious_numbers
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in alerts
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24):
        """Export call data to JSON file"""
        if not filename:
            filename = f"call_trace_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename

class CallTraceManager:
    """Main manager class for the call trace system"""
    
    def __init__(self):
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.reporter = CallTraceReporter(self.db)
        self.monitor = None
        self.monitor_thread = None
    
    def start_monitoring(self, host: str = "0.0.0.0", port: int = 5060):
        """Start call monitoring"""
        self.monitor = SIPMonitor(host, port)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Call trace monitoring started")
    
    def stop_monitoring(self):
        """Stop call monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
        logger.info("Call trace monitoring stopped")
    
    def add_manual_call(self, caller_id: str, destination: str, duration: int = 0):
        """Manually add a call record for testing"""
        call = CallRecord(
            call_id=hashlib.md5(f"{caller_id}{time.time()}".encode()).hexdigest(),
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=duration,
            call_type="MANUAL"
        )
        
        call = self.analyzer.analyze_call(call)
        self.db.insert_call(call)
        self.analyzer.generate_alert(call)
        
        return call
    
    def get_recent_calls(self, limit: int = 50) -> List[CallRecord]:
        """Get recent call records"""
        return self.db.get_calls(limit)
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report"""
        return self.reporter.generate_summary_report(hours)
    
    def export_report(self, filename: str = None, hours: int = 24) -> str:
        """Export report to file"""
        return self.reporter.export_to_json(filename, hours)

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Call Trap and Trace System")
    parser.add_argument('--monitor', action='store_true', help='Start SIP monitoring')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5060, help='Port to bind to')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours to include in report')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--test', help='Add test call (format: caller_id,destination,duration)')
    
    args = parser.parse_args()
    
    manager = CallTraceManager()
    
    if args.monitor:
        try:
            manager.start_monitoring(args.host, args.port)
            print(f"Monitoring started on {args.host}:{args.port}")
            print("Press Ctrl+C to stop...")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop_monitoring()
            print("\nMonitoring stopped")
    
    elif args.report:
        report = manager.generate_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.export:
        filename = manager.export_report(args.export, args.hours)
        print(f"Report exported to {filename}")
    
    elif args.test:
        parts = args.test.split(',')
        if len(parts) >= 2:
            caller_id = parts[0]
            destination = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 0
            
            call = manager.add_manual_call(caller_id, destination, duration)
            print(f"Test call added: {call.call_id} (Risk: {call.risk_score})")
        else:
            print("Invalid test format. Use: caller_id,destination,duration")
    
    else:
        # Interactive mode
        print("Call Trap and Trace System - Interactive Mode")
        print("Commands: monitor, report, export, test, quit")
        
        while True:
            try:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'monitor':
                    print("Starting monitor... (Press Ctrl+C to stop)")
                    manager.start_monitoring()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("\nMonitoring stopped")
                
                elif cmd == 'report':
                    report = manager.generate_report()
                    print(json.dumps(report, indent=2))
                
                elif cmd == 'export':
                    filename = manager.export_report()
                    print(f"Report exported to {filename}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call added: Risk score {call.risk_score}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Unknown command. Available: monitor, report, export, test, quit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
,  # All same digits
        ]
        
        self.high_risk_countries = [
            '+234',  # Nigeria
            '+91',   # India (common for scams)
            '+86',   # China
            '+7',    # Russia
            '+92',   # Pakistan
            '+880',  # Bangladesh
        ]
        
        self.suspicious_user_agents = [
            'scanner', 'exploit', 'hack', 'bot', 'sipvicious',
            'friendly-scanner', 'sipcli', 'sipsak'
        ]
        
        self.legitimate_codecs = [
            'PCMU', 'PCMA', 'G729', 'G722', 'OPUS', 'H264', 'H263'
        ]
        
        self.trusted_networks = [
            '192.168.', '10.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.'
        ]
    
    def analyze_call(self, call: CallRecord) -> CallRecord:
        """Enhanced threat analysis using comprehensive metadata"""
        risk_score = 0
        flags = []
        
        # Basic pattern analysis
        for pattern in self.suspicious_patterns:
            if re.match(pattern, call.caller_id):
                risk_score += 30
                flags.append(f"SUSPICIOUS_PATTERN: {pattern}")
        
        # Geographic risk analysis
        risk_score += self.analyze_geographic_risk(call, flags)
        
        # Call frequency analysis
        risk_score += self.analyze_call_frequency(call, flags)
        
        # SIP protocol analysis
        risk_score += self.analyze_sip_protocol(call, flags)
        
        # Device fingerprinting analysis
        risk_score += self.analyze_device_fingerprint(call, flags)
        
        # Network analysis
        risk_score += self.analyze_network_metadata(call, flags)
        
        # Media analysis
        risk_score += self.analyze_media_metadata(call, flags)
        
        # Authentication analysis
        risk_score += self.analyze_authentication(call, flags)
        
        # Call chain analysis
        risk_score += self.analyze_call_chain(call, flags)
        
        # Timing analysis
        risk_score += self.analyze_timing_patterns(call, flags)
        
        # Header manipulation detection
        risk_score += self.analyze_header_manipulation(call, flags)
        
        call.risk_score = min(risk_score, 100)
        call.flags = flags
        
        return call
    
    def analyze_geographic_risk(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze geographic metadata for risk indicators"""
        risk = 0
        
        # High-risk countries
        for country_code in self.high_risk_countries:
            if call.caller_id.startswith(country_code):
                risk += 25
                flags.append(f"HIGH_RISK_COUNTRY: {country_code}")
        
        # Untrusted source IP
        if call.source_ip and not any(call.source_ip.startswith(net) for net in self.trusted_networks):
            if call.caller_country in ['Unknown', None]:
                risk += 15
                flags.append("UNKNOWN_GEOGRAPHIC_ORIGIN")
        
        # Country mismatch (caller ID vs IP location)
        if call.caller_id and call.caller_country:
            caller_country_code = self.extract_country_from_number(call.caller_id)
            if caller_country_code and caller_country_code != call.caller_country:
                risk += 20
                flags.append("GEOGRAPHIC_MISMATCH")
        
        return risk
    
    def analyze_call_frequency(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze call frequency patterns"""
        risk = 0
        
        # Get recent calls from same source
        recent_calls = self.db.get_calls(limit=20, caller_id=call.caller_id)
        
        if len(recent_calls) > 1:
            # Check for rapid sequential calls
            time_diffs = []
            for i in range(1, min(len(recent_calls), 5)):
                diff = (recent_calls[i-1].timestamp - recent_calls[i].timestamp).total_seconds()
                time_diffs.append(diff)
            
            if time_diffs:
                avg_interval = sum(time_diffs) / len(time_diffs)
                if avg_interval < 60:  # Less than 1 minute between calls
                    risk += 35
                    flags.append("RAPID_SEQUENTIAL_CALLS")
                elif avg_interval < 300:  # Less than 5 minutes
                    risk += 20
                    flags.append("FREQUENT_CALLS")
        
        # Check for distributed attack patterns
        if call.source_ip:
            ip_calls = self.get_calls_by_ip(call.source_ip, hours=1)
            if len(ip_calls) > 10:
                risk += 30
                flags.append("HIGH_VOLUME_FROM_IP")
        
        return risk
    
    def analyze_sip_protocol(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze SIP protocol metadata for anomalies"""
        risk = 0
        
        # Unusual SIP methods
        if call.sip_method and call.sip_method not in ['INVITE', 'BYE', 'CANCEL', 'REGISTER', 'OPTIONS']:
            risk += 20
            flags.append(f"UNUSUAL_SIP_METHOD: {call.sip_method}")
        
        # Response code analysis
        if call.response_code:
            if call.response_code in [401, 403, 407]:
                risk += 25
                flags.append("AUTH_FAILURE")
            elif call.response_code >= 500:
                risk += 15
                flags.append("SERVER_ERROR")
        
        # Via header analysis
        if call.via_headers:
            for via in call.via_headers:
                if 'rport' not in via:
                    risk += 10
                    flags.append("MISSING_RPORT")
                if len(call.via_headers) > 5:
                    risk += 15
                    flags.append("EXCESSIVE_VIA_HEADERS")
        
        # CSeq analysis
        if call.cseq:
            try:
                seq_num = int(call.cseq.split()[0])
                if seq_num == 1 and call.sip_method != 'INVITE':
                    risk += 10
                    flags.append("SUSPICIOUS_CSEQ")
            except (ValueError, IndexError):
                risk += 5
                flags.append("MALFORMED_CSEQ")
        
        # Max-Forwards analysis
        if call.max_forwards is not None:
            if call.max_forwards > 70:
                risk += 10
                flags.append("HIGH_MAX_FORWARDS")
            elif call.max_forwards < 10:
                risk += 15
                flags.append("LOW_MAX_FORWARDS")
        
        return risk
    
    def analyze_device_fingerprint(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze device fingerprinting data"""
        risk = 0
        
        # Suspicious User-Agent patterns
        if call.user_agent:
            ua_lower = call.user_agent.lower()
            for suspicious in self.suspicious_user_agents:
                if suspicious in ua_lower:
                    risk += 40
                    flags.append(f"SUSPICIOUS_USER_AGENT: {suspicious}")
        
        # Device type inconsistencies
        if call.device_type == 'Unknown' and call.user_agent:
            risk += 10
            flags.append("UNKNOWN_DEVICE_TYPE")
        
        # SIP stack analysis
        if call.sip_stack in ['Unknown', None] and call.user_agent:
            risk += 5
            flags.append("UNKNOWN_SIP_STACK")
        
        return risk
    
    def analyze_network_metadata(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze network-level metadata"""
        risk = 0
        
        # Packet size analysis
        if call.packet_size:
            if call.packet_size > 4000:
                risk += 10
                flags.append("LARGE_PACKET_SIZE")
            elif call.packet_size < 100:
                risk += 15
                flags.append("UNUSUALLY_SMALL_PACKET")
        
        # Fragmentation detection
        if call.fragmented:
            risk += 20
            flags.append("FRAGMENTED_PACKET")
        
        # Protocol inconsistencies
        if call.protocol == 'TCP' and call.destination_port != 5060:
            risk += 10
            flags.append("NON_STANDARD_TCP_PORT")
        
        # Port scanning detection
        if call.source_port and call.source_port < 1024:
            risk += 15
            flags.append("PRIVILEGED_SOURCE_PORT")
        
        return risk
    
    def analyze_media_metadata(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze media and codec metadata"""
        risk = 0
        
        # Unusual codec combinations
        if call.audio_codecs:
            for codec in call.audio_codecs:
                if codec not in self.legitimate_codecs:
                    risk += 15
                    flags.append(f"UNUSUAL_AUDIO_CODEC: {codec}")
        
        # Media IP analysis
        if call.media_ip and call.source_ip:
            if call.media_ip != call.source_ip:
                risk += 10
                flags.append("MEDIA_IP_MISMATCH")
        
        # Excessive media ports
        if call.media_ports and len(call.media_ports) > 4:
            risk += 10
            flags.append("EXCESSIVE_MEDIA_PORTS")
        
        return risk
    
    def analyze_authentication(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze authentication metadata"""
        risk = 0
        
        # Missing authentication for REGISTER
        if call.sip_method == 'REGISTER' and not call.authorization:
            risk += 25
            flags.append("UNAUTHENTICATED_REGISTER")
        
        # Weak authentication realms
        if call.realm:
            if call.realm in ['*', 'asterisk', 'test', 'default']:
                risk += 20
                flags.append("WEAK_AUTH_REALM")
        
        # Nonce analysis
        if call.nonce and len(call.nonce) < 16:
            risk += 10
            flags.append("WEAK_NONCE")
        
        return risk
    
    def analyze_call_chain(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze call chain and routing metadata"""
        risk = 0
        
        # Excessive diversions
        if call.diversion_headers and len(call.diversion_headers) > 3:
            risk += 20
            flags.append("EXCESSIVE_DIVERSIONS")
        
        # Suspicious call replacements
        if call.replaces:
            risk += 15
            flags.append("CALL_REPLACEMENT_DETECTED")
        
        return risk
    
    def analyze_timing_patterns(self, call: CallRecord, flags: List[str]) -> int:
        """Analyze call timing patterns"""
        risk = 0
        
        # Very short calls
        if call.duration and call.duration < 3:
            risk += 15
            flags.append("VERY_SHORT_CALL")
        
        # Unusual setup times
        if call.setup_time and call.setup_time > 30:
            risk += 10
            flags.append("SLOW_SETUP_TIME")
        
        return risk
    
    def analyze_header_manipulation(self, call: CallRecord, flags: List[str]) -> int:
        """Detect header manipulation attempts"""
        risk = 0
        
        # Custom headers analysis
        if call.custom_headers:
            for header, value in call.custom_headers.items():
                if 'exploit' in value.lower() or 'hack' in value.lower():
                    risk += 30
                    flags.append(f"MALICIOUS_CUSTOM_HEADER: {header}")
        
        return risk
    
    def extract_country_from_number(self, phone_number: str) -> Optional[str]:
        """Extract country from phone number (simplified)"""
        # Simplified country code extraction
        country_codes = {
            '+1': 'US',
            '+44': 'GB',
            '+33': 'FR',
            '+49': 'DE',
            '+86': 'CN',
            '+91': 'IN',
            '+7': 'RU',
            '+234': 'NG'
        }
        
        for code, country in country_codes.items():
            if phone_number.startswith(code):
                return country
        
        return None
    
    def get_calls_by_ip(self, ip_address: str, hours: int = 1) -> List[CallRecord]:
        """Get calls from specific IP within time window"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        cursor.execute('''
            SELECT call_id FROM calls 
            WHERE source_ip = ? AND timestamp > ?
        ''', (ip_address, threshold.isoformat()))
        
        call_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return call_ids
    
    def generate_alert(self, call: CallRecord):
        """Generate security alert for high-risk calls"""
        if call.risk_score >= 70:
            severity = "HIGH"
        elif call.risk_score >= 40:
            severity = "MEDIUM"
        else:
            return
        
        alert_message = f"Suspicious call detected from {call.caller_id} (Risk: {call.risk_score})"
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (call_id, alert_type, message, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            call.call_id,
            "THREAT_DETECTION",
            alert_message,
            severity,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}]: {alert_message}")

class SIPMonitor:
    """Monitor SIP traffic for call events"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
    
    def start_monitoring(self):
        """Start monitoring SIP traffic"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"SIP Monitor started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.process_sip_message(data.decode('utf-8'), addr)
            except Exception as e:
                logger.error(f"Error processing SIP message: {e}")
    
    def process_sip_message(self, message: str, addr: Tuple[str, int]):
        """Process incoming SIP message and extract call information"""
        lines = message.split('\r\n')
        if not lines:
            return
        
        # Parse SIP request/response line
        request_line = lines[0]
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            return
        
        # Extract call information
        call_id = self.extract_header(lines, 'Call-ID')
        from_header = self.extract_header(lines, 'From')
        to_header = self.extract_header(lines, 'To')
        user_agent = self.extract_header(lines, 'User-Agent')
        
        if not call_id:
            return
        
        # Extract caller ID from From header
        caller_id = self.extract_phone_number(from_header) if from_header else "Unknown"
        destination = self.extract_phone_number(to_header) if to_header else "Unknown"
        
        # Determine call type and method
        if parts[0] in ['INVITE', 'BYE', 'CANCEL', 'REGISTER']:
            sip_method = parts[0]
            call_type = "INBOUND" if sip_method == "INVITE" else "CONTROL"
        else:
            # This is a response
            sip_method = None
            call_type = "RESPONSE"
        
        # Create call record
        call = CallRecord(
            call_id=call_id,
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=0,  # Will be updated on BYE
            call_type=call_type,
            source_ip=addr[0],
            user_agent=user_agent,
            sip_method=sip_method,
            response_code=int(parts[1]) if parts[0] == 'SIP/2.0' else None
        )
        
        # Analyze for threats
        call = self.analyzer.analyze_call(call)
        
        # Store in database
        self.db.insert_call(call)
        
        # Generate alerts if necessary
        self.analyzer.generate_alert(call)
    
    def extract_header(self, lines: List[str], header_name: str) -> Optional[str]:
        """Extract header value from SIP message"""
        for line in lines:
            if line.startswith(f"{header_name}:"):
                return line.split(":", 1)[1].strip()
        return None
    
    def extract_phone_number(self, header: str) -> str:
        """Extract phone number from SIP header"""
        # Simple regex to extract phone number from SIP URI
        match = re.search(r'sip:([^@]+)@', header)
        if match:
            return match.group(1)
        return "Unknown"
    
    def stop_monitoring(self):
        """Stop SIP monitoring"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("SIP Monitor stopped")

class CallTraceReporter:
    """Generate reports and statistics from call data"""
    
    def __init__(self, db: CallDatabase):
        self.db = db
    
    def generate_summary_report(self, hours: int = 24) -> Dict:
        """Generate summary report for the last N hours"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        # Get call statistics
        cursor.execute('''
            SELECT COUNT(*) as total_calls,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_calls
            FROM calls 
            WHERE timestamp > ?
        ''', (threshold.isoformat(),))
        
        stats = cursor.fetchone()
        
        # Get top suspicious numbers
        cursor.execute('''
            SELECT caller_id, COUNT(*) as call_count, AVG(risk_score) as avg_risk
            FROM calls 
            WHERE timestamp > ? AND risk_score > 30
            GROUP BY caller_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''', (threshold.isoformat(),))
        
        suspicious_numbers = cursor.fetchall()
        
        # Get recent alerts
        cursor.execute('''
            SELECT alert_type, message, severity, timestamp
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (threshold.isoformat(),))
        
        alerts = cursor.fetchall()
        
        conn.close()
        
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'time_period_hours': hours,
            'statistics': {
                'total_calls': stats[0] or 0,
                'average_risk_score': round(stats[1] or 0, 2),
                'maximum_risk_score': stats[2] or 0,
                'high_risk_calls': stats[3] or 0
            },
            'suspicious_numbers': [
                {
                    'caller_id': row[0],
                    'call_count': row[1],
                    'average_risk': round(row[2], 2)
                }
                for row in suspicious_numbers
            ],
            'recent_alerts': [
                {
                    'type': row[0],
                    'message': row[1],
                    'severity': row[2],
                    'timestamp': row[3]
                }
                for row in alerts
            ]
        }
    
    def export_to_json(self, filename: str = None, hours: int = 24):
        """Export call data to JSON file"""
        if not filename:
            filename = f"call_trace_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_summary_report(hours)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename

class CallTraceManager:
    """Main manager class for the call trace system"""
    
    def __init__(self):
        self.db = CallDatabase()
        self.analyzer = ThreatAnalyzer(self.db)
        self.reporter = CallTraceReporter(self.db)
        self.monitor = None
        self.monitor_thread = None
    
    def start_monitoring(self, host: str = "0.0.0.0", port: int = 5060):
        """Start call monitoring"""
        self.monitor = SIPMonitor(host, port)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Call trace monitoring started")
    
    def stop_monitoring(self):
        """Stop call monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
        logger.info("Call trace monitoring stopped")
    
    def add_manual_call(self, caller_id: str, destination: str, duration: int = 0):
        """Manually add a call record for testing"""
        call = CallRecord(
            call_id=hashlib.md5(f"{caller_id}{time.time()}".encode()).hexdigest(),
            timestamp=datetime.datetime.now(),
            caller_id=caller_id,
            destination=destination,
            duration=duration,
            call_type="MANUAL"
        )
        
        call = self.analyzer.analyze_call(call)
        self.db.insert_call(call)
        self.analyzer.generate_alert(call)
        
        return call
    
    def get_recent_calls(self, limit: int = 50) -> List[CallRecord]:
        """Get recent call records"""
        return self.db.get_calls(limit)
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive report"""
        return self.reporter.generate_summary_report(hours)
    
    def export_report(self, filename: str = None, hours: int = 24) -> str:
        """Export report to file"""
        return self.reporter.export_to_json(filename, hours)

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Call Trap and Trace System")
    parser.add_argument('--monitor', action='store_true', help='Start SIP monitoring')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5060, help='Port to bind to')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours to include in report')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--test', help='Add test call (format: caller_id,destination,duration)')
    
    args = parser.parse_args()
    
    manager = CallTraceManager()
    
    if args.monitor:
        try:
            manager.start_monitoring(args.host, args.port)
            print(f"Monitoring started on {args.host}:{args.port}")
            print("Press Ctrl+C to stop...")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop_monitoring()
            print("\nMonitoring stopped")
    
    elif args.report:
        report = manager.generate_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.export:
        filename = manager.export_report(args.export, args.hours)
        print(f"Report exported to {filename}")
    
    elif args.test:
        parts = args.test.split(',')
        if len(parts) >= 2:
            caller_id = parts[0]
            destination = parts[1]
            duration = int(parts[2]) if len(parts) > 2 else 0
            
            call = manager.add_manual_call(caller_id, destination, duration)
            print(f"Test call added: {call.call_id} (Risk: {call.risk_score})")
        else:
            print("Invalid test format. Use: caller_id,destination,duration")
    
    else:
        # Interactive mode
        print("Call Trap and Trace System - Interactive Mode")
        print("Commands: monitor, report, export, test, quit")
        
        while True:
            try:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'monitor':
                    print("Starting monitor... (Press Ctrl+C to stop)")
                    manager.start_monitoring()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        manager.stop_monitoring()
                        print("\nMonitoring stopped")
                
                elif cmd == 'report':
                    report = manager.generate_report()
                    print(json.dumps(report, indent=2))
                
                elif cmd == 'export':
                    filename = manager.export_report()
                    print(f"Report exported to {filename}")
                
                elif cmd.startswith('test'):
                    parts = cmd.split(' ', 1)
                    if len(parts) > 1:
                        test_data = parts[1].split(',')
                        if len(test_data) >= 2:
                            call = manager.add_manual_call(test_data[0], test_data[1])
                            print(f"Test call added: Risk score {call.risk_score}")
                        else:
                            print("Usage: test caller_id,destination")
                    else:
                        print("Usage: test caller_id,destination")
                
                else:
                    print("Unknown command. Available: monitor, report, export, test, quit")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
