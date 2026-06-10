# detection/syn_scan_detector.py

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

class SYNScanDetector:
    def __init__(self, config, logger, prevention_controller):
        self.threshold_ports = config.get('detection.syn_scan.threshold_ports', 50)
        self.time_window = config.get('detection.syn_scan.time_window', 60)
        self.logger = logger
        self.prevention_controller = prevention_controller
        
        self.src_ip_data = defaultdict(lambda: {
            'ports': set(),
            'timestamps': deque(),
            'alert_count': 0
        })
        
        self.blocked_ips = {}
    
    def analyze_packet(self, packet_info):
        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        timestamp = packet_info['timestamp']
        
        ip_data = self.src_ip_data[src_ip]
        
        # Clean old timestamps
        cutoff_time = timestamp - timedelta(seconds=self.time_window)
        while ip_data['timestamps'] and ip_data['timestamps'][0] < cutoff_time:
            ip_data['timestamps'].popleft()
        
        # Add current packet
        ip_data['ports'].add(dst_port)
        ip_data['timestamps'].append(timestamp)
        
        # Generate monitoring alert for new IPs
        if len(ip_data['timestamps']) == 1:
            self.logger.log_alert(
                attack_type="MONITORING",
                src_ip=src_ip,
                details=f"Started monitoring {src_ip} for port scan activity",
                severity="LOW"
            )
        
        # Check for port scan
        if len(ip_data['ports']) >= self.threshold_ports:
            if self._is_new_attack(src_ip):
                self._handle_port_scan(src_ip, ip_data)
    
    def _is_new_attack(self, src_ip):
        last_block = self.blocked_ips.get(src_ip, 0)
        return time.time() - last_block > 300  # 5 minutes cooldown
    
    def _handle_port_scan(self, src_ip, ip_data):
        self.logger.log_alert(
            attack_type="SYN_PORT_SCAN",
            src_ip=src_ip,
            details=f"Port scan detected to {len(ip_data['ports'])} different ports",
            severity="HIGH"
        )
        
        # Block the IP
        self.prevention_controller.block_ip(src_ip, duration=300)
        self.blocked_ips[src_ip] = time.time()
        ip_data['alert_count'] += 1
        
        # Clean up old data
        self._cleanup_old_data()
    
    def _cleanup_old_data(self):
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window * 2)
        
        to_remove = []
        for src_ip, data in self.src_ip_data.items():
            if not data['timestamps'] or data['timestamps'][0] < cutoff_time:
                to_remove.append(src_ip)
        
        for src_ip in to_remove:
            del self.src_ip_data[src_ip]
    
    def get_statistics(self):
        return {
            'monitored_ips': len(self.src_ip_data),
            'blocked_ips': len(self.blocked_ips),
            'recent_detections': sum(1 for data in self.src_ip_data.values() if data['alert_count'] > 0)
        }