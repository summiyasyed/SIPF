# detection/syn_flood_detector.py

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

class SYNFloodDetector:
    def __init__(self, config, logger, prevention_controller):
        self.threshold_rate = config.get('detection.syn_flood.threshold_rate', 50)
        self.time_window = config.get('detection.syn_flood.time_window', 5)
        self.logger = logger
        self.prevention_controller = prevention_controller
        
        self.src_ip_data = defaultdict(lambda: {
            'syn_count': 0,
            'timestamps': deque(),
            'alert_count': 0
        })
        
        self.global_syn_count = 0
        self.global_timestamps = deque()
        self.blocked_ips = {}
        
        # Debug counters
        self.total_packets_processed = 0
        self.debug_counter = 0
        self.last_debug_time = time.time()
        
        # Force immediate detection for testing
        self.test_mode = True
        # In the __init__ method, change this line:
        self.packets_until_block = 10
        # TO THIS:
        self.packets_until_block = 1000 # Or a higher number
                

        # Track rate calculation
        self.last_rate_calculation = time.time()
        self.previous_global_count = 0
        self.current_rate = 0
    
    def analyze_packet(self, packet_info):
        self.total_packets_processed += 1
        src_ip = packet_info['src_ip']
        timestamp = packet_info['timestamp']
        
        # Debug: Log every packet in test mode
        if self.test_mode:
            self.logger.log_info(f"PACKET: #{self.total_packets_processed} from {src_ip} to {packet_info['dst_ip']}:{packet_info['dst_port']}")
        
        # Update source IP data
        ip_data = self.src_ip_data[src_ip]
        
        # Clean old timestamps for this IP
        cutoff_time = timestamp - timedelta(seconds=self.time_window)
        while ip_data['timestamps'] and ip_data['timestamps'][0] < cutoff_time:
            ip_data['timestamps'].popleft()
            ip_data['syn_count'] -= 1
        
        # Add current packet
        ip_data['timestamps'].append(timestamp)
        ip_data['syn_count'] += 1
        
        # Update global counters
        while self.global_timestamps and self.global_timestamps[0] < cutoff_time:
            self.global_timestamps.popleft()
            self.global_syn_count -= 1
        
        self.global_timestamps.append(timestamp)
        self.global_syn_count += 1
        
        # Calculate rate every second
        current_time = time.time()
        if current_time - self.last_rate_calculation >= 1.0:
            time_diff = current_time - self.last_rate_calculation
            count_diff = self.global_syn_count - self.previous_global_count
            self.current_rate = count_diff / time_diff if time_diff > 0 else 0
            self.previous_global_count = self.global_syn_count
            self.last_rate_calculation = current_time
        
        # Generate monitoring alert for new IPs
        if ip_data['syn_count'] == 1:
            self.logger.log_alert(
                attack_type="MONITORING",
                src_ip=src_ip,
                details=f"Started monitoring {src_ip} for SYN activity",
                severity="LOW"
            )
        
        # Debug: Log current state
        if current_time - self.last_debug_time > 2:  # Log every 2 seconds
            self.logger.log_info(f"DEBUG: {src_ip} has {ip_data['syn_count']} SYN packets in {self.time_window}s")
            self.logger.log_info(f"DEBUG: Global SYN rate: {self.current_rate:.2f} pps")
            self.logger.log_info(f"DEBUG: Threshold is {self.threshold_rate}")
            self.last_debug_time = current_time
        
        # Test mode: Block after a few packets
        if self.test_mode and ip_data['syn_count'] >= self.packets_until_block:
            self.logger.log_info(f"TEST MODE: Triggering block for {src_ip} after {ip_data['syn_count']} packets")
            self._handle_syn_flood(src_ip, ip_data)
            return
        
        # Normal detection
        if ip_data['syn_count'] >= self.threshold_rate:
            self.logger.log_info(f"THRESHOLD EXCEEDED: {src_ip} has {ip_data['syn_count']} SYN packets (threshold: {self.threshold_rate})")
            if self._is_new_attack(src_ip):
                self._handle_syn_flood(src_ip, ip_data)
        
        # Check for global SYN flood
        if self.current_rate >= self.threshold_rate * 5:
            self._handle_global_syn_flood()
    
    def _is_new_attack(self, src_ip):
        last_block = self.blocked_ips.get(src_ip, 0)
        return time.time() - last_block > 300  # 5 minutes cooldown
    
    def _handle_syn_flood(self, src_ip, ip_data):
        self.logger.log_alert(
            attack_type="SYN_FLOOD",
            src_ip=src_ip,
            details=f"SYN flood detected: {ip_data['syn_count']} SYN packets in {self.time_window}s (rate: {self.current_rate:.2f} pps)",
            severity="CRITICAL"
        )
        
        # Block the IP
        self.prevention_controller.block_ip(src_ip, duration=600)
        self.blocked_ips[src_ip] = time.time()
        ip_data['alert_count'] += 1
        
        self._cleanup_old_data()
    
    def _handle_global_syn_flood(self):
        self.logger.log_alert(
            attack_type="GLOBAL_SYN_FLOOD",
            src_ip="MULTIPLE",
            details=f"Global SYN flood: {self.global_syn_count} SYN packets detected (rate: {self.current_rate:.2f} pps)",
            severity="CRITICAL"
        )
        
        # Apply rate limiting globally
        self.prevention_controller.apply_global_rate_limit()
    
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
            'global_syn_rate': round(self.current_rate, 2),  # Return the actual rate in packets per second
            'recent_detections': sum(1 for data in self.src_ip_data.values() if data['alert_count'] > 0),
            'total_packets_processed': self.total_packets_processed
        }