#!/usr/bin/env python3

import os
import sys
import signal
import threading
import time

from core.config import Config
from core.packet_capture import PacketCapture
from detection.syn_scan_detector import SYNScanDetector
from detection.syn_flood_detector import SYNFloodDetector
from prevention.iptables_controller import IPTablesController
from sipf_logging.logger import SIPFLogger
from dashboard.app import Dashboard


class SIPF:
    def __init__(self):
        self.config = Config()
        self.logger = SIPFLogger(self.config)
        self.running = False

        # Prevention
        self.prevention_controller = IPTablesController(
            self.config,
            self.logger
        )

        # Packet capture
        self.packet_capture = PacketCapture(
            self.config.get('network.interface'),
            self,
            self.logger
        )

        # Detection engines
        self.detection_engine = {
            'syn_scan': SYNScanDetector(
                self.config,
                self.logger,
                self.prevention_controller
            ),
            'syn_flood': SYNFloodDetector(
                self.config,
                self.logger,
                self.prevention_controller
            )
        }

        # Dashboard
        self.dashboard = Dashboard(
            self.config,
            self.detection_engine,
            self.prevention_controller,
            self.logger,
            self.packet_capture
        )

        # Signals
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    # ------------------------------------
    # PACKET ROUTING
    # ------------------------------------
    def analyze_packet(self, packet_info):
        self.detection_engine['syn_scan'].analyze_packet(packet_info)
        self.detection_engine['syn_flood'].analyze_packet(packet_info)

    # ------------------------------------
    # START SYSTEM
    # ------------------------------------
    def start(self):
        self.logger.log_info("Starting SIPF...")

        if os.geteuid() != 0:
            self.logger.log_error(
                "SIPF must be run as root for packet capture"
            )
            sys.exit(1)

        # Snapshot firewall state (simulation-safe)
        self.prevention_controller.save_rules_snapshot()

        # Start packet capture
        self.packet_capture.start_capture()

        # Start dashboard
        dashboard_thread = threading.Thread(
            target=self.dashboard.run,
            daemon=True
        )
        dashboard_thread.start()

        self.running = True
        self.logger.log_info("SIPF started successfully")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    # ------------------------------------
    # STOP SYSTEM
    # ------------------------------------
    def stop(self):
        self.logger.log_info("Stopping SIPF...")
        self.running = False

        self.packet_capture.stop_capture()

        # Remove active rules (simulation-safe)
        active_rules = self.prevention_controller.get_active_rules()
        for ip in list(active_rules.keys()):
            self.prevention_controller._remove_rule(ip)

        # Final snapshot
        self.prevention_controller.save_rules_snapshot()

        self.logger.log_info("SIPF stopped")
        sys.exit(0)

    def _signal_handler(self, signum, frame):
        self.logger.log_info(f"Received signal {signum}")
        self.stop()


def main():
    sipf = SIPF()
    sipf.start()


if __name__ == '__main__':
    main()



