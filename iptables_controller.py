import subprocess
import time
import os
from datetime import datetime


class IPTablesController:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.simulation_mode = config.get("iptables.simulation", True)

        self.active_rules = {}

        mode = "SIMULATION" if self.simulation_mode else "LIVE"
        self.logger.log_info(f"IPTablesController initialized in {mode} mode")

    # ------------------------------------
    # BLOCK IP
    # ------------------------------------
    def block_ip(self, ip, duration=300):
        if ip in self.active_rules:
            return

        self.active_rules[ip] = {
            "blocked_at": time.time(),
            "duration": duration
        }

        if self.simulation_mode:
            self.logger.log_info(f"[SIMULATION] Blocking IP {ip} for {duration}s")
        else:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=False
            )
            self.logger.log_info(f"Blocked IP {ip}")

    # ------------------------------------
    # REMOVE RULE
    # ------------------------------------
    def _remove_rule(self, ip):
        if ip not in self.active_rules:
            return

        if self.simulation_mode:
            self.logger.log_info(f"[SIMULATION] Removing block for IP {ip}")
        else:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=False
            )

        del self.active_rules[ip]

    # ------------------------------------
    # GLOBAL RATE LIMIT (SIMULATED)
    # ------------------------------------
    def apply_global_rate_limit(self):
        self.logger.log_alert(
            attack_type="GLOBAL_RATE_LIMIT",
            src_ip="ALL",
            details="Applying global SYN rate limiting",
            severity="CRITICAL"
        )

        if self.simulation_mode:
            self.logger.log_info("[SIMULATION] Global rate limiting applied")

    # ------------------------------------
    # GET ACTIVE RULES
    # ------------------------------------
    def get_active_rules(self):
        return self.active_rules

    # ------------------------------------
    # SAVE IPTABLES SNAPSHOT  ✅ REQUIRED
    # ------------------------------------
    def save_rules_snapshot(self):
        try:
            os.makedirs("logs", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot = f"logs/iptables_snapshot_{timestamp}.txt"

            if self.simulation_mode:
                with open(snapshot, "w") as f:
                    f.write("# SIMULATION MODE\n")
                    f.write("# Active simulated iptables rules\n\n")
                    for ip, rule in self.active_rules.items():
                        f.write(f"{ip} -> {rule}\n")

                self.logger.log_info(
                    f"[SIMULATION] iptables snapshot saved to {snapshot}"
                )
            else:
                with open(snapshot, "w") as f:
                    subprocess.run(["iptables-save"], stdout=f, check=True)

                self.logger.log_info(
                    f"iptables snapshot saved to {snapshot}"
                )

            return snapshot

        except Exception as e:
            self.logger.log_error(f"Failed to save iptables snapshot: {e}")
            return None


