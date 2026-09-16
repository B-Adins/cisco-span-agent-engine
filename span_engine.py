"""
span_engine.py
Passive Cisco SPAN traffic analysis engine with agentic webhook escalation.
Captures mirrored port traffic, evaluates sliding-window anomalies, and 
dispatches structured event payloads to AI orchestration endpoints.
"""

import os
import json
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, Tuple
import requests
from scapy.all import sniff, IP, TCP, UDP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("SpanEngine")

# --- Configuration ---
INTERFACE = os.getenv("SPAN_INTERFACE", "eth1")
AI_AGENT_WEBHOOK = os.getenv("AI_AGENT_WEBHOOK_URL", "http://localhost:8000/webhook/network-event")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Detection Thresholds (Packets per rolling window)
WINDOW_SECONDS = 10
SYN_FLOOD_THRESHOLD = 150
PORT_SCAN_THRESHOLD = 30


@dataclass
class AnomalyEvent:
    timestamp: float
    source_ip: str
    target_ip: str
    event_type: str
    observed_rate: int
    threshold: int
    protocol: str
    metadata: dict


class TrafficTracker:
    """Maintains short-term state to detect anomalous spikes and scans."""
    def __init__(self, window_size: int = WINDOW_SECONDS):
        self.window_size = window_size
        self.syn_counts: Dict[str, list] = defaultdict(list)
        self.port_scan_tracker: Dict[Tuple[str, str], set] = defaultdict(set)
        self.last_purge = time.time()

    def prune(self, current_time: float):
        """Purges records outside the rolling time window."""
        if current_time - self.last_purge < 5.0:
            return
        cutoff = current_time - self.window_size
        for src in list(self.syn_counts.keys()):
            self.syn_counts[src] = [t for t in self.syn_counts[src] if t > cutoff]
            if not self.syn_counts[src]:
                del self.syn_counts[src]
        self.last_purge = current_time

    def record_syn(self, src_ip: str, current_time: float) -> int:
        self.syn_counts[src_ip].append(current_time)
        return len(self.syn_counts[src_ip])

    def record_port(self, src_ip: str, dst_ip: str, dst_port: int) -> int:
        key = (src_ip, dst_ip)
        self.port_scan_tracker[key].add(dst_port)
        return len(self.port_scan_tracker[key])


class AlertDispatcher:
    """Dispatches alerts to autonomous AI agents and secondary channels."""
    def __init__(self, webhook_url: str, tg_token: str = "", tg_chat_id: str = ""):
        self.webhook_url = webhook_url
        self.tg_token = tg_token
        self.tg_chat_id = tg_chat_id

    def dispatch(self, event: AnomalyEvent):
        payload = asdict(event)
        
        # 1. Primary: AI Agent Webhook
        try:
            res = requests.post(self.webhook_url, json=payload, timeout=3.0)
            logger.info("Dispatched event %s to AI Agent (Status: %s)", event.event_type, res.status_code)
        except requests.exceptions.RequestException as e:
            logger.error("Failed to forward alert to AI Agent webhook: %s", e)

        # 2. Secondary: Telegram Notification Fallback
        if self.tg_token and self.tg_chat_id:
            self._send_telegram(event)

    def _send_telegram(self, event: AnomalyEvent):
        text = (
            f"🚨 *Network Anomaly Detected*\n"
            f"*Type:* {event.event_type}\n"
            f"*Source:* `{event.source_ip}` -> *Target:* `{event.target_ip}`\n"
            f"*Rate:* {event.observed_rate} (Threshold: {event.threshold})\n"
            f"*Protocol:* {event.protocol}"
        )
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        try:
            requests.post(url, json={"chat_id": self.tg_chat_id, "text": text, "parse_mode": "Markdown"}, timeout=3.0)
        except requests.exceptions.RequestException as e:
            logger.error("Failed sending Telegram escalation: %s", e)


tracker = TrafficTracker()
dispatcher = AlertDispatcher(AI_AGENT_WEBHOOK, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)


def packet_callback(pkt):
    """Processes incoming mirrored packets off the SPAN interface."""
    now = time.time()
    tracker.prune(now)

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # Evaluate TCP Flags for SYN Flood / Half-Open scans
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        dst_port = pkt[TCP].dport

        # Check SYN packets (Flag 'S') without ACK
        if flags == "S":
            syn_rate = tracker.record_syn(src_ip, now)
            if syn_rate > SYN_FLOOD_THRESHOLD:
                event = AnomalyEvent(
                    timestamp=now,
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    event_type="SYN_FLOOD_SUSPECTED",
                    observed_rate=syn_rate,
                    threshold=SYN_FLOOD_THRESHOLD,
                    protocol="TCP",
                    metadata={"target_port": dst_port}
                )
                dispatcher.dispatch(event)

            port_count = tracker.record_port(src_ip, dst_ip, dst_port)
            if port_count > PORT_SCAN_THRESHOLD:
                event = AnomalyEvent(
                    timestamp=now,
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    event_type="HORIZONTAL_PORT_SCAN",
                    observed_rate=port_count,
                    threshold=PORT_SCAN_THRESHOLD,
                    protocol="TCP",
                    metadata={"unique_ports_contacted": port_count}
                )
                dispatcher.dispatch(event)


def main():
    logger.info("Initializing SPAN Packet Inspection on interface: %s", INTERFACE)
    logger.info("Target Webhook: %s", AI_AGENT_WEBHOOK)
    
    # Run passive packet capture (Requires root/promiscuous access on interface)
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False)
    except PermissionError:
        logger.fatal("Insufficient privileges. Raw socket sniffing requires CAP_NET_RAW or root privileges.")
    except Exception as e:
        logger.fatal("Engine terminated unexpectedly: %s", e)


if __name__ == "__main__":
    main()
