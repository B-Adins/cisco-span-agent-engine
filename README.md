# Cisco SPAN Anomaly Detection & AI Dispatch Engine

A high-throughput, passive packet analysis service that captures mirrored traffic from a Cisco SPAN (Switched Port Analyzer) interface, detects layer-3 and layer-4 anomalous signatures in real time, and dispatches structured JSON payloads to autonomous AI agents (LangGraph / OpenClaw harnesses) or SOC escalation channels.

---

## Architectural Overview

```text
 [Enterprise Core Switch]
            │
 (Cisco SPAN / Mirrored Port)
            ▼
┌─────────────────────────────────────────┐
│     span-engine (Passive Collector)     │
│  - Promiscuous packet listener (Scapy)  │
│  - Sliding-window traffic tracking      │
│  - Heuristic anomaly identification     │
└───────────────────┬─────────────────────┘
                    │ Structured JSON Payload
                    ▼
┌─────────────────────────────────────────┐
│    Autonomous AI Agent / Orchestrator   │
│       (LangGraph / OpenClaw)            │
│  - Anomaly validation & triage          │
│  - Dynamic ACL remediation              │
│  - Escalation via Telegram notifications│
└─────────────────────────────────────────┘
```

---

## Key Features

* **Passive Network Observability:** Operates out-of-band via a mirrored switch port without introducing inline latency or packet degradation into production traffic.
* **Low-Overhead Sliding Window Analytics:** Employs in-memory timestamp buckets to track SYN bursts, rapid port enumeration, and volumetric anomalies.
* **Agentic Orchestration Ready:** Emits standardized event payloads directly to webhook endpoints consumed by autonomous remediation agents.
* **Dual-Channel Alerting:** Supports real-time webhook propagation with automatic fallback alerts to Telegram groups for human-in-the-loop oversight.

---

## Repository Structure

```text
├── span_engine.py         # Core packet capture loop and anomaly evaluator
├── requirements.txt       # Dependencies
├── Dockerfile             # Container definition with host network capabilities
├── .env.example           # Configuration template
└── README.md
```

---

## Prerequisites

* Linux host (Ubuntu 22.04 LTS or Pop!_OS recommended) with a dedicated network interface configured in promiscuous mode.
* Upstream Cisco Catalyst switch configured to mirror traffic:
  ```ios
  monitor session 1 source interface GigabitEthernet1/0/1 - 24 both
  monitor session 1 destination interface GigabitEthernet1/0/48
  ```
* Python 3.10+
* Root or `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities for socket binding.

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/cisco-span-agent-engine.git
   cd cisco-span-agent-engine
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables:**
   Copy the template and update interface details:
   ```bash
   cp .env.example .env
   ```

   ```env
   SPAN_INTERFACE=eth1
   AI_AGENT_WEBHOOK_URL=http://localhost:8000/webhook/network-event
   TELEGRAM_BOT_TOKEN=your_bot_token_here
   TELEGRAM_CHAT_ID=your_chat_id_here
   ```

---

## Running the Engine

### Local Execution (Native Linux)
Because the engine binds to raw network sockets for passive capture, run with elevated privileges or grant capability flags:

```bash
# Option A: Run directly with sudo
sudo -E env "PATH=$PATH" python span_engine.py

# Option B: Grant CAP_NET_RAW to your Python binary (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python span_engine.py
```

### Docker Deployment
```bash
docker build -t span-engine .
docker run -d \
  --name span-engine \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --env-file .env \
  span-engine
```

---

## Webhook Payload Specification

When an anomaly triggers, the engine pushes a `POST` request to `AI_AGENT_WEBHOOK_URL` formatted as follows:

```json
{
  "timestamp": 1773678000.421,
  "source_ip": "192.168.10.145",
  "target_ip": "10.0.0.5",
  "event_type": "SYN_FLOOD_SUSPECTED",
  "observed_rate": 182,
  "threshold": 150,
  "protocol": "TCP",
  "metadata": {
    "target_port": 443
  }
}
```

---

## License
MIT License
