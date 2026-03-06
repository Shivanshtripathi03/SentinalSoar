# Mini SIEM — Network & Transport-Layer Threat Detection

> **BCSE309L: Cryptography & Network Security**
> Priyanshu Kumar Jha (23BCE1554) · Prikesh Kumar (23BCE1884) · Shivansh Tripathi (23BCE1912)

A self-contained Security Information and Event Management (SIEM) system deployed as a 9-container Docker cyber range. It collects logs from three simulated network services, normalises them, runs four sliding-window detection rules, auto-blocks attackers, and shows everything on a live web dashboard with real-time charts.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Network Map](#2-network-map)
3. [Data Flow Pipeline](#3-data-flow-pipeline)
4. [File Reference](#4-file-reference)
5. [Detection Rules](#5-detection-rules)
6. [Dashboard](#6-dashboard)
7. [Configuration & Tweaking](#7-configuration--tweaking)
8. [Quick Start](#8-quick-start)
9. [Attack Scenarios](#9-attack-scenarios)
10. [FAQ / Viva Questions](#10-faq--viva-questions)

---

## 1. Architecture

```
┌──────────────────── Docker Network: siem_net (10.10.0.0/24) ────────────────────┐
│                                                                                  │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                          │
│   │ web-server   │   │ auth-server  │   │ db-server    │                          │
│   │ 10.10.0.10   │   │ 10.10.0.11   │   │ 10.10.0.12   │                          │
│   │ Port 80      │   │ Port 22      │   │ Port 3306    │                          │
│   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                          │
│          │ web.log          │ auth.log          │ db.log                           │
│          └─────────┬────────┴───────────────────┘                                 │
│                    │  Shared Docker Volume: /logs                                  │
│                    ▼                                                               │
│   ┌──────────────────────────────────────────────────────────┐                    │
│   │                 SIEM Core  (10.10.0.50)                   │                    │
│   │                                                          │                    │
│   │  ingestion.py → normaliser.py → rule_engine.py           │                    │
│   │                                    ├─ port_scan.py       │                    │
│   │                                    ├─ flooding.py        │                    │
│   │                                    ├─ beaconing.py       │                    │
│   │                                    └─ lateral_movement   │                    │
│   │                                         │                │                    │
│   │                          alert_manager.py → blocklist.py │                    │
│   │                                                          │                    │
│   │  app.py (Flask) → Dashboard at :5050                     │                    │
│   └──────────────────────────────────────────────────────────┘                    │
│                                                                                  │
│   Traffic generators (idle until invoked):                                        │
│   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐               │
│   │ normal-traffic     │  │ attacker-portscan │  │ attacker-flood    │               │
│   │ 10.10.0.101        │  │ 10.10.0.100       │  │ 10.10.0.102       │               │
│   └──────────────────┘  └──────────────────┘  └──────────────────┘               │
│   ┌──────────────────┐  ┌──────────────────┐                                     │
│   │ attacker-beacon    │  │ attacker-lateral   │                                     │
│   │ 10.10.0.103        │  │ 10.10.0.104        │                                     │
│   └──────────────────┘  └──────────────────┘                                     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Network Map

| Container         | IP          | Port      | Role                       |
| ----------------- | ----------- | --------- | -------------------------- |
| web-server        | 10.10.0.10  | 80        | Simulated HTTP server      |
| auth-server       | 10.10.0.11  | 22        | Simulated SSH/auth service |
| db-server         | 10.10.0.12  | 3306      | Simulated MySQL service    |
| siem-core         | 10.10.0.50  | 5050→5000 | SIEM engine + dashboard    |
| attacker-portscan | 10.10.0.100 | —         | Port scan attack           |
| normal-traffic    | 10.10.0.101 | —         | Benign traffic generator   |
| attacker-flood    | 10.10.0.102 | —         | Flood/DoS attack           |
| attacker-beacon   | 10.10.0.103 | —         | C2 beaconing attack        |
| attacker-lateral  | 10.10.0.104 | —         | Lateral movement attack    |

Each attacker gets a unique IP so detection rules never cross-contaminate.

---

## 3. Data Flow Pipeline

```
Service containers write structured log lines to /logs/*.log
                          │
                          ▼
              ┌─── ingestion.py ───┐
              │  Tails .log files   │
              │  Tracks byte offsets│
              └────────┬───────────┘
                       ▼
              ┌─── normaliser.py ──┐
              │  Regex → JSON       │
              │  Common schema:     │
              │   src_ip, dst_ip,   │
              │   dst_port, action, │
              │   source_type, ...  │
              └────────┬───────────┘
                       ▼
              ┌─── rule_engine.py ─┐
              │  Evaluates 4 rules  │
              │  Sliding windows    │
              └────────┬───────────┘
                       ▼
              ┌─ alert_manager.py ─┐
              │  Stores alert JSON  │
              │  With evidence      │
              └────────┬───────────┘
                       ▼
              ┌─── blocklist.py ───┐
              │  Auto-blocks IPs    │
              │  severity ≥ high    │
              └────────────────────┘
```

All timestamps are in IST (+05:30).

---

## 4. File Reference

```
cns-proj/
├── app.py                      # Flask dashboard + SIEM bootstrap
├── docker-compose.yml          # 9 containers, siem_net network
├── Dockerfile                  # SIEM core image (Python 3.11)
├── requirements.txt            # flask>=3.0, pyyaml>=6.0
├── config/
│   └── rules.yaml              # Rule thresholds + containment config
├── dashboard/
│   ├── templates/index.html    # Dashboard HTML (Chart.js)
│   └── static/
│       ├── style.css           # Dark navy SIEM theme
│       └── script.js           # Charts, tables, auto-refresh
├── data/
│   ├── alerts.json             # Persisted alerts
│   └── blocklist.json          # Persisted blocked IPs
├── services/
│   ├── web_server/             # HTTP server simulator
│   │   ├── app.py
│   │   └── Dockerfile
│   ├── auth_server/            # SSH/auth simulator
│   │   ├── app.py
│   │   └── Dockerfile
│   ├── db_server/              # MySQL simulator
│   │   ├── app.py
│   │   └── Dockerfile
│   ├── attacker/               # Attack traffic generator
│   │   ├── attack.py           # 4 scenarios via SCENARIO env var
│   │   └── Dockerfile
│   └── normal_traffic/         # Benign traffic generator
│       ├── normal_traffic.py
│       └── Dockerfile
└── siem/
    ├── __init__.py
    ├── core.py                 # Main pipeline loop (1s polling)
    ├── ingestion.py            # Log file tailer
    ├── normaliser.py           # Regex parser → JSON
    ├── rule_engine.py          # Loads and runs all rules
    ├── alert_manager.py        # Alert creation + storage
    ├── blocklist.py            # IP block/unblock + persistence
    └── rules/
        ├── __init__.py
        ├── port_scan.py        # Distinct endpoint probe detection
        ├── flooding.py         # Connection rate detection
        ├── beaconing.py        # C2 jitter analysis
        └── lateral_movement.py # Distinct destination IP detection
```

---

## 5. Detection Rules

| Rule                 | Severity | Window | Threshold                                           | What It Detects        |
| -------------------- | -------- | ------ | --------------------------------------------------- | ---------------------- |
| **port_scan**        | high     | 60s    | 10 distinct (dst_ip, dst_port, detail) probes       | Endpoint enumeration   |
| **flooding**         | critical | 10s    | 50 connections from same src_ip                     | DoS / connection flood |
| **beaconing**        | medium   | 300s   | Jitter σ < 1.5s, mean interval ≥ 2.0s, min 5 events | C2 callback pattern    |
| **lateral_movement** | high     | 120s   | 3 distinct dst_ips from same src_ip                 | Internal pivoting      |

All rules use a **15-second cooldown** to avoid duplicate alerts on the same IP.

**Containment**: Alerts with severity `high` or `critical` trigger automatic IP blocking. Blocked IPs are dropped at the ingestion stage — no further events are stored or evaluated.

---

## 6. Dashboard

The dashboard is served at **http://localhost:5050** and auto-refreshes every 1 second.

### Layout

| Section                  | Description                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------- |
| **Summary Cards**        | Total Events, Alerts, Blocked IPs, Active Rules                                                      |
| **Events Over Time**     | Line chart — events/sec per source IP, with flood threshold line. Seekable slider: last 20–1000 logs |
| **Service Distribution** | Doughnut chart — Web vs Auth vs DB volume                                                            |
| **Alert Summary**        | Table grouped by rule name with severity and count                                                   |
| **Live Logs**            | Filterable real-time log stream (last 200 events)                                                    |
| **Alerts**               | Full alert table with evidence viewer modal                                                          |
| **Blocked IPs**          | Active blocklist with one-click unblock                                                              |

### REST API

| Endpoint                    | Method | Returns                       |
| --------------------------- | ------ | ----------------------------- |
| `/api/events?limit=200`     | GET    | Recent normalised events      |
| `/api/alerts?limit=100`     | GET    | Recent alerts                 |
| `/api/blocklist`            | GET    | All blocked IPs               |
| `/api/blocklist/unblock`    | POST   | Unblock an IP `{"ip": "..."}` |
| `/api/stats`                | GET    | Processing counters           |
| `/api/timeseries?last=200`  | GET    | Per-IP event counts by second |
| `/api/service-distribution` | GET    | Event counts per service type |
| `/api/alert-summary`        | GET    | Alerts grouped by rule        |

---

## 7. Configuration & Tweaking

All rule parameters live in `config/rules.yaml`:

```yaml
rules:
  port_scan:
    enabled: true
    severity: high
    window_seconds: 60
    threshold: 10

  flooding:
    enabled: true
    severity: critical
    window_seconds: 10
    threshold: 50

  beaconing:
    enabled: true
    severity: medium
    window_seconds: 300
    min_events: 5
    jitter_threshold: 1.5

  lateral_movement:
    enabled: true
    severity: high
    window_seconds: 120
    threshold: 3

containment:
  auto_block_severity:
    - high
    - critical
```

**Common tweaks:**

| Goal                         | Change                                   |
| ---------------------------- | ---------------------------------------- |
| Make flooding more sensitive | Lower `flooding.threshold` (e.g. 30)     |
| Widen beaconing detection    | Raise `jitter_threshold` (e.g. 3.0)      |
| Only auto-block critical     | Remove `high` from `auto_block_severity` |
| Disable a rule               | Set `enabled: false`                     |
| Change detection window      | Adjust `window_seconds`                  |

Changes to `rules.yaml` take effect on container restart.

---

## 8. Quick Start

### Prerequisites

- Docker Desktop (with Compose v2)
- Ports 5050 free on host

### Build & Run

```bash
cd cns-proj

# Clean start
echo '[]' > data/alerts.json
echo '{}' > data/blocklist.json
docker compose up --build -d
```

### Verify

```bash
docker compose ps          # All 9 containers should be Up
open http://localhost:5050  # Dashboard
```

### Start Traffic

```bash
# Normal traffic (benign — hits web + auth only)
docker exec -d normal-traffic python normal_traffic.py

# Attack scenarios (run one at a time for clean demos)
docker exec attacker-portscan python attack.py
docker exec attacker-flood python attack.py
docker exec -d attacker-beacon python attack.py
docker exec attacker-lateral python attack.py
```

### Reset

```bash
docker compose down -v
echo '[]' > data/alerts.json
echo '{}' > data/blocklist.json
docker compose up --build -d
```

---

## 9. Attack Scenarios

### Port Scan (10.10.0.100)

Sends requests to 29 distinct URL paths on the web server. The `port_scan` rule fires when ≥ 10 unique endpoint probes are seen within 60 seconds.

```bash
docker exec attacker-portscan python attack.py
```

### Flood / DoS (10.10.0.102)

Sends 100 rapid requests to `/flood` on the web server. The `flooding` rule fires when ≥ 50 connections arrive within 10 seconds from the same IP.

```bash
docker exec attacker-flood python attack.py
```

### Beaconing / C2 (10.10.0.103)

Sends periodic requests every ~10 seconds for 2 minutes. The `beaconing` rule fires when it detects low jitter (σ < 1.5s) in inter-arrival times with at least 5 events and a mean interval ≥ 2.0s.

```bash
docker exec -d attacker-beacon python attack.py
```

### Lateral Movement (10.10.0.104)

Contacts all three services (web, auth, db). The `lateral_movement` rule fires when a single IP touches ≥ 3 distinct destination IPs within 120 seconds.

```bash
docker exec attacker-lateral python attack.py
```

---

## 10. FAQ / Viva Questions

**Q: What is a SIEM?**
A system that collects, normalises, correlates, and analyses security logs from multiple sources to detect threats, generate alerts, and support incident response.

**Q: Why Docker?**
It provides an isolated, reproducible network environment. Each container has a fixed IP, and the shared volume simulates real log collection.

**Q: How are logs collected?**
`ingestion.py` tails `.log` files from a shared Docker volume, tracking byte offsets so it only reads new lines each polling cycle.

**Q: What does normalisation do?**
`normaliser.py` uses regex to parse raw log lines into a common JSON schema with fields like `src_ip`, `dst_ip`, `dst_port`, `action`, `source_type`, `timestamp`.

**Q: How do the detection rules work?**
Each rule maintains a per-IP sliding time window (deque). When a new event arrives, expired entries are purged and the rule checks whether the remaining count/pattern exceeds its threshold.

**Q: Why separate attacker containers?**
Each attack has a unique source IP (10.10.0.100–104). This prevents log interference — e.g., a flood from one IP won't accidentally trigger the port scan rule.

**Q: How does auto-blocking work?**
When an alert has severity `high` or `critical`, `blocklist.py` adds the source IP. In the next polling cycle, `core.py` drops all events from that IP before they reach the dashboard or rules.

**Q: How do I unblock an IP?**
Click "Unblock" on the dashboard, or POST to `/api/blocklist/unblock` with `{"ip": "10.10.0.100"}`.

**Q: Why is beaconing severity only medium?**
Beaconing indicates C2 communication, which is suspicious but not immediately destructive. Medium severity means it generates an alert but does not trigger auto-blocking.

**Q: What is the cooldown?**
A 15-second window after an alert fires during which the same rule won't re-alert for the same source IP. This prevents alert flooding.

**Q: What happens when you re-run an attack after unblocking?**
The 15-second cooldown is short enough that the rule will fire again on a fresh attack run. Reset data files for a completely clean slate.

**Q: How does the Events Over Time chart work?**
The SIEM stores `(timestamp, src_ip)` tuples. The `/api/timeseries` endpoint buckets these by second per IP. The dashboard uses Chart.js to render the line chart with a seekable slider (20–1000 logs).

**Q: What does the flood threshold line on the chart mean?**
It's a visual reference at 5 events/sec (equivalent to the flooding rule's 50 events in 10 seconds).

**Q: What is the tech stack?**
Python 3.11, Flask ≥ 3.0, PyYAML, Chart.js 4, Docker Compose. No database — alerts and blocklist are stored as JSON files.

**Q: Can I add a new rule?**
Yes. Create a new file in `siem/rules/`, implement `evaluate(event) → list[alert]`, add it to `rules.yaml`, and register it in `rule_engine.py`.
