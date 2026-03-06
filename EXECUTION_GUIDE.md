# Mini SIEM Cyber Range — Execution Guide

Step-by-step guide to build, run, demonstrate, and troubleshoot the project.

---

## Table of Contents

| #   | Section                                               |
| --- | ----------------------------------------------------- |
| 1   | [Prerequisites](#1-prerequisites)                     |
| 2   | [Network & IP Map](#2-network--ip-map)                |
| 3   | [First-Time Setup](#3-first-time-setup)               |
| 4   | [Build & Start](#4-build--start)                      |
| 5   | [Verify Clean Baseline](#5-verify-clean-baseline)     |
| 6   | [Generate Normal Traffic](#6-generate-normal-traffic) |
| 7   | [Launch Attacks](#7-launch-attacks)                   |
| 8   | [Dashboard Walkthrough](#8-dashboard-walkthrough)     |
| 9   | [API Reference](#9-api-reference)                     |
| 10  | [Unblock & Re-run](#10-unblock--re-run)               |
| 11  | [Stop & Clean Up](#11-stop--clean-up)                 |
| 12  | [Tuning Detection Rules](#12-tuning-detection-rules)  |
| 13  | [Full Demo Script](#13-full-demo-script)              |
| 14  | [Troubleshooting](#14-troubleshooting)                |

---

## 1. Prerequisites

| Tool              | Minimum | Check                    |
| ----------------- | ------- | ------------------------ |
| Docker Engine     | 20.10+  | `docker --version`       |
| Docker Compose V2 | 2.0+    | `docker compose version` |
| Free RAM          | ~1 GB   | —                        |
| Free port         | 5050    | `lsof -i :5050`          |

Docker Desktop (macOS / Windows) bundles both. On Linux install `docker-compose-plugin`.

---

## 2. Network & IP Map

All containers share the bridge network **siem_net** (`10.10.0.0/24`).

| Container         | IP          | Role                        | Starts on boot? |
| ----------------- | ----------- | --------------------------- | --------------- |
| web-server        | 10.10.0.10  | HTTP target (port 80)       | Yes             |
| auth-server       | 10.10.0.11  | SSH simulator (port 22)     | Yes             |
| db-server         | 10.10.0.12  | MySQL simulator (port 3306) | Yes             |
| siem-core         | 10.10.0.50  | SIEM engine + dashboard     | Yes             |
| attacker-portscan | 10.10.0.100 | Port-scan generator         | No — sleeps     |
| normal-traffic    | 10.10.0.101 | Benign traffic generator    | No — sleeps     |
| attacker-flood    | 10.10.0.102 | HTTP flood generator        | No — sleeps     |
| attacker-beacon   | 10.10.0.103 | C2 beaconing generator      | No — sleeps     |
| attacker-lateral  | 10.10.0.104 | Lateral-movement generator  | No — sleeps     |

> **9 containers total.** The four attacker containers and normal-traffic sleep on startup
> and do nothing until you explicitly `docker exec` into them.

---

## 3. First-Time Setup

```bash
cd cns-proj

# Ensure data files are clean
echo '[]' > data/alerts.json
echo '{}' > data/blocklist.json
```

---

## 4. Build & Start

```bash
docker compose up --build -d
```

Wait ~30 seconds for all images to build. Verify:

```bash
docker compose ps
```

You should see **9 containers**, all with status `Up` or `Up (healthy)`.

---

## 5. Verify Clean Baseline

Open the dashboard:

```
http://localhost:5050
```

You should see:

- **Summary cards:** 0 events, 0 alerts, 0 blocked IPs.
- **Events-over-time chart:** Empty (flat line).
- **Service distribution doughnut:** Empty.
- **Alert table:** No rows.

Quick API check:

```bash
curl -s http://localhost:5050/api/stats | python3 -m json.tool
```

Expected: `total_events: 0`, `total_alerts: 0`, `blocked_ips: 0`.

---

## 6. Generate Normal Traffic

```bash
docker exec -it normal-traffic python /app/attacker.py
```

This sends benign requests to all three target servers at a low rate.
Watch the dashboard — events climb, the doughnut fills in, but **no alerts fire**.

> Leave this running in its own terminal tab throughout the demo.

---

## 7. Launch Attacks

Open a **new terminal tab** for each attack. The order below is recommended
because it builds from low to high severity.

### 7.1 Port Scan (source: 10.10.0.100)

```bash
docker exec -it attacker-portscan python /app/attacker.py
```

- Probes multiple ports across all three targets.
- **Expected alert:** `port_scan` (HIGH) after ≥ 10 unique ports in 60 s.
- The source IP (`10.10.0.100`) is auto-blocked because HIGH ∈ `auto_block`.

### 7.2 HTTP Flood (source: 10.10.0.102)

```bash
docker exec -it attacker-flood python /app/attacker.py
```

- Sends rapid HTTP requests to `web-server`.
- **Expected alert:** `flooding` (CRITICAL) after ≥ 50 requests in 10 s.
- `10.10.0.102` is auto-blocked.

### 7.3 C2 Beaconing (source: 10.10.0.103)

```bash
docker exec -it attacker-beacon python /app/attacker.py
```

- Sends periodic callbacks with low jitter.
- **Expected alert:** `beaconing` (MEDIUM) after regular intervals detected over 300 s.
- MEDIUM is **not** in `auto_block`, so the IP stays unblocked.

### 7.4 Lateral Movement (source: 10.10.0.104)

```bash
docker exec -it attacker-lateral python /app/attacker.py
```

- Connects to auth-server then pivots to db-server.
- **Expected alert:** `lateral_movement` (HIGH) after ≥ 3 targets in 120 s.
- `10.10.0.104` is auto-blocked.

---

## 8. Dashboard Walkthrough

### Summary Cards

| Card         | Expected (after all attacks)               |
| ------------ | ------------------------------------------ |
| Total Events | Several hundred+                           |
| Total Alerts | 4+ (one per rule)                          |
| Blocked IPs  | 3 (port-scan, flood, lateral — not beacon) |

### Events-over-time Line Chart

- Each IP is a separate coloured line.
- Use the **range slider** (20 – 1 000) to control how many recent log events
  are visualised. Drag left for a tight window, right for more history.
- Normal-traffic IP (`10.10.0.101`) shows a steady baseline.
- Attacker IPs show spikes at the moment each attack runs.

### Service Distribution Doughnut

- Segments for `web`, `auth`, and `db`.
- `web` is usually largest because flood targets it.

### Alert Summary Table

| Column     | Description                  |
| ---------- | ---------------------------- |
| Time (IST) | Alert timestamp in UTC+05:30 |
| Rule       | Which rule fired             |
| Source     | Attacker IP                  |
| Severity   | MEDIUM / HIGH / CRITICAL     |

---

## 9. API Reference

All endpoints return JSON. Base URL: `http://localhost:5050`.

| Method | Endpoint                    | Description                         |
| ------ | --------------------------- | ----------------------------------- |
| GET    | `/api/events`               | Last 200 normalised events          |
| GET    | `/api/alerts`               | All alerts                          |
| GET    | `/api/blocklist`            | Currently blocked IPs               |
| POST   | `/api/blocklist/unblock`    | Unblock an IP (`{"ip":"..."}`)      |
| GET    | `/api/stats`                | Summary counters                    |
| GET    | `/api/timeseries?last=N`    | Per-IP event counts (last N events) |
| GET    | `/api/service-distribution` | Event split by service type         |
| GET    | `/api/alert-summary`        | Alert table data                    |

Example — unblock an IP:

```bash
curl -X POST http://localhost:5050/api/blocklist/unblock \
     -H "Content-Type: application/json" \
     -d '{"ip": "10.10.0.100"}'
```

---

## 10. Unblock & Re-run

After an attacker is blocked, its traffic is dropped. To demonstrate detection
again:

```bash
# Unblock the port-scan attacker
curl -X POST http://localhost:5050/api/blocklist/unblock \
     -H "Content-Type: application/json" \
     -d '{"ip": "10.10.0.100"}'

# Re-run the attack
docker exec -it attacker-portscan python /app/attacker.py
```

A new alert fires and the IP is blocked again.

---

## 11. Stop & Clean Up

```bash
# Stop all containers
docker compose down

# Full clean (removes volumes + data)
docker compose down -v
echo '[]' > data/alerts.json
echo '{}' > data/blocklist.json
```

---

## 12. Tuning Detection Rules

Edit `config/rules.yaml`:

```yaml
rules:
  port_scan:
    severity: high
    window: 60 # seconds
    threshold: 10 # unique ports
  flooding:
    severity: critical
    window: 10
    threshold: 50 # requests
  beaconing:
    severity: medium
    window: 300
    jitter: 1.5
  lateral_movement:
    severity: high
    window: 120
    threshold: 3 # distinct targets

auto_block:
  - high
  - critical
```

After editing, rebuild only the SIEM container:

```bash
docker compose up --build -d siem-core
```

---

## 13. Full Demo Script

Copy-paste-ready block to run the entire demonstration from scratch.

```bash
# ── 1. Clean slate ──────────────────────────────────
cd cns-proj
echo '[]' > data/alerts.json && echo '{}' > data/blocklist.json
docker compose down -v
docker compose up --build -d
sleep 30

# ── 2. Verify baseline ─────────────────────────────
curl -s http://localhost:5050/api/stats | python3 -m json.tool

# ── 3. Normal traffic (leave running) ──────────────
docker exec -d normal-traffic python /app/attacker.py

# ── 4. Wait a moment then run attacks ──────────────
sleep 10

docker exec -d attacker-portscan python /app/attacker.py
sleep 5
docker exec -d attacker-flood    python /app/attacker.py
sleep 5
docker exec -d attacker-beacon   python /app/attacker.py
sleep 5
docker exec -d attacker-lateral  python /app/attacker.py

# ── 5. Watch dashboard ─────────────────────────────
echo "Open http://localhost:5050 in your browser"

# ── 6. Check alerts after ~60 s ────────────────────
sleep 60
curl -s http://localhost:5050/api/alerts | python3 -m json.tool
curl -s http://localhost:5050/api/blocklist | python3 -m json.tool
```

> The `-d` flag runs each attack in the background inside its container,
> so all four run concurrently from a single terminal.

---

## 14. Troubleshooting

| Symptom                             | Fix                                                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `port 5050 already in use`          | `lsof -i :5050` → kill the process, or change the port in `docker-compose.yml`                              |
| Containers exit immediately         | `docker compose logs <name>` — usually a Python import error; rebuild with `--no-cache`                     |
| No events on dashboard              | Make sure `normal-traffic` or an attacker is running; check `docker compose logs siem-core` for poll errors |
| Alerts don't fire                   | Verify `config/rules.yaml` thresholds; lower them for faster triggering                                     |
| IP blocked but attack still running | The SIEM drops events from blocked IPs; unblock via API to resume                                           |
| Dashboard charts not updating       | Hard-refresh the browser (`Cmd+Shift+R`); make sure JS has no console errors                                |
| `docker compose` not found          | Install Docker Compose V2 plugin: `apt install docker-compose-plugin`                                       |
| Stale data from previous run        | `docker compose down -v && echo '[]' > data/alerts.json && echo '{}' > data/blocklist.json`                 |

---

_All timestamps in the dashboard and alerts are in IST (UTC+05:30)._
