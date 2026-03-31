"""
Attack Traffic Generator — simulates 4 attack scenarios.
Run from the attacker container with: python attack.py --scenario <name>

Scenarios:
  port_scan      — probe many ports on web-server
  beaconing      — periodic low-volume C2-like connections
  flood          — burst of rapid connections
  lateral        — probe all internal services from one source
  all            — run all scenarios sequentially
"""

import os
import time
import random
import requests
import sys

TARGETS = {
    "web": ("web-server", 80),
    "auth": ("auth-server", 22),
    "db": ("db-server", 3306),
}


def scenario_port_scan():
    """
    PORT SCAN — Rapidly hit many different ports on the web server.
    Since our services only listen on specific ports, we simulate scanning
    by hitting the web server many times with different path patterns
    that represent different service probes.
    """
    print("[!] Running PORT SCAN scenario")
    host, port = TARGETS["web"]

    # Simulate scanning by rapidly probing many different endpoints
    scan_paths = [f"/port/{p}" for p in range(1, 30)]

    for path in scan_paths:
        try:
            requests.get(f"http://{host}:{port}{path}", timeout=2)
        except Exception:
            pass
        time.sleep(random.uniform(0.1, 0.3))

    print("[+] Port scan complete")


def scenario_beaconing():
    """
    BEACONING — Periodic connections at regular intervals (simulated C2).
    Connects to the web server every ~10 seconds for 2 minutes.
    The regularity (low jitter) is the detection signal.
    """
    print("[!] Running BEACONING scenario")
    host, port = TARGETS["web"]
    interval = 10  # seconds between beacons
    duration = 120  # total duration

    start = time.time()
    count = 0
    while time.time() - start < duration:
        try:
            requests.get(f"http://{host}:{port}/beacon", timeout=2)
            count += 1
        except Exception:
            pass
        # Very regular interval with tiny jitter (< 1s)
        time.sleep(interval + random.uniform(-0.5, 0.5))

    print(f"[+] Beaconing complete — {count} beacons sent over {duration}s")


def scenario_flood():
    """
    FLOODING — Burst of rapid connections to overwhelm a service.
    Sends 100 requests as fast as possible to the web server.
    """
    print("[!] Running FLOOD scenario")
    host, port = TARGETS["web"]

    for i in range(100):
        try:
            requests.get(f"http://{host}:{port}/flood", timeout=1)
        except Exception:
            pass
        # Tiny delay so they all hit within a few seconds
        time.sleep(0.02)

    print("[+] Flood complete — 100 connections sent")


def scenario_lateral():
    """
    LATERAL MOVEMENT — Probe all internal services rapidly.
    Access web, auth, and db services from the same source IP.
    """
    print("[!] Running LATERAL MOVEMENT scenario")

    for _ in range(5):  # 5 rounds of probing all services
        for svc_name, (host, port) in TARGETS.items():
            try:
                if svc_name == "auth":
                    requests.post(
                        f"http://{host}:{port}/login",
                        json={"username": "root", "password": "toor"},
                        timeout=2,
                    )
                elif svc_name == "db":
                    requests.post(
                        f"http://{host}:{port}/query",
                        json={"type": "SELECT"},
                        timeout=2,
                    )
                else:
                    requests.get(f"http://{host}:{port}/", timeout=2)
            except Exception:
                pass
            time.sleep(0.2)
        time.sleep(1)

    print("[+] Lateral movement complete")


def scenario_brute_force():
    """
    BRUTE FORCE — Rapid failed login attempts against the auth server.
    Sends 20 login attempts with wrong passwords.
    The brute_force rule fires when >= 5 LOGIN_FAIL events arrive
    within 60 seconds from the same IP.
    """
    print("[!] Running BRUTE FORCE scenario")
    host, port = TARGETS["auth"]

    usernames = ["admin", "root", "user1", "test", "guest", "administrator"]
    passwords = ["password", "123456", "admin", "letmein", "qwerty", "toor"]

    for i in range(20):
        user = random.choice(usernames)
        passwd = random.choice(passwords)
        try:
            requests.post(
                f"http://{host}:{port}/login",
                json={"username": user, "password": passwd},
                timeout=2,
            )
        except Exception:
            pass
        time.sleep(random.uniform(0.2, 0.5))

    print("[+] Brute force complete — 20 login attempts sent")


SCENARIOS = {
    "port_scan": scenario_port_scan,
    "beaconing": scenario_beaconing,
    "flood": scenario_flood,
    "lateral": scenario_lateral,
    "brute_force": scenario_brute_force,
}


def main():
    scenario = os.environ.get("SCENARIO", "")
    if not scenario:
        print("[!] No SCENARIO env var set. Use docker exec to run.")
        sys.exit(1)

    if scenario not in SCENARIOS and scenario != "all":
        print(f"[!] Unknown scenario: {scenario}")
        print(f"    Available: {', '.join(SCENARIOS.keys())}, all")
        sys.exit(1)

    # Give services time to start
    print(f"[*] Running scenario: {scenario}")
    time.sleep(3)

    if scenario == "all":
        for name, fn in SCENARIOS.items():
            fn()
            print(f"--- Pausing before next scenario ---")
            time.sleep(5)
    else:
        SCENARIOS[scenario]()

    print("[*] Attack generator finished")


if __name__ == "__main__":
    main()
