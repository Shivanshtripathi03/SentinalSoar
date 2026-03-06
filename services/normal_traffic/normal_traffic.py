"""
Normal Traffic Generator — simulates legitimate user activity.
Runs continuously, making occasional requests to each service.
"""

import time
import random
import requests

SERVICES = {
    "web": "http://web-server:80",
    "auth": "http://auth-server:22",
}


def normal_web_traffic():
    """Simulate a normal user browsing."""
    paths = ["/", "/about", "/index.html", "/products", "/contact"]
    try:
        url = f"{SERVICES['web']}{random.choice(paths)}"
        requests.get(url, timeout=3)
    except Exception:
        pass


def normal_auth_traffic():
    """Simulate occasional login attempts."""
    try:
        requests.post(
            f"{SERVICES['auth']}/login",
            json={"username": "admin", "password": "admin123"},
            timeout=3,
        )
    except Exception:
        pass


def main():
    """Generate steady, low-volume normal traffic."""
    print("[*] Normal traffic generator started")
    while True:
        action = random.choice(["web", "web", "web", "auth"])
        if action == "web":
            normal_web_traffic()
        else:
            normal_auth_traffic()

        # Normal users: 1 request every 3-8 seconds
        time.sleep(random.uniform(3, 8))


if __name__ == "__main__":
    main()
