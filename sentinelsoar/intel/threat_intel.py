"""
Threat Intelligence Module — IP reputation, geolocation, and IOC matching.

Integrates:
  - ip-api.com   (geolocation — free, no key)
  - AbuseIPDB    (abuse score — set ABUSEIPDB_API_KEY)
  - VirusTotal   (malware detections — set VIRUSTOTAL_API_KEY)

All lookups are cached in-memory with a configurable TTL.
"""

import os
import time
import json
import threading

try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ThreatIntelManager:
    """Unified threat intelligence lookup with caching."""

    def __init__(self, cache_ttl=600):
        self.cache_ttl = cache_ttl  # 10 min default
        self._cache = {}
        self.lock = threading.Lock()

        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

        status = []
        if self.abuseipdb_key:
            status.append("AbuseIPDB")
        if self.virustotal_key:
            status.append("VirusTotal")
        status.append("GeoIP")  # always available

        print(f"[threat_intel] Initialised — services: {', '.join(status)}")

    def lookup(self, ip: str) -> dict:
        """
        Full threat intelligence lookup for an IP address.
        Returns combined results from all configured sources.
        """
        # Check cache
        with self.lock:
            if ip in self._cache:
                cached = self._cache[ip]
                if time.time() - cached.get("_cached_at", 0) < self.cache_ttl:
                    return cached

        result = {
            "ip": ip,
            "geo": self._geoip_lookup(ip),
            "abuse": self._abuseipdb_lookup(ip),
            "virustotal": self._virustotal_lookup(ip),
            "is_private": self._is_private_ip(ip),
            "threat_score": 0,
        }

        # Calculate composite threat score (0-100)
        result["threat_score"] = self._calculate_threat_score(result)

        # Cache
        result["_cached_at"] = time.time()
        with self.lock:
            self._cache[ip] = result

        return result

    def _geoip_lookup(self, ip: str) -> dict:
        """Geolocation lookup via ip-api.com (free, no key)."""
        if self._is_private_ip(ip):
            return {
                "country": "Private Network",
                "city": "Internal",
                "isp": "Docker Network",
                "org": "Lab Environment",
                "asn": "AS0",
            }

        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not installed"}

        try:
            resp = req_lib.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as",
                timeout=5
            )
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                }
            return {"country": "Unknown", "error": data.get("message", "lookup failed")}
        except Exception as e:
            return {"country": "Unknown", "error": str(e)}

    def _abuseipdb_lookup(self, ip: str) -> dict:
        """AbuseIPDB reputation lookup."""
        if not self.abuseipdb_key:
            return {"enabled": False, "message": "Set ABUSEIPDB_API_KEY to enable"}

        if self._is_private_ip(ip):
            return {"enabled": True, "abuse_score": 0, "total_reports": 0, "note": "Private IP"}

        if not REQUESTS_AVAILABLE:
            return {"enabled": False, "error": "requests library not installed"}

        try:
            resp = req_lib.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            data = resp.json().get("data", {})
            return {
                "enabled": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "is_tor": data.get("isTor", False),
                "last_reported": data.get("lastReportedAt", ""),
            }
        except Exception as e:
            return {"enabled": True, "error": str(e)}

    def _virustotal_lookup(self, ip: str) -> dict:
        """VirusTotal IP lookup."""
        if not self.virustotal_key:
            return {"enabled": False, "message": "Set VIRUSTOTAL_API_KEY to enable"}

        if self._is_private_ip(ip):
            return {"enabled": True, "malicious": 0, "suspicious": 0, "note": "Private IP"}

        if not REQUESTS_AVAILABLE:
            return {"enabled": False, "error": "requests library not installed"}

        try:
            resp = req_lib.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.virustotal_key},
                timeout=10,
            )
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "enabled": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country", ""),
            }
        except Exception as e:
            return {"enabled": True, "error": str(e)}

    def _calculate_threat_score(self, result: dict) -> int:
        """Calculate a composite threat score (0-100)."""
        score = 0

        # AbuseIPDB contribution (0-50)
        abuse = result.get("abuse", {})
        if abuse.get("enabled") and "abuse_score" in abuse:
            score += min(abuse["abuse_score"] // 2, 50)

        # VirusTotal contribution (0-40)
        vt = result.get("virustotal", {})
        if vt.get("enabled") and "malicious" in vt:
            score += min(vt["malicious"] * 5, 40)

        # Private IP penalty (lower score)
        if result.get("is_private"):
            score = max(score - 20, 0)

        # Tor exit node bonus
        if abuse.get("is_tor"):
            score = min(score + 20, 100)

        return min(score, 100)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP is in a private range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
        except ValueError:
            return False

        return (
            first == 10
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or first == 127
        )

    def get_cache_stats(self) -> dict:
        """Return cache statistics."""
        with self.lock:
            return {
                "cached_ips": len(self._cache),
                "cache_ttl_seconds": self.cache_ttl,
            }
