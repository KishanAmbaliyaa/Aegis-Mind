import os
import logging
import requests
from typing import Dict, Any, Optional
from cachetools import TTLCache
from config import settings

logger = logging.getLogger("AegisMind.ThreatIntel")

# In-memory TTL Cache to prevent API rate exhaustion and cut latency
# Thread-safe for read operations; caches up to CACHE_MAX_SIZE for CACHE_TTL_SECONDS
ti_cache = TTLCache(maxsize=settings.CACHE_MAX_SIZE, ttl=settings.CACHE_TTL_SECONDS)

# Known mass internet scanner ASNs / IP prefixes for benign noise classification
KNOWN_SCANNER_TAGS = {
    "SHODAN": ["shodan.io", "Shodan"],
    "CENSYS": ["censys-scanner.com", "Censys"],
    "SHADOWSERVER": ["shadowserver.org"],
    "PROJECT_SONAR": ["rapid7.com"]
}


def _check_known_scanners(data: Dict[str, Any]) -> Optional[str]:
    """Check if the threat intel points to known benign research scanners."""
    as_owner = str(data.get("as_owner", "")).lower()
    for scanner, identifiers in KNOWN_SCANNER_TAGS.items():
        if any(ident.lower() in as_owner for ident in identifiers):
            return scanner
    return None


def enrich_ip(ip_address: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 API for IP reputation with TTL caching.
    Supports private IP detection and graceful fallbacks.
    """
    # 1. Check local cache first
    cache_key = f"ip:{ip_address}"
    if cache_key in ti_cache:
        logger.info(f"[*] Threat intel cache HIT for IP: {ip_address}")
        cached_result = ti_cache[cache_key].copy()
        cached_result["cached"] = True
        return cached_result

    # 2. Check for private/loopback RFC1918 addresses
    if ip_address.startswith(("127.", "10.", "192.168.")) or (
        ip_address.startswith("172.") and 16 <= int(ip_address.split(".")[1] or 0) <= 31
    ):
        result = {
            "source": "Local-RFC1918",
            "indicator": ip_address,
            "type": "private_network",
            "malicious_votes": 0,
            "total_votes": 0,
            "network": "RFC1918 Private Subnet",
            "country": "Internal / Non-Routable",
            "as_owner": "Internal Enterprise Network",
            "reputation_score": 0,
            "is_known_scanner": None,
            "cached": False
        }
        ti_cache[cache_key] = result
        return result

    # 3. Check API key configuration
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key or api_key == "your_virustotal_api_key_here":
        logger.warning("[!] VirusTotal API key not configured. Returning simulated threat intel.")
        result = {
            "source": "Mock-Intel",
            "indicator": ip_address,
            "type": "ipv4",
            "malicious_votes": 12,
            "total_votes": 90,
            "network": "185.122.204.0/24",
            "country": "NL",
            "as_owner": "HOSTKEY B.V.",
            "reputation_score": -25,
            "is_known_scanner": None,
            "cached": False
        }
        ti_cache[cache_key] = result
        return result

    # 4. Query live VirusTotal v3 API
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "User-Agent": "Aegis-Mind-SOAR/2.0"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            result = {
                "source": "VirusTotal",
                "indicator": ip_address,
                "type": "ipv4",
                "malicious_votes": 0,
                "total_votes": 0,
                "network": "Unknown",
                "country": "Unknown",
                "as_owner": "Unassigned / Not Indexed",
                "reputation_score": 0,
                "is_known_scanner": None,
                "cached": False
            }
        elif response.status_code == 429:
            logger.error("[!] VirusTotal Rate Limit Exceeded (429). Using throttled fallback.")
            result = {
                "source": "VirusTotal-RateLimited",
                "indicator": ip_address,
                "error": "Rate limit exceeded on external TI provider",
                "malicious_votes": 0,
                "total_votes": 0,
                "cached": False
            }
        else:
            response.raise_for_status()
            raw_attrs = response.json().get("data", {}).get("attributes", {})
            last_analysis = raw_attrs.get("last_analysis_stats", {})

            result = {
                "source": "VirusTotal",
                "indicator": ip_address,
                "type": "ipv4",
                "malicious_votes": last_analysis.get("malicious", 0),
                "suspicious_votes": last_analysis.get("suspicious", 0),
                "harmless_votes": last_analysis.get("harmless", 0),
                "total_votes": sum(last_analysis.values()),
                "network": raw_attrs.get("network", "Unknown"),
                "country": raw_attrs.get("country", "Unknown"),
                "as_owner": raw_attrs.get("as_owner", "Unknown"),
                "reputation_score": raw_attrs.get("reputation", 0),
                "is_known_scanner": None,
                "cached": False
            }
            result["is_known_scanner"] = _check_known_scanners(result)

        # Store in cache
        ti_cache[cache_key] = result
        return result

    except Exception as e:
        logger.error(f"[!] Error querying VirusTotal for IP {ip_address}: {e}")
        return {
            "source": "VirusTotal",
            "indicator": ip_address,
            "error": str(e),
            "malicious_votes": 0,
            "total_votes": 0,
            "cached": False
        }


def enrich_file_hash(file_hash: str) -> Dict[str, Any]:
    """Queries VirusTotal v3 for file hash reputation (SHA256, MD5)."""
    cache_key = f"hash:{file_hash}"
    if cache_key in ti_cache:
        return {**ti_cache[cache_key], "cached": True}

    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key or api_key == "your_virustotal_api_key_here":
        return {"source": "Mock-Intel", "indicator": file_hash, "malicious_votes": 0}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            res = {
                "source": "VirusTotal",
                "indicator": file_hash,
                "malicious_votes": stats.get("malicious", 0),
                "total_votes": sum(stats.values()),
                "cached": False
            }
            ti_cache[cache_key] = res
            return res
        return {"source": "VirusTotal", "indicator": file_hash, "status": response.status_code}
    except Exception as e:
        logger.error(f"[!] Error querying VirusTotal for hash {file_hash}: {e}")
        return {"error": str(e)}
