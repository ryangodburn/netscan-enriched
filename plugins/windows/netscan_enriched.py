# Enhanced NetScan Plugin for Volatility 3
# ==========================================
#
# Original netscan plugin: Copyright 2019 Volatility Foundation
# Licensed under the Volatility Software License 1.0
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
# Enrichment extensions by:
#   Ryan Godburn, Braeden Allen, and Anthony Ciavarella
#
# Description:
#   This plugin extends the standard Volatility 3 windows.netscan module by adding
#   real-time IP enrichment capabilities on top of the original memory-forensic
#   network scanning. For each network connection found in a Windows memory image,
#   the plugin can perform live lookups to provide additional context that helps
#   analysts quickly triage connections during incident response.
#
#   The enrichment is divided into three tiers:
#
#   Tier 1: Offline Analysis (always active, no internet required)
#     - Classifies each IP as Public, Private-RFC1918, Loopback, Multicast, etc.
#     - Maps local and foreign ports to well-known service names (e.g., 443 -> HTTPS)
#     - Flags suspicious ports commonly associated with malware, C2 channels, and
#       backdoors (e.g., 4444 -> Metasploit, 6667 -> IRC botnet C2, 9050 -> Tor)
#
#   Tier 2: Geolocation & DNS Enrichment (requires --enrich flag + internet)
#     - Resolves the geographic location (country, state/region, city) of public IPs
#       using the free ip-api.com service (no API key required, 45 req/min)
#     - Identifies the ISP and ASN (Autonomous System Number) that owns the IP block
#     - Performs reverse DNS (PTR record) lookups to find hostnames behind IPs
#     - Generates URL hints when reverse DNS reveals a recognizable web hostname
#     - Detects whether an IP belongs to a hosting provider or VPN/proxy service
#
#   Tier 3: VirusTotal Threat Intelligence (requires --vtkey flag + internet)
#     - Checks each unique public IP against VirusTotal's database of 70+ AV engines
#       and security blocklists using the VirusTotal API v3
#     - Reports detection counts (e.g., "3/87" = 3 of 87 engines flagged it)
#     - Assigns an automated verdict: MALICIOUS, SUSPICIOUS, CLEAN, or NO_DATA
#     - Includes VT community reputation score and tags (e.g., "botnet", "miner")
#     - Provides a direct link to the VirusTotal GUI for deeper manual investigation
#     - Free VT API keys are rate-limited to 4 req/min; the plugin handles this
#       automatically with a ~15s delay between queries
#
# Usage Examples:
#   # Basic scan (offline enrichment only; fast, no internet needed)
#   python3 vol.py -f <memory_image> windows.netscan_enriched.NetScanEnriched
#
#   # With geolocation and DNS enrichment
#   python3 vol.py -f <memory_image> windows.netscan_enriched.NetScanEnriched --enrich
#
#   # With geolocation + VirusTotal threat intel (API key via command line)
#   python3 vol.py -f <memory_image> windows.netscan_enriched.NetScanEnriched --enrich --vtkey YOUR_VT_API_KEY
#
#   # With VirusTotal via environment variable (useful for scripting/automation)
#   export VT_API_KEY="your_key_here"
#   python3 vol.py -f <memory_image> windows.netscan_enriched.NetScanEnriched --enrich
#
#   # Export enriched results to CSV for analysis in Excel, Splunk, etc.
#   # (-r is a global Volatility option, so it goes before the plugin name)
#   python3 vol.py -r csv -f <memory_image> windows.netscan_enriched.NetScanEnriched --enrich --vtkey YOUR_KEY > enriched_connections.csv
#
# Installation:
#   Either point Volatility at the directory that contains windows/netscan_enriched.py:
#     python3 vol.py -p /path/to/netscan-enriched/plugins -f <memory_image> windows.netscan_enriched.NetScanEnriched
#   or copy this file into your Volatility 3 plugins directory:
#     volatility3/framework/plugins/windows/netscan_enriched.py
#
# Performance Notes:
#   - All API lookups are cached per-run: if the same IP appears in 50 connections,
#     it is only queried once. Subsequent rows reuse the cached result instantly.
#   - ip-api.com lookups take ~1.4s each (rate limit). For 20 unique public IPs,
#     expect roughly 28 seconds of enrichment time.
#   - VirusTotal lookups take ~15s each (free tier rate limit). For 20 unique public
#     IPs, expect roughly 5 minutes. With a premium VT key, lower
#     VirusTotalCache.RATE_LIMIT_DELAY to speed this up.
#   - Both services degrade gracefully: after 5 consecutive failures, the respective
#     enrichment engine disables itself and the scan continues with partial data
#     rather than crashing.

import datetime
import ipaddress     # NEW: used to classify IPs as public/private/loopback/etc.
import json          # NEW: used to parse JSON responses from ip-api.com and VirusTotal
import logging
import os
import socket        # NEW: used for reverse DNS (PTR) lookups via gethostbyaddr()
import time          # NEW: used for rate-limiting delays between API requests
import urllib.request  # NEW: used to make HTTP requests to ip-api.com and VirusTotal
import urllib.error    # NEW: used to handle HTTP error responses (401, 429, 404, etc.)
from typing import Dict, Iterable, List, Optional, Tuple, Type

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import network
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info, poolscanner

# The verinfo module is used by the original netscan to determine the exact
# version of tcpip.sys for symbol table selection. It may not be present in
# all Volatility 3 builds (some versions moved it to a different location),
# so we import it defensively and set a flag to skip its usage if unavailable.
# The plugin will still work without it; it just won't be able to disambiguate
# certain Windows builds that share the same kernel version number.
try:
    from volatility3.plugins.windows import verinfo
    HAS_VERINFO = True
except ImportError:
    HAS_VERINFO = False

vollog = logging.getLogger(__name__)


# =============================================================================
# NEW SECTION: Offline Enrichment Data
# =============================================================================
# The following dictionaries and helper functions provide enrichment that works
# entirely offline, with no internet connection or API keys required. They run on
# every scan regardless of the --enrich or --vtkey flags.
# =============================================================================

# WELL_KNOWN_PORTS maps port numbers to their standard service names.
# This allows the analyst to see "HTTPS" or "RDP" in the output instead of
# having to remember that 443 = HTTPS or 3389 = RDP. This covers the most
# commonly encountered ports in memory forensics, with a focus on services
# relevant to incident response (remote access, databases, C2 protocols, etc.).
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-Pwd",
    465: "SMTPS", 500: "IKE/IPSec", 514: "Syslog", 515: "LPD",
    520: "RIP", 548: "AFP", 554: "RTSP", 587: "SMTP-Submission",
    593: "MS-RPC-HTTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-Browser",
    1521: "Oracle-DB", 1723: "PPTP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
    3128: "Squid-Proxy", 3268: "Global-Catalog", 3269: "Global-Catalog-SSL",
    3306: "MySQL", 3389: "RDP", 3478: "STUN/TURN",
    4443: "Pharos", 4444: "Metasploit-Default",
    5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5432: "PostgreSQL",
    5500: "VNC-HTTP", 5632: "PCAnywhere", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 6660: "IRC", 6661: "IRC",
    6662: "IRC", 6663: "IRC", 6664: "IRC", 6665: "IRC", 6666: "IRC",
    6667: "IRC", 6668: "IRC", 6669: "IRC",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "WebSM", 9200: "Elasticsearch", 9418: "Git",
    11211: "Memcached", 27017: "MongoDB",
}

# SUSPICIOUS_PORTS is a set of port numbers that are commonly associated with
# malware, backdoors, command-and-control (C2) infrastructure, or anonymization
# tools. When a connection uses one of these ports, the Flags column will
# automatically include a warning. This does NOT mean the connection is
# definitively malicious; it just warrants closer inspection by the analyst.
#
# Notable entries:
#   4444:        Default listener port for Metasploit's Meterpreter reverse shell
#   6667:        Standard IRC port, frequently abused by botnets for C2 communication
#   1337, 31337: "leet" ports historically used by trojans and script-kiddie tools
#   9050, 9150:  Tor SOCKS proxy ports (may indicate data exfiltration or anonymous C2)
#   12345:       Classic trojan port (NetBus, other legacy malware)
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 6667, 1337, 31337, 12345, 54321,
    4443, 8443, 9001, 9030, 9050, 9051, 9150,
    6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669,
}


def classify_ip(ip_str: str) -> str:
    """Classify an IP address into a human-readable network category.

    Uses Python's ipaddress module to determine whether an IP is public
    (routable on the internet) or belongs to a special-use range. This
    classification appears in the IPType column of the output and helps
    analysts quickly filter out local/internal connections to focus on
    external communication.

    Returns one of:
        "Public":          Routable internet IP; candidate for geo/VT enrichment
        "Private-RFC1918": Internal network (10.x, 172.16-31.x, 192.168.x)
        "Loopback":        127.0.0.0/8 or ::1
        "Link-Local":      169.254.x.x (APIPA) or fe80::/10
        "Multicast":       224.0.0.0/4 or ff00::/8
        "Reserved":        IANA reserved ranges
        "Unspecified":     0.0.0.0 or ::
        "Wildcard/Any":    Listener bound to all interfaces (*, 0.0.0.0, ::)
        "Invalid":         Could not be parsed as a valid IP address
    """
    if not ip_str or ip_str in ("*", "", "?", "0.0.0.0", "::"):
        return "Wildcard/Any"
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Invalid"

    if addr.is_loopback:
        return "Loopback"
    if addr.is_private:
        return "Private-RFC1918"
    if addr.is_link_local:
        return "Link-Local"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_reserved:
        return "Reserved"
    if addr.is_unspecified:
        return "Unspecified"
    return "Public"


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP address is a public, routable unicast address.

    Only public IPs are worth querying against external APIs (ip-api.com,
    VirusTotal). Private/loopback/multicast addresses would either fail
    or return meaningless results, so we skip them to save API quota.
    """
    return classify_ip(ip_str) == "Public"


def get_port_service(port: int) -> str:
    """Map a port number to its well-known service name.

    Returns the service name (e.g., "HTTPS" for port 443) or an empty
    string if the port is not in our lookup table. The result populates
    the LocalPortSvc and ForeignPortSvc columns in the output.
    """
    if isinstance(port, renderers.UnreadableValue):
        return ""
    return WELL_KNOWN_PORTS.get(port, "")


def flag_port(port: int) -> str:
    """Check if a port number is in the suspicious ports list.

    Returns "SUSPICIOUS" if the port is commonly associated with malware
    or C2 activity, or an empty string if it's not flagged. Suspicious
    port hits are added to the Flags column to draw analyst attention.
    """
    if isinstance(port, renderers.UnreadableValue):
        return ""
    if port in SUSPICIOUS_PORTS:
        return "SUSPICIOUS"
    return ""


# =============================================================================
# NEW SECTION: Geolocation & DNS Enrichment Engine
# =============================================================================
# This class handles Tier 2 enrichment: geographic location, ISP identification,
# reverse DNS lookups, and hosting/proxy detection for public IP addresses.
# It is only instantiated when the user passes the --enrich flag.
# =============================================================================

class IPEnrichmentCache:
    """Performs and caches geolocation, DNS, and ISP lookups for public IPs.

    Data source: ip-api.com, a free geolocation API that requires no API key.
    Rate limit: 45 requests per minute. The plugin enforces a 1.4-second delay
    between requests to stay safely within this limit (~43 req/min actual).

    For each public IP, this class retrieves:
        - Geographic location: country, state/region, city, ZIP code, lat/lon
        - Network ownership: ISP name, organization, ASN (e.g., "AS15169 Google LLC")
        - Reverse DNS: the PTR record hostname (e.g., "lax17s61-in-f14.1e100.net")
        - Hosting/proxy detection: whether ip-api.com identifies the IP as belonging
          to a hosting provider (datacenter) or a known VPN/proxy service
        - URL hint: if the reverse DNS looks like a web-facing hostname (starts with
          "www.", "cdn.", etc.), a clickable HTTPS link is generated for convenience

    Caching: Results are stored in a dict keyed by IP string. Once an IP has been
    looked up, all subsequent rows with the same IP reuse the cached result without
    making another API call. This is important because memory images often contain
    many connections to the same IP (e.g., multiple Chrome tabs to Google's servers).

    Error handling: After 5 consecutive API failures (network timeout, service down,
    etc.), the enricher disables further lookups and silently returns empty results
    for all remaining IPs. This prevents the scan from hanging indefinitely if the
    analyst's machine has no internet access.
    """

    # API URL with field selection: we request only the fields we need to minimize
    # response size and parsing overhead. Full field list at https://ip-api.com/docs/api:json
    API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,reverse,hosting,proxy"

    # Minimum seconds between consecutive HTTP requests to ip-api.com.
    # The free tier allows 45/min; 1.4s spacing gives us ~43/min with margin.
    RATE_LIMIT_DELAY = 1.4

    def __init__(self):
        self._cache: Dict[str, dict] = {}       # IP string -> enrichment result dict
        self._last_request_time: float = 0.0     # Timestamp of most recent API call
        self._failures: int = 0                  # Count of consecutive failures
        self._max_consecutive_failures = 5       # Disable after this many failures

    def _rate_limit(self):
        """Sleep if necessary to maintain the minimum delay between API requests.

        Called immediately before each HTTP request. If less than RATE_LIMIT_DELAY
        seconds have elapsed since the last request, this method blocks for the
        remaining time. This ensures we never exceed ip-api.com's rate limit even
        if the scan finds many unique public IPs in rapid succession.
        """
        elapsed = time.time() - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)

    @staticmethod
    def empty_result() -> dict:
        """Return a blank enrichment result dict with all expected keys.

        Used as the return value when enrichment is skipped (non-public IP),
        when the lookup fails, or when the enricher has been disabled due to
        too many consecutive failures. All values are empty strings so the
        Volatility renderer can display them without errors.
        """
        return {
            "country": "", "region": "", "city": "", "zip": "",
            "lat": "", "lon": "", "isp": "", "org": "", "asn": "",
            "reverse_dns": "", "is_hosting": "", "is_proxy": "",
            "url_hint": "",
        }

    def lookup(self, ip_str: str) -> dict:
        """Look up geolocation, DNS, and ISP data for a single public IP.

        Workflow:
            1. Check if the IP is public (skip private/loopback/multicast IPs)
            2. Check the cache (return immediately if we've already looked up this IP)
            3. Check the failure counter (bail out if too many failures have occurred)
            4. Perform a reverse DNS lookup using the system resolver (socket.gethostbyaddr)
            5. Query ip-api.com for geolocation, ISP, ASN, and hosting/proxy info
            6. If the reverse DNS hostname looks like a website, generate a URL hint
            7. Cache and return the combined result

        Returns:
            A dict with keys: country, region, city, zip, lat, lon, isp, org, asn,
            reverse_dns, is_hosting, is_proxy, url_hint. All values are strings.
            Empty strings indicate unavailable data.
        """
        empty = self.empty_result()

        # Only public IPs are worth enriching; skip everything else
        if not is_public_ip(ip_str):
            return empty

        # Return cached result if we've already queried this IP
        if ip_str in self._cache:
            return self._cache[ip_str]

        # If we've had too many consecutive failures (e.g., no internet), stop trying
        if self._failures >= self._max_consecutive_failures:
            vollog.warning("Too many consecutive geo-API failures; skipping further lookups.")
            return empty

        # Step 1: Reverse DNS lookup using the system's DNS resolver.
        # This is independent of ip-api.com and works even if the API is down.
        # gethostbyaddr() returns (hostname, aliases, addresses) or raises an error
        # if no PTR record exists for this IP.
        reverse_dns = ""
        try:
            reverse_dns = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass  # No PTR record found; this is normal for many IPs

        # Step 2: Query ip-api.com for geolocation and network ownership data
        try:
            self._rate_limit()
            url = self.API_URL.format(ip=ip_str)
            req = urllib.request.Request(url, headers={"User-Agent": "Volatility3-NetScanEnriched/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._last_request_time = time.time()
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success":
                self._failures = 0  # Reset failure counter on success
                result = {
                    "country": data.get("country", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "zip": data.get("zip", ""),
                    "lat": str(data.get("lat", "")),
                    "lon": str(data.get("lon", "")),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    # Prefer our own reverse DNS result; fall back to ip-api's reverse field
                    "reverse_dns": reverse_dns or data.get("reverse", ""),
                    "is_hosting": "Yes" if data.get("hosting") else "No",
                    "is_proxy": "Yes" if data.get("proxy") else "No",
                    "url_hint": "",
                }

                # Step 3: Generate a URL hint if the reverse DNS looks like a website.
                # This heuristic checks for common web-facing hostname prefixes (www, cdn,
                # edge, etc.) and also accepts any hostname with a dot that isn't just a
                # numeric IP formatted as a hostname (some PTR records are like "1-2-3-4.isp.net").
                rdns = result["reverse_dns"]
                if rdns:
                    rdns = rdns.rstrip(".")  # Remove trailing dot from FQDN
                    if any(rdns.startswith(p) for p in ("www.", "web.", "cdn.", "edge.", "srv.")):
                        result["url_hint"] = f"https://{rdns}"
                    elif "." in rdns and not rdns.replace(".", "").replace("-", "").isdigit():
                        result["url_hint"] = f"https://{rdns}"

                self._cache[ip_str] = result
                return result
            else:
                self._failures += 1
                vollog.debug(f"ip-api returned non-success for {ip_str}: {data.get('message', '?')}")
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as e:
            self._failures += 1
            self._last_request_time = time.time()
            vollog.debug(f"IP enrichment lookup failed for {ip_str}: {e}")

        # If the API call failed but we got a reverse DNS result, still cache
        # that partial data so it's available in the output
        result = dict(empty)
        result["reverse_dns"] = reverse_dns
        self._cache[ip_str] = result
        return result


# =============================================================================
# NEW SECTION: VirusTotal Threat Intelligence Engine
# =============================================================================
# This class handles Tier 3 enrichment: checking public IPs against VirusTotal's
# database of 70+ antivirus engines, security blocklists, and community intelligence.
# It is only instantiated when the user provides a VT API key via --vtkey or the
# VT_API_KEY environment variable.
# =============================================================================

class VirusTotalCache:
    """Performs and caches VirusTotal API v3 IP address lookups.

    VirusTotal aggregates scan results from 70+ antivirus products, security
    blocklists, and community intelligence. For each IP address queried, VT
    returns how many of these engines consider the IP malicious, suspicious,
    harmless, or undetected, along with a community reputation score and tags.

    API details:
        Endpoint: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
        Auth:     x-apikey header with your API key
        Docs:     https://docs.virustotal.com/reference/ip-info

    Rate limiting:
        Free VT API keys are limited to 4 requests per minute. The plugin
        enforces a 15.5-second delay between requests to stay within this limit.
        If a 429 (rate limit exceeded) response is received anyway, the plugin
        waits 60 seconds before retrying. Premium API keys have higher limits;
        the delay is conservative by default to avoid any issues.

    Verdict logic:
        The plugin assigns a simple verdict based on detection counts:
        - MALICIOUS:  5 or more AV engines flagged the IP as malicious
        - SUSPICIOUS: 1-4 malicious detections, or 3+ suspicious detections
        - CLEAN:      At least one engine scanned it, zero malicious/suspicious
        - NO_DATA:    VirusTotal has no record for this IP (HTTP 404)
        - UNKNOWN:    Insufficient data to make a determination

        These thresholds are intentionally conservative: a single AV detection
        could be a false positive, so we require 5+ for a MALICIOUS verdict.
        Analysts should always check the VT_Link for the full report.

    Caching:
        Same strategy as IPEnrichmentCache: each unique IP is queried only once
        per run, with results stored in a dict keyed by IP string.

    Error handling:
        - HTTP 401 (bad API key): immediately disables all further VT lookups
        - HTTP 429 (rate limited): waits 60 seconds, then retries on next IP
        - HTTP 404 (no data): caches as NO_DATA verdict (not an error)
        - Network failures: after 5 consecutive failures, disables VT lookups
        - All errors are logged but never crash the scan
    """

    # VirusTotal API v3 endpoint for IP address reports
    API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    # URL template for the VirusTotal web GUI, included in output so analysts
    # can click through to view the full report, related files, WHOIS data, etc.
    GUI_URL = "https://www.virustotal.com/gui/ip-address/{ip}"

    # Minimum seconds between consecutive VT API requests.
    # Free tier allows 4 req/min; 15.5s spacing gives us ~3.9/min with margin.
    # This is deliberately conservative to avoid 429 errors. Premium users can
    # modify this value if they need faster throughput.
    RATE_LIMIT_DELAY = 15.5

    def __init__(self, api_key: str):
        self._api_key = api_key              # VT API key (passed via --vtkey or env var)
        self._cache: Dict[str, dict] = {}    # IP string -> VT result dict
        self._last_request_time: float = 0.0  # Timestamp of most recent API call
        self._failures: int = 0               # Count of consecutive failures
        self._max_consecutive_failures = 5    # Disable after this many failures in a row
        self._disabled = False                # Set to True if API key is invalid or too many failures
        self._total_lookups = 0               # Counter for progress logging

    def _rate_limit(self):
        """Sleep if necessary to respect VirusTotal's API rate limit.

        The free VT API tier allows 4 requests per minute. This method ensures
        at least RATE_LIMIT_DELAY seconds elapse between consecutive requests.
        During the wait, a debug log message shows the remaining wait time so
        analysts can monitor progress during long scans.
        """
        elapsed = time.time() - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            wait = self.RATE_LIMIT_DELAY - elapsed
            vollog.debug(f"[VT] Rate limit: waiting {wait:.1f}s before next request")
            time.sleep(wait)

    @staticmethod
    def empty_result() -> dict:
        """Return a blank VT result dict with all expected keys.

        Used when VT lookup is skipped (non-public IP, disabled, or failed).
        All values are empty strings for clean rendering in the Volatility output.
        """
        return {
            "vt_malicious": "",      # Number of AV engines that flagged as malicious
            "vt_suspicious": "",     # Number of AV engines that flagged as suspicious
            "vt_harmless": "",       # Number of AV engines that consider it harmless
            "vt_undetected": "",     # Number of AV engines that didn't detect anything
            "vt_detections": "",     # Summary string: "malicious_count/total_engines"
            "vt_reputation": "",     # VT community reputation score (negative = bad)
            "vt_tags": "",           # VT tags like "miner", "botnet", "tor", "phishing"
            "vt_verdict": "",        # Our computed verdict: MALICIOUS/SUSPICIOUS/CLEAN/etc.
            "vt_link": "",           # Direct link to VT GUI for this IP
        }

    def lookup(self, ip_str: str) -> dict:
        """Query VirusTotal for threat intelligence on a single public IP.

        Workflow:
            1. Check if VT lookups are disabled (bad key or too many failures)
            2. Check if the IP is public (skip private/loopback/multicast)
            3. Check the cache (return immediately if already looked up)
            4. Check the failure counter (disable if threshold exceeded)
            5. Make an authenticated GET request to the VT API v3 IP endpoint
            6. Parse the response to extract detection stats, reputation, and tags
            7. Compute a verdict based on detection thresholds
            8. Cache the result and log notable findings (MALICIOUS/SUSPICIOUS)
            9. Handle HTTP errors: 401 (bad key), 429 (rate limit), 404 (no data)

        Returns:
            A dict with keys: vt_malicious, vt_suspicious, vt_harmless,
            vt_undetected, vt_detections, vt_reputation, vt_tags, vt_verdict,
            vt_link. All values are strings. Empty strings indicate unavailable data.
        """
        empty = self.empty_result()

        # If VT has been disabled (bad API key or too many failures), skip immediately
        if self._disabled:
            return empty

        # Only public IPs are worth checking against VT
        if not is_public_ip(ip_str):
            return empty

        # Return cached result if we've already queried this IP
        if ip_str in self._cache:
            return self._cache[ip_str]

        # After too many consecutive failures, disable VT to avoid wasting time
        if self._failures >= self._max_consecutive_failures:
            vollog.warning(
                "[VT] Too many consecutive API failures; disabling further VT lookups. "
                "Check your API key and network connectivity."
            )
            self._disabled = True
            return empty

        try:
            self._rate_limit()
            self._total_lookups += 1

            # Build the authenticated API request.
            # VT API v3 uses the x-apikey header for authentication (not URL params).
            url = self.API_URL.format(ip=ip_str)
            req = urllib.request.Request(url, headers={
                "x-apikey": self._api_key,
                "Accept": "application/json",
                "User-Agent": "Volatility3-NetScanEnriched/2.0",
            })

            vollog.info(f"[VT] Querying IP #{self._total_lookups}: {ip_str}")

            with urllib.request.urlopen(req, timeout=15) as resp:
                self._last_request_time = time.time()
                data = json.loads(resp.read().decode("utf-8"))

            # Parse the VT response structure:
            # data.data.attributes.last_analysis_stats contains the detection counts
            # data.data.attributes.reputation is the community reputation score
            # data.data.attributes.tags is a list of descriptive tags
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            # Extract individual detection counts from the analysis stats.
            # "malicious" = engines that positively identify this IP as a threat
            # "suspicious" = engines that flag it as potentially harmful
            # "harmless" = engines that explicitly consider it safe
            # "undetected" = engines that have no opinion (didn't scan or no match)
            # "timeout" = engines that timed out during analysis
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            timeout_count = int(stats.get("timeout", 0))
            total = malicious + suspicious + harmless + undetected + timeout_count

            # The reputation score is a community-voted integer.
            # Positive values indicate a good reputation, negative values indicate
            # the community has flagged this IP as malicious. It's separate from
            # the AV engine detections and provides a "wisdom of the crowd" signal.
            reputation = attrs.get("reputation", 0)

            # Tags are descriptive labels applied by VT, such as:
            # "miner" (cryptocurrency mining), "botnet", "tor" (Tor exit node),
            # "phishing", "malware", etc.
            tags = attrs.get("tags", [])

            # Compute a simplified verdict based on detection thresholds.
            # These thresholds balance sensitivity vs. false positives:
            #   - 5+ malicious = high confidence threat
            #   - 1+ malicious or 3+ suspicious = warrants investigation
            #   - 0 malicious and 0 suspicious = likely clean
            if malicious >= 5:
                verdict = "MALICIOUS"
            elif malicious >= 1 or suspicious >= 3:
                verdict = "SUSPICIOUS"
            elif total > 0 and malicious == 0 and suspicious == 0:
                verdict = "CLEAN"
            else:
                verdict = "UNKNOWN"

            result = {
                "vt_malicious": str(malicious),
                "vt_suspicious": str(suspicious),
                "vt_harmless": str(harmless),
                "vt_undetected": str(undetected),
                "vt_detections": f"{malicious}/{total}",   # e.g., "3/87"
                "vt_reputation": str(reputation),
                "vt_tags": ", ".join(tags) if tags else "",
                "vt_verdict": verdict,
                "vt_link": self.GUI_URL.format(ip=ip_str),
            }

            self._failures = 0  # Reset failure counter on success
            self._cache[ip_str] = result

            # Log notable findings immediately so the analyst can see them in
            # real-time during long scans (VT lookups can take several minutes
            # for many unique IPs). MALICIOUS findings are logged as warnings
            # so they stand out even at default verbosity levels.
            if verdict == "MALICIOUS":
                vollog.warning(
                    f"[VT] *** MALICIOUS ***: {ip_str} ({malicious}/{total} detections, "
                    f"reputation={reputation}, tags={tags})"
                )
            elif verdict == "SUSPICIOUS":
                vollog.warning(
                    f"[VT] SUSPICIOUS: {ip_str} ({malicious}/{total} detections, "
                    f"reputation={reputation})"
                )
            else:
                vollog.info(
                    f"[VT] {verdict}: {ip_str} ({malicious}/{total} detections, "
                    f"reputation={reputation})"
                )

            return result

        except urllib.error.HTTPError as e:
            self._last_request_time = time.time()

            if e.code == 401:
                # HTTP 401 Unauthorized: the API key is invalid or has been revoked.
                # Disable all further VT lookups since every request will fail.
                vollog.error(
                    "[VT] API key is invalid or unauthorized (HTTP 401). "
                    "Disabling VirusTotal lookups for this run."
                )
                self._disabled = True

            elif e.code == 429:
                # HTTP 429 Too Many Requests: we've exceeded the rate limit.
                # This can happen if the analyst runs multiple scans in parallel
                # or if the key's quota has been exhausted. Wait 60 seconds and
                # the next IP lookup will retry automatically.
                vollog.warning(
                    "[VT] Rate limit exceeded (HTTP 429). "
                    "Waiting 60s before retrying. Consider upgrading to a premium VT API key."
                )
                time.sleep(60)
                self._failures += 1

            elif e.code == 404:
                # HTTP 404 Not Found: VT has no record for this IP address.
                # This is not an error; it just means no one has ever submitted
                # or scanned this IP on VT. Cache it as NO_DATA so we don't
                # waste a request if the same IP appears again.
                vollog.debug(f"[VT] No record found for {ip_str} (HTTP 404)")
                result = dict(empty)
                result["vt_verdict"] = "NO_DATA"
                result["vt_link"] = self.GUI_URL.format(ip=ip_str)
                self._cache[ip_str] = result
                return result

            else:
                self._failures += 1
                vollog.debug(f"[VT] HTTP {e.code} for {ip_str}: {e.reason}")

        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as e:
            # Catch-all for network errors (DNS resolution failure, connection timeout,
            # SSL errors), malformed JSON responses, or other unexpected issues
            self._failures += 1
            self._last_request_time = time.time()
            vollog.debug(f"[VT] Lookup failed for {ip_str}: {e}")

        return empty

    def get_summary(self) -> str:
        """Generate a one-line summary of all VT lookups performed during this scan.

        Called at the end of the scan and logged at WARNING level so it's visible
        even without verbose mode. Gives the analyst a quick overview like:
        "VT Summary: 14 IPs checked (2 MALICIOUS, 1 SUSPICIOUS, 11 CLEAN)"
        """
        if not self._cache:
            return "No VT lookups performed."

        mal_count = sum(1 for v in self._cache.values() if v.get("vt_verdict") == "MALICIOUS")
        sus_count = sum(1 for v in self._cache.values() if v.get("vt_verdict") == "SUSPICIOUS")
        clean_count = sum(1 for v in self._cache.values() if v.get("vt_verdict") == "CLEAN")
        total = len(self._cache)

        return (
            f"VT Summary: {total} IPs checked ("
            f"{mal_count} MALICIOUS, {sus_count} SUSPICIOUS, {clean_count} CLEAN)"
        )


# =============================================================================
# PLUGIN CLASS: NetScanEnriched
# =============================================================================
# This is the main Volatility 3 plugin class. It inherits the core netscan
# functionality (pool scanning for TCP/UDP network objects in memory) from the
# original Volatility Foundation code, and adds the enrichment pipeline on top.
#
# The original methods (create_netscan_constraints, determine_tcpip_version,
# create_netscan_symbol_table, scan) are preserved as-is from the upstream
# netscan plugin. Only the _generator, _build_enriched_row, generate_timeline,
# and run methods are modified to incorporate the enrichment data.
# =============================================================================

class NetScanEnriched(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for network objects in a Windows memory image and enriches IPs
    with geolocation, reverse DNS, ASN/ISP, VirusTotal threat intel, and
    forensic flags."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        reqs = [
            # --- Original netscan requirements (unchanged) ---
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="include-corrupt",
                description="Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!",
                default=False,
                optional=True,
            ),
            # --- NEW: Enrichment flag ---
            # When set, the plugin will make live API calls to ip-api.com for each
            # unique public IP found in the memory image. Without this flag, only
            # offline enrichment (IP classification, port labeling, suspicious port
            # flagging) is performed.
            requirements.BooleanRequirement(
                name="enrich",
                description="Enable live IP enrichment via internet lookup (geolocation, reverse DNS, ASN/ISP). Requires network access. Without this flag, only offline analysis (IP classification, port services, forensic flags) is performed.",
                default=False,
                optional=True,
            ),
            # --- NEW: VirusTotal API key ---
            # Accepts the user's VT API key directly on the command line. If not
            # provided, the plugin also checks the VT_API_KEY environment variable
            # as a fallback (convenient for scripted/automated workflows). The VT
            # lookup runs independently of --enrich, so you can use VT alone without
            # geolocation if desired.
            requirements.StringRequirement(
                name="vtkey",
                description="VirusTotal API v3 key (free or premium). Each unique public IP will be checked against VT threat database. If omitted, falls back to VT_API_KEY environment variable. Free tier is rate-limited to 4 requests/minute (~15s per IP).",
                default=None,
                optional=True,
            ),
        ]
        # Conditionally add verinfo dependency only if it's available in this
        # Volatility 3 build (see the try/except import at the top of this file)
        if HAS_VERINFO:
            reqs.insert(4, requirements.VersionRequirement(
                name="verinfo", component=verinfo.VerInfo, version=(1, 0, 0)
            ))
        return reqs

    # =========================================================================
    # ORIGINAL NETSCAN INFRASTRUCTURE (unchanged from upstream)
    # =========================================================================
    # The following four methods are copied directly from the original Volatility
    # Foundation netscan plugin. They handle the low-level work of:
    #   - Defining pool tag constraints for TcpL, TcpE, UdpA objects
    #   - Determining the correct tcpip.sys symbol file based on Windows version
    #   - Creating the intermediate symbol table for network structures
    #   - Scanning physical memory for pool-tagged network objects

    @classmethod
    def create_netscan_constraints(
        cls, context: interfaces.context.ContextInterface, symbol_table: str
    ) -> List[poolscanner.PoolConstraint]:
        """Creates Pool Tag Constraints for network objects (identical to original)."""
        tcpl_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_TCP_LISTENER"
        ).size
        tcpe_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_TCP_ENDPOINT"
        ).size
        udpa_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_UDP_ENDPOINT"
        ).size

        constraints = [
            poolscanner.PoolConstraint(
                b"TcpL",
                type_name=symbol_table + constants.BANG + "_TCP_LISTENER",
                size=(tcpl_size, None),
                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
            ),
            poolscanner.PoolConstraint(
                b"TcpE",
                type_name=symbol_table + constants.BANG + "_TCP_ENDPOINT",
                size=(tcpe_size, None),
                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
            ),
            poolscanner.PoolConstraint(
                b"UdpA",
                type_name=symbol_table + constants.BANG + "_UDP_ENDPOINT",
                size=(udpa_size, None),
                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
            ),
        ]

        if symbol_table.startswith("netscan-win10-20348"):
            vollog.debug("Adding additional pool constraint for `TTcb` tags")
            constraints.append(
                poolscanner.PoolConstraint(
                    b"TTcb",
                    type_name=symbol_table + constants.BANG + "_TCP_ENDPOINT",
                    size=(tcpe_size, None),
                    page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
                )
            )

        return constraints

    @classmethod
    def determine_tcpip_version(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Tuple[str, Type]:
        """Determines which symbol filename to use for the image's tcpip driver."""

        kernel = context.modules[kernel_module_name]

        is_64bit = symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=kernel.symbol_table_name
        )

        is_18363_or_later = versions.is_win10_18363_or_later(
            context=context, symbol_table=kernel.symbol_table_name
        )

        if is_64bit:
            arch = "x64"
        else:
            arch = "x86"

        vers = info.Info.get_version_structure(context, kernel_module_name)
        kuser = info.Info.get_kuser_structure(context, kernel_module_name)

        try:
            vers_minor_version = int(vers.MinorVersion)
            nt_major_version = int(kuser.NtMajorVersion)
            nt_minor_version = int(kuser.NtMinorVersion)
        except ValueError:
            raise NotImplementedError(
                "Kernel Debug Structure version format not supported!"
            )
        except Exception:
            raise exceptions.VolatilityException(
                "Kernel Debug Structure missing VERSION/KUSER structure, unable to determine Windows version!"
            )

        vollog.debug(
            f"Determined OS Version: {kuser.NtMajorVersion}.{kuser.NtMinorVersion} {vers.MajorVersion}.{vers.MinorVersion}"
        )

        if nt_major_version == 10 and arch == "x64":
            class_types = network.win10_x64_class_types
        else:
            class_types = network.class_types

        if arch == "x86":
            version_dict = {
                (6, 0, 6000, 0): "netscan-vista-x86",
                (6, 0, 6001, 0): "netscan-vista-x86",
                (6, 0, 6002, 0): "netscan-vista-x86",
                (6, 0, 6003, 0): "netscan-vista-x86",
                (6, 1, 7600, 0): "netscan-win7-x86",
                (6, 1, 7601, 0): "netscan-win7-x86",
                (6, 1, 8400, 0): "netscan-win7-x86",
                (6, 2, 9200, 0): "netscan-win8-x86",
                (6, 3, 9600, 0): "netscan-win81-x86",
                (10, 0, 10240, 0): "netscan-win10-10240-x86",
                (10, 0, 10586, 0): "netscan-win10-10586-x86",
                (10, 0, 14393, 0): "netscan-win10-14393-x86",
                (10, 0, 15063, 0): "netscan-win10-15063-x86",
                (10, 0, 16299, 0): "netscan-win10-15063-x86",
                (10, 0, 17134, 0): "netscan-win10-17134-x86",
                (10, 0, 17763, 0): "netscan-win10-17134-x86",
                (10, 0, 18362, 0): "netscan-win10-17134-x86",
                (10, 0, 18363, 0): "netscan-win10-17134-x86",
            }
        else:
            version_dict = {
                (6, 0, 6000, 0): "netscan-vista-x64",
                (6, 0, 6001, 0): "netscan-vista-sp12-x64",
                (6, 0, 6002, 0): "netscan-vista-sp12-x64",
                (6, 0, 6003, 0): "netscan-vista-sp12-x64",
                (6, 1, 7600, 0): "netscan-win7-x64",
                (6, 1, 7601, 0): "netscan-win7-x64",
                (6, 1, 8400, 0): "netscan-win7-x64",
                (6, 2, 9200, 0): "netscan-win8-x64",
                (6, 3, 9600, 0): "netscan-win81-x64",
                (6, 3, 9600, 19935): "netscan-win81-19935-x64",
                (10, 0, 10240, 0): "netscan-win10-x64",
                (10, 0, 10586, 0): "netscan-win10-x64",
                (10, 0, 14393, 0): "netscan-win10-x64",
                (10, 0, 15063, 0): "netscan-win10-15063-x64",
                (10, 0, 16299, 0): "netscan-win10-16299-x64",
                (10, 0, 17134, 0): "netscan-win10-17134-x64",
                (10, 0, 17763, 0): "netscan-win10-17763-x64",
                (10, 0, 18362, 0): "netscan-win10-18362-x64",
                (10, 0, 18363, 0): "netscan-win10-18363-x64",
                (10, 0, 19041, 0): "netscan-win10-19041-x64",
                (10, 0, 20348, 0): "netscan-win10-20348-x64",
            }

        tcpip_mod_version = 0

        if vers_minor_version == 18362 and is_18363_or_later:
            vollog.debug(
                "Detected 18363 data structures: working with 18363 symbol table."
            )
            vers_minor_version = 18363

        if [
            (a, b, c, d)
            for a, b, c, d in version_dict
            if (a, b, c) == (nt_major_version, nt_minor_version, vers_minor_version)
            and d != 0
        ]:
            vollog.debug(
                "Requiring further version inspection due to OS version by checking tcpip.sys's FileVersion header"
            )
            physical_layer_name = context.layers[kernel.layer_name].config.get(
                "memory_layer", None
            )
            if physical_layer_name and HAS_VERINFO:
                ver = verinfo.VerInfo.find_version_info(
                    context, physical_layer_name, "tcpip.sys"
                )
                if ver:
                    tcpip_mod_version = ver[3]
                    vollog.debug(
                        f"Determined tcpip.sys's FileVersion: {tcpip_mod_version}"
                    )
                else:
                    vollog.debug("Could not determine tcpip.sys's FileVersion.")
            elif not HAS_VERINFO:
                vollog.debug(
                    "verinfo module not available, skipping FileVersion check."
                )
            else:
                vollog.debug(
                    "Unable to retrieve physical memory layer, skipping FileVersion check."
                )

        filename = version_dict.get(
            (nt_major_version, nt_minor_version, vers_minor_version, tcpip_mod_version)
        )
        if not filename:
            current_versions = [
                (nt_maj, nt_min, vers_min, tcpip_ver)
                for nt_maj, nt_min, vers_min, tcpip_ver in version_dict
                if nt_maj == nt_major_version
                and nt_min == nt_minor_version
                and tcpip_ver <= tcpip_mod_version
            ]
            current_versions.sort()

            if current_versions:
                latest_version = current_versions[-1]
                filename = version_dict.get(latest_version)
                vollog.debug(
                    f"Unable to find exact matching symbol file, going with latest: {filename}"
                )
            else:
                raise NotImplementedError(
                    f"This version of Windows is not supported: {nt_major_version}.{nt_minor_version} {vers.MajorVersion}.{vers_minor_version}!"
                )

        vollog.debug(f"Determined symbol filename: {filename}")

        return filename, class_types

    @classmethod
    def create_netscan_symbol_table(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        config_path: str,
    ) -> str:
        """Creates a symbol table for TCP Listeners and TCP/UDP Endpoints."""
        kernel = context.modules[kernel_module_name]
        table_mapping = {"nt_symbols": kernel.symbol_table_name}
        symbol_filename, class_types = cls.determine_tcpip_version(
            context, kernel_module_name,
        )
        return intermed.IntermediateSymbolTable.create(
            context, config_path,
            os.path.join("windows", "netscan"),
            symbol_filename,
            class_types=class_types,
            table_mapping=table_mapping,
        )

    @classmethod
    def scan(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        netscan_symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for network objects using the poolscanner module."""
        constraints = cls.create_netscan_constraints(context, netscan_symbol_table)
        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, kernel_module_name, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object

    # =========================================================================
    # NEW: VT API Key Resolution
    # =========================================================================

    def _resolve_vt_key(self) -> Optional[str]:
        """Resolve the VirusTotal API key from available sources.

        Checks two sources in order of priority:
            1. The --vtkey command-line argument (self.config["vtkey"])
            2. The VT_API_KEY environment variable

        The environment variable fallback is useful for:
            - Automated/scripted workflows where you don't want the key in command history
            - CI/CD pipelines that inject secrets via environment
            - Analysts who run many scans and don't want to type the key each time

        Returns:
            The API key string if found, or None if neither source provides one.
        """
        key = self.config.get("vtkey", None)
        if key:
            return key
        env_key = os.environ.get("VT_API_KEY", "").strip()
        if env_key:
            vollog.info("Using VirusTotal API key from VT_API_KEY environment variable.")
            return env_key
        return None

    # =========================================================================
    # NEW: Enhanced Generator (replaces original _generator)
    # =========================================================================

    def _generator(self, show_corrupt_results: Optional[bool] = None):
        """Generates enriched network connection rows for the output table.

        This method replaces the original netscan _generator. It performs the same
        core memory scanning (via self.scan()), but for each network object found,
        it passes the connection data through _build_enriched_row() which adds
        the offline analysis, geolocation, and VirusTotal columns.

        The enrichment engines (IPEnrichmentCache and VirusTotalCache) are
        instantiated here based on the user's flags:
            - --enrich flag    -> creates an IPEnrichmentCache for geo/DNS lookups
            - --vtkey or env   -> creates a VirusTotalCache for threat intel lookups
            - Neither          -> only offline enrichment (IP classification, port labels, flags)

        At the end of the scan, if VT was used, a summary line is logged showing
        how many IPs were MALICIOUS, SUSPICIOUS, and CLEAN.
        """
        netscan_symbol_table = self.create_netscan_symbol_table(
            self.context, self.config["kernel"], self.config_path
        )

        # Initialize the geolocation/DNS enricher if --enrich flag was set
        do_enrich = self.config.get("enrich", False)
        enricher = IPEnrichmentCache() if do_enrich else None

        # Initialize the VirusTotal checker if an API key is available
        vt_key = self._resolve_vt_key()
        vt_checker = None
        if vt_key:
            vt_checker = VirusTotalCache(vt_key)
            vollog.warning(
                "VirusTotal lookups ENABLED: each unique public IP will be checked. "
                "Free tier: ~4 req/min (expect ~15s per new unique IP)."
            )
        else:
            vollog.info(
                "VirusTotal DISABLED: no API key provided. "
                "Use --vtkey YOUR_KEY or set VT_API_KEY env var to enable."
            )

        if do_enrich:
            vollog.info("Geo/DNS enrichment ENABLED via ip-api.com")
        else:
            vollog.info("Geo/DNS enrichment DISABLED: use --enrich for live lookups.")

        # Core scan loop: identical structure to the original netscan, but each
        # network object is passed through _build_enriched_row instead of being
        # yielded directly. The enricher and vt_checker are passed along so that
        # _build_enriched_row can query them for each connection's IP.
        for netw_obj in self.scan(
            self.context, self.config["kernel"], netscan_symbol_table,
        ):
            vollog.debug(
                f"Found netw obj @ 0x{netw_obj.vol.offset:2x} of assumed type {type(netw_obj)}"
            )
            if not show_corrupt_results and not netw_obj.is_valid():
                continue

            # --- UDP Endpoints ---
            # For UDP, the state is always blank and the remote end is wildcards
            if isinstance(netw_obj, network._UDP_ENDPOINT):
                for ver, laddr, _ in netw_obj.dual_stack_sockets():
                    yield self._build_enriched_row(
                        netw_obj, "UDP" + ver, laddr, netw_obj.Port,
                        "*", 0, "", enricher, vt_checker,
                    )

            # --- TCP Endpoints (established/active connections) ---
            elif isinstance(netw_obj, network._TCP_ENDPOINT):
                if netw_obj.get_address_family() == network.AF_INET:
                    proto = "TCPv4"
                elif netw_obj.get_address_family() == network.AF_INET6:
                    proto = "TCPv6"
                else:
                    proto = "TCPv?"

                try:
                    state = netw_obj.State.description
                except ValueError:
                    state = renderers.UnreadableValue()

                yield self._build_enriched_row(
                    netw_obj, proto,
                    netw_obj.get_local_address() or renderers.UnreadableValue(),
                    netw_obj.LocalPort,
                    netw_obj.get_remote_address() or renderers.UnreadableValue(),
                    netw_obj.RemotePort,
                    state, enricher, vt_checker,
                )

            # --- TCP Listeners (listening sockets) ---
            # For listeners, the state is always LISTENING and the remote port is zero
            elif isinstance(netw_obj, network._TCP_LISTENER):
                for ver, laddr, raddr in netw_obj.dual_stack_sockets():
                    yield self._build_enriched_row(
                        netw_obj, "TCP" + ver, laddr, netw_obj.Port,
                        raddr, 0, "LISTENING", enricher, vt_checker,
                    )
            else:
                vollog.debug(
                    f"Found network object unsure of its type: {netw_obj} of type {type(netw_obj)}"
                )

        # After all connections have been processed, print a VT summary so the
        # analyst immediately knows how many threats were found without scrolling
        if vt_checker:
            vollog.warning(vt_checker.get_summary())

    # =========================================================================
    # NEW: Enriched Row Builder
    # =========================================================================

    def _build_enriched_row(self, netw_obj, proto, local_addr, local_port,
                            foreign_addr, foreign_port, state, enricher, vt_checker):
        """Construct a single output row with all original + enrichment columns.

        This is the core of the enrichment pipeline. For each network connection
        found in memory, this method:

            1. Converts addresses and ports to strings/ints for safe processing
               (Volatility objects may be UnreadableValue if memory is corrupt)

            2. Runs OFFLINE enrichment (always, regardless of flags):
               - Classifies the foreign IP (Public/Private/Loopback/etc.)
               - Maps local and foreign ports to service names via WELL_KNOWN_PORTS
               - Checks ports against SUSPICIOUS_PORTS and builds forensic flags

            3. Runs GEOLOCATION enrichment (if enricher is not None):
               - Determines which IP to enrich: prefers the foreign (remote) IP
                 since that's usually the interesting one in forensics; falls back
                 to the local IP if the foreign is not public (e.g., a listener
                 bound to a public-facing interface)
               - Calls enricher.lookup() which returns geo, DNS, ISP, proxy data

            4. Runs VIRUSTOTAL enrichment (if vt_checker is not None):
               - Uses the same IP selection logic as geo enrichment
               - Calls vt_checker.lookup() which returns detection counts, verdict,
                 reputation score, tags, and a GUI link
               - If VT returns MALICIOUS or SUSPICIOUS, appends a flag to the
                 Flags column (e.g., "VT:MALICIOUS(3/87)")

            5. Assembles all data into a tuple matching the TreeGrid column order
               defined in run(). The tuple has 28 elements (indices 0-27):
               Indices 0-11:  Original netscan columns (Offset through Created)
               Indices 12-21: Geo/DNS enrichment columns (IPType through Proxy/VPN)
               Indices 22-26: VirusTotal columns (VT_Detections through VT_Link)
               Index 27:      Forensic Flags (combined from port + VT analysis)

        Args:
            netw_obj:     The Volatility network object (TCP_LISTENER, TCP_ENDPOINT, etc.)
            proto:        Protocol string ("TCPv4", "TCPv6", "UDPv4", etc.)
            local_addr:   Local IP address (string or UnreadableValue)
            local_port:   Local port number (int or UnreadableValue)
            foreign_addr: Foreign/remote IP address (string or UnreadableValue)
            foreign_port: Foreign/remote port number (int or UnreadableValue)
            state:        Connection state ("ESTABLISHED", "LISTENING", etc.)
            enricher:     IPEnrichmentCache instance or None (if --enrich not set)
            vt_checker:   VirusTotalCache instance or None (if no VT API key)

        Returns:
            A (depth, tuple) pair as expected by Volatility's TreeGrid renderer.
            depth is always 0 (flat table, no tree hierarchy).
        """
        # Safely convert Volatility objects to Python primitives.
        # UnreadableValue means the memory at that location was corrupt/paged out.
        la_str = str(local_addr) if not isinstance(local_addr, renderers.UnreadableValue) else ""
        fa_str = str(foreign_addr) if not isinstance(foreign_addr, renderers.UnreadableValue) else ""
        lp_int = int(local_port) if not isinstance(local_port, renderers.UnreadableValue) else 0
        fp_int = int(foreign_port) if not isinstance(foreign_port, renderers.UnreadableValue) else 0

        # ----- Tier 1: Offline enrichment (always runs) -----
        local_class = classify_ip(la_str)
        foreign_class = classify_ip(fa_str)
        local_svc = get_port_service(lp_int)    # e.g., 443 -> "HTTPS"
        foreign_svc = get_port_service(fp_int)   # e.g., 4444 -> "Metasploit-Default"

        # Build forensic flags for suspicious ports.
        # Format: "L:4444-Metasploit-Default" (local) or "R:6667-IRC" (remote)
        flags = []
        if flag_port(lp_int):
            flags.append(f"L:{lp_int}-{WELL_KNOWN_PORTS.get(lp_int, 'SUSPICIOUS')}")
        if flag_port(fp_int):
            flags.append(f"R:{fp_int}-{WELL_KNOWN_PORTS.get(fp_int, 'SUSPICIOUS')}")

        # ----- Determine which IP to enrich -----
        # We prefer the foreign (remote) IP because in incident response, the
        # remote end of the connection is usually what the analyst cares about
        # (who is the victim's machine talking to?). If the foreign IP is not
        # public (e.g., a listener with foreign=*), we fall back to the local IP
        # in case it's a public-facing server with a routable address.
        enrich_ip = ""
        if is_public_ip(fa_str):
            enrich_ip = fa_str
        elif is_public_ip(la_str):
            enrich_ip = la_str

        # ----- Tier 2: Geolocation & DNS enrichment (if --enrich flag is set) -----
        country = region = city = isp = asn = reverse_dns = url_hint = is_hosting = is_proxy = ""

        if enrich_ip and enricher:
            info_data = enricher.lookup(enrich_ip)
            country = info_data["country"]          # e.g., "United States"
            region = info_data["region"]             # e.g., "California"
            city = info_data["city"]                 # e.g., "Mountain View"
            isp = info_data["isp"]                   # e.g., "Google LLC"
            asn = info_data["asn"]                   # e.g., "AS15169 Google LLC"
            reverse_dns = info_data["reverse_dns"]   # e.g., "lax17s61-in-f14.1e100.net"
            url_hint = info_data["url_hint"]         # e.g., "https://www.google.com"
            is_hosting = info_data["is_hosting"]     # "Yes" or "No"
            is_proxy = info_data["is_proxy"]         # "Yes" or "No"

        # ----- Tier 3: VirusTotal threat intelligence (if VT API key provided) -----
        vt_detections = vt_verdict = vt_reputation = vt_tags = vt_link = ""

        if enrich_ip and vt_checker:
            vt_data = vt_checker.lookup(enrich_ip)
            vt_detections = vt_data["vt_detections"]   # e.g., "3/87" (3 of 87 engines flagged)
            vt_verdict = vt_data["vt_verdict"]         # e.g., "MALICIOUS"
            vt_reputation = vt_data["vt_reputation"]   # e.g., "-47" (negative = bad)
            vt_tags = vt_data["vt_tags"]               # e.g., "botnet, miner"
            vt_link = vt_data["vt_link"]               # e.g., "https://www.virustotal.com/gui/ip-address/1.2.3.4"

            # Append VT findings to the forensic flags column so they're visible
            # even in wide tables where the VT columns might be scrolled offscreen
            if vt_verdict == "MALICIOUS":
                flags.append(f"VT:MALICIOUS({vt_detections})")
            elif vt_verdict == "SUSPICIOUS":
                flags.append(f"VT:SUSPICIOUS({vt_detections})")

        # Combine all forensic flags into a single semicolon-separated string
        forensic_flags = "; ".join(flags) if flags else ""

        # Assemble the output tuple. The order must exactly match the TreeGrid
        # column definitions in run() below.
        return (
            0,  # Tree depth (always 0 for flat output)
            (
                format_hints.Hex(netw_obj.vol.offset),           # 0  Offset
                proto,                                            # 1  Proto
                local_addr,                                       # 2  LocalAddr
                local_port,                                       # 3  LocalPort
                local_svc,                                        # 4  LocalPortSvc     [NEW]
                foreign_addr,                                     # 5  ForeignAddr
                foreign_port,                                     # 6  ForeignPort
                foreign_svc,                                      # 7  ForeignPortSvc   [NEW]
                state,                                            # 8  State
                netw_obj.get_owner_pid() or renderers.UnreadableValue(),   # 9  PID
                netw_obj.get_owner_procname() or renderers.UnreadableValue(),  # 10 Owner
                netw_obj.get_create_time() or renderers.UnreadableValue(),     # 11 Created
                foreign_class,                                    # 12 IPType           [NEW]
                country,                                          # 13 Country          [NEW]
                region,                                           # 14 Region           [NEW]
                city,                                             # 15 City             [NEW]
                isp,                                              # 16 ISP              [NEW]
                asn,                                              # 17 ASN              [NEW]
                reverse_dns,                                      # 18 ReverseDNS       [NEW]
                url_hint,                                         # 19 URLHint          [NEW]
                is_hosting,                                       # 20 Hosting          [NEW]
                is_proxy,                                         # 21 Proxy/VPN        [NEW]
                vt_detections,                                    # 22 VT_Detections    [NEW]
                vt_verdict,                                       # 23 VT_Verdict       [NEW]
                vt_reputation,                                    # 24 VT_Reputation    [NEW]
                vt_tags,                                          # 25 VT_Tags          [NEW]
                vt_link,                                          # 26 VT_Link          [NEW]
                forensic_flags,                                   # 27 Flags            [NEW]
            ),
        )

    # =========================================================================
    # MODIFIED: Timeline Generator (adds enrichment data to timeline entries)
    # =========================================================================

    def generate_timeline(self):
        """Generate timeline entries for the timeliner plugin.

        Same as the original netscan timeline generator, but the description
        string now includes enrichment data (country, ISP, DNS, VT verdict)
        so that timeline analysis shows geographic and threat context alongside
        each network connection event.

        Note: row_data indices have shifted compared to the original netscan
        because we inserted new columns (LocalPortSvc, ForeignPortSvc, etc.)
        between the original columns. The Created timestamp is now at index 11
        (was index 9 in the original).
        """
        for row in self._generator():
            _depth, row_data = row
            # Skip connections without a creation timestamp
            if not isinstance(row_data[11], datetime.datetime):
                continue
            row_data = [
                (
                    "N/A"
                    if isinstance(i, renderers.UnreadableValue)
                    or isinstance(i, renderers.UnparsableValue)
                    else i
                )
                for i in row_data
            ]
            # Build an enriched description string for the timeline entry.
            # Includes country, ISP, reverse DNS, and VT verdict when available.
            description = (
                f"Network connection: Process {row_data[9]} {row_data[10]} "
                f"Local Address {row_data[2]}:{row_data[3]} "
                f"Remote Address {row_data[5]}:{row_data[6]} "
                f"State {row_data[8]} Protocol {row_data[1]} "
                f"Country {row_data[13]} ISP {row_data[16]} "
                f"DNS {row_data[18]} "
                f"VT:{row_data[23]}({row_data[22]})"
            )
            yield (description, timeliner.TimeLinerType.CREATED, row_data[11])

    # =========================================================================
    # MODIFIED: Run Method (expanded column definitions for enriched output)
    # =========================================================================

    def run(self):
        """Execute the plugin and return the enriched results table.

        The TreeGrid column list defines the output schema. Compared to the
        original netscan plugin which has 10 columns (Offset through Created),
        this enriched version adds 18 new columns for a total of 28:

        Original columns (0-3, 5-6, 8-11):
            Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort,
            State, PID, Owner, Created

        New enrichment columns (4, 7, 12-27):
            LocalPortSvc:   Well-known service name for the local port
            ForeignPortSvc: Well-known service name for the foreign port
            IPType:         IP classification (Public, Private, Loopback, etc.)
            Country:        Country where the IP is geolocated
            Region:         State or region within the country
            City:           City where the IP is geolocated
            ISP:            Internet Service Provider that owns the IP
            ASN:            Autonomous System Number and name
            ReverseDNS:     Reverse DNS (PTR record) hostname
            URLHint:        Auto-generated website URL from reverse DNS
            Hosting:        Whether ip-api.com identifies this as a hosting provider
            Proxy/VPN:      Whether ip-api.com identifies this as a VPN/proxy
            VT_Detections:  VirusTotal detection ratio (e.g., "3/87")
            VT_Verdict:     Computed verdict (MALICIOUS/SUSPICIOUS/CLEAN/etc.)
            VT_Reputation:  VT community reputation score
            VT_Tags:        VT tags (e.g., "botnet, miner, tor")
            VT_Link:        Direct link to VirusTotal GUI for this IP
            Flags:          Combined forensic flags (suspicious ports + VT alerts)
        """
        show_corrupt_results = self.config.get("include-corrupt", None)

        return renderers.TreeGrid(
            [
                # --- Original netscan columns ---
                ("Offset", format_hints.Hex),
                ("Proto", str),
                ("LocalAddr", str),
                ("LocalPort", int),
                # --- NEW columns start here ---
                ("LocalPortSvc", str),
                # --- Original columns continue ---
                ("ForeignAddr", str),
                ("ForeignPort", int),
                # --- NEW ---
                ("ForeignPortSvc", str),
                # --- Original columns continue ---
                ("State", str),
                ("PID", int),
                ("Owner", str),
                ("Created", datetime.datetime),
                # --- All remaining columns are NEW ---
                ("IPType", str),
                ("Country", str),
                ("Region", str),
                ("City", str),
                ("ISP", str),
                ("ASN", str),
                ("ReverseDNS", str),
                ("URLHint", str),
                ("Hosting", str),
                ("Proxy/VPN", str),
                ("VT_Detections", str),
                ("VT_Verdict", str),
                ("VT_Reputation", str),
                ("VT_Tags", str),
                ("VT_Link", str),
                ("Flags", str),
            ],
            self._generator(show_corrupt_results=show_corrupt_results),
        )
