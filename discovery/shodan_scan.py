"""
Targeted Shodan Xtream Codes Discovery Scanner.
Specifically queries Shodan for Xtream Codes signatures, panels, and player_api endpoints
instead of blind IP sampling.

Features:
  1. Targeted Shodan Dorks (e.g. http.html:"player_api.php", http.title:"Xtream Codes")
  2. Public Shodan Web Search Scraper (no API key required)
  3. Optional Shodan API Search (if API key is configured)
  4. Search Engine Dorking fallback (DuckDuckGo / Bing for player_api.php)
  5. InternetDB Port Enrichment (discovers all open streaming ports for found IPs)
"""
import re
import json
import logging
import time
import threading
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

# Targeted queries designed to find authentic Xtream Codes / XUI panels
# Works across standard keyword search and filter-enabled plans
SHODAN_XTREAM_DORKS = [
    'player_api.php',
    '"Undefined index: username"',
    'xtream-codes',
    'xui.one',
    'http.html:"player_api.php"',
    'http.title:"Xtream Codes"',
]

# Public web search dorks for indexing engines (DuckDuckGo / Bing)
WEB_DORKS = [
    'inurl:"/player_api.php" "Undefined index: username"',
    'inurl:"/player_api.php" "user_info"',
    'inurl:"/player_api.php?username="',
    'site:shodan.io "player_api.php"',
]

SHODAN_SEARCH_URL = "https://www.shodan.io/search?query={query}&page={page}"
SHODAN_API_URL = "https://api.shodan.io/shodan/host/search?key={api_key}&query={query}&page={page}"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

import ipaddress
import random

# Common Xtream Codes ports
XTREAM_PORTS = {80, 8080, 8000, 25461, 2082, 2086, 8880, 25462, 25463, 8001, 8081}

# Top European & Global VPS Hosting Ranges frequently hosting streaming servers
POPULAR_HOSTING_RANGES = [
    # Contabo
    {"name": "Contabo DE", "cidr": "62.171.128.0/17"},
    {"name": "Contabo DE-2", "cidr": "144.91.64.0/18"},
    {"name": "Contabo DE-3", "cidr": "161.97.64.0/18"},
    {"name": "Contabo DE-4", "cidr": "167.86.64.0/18"},
    {"name": "Contabo DE-5", "cidr": "173.249.0.0/17"},
    {"name": "Contabo DE-6", "cidr": "194.163.128.0/18"},
    {"name": "Contabo US", "cidr": "213.136.64.0/18"},
    {"name": "Contabo US-2", "cidr": "209.126.0.0/18"},
    {"name": "Contabo SG", "cidr": "194.233.64.0/18"},
    # Hetzner
    {"name": "Hetzner DE", "cidr": "78.46.0.0/15"},
    {"name": "Hetzner DE-2", "cidr": "116.202.0.0/15"},
    {"name": "Hetzner DE-3", "cidr": "168.119.0.0/16"},
    {"name": "Hetzner FI", "cidr": "95.216.0.0/15"},
    {"name": "Hetzner FI-2", "cidr": "65.108.0.0/15"},
    # OVH
    {"name": "OVH FR", "cidr": "51.68.0.0/14"},
    {"name": "OVH FR-2", "cidr": "51.75.0.0/15"},
    {"name": "OVH FR-3", "cidr": "51.77.0.0/16"},
    {"name": "OVH FR-4", "cidr": "51.79.0.0/16"},
    {"name": "OVH FR-5", "cidr": "51.83.0.0/16"},
    {"name": "OVH FR-6", "cidr": "51.89.0.0/16"},
    {"name": "OVH FR-7", "cidr": "51.91.0.0/16"},
    {"name": "OVH CA", "cidr": "144.217.0.0/16"},
    {"name": "OVH CA-2", "cidr": "149.56.0.0/16"},
    {"name": "OVH PL", "cidr": "147.135.128.0/17"},
    {"name": "OVH UK", "cidr": "151.80.0.0/16"},
    {"name": "OVH DE", "cidr": "188.165.0.0/16"},
    # Scaleway
    {"name": "Scaleway FR", "cidr": "51.15.0.0/16"},
    {"name": "Scaleway NL", "cidr": "51.158.0.0/16"},
    {"name": "Scaleway PL", "cidr": "51.159.0.0/16"},
    # DigitalOcean
    {"name": "DigitalOcean", "cidr": "64.227.0.0/16"},
    {"name": "DigitalOcean-2", "cidr": "134.209.0.0/16"},
    {"name": "DigitalOcean-3", "cidr": "159.65.0.0/16"},
    {"name": "DigitalOcean-4", "cidr": "165.22.0.0/16"},
    {"name": "DigitalOcean-5", "cidr": "167.99.0.0/16"},
    # Vultr
    {"name": "Vultr", "cidr": "45.32.0.0/16"},
    {"name": "Vultr-2", "cidr": "45.63.0.0/16"},
    {"name": "Vultr-3", "cidr": "45.76.0.0/16"},
    {"name": "Vultr-4", "cidr": "45.77.0.0/16"},
    # IONOS / 1&1
    {"name": "IONOS", "cidr": "217.160.0.0/16"},
]

# Regex to extract IPv4 addresses
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
# Regex to extract host:port patterns
HOST_PORT_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})')
# Regex to extract Shodan host links
SHODAN_HOST_LINK_RE = re.compile(r'/host/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


class TargetedShodanScanner:
    """Discovers Xtream Codes panels by searching Shodan for exact API signatures."""

    def __init__(self, api_key=None, max_pages=3, timeout=12, stop_event=None):
        """
        Args:
            api_key: Optional Shodan REST API key.
            max_pages: Maximum search result pages to query per dork.
            timeout: HTTP request timeout in seconds.
            stop_event: Threading event to signal stop.
        """
        self.api_key = api_key
        self.max_pages = max_pages
        self.timeout = timeout
        self.stop_event = stop_event or threading.Event()
        self.discovered_hosts = []
        self._lock = threading.Lock()

    def _enrich_ip_ports(self, ip):
        """Query InternetDB for a discovered IP to find all open streaming ports."""
        if self.stop_event.is_set():
            return []

        url = INTERNETDB_URL.format(ip=ip)
        results = []
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            open_ports = set(data.get('ports', []))
            xtream_ports_found = open_ports & XTREAM_PORTS

            hostnames = data.get('hostnames', [])
            host = hostnames[0] if hostnames else ip

            if xtream_ports_found:
                for port in xtream_ports_found:
                    results.append({
                        'host': host,
                        'port': port,
                        'ip': ip,
                        'source': 'Shodan-Targeted'
                    })
            else:
                # Default to port 80 and 8080 if not indexed
                for port in [80, 8080]:
                    results.append({
                        'host': host,
                        'port': port,
                        'ip': ip,
                        'source': 'Shodan-Targeted'
                    })
        except Exception:
            # Fallback if InternetDB has no record
            for port in [80, 8080]:
                results.append({
                    'host': ip,
                    'port': port,
                    'ip': ip,
                    'source': 'Shodan-Targeted'
                })
        return results

    def _scrape_shodan_dork(self, query, page=1):
        """Scrape public Shodan search results for a specific query."""
        if self.stop_event.is_set():
            return []

        encoded_q = urllib.parse.quote(query)
        url = SHODAN_SEARCH_URL.format(query=encoded_q, page=page)
        found_ips = set()

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                html = resp.read().decode('utf-8', errors='ignore')

            # Extract IPs from /host/<ip> links
            for ip in SHODAN_HOST_LINK_RE.findall(html):
                found_ips.add(ip)

            # Extract any other IP occurrences in search results
            for ip in IP_RE.findall(html):
                # Filter out standard non-routable / local IPs
                if not (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('0.')):
                    found_ips.add(ip)

            if found_ips:
                log.info(f"  🔍 Shodan Search (page {page}): Found {len(found_ips)} IPs for query: {query}")

        except urllib.error.HTTPError as e:
            if e.code == 429:
                log.warning("  ⏳ Shodan search rate limited, cooling down 10s...")
                time.sleep(10)
            elif e.code == 403:
                log.warning("  ⚠️ Shodan requires login for extended search pages.")
        except Exception as e:
            log.debug(f"  Shodan scrape error: {e}")

        return list(found_ips)

    def _scrape_duckduckgo_dork(self, query):
        """Scrape DuckDuckGo HTML search for public web dorks pointing to player_api.php."""
        if self.stop_event.is_set():
            return []

        encoded_q = urllib.parse.quote(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded_q}"
        found_ips = set()

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                html = resp.read().decode('utf-8', errors='ignore')

            # Extract IP addresses from search snippets
            for ip in IP_RE.findall(html):
                if not (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('0.')):
                    found_ips.add(ip)

            # Extract URLs from result links
            urls = re.findall(r'href="//duckduckgo\.com/l/\?uddg=([^"&]+)', html)
            for raw_u in urls:
                try:
                    decoded = urllib.parse.unquote(raw_u)
                    ip_match = IP_RE.search(decoded)
                    if ip_match:
                        found_ips.add(ip_match.group(0))
                except Exception:
                    pass

            if found_ips:
                log.info(f"  🌐 Web Dorking: Found {len(found_ips)} target IPs for dork: {query[:45]}...")

        except Exception as e:
            log.debug(f"  Web dork error: {e}")

        return list(found_ips)

    def _query_shodan_api(self, query, page=1):
        """Query official Shodan REST API if API key is provided."""
        if not self.api_key or self.stop_event.is_set():
            return []

        encoded_q = urllib.parse.quote(query)
        url = SHODAN_API_URL.format(api_key=self.api_key, query=encoded_q, page=page)
        results = []

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            matches = data.get('matches', [])
            for m in matches:
                ip = m.get('ip_str')
                port = m.get('port', 80)
                hostnames = m.get('hostnames', [])
                host = hostnames[0] if hostnames else ip

                if ip:
                    results.append({
                        'host': host,
                        'port': port,
                        'ip': ip,
                        'source': 'Shodan-API'
                    })

            if results:
                log.info(f"  🔑 Shodan API (page {page}): Found {len(results)} exact matches for: {query}")

        except urllib.error.HTTPError as e:
            if e.code == 403:
                log.warning("  ⚠️ Shodan API: 403 Forbidden (Filter requires a paid query subscription or API credits).")
            elif e.code == 401:
                log.warning("  ⚠️ Shodan API: 401 Unauthorized (Invalid API key).")
            else:
                log.warning(f"  ⚠️ Shodan API HTTP error: {e}")
        except Exception as e:
            log.warning(f"  ⚠️ Shodan API error: {e}")

        return results

    def _sample_hosting_ranges(self, sample_size_per_range=30, max_ranges=20):
        """Sample random IPs across popular IPTV hosting CIDRs and check open ports via InternetDB."""
        if self.stop_event.is_set():
            return []

        selected_ranges = POPULAR_HOSTING_RANGES[:max_ranges]
        candidate_ips = []

        for r in selected_ranges:
            try:
                net = ipaddress.ip_network(r['cidr'], strict=False)
                num_hosts = net.num_addresses
                count = min(sample_size_per_range, max(1, num_hosts - 2))
                sample_indices = random.sample(range(1, num_hosts - 1), count)
                for idx in sample_indices:
                    candidate_ips.append(str(net[idx]))
            except Exception:
                pass

        log.info(f"🌐 Shodan InternetDB: Scanning {len(candidate_ips)} random IPs across {len(selected_ranges)} hosting ranges...")

        found_hosts = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            future_to_ip = {executor.submit(self._enrich_ip_ports, ip): ip for ip in candidate_ips}
            for future in as_completed(future_to_ip):
                if self.stop_event.is_set():
                    break
                try:
                    res = future.result()
                    if res:
                        found_hosts.extend(res)
                except Exception:
                    pass

        return found_hosts

    def scan(self):
        """
        Execute targeted Xtream search across Shodan dorks and search queries.
        Returns deduplicated list of {'host': str, 'port': int, 'ip': str} dicts.
        """
        log.info(f"🎯 Starting Targeted & Hybrid Shodan Xtream Scanner ({len(SHODAN_XTREAM_DORKS)} dorks + hosting ranges)...")

        raw_ips = set()
        direct_matches = []

        # 1. Query Shodan API if key is available
        if self.api_key:
            for query in SHODAN_XTREAM_DORKS:
                if self.stop_event.is_set():
                    break
                for page in range(1, self.max_pages + 1):
                    matches = self._query_shodan_api(query, page=page)
                    direct_matches.extend(matches)
                    if not matches:
                        break
                    time.sleep(1)

        # 2. Scrape Shodan search dorks (no API key needed)
        for query in SHODAN_XTREAM_DORKS:
            if self.stop_event.is_set():
                break
            for page in range(1, min(self.max_pages + 1, 3)):
                ips = self._scrape_shodan_dork(query, page=page)
                raw_ips.update(ips)
                time.sleep(2)  # Polite delay

        # 3. Scrape Public Web Dorks for Xtream APIs
        for dork in WEB_DORKS:
            if self.stop_event.is_set():
                break
            ips = self._scrape_duckduckgo_dork(dork)
            raw_ips.update(ips)
            time.sleep(2)

        log.info(f"🎯 Shodan Targeted Search: Discovered {len(raw_ips)} unique target IPs. Enriching open ports...")

        # 4. Port Enrichment via InternetDB for all discovered target IPs
        enriched_results = list(direct_matches)
        if raw_ips:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self._enrich_ip_ports, ip): ip for ip in raw_ips}
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    try:
                        res = future.result()
                        enriched_results.extend(res)
                    except Exception:
                        pass

        # 5. Hybrid Range Sampling via InternetDB (pulls 100+ random candidate IPs with open ports)
        range_hosts = self._sample_hosting_ranges(sample_size_per_range=30, max_ranges=20)
        enriched_results.extend(range_hosts)

        # 6. Deduplicate
        seen = set()
        unique = []
        for h in enriched_results:
            key = f"{h['host']}:{h['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(h)

        log.info(f"🎯 Shodan Scan complete: {len(unique)} candidate host:port pairs found")
        self.discovered_hosts = unique
        return unique

    def run(self):
        """Run the targeted Shodan discovery pipeline."""
        return self.scan()


# Alias for engine backwards-compatibility
ShodanInternetDBScanner = TargetedShodanScanner
