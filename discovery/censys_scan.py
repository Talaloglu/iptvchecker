"""
Censys Search & Official API Integration.
Discovers Xtream Codes servers by querying Censys Search v2 API
(or scraping public search as fallback).

Official Censys API v2:
  Endpoint: https://search.censys.io/api/v2/hosts/search
  Auth: Basic Auth with API ID (username) and API Secret (password)
"""
import re
import json
import base64
import logging
import time
import threading
import urllib.request
import urllib.parse
import urllib.error

log = logging.getLogger(__name__)

# Search queries designed to find Xtream Codes panels
CENSYS_QUERIES = [
    'services.http.response.body:"player_api.php"',
    'services.http.response.body:"Undefined index: username"',
    'services.http.response.body:"user_info" AND services.http.response.body:"server_info"',
    'services.http.response.body:"allowed_output_formats"',
    'services.http.response.html_title:"Xtream Codes"',
    'services.http.response.html_title:"XUI"',
]

CENSYS_API_URL = "https://search.censys.io/api/v2/hosts/search?q={query}&per_page=50"
CENSYS_SEARCH_URL = "https://search.censys.io/search?resource=hosts&q={query}&page={page}"

# Regex patterns
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
HOST_PORT_PATTERN = re.compile(r'/hosts/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
DEFAULT_PORTS = [80, 8080, 8000, 25461, 2082, 8880]


class CensysSearchScraper:
    """Discovers Xtream Codes servers via Censys API v2 or web search."""

    def __init__(self, api_id=None, api_secret=None, max_pages=2, timeout=15, stop_event=None):
        """
        Args:
            api_id: Censys API ID (username).
            api_secret: Censys API Secret (password).
            max_pages: Maximum pages to scrape or fetch.
            timeout: HTTP request timeout in seconds.
            stop_event: Threading event to signal stop.
        """
        self.api_id = (api_id or "").strip()
        self.api_secret = (api_secret or "").strip()
        self.max_pages = max_pages
        self.timeout = timeout
        self.stop_event = stop_event or threading.Event()
        self.discovered_hosts = []

    def _query_api(self, query):
        """Query official Censys v2 Hosts Search API using Basic Auth."""
        if self.stop_event.is_set():
            return []

        results = []
        encoded_query = urllib.parse.quote(query)
        url = CENSYS_API_URL.format(query=encoded_query)

        # Determine authentication method: Personal Access Token (Bearer) or API ID+Secret (Basic)
        if self.api_id and self.api_secret:
            auth_str = f"{self.api_id}:{self.api_secret}"
            b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            auth_header = f"Basic {b64_auth}"
        else:
            token = self.api_secret or self.api_id
            auth_header = f"Bearer {token}"

        try:
            req = urllib.request.Request(url, headers={
                'Authorization': auth_header,
                'Accept': 'application/json',
                'User-Agent': 'IPTVChecker-Discovery/1.0'
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            hits = data.get('result', {}).get('hits', [])
            for hit in hits:
                ip = hit.get('ip')
                services = hit.get('services', [])
                if not ip:
                    continue

                if services:
                    for svc in services:
                        port = svc.get('port')
                        if port:
                            results.append({
                                'host': ip,
                                'port': port,
                                'ip': ip,
                                'source': 'Censys-API'
                            })
                else:
                    for port in DEFAULT_PORTS:
                        results.append({
                            'host': ip,
                            'port': port,
                            'ip': ip,
                            'source': 'Censys-API'
                        })

            if results:
                log.info(f"  🔑 Censys API: Discovered {len(hits)} hosts for query: {query[:40]}...")

        except urllib.error.HTTPError as e:
            if e.code == 401:
                log.warning("  ⚠️ Censys API: 401 Unauthorized (Invalid API ID or Secret).")
            elif e.code == 403:
                log.warning("  ⚠️ Censys API: 403 Forbidden (Insufficient quota or plan access).")
            elif e.code == 429:
                log.warning("  ⏳ Censys API: Rate limited, cooling down...")
            else:
                log.warning(f"  ⚠️ Censys API error: {e}")
        except Exception as e:
            log.warning(f"  ⚠️ Censys API error: {e}")

        return results

    def _scrape_web(self, query, page=1):
        """Scrape public web search page as fallback."""
        if self.stop_event.is_set():
            return []

        encoded_query = urllib.parse.quote(query)
        url = CENSYS_SEARCH_URL.format(query=encoded_query, page=page)
        results = []

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'en-US,en;q=0.9',
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                html = resp.read().decode('utf-8', errors='ignore')

            ip_matches = HOST_PORT_PATTERN.findall(html)
            for ip in set(ip_matches):
                for port in DEFAULT_PORTS:
                    results.append({
                        'host': ip,
                        'port': port,
                        'ip': ip,
                        'source': 'Censys-Web'
                    })

            if ip_matches:
                log.info(f"  🔍 Censys Web: Found {len(set(ip_matches))} IPs for: {query[:40]}...")

        except urllib.error.HTTPError as e:
            if e.code == 403:
                log.warning("  ⚠️ Censys Web: 403 Forbidden (Censys requires official API key for automated access).")
            else:
                log.warning(f"  ⚠️ Censys Web HTTP error: {e.code}")
        except Exception as e:
            log.debug(f"  Censys web error: {e}")

        return results

    def scan(self):
        """Execute Censys scan (API mode if credentials/token provided, else Web mode)."""
        has_api = bool(self.api_id or self.api_secret)
        if self.api_id and self.api_secret:
            mode = "API ID + Secret"
        elif self.api_id or self.api_secret:
            mode = "Personal Access Token"
        else:
            mode = "Public Web Scraper"
        log.info(f"🔍 Starting Censys Xtream Scanner ({mode}, {len(CENSYS_QUERIES)} queries)...")

        all_results = []
        for query in CENSYS_QUERIES:
            if self.stop_event.is_set():
                break

            if has_api:
                res = self._query_api(query)
                all_results.extend(res)
                time.sleep(1)
            else:
                res = self._scrape_web(query, page=1)
                all_results.extend(res)
                if not res:
                    break
                time.sleep(2)

        # Deduplicate
        seen = set()
        unique = []
        for h in all_results:
            key = f"{h['host']}:{h['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(h)

        log.info(f"🔍 Censys Scan complete: {len(unique)} candidate host:port pairs found")
        self.discovered_hosts = unique
        return unique

    def run(self):
        """Pipeline alias for scan()."""
        return self.scan()
