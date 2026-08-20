"""
FOFA Search & Official API Integration.
Discovers Xtream Codes servers by querying official FOFA REST API v1
(or scraping public search as fallback).

Official FOFA API v1:
  Endpoint: https://fofa.info/api/v1/search/all
  Params: email={email}&key={key}&qbase64={query_b64}&fields=ip,port,host,domain
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

# Search queries designed to find Xtream Codes panels on FOFA
FOFA_QUERIES = [
    'body="player_api.php"',
    'body="Undefined index: username"',
    'body="user_info" && body="server_info"',
    'header="xtream" || body="xtream-codes"',
    'body="allowed_output_formats"',
    'title="XUI" || body="x-ui"',
]

FOFA_API_URL = "https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={query_b64}&size=100&fields=ip,port,host"
FOFA_SEARCH_URL = "https://fofa.info/result?qbase64={query_b64}&page={page}&page_size=20"

# Regex to extract IPs from FOFA result pages
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
DEFAULT_PORTS = [80, 8080, 8000, 25461]


class FOFASearchScraper:
    """Discovers Xtream Codes servers via FOFA REST API v1 or web search."""

    def __init__(self, email=None, api_key=None, max_pages=2, timeout=15, stop_event=None):
        """
        Args:
            email: FOFA registered email.
            api_key: FOFA API key.
            max_pages: Maximum pages to scrape or fetch.
            timeout: HTTP request timeout in seconds.
            stop_event: Threading event to signal stop.
        """
        self.email = (email or "").strip()
        self.api_key = (api_key or "").strip()
        self.max_pages = max_pages
        self.timeout = timeout
        self.stop_event = stop_event or threading.Event()
        self.discovered_hosts = []

    def _query_api(self, query):
        """Query official FOFA REST API using email and API key."""
        if self.stop_event.is_set():
            return []

        results = []
        q_b64 = base64.b64encode(query.encode('utf-8')).decode('utf-8')
        url = FOFA_API_URL.format(email=urllib.parse.quote(self.email),
                                  key=urllib.parse.quote(self.api_key),
                                  query_b64=urllib.parse.quote(q_b64))

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'IPTVChecker-Discovery/1.0',
                'Accept': 'application/json'
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            if data.get('error'):
                errmsg = str(data.get('errmsg', 'Unknown FOFA API error'))
                if '820031' in errmsg or 'F点' in errmsg or '余额不足' in errmsg:
                    log.warning("  ⚠️ FOFA API: Insufficient F-Points (Account has 0 query credits on FOFA).")
                else:
                    log.warning(f"  ⚠️ FOFA API error: {errmsg}")
                return []

            matches = data.get('results', [])
            for item in matches:
                # Format: [ip, port, host]
                if isinstance(item, list) and len(item) >= 2:
                    ip = item[0]
                    port = int(item[1])
                    host = item[2] if len(item) > 2 and item[2] else ip
                    if "://" in host:
                        host = host.split("://", 1)[1].split("/")[0].split(":")[0]

                    results.append({
                        'host': host,
                        'port': port,
                        'ip': ip,
                        'source': 'FOFA-API'
                    })

            if results:
                log.info(f"  🔑 FOFA API: Discovered {len(results)} exact matches for: {query}")

        except urllib.error.HTTPError as e:
            if e.code == 401 or e.code == 403:
                log.warning("  ⚠️ FOFA API: Invalid email or API key.")
            else:
                log.warning(f"  ⚠️ FOFA API HTTP error: {e}")
        except Exception as e:
            log.warning(f"  ⚠️ FOFA API error: {e}")

        return results

    def _scrape_web(self, query, page=1):
        """Scrape public web search page as fallback."""
        if self.stop_event.is_set():
            return []

        q_b64 = base64.b64encode(query.encode('utf-8')).decode('utf-8')
        url = FOFA_SEARCH_URL.format(query_b64=urllib.parse.quote(q_b64), page=page)
        results = []

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml',
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                html = resp.read().decode('utf-8', errors='ignore')

            ips = IP_PATTERN.findall(html)
            for ip in set(ips):
                for port in DEFAULT_PORTS:
                    results.append({
                        'host': ip,
                        'port': port,
                        'ip': ip,
                        'source': 'FOFA-Web'
                    })

            if ips:
                log.info(f"  🔍 FOFA Web: Found {len(set(ips))} IPs for: {query[:35]}...")

        except Exception as e:
            log.debug(f"  FOFA web error: {e}")

        return results

    def scan(self):
        """Execute FOFA scan (API mode if credentials provided, else Web mode)."""
        has_api = bool(self.email and self.api_key)
        mode = "Official API" if has_api else "Public Web Scraper"
        log.info(f"🔍 Starting FOFA Xtream Scanner ({mode}, {len(FOFA_QUERIES)} queries)...")

        all_results = []
        for query in FOFA_QUERIES:
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

        log.info(f"🔍 FOFA Scan complete: {len(unique)} candidate host:port pairs found")
        self.discovered_hosts = unique
        return unique

    def run(self):
        """Pipeline alias for scan()."""
        return self.scan()
