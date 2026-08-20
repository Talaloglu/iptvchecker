"""
Certificate Transparency Log Mining.
Queries crt.sh to discover IPTV-related domains from public SSL certificate logs.
Free, no API key needed.
"""
import json
import socket
import logging
import urllib.request
import urllib.parse
import urllib.error
import time

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q={query}&output=json"

# High-precision keywords to search in certificate transparency logs
DEFAULT_KEYWORDS = [
    "xtream", "xui", "player_api", "panel_api",
    "iptv", "ott", "stalker", "m3u8", "xtream-codes"
]

# Subdomain hints that strongly correlate with Xtream / IPTV panels
IPTV_SUBDOMAIN_HINTS = [
    "panel", "player", "xui", "xtream", "api",
    "portal", "iptv", "stream", "vod", "live",
    "line", "client", "billing"
]

# Major ISPs, cloud providers, and domains that should be excluded from CT log results
CT_EXCLUDED_DOMAINS = [
    'att.net', 'bell.ca', 'bahnhof.net', 't-home.hu', 'telekom', 'vodafone',
    'comcast.net', 'verizon.net', 'cox.net', 'charter.com', 'centurylink.net',
    'pages.dev', 'workers.dev', 'cloudflare.com', 'amazonaws.com', 'azure.com',
    'googleusercontent.com', 'herokuapp.com', 'netlify.app', 'vercel.app',
    'github.io', 'gitlab.io', 'firebase.app', 'firebaseapp.com'
]


class CTLogScanner:
    """Discovers IPTV servers by mining Certificate Transparency logs."""

    def __init__(self, keywords=None, timeout=15):
        self.keywords = keywords or DEFAULT_KEYWORDS
        self.timeout = timeout
        self.discovered_domains = set()
        self.discovered_hosts = []

    def search_crtsh(self, keyword):
        """
        Query crt.sh for certificates matching a keyword.
        Returns list of unique domain names found.
        """
        url = CRTSH_URL.format(query=urllib.parse.quote(f"%{keyword}%"))
        domains = set()

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; IPTV-Checker/1.0)'
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))

                for entry in data:
                    name = entry.get('name_value', '')
                    # crt.sh returns newline-separated names
                    for domain in name.split('\n'):
                        domain = domain.strip().lower()
                        # Remove wildcard prefix
                        if domain.startswith('*.'):
                            domain = domain[2:]
                        if domain and '.' in domain:
                            domains.add(domain)

            log.info(f"  📜 crt.sh [{keyword}]: {len(domains)} domains found")

        except urllib.error.HTTPError as e:
            if e.code == 429:
                log.warning(f"  ⏳ crt.sh rate-limited for [{keyword}], "
                            f"waiting 5s...")
                time.sleep(5)
            else:
                log.warning(f"  ⚠️ crt.sh error for [{keyword}]: {e}")
        except Exception as e:
            log.warning(f"  ⚠️ crt.sh query failed for [{keyword}]: {e}")

        return domains

    def scan_all_keywords(self):
        """
        Search crt.sh for all configured keywords.
        Returns set of all discovered unique domains.
        """
        log.info("📜 Starting CT log mining...")
        all_domains = set()

        for keyword in self.keywords:
            domains = self.search_crtsh(keyword)
            all_domains.update(domains)
            # Polite delay between queries
            time.sleep(1)

        # Filter to likely IPTV domains while excluding major ISPs and Cloud providers
        iptv_domains = set()
        for domain in all_domains:
            domain_lower = domain.lower()
            # Skip excluded telecom/cloud domains
            if any(domain_lower == ex or domain_lower.endswith('.' + ex) for ex in CT_EXCLUDED_DOMAINS):
                continue
            # Must contain an IPTV subdomain hint
            if any(hint in domain_lower for hint in IPTV_SUBDOMAIN_HINTS):
                iptv_domains.add(domain)

        self.discovered_domains = iptv_domains
        log.info(f"📜 CT log mining complete: {len(all_domains)} total, "
                 f"{len(iptv_domains)} high-precision IPTV domains selected")
        return iptv_domains

    def resolve_domains(self):
        """
        Resolve discovered domains to IP addresses.
        Returns list of {'host': str, 'port': int} dicts.
        """
        hosts = []
        resolved = 0
        failed = 0

        for domain in self.discovered_domains:
            try:
                ip = socket.gethostbyname(domain)
                # Add common Xtream ports for each resolved domain
                for port in [80, 8080, 8000, 25461]:
                    hosts.append({
                        'host': domain,
                        'port': port,
                        'ip': ip
                    })
                resolved += 1
            except socket.gaierror:
                failed += 1
                continue

        self.discovered_hosts = hosts
        log.info(f"🌐 DNS resolution: {resolved} resolved, {failed} failed")
        return hosts

    def run(self):
        """
        Full CT log discovery pipeline.
        Returns list of {'host': str, 'port': int} dicts.
        """
        self.scan_all_keywords()
        if not self.discovered_domains:
            log.info("📜 No IPTV-related domains found in CT logs.")
            return []
        return self.resolve_domains()
