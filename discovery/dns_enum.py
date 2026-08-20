"""
DNS Subdomain Enumeration for IPTV servers.
Resolves common IPTV-related subdomain prefixes against discovered domains.
Non-intrusive passive DNS lookups.
"""
import socket
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

# Common subdomain prefixes used by IPTV providers
DEFAULT_PREFIXES = [
    "portal", "stream", "live", "api", "panel",
    "iptv", "vod", "m3u", "tv", "player",
    "smart", "hd", "premium", "pro", "server",
    "cdn", "media", "watch", "play", "app",
    "billing", "admin", "dns", "ns1", "ns2"
]

# Common Xtream Codes ports
XTREAM_PORTS = [80, 8080, 8000, 25461, 2082, 2086]


class DNSEnumerator:
    """Enumerates IPTV subdomains against target domains."""

    def __init__(self, prefixes=None, threads=10, timeout=3):
        self.prefixes = prefixes or DEFAULT_PREFIXES
        self.threads = threads
        self.timeout = timeout
        self.discovered = []
        self._lock = threading.Lock()

    def enumerate_domain(self, base_domain):
        """
        Try common IPTV subdomain prefixes against a base domain.
        Returns list of resolved {'host': str, 'port': int, 'ip': str} dicts.
        """
        results = []
        candidates = [f"{prefix}.{base_domain}" for prefix in self.prefixes]
        # Also check the base domain itself
        candidates.append(base_domain)

        for subdomain in candidates:
            try:
                socket.setdefaulttimeout(self.timeout)
                ip = socket.gethostbyname(subdomain)
                for port in XTREAM_PORTS:
                    results.append({
                        'host': subdomain,
                        'port': port,
                        'ip': ip
                    })
                log.info(f"  ✅ {subdomain} → {ip}")
            except (socket.gaierror, socket.timeout):
                continue

        return results

    def enumerate_domains(self, base_domains):
        """
        Enumerate subdomains for multiple base domains using thread pool.
        Returns list of all resolved hosts.
        """
        log.info(f"🌐 DNS enumeration: {len(base_domains)} domains, "
                 f"{len(self.prefixes)} prefixes each...")

        all_results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.enumerate_domain, domain): domain
                for domain in base_domains
            }
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    log.warning(f"  ⚠️ DNS enum error: {e}")

        # Deduplicate
        seen = set()
        unique = []
        for h in all_results:
            key = f"{h['host']}:{h['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(h)

        self.discovered = unique
        log.info(f"🌐 DNS enumeration complete: "
                 f"{len(unique)} unique host:port pairs found")
        return unique

    def extract_base_domains(self, domains):
        """
        Extract base (root) domains from a list of subdomains.
        e.g., 'portal.iptv.example.com' → 'example.com'
        """
        base_domains = set()
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                # Take last 2 parts as base domain
                base = '.'.join(parts[-2:])
                base_domains.add(base)
        return base_domains

    def run(self, domains):
        """
        Full DNS enumeration pipeline.
        Takes a set of discovered domains, extracts base domains,
        and enumerates subdomains.
        """
        base_domains = self.extract_base_domains(domains)
        log.info(f"🌐 Extracted {len(base_domains)} base domains "
                 f"from {len(domains)} discovered domains")
        return self.enumerate_domains(base_domains)
