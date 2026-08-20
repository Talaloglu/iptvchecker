"""
Thread-safe proxy pool with health tracking, rotation, and auto-removal.
"""
import socket
import random
import threading
import logging
from network.proxy_connect import parse_proxy_string

log = logging.getLogger(__name__)


class ProxyPool:
    """Manages a pool of proxies with health tracking and auto-removal."""

    def __init__(self, max_failures=3):
        self.proxies = []
        self.failures = {}  # proxy_key -> consecutive failure count
        self.lock = threading.Lock()
        self.removed_count = 0
        self.max_failures = max_failures

    def _key(self, proxy):
        return f"{proxy['type']}://{proxy['host']}:{proxy['port']}"

    def add(self, proxy):
        """Add a proxy to the pool."""
        with self.lock:
            key = self._key(proxy)
            self.proxies.append(proxy)
            self.failures[key] = 0

    def load_from_file(self, proxy_file):
        """Load and parse proxies from a file."""
        try:
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    p = parse_proxy_string(line)
                    if p:
                        self.add(p)
            log.info(f"📦 Loaded {self.alive_count} proxies from {proxy_file}.")
        except Exception as e:
            log.error(f"Error loading proxies: {e}")

    def get_random(self):
        """Get a random proxy from the pool, or None if empty."""
        with self.lock:
            if not self.proxies:
                return None
            return random.choice(self.proxies)

    def report_success(self, proxy):
        """Reset failure count on successful use."""
        with self.lock:
            key = self._key(proxy)
            if key in self.failures:
                self.failures[key] = 0

    def report_failure(self, proxy):
        """Increment failure count. Remove proxy after max consecutive failures."""
        with self.lock:
            key = self._key(proxy)
            if key not in self.failures:
                return
            self.failures[key] += 1
            if self.failures[key] >= self.max_failures:
                self.proxies = [p for p in self.proxies if self._key(p) != key]
                del self.failures[key]
                self.removed_count += 1
                log.warning(f"🚫 Proxy {key} removed after {self.max_failures} "
                            f"consecutive failures. ({len(self.proxies)} remaining)")

    @property
    def alive_count(self):
        with self.lock:
            return len(self.proxies)

    def health_check(self, dest_host="google.com", dest_port=80):
        """Pre-check all proxies with TCP connect. Remove unreachable ones."""
        log.info("🔍 Running proxy health pre-check...")
        alive = []
        dead = 0
        for proxy in list(self.proxies):
            key = self._key(proxy)
            try:
                sock = socket.create_connection(
                    (proxy['host'], proxy['port']), timeout=5)
                sock.close()
                alive.append(proxy)
                log.info(f"  ✅ {key} – reachable")
            except Exception:
                dead += 1
                log.warning(f"  ❌ {key} – unreachable, removing")

        with self.lock:
            self.proxies = alive
            self.failures = {self._key(p): 0 for p in alive}
            self.removed_count += dead

        log.info(f"🔍 Health check complete: {len(alive)} alive, {dead} removed.")
