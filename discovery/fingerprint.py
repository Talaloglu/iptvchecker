"""
Xtream Codes Server Fingerprinting — High-Precision Verification Engine.
Confirms whether a discovered host actually runs an authentic Xtream Codes / XUI panel
by probing /player_api.php with multi-stage verification and active validation.

Zero false-positive design:
  1. Strict HTTP Status Filter (rejects 404, 400, 500, etc.)
  2. False Positive & CMS Pattern Filter (rejects WordPress, Grafana, cPanel, etc.)
  3. Definitive Xtream JSON & PHP Signature Matching
  4. Active Probe Verification (?username=probe_test&password=probe_test)
"""
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from network.proxy_connect import get_proxied_session

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

PLAYER_API = "/player_api.php"

# ── DEFINITIVE XTREAM SIGNATURES ──
# These signatures appear EXCLUSIVELY on authentic Xtream Codes / XUI panels.
XTREAM_DEFINITIVE_SIGNATURES = [
    'undefined index: username',       # PHP warning when no ?username= is supplied
    'undefined index: password',       # PHP warning when no ?password= is supplied
    '"user_info"',                     # Standard Xtream JSON response key
    '"server_info"',                   # Standard Xtream JSON response key
    '"allowed_output_formats"',        # Xtream supported output formats array
    '"active_cons"',                   # Xtream active connections key
    '"max_connections"',               # Xtream maximum allowed connections key
]

# ── FALSE POSITIVE REJECTION SIGNATURES ──
# If ANY of these appear in the response, the server is NOT an Xtream panel.
FALSE_POSITIVE_SIGNATURES = [
    '<!doctype html',                  # Standard HTML document
    '<html',                           # HTML markup
    '<head>',                          # HTML head section
    '<body>',                          # HTML body section
    'wordpress',                       # WordPress CMS
    'joomla',                          # Joomla CMS
    'drupal',                          # Drupal CMS
    'domain marketplace',             # Domain parking
    'domain for sale',                # Domain parking
    'buy this domain',                # Domain parking
    'parked domain',                  # Domain parking
    'godaddy',                        # Registrar parking
    'namecheap',                      # Registrar parking
    'im.forsale',                     # Domain marketplace
    'coming soon',                    # Placeholder page
    'under construction',             # Placeholder page
    'cpanel',                         # Web hosting control panel
    'plesk',                          # Web hosting control panel
    'webmail',                        # Mail client
    'roundcube',                      # Mail client
    'grafana',                        # Monitoring dashboard
    'jenkins',                        # CI/CD panel
    'pfsense',                        # Firewall interface
    'proxmox',                        # Virtualization dashboard
    'nextcloud',                      # Cloud storage
    '<meta name=',                    # SEO meta tags
    'cloudflare',                     # Cloudflare challenge or error
    'just a moment',                  # Cloudflare protection page
    'cannot get /player_api.php',     # Express / Node.js 404 echo
    'cannot post /player_api.php',    # Express / Node.js 404 echo
    'not found: /player_api.php',     # Generic 404 URL echo
    'url /player_api.php was not found', # Apache 404 echo
    '"detail":"not found"',           # FastAPI / generic REST 404
    '"error_code":',                  # Generic REST API error format
    '"message":"not found"',          # Generic REST 404
]

# ── CDN & CLOUD DOMAIN BLACKLIST ──
CDN_DOMAIN_BLACKLIST = [
    'pages.dev',
    'workers.dev',
    'cloudflare.com',
    'cloudflare-dns.com',
    'amazonaws.com',
    'azure.com',
    'googleusercontent.com',
    'herokuapp.com',
    'netlify.app',
    'vercel.app',
    'github.io',
    'gitlab.io',
    'firebase.app',
    'firebaseapp.com',
    'forsale',
    'cloudwaysapps.com',
]


class XtreamFingerprinter:
    """High-precision fingerprinter confirming authentic Xtream Codes APIs."""

    def __init__(self, threads=20, timeout=8, proxy_pool=None, stop_event=None):
        self.threads = threads
        self.timeout = timeout
        self.proxy_pool = proxy_pool
        self.stop_event = stop_event
        self.confirmed = []
        self.rejected = 0
        self._lock = threading.Lock()

    def _verify_with_active_probe(self, session, proto, formatted_host, port):
        """
        Active probe test: Sends dummy credentials to /player_api.php.
        An authentic Xtream Codes / XUI server will parse the parameters and return
        JSON containing {"user_info": {"auth": 0}} with HTTP 200.
        """
        probe_url = f"{proto}://{formatted_host}:{port}/player_api.php"
        params = {'username': 'chk_probe_v1', 'password': 'chk_probe_v1'}
        try:
            resp = session.get(probe_url, params=params, timeout=self.timeout,
                               allow_redirects=False, verify=False)
            
            if resp.status_code != 200:
                return False
                
            try:
                data = resp.json()
                if isinstance(data, dict) and 'user_info' in data:
                    user_info = data['user_info']
                    if isinstance(user_info, dict) and ('auth' in user_info or 'status' in user_info):
                        return True
            except (json.JSONDecodeError, ValueError):
                pass
        except Exception:
            pass
        return False

    def fingerprint(self, host, port):
        """
        Multi-stage verification to confirm authentic Xtream Codes panels.

        Stages:
          1. Blacklist check (skips CDNs/Cloud providers)
          2. Passive GET /player_api.php probe
          3. HTTP status & false positive signature filtering
          4. Definitive Xtream signature analysis
          5. Active probe confirmation if needed
        """
        host_lower = host.lower()
        for blacklisted in CDN_DOMAIN_BLACKLIST:
            if host_lower == blacklisted or host_lower.endswith('.' + blacklisted):
                log.info(f"    ❌ {host}:{port} → Rejected: blacklisted domain ({blacklisted})")
                return None

        proxy = None
        if self.proxy_pool:
            proxy = self.proxy_pool.get_random()

        for proto in ['http', 'https']:
            formatted_host = f"[{host}]" if ':' in host else host
            url = f"{proto}://{formatted_host}:{port}/player_api.php"
            try:
                session = get_proxied_session(proxy)
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/120.0.0.0 Safari/537.36'
                })

                resp = session.get(url, timeout=self.timeout,
                                   allow_redirects=False, verify=False)

                content = resp.text
                content_lower = content.lower()

                # ── STAGE 1: Handle Redirects (XUI Panels) ──
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '').lower()
                    
                    # Real XUI panels redirect /player_api.php to ../login or /login
                    if 'login' in location:
                        try:
                            if location.startswith('http://') or location.startswith('https://'):
                                target_url = location
                            elif location.startswith('/'):
                                target_url = f"{proto}://{formatted_host}:{port}{location}"
                            else:
                                target_url = f"{proto}://{formatted_host}:{port}/{location.lstrip('./')}"

                            login_resp = session.get(target_url, timeout=self.timeout, allow_redirects=True, verify=False)
                            login_body = login_resp.text.lower()

                            # Reject standard web apps redirecting to login
                            if any(app in login_body for app in ['wordpress', 'wp-login', 'cpanel', 'plesk', 'pfsense', 'proxmox', 'grafana', 'jenkins']):
                                log.info(f"    ❌ {host}:{port} → Rejected: login redirect belongs to non-IPTV app")
                                continue

                            # Confirm only if XUI / Xtream UI indicators exist on the login page
                            if any(ind in login_body for ind in ['xui', 'xtream', 'x-ui', 'xtream codes', 'xtream ui']):
                                result = {
                                    'host': host,
                                    'port': port,
                                    'protocol': proto,
                                    'base_url': f"{proto}://{formatted_host}:{port}",
                                    'score': 5,
                                    'body_score': 5,
                                    'status_code': resp.status_code,
                                    'content_length': len(login_resp.text)
                                }
                                log.info(f"  🎯 CONFIRMED (XUI Panel): {host}:{port} (login branding verified)")
                                return result
                        except Exception:
                            pass

                    log.info(f"    ❌ {host}:{port} → Rejected: non-IPTV redirect ({resp.status_code} → {location[:50]})")
                    continue

                # ── STAGE 2: Strict Status Code Filtering ──
                # If the endpoint returns 404, 400, 405, 500+, player_api.php is not an active Xtream API
                if resp.status_code in (404, 400, 405, 500, 502, 503, 504, 520, 521):
                    log.info(f"    ❌ {host}:{port} → Rejected: invalid HTTP status {resp.status_code} on {PLAYER_API}")
                    continue

                # ── STAGE 3: False Positive Signature Filtering ──
                has_false_positive = any(fp in content_lower for fp in FALSE_POSITIVE_SIGNATURES)
                if has_false_positive:
                    log.info(f"    ❌ {host}:{port} → Rejected: matched generic web/CMS signature")
                    continue

                # ── STAGE 4: Definitive Xtream Signature Matching ──
                is_definitive = False

                # Check for PHP Undefined index notices (unauthenticated Xtream PHP scripts)
                if 'undefined index: username' in content_lower or 'undefined index: password' in content_lower:
                    is_definitive = True

                # Check for structured Xtream JSON
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        # Dual structure: user_info + server_info (standard Xtream)
                        if 'user_info' in data:
                            user_info = data.get('user_info')
                            if isinstance(user_info, dict) and ('auth' in user_info or 'status' in user_info or 'active_cons' in user_info):
                                is_definitive = True
                        elif 'server_info' in data and 'auth' in str(data):
                            is_definitive = True
                except (json.JSONDecodeError, ValueError):
                    pass

                # Check body keywords
                if not is_definitive:
                    matching_signatures = [sig for sig in XTREAM_DEFINITIVE_SIGNATURES if sig in content_lower]
                    if len(matching_signatures) >= 2:
                        is_definitive = True

                # ── STAGE 5: Active Probe Confirmation ──
                # If HTTP status is 200 but passive signatures are uncertain, perform an active probe
                if not is_definitive and resp.status_code == 200:
                    if self._verify_with_active_probe(session, proto, formatted_host, port):
                        is_definitive = True
                        log.info(f"  🎯 ACTIVE PROBE CONFIRMED: {host}:{port} responded to player_api auth test")

                if is_definitive:
                    result = {
                        'host': host,
                        'port': port,
                        'protocol': proto,
                        'base_url': f"{proto}://{formatted_host}:{port}",
                        'score': 5,
                        'body_score': 5,
                        'status_code': resp.status_code,
                        'content_length': len(content)
                    }
                    log.info(f"  🎯 CONFIRMED (Xtream Codes API): {host}:{port} "
                             f"(status={resp.status_code}, proto={proto})")
                    return result
                else:
                    body_preview = content[:60].replace('\n', ' ').strip()
                    log.info(f"    ❌ {host}:{port} → Rejected: no authentic Xtream signatures found (body='{body_preview}...')")

            except Exception as e:
                err_msg = str(e)[:50]
                log.info(f"    ❌ {host}:{port} → Rejected: connection error ({proto}: {err_msg})")
                continue

        return None

    def bulk_fingerprint(self, hosts):
        """Fingerprint multiple candidate hosts concurrently."""
        if not hosts:
            return []

        seen = set()
        unique_hosts = []
        for h in hosts:
            key = f"{h['host']}:{h['port']}"
            if key not in seen:
                seen.add(key)
                unique_hosts.append(h)

        log.info(f"🎯 Fingerprinting {len(unique_hosts)} candidate hosts "
                 f"with {self.threads} threads (Zero False-Positive Mode)...")

        confirmed = []
        checked = 0
        total = len(unique_hosts)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(
                    self.fingerprint, h['host'], h['port']
                ): h for h in unique_hosts
            }

            for future in as_completed(futures):
                if self.stop_event and self.stop_event.is_set():
                    break
                checked += 1
                try:
                    result = future.result()
                    if result:
                        confirmed.append(result)
                except Exception:
                    pass

                if checked % max(1, total // 10) == 0:
                    log.info(f"  🔍 Fingerprinted {checked}/{total} "
                             f"({len(confirmed)} confirmed)")

        with self._lock:
            self.confirmed = confirmed
            self.rejected = total - len(confirmed)

        log.info(f"🎯 Fingerprinting complete: {len(confirmed)} confirmed Xtream servers, "
                 f"{self.rejected} non-Xtream hosts rejected out of {total}")
        return confirmed

    def run(self, hosts):
        """Run fingerprinting pipeline."""
        return self.bulk_fingerprint(hosts)
