"""
Xtream Codes API connector.
Checks IPTV servers using the Xtream Codes API endpoint:
  http://{host}:{port}/player_api.php?username={user}&password={pass}

Returns structured result codes matching the worker protocol.
"""
import logging
from network.proxy_connect import get_proxied_session

log = logging.getLogger(__name__)

# Common Xtream Codes API endpoints
PLAYER_API = "/player_api.php"
PANEL_API = "/panel_api.php"


def parse_xtream_line(line):
    """
    Parse an Xtream Codes credential line into components.
    Supported formats:
      - http://host:port/username/password
      - host:port:username:password
      - host port username password  (space-separated)
      - http://host:port  username  password  (mixed)

    Returns dict with keys: host, port, username, password, base_url
    or None if parsing fails.
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Format: http(s)://host:port/username/password
    if line.startswith('http://') or line.startswith('https://'):
        try:
            # Strip protocol
            proto = 'https' if line.startswith('https://') else 'http'
            rest = line.split('://', 1)[1]
            parts = rest.split('/')
            host_port = parts[0]

            if ':' in host_port:
                host, port = host_port.rsplit(':', 1)
                port = int(port)
            else:
                host = host_port
                port = 80 if proto == 'http' else 443

            if len(parts) >= 3:
                username = parts[1]
                password = parts[2]
            else:
                return None

            formatted_host = f"[{host}]" if ':' in host else host
            base_url = f"{proto}://{formatted_host}:{port}"
            return {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'base_url': base_url
            }
        except (ValueError, IndexError):
            return None

    # Format: host:port:username:password
    colon_parts = line.split(':')
    if len(colon_parts) == 4:
        try:
            host = colon_parts[0]
            port = int(colon_parts[1])
            username = colon_parts[2]
            password = colon_parts[3]
            formatted_host = f"[{host}]" if ':' in host else host
            base_url = f"http://{formatted_host}:{port}"
            return {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'base_url': base_url
            }
        except ValueError:
            pass

    # Format: space-separated  host port username password
    space_parts = line.split()
    if len(space_parts) == 4:
        try:
            host = space_parts[0]
            port = int(space_parts[1])
            username = space_parts[2]
            password = space_parts[3]
            formatted_host = f"[{host}]" if ':' in host else host
            base_url = f"http://{formatted_host}:{port}"
            return {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'base_url': base_url
            }
        except ValueError:
            pass

    return None


def check_xtream(cred, proxy=None, timeout=15, debug=False, session=None):
    """
    Attempt login to an Xtream Codes server.

    Args:
        cred: dict with host, port, username, password, base_url
        proxy: proxy info dict or None
        timeout: connection timeout in seconds
        debug: if True, log detailed response diagnostics
        session: optional persistent requests.Session for Keep-Alive pooling

    Returns one of:
      'active'           – server is active, credentials work
      'expired'          – credentials valid but subscription expired
      'fail'             – invalid credentials
      'rate_limited'     – server rate-limited us
      'connection_error' – network or server unreachable
    """
    try:
        if session is None:
            session = get_proxied_session(proxy)

        url = f"{cred['base_url']}{PLAYER_API}"
        params = {
            'username': cred['username'],
            'password': cred['password']
        }

        resp = session.get(url, params=params, timeout=timeout,
                           allow_redirects=False)

        # Debug: log raw response details
        if debug:
            body_preview = resp.text[:150].replace('\n', ' ').strip()
            ct = resp.headers.get('Content-Type', 'unknown')
            server = resp.headers.get('Server', 'unknown')
            log.info(f"    🔬 DEBUG {cred['base_url']} | "
                     f"cred={cred['username']}:{cred['password']} | "
                     f"status={resp.status_code} | ct={ct} | server={server}")
            log.info(f"       body: {body_preview}")

        # Handle redirects: XUI panels redirect to login for invalid creds
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get('Location', '').lower()
            if debug:
                log.info(f"       → DECISION: fail (redirect to '{location}')")
            if 'login' in location:
                return 'fail'  # XUI: wrong credentials → redirects to login
            return 'fail'  # Any redirect from API = not authenticated

        # Check HTTP status
        if resp.status_code in (404, 403):
            if debug:
                log.info(f"       → DECISION: fail ({resp.status_code} not found/forbidden)")
            return 'fail'
        if resp.status_code == 429:
            if debug:
                log.info(f"       → DECISION: rate_limited (429)")
            return 'rate_limited'
        if resp.status_code >= 500:
            if debug:
                log.info(f"       → DECISION: connection_error (status {resp.status_code})")
            return 'connection_error'

        # Try to parse JSON response
        try:
            data = resp.json()
            if debug:
                keys = list(data.keys())[:10] if isinstance(data, dict) else f"[array len={len(data)}]"
                log.info(f"       json_keys: {keys}")
        except Exception:
            # Non-JSON response – server is not a valid Xtream player API
            if debug:
                log.info(f"       → DECISION: invalid_server (non-JSON response)")
            return 'invalid_server'

        # Check auth result from Xtream API
        user_info = data.get('user_info')
        if not user_info or not isinstance(user_info, dict):
            if debug:
                log.info(f"       → DECISION: invalid_server (missing or invalid 'user_info' dict)")
            return 'invalid_server'

        # Standard Xtream Codes auth verification
        auth = user_info.get('auth')
        if auth is not None:
            # auth must be explicitly 1 or "1" or True
            if auth in (0, '0', False) or not auth:
                if debug:
                    log.info(f"       → DECISION: fail (auth={auth})")
                return 'fail'
        else:
            # If 'auth' key is completely missing, verify non-standard panel indicators
            result_data = data.get('result')
            has_result = isinstance(result_data, list) and len(result_data) > 0
            has_account_type = bool(user_info.get('account_type'))

            if not has_result and not has_account_type:
                if debug:
                    log.info(f"       → DECISION: fail (no auth key and no valid alternative indicators)")
                return 'fail'

        # Account status check
        status = str(user_info.get('status', '')).lower()
        if status in ('expired', 'disabled', 'banned', 'inactive'):
            if debug:
                log.info(f"       → DECISION: ⏰ EXPIRED (status={status})")
            return 'expired'

        # Expiry date check
        exp_date = user_info.get('exp_date')
        if exp_date:
            try:
                import time
                exp_ts = int(exp_date)
                # If exp_date is a positive non-zero timestamp in the past, it's expired
                if 0 < exp_ts < time.time():
                    if debug:
                        log.info(f"       → DECISION: ⏰ EXPIRED (exp_date timestamp {exp_ts} is in the past)")
                    return 'expired'
            except (ValueError, TypeError):
                pass

        # Confirmed active hit
        if debug:
            log.info(f"       → DECISION: ✅ ACTIVE (auth verified, status={status})")
        return 'active'

    except Exception as e:
        err = str(e).lower()
        if debug:
            log.info(f"    🔬 DEBUG {cred['base_url']} | "
                     f"cred={cred['username']}:{cred['password']} | "
                     f"EXCEPTION: {str(e)[:100]}")
        if any(phrase in err for phrase in ['timeout', 'timed out']):
            return 'connection_error'
        if any(phrase in err for phrase in ['too many', 'rate', '429']):
            return 'rate_limited'
        if any(phrase in err for phrase in ['connection', 'refused', 'reset']):
            return 'connection_error'
        return 'connection_error'


def verify_stream_playback(cred, proxy=None, timeout=6):
    """
    Probe the server's actual live video stream endpoints to verify if channels
    are actively transmitting video/audio data.

    Returns a dict with:
      - is_playable: bool (True if at least 1 stream delivered valid video chunks)
      - live_count: int (Total live channels in playlist)
      - vod_count: int (Total VOD movies in playlist)
      - sample_verified: str (Name of the verified channel)
    """
    result = {
        'is_playable': False,
        'live_count': 0,
        'vod_count': 0,
        'sample_verified': 'N/A'
    }

    headers = {
        'User-Agent': 'IPTVSmartersPro/3.1.5.1 (Linux; Android 10; SM-G988N)',
        'Accept': '*/*',
        'Connection': 'close'
    }

    try:
        session = get_proxied_session(proxy)
        url = f"{cred['base_url']}{PLAYER_API}"
        params = {
            'username': cred['username'],
            'password': cred['password']
        }

        # 1. Fetch live channels list
        try:
            r_live = session.get(url, params={**params, 'action': 'get_live_streams'}, headers=headers, timeout=timeout)
            if r_live.status_code == 200:
                live_streams = r_live.json()
                if isinstance(live_streams, list):
                    result['live_count'] = len(live_streams)

                    # Probe first 3 streams for playable video chunks
                    for s in live_streams[:3]:
                        stream_id = s.get('stream_id')
                        name = s.get('name', f'Stream {stream_id}')
                        ext = s.get('container_extension', 'ts')
                        stream_url = f"{cred['base_url']}/live/{cred['username']}/{cred['password']}/{stream_id}.{ext}"

                        try:
                            with session.get(stream_url, headers=headers, timeout=timeout, stream=True, allow_redirects=True) as s_resp:
                                if s_resp.status_code in (200, 206):
                                    chunk = next(s_resp.iter_content(chunk_size=1024), None)
                                    if chunk and len(chunk) > 0:
                                        result['is_playable'] = True
                                        result['sample_verified'] = name
                                        break
                        except Exception:
                            continue
        except Exception:
            pass

        # 2. Fetch VOD count
        try:
            r_vod = session.get(url, params={**params, 'action': 'get_vod_streams'}, headers=headers, timeout=timeout)
            if r_vod.status_code == 200:
                vod_streams = r_vod.json()
                if isinstance(vod_streams, list):
                    result['vod_count'] = len(vod_streams)
        except Exception:
            pass

    except Exception as e:
        log.debug(f"Stream verification error for {cred.get('base_url')}: {e}")

    return result


def get_server_info(cred, proxy=None, timeout=15):
    """
    Fetch detailed server info and stream verification for a working Xtream credential.
    Returns a dict with server info or None.
    """
    try:
        session = get_proxied_session(proxy)

        url = f"{cred['base_url']}{PLAYER_API}"
        params = {
            'username': cred['username'],
            'password': cred['password']
        }

        headers = {
            'User-Agent': 'IPTVSmartersPro/3.1.5.1 (Linux; Android 10; SM-G988N)',
            'Accept': '*/*',
            'Connection': 'close'
        }

        resp = session.get(url, params=params, headers=headers, timeout=timeout)
        data = resp.json()

        user_info = data.get('user_info', {})
        server_info = data.get('server_info', {})

        # Probe live stream playability
        stream_probe = verify_stream_playback(cred, proxy=proxy, timeout=6)

        return {
            'username': user_info.get('username', cred['username']),
            'status': user_info.get('status', 'Active'),
            'is_playable': 'Yes' if stream_probe['is_playable'] else 'Unverified',
            'live_channels': stream_probe['live_count'],
            'vod_movies': stream_probe['vod_count'],
            'verified_sample': stream_probe['sample_verified'],
            'exp_date': user_info.get('exp_date', 'N/A'),
            'is_trial': user_info.get('is_trial', 'N/A'),
            'active_cons': user_info.get('active_cons', 'N/A'),
            'max_connections': user_info.get('max_connections', 'N/A'),
            'server_url': server_info.get('url', cred['host']),
            'server_port': server_info.get('port', cred['port']),
            'server_protocol': server_info.get('server_protocol', 'http'),
            'timezone': server_info.get('timezone', 'N/A'),
        }
    except Exception:
        return None
