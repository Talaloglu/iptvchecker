"""
Low-level proxy socket connection handlers.
Supports HTTP CONNECT, SOCKS4, SOCKS4a, SOCKS5 protocols.
"""
import socket
import base64
import urllib.parse
import logging

log = logging.getLogger(__name__)


def parse_proxy_string(proxy_str):
    """
    Parses a proxy string into a structured dictionary.
    Supported formats:
      - host:port (assumes http)
      - protocol://host:port
      - protocol://host:port:username:password
      - protocol://username:password@host:port
    Returns None for comments and blank lines.
    """
    proxy_str = proxy_str.strip()
    if not proxy_str or proxy_str.startswith("#"):
        return None

    parts = proxy_str.split("://", 1)
    protocol = "http"
    address_part = proxy_str
    if len(parts) == 2:
        protocol = parts[0].lower()
        address_part = parts[1]

    # Check protocol://host:port:username:password format
    subparts = address_part.split(":")
    if len(subparts) == 4:
        host, port, user, password = subparts
        return {
            'type': protocol,
            'host': host,
            'port': int(port),
            'user': user,
            'pass': password
        }

    # Standard URL parsing
    if "://" not in proxy_str:
        parsed = urllib.parse.urlparse("http://" + proxy_str)
    else:
        parsed = urllib.parse.urlparse(proxy_str)

    host = parsed.hostname
    port = parsed.port or (1080 if "socks" in protocol else 8080)
    user = parsed.username
    password = parsed.password

    return {
        'type': protocol,
        'host': host,
        'port': int(port),
        'user': user,
        'pass': password
    }


def connect_via_proxy(proxy_info, dest_host, dest_port, timeout=None):
    """
    Establishes a TCP connection to dest_host:dest_port through the given proxy.
    Returns a raw connected socket.
    """
    proxy_host = proxy_info['host']
    proxy_port = proxy_info['port']
    proxy_type = proxy_info['type']

    sock = socket.create_connection((proxy_host, proxy_port), timeout)

    try:
        if proxy_type == 'http':
            _http_connect(sock, proxy_info, dest_host, dest_port)
        elif proxy_type in ('socks5', 'socks5h'):
            _socks5_connect(sock, proxy_info, dest_host, dest_port)
        elif proxy_type == 'socks4':
            _socks4_connect(sock, dest_host, dest_port)
        elif proxy_type == 'socks4a':
            _socks4a_connect(sock, dest_host, dest_port)
        else:
            raise ValueError(f"Unsupported proxy type: {proxy_type}")

        return sock
    except Exception:
        sock.close()
        raise


def _http_connect(sock, proxy_info, dest_host, dest_port):
    """HTTP CONNECT tunnel with optional basic authentication."""
    req = f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
    req += f"Host: {dest_host}:{dest_port}\r\n"
    if proxy_info.get('user') and proxy_info.get('pass'):
        auth_str = f"{proxy_info['user']}:{proxy_info['pass']}"
        b64_auth = base64.b64encode(auth_str.encode()).decode()
        req += f"Proxy-Authorization: Basic {b64_auth}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Proxy connection closed prematurely.")
        response += chunk
        if len(response) > 4096:
            raise ConnectionError("Proxy response headers too long.")

    status_line = response.split(b"\r\n")[0].decode()
    if "200" not in status_line:
        raise ConnectionError(f"Proxy rejected CONNECT: {status_line}")


def _socks5_connect(sock, proxy_info, dest_host, dest_port):
    """SOCKS5 handshake with optional username/password authentication."""
    # Greeting: offer no-auth and user/pass
    sock.sendall(b'\x05\x02\x00\x02')
    resp = sock.recv(2)
    if len(resp) < 2 or resp[0] != 0x05:
        raise ConnectionError("Invalid SOCKS5 greeting response.")

    method = resp[1]
    if method == 0x02:
        # Username/Password auth
        user = (proxy_info.get('user') or '').encode()
        pw = (proxy_info.get('pass') or '').encode()
        auth_req = (b'\x01' +
                    len(user).to_bytes(1, 'big') + user +
                    len(pw).to_bytes(1, 'big') + pw)
        sock.sendall(auth_req)
        auth_resp = sock.recv(2)
        if len(auth_resp) < 2 or auth_resp[1] != 0x00:
            raise ConnectionError("SOCKS5 authentication failed.")
    elif method != 0x00:
        raise ConnectionError(f"Unsupported SOCKS5 auth method: {method}")

    # Connect request (domain name)
    dest_bytes = dest_host.encode()
    req = (b'\x05\x01\x00\x03' +
           len(dest_bytes).to_bytes(1, 'big') + dest_bytes +
           dest_port.to_bytes(2, 'big'))
    sock.sendall(req)

    reply = sock.recv(10)
    if len(reply) < 4 or reply[0] != 0x05 or reply[1] != 0x00:
        code = reply[1] if len(reply) >= 2 else 'unknown'
        raise ConnectionError(f"SOCKS5 connect failed. Code: {code}")


def _socks4_connect(sock, dest_host, dest_port):
    """SOCKS4 connect (requires DNS resolution)."""
    dest_ip = socket.gethostbyname(dest_host)
    ip_bytes = socket.inet_aton(dest_ip)
    req = b'\x04\x01' + dest_port.to_bytes(2, 'big') + ip_bytes + b'\x00'
    sock.sendall(req)

    reply = sock.recv(8)
    if len(reply) < 8 or reply[0] != 0x00 or reply[1] != 90:
        code = reply[1] if len(reply) >= 2 else 'unknown'
        raise ConnectionError(f"SOCKS4 connect failed. Code: {code}")


def _socks4a_connect(sock, dest_host, dest_port):
    """SOCKS4a connect (remote DNS resolution)."""
    dummy_ip = b'\x00\x00\x00\x01'
    dest_bytes = dest_host.encode()
    req = (b'\x04\x01' + dest_port.to_bytes(2, 'big') +
           dummy_ip + b'\x00' + dest_bytes + b'\x00')
    sock.sendall(req)

    reply = sock.recv(8)
    if len(reply) < 8 or reply[0] != 0x00 or reply[1] != 90:
        code = reply[1] if len(reply) >= 2 else 'unknown'
        raise ConnectionError(f"SOCKS4a connect failed. Code: {code}")


def get_proxied_session(proxy_info):
    """
    Build a requests.Session with the given proxy configured.
    Used by xtream_client and m3u_client for HTTP-based requests.
    Returns a session with proxies dict set.
    """
    import requests

    session = requests.Session()
    if proxy_info is None:
        return session

    ptype = proxy_info['type']
    host = proxy_info['host']
    port = proxy_info['port']
    user = proxy_info.get('user')
    pw = proxy_info.get('pass')

    if user and pw:
        proxy_url = f"{ptype}://{user}:{pw}@{host}:{port}"
    else:
        proxy_url = f"{ptype}://{host}:{port}"

    session.proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

    return session
