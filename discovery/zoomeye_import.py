"""
ZoomEye Results Importer.
Parses results exported from manual ZoomEye searches (JSON, CSV, or plain text).
Supports ZoomEye web/API exports (https://www.zoomeye.ai).
No direct API key required — parses exported files or direct copy-pasted results.
"""
import os
import json
import csv
import re
import logging

log = logging.getLogger(__name__)

# Regex to match IP:port or hostname:port patterns
HOST_PORT_RE = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4
    r'(?::(\d{1,5}))?'                          # Optional port
)

HOSTNAME_PORT_RE = re.compile(
    r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'  # hostname
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,})'                                     # TLD
    r'(?::(\d{1,5}))?'                                      # Optional port
)

# Common Xtream Codes ports
DEFAULT_PORTS = [80, 8080, 8000, 25461, 2082, 2086]


def _extract_host_port_from_item(item):
    """Extract host and port from a parsed ZoomEye item dict."""
    if not isinstance(item, dict):
        return None

    # ZoomEye structures:
    # 1. portinfo: {"port": 8080, "service": "http", ...}
    # 2. direct port field: item['port'] or item['Port']
    port = None
    if isinstance(item.get('portinfo'), dict):
        port = item['portinfo'].get('port')
    if not port:
        port = item.get('port') or item.get('Port') or item.get('PORT')

    # ZoomEye host structures:
    # 1. ip or ip_str
    # 2. site (e.g. "1.2.3.4:8080" or "http://1.2.3.4:8000")
    # 3. host or domain
    host = (item.get('ip') or item.get('ip_str') or item.get('site') or
            item.get('host') or item.get('domain') or '')

    if isinstance(host, dict):
        host = host.get('ip') or host.get('domain') or ''

    host_str = str(host).strip()
    if not host_str:
        return None

    # Clean protocol prefix
    if '://' in host_str:
        host_str = host_str.split('://', 1)[1]
    if '/' in host_str:
        host_str = host_str.split('/', 1)[0]

    # Handle host:port inside host string
    if host_str.startswith('[') and ']:' in host_str:
        parts = host_str.split(']:', 1)
        host_str = parts[0][1:]
        port = parts[1]
    elif host_str.count(':') == 1 and not host_str.startswith('['):
        parts = host_str.split(':', 1)
        host_str = parts[0]
        port = parts[1]

    if not port:
        port = 80

    try:
        return {'host': host_str.strip(), 'port': int(port)}
    except (ValueError, TypeError):
        return {'host': host_str.strip(), 'port': 80}


def parse_zoomeye_json(filepath):
    """
    Parse a ZoomEye JSON export file.
    Supports ZoomEye single JSON list, ZoomEye dictionary results (e.g. 'matches', 'results', 'items'),
    standard JSON Lines (JSONL), or pretty-printed multi-line JSON blocks.

    Returns list of {'host': str, 'port': int} dicts.
    """
    results = []
    if not os.path.exists(filepath):
        log.error(f"JSON file not found: {filepath}")
        return results

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
        if not content:
            return results

        # 1. Try parsing full file as a single JSON structure
        try:
            data = json.loads(content)
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get('matches', data.get('results', data.get('items', data.get('data', []))))
                if not items and isinstance(data, dict):
                    items = [data]

            for item in items:
                hp = _extract_host_port_from_item(item)
                if hp:
                    results.append(hp)

            if results:
                results = _deduplicate(results)
                log.info(f"📥 Parsed {len(results)} hosts from ZoomEye JSON structure.")
                return results
        except json.JSONDecodeError:
            pass

        # 2. Parse sequential JSON objects (JSONL or multi-line JSON blocks)
        brace_count = 0
        current_block = []
        in_string = False
        escape = False

        for char in content:
            if char == '"' and not escape:
                in_string = not in_string

            if char == '\\' and in_string:
                escape = not escape
            else:
                escape = False

            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1

            current_block.append(char)

            if brace_count == 0 and char == '}':
                block_str = ''.join(current_block).strip()
                current_block = []
                if block_str:
                    try:
                        item = json.loads(block_str)
                        hp = _extract_host_port_from_item(item)
                        if hp:
                            results.append(hp)
                    except (json.JSONDecodeError, ValueError):
                        pass

    except Exception as e:
        log.error(f"Error parsing ZoomEye JSON: {e}")

    results = _deduplicate(results)
    log.info(f"📥 Parsed {len(results)} hosts from ZoomEye JSON Lines / Blocks.")
    return results


def parse_zoomeye_csv(filepath):
    """
    Parse a ZoomEye CSV export file.
    Expected columns include 'ip', 'ip_str', 'host', 'site', 'domain', 'port', 'portinfo', etc.

    Returns list of {'host': str, 'port': int} dicts.
    """
    results = []
    if not os.path.exists(filepath):
        log.error(f"CSV file not found: {filepath}")
        return results

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                hp = _extract_host_port_from_item(row)
                if hp:
                    results.append(hp)
    except Exception as e:
        log.error(f"Error parsing ZoomEye CSV: {e}")

    results = _deduplicate(results)
    log.info(f"📥 Parsed {len(results)} hosts from ZoomEye CSV export.")
    return results


def parse_plain_text(filepath):
    """
    Parse a plain text file with IP:port or hostname:port entries.
    One entry per line. Port is optional (defaults cycle through common ports).

    Returns list of {'host': str, 'port': int} dicts.
    """
    results = []
    if not os.path.exists(filepath):
        log.error(f"Text file not found: {filepath}")
        return results

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                hosts = _extract_hosts_from_line(line)
                results.extend(hosts)
    except Exception as e:
        log.error(f"Error parsing text file: {e}")

    results = _deduplicate(results)
    log.info(f"📥 Parsed {len(results)} hosts from text file.")
    return results


def parse_pasted_text(text):
    """
    Parse pasted text containing IP:port or hostname:port entries.

    Returns list of {'host': str, 'port': int} dicts.
    """
    results = []
    for line in text.split('\n'):
        hosts = _extract_hosts_from_line(line)
        results.extend(hosts)

    results = _deduplicate(results)
    log.info(f"📥 Parsed {len(results)} hosts from pasted ZoomEye text.")
    return results


def parse_any_file(filepath):
    """
    Auto-detect ZoomEye file format and parse accordingly.
    Tries JSON first, then CSV, then plain text.
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.json':
        return parse_zoomeye_json(filepath)
    elif ext == '.csv':
        return parse_zoomeye_csv(filepath)
    else:
        # Try JSON first
        results = parse_zoomeye_json(filepath)
        if results:
            return results
        # Try CSV
        results = parse_zoomeye_csv(filepath)
        if results:
            return results
        # Fall back to plain text
        return parse_plain_text(filepath)


def interactive_paste():
    """
    Interactive mode: prompt user to paste ZoomEye search results.
    Returns list of {'host': str, 'port': int} dicts.
    """
    print("\n📋 Paste your ZoomEye search results below (IP:port or site URL, one per line).")
    print("   Press Enter twice (empty line) when done.\n")

    lines = []
    while True:
        try:
            line = input()
            if not line.strip():
                if lines:
                    break
                continue
            lines.append(line)
        except EOFError:
            break

    text = '\n'.join(lines)
    return parse_pasted_text(text)


def _extract_hosts_from_line(line):
    """Extract host:port pairs from a single line of text."""
    results = []
    line = line.strip()
    if not line or line.startswith('#'):
        return results

    # Clean http:// or https:// scheme if present
    if '://' in line:
        line = line.split('://', 1)[1]
    if '/' in line:
        line = line.split('/', 1)[0]

    # Try IP:port pattern
    ip_matches = HOST_PORT_RE.findall(line)
    for ip, port in ip_matches:
        if port:
            results.append({'host': ip, 'port': int(port)})
        else:
            for p in DEFAULT_PORTS:
                results.append({'host': ip, 'port': p})

    # Try hostname:port pattern (if no IP found)
    if not ip_matches:
        host_matches = HOSTNAME_PORT_RE.findall(line)
        for hostname, port in host_matches:
            if port:
                results.append({'host': hostname, 'port': int(port)})
            else:
                for p in DEFAULT_PORTS:
                    results.append({'host': hostname, 'port': p})

    return results


def _deduplicate(hosts):
    """Remove duplicate host:port entries."""
    seen = set()
    unique = []
    for h in hosts:
        key = f"{h['host']}:{h['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique
