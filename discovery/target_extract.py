"""
Target File Extractor — Credentials & Hosts.
Reads targets file (e.g. targets.txt) containing IPTV URLs with credentials,
and extracts both:
  1. Unique username:password pairs into wordlist.txt
  2. Unique host:port candidate targets for direct discovery testing
"""
import os
import logging

log = logging.getLogger(__name__)


def parse_cred_line(line):
    """Parse a single line and extract (username, password) tuple or None."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Handle pipe format: http://host:port | username | password
    if '|' in line:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 3:
            return parts[1], parts[2]

    # Handle slash format: http://host:port/username/password
    if line.startswith('http://') or line.startswith('https://'):
        try:
            rest = line.split('://', 1)[1]
            parts = rest.split('/')
            if len(parts) >= 3:
                return parts[1], parts[2]
        except IndexError:
            pass

    # Handle colon format: host:port:username:password
    colon_parts = line.split(':')
    if len(colon_parts) == 4:
        return colon_parts[2], colon_parts[3]

    # Handle space format: host port username password
    space_parts = line.split()
    if len(space_parts) == 4:
        return space_parts[2], space_parts[3]

    return None


def extract_credentials(target_file, wordlist_file="wordlist.txt"):
    """
    Extract unique credentials from a target file and merge them into the wordlist.

    Args:
        target_file: Path to the targets file (e.g. targets.txt).
        wordlist_file: Path to the wordlist file to write/merge into.

    Returns:
        dict with extraction stats:
            - extracted: Total raw credentials parsed
            - unique_new: Number of new unique credentials added
            - total_in_wordlist: Total credentials in the wordlist after merge
    """
    if not os.path.exists(target_file):
        log.warning(f"⚠️ Target file not found: {target_file}")
        return {'extracted': 0, 'unique_new': 0, 'total_in_wordlist': 0}

    log.info(f"🔑 Extracting credentials from: {target_file}")

    new_creds = set()
    total_parsed = 0

    with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            cred = parse_cred_line(line)
            if cred:
                username, password = cred
                if username and password and len(username) > 0 and len(password) > 0:
                    new_creds.add(f"{username}:{password}")
                    total_parsed += 1

    log.info(f"  📋 Parsed {total_parsed} credentials "
             f"({len(new_creds)} unique) from {target_file}")

    existing_creds = set()
    if os.path.exists(wordlist_file):
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    existing_creds.add(line)

    new_only = new_creds - existing_creds
    merged = existing_creds | new_creds

    with open(wordlist_file, 'w', encoding='utf-8') as f:
        for cred in sorted(merged):
            f.write(f"{cred}\n")

    log.info(f"  ✅ Added {len(new_only)} new credentials to {wordlist_file} "
             f"(total: {len(merged)})")

    return {
        'extracted': total_parsed,
        'unique_new': len(new_only),
        'total_in_wordlist': len(merged)
    }


def extract_target_hosts(target_file):
    """
    Extract all unique (host, port) endpoints from the target file.
    Returns list of dicts: [{'host': str, 'port': int, 'source': 'TargetsFile'}]
    """
    if not os.path.exists(target_file):
        return []

    unique_hosts = set()
    results = []

    with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            raw_target = line.split('|')[0].strip() if '|' in line else line

            if '://' in raw_target:
                try:
                    proto_rest = raw_target.split('://', 1)
                    proto = proto_rest[0].lower()
                    host_part = proto_rest[1].split('/')[0].strip()
                    if ':' in host_part:
                        h, p = host_part.rsplit(':', 1)
                        port = int(p)
                    else:
                        h = host_part
                        port = 443 if proto == 'https' else 80

                    if h and (h, port) not in unique_hosts:
                        unique_hosts.add((h, port))
                        results.append({'host': h, 'port': port, 'source': 'TargetsFile'})
                except Exception:
                    pass
            elif ':' in raw_target:
                parts = raw_target.split(':')
                if len(parts) >= 2:
                    try:
                        h = parts[0].strip()
                        port = int(parts[1].strip())
                        if h and (h, port) not in unique_hosts:
                            unique_hosts.add((h, port))
                            results.append({'host': h, 'port': port, 'source': 'TargetsFile'})
                    except ValueError:
                        pass

    log.info(f"  🎯 Extracted {len(results)} unique targeted host:port servers from {target_file}")
    return results
