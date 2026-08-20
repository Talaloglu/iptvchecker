"""
Session management – checkpoint saving and session log.
Saves active IPTV results and session history.
"""
import os
import json
import logging
import threading
from datetime import datetime

log = logging.getLogger(__name__)

SESSION_LOG_FILE = os.path.join("results", "session_log.json")
file_lock = threading.Lock()


def save_active(target_type, raw_line, details=None):
    """
    Save a found active IPTV service to active.txt.

    Args:
        target_type: 'xtream' or 'm3u'
        raw_line: Original line from the input file
        details: Optional dict with extra info (server info, stream count)
    """
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    active_path = os.path.join(results_dir, "active.txt")

    try:
        with file_lock:
            with open(active_path, "a", encoding='utf-8') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] [{target_type.upper()}] {raw_line}\n")
                if details:
                    for key, value in details.items():
                        f.write(f"  {key}: {value}\n")
                    f.write("\n")
    except Exception as e:
        log.error(f"Failed to save active result: {e}")


def save_expired(target_type, raw_line):
    """Save an expired IPTV service to expired.txt."""
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    expired_path = os.path.join(results_dir, "expired.txt")

    try:
        with file_lock:
            with open(expired_path, "a", encoding='utf-8') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] [{target_type.upper()}] {raw_line}\n")
    except Exception as e:
        log.error(f"Failed to save expired result: {e}")


def save_session_log(stats, active_count=0, expired_count=0,
                     xtream_count=0, m3u_count=0, proxies_removed=0):
    """Append session metadata to session_log.json."""
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    session = {
        'started_at': datetime.fromtimestamp(stats.start_time).isoformat(),
        'ended_at': datetime.now().isoformat(),
        'total_targets': stats.total,
        'checked': stats.attempted,
        'active_found': active_count,
        'expired_found': expired_count,
        'xtream_targets': xtream_count,
        'm3u_targets': m3u_count,
        'elapsed_seconds': round(stats.get_stats()['elapsed'], 1),
        'speed_per_min': round(stats.get_stats()['speed'], 1),
        'errors': stats.errors,
        'proxies_removed': proxies_removed
    }

    # Append to session log history
    history = []
    log_path = SESSION_LOG_FILE
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                history = json.load(f)
                if not isinstance(history, list):
                    history = [history]
        except (json.JSONDecodeError, Exception):
            history = []

    history.append(session)

    try:
        with open(log_path, 'w') as f:
            json.dump(history, f, indent=2)
        log.info(f"📝 Session saved to {log_path}")
    except Exception as e:
        log.error(f"Failed to save session log: {e}")

    return session
