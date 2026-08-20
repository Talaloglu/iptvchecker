"""
Thread-safe statistics tracker with real-time dashboard output.
"""
import time
import threading
import logging
from output.colors import cyan, green, yellow, red, bold, gray

log = logging.getLogger(__name__)


class StatsTracker:
    """Thread-safe statistics tracker with formatted dashboard output."""

    def __init__(self, total_targets):
        self.total = total_targets
        self.attempted = 0
        self.active_count = 0
        self.expired_count = 0
        self.errors = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

    def record_attempt(self):
        with self.lock:
            self.attempted += 1

    def record_active(self):
        with self.lock:
            self.active_count += 1

    def record_expired(self):
        with self.lock:
            self.expired_count += 1

    def record_error(self):
        with self.lock:
            self.errors += 1

    def get_stats(self, proxies_alive=0):
        """Get a snapshot of current statistics."""
        with self.lock:
            elapsed = time.time() - self.start_time
            speed = (self.attempted / elapsed * 60) if elapsed > 0 else 0
            pct = (self.attempted / self.total * 100) if self.total > 0 else 0
            remaining = self.total - self.attempted
            eta_minutes = (remaining / speed) if speed > 0 else float('inf')

            if eta_minutes == float('inf'):
                eta_str = "∞"
            elif eta_minutes < 60:
                eta_str = f"{eta_minutes:.0f}m"
            elif eta_minutes < 1440:
                eta_str = f"{eta_minutes / 60:.1f}h"
            else:
                eta_str = f"{eta_minutes / 1440:.1f}d"

            return {
                'attempted': self.attempted,
                'total': self.total,
                'active': self.active_count,
                'expired': self.expired_count,
                'speed': speed,
                'pct': pct,
                'eta': eta_str,
                'errors': self.errors,
                'proxies_alive': proxies_alive,
                'elapsed': elapsed
            }

    def format_line(self, proxies_alive=0):
        """Format a single-line stats dashboard."""
        s = self.get_stats(proxies_alive)
        parts = [
            cyan(f"⚡ Speed: {s['speed']:.1f}/min"),
            f"Checked: {bold(str(s['attempted']))}/{s['total']} ({s['pct']:.1f}%)",
            green(f"Active: {s['active']}"),
            yellow(f"Expired: {s['expired']}"),
            yellow(f"ETA: ~{s['eta']}"),
        ]
        if s['errors'] > 0:
            parts.append(red(f"Errors: {s['errors']}"))
        else:
            parts.append(green(f"Errors: {s['errors']}"))

        if s['proxies_alive'] > 0:
            parts.append(gray(f"Proxies: {s['proxies_alive']}"))

        return " | ".join(parts)
