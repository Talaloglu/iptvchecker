"""
Main engine – orchestrates discovery phases, fingerprinting, credential testing, and reporting.
"""
import os
import queue
import signal
import sys
import time
import threading
import logging

from core.config import Config
from network.proxy_pool import ProxyPool
from output.stats import StatsTracker
from output.notifier import TelegramNotifier
from output.reporter import generate_report
from core.session import save_active, save_expired, save_session_log
from output.colors import (bold, cyan, green, red, yellow, magenta,
                            header, success, error)

log = logging.getLogger(__name__)


class IPTVChecker:
    """Main orchestrator for the IPTV Discovery and Credential Testing pipeline."""

    def __init__(self, target_file=None, config=None, proxy_file=None,
                 max_threads=None, no_resume=True,
                 discover_mode=False, zoomeye_file=None, zoomeye_paste=False,
                 wordlist_file=None):
        self.config = config or Config()
        self.discover_mode = discover_mode
        self.zoomeye_file = zoomeye_file
        self.zoomeye_paste = zoomeye_paste
        self.wordlist_file = wordlist_file
        self.stop_event = threading.Event()
        self.active_results = []
        self.expired_results = []
        self.active_lock = threading.Lock()
        
        # State tracking for Web UI API
        self._current_phase = "idle"  # "idle", "discovery", "fingerprinting", "credential_testing", "completed"
        self.discovery_metrics = {
            "extracted_targets": 0,
            "extracted_creds": 0,
            "recon_hosts": 0,
            "unique_candidates": 0,
            "confirmed_panels": 0,
            "active_hits": 0,
            "expired_hits": 0,
            "total_checks": 0
        }

        # Override threads if specified
        if max_threads is not None:
            self.config.threads = max_threads

        # Setup proxy pool
        self.proxy_pool = ProxyPool(max_failures=self.config.max_proxy_failures)
        if proxy_file:
            self.proxy_pool.load_from_file(proxy_file)
            self.proxy_pool.health_check()
            # Auto-scale threads to proxy count
            if (self.proxy_pool.alive_count > 0 and max_threads is None):
                self.config.threads = min(self.proxy_pool.alive_count, 15)
                log.info(cyan(f"🧵 Auto-scaled threads to "
                              f"{self.config.threads} (matching proxy count)"))

        # Setup notification
        self.notifier = TelegramNotifier(
            self.config.telegram_bot_token,
            self.config.telegram_chat_id
        )

        # Stats (initially 0 targets; will be updated dynamically during credential testing)
        self.stats = StatsTracker(0)

        # Setup signal handlers
        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
            except ValueError:
                pass

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        if self.stop_event.is_set():
            log.info(error("\n⚠️  Force exit!"))
            sys.exit(1)
        log.info(yellow("\n\n🛑 Ctrl+C received! Finishing current checks and stopping..."))
        self.stop_event.set()

    def _on_active(self, task, details):
        """Callback when an active service is found."""
        with self.active_lock:
            self.active_results.append({'task': task, 'details': details})

        # Save instantly
        raw = f"{task['base_url']}/{task['username']}/{task['password']}"
        save_active('xtream', raw, details)

        # Send notification
        if self.notifier.enabled:
            self.notifier.notify_active('xtream', raw, details)

    def _on_expired(self, task):
        """Callback when an expired service is found."""
        with self.active_lock:
            self.expired_results.append(task)
            
        # Save instantly
        raw = f"{task['base_url']}/{task['username']}/{task['password']}"
        save_expired('xtream', raw)

    def _stats_printer(self):
        """Background thread that prints real-time stats."""
        while not self.stop_event.is_set() and self._current_phase == "credential_testing":
            time.sleep(self.config.stats_interval)
            if not self.stop_event.is_set() and self._current_phase == "credential_testing":
                line = self.stats.format_line(self.proxy_pool.alive_count)
                log.info(line)

    def run(self):
        """Launch the entire discovery and testing pipeline."""
        log.info(f"\n{header('=' * 65)}")
        log.info(f"  🔍 STARTING AUTO-DISCOVERY PIPELINE")
        log.info(f"{header('=' * 65)}\n")
        
        # Clean previous results on disk for fresh discovery run
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)
        for fname in ["active.txt", "expired.txt", "session_log.json", "report.html"]:
            fpath = os.path.join(results_dir, fname)
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass

        self._current_phase = "discovery"
        discovered_hosts = []
        disc_config = self.config.data.get("discovery", {})
        
        # 0. Auto-extract credentials and target hosts from targets.txt (toggle: use_targets_extract)
        if disc_config.get("use_targets_extract", False):
            from discovery.target_extract import extract_credentials, extract_target_hosts
            targets_file = disc_config.get("targets_extract_file", "targets.txt")
            wordlist_path = self.wordlist_file or "wordlist.txt"
            cred_stats = extract_credentials(targets_file, wordlist_path)
            target_hosts = extract_target_hosts(targets_file)
            discovered_hosts.extend(target_hosts)
            self.discovery_metrics["extracted_targets"] = len(target_hosts)
            if isinstance(cred_stats, dict):
                self.discovery_metrics["extracted_creds"] = cred_stats.get("unique_total", cred_stats.get("extracted", 0))

        # 1. Candidate Collection Phase
        if self.zoomeye_file and not self.stop_event.is_set():
            from discovery.zoomeye_import import parse_any_file
            log.info(f"Importing ZoomEye results from: {self.zoomeye_file}")
            discovered_hosts.extend(parse_any_file(self.zoomeye_file))
            
        if self.zoomeye_paste and not self.stop_event.is_set():
            if threading.current_thread() is threading.main_thread():
                from discovery.zoomeye_import import interactive_paste
                discovered_hosts.extend(interactive_paste())
            else:
                log.warning("⚠️ Interactive ZoomEye paste requested but running in background thread. Skipping stdin prompt.")
        
        # 1a. CT Log + DNS Discovery (toggle: use_ct_logs)
        if self.discover_mode and disc_config.get("use_ct_logs", True) and not self.stop_event.is_set():
            from discovery.ct_recon import CTLogScanner
            ct_keywords = disc_config.get("ct_keywords", [])
            ct_scanner = CTLogScanner(keywords=ct_keywords)
            ct_domains = ct_scanner.scan_all_keywords()
            
            # DNS subdomain enumeration
            if ct_domains and not self.stop_event.is_set():
                from discovery.dns_enum import DNSEnumerator
                dns_prefixes = disc_config.get("dns_prefixes", [])
                dns_threads = disc_config.get("dns_threads", 10)
                dns_enum = DNSEnumerator(prefixes=dns_prefixes, threads=dns_threads)
                dns_hosts = dns_enum.run(ct_domains)
                discovered_hosts.extend(dns_hosts)
        
        # 1b. Targeted Shodan Discovery (toggle: use_shodan)
        if disc_config.get("use_shodan", False) and not self.stop_event.is_set():
            from discovery.shodan_scan import TargetedShodanScanner
            api_key = disc_config.get("shodan_api_key", None)
            shodan_scanner = TargetedShodanScanner(
                api_key=api_key,
                max_pages=3,
                stop_event=self.stop_event
            )
            shodan_hosts = shodan_scanner.run()
            discovered_hosts.extend(shodan_hosts)
        
        # 1c. Censys Discovery (toggle: use_censys)
        if disc_config.get("use_censys", False) and not self.stop_event.is_set():
            from discovery.censys_scan import CensysSearchScraper
            censys_id = disc_config.get("censys_api_id", None)
            censys_secret = disc_config.get("censys_api_secret", None)
            censys_scanner = CensysSearchScraper(
                api_id=censys_id,
                api_secret=censys_secret,
                max_pages=2,
                stop_event=self.stop_event
            )
            censys_hosts = censys_scanner.run()
            discovered_hosts.extend(censys_hosts)
        
        # 1d. FOFA Discovery (toggle: use_fofa)
        if disc_config.get("use_fofa", False) and not self.stop_event.is_set():
            from discovery.fofa_scan import FOFASearchScraper
            f_email = disc_config.get("fofa_email", None)
            f_key = disc_config.get("fofa_api_key", None)
            fofa_scanner = FOFASearchScraper(
                email=f_email,
                api_key=f_key,
                max_pages=2,
                stop_event=self.stop_event
            )
            fofa_hosts = fofa_scanner.run()
            discovered_hosts.extend(fofa_hosts)
        
        # Deduplicate candidates (host:port)
        seen_hosts = set()
        unique_hosts = []
        for h in discovered_hosts:
            key = f"{h['host']}:{h['port']}"
            if key not in seen_hosts:
                seen_hosts.add(key)
                unique_hosts.append(h)

        self.discovery_metrics["recon_hosts"] = len(discovered_hosts)
        self.discovery_metrics["unique_candidates"] = len(unique_hosts)
                
        if self.stop_event.is_set():
            log.info(yellow("⚠️ Process stopped by user during candidate collection."))
            return
            
        log.info(f"🔍 Discovered {len(unique_hosts)} candidate hosts. Starting fingerprinting...")
        
        # 2. Fingerprinting Phase
        self._current_phase = "fingerprinting"
        confirmed_servers = []
        if unique_hosts and not self.stop_event.is_set():
            from discovery.fingerprint import XtreamFingerprinter
            disc_config = self.config.data.get("discovery", {})
            fp_threads = disc_config.get("fingerprint_threads", 20)
            fingerprinter = XtreamFingerprinter(threads=fp_threads, proxy_pool=self.proxy_pool, stop_event=self.stop_event)
            confirmed_servers = fingerprinter.run(unique_hosts)

        self.discovery_metrics["confirmed_panels"] = len(confirmed_servers)
            
        if self.stop_event.is_set():
            log.info(yellow("⚠️ Process stopped by user during fingerprinting."))
            return
            
        log.info(f"🎯 Confirmed {len(confirmed_servers)} Xtream Codes servers. Starting credential testing...")
        
        # 3. Credential Testing Phase
        self._current_phase = "credential_testing"
        if confirmed_servers and not self.stop_event.is_set():
            from discovery.cred_tester import CredentialTester
            disc_config = self.config.data.get("discovery", {})
            ct_threads = disc_config.get("cred_test_threads", 5)
            
            # Instantiate tester with stats and callbacks
            tester = CredentialTester(
                threads=ct_threads, 
                proxy_pool=self.proxy_pool, 
                polite_delay=self.config.polite_delay,
                stats=self.stats,
                stop_event=self.stop_event,
                active_callback=self._on_active,
                expired_callback=self._on_expired
            )
            
            # Load custom wordlist if provided
            if self.wordlist_file:
                tester.load_wordlist(self.wordlist_file)
                
            # Initialize stats total search space: confirmed_servers * credentials
            total_checks = len(confirmed_servers) * len(tester.credentials)
            self.stats.total = total_checks
            
            log.info(cyan(f"📊 Search space configured: {len(confirmed_servers)} servers x {len(tester.credentials)} credentials = {total_checks} checks."))
            
            # Start background stats printer
            stats_thread = threading.Thread(target=self._stats_printer, daemon=True)
            stats_thread.start()
            
            # Run parallel testing
            tester.run(confirmed_servers)
            
        self._current_phase = "completed"
        
        # --- Final summary and reports ---
        self._print_summary()

        # Save session log
        session = save_session_log(
            self.stats,
            active_count=self.stats.active_count,
            expired_count=self.stats.expired_count,
            xtream_count=self.stats.attempted,
            m3u_count=0,
            proxies_removed=self.proxy_pool.removed_count
        )

        # Generate HTML report
        generate_report(
            self.stats.get_stats(self.proxy_pool.alive_count),
            session
        )

        # Send completion notification
        if self.notifier.enabled:
            s = self.stats.get_stats()
            self.notifier.notify_complete(
                s['total'], s['attempted'],
                s['active'], s['expired']
            )

    def _print_summary(self):
        """Print the final summary."""
        s = self.stats.get_stats(self.proxy_pool.alive_count)
        log.info(f"\n{header('=' * 65)}")
        log.info(f"  📺 IPTV DISCOVERY – FINAL RESULTS")
        log.info(f"{header('-' * 65)}")

        if s['active'] > 0:
            log.info(success(
                f"  ✅ {s['active']} ACTIVE SERVICE"
                f"{'S' if s['active'] != 1 else ''} FOUND!"))
            log.info(f"  📄 Saved to: results/active.txt")
        elif self.stop_event.is_set():
            log.info(yellow(f"  🛑 Stopped by user."))
        else:
            log.info(red(f"  ❌ No active services found."))

        if s['expired'] > 0:
            log.info(yellow(
                f"  ⏰ {s['expired']} expired service"
                f"{'s' if s['expired'] != 1 else ''} found."))
            log.info(f"  📄 Saved to: results/expired.txt")

        final_stats = self.stats.format_line(self.proxy_pool.alive_count)
        log.info(f"  {final_stats}")
        log.info(f"{header('=' * 65)}\n")
