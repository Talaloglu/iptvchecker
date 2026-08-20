#!/usr/bin/env python3
"""
IPTV Checker v1.0 – Entry Point (Restructured)
A modular, multi-threaded IPTV discovery and credential testing pipeline.

Usage:
  python run.py --ui
  python run.py --discover -w wordlist.txt
  python run.py --zoomeye zoomeye_results.json -w wordlist.txt
  python run.py --zoomeye-paste -w wordlist.txt -p proxies.txt
"""
import argparse
import logging
import sys
import os

# Setup logging before any imports that use it
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)

from core.config import Config
from core.engine import IPTVChecker
from output.colors import bold, header, red, green, cyan


BANNER = r"""
  _____ _____ _______     __   _____ _               _
 |_   _|  __ \__   __|   /  \ / ____| |             | |
   | | | |__) | | |     / /\ \ |    | |__   ___  ___| | _____ _ __
   | | |  ___/  | |    / ____ \ |   | '_ \ / _ \/ __| |/ / _ \ '__|
  _| |_| |      | |   / /    \ \____| | | |  __/ (__|   <  __/ |
 |_____|_|      |_|  /_/      \_\____|_| |_|\___|\___|_|\_\___|_|
                                                      v1.0 (Discovery)
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="IPTV Checker v1.0 – Xtream Codes Discovery & Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --ui
  python run.py --discover -w wordlist.txt
  python run.py --zoomeye zoomeye_export.json -w wordlist.txt
  python run.py --zoomeye-paste -w wordlist.txt -p proxies.txt
        """
    )

    # UI option
    parser.add_argument("--ui", action="store_true",
                        help="Launch the web-based administrator user interface")
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0"),
                        help="Host address to bind Web UI (default: 0.0.0.0)")
    parser.add_argument("--ui-port", "--port", type=int, default=int(os.environ.get("PORT", 8080)),
                        help="Port to host the Web UI (default: 8080 or $PORT)")

    # Discovery Mode
    parser.add_argument("--discover", action="store_true",
                        help="Run automated discovery (CT log mining + DNS enum)")
    parser.add_argument("--zoomeye",
                        help="Path to manually exported ZoomEye file (JSON, CSV, or text)")
    parser.add_argument("--zoomeye-paste", action="store_true",
                        help="Paste ZoomEye results interactively from clipboard")

    # Optional
    parser.add_argument("-w", "--wordlist",
                        help="Path to custom wordlist of username:password pairs for credential testing")
    parser.add_argument("-p", "--proxies",
                        help="Path to proxy list file")
    parser.add_argument("-c", "--config",
                        help="Path to config.json (default: ./config.json)")
    parser.add_argument("--threads", type=int,
                        help="Number of worker threads")

    return parser.parse_args()


def main():
    args = parse_args()
    log = logging.getLogger(__name__)

    # Print banner
    log.info(cyan(BANNER))

    # Launch Web UI if requested
    if args.ui:
        from web_gui import serve_gui
        serve_gui(host=args.host, port=args.ui_port)
        return

    # Validate that we have at least one discovery method if UI is not launched
    if not (args.discover or args.zoomeye or args.zoomeye_paste):
        log.error(red("Error: You must provide a discovery option (--discover, "
                      "--zoomeye, or --zoomeye-paste) or launch the Web UI (--ui)."))
        sys.exit(1)

    # Require a wordlist (-w) if using CLI discovery
    if not args.wordlist:
        log.error(red("Error: You must provide a custom wordlist (-w / --wordlist) for credential testing."))
        sys.exit(1)

    # Validate ZoomEye file if provided
    if args.zoomeye and not os.path.exists(args.zoomeye):
        log.error(red(f"ZoomEye export file not found: {args.zoomeye}"))
        sys.exit(1)

    # Validate wordlist file if provided
    if args.wordlist and not os.path.exists(args.wordlist):
        log.error(red(f"Wordlist file not found: {args.wordlist}"))
        sys.exit(1)

    # Validate proxy file if provided
    if args.proxies and not os.path.exists(args.proxies):
        log.error(red(f"Proxy file not found: {args.proxies}"))
        sys.exit(1)

    # Load config
    config = Config(args.config)

    # Run checker in CLI mode
    checker = IPTVChecker(
        target_file=None,
        config=config,
        proxy_file=args.proxies,
        max_threads=args.threads,
        no_resume=True,
        discover_mode=args.discover,
        zoomeye_file=args.zoomeye,
        zoomeye_paste=args.zoomeye_paste,
        wordlist_file=args.wordlist
    )
    checker.run()


if __name__ == "__main__":
    main()
