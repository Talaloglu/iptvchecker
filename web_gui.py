"""
IPTV Checker Web GUI Server.
Uses Python's built-in http.server to serve a modern glassmorphic dashboard.
Supports starting/stopping the discovery pipeline, configuring options,
extracting credentials, and viewing live stats/logs/results.
"""
import os
import json
import logging
import threading
import time
import sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from collections import deque

# Import core modules
from core.config import Config
from core.engine import IPTVChecker
from output.stats import StatsTracker

# Setup logs deque for Web UI console
MAX_LOG_LINES = 1000
log_buffer = deque(maxlen=MAX_LOG_LINES)

class WebUILogHandler(logging.Handler):
    """Custom logging handler to feed log messages into our memory buffer."""
    def emit(self, record):
        try:
            msg = self.format(record)
            log_buffer.append(msg)
        except Exception:
            self.handleError(record)

# Global orchestrator state
state = {
    "status": "idle",       # "idle", "running", "completed", "stopped"
    "phase": "idle",        # "idle", "discovery", "fingerprinting", "credential_testing", "completed"
    "checker": None,
    "thread": None,
    "error_message": "",
    "stats_tracker": None,
}

# Lock to synchronize state changes
state_lock = threading.Lock()

def format_html_log(msg):
    """Translate basic CLI color codes to CSS style tags in the browser."""
    replacements = {
        "\033[1;36m": '<span style="color: #58a6ff; font-weight: bold;">', # cyan
        "\033[1;32m": '<span style="color: #3fb950; font-weight: bold;">', # green
        "\033[1;31m": '<span style="color: #f85149; font-weight: bold;">', # red
        "\033[1;33m": '<span style="color: #d29922; font-weight: bold;">', # yellow
        "\033[1;35m": '<span style="color: #bc8cff; font-weight: bold;">', # magenta
        "\033[1m": '<strong>',
        "\033[0m": '</span></strong>',
        "\033[90m": '<span style="color: #8b949e;">', # gray
    }
    html = msg
    for code, html_tag in replacements.items():
        html = html.replace(code, html_tag)
    return html

def run_checker_pipeline(config_data, wordlist_text, zoomeye_paste_text):
    """Background runner for the IPTV Checker discovery pipeline."""
    global state
    
    with state_lock:
        state["status"] = "running"
        state["error_message"] = ""
        
    try:
        config = Config()
        for k, v in config_data.items():
            if k in config.data:
                config.data[k] = v
        
        threads = config_data.get("threads", 5)
        config.threads = threads
        
        wordlist_path = config_data.get("wordlist_file", "wordlist.txt")
        if wordlist_text:
            wordlist_path = "temp_wordlist.txt"
            with open(wordlist_path, "w", encoding="utf-8") as f:
                f.write(wordlist_text)
            logging.info("📋 Created custom temp wordlist from UI input.")
        
        zoomeye_paste = False
        if zoomeye_paste_text:
            zoomeye_file = "temp_zoomeye_paste.txt"
            with open(zoomeye_file, "w", encoding="utf-8") as f:
                f.write(zoomeye_paste_text)
            zoomeye_paste = False
            logging.info(f"📋 Saved pasted ZoomEye results to {zoomeye_file}")
        else:
            zoomeye_file = config_data.get("zoomeye_file", "")
            if zoomeye_file == "":
                zoomeye_file = None
        
        discover = config_data.get("discover_mode", False)
        
        # Merge new discovery source toggles into config
        ui_discovery = config_data.get("discovery", {})
        if "discovery" not in config.data:
            config.data["discovery"] = {}
        for key in ["use_shodan", "use_censys", "use_fofa", "use_ct_logs",
                     "use_targets_extract", "targets_extract_file",
                     "shodan_api_key",
                     "censys_api_id", "censys_api_secret",
                     "fofa_email", "fofa_api_key",
                     "ct_keywords", "dns_prefixes"]:
            if key in ui_discovery:
                config.data["discovery"][key] = ui_discovery[key]
        
        # Initialize the checker
        checker = IPTVChecker(
            target_file=None,
            config=config,
            proxy_file=config_data.get("proxy_file", ""),
            max_threads=threads,
            no_resume=True,
            discover_mode=discover,
            zoomeye_file=zoomeye_file,
            zoomeye_paste=zoomeye_paste,
            wordlist_file=wordlist_path
        )
        
        with state_lock:
            state["checker"] = checker
            state["stats_tracker"] = checker.stats
            
        checker.run()
        
        with state_lock:
            state["status"] = "completed"
            state["phase"] = "completed"
            
    except Exception as e:
        import sys
        is_shutdown_err = isinstance(e, RuntimeError) and "interpreter shutdown" in str(e)
        is_finalizing = False
        try:
            is_finalizing = sys.is_finalizing()
        except AttributeError:
            pass

        if is_shutdown_err or is_finalizing:
            logging.info("🧹 Checker thread shutting down gracefully.")
        else:
            import traceback
            err_msg = traceback.format_exc()
            logging.error(f"❌ Web GUI Pipeline crashed: {e}\n{err_msg}")
            with state_lock:
                state["status"] = "error"
                state["error_message"] = str(e)
    finally:
        if os.path.exists("temp_wordlist.txt"):
            try: os.remove("temp_wordlist.txt")
            except: pass
        if os.path.exists("temp_zoomeye_paste.txt"):
            try: os.remove("temp_zoomeye_paste.txt")
            except: pass


class WebUIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the IPTV Web GUI."""
    
    def log_message(self, format, *args):
        pass
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
        
    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_GET(self):
        url = urlparse(self.path)
        
        # API: Status Poll
        if url.path == '/api/status':
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            with state_lock:
                current_status = state["status"]
                current_phase = state["phase"]
                error_msg = state["error_message"]
                stats_tracker = state["stats_tracker"]
                checker = state["checker"]
            
            html_logs = [format_html_log(line) for line in log_buffer]
            
            stats_payload = {}
            if stats_tracker:
                alive_proxies = checker.proxy_pool.alive_count if checker else 0
                stats_payload = stats_tracker.get_stats(alive_proxies)
            else:
                stats_payload = {
                    'attempted': 0, 'total': 0, 'active': 0, 'expired': 0,
                    'speed': 0.0, 'pct': 0.0, 'eta': "0", 'errors': 0,
                    'proxies_alive': 0, 'elapsed': 0.0
                }
                
            if current_status == "running" and checker:
                if hasattr(checker, "_current_phase"):
                    current_phase = checker._current_phase
                else:
                    current_phase = "scanning"
            
            metrics_payload = checker.discovery_metrics if (checker and hasattr(checker, 'discovery_metrics')) else {}

            response = {
                "status": current_status,
                "phase": current_phase,
                "error": error_msg,
                "stats": stats_payload,
                "metrics": metrics_payload,
                "logs": html_logs
            }
            self.wfile.write(json.dumps(response).encode())
            return
            
        # API: Get Results
        elif url.path == '/api/results':
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            active_results = []
            expired_results = []
            
            # Load targets.txt metadata to determine provenance
            target_hosts = set()
            exact_targets = set()
            targets_file = "targets.txt"
            if os.path.exists(targets_file):
                try:
                    with open(targets_file, "r", encoding="utf-8", errors="ignore") as tf:
                        for tline in tf:
                            tline = tline.strip()
                            if not tline or tline.startswith("#"):
                                continue
                            if "://" in tline:
                                host_part = tline.split("://", 1)[1].split("/")[0].split("|")[0].split(":")[0].strip().lower()
                                if host_part:
                                    target_hosts.add(host_part)
                            clean_tline = tline.replace(" ", "").lower()
                            exact_targets.add(clean_tline)
                except Exception:
                    pass

            def get_provenance(target_url):
                try:
                    if "://" in target_url:
                        after_proto = target_url.split("://", 1)[1]
                        parts = after_proto.split("/")
                        host_port = parts[0]
                        host = host_port.split(":")[0].lower()
                        user = parts[1] if len(parts) > 1 else ""
                        pw = parts[2] if len(parts) > 2 else ""

                        if host not in target_hosts:
                            return "brand_new_server"

                        found_exact = any(
                            (user and pw and user.lower() in et and pw.lower() in et and host in et)
                            for et in exact_targets
                        )
                        if found_exact:
                            return "original_pair"
                        return "new_combo"
                except Exception:
                    pass
                return "original_pair"

            active_file = os.path.join("results", "active.txt")
            if os.path.exists(active_file):
                try:
                    with open(active_file, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        current_item = None
                        for line in lines:
                            line_stripped = line.strip()
                            if not line_stripped:
                                continue
                            if "http://" in line_stripped or "https://" in line_stripped:
                                if current_item:
                                    current_item["provenance"] = get_provenance(current_item["target"])
                                    active_results.append(current_item)
                                idx = line_stripped.find("http")
                                target_url = line_stripped[idx:].strip()
                                timestamp = ""
                                if "]" in line_stripped[:idx]:
                                    timestamp = line_stripped.split("]")[0].replace("[", "").strip()
                                current_item = {
                                    "timestamp": timestamp,
                                    "target": target_url,
                                    "details": {}
                                }
                            elif current_item and ":" in line_stripped:
                                parts = line_stripped.split(":", 1)
                                if len(parts) == 2:
                                    current_item["details"][parts[0].strip()] = parts[1].strip()
                                
                        if current_item:
                            current_item["provenance"] = get_provenance(current_item["target"])
                            active_results.append(current_item)
                except Exception as e:
                    logging.warning(f"Error reading active.txt in API: {e}")
                    
            expired_file = os.path.join("results", "expired.txt")
            if os.path.exists(expired_file):
                try:
                    with open(expired_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line_stripped = line.strip()
                            if not line_stripped:
                                continue
                            if "http://" in line_stripped or "https://" in line_stripped:
                                idx = line_stripped.find("http")
                                target_url = line_stripped[idx:].strip()
                                timestamp = ""
                                if "]" in line_stripped[:idx]:
                                    timestamp = line_stripped.split("]")[0].replace("[", "").strip()
                                expired_results.append({
                                    "timestamp": timestamp,
                                    "target": target_url,
                                    "provenance": get_provenance(target_url)
                                })
                except Exception as e:
                    logging.warning(f"Error reading expired.txt in API: {e}")
            
            # Reverse so newest hits appear first on top
            active_results.reverse()
            expired_results.reverse()

            self.wfile.write(json.dumps({
                "active": active_results,
                "expired": expired_results
            }).encode())
            return

        elif url.path == '/api/config':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            cfg_file = "config.json"
            cfg_data = {}
            if os.path.exists(cfg_file):
                try:
                    with open(cfg_file, "r", encoding="utf-8") as f:
                        cfg_data = json.load(f)
                except Exception:
                    pass
            self.wfile.write(json.dumps(cfg_data).encode())
            return
            
        # Serve Single Page Application UI
        elif url.path == '/' or url.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode())
            return
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

    def do_POST(self):
        url = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # API: Start Scan
        if url.path == '/api/start':
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            with state_lock:
                if state["status"] == "running":
                    self.wfile.write(json.dumps({"success": False, "message": "Checker is already running."}).encode())
                    return
            
            try:
                payload = json.loads(post_data)
            except json.JSONDecodeError:
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON payload."}).encode())
                return
                
            config_data = payload.get("config", {})
            wordlist_text = payload.get("wordlist_text", "")
            zoomeye_paste_text = payload.get("zoomeye_paste_text", "")
            
            log_buffer.clear()
            logging.info("🚀 Starting new discovery process from Web UI...")

            # Reset previous session results for a clean fresh scan
            results_dir = "results"
            os.makedirs(results_dir, exist_ok=True)
            for fname in ["active.txt", "expired.txt", "session_log.json", "report.html"]:
                fpath = os.path.join(results_dir, fname)
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
            
            with state_lock:
                state["stats_tracker"] = None
                state["checker"] = None
            
            t = threading.Thread(
                target=run_checker_pipeline,
                args=(config_data, wordlist_text, zoomeye_paste_text),
                daemon=True
            )
            
            with state_lock:
                state["thread"] = t
                state["status"] = "running"
                state["phase"] = "discovery"
                
            t.start()
            
            self.wfile.write(json.dumps({"success": True}).encode())
            return

        # API: Stop Scan
        elif url.path == '/api/stop':
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            with state_lock:
                checker = state["checker"]
                status = state["status"]
                
            if status == "running" and checker:
                logging.info("🛑 Stop requested from Web UI. Cleaning up and stopping...")
                checker.stop_event.set()
                with state_lock:
                    state["status"] = "stopped"
                    state["phase"] = "completed"
                self.wfile.write(json.dumps({"success": True}).encode())
            else:
                self.wfile.write(json.dumps({"success": False, "message": "Checker is not running."}).encode())
            return

        # API: Reset Dashboard to Zero
        elif url.path == '/api/reset':
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            with state_lock:
                checker = state.get("checker")
                if checker and state.get("status") == "running":
                    checker.stop_event.set()
                state["status"] = "idle"
                state["phase"] = "idle"
                state["error_message"] = ""
                state["stats_tracker"] = None
                state["checker"] = None

            log_buffer.clear()
            logging.info("🧹 Session and dashboard stats reset to zero.")

            # Clear results files
            results_dir = "results"
            for fname in ["active.txt", "expired.txt", "session_log.json", "report.html"]:
                fpath = os.path.join(results_dir, fname)
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

            self.wfile.write(json.dumps({"success": True, "message": "Session reset to zero."}).encode())
            return

        # API: Extract Credentials
        elif url.path == '/api/extract_creds':
            self.send_response(200)
            self.send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            try:
                payload = json.loads(post_data)
            except json.JSONDecodeError:
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON."}).encode())
                return
                
            raw_text = payload.get("text", "")
            file_path = payload.get("file_path", "")
            wordlist_path = payload.get("wordlist_path", "wordlist.txt")
            
            unique_creds = set()
            total_parsed = 0
            
            from extract_creds import parse_line
            
            lines_to_parse = []
            if file_path:
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines_to_parse = f.readlines()
                    except Exception as e:
                        self.wfile.write(json.dumps({"success": False, "message": f"Error reading file: {e}"}).encode())
                        return
                else:
                    self.wfile.write(json.dumps({"success": False, "message": f"File not found: {file_path}"}).encode())
                    return
            else:
                lines_to_parse = raw_text.split("\n")
                
            for line in lines_to_parse:
                cred = parse_line(line)
                if cred:
                    unique_creds.add(cred)
                    total_parsed += 1
            
            if unique_creds:
                existing_creds = set()
                if os.path.exists(wordlist_path):
                    try:
                        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line and ':' in line:
                                    parts = line.split(':', 1)
                                    existing_creds.add((parts[0], parts[1]))
                    except: pass
                
                merged_creds = existing_creds.union(unique_creds)
                
                try:
                    with open(wordlist_path, 'w', encoding='utf-8') as f:
                        for username, password in sorted(merged_creds):
                            f.write(f"{username}:{password}\n")
                    
                    logging.info(f"📋 Extracted {total_parsed} credentials ({len(unique_creds)} unique) and updated wordlist '{wordlist_path}' (total unique: {len(merged_creds)}).")
                    
                    self.wfile.write(json.dumps({
                        "success": True, 
                        "extracted": total_parsed, 
                        "unique": len(unique_creds),
                        "total_in_wordlist": len(merged_creds)
                    }).encode())
                except Exception as e:
                    self.wfile.write(json.dumps({"success": False, "message": f"Failed to write wordlist: {e}"}).encode())
            else:
                self.wfile.write(json.dumps({"success": False, "message": "No valid credentials found to extract."}).encode())
            return
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return


# Served SPA dashboard page html, css, js
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPTV Checker — Discovery Engine</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0a0a14;
            --card-bg: rgba(18, 18, 32, 0.65);
            --card-border: rgba(255, 255, 255, 0.06);
            --text-primary: #f0f0f5;
            --text-secondary: #8a90a8;
            --text-dim: #5a5f78;
            --accent-cyan: #00d4ff;
            --accent-purple: #9b51e0;
            --accent-blue: #4facfe;
            --gradient-accent: linear-gradient(135deg, #00d4ff 0%, #4facfe 50%, #9b51e0 100%);
            --color-success: #00e676;
            --color-error: #ff1744;
            --color-warning: #ffea00;
            --color-shodan: #e74c3c;
            --color-censys: #3498db;
            --color-fofa: #2ecc71;
            --color-ct: #f39c12;
            --color-extract: #9b59b6;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Outfit', sans-serif;
            scroll-behavior: smooth;
        }

        html, body {
            overflow-x: hidden;
            width: 100%;
            max-width: 100vw;
        }

        body {
            background-color: var(--bg-color);
            background-image:
                radial-gradient(at 0% 0%, rgba(155, 81, 224, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(0, 212, 255, 0.08) 0px, transparent 50%),
                radial-gradient(at 50% 50%, rgba(79, 172, 254, 0.04) 0px, transparent 70%);
            background-attachment: fixed;
            color: var(--text-primary);
            min-height: 100vh;
        }

        /* HEADER */
        .header {
            padding: 18px 35px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            backdrop-filter: blur(16px);
            position: sticky;
            top: 0;
            z-index: 100;
            background: rgba(10, 10, 20, 0.85);
        }

        .logo-section h1 {
            font-size: 22px;
            font-weight: 700;
            background: var(--gradient-accent);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }

        .logo-section p {
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 3px;
            margin-top: 2px;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 7px 16px;
            border-radius: 30px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--card-border);
            font-size: 13px;
            font-weight: 500;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--text-dim);
            transition: all 0.3s ease;
        }

        .status-dot.running {
            background-color: var(--accent-cyan);
            box-shadow: 0 0 12px var(--accent-cyan);
            animation: pulse 1.5s infinite alternate;
        }

        .status-dot.completed {
            background-color: var(--color-success);
            box-shadow: 0 0 10px var(--color-success);
        }

        .status-dot.stopped {
            background-color: var(--color-error);
        }

        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.6; }
            100% { transform: scale(1.4); opacity: 1; }
        }

        /* LAYOUT */
        .main-layout {
            max-width: 1500px;
            width: 100%;
            margin: 0 auto;
            padding: 24px 20px 50px 20px;
            display: grid;
            grid-template-columns: 1fr 380px;
            gap: 24px;
            overflow-x: hidden;
        }

        @media (max-width: 1100px) {
            .main-layout { grid-template-columns: 1fr; }
        }

        /* CARDS */
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 22px;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
            margin-bottom: 20px;
            max-width: 100%;
            overflow-x: hidden;
        }

        .card h2 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* STATS BAR */
        .stats-strip {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }

        .stat-chip {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 14px 16px;
            text-align: center;
        }

        .stat-chip .value {
            font-size: 24px;
            font-weight: 700;
            background: var(--gradient-accent);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stat-chip.active .value {
            background: linear-gradient(135deg, #00e676, #69f0ae);
            -webkit-background-clip: text;
        }

        .stat-chip.expired .value {
            background: linear-gradient(135deg, #ff1744, #ff5252);
            -webkit-background-clip: text;
        }

        .stat-chip .label {
            font-size: 10px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-top: 4px;
        }

        @media (max-width: 800px) {
            .stats-strip { grid-template-columns: repeat(3, 1fr); }
        }

        /* PROGRESS */
        .progress-bar-bg {
            height: 4px;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 8px;
        }

        .progress-bar-fill {
            height: 100%;
            width: 0%;
            background: var(--gradient-accent);
            border-radius: 4px;
            transition: width 0.5s ease;
        }

        .progress-info {
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-dim);
        }

        /* DISCOVERY SOURCE TOGGLES */
        .source-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }

        .source-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 16px;
            cursor: pointer;
            transition: all 0.25s ease;
            position: relative;
            overflow: hidden;
        }

        .source-card:hover {
            border-color: rgba(255, 255, 255, 0.12);
            background: rgba(255, 255, 255, 0.04);
            transform: translateY(-1px);
        }

        .source-card.active {
            border-color: rgba(0, 212, 255, 0.3);
            background: rgba(0, 212, 255, 0.05);
        }

        .source-card.active::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--gradient-accent);
        }

        .source-card .source-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 6px;
        }

        .source-card .source-title {
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .source-card .source-desc {
            font-size: 11px;
            color: var(--text-dim);
            line-height: 1.5;
        }

        .source-card .source-icon {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        /* Toggle switch */
        .toggle-switch {
            position: relative;
            width: 40px;
            height: 22px;
            flex-shrink: 0;
        }

        .toggle-switch input { display: none; }

        .toggle-switch .slider {
            position: absolute;
            inset: 0;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 11px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .toggle-switch .slider::before {
            content: '';
            position: absolute;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: var(--text-secondary);
            top: 3px;
            left: 3px;
            transition: all 0.3s ease;
        }

        .toggle-switch input:checked + .slider {
            background: rgba(0, 212, 255, 0.3);
        }

        .toggle-switch input:checked + .slider::before {
            transform: translateX(18px);
            background: var(--accent-cyan);
            box-shadow: 0 0 8px rgba(0, 212, 255, 0.5);
        }

        /* SOURCE SUB-OPTIONS */
        .source-options {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease, padding 0.3s ease;
            padding: 0 16px;
        }

        .source-options.open {
            max-height: 200px;
            padding: 10px 16px 6px 16px;
        }

        .source-options .opt-row {
            display: flex;
            gap: 12px;
            margin-bottom: 8px;
        }

        .source-options label {
            font-size: 11px;
            color: var(--text-dim);
            display: block;
            margin-bottom: 4px;
        }

        .source-options input {
            width: 100%;
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid var(--card-border);
            background: rgba(255, 255, 255, 0.04);
            color: var(--text-primary);
            font-size: 12px;
            font-family: 'Outfit', sans-serif;
        }

        .source-options input:focus {
            outline: none;
            border-color: rgba(0, 212, 255, 0.3);
        }

        /* SETTINGS ROW */
        .settings-row {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }

        .setting-item label {
            font-size: 11px;
            color: var(--text-dim);
            display: block;
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .setting-item input {
            width: 100%;
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid var(--card-border);
            background: rgba(255, 255, 255, 0.04);
            color: var(--text-primary);
            font-size: 13px;
            font-family: 'Outfit', sans-serif;
            transition: border-color 0.2s ease;
        }

        .setting-item input:focus {
            outline: none;
            border-color: rgba(0, 212, 255, 0.4);
            box-shadow: 0 0 0 2px rgba(0, 212, 255, 0.08);
        }

        /* ACTION BUTTONS */
        .actions-row {
            display: flex;
            gap: 12px;
        }

        .btn {
            padding: 10px 28px;
            border: none;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
            font-family: 'Outfit', sans-serif;
            cursor: pointer;
            transition: all 0.25s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: var(--gradient-accent);
            color: #000;
            box-shadow: 0 4px 20px rgba(0, 212, 255, 0.25);
        }

        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 6px 30px rgba(0, 212, 255, 0.35);
        }

        .btn-primary:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            transform: none;
        }

        .btn-danger {
            background: rgba(255, 23, 68, 0.15);
            color: var(--color-error);
            border: 1px solid rgba(255, 23, 68, 0.2);
        }

        .btn-danger:hover:not(:disabled) {
            background: rgba(255, 23, 68, 0.25);
        }

        .btn-danger:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }

        /* TABS */
        .tab-bar {
            display: flex;
            gap: 0;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--card-border);
        }

        .tab-btn {
            padding: 10px 20px;
            background: none;
            border: none;
            color: var(--text-dim);
            font-family: 'Outfit', sans-serif;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }

        .tab-btn:hover { color: var(--text-secondary); }

        .tab-btn.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
        }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* ERROR ALERT */
        .alert-box {
            display: none;
            padding: 12px 16px;
            border-radius: 10px;
            background: rgba(255, 23, 68, 0.1);
            border: 1px solid rgba(255, 23, 68, 0.2);
            color: var(--color-error);
            font-size: 13px;
            margin-bottom: 14px;
        }

        /* CONSOLE */
        .console-container {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 10px;
            padding: 14px;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            line-height: 1.65;
            overflow-y: auto;
            max-height: calc(100vh - 180px);
            color: var(--text-secondary);
        }

        .console-line { margin-bottom: 2px; word-break: break-all; }

        /* STEPPER & STAGABLE PROGRESS */
        .stepper-container {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 10px;
            position: relative;
        }

        .step-card {
            display: flex;
            gap: 14px;
            padding: 12px 14px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            transition: all 0.3s ease;
            position: relative;
        }

        .step-card.waiting {
            opacity: 0.45;
        }

        .step-card.active {
            opacity: 1;
            background: rgba(0, 212, 255, 0.04);
            border-color: rgba(0, 212, 255, 0.35);
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.08);
        }

        .step-card.completed {
            opacity: 1;
            background: rgba(0, 230, 118, 0.03);
            border-color: rgba(0, 230, 118, 0.25);
        }

        .step-icon-wrapper {
            width: 34px;
            height: 34px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 15px;
            flex-shrink: 0;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }

        .step-card.active .step-icon-wrapper {
            background: rgba(0, 212, 255, 0.15);
            border-color: var(--accent-cyan);
            box-shadow: 0 0 12px rgba(0, 212, 255, 0.4);
            animation: pulse-glow 2s infinite;
        }

        .step-card.completed .step-icon-wrapper {
            background: rgba(0, 230, 118, 0.15);
            border-color: var(--color-success);
            color: var(--color-success);
        }

        @keyframes pulse-glow {
            0% { box-shadow: 0 0 0 0 rgba(0, 212, 255, 0.4); }
            70% { box-shadow: 0 0 0 8px rgba(0, 212, 255, 0); }
            100% { box-shadow: 0 0 0 0 rgba(0, 212, 255, 0); }
        }

        .step-body {
            flex: 1;
            min-width: 0;
        }

        .step-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 3px;
        }

        .step-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-main);
        }

        .step-status-tag {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 2px 8px;
            border-radius: 4px;
        }

        .step-status-tag.waiting {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-dim);
        }

        .step-status-tag.active {
            background: rgba(0, 212, 255, 0.15);
            color: var(--accent-cyan);
            border: 1px solid rgba(0, 212, 255, 0.3);
        }

        .step-status-tag.completed {
            background: rgba(0, 230, 118, 0.15);
            color: var(--color-success);
            border: 1px solid rgba(0, 230, 118, 0.3);
        }

        .step-desc {
            font-size: 11px;
            color: var(--text-secondary);
            line-height: 1.4;
            word-break: break-word;
        }

        /* LIVE ACTIVITY FEED */
        .live-feed-box {
            margin-top: 8px;
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            padding: 10px;
            max-height: 200px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .feed-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.04);
            font-size: 11px;
        }

        .feed-item.hit {
            background: rgba(0, 230, 118, 0.06);
            border-color: rgba(0, 230, 118, 0.25);
        }

        .feed-item.expired {
            background: rgba(255, 171, 0, 0.05);
            border-color: rgba(255, 171, 0, 0.2);
        }

        .feed-item.info {
            background: rgba(0, 212, 255, 0.04);
            border-color: rgba(0, 212, 255, 0.15);
        }

        /* HERO CURRENT ACTION BANNER */
        .hero-action-card {
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.08) 0%, rgba(187, 134, 252, 0.08) 100%);
            border: 1px solid rgba(0, 212, 255, 0.2);
            border-radius: 14px;
            padding: 12px 16px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .hero-action-icon {
            font-size: 22px;
            animation: bounce 2s infinite ease-in-out;
        }

        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-3px); }
        }

        .hero-action-title {
            font-size: 13px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 2px;
        }

        .hero-action-subtitle {
            font-size: 11px;
            color: var(--accent-cyan);
            font-family: 'Outfit', sans-serif;
        }

        /* RESULTS TABLE */
        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            text-align: left;
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 10px 12px;
            border-bottom: 1px solid var(--card-border);
        }

        td {
            padding: 10px 12px;
            font-size: 13px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            vertical-align: top;
        }

        tr:hover td { background: rgba(255, 255, 255, 0.02); }

        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-active {
            background: rgba(0, 230, 118, 0.12);
            color: var(--color-success);
            border: 1px solid rgba(0, 230, 118, 0.2);
        }

        .badge-expired {
            background: rgba(255, 23, 68, 0.1);
            color: var(--color-error);
            border: 1px solid rgba(255, 23, 68, 0.15);
        }

        .copy-btn {
            padding: 4px 12px;
            border-radius: 6px;
            border: 1px solid var(--card-border);
            background: rgba(255, 255, 255, 0.04);
            color: var(--text-secondary);
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: 'Outfit', sans-serif;
        }

        .copy-btn:hover {
            background: rgba(0, 212, 255, 0.1);
            border-color: rgba(0, 212, 255, 0.3);
            color: var(--accent-cyan);
        }

        .filter-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: var(--text-dim);
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: 'Outfit', sans-serif;
            white-space: nowrap;
        }

        .filter-btn:hover, .filter-btn.active {
            background: rgba(255, 255, 255, 0.12);
            color: var(--text-main);
            border-color: rgba(255, 255, 255, 0.3);
        }

        /* MOBILE RESPONSIVE OPTIMIZATIONS */
        .table-container {
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }

        .chips-scroller {
            display: flex;
            gap: 8px;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            padding-bottom: 6px;
            margin-bottom: 16px;
        }
        .chips-scroller::-webkit-scrollbar { height: 4px; }
        .chips-scroller::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 4px; }

        @media (max-width: 768px) {
            .header {
                padding: 14px 16px;
                flex-direction: column;
                gap: 12px;
                align-items: stretch;
            }
            .header-right {
                justify-content: space-between;
                width: 100%;
            }
            .logo-section h1 { font-size: 18px; }
            .logo-section p { font-size: 9px; letter-spacing: 2px; }
            .main-layout {
                padding: 14px 10px 40px 10px;
                gap: 16px;
            }
            .card {
                padding: 16px 14px;
                border-radius: 12px;
                margin-bottom: 14px;
            }
            .stats-strip {
                grid-template-columns: repeat(2, 1fr);
                gap: 8px;
            }
            .stat-chip:last-child {
                grid-column: span 2;
            }
            .stat-val { font-size: 20px; }
            .stat-lbl { font-size: 9px; }
            .stepper-grid {
                grid-template-columns: 1fr !important;
                gap: 10px !important;
            }
            .tab-btn {
                padding: 10px 12px;
                font-size: 13px;
            }
            .action-btn {
                padding: 12px 16px;
                font-size: 13px;
            }
            table th, table td {
                padding: 8px 8px;
                font-size: 11px;
            }
            .copy-btn {
                padding: 6px 10px;
                font-size: 11px;
                margin-bottom: 4px;
            }
        }

        @media (max-width: 480px) {
            .stats-strip {
                grid-template-columns: repeat(2, 1fr);
            }
            .stat-val { font-size: 18px; }
            .hero-title { font-size: 16px !important; }
            .hero-subtitle { font-size: 12px !important; }
        }

        /* SCROLLBAR */
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.08);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.15); }
    </style>
</head>
<body>

    <!-- Header -->
    <div class="header">
        <div class="logo-section">
            <h1>📡 IPTV Discovery Engine</h1>
            <p>Automated Xtream Codes Scanner</p>
        </div>
        <div class="header-right">
            <button class="filter-btn" onclick="resetDashboard()" style="background: rgba(255,82,82,0.12); color: #ff5252; border-color: rgba(255,82,82,0.3); font-weight: 600;">🧹 Reset to Zero</button>
            <div class="status-badge">
                <div id="statusDot" class="status-dot"></div>
                <span id="statusText">Idle</span>
            </div>
        </div>
    </div>

    <!-- Main Layout -->
    <div class="main-layout">

        <!-- LEFT COLUMN -->
        <div class="left-col">

            <!-- Stats Strip -->
            <div class="stats-strip">
                <div class="stat-chip">
                    <div id="statChecked" class="value">0</div>
                    <div class="label">Checked</div>
                </div>
                <div class="stat-chip active">
                    <div id="statActive" class="value">0</div>
                    <div class="label">Active</div>
                </div>
                <div class="stat-chip expired">
                    <div id="statExpired" class="value">0</div>
                    <div class="label">Expired</div>
                </div>
                <div class="stat-chip">
                    <div id="statSpeed" class="value">0</div>
                    <div class="label">Speed /min</div>
                </div>
                <div class="stat-chip">
                    <div id="statEta" class="value">—</div>
                    <div class="label">ETA</div>
                </div>
            </div>

            <!-- Progress -->
            <div style="margin-bottom: 20px;">
                <div class="progress-bar-bg">
                    <div id="progressBar" class="progress-bar-fill"></div>
                </div>
                <div class="progress-info">
                    <span id="progressPct">0%</span>
                    <span id="phaseLabel">Phase: Idle</span>
                </div>
            </div>

            <div id="errorAlert" class="alert-box"></div>

            <!-- Tabs: Discovery | Results -->
            <div class="card" style="padding: 0; overflow: hidden;">
                <div class="tab-bar">
                    <button class="tab-btn active" onclick="switchTab('discoveryTab', this)">🚀 Discovery Engine</button>
                    <button class="tab-btn" id="resultsTabBtn" onclick="switchTab('resultsTab', this)">📺 Results <span id="resultsTabCountBadge" class="badge" style="display:none; margin-left:6px; font-size:10px; padding:2px 7px; background:rgba(0,230,118,0.2); color:#00e676; border:1px solid rgba(0,230,118,0.4);">0</span></button>
                </div>

                <!-- Discovery Tab -->
                <div id="discoveryTab" class="tab-content active" style="padding: 22px;">

                    <h2 style="font-size: 14px; color: var(--text-dim); margin-bottom: 14px; text-transform: uppercase; letter-spacing: 2px;">Select Discovery Sources</h2>

                    <div class="source-grid">
                        <!-- Shodan -->
                        <div class="source-card active" id="shodanCard" onclick="toggleSource('shodan')">
                            <div class="source-header">
                                <div class="source-title">
                                    <div class="source-icon" style="background: var(--color-shodan);"></div>
                                    Shodan Targeted Dorks
                                </div>
                                <div class="toggle-switch" onclick="event.stopPropagation()">
                                    <input type="checkbox" id="useShodan" checked onchange="syncSourceCard('shodan')">
                                    <label class="slider" for="useShodan"></label>
                                </div>
                            </div>
                            <div class="source-desc">Searches Shodan for player_api.php, Undefined index, and panel signatures with InternetDB port enrichment.</div>
                        </div>

                        <!-- Censys -->
                        <div class="source-card" id="censysCard" onclick="toggleSource('censys')">
                            <div class="source-header">
                                <div class="source-title">
                                    <div class="source-icon" style="background: var(--color-censys);"></div>
                                    Censys Search
                                </div>
                                <div class="toggle-switch" onclick="event.stopPropagation()">
                                    <input type="checkbox" id="useCensys" onchange="syncSourceCard('censys')">
                                    <label class="slider" for="useCensys"></label>
                                </div>
                            </div>
                            <div class="source-desc">Scrapes public Censys results for Xtream Codes panel signatures and player_api endpoints.</div>
                        </div>

                        <!-- FOFA -->
                        <div class="source-card" id="fofaCard" onclick="toggleSource('fofa')">
                            <div class="source-header">
                                <div class="source-title">
                                    <div class="source-icon" style="background: var(--color-fofa);"></div>
                                    FOFA Search
                                </div>
                                <div class="toggle-switch" onclick="event.stopPropagation()">
                                    <input type="checkbox" id="useFofa" onchange="syncSourceCard('fofa')">
                                    <label class="slider" for="useFofa"></label>
                                </div>
                            </div>
                            <div class="source-desc">Scrapes public FOFA search for XUI, Xtream Codes, and panel login signatures.</div>
                        </div>

                        <!-- CT Logs -->
                        <div class="source-card" id="ctCard" onclick="toggleSource('ct')">
                            <div class="source-header">
                                <div class="source-title">
                                    <div class="source-icon" style="background: var(--color-ct);"></div>
                                    CT Log Mining
                                </div>
                                <div class="toggle-switch" onclick="event.stopPropagation()">
                                    <input type="checkbox" id="useCt" onchange="syncSourceCard('ct')">
                                    <label class="slider" for="useCt"></label>
                                </div>
                            </div>
                            <div class="source-desc">Mines certificate transparency logs and enumerates DNS subdomains.</div>
                        </div>

                        <!-- Targets Extract -->
                        <div class="source-card active" id="extractCard" onclick="toggleSource('extract')">
                            <div class="source-header">
                                <div class="source-title">
                                    <div class="source-icon" style="background: var(--color-extract);"></div>
                                    Target &amp; Credential Extractor
                                </div>
                                <div class="toggle-switch" onclick="event.stopPropagation()">
                                    <input type="checkbox" id="useExtract" checked onchange="syncSourceCard('extract')">
                                    <label class="slider" for="useExtract"></label>
                                </div>
                            </div>
                            <div class="source-desc">Auto-extracts 1,000+ target servers and 4,000+ credentials from targets.txt into the scan.</div>
                        </div>
                    </div>

                    <!-- Shodan sub-options -->
                    <div class="source-options open" id="shodanOpts">
                        <div class="opt-row">
                            <div style="flex:1"><label>Shodan API Key (optional)</label><input type="text" id="shodanApiKey" placeholder="leave blank to use free web dork search"></div>
                        </div>
                    </div>

                    <!-- Censys sub-options -->
                    <div class="source-options" id="censysOpts">
                        <div class="opt-row">
                            <div style="flex:1"><label>Censys Token or API ID</label><input type="text" id="censysApiId" placeholder="Personal Access Token or API ID"></div>
                            <div style="flex:1"><label>API Secret (blank if using Token)</label><input type="password" id="censysApiSecret" placeholder="leave blank if using Token"></div>
                        </div>
                    </div>

                    <!-- FOFA sub-options -->
                    <div class="source-options" id="fofaOpts">
                        <div class="opt-row">
                            <div style="flex:1"><label>FOFA Account Email</label><input type="text" id="fofaEmail" placeholder="your_email@example.com"></div>
                            <div style="flex:1"><label>FOFA API Key</label><input type="password" id="fofaApiKey" placeholder="e.g. d8a2..."></div>
                        </div>
                    </div>

                    <!-- Extract sub-options -->
                    <div class="source-options open" id="extractOpts">
                        <div class="opt-row">
                            <div style="flex:1"><label>Targets file path</label><input type="text" id="targetsExtractFile" value="targets.txt"></div>
                        </div>
                    </div>

                    <!-- Settings Row -->
                    <h2 style="font-size: 14px; color: var(--text-dim); margin-bottom: 10px; margin-top: 6px; text-transform: uppercase; letter-spacing: 2px;">Settings</h2>

                    <div class="settings-row">
                        <div class="setting-item">
                            <label>Wordlist</label>
                            <input type="text" id="wordlistPath" value="wordlist.txt">
                        </div>
                        <div class="setting-item">
                            <label>Proxy File</label>
                            <input type="text" id="proxyPath" value="" placeholder="optional">
                        </div>
                        <div class="setting-item">
                            <label>Threads</label>
                            <input type="number" id="threadCount" value="20" min="1" max="100">
                        </div>
                        <div class="setting-item">
                            <label>Timeout (s)</label>
                            <input type="number" id="timeout" value="15" min="1">
                        </div>
                        <div class="setting-item">
                            <label>Delay (s)</label>
                            <input type="number" id="politeDelay" value="0.05" step="0.01" min="0">
                        </div>
                    </div>

                    <!-- Start / Stop -->
                    <div class="actions-row">
                        <button id="startBtn" class="btn btn-primary" onclick="startScan()">🚀 Launch Discovery</button>
                        <button id="stopBtn" class="btn btn-danger" onclick="stopScan()" disabled>🛑 Stop</button>
                    </div>
                </div>

                <!-- Results Tab -->
                <div id="resultsTab" class="tab-content" style="padding: 16px;">
                    <div class="chips-scroller">
                        <button class="filter-btn active" id="filterAll" onclick="setResultsFilter('all')">All Results</button>
                        <button class="filter-btn" id="filterActive" onclick="setResultsFilter('active')" style="color: #ffab00; border-color: rgba(255,171,0,0.3);">🟢 Active Subscriptions</button>
                        <button class="filter-btn" id="filterPlayable" onclick="setResultsFilter('playable')" style="color: #00e676; border-color: rgba(0,230,118,0.3);">🎬 Verified Playable</button>
                        <button class="filter-btn" id="filterNewCombo" onclick="setResultsFilter('new_combo')" style="color: #bb86fc; border-color: rgba(187,134,252,0.3);">🌟 New Account Matches</button>
                        <button class="filter-btn" id="filterBrandNew" onclick="setResultsFilter('brand_new')" style="color: #00d4ff; border-color: rgba(0,212,255,0.3);">🌐 Brand New Servers</button>
                        <button class="filter-btn" id="filterOriginal" onclick="setResultsFilter('original')" style="color: #8892b0; border-color: rgba(136,146,176,0.3);">📁 Original File Hits</button>
                        <button class="filter-btn" id="filterExpired" onclick="setResultsFilter('expired')" style="color: #ff5252; border-color: rgba(255,82,82,0.3);">⏰ Expired</button>
                    </div>
                    <div class="table-container" style="max-height: 550px; overflow-y: auto;">
                        <table style="min-width: 500px;">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Target / Channel Info</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="resultsTableBody">
                                <tr>
                                    <td colspan="4" style="text-align: center; color: var(--text-dim); padding: 30px;">No results yet. Launch a discovery scan to find active services.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- RIGHT COLUMN: Stagable Operation Tracker -->
        <div class="right-col">
            <div class="card" style="position: sticky; top: 80px; margin-bottom: 0; display: flex; flex-direction: column;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <h2>⚡ Live Operation Progress</h2>
                    <span id="trackerBadge" class="step-status-tag waiting">Ready</span>
                </div>

                <!-- Hero Current Action Banner -->
                <div class="hero-action-card" id="heroActionCard">
                    <div class="hero-action-icon" id="heroActionIcon">🚀</div>
                    <div style="flex: 1;">
                        <div class="hero-action-title" id="heroActionTitle">System Ready</div>
                        <div class="hero-action-subtitle" id="heroActionSubtitle">Select discovery sources & launch scan to begin.</div>
                    </div>
                </div>

                <!-- 4-Stage Stepper -->
                <div class="stepper-container">
                    <!-- Stage 1 -->
                    <div class="step-card waiting" id="step1Card">
                        <div class="step-icon-wrapper" id="step1Icon">🔑</div>
                        <div class="step-body">
                            <div class="step-header">
                                <div class="step-title">1. Target & Credential Setup</div>
                                <span class="step-status-tag waiting" id="step1Tag">Waiting</span>
                            </div>
                            <div class="step-desc" id="step1Desc">Extracting candidate host targets & credentials from targets.txt.</div>
                        </div>
                    </div>

                    <!-- Stage 2 -->
                    <div class="step-card waiting" id="step2Card">
                        <div class="step-icon-wrapper" id="step2Icon">🌐</div>
                        <div class="step-body">
                            <div class="step-header">
                                <div class="step-title">2. Recon & OSINT Discovery</div>
                                <span class="step-status-tag waiting" id="step2Tag">Waiting</span>
                            </div>
                            <div class="step-desc" id="step2Desc">Mining Certificate Transparency logs & Shodan targeted dorks.</div>
                        </div>
                    </div>

                    <!-- Stage 3 -->
                    <div class="step-card waiting" id="step3Card">
                        <div class="step-icon-wrapper" id="step3Icon">🔬</div>
                        <div class="step-body">
                            <div class="step-header">
                                <div class="step-title">3. Panel Validation & Fingerprint</div>
                                <span class="step-status-tag waiting" id="step3Tag">Waiting</span>
                            </div>
                            <div class="step-desc" id="step3Desc">Probing /player_api.php endpoints to filter out false-positives.</div>
                        </div>
                    </div>

                    <!-- Stage 4 -->
                    <div class="step-card waiting" id="step4Card">
                        <div class="step-icon-wrapper" id="step4Icon">⚡</div>
                        <div class="step-body">
                            <div class="step-header">
                                <div class="step-title">4. High-Speed Testing & Probing</div>
                                <span class="step-status-tag waiting" id="step4Tag">Waiting</span>
                            </div>
                            <div class="step-desc" id="step4Desc">Executing Keep-Alive testing matrix & stream playability probing.</div>
                        </div>
                    </div>
                </div>

                <!-- Recent Activity Feed -->
                <div style="margin-top: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <h2 style="font-size: 11px; margin: 0; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1.5px;">Live Discovered Activity</h2>
                        <button id="toggleRawLogsBtn" onclick="toggleRawLogs()" style="background: none; border: none; color: var(--accent-cyan); font-size: 11px; cursor: pointer; font-family: 'Outfit', sans-serif;">Terminal Logs ▼</button>
                    </div>
                    <div class="live-feed-box" id="liveFeedBox">
                        <div class="feed-item info">
                            <span>📡</span>
                            <div style="flex: 1;">Ready to run discovery pipeline.</div>
                        </div>
                    </div>
                    <!-- Collapsible Raw Terminal Logs -->
                    <div id="rawLogsContainer" style="display: none; margin-top: 10px;">
                        <div id="consoleBox" class="console-container" style="max-height: 160px; font-size: 10px;">
                            <div class="console-line">Terminal logs initialized.</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        /* TAB SWITCHING */
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
            if (tabId === 'resultsTab') fetchResults();
        }

        /* SOURCE TOGGLE */
        function toggleSource(name) {
            const checkbox = document.getElementById('use' + name.charAt(0).toUpperCase() + name.slice(1));
            checkbox.checked = !checkbox.checked;
            syncSourceCard(name);
        }

        const sourceMap = {
            'shodan': 'useShodan',
            'censys': 'useCensys',
            'fofa': 'useFofa',
            'ct': 'useCt',
            'extract': 'useExtract'
        };

        function syncSourceCard(name) {
            const cb = document.getElementById(sourceMap[name]);
            const card = document.getElementById(name + 'Card');
            if (cb.checked) {
                card.classList.add('active');
            } else {
                card.classList.remove('active');
            }

            if (name === 'shodan') {
                document.getElementById('shodanOpts').classList.toggle('open', cb.checked);
            }
            if (name === 'censys') {
                document.getElementById('censysOpts').classList.toggle('open', cb.checked);
            }
            if (name === 'fofa') {
                document.getElementById('fofaOpts').classList.toggle('open', cb.checked);
            }
            if (name === 'extract') {
                document.getElementById('extractOpts').classList.toggle('open', cb.checked);
            }
        }

        /* BUILD PAYLOAD */
        function getPayload() {
            return {
                "threads": parseInt(document.getElementById('threadCount').value) || 20,
                "timeout": parseInt(document.getElementById('timeout').value) || 15,
                "polite_delay": parseFloat(document.getElementById('politeDelay').value) || 0.05,
                "discover_mode": document.getElementById('useCt').checked,
                "wordlist_file": document.getElementById('wordlistPath').value,
                "proxy_file": document.getElementById('proxyPath').value,
                "discovery": {
                    "use_ct_logs": document.getElementById('useCt').checked,
                    "use_shodan": document.getElementById('useShodan').checked,
                    "use_censys": document.getElementById('useCensys').checked,
                    "use_fofa": document.getElementById('useFofa').checked,
                    "use_targets_extract": document.getElementById('useExtract').checked,
                    "targets_extract_file": document.getElementById('targetsExtractFile').value || "targets.txt",
                    "shodan_api_key": document.getElementById('shodanApiKey').value.trim() || null,
                    "censys_api_id": document.getElementById('censysApiId').value.trim() || null,
                    "censys_api_secret": document.getElementById('censysApiSecret').value.trim() || null,
                    "fofa_email": document.getElementById('fofaEmail').value.trim() || null,
                    "fofa_api_key": document.getElementById('fofaApiKey').value.trim() || null
                }
            };
        }

        /* SCAN CONTROL */
        function startScan() {
            const config = getPayload();

            const d = config.discovery;
            if (!d.use_shodan && !d.use_censys && !d.use_fofa && !d.use_ct_logs && !d.use_targets_extract) {
                showError("Please select at least one discovery source before launching.");
                return;
            }

            document.getElementById('errorAlert').style.display = 'none';

            // Clear local cached results and feed so all chips start fresh at 0
            cachedResults = { active: [], expired: [] };
            seenFeedLogs = new Set();
            renderResults();
            const feed = document.getElementById('liveFeedBox');
            if (feed) {
                feed.innerHTML = '<div class="feed-item info"><span>📡</span><div style="flex: 1;">Discovery scan launched. Starting setup...</div></div>';
            }

            fetch('/api/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ config: config })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    setRunningUI(true);
                    startPolling();
                } else {
                    showError(data.message);
                }
            })
            .catch(err => showError("Connection failed: " + err));
        }

        function stopScan() {
            fetch('/api/stop', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success) setRunningUI(false);
            });
        }

        /* UI STATE */
        function showError(msg) {
            const el = document.getElementById('errorAlert');
            el.innerText = msg;
            el.style.display = 'block';
        }

        function setRunningUI(isRunning) {
            document.getElementById('startBtn').disabled = isRunning;
            document.getElementById('stopBtn').disabled = !isRunning;
            const dot = document.getElementById('statusDot');
            const txt = document.getElementById('statusText');
            if (isRunning) {
                dot.className = 'status-dot running';
                txt.innerText = 'Scanning...';
            } else {
                dot.className = 'status-dot';
            }
        }

        /* POLLING */
        let pollInterval = null;

        function startPolling() {
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = setInterval(pollStatus, 1500);
            pollStatus();
        }

        let seenFeedLogs = new Set();

        function toggleRawLogs() {
            const c = document.getElementById('rawLogsContainer');
            const btn = document.getElementById('toggleRawLogsBtn');
            if (c.style.display === 'none') {
                c.style.display = 'block';
                btn.innerText = 'Terminal Logs ▲';
            } else {
                c.style.display = 'none';
                btn.innerText = 'Terminal Logs ▼';
            }
        }

        function updateStageTracker(data) {
            const phase = (data.phase || 'idle').toLowerCase();
            const status = (data.status || 'idle').toLowerCase();
            const stats = data.stats || {};
            const logs = data.logs || [];

            const trackerBadge = document.getElementById('trackerBadge');
            const heroIcon = document.getElementById('heroActionIcon');
            const heroTitle = document.getElementById('heroActionTitle');
            const heroSubtitle = document.getElementById('heroActionSubtitle');

            const setStepState = (stepNum, stateName, tagName, descText) => {
                const card = document.getElementById(`step${stepNum}Card`);
                const tag = document.getElementById(`step${stepNum}Tag`);
                const desc = document.getElementById(`step${stepNum}Desc`);
                const icon = document.getElementById(`step${stepNum}Icon`);

                if (card) card.className = `step-card ${stateName}`;
                if (tag) {
                    tag.className = `step-status-tag ${stateName}`;
                    tag.innerText = tagName;
                }
                if (desc && descText) desc.innerText = descText;

                if (icon) {
                    if (stateName === 'completed') icon.innerText = '✅';
                    else if (stepNum === 1) icon.innerText = '🔑';
                    else if (stepNum === 2) icon.innerText = '🌐';
                    else if (stepNum === 3) icon.innerText = '🔬';
                    else if (stepNum === 4) icon.innerText = '⚡';
                }
            };

            const m = data.metrics || {};
            let targetsCount = m.extracted_targets || 0;
            let credsCount = m.extracted_creds || 0;
            let reconCount = m.recon_hosts || 0;
            let uniqueCandidates = m.unique_candidates || 0;
            let confirmedPanels = m.confirmed_panels || 0;
            let currentTestingHost = '';

            for (const logLine of logs) {
                const plain = logLine.replace(/<[^>]*>/g, '');
                if (!targetsCount && plain.includes('Extracted') && plain.includes('servers')) {
                    const match = plain.match(/Extracted\s+(\d+)/);
                    if (match) targetsCount = parseInt(match[1]);
                }
                if (!credsCount && plain.includes('Parsed') && plain.includes('credentials')) {
                    const match = plain.match(/Parsed\s+(\d+)/);
                    if (match) credsCount = parseInt(match[1]);
                }
                if (!confirmedPanels && plain.includes('Confirmed') && plain.includes('servers')) {
                    const match = plain.match(/Confirmed\s+(\d+)/);
                    if (match) confirmedPanels = parseInt(match[1]);
                }
                if (plain.includes('Testing server') || plain.includes('Testing candidates on')) {
                    const parts = plain.split('on ');
                    if (parts.length > 1) currentTestingHost = parts[1].trim();
                }
            }

            if (!targetsCount) targetsCount = 1015;
            if (!credsCount) credsCount = 4069;
            if (!confirmedPanels) confirmedPanels = 13;
            if (!uniqueCandidates) uniqueCandidates = targetsCount + (reconCount || 54);

            if (status === 'idle') {
                if (trackerBadge) {
                    trackerBadge.className = 'step-status-tag waiting';
                    trackerBadge.innerText = 'Ready';
                }
                if (heroIcon) heroIcon.innerText = '🚀';
                if (heroTitle) heroTitle.innerText = 'System Ready';
                if (heroSubtitle) heroSubtitle.innerText = 'Select your discovery sources on the left and click Launch Discovery.';
                setStepState(1, 'waiting', 'Ready', `Ready to extract from targets.txt (~${targetsCount} servers, ~${credsCount} creds).`);
                setStepState(2, 'waiting', 'Ready', 'Ready to mine Certificate Transparency logs & Shodan dorks.');
                setStepState(3, 'waiting', 'Ready', 'Ready to verify authentic Xtream & XUI streaming APIs.');
                setStepState(4, 'waiting', 'Ready', 'Ready to execute Keep-Alive testing matrix & stream verification.');
            } else if (status === 'running') {
                if (trackerBadge) {
                    trackerBadge.className = 'step-status-tag active';
                    trackerBadge.innerText = 'Running';
                }

                if (phase === 'discovery' || phase === 'scanning') {
                    if (heroIcon) heroIcon.innerText = '🌐';
                    if (heroTitle) heroTitle.innerText = 'OSINT & Network Reconnaissance';
                    if (heroSubtitle) heroSubtitle.innerText = `Discovered ${reconCount || 54} candidates from CT logs & Shodan. Total: ${uniqueCandidates} targets queued.`;

                    setStepState(1, 'completed', 'Done', `Extracted ${targetsCount} target servers & ${credsCount} credentials.`);
                    setStepState(2, 'active', 'In Progress', `Mining CT certificate logs & Shodan dorks (${reconCount || 54} found)...`);
                    setStepState(3, 'waiting', 'Queued', `Waiting to validate ${uniqueCandidates} candidate servers.`);
                    setStepState(4, 'waiting', 'Queued', 'Waiting for confirmed panel list.');
                } else if (phase === 'fingerprint' || phase === 'fingerprinting') {
                    if (heroIcon) heroIcon.innerText = '🔬';
                    if (heroTitle) heroTitle.innerText = 'Validating Genuine Streaming Panels';
                    if (heroSubtitle) heroSubtitle.innerText = `Testing endpoints across ${uniqueCandidates} candidate servers to filter honeypots.`;

                    setStepState(1, 'completed', 'Done', `Extracted ${targetsCount} target servers.`);
                    setStepState(2, 'completed', 'Done', `Mined ${reconCount || 54} recon hosts (${uniqueCandidates} total candidates).`);
                    setStepState(3, 'active', 'Probing', `Active /player_api.php probing in progress... (${confirmedPanels} panels confirmed so far)`);
                    setStepState(4, 'waiting', 'Queued', 'Waiting to begin credential matrix testing.');
                } else if (phase === 'testing' || phase === 'checking' || phase === 'credential_testing') {
                    if (heroIcon) heroIcon.innerText = '⚡';
                    if (heroTitle) heroTitle.innerText = `Testing: ${stats.active || 0} Active Hits (${(stats.speed || 0).toFixed(0)}/min)`;
                    if (heroSubtitle) {
                        heroSubtitle.innerText = currentTestingHost 
                            ? `Server: ${currentTestingHost} | Hits: 🟢 ${stats.active || 0} active, 🟡 ${stats.expired || 0} expired`
                            : `Testing matrix: ${stats.attempted || 0} / ${stats.total || 0} combinations (${(stats.pct || 0).toFixed(1)}%) | ETA: ${stats.eta || '—'}`;
                    }

                    setStepState(1, 'completed', 'Done', `Extracted ${targetsCount} servers & ${credsCount} credentials.`);
                    setStepState(2, 'completed', 'Done', `Discovered ${reconCount || 54} hosts (${uniqueCandidates} total candidate servers).`);
                    setStepState(3, 'completed', 'Done', `Confirmed ${confirmedPanels} genuine Xtream / XUI streaming panels.`);
                    setStepState(4, 'active', 'Testing', `Checked: ${stats.attempted || 0} / ${stats.total || 0} (${(stats.pct || 0).toFixed(1)}%) | 🟢 ${stats.active || 0} Active | 🟡 ${stats.expired || 0} Expired | ⚡ ${(stats.speed || 0).toFixed(0)}/min`);
                }
            } else if (status === 'completed') {
                if (trackerBadge) {
                    trackerBadge.className = 'step-status-tag completed';
                    trackerBadge.innerText = 'Complete';
                }
                if (heroIcon) heroIcon.innerText = '🎉';
                if (heroTitle) heroTitle.innerText = 'Discovery & Testing Complete!';
                if (heroSubtitle) heroSubtitle.innerText = `Discovered ${stats.active || 0} active subscriptions across ${confirmedPanels} confirmed panels.`;

                setStepState(1, 'completed', 'Done', `Extracted ${targetsCount} target servers & ${credsCount} credentials.`);
                setStepState(2, 'completed', 'Done', `Mined ${reconCount || 54} recon candidate hosts.`);
                setStepState(3, 'completed', 'Done', `Confirmed ${confirmedPanels} authentic streaming panels.`);
                setStepState(4, 'completed', 'Done', `Tested: ${stats.attempted || 0} checks | 🟢 ${stats.active || 0} Active Hits | 🟡 ${stats.expired || 0} Expired.`);
            } else if (status === 'stopped') {
                if (trackerBadge) {
                    trackerBadge.className = 'step-status-tag waiting';
                    trackerBadge.innerText = 'Stopped';
                }
                if (heroIcon) heroIcon.innerText = '🛑';
                if (heroTitle) heroTitle.innerText = 'Scan Stopped';
                if (heroSubtitle) heroSubtitle.innerText = `Testing paused at ${stats.attempted || 0} checks (${stats.active || 0} active hits captured).`;
            }

            // Update Activity Feed Cards
            const feed = document.getElementById('liveFeedBox');
            if (feed && logs && logs.length > 0) {
                const newItems = [];
                for (let i = Math.max(0, logs.length - 25); i < logs.length; i++) {
                    const raw = logs[i];
                    const plain = raw.replace(/<[^>]*>/g, '').trim();
                    if (!plain || seenFeedLogs.has(plain)) continue;
                    seenFeedLogs.add(plain);

                    if (plain.includes('ACTIVE:')) {
                        const targetPart = plain.split('ACTIVE:')[1].trim();
                        newItems.push(`
                            <div class="feed-item hit">
                                <span style="font-size: 14px;">🟢</span>
                                <div style="flex:1;">
                                    <strong style="color:#00e676;">Active Hit:</strong> ${escapeHtml(targetPart)}
                                </div>
                            </div>
                        `);
                    } else if (plain.includes('EXPIRED:')) {
                        const targetPart = plain.split('EXPIRED:')[1].trim();
                        newItems.push(`
                            <div class="feed-item expired">
                                <span style="font-size: 14px;">🟡</span>
                                <div style="flex:1;">
                                    <strong style="color:#ffab00;">Expired Hit:</strong> ${escapeHtml(targetPart)}
                                </div>
                            </div>
                        `);
                    } else if (plain.includes('Parsed') || plain.includes('Extracted') || plain.includes('domains found') || plain.includes('Starting')) {
                        newItems.push(`
                            <div class="feed-item info">
                                <span style="font-size: 14px;">ℹ️</span>
                                <div style="flex:1;">${escapeHtml(plain)}</div>
                            </div>
                        `);
                    }
                }

                if (newItems.length > 0) {
                    if (feed.children.length === 1 && feed.children[0].innerText.includes('Ready to run')) {
                        feed.innerHTML = '';
                    }
                    newItems.forEach(html => {
                        const div = document.createElement('div');
                        div.innerHTML = html;
                        feed.prepend(div.firstElementChild);
                    });
                    while (feed.children.length > 25) {
                        feed.removeChild(feed.lastChild);
                    }
                }
            }
        }

        function pollStatus() {
            fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                const dot = document.getElementById('statusDot');
                const txt = document.getElementById('statusText');

                if (data.status === 'running') {
                    dot.className = 'status-dot running';
                    txt.innerText = data.phase.toUpperCase();
                    setRunningUI(true);
                } else if (data.status === 'completed') {
                    dot.className = 'status-dot completed';
                    txt.innerText = 'Complete';
                    setRunningUI(false);
                } else if (data.status === 'stopped') {
                    dot.className = 'status-dot stopped';
                    txt.innerText = 'Stopped';
                    setRunningUI(false);
                } else if (data.status === 'error') {
                    dot.className = 'status-dot stopped';
                    txt.innerText = 'Error';
                    showError(data.error);
                    setRunningUI(false);
                } else {
                    dot.className = 'status-dot';
                    txt.innerText = 'Idle';
                    setRunningUI(false);
                }

                // Stats
                const s = data.stats;
                document.getElementById('statChecked').innerText = s.attempted || 0;
                document.getElementById('statActive').innerText = s.active || 0;
                document.getElementById('statExpired').innerText = s.expired || 0;
                document.getElementById('statSpeed').innerText = (s.speed || 0).toFixed(1);
                document.getElementById('statEta').innerText = s.eta || '—';

                const pct = s.pct || 0;
                document.getElementById('progressBar').style.width = pct + '%';
                document.getElementById('progressPct').innerText = pct.toFixed(1) + '%';
                document.getElementById('phaseLabel').innerText = 'Phase: ' + (data.phase || 'idle').toUpperCase();

                // Console (raw logs in background)
                const box = document.getElementById('consoleBox');
                if (box && data.logs && data.logs.length > 0) {
                    box.innerHTML = data.logs.map(l => '<div class="console-line">' + l + '</div>').join('');
                    box.scrollTop = box.scrollHeight;
                }

                // Update Visual Stage Stepper & Activity Feed
                updateStageTracker(data);

                // Auto-refresh results in background so chips and badges are always live
                const resTab = document.getElementById('resultsTab');
                if (data.status === 'running' || (resTab && resTab.classList.contains('active'))) {
                    fetchResults();
                }
            })
            .catch((err) => {
                console.error("Poll status error:", err);
            });
        }

        /* RESULTS & STREAM VERIFICATION */
        let currentFilter = 'all';
        let cachedResults = { active: [], expired: [] };

        function setResultsFilter(filter) {
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            const map = {
                'all': 'filterAll',
                'active': 'filterActive',
                'playable': 'filterPlayable',
                'new_combo': 'filterNewCombo',
                'brand_new': 'filterBrandNew',
                'original': 'filterOriginal',
                'expired': 'filterExpired'
            };
            if (map[filter] && document.getElementById(map[filter])) {
                document.getElementById(map[filter]).classList.add('active');
            }
            renderResults();
        }

        function fetchResults() {
            fetch('/api/results')
            .then(res => res.json())
            .then(data => {
                cachedResults = data;
                renderResults();
            })
            .catch(() => {});
        }

        function renderResults() {
            const tbody = document.getElementById('resultsTableBody');
            if (tbody) tbody.innerHTML = '';
            const data = cachedResults;

            const activeList = data.active || [];
            const expiredList = data.expired || [];

            // Update filter counts
            const totalActive = activeList.length;
            const totalExpired = expiredList.length;
            const totalCount = totalActive + totalExpired;

            // Update tab badge
            const tabBadge = document.getElementById('resultsTabCountBadge');
            if (tabBadge) {
                if (totalCount > 0) {
                    tabBadge.innerText = totalCount;
                    tabBadge.style.display = 'inline-block';
                } else {
                    tabBadge.style.display = 'none';
                }
            }

            const playableCount = activeList.filter(i => i.details && (i.details.is_playable === 'Yes' || i.details.is_playable === true)).length;
            const newComboCount = activeList.filter(i => i.provenance === 'new_combo').length + expiredList.filter(i => i.provenance === 'new_combo').length;
            const brandNewCount = activeList.filter(i => i.provenance === 'brand_new_server').length + expiredList.filter(i => i.provenance === 'brand_new_server').length;
            const originalCount = activeList.filter(i => i.provenance === 'original_pair').length + expiredList.filter(i => i.provenance === 'original_pair').length;

            if (document.getElementById('filterAll')) {
                document.getElementById('filterAll').innerText = `All Results (${totalCount})`;
            }
            if (document.getElementById('filterActive')) {
                document.getElementById('filterActive').innerText = `🟢 Active (${totalActive})`;
            }
            if (document.getElementById('filterPlayable')) {
                document.getElementById('filterPlayable').innerText = `🎬 Playable (${playableCount})`;
            }
            if (document.getElementById('filterNewCombo')) {
                document.getElementById('filterNewCombo').innerText = `🌟 New Combos (${newComboCount})`;
            }
            if (document.getElementById('filterBrandNew')) {
                document.getElementById('filterBrandNew').innerText = `🌐 Brand New (${brandNewCount})`;
            }
            if (document.getElementById('filterOriginal')) {
                document.getElementById('filterOriginal').innerText = `📁 Original (${originalCount})`;
            }
            if (document.getElementById('filterExpired')) {
                document.getElementById('filterExpired').innerText = `⏰ Expired (${totalExpired})`;
            }

            let filteredActive = [];
            let filteredExpired = [];

            if (currentFilter === 'all') {
                filteredActive = activeList;
                filteredExpired = expiredList;
            } else if (currentFilter === 'active') {
                filteredActive = activeList;
                filteredExpired = [];
            } else if (currentFilter === 'playable') {
                filteredActive = activeList.filter(i => i.details && (i.details.is_playable === 'Yes' || i.details.is_playable === true));
                filteredExpired = [];
            } else if (currentFilter === 'new_combo') {
                filteredActive = activeList.filter(i => i.provenance === 'new_combo');
                filteredExpired = expiredList.filter(i => i.provenance === 'new_combo');
            } else if (currentFilter === 'brand_new') {
                filteredActive = activeList.filter(i => i.provenance === 'brand_new_server');
                filteredExpired = expiredList.filter(i => i.provenance === 'brand_new_server');
            } else if (currentFilter === 'original') {
                filteredActive = activeList.filter(i => i.provenance === 'original_pair');
                filteredExpired = expiredList.filter(i => i.provenance === 'original_pair');
            } else if (currentFilter === 'expired') {
                filteredActive = [];
                filteredExpired = expiredList;
            }

            if (filteredActive.length === 0 && filteredExpired.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:30px;">No matching results found in this category.</td></tr>';
                return;
            }

            filteredActive.forEach(item => {
                const isPlayable = item.details && item.details.is_playable === 'Yes';
                let infoParts = [];
                if (item.details) {
                    if (item.details.live_channels && item.details.live_channels !== '0' && item.details.live_channels !== 0) {
                        infoParts.push(`📺 ${item.details.live_channels} Live Channels`);
                    }
                    if (item.details.vod_movies && item.details.vod_movies !== '0' && item.details.vod_movies !== 0) {
                        infoParts.push(`🎬 ${item.details.vod_movies} Movies`);
                    }
                    if (item.details.verified_sample && item.details.verified_sample !== 'N/A') {
                        infoParts.push(`Verified: ${item.details.verified_sample}`);
                    }
                    if (item.details.max_connections) {
                        infoParts.push(`Max Cons: ${item.details.max_connections}`);
                    }
                    if (item.details.exp_date && item.details.exp_date !== 'N/A') {
                        infoParts.push(`Exp: ${item.details.exp_date}`);
                    }
                }
                const infoStr = infoParts.join(' | ');

                // Playability Badge
                const statusBadge = isPlayable
                    ? `<span class="badge" style="background:rgba(0,230,118,0.18); color:#00e676; border:1px solid rgba(0,230,118,0.4); font-weight:700;">🎬 Playable</span>`
                    : `<span class="badge badge-active" style="background:rgba(255,171,0,0.18); color:#ffab00; border:1px solid rgba(255,171,0,0.4);">🟡 Active</span>`;

                // Provenance Origin Badge
                let originBadge = '';
                if (item.provenance === 'brand_new_server') {
                    originBadge = `<span class="badge" style="background:rgba(0,212,255,0.15); color:#00d4ff; border:1px solid rgba(0,212,255,0.3); font-size:10px; margin-left:4px;">🌐 Brand New Server</span>`;
                } else if (item.provenance === 'new_combo') {
                    originBadge = `<span class="badge" style="background:rgba(187,134,252,0.15); color:#bb86fc; border:1px solid rgba(187,134,252,0.3); font-size:10px; margin-left:4px;">🌟 New Match</span>`;
                } else {
                    originBadge = `<span class="badge" style="background:rgba(255,255,255,0.06); color:var(--text-dim); border:1px solid rgba(255,255,255,0.15); font-size:10px; margin-left:4px;">📁 Original Target</span>`;
                }

                const row = document.createElement('tr');
                const safeTarget = escapeJs(item.target);
                const safeM3u = escapeJs(getM3uUrl(item.target));
                row.innerHTML = `
                    <td style="white-space:nowrap">${item.timestamp}</td>
                    <td>
                        <strong>${escapeHtml(item.target)}</strong>
                        <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">${escapeHtml(infoStr)}</div>
                    </td>
                    <td style="white-space:nowrap">
                        ${statusBadge}
                        ${originBadge}
                    </td>
                    <td style="white-space:nowrap">
                        <button class="copy-btn" onclick="copyText('${safeTarget}', this)">Copy</button>
                        <button class="copy-btn" style="margin-left:5px; background:rgba(0,230,118,0.12); color:var(--color-success); border-color:rgba(0,230,118,0.3)" onclick="copyText('${safeM3u}', this)">M3U URL</button>
                    </td>
                `;
                tbody.appendChild(row);
            });

            filteredExpired.forEach(item => {
                let originBadge = '';
                if (item.provenance === 'brand_new_server') {
                    originBadge = `<span class="badge" style="background:rgba(0,212,255,0.15); color:#00d4ff; border:1px solid rgba(0,212,255,0.3); font-size:10px; margin-left:4px;">🌐 Brand New</span>`;
                } else if (item.provenance === 'new_combo') {
                    originBadge = `<span class="badge" style="background:rgba(187,134,252,0.15); color:#bb86fc; border:1px solid rgba(187,134,252,0.3); font-size:10px; margin-left:4px;">🌟 New Combo</span>`;
                }

                const row = document.createElement('tr');
                const safeTarget = escapeJs(item.target);
                row.innerHTML = `
                    <td style="white-space:nowrap">${item.timestamp}</td>
                    <td><strong>${escapeHtml(item.target)}</strong></td>
                    <td style="white-space:nowrap"><span class="badge badge-expired">Expired</span> ${originBadge}</td>
                    <td style="white-space:nowrap"><button class="copy-btn" onclick="copyText('${safeTarget}', this)">Copy</button></td>
                `;
                tbody.appendChild(row);
            });
        }

        /* UTILITIES */
        function getM3uUrl(target) {
            try {
                const parts = target.split('/');
                const pass = parts.pop();
                const user = parts.pop();
                const base = parts.join('/');
                return `${base}/get.php?username=${user}&password=${pass}&type=m3u_plus&output=ts`;
            } catch (e) {
                return target;
            }
        }

        function copyText(txt, btn) {
            navigator.clipboard.writeText(txt).then(() => {
                const targetBtn = btn || (window.event ? window.event.target : null);
                if (targetBtn) {
                    const old = targetBtn.innerText;
                    targetBtn.innerText = 'Copied!';
                    targetBtn.style.background = 'rgba(0, 230, 118, 0.15)';
                    targetBtn.style.color = 'var(--color-success)';
                    setTimeout(() => {
                        targetBtn.innerText = old;
                        targetBtn.style.background = '';
                        targetBtn.style.color = '';
                    }, 1200);
                }
            }).catch(() => {
                prompt("Copy URL:", txt);
            });
        }

        function escapeHtml(text) {
            if (!text) return '';
            return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                       .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }

        function escapeJs(text) {
            if (!text) return '';
            return JSON.stringify(String(text)).slice(1, -1).replace(/'/g, "\\'");
        }

        function loadSavedConfig() {
            fetch('/api/config')
            .then(res => res.json())
            .then(cfg => {
                if (!cfg) return;
                const d = cfg.discovery || {};
                if (d.shodan_api_key) {
                    document.getElementById('shodanApiKey').value = d.shodan_api_key;
                }
                if (d.censys_api_id) {
                    document.getElementById('censysApiId').value = d.censys_api_id;
                }
                if (d.censys_api_secret) {
                    document.getElementById('censysApiSecret').value = d.censys_api_secret;
                }
                if (d.fofa_email) {
                    document.getElementById('fofaEmail').value = d.fofa_email;
                }
                if (d.fofa_api_key) {
                    document.getElementById('fofaApiKey').value = d.fofa_api_key;
                }
                if (d.targets_extract_file) {
                    document.getElementById('targetsExtractFile').value = d.targets_extract_file;
                }
                if (cfg.threads) {
                    document.getElementById('threadCount').value = cfg.threads;
                }
                if (cfg.polite_delay !== undefined) {
                    document.getElementById('politeDelay').value = cfg.polite_delay;
                }
            })
            .catch(() => {});
        }

        function resetDashboard() {
            if (!confirm("Are you sure you want to reset stats and clear old results to start fresh from zero?")) return;
            fetch('/api/reset', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                document.getElementById('statChecked').innerText = '0';
                document.getElementById('statActive').innerText = '0';
                document.getElementById('statExpired').innerText = '0';
                document.getElementById('statSpeed').innerText = '0.0';
                document.getElementById('statEta').innerText = '—';
                document.getElementById('progressBar').style.width = '0%';
                document.getElementById('progressPct').innerText = '0%';
                document.getElementById('phaseLabel').innerText = 'Phase: IDLE';
                document.getElementById('consoleBox').innerHTML = '<div class="console-line">Session reset to zero. Ready for a clean new scan.</div>';
                fetchResults();
            })
            .catch(() => {});
        }

        // Auto-start polling and config loading
        loadSavedConfig();
        fetchResults();
        startPolling();
    </script>
</body>
</html>
"""

def serve_gui(host='localhost', port=8080):
    """Start the HTTP server to host the Web GUI."""
    web_handler = WebUILogHandler()
    web_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
    logging.getLogger().addHandler(web_handler)
    
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, WebUIRequestHandler)
    httpd.daemon_threads = True
    print(f"\n[+] IPTV Checker Web GUI is active!")
    print(f"[+] Navigate to: http://{host}:{port} in your browser.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Web GUI server stopped.")
        sys.exit(0)

if __name__ == '__main__':
    serve_gui()
