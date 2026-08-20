"""
HTML report generator.
Creates a visual summary report after each IPTV check run.
"""
import os
import logging
from datetime import datetime

log = logging.getLogger(__name__)

RESULTS_DIR = "results"


def generate_report(stats, session_data, output_dir=None):
    """
    Generate an HTML report summarizing the IPTV check run.

    Args:
        stats: Dictionary from StatsTracker.get_stats().
        session_data: Dictionary with session metadata.
        output_dir: Directory to write the report to.
    """
    if output_dir is None:
        output_dir = RESULTS_DIR

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "report.html")

    active = session_data.get('active_found', 0)
    expired = session_data.get('expired_found', 0)
    checked = stats.get('attempted', 0)
    total = stats.get('total', 0)
    speed = stats.get('speed', 0)
    errors = stats.get('errors', 0)
    elapsed = stats.get('elapsed', 0)
    proxies = stats.get('proxies_alive', 0)
    xtream = session_data.get('xtream_targets', 0)
    m3u = session_data.get('m3u_targets', 0)

    pct = (checked / total * 100) if total > 0 else 0
    elapsed_str = _format_elapsed(elapsed)

    # Determine overall status
    if active > 0:
        status_class = "success"
        status_text = f"🎉 {active} ACTIVE SERVICE{'S' if active != 1 else ''} FOUND"
    elif checked >= total:
        status_class = "fail"
        status_text = "❌ NO ACTIVE SERVICES FOUND"
    else:
        status_class = "partial"
        status_text = "⏸️ CHECK INCOMPLETE"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPTV Checker Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0a14;
            color: #e0e0e0;
            padding: 40px 20px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 35px;
            background: linear-gradient(135deg, #0d1117, #161b22, #1a1a2e);
            border-radius: 20px;
            border: 1px solid #30363d;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }}
        .header h1 {{
            font-size: 32px;
            background: linear-gradient(135deg, #58a6ff, #bc8cff, #f778ba);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        .header .subtitle {{ color: #8b949e; font-size: 15px; }}
        .header .timestamp {{ color: #484f58; font-size: 13px; margin-top: 10px; }}

        .status {{
            text-align: center;
            padding: 28px;
            border-radius: 16px;
            margin-bottom: 30px;
            font-size: 24px;
            font-weight: bold;
            box-shadow: 0 4px 16px rgba(0,0,0,0.3);
        }}
        .status.success {{
            background: linear-gradient(135deg, #0d3b1e, #1a5c30);
            border: 1px solid #238636;
            color: #3fb950;
        }}
        .status.fail {{
            background: linear-gradient(135deg, #3b0d0d, #5c1a1a);
            border: 1px solid #da3633;
            color: #f85149;
        }}
        .status.partial {{
            background: linear-gradient(135deg, #3b2e0d, #5c4a1a);
            border: 1px solid #d29922;
            color: #e3b341;
        }}
        .status .detail {{
            font-size: 14px;
            margin-top: 10px;
            font-weight: normal;
            color: #8b949e;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .card {{
            background: linear-gradient(145deg, #161b22, #0d1117);
            border: 1px solid #30363d;
            border-radius: 14px;
            padding: 22px 16px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(88, 166, 255, 0.1);
        }}
        .card .value {{
            font-size: 30px;
            font-weight: bold;
            background: linear-gradient(135deg, #58a6ff, #bc8cff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .card .label {{
            font-size: 12px;
            color: #8b949e;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .card.active .value {{
            background: linear-gradient(135deg, #3fb950, #56d364);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .card.expired .value {{
            background: linear-gradient(135deg, #e3b341, #d29922);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .card.error .value {{
            background: linear-gradient(135deg, #f85149, #da3633);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .progress-section {{ margin-bottom: 30px; }}
        .progress-bar {{
            background: #161b22;
            border-radius: 10px;
            height: 28px;
            overflow: hidden;
            border: 1px solid #30363d;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #58a6ff, #bc8cff, #f778ba);
            border-radius: 10px;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
            color: white;
            min-width: 50px;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
        }}
        .progress-label {{
            text-align: center;
            margin-top: 10px;
            color: #8b949e;
            font-size: 13px;
        }}

        .types-bar {{
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-bottom: 30px;
        }}
        .type-badge {{
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
        }}
        .type-badge.xtream {{
            background: rgba(88, 166, 255, 0.15);
            border: 1px solid #58a6ff;
            color: #58a6ff;
        }}
        .type-badge.m3u {{
            background: rgba(188, 140, 255, 0.15);
            border: 1px solid #bc8cff;
            color: #bc8cff;
        }}

        .footer {{
            text-align: center;
            color: #484f58;
            font-size: 12px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #21262d;
        }}

        code {{
            background: #2a2a4a;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            color: #3fb950;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📺 IPTV Checker Report</h1>
            <div class="subtitle">Xtream Codes Server Discovery</div>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <div class="status {status_class}">
            {status_text}
            <div class="detail">
                Checked {checked:,} of {total:,} credential combinations in {elapsed_str}
            </div>
        </div>

        <div class="types-bar">
            <span class="type-badge xtream">🔌 Xtream Servers: {xtream}</span>
        </div>

        <div class="grid">
            <div class="card">
                <div class="value">{checked:,}</div>
                <div class="label">Checked</div>
            </div>
            <div class="card">
                <div class="value">{total:,}</div>
                <div class="label">Total Targets</div>
            </div>
            <div class="card active">
                <div class="value">{active}</div>
                <div class="label">Active</div>
            </div>
            <div class="card expired">
                <div class="value">{expired}</div>
                <div class="label">Expired</div>
            </div>
            <div class="card">
                <div class="value">{speed:.1f}/m</div>
                <div class="label">Speed</div>
            </div>
            <div class="card">
                <div class="value">{elapsed_str}</div>
                <div class="label">Duration</div>
            </div>
            <div class="card error">
                <div class="value">{errors}</div>
                <div class="label">Errors</div>
            </div>
            <div class="card">
                <div class="value">{proxies}</div>
                <div class="label">Proxies</div>
            </div>
        </div>

        <div class="progress-section">
            <div class="progress-bar">
                <div class="progress-fill" style="width: {max(pct, 1):.1f}%">
                    {pct:.1f}%
                </div>
            </div>
            <div class="progress-label">
                {checked:,} of {total:,} targets checked
            </div>
        </div>

        <div class="footer">
            IPTV Checker v1.0 &mdash; Report generated automatically
        </div>
    </div>
</body>
</html>"""

    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        log.info(f"📊 HTML report saved to {report_path}")
    except Exception as e:
        log.error(f"Failed to save HTML report: {e}")


def _format_elapsed(seconds):
    """Format elapsed seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"
