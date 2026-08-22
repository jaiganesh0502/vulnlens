"""Local offline web server for NexoraPay Cyber Risk Simulator.

Runs with Python's standard library (zero external dependencies required)
and serves the cybersecurity operations console dashboard.
"""

from __future__ import annotations

import json
import os
import sys
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from nexorapay.models import (
    Criticality,
    Exposure,
    PriorityLevel,
    RiskAppetite,
)
from nexorapay.scenarios import (
    DEMO_SCENARIOS,
    EDUCATIONAL_SIGNALS,
    NEXORAPAY_ORG,
    REAL_WORLD_CASE_STUDY,
)
from nexorapay.scoring import (
    PROFILE_WEIGHTS,
    calculate_score_breakdown,
)
from nexorapay.simulator import CyberRiskSimulator

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class NexoraPayHandler(SimpleHTTPRequestHandler):
    """Custom request handler serving static dashboard and JSON API endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/bootstrap":
            simulator = CyberRiskSimulator()
            appetite_param = query.get("appetite", ["low"])[0]
            appetite = RiskAppetite.from_str(appetite_param)

            evaluated = simulator.evaluate_all(risk_appetite=appetite)
            scenarios_payload = []
            for vuln, breakdown in evaluated:
                scenarios_payload.append({
                    "scenario": vuln.to_dict(),
                    "breakdown": breakdown.to_dict(),
                })

            payload = {
                "organisation": simulator.organisation.to_dict(),
                "scenarios": scenarios_payload,
                "educational_signals": EDUCATIONAL_SIGNALS,
                "case_study": REAL_WORLD_CASE_STUDY,
                "profiles": {
                    app.value: {
                        "weights": weights.to_dict(),
                        "percentages": weights.format_percentages(),
                    }
                    for app, weights in PROFILE_WEIGHTS.items()
                },
                "active_profile": appetite.value,
            }
            self._send_json(payload)
            return

        if path == "/api/what-if":
            try:
                vuln_id = query.get("vuln_id", ["NXP-DEMO-002"])[0]
                exp_param = query.get("exposure", [None])[0]
                crit_param = query.get("criticality", [None])[0]
                kev_param = query.get("kev", [None])[0]
                epss_param = query.get("epss", [None])[0]
                app_param = query.get("risk_appetite", [None])[0]

                exp = Exposure.from_str(exp_param) if exp_param else None
                crit = Criticality.from_str(crit_param) if crit_param else None
                kev = (kev_param.lower() in ("yes", "true", "1")) if kev_param is not None else None
                epss = float(epss_param) if epss_param is not None else None
                appetite = RiskAppetite.from_str(app_param) if app_param else None

                simulator = CyberRiskSimulator()
                result = simulator.run_what_if(
                    vuln_id=vuln_id,
                    exposure=exp,
                    criticality=crit,
                    kev=kev,
                    epss=epss,
                    risk_appetite=appetite,
                )
                self._send_json(result.to_dict())
            except Exception as e:
                self._send_json({"error": str(e)}, status_code=400)
            return

        # Fallback to serving static files
        super().do_GET()


def launch_server(port: int = 8085, open_browser: bool = True):
    """Start local web server and optionally open default browser."""
    server_address = ("127.0.0.1", port)
    try:
        httpd = HTTPServer(server_address, NexoraPayHandler)
    except OSError:
        # Try port + 1 if busy
        port = port + 1
        server_address = ("127.0.0.1", port)
        httpd = HTTPServer(server_address, NexoraPayHandler)

    url = f"http://127.0.0.1:{port}"
    print("=" * 60)
    print(" NEXORAPAY CYBER RISK SIMULATOR — WEB CONSOLE")
    print("=" * 60)
    print(f" Local Web Server running at: {url}")
    print(" 100% Offline-First. No external telemetry or APIs.")
    print(" Press Ctrl+C to terminate.")
    print("=" * 60)

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NexoraPay Cyber Risk Simulator Web Server.")
        httpd.server_close()


if __name__ == "__main__":
    launch_server()
