#!/usr/bin/env python3
"""
alert-sink.py — Dich nhan canh bao, chi dung thu vien chuan.

Can cu: Juice_Shop_Telemetry_Lab_Guide.docx muc 3.3:
  "Dashboards show events, but an alert should also reach a place a person or a
   script can act on. The lab uses a tiny local webhook receiver, the alert sink,
   which appends one readable line per alert to /var/log/lab-alerts.log."

Ly do ton tai trong du an nay: `loki-config.yml:30` tro ruler toi
`http://alertmanager:9093`, nhung khong tep compose nao co dich vu alertmanager.
Vi vay ca 9 luat canh bao cua ban goc deu duoc danh gia roi gui vao mot host
khong ton tai. Chuoi phat hien dut o buoc cuoi.

Trong trien khai that, dich nay duoc thay bang email, Slack hoac he thong ticket.
"""

import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.environ.get("ALERT_LOG", "/var/log/lab-alerts.log")
LISTEN_PORT = int(os.environ.get("ALERT_PORT", "9099"))


def write_line(text: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{stamp} {text}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(f"{stamp} khong ghi duoc {LOG_PATH}: {exc}", file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            write_line(f"payload khong doc duoc, {length} byte")
            self.send_response(400)
            self.end_headers()
            return

        alerts = payload.get("alerts") or [payload]
        for alert in alerts:
            labels = alert.get("labels") or {}
            annotations = alert.get("annotations") or {}
            write_line(
                "status={status} alert={name} severity={sev} mitre={mitre} "
                "client_ip={ip} summary={summary}".format(
                    status=alert.get("status", payload.get("status", "?")),
                    name=labels.get("alertname", "?"),
                    sev=labels.get("severity", "?"),
                    mitre=labels.get("mitre", "-"),
                    ip=labels.get("client_ip", "-"),
                    summary=annotations.get("summary", "-"),
                )
            )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"alert sink dang chay\n")

    def log_message(self, fmt: str, *args: object) -> None:
        return  # im lang, moi dong ghi ra da do write_line dam nhiem


if __name__ == "__main__":
    write_line(f"alert sink khoi dong, cong {LISTEN_PORT}, ghi vao {LOG_PATH}")
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
