"""Read only the running Service Agent's deployed public protocol catalog."""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

def validate(value):
    if not isinstance(value, dict) or set(value) != {"version", "language", "document"}:
        raise ValueError("selector")
    if value["version"] not in {"1.0", "1.1", "1.2"} or value["language"] not in {"en", "zh"}:
        raise ValueError("selector")
    if not isinstance(value["document"], str) or len(value["document"]) > 256 or not re.fullmatch(r"[a-z0-9_-]+(?:/[a-z0-9_-]+)*", value["document"]):
        raise ValueError("selector")

def observe(value):
    release = Path("/opt/anp-service-agent/current").resolve(strict=True)
    pid = int(subprocess.check_output(["systemctl", "show", "anp-service-agent.service", "-p", "MainPID", "--value"], text=True))
    if pid <= 0 or Path("/proc/" + str(pid) + "/cwd").resolve(strict=True) != release:
        raise ValueError("running_release")
    catalog = release / "protocol-catalog.json"
    if not catalog.is_file() or catalog.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("catalog")
    rows = json.loads(catalog.read_bytes())
    matches = [row for row in rows if all(row.get(key) == field for key, field in value.items())]
    if len(matches) != 1 or not isinstance(matches[0].get("content"), str):
        raise ValueError("document")
    body = matches[0]["content"].encode("utf-8")
    return {**value, "sha256": hashlib.sha256(body).hexdigest(), "utf8Bytes": len(body)}

if __name__ == "__main__":
    try:
        value = json.load(sys.stdin)
        validate(value)
        print(json.dumps(observe(value)))
    except Exception:
        print(json.dumps({"error": "protocol_document_oracle_unavailable"}))
        sys.exit(1)
