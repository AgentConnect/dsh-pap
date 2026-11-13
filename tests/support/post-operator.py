"""Narrow existing-Service-Agent post observer/cleanup; no deployment or configuration writes."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

def main():
    request = json.load(sys.stdin)
    action = request.get("action")
    if action not in {"preflight", "quota", "locate", "observe", "cleanup"}:
        raise ValueError("action")
    settings = {}
    for line in Path("/etc/anp-service-agent/runtime.env").read_text().splitlines():
        match = re.match(r"\s*([A-Z_]+)\s*=\s*(.*?)\s*$", line)
        if match:
            settings[match[1]] = match[2].strip("\"'")
    if settings.get("SERVICE_ORIGIN") != "https://agent.agent-network-protocol.com":
        raise ValueError("origin")
    url = urlsplit(settings["DATABASE_URL"])
    query = parse_qs(url.query)
    environment = {**os.environ, "PGHOST": query.get("host", [url.hostname or "localhost"])[0],
                   "PGPORT": str(url.port or 5432), "PGUSER": unquote(url.username or ""),
                   "PGPASSWORD": unquote(url.password or ""), "PGDATABASE": unquote(url.path.lstrip("/"))}
    command = ["runuser", "-u", "anp_service_agent", "--", "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"]
    if action == "preflight":
        sql = ("SELECT has_table_privilege(current_user,'website_posts','SELECT'),"
               "has_table_privilege(current_user,'website_posts','DELETE'),"
               "has_table_privilege(current_user,'website_post_daily_counts','SELECT'),"
               "has_table_privilege(current_user,'website_post_daily_counts','UPDATE'),"
               "has_table_privilege(current_user,'website_post_daily_counts','DELETE');")
    else:
        post_id = request.get("id", "")
        subject = request.get("subject", "")
        protocol = request.get("protocol", "")
        marker = request.get("marker", "")
        if action not in {"locate", "quota"} and not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", post_id):
            raise ValueError("id")
        if protocol not in {"anp", "pap"} or not re.fullmatch(
                r"dsh-" + protocol + r"-acceptance-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", marker):
            raise ValueError("marker")
        subject_url = urlsplit(subject)
        valid_subject = bool(re.fullmatch(r"did:(?:wba|web):awiki\.me:[A-Za-z0-9_.:%-]+", subject)) if protocol == "anp" else (
            subject_url.scheme == "https" and subject_url.netloc == "awiki.me" and subject_url.path.startswith("/")
            and len(subject_url.path) > 1 and not subject_url.query and not subject_url.fragment
        )
        if not valid_subject:
            raise ValueError("subject")
        for key in ("id", "subject", "protocol", "marker"):
            if key in request:
                command.extend(["-v", key + "=" + request[key]])
        predicate = "id=:'id'::uuid AND subject=:'subject' AND protocol=:'protocol' AND content=:'marker'"
        if action == "quota":
            sql = "SELECT COALESCE(sum(count),0) FROM website_post_daily_counts WHERE subject=:'subject';"
        elif action == "locate":
            sql = "SELECT id FROM website_posts WHERE subject=:'subject' AND protocol=:'protocol' AND content=:'marker' LIMIT 2;"
        elif action == "observe":
            sql = "SELECT count(*) FROM website_posts WHERE " + predicate + ";"
        else:
            sql = ("BEGIN; WITH removed AS (DELETE FROM website_posts WHERE " + predicate
                   + " RETURNING subject, (created_at AT TIME ZONE 'UTC')::date AS day),"
                   + "amounts AS (SELECT subject,day,count(*)::int AS amount FROM removed GROUP BY subject,day),"
                   + "updated AS (UPDATE website_post_daily_counts c SET count=c.count-a.amount FROM amounts a"
                   + " WHERE c.subject=a.subject AND c.day=a.day AND c.count>a.amount RETURNING c.subject),"
                   + "cleared AS (DELETE FROM website_post_daily_counts c USING amounts a"
                   + " WHERE c.subject=a.subject AND c.day=a.day AND c.count<=a.amount RETURNING c.subject)"
                   + " SELECT count(*) FROM removed;"
                   + "SELECT count(*) FROM website_posts WHERE id=:'id'::uuid; COMMIT;")
    result = subprocess.run(command, input=sql, text=True, capture_output=True, env=environment, timeout=15)
    if result.returncode:
        raise RuntimeError("database")
    lines = result.stdout.strip().splitlines()
    if action == "preflight":
        if lines != ["t|t|t|t|t"]:
            raise RuntimeError("permissions")
        return {"ready": True, "target": "https://agent.agent-network-protocol.com", "exactCleanup": True}
    if action == "quota":
        return {"count": int(lines[0])}
    if action == "locate":
        if len(lines) > 1:
            raise RuntimeError("ambiguous_owned_post")
        return {"ids": lines}
    if action == "observe":
        return {"matches": int(lines[0])}
    if len(lines) != 2 or lines[0] not in {"0", "1"} or lines[1] != "0":
        raise RuntimeError("cleanup_unconfirmed")
    return {"cleanupComplete": True, "deleted": int(lines[0]), "remaining": 0}

try:
    print(json.dumps(main()))
except Exception:
    print(json.dumps({"error": "service_agent_post_operator_failed"}))
    sys.exit(1)
