from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "threatlens.db"


class SecurityEvent(BaseModel):
    timestamp: Optional[str] = None
    source_ip: str = "127.0.0.1"
    username: Optional[str] = None
    event_type: str = Field(..., description="login_failed, login_success, port_scan, suspicious_request")
    message: str = ""
    destination_port: Optional[int] = None


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL, username TEXT, event_type TEXT NOT NULL,
            message TEXT, destination_port INTEGER)""")
        con.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            source_ip TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
            description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
            event_count INTEGER NOT NULL DEFAULT 1)""")
        con.execute("""CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL,
            title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'investigating',
            notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
            FOREIGN KEY(alert_id) REFERENCES alerts(id))""")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="ThreatLens",
    version="1.0.0",
    description="An educational defensive security monitoring and incident triage portfolio project.",
    lifespan=lifespan,
)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def detect(event: SecurityEvent):
    """Simple transparent rules for synthetic/lab events; not a production IDS."""
    with connect() as con:
        con.execute(
            """INSERT INTO events(timestamp, source_ip, username, event_type, message, destination_port)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (event.timestamp or now_iso(), event.source_ip, event.username, event.event_type,
             event.message, event.destination_port),
        )

        if event.event_type == "login_failed":
            count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE source_ip=? AND event_type='login_failed'
                   AND timestamp >= datetime('now','-15 minutes')""",
                (event.source_ip,),
            ).fetchone()[0]
            all_count = con.execute(
                "SELECT COUNT(*) FROM events WHERE source_ip=? AND event_type='login_failed'",
                (event.source_ip,),
            ).fetchone()[0]
            count = max(count, all_count)
            if count >= 5:
                create_alert(
                    con, event.source_ip, "high", "Possible brute-force activity",
                    f"{count} failed login events observed from {event.source_ip}. Review authentication logs and validate whether activity is expected.",
                    count,
                )
        elif event.event_type == "port_scan":
            create_alert(
                con, event.source_ip, "medium", "Possible port scan",
                f"A port-scan event was reported from {event.source_ip}. Validate against network telemetry and approved scanner inventory.",
                1,
            )
        elif event.event_type == "suspicious_request":
            create_alert(
                con, event.source_ip, "medium", "Suspicious web request",
                f"A request was flagged for review from {event.source_ip}. Inspect the request context and application logs.",
                1,
            )
        return con.execute("SELECT last_insert_rowid()").fetchone()[0]


def create_alert(con, ip, severity, title, description, event_count):
    existing = con.execute(
        "SELECT id FROM alerts WHERE source_ip=? AND title=? AND status='open'",
        (ip, title),
    ).fetchone()
    if existing:
        con.execute("UPDATE alerts SET event_count=? WHERE id=?", (event_count, existing["id"]))
    else:
        con.execute(
            """INSERT INTO alerts(created_at, source_ip, severity, title, description, event_count)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now_iso(), ip, severity, title, description, event_count),
        )


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (ROOT / "app" / "dashboard.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok", "service": "ThreatLens"}


@app.post("/api/events")
def ingest_event(event: SecurityEvent):
    event_id = detect(event)
    return {"accepted": True, "event_id": event_id, "message": "Event stored and evaluated against demo rules."}


@app.post("/api/demo/seed")
def seed_demo_data():
    sample = [
        SecurityEvent(source_ip="198.51.100.24", username="admin", event_type="login_failed", message="Synthetic invalid password"),
        SecurityEvent(source_ip="198.51.100.24", username="admin", event_type="login_failed", message="Synthetic invalid password"),
        SecurityEvent(source_ip="198.51.100.24", username="admin", event_type="login_failed", message="Synthetic invalid password"),
        SecurityEvent(source_ip="198.51.100.24", username="admin", event_type="login_failed", message="Synthetic invalid password"),
        SecurityEvent(source_ip="198.51.100.24", username="admin", event_type="login_failed", message="Synthetic invalid password"),
        SecurityEvent(source_ip="203.0.113.17", event_type="port_scan", message="Synthetic scan indicator"),
        SecurityEvent(source_ip="203.0.113.29", event_type="suspicious_request", message="Synthetic suspicious request indicator"),
    ]
    for item in sample:
        detect(item)
    return {"seeded_events": len(sample), "note": "Uses documentation-only TEST-NET IP addresses and synthetic events."}


@app.get("/api/summary")
def summary():
    with connect() as con:
        events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = con.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        incidents = con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    return {"events": events, "alerts": alerts, "open_alerts": open_alerts, "incidents": incidents}


@app.get("/api/alerts")
def list_alerts(status: Optional[str] = None):
    with connect() as con:
        if status:
            rows = con.execute("SELECT * FROM alerts WHERE status=? ORDER BY id DESC", (status,)).fetchall()
        else:
            rows = con.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, status: str):
    if status not in {"open", "investigating", "resolved"}:
        raise HTTPException(status_code=400, detail="status must be open, investigating, or resolved")
    with connect() as con:
        cur = con.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
    return {"updated": True, "alert_id": alert_id, "status": status}


@app.post("/api/alerts/{alert_id}/incidents")
def create_incident(alert_id: int, title: Optional[str] = None):
    with connect() as con:
        alert = con.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        cur = con.execute(
            "INSERT INTO incidents(alert_id,title,created_at) VALUES (?,?,?)",
            (alert_id, title or alert["title"], now_iso()),
        )
        incident_id = cur.lastrowid
    return {"created": True, "incident_id": incident_id, "alert_id": alert_id}


@app.get("/api/incidents")
def list_incidents():
    with connect() as con:
        rows = con.execute(
            """SELECT incidents.*, alerts.source_ip, alerts.severity
               FROM incidents JOIN alerts ON alerts.id=incidents.alert_id ORDER BY incidents.id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]
