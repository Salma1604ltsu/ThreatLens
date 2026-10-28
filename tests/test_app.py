from fastapi.testclient import TestClient
import tempfile
from pathlib import Path
import app.main as main
from app.main import app


def setup_function():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    main.DB_PATH = Path(tmp.name)
    main.init_db()


def test_health():
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"


def test_event_ingestion_and_detection():
    client = TestClient(app)
    for _ in range(5):
        r = client.post("/api/events", json={
            "source_ip": "198.51.100.44", "username": "demo",
            "event_type": "login_failed", "message": "synthetic failed login"
        })
        assert r.status_code == 200
    alerts = client.get("/api/alerts").json()
    assert any(a["title"] == "Possible brute-force activity" for a in alerts)


def test_invalid_alert_status():
    client = TestClient(app)
    r = client.patch("/api/alerts/1?status=banana")
    assert r.status_code == 400
