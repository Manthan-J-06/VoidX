import os

# Set env vars BEFORE importing main so the module-level code uses them
os.environ.setdefault("PB_API_KEY", "smoke-test-key-not-real-1234567890")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:16379/0")
os.environ.setdefault("REAPER_INTERVAL_SECONDS", "3600")

import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app


def test_health_returns_json_with_status():
    with TestClient(app) as client:
        res = client.get("/health")
        assert res.status_code in (200, 503), f"Expected 200 or 503, got {res.status_code}"
        data = res.json()
        assert "status" in data, f"Response body missing 'status' key: {data}"


def test_dashboard_loads_without_key():
    with TestClient(app) as client:
        res = client.get("/")
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        assert "text/html" in res.headers.get("content-type", ""), \
            f"Expected text/html content-type, got {res.headers.get('content-type')}"
        assert "VoidX" in res.text, "Expected 'VoidX' in dashboard body"


def test_dashboard_has_security_headers():
    with TestClient(app) as client:
        res = client.get("/")
        headers = {k.lower(): v for k, v in res.headers.items()}
        assert "content-security-policy" in headers, \
            "Missing 'content-security-policy' header"
        assert "x-frame-options" in headers, \
            "Missing 'x-frame-options' header"
        assert "cache-control" in headers, \
            "Missing 'cache-control' header"


def test_sessions_requires_key():
    with TestClient(app) as client:
        res = client.get("/sessions")
        assert res.status_code == 401, f"Expected 401 with no key, got {res.status_code}"


def test_sessions_rejects_wrong_key():
    with TestClient(app) as client:
        res = client.get("/sessions", headers={"X-API-Key": "wrong"})
        assert res.status_code == 401, f"Expected 401 with wrong key, got {res.status_code}"


def test_create_session_requires_key():
    with TestClient(app) as client:
        res = client.post("/sessions")
        assert res.status_code == 401, f"Expected 401 with no key on POST /sessions, got {res.status_code}"


def test_unknown_path_requires_key():
    with TestClient(app) as client:
        res = client.get("/this-does-not-exist")
        assert res.status_code == 401, \
            f"Expected 401 (key check before routing) for unknown path, got {res.status_code}"
