import os
import subprocess
import time
import json
import pathlib

import pytest
import requests

PROJECT_DIR = pathlib.Path(__file__).parent.parent


def _read_env():
    """Parse PROJECT_DIR/.env the same way start.ps1 does."""
    env_file = PROJECT_DIR / ".env"
    if not env_file.exists():
        return {}
    result = {}
    for line in env_file.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        idx = line.index("=") if "=" in line else -1
        if idx > 0:
            result[line[:idx]] = line[idx + 1:]
    return result


@pytest.fixture(scope="session")
def api_key():
    env = _read_env()
    if "PB_API_KEY" not in env:
        pytest.skip("No .env found — run start.ps1 first for integration tests")
    return env["PB_API_KEY"]


@pytest.fixture(scope="session")
def redis_auth_env():
    env = _read_env()
    return {"REDISCLI_AUTH": env.get("REDIS_PASSWORD", "")}


@pytest.fixture(scope="session")
def base_url():
    return "http://127.0.0.1:8000"


@pytest.fixture(scope="session", autouse=True)
def _require_live_server(request, base_url):
    """Skip integration tests when the live server is not reachable."""
    # Only apply to integration-marked tests
    if not any(item.get_closest_marker("integration") for item in request.session.items):
        return
    try:
        requests.get(base_url + "/health", timeout=3)
    except requests.exceptions.RequestException:
        pytest.skip("Server not reachable at 127.0.0.1:8000 — run start.ps1 first")


def docker(*args, timeout=30):
    """Run a docker command and return combined stdout+stderr stripped."""
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ,
    )
    return (result.stdout + result.stderr).strip()


def redis_cli(redis_auth_env, *args):
    """Run redis-cli inside the redis container with auth and return stdout stripped."""
    result = subprocess.run(
        ["docker", "exec", "-e", f"REDISCLI_AUTH={redis_auth_env['REDISCLI_AUTH']}", "redis", "redis-cli", *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=os.environ,
    )
    return result.stdout.strip()


def api_post(base_url, api_key, path, json_body=None):
    """POST helper with X-API-Key header."""
    kwargs = {"headers": {"X-API-Key": api_key}, "timeout": 15}
    if json_body is not None:
        kwargs["json"] = json_body
    return requests.post(base_url + path, **kwargs)


def api_get(base_url, api_key, path):
    """GET helper with X-API-Key header."""
    return requests.get(base_url + path, headers={"X-API-Key": api_key}, timeout=15)


def api_delete(base_url, api_key, path):
    """DELETE helper with X-API-Key header."""
    return requests.delete(base_url + path, headers={"X-API-Key": api_key}, timeout=15)


def wait_until_ready(base_url, api_key, session_id, timeout=90):
    """
    Poll GET /sessions/<session_id> every 3 seconds until ready is True or timeout expires.
    Returns True if became ready, False if timed out.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            res = api_get(base_url, api_key, f"/sessions/{session_id}")
            if res.status_code == 200 and res.json().get("ready"):
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    return False


@pytest.fixture
def cleanup_sessions(base_url, api_key):
    """Yield a list; DELETE every session_id appended to it after the test."""
    session_ids = []
    yield session_ids
    for sid in session_ids:
        try:
            api_delete(base_url, api_key, f"/sessions/{sid}")
        except Exception:
            pass
