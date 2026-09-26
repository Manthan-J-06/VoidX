"""
Integration tests — require a live server, Docker, Redis, and Tor.
Run with:  pytest -m integration -v
"""
import subprocess
import time
import os

import pytest
import requests

from tests.conftest import (
    docker,
    redis_cli,
    api_post,
    api_get,
    api_delete,
    wait_until_ready,
    _read_env,
)


# ---------------------------------------------------------------------------
# a. Health check with live Redis
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_health_connected_to_redis(base_url, api_key):
    res = requests.get(base_url + "/health", timeout=10)
    assert res.status_code == 200, f"Expected 200 from /health, got {res.status_code}"
    data = res.json()
    assert data.get("redis") is True, f"Expected redis=True in health response, got {data}"


# ---------------------------------------------------------------------------
# b. Redis password enforcement
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_redis_requires_password():
    result = subprocess.run(
        ["docker", "exec", "redis", "redis-cli", "PING"],
        capture_output=True,
        text=True,
        timeout=10,
        env=os.environ,
    )
    output = (result.stdout + result.stderr).strip()
    assert "NOAUTH" in output, \
        f"Expected 'NOAUTH' when connecting without password, got: {output!r}"


# ---------------------------------------------------------------------------
# c. Full CRUD lifecycle for a session
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_create_list_get_destroy_session(base_url, api_key, cleanup_sessions):
    # Create
    create_res = api_post(base_url, api_key, "/sessions")
    assert create_res.status_code == 201, \
        f"Expected 201 on session creation, got {create_res.status_code}: {create_res.text}"
    data = create_res.json()
    for key in ("session_id", "url", "expires_in", "username", "password"):
        assert key in data, f"Missing key '{key}' in create response: {data}"
    session_id = data["session_id"]
    cleanup_sessions.append(session_id)

    # GET single
    get_res = api_get(base_url, api_key, f"/sessions/{session_id}")
    assert get_res.status_code == 200, \
        f"Expected 200 on GET /sessions/{session_id}, got {get_res.status_code}"
    assert "ready" in get_res.json(), f"'ready' key missing in GET response: {get_res.json()}"

    # Poll until ready
    became_ready = wait_until_ready(base_url, api_key, session_id, timeout=90)
    assert became_ready, f"Session {session_id} did not become ready within 90s"

    # List
    list_res = api_get(base_url, api_key, "/sessions")
    assert list_res.status_code == 200, \
        f"Expected 200 on GET /sessions, got {list_res.status_code}"
    listed_ids = [s["session_id"] for s in list_res.json().get("sessions", [])]
    assert session_id in listed_ids, \
        f"Session {session_id} not found in session list: {listed_ids}"

    # Delete
    del_res = api_delete(base_url, api_key, f"/sessions/{session_id}")
    assert del_res.status_code == 200, \
        f"Expected 200 on DELETE /sessions/{session_id}, got {del_res.status_code}"
    assert del_res.json() == {"destroyed": session_id}, \
        f"Unexpected delete response: {del_res.json()}"
    cleanup_sessions.remove(session_id)

    # Confirm containers cleaned up
    deadline = time.time() + 10
    containers_gone = False
    while time.time() < deadline:
        ps_out = docker("ps", "-aq", "--filter", f"label=pb.session={session_id}")
        if not ps_out:
            containers_gone = True
            break
        time.sleep(1)
    assert containers_gone, \
        f"Containers for session {session_id} still present after DELETE"


# ---------------------------------------------------------------------------
# d. Custom duration accepted and enforced
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_custom_duration_accepted_and_enforced(base_url, api_key, cleanup_sessions, redis_auth_env):
    res = api_post(base_url, api_key, "/sessions", json_body={"duration_seconds": 120})
    assert res.status_code == 201, \
        f"Expected 201 with duration_seconds=120, got {res.status_code}: {res.text}"
    data = res.json()
    session_id = data["session_id"]
    cleanup_sessions.append(session_id)

    assert data["expires_in"] == 120, \
        f"Expected expires_in=120, got {data['expires_in']}"

    ttl_str = redis_cli(redis_auth_env, "TTL", f"session:{session_id}")
    try:
        ttl = int(ttl_str)
    except ValueError:
        pytest.fail(f"redis TTL returned non-integer: {ttl_str!r}")
    assert 100 <= ttl <= 120, \
        f"Expected Redis TTL between 100 and 120, got {ttl}"

    api_delete(base_url, api_key, f"/sessions/{session_id}")
    cleanup_sessions.remove(session_id)


# ---------------------------------------------------------------------------
# e. Custom duration out-of-range rejected
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_custom_duration_out_of_range_rejected(base_url, api_key):
    # Too short
    res_low = api_post(base_url, api_key, "/sessions", json_body={"duration_seconds": 10})
    assert res_low.status_code == 400, \
        f"Expected 400 for duration_seconds=10, got {res_low.status_code}"
    assert res_low.json().get("error") == "invalid_duration", \
        f"Expected error='invalid_duration', got {res_low.json()}"

    # Too long
    res_high = api_post(base_url, api_key, "/sessions", json_body={"duration_seconds": 10000})
    assert res_high.status_code == 400, \
        f"Expected 400 for duration_seconds=10000, got {res_high.status_code}"
    assert res_high.json().get("error") == "invalid_duration", \
        f"Expected error='invalid_duration', got {res_high.json()}"


# ---------------------------------------------------------------------------
# f. Session hardening
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_session_hardening(base_url, api_key, cleanup_sessions):
    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    session_id = res.json()["session_id"]
    cleanup_sessions.append(session_id)

    became_ready = wait_until_ready(base_url, api_key, session_id, timeout=90)
    assert became_ready, f"Session {session_id} did not become ready within 90s"

    name = f"pbsession-{session_id}"

    sec_opt = docker("inspect", name, "--format", "{{.HostConfig.SecurityOpt}}")
    assert "no-new-privileges" in sec_opt, \
        f"Expected no-new-privileges in SecurityOpt, got: {sec_opt!r}"

    pids = docker("inspect", name, "--format", "{{.HostConfig.PidsLimit}}")
    assert pids.strip() == "512", \
        f"Expected PidsLimit=512, got: {pids!r}"

    cap_drop = docker("inspect", name, "--format", "{{.HostConfig.CapDrop}}")
    assert "ALL" in cap_drop, \
        f"Expected ALL in CapDrop, got: {cap_drop!r}"

    sudo_result = docker("exec", "-u", "abc", name, "sh", "-c",
                         "sudo -n true >/dev/null 2>&1; echo $?")
    assert sudo_result.strip() != "0", \
        f"Expected sudo to fail (non-zero exit) inside container, got: {sudo_result!r}"

    api_delete(base_url, api_key, f"/sessions/{session_id}")
    cleanup_sessions.remove(session_id)


# ---------------------------------------------------------------------------
# g. Network isolation
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_session_network_isolation(base_url, api_key, cleanup_sessions):
    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    session_id = res.json()["session_id"]
    cleanup_sessions.append(session_id)

    became_ready = wait_until_ready(base_url, api_key, session_id, timeout=90)
    assert became_ready, f"Session {session_id} did not become ready within 90s"

    container = f"pbsession-{session_id}"
    net = f"pbint-{session_id}"

    # Internal network flag
    internal_flag = docker("network", "inspect", net, "--format", "{{.Internal}}")
    assert internal_flag.strip() == "true", \
        f"Expected pbint-{session_id} to be internal, got: {internal_flag!r}"

    # No direct internet access
    reach_internet = docker("exec", "-u", "abc", container, "sh", "-c",
                            "timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/443' >/dev/null 2>&1 && echo OPEN || echo CLOSED")
    assert "CLOSED" in reach_internet, \
        f"Expected CLOSED for 1.1.1.1:443, got: {reach_internet!r}"

    # No access to host Redis
    reach_redis = docker("exec", "-u", "abc", container, "sh", "-c",
                         "timeout 3 bash -c 'echo > /dev/tcp/host.docker.internal/16379' >/dev/null 2>&1 && echo OPEN || echo CLOSED")
    assert "CLOSED" in reach_redis, \
        f"Expected CLOSED for host Redis:16379, got: {reach_redis!r}"

    # No access to host API
    reach_api = docker("exec", "-u", "abc", container, "sh", "-c",
                       "timeout 3 bash -c 'echo > /dev/tcp/host.docker.internal/8000' >/dev/null 2>&1 && echo OPEN || echo CLOSED")
    assert "CLOSED" in reach_api, \
        f"Expected CLOSED for host API:8000, got: {reach_api!r}"

    # Tor proxy reachable
    reach_tor = docker("exec", "-u", "abc", container, "sh", "-c",
                       "timeout 3 bash -c 'echo > /dev/tcp/tor/9050' >/dev/null 2>&1 && echo OPEN || echo CLOSED")
    assert "OPEN" in reach_tor, \
        f"Expected OPEN for tor:9050, got: {reach_tor!r}"

    api_delete(base_url, api_key, f"/sessions/{session_id}")
    cleanup_sessions.remove(session_id)


# ---------------------------------------------------------------------------
# h. Tor routing
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_tor_routing(base_url, api_key, cleanup_sessions):
    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    session_id = res.json()["session_id"]
    cleanup_sessions.append(session_id)

    became_ready = wait_until_ready(base_url, api_key, session_id, timeout=90)
    assert became_ready, f"Session {session_id} did not become ready within 90s"

    container = f"pbsession-{session_id}"
    output = docker("exec", "-u", "abc", container, "sh", "-c",
                    "curl -s -m 45 --socks5-hostname tor:9050 https://check.torproject.org/api/ip",
                    timeout=60)
    assert '"IsTor":true' in output or '"IsTor": true' in output, \
        f"Expected IsTor=true from check.torproject.org, got: {output!r}"

    api_delete(base_url, api_key, f"/sessions/{session_id}")
    cleanup_sessions.remove(session_id)


# ---------------------------------------------------------------------------
# i. Rate limiting on session creation
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_rate_limit_on_session_creation(base_url, api_key, cleanup_sessions, redis_auth_env):
    # Reset the rate limit counter
    redis_cli(redis_auth_env, "DEL", "rl:create")

    got_429 = False
    retry_after_present = False

    for _ in range(6):
        res = api_post(base_url, api_key, "/sessions")
        if res.status_code == 201:
            data = res.json()
            cleanup_sessions.append(data["session_id"])
        elif res.status_code == 429:
            data = res.json()
            if data.get("error") == "rate_limited":
                got_429 = True
                retry_after_present = "Retry-After" in res.headers
                break

    assert got_429, "Expected at least one 429 rate_limited response among 6 rapid POSTs"
    assert retry_after_present, "Expected Retry-After header in 429 rate_limited response"


# ---------------------------------------------------------------------------
# j. Wrong-key lockout and recovery  (slow: ~70s)
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_wrong_key_lockout_and_recovery(base_url, api_key, redis_auth_env):
    # Reset lockout counter for localhost
    redis_cli(redis_auth_env, "DEL", "rl:auth:127.0.0.1")

    got_lockout = False
    for i in range(15):
        res = requests.get(
            base_url + "/sessions",
            headers={"X-API-Key": f"wrong-key-{i}"},
            timeout=10,
        )
        if res.status_code == 429 and res.json().get("error") == "too_many_attempts":
            got_lockout = True
            break

    assert got_lockout, "Expected a 429 too_many_attempts lockout within 15 wrong-key attempts"

    # Even the real key should be locked out right now
    locked_res = api_get(base_url, api_key, "/sessions")
    assert locked_res.status_code == 429, \
        f"Expected real key to be locked out (429), got {locked_res.status_code}"

    # Wait for lockout to expire
    time.sleep(65)

    # Real key should work again
    recovered_res = api_get(base_url, api_key, "/sessions")
    assert recovered_res.status_code == 200, \
        f"Expected 200 after lockout expired, got {recovered_res.status_code}"


# ---------------------------------------------------------------------------
# k. Audit log records events and no secrets
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_audit_log_records_events_and_no_secrets(base_url, api_key, cleanup_sessions):
    env = _read_env()
    redis_password = env.get("REDIS_PASSWORD", "")

    # Create session
    create_res = api_post(base_url, api_key, "/sessions")
    assert create_res.status_code == 201, \
        f"Expected 201, got {create_res.status_code}: {create_res.text}"
    create_data = create_res.json()
    session_id = create_data["session_id"]
    session_password = create_data["password"]
    cleanup_sessions.append(session_id)

    # Delete session
    del_res = api_delete(base_url, api_key, f"/sessions/{session_id}")
    assert del_res.status_code == 200
    cleanup_sessions.remove(session_id)

    # Get audit log
    audit_res = api_get(base_url, api_key, "/audit?count=200")
    assert audit_res.status_code == 200, \
        f"Expected 200 from /audit, got {audit_res.status_code}"
    audit_data = audit_res.json()
    assert "events" in audit_data, f"'events' key missing in audit response: {audit_data}"

    events = audit_data["events"]
    created_events = [e for e in events if e.get("event") == "session_created" and e.get("session_id") == session_id]
    destroyed_events = [e for e in events if e.get("event") == "session_destroyed" and e.get("session_id") == session_id]

    assert created_events, f"No session_created event found for session {session_id}"
    assert destroyed_events, f"No session_destroyed event found for session {session_id}"

    raw_text = audit_res.text
    assert api_key not in raw_text, "API key exposed in audit log response!"
    if redis_password:
        assert redis_password not in raw_text, "Redis password exposed in audit log response!"
    assert session_password not in raw_text, \
        "Session password exposed in audit log response!"


# ---------------------------------------------------------------------------
# l. Reaper cleans up abandoned session
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_reaper_cleans_up_abandoned_session(base_url, api_key, redis_auth_env):
    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    session_id = res.json()["session_id"]

    # Wait briefly for containers to be created
    time.sleep(5)

    # Simulate crash — delete the Redis record without stopping containers
    redis_cli(redis_auth_env, "DEL", f"session:{session_id}")

    # Poll up to 90s for containers to disappear
    deadline = time.time() + 90
    containers_gone = False
    while time.time() < deadline:
        ps_out = docker("ps", "-aq", "--filter", f"label=pb.session={session_id}")
        if not ps_out:
            containers_gone = True
            break
        time.sleep(3)

    # Poll up to 90s for network to disappear
    net_gone = False
    deadline2 = time.time() + 90
    while time.time() < deadline2:
        net_out = docker("network", "ls", "-q", "--filter", f"label=pb.session={session_id}")
        if not net_out:
            net_gone = True
            break
        time.sleep(3)

    assert containers_gone, \
        f"Containers for abandoned session {session_id} were not reaped within 90s"
    assert net_gone, \
        f"Network for abandoned session {session_id} was not reaped within 90s"
