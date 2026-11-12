import re
import time
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

pytestmark = pytest.mark.integration


def metric(text, name):
    m = re.search(r"(?m)^" + re.escape(name) + r"\s+([0-9.eE+-]+)\s*$", text)
    if m:
        return float(m.group(1))
    return None


def snapshot(base_url, api_key):
    res = api_get(base_url, api_key, "/metrics")
    assert res.status_code == 200, f"Expected 200 from GET /metrics, got {res.status_code}: {res.text}"
    return res.text


def clear_limits(redis_auth_env):
    return redis_cli(redis_auth_env, "DEL", "rl:create", "rl:auth:127.0.0.1")


def test_metrics_requires_key_and_exposes_all_series(base_url, api_key, redis_auth_env):
    try:
        r_unauth = requests.get(base_url + "/metrics", timeout=15)
        assert r_unauth.status_code == 401, f"Expected 401 without key, got {r_unauth.status_code}: {r_unauth.text}"

        r_auth = api_get(base_url, api_key, "/metrics")
        assert r_auth.status_code == 200, f"Expected 200 with key, got {r_auth.status_code}: {r_auth.text}"
        ct = r_auth.headers.get("content-type", "")
        assert "text/plain" in ct, f"Expected 'text/plain' in content-type, got: {ct}"

        series_names = [
            "voidx_sessions_created_total",
            "voidx_sessions_destroyed_total",
            "voidx_sessions_expired_total",
            "voidx_rate_limited_total",
            "voidx_auth_failures_total",
            "voidx_auth_lockout_responses_total",
            "voidx_sessions_active",
            "voidx_time_to_ready_seconds_sum",
            "voidx_time_to_ready_seconds_count",
        ]
        for name in series_names:
            val = metric(r_auth.text, name)
            assert val is not None, f"Expected series '{name}' in metrics, but not found in:\n{r_auth.text}"

        type_lines = [line for line in r_auth.text.splitlines() if line.startswith("# TYPE ")]
        assert len(type_lines) == 8, f"Expected exactly 8 '# TYPE ' lines, got {len(type_lines)}: {type_lines}"
    finally:
        clear_limits(redis_auth_env)


def test_metrics_session_lifecycle_counts(base_url, api_key, redis_auth_env, cleanup_sessions):
    clear_limits(redis_auth_env)
    before = snapshot(base_url, api_key)
    before_created = metric(before, "voidx_sessions_created_total")
    before_active = metric(before, "voidx_sessions_active")
    before_ttr_count = metric(before, "voidx_time_to_ready_seconds_count")
    before_ttr_sum = metric(before, "voidx_time_to_ready_seconds_sum")
    before_destroyed = metric(before, "voidx_sessions_destroyed_total")

    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, f"Expected 201 creating session, got {res.status_code}: {res.text}"
    sid = res.json()["session_id"]
    cleanup_sessions.append(sid)

    ready = wait_until_ready(base_url, api_key, sid, timeout=150)
    assert ready is True, f"Session {sid} did not become ready within 150 seconds"

    res_get1 = api_get(base_url, api_key, f"/sessions/{sid}")
    assert res_get1.status_code == 200, f"Expected 200 on GET /sessions/{sid}, got {res_get1.status_code}"
    res_get2 = api_get(base_url, api_key, f"/sessions/{sid}")
    assert res_get2.status_code == 200, f"Expected 200 on GET /sessions/{sid}, got {res_get2.status_code}"
    res_list = api_get(base_url, api_key, "/sessions")
    assert res_list.status_code == 200, f"Expected 200 on GET /sessions, got {res_list.status_code}"

    after = snapshot(base_url, api_key)
    after_created = metric(after, "voidx_sessions_created_total")
    after_active = metric(after, "voidx_sessions_active")
    after_ttr_count = metric(after, "voidx_time_to_ready_seconds_count")
    after_ttr_sum = metric(after, "voidx_time_to_ready_seconds_sum")

    assert after_created == before_created + 1, (
        f"Expected created to rise by 1: before={before_created}, after={after_created}"
    )
    assert after_active == before_active + 1, (
        f"Expected active to rise by 1: before={before_active}, after={after_active}"
    )
    assert after_ttr_count == before_ttr_count + 1, (
        f"Expected ttr_count to rise by 1: before={before_ttr_count}, after={after_ttr_count}"
    )
    ttr_diff = after_ttr_sum - before_ttr_sum
    assert 0 <= ttr_diff <= 400, (
        f"Expected ttr_sum to rise by between 0 and 400: before={before_ttr_sum}, after={after_ttr_sum}, diff={ttr_diff}"
    )

    del_res = api_delete(base_url, api_key, f"/sessions/{sid}")
    assert del_res.status_code == 200, f"Expected 200 deleting session, got {del_res.status_code}: {del_res.text}"
    if sid in cleanup_sessions:
        cleanup_sessions.remove(sid)

    time.sleep(3)
    final = snapshot(base_url, api_key)
    final_destroyed = metric(final, "voidx_sessions_destroyed_total")
    final_active = metric(final, "voidx_sessions_active")

    assert final_destroyed == before_destroyed + 1, (
        f"Expected destroyed to rise by 1: before={before_destroyed}, final={final_destroyed}"
    )
    assert final_active == before_active, (
        f"Expected active to return to before value: before={before_active}, final={final_active}"
    )


def test_metrics_expiry_counted(base_url, api_key, redis_auth_env):
    clear_limits(redis_auth_env)
    before = snapshot(base_url, api_key)
    before_expired = metric(before, "voidx_sessions_expired_total")
    before_destroyed = metric(before, "voidx_sessions_destroyed_total")

    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, f"Expected 201 creating session, got {res.status_code}: {res.text}"
    sid = res.json()["session_id"]

    try:
        time.sleep(5)
        redis_cli(redis_auth_env, "DEL", "session:" + sid)

        deadline = time.time() + 90
        cleaned_up = False
        out = ""
        while time.time() < deadline:
            out = docker("ps", "-aq", "--filter", "label=pb.session=" + sid)
            if not out:
                cleaned_up = True
                break
            time.sleep(3)
        assert cleaned_up, f"Containers for session {sid} were not reaped within 90s: {out}"

        time.sleep(3)
        after = snapshot(base_url, api_key)
        after_expired = metric(after, "voidx_sessions_expired_total")
        after_destroyed = metric(after, "voidx_sessions_destroyed_total")

        assert after_expired == before_expired + 1, (
            f"Expected expired to rise by 1: before={before_expired}, after={after_expired}"
        )
        assert after_destroyed == before_destroyed, (
            f"Expected destroyed to remain unchanged: before={before_destroyed}, after={after_destroyed}"
        )
    finally:
        leftover = docker("ps", "-aq", "--filter", "label=pb.session=" + sid)
        if leftover:
            for cid in leftover.split():
                docker("rm", "-f", cid)
        docker("network", "rm", "pbint-" + sid)


def test_metrics_rate_limited_counted(base_url, api_key, redis_auth_env):
    clear_limits(redis_auth_env)
    before = snapshot(base_url, api_key)
    before_rate_limited = metric(before, "voidx_rate_limited_total")

    try:
        redis_cli(redis_auth_env, "SET", "rl:create", "5", "EX", "60")
        res = api_post(base_url, api_key, "/sessions")
        assert res.status_code == 429, f"Expected 429 when rate limited, got {res.status_code}: {res.text}"
        data = res.json()
        assert data.get("error") == "rate_limited", f"Expected error 'rate_limited', got: {data}"
    finally:
        clear_limits(redis_auth_env)

    after = snapshot(base_url, api_key)
    after_rate_limited = metric(after, "voidx_rate_limited_total")
    assert after_rate_limited == before_rate_limited + 1, (
        f"Expected rate_limited to rise by 1: before={before_rate_limited}, after={after_rate_limited}"
    )


def test_metrics_auth_failures_and_lockout(base_url, api_key, redis_auth_env):
    clear_limits(redis_auth_env)
    before = snapshot(base_url, api_key)
    before_auth_fail = metric(before, "voidx_auth_failures_total")

    for i in (1, 2):
        r = requests.get(base_url + "/sessions", headers={"X-API-Key": "wrong-key-" + str(i)}, timeout=15)
        assert r.status_code == 401, f"Expected 401 for wrong key {i}, got {r.status_code}: {r.text}"

    clear_limits(redis_auth_env)
    mid = snapshot(base_url, api_key)
    mid_auth_fail = metric(mid, "voidx_auth_failures_total")
    mid_lockout = metric(mid, "voidx_auth_lockout_responses_total")

    assert mid_auth_fail == before_auth_fail + 2, (
        f"Expected auth_failures +2: before={before_auth_fail}, mid={mid_auth_fail}"
    )

    clear_limits(redis_auth_env)
    count_401 = 0
    got_429 = False
    try:
        for i in range(1, 16):
            r = requests.get(base_url + "/sessions", headers={"X-API-Key": "wrong-key-" + str(i)}, timeout=15)
            if r.status_code == 401:
                count_401 += 1
            elif r.status_code == 429:
                got_429 = True
                data = r.json()
                assert data.get("error") == "too_many_attempts", f"Expected error 'too_many_attempts', got: {data}"
                break
            else:
                pytest.fail(f"Unexpected status code {r.status_code}: {r.text}")
        assert got_429 is True, f"Expected 429 lockout within 15 attempts, but none seen; 401s={count_401}"
    finally:
        clear_limits(redis_auth_env)

    end = snapshot(base_url, api_key)
    end_auth_fail = metric(end, "voidx_auth_failures_total")
    end_lockout = metric(end, "voidx_auth_lockout_responses_total")

    assert end_auth_fail == mid_auth_fail + count_401, (
        f"Expected auth_failures to rise by {count_401}: mid={mid_auth_fail}, end={end_auth_fail}"
    )
    assert end_lockout == mid_lockout + 1, (
        f"Expected lockout_responses to rise by 1: mid={mid_lockout}, end={end_lockout}"
    )


def test_metrics_contain_no_secrets(base_url, api_key):
    text = snapshot(base_url, api_key)
    env = _read_env()
    secret_key = env.get("PB_API_KEY", "")
    secret_redis_pw = env.get("REDIS_PASSWORD", "")
    assert secret_key != "", "PB_API_KEY is empty in .env"
    assert secret_key not in text, f"API key was leaked in /metrics: {secret_key}"
    if secret_redis_pw:
        assert secret_redis_pw not in text, f"Redis password was leaked in /metrics: {secret_redis_pw}"

