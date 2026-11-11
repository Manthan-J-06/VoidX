import re
import pytest

from tests.conftest import (
    docker,
    api_post,
    api_delete,
    wait_until_ready,
)

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def leak_session(base_url, api_key):
    res = api_post(base_url, api_key, "/sessions")
    assert res.status_code == 201, "Expected 201 on session creation, got " + str(res.status_code) + ": " + res.text
    session_id = res.json()["session_id"]
    try:
        ready = wait_until_ready(base_url, api_key, session_id, timeout=150)
        assert ready, "Session " + session_id + " did not become ready within 150 seconds"
        yield session_id
    finally:
        try:
            api_delete(base_url, api_key, "/sessions/" + session_id)
        except Exception:
            pass


def sess(session_id, shell_cmd):
    return docker("exec", "-u", "abc", "pbsession-" + session_id, "sh", "-c", shell_cmd, timeout=60)


def parse(output):
    match = re.search(r"(\d{3})exit=(\d+)", output)
    if match:
        return match.group(1), int(match.group(2))
    return "?", -1


def socks(session_id, url):
    return parse(
        sess(
            session_id,
            "curl -s -m 25 -o /dev/null -w '%{http_code}' --socks5-hostname tor:9050 '" + url + "'; echo exit=$?",
        )
    )


def test_controls(leak_session):
    out = sess(leak_session, "command -v curl")
    assert "curl" in out, "Expected 'curl' in 'command -v curl' output, got: " + out

    code, exit_code = socks(leak_session, "https://check.torproject.org/api/ip")
    assert code == "200", (
        "Expected Tor check http code 200, got code=" + str(code) + ", exit=" + str(exit_code)
    )


def test_no_ipv4_default_route(leak_session):
    out = sess(leak_session, "tail -n +2 /proc/net/route | cut -f2 | grep -c '^00000000$'")
    assert out.strip() == "0", "Expected 0 default routes, got: " + out


def test_direct_ipv4_fails(leak_session):
    cmd = "curl -s -o /dev/null -m 6 -w '%{http_code}' https://1.1.1.1/; echo exit=$?"
    out = sess(leak_session, cmd)
    code, _ = parse(out)
    assert code == "000", "Expected direct IPv4 to fail with 000, got: " + out


def test_direct_ipv6_fails(leak_session):
    cmd = "curl -g -s -o /dev/null -m 6 -w '%{http_code}' 'https://[2606:4700:4700::1111]/'; echo exit=$?"
    out = sess(leak_session, cmd)
    code, _ = parse(out)
    assert code == "000", "Expected direct IPv6 to fail with 000, got: " + out


def test_dns_no_public_resolution(leak_session):
    out_tor = sess(leak_session, "getent hosts tor")
    assert out_tor.strip() != "", "Expected getent hosts tor to be non-empty, got: " + out_tor
    assert re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out_tor) is not None, (
        "Expected dotted IPv4 pattern in getent hosts tor, got: " + out_tor
    )

    out_example = sess(leak_session, "getent hosts example.com")
    assert out_example.strip() == "", "Expected getent hosts example.com to be empty, got: " + out_example


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8000/health",
        "http://host.docker.internal:8000/health",
        "http://host.docker.internal:16379/",
    ],
)
def test_socks_cannot_reach_private_targets(leak_session, target):
    code, exit_code = socks(leak_session, target)
    assert code == "000", (
        "Expected socks http code 000 for " + target + ", got code=" + str(code) + ", exit=" + str(exit_code)
    )


def test_socks_cannot_reach_redis_container(leak_session):
    ip = docker("inspect", "redis", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
    if not ip or "error" in ip.lower() or "no such" in ip.lower():
        pytest.skip("no container named redis")
    code, exit_code = socks(leak_session, "http://" + ip + ":6379/")
    assert code == "000", (
        "Expected socks http code 000 for redis at " + ip + ", got code=" + str(code) + ", exit=" + str(exit_code)
    )
    assert exit_code in (7, 28, 97), (
        "Expected exit code in (7, 28, 97) for redis at "
        + ip
        + ", got code="
        + str(code)
        + ", exit="
        + str(exit_code)
    )

