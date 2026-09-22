import os
import re
import asyncio
import time
import uuid
import json
import datetime
import threading
import logging
from contextlib import asynccontextmanager

import redis
import docker
import docker.errors
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from pathlib import Path
import hmac
import secrets
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("uvicorn.error")

API_KEY = os.environ.get("PB_API_KEY", "")

redis_url = os.environ.get("REDIS_URL", "redis://127.0.0.1:16379/0")
client = redis.Redis.from_url(
    redis_url, 
    socket_connect_timeout=2, 
    socket_timeout=2, 
    decode_responses=True
)

SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "600"))
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "3"))
REAPER_INTERVAL_SECONDS = int(os.environ.get("REAPER_INTERVAL_SECONDS", "5"))
REAPER_GRACE_SECONDS = int(os.environ.get("REAPER_GRACE_SECONDS", "20"))
RATE_CREATE_LIMIT = int(os.environ.get("RATE_CREATE_LIMIT", "5"))
RATE_CREATE_WINDOW = int(os.environ.get("RATE_CREATE_WINDOW", "60"))
AUTH_FAIL_LIMIT = int(os.environ.get("AUTH_FAIL_LIMIT", "10"))
AUTH_FAIL_WINDOW = int(os.environ.get("AUTH_FAIL_WINDOW", "60"))
AUDIT_STREAM = "audit"
AUDIT_MAXLEN = 1000
REDIS_ERRORS = (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError)
IMAGE = "pb-browser:latest"
TOR_IMAGE = "pb-net:latest"
SESSION_NETWORK = "pb-sessions"
PIDS_LIMIT = 512

def get_docker():
    return docker.from_env()

def ensure_network(dclient):
    try:
        dclient.networks.get(SESSION_NETWORK)
    except docker.errors.NotFound:
        dclient.networks.create(SESSION_NETWORK, driver="bridge", options={"com.docker.network.bridge.enable_icc": "false"})

def tor_ready(session_id):
    try:
        text = get_docker().containers.get("pbtor-" + session_id).logs(tail=300).decode("utf-8", "replace")
        return "Bootstrapped 100%" in text
    except docker.errors.DockerException:
        return False

def session_ready(port, session_id):
    try:
        r = requests.get(f"https://127.0.0.1:{int(port)}/", verify=False, timeout=2, allow_redirects=False)
        return r.status_code in (200, 401) and tor_ready(session_id)
    except requests.exceptions.RequestException:
        return False

def remove_session_network(dclient, session_id):
    for attempt in range(10):
        try:
            dclient.networks.get("pbint-" + session_id).remove()
            return True
        except docker.errors.NotFound:
            return True
        except docker.errors.APIError:
            time.sleep(0.5)
    return False

def cleanup_session(dclient, session_id):
    for name in ("pbfwd-"+session_id, "pbtor-"+session_id, "pbsession-"+session_id):
        try:
            dclient.containers.get(name).stop(timeout=3)
        except docker.errors.NotFound:
            pass
    remove_session_network(dclient, session_id)

def safe_cleanup(dclient, session_id):
    try:
        cleanup_session(dclient, session_id)
    except docker.errors.DockerException as e:
        logger.warning(f"safe_cleanup error for {session_id}: {e}")

def audit(event, session_id="", detail=""):
    try:
        client.xadd(AUDIT_STREAM, {"event": event, "session_id": session_id, "detail": detail}, maxlen=AUDIT_MAXLEN, approximate=True)
    except REDIS_ERRORS:
        logger.warning("audit: redis unavailable, event dropped")

def hit(key, window):
    pipe = client.pipeline()
    pipe.incr(key)
    pipe.ttl(key)
    count, ttl = pipe.execute()
    if ttl < 0:
        client.expire(key, window)
        ttl = window
    return count, ttl

def auth_locked(ip):
    try:
        n = int(client.get("rl:auth:" + ip) or 0)
        if n >= AUTH_FAIL_LIMIT:
            return max(client.ttl("rl:auth:" + ip), 1)
        return 0
    except REDIS_ERRORS:
        logger.warning("rate limit: redis unavailable, lockout check skipped")
        return 0

def record_auth_failure(ip, path):
    try:
        hit("rl:auth:" + ip, AUTH_FAIL_WINDOW)
    except REDIS_ERRORS:
        logger.warning("rate limit: redis unavailable, failure not counted")
    audit("auth_failed", detail="path=" + path)

def parse_docker_time(s):
    s = s.rstrip("Z")
    if "." in s:
        main_part, frac = s.split(".", 1)
        frac = frac[:6]
        s = f"{main_part}.{frac}"
    return datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.timezone.utc)

def reap_once():
    try:
        live = {k.split(":", 1)[1] for k in client.scan_iter("session:*")}
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
        logger.warning("reaper: redis unavailable, skipping cycle")
        return

    try:
        dclient = get_docker()
        found = dclient.containers.list(filters={"label": "pb.managed=true"})
    except docker.errors.DockerException:
        logger.warning("reaper: docker unavailable, skipping cycle")
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    for c in found:
        sid = c.labels.get("pb.session")
        if sid is None or sid in live:
            continue
        try:
            created = parse_docker_time(c.attrs["Created"])
        except (KeyError, ValueError):
            logger.warning(f"reaper: cannot read age of {c.name}, leaving it")
            continue
        
        if (now - created).total_seconds() < REAPER_GRACE_SECONDS:
            continue
            
        try:
            c.stop(timeout=5)
            logger.info(f"reaper: stopped {c.name} (no session record)")
            if c.labels.get("pb.role") == "session":
                audit("session_expired", sid)
        except docker.errors.NotFound:
            pass
        except docker.errors.DockerException as e:
            logger.warning(f"reaper: could not stop {c.name}: {e}")

    try:
        nets = dclient.networks.list(filters={"label": "pb.managed=true"})
    except docker.errors.DockerException:
        logger.warning("reaper: network list docker unavailable")
        return

    for n in nets:
        sid = (n.attrs.get("Labels") or {}).get("pb.session")
        if sid is None or sid in live:
            continue
        try:
            created = parse_docker_time(n.attrs["Created"])
        except (KeyError, ValueError):
            continue
        if (now - created).total_seconds() < REAPER_GRACE_SECONDS:
            continue
        n.reload()
        if n.attrs.get("Containers"):
            continue
        try:
            n.remove()
            logger.info(f"reaper: removed network {n.name}")
        except docker.errors.NotFound:
            pass
        except docker.errors.DockerException:
            logger.warning(f"reaper: failed to remove network {n.name}")

stop_event = threading.Event()

def reaper_loop():
    while not stop_event.is_set():
        try:
            reap_once()
        except Exception:
            logger.exception("reaper: unexpected error")
        stop_event.wait(REAPER_INTERVAL_SECONDS)

@asynccontextmanager
async def lifespan(app):
    if len(API_KEY) < 16:
        raise RuntimeError("PB_API_KEY must be set (at least 16 characters)")
    stop_event.clear()
    t = threading.Thread(target=reaper_loop, name="reaper", daemon=True)
    t.start()
    logger.info(f"reaper: started (interval={REAPER_INTERVAL_SECONDS}s, grace={REAPER_GRACE_SECONDS}s)")
    yield
    stop_event.set()

app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def require_key(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    if request.url.path == "/" and request.method == "GET":
        return await call_next(request)
    
    ip = request.client.host if request.client else "unknown"
    retry = await asyncio.to_thread(auth_locked, ip)
    if retry:
        return JSONResponse(status_code=429, content={"error": "too_many_attempts"}, headers={"Retry-After": str(retry)})
    
    supplied = request.headers.get("x-api-key", "")
    if not hmac.compare_digest(supplied.encode(), API_KEY.encode()):
        await asyncio.to_thread(record_auth_failure, ip, request.url.path)
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    return await call_next(request)

@app.get("/")
def get_dashboard():
    try:
        content = (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")
        return HTMLResponse(content=content, headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        })
    except FileNotFoundError:
        return JSONResponse(status_code=503, content={"error": "dashboard_missing"})

@app.get("/health")
def health():
    try:
        ping_result = client.ping()
        if ping_result is True:
            return JSONResponse(status_code=200, content={"status": "ok", "redis": True})
        else:
            return JSONResponse(status_code=503, content={"status": "degraded", "redis": False})
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        return JSONResponse(status_code=503, content={"status": "degraded", "redis": False})

@app.post("/sessions")
def create_session():
    try:
        count, ttl = hit("rl:create", RATE_CREATE_WINDOW)
    except REDIS_ERRORS:
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})
    if count > RATE_CREATE_LIMIT:
        audit("rate_limited", detail="create")
        return JSONResponse(status_code=429, content={"error": "rate_limited"}, headers={"Retry-After": str(ttl)})

    try:
        keys = list(client.scan_iter("session:*"))
        if len(keys) >= MAX_SESSIONS:
            return JSONResponse(status_code=429, content={"error": "too_many_sessions"})
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})
    
    try:
        live_count = len(get_docker().containers.list(filters={"label": ["pb.managed=true", "pb.role=session"]}))
    except docker.errors.DockerException:
        return JSONResponse(status_code=503, content={"error": "docker_unavailable"})
    if live_count >= MAX_SESSIONS:
        return JSONResponse(status_code=429, content={"error": "too_many_sessions"})

    used_ports = set()
    if keys:
        try:
            values = client.mget(keys)
            for val in values:
                if val is not None:
                    data = json.loads(val)
                    if "port" in data:
                        used_ports.add(data["port"])
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
            return JSONResponse(status_code=503, content={"error": "redis_unavailable"})

    session_id = uuid.uuid4().hex[:12]
    name = "pbsession-" + session_id

    try:
        dclient = get_docker()
    except docker.errors.DockerException:
        return JSONResponse(status_code=503, content={"error": "docker_unavailable"})

    try:
        ensure_network(dclient)
        dclient.networks.create("pbint-" + session_id, driver="bridge", internal=True, labels={"pb.managed": "true", "pb.session": session_id})
    except docker.errors.DockerException:
        return JSONResponse(status_code=503, content={"error": "docker_unavailable"})

    container = None
    worked_port = None
    
    pw = secrets.token_urlsafe(16)
    
    try:
        container = dclient.containers.run(
            image=IMAGE,
            name=name,
            detach=True,
            auto_remove=True,
            shm_size="1g",
            tmpfs={"/config": "rw,size=512m"},
            environment={"CHROME_CLI": "--incognito --proxy-server=socks5://tor:9050", "CUSTOM_USER": "pb", "PASSWORD": pw},
            mem_limit="2g",
            nano_cpus=2000000000,
            labels={"pb.managed": "true", "pb.session": session_id, "pb.role": "session"},
            network="pbint-" + session_id,
            security_opt=["no-new-privileges:true"],
            pids_limit=PIDS_LIMIT,
            cap_drop=["ALL"],
            cap_add=["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"]
        )
    except docker.errors.ImageNotFound:
        safe_cleanup(dclient, session_id)
        return JSONResponse(status_code=503, content={"error": "image_missing"})
    except docker.errors.DockerException:
        safe_cleanup(dclient, session_id)
        return JSONResponse(status_code=503, content={"error": "docker_unavailable"})

    try:
        tor_container = dclient.containers.run(
            image=TOR_IMAGE,
            name="pbtor-" + session_id,
            command=["tor", "--SocksPort", "0.0.0.0:9050", "--SocksPolicy", "accept *", "--DataDirectory", "/tmp/tor", "--Log", "notice stdout"],
            detach=True,
            auto_remove=True,
            network=SESSION_NETWORK,
            tmpfs={"/tmp": "rw,size=64m"},
            mem_limit="256m",
            nano_cpus=500000000,
            security_opt=["no-new-privileges:true"],
            cap_drop=["ALL"],
            pids_limit=256,
            labels={"pb.managed": "true", "pb.session": session_id, "pb.role": "tor"}
        )
        dclient.networks.get("pbint-" + session_id).connect(tor_container, aliases=["tor"])
    except docker.errors.ImageNotFound:
        safe_cleanup(dclient, session_id)
        return JSONResponse(status_code=503, content={"error": "image_missing"})
    except docker.errors.DockerException:
        safe_cleanup(dclient, session_id)
        return JSONResponse(status_code=503, content={"error": "docker_unavailable"})

    for port in range(13001, 13101):
        if port in used_ports:
            continue
        try:
            relay_container = dclient.containers.run(
                image=TOR_IMAGE,
                name="pbfwd-" + session_id,
                entrypoint="socat",
                command=["TCP-LISTEN:3001,fork,reuseaddr", "TCP:pbsession-" + session_id + ":3001"],
                detach=True,
                auto_remove=True,
                network=SESSION_NETWORK,
                ports={"3001/tcp": ("127.0.0.1", port)},
                mem_limit="64m",
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                pids_limit=64,
                labels={"pb.managed": "true", "pb.session": session_id, "pb.role": "fwd"}
            )
            dclient.networks.get("pbint-" + session_id).connect(relay_container)
            worked_port = port
            break
        except docker.errors.ImageNotFound:
            safe_cleanup(dclient, session_id)
            return JSONResponse(status_code=503, content={"error": "image_missing"})
        except docker.errors.APIError as e:
            if "port" in str(e).lower():
                continue
            safe_cleanup(dclient, session_id)
            return JSONResponse(status_code=503, content={"error": "docker_unavailable"})
        except docker.errors.DockerException:
            safe_cleanup(dclient, session_id)
            return JSONResponse(status_code=503, content={"error": "docker_unavailable"})

    if worked_port is None:
        safe_cleanup(dclient, session_id)
        return JSONResponse(status_code=503, content={"error": "no_free_port"})

    created_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    
    try:
        session_data = {
            "session_id": session_id,
            "container": name,
            "port": worked_port,
            "created_at": created_at
        }
        client.set("session:" + session_id, json.dumps(session_data), ex=SESSION_TTL_SECONDS)
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
        safe_cleanup(dclient, session_id)
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})

    audit("session_created", session_id)

    return JSONResponse(status_code=201, content={
        "session_id": session_id,
        "url": f"https://localhost:{worked_port}",
        "expires_in": SESSION_TTL_SECONDS,
        "username": "pb",
        "password": pw
    })

@app.get("/sessions")
def list_sessions():
    try:
        keys = list(client.scan_iter("session:*"))
        vals = client.mget(keys) if keys else []
        
        raw_sessions = []
        for key, val in zip(keys, vals):
            if val is None:
                continue
            ttl = client.ttl(key)
            if ttl < 0:
                continue
            data = json.loads(val)
            raw_sessions.append((data.get("created_at", ""), data, ttl))
            
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})
        
    raw_sessions.sort(key=lambda x: x[0])
    
    sessions = []
    for _, data, ttl in raw_sessions:
        sessions.append({
            "session_id": data["session_id"],
            "url": f"https://localhost:{data['port']}",
            "expires_in": ttl,
            "ready": session_ready(data["port"], data["session_id"])
        })
        
    return JSONResponse(status_code=200, content={"sessions": sessions})

@app.get("/sessions/{session_id}")
def get_session(session_id: str):
    if not re.match(r"^[0-9a-f]{12}$", session_id):
        return JSONResponse(status_code=404, content={"error": "not_found"})
    
    try:
        val = client.get("session:" + session_id)
        if val is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        data = json.loads(val)
        ttl = client.ttl("session:" + session_id)
        
        return JSONResponse(status_code=200, content={
            "session_id": session_id,
            "url": f"https://localhost:{data.get('port')}",
            "expires_in": ttl,
            "ready": session_ready(data.get("port"), session_id)
        })
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})

@app.delete("/sessions/{session_id}")
def delete_session(session_id: str):
    if not re.match(r"^[0-9a-f]{12}$", session_id):
        return JSONResponse(status_code=404, content={"error": "not_found"})
    
    try:
        val = client.get("session:" + session_id)
        if val is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})
    
    try:
        dclient = get_docker()
        for cname in ("pbfwd-" + session_id, "pbtor-" + session_id, "pbsession-" + session_id):
            try:
                dclient.containers.get(cname).stop(timeout=3)
            except docker.errors.NotFound:
                pass
    except docker.errors.DockerException:
        return JSONResponse(status_code=503, content={"error": "docker_unavailable"})
    
    if not remove_session_network(dclient, session_id):
        logger.warning(f"Failed to remove network for session {session_id}")

    try:
        client.delete("session:" + session_id)
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, redis.exceptions.RedisError):
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})
    
    audit("session_destroyed", session_id)
    return JSONResponse(status_code=200, content={"destroyed": session_id})

@app.get("/audit")
def get_audit(count: int = 50):
    count = max(1, min(count, 200))
    try:
        rows = client.xrevrange(AUDIT_STREAM, count=count)
    except REDIS_ERRORS:
        return JSONResponse(status_code=503, content={"error": "redis_unavailable"})
    
    events = []
    for entry_id, fields in rows:
        ms = int(entry_id.split("-")[0])
        time_str = datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append({
            "id": entry_id,
            "time": time_str,
            "event": fields.get("event", ""),
            "session_id": fields.get("session_id", ""),
            "detail": fields.get("detail", "")
        })
    return JSONResponse(status_code=200, content={"events": events})
