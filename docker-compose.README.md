# Docker Compose Setup (Alternative to start.ps1)

This is an **alternative** to `start.ps1` — useful on Mac, Linux, or for anyone who prefers `docker compose`. It does not replace or affect the PowerShell workflow.

---

## Prerequisites

- Docker Engine with Compose v2 (`docker compose` command)
- The session images `pb-net:latest` and `pb-browser:latest` must be built once before starting (see step 2 below)

---

## Quick Start

### 1. Create your `.env` file

```bash
cp .env.example .env
```

Open `.env` and replace both placeholder values with real random secrets. For example:

```bash
# Generate a random API key (32+ chars)
openssl rand -hex 32

# Generate a random Redis password
openssl rand -hex 24
```

### 2. Build the session images (one-time setup)

These images are not built automatically on `up` — they use the `build` profile so they don't run as persistent services.

```bash
docker compose --profile build run --rm image-net
docker compose --profile build run --rm image-browser
```

Run this again only if you change the `pbnet/` or `pbbrowser/` build contexts.

### 3. Start the stack

```bash
docker compose up -d
```

### 4. Open the dashboard

Visit [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## Stopping

```bash
docker compose down
```

---

## What each service does

| Service | Purpose |
|---|---|
| `redis` | Session metadata store, bound to localhost only |
| `docker-proxy` | Restricted Docker socket proxy (see below) |
| `app` | The FastAPI application (`main.py`) |
| `image-net` *(build profile)* | One-shot builder for `pb-net:latest` |
| `image-browser` *(build profile)* | One-shot builder for `pb-browser:latest` |

---

## Session containers are NOT managed by Compose

When a browser session is created, `main.py` spins up additional containers (browser, tor relay, network) at runtime **outside** of Compose. These will **not** appear in `docker compose ps` — that is expected and by design. They are cleaned up automatically by the app's reaper logic, not by `docker compose down`.

---

## docker-proxy — why it's here

The `app` container never connects to the real Docker socket (`/var/run/docker.sock`). Instead, it talks to the `docker-proxy` service (`tecnativa/docker-socket-proxy`) over TCP on an internal network. This proxy exposes only the API operations the app actually needs:

- ✅ **Allowed:** create/start/stop/remove containers, create/remove networks
- ❌ **Blocked:** image pulls, volume management, `exec` into containers, host system info, swarm/secret/config operations, and all other Docker API surfaces

This ensures that even if the `app` container is compromised, an attacker cannot escalate to full Docker socket access or pull arbitrary images.
