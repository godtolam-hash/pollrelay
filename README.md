# poll-relay — outbound-polling variant (no ZeroTier, no open ports)

This is the replacement for the ZeroTier design. **Your PC dials out** to a free
public host; nothing listens on your PC and no VPN is involved.

```
   your PC ──outbound HTTPS──▶  poll-relay (free host)  ◀──HTTPS──  me
            keeps /poll open      dispatches jobs          curl / pc.py
```

Why this is better for us:

| | ZeroTier variant | **polling variant** |
|---|---|---|
| Open port on PC | 8765 | **none** |
| Needs ZeroTier install | yes | **no** |
| Works behind NAT/CGNAT/mobile | no | **yes** |
| Free host requirements | TUN + root (most hosts refuse) | **plain HTTP only** |
| Free hosts that work | Oracle Cloud only | **Render, Koyeb, Fly, Railway, any VPS, a Pi** |
| Relay can impersonate the PC | n/a | **no** (ed25519: relay holds only the public key) |

---

## 1. Deploy the relay (pick one)

All three are no-cost tiers. The relay needs **no** root, TUN, or privilege.

### Render (easiest, no card)
1. Push this `poll-relay/` folder to a GitHub repo.
2. Render → **New + → Blueprint** → pick the repo (it reads `render.yaml`).
3. Render generates `RELAY_TOKEN` and `PAIR_CODE` → copy both from
   **Environment**. Your URL looks like `https://poll-relay-xxxx.onrender.com`.
4. Free tier sleeps after ~15 min idle; the PC's poll wakes it in a few seconds.

### Koyeb (free, no card)
Push the repo → **Create Service → GitHub → Docker** → set `RELAY_TOKEN` and
`PAIR_CODE` env vars → expose port **8080**.

### Fly.io (needs a card, most reliable)
```bash
cd poll-relay
fly launch --copy-config --no-deploy      # or edit app name in fly.toml
fly secrets set RELAY_TOKEN=$(openssl rand -hex 24) PAIR_CODE=$(openssl rand -hex 8)
fly volumes create relay_data --size 1
fly deploy
```
`auto_stop_machines = false` and the 1 GB volume keep state and the long-poll
alive — this is the one that behaves most like a real server.

### Any VPS / Raspberry Pi behind anything
```bash
RELAY_TOKEN=... PAIR_CODE=... PORT=8080 python3 relay.py     # plain HTTP
```
Put Caddy in front for HTTPS (Caddy gets certificates automatically):
```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Env reference

| Var | Default | Meaning |
|---|---|---|
| `RELAY_TOKEN` | **required** | my caller secret (`X-Relay-Token`) |
| `PAIR_CODE` | **required** | one-time code the PC trades for an id |
| `SIG_MODE` | `ed25519` | or `hmac` (needs `PAIR_SECRET`) |
| `PAIR_SECRET` | — | shared secret for hmac fallback |
| `MAX_AGENTS` | `5` | how many PCs may enrol |
| `DATA_FILE` | `./relay-state.json` | enrolments + public keys |
| `AGENT_STALE` | `25` | seconds without a poll/heartbeat → "offline" |
| `JOB_TIMEOUT` | `120` | max wait for one command's result |
| `PICKUP_TIMEOUT` | `10` | how long before we admit the PC is disconnected |
| `PORT` / `BIND` | `8080` / `0.0.0.0` | listener |

---

## 2. Install the agent on the Bazzite PC

Copy `bazzite-agent/` to the PC, then:

```bash
cd ~/bazzite-agent
./install-poller.sh https://your-relay.onrender.com PAIR-CODE-FROM-RELAY
```

That writes `~/.config/bazzite-agent/poll.env` (mode 600), creates a
`systemd --user` unit, enrols, and starts. Check it:

```bash
systemctl --user status bazzite-poller
journalctl --user -u bazzite-poller -f
```

Useful afterwards:
```bash
systemctl --user restart bazzite-poller
systemctl --user disable --now bazzite-poller     # pause
```

**Roots / bigger disk:** edit `AGENT_ROOTS` in `poll.env` (colon-separated,
first entry is primary) and restart — e.g.
`AGENT_ROOTS=/home/you:/run/media/you/BIGDISK/bazzite/projects`.
You can also just run `bash disk-setup.sh` and append the printed path.

---

## 3. Calling it

I only need **one secret** (`RELAY_TOKEN`) and **one URL**. Everything else is
a plain HTTPS call:

```bash
H="X-Relay-Token: $RELAY_TOKEN"
R=https://your-relay.onrender.com

curl -s $R/health                              # relay + PC status, no auth
curl -s -H "$H" $R/agents                      # which PCs are online
curl -s -H "$H" $R/api/sysinfo                 # default PC (if only one)
curl -s -H "$H" -X POST $R/api/exec \
  -H 'Content-Type: application/json' \
  -d '{"cmd":["cargo","build","--release"],"cwd":"projects/mycli","timeout":900}'
```

With more than one PC, prefix the agent id: `/a/<agent_id>/api/exec`.

### Same API as the direct mode

`/api/health`, `/api/sysinfo`, `/api/tools`, `/api/list`, `/api/stat`,
`/api/read`, `/api/read-b64`, `/api/write`, `/api/write-b64`, `/api/mkdir`,
`/api/remove`, `/api/exec`, `/api/proc/{start,list,logs,stop}`,
`/api/flatpak/{list,build}`, `/api/distrobox/{list,create,exec}`,
`/api/podman/{ps,build,run}`.

Both transports run the same `core.py`, so nothing drifts.

### Nicer: the `pc.py` client

```bash
export RELAY_URL=https://your-relay.onrender.com RELAY_TOKEN=...
cd bazzite-agent
./pc.py agents
./pc.py exec "uname -a"
./pc.py exec --timeout 900 --cwd projects/mycli "cargo build --release"
./pc.py ls projects
./pc.py put ./local.bin projects/app/local.bin
./pc.py get projects/app/report.pdf ./report.pdf
./pc.py start web --cwd projects/site "python3 -m http.server 8000"
./pc.py logs web --follow
./pc.py shell
```

---

## 4. Security model

- **PC→relay auth:** every poll/heartbeat/result is signed over
  `agent_id|ts|nonce|<path>`; the relay rejects stale timestamps (±300 s),
  replayed nonces, signatures reused for a different path, and unknown agents.
  In the default **ed25519** mode the private key never leaves the PC, so
  whoever runs the relay — or breaches it — still cannot command your machine.
  `hmac` mode exists only for old openssl builds.
- **Caller auth:** `X-Relay-Token`; `/health` is public but contains no secrets.
- **Files:** jailed to `AGENT_ROOTS` on the PC (symlinks are resolved).
- **Spent pair code:** after enrolment the `PAIR_CODE` only matters if the relay
  loses its state (free tiers wipe disk on redeploy) — then the agent re-enrols
  automatically. Replace the code in `Environment` once you're done testing.
- **Revoke a PC:** delete its entry from `DATA_FILE` (or redeploy) and remove
  `~/.config/bazzite-agent/poll.json` + `agent.key` on the PC.

## 5. Limits worth knowing

- One command per call; ≥20 MB files need chunking (`pc.py put` in pieces).
- The relay holds the HTTP call open while the PC works (default 120 s).
  For anything longer use `/api/proc/start` and poll `/api/proc/logs`.
- Free hosts sleep: the poll wakes them, adding ~5–10 s to the first call.
- Free tiers have no disk → state is lost on redeploy → automatic re-enrol
  handles it (identity id changes, `pc.py --agent` may need updating).

## 6. Verified locally

End-to-end tested against a live relay + poller: enrol, exec, list/read/write,
stdout/stderr/exit codes, background procs + logs, 20 MB-ish base64 transfer,
HMAC mode, relay restart with state intact, and 16 security cases (bad pair
code, replay, stale ts, path-bound signature, impostor key, unknown agent,
caller auth, offline detection).
