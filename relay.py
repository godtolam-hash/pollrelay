#!/usr/bin/env python3
"""poll-relay — the public half of the outbound-polling connection (stdlib only).

Runs on ANY free host (Render, Koyeb, Fly, a $3 VPS, systemd, screen). Needs
plain HTTPS and nothing else: no ZeroTier, no TUN, no root, no inbound port on
your PC.

    your PC ──outbound HTTPS──▶ this relay ◀──HTTPS── me
              (keeps /poll open)         (dispatches jobs, returns results)

Assistant-facing API (mirrors the agent's API 1:1)
--------------------------------------------------
    POST /a/<agent_id>/api/exec      {cmd:[...]}          -> agent's response
    GET  /a/<agent_id>/api/sysinfo
    GET  /a/<agent_id>/api/list?path=projects
    POST /api/...                    -> default agent (when only one is enrolled)
    GET  /health                     -> relay + agents status (no auth)
    GET  /agents                     -> enrolled agents
    GET  /                           -> small dashboard (token prompt)

Auth: X-Relay-Token: $RELAY_TOKEN   (or Authorization: Bearer ...)

Agent-facing endpoints (signed with ed25519, or hmac fallback)
    POST /enroll      one-time, with PAIR_CODE
    POST /poll        long-poll for jobs
    POST /result/<id> post a job's result
    POST /heartbeat   load/mem/disk/liveness

Env:
  RELAY_TOKEN   required. Caller secret (assistant).
  PAIR_CODE     required. One-time enrollment code shown to the PC owner.
  PAIR_SECRET   required for hmac mode, optional otherwise.
  SIG_MODE      ed25519 (default) | hmac
  MAX_AGENTS    default 5
  DATA_FILE     default ./relay-state.json  (agents + pubkeys)
  PORT/BIND     default 8080 / 0.0.0.0
  JOB_TIMEOUT   default 120s max wait for a job result
"""
import json
import os
import queue
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import signing  # noqa: E402

RELAY_TOKEN = os.environ.get("RELAY_TOKEN", "").strip()
PAIR_CODE = os.environ.get("PAIR_CODE", "").strip()
PAIR_SECRET = os.environ.get("PAIR_SECRET", "")
SIG_MODE = os.environ.get("SIG_MODE", "ed25519").lower()
MAX_AGENTS = int(os.environ.get("MAX_AGENTS", "5"))
DATA_FILE = Path(os.environ.get("DATA_FILE", "./relay-state.json"))
PORT = int(os.environ.get("PORT", "8080"))
BIND = os.environ.get("BIND", "0.0.0.0")
JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT", "120"))
AGENT_STALE = int(os.environ.get("AGENT_STALE", "25"))  # no poll/heartbeat = offline
DEFAULT_AGENT = os.environ.get("DEFAULT_AGENT", "").strip()
STARTED = time.time()

LOCK = threading.RLock()
AGENTS = {}   # agent_id -> dict(...) incl. runtime state
NONCES = {}   # agent_id -> {nonce: ts}


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, file=sys.stderr, flush=True)


# ------------------------------------------------------------------- state I/O
class Agent:
    def __init__(self, aid, rec):
        self.id = aid
        self.rec = rec                       # persisted stuff
        self.jobs = queue.Queue()            # job_id -> dict  (waiting for poll)
        self.results = {}                    # job_id -> {"event": Event, "payload": ..}
        self.last_seen = 0.0
        self.last_hb = {}
        self.cond = threading.Condition()

    def push(self, job):
        self.jobs.put(job)
        with self.cond:
            self.cond.notify_all()

    def take(self, limit=8):
        out = []
        while len(out) < limit:
            try:
                out.append(self.jobs.get_nowait())
            except queue.Empty:
                break
        for j in out:
            j["_taken"] = True          # poller has picked it up
        return out

    def online(self):
        return (time.time() - self.last_seen) < AGENT_STALE

    def view(self):
        return {
            "agent_id": self.id,
            "name": self.rec.get("name"),
            "hostname": self.rec.get("hostname"),
            "version": self.rec.get("version"),
            "sig_mode": self.rec.get("sig_mode"),
            "enrolled_at": self.rec.get("enrolled_at"),
            "last_seen": int(self.last_seen) if self.last_seen else None,
            "online": self.online(),
            "queued": self.jobs.qsize(),
            "heartbeat": self.last_hb or None,
        }


def save_state():
    with LOCK:
        data = {"agents": {k: a.rec for k, a in AGENTS.items()}}
    tmp = str(DATA_FILE) + ".tmp"
    try:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, DATA_FILE)
    except Exception as e:
        log(f"state save failed: {e}")


def load_state():
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text())
            for aid, rec in (data.get("agents") or {}).items():
                AGENTS[aid] = Agent(aid, rec)
            log(f"loaded {len(AGENTS)} agent(s) from {DATA_FILE}")
        except Exception as e:
            log(f"state load failed: {e}")


# ------------------------------------------------------------- agent identity
def verify_agent(headers, signed_path: str, agent_id: str) -> tuple[bool, str]:
    ts = headers.get("X-Agent-Ts", "")
    nonce = headers.get("X-Agent-Nonce", "")
    sig = headers.get("X-Agent-Sig", "")
    mode = headers.get("X-Agent-Sig-Mode", SIG_MODE).lower()
    if not (ts and nonce and sig):
        return False, "missing signature headers"
    try:
        ts_i = int(ts)
    except ValueError:
        return False, "bad ts"
    if not signing.fresh(ts_i):
        return False, "stale timestamp (check clock skew)"
    with LOCK:
        agent = AGENTS.get(agent_id)
        if not agent:
            return False, "unknown agent"
        seen = NONCES.setdefault(agent_id, {})
        if nonce in seen:
            return False, "replayed nonce"
        seen[nonce] = ts_i
        for n, t in list(seen.items()):
            if abs(time.time() - t) > signing.MAX_SKEW * 2:
                del seen[n]
        pub = agent.rec.get("pubkey")
        secret = agent.rec.get("pair_secret", "") if mode == "hmac" else ""
    msg = f"{agent_id}|{ts_i}|{nonce}|{signed_path}".encode()
    if mode == "hmac":
        if not PAIR_SECRET:
            return False, "relay not configured for hmac"
        ok = signing.hmac_verify(PAIR_SECRET, msg, sig)
    else:
        if not pub:
            return False, "no public key on file"
        ok = signing.verify(pub, msg, sig)
    return (True, "") if ok else (False, "bad signature")


# --------------------------------------------------------------- dispatch path
def pick_agent(requested: str) -> Agent | None:
    with LOCK:
        if requested:
            return AGENTS.get(requested)
        if DEFAULT_AGENT:
            return AGENTS.get(DEFAULT_AGENT)
        online = [a for a in AGENTS.values() if a.online()]
        if len(online) == 1:
            return online[0]
        if not AGENTS:
            return None
        # fall back to the most recently seen agent
        return sorted(AGENTS.values(), key=lambda a: a.last_seen, reverse=True)[0]


def dispatch(agent: Agent, method: str, path: str, query: dict, body, headers) -> tuple[int, dict]:
    jid = secrets.token_urlsafe(9)
    job = {"id": jid, "method": method, "path": path, "query": query, "body": body,
           "headers": {k.lower(): v for k, v in headers if k.lower().startswith("x-job-")},
           "ts": int(time.time())}
    wait_event = threading.Event()
    slot = {"event": wait_event, "payload": None, "taken": False}
    with LOCK:
        agent.results[jid] = slot
    agent.push(job)
    # Wait in 1s slices so a PC that vanishes costs seconds, not minutes:
    #  - nobody picks the job up within PICKUP_TIMEOUT  -> not connected
    #  - picked up, then the poller disappears          -> offline mid-job
    PICKUP_TIMEOUT = int(os.environ.get("PICKUP_TIMEOUT", "10"))
    started = time.time()
    deadline = started + JOB_TIMEOUT
    ok, went_offline, never_picked = False, False, False
    while time.time() < deadline:
        if wait_event.wait(1.0):
            ok = True
            break
        took = job.get("_taken", False)
        if not took and (time.time() - started) > PICKUP_TIMEOUT:
            never_picked = True
            break
        if took and not agent.online():
            went_offline = True
            break
    with LOCK:
        agent.results.pop(jid, None)
    if not ok:
        if never_picked:
            return 503, {"error": "agent is not connected (no poll in "
                                  f"{PICKUP_TIMEOUT}s)",
                         "agent": agent.id,
                         "last_seen": int(agent.last_seen) if agent.last_seen else None,
                         "hint": "start it on the PC: systemctl --user status bazzite-poller"}
        if went_offline:
            return 503, {"error": "agent went offline while running the job",
                         "agent": agent.id, "job_id": jid,
                         "hint": "the command may still be running on the PC; "
                                 "reconnect and check /api/proc/list"}
        return 504, {"error": "agent did not answer in time",
                     "agent": agent.id, "online": agent.online(),
                     "job_id": jid,
                     "hint": "the command is probably still running; use "
                             "/api/proc/start for long tasks"}
    p = slot["payload"] or {"status": 502, "body": {"error": "no payload"}}
    return int(p.get("status", 200)), p.get("body", {})


# ---------------------------------------------------------------------- HTML UI
DASH = """<!doctype html><html><head><meta charset="utf-8">
<title>poll-relay</title>
<style>
body{font-family:system-ui;max-width:980px;margin:2rem auto;padding:0 1rem;color:#111}
table{border-collapse:collapse;width:100%%;font-size:.9rem}
td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}
tr:nth-child(even){background:#fafafa}
.on{color:#0a0}.off{color:#c00}
pre{background:#111;color:#eee;padding:1rem;border-radius:8px;overflow:auto;max-height:420px}
input,button,textarea{padding:.5rem;margin:.2rem 0;font-family:inherit}
input[type=text]{width:100%%}
</style></head><body>
<h1>poll-relay</h1>
<p>Relay token: <input id="tok" type="password" style="width:320px">
<button onclick="save()">Save</button> <span id="st"></span></p>
<p><button onclick="refresh()">Refresh agents</button>
<button onclick="probe()">Probe default agent (/api/health)</button></p>
<div id="agents">loading…</div>
<h2>Run a command</h2>
<input id="agent" type="text" placeholder="agent_id (blank = default)">
<input id="cmd" type="text" value="uname -a">
<button onclick="run()">Run</button>
<pre id="out">—</pre>
<script>
const $=id=>document.getElementById(id);
$('tok').value=localStorage.getItem('rt')||'';
function save(){localStorage.setItem('rt',$('tok').value);$('st').textContent='saved';refresh();}
function H(extra){return Object.assign({'X-Relay-Token':$('tok').value,'Content-Type':'application/json'},extra||{});}
async function refresh(){
  const r=await fetch('/agents',{headers:H()});
  const j=await r.json();
  if(!j.agents){$('agents').textContent=JSON.stringify(j);return;}
  let h='<table><tr><th>id</th><th>name</th><th>host</th><th>state</th><th>load</th><th>disk</th><th>last seen</th></tr>';
  for(const a of j.agents){
    const hb=a.heartbeat||{};
    h+=`<tr><td>${a.agent_id}</td><td>${a.name||''}</td><td>${a.hostname||''}</td>
    <td class="${a.online?'on':'off'}">${a.online?'online':'offline'}</td>
    <td>${hb.load1!==undefined?Number(hb.load1).toFixed(2):''}</td>
    <td><code>${(hb.disk||'').replace(/</g,'&lt;')}</code></td>
    <td>${a.last_seen?new Date(a.last_seen*1000).toLocaleTimeString():'never'}</td></tr>`;
  }
  $('agents').innerHTML=h+'</table>';
}
async function probe(){const r=await fetch('/api/health',{headers:H()});$('out').textContent=await r.text();}
async function run(){
  const a=$('agent').value.trim(); const p=(a?`/a/${a}`:'')+'/api/exec';
  $('out').textContent='running…';
  const r=await fetch(p,{method:'POST',headers:H(),body:JSON.stringify({cmd:$('cmd').value.split(' ')})});
  $('out').textContent=await r.text();
}
refresh();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "poll-relay/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log(f"{self.address_string()} {fmt % args}")

    # -- helpers
    def _json(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, text):
        b = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {"_raw": raw.decode("utf-8", "replace")}

    def _caller_ok(self) -> bool:
        tok = self.headers.get("X-Relay-Token", "")
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:]
        return bool(RELAY_TOKEN) and secrets.compare_digest(tok, RELAY_TOKEN)

    # -- GET
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p == "/":
            return self._html(200, DASH)
        if p == "/health":
            with LOCK:
                agents = [a.view() for a in AGENTS.values()]
            return self._json(200, {
                "ok": True, "relay": "poll-relay/1.0",
                "uptime_s": int(time.time() - STARTED),
                "agents_total": len(agents),
                "agents_online": sum(1 for a in agents if a["online"]),
                "sig_mode": SIG_MODE, "agents": agents,
            })
        if not self._caller_ok():
            return self._json(401, {"error": "unauthorized",
                                    "hint": "send X-Relay-Token: $RELAY_TOKEN"})
        if p == "/agents":
            with LOCK:
                agents = [a.view() for a in AGENTS.values()]
            return self._json(200, {"agents": agents})
        if p == "/favicon.ico":
            return self._json(404, {"error": "nope"})
        return self._proxy("GET", p, u)

    # -- POST
    def do_POST(self):
        u = urlparse(self.path)
        p = u.path
        if p == "/enroll":
            return self._enroll()
        if p in ("/poll", "/heartbeat") or p.startswith("/result/"):
            return self._agent_call(p)
        if not self._caller_ok():
            return self._json(401, {"error": "unauthorized",
                                    "hint": "send X-Relay-Token: $RELAY_TOKEN"})
        return self._proxy("POST", p, u)

    # -- agent side
    def _enroll(self):
        b = self._body()
        code = str(b.get("pair_code", ""))
        if not PAIR_CODE or not secrets.compare_digest(code, PAIR_CODE):
            log(f"enroll rejected: bad pair code from {self.address_string()}")
            return self._json(403, {"error": "bad pair code"})
        mode = str(b.get("sig_mode", SIG_MODE)).lower()
        if mode not in ("ed25519", "hmac"):
            return self._json(400, {"error": "sig_mode must be ed25519 or hmac"})
        if mode == "hmac":
            if not PAIR_SECRET:
                return self._json(400, {"error": "relay not configured for hmac"})
            proof = str(b.get("proof", ""))
            if not signing.hmac_verify(PAIR_SECRET, code.encode(), proof):
                return self._json(403, {"error": "bad hmac proof"})
        else:
            if not b.get("pubkey"):
                return self._json(400, {"error": "pubkey required for ed25519"})

        with LOCK:
            if len(AGENTS) >= MAX_AGENTS:
                # allow re-enroll of an existing hostname (same machine)
                match = [a for a in AGENTS.values()
                         if a.rec.get("hostname") == b.get("hostname")]
                if not match:
                    return self._json(409, {"error": f"max agents reached ({MAX_AGENTS})"})
                aid = match[0].id
                agent = match[0]
                agent.rec.update({"name": b.get("name"), "version": b.get("version"),
                                  "sig_mode": mode, "pubkey": b.get("pubkey"),
                                  "capabilities": b.get("capabilities"),
                                  "enrolled_at": int(time.time())})
            else:
                aid = "ag-" + secrets.token_hex(4)
                rec = {"name": b.get("name"), "hostname": b.get("hostname"),
                       "version": b.get("version"), "sig_mode": mode,
                       "pubkey": b.get("pubkey"),
                       "capabilities": b.get("capabilities"),
                       "enrolled_at": int(time.time())}
                AGENTS[aid] = Agent(aid, rec)
                agent = AGENTS[aid]
            agent.last_seen = time.time()
        save_state()
        log(f"enrolled {aid} name={b.get('name')} host={b.get('hostname')} mode={mode}")
        return self._json(200, {"agent_id": aid, "sig_mode": mode,
                                "relay": "poll-relay/1.0"})

    def _agent_call(self, p):
        aid = self.headers.get("X-Agent-Id", "")
        signed = p.lstrip("/")
        ok, why = verify_agent(self.headers, signed, aid)
        if not ok:
            log(f"agent auth failed for {aid or '?'} on /{signed}: {why}")
            return self._json(401, {"error": why})
        with LOCK:
            agent = AGENTS.get(aid)
            if not agent:
                return self._json(401, {"error": "unknown agent"})
        agent.last_seen = time.time()

        if p == "/heartbeat":
            b = self._body()
            b.pop("hb", None)
            agent.last_hb = b
            agent.last_hb["received_at"] = int(time.time())
            return self._json(200, {"ok": True})

        if p.startswith("/result/"):
            jid = p.split("/", 2)[2]
            b = self._body()
            with LOCK:
                slot = agent.results.get(jid)
            if not slot:
                return self._json(410, {"error": "job expired or already timed out"})
            slot["payload"] = b
            slot["event"].set()
            return self._json(200, {"ok": True})

        # /poll — long-poll
        b = self._body()
        wait_s = max(1, min(int(b.get("wait", 25)), 60))
        deadline = time.time() + wait_s
        jobs = []
        with agent.cond:
            while True:
                jobs = agent.take()
                if jobs:
                    break
                left = deadline - time.time()
                if left <= 0:
                    break
                agent.cond.wait(timeout=left)
        return self._json(200, {"jobs": jobs, "cancels": {},
                                "server_time": int(time.time())})

    # -- assistant side (transparent proxy)
    def _proxy(self, method: str, path: str, u):
        q = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(u.query).items()}
        aid = ""
        target = path
        if path.startswith("/a/"):
            parts = path.split("/", 3)          # ['', 'a', '<id>', 'api/...']
            if len(parts) < 4:
                return self._json(400, {"error": "use /a/<agent_id>/api/..."})
            aid, target = parts[2], "/" + parts[3]
        elif path.startswith("/api/"):
            target = path
        else:
            return self._json(404, {"error": f"unknown path {path}",
                                    "hint": "POST /a/<agent_id>/api/exec"})

        agent = pick_agent(aid)
        if agent is None:
            return self._json(503, {"error": "no agent enrolled yet",
                                    "hint": "start poller.py on the PC with PAIR_CODE"})
        if not agent.online():
            return self._json(503, {"error": "agent offline",
                                    "agent": agent.id,
                                    "last_seen": int(agent.last_seen) if agent.last_seen else None,
                                    "hint": "check `systemctl --user status bazzite-poller`"})

        body = self._body() if method == "POST" else None
        code, obj = dispatch(agent, method, target, q, body, self.headers.items())
        return self._json(code, obj)


def main():
    if not RELAY_TOKEN:
        print("[poll-relay] RELAY_TOKEN is required.", file=sys.stderr)
        sys.exit(2)
    if not PAIR_CODE:
        print("[poll-relay] PAIR_CODE is required (the PC trades it for an id).",
              file=sys.stderr)
        sys.exit(2)
    load_state()
    print(f"[poll-relay] sig_mode={SIG_MODE} max_agents={MAX_AGENTS} "
          f"listening on {BIND}:{PORT}", file=sys.stderr)
    print("[poll-relay] caller auth: X-Relay-Token", file=sys.stderr)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()


if __name__ == "__main__":
    main()
