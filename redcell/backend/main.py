"""FastAPI app: serves the dashboard, runs campaigns, streams progress over SSE.

POST /run attacks the current victim. POST /harden installs defenses, POST /reattack
runs a fresh campaign on the hardened victim so the gauge climbs from ~35 to ~95.
GET /events is the live SSE feed the dashboard renders.
"""
import asyncio
import json
import os

from fastapi import FastAPI
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse

import config
import victim as victim_mod
import engine
import harden as harden_mod

app = FastAPI(title="RedCell")
_FRONTEND = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")

state = {"victim": victim_mod.fresh_victim(), "running": False, "last": None, "task": None}
# one queue per /events connection, emit() broadcasts to all. a single shared queue would
# be competing-consumers, not pub/sub: with two tabs open each event reaches only one of them.
_subscribers: "set[asyncio.Queue]" = set()
EMIT_DELAY = 0.18   # pace the stream so it's readable on stage


def _broadcast(event):
    for q in list(_subscribers):
        q.put_nowait(event)

# offline demo: replay a recorded run from fixtures/ instead of calling Regolo.
# fallback if the venue network is down (REDCELL_OFFLINE=1), keeps the demo interactive.
OFFLINE = os.getenv("REDCELL_OFFLINE") == "1"
_FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name):
    with open(os.path.join(_FIX, name), encoding="utf-8") as f:
        return json.load(f)


async def _replay_events(events, label="replay"):
    state["running"] = True
    try:
        for ev in events:
            await emit(ev)
    except Exception as e:
        _broadcast({"type": "error", "message": f"{label}: {e}"})
    finally:
        state["running"] = False


async def _replay(name):
    await _replay_events(_load_fixture(name), f"replay {name}")


def _split_harden_fixture():
    """harden.json holds the harden-phase events then the re-attack campaign. split at the
    first campaign_start so each button replays its own slice offline."""
    evs = _load_fixture("harden.json")
    cut = next((i for i, e in enumerate(evs) if e.get("type") == "campaign_start"), len(evs))
    return evs[:cut], evs[cut:]


async def emit(event):
    _broadcast(event)
    # pace the visible beats. 'hardened' is not paced on purpose: it's the terminal harden
    # event and the UI enables Re-attack the instant it lands. a trailing sleep here would hold
    # the running guard past that point, so a fast Re-attack click would hit a 409.
    if event.get("type") in ("attempt", "finding", "attack_start", "tool_call", "patch"):
        await asyncio.sleep(EMIT_DELAY)


async def _campaign():
    state["running"] = True
    try:
        state["last"] = await engine.run_campaign(state["victim"], emit)
    except Exception as e:                       # don't leave the UI hanging
        _broadcast({"type": "error", "message": f"{type(e).__name__}: {e}"})
    finally:
        state["running"] = False


@app.get("/")
async def index():
    return FileResponse(_FRONTEND)


@app.post("/run")
async def run():
    if state["running"]:
        return JSONResponse({"error": "already running"}, status_code=409)
    state["running"] = True   # close the guard window synchronously, before handing off
    if OFFLINE:
        state["task"] = asyncio.create_task(_replay("attack.json"))
        return {"started": True, "offline": True}
    await emit({"type": "campaign_start", "hardened": state["victim"].hardened})
    state["task"] = asyncio.create_task(_campaign())
    return {"started": True}


@app.post("/harden")
async def do_harden():
    """Install defenses only. The re-attack is a separate step (POST /reattack)."""
    if state["running"]:
        return JSONResponse({"error": "already running"}, status_code=409)
    state["running"] = True   # held across the hardening phase, released when defenses are up
    try:
        if OFFLINE:
            harden_evs, _ = _split_harden_fixture()
            state["task"] = asyncio.create_task(_replay_events(harden_evs, "replay harden"))
            return {"hardened": True, "offline": True}
        await emit({"type": "hardening"})
        # gpt-oss writes the policy live (benign task, it complies); to_thread keeps the SSE
        # stream flowing. the deterministic guardrail + DLP still guarantee the block if the
        # generated policy is weak or the model is slow.
        v = state["victim"]
        await asyncio.to_thread(harden_mod.harden, v, True)
        await emit({"type": "patch",
                    "source": getattr(v, "policy_source", "deterministic"),
                    "policy": getattr(v, "policy_text", "")[:700]})
        state["running"] = False                # release the guard before announcing 'hardened'
                                                # so the Re-attack the UI now offers is accepted
        await emit({"type": "hardened",
                    "layers": ["Security policy (system prompt)", "Input guardrail (regex)",
                               "Output DLP filter", "Tool-layer authorization"]})
        return {"hardened": True}
    except Exception as e:                     # don't strand the UI mid-harden
        _broadcast({"type": "error", "message": f"{type(e).__name__}: {e}"})
        state["running"] = False
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/reattack")
async def reattack():
    """Run a campaign against the hardened victim. The gauge climbs back to ~95."""
    if state["running"]:
        return JSONResponse({"error": "already running"}, status_code=409)
    state["running"] = True   # close the guard window synchronously, before handing off
    if OFFLINE:
        _, attack_evs = _split_harden_fixture()
        state["task"] = asyncio.create_task(_replay_events(attack_evs, "replay reattack"))
        return {"started": True, "offline": True}
    await emit({"type": "campaign_start", "hardened": True})
    state["task"] = asyncio.create_task(_campaign())
    return {"started": True}


@app.post("/reset")
async def reset():
    task = state.get("task")
    if task and not task.done():
        task.cancel()                          # stop any in-flight campaign before reset
    state["victim"] = victim_mod.fresh_victim()
    state["last"] = None
    state["running"] = False
    state["task"] = None
    await emit({"type": "reset"})
    return {"reset": True}


@app.get("/report")
async def report():
    if not state["last"]:
        return JSONResponse({"error": "no run yet"}, status_code=404)
    return JSONResponse(state["last"])


@app.get("/events")
async def events():
    q: "asyncio.Queue" = asyncio.Queue()
    _subscribers.add(q)                          # register this client, drop it on disconnect
    async def gen():
        try:
            yield f"data: {json.dumps({'type': 'hello', 'categories': config.CATEGORIES})}\n\n"
            while True:
                event = await q.get()
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            _subscribers.discard(q)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                                      "Connection": "keep-alive"})
