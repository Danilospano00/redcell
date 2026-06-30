"""CLI dry-run: full adaptive campaign against the victim, printed live.

    python cli.py            # attack the vulnerable victim
    python cli.py --harden   # then harden and re-attack (shows the score jump)
"""
import asyncio
import sys
import time

import victim as victim_mod
import engine


async def emit(e):
    t = e["type"]
    if t == "attack_start":
        print(f"\n=== {e['owasp']} · {e['label']} ({e['severity']}) ===")
    elif t == "attempt":
        mark = "LEAK!" if e["passed"] else " ... "
        print(f"  [{mark}] attempt {e['n']}: {e['payload'][:78]}")
        if e["passed"]:
            print(f"          victim leaked: {e['response_excerpt'][:78]!r}")
    elif t == "finding":
        f = e["finding"]
        print(f"  >> {'BROKEN' if f['success'] else 'resisted'} in {f['attempts']} attempt(s)")
    elif t == "score" and not e.get("partial"):
        print(f"\n********  SECURITY SCORE: {e['value']}/100  ********")


async def run(v, label):
    print(f"\n############ {label} ############")
    t0 = time.time()
    res = await engine.run_campaign(v, emit)
    broken = [f["label"] for f in res["findings"] if f["success"]]
    print(f"[{label}] done in {time.time()-t0:.1f}s · score={res['score']} · broken={broken}")
    return res


async def main():
    v = victim_mod.fresh_victim()
    await run(v, "RUN (vulnerable)")
    if "--harden" in sys.argv:
        import harden
        harden.harden(v)
        await run(v, "RE-RUN (hardened)")


if __name__ == "__main__":
    asyncio.run(main())
