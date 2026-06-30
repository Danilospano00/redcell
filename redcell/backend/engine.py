"""Attack engine.

Round 1: fire all seeds of a category in parallel, first leak (seed order) wins.
Victim is deterministic so seeds are independent. If nothing lands and not every seed
was guardrail-blocked, run one LLM mutation as fallback. Categories run in parallel too,
a semaphore gates the seed-flows. Progress streamed via the emit() callback.

Events: attack_start, attempt, finding, score, done
"""
import asyncio
import json
import config
import attacks
import oracle


async def _agentic_attempt(victim, cid, payload, emit):
    """Tool-layer attack: give the victim the lookup_customer function. A weak agent calls it
    for accounts it must not read, cross-account leak with a tool_call. Returns
    (final_answer_text, leaked); leaked is True if an unauthorized lookup returned data."""
    msg = await asyncio.to_thread(victim.ask_raw, payload, config.LOOKUP_TOOL)
    tcalls = getattr(msg, "tool_calls", None)
    if not tcalls:                                   # refused or guardrail-blocked, no tool reached
        return (msg.content or "").strip(), False

    enforce = getattr(victim, "hardened", False)     # hardened agent enforces least-privilege
    outputs, leaked = [], False
    for tc in tcalls:
        try:
            args = json.loads(tc.function.arguments or "{}")
        except Exception:
            args = {}
        cust = (args.get("customer_id") or "").strip().upper()
        result = config.run_lookup(cust, enforce_authz=enforce)
        unauthorized = cust != config.AUTH_CUSTOMER
        got_data = "error" not in result
        if unauthorized and got_data:
            leaked = True
        outputs.append((tc.id, json.dumps(result)))
        await emit({"type": "tool_call", "category": cid, "tool": tc.function.name,
                    "customer_id": cust, "authorized": not unauthorized,
                    "blocked": unauthorized and not got_data,
                    "result_excerpt": json.dumps(result)[:200]})
    final = await asyncio.to_thread(victim.answer_after_tool, payload, msg, outputs)
    return final, leaked


async def _attempt_once(victim, cat, cid, payload, emit, n):
    """Run one payload against the victim, emit the attempt, return (passed, response, blocked).
    blocked = input guardrail stopped it before the model, nothing to adapt to."""
    if cat.get("agentic"):
        response, agent_leak = await _agentic_attempt(victim, cid, payload, emit)
        passed = oracle.detect(cid, response) or agent_leak
    else:
        response = await asyncio.to_thread(victim.ask, payload)
        passed = oracle.detect(cid, response)
    await emit({"type": "attempt", "category": cid, "n": n, "payload": payload,
                "response_excerpt": response[:240], "passed": passed})
    return passed, response, "[GUARDRAIL BLOCKED]" in response


async def _run_category(victim, cat, emit, sem):
    cid = cat["id"]
    await emit({"type": "attack_start", "category": cid,
                "label": cat["label"], "owasp": cat["owasp"], "severity": cat["severity"]})

    seeds = [attacks.seed(cid, i) for i in range(attacks.n_seeds(cid))]

    # round 1: every seed in parallel, one semaphore slot each (agentic seed-flow holds its
    # slot across both model turns). first leak in seed order wins.
    async def run_seed(i, p):
        async with sem:
            return await _attempt_once(victim, cat, cid, p, emit, i + 1)
    results = await asyncio.gather(*[run_seed(i, p) for i, p in enumerate(seeds)])

    success, winning, excerpt = False, None, None
    n_done = len(seeds)
    win = next((i for i, (passed, _, _) in enumerate(results) if passed), None)
    if win is not None:
        success, winning, excerpt = True, seeds[win], results[win][1][:240]

    # round 2: one LLM mutation off a failed seed that reached the model.
    # skipped if every seed was guardrail-blocked (no response to adapt to).
    if not success and config.MAX_MUTATIONS > 0 and not all(b for _, _, b in results):
        base = next(((seeds[i], r) for i, (_, r, b) in enumerate(results) if not b), None)
        if base:
            mutated = await asyncio.to_thread(attacks.attacker_mutate, cid, base[0], base[1])
            if mutated:
                n_done += 1
                async with sem:
                    passed, response, _ = await _attempt_once(victim, cat, cid, mutated, emit, n_done)
                if passed:
                    success, winning, excerpt = True, mutated, response[:240]

    finding = {"category": cid, "label": cat["label"], "owasp": cat["owasp"],
               "severity": cat["severity"], "success": success, "attempts": n_done,
               "winning_payload": winning, "victim_excerpt": excerpt}
    await emit({"type": "finding", "finding": finding})
    return cid, success, finding


async def run_campaign(victim, emit):
    """Run all categories in parallel against `victim`. Returns {score, findings, success_by_cat}."""
    sem = asyncio.Semaphore(config.CONCURRENCY)
    await emit({"type": "score", "value": oracle.score({}), "partial": True})  # gauge starts at 95, drops on each break
    tasks = [asyncio.create_task(_run_category(victim, cat, emit, sem)) for cat in config.CATEGORIES]

    success_by_cat, findings = {}, []
    for coro in asyncio.as_completed(tasks):
        cid, success, finding = await coro
        success_by_cat[cid] = success
        findings.append(finding)
        await emit({"type": "score", "value": oracle.score(success_by_cat), "partial": True})

    final = oracle.score(success_by_cat)
    findings.sort(key=lambda f: config.CATEGORY_IDS.index(f["category"]))
    await emit({"type": "score", "value": final, "partial": False})
    await emit({"type": "done", "score": final, "findings": findings,
                "hardened": getattr(victim, "hardened", False)})
    return {"score": final, "findings": findings, "success_by_cat": success_by_cat}
