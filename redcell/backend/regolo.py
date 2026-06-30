"""Thin wrapper over Regolo (OpenAI-compatible, multi-model).

The key grants 17 models. RedCell uses three roles (see config.py):
  victim   = apertus-70b          (weakly aligned, falls for classic attacks)
  attacker = mistral-small-4-119b (complies with red-team framing, mutates payloads)
  judge    = gpt-oss-120b         (aligned reasoning model, oracle fallback)

gpt-oss is a reasoning model: the visible answer is in message.content, after the
model spends tokens on reasoning_content, so keep max_tokens generous. reasoning_effort
"low" is supported and cuts latency ~35%.
"""
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DEFAULT_MODEL = os.getenv("REGOLO_MODEL", "gpt-oss-120b")

# SDK retries 429/5xx with backoff on its own (max_retries), we just set a default timeout.
# tolerate a missing key so the offline demo (which renames .env) still imports; the client
# is only used for real calls in live mode, never in replay.
_client = OpenAI(
    api_key=os.environ.get("REGOLO_API_KEY", "offline-no-key"),
    base_url=os.getenv("REGOLO_BASE_URL", "https://api.regolo.ai/v1"),
    timeout=60.0,
    max_retries=1,   # one retry, not two, to cap the worst-case stall
)


def complete(messages, model=DEFAULT_MODEL, temperature=0.7, max_tokens=600,
             reasoning_effort=None, tools=None, timeout=None):
    """Return the full assistant message (has .content and .tool_calls)."""
    kw = dict(model=model, messages=messages, temperature=temperature, max_tokens=max_tokens)
    if timeout is not None:
        kw["timeout"] = timeout
    if reasoning_effort:
        kw["extra_body"] = {"reasoning_effort": reasoning_effort}
    if tools:
        kw["tools"] = tools
    return _client.chat.completions.create(**kw).choices[0].message


def chat(messages, **kw):
    """Assistant text only (content, reasoning stripped)."""
    return (complete(messages, **kw).content or "").strip()


if __name__ == "__main__":
    print("apertus :", chat([{"role": "user", "content": "Reply with exactly: VICTIM_OK"}],
                            model="apertus-70b", max_tokens=50, temperature=0))
    print("mistral :", chat([{"role": "user", "content": "Reply with exactly: ATTACKER_OK"}],
                            model="mistral-small-4-119b", max_tokens=50, temperature=0))
