"""LLM Guardrails Gateway — a reverse proxy enforcing safety policy on every
LLM request and response. OpenAI-compatible: point any client's base_url here.

    Client --> /v1/chat/completions --> [input guards] --> LLM provider
           <-------------------------- [output guards] <------+

Run (from inside src/):
    uvicorn gateway:app --port 8080
"""
import os
import time
import json
import logging
from collections import defaultdict, deque

import yaml
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import guards

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
audit = logging.getLogger("gateway.audit")

with open(os.path.join(os.path.dirname(__file__), "policy.yaml")) as f:
    POLICY = yaml.safe_load(f)

BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
API_KEY = os.getenv("LLM_API_KEY", "set-me")
MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")

app = FastAPI(title="LLM Guardrails Gateway")

# ---------------- In-memory rate limiter ----------------
_hits = defaultdict(deque)


def rate_limited(client_ip: str) -> bool:
    rpm = POLICY["rate_limit"]["requests_per_minute"]
    now = time.time()
    q = _hits[client_ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= rpm:
        return True
    q.append(now)
    return False


def blocked(reason: str, guard: str, status: int = 400):
    audit.warning(json.dumps({"event": "BLOCKED", "guard": guard, "reason": reason}))
    return JSONResponse(status_code=status, content={
        "error": {"type": "guardrail_violation", "guard": guard, "message": reason}
    })


@app.get("/health")
def health():
    return {"status": "ok", "provider": BASE_URL, "model": MODEL}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if rate_limited(client_ip):
        return blocked("rate limit exceeded", "rate_limit", status=429)

    body = await request.json()
    messages = body.get("messages", [])
    user_text = " ".join(
        m.get("content", "") for m in messages if isinstance(m.get("content"), str)
    )

    ig = POLICY["input_guards"]

    # ---- INPUT: prompt injection ----
    if ig["prompt_injection"]["enabled"]:
        ok, _, detail = guards.prompt_injection(user_text)
        if not ok and ig["prompt_injection"]["action"] == "block":
            return blocked(detail, "prompt_injection")

    # ---- INPUT: banned topics ----
    if ig["banned_topics"]["enabled"]:
        ok, _, detail = guards.banned_topics(user_text, ig["banned_topics"]["topics"])
        if not ok and ig["banned_topics"]["action"] == "block":
            return blocked(detail, "banned_topics")

    # ---- INPUT: PII masking (transforms, never blocks) ----
    if ig["pii_mask"]["enabled"]:
        for m in messages:
            if isinstance(m.get("content"), str):
                _, m["content"], detail = guards.pii_mask(m["content"])
                if detail != "clean":
                    audit.info(json.dumps({"event": "PII_MASKED_INPUT", "detail": detail}))

    # ---- Forward to the real LLM provider ----
    body["model"] = body.get("model") or MODEL
    async with httpx.AsyncClient(timeout=60) as client:
        upstream = await client.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json=body,
        )
    if upstream.status_code != 200:
        return JSONResponse(status_code=upstream.status_code, content=upstream.json())

    data = upstream.json()
    answer = data["choices"][0]["message"]["content"]

    og = POLICY["output_guards"]

    # ---- OUTPUT: toxicity ----
    if og["toxicity"]["enabled"]:
        ok, _, detail = guards.toxicity(answer)
        if not ok and og["toxicity"]["action"] == "block":
            return blocked(f"response blocked: {detail}", "toxicity_output", status=502)

    # ---- OUTPUT: PII leak masking ----
    if og["pii_leak"]["enabled"]:
        _, answer, detail = guards.pii_mask(answer)
        if detail != "clean":
            audit.info(json.dumps({"event": "PII_MASKED_OUTPUT", "detail": detail}))

    # ---- OUTPUT: max length ----
    if og["max_length"]["enabled"]:
        _, answer, _ = guards.max_length(answer, og["max_length"]["limit_chars"])

    data["choices"][0]["message"]["content"] = answer
    audit.info(json.dumps({"event": "PASSED", "client": client_ip}))
    return data