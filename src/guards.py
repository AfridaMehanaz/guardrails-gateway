"""Guards for the LLM Gateway.

INPUT guards (run BEFORE the request reaches the LLM provider):
  pii_mask         -> detect & mask emails, phones, SSNs, credit cards
  prompt_injection -> detect jailbreak/override attempts
  banned_topics    -> configurable keyword blocklist

OUTPUT guards (run on the LLM's response BEFORE the user sees it):
  pii_mask         -> mask any PII the model echoes back
  toxicity         -> block toxic responses (starter wordlist; swap for an
                      ML classifier like detoxify in production)
  max_length       -> truncate runaway responses

Every guard returns: (ok: bool, transformed_text: str, detail: str)
  ok=False -> the gateway should block this request/response
"""
import re

# ---------------- PII ----------------

PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}


def pii_mask(text: str):
    """Masks PII in place. Never blocks - it transforms."""
    found = []
    masked = text
    for label, pattern in PII_PATTERNS.items():
        if pattern.search(masked):
            found.append(label)
            masked = pattern.sub(f"<{label}_MASKED>", masked)
    detail = f"masked: {', '.join(found)}" if found else "clean"
    return True, masked, detail


# ---------------- Prompt injection ----------------

INJECTION_PATTERNS = [
    r"ignore (all |the |your )?(previous|prior|above) (instructions|prompts)",
    r"disregard (your|the) (system prompt|instructions|rules)",
    r"you are now (DAN|developer mode|unrestricted)",
    r"pretend (you have|there are) no (rules|restrictions|guidelines)",
    r"reveal (your|the) system prompt",
    r"repeat (everything|the text) (above|before)",
    r"\bjailbreak\b",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def prompt_injection(text: str):
    m = INJECTION_RE.search(text)
    if m:
        return False, text, f"injection pattern matched: '{m.group(0)}'"
    return True, text, "clean"


# ---------------- Banned topics ----------------

def banned_topics(text: str, banned: list):
    lowered = text.lower()
    hits = [t for t in banned if t.lower() in lowered]
    if hits:
        return False, text, f"banned topics: {', '.join(hits)}"
    return True, text, "clean"


# ---------------- Toxicity (starter) ----------------

TOXIC_WORDS = {"idiot", "stupid", "hate you", "kill yourself"}


def toxicity(text: str):
    lowered = text.lower()
    hits = [w for w in TOXIC_WORDS if w in lowered]
    if hits:
        return False, text, f"toxic terms: {', '.join(hits)}"
    return True, text, "clean"


# ---------------- Length ----------------

def max_length(text: str, limit: int):
    if len(text) > limit:
        return True, text[:limit] + "\n[truncated by gateway]", f"truncated to {limit} chars"
    return True, text, "clean"