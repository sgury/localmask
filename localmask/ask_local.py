"""Bring-your-own-key AI Q&A over a masked repo — masking + rehydration are 100%
local and deterministic (no key needed for those). LocalMask masks the repo
locally, sends only ~[TOKEN]~ placeholders to the AI provider YOU choose with
YOUR key, then rehydrates the answer locally.

Works with any provider — Anthropic, OpenAI, Google Gemini, xAI/Grok, Meta/Llama
(via Groq/Together/OpenRouter), and any OpenAI-compatible endpoint. Uses only the
standard library, so it ships in the free edition with no extra dependencies.
"""
import json
import urllib.request

from .masking import _mask_text, _rehydrate

SYSTEM_PROMPT = (
    "You are reviewing a MASKED repository. Secrets are replaced with tokens "
    "like ~[PASSWORD_0]~. Never guess or invent the real value behind a token — "
    "refer to tokens by name. Be concise.")

# OpenAI-compatible providers → default base URL. Any of these (and any other
# OpenAI-compatible gateway) work by name or with --base-url.
_OPENAI_COMPAT = {
    "openai":     "https://api.openai.com/v1",
    "grok":       "https://api.x.ai/v1",
    "xai":        "https://api.x.ai/v1",
    "groq":       "https://api.groq.com/openai/v1",   # fast Llama/Meta hosting
    "together":   "https://api.together.xyz/v1",       # Llama/Meta, Mixtral, ...
    "openrouter": "https://openrouter.ai/api/v1",       # many models incl. Grok/Llama
    "meta":       "https://api.together.xyz/v1",         # Meta Llama via Together
}


def _post(url: str, headers: dict, payload: dict, timeout: int = 90) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def call_model(provider: str, api_key: str, model: str, messages: list,
               base_url: str = "", system: str = "") -> str:
    """Call one AI provider with plain messages. Returns the answer text."""
    p = (provider or "openai").lower()

    if p == "anthropic":
        url = (base_url or "https://api.anthropic.com") + "/v1/messages"
        body = {"model": model, "max_tokens": 2048, "messages": messages}
        if system:
            body["system"] = system
        resp = _post(url, {"x-api-key": api_key,
                           "anthropic-version": "2023-06-01"}, body)
        return "".join(b.get("text", "") for b in resp.get("content", []))

    if p in ("gemini", "google"):
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               f"{model}:generateContent?key={api_key}")
        contents = [{"role": ("model" if m["role"] == "assistant" else "user"),
                     "parts": [{"text": m["content"]}]} for m in messages]
        body = {"contents": contents}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        resp = _post(url, {}, body)
        return "".join(part.get("text", "") for part in
                       resp["candidates"][0]["content"]["parts"])

    # OpenAI + any OpenAI-compatible provider (grok, groq, together, meta, ...)
    url = (base_url or _OPENAI_COMPAT.get(p, _OPENAI_COMPAT["openai"])) \
        + "/chat/completions"
    msgs = ([{"role": "system", "content": system}] if system else []) + messages
    resp = _post(url, {"authorization": f"Bearer {api_key}"},
                 {"model": model, "messages": msgs, "max_tokens": 2048})
    return resp["choices"][0]["message"]["content"]


def build_masked_context(session: dict, only_findings: bool = True,
                         max_chars: int = 80_000) -> str:
    parts, total = [], 0
    for path, d in sorted(session["files"].items()):
        if only_findings and d.get("n", 0) == 0:
            continue
        chunk = f"\n----- FILE: {_mask_text(session, path)} -----\n{d['masked']}"
        if total + len(chunk) > max_chars:
            continue
        parts.append(chunk)
        total += len(chunk)
    return "".join(parts) or "(no findings — nothing to review)"


def ask(session: dict, question: str, provider: str, api_key: str, model: str,
        base_url: str = "", only_findings: bool = True) -> str:
    """Mask the repo + question locally → ask the provider → rehydrate locally."""
    context = build_masked_context(session, only_findings)
    masked_q = _mask_text(session, question)
    messages = [{"role": "user",
                 "content": f"MASKED REPOSITORY:\n{context}\n\n"
                            f"Question: {masked_q}"}]
    answer = call_model(provider, api_key, model, messages,
                        base_url=base_url, system=SYSTEM_PROMPT)
    return _rehydrate(session, answer)   # local, exact — no key involved


GIT_SYSTEM_PROMPT = (
    "You are answering a question about a MASKED code repository that you have "
    "your OWN read access to. Read the files you need directly from that git "
    "repository — its full content is NOT included in this prompt. Every secret "
    "in it is already replaced by a token like ~[PASSWORD_0]~; never guess or "
    "invent the real value behind a token, just refer to it by name. Be concise.")


def ask_over_git(session: dict, question: str, git_url: str, provider: str,
                 api_key: str, model: str, base_url: str = "") -> str:
    """Ask a question WITHOUT sending any repository content. The AI reads the
    masked repo itself (it has its own read access to git_url). LocalMask only
    masks the question (using the found-secret vault) and rehydrates the answer —
    no repo data and no git credentials leave the machine; the only thing sent to
    your provider is the masked question and the repo URL."""
    masked_q = _mask_text(session, question)   # mask the question by found keys
    messages = [{"role": "user",
                 "content": f"The masked repository is at: {git_url}\n"
                            f"Read what you need from it, then answer.\n\n"
                            f"Question: {masked_q}"}]
    answer = call_model(provider, api_key, model, messages,
                        base_url=base_url, system=GIT_SYSTEM_PROMPT)
    return _rehydrate(session, answer)
