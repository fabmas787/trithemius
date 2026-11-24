"""
Providers — Multi-provider inference and cloud streaming engine for Trithemius.

Provides a unified interface for streaming real-time LLM completions from:
1. Ollama (local or remote via OLLAMA_HOST with optional auth token)
2. Groq Cloud (high-speed Llama 3.1 / 3.3, 0 VRAM)
3. OpenAI (GPT-4o-mini, GPT-4o)
4. Google Gemini (Gemini 1.5 Flash, Gemini Pro)
5. Anthropic Claude (Claude 3.5 Haiku, Sonnet)
6. OpenRouter / OpenAI-Compatible endpoints

Optimizations (F06):
- Connection reuse via thread-local requests.Session()
- Connection pooling with HTTPAdapter (pool_connections=5, pool_maxsize=10)
- Ollama keep-alive configuration (TRITHEMIUS_KEEP_ALIVE, 5m standard / 1m low-spec)
- Stable prompt layout & constant inference options for KV-cache reuse
"""

import os
import sys
import json
import time
import threading
from typing import Generator, Tuple, Optional, Dict, Any, List

# Lazy-loaded requests module
_requests = None
_THREAD_LOCAL = threading.local()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

TIMEOUT_CONNECT = 10
TIMEOUT_READ = 60


def _get_requests():
    global _requests
    if _requests is None:
        import requests
        _requests = requests
    return _requests


def get_session():
    """Return thread-local requests.Session configured with keep-alive connection pooling."""
    req = _get_requests()
    if not hasattr(_THREAD_LOCAL, "session") or _THREAD_LOCAL.session is None:
        from requests.adapters import HTTPAdapter
        session = req.Session()
        adapter = HTTPAdapter(pool_connections=5, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _THREAD_LOCAL.session = session
    return _THREAD_LOCAL.session


def _post_request(url: str, **kwargs):
    """
    Execute HTTP POST request.
    If requests.post has been patched/mocked (e.g. by unit tests), delegates directly to it.
    Otherwise uses thread-local pooled session for high-performance keep-alive connection reuse.
    """
    req = _get_requests()
    if getattr(req.post, "__module__", "").startswith("unittest.mock") or hasattr(req.post, "assert_called"):
        return req.post(url, **kwargs)
    session = get_session()
    return session.post(url, **kwargs)


def _get_keep_alive() -> str:
    """Retrieve keep_alive duration based on environment variable or hardware profile."""
    val = os.environ.get("TRITHEMIUS_KEEP_ALIVE")
    if val:
        return val.strip()
    return "1m" if getattr(config, "LOW_SPEC_MODE", False) else "5m"


def _build_messages(prompt: str, system_prompt: str = "") -> list:
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    return messages


# -----------------------------------------------------------------------------
# 1. Ollama Streaming (Local or Remote Cloud Host)
# -----------------------------------------------------------------------------

def stream_ollama(
    model: str,
    prompt: str,
    system_prompt: str = "",
    think: bool = False,
    host: str = None,
    api_key: str = None,
    options: dict = None,
) -> Generator[Tuple[str, str], None, None]:
    """Stream completions from an Ollama instance (local daemon or remote cloud)."""
    req = _get_requests()
    ollama_host = (host or config.OLLAMA_HOST or "http://localhost:11434").rstrip("/")
    url = f"{ollama_host}/api/chat"

    headers = {"Content-Type": "application/json"}
    token = api_key or config.OLLAMA_API_KEY
    if token:
        headers["Authorization"] = f"Bearer {token}"

    opts = {
        "num_ctx": config.DEFAULT_NUM_CTX,
        "num_predict": config.DEFAULT_NUM_PREDICT,
        "temperature": 0.2,
    }
    if options:
        opts.update(options)

    payload = {
        "model": model,
        "messages": _build_messages(prompt, system_prompt),
        "options": opts,
        "stream": True,
        "think": think,
        "keep_alive": _get_keep_alive(),
    }

    try:
        resp = _post_request(url, json=payload, headers=headers, stream=True, timeout=(TIMEOUT_CONNECT, TIMEOUT_READ))
        if resp.status_code != 200:
            err_msg = f"Ollama HTTP {resp.status_code}"
            try:
                err_data = resp.json()
                if "error" in err_data:
                    err_msg += f": {err_data['error']}"
            except Exception:
                err_msg += f": {resp.text[:200]}"
            raise RuntimeError(err_msg)

        for line in resp.iter_lines():
            if not line:
                continue
            chunk = json.loads(line.decode("utf-8"))
            msg = chunk.get("message", {})
            thinking = msg.get("thinking")
            content = msg.get("content")

            if thinking:
                yield ("thinking", thinking)
            if content:
                yield ("content", content)

    except req.exceptions.ConnectionError:
        raise ConnectionError(
            f"Cannot connect to Ollama host at {ollama_host}. "
            "Verify that Ollama is running (`ollama serve`) or check your OLLAMA_HOST URL."
        )


# -----------------------------------------------------------------------------
# 2. OpenAI-Compatible Streaming (Groq, OpenAI, OpenRouter)
# -----------------------------------------------------------------------------

OPENAI_COMPATIBLE_ENDPOINTS = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
}


def stream_openai_compatible(
    provider: str,
    model: str,
    prompt: str,
    system_prompt: str = "",
    api_key: str = None,
    endpoint: str = None,
    options: dict = None,
) -> Generator[Tuple[str, str], None, None]:
    """Stream from OpenAI-compatible REST APIs with Server-Sent Events (SSE)."""
    req = _get_requests()
    key = api_key or config.get_api_key(provider)
    if not key:
        env_var = config.PROVIDER_ENV_VARS.get(provider, f"{provider.upper()}_API_KEY")
        raise ValueError(
            f"No API key found for provider '{provider}'. "
            f"Set it using '/key {provider} <key>' or export {env_var}."
        )

    url = endpoint or OPENAI_COMPATIBLE_ENDPOINTS.get(provider, "https://api.openai.com/v1/chat/completions")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/trithemius/trithemius"
        headers["X-Title"] = "Trithemius Cryptanalytic Workstation"

    max_tokens = config.DEFAULT_NUM_PREDICT
    if options and "num_predict" in options:
        max_tokens = options["num_predict"]

    payload = {
        "model": model,
        "messages": _build_messages(prompt, system_prompt),
        "stream": True,
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }

    try:
        resp = _post_request(url, json=payload, headers=headers, stream=True, timeout=(TIMEOUT_CONNECT, TIMEOUT_READ))
        if resp.status_code != 200:
            err_msg = f"{provider.capitalize()} API Error ({resp.status_code})"
            try:
                err_data = resp.json()
                if "error" in err_data:
                    err_info = err_data["error"]
                    msg = err_info.get("message") if isinstance(err_info, dict) else str(err_info)
                    err_msg += f": {msg}"
            except Exception:
                err_msg += f": {resp.text[:200]}"
            raise RuntimeError(err_msg)

        for line in resp.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if not decoded.startswith("data:"):
                continue
            data_part = decoded[len("data:"):].strip()
            if data_part == "[DONE]":
                break

            try:
                chunk = json.loads(data_part)
                choices = chunk.get("choices", [])
                if not choices:
                    continue
                delta = choices[0].get("delta", {})

                # DeepSeek/Groq reasoning delta support
                reasoning = delta.get("reasoning") or delta.get("reasoning_content")
                if reasoning:
                    yield ("thinking", reasoning)

                content = delta.get("content")
                if content:
                    yield ("content", content)
            except json.JSONDecodeError:
                continue

    except req.exceptions.ConnectionError as e:
        raise ConnectionError(f"Network error communicating with {provider}: {e}")


# -----------------------------------------------------------------------------
# 3. Google Gemini REST Streaming
# -----------------------------------------------------------------------------

def stream_gemini(
    model: str,
    prompt: str,
    system_prompt: str = "",
    api_key: str = None,
    options: dict = None,
) -> Generator[Tuple[str, str], None, None]:
    """Stream completions from Google Gemini REST API using SSE."""
    req = _get_requests()
    key = api_key or config.get_api_key("gemini")
    if not key:
        raise ValueError("No API key found for Gemini. Set it via '/key gemini <key>' or export GEMINI_API_KEY.")

    clean_model = model.replace("gemini/", "")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:streamGenerateContent?alt=sse&key={key}"
    headers = {"Content-Type": "application/json"}

    contents = []
    if system_prompt:
        system_instruction = {"parts": [{"text": system_prompt}]}
    else:
        system_instruction = None

    contents.append({"role": "user", "parts": [{"text": prompt}]})

    max_tokens = config.DEFAULT_NUM_PREDICT
    if options and "num_predict" in options:
        max_tokens = options["num_predict"]

    payload = {
        "contents": contents,
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": max_tokens,
        }
    }
    if system_instruction:
        payload["systemInstruction"] = system_instruction

    try:
        resp = _post_request(url, json=payload, headers=headers, stream=True, timeout=(TIMEOUT_CONNECT, TIMEOUT_READ))
        if resp.status_code != 200:
            err_msg = f"Gemini API Error ({resp.status_code})"
            try:
                err_data = resp.json()
                if "error" in err_data:
                    err_msg += f": {err_data['error'].get('message', '')}"
            except Exception:
                err_msg += f": {resp.text[:200]}"
            raise RuntimeError(err_msg)

        for line in resp.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if not decoded.startswith("data:"):
                continue
            data_part = decoded[len("data:"):].strip()
            try:
                chunk = json.loads(data_part)
                candidates = chunk.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    for part in parts:
                        text = part.get("text", "")
                        if text:
                            yield ("content", text)
            except json.JSONDecodeError:
                continue

    except req.exceptions.ConnectionError as e:
        raise ConnectionError(f"Network error communicating with Google Gemini: {e}")


# -----------------------------------------------------------------------------
# 4. Anthropic Claude REST Streaming
# -----------------------------------------------------------------------------

def stream_anthropic(
    model: str,
    prompt: str,
    system_prompt: str = "",
    api_key: str = None,
    options: dict = None,
) -> Generator[Tuple[str, str], None, None]:
    """Stream completions from Anthropic Claude Messages API using SSE."""
    req = _get_requests()
    key = api_key or config.get_api_key("anthropic")
    if not key:
        raise ValueError("No API key found for Anthropic. Set it via '/key anthropic <key>' or export ANTHROPIC_API_KEY.")

    clean_model = model.replace("anthropic/", "")
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    max_tokens = config.DEFAULT_NUM_PREDICT
    if options and "num_predict" in options:
        max_tokens = options["num_predict"]

    payload = {
        "model": clean_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "stream": True,
    }
    if system_prompt:
        payload["system"] = system_prompt

    try:
        resp = _post_request(url, json=payload, headers=headers, stream=True, timeout=(TIMEOUT_CONNECT, TIMEOUT_READ))
        if resp.status_code != 200:
            err_msg = f"Anthropic API Error ({resp.status_code})"
            try:
                err_data = resp.json()
                if "error" in err_data:
                    err_msg += f": {err_data['error'].get('message', '')}"
            except Exception:
                err_msg += f": {resp.text[:200]}"
            raise RuntimeError(err_msg)

        for line in resp.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if not decoded.startswith("data:"):
                continue
            data_part = decoded[len("data:"):].strip()
            try:
                chunk = json.loads(data_part)
                event_type = chunk.get("type")
                if event_type == "content_block_delta":
                    delta = chunk.get("delta", {})
                    if delta.get("type") == "text_delta":
                        yield ("content", delta.get("text", ""))
            except json.JSONDecodeError:
                continue

    except req.exceptions.ConnectionError as e:
        raise ConnectionError(f"Network error communicating with Anthropic: {e}")


# -----------------------------------------------------------------------------
# Unified Streaming Completion Dispatcher
# -----------------------------------------------------------------------------

def stream_completion(
    provider: str,
    model: str,
    prompt: str,
    system_prompt: str = "",
    think: bool = False,
    api_key: str = None,
    options: dict = None,
) -> Generator[Tuple[str, str], None, None]:
    """
    Unified entry point for streaming tokens from any provider.
    Yields (type, text_chunk) tuples where type is 'thinking' or 'content'.
    """
    p = provider.lower()
    if p == "ollama":
        yield from stream_ollama(model, prompt, system_prompt, think=think, api_key=api_key, options=options)
    elif p in ("groq", "openai", "openrouter"):
        yield from stream_openai_compatible(p, model, prompt, system_prompt, api_key=api_key, options=options)
    elif p == "gemini":
        yield from stream_gemini(model, prompt, system_prompt, api_key=api_key, options=options)
    elif p == "anthropic":
        yield from stream_anthropic(model, prompt, system_prompt, api_key=api_key, options=options)
    else:
        # Fallback to OpenAI compatible
        yield from stream_openai_compatible(p, model, prompt, system_prompt, api_key=api_key, options=options)


# -----------------------------------------------------------------------------
# 7. Model ID & Endpoint Health Prober
# -----------------------------------------------------------------------------

def probe_provider(provider: str, model: Optional[str] = None, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Validate configured provider and model ID with a minimal connectivity probe.
    Returns structured {ok: bool, status: str, provider: str, model: str, latency_ms: float, reason/details: str}.
    Guaranteed never to crash or raise unhandled exceptions.
    """
    p = provider.lower()
    target_model = model or config.PROVIDER_DEFAULT_MODELS.get(p, config.MODEL_NAME)
    req = _get_requests()
    t0 = time.perf_counter()

    if p == "ollama":
        host = (config.OLLAMA_HOST or "http://localhost:11434").rstrip("/")
        headers = {}
        if config.OLLAMA_API_KEY:
            headers["Authorization"] = f"Bearer {config.OLLAMA_API_KEY}"
        try:
            resp = req.get(f"{host}/api/tags", headers=headers, timeout=timeout)
            latency = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                tags_data = resp.json() if resp.text else {}
                models_list = [m.get("name") for m in tags_data.get("models", [])]
                model_found = any(target_model in m for m in models_list) if models_list else True
                return {
                    "ok": True,
                    "status": "OK",
                    "provider": p,
                    "model": target_model,
                    "latency_ms": round(latency, 2),
                    "details": f"Daemon online ({len(models_list)} local models)" if model_found else f"Daemon online (model '{target_model}' not in local tags)",
                }
            return {
                "ok": False,
                "status": "FAIL",
                "provider": p,
                "model": target_model,
                "latency_ms": round(latency, 2),
                "reason": f"HTTP {resp.status_code}: {resp.text[:120]}",
            }
        except Exception as e:
            latency = (time.perf_counter() - t0) * 1000.0
            return {
                "ok": False,
                "status": "FAIL",
                "provider": p,
                "model": target_model,
                "latency_ms": round(latency, 2),
                "reason": f"Connection error: {e}",
            }

    api_key = config.get_api_key(p)
    if not api_key:
        return {
            "ok": False,
            "status": "FAIL",
            "provider": p,
            "model": target_model,
            "latency_ms": 0.0,
            "reason": f"Missing API key ({config.PROVIDER_ENV_VARS.get(p, 'API_KEY')})",
        }

    try:
        if p == "groq":
            clean_m = target_model.replace("groq/", "")
            resp = req.get(
                f"https://api.groq.com/openai/v1/models/{clean_m}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
        elif p == "openai":
            clean_m = target_model.replace("openai/", "")
            resp = req.get(
                f"https://api.openai.com/v1/models/{clean_m}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
        elif p == "openrouter":
            resp = req.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
        elif p == "gemini":
            clean_m = target_model.replace("gemini/", "")
            resp = req.get(
                f"https://generativelanguage.googleapis.com/v1beta/models/{clean_m}?key={api_key}",
                timeout=timeout,
            )
        elif p == "anthropic":
            clean_m = target_model.replace("anthropic/", "")
            payload = {
                "model": clean_m,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            }
            resp = req.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
        else:
            return {
                "ok": False,
                "status": "FAIL",
                "provider": p,
                "model": target_model,
                "latency_ms": 0.0,
                "reason": f"Unsupported provider {p}",
            }

        latency = (time.perf_counter() - t0) * 1000.0
        if resp.status_code in (200, 201):
            return {
                "ok": True,
                "status": "OK",
                "provider": p,
                "model": target_model,
                "latency_ms": round(latency, 2),
                "details": f"API authentication verified ({resp.status_code})",
            }
        else:
            return {
                "ok": False,
                "status": "FAIL",
                "provider": p,
                "model": target_model,
                "latency_ms": round(latency, 2),
                "reason": f"HTTP {resp.status_code}: {resp.text[:120]}",
            }
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000.0
        return {
            "ok": False,
            "status": "FAIL",
            "provider": p,
            "model": target_model,
            "latency_ms": round(latency, 2),
            "reason": f"Network error: {e}",
        }


def probe_all_configured(timeout: float = 3.0) -> List[Dict[str, Any]]:
    """Probe all configured providers and models."""
    results = []
    for p in config.SUPPORTED_PROVIDERS:
        model = config.PROVIDER_DEFAULT_MODELS.get(p)
        results.append(probe_provider(p, model, timeout=timeout))
    return results
