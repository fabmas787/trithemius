"""
Config — legacy shim providing a read/write view onto workstation.settings.current().
Preserves 100% backward compatibility for all existing scripts and tests.
"""

import os
import sys
import types
from typing import Optional, Dict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(BASE_DIR, ".env")


def _load_env_file():
    """Load key-value pairs from .env if present and not already in os.environ."""
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


_load_env_file()

SUPPORTED_PROVIDERS = ("ollama", "groq", "openai", "gemini", "anthropic", "openrouter")

MODELS = {
    "lfm": "hf.co/LiquidAI/LFM2.5-8B-A1B-GGUF:Q6_K",
    "lfm-fast": "hf.co/LiquidAI/LFM2.5-8B-A1B-GGUF:Q5_K_M",
    "spark": "SparkLLM/Spark-X2.5-4B",
    "moe": "deepseek-coder-v2:16b",
    "moe-fast": "olmoe:1b-7b",
    "tiny": "qwen2.5:0.5b",
    "light": "llama3.2:1b",
    "fast": "qwen2.5:1.5b",
    "groq": "llama-3.1-8b-instant",
    "groq-large": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
    "openai-large": "gpt-4o",
    "gemini": "gemini-1.5-flash",
    "gemini-pro": "gemini-1.5-pro",
    "claude": "claude-3-5-haiku-20241022",
    "claude-large": "claude-3-5-sonnet-20241022",
    "openrouter": "meta-llama/llama-3.1-8b-instruct:free",
}

PROVIDER_DEFAULT_MODELS = {
    "ollama": "SparkLLM/Spark-X2.5-4B",
    "groq": "llama-3.1-8b-instant",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-1.5-flash",
    "anthropic": "claude-3-5-haiku-20241022",
    "openrouter": "meta-llama/llama-3.1-8b-instruct:free",
}

PROVIDER_ENV_VARS = {
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "ollama": "OLLAMA_API_KEY",
}


def get_model(choice: str = None, provider: str = None) -> str:
    """Return model name by key or fall back to default for provider."""
    from workstation.settings import current
    s = current()
    if not choice:
        p = provider or s.provider
        return PROVIDER_DEFAULT_MODELS.get(p, s.active_model)
    return MODELS.get(choice.lower(), choice)


def get_api_key(provider: str) -> Optional[str]:
    """Retrieve API key for given provider from environment or .env."""
    env_var = PROVIDER_ENV_VARS.get(provider.lower())
    if not env_var:
        return None
    val = os.environ.get(env_var)
    if val:
        return val
    _load_env_file()
    return os.environ.get(env_var)


def set_api_key(provider: str, key: str) -> bool:
    """Store API key for provider into environment and persist in .env file."""
    env_var = PROVIDER_ENV_VARS.get(provider.lower())
    if not env_var:
        return False

    os.environ[env_var] = key.strip()

    lines = []
    found = False
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            lines = []

    new_lines = []
    for line in lines:
        if line.strip().startswith(f"{env_var}="):
            new_lines.append(f"{env_var}={key.strip()}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines.append("\n")
        new_lines.append(f"{env_var}={key.strip()}\n")

    try:
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        os.chmod(CREDENTIALS_FILE, 0o600)
        return True
    except Exception:
        return False


def get_all_keys_status() -> Dict[str, bool]:
    """Return dict of provider -> boolean indicating if key is configured."""
    return {
        p: bool(get_api_key(p))
        for p in SUPPORTED_PROVIDERS
        if p != "ollama"
    }


def clear_api_key(provider: str) -> bool:
    """Remove API key for provider from environment and .env file."""
    env_var = PROVIDER_ENV_VARS.get(provider.lower())
    if not env_var:
        return False

    if env_var in os.environ:
        del os.environ[env_var]

    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if not l.strip().startswith(f"{env_var}=")]
            with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            os.chmod(CREDENTIALS_FILE, 0o600)
            return True
        except Exception:
            return False
    return True


class _LegacyConfig(types.ModuleType):
    """Dynamic module proxy redirecting legacy config attributes to workstation.settings.current()."""

    @property
    def ACTIVE_PROVIDER(self) -> str:
        from workstation.settings import current
        return current().provider

    @ACTIVE_PROVIDER.setter
    def ACTIVE_PROVIDER(self, val: str):
        from workstation.settings import current
        current().provider = val.lower() if isinstance(val, str) else val

    @property
    def ACTIVE_MODEL_KEY(self) -> str:
        from workstation.settings import current
        return current().model_key

    @ACTIVE_MODEL_KEY.setter
    def ACTIVE_MODEL_KEY(self, val: str):
        from workstation.settings import current
        current().model_key = val

    @property
    def MODEL_NAME(self) -> str:
        from workstation.settings import current
        return current().active_model

    @MODEL_NAME.setter
    def MODEL_NAME(self, val: str):
        from workstation.settings import current
        current().active_model = val

    @property
    def OLLAMA_HOST(self) -> str:
        from workstation.settings import current
        return current().ollama_host

    @OLLAMA_HOST.setter
    def OLLAMA_HOST(self, val: str):
        from workstation.settings import current
        current().ollama_host = val

    @property
    def OLLAMA_API_KEY(self) -> str:
        from workstation.settings import current
        return current().ollama_api_key

    @OLLAMA_API_KEY.setter
    def OLLAMA_API_KEY(self, val: str):
        from workstation.settings import current
        current().ollama_api_key = val

    @property
    def LOW_SPEC_MODE(self) -> bool:
        from workstation.settings import current
        return current().low_spec

    @LOW_SPEC_MODE.setter
    def LOW_SPEC_MODE(self, val: bool):
        from workstation.settings import current
        current().low_spec = bool(val)

    @property
    def DEFAULT_NUM_CTX(self) -> int:
        from workstation.settings import current
        return current().default_num_ctx

    @DEFAULT_NUM_CTX.setter
    def DEFAULT_NUM_CTX(self, val: int):
        from workstation.settings import current
        current().default_num_ctx = int(val)

    @property
    def DEFAULT_NUM_PREDICT(self) -> int:
        from workstation.settings import current
        return current().default_num_predict

    @DEFAULT_NUM_PREDICT.setter
    def DEFAULT_NUM_PREDICT(self, val: int):
        from workstation.settings import current
        current().default_num_predict = int(val)

    @property
    def CREWAI_MODEL_NAME(self) -> str:
        from workstation.settings import current
        s = current()
        if s.provider == "ollama":
            return f"ollama/{s.active_model}"
        return f"{s.provider}/{s.active_model}"


sys.modules[__name__].__class__ = _LegacyConfig
