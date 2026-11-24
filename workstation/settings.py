"""
Workstation Settings — Single source of truth for runtime configuration.
Zero external dependencies (stdlib only).
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict

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


@dataclass
class Settings:
    """Runtime workstation settings and active hardware/inference profiles."""
    provider: str = "ollama"
    model_key: str = "spark"
    active_model: str = "SparkLLM/Spark-X2.5-4B"
    think: bool = False
    boost: bool = False
    low_spec: bool = False
    ollama_host: str = "http://localhost:11434"
    ollama_api_key: str = ""
    default_num_ctx: int = 8192
    default_num_predict: int = 2048
    api_key: Optional[str] = None

    def __post_init__(self):
        if self.provider not in SUPPORTED_PROVIDERS:
            self.provider = "ollama"
        if not self.active_model:
            self.active_model = PROVIDER_DEFAULT_MODELS.get(self.provider, MODELS.get("spark", "SparkLLM/Spark-X2.5-4B"))

    @classmethod
    def from_env_and_args(
        cls,
        provider: Optional[str] = None,
        model_key: Optional[str] = None,
        think: Optional[bool] = None,
        boost: Optional[bool] = None,
        low_spec: Optional[bool] = None,
        ollama_host: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> "Settings":
        env_prov = os.environ.get("TRITHEMIUS_PROVIDER", "ollama").lower()
        prov = (provider or env_prov).lower()
        if prov not in SUPPORTED_PROVIDERS:
            prov = "ollama"

        env_low_spec = os.environ.get("TRITHEMIUS_LOW_SPEC", "false").lower() in ("true", "1", "yes")
        is_low_spec = low_spec if low_spec is not None else env_low_spec

        env_model_key = os.environ.get("TRITHEMIUS_MODEL", "spark")
        m_key = model_key or env_model_key
        act_model = MODELS.get(m_key.lower(), PROVIDER_DEFAULT_MODELS.get(prov, MODELS.get("spark", "SparkLLM/Spark-X2.5-4B")))

        host = (ollama_host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).strip()
        host_key = os.environ.get("OLLAMA_API_KEY", "")

        ctx = int(os.environ.get("TRITHEMIUS_NUM_CTX", 2048 if is_low_spec else 8192))
        predict = int(os.environ.get("TRITHEMIUS_NUM_PREDICT", 2048))

        is_think = bool(think) if think is not None else False
        if boost is not None:
            is_boost = bool(boost)
        else:
            is_boost = os.environ.get("TRITHEMIUS_BOOST", "off").lower() in ("on", "true", "1")

        return cls(
            provider=prov,
            model_key=m_key,
            active_model=act_model,
            think=is_think,
            boost=is_boost,
            low_spec=is_low_spec,
            ollama_host=host,
            ollama_api_key=host_key,
            default_num_ctx=ctx,
            default_num_predict=predict,
            api_key=api_key,
        )


_CURRENT_SETTINGS: Optional[Settings] = None


def current() -> Settings:
    """Retrieve the global active Settings singleton."""
    global _CURRENT_SETTINGS
    if _CURRENT_SETTINGS is None:
        _CURRENT_SETTINGS = Settings.from_env_and_args()
    return _CURRENT_SETTINGS


def set_current(s: Settings):
    """Set the active Settings singleton."""
    global _CURRENT_SETTINGS
    _CURRENT_SETTINGS = s
