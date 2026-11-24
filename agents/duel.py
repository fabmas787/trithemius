"""
Duel — adversarial verification module for decryption candidates.

Prevents false positives and motivated pattern-matching by pitting opposing
agents against each other on the same local model:
  - Prover: argues the candidate IS genuine (syntactic structure, themes, Gematria).
  - Skeptic: attacks the candidate (cherry-picked fragments, statistical anomalies, noise).
  - Judge: weighs both sides alongside quantitative metrics (Al-Kindi) to render a verdict.

Usage:
    from duel import adjudicate

    verdict = adjudicate(
        ciphertext="...",
        candidate_plaintext="...",
        method_used="Rune Vigenere, key=DIVINITY"
    )
"""

import os
import sys
import ollama

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ciphers"))
from config import MODEL_NAME, get_model
from al_kindi import is_plausible_english

CHAT_MODEL = MODEL_NAME

PROVER_SYSTEM = """You are the Prover in an adversarial cryptanalysis review of Cicada 3301 / Liber Primus. \
Your job is to argue, as rigorously and factually as possible, that the proposed candidate plaintext \
IS a genuine decryption. Highlight coherent English syntax, semantic alignment with Liber Primus \
philosophy, and mathematical plausibility. Do not overstate weak evidence."""

SKEPTIC_SYSTEM = """You are the Skeptic in an adversarial cryptanalysis review of Cicada 3301 / Liber Primus. \
Your job is to challenge the proposed decryption. Look for: coincidental pattern-matching, \
cherry-picked words surrounded by anagrammed noise, unaddressed ciphertext characters, \
and forced interpretations. Be fiercely adversarial — your duty is to prevent false positives."""

JUDGE_SYSTEM = """You are an impartial cryptographic Judge. Review the case, statistical metrics, \
and arguments from both the Prover and Skeptic. Render an objective verdict:
- ACCEPT: Overwhelming mathematical and linguistic evidence of genuine decryption.
- REJECT: Probable false positive, coincidental pattern, or anagrammed noise.
- INCONCLUSIVE: Intriguing signals but insufficient proof to establish truth.
Explain your reasoning in 2-3 precise sentences."""


def _ask_llm(system_prompt: str, user_prompt: str, model_name: str = None) -> str:
    target_model = model_name or CHAT_MODEL
    try:
        response = ollama.chat(
            model=target_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response["message"]["content"]
    except Exception as e:
        return f"[LLM query failed: {e}]"


def adjudicate(ciphertext: str, candidate_plaintext: str, method_used: str, model_name: str = None) -> dict:
    """Run adversarial adjudication with quantitative statistical metrics."""
    passed, stats = is_plausible_english(candidate_plaintext)

    case = f"""Ciphertext:
{ciphertext}

Method Used:
{method_used}

Proposed Candidate Plaintext:
{candidate_plaintext}

Quantitative Metrics (Al-Kindi):
- Statistical Verdict: {stats['verdict']}
- Chi-Squared (English goodness of fit): {stats['chi_squared']}
- N-gram Plausibility Score: {stats['ngram_score']}
- Recognizable Word Ratio: {stats['word_ratio']}"""

    prover_arg = _ask_llm(PROVER_SYSTEM, case, model_name=model_name)
    skeptic_arg = _ask_llm(SKEPTIC_SYSTEM, case, model_name=model_name)

    judge_prompt = f"""{case}

--- PROVER ARGUMENT ---
{prover_arg}

--- SKEPTIC ARGUMENT ---
{skeptic_arg}

Based on the quantitative metrics and arguments above, provide your final verdict (ACCEPT, REJECT, or INCONCLUSIVE) and justification:"""

    judge_verdict = _ask_llm(JUDGE_SYSTEM, judge_prompt, model_name=model_name)

    verdict_label = "INCONCLUSIVE"
    upper = judge_verdict.upper()
    if "ACCEPT" in upper and "REJECT" not in upper:
        verdict_label = "ACCEPT"
    elif "REJECT" in upper:
        verdict_label = "REJECT"

    return {
        "verdict": verdict_label,
        "statistical_metrics": stats,
        "judge_reasoning": judge_verdict,
        "prover_argument": prover_arg,
        "skeptic_argument": skeptic_arg,
    }


if __name__ == "__main__":
    result = adjudicate(
        ciphertext="ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ",
        candidate_plaintext="WELCOME PILGRIMS",
        method_used="Direct Futhorc Transliteration",
    )
    print("VERDICT:", result["verdict"])
    print("Metrics:", result["statistical_metrics"])
    print("\nJudge:", result["judge_reasoning"])
