"""
Router — Deterministic query classification and hybrid execution engine.

Provides zero-overhead deterministic bypass and hybrid ground-truth precomputation:
1. Pure Deterministic: Bypasses LLM completely (0 tokens, 0ms LLM time) for:
   - Prime checks (is_prime)
   - Prime factorizations (prime_factors)
   - Euler totient calculations (euler_totient)
   - Direct Gematria Primus lookups
   - Direct Vigenère encryptions/decryptions
   - Direct page raw text inspection (with corpus directory traversal safeguards)
   - System telemetry status
2. Hybrid Mode: For conceptual / analytical queries referencing pages or math,
   precalculates deterministic ground truth and injects it into LLM prompt context
   to guarantee 0 arithmetic hallucinations.
3. Fallthrough: Routes natural language queries to standard RAG pipeline.

Features:
- Sub-0.1ms regex intent matching
- English and Italian multilingual pattern support
- Strict operand bounds (numbers <= 10^12, text <= 10,000 chars)
- Safe page 0 ("Welcome" page) handling
- Feature flag: TRITHEMIUS_ROUTER=off to disable routing
"""

import os
import sys
import re
import glob
from typing import Dict, Any, Optional, Union, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import (
        decode_runes, latin_to_rune, gematria_prime_sum, gematria_word_sums,
        rune_atbash, euler_totient, is_prime, prime_factors, INDEX_BY_RUNE
    )
    from ciphers.kasiski import (
        rune_vigenere_decode, rune_vigenere_encode, vigenere_decode, vigenere_encode,
        rune_index_of_coincidence, index_of_coincidence
    )
    from ciphers.al_kindi import is_plausible_english
    from ciphers.entropy import shannon_entropy, is_high_entropy
except ImportError:
    from agrippa import (
        decode_runes, latin_to_rune, gematria_prime_sum, gematria_word_sums,
        rune_atbash, euler_totient, is_prime, prime_factors, INDEX_BY_RUNE
    )
    from kasiski import (
        rune_vigenere_decode, rune_vigenere_encode, vigenere_decode, vigenere_encode,
        rune_index_of_coincidence, index_of_coincidence
    )
    from al_kindi import is_plausible_english
    from entropy import shannon_entropy, is_high_entropy

MAX_OPERAND = 10**12
_MAX_OPERAND_DIGITS = len(str(MAX_OPERAND))
MAX_TEXT_LEN = 10_000
ROUTER_INDICATOR = "[Deterministic Cryptanalytic Engine — 0 LLM tokens]"

PAGE_TITLES_MAP = {
    "loss of innocence": "56",
    "innocence": "56",
    "a warning": "57",
    "warning": "57",
    "an end": "73",
    "the end": "73",
    "welcome pilgrim": "0",
    "welcome": "0",
    "gematria primus table": "gematria_primus_table",
    "gematria table": "gematria_primus_table",
}

# Explanatory / conceptual triggers (Hybrid candidate)
RE_EXPLANATORY = re.compile(
    r"\b(?:why|perch[eé]|explain|spiega|meaning|significato|significance|significativ[ao]|"
    r"how|come|what\s+is\s+the\s+(?:meaning|significance|reason)|qual\s+[eè]\s+il\s+senso|"
    r"cosa\s+rappresenta|tell\s+me\s+about|racconta|interpreta|interpret)\b",
    re.IGNORECASE
)

# Page number detection
RE_PAGE = re.compile(r"(?:page|pagina|pg\.?)\s*([0-9]{1,2})", re.IGNORECASE)

# Atbash reflection patterns
RE_ATBASH = re.compile(
    r"^(?:(?:what\s+is\s+(?:the\s+)?)?atbash\s+(?:of\s+)?(.+)|atbash\s+(.+))$",
    re.IGNORECASE
)

# Transliteration patterns
RE_TRANSLITERATE = re.compile(
    r"^(?:(?:decode\s+runes|transliterate(?:\s+runes)?|runes?\s+to\s+latin)\s+(.+)|(?:latin\s+to\s+runes?)\s+(.+))$",
    re.IGNORECASE
)

# Shannon Entropy patterns
RE_ENTROPY = re.compile(
    r"^(?:(?:what\s+is\s+(?:the\s+)?)?entropy\s+(?:of\s+)?(.+)|shannon\s+entropy\s+(?:of\s+)?(.+))$",
    re.IGNORECASE
)

# Index of Coincidence patterns
RE_IOC = re.compile(
    r"^(?:(?:what\s+is\s+(?:the\s+)?)?ioc\s+(?:of\s+)?(.+)|index\s+of\s+coincidence\s+(?:of\s+)?(.+))$",
    re.IGNORECASE
)

# Pure deterministic patterns (English & Italian)
RE_STATUS = re.compile(r"^(?:/status|status|stato(?:\s+del\s+sistema)?|telemetr(?:y|ia))$", re.IGNORECASE)

RE_PRIME_EN = re.compile(
    r"^(?:is\s+([0-9]+)\s+prime\??|(?:check\s+)?prime(?:\s+check)?\s+([0-9]+)\??|prime\s+test\s+([0-9]+)\??)$",
    re.IGNORECASE
)
RE_PRIME_IT = re.compile(
    r"^(?:[eè]\s+([0-9]+)\s+primo\??|primalit[àa]\s+di\s+([0-9]+)\??|([0-9]+)\s+[eè]\s+(?:un\s+)?numero\s+primo\??)$",
    re.IGNORECASE
)

RE_FACTORS_EN = re.compile(
    r"^(?:(?:prime\s+)?factors\s+of\s+([0-9]+)|factor(?:ize)?\s+([0-9]+)|prime\s+factorization\s+of\s+([0-9]+))$",
    re.IGNORECASE
)
RE_FACTORS_IT = re.compile(
    r"^(?:fattori\s+(?:primi\s+)?di\s+([0-9]+)|scomponi\s+([0-9]+)|fattorizza\s+([0-9]+)|scomposizione\s+in\s+fattori\s+primi\s+di\s+([0-9]+))$",
    re.IGNORECASE
)

RE_TOTIENT_EN = re.compile(
    r"^(?:totient\s+of\s+([0-9]+)|phi\s+of\s+([0-9]+)|phi\s*\(\s*([0-9]+)\s*\)|euler(?:'s)?\s+totient\s+(?:of\s+)?([0-9]+))$",
    re.IGNORECASE
)
RE_TOTIENT_IT = re.compile(
    r"^(?:totiente\s+di\s+([0-9]+)|funzione\s+di\s+eulero\s+di\s+([0-9]+)|phi\s+di\s+([0-9]+))$",
    re.IGNORECASE
)

RE_GEMATRIA_EN = re.compile(
    r"^(?:gematria\s+(?:of|for)\s+(.+)|(?:prime|rune)\s+sum\s+of\s+(.+))$",
    re.IGNORECASE
)
RE_GEMATRIA_IT = re.compile(
    r"^(?:somma\s+gematrica\s+di\s+(.+)|gematria\s+di\s+(.+)|valore\s+gematrico\s+di\s+(.+))$",
    re.IGNORECASE
)

RE_VIGENERE_EN = re.compile(
    r"^(?:(decrypt|decode|encrypt|encode)\s+(.+)\s+with\s+key\s+(.+))$",
    re.IGNORECASE
)
RE_VIGENERE_IT = re.compile(
    r"^(?:(decifra|decodifica|cifra|codifica)\s+(.+)\s+con\s+chiave\s+(.+))$",
    re.IGNORECASE
)

RE_PAGE_RAW_EN = re.compile(
    r"^(?:(?:show|display|view|read|raw\s+text\s+of)\s+page\s+([0-9]{1,2})|page\s+([0-9]{1,2})\s+raw\s+text)$",
    re.IGNORECASE
)
RE_PAGE_RAW_IT = re.compile(
    r"^(?:(?:mostra|leggi|visualizza)\s+pagina\s+([0-9]{1,2})|testo\s+(?:della|di)\s+pagina\s+([0-9]{1,2}))$",
    re.IGNORECASE
)


def _extract_number(match: re.Match) -> Optional[int]:
    for g in match.groups():
        if g is not None and g.isdigit():
            normalized = g.lstrip("0") or "0"
            if len(normalized) > _MAX_OPERAND_DIGITS:
                return MAX_OPERAND + 1
            return int(normalized)
    return None


def get_page_corpus_path(page_num: Union[int, str], corpus_dir: str = CORPUS_DIR) -> Optional[str]:
    """Locate corpus document for a specific page with directory traversal safeguards."""
    s_page = str(page_num).strip().lower()
    norm_page = f"{int(s_page):02d}" if s_page.isdigit() else s_page

    pattern = os.path.join(corpus_dir, f"page_{norm_page}_*.*")
    matches = glob.glob(pattern)
    if not matches:
        pattern = os.path.join(corpus_dir, f"page_{norm_page}.*")
        matches = glob.glob(pattern)
    if not matches:
        pattern = os.path.join(corpus_dir, f"*{s_page}*.*")
        matches = glob.glob(pattern)

    matches.sort(key=lambda p: (
        0 if any(sig in os.path.basename(p) for sig in ("welcome", "loss_of_innocence", "a_warning", "an_end"))
        else (1 if not os.path.basename(p).endswith("_runes.md") else 2),
        os.path.basename(p)
    ))

    real_corpus = os.path.realpath(corpus_dir)
    for m in matches:
        real_m = os.path.realpath(m)
        if real_m.startswith(real_corpus + os.sep) and os.path.isfile(real_m):
            return real_m
    return None


def precompute_page_ground_truth(page_num: Union[int, str], corpus_dir: str = CORPUS_DIR) -> Optional[dict]:
    """Extract page text and calculate verified cryptographic and arithmetic properties."""
    fpath = get_page_corpus_path(page_num, corpus_dir=corpus_dir)
    if not fpath:
        return None

    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return None

    has_runes = any(c in INDEX_BY_RUNE for c in content)
    p_sum = gematria_prime_sum(content) if has_runes else 0
    tot = euler_totient(p_sum) if p_sum > 0 else 0
    p_prime = is_prime(p_sum) if p_sum > 0 else False
    factors = prime_factors(p_sum) if p_sum > 0 else []

    return {
        "page": str(page_num),
        "file": os.path.basename(fpath),
        "has_runes": has_runes,
        "prime_sum": p_sum,
        "totient": tot,
        "is_prime": p_prime,
        "prime_factors": factors,
    }


def classify_query(query: str, corpus_dir: str = CORPUS_DIR) -> Dict[str, Any]:
    """
    Classify incoming query into 'deterministic', 'hybrid', or 'rag'.
    Evaluates in <0.1ms with pre-compiled regex patterns.
    """
    if os.environ.get("TRITHEMIUS_ROUTER", "on").lower() == "off":
        return {"mode": "rag", "action": None, "params": {}, "ground_truth": None}

    q = query.strip()
    norm_q = q.rstrip("?.").strip()

    # 1. Check System Status
    if RE_STATUS.match(norm_q):
        return {"mode": "deterministic", "action": "status", "params": {}, "ground_truth": None}

    # 2. Check Explanatory Query for Hybrid Ground-Truth Injection
    if RE_EXPLANATORY.search(q):
        m_page = RE_PAGE.search(q)
        if m_page:
            p_num = m_page.group(1)
            gt = precompute_page_ground_truth(p_num, corpus_dir=corpus_dir)
            if gt:
                return {"mode": "hybrid", "action": "page_exploratory", "params": {"page": p_num}, "ground_truth": gt}
        else:
            q_lower = q.lower()
            for title, p_val in PAGE_TITLES_MAP.items():
                if title in q_lower:
                    gt = precompute_page_ground_truth(p_val, corpus_dir=corpus_dir)
                    if gt:
                        return {"mode": "hybrid", "action": "page_exploratory", "params": {"page": p_val}, "ground_truth": gt}
                    break

        # Check if query asks why/how about a specific number's primality or totient
        m_nums = []
        for raw_num in re.findall(r"\b([0-9]+)\b", q):
            normalized = raw_num.lstrip("0") or "0"
            if len(normalized) <= _MAX_OPERAND_DIGITS:
                val = int(normalized)
                if val <= MAX_OPERAND:
                    m_nums.append(val)
        if m_nums and any(w in q.lower() for w in ("prime", "primo", "totient", "phi", "factor", "fattor")):
            n = m_nums[0]
            gt = {
                "number": n,
                "is_prime": is_prime(n),
                "totient": euler_totient(n),
                "prime_factors": prime_factors(n),
            }
            return {"mode": "hybrid", "action": "math_exploratory", "params": {"number": n}, "ground_truth": gt}

        # Check if query contains runes to ground truth
        runes_in_q = "".join(c for c in q if c in INDEX_BY_RUNE)
        if len(runes_in_q) >= 2:
            p_sum = gematria_prime_sum(runes_in_q)
            gt = {
                "runes": runes_in_q,
                "decoded_latin": decode_runes(runes_in_q),
                "prime_sum": p_sum,
                "totient": euler_totient(p_sum),
                "is_prime": is_prime(p_sum),
                "prime_factors": prime_factors(p_sum),
            }
            return {"mode": "hybrid", "action": "runes_exploratory", "params": {"runes": runes_in_q}, "ground_truth": gt}

    # 3. Pure Prime Check
    m_p = RE_PRIME_EN.match(norm_q) or RE_PRIME_IT.match(norm_q)
    if m_p:
        n = _extract_number(m_p)
        if n is not None:
            return {"mode": "deterministic", "action": "prime_check", "params": {"number": n}, "ground_truth": None}

    # 4. Pure Factorization
    m_f = RE_FACTORS_EN.match(norm_q) or RE_FACTORS_IT.match(norm_q)
    if m_f:
        n = _extract_number(m_f)
        if n is not None:
            return {"mode": "deterministic", "action": "prime_factors", "params": {"number": n}, "ground_truth": None}

    # 5. Pure Euler Totient
    m_t = RE_TOTIENT_EN.match(norm_q) or RE_TOTIENT_IT.match(norm_q)
    if m_t:
        n = _extract_number(m_t)
        if n is not None:
            return {"mode": "deterministic", "action": "euler_totient", "params": {"number": n}, "ground_truth": None}

    # 6. Pure Page Raw Text
    m_pg = RE_PAGE_RAW_EN.match(norm_q) or RE_PAGE_RAW_IT.match(norm_q)
    if m_pg:
        n_str = next((g for g in m_pg.groups() if g is not None), None)
        if n_str is not None:
            return {"mode": "deterministic", "action": "page_text", "params": {"page": n_str}, "ground_truth": None}
    else:
        # Check canonical named pages for raw text (e.g. "show welcome", "read loss of innocence")
        q_l = norm_q.lower()
        if any(w in q_l for w in ("show", "display", "view", "read", "mostra", "leggi")):
            for title, p_val in PAGE_TITLES_MAP.items():
                if title in q_l:
                    return {"mode": "deterministic", "action": "page_text", "params": {"page": p_val}, "ground_truth": None}

    # 7. Pure Gematria Lookup
    m_g = RE_GEMATRIA_EN.match(norm_q) or RE_GEMATRIA_IT.match(norm_q)
    if m_g:
        target_text = next((g for g in m_g.groups() if g is not None), "").strip()
        if target_text and len(target_text) <= MAX_TEXT_LEN:
            return {"mode": "deterministic", "action": "gematria", "params": {"text": target_text}, "ground_truth": None}

    # 8. Pure Vigenere Cipher
    m_v = RE_VIGENERE_EN.match(norm_q) or RE_VIGENERE_IT.match(norm_q)
    if m_v:
        mode_str, text_str, key_str = m_v.groups()
        is_dec = mode_str.lower() in ("decrypt", "decode", "decifra", "decodifica")
        return {
            "mode": "deterministic",
            "action": "vigenere",
            "params": {
                "mode": "decode" if is_dec else "encode",
                "text": text_str.strip(),
                "key": key_str.strip(),
            },
            "ground_truth": None,
        }

    # 9. Pure Runic Atbash
    m_at = RE_ATBASH.match(norm_q)
    if m_at:
        target_text = next((g for g in m_at.groups() if g is not None), "").strip()
        if target_text and len(target_text) <= MAX_TEXT_LEN:
            return {"mode": "deterministic", "action": "atbash", "params": {"text": target_text}, "ground_truth": None}

    # 10. Pure Rune Transliteration
    m_tr = RE_TRANSLITERATE.match(norm_q)
    if m_tr:
        target_text = next((g for g in m_tr.groups() if g is not None), "").strip()
        if target_text and len(target_text) <= MAX_TEXT_LEN:
            return {"mode": "deterministic", "action": "transliterate", "params": {"text": target_text}, "ground_truth": None}

    # 11. Pure Shannon Entropy
    m_ent = RE_ENTROPY.match(norm_q)
    if m_ent:
        target_text = next((g for g in m_ent.groups() if g is not None), "").strip()
        if target_text and len(target_text) <= MAX_TEXT_LEN:
            return {"mode": "deterministic", "action": "entropy", "params": {"text": target_text}, "ground_truth": None}

    # 12. Pure Index of Coincidence
    m_ioc = RE_IOC.match(norm_q)
    if m_ioc:
        target_text = next((g for g in m_ioc.groups() if g is not None), "").strip()
        if target_text and len(target_text) <= MAX_TEXT_LEN:
            return {"mode": "deterministic", "action": "ioc", "params": {"text": target_text}, "ground_truth": None}

    # Fallthrough to standard RAG
    return {"mode": "rag", "action": None, "params": {}, "ground_truth": None}


def format_ground_truth_for_prompt(gt: dict) -> str:
    """Serialize precomputed ground truth into prompt injection block."""
    if not gt:
        return ""
    if "page" in gt:
        parts = [
            f"Page: {gt['page']}",
            f"Document: {gt.get('file', 'unknown')}",
            f"Futhorc Runes: {'Yes' if gt.get('has_runes') else 'No'}",
        ]
        if gt.get("has_runes"):
            parts.extend([
                f"Gematria Prime Sum: {gt.get('prime_sum')}",
                f"Euler Totient phi: {gt.get('totient')}",
                f"Is Prime: {gt.get('is_prime')}",
                f"Prime Factors: {gt.get('prime_factors')}",
            ])
        return "[Deterministic Pre-computation: " + " | ".join(parts) + "]"
    elif "runes" in gt:
        return (
            f"[Deterministic Pre-computation: Runes='{gt['runes']}' | "
            f"Latin='{gt.get('decoded_latin')}' | "
            f"Gematria Prime Sum={gt.get('prime_sum')} | "
            f"Euler Totient phi={gt.get('totient')} | "
            f"Is Prime={gt.get('is_prime')} | "
            f"Prime Factors={gt.get('prime_factors')}]"
        )
    elif "number" in gt:
        return (
            f"[Deterministic Pre-computation: N={gt['number']} | "
            f"Is Prime: {gt['is_prime']} | "
            f"Euler Totient phi: {gt['totient']} | "
            f"Prime Factors: {gt['prime_factors']}]"
        )
    return ""


def execute_deterministic(
    route: Dict[str, Any],
    corpus_dir: str = CORPUS_DIR,
    workstation: Any = None,
) -> str:
    """Execute pure deterministic computation and return fully formatted result."""
    action = route.get("action")
    params = route.get("params", {})

    if action == "status":
        if workstation and hasattr(workstation, "run_status"):
            workstation.run_status()
            return f"{ROUTER_INDICATOR}\nTelemetry displayed above."
        return f"{ROUTER_INDICATOR}\nTrithemius core online."

    elif action == "prime_check":
        n = params.get("number", 0)
        if n > MAX_OPERAND:
            return f"{ROUTER_INDICATOR}\nOperand exceeds deterministic calculation bound of 10^12."
        if n <= 0:
            return f"{ROUTER_INDICATOR}\nPrime check requires a positive integer."
        p = is_prime(n)
        if p:
            return f"{ROUTER_INDICATOR}\n{n} is a PRIME number (no divisors other than 1 and {n}). In Liber Primus cryptography, primes are sacred."
        else:
            factors = prime_factors(n)
            return f"{ROUTER_INDICATOR}\n{n} is a COMPOSITE number. Prime factors: {factors}."

    elif action == "prime_factors":
        n = params.get("number", 0)
        if n > MAX_OPERAND:
            return f"{ROUTER_INDICATOR}\nOperand exceeds deterministic calculation bound of 10^12."
        if n <= 0:
            return f"{ROUTER_INDICATOR}\nPrime factorization requires a positive integer."
        factors = prime_factors(n)
        p = is_prime(n)
        if p:
            return f"{ROUTER_INDICATOR}\n{n} is prime. Prime factorization: [{n}]."
        return f"{ROUTER_INDICATOR}\nPrime factors of {n}: {factors}."

    elif action == "euler_totient":
        n = params.get("number", 0)
        if n > MAX_OPERAND:
            return f"{ROUTER_INDICATOR}\nOperand exceeds deterministic calculation bound of 10^12."
        if n <= 0:
            return f"{ROUTER_INDICATOR}\nEuler totient calculation requires a positive integer."
        phi = euler_totient(n)
        p = is_prime(n)
        note = f" Since {n} is prime, phi({n}) = {n} - 1 = {phi}." if p else ""
        return f"{ROUTER_INDICATOR}\nEuler totient phi({n}) = {phi}.{note}"

    elif action == "gematria":
        text = params.get("text", "")
        if len(text) > MAX_TEXT_LEN:
            return f"{ROUTER_INDICATOR}\nInput length exceeds maximum bound of 10,000 characters."
        has_runes = any(c in INDEX_BY_RUNE for c in text)
        runes = text if has_runes else latin_to_rune(text)
        latin = decode_runes(runes)
        p_sum = gematria_prime_sum(runes)
        tot = euler_totient(p_sum)
        prime_status = is_prime(p_sum)
        factors = prime_factors(p_sum)
        atbash_runes = rune_atbash(runes)
        atbash_latin = decode_runes(atbash_runes)

        lines = [
            ROUTER_INDICATOR,
            f"Input Text:      {text}",
            f"Futhorc Runes:   {runes}",
            f"Decoded Latin:   {latin}",
            f"Prime Sum:       {p_sum} (Totient phi: {tot}, Is Prime: {prime_status})",
            f"Prime Factors:   {factors}",
            f"Atbash Runes:    {atbash_runes}",
            f"Atbash Latin:    {atbash_latin}",
        ]
        return "\n".join(lines)

    elif action == "vigenere":
        mode = params.get("mode", "decode")
        text = params.get("text", "")
        key = params.get("key", "")
        if len(text) > MAX_TEXT_LEN or len(key) > MAX_TEXT_LEN:
            return f"{ROUTER_INDICATOR}\nInput length exceeds maximum bound of 10,000 characters."

        has_runes = any(c in INDEX_BY_RUNE for c in text)
        is_dec = mode == "decode"
        if has_runes:
            res_text = rune_vigenere_decode(text, key) if is_dec else rune_vigenere_encode(text, key)
            latin_res = decode_runes(res_text)
            ioc = rune_index_of_coincidence(res_text)
            passed, metrics = is_plausible_english(latin_res)
            alphabet = "Modulo-29 (Futhorc Runes)"
        else:
            res_text = vigenere_decode(text, key) if is_dec else vigenere_encode(text, key)
            latin_res = res_text
            ioc = index_of_coincidence(res_text)
            passed, metrics = is_plausible_english(latin_res)
            alphabet = "Modulo-26 (Classical Latin A-Z)"

        lines = [
            ROUTER_INDICATOR,
            f"Operation:       {mode.upper()} via {alphabet}",
            f"Key:             {key}",
            f"Result:          {res_text}",
        ]
        if res_text != latin_res:
            lines.append(f"Decoded Latin:   {latin_res}")
        lines.append(f"Index of Coinc:  {round(ioc, 4)}")
        lines.append(f"Gatekeeper:      [{metrics.get('verdict', 'UNKNOWN')}]")
        return "\n".join(lines)

    elif action == "page_text":
        page_val = params.get("page")
        if page_val is None:
            return f"{ROUTER_INDICATOR}\nPage number parameter is required."
        fpath = get_page_corpus_path(page_val, corpus_dir=corpus_dir)
        if not fpath:
            return f"{ROUTER_INDICATOR}\nNo corpus document found for page {page_val}."

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            fname = os.path.basename(fpath)
            return f"{ROUTER_INDICATOR}\n[Document: {fname}]\n\n{content.strip()}"
        except Exception as e:
            return f"{ROUTER_INDICATOR}\nError reading page document: {e}"

    elif action == "atbash":
        text = params.get("text", "")
        has_runes = any(c in INDEX_BY_RUNE for c in text)
        runes = text if has_runes else latin_to_rune(text)
        latin = decode_runes(runes)
        atbash_runes = rune_atbash(runes)
        atbash_latin = decode_runes(atbash_runes)
        lines = [
            ROUTER_INDICATOR,
            f"Input Text:      {text}",
            f"Futhorc Runes:   {runes}",
            f"Decoded Latin:   {latin}",
            f"Atbash Runes:    {atbash_runes}",
            f"Atbash Latin:    {atbash_latin}",
        ]
        return "\n".join(lines)

    elif action == "transliterate":
        text = params.get("text", "")
        has_runes = any(c in INDEX_BY_RUNE for c in text)
        if has_runes:
            res_latin = decode_runes(text)
            lines = [
                ROUTER_INDICATOR,
                f"Futhorc Runes:   {text}",
                f"Decoded Latin:   {res_latin}",
            ]
        else:
            res_runes = latin_to_rune(text)
            lines = [
                ROUTER_INDICATOR,
                f"Latin Text:      {text}",
                f"Futhorc Runes:   {res_runes}",
            ]
        return "\n".join(lines)

    elif action == "entropy":
        text = params.get("text", "")
        ent = shannon_entropy(text)
        high = is_high_entropy(text)
        lines = [
            ROUTER_INDICATOR,
            f"Input:           {text[:80]}{'...' if len(text) > 80 else ''}",
            f"Shannon Entropy: {ent:.4f} bits/char",
            f"Classification:  [{'CIPHERTEXT / COMPRESSED' if high else 'STRUCTURED / NATURAL LANGUAGE'}]",
        ]
        return "\n".join(lines)

    elif action == "ioc":
        text = params.get("text", "")
        has_runes = any(c in INDEX_BY_RUNE for c in text)
        ioc = rune_index_of_coincidence(text) if has_runes else index_of_coincidence(text)
        alphabet = "29-Rune Futhorc" if has_runes else "26-Letter English"
        lines = [
            ROUTER_INDICATOR,
            f"Input:           {text[:80]}{'...' if len(text) > 80 else ''}",
            f"Alphabet:        {alphabet}",
            f"Index of Coinc:  {ioc:.4f} (English baseline: ~0.0667, Random: ~0.0385)",
        ]
        return "\n".join(lines)

    return f"{ROUTER_INDICATOR}\nUnknown deterministic action."
