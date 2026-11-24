"""
Agrippa — Gematria Primus & Sacred Arithmetic module.
Named for Heinrich Cornelius Agrippa, Renaissance occultist steeped in
numerology and gematria.

The official 29-rune Futhorc alphabet used throughout Liber Primus,
mapped to indices (0-28) and the first 29 prime numbers (2..109).

Usage:
    from agrippa import (
        decode_runes, latin_to_rune, rune_to_prime, gematria_prime_sum,
        gematria_word_sums, rune_atbash, euler_totient, is_prime, prime_factors
    )
"""

import math
import re
import functools
from typing import List, Tuple, Optional, Dict

# The official 29 runes of Cicada 3301 Gematria Primus
# (Rune, Latin, Index 0-28, Prime Value)
RUNE_TABLE = [
    ("ᚠ", "F", 0, 2),
    ("ᚢ", "U", 1, 3),        # also V
    ("ᚦ", "TH", 2, 5),
    ("ᚩ", "O", 3, 7),
    ("ᚱ", "R", 4, 11),
    ("ᚳ", "C", 5, 13),       # also K
    ("ᚷ", "G", 6, 17),
    ("ᚹ", "W", 7, 19),
    ("ᚻ", "H", 8, 23),
    ("ᚾ", "N", 9, 29),
    ("ᛁ", "I", 10, 31),
    ("ᛄ", "J", 11, 37),
    ("ᛇ", "EO", 12, 41),
    ("ᛈ", "P", 13, 43),
    ("ᛉ", "X", 14, 47),
    ("ᛋ", "S", 15, 53),      # also Z
    ("ᛏ", "T", 16, 59),
    ("ᛒ", "B", 17, 61),
    ("ᛖ", "E", 18, 67),
    ("ᛗ", "M", 19, 71),
    ("ᛚ", "L", 20, 73),
    ("ᛝ", "ING", 21, 79),
    ("ᛟ", "OE", 22, 83),
    ("ᛞ", "D", 23, 89),
    ("ᚪ", "A", 24, 97),
    ("ᚫ", "AE", 25, 101),
    ("ᚣ", "Y", 26, 103),
    ("ᛡ", "IA", 27, 107),    # also IO
    ("ᛠ", "EA", 28, 109),
]

# Quick lookup tables
RUNE_BY_INDEX = [r[0] for r in RUNE_TABLE]
INDEX_BY_RUNE = {r[0]: r[2] for r in RUNE_TABLE}
PRIME_BY_RUNE = {r[0]: r[3] for r in RUNE_TABLE}
LATIN_BY_RUNE = {r[0]: r[1] for r in RUNE_TABLE}

# Punctuation / separators in Liber Primus
PUNCTUATION_MAP = {
    "᛫": " ",   # Single dot: word divider -> space
    "᛬": "\n",  # Double dot: clause/line divider -> newline
    "᛭": "\n\n",# Cross dot: section divider
}

# Mapping Latin back to Rune (ordered by longest prefix first)
_LATIN_TO_RUNE_LIST = [
    ("ING", "ᛝ"),
    ("TH", "ᚦ"),
    ("EO", "ᛇ"),
    ("OE", "ᛟ"),
    ("AE", "ᚫ"),
    ("IA", "ᛡ"),
    ("IO", "ᛡ"),
    ("EA", "ᛠ"),
    ("F", "ᚠ"),
    ("U", "ᚢ"),
    ("V", "ᚢ"),
    ("O", "ᚩ"),
    ("R", "ᚱ"),
    ("C", "ᚳ"),
    ("K", "ᚳ"),
    ("G", "ᚷ"),
    ("W", "ᚹ"),
    ("H", "ᚻ"),
    ("N", "ᚾ"),
    ("I", "ᛁ"),
    ("J", "ᛄ"),
    ("P", "ᛈ"),
    ("X", "ᛉ"),
    ("S", "ᛋ"),
    ("Z", "ᛋ"),
    ("T", "ᛏ"),
    ("B", "ᛒ"),
    ("E", "ᛖ"),
    ("M", "ᛗ"),
    ("L", "ᛚ"),
    ("D", "ᛞ"),
    ("A", "ᚪ"),
    ("Y", "ᚣ"),
    (" ", "᛫"),
]

_LATIN_TO_RUNE_MAP = dict(_LATIN_TO_RUNE_LIST)
_LATIN_TO_RUNE_PATTERN = re.compile(
    "|".join(re.escape(k) for k, _ in _LATIN_TO_RUNE_LIST)
)
_RUNE_DECODE_MAP = {**LATIN_BY_RUNE, **PUNCTUATION_MAP}


def rune_to_index(rune: str) -> Optional[int]:
    """Return index (0-28) of a Futhorc rune."""
    return INDEX_BY_RUNE.get(rune)


def index_to_rune(index: int) -> str:
    """Return the rune corresponding to index (modulo 29)."""
    return RUNE_BY_INDEX[index % 29]


def rune_to_prime(rune: str) -> Optional[int]:
    """Return Gematria Primus prime value for a rune."""
    return PRIME_BY_RUNE.get(rune)


def rune_to_latin(rune: str) -> str:
    """Translate single rune or separator to Latin."""
    if rune in LATIN_BY_RUNE:
        return LATIN_BY_RUNE[rune]
    if rune in PUNCTUATION_MAP:
        return PUNCTUATION_MAP[rune]
    return rune


def decode_runes(rune_string: str, preserve_punctuation: bool = True) -> str:
    """Convert a string of Gematria Primus runes into Latin letters."""
    if not rune_string:
        return ""
    if preserve_punctuation:
        return "".join(_RUNE_DECODE_MAP.get(r, r) for r in rune_string)
    out = []
    for r in rune_string:
        if r in LATIN_BY_RUNE:
            out.append(LATIN_BY_RUNE[r])
        elif r in PUNCTUATION_MAP:
            out.append(" ")
        else:
            out.append(r)
    return "".join(out)


def latin_to_rune(text: str) -> str:
    """Convert Latin text to Gematria Primus runes."""
    if not text:
        return ""
    return _LATIN_TO_RUNE_PATTERN.sub(lambda m: _LATIN_TO_RUNE_MAP.get(m.group(0), m.group(0)), text.upper())


def gematria_prime_sum(text: str) -> int:
    """
    Calculate the sum of Gematria Primus prime values.
    Can accept either runes or Latin characters.
    """
    if not text:
        return 0
    has_runes = any(c in INDEX_BY_RUNE for c in text)
    rune_text = text if has_runes else latin_to_rune(text)
    return sum(PRIME_BY_RUNE[c] for c in rune_text if c in PRIME_BY_RUNE)


def gematria_word_sums(text: str) -> List[Tuple[str, int]]:
    """
    Calculate Gematria sum for each word in text.
    Handles runes separated by '᛫' or whitespace.
    """
    # Replace runic word separators with standard spaces
    normalized = text.replace("᛫", " ").replace("᛬", " ").replace("᛭", " ")
    words = normalized.split()
    return [(w, gematria_prime_sum(w)) for w in words if w.strip()]


def rune_atbash(text: str, preserve_separators: bool = True) -> str:
    """
    Apply Atbash cipher on 29 runes: index -> (28 - index) % 29.
    Transliterates Latin input to runes if Latin alphabetic characters are present.
    Preserves separators and whitespace if preserve_separators is True.
    """
    has_runes = any(c in INDEX_BY_RUNE for c in text)
    has_latin = any(c.isalpha() for c in text)
    input_runes = text if (has_runes or not has_latin) else latin_to_rune(text)
    result = []
    for c in input_runes:
        if c in INDEX_BY_RUNE:
            idx = INDEX_BY_RUNE[c]
            new_idx = (28 - idx) % 29
            result.append(index_to_rune(new_idx))
        elif preserve_separators:
            result.append(c)
    return "".join(result)


def rune_atbash_shift(text: str, shift: int = 3, preserve_separators: bool = True) -> str:
    """
    Apply Atbash in F_29 followed by a Caesar shift:
        decimal[i] = ((28 - decimal[i]) + shift) % 29
    (Canonical method for Liber Primus Koan 1 with shift = 3).
    Transliterates Latin input to runes if Latin alphabetic characters are present.

    Note: This transformation is self-inverse over F_29:
        ((28 - (((28 - x) + s) % 29)) + s) % 29 == x % 29.
    """
    has_runes = any(c in INDEX_BY_RUNE for c in text)
    has_latin = any(c.isalpha() for c in text)
    input_runes = text if (has_runes or not has_latin) else latin_to_rune(text)
    result = []
    for c in input_runes:
        if c in INDEX_BY_RUNE:
            idx = INDEX_BY_RUNE[c]
            new_idx = ((28 - idx) + shift) % 29
            result.append(index_to_rune(new_idx))
        elif preserve_separators:
            result.append(c)
    return "".join(result)


def direct_translation(text: str, preserve_punctuation: bool = True) -> str:
    """
    Direct Gematria Primus identity cipher for unencrypted solved pages.
    Preserves runes and punctuation unaltered for direct transliteration:
    - Page 05 ('Some wisdom')
    - Pages 10-13 ('The loss of divinity')
    - Page 16 ('An instruction')
    - Page 57/72 ('Parable')
    """
    return text


# --- Sacred Arithmetic / Number Theory Tools for Cicada ---

@functools.lru_cache(maxsize=32768)
def is_prime(n: int) -> bool:
    """Check if n is prime."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    limit = (math.isqrt(n) if hasattr(math, "isqrt") else int(math.sqrt(n))) + 1
    for i in range(5, limit, 6):
        if n % i == 0 or n % (i + 2) == 0:
            return False
    return True


@functools.lru_cache(maxsize=8192)
def prime_factors(n: int) -> List[int]:
    """Return prime factorization of n using accelerated odd-step trial division."""
    factors = []
    temp = abs(n)
    while temp % 2 == 0:
        factors.append(2)
        temp //= 2
    d = 3
    while d * d <= temp:
        while temp % d == 0:
            factors.append(d)
            temp //= d
        d += 2
    if temp > 1:
        factors.append(temp)
    return factors


@functools.lru_cache(maxsize=8192)
def euler_totient(n: int) -> int:
    """
    Compute Euler's totient phi(n): count of numbers <= n coprime to n.
    Widely referenced in Liber Primus (e.g. 'A WARNING' and totient key streams).
    Uses accelerated odd-step prime factor extraction.
    """
    if n <= 0:
        return 0
    result = n
    temp = n
    if temp % 2 == 0:
        while temp % 2 == 0:
            temp //= 2
        result -= result // 2
    p = 3
    while p * p <= temp:
        if temp % p == 0:
            while temp % p == 0:
                temp //= p
            result -= result // p
        p += 2
    if temp > 1:
        result -= result // temp
    return result


if __name__ == "__main__":
    sample = "ᚠᚢᚦᚩᚱᚳ᛫ᚹᛖᛚᚳᚩᛗᛖ"
    print("Sample:", sample)
    print("Decoded:", decode_runes(sample))
    print("Prime Sum:", gematria_prime_sum(sample))
    print("Word Sums:", gematria_word_sums(sample))
    print("Atbash:", rune_atbash(sample))
    print("Decoded Atbash:", decode_runes(rune_atbash(sample)))
    print("Totient(3301):", euler_totient(3301), "Prime?", is_prime(3301))
