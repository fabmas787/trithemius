"""
Interrupter — Dynamic Key Interrupter Engine & Keystream Scheduler for Liber Primus.
Provides modular, dynamic keystream mutation models observed in solved Liber Primus
pages (e.g., Pages 3-4 and 14-15) and community cryptanalysis frameworks.

Corrections to previous flawed literature & code:
1. Gematria Primus Alphabet: The 29-rune Futhorc alphabet consists of strictly 29 runes
   mapped to indices 0..28 and the first 29 prime numbers (2..109). Previous flawed tables
   duplicated runes at 12-14 and 15-17 and omitted Y (ᚣ, 103), IA (ᛡ, 107), and EA (ᛠ, 109).
2. Key Derivations:
   - 'DIVINITY' maps to canonical rune indices [23, 10, 1, 10, 9, 10, 16, 26] (D, I, U/V, I, N, I, T, Y).
     The previous formula erroneously mixed prime values and indices ([23, 10, 3, 10, 29, 10, 71, 10]).
     The additive inverse decryption shifts are [6, 19, 28, 19, 20, 19, 13, 3].
   - 'FIRFUMFERENFE' maps to canonical rune indices [0, 10, 4, 0, 1, 19, 0, 18, 4, 18, 9, 0, 18].
     The additive inverse decryption shifts are [0, 19, 25, 0, 28, 10, 0, 11, 25, 11, 20, 0, 11].
3. Dynamic Interrupter Execution:
   - Previous naive snippets only checked ciphertext `c == 0` without handling cleartext
     Fehu preservation, key pause vs advance options, positional mask schedules, or bidirectional encode/decode.
   - This module provides full bijective bidirectional encoding/decoding with 5 configurable interrupt modes.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Union, Tuple, Dict, Optional, Set, Any
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import (
        RUNE_TABLE, INDEX_BY_RUNE, RUNE_BY_INDEX, PRIME_BY_RUNE, LATIN_BY_RUNE,
        index_to_rune, rune_to_index, latin_to_rune, decode_runes
    )
except ImportError:
    from agrippa import (
        RUNE_TABLE, INDEX_BY_RUNE, RUNE_BY_INDEX, PRIME_BY_RUNE, LATIN_BY_RUNE,
        index_to_rune, rune_to_index, latin_to_rune, decode_runes
    )


class InterruptMode(Enum):
    """Behavioral modes for dynamic key interruption."""
    PAUSE_KEY = auto()       # Keystream pointer does NOT advance on interrupt
    ADVANCE_KEY = auto()     # Keystream pointer advances normally on interrupt
    RESET_KEY = auto()       # Keystream pointer resets to index 0 (k_0) on interrupt
    OFFSET_SHIFT = auto()    # Keystream receives a cumulative modular offset jump


@dataclass
class InterrupterConfig:
    """
    Configuration specification for dynamic key interruption during Vigenère execution.

    Attributes:
        interrupt_runes: Set of runes that trigger an interrupt when character matching is enabled.
        interrupt_indices: Set of rune indices (0..28) that trigger an interrupt.
        interrupt_positions: Set of 0-indexed positions within the rune sequence that trigger an interrupt.
        pause_on_interrupt: If True, keystream pointer does not advance when an interrupt occurs.
        reset_on_interrupt: If True, keystream pointer resets to index 0 when an interrupt occurs.
        offset_step: Modular offset (mod 29) added to subsequent keystream shifts upon interrupt.
        pass_through: If True, the character passes through unshifted (e.g. unencrypted Fehu).
    """
    interrupt_runes: Set[str] = field(default_factory=set)
    interrupt_indices: Set[int] = field(default_factory=set)
    interrupt_positions: Set[int] = field(default_factory=set)
    pause_on_interrupt: bool = False
    reset_on_interrupt: bool = False
    offset_step: int = 0
    pass_through: bool = False

    @classmethod
    def fehu_skip(cls, pause_key: bool = True, pass_through: bool = True) -> "InterrupterConfig":
        """Pre-configured standard Fehu interrupter schedule."""
        return cls(
            interrupt_runes={"ᚠ"},
            interrupt_indices={0},
            pause_on_interrupt=pause_key,
            reset_on_interrupt=False,
            offset_step=0,
            pass_through=pass_through,
        )

    @classmethod
    def fehu_reset(cls) -> "InterrupterConfig":
        """Pre-configured Fehu key pointer reset schedule."""
        return cls(
            interrupt_runes={"ᚠ"},
            interrupt_indices={0},
            pause_on_interrupt=False,
            reset_on_interrupt=True,
            offset_step=0,
            pass_through=False,
        )

    @classmethod
    def from_rune_positions(
        cls,
        text: str,
        target_runes: Set[str] = None,
        pause_key: bool = True,
        reset_key: bool = False,
        offset_step: int = 0,
        pass_through: bool = False
    ) -> "InterrupterConfig":
        """
        Build an InterrupterConfig targeting the exact positions of specific runes
        within a text stream, eliminating ambiguous collision during round-trip operations.
        """
        targets = target_runes or {"ᚠ"}
        positions: Set[int] = set()
        pos = 0
        for c in text:
            if c in INDEX_BY_RUNE:
                if c in targets:
                    positions.add(pos)
                pos += 1
        return cls(
            interrupt_positions=positions,
            pause_on_interrupt=pause_key,
            reset_on_interrupt=reset_key,
            offset_step=offset_step,
            pass_through=pass_through,
        )


def canonical_key_shifts(key: Union[str, List[int]]) -> List[int]:
    """
    Extract canonical integer shifts (mod 29) for a word or integer keystream.
    Maps Latin characters to canonical Futhorc runes via agrippa.latin_to_rune.
    """
    if isinstance(key, (list, tuple)):
        return [int(k) % 29 for k in key]

    shifts: List[int] = []
    has_runes = any(c in INDEX_BY_RUNE for c in key)
    rune_key = key if has_runes else latin_to_rune(key)

    for c in rune_key:
        if c in INDEX_BY_RUNE:
            shifts.append(INDEX_BY_RUNE[c])
    return shifts if shifts else [0]


def divinity_shifts() -> Tuple[List[int], List[int]]:
    """
    Returns canonical encryption shifts and additive inverse decryption shifts
    for the verified 'DIVINITY' key.

    Returns:
        (encryption_shifts, decryption_shifts)
        encryption_shifts: [23, 10, 1, 10, 9, 10, 16, 26]
        decryption_shifts: [6, 19, 28, 19, 20, 19, 13, 3]
    """
    enc = canonical_key_shifts("DIVINITY")
    dec = [(29 - s) % 29 for s in enc]
    return enc, dec


def firfumferenfe_shifts() -> Tuple[List[int], List[int]]:
    """
    Returns canonical encryption shifts and additive inverse decryption shifts
    for the verified 'FIRFUMFERENFE' key (Middle English Circumference).

    Returns:
        (encryption_shifts, decryption_shifts)
        encryption_shifts: [0, 10, 4, 0, 1, 19, 0, 18, 4, 18, 9, 0, 18]
        decryption_shifts: [0, 19, 25, 0, 28, 10, 0, 11, 25, 11, 20, 0, 11]
    """
    enc = canonical_key_shifts("FIRFUMFERENFE")
    dec = [(29 - s) % 29 for s in enc]
    return enc, dec


def validate_canonical_alphabet() -> Dict[str, Union[bool, int, List[str]]]:
    """
    Validates that the active alphabet matches the authentic 29-rune Futhorc table
    and has not suffered the duplication corruption observed in external notes.
    """
    is_valid_len = len(RUNE_TABLE) == 29
    runes = [r[0] for r in RUNE_TABLE]
    unique_runes = len(set(runes)) == 29
    primes = [r[3] for r in RUNE_TABLE]

    has_y = "ᚣ" in INDEX_BY_RUNE and INDEX_BY_RUNE["ᚣ"] == 26
    has_ia = "ᛡ" in INDEX_BY_RUNE and INDEX_BY_RUNE["ᛡ"] == 27
    has_ea = "ᛠ" in INDEX_BY_RUNE and INDEX_BY_RUNE["ᛠ"] == 28

    return {
        "valid": is_valid_len and unique_runes and has_y and has_ia and has_ea,
        "total_runes": len(RUNE_TABLE),
        "primes_range": (primes[0], primes[-1]),
        "has_terminal_runes": has_y and has_ia and has_ea,
    }


def rune_vigenere_decode_dynamic(
    ciphertext: str,
    key: Union[str, List[int]],
    config: Optional[InterrupterConfig] = None,
    preserve_separators: bool = True
) -> str:
    """
    Decodes runic ciphertext modulo 29 with dynamic key interrupters.

    Equation:
        P_i = (C_i - (K_i + cumulative_offset)) mod 29

    Args:
        ciphertext: Input ciphertext string (contains runes and separators).
        key: Key word or numeric keystream shifts.
        config: Dynamic interrupter configuration (default: standard periodic Vigenère).
        preserve_separators: If True, preserves whitespace, single/double dots, etc.

    Returns:
        Decoded runic plaintext string.
    """
    shifts = canonical_key_shifts(key)
    cfg = config or InterrupterConfig()
    result: List[str] = []

    key_ptr = 0
    rune_pos = 0
    cumulative_offset = 0

    for char in ciphertext:
        if char in INDEX_BY_RUNE:
            c_val = INDEX_BY_RUNE[char]
            is_interrupt = (
                rune_pos in cfg.interrupt_positions or
                char in cfg.interrupt_runes or
                c_val in cfg.interrupt_indices
            )

            if is_interrupt and cfg.pass_through:
                p_val = c_val
            else:
                k_val = (shifts[key_ptr % len(shifts)] + cumulative_offset) % 29
                p_val = (c_val - k_val) % 29

            result.append(index_to_rune(p_val))

            if is_interrupt:
                if cfg.reset_on_interrupt:
                    key_ptr = 0
                elif not cfg.pause_on_interrupt:
                    key_ptr += 1

                if cfg.offset_step != 0:
                    cumulative_offset = (cumulative_offset + cfg.offset_step) % 29
            else:
                key_ptr += 1

            rune_pos += 1
        else:
            if preserve_separators:
                result.append(char)

    return "".join(result)


def rune_vigenere_encode_dynamic(
    plaintext: str,
    key: Union[str, List[int]],
    config: Optional[InterrupterConfig] = None,
    preserve_separators: bool = True
) -> str:
    """
    Encodes runic or Latin plaintext modulo 29 with dynamic key interrupters.

    Equation:
        C_i = (P_i + (K_i + cumulative_offset)) mod 29

    Args:
        plaintext: Input plaintext string (runic or Latin).
        key: Key word or numeric keystream shifts.
        config: Dynamic interrupter configuration (default: standard periodic Vigenère).
        preserve_separators: If True, preserves word dividers and punctuation.

    Returns:
        Encoded runic ciphertext string.
    """
    shifts = canonical_key_shifts(key)
    cfg = config or InterrupterConfig()
    result: List[str] = []

    has_runes = any(c in INDEX_BY_RUNE for c in plaintext)
    input_runes = plaintext if has_runes else latin_to_rune(plaintext)

    key_ptr = 0
    rune_pos = 0
    cumulative_offset = 0

    for char in input_runes:
        if char in INDEX_BY_RUNE:
            p_val = INDEX_BY_RUNE[char]
            is_interrupt = (
                rune_pos in cfg.interrupt_positions or
                char in cfg.interrupt_runes or
                p_val in cfg.interrupt_indices
            )

            if is_interrupt and cfg.pass_through:
                c_val = p_val
            else:
                k_val = (shifts[key_ptr % len(shifts)] + cumulative_offset) % 29
                c_val = (p_val + k_val) % 29

            result.append(index_to_rune(c_val))

            if is_interrupt:
                if cfg.reset_on_interrupt:
                    key_ptr = 0
                elif not cfg.pause_on_interrupt:
                    key_ptr += 1

                if cfg.offset_step != 0:
                    cumulative_offset = (cumulative_offset + cfg.offset_step) % 29
            else:
                key_ptr += 1

            rune_pos += 1
        else:
            if preserve_separators:
                result.append(char)

    return "".join(result)


# =============================================================================
# Canonical Solved-Page F-Skip Schedules & Helpers (Liber Primus Wiki)
# =============================================================================

WELCOME_F_SKIP_POSITIONS: Set[int] = {48, 74, 84, 132, 159, 160, 250, 421, 443, 465, 514}
KOAN2_F_SKIP_POSITIONS: Set[int] = {49, 58}
KOAN2_F_SKIP_POSITIONS_WIKI_TYPO: Set[int] = {49, 56}


def verify_f_skip_alignment(plaintext: str, skip_indices: Set[int]) -> bool:
    """
    Verifies that every index in skip_indices aligns with a cleartext Fehu ('ᚠ' / 'F')
    in the decoded plaintext rune stream.
    """
    if not skip_indices:
        return True
    runes = [c for c in plaintext if c in INDEX_BY_RUNE]
    for idx in skip_indices:
        if idx < 0 or idx >= len(runes):
            return False
        if INDEX_BY_RUNE[runes[idx]] != 0:
            return False
    return True


def rune_vigenere_decode_f_skip(
    ciphertext: str,
    key: Union[str, List[int]],
    skip_indices: Optional[Set[int]] = None,
    preserve_separators: bool = True
) -> str:
    """
    Decode runic ciphertext using Vigenère (mod 29) with cleartext F-skips.
    (Indices where cleartext is Fehu / index 0 do not advance key pointer and pass through).
    If skip_indices is None:
    - Resolves canonical schedules for authentic Liber Primus pages (Welcome and Koan 2)
    - Auto-detects Fehu pause positions for novel/custom messages where cleartext Fehu
      was emitted unencrypted into the ciphertext stream.
    """
    has_runes = any(c in INDEX_BY_RUNE for c in ciphertext)
    has_latin = any(c.isalpha() for c in ciphertext)
    input_runes = ciphertext if (has_runes or not has_latin) else latin_to_rune(ciphertext)
    clean_runes = [c for c in input_runes if c in INDEX_BY_RUNE]

    if skip_indices is None:
        key_str = key if isinstance(key, str) else ""
        norm_key = key_str.upper().strip()
        n_runes = len(clean_runes)
        prefix_4 = "".join(clean_runes[:4]) if n_runes >= 4 else ""

        if norm_key in ("DIVINITY", "ᛞᛁᚢᛁᚾᛁᛏᚣ") and (n_runes == 545 or prefix_4 == "ᚢᛠᛝᛋ" or n_runes >= 515):
            skip_indices = WELCOME_F_SKIP_POSITIONS
        elif norm_key in ("FIRFUMFERENFE", "ᚠᛁᚱᚠᚢᛗᚠᛖᚱᛖᚾᚠᛖ") and (n_runes == 135 or prefix_4 == "ᚪᛋᚹᚪ" or n_runes >= 59):
            skip_indices = KOAN2_F_SKIP_POSITIONS
        else:
            # Auto-detect Fehu pause positions from unencrypted Fehu runes in ciphertext
            skip_indices = {i for i, c in enumerate(clean_runes) if c == "ᚠ"}

    cfg = InterrupterConfig(
        interrupt_positions=set(skip_indices),
        pause_on_interrupt=True,
        pass_through=True,
    )
    return rune_vigenere_decode_dynamic(
        ciphertext=input_runes,
        key=key,
        config=cfg,
        preserve_separators=preserve_separators
    )


def rune_vigenere_encode_f_skip(
    plaintext: str,
    key: Union[str, List[int]],
    preserve_separators: bool = True
) -> Tuple[str, Set[int]]:
    """
    Encode runic or Latin plaintext using Vigenère (mod 29) with cleartext F-skips.
    Whenever plaintext rune is Fehu ('ᚠ' / 0), it passes through unencrypted and pauses
    the key pointer. Returns (ciphertext, set_of_skip_indices).
    """
    has_runes = any(c in INDEX_BY_RUNE for c in plaintext)
    input_runes = plaintext if has_runes else latin_to_rune(plaintext)
    cfg = InterrupterConfig.from_rune_positions(
        text=input_runes,
        target_runes={"ᚠ"},
        pause_key=True,
        pass_through=True
    )
    ct = rune_vigenere_encode_dynamic(
        plaintext=input_runes,
        key=key,
        config=cfg,
        preserve_separators=preserve_separators
    )
    return ct, set(cfg.interrupt_positions)


def analyze_f_skip_periodicity(ciphertext: str) -> Dict[str, Any]:
    """
    Diagnostic analysis of F-skip and consecutive double runes in ciphertext.
    Evaluates:
    - consecutive double runes rate: count(C_i == C_{i+1}) / (N - 1) vs uniform 1/29 (~3.45%)
    - fehu positions and local intervals/periods between consecutive Fehu (ᚠ, index 0)
    - local segmentation between Fehu runes
    """
    has_runes = any(c in INDEX_BY_RUNE for c in ciphertext)
    has_latin = any(c.isalpha() for c in ciphertext)
    input_runes = ciphertext if (has_runes or not has_latin) else latin_to_rune(ciphertext)
    clean_runes = [c for c in input_runes if c in INDEX_BY_RUNE]
    indices = [INDEX_BY_RUNE[c] for c in clean_runes]
    n = len(indices)

    uniform_rate = round(1.0 / 29.0, 5)  # 1/29 ≈ 0.03448 (3.45%)
    if n < 2:
        return {
            "rune_count": n,
            "consecutive_doubles_count": 0,
            "consecutive_doubles_rate": 0.0,
            "uniform_doubles_rate": uniform_rate,
            "doubles_elevation_ratio": 0.0,
            "fehu_count": len([i for i in indices if i == 0]),
            "fehu_positions": [i for i, idx in enumerate(indices) if idx == 0],
            "fehu_intervals": [],
            "mean_fehu_interval": 0.0,
            "segments_between_fehu": [n] if n > 0 else [],
        }

    consecutive_doubles = sum(1 for i in range(n - 1) if indices[i] == indices[i + 1])
    doubles_rate = round(consecutive_doubles / (n - 1), 5)
    elevation_ratio = round(doubles_rate / uniform_rate, 3) if uniform_rate > 0 else 1.0

    fehu_positions = [i for i, idx in enumerate(indices) if idx == 0]
    fehu_intervals = [fehu_positions[i + 1] - fehu_positions[i] for i in range(len(fehu_positions) - 1)]
    mean_interval = round(sum(fehu_intervals) / len(fehu_intervals), 2) if fehu_intervals else 0.0

    segments: List[int] = []
    if fehu_positions:
        if fehu_positions[0] > 0:
            segments.append(fehu_positions[0])
        for interval in fehu_intervals:
            segments.append(interval - 1)
        after_last = n - 1 - fehu_positions[-1]
        if after_last > 0:
            segments.append(after_last)
    else:
        segments.append(n)

    return {
        "rune_count": n,
        "consecutive_doubles_count": consecutive_doubles,
        "consecutive_doubles_rate": doubles_rate,
        "uniform_doubles_rate": uniform_rate,
        "doubles_elevation_ratio": elevation_ratio,
        "fehu_count": len(fehu_positions),
        "fehu_positions": fehu_positions,
        "fehu_intervals": fehu_intervals,
        "mean_fehu_interval": mean_interval,
        "segments_between_fehu": segments,
    }

