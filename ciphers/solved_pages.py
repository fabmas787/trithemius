"""
Solved Pages — Canonical Solved-Page Cipher Engine & Verification Suite for Liber Primus.
Details and reproduces the exact cryptographic methods documented on the Uncovering Cicada Wiki:
https://uncovering-cicada.fandom.com/wiki/How_the_solved_pages_of_the_Liber_Primus_were_solved

Canonical Solved Pages:
1. Page 00 ('A warning', 01.jpg):
   Atbash in F_29: decimal[i] = (28 - decimal[i]) % 29
2. Welcome (03.jpg - 04.jpg, Chunks 1-2):
   Vigenere (mod 29) with key 'DIVINITY' with cleartext F-skips (indices where cleartext is F do not advance key)
3. Some wisdom (05.jpg, Chunk 3):
   Direct Gematria Primus transliteration
4. Koan 1 (06.jpg - 09.jpg, Chunks 4-7):
   Atbash followed by Caesar shift of +3 in F_29: decimal[i] = ((28 - decimal[i]) + 3) % 29
5. The loss of divinity (10.jpg - 13.jpg, Chunks 8-11):
   Direct Gematria Primus transliteration
6. Koan 2 (14.jpg - 15.jpg, Chunks 12-13):
   Vigenere (mod 29) with key 'FIRFUMFERENFE' with cleartext F-skips
7. An instruction (16.jpg, Chunk 14):
   Direct Gematria Primus transliteration
8. An end (56.jpg in original dump / 73.jpg in some numbering, Chunk 71):
   Prime Totient Stream Cipher: decimal[i] = (decimal[i] - (primes[i] - 1)) % 29
9. Parable (57.jpg in original dump, Chunk 72):
   Direct Gematria Primus transliteration
"""

from dataclasses import dataclass
import os
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Path resolution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")

import sys
for d in (BASE_DIR, CURRENT_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from agrippa import (
    INDEX_BY_RUNE,
    decode_runes,
    direct_translation,
    latin_to_rune,
    rune_atbash,
    rune_atbash_shift,
)
from interrupter import (
    KOAN2_F_SKIP_POSITIONS,
    WELCOME_F_SKIP_POSITIONS,
    rune_vigenere_decode_f_skip,
    verify_f_skip_alignment,
)
from kasiski import (
    prime_totient_stream_decode,
    rune_vigenere_decode,
)


@dataclass(frozen=True)
class CanonicalSolvedPage:
    """Specification of a canonical solved page from the Liber Primus wiki."""
    id: str
    title: str
    original_image: str
    chunks: List[int]
    method_name: str
    method_description: str
    key: Optional[str]
    skip_indices: Optional[Set[int]]
    expected_latin_fragments: List[str]


# -----------------------------------------------------------------------------
# Canonical Registry
# -----------------------------------------------------------------------------

SOLVED_PAGES_REGISTRY: List[CanonicalSolvedPage] = [
    CanonicalSolvedPage(
        id="page_00",
        title="A warning",
        original_image="01.jpg",
        chunks=[0],
        method_name="Atbash in F_29",
        method_description="decimal[i] = (28 - decimal[i]) % 29",
        key=None,
        skip_indices=None,
        expected_latin_fragments=[
            "A WARNNG",
            "BELIEVE NOTHNG FROM THIS BOOC",
            "EXCEPT WHAT YOV CNOW TO BE TRVE",
            "TEST THE CNOWLEDGE",
            "FIND YOVR TRVTH",
            "EXPERIENCE YOVR DEATH",
            "DO NOT EDIT OR CHANGE THIS BOOC",
            "FOR ALL IS SACRED",
        ],
    ),
    CanonicalSolvedPage(
        id="welcome",
        title="Welcome",
        original_image="03.jpg - 04.jpg",
        chunks=[1, 2],
        method_name="Vigenère (mod 29) key 'DIVINITY' with cleartext F-skips",
        method_description="decimal[i] = (decimal[i] - key[k_ptr]) % 29; key paused when cleartext is Fehu (0)",
        key="DIVINITY",
        skip_indices=WELCOME_F_SKIP_POSITIONS,
        expected_latin_fragments=[
            "WELCOME",
            "WELCOME PILGRIM TO THE GREAT JOVRNEY",
            "TOWARD THE END OF ALL THNGS",
            "IT IS NOT AN EASY TRIP",
            "ALONG THE WAY YOV WILL FIND AN END",
            "VLTIMATELY YOV WILL DISCOVER AN END TO SELF",
            "EACH INTELLIGENCE IS HOLY",
            "AN INSTRVCTIAN COMMAND YOVR OWN SELF",
        ],
    ),
    CanonicalSolvedPage(
        id="some_wisdom",
        title="Some wisdom",
        original_image="05.jpg",
        chunks=[3],
        method_name="Direct translation",
        method_description="Direct Gematria Primus transliteration (no encryption)",
        key=None,
        skip_indices=None,
        expected_latin_fragments=[
            "SOME WISDOM",
            "THE PRIMES ARE SACRED",
            "THE TOTIENT FVNCTIAN IS SACRED",
            "ALL THNGS SHOVLD BE ENCRYPTED",
            "CNOW THIS",
            "SHADOWS",
            "AETHEREAL",
        ],
    ),
    CanonicalSolvedPage(
        id="koan_1",
        title="Koan 1",
        original_image="06.jpg - 09.jpg",
        chunks=[4, 5, 6, 7],
        method_name="Atbash in F_29 followed by Caesar shift of +3",
        method_description="decimal[i] = ((28 - decimal[i]) + 3) % 29",
        key="Atbash+3",
        skip_indices=None,
        expected_latin_fragments=[
            "A COAN",
            "A MAN DECIDED TO GO AND STVDY WITH A MASTER",
            "WHO ARE YOV WHO WISHES TO STVDY HERE ASCED THE MASTER",
            "THE STVDENT TOLD THE MASTER HIS NAME",
            "I AM A PROFESSOR",
            "I AM A HVMAN BENG",
            "I AM A CONSCIAVSNESS INHABITNG AN ARBITRARY BODY",
            "DO FOVR VNREASONABLE THNGS EACH DAY",
        ],
    ),
    CanonicalSolvedPage(
        id="loss_of_divinity",
        title="The loss of divinity",
        original_image="10.jpg - 13.jpg",
        chunks=[8, 9, 10, 11],
        method_name="Direct translation",
        method_description="Direct Gematria Primus transliteration (no encryption)",
        key=None,
        skip_indices=None,
        expected_latin_fragments=[
            "THE LOSS OF DIVINITY",
            "THE CIRCVMFERENCE PRACTICES THREE BEHAVIARS",
            "CONSVMPTIAN",
            "PRESERVATIAN",
            "ADHERENCE",
            "TO BELONG IS DEATH",
            "AMASS GREAT WEALTH",
            "PROGRAM YOVR MIND",
            "PROGRAM REALITY",
        ],
    ),
    CanonicalSolvedPage(
        id="koan_2",
        title="Koan 2",
        original_image="14.jpg - 15.jpg",
        chunks=[12, 13],
        method_name="Vigenère (mod 29) key 'FIRFUMFERENFE' with cleartext F-skips",
        method_description="decimal[i] = (decimal[i] - key[k_ptr]) % 29; key paused when cleartext is Fehu (0)",
        key="FIRFUMFERENFE",
        skip_indices=KOAN2_F_SKIP_POSITIONS,
        expected_latin_fragments=[
            "A COAN",
            "DVRNG A LESSON THE MASTER EXPLAINED THE I",
            "THE I IS THE VOICE OF THE CIRCVMFERENCE HE SAID",
            "IT IS A VOICE INSIDE YOVR HEAD",
            "I DONT HAVE A VOICE IN MY HEAD",
            "AND THE STVDENTS WERE ENLIGHTENED",
        ],
    ),
    CanonicalSolvedPage(
        id="instruction",
        title="An instruction",
        original_image="16.jpg",
        chunks=[14],
        method_name="Direct translation",
        method_description="Direct Gematria Primus transliteration (no encryption)",
        key=None,
        skip_indices=None,
        expected_latin_fragments=[
            "AN INSTRVCTIAN",
            "CWESTIAN ALL THNGS",
            "DISCOVER TRVTH INSIDE YOVRSELF",
            "FOLLOW YOVR TRVTH",
            "IMPOSE NOTHNG ON OTHERS",
            "CNOW THIS",
        ],
    ),
    CanonicalSolvedPage(
        id="an_end",
        title="An end",
        original_image="56.jpg (LP 73.jpg)",
        chunks=[71],
        method_name="Prime Totient Stream Cipher",
        method_description="decimal[i] = (decimal[i] - (primes[i] - 1)) % 29 where phi(p) = p - 1",
        key="phi(primes[i]) = primes[i] - 1",
        skip_indices={56},
        expected_latin_fragments=[
            "AN END",
            "WITHIN THE DEEP WEB",
            "THERE EXISTS A PAGE THAT HASHES TO",
            "36367763ab73783c7af284446c59466b4cd653239a311cb7116d4618dee09a8425893dc7500b464fdaf1672d7bef5e891c6e2274568926a49fb4f45132c2a8b4",
            "IT IS THE DVTY OF EVERY PILGRIM TO SEEC OVT THIS PAGE",
        ],
    ),
    CanonicalSolvedPage(
        id="parable",
        title="Parable",
        original_image="57.jpg",
        chunks=[72],
        method_name="Direct translation",
        method_description="Direct Gematria Primus transliteration (no encryption)",
        key=None,
        skip_indices=None,
        expected_latin_fragments=[
            "PARABLE",
            "LICE THE INSTAR",
            "TVNNELNG TO THE SVRFACE",
            "WE MVST SHED OVR OWN CIRCVMFERENCES",
            "FIND THE DIVINITY WITHIN AND EMERGE",
        ],
    ),
]


# Lookup map for flexible resolution by id, title, image name, chunk, or page number
_LOOKUP_MAP: Dict[str, CanonicalSolvedPage] = {}

for _p in SOLVED_PAGES_REGISTRY:
    _LOOKUP_MAP[_p.id.lower()] = _p
    _LOOKUP_MAP[_p.title.lower()] = _p
    _LOOKUP_MAP[_p.original_image.lower()] = _p
    for _c in _p.chunks:
        _LOOKUP_MAP[str(_c)] = _p
        _LOOKUP_MAP[f"{_c:02d}"] = _p
        _LOOKUP_MAP[f"chunk_{_c}"] = _p
        _LOOKUP_MAP[f"page_{_c:02d}"] = _p

# Aliases matching historical references
_ALIASES = {
    "warning": "page_00",
    "a warning": "page_00",
    "0": "page_00",
    "00": "page_00",
    "01.jpg": "page_00",
    "welcome": "welcome",
    "03.jpg": "welcome",
    "04.jpg": "welcome",
    "1": "welcome",
    "2": "welcome",
    "wisdom": "some_wisdom",
    "some wisdom": "some_wisdom",
    "05.jpg": "some_wisdom",
    "3": "some_wisdom",
    "koan1": "koan_1",
    "koan 1": "koan_1",
    "06.jpg": "koan_1",
    "07.jpg": "koan_1",
    "08.jpg": "koan_1",
    "09.jpg": "koan_1",
    "4": "koan_1",
    "5": "koan_1",
    "6": "koan_1",
    "7": "koan_1",
    "loss": "loss_of_divinity",
    "the loss of divinity": "loss_of_divinity",
    "loss of divinity": "loss_of_divinity",
    "10.jpg": "loss_of_divinity",
    "11.jpg": "loss_of_divinity",
    "12.jpg": "loss_of_divinity",
    "13.jpg": "loss_of_divinity",
    "8": "loss_of_divinity",
    "9": "loss_of_divinity",
    "10": "loss_of_divinity",
    "11": "loss_of_divinity",
    "koan2": "koan_2",
    "koan 2": "koan_2",
    "14.jpg": "koan_2",
    "15.jpg": "koan_2",
    "12": "koan_2",
    "13": "koan_2",
    "instruction": "instruction",
    "an instruction": "instruction",
    "16.jpg": "instruction",
    "14": "instruction",
    "16": "instruction",
    "end": "an_end",
    "an end": "an_end",
    "56.jpg": "an_end",
    "56": "an_end",
    "71": "an_end",
    "73": "an_end",
    "73.jpg": "an_end",
    "parable": "parable",
    "57.jpg": "parable",
    "57": "parable",
    "72": "parable",
}


def resolve_solved_page(target: Union[str, int, CanonicalSolvedPage]) -> Optional[CanonicalSolvedPage]:
    """
    Resolve a user query (string, number, slug, filename, or filepath) to a CanonicalSolvedPage.
    """
    if isinstance(target, CanonicalSolvedPage):
        return target
    if isinstance(target, int):
        target = str(target)
    raw_str = str(target).strip()

    # 1. Check if target is an existing file on disk and inspect headers
    if os.path.isfile(raw_str):
        file_path = os.path.abspath(raw_str)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)
            m_c = re.search(r"cicada:chunk_index=(\d+)", content)
            if m_c:
                chunk_page = resolve_solved_page(int(m_c.group(1)))
                if chunk_page:
                    return chunk_page
            m_p = re.search(r"cicada:page=(\d+)", content)
            if m_p:
                page_match = resolve_solved_page(m_p.group(1))
                if page_match:
                    return page_match
            m_t = re.search(r"# Liber Primus — Page (\d+)", content)
            if m_t:
                page_match = resolve_solved_page(int(m_t.group(1)))
                if page_match:
                    return page_match
        except Exception:
            pass

    # 2. Normalize and check direct names, aliases, and filenames
    clean = raw_str.lower()
    base = os.path.basename(clean).replace(".md", "").replace(".txt", "")
    base_stripped = re.sub(r"_(?:runes|transcript)$", "", base)

    for cand in (clean, base, base_stripped):
        cand_clean = cand.replace(".md", "").replace(".txt", "")
        if cand_clean in _ALIASES:
            return _LOOKUP_MAP.get(_ALIASES[cand_clean])
        if cand_clean in _LOOKUP_MAP:
            return _LOOKUP_MAP[cand_clean]
        m = re.match(r"^(?:page_?|chunk_?)?(\d+)$", cand_clean)
        if m:
            num_str = str(int(m.group(1)))
            if num_str in _ALIASES:
                return _LOOKUP_MAP.get(_ALIASES[num_str])
            if num_str in _LOOKUP_MAP:
                return _LOOKUP_MAP[num_str]

    # 3. Content signature match if target is a file
    if os.path.isfile(raw_str):
        runes_text = extract_runes_from_file(raw_str)
        clean_r = [c for c in runes_text if c in INDEX_BY_RUNE]
        if len(clean_r) >= 10:
            prefix_10 = "".join(clean_r[:10])
            for p in SOLVED_PAGES_REGISTRY:
                try:
                    p_runes = load_solved_page_transcript(p)
                    p_clean = [c for c in p_runes if c in INDEX_BY_RUNE]
                    if "".join(p_clean[:10]) == prefix_10:
                        return p
                except Exception:
                    pass

    return None


# -----------------------------------------------------------------------------
# Transcript Loader
# -----------------------------------------------------------------------------

def extract_runes_from_file(filepath: str) -> str:
    """
    Extract runic transcription from an arbitrary markdown or text file.
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    m = re.search(r"## Rune Transcription\n(.*?)(?:\n---|\n## Latin|\Z)", content, re.DOTALL)
    if m:
        return m.group(1).strip()

    lines = [l for l in content.splitlines() if any(c in INDEX_BY_RUNE for c in l)]
    return "\n".join(lines).strip() if lines else content.strip()


def load_chunk_transcript(chunk_index: int, corpus_dir: Optional[str] = None) -> str:
    """
    Extract the clean runic transcript of a specific Liber Primus chunk from corpus.
    """
    cdir = corpus_dir or CORPUS_DIR
    target_file = os.path.join(cdir, f"page_{chunk_index:02d}_runes.md")
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"Corpus transcript not found: {target_file}")
    return extract_runes_from_file(target_file)


def load_solved_page_transcript(page: CanonicalSolvedPage, corpus_dir: Optional[str] = None) -> str:
    """
    Load and concatenate the authentic runic transcripts for all chunks of a solved page.
    """
    texts = [load_chunk_transcript(c, corpus_dir=corpus_dir) for c in page.chunks]
    return "\n".join(texts)


# -----------------------------------------------------------------------------
# Solver & Normalization
# -----------------------------------------------------------------------------

def _normalize_latin_for_comparison(text: str) -> str:
    """
    Normalizes Latin text to compare against wiki transcriptions:
    - Uppercase
    - Maps common variant spellings: V/U -> U, K/C -> C, J/I -> I
    - Maps ING -> NG (for Futhorc runic ING/NG character equivalence)
    - Maps archaic Cicada Futhorc suffix variants: TIAN -> TION, SIAN -> SION, CIAUS -> CIOUS
    - Strips all whitespace and non-alphanumeric punctuation
    """
    s = text.upper()
    s = s.replace("V", "U").replace("K", "C").replace("J", "I")
    s = s.replace("QU", "CW").replace("Q", "CW")
    s = s.replace("ING", "NG")
    s = s.replace("TIAN", "TION").replace("SIAN", "SION").replace("CIAUS", "CIOUS")
    s = re.sub(r"[^A-Z0-9]+", "", s)
    return s


def solve_page(
    target: Union[str, int, CanonicalSolvedPage],
    corpus_dir: Optional[str] = None,
    preserve_separators: bool = True
) -> Dict[str, Any]:
    """
    Execute the canonical wiki cipher method for a solved Liber Primus page,
    reproducing and validating the authentic plaintext.

    Args:
        target: Page number, slug, filename, filepath, or CanonicalSolvedPage instance.
        corpus_dir: Optional path to the corpus directory.
        preserve_separators: Whether to retain punctuation / layout separators.

    Returns:
        Result dictionary containing decrypted runes, Latin text, method description,
        and verification status.
    """
    page = target if isinstance(target, CanonicalSolvedPage) else resolve_solved_page(target)
    if not page:
        raise ValueError(f"Unknown or unsolved Liber Primus page identifier: '{target}'")

    if isinstance(target, str) and os.path.isfile(target):
        raw_runes = extract_runes_from_file(target)
    else:
        raw_runes = load_solved_page_transcript(page, corpus_dir=corpus_dir)

    rune_count = sum(1 for c in raw_runes if c in INDEX_BY_RUNE)

    # Dispatch to canonical wiki cipher
    if page.id == "page_00":
        dec_runes = rune_atbash(raw_runes, preserve_separators=preserve_separators)
    elif page.id == "welcome":
        dec_runes = rune_vigenere_decode_f_skip(
            raw_runes,
            key=page.key or "DIVINITY",
            skip_indices=page.skip_indices,
            preserve_separators=preserve_separators,
        )
    elif page.id == "some_wisdom":
        dec_runes = direct_translation(raw_runes, preserve_punctuation=preserve_separators)
    elif page.id == "koan_1":
        dec_runes = rune_atbash_shift(raw_runes, shift=3, preserve_separators=preserve_separators)
    elif page.id == "loss_of_divinity":
        dec_runes = direct_translation(raw_runes, preserve_punctuation=preserve_separators)
    elif page.id == "koan_2":
        dec_runes = rune_vigenere_decode_f_skip(
            raw_runes,
            key=page.key or "FIRFUMFERENFE",
            skip_indices=page.skip_indices,
            preserve_separators=preserve_separators,
        )
    elif page.id == "instruction":
        dec_runes = direct_translation(raw_runes, preserve_punctuation=preserve_separators)
    elif page.id == "an_end":
        dec_runes = prime_totient_stream_decode(
            raw_runes,
            offset=0,
            preserve_separators=preserve_separators,
            skip_indices=page.skip_indices,
        )
    elif page.id == "parable":
        dec_runes = direct_translation(raw_runes, preserve_punctuation=preserve_separators)
    else:
        raise NotImplementedError(f"Cipher implementation missing for page: {page.id}")

    latin_text = decode_runes(dec_runes, preserve_punctuation=preserve_separators)
    norm_latin = _normalize_latin_for_comparison(latin_text)

    # Verification against expected canonical fragments
    matched_fragments = []
    missing_fragments = []
    for frag in page.expected_latin_fragments:
        norm_frag = _normalize_latin_for_comparison(frag)
        if norm_frag in norm_latin:
            matched_fragments.append(frag)
        else:
            missing_fragments.append(frag)

    verified = len(matched_fragments) >= max(1, int(len(page.expected_latin_fragments) * 0.75))

    return {
        "id": page.id,
        "title": page.title,
        "original_image": page.original_image,
        "chunks": page.chunks,
        "method": page.method_name,
        "method_description": page.method_description,
        "key": page.key,
        "skip_indices": sorted(page.skip_indices) if page.skip_indices else None,
        "rune_count": rune_count,
        "decrypted_runes": dec_runes,
        "plaintext_latin": latin_text,
        "verified": verified,
        "matched_fragments": matched_fragments,
        "missing_fragments": missing_fragments,
    }


def verify_all_solved_pages(
    corpus_dir: Optional[str] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Executes and validates all canonical solved pages from the Liber Primus wiki.
    """
    results: Dict[str, Any] = {}
    verified_count = 0

    for page in SOLVED_PAGES_REGISTRY:
        res = solve_page(page, corpus_dir=corpus_dir)
        results[page.id] = res
        if res["verified"]:
            verified_count += 1
        if verbose:
            status_str = "[PASS]" if res["verified"] else "[FAIL]"
            print(f"{status_str} {page.title:22s} ({page.original_image}) -> {page.method_name}")

    total = len(SOLVED_PAGES_REGISTRY)
    return {
        "total": total,
        "verified": verified_count,
        "failed": total - verified_count,
        "all_passed": verified_count == total,
        "results": results,
    }


if __name__ == "__main__":
    report = verify_all_solved_pages(verbose=True)
    print(f"\nVerification Complete: {report['verified']}/{report['total']} pages passed.")
