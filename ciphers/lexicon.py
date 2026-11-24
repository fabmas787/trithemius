"""
Lexicon — Master Cryptanalytic Keyword & Vocabulary Engine.
Provides comprehensive candidate wordlists and mathematical transformations
for Liber Primus and Cicada 3301 cryptanalysis over GF(29) Futhorc.

Features:
- Curated Sacred, Mathematical, Philosophical, and Lore Key Vocabulary
- Dynamic Extraction and Cleansing of Full Corpus Vocabulary
- Multi-Vector Key Generation: Forward, Reversed, Atbash, Prime Mod 29, Variant Beaufort
- Fast O(1) Prefix and Word Membership Lookups for Crib Dragging
- Beaufort Matrix and Additive Shift Generators for T-table Screening
"""

import os
import re
import sys
import hashlib
import random
from typing import Dict, List, Optional, Set, Tuple, Any

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")
REFERENCE_DIR = os.path.join(CORPUS_DIR, "reference_texts")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import (
        INDEX_BY_RUNE,
        PRIME_BY_RUNE,
        latin_to_rune,
        decode_runes,
        index_to_rune,
        rune_atbash,
    )
except ImportError:
    from agrippa import (
        INDEX_BY_RUNE,
        PRIME_BY_RUNE,
        latin_to_rune,
        decode_runes,
        index_to_rune,
        rune_atbash,
    )

M = 29  # Field size GF(29)

try:
    from agents.ledger import get_tested_words
except ImportError:
    try:
        from ledger import get_tested_words
    except ImportError:
        get_tested_words = None

# =============================================================================
# 1. Curated Sacred, Mathematical & Philosophical Vocabulary
# =============================================================================

SACRED_CANONICAL_WORDS: List[str] = [
    # Solved Keys & Canonical Cicada Lore
    "WELCOME", "PILGRIM", "PILGRIMS", "PILGRIMAGE", "JOURNEY", "SACRED",
    "PRIME", "PRIMES", "TOTIENT", "TOTIENTS", "WISDOM", "TRUTH", "KNOWLEDGE",
    "BELIEVE", "BELIEF", "FAITH", "DOUBT", "CERTAINTY", "DIVINITY", "DIVINE",
    "CIRCUMFERENCE", "CENTER", "RADIUS", "DIAMETER", "CIRCLE", "CIRCLES",
    "FIRFUMFERENFE", "WARNING", "DEATH", "MASTER", "STUDENT", "STUDENTS",
    "DISCIPLE", "SEEKER", "INITIATE", "NOTHING", "NOTHINGNESS", "VOID",
    "ABYSS", "MESSAGE", "WORDS", "NUMBERS", "SIMPLEST", "STATE", "PATH",
    "END", "DEEP", "WEB", "OBJECT", "KOAN", "KOANS", "PARABLE", "LESSON",
    "CICADA", "INSTAR", "EMERGENCE", "METAMORPHOSIS", "CHRYSALIS", "PUPA",
    "NYMPH", "BROOD", "WING", "WINGS", "FLIGHT", "CYCLE", "PERIODICITY",
    "TRITHEMIUS", "AGRIPPA", "STEGANOGRAPHIA", "POLYGRAPHIA", "TABULA", "RECTA",
    "KASISKI", "ALKINDI", "VIGENERE", "BEAUFORT", "CAESAR", "ATBASH", "SCYTALE",
    "ENIGMA", "VERNAM", "SHANNON", "LIBER", "PRIMUS", "LIBERPRIMUS", "BOOK",
    "RUNES", "FUTHORC", "FUTHARK", "GEMATRIA", "INTERRUPTER", "INTERPUNCT",
    "HASH", "DIGEST", "ONION", "PGP", "SIGNATURE", "AUTHENTIC", "OUTAGUES",
    "PRESERVATION", "INNOCENCE", "DESTINY", "CIRCUMSTANCE", "ARCHITECTURE",
    "BUILDING", "BLOCKS", "COMPOSITE", "COMPOSITES", "FACTOR", "FACTORS",
    "FACTORIZATION", "DIVISOR", "DIVISORS", "FACTORIAL", "MULTIPLE",

    # Sacred Mathematics & Geometry
    "FIBONACCI", "LUCAS", "EULER", "EUCLID", "PYTHAGORAS", "ERATOSTHENES",
    "MERSENNE", "PASCAL", "FERMAT", "GAUSS", "NEWTON", "LEIBNIZ", "BOOLE",
    "TURING", "SPIRAL", "TORUS", "SPHERE", "CYLINDER", "CONE", "POLYHEDRON",
    "PLATONIC", "DODECAHEDRON", "ICOSAHEDRON", "OCTAHEDRON", "HEXAHEDRON",
    "TETRAHEDRON", "TETRACTYS", "SEVEN", "THREE", "THIRTYTHREE", "THREEHUNDRED",
    "GOLDEN", "RATIO", "PHI", "SECTIO", "AUREA", "GEOMETRY", "SYMMETRY",
    "DIMENSION", "PROPORTION", "OCTAVE", "HARMONY", "MODULO", "CONGRUENCE",
    "RESIDUE", "LATTICE", "MATRIX", "DETERMINANT", "GALOIS", "FIELD", "GROUP",
    "RING", "ALGEBRA", "SEQUENCE", "SERIES", "PROGRESSION", "RECURRENCE",
    "LIMIT", "INFINITY", "INFINITE", "FINITE", "DISCRETE", "CONTINUOUS",
    "TOPOLOGY", "MANIFOLD", "EXPONENT", "LOGARITHM", "INTEGRAL", "DERIVATIVE",
    "CONSTANT", "VARIABLE", "FUNCTION", "EQUATION", "ROOT", "SQUARE", "CUBE",

    # Metaphysics, Mysticism & Epistemology
    "REASON", "LOGIC", "UNDERSTANDING", "INTELLECT", "INSIGHT", "INTUITION",
    "PERCEPTION", "CONSCIOUSNESS", "AWARENESS", "MIND", "SPIRIT", "SOUL",
    "MONAD", "DUAD", "TRIAD", "TETRAD", "PENTAD", "HEXAD", "HEPTAD", "OGDOAD",
    "ENNEAD", "DECAD", "DUALITY", "UNITY", "ONE", "ALL", "WHOLE", "PART",
    "PARTS", "CHAOS", "ORDER", "COSMOS", "UNIVERSE", "REALITY", "EXISTENCE",
    "BEING", "BECOMING", "NATURE", "ESSENCE", "SUBSTANCE", "FORM", "MATTER",
    "ENERGY", "BREATH", "REBIRTH", "RESURRECTION", "TRANSCENDENCE",
    "IMMORTALITY", "MORTALITY", "ETERNITY", "TIME", "SPACE", "SHADOW",
    "LIGHT", "DARKNESS", "VEIL", "APOCALYPSE", "REVELATION", "UNVEILING",
    "CONCEALMENT", "SECRECY", "SILENCE", "FATE", "HOLY", "PURITY",
    "SANCTITY", "AMASSING", "INFORMATION", "COMMAND", "COVENANT", "DOCTRINE",
    "CREED", "TEST", "EXPERIENCE", "LOSS", "FIND", "SEEK", "DISCOVER",
    "RECOGNIZE", "REMEMBER", "FORGET", "AWAKEN", "AWAKENING", "DREAM",
    "SLEEP", "ILLUSION", "MAYA", "SHADOWS", "CAVE", "ALLEGORY", "THRESHOLD",
    "PORTAL", "GATEWAY", "GATE", "DOOR", "PASSAGE", "LABYRINTH", "MAZE",

    # Literary & Intertextual Cicada References
    # William Blake
    "TYGER", "LAMB", "MARRIAGE", "HEAVEN", "HELL", "VALA", "URIZEN", "LOS",
    "ALBION", "ENITHARMON", "GOLGONOOZA", "JERUSALEM", "INVENTION", "PROPHECY",
    "POETIC", "GENIUS", "CLEANSED", "DOORS",
    # Ralph Waldo Emerson
    "OVERSOUL", "COMPENSATION", "SELFRELIANCE", "TRANSCENDENTAL", "CORRESPONDENCE",
    # Carl Jung
    "ARCHETYPE", "ARCHETYPES", "SYNCHRONICITY", "INDIVIDUATION", "COLLECTIVE",
    "UNCONSCIOUS", "ANIMA", "ANIMUS", "PERSONA", "ALCHEMY", "ALCHEMICAL",
    "MANDALA", "TRANSFORMATION",
    # Kahlil Gibran & Nietzsche
    "PROPHET", "WANDERER", "SAND", "FOAM", "MADMAN", "GARDEN", "ZARATHUSTRA",
    "UBERMENSCH", "SUPERMAN", "POWER", "APOLLO", "DIONYSUS", "IDOL", "TWILIGHT",
    # Gnostic & WingMakers
    "SOVEREIGN", "SOURCE", "TRIBUTARY", "CHAMBER", "CAPSULE", "ANCIENT",
    "ARROW", "GNOSIS", "ANAMNESIS", "OUROBOROS", "ARCHON", "PLEROMA", "SOPHIA",
    "DEMIURGE", "HYLIC", "PSYCHIC", "PNEUMATIC", "HERMES", "TRISMEGISTUS",
    "SMARAGDINA", "ASABOVE", "SOBELOW",

    # 29 Futhorc Rune Names
    "FEHU", "URUZ", "THURISAZ", "ANSUZ", "RAIDO", "KAUNA", "GEBO", "WUNJO",
    "HAGALAZ", "NAUDIZ", "ISA", "JERA", "EIHWAZ", "PERTHO", "ALGIZ", "SOWILO",
    "TIWAZ", "BERKANA", "EHWAZ", "MANNAZ", "LAGUZ", "INGWAZ", "DAGAZ", "OTHILA",
    "AC", "AESC", "YR", "IOR", "EAR",
    # Old English Rune Name Variants
    "FEOH", "UR", "THORN", "OS", "RAD", "CEN", "GYFU", "WYNN", "HAEGL", "NYD",
    "IS", "GER", "EOH", "PEORD", "EOLH", "SIGEL", "TIR", "BEORC", "EH", "MANN",
    "LAGU", "ING", "DAEG", "ETHEL"
]


# =============================================================================
# 2. Dynamic Corpus Vocabulary Harvester
# =============================================================================

def _is_valid_corpus_word(token: str, min_len: int = 3, max_len: int = 24) -> bool:
    """Filter out hashes, hexadecimal runs, and non-alphabetic fragments."""
    if not (min_len <= len(token) <= max_len):
        return False
    # Exclude hex strings/hashes
    if len(token) >= 7 and all(c in "0123456789ABCDEF" for c in token):
        return False
    # Must have vowels or vocalic Y
    if not any(c in "AEIOUY" for c in token):
        return False
    # Avoid 5+ consecutive consonants
    if re.search(r"[BCDFGHJKLMNPQRSTVWXZ]{5,}", token):
        return False
    # Must be pure uppercase letters
    return token.isalpha() and token.isupper()


def load_corpus_vocabulary(corpus_dir: str = CORPUS_DIR, min_len: int = 3, max_len: int = 24) -> List[str]:
    """Scan and extract all clean, distinct uppercase words from the corpus files."""
    if not os.path.exists(corpus_dir):
        return []

    words = set()
    for fname in sorted(os.listdir(corpus_dir)):
        if fname.endswith(".md") or fname.endswith(".txt"):
            fpath = os.path.join(corpus_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    tokens = re.findall(r"\b[A-Za-z]+\b", content)
                    for t in tokens:
                        up = t.upper()
                        if _is_valid_corpus_word(up, min_len=min_len, max_len=max_len):
                            words.add(up)
            except Exception:
                continue

    return sorted(words)


# =============================================================================
# 2b. Canonical Philosophical Phrases & Reference Text Harvester
# =============================================================================

PHILOSOPHICAL_CANONICAL_PHRASES: List[str] = [
    # William Blake (The Marriage of Heaven and Hell, Auguries of Innocence)
    "FORALLTHATLIVESISHOLY",
    "DOORSOFPERCEPTION",
    "PROVERBSOFHELL",
    "MARRIAGEOFHEAVENANDHELL",
    "GRAINOFSAND",
    "WORLDIANAGRAINOFSAND",
    "HEAVENINAWILDFLOWER",
    "HOLDINFINITY",
    "ETERNITYINANHOUR",
    "AUGURIESOFINNOCENCE",
    "TYGERSOFWRATH",
    "HORSESOFINSTRUCTION",
    "EXUBERANCEISBEAUTY",
    "ROADOFEXCESS",
    "PALACEOFWISDOM",
    "ETERNITYISINLOVE",
    "CLEANSETHEDOORS",
    "INFINITEPALACE",
    "ENERGYISETERNALDELIGHT",

    # Ralph Waldo Emerson (Self-Reliance, The Over-Soul)
    "TRUSTTHYSELF",
    "SELFRELIANCE",
    "THEOVERSOUL",
    "OVERSOUL",
    "INTEGRITYOFYOUROWNMIND",
    "NOTHINGISLASTSACRED",
    "NOTHINGISSACRED",
    "NONCONFORMIST",
    "FOOLISHCONSISTENCY",
    "CIRCUMFERENCEANDCENTER",
    "CENTERANDCIRCUMFERENCE",
    "SPHERICALEXPANSION",
    "UNIVERSALBEAUTY",
    "SOVEREIGNSOUL",
    "DIVINEMIND",
    "COMMANDYOUROWNSELF",
    "ABSOLUTELYTRUSTWORTHY",

    # Friedrich Nietzsche (Thus Spoke Zarathustra)
    "THREEMETAMORPHOSES",
    "THREEFOLDMETAMORPHOSIS",
    "CAMELANDLIONANDCHILD",
    "ZARATHUSTRA",
    "THUSSPOKEZARATHUSTRA",
    "INSTAREMERGENCE",
    "SUPERMAN",
    "OVERMAN",
    "ROPEOVERANABYSS",
    "HOLYYEA",
    "HOLYNAY",
    "SELFOROLLINGWHEEL",
    "FIRSTMOVEMENT",
    "GREATDESPISER",
    "GREATADORER",

    # Hermes Trismegistus (Tabula Smaragdina / Emerald Tablet)
    "ASABOVESOBELOW",
    "SOBELOWASABOVE",
    "THATWHICHISBELOW",
    "THATWHICHISABOVE",
    "TABULASMARAGDINA",
    "EMERALDTABLET",
    "HERMESTRISMEGISTUS",
    "MIRACLESOFONE",
    "PATERSEUSSOL",
    "MATEREIUSLUNA",
    "SEPARATETHEEARTH",

    # Aleister Crowley (Liber AL vel Legis)
    "EVERYMANANDWOMANISASTAR",
    "DOWHATTHOUWILT",
    "SHALLBETHEWHOLEOFTHELAW",
    "LOVEISTHELAW",
    "LOVEUNDERWILL",
    "WORDSISSIXANDFIFTY",
    "DIVIDEADDMULTIPLY",
    "THELEMA",
    "NOTHINGISASECRETKEY",
    "RAHOORKHUIT",
    "HADITANDNUIT",

    # William Gibson (Agrippa - A Book of the Dead)
    "AGRIPPA",
    "ABOOKOFTHEDEAD",
    "THEBLACKALBUM",
    "THEMECHANISMOFTHECAMERA",
    "ACOLDWINDISCOMING",
    "COPPERTOKENS",
    "MEMORIESTURNTODUST",
    "ELROITAN",

    # Gospel of Thomas & Nag Hammadi
    "SEEKANDYESHALLFIND",
    "THEKINGDOMISWITHINYOU",
    "KNOWTHYSELF",
    "MAKETHEPLEROMA",
    "MAKETWONE",
    "INNERLIKETHEOUTER",
    "LIGHTWITHINAPERSON",
    "SPLITTHEWOOD",
    "LIFTTHESTONE",
    "LIVINGFATHER",

    # Kahlil Gibran (The Prophet)
    "SELFKNOWLEDGE",
    "BOUNDLESSANDMEASURELESS",
    "LOTUSOFCOUNTLESSPETALS",
    "THRESHOLDOFYOUROWNMIND",
    "HOUSEOFWISDOM",
    "UNBOUNDANDFREE",
    "WALKINGUPONMYPATH",

    # Carl Jung (Seven Sermons to the Dead)
    "SEVENSERMONSTOTHEDEAD",
    "PLEROMA",
    "CREATURA",
    "PLEROMAANDCREATURA",
    "PRINCIPIUM",
    "INDIVIDUATIONIS",
    "PRINCIPIUMINDIVIDUATIONIS",
    "HOLYABRAXAS",
    "UNIONOFCONTRARIES",
    "EFFECTIVEFULLNESS",

    # Sacred & Cicada Lore
    "THEPRIMESARESACRED",
    "SOVEREIGNSOURCE",
    "ANAMNESIS",
    "WELCOMEPILGRIM",
    "BELIEVETRUTH",
    "LOSSANDINNOCENCE",
    "ENDOFJOURNEY",
]


def generate_philosophical_phrases() -> List[str]:
    """
    Returns curated philosophical aphorisms and multi-word phrases
    harvested from canonical Cicada 3301 literary and mystical source texts.
    """
    seen = set()
    phrases = []
    for p in PHILOSOPHICAL_CANONICAL_PHRASES:
        up = p.upper().replace(" ", "").replace("-", "")
        if up and up not in seen:
            seen.add(up)
            phrases.append(up)
    return sorted(phrases)


def load_reference_text_vocabulary(reference_dir: str = REFERENCE_DIR, min_len: int = 3, max_len: int = 24) -> List[str]:
    """Scan and extract all clean, distinct uppercase words from the reference text files."""
    if not os.path.exists(reference_dir):
        return []

    words = set()
    for fname in sorted(os.listdir(reference_dir)):
        if fname.endswith(".md") or fname.endswith(".txt"):
            fpath = os.path.join(reference_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    tokens = re.findall(r"\b[A-Za-z]+\b", content)
                    for t in tokens:
                        up = t.upper()
                        if _is_valid_corpus_word(up, min_len=min_len, max_len=max_len):
                            words.add(up)
                    # Also extract hyphenated compound words (e.g. Over-Soul -> OVERSOUL)
                    compounds = re.findall(r"\b[A-Za-z]+-[A-Za-z]+\b", content)
                    for c in compounds:
                        up = c.replace("-", "").upper()
                        if _is_valid_corpus_word(up, min_len=min_len, max_len=max_len):
                            words.add(up)
            except Exception:
                continue

    return sorted(words)


# Master combined and deduplicated dictionary
_CACHED_MASTER_DICT: Optional[List[str]] = None
_CACHED_MASTER_DICTS: Dict[Tuple[bool, bool, int, int], List[str]] = {}
_CACHED_MASTER_FROZENSET: Optional[frozenset[str]] = None
_CACHED_MASTER_FROZENSETS: Dict[Tuple[bool, bool, int, int], frozenset[str]] = {}


def get_master_dictionary(
    include_corpus: bool = True,
    include_references: Any = True,
    min_len: int = 3,
    max_len: int = 24
) -> List[str]:
    """
    Returns the comprehensive, deduplicated master keyword dictionary.
    Prioritizes curated sacred terms and philosophical phrases, followed by
    reference text vocabulary and corpus vocabulary.
    """
    global _CACHED_MASTER_DICT

    # Handle backward-compatible positional arguments: (include_corpus, min_len, max_len)
    if isinstance(include_references, int) and not isinstance(include_references, bool):
        max_len = min_len
        min_len = include_references
        include_references = True
    else:
        include_references = bool(include_references)

    cache_key = (bool(include_corpus), bool(include_references), int(min_len), int(max_len))
    if cache_key in _CACHED_MASTER_DICTS:
        return _CACHED_MASTER_DICTS[cache_key]

    seen = set()
    result = []

    def _add_word(w: str, max_l: Optional[int] = None):
        up = w.upper()
        effective_max = max_l if max_l is not None else max_len
        if up not in seen and min_len <= len(up) <= effective_max:
            seen.add(up)
            result.append(up)

    # 1. Add curated sacred words first
    for w in SACRED_CANONICAL_WORDS:
        _add_word(w)

    # 2. Add philosophical phrases
    for p in generate_philosophical_phrases():
        _add_word(p, max_l=max(max_len, len(p)))

    # 3. Add dynamically harvested reference text vocabulary
    if include_references:
        ref_words = load_reference_text_vocabulary(min_len=min_len, max_len=max_len)
        for w in ref_words:
            _add_word(w)

    # 4. Add dynamically harvested corpus vocabulary
    if include_corpus:
        corpus_words = load_corpus_vocabulary(min_len=min_len, max_len=max_len)
        for w in corpus_words:
            _add_word(w)

    _CACHED_MASTER_DICTS[cache_key] = result
    if include_corpus and include_references and min_len == 3 and max_len == 24:
        _CACHED_MASTER_DICT = result

    return result


def get_master_dictionary_set(
    include_corpus: bool = True,
    include_references: Any = True,
    min_len: int = 3,
    max_len: int = 24
) -> frozenset[str]:
    """
    Returns an immutable frozenset of the deduplicated master keyword dictionary
    for high-performance O(1) membership lookups.
    """
    global _CACHED_MASTER_FROZENSET

    if isinstance(include_references, int) and not isinstance(include_references, bool):
        max_len = min_len
        min_len = include_references
        include_references = True
    else:
        include_references = bool(include_references)

    cache_key = (bool(include_corpus), bool(include_references), int(min_len), int(max_len))
    if cache_key in _CACHED_MASTER_FROZENSETS:
        return _CACHED_MASTER_FROZENSETS[cache_key]

    word_list = get_master_dictionary(
        include_corpus=include_corpus,
        include_references=include_references,
        min_len=min_len,
        max_len=max_len,
    )
    fset = frozenset(word_list)
    _CACHED_MASTER_FROZENSETS[cache_key] = fset
    if include_corpus and include_references and min_len == 3 and max_len == 24:
        _CACHED_MASTER_FROZENSET = fset

    return fset


# =============================================================================
# 3. Comprehensive Mathematical Key Transformations
# =============================================================================

def word_to_rune_indices(word: str) -> List[int]:
    """Convert Latin word to GF(29) Futhorc rune indices."""
    runes = latin_to_rune(word)
    return [INDEX_BY_RUNE[c] for c in runes if c in INDEX_BY_RUNE]


def word_to_prime_mod29(word: str) -> List[int]:
    """Convert Latin word to Gematria Primus prime values mod 29."""
    runes = latin_to_rune(word)
    primes = []
    for c in runes:
        if c in PRIME_BY_RUNE:
            primes.append(PRIME_BY_RUNE[c] % M)
    return primes


def generate_cyclic_rotations(shifts: List[int], word: str, base_label: str = "FORWARD") -> List[Dict[str, Any]]:
    """
    Generate all non-trivial cyclic phase rotations k_{(i + r) mod L} for r in 1..L-1.
    A keyword of length L used in polyalphabetic substitution can begin at any cyclic phase offset.
    """
    L = len(shifts)
    if L < 2:
        return []
    rotations = []
    for r in range(1, L):
        rot_shifts = shifts[r:] + shifts[:r]
        rotations.append({
            "label": f"{base_label}_ROT_{r}",
            "shifts": rot_shifts,
            "word": f"{word}_ROT{r}",
            "length": L,
            "rotation_offset": r,
        })
    return rotations


def generate_all_key_variants(word: str, include_rotations: bool = False) -> List[Dict[str, Any]]:
    """
    Generates all cryptanalytic key shift variants for a given word:
    1. FORWARD: standard Futhorc rune indices
    2. REVERSED: mirror/reverse key
    3. ATBASH: Gematria Primus inverse (28 - x) % 29
    4. REVERSED_ATBASH: mirror of Atbash key
    5. PRIME_MOD29: Gematria Primus prime values mod 29
    6. VARIANT_BEAUFORT: additive inverse (-x) % 29 (for additive / variant Beaufort)
    7. CYCLIC_ROTATIONS: all cyclic phase shifts k_{(i+r) mod L} (if include_rotations=True)
    """
    indices = word_to_rune_indices(word)
    if not indices:
        return []

    variants = []

    # 1. Forward
    variants.append({
        "label": "FORWARD",
        "shifts": indices,
        "word": word,
        "length": len(indices),
    })

    # 2. Reversed
    rev = indices[::-1]
    if rev != indices:
        variants.append({
            "label": "REVERSED",
            "shifts": rev,
            "word": word,
            "length": len(rev),
        })

    # 3. Atbash
    atbash = [(28 - x) % M for x in indices]
    variants.append({
        "label": "ATBASH",
        "shifts": atbash,
        "word": word,
        "length": len(atbash),
    })

    # 4. Reversed Atbash
    rev_atbash = atbash[::-1]
    if rev_atbash != atbash:
        variants.append({
            "label": "REVERSED_ATBASH",
            "shifts": rev_atbash,
            "word": word,
            "length": len(rev_atbash),
        })

    # 5. Gematria Primes Mod 29
    primes_mod = word_to_prime_mod29(word)
    if primes_mod and primes_mod != indices:
        variants.append({
            "label": "PRIME_MOD29",
            "shifts": primes_mod,
            "word": word,
            "length": len(primes_mod),
        })

    # 6. Variant Beaufort (Additive Inverse)
    additive = [(-x) % M for x in indices]
    if additive != indices and additive != atbash:
        variants.append({
            "label": "VARIANT_BEAUFORT",
            "shifts": additive,
            "word": word,
            "length": len(additive),
        })

    # 7. Cyclic phase rotations
    if include_rotations:
        variants.extend(generate_cyclic_rotations(indices, word, base_label="FORWARD"))
        if rev != indices:
            variants.extend(generate_cyclic_rotations(rev, word, base_label="REVERSED"))
        variants.extend(generate_cyclic_rotations(atbash, word, base_label="ATBASH"))

    return variants


def get_rotated_vocabulary(
    page_id: Optional[str] = None,
    limit: int = 60,
    randomize: bool = False,
    seed: Optional[int] = None,
    min_len: int = 3,
    max_len: int = 24,
    filter_tested: bool = True,
) -> List[str]:
    """
    Select candidate words for crib dragging and dictionary sweeps.
    Avoids static repetitive wordlists and redundant compute by:
    1. Vector Database Filtering: Queries the ChromaDB vector database (and SQLite ledger)
       for words already tested on this page, excluding them so no word is tested twice.
    2. Page-Deterministic Rotation: Hashes page_id to an offset in the untested vocabulary pool,
       ensuring different pages explore different segments of the lexicon.
    3. Randomization: Randomly samples from the untested pool when requested.
    4. Fallback: Returns top available untried words when neither is specified.
    """
    all_words = get_master_dictionary(min_len=min_len, max_len=max_len)
    if not all_words:
        all_words = list(SACRED_CANONICAL_WORDS) if SACRED_CANONICAL_WORDS else []

    # Filter out already tested words for this page using the vector database
    available_words = all_words
    if filter_tested and get_tested_words is not None:
        try:
            tested_set = get_tested_words(page=page_id)
            if tested_set:
                available_words = [w for w in all_words if w.upper() not in tested_set]
                if not available_words:
                    available_words = all_words
        except Exception:
            available_words = all_words

    total = len(available_words)
    if randomize:
        rng = random.Random(seed)
        if total <= limit:
            sample = list(available_words)
            rng.shuffle(sample)
            return sample
        return rng.sample(available_words, limit)

    if page_id:
        h = int(hashlib.sha256(str(page_id).encode("utf-8")).hexdigest(), 16)
        start_idx = h % max(1, total)
        rotated = available_words[start_idx:] + available_words[:start_idx]
        return rotated[:limit]

    return available_words[:limit]


# =============================================================================
# 4. Fast Beaufort T-Table Generator
# =============================================================================

def compute_beaufort_t_table(
    indices: List[int],
    m: int,
    unigram_logp: List[float],
) -> List[List[float]]:
    """
    Precomputes the Beaufort T-table where Plaintext = (Key - Ciphertext) mod 29.
    T_beaufort[i][k] = sum_{j} unigram_logp[(k - C_{j*m + i}) mod 29].
    Allows O(m) Beaufort dictionary scoring identical to Vigenère T-tables.
    """
    n = len(indices)
    t_table = [[0.0] * M for _ in range(m)]
    counts = [0] * m

    for pos in range(n):
        col = pos % m
        c = indices[pos] % M
        counts[col] += 1
        for k in range(M):
            p = (k - c) % M
            t_table[col][k] += unigram_logp[p]

    for col in range(m):
        if counts[col] > 0:
            for k in range(M):
                t_table[col][k] /= counts[col]

    return t_table


# =============================================================================
# 5. Fast Prefix and Word Set Indexing for High-Speed Crib Dragging
# =============================================================================

class FastLexiconIndex:
    """O(1) prefix and word membership checker across full master vocabulary."""

    def __init__(self, words: Optional[List[str]] = None):
        self.words = words or get_master_dictionary()
        self.rune_words: frozenset[str] = frozenset()
        self.rune_prefixes: frozenset[str] = frozenset()
        self._build_index()

    def _build_index(self):
        rune_words = set()
        rune_prefixes = set()
        for w in self.words:
            rw = "".join(c for c in latin_to_rune(w) if c in INDEX_BY_RUNE)
            if rw and len(rw) >= 3:
                rune_words.add(rw)
                for k in range(3, len(rw) + 1):
                    rune_prefixes.add(rw[:k])
        self.rune_words = frozenset(rune_words)
        self.rune_prefixes = frozenset(rune_prefixes)

    def is_word(self, rune_str: str) -> bool:
        return rune_str in self.rune_words

    def is_prefix(self, rune_str: str) -> bool:
        return rune_str in self.rune_prefixes


# Global singleton instance for high-performance crib dragging
LEXICON_INDEX = FastLexiconIndex()
