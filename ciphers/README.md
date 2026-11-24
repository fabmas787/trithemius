# Cipher Tools

Standalone, dependency-free Python cryptography modules for Liber Primus work.
Each is named for the historical figure whose work it echoes.

## agrippa.py — Gematria Primus & Sacred Math
Named for Heinrich Cornelius Agrippa (Renaissance occultist, numerology/gematria).
Full mapping of the 29 Futhorc runes with indices (0..28) and official prime values (2..109).

- Rune <-> Latin transliteration
- Gematria prime sum calculation (per-word and total)
- Rune Atbash inversion (index -> 28 - index)
- Sacred arithmetic: Euler's totient function \(\phi(n)\), primality tests, prime factorizations

```python
from agrippa import (
    decode_runes, latin_to_rune, rune_to_prime,
    gematria_prime_sum, gematria_word_sums, rune_atbash, euler_totient
)

decode_runes("ᚹᛖᛚᚳᚩᛗᛖ")         # -> "WELCOME"
gematria_prime_sum("ᚹᛖᛚᚳᚩᛗᛖ")   # -> 317 (sum of prime values)
rune_atbash("ᚠᚢᚦ")                # -> Atbash inverted runes
euler_totient(3301)               # -> 3300
```

## kasiski.py — Vigenère Solvers & Keystreams
Named for Friedrich Kasiski, who first published a general method for breaking
the Vigenère cipher via key-length analysis.

Supports both:
1. **Modulo-29 Rune Vigenère**: operates directly on the 29 Futhorc runes, matching known solved pages (e.g. Page 0, Page 56).
2. **Keystream generators**: Prime number sequences, Fibonacci sequences, Euler totient sequences.
3. **Classical A-Z (mod 26)**: per-column chi-squared key cracking, IoC, and Friedman's test.

```python
from kasiski import (
    rune_vigenere_decode, rune_vigenere_encode,
    generate_primes, generate_fibonacci, rune_index_of_coincidence
)

# Decode runes with keyword key
rune_vigenere_decode("ᚢᛠᛝᛋᛇᚠᚳ᛫ᛁᚱᚢᚹᛉᛗᚠᚦ", key="DIVINITY")

# Decode runes with prime keystream
primes = generate_primes(30)
rune_vigenere_decode(ciphertext_runes, key=primes)
```

## al_kindi.py — Statistical Cryptanalysis & Plausibility Gate
Named for Al-Kindi, the 9th-century polymath who invented frequency analysis.

Filters out noise, anagrams, and motivated false positives:
- **Chi-squared test**: Goodness of fit against English letter distributions.
- **Quadgram and trigram log-likelihood scoring**: Evaluates grammatical and linguistic plausibility.
- **Dictionary validation**: Checks ratio of recognized vocabulary words.
- **`is_plausible_english` & `rank_candidates`**: Automates ranking of brute-force outputs.

```python
from al_kindi import is_plausible_english, rank_candidates

passed, metrics = is_plausible_english("WELCOME PILGRIMS ON THE SACRED PATH")
# metrics -> {'passed': True, 'chi_squared': 10.73, 'ngram_score': 0.2467, 'word_ratio': 1.0}
```
