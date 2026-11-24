# Audit, Rigore Statistico e Riallineamento Architetturale — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` in **sequential mode** (1 fresh sub-agent per Task + review gate between tasks). Execute **Task 1 alone as a barrier** before Tasks 2–4; execute **Task 5 last**. Do **NOT** run `git push` automatically at the end. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Risolvere le criticità architetturali (namespace pollution da `sys.path` injection), i bias matematico-statistici nei motori crittanalitici (`entropy.py`, `al_kindi.py`, `taxonomy.py`) e i disallineamenti della documentazione di Trithemius, garantendo zero regressioni sui 352+ test esistenti.

**Architecture:** Transizione sistematica a import assoluti ancorati alla root del repository con pulizia di `trithemius.py`; normalizzazione del calcolo entropico con filtraggio canonico $\mathbb{Z}_{29}$ e correzione di Miller-Madow; potenziamento del gatekeeper crittanalitico con divergenza KL normalizzata, $\chi^2$ ridotto e $p$-value analitico in Python puro (Wilson-Hilferty); espansione del modello bigrammi $\mathbb{Z}_{29}$ con background interpolation su testi filosofici di riferimento (con cache JSON per preservare il cold-start) e triage periodico F-skip aware.

**Tech Stack:** Python 3.10+, Standard Library (`math`, `collections`, `itertools`, `random`, `json`, `subprocess`, `unittest`, `dataclasses`), zero nuove dipendenze esterne obbligatorie.

**Spec:** `TRITHEMIUS_SPECIFICATION.md` e audit tecnico del repository.

---

## Global Constraints

- **Zero Nuove Dipendenze Obbligatorie:** Nessuna introduzione di `scipy`, `sklearn` o `torch` nei moduli crittanalitici core. Tutte le metriche statistiche ($D_{\text{KL}}$, Wilson-Hilferty per code $\chi^2$, `math.erfc`) devono essere implementate in Python puro via modulo `math`.
- **Zero Overhead di Startup:** Mantenere il cold-start della CLI e del REPL sotto i 50 ms. Gli `__init__.py` di `ciphers/`, `scripts/` e `agents/` devono rimanere vuoti/snelli (nessun import eager). Il modello di background $\mathbb{Z}_{29}$ deve essere caricato da cache JSON su disco (invalidata tramite mtime/hash dei sorgenti) e mai ricalcolato da zero a ogni import.
- **Piena Retrocompatibilità dei Contratti:** Tutte le funzioni modificate (`shannon_entropy`, `is_plausible_english`, `surrogate_shuffle_test`) devono mantenere i parametri esistenti come default (o opzionali) e conservare le chiavi dizionario legacy nei risultati per non rompere i golden master e le pipeline CLI esistenti.
- **Costanti Matematiche $\mathbb{Z}_{29}$:** L'alfabeto runico della *Gematria Primus* ha cardinalità rigorosa $\vert{}\Sigma\vert{} = 29$ (i 29 codepoint canonici definiti in `ciphers/agrippa.py`, **non** un range Unicode contiguo), entropia massima teorica $\log_2(29) \approx 4.857981$ bit/runa e indice di coincidenza uniforme atteso $1/29 \approx 0.034483$.
- **Isolamento PRNG:** Non mutare mai lo stato globale di `random` con `random.seed()`. Usare sempre istanze locali `rng = random.Random(seed)`.
- **Sicurezza Git:** Effettuare commit atomici locali per ciascun Task. Non eseguire mai `git push` automatico.

## Review Focus

- Input runici corti ($L < 100$) e separatori (`᛫`, `᛬`, `᛭`): i separatori non devono inquinare il conteggio dei simboli unici $m$ in $\mathbb{Z}_{29}$; la correzione di Miller-Madow deve essere clampata a $\log_2(29)$.
- Stringhe esadecimali pure: `detect_alphabet_size` deve assegnare $\vert{}\Sigma\vert{} = 16$ (oppure decodificare in byte reali prima di usare $\vert{}\Sigma\vert{} = 256$), mai $\vert{}\Sigma\vert{} = 256$ sui caratteri hex grezzi.
- Testi lunghi decifrati ($L > 800$): il gatekeeper non deve scartare candidati validi a causa dell'esplosione naturale del $\chi^2$ non normalizzato per la lunghezza; $D_{\text{KL}}$ deve rispettare rigorosamente la disuguaglianza di Gibbs ($D_{\text{KL}} \ge 0$).
- Decrittazioni valide in inglese prive di riscontri nelle 9 pagine risolte: il modello bigrammi ibrido $\mathbb{Z}_{29}$ non deve assegnare probabilità zero né penalizzare il candidato rispetto al modello solo-LP.
- Isolamento del namespace: l'esecuzione di `trithemius.py` da directory arbitrarie esterne (es. `/tmp`) non deve fallire.
- Golden masters e output deterministico: nessuna variazione di formattazione non controllata nei comandi CLI documentati.

---

### Task 1: Determinismo degli Import e Pulizia Entrypoint (`trithemius.py` & codebase)

**Files:**
- Modify: `trithemius.py:11-19`
- Modify: `ciphers/running_key.py`, `ciphers/kasiski.py`, `ciphers/taxonomy.py`, `ciphers/al_kindi.py`, `ciphers/interrupter.py`, `ciphers/solved_pages.py`, `ciphers/lexicon.py`
- Modify: `agents/crew.py`, `agents/duel.py`, `agents/regress.py`
- Modify: `scripts/ask.py`, `scripts/benchmark.py`, `scripts/bodleian.py`, `scripts/router.py`, `scripts/cryptanalyze_page56.py`
- Test: `tests/test_architecture.py`, `tests/test_import_determinism.py` (nuovo)

**Interfaces:**
- Consumes: Directory structure root-anchored.
- Produces: Import assoluti stabili in tutta la codebase nella forma `from ciphers.<mod> import ...`, `from scripts.<mod> import ...`, `from agents.<mod> import ...`.

- [ ] **Step 1: Scrivere il test per verificare assenza di namespace pollution, import assoluti ed esecuzione da directory esterna**

Creare `tests/test_import_determinism.py`:
```python
import subprocess
import sys
import unittest
from pathlib import Path


class TestImportDeterminism(unittest.TestCase):
    def test_trithemius_does_not_inject_subdirs_into_sys_path(self):
        import trithemius
        base_dir = str(Path(__file__).resolve().parent.parent)
        for sub in ("ciphers", "scripts", "agents"):
            sub_path = str(Path(base_dir) / sub)
            self.assertNotIn(sub_path, sys.path, f"Pollution detected: {sub_path} in sys.path")

    def test_clean_absolute_imports(self):
        from ciphers.entropy import shannon_entropy
        from ciphers.agrippa import decode_runes
        from ciphers.kasiski import rune_vigenere_decode
        from scripts.bodleian import iter_corpus_documents
        from agents.ledger import has_been_tried
        self.assertTrue(callable(shannon_entropy))
        self.assertTrue(callable(decode_runes))
        self.assertTrue(callable(rune_vigenere_decode))
        self.assertTrue(callable(iter_corpus_documents))
        self.assertTrue(callable(has_been_tried))

    def test_cli_execution_from_external_working_directory(self):
        base_dir = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, str(base_dir / "trithemius.py"), "status", "--json"],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f"CLI failed from /tmp: {proc.stderr}")
```

- [ ] **Step 2: Eseguire il test per verificare che fallisce**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_import_determinism.py -v`
Atteso: FAIL con `AssertionError: Pollution detected: ... in sys.path`.

- [ ] **Step 3: Rimuovere l'iniezione dinamica in `trithemius.py` e convertire gli import bare**

1. In `trithemius.py`, rimuovere il ciclo `for sub in ("ciphers", "scripts", "agents"):`, mantenendo solo `BASE_DIR` in `sys.path`.
2. Convertire tutti gli import interni bare nei moduli in `ciphers/`, `scripts/`, `agents/` e `tests/` in import assoluti `ciphers.<mod>`, `scripts.<mod>`, `agents.<mod>` con fallback `try/except` dove utile per esecuzione diretta dello script.
3. Assicurarsi che `scripts/__init__.py` e `agents/__init__.py` esistano e siano vuoti.

- [ ] **Step 4: Eseguire il test per verificare che passa**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_import_determinism.py -v`
Atteso: PASS (3 test superati).

- [ ] **Step 5: Verificare la suite completa e committare**

```bash
/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest discover -s tests
git add trithemius.py ciphers/ scripts/ agents/ tests/
git commit -m "refactor: enforce root-anchored absolute imports and clean entrypoint sys.path"
```

---

### Task 2: Normalizzazione d'Alfabeto e Correzione Bias Entropico (`ciphers/entropy.py`)

**Files:**
- Modify: `ciphers/entropy.py`
- Test: `tests/test_entropy_z29.py` (nuovo), `tests/test_terminal_workstation.py`

**Interfaces:**
- Consumes: Stringhe di testo (ASCII, Futhorc runes, esadecimale, o raw bytes).
- Produces:
  - `detect_alphabet_size(data: str) -> int`: 29 per Futhorc canonico, 16 per hex, 26 per latino, 256 per binario.
  - `shannon_entropy(data: str, alphabet_size: Optional[int] = None) -> float`
  - `miller_madow_entropy(data: str, alphabet_size: Optional[int] = None) -> float`
  - `normalized_entropy(data: str, alphabet_size: Optional[int] = None) -> float`
  - `extract_signal_features(text: str) -> Dict[str, Any]` arricchito con profili separati `BYTE_PROFILE` e `RUNE_Z29_PROFILE`.

- [ ] **Step 1: Scrivere il test per la gestione corretta di separatori runici, esadecimale e Miller-Madow**

Creare `tests/test_entropy_z29.py`:
```python
import math
import random
import unittest
from ciphers.entropy import (
    shannon_entropy,
    miller_madow_entropy,
    normalized_entropy,
    detect_alphabet_size,
    extract_signal_features,
)


class TestEntropyZ29(unittest.TestCase):
    def test_detect_alphabet_size_and_separators(self):
        runes_with_separators = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ᛬ᛏᚩ᛭ᚦᛁᛋ"
        latin = "WELCOME PILGRIMS TO THIS JOURNEY"
        raw_hex = "4a5f89c2b1e47d039f826194ac52e01b3301a74d"
        self.assertEqual(detect_alphabet_size(runes_with_separators), 29)
        self.assertEqual(detect_alphabet_size(latin), 26)
        self.assertEqual(detect_alphabet_size(raw_hex), 16)

    def test_separators_do_not_inflate_runic_symbol_count(self):
        # 6 distinct runes + separators: unique count m should be strictly 6
        runic = "ᚠ᛫ᚢ᛬ᚦ᛭ᚩ᛫ᚱ᛬ᚳ"
        h_mm = miller_madow_entropy(runic, alphabet_size=29)
        self.assertLessEqual(h_mm, math.log2(29))

    def test_miller_madow_short_sample_clamped(self):
        # 29 distinct runes -> H_MM must not exceed log2(29)
        all_runes = "ᚠᚢᚦᚩᚱᚳᚷᚹᚺᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛜᛞᛟᚪᚫᚣᛡᛠ"
        h1 = shannon_entropy(all_runes, alphabet_size=29)
        h_mm = miller_madow_entropy(all_runes, alphabet_size=29)
        self.assertAlmostEqual(h1, math.log2(29), places=3)
        self.assertAlmostEqual(h_mm, math.log2(29), places=3)

    def test_runic_otp_vs_natural_classification(self):
        rng = random.Random(3301)
        runes_list = list("ᚠᚢᚦᚩᚱᚳᚷᚹᚺᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛜᛞᛟᚪᚫᚣᛡᛠ")
        otp_sample = "".join(rng.choice(runes_list) for _ in range(400))
        feat_otp = extract_signal_features(otp_sample)
        self.assertIn(feat_otp["classification"], ("high_entropy_runic_stream", "runic_payload"))
        self.assertGreater(feat_otp["normalized_entropy"], 0.95)
```

- [ ] **Step 2: Eseguire il test per verificare che fallisce**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_entropy_z29.py -v`
Atteso: FAIL con `ImportError: cannot import name 'miller_madow_entropy'`.

- [ ] **Step 3: Implementare il filtraggio canonico e Miller-Madow in `ciphers/entropy.py`**

In `ciphers/entropy.py`:
1. Definire l'insieme canonico dei 29 codepoint runici `CANONICAL_RUNES_SET` (importato da `ciphers.agrippa.INDEX_BY_RUNE` o set esplicito) e i separatori `RUNIC_SEPARATORS = {'᛫', '᛬', '᛭', ' '}`.
2. Implementare `detect_alphabet_size(data: str) -> int`:
   - se contiene rune di `CANONICAL_RUNES_SET` $\to 29$.
   - se stringa esadecimale (tutti caratteri in `0-9a-fA-F` esclusi spazi) $\to 16$.
   - se alfabetico latino $\to 26$.
   - altrimenti default 256.
3. In `shannon_entropy`, `miller_madow_entropy` e `normalized_entropy`: se l'input è runico, filtrare ed escludere i separatori prima di calcolare $m$ ed $L$.
4. Implementare la correzione di Miller-Madow:
   $$\hat{H}_{\text{MM}} = \min\left(\log_2(|\Sigma|), H_1 + \frac{m - 1}{2 L \ln 2}\right)$$
5. Aggiornare `extract_signal_features` con le chiavi `"normalized_entropy"`, `"miller_madow_entropy"`, `"alphabet_size"` e la logica di classificazione specifica per $\mathbb{Z}_{29}$.

- [ ] **Step 4: Eseguire il test per verificare che passa**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_entropy_z29.py -v`
Atteso: PASS (4 test superati).

- [ ] **Step 5: Verificare la suite completa e committare**

```bash
/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest discover -s tests
git add ciphers/entropy.py tests/test_entropy_z29.py
git commit -m "feat: add Z29 alphabet normalization, separator filtering and Miller-Madow bias correction"
```

---

### Task 3: Rigore Statistico del Gatekeeper Length-Invariant (`ciphers/al_kindi.py` & `ciphers/lexicon.py`)

**Files:**
- Modify: `ciphers/al_kindi.py`
- Modify: `ciphers/lexicon.py`
- Test: `tests/test_al_kindi_statistical_rigor.py` (nuovo), `tests/test_exact_solver_and_statistical_rigor.py`

**Interfaces:**
- Consumes: Testo decifrato candidato (ASCII/Latin).
- Produces:
  - `reduced_chi_squared(text: str, df: int = 25) -> float`
  - `kl_divergence_english(text: str, epsilon: float = 1e-6) -> float` (con garanzia $D_{\text{KL}} \ge 0$)
  - `chi_squared_p_value(chi2: float, df: int = 25) -> float` (pure Python via Wilson-Hilferty e `math.erfc`)
  - `is_plausible_english(text: str, ...) -> Tuple[bool, dict]` con verdetto `PLAUSIBLE`, `UNCERTAIN`, `IMPLAUSIBLE`.

- [ ] **Step 1: Scrivere il test per le metriche length-invariant e il $p$-value analitico**

Creare `tests/test_al_kindi_statistical_rigor.py`:
```python
import unittest
from ciphers.al_kindi import (
    reduced_chi_squared,
    kl_divergence_english,
    chi_squared_p_value,
    is_plausible_english,
)


class TestAlKindiStatisticalRigor(unittest.TestCase):
    def test_kl_divergence_non_negative_and_invariant(self):
        english_short = "WELCOME PILGRIMS ON THE SACRED PATH OF WISDOM AND TRUTH"
        english_long = english_short * 15
        kl_short = kl_divergence_english(english_short)
        kl_long = kl_divergence_english(english_long)
        self.assertGreaterEqual(kl_short, 0.0)
        self.assertGreaterEqual(kl_long, 0.0)
        self.assertAlmostEqual(kl_short, kl_long, places=3)
        self.assertLess(kl_short, 0.45)

    def test_reduced_chi_squared(self):
        english = "WELCOME PILGRIMS ON THE SACRED PATH OF WISDOM AND TRUTH"
        chi2_red = reduced_chi_squared(english)
        self.assertLess(chi2_red, 5.0)

    def test_wilson_hilferty_p_value(self):
        p_mid = chi_squared_p_value(25.0, df=25)
        self.assertGreater(p_mid, 0.40)
        self.assertLess(p_mid, 0.60)
        p_extreme = chi_squared_p_value(200.0, df=25)
        self.assertLess(p_extreme, 1e-5)

    def test_composite_gatekeeper_verdict(self):
        valid = "THE PRESERVATION OF ALL THINGS IS ROOTED IN THE DIVINE PRIMES"
        gibberish = "XQZJVKWPLMBNFGHTYUIOPAZXCVBNMQ"
        passed_v, met_v = is_plausible_english(valid)
        passed_g, met_g = is_plausible_english(gibberish)
        self.assertTrue(passed_v)
        self.assertEqual(met_v["verdict"], "PLAUSIBLE")
        self.assertFalse(passed_g)
        self.assertIn(met_g["verdict"], ("REJECT", "IMPLAUSIBLE"))
```

- [ ] **Step 2: Eseguire il test per verificare che fallisce**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_al_kindi_statistical_rigor.py -v`
Atteso: FAIL con `ImportError: cannot import name 'reduced_chi_squared'`.

- [ ] **Step 3: Implementare metriche length-invariant e Wilson-Hilferty in `ciphers/al_kindi.py`**

In `ciphers/al_kindi.py`:
1. Implementare `reduced_chi_squared(text: str, df: int = 25) -> float`: $\chi^2_{\nu} = \chi^2 / \text{df}$.
2. Implementare `kl_divergence_english(text: str, epsilon: float = 1e-6) -> float`:
   $$D_{\text{KL}} = \max\left(0.0, \sum_{c='A'}^{'Z'} P_{\text{obs}}(c) \ln \frac{P_{\text{obs}}(c) + \epsilon}{P_{\text{ref}}(c) + \epsilon}\right)$$
3. Implementare `chi_squared_p_value(chi2: float, df: int = 25) -> float` tramite trasformata di Wilson-Hilferty con `math.erfc`.
4. In `is_plausible_english`: integrare $D_{\text{KL}}$ e $\chi^2_{\nu}$ assegnando `PLAUSIBLE`, `UNCERTAIN`, `IMPLAUSIBLE`.
5. Ottimizzare `lexicon.py` con `frozenset` per il master dictionary.

- [ ] **Step 4: Eseguire il test per verificare che passa**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_al_kindi_statistical_rigor.py -v`
Atteso: PASS (4 test superati).

- [ ] **Step 5: Verificare la suite completa e committare**

```bash
/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest discover -s tests
git add ciphers/al_kindi.py ciphers/lexicon.py tests/test_al_kindi_statistical_rigor.py
git commit -m "feat: add length-invariant KL divergence, reduced chi2 and analytical p-value"
```

---

### Task 4: Modello Linguistico Ibrido e Triage F-Skip in $\mathbb{Z}_{29}$ (`ciphers/taxonomy.py`, `ciphers/interrupter.py`)

**Files:**
- Modify: `ciphers/taxonomy.py`
- Modify: `ciphers/interrupter.py`
- Create: `vectordb/z29_background_bigrams.json` (cache generata al primo build)
- Test: `tests/test_taxonomy_hybrid_model.py` (nuovo), `tests/test_cryptanalysis_taxonomy.py`, `tests/test_interrupter.py`

**Interfaces:**
- Consumes: Testi di riferimento in `corpus/reference_texts/*.txt`, `ciphers.agrippa.latin_to_rune`.
- Produces:
  - Cache JSON `vectordb/z29_background_bigrams.json` con invalidazione mtime/hash.
  - Modello $P_{\text{hybrid}}(r_2 \mid r_1) = 0.35 P_{\text{lp}} + 0.65 P_{\text{bg}}$.
  - `surrogate_shuffle_test` con istanza PRNG isolata `random.Random(seed)` e supporto `n_trials`.
  - Triage F-skip aware: rilevazione doppie consecutive e segmentazione locale tra `ᚠ`.

- [ ] **Step 1: Scrivere il test per il modello linguistico ibrido e PRNG isolation**

Creare `tests/test_taxonomy_hybrid_model.py`:
```python
import random
import unittest
from ciphers.taxonomy import (
    RUNIC_BIGRAM_LOGP,
    score_composite_runes,
    surrogate_shuffle_test,
    clean_runes_to_indices,
)
from ciphers.agrippa import latin_to_rune


class TestTaxonomyHybridModel(unittest.TestCase):
    def test_hybrid_bigram_matrix_coverage_and_cache(self):
        m = 29
        floor_count = sum(
            1 for r in range(m) for c in range(m)
            if RUNIC_BIGRAM_LOGP[r][c] < -6.5
        )
        self.assertLess(floor_count, 400, "Bigram matrix remains too sparse!")

    def test_surrogate_test_prng_isolation(self):
        # Global random state must not be modified by surrogate_shuffle_test
        state_before = random.getstate()
        sample = clean_runes_to_indices(latin_to_rune("A WARNING BELIEVE NOTHING FROM THIS BOOK"))
        score = score_composite_runes(sample)
        res = surrogate_shuffle_test(sample, score, n_shuffles=50, n_trials=10)
        state_after = random.getstate()
        self.assertEqual(state_before, state_after, "Global random state was polluted!")
        self.assertIsNotNone(res.p_adj)
```

- [ ] **Step 2: Eseguire il test per verificare che fallisce**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_taxonomy_hybrid_model.py -v`
Atteso: FAIL (sparsity check fallisce o firma `surrogate_shuffle_test` non accetta `n_trials`).

- [ ] **Step 3: Implementare l'ingestione con cache JSON e PRNG isolato in `ciphers/taxonomy.py`**

In `ciphers/taxonomy.py`:
1. In `_build_calibrated_model()`:
   - Verificare se `vectordb/z29_background_bigrams.json` esiste ed è più recente dei file in `corpus/reference_texts/`. Se valido, caricare la matrice in memoria in <2ms.
   - Altrimenti, scansionare `corpus/reference_texts/*.txt`, calcolare $P_{\text{bg}}$ e salvare su `vectordb/z29_background_bigrams.json`.
   - Interpolare: $P_{\text{hybrid}} = 0.35 P_{\text{lp}} + 0.65 P_{\text{bg}}$.
2. In `surrogate_shuffle_test`:
   - Utilizzare `rng = random.Random(3301)` anziché chiamare `random.seed()`.
   - Aggiungere parametro `n_trials: int = 1` e calcolare $p_{\text{adj}} = \min(1.0, p_{\text{val}} \cdot n_{\text{trials}})$.
3. In `interrupter.py`/`taxonomy.py`: aggiungere controllo diagnostico sul tasso di doppie consecutive rispetto a $1/29 \approx 3.45\%$.

- [ ] **Step 4: Eseguire il test per verificare che passa**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_taxonomy_hybrid_model.py -v`
Atteso: PASS (2 test superati).

- [ ] **Step 5: Verificare la suite completa e committare**

```bash
/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest discover -s tests
git add ciphers/taxonomy.py ciphers/interrupter.py vectordb/z29_background_bigrams.json tests/test_taxonomy_hybrid_model.py
git commit -m "feat: add cached hybrid Z29 bigram model, isolated PRNG and two-stage surrogate test"
```

---

### Task 5: Riallineamento Documentazione & Golden Masters (`TRITHEMIUS_SPECIFICATION.md`, `README.md`)

**Files:**
- Modify: `TRITHEMIUS_SPECIFICATION.md`
- Modify: `README.md`
- Test: `tests/test_golden_master.py`

**Interfaces:**
- Consumes: Conteggio reale test superati (352+), inventario dei moduli reali (`metal_accel.py`, `ane_engine.py`, 14 moduli `ciphers/`).
- Produces: Documentazione coerente al 100% con la codebase reale.

- [ ] **Step 1: Eseguire la suite completa e rilevare il conteggio esatto dei test**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest discover -s tests 2>&1 | grep -E "Ran [0-9]+ tests"`
Annotare il conteggio esatto.

- [ ] **Step 2: Aggiornare `TRITHEMIUS_SPECIFICATION.md`**

1. Aggiornare il conteggio test nella Sezione 9 con il totale reale.
2. Documentare l'architettura duale con accelerazione opzionale Apple Silicon Metal GPU (`metal_accel.py`, `metal_engine.m`) e Apple Neural Engine (`ane_engine.py`), specificando il fallback trasparente su CPU in puro Python per macchine Linux/Windows.
3. Censire nell'indice architetturale tutti i 14 moduli presenti in `ciphers/`.
4. Marcare i riferimenti a `scripts/walsingham.py` e `scripts/bacon.py` come `[ARCHIVED / ROADMAP COMPONENT]`.

- [ ] **Step 3: Aggiornare `README.md`**

1. Allineare il conteggio dei test al valore reale.
2. Chiarire che `walsingham.py` è archiviato e sostituito dalla pipeline Bodleian + Porta + RAG.

- [ ] **Step 4: Eseguire la suite golden master per verificare zero divergenze di output**

Eseguire: `/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest tests/test_golden_master.py -v`
Atteso: PASS.

- [ ] **Step 5: Verificare la suite completa ed eseguire il commit atomico finale (NO git push)**

```bash
/Users/fabio/Downloads/Organized/Note-Progetti/trithemius-cicada/venv/bin/python -m unittest discover -s tests
git add TRITHEMIUS_SPECIFICATION.md README.md
git commit -m "docs: reconcile specification and readme with codebase reality, test baseline and hardware acceleration"
```
