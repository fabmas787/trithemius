# Trithemius — Liber Primus Research Workstation

A local-first, terminal-centric RAG research assistant and $\text{GF}(29)$ cryptanalysis workstation for investigating the Cicada 3301 mystery and the *Liber Primus*.
Runs locally using Ollama (**SparkLLM/Spark-X2.5-4B** or **DeepSeek-Coder-V2-Lite MoE**) + ChromaDB, or with **0 VRAM** via cloud LLM providers (Groq, OpenAI, Google Gemini, Anthropic Claude, OpenRouter) and a pure-Python BM25 lexical fallback.

Each core module is named after a historical cryptographer, philosopher, or scholar whose work matches its purpose:
- **Trithemius** (Johannes Trithemius, 1462–1516): Father of Western steganography & cryptography — Unified terminal workstation (`trithemius.py`) & RAG orchestrator.
- **Agrippa** (Heinrich Cornelius Agrippa, 1486–1535): Occult philosopher & numerologist — 29-rune Gematria Primus & sacred number theory.
- **Kasiski** (Friedrich Kasiski, 1805–1881): Pioneer of polyalphabetic cryptanalysis — Modulo-29/26 Vigenère solvers & keystream generators.
- **Al-Kindi** (Abu Yusuf Al-Kindi, 801–873): Inventor of frequency analysis — Length-invariant KL divergence, reduced $\chi^2_\nu$, and n-gram statistical gatekeeper.
- **Zimmermann** (Phil Zimmermann, b. 1954): Creator of PGP — Native RFC 4880 v4 OpenPGP + RSA signature verification (`7A35090F`).
- **Bodley** (Sir Thomas Bodley, 1545–1613): Founder of the Bodleian Library — Page-aware semantic chunking & ChromaDB vector ingestion.
- **Porta** (Giambattista della Porta, 1535–1615): Renaissance author of *De Furtivis Literarum Notis* — Corpus classifier, standardized renaming & SHA-256 deduplication.
- **Walsingham** (Sir Francis Walsingham, 1532–1590) `[ARCHIVED]`: Elizabethan spymaster — Autonomous web scout (archived and superseded by the deterministic offline **Bodleian + Porta + RAG** pipeline).
- **Bacon** (Roger Bacon, 1220–1292) `[ARCHIVED]`: Medieval empiricist — Live web search context injection (archived; `/web` now queries the curated offline corpus via RAG).

---

## Architecture Overview

```text
[Master Transcript & Curated Corpus] ──► [scripts/split_master_transcript.py]
                                                          │
                                                          ▼
                                                 [corpus/ Directory]
                                                          │
                         ┌────────────────────────────────┼────────────────────────────────┐
                         ▼                                ▼                                ▼
               [scripts/porta.py]              [scripts/bodleian.py]               [ciphers/opsec.py]
          (Classify & Dedup, 0 VRAM)      (Entropy Chunking & ChromaDB)       (PGP 7A35090F Verification)
                         │                                │                                │
                         └────────────────────────────────┼────────────────────────────────┘
                                                          ▼
                                           [vectordb/ (ChromaDB & SQLite)]
                                                          │
                                                          ▼
                                    [Trithemius Terminal Workstation & TUI]
                                     (trithemius.py / workstation/ / ciphers/)
                                       Local Ollama or 0-VRAM Cloud Providers
```

> [!NOTE]
> **100% Offline & Deterministic Pipeline**: Legacy web scraping (`scripts/walsingham.py`) and live web search injection (`scripts/bacon.py`) are archived and replaced by the deterministic offline **Bodleian + Porta + RAG** pipeline. The workstation `/web` command is a direct alias for querying the indexed offline corpus via RAG, ensuring OpSec, zero network latency, and reproducible results.

### Key Components
1. **`trithemius.py` & `workstation/`** — Unified terminal cryptanalytic workstation featuring an interactive **Textual TUI Dashboard** (`--tui`), a readline **REPL**, direct **CLI subcommands**, and machine-readable **`--json`** output across 37 registered commands (`workstation/commands.py`).
2. **`corpus/`** — Curated Liber Primus rune transcripts (`page_XX_runes.md`), solved page references (`page_XX_solved.md`), page metadata index (`pages_index.json`), and philosophical reference literature (`reference_texts/`).
3. **`wordlists/`** — Deduplicated uppercase English wordlists (`00_sacred_lexicon.txt`, `01_english_dictionary.txt`, `02_english_ngrams_extra.txt`) totaling **1,248,755** words via `get_extended_dictionary()` for `/key-sweep` and T-table sweeps.
4. **`scripts/split_master_transcript.py`** — Partitions the master Liber Primus runic transcription into standardized per-page rune files while preserving delimiters.
5. **`scripts/porta.py`** — Corpus librarian (page number detection, standardized file naming, and SHA-256 deduplication at 0% VRAM).
6. **`scripts/bodleian.py`** — Paragraph-boundary semantic chunking, Futhorc rune annotation, and ChromaDB vector ingestion (`nomic-embed-text`).
7. **`scripts/ask.py` & `scripts/router.py`** — Hybrid RAG query engine (ChromaDB dense vectors + zero-VRAM BM25 lexical fallback) with deterministic routing for exact page and Gematria lookups.
8. **`scripts/providers.py` & `config.py`** — Multi-provider streaming inference supporting local/remote **Ollama**, **Groq**, **OpenAI**, **Google Gemini**, **Anthropic Claude**, and **OpenRouter**.
9. **`scripts/normalize_runes.py`** — Futhorc rune normalization (`᛫`, `᛬`, `᛭`) and OCR cleanup.
10. **`scripts/solve_canonical.py`** — Standalone solver and formal verifier for all 9 historically solved Liber Primus pages.
11. **`scripts/totient_stream.py`** — Standalone encoder/decoder for the Prime Totient Stream Cipher ($\phi(p) = p - 1 \pmod{29}$) with cleartext Fehu pause (`--f-skip`) support.
12. **`scripts/cryptanalyze_page56.py`** — Exhaustive cascade solver for Page 56 / 73 (offset Euler totients, Pisano orbits in $\mathbb{F}_{29}$, syntactic interrupter Vigenère, and SQLite ledger logging).
13. **`scripts/benchmark.py`** — Microsecond-precision latency benchmarking, baseline comparison, and `cProfile` hotspot profiling.
14. **`ciphers/` (28 modules)** — Complete $\text{GF}(29)$ cryptanalysis suite:
    - `agrippa.py`, `kasiski.py`, `al_kindi.py`, `solved_pages.py`, `entropy.py`, `opsec.py`, `zimmermann.py`, `provenance.py`
    - `taxonomy.py` (10-stage automated cascade solver), `solvers_ext.py` (selective Fehu-skip DP, autokey, columnar transposition, rail-fence, MASC simulated annealing, Trithemius progressive/word-reset sweeps)
    - `unicity.py`, `sprt.py`, `difference.py`, `lagcoinc.py`, `interrupter.py`, `running_key.py`, `affine.py`, `fingerprint.py`, `container.py`, `layout.py`, `lexicon.py`, `keymap.py`, `hash_hunt.py`, `telemetry.py`
    - **Hardware Acceleration**: `metal_accel.py` (`metal_engine.m`, Apple Silicon Metal GPU), `ane_engine.py` (Apple Neural Engine via CoreML), and `native_accel.py` (`native_engine.c`, Tier-2 C99/clang GIL-free kernels), all with transparent pure-Python/NumPy CPU fallbacks.
15. **`agents/`** — Multi-agent orchestration (`crew.py`, `duel.py`), Bayesian epistemic evidence ledger (`evidence.py`, `ledger.py`), and automated regression runner (`regress.py`).

---

## Installation by Operating System

Trithemius includes **1-click automated setup and launch scripts** for both **macOS/Linux** and **Windows**, which verify prerequisites, create a `venv` virtual environment, and install all dependencies from `requirements.txt`.

### macOS & Linux (Apple Silicon, Intel, or x86_64)

#### 1. Prerequisites
- **Python 3.10 – 3.13** (Python 3.11 recommended via Homebrew on macOS for optimal compatibility):
  ```bash
  brew install python@3.11
  ```
- **NumPy $\ge 1.24.0$** (included in `requirements.txt`): Enables Apple Silicon Metal GPU acceleration, Apple Neural Engine (CoreML), and FFT lag-coincidence calculations.
- **Ollama** (optional for local inference; not required if using cloud API keys):
  ```bash
  brew install ollama
  ollama serve &
  ```

#### 2. Automated Setup (1-Click)
From the project root directory, run:
```bash
./install.sh
```
The script will:
- Locate a compatible Python interpreter (3.10–3.13).
- Create the isolated virtual environment `venv/`.
- Install all dependencies from `requirements.txt`.
- Pull the default Ollama models (`nomic-embed-text` and `SparkLLM/Spark-X2.5-4B`) if Ollama is running locally (pass `--no-pull` or `--cloud` to skip model downloads).

#### 3. Launch the Workstation
```bash
./start.sh
```

---

### Windows (10/11 — NVIDIA or CPU)

#### 1. Prerequisites
- **Python $\ge 3.10$**: Download the installer from [python.org/downloads](https://www.python.org/downloads/).
  > **Important**: During Python installation, check **"Add python.exe to PATH"**.
- **Ollama for Windows** (optional for local inference): Download from [ollama.com/download/windows](https://ollama.com/download/windows).

#### 2. Automated Setup (1-Click)
Double-click `install.bat` (or run `install.bat` in Command Prompt / PowerShell). It detects Python, creates `venv\`, installs `requirements.txt`, and pulls the Ollama models if available.

#### 3. Launch the Workstation
Double-click `start.bat` (or run `start.bat` from Command Prompt / PowerShell).

---

### Manual Installation (Cross-Platform)

```bash
# 1. Create and activate a virtual environment (Python 3.10 - 3.13)
# macOS/Linux:
python3 -m venv venv
source venv/bin/activate

# Windows (CMD or PowerShell):
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Pull Ollama models (optional if using cloud providers)
ollama pull nomic-embed-text
ollama pull SparkLLM/Spark-X2.5-4B
# Optional complementary MoE model:
ollama pull deepseek-coder-v2:16b

# 4. Launch the Terminal Workstation
python3 trithemius.py
```

> [!IMPORTANT]
> **Python & Hardware Acceleration Notes**:
> - **Python $\ge 3.10$**: The codebase uses modern generic type hints (e.g. `frozenset[str]`) and native modular inverse arithmetic (`pow(base, -1, mod)`).
> - **NumPy $\ge 1.24.0$**: Enables Apple Silicon Metal GPU compute shaders, Apple Neural Engine (CoreML) scoring, and FFT autocorrelation/lag-coincidence. Without NumPy, pure-Python standard library fallbacks are used automatically.
> - **C99 Native Acceleration**: `ciphers/native_accel.py` compiles `ciphers/native_engine.c` with `clang` for GIL-free $\mathbb{Z}_{29}$ running-key scans and sliding-window entropy, falling back to Python/NumPy if unavailable.

---

## Guide 1: Using the Terminal Workstation (`trithemius.py`)

Trithemius operates as a high-performance **Terminal Workstation** with three interface modes:
1. **Textual TUI Dashboard** (auto-launched on interactive TTYs when `textual` is installed, or forced with `--tui`): 3-pane split interface with live telemetry header, Console & Assistant / Solver & Live Calculation Trace tabs, and command bar with inline auto-completion.
2. **Classic Interactive REPL** (forced with `--no-tui`): `trithemius>` prompt with GNU readline tab-completion and command history.
3. **Direct CLI & Headless JSON**: Execute any subcommand directly from the shell, optionally with `--json` for machine-readable output.

```bash
python3 trithemius.py                # Launch TUI (or REPL if non-TTY / --no-tui)
python3 trithemius.py --no-tui       # Launch classic text REPL
python3 trithemius.py status --json  # Direct CLI with JSON output
```

### Workstation Commands (37 Registered Commands)

- **Knowledge & Corpus Navigation**:
  - `/ask [--fresh] <query>`: Hybrid dense vector (ChromaDB) + zero-VRAM BM25 retrieval with deterministic routing for page transcripts and Gematria lookups. (Free text without a `/` prefix is also routed here.)
  - `/web <query>`: Query the curated offline Liber Primus corpus via RAG (offline alias; no external network calls).
  - `/page <page_num>`: Inspect metadata, raw Futhorc runes, and English transcription preview for a page (e.g. `/page 56`, `/page 00`, `/page 73`).
  - `/organize`: Deduplicate and classify corpus files via Porta (`0%` VRAM).
  - `/ingest`: Chunk and embed corpus documents into ChromaDB via Bodleian.

- **Gematria & Classical Ciphers**:
  - `/gematria <runes_or_latin>`: Bidirectional Latin/Futhorc transliteration, sacred prime sum (2..109), primality test, prime factorization, Euler totient $\phi(n)$, and Atbash reflection.
  - `/atbash <target> [--shift N]`: Atbash reflection in $\mathbb{F}_{29}$ with optional Caesar shift (e.g. `/atbash 00`, `/atbash 06 --shift 3` for Koan 1).
  - `/vigenere <enc|dec> <target> <key> [--f-skip] [--skip-indices ...]`: Modulo-29 (Futhorc) or Modulo-26 (Latin) Vigenère cipher with cleartext Fehu keystream pauses (`--f-skip`) and Al-Kindi statistical verification.
  - `/totient-stream` (alias `/totient`) `<enc|dec> <target> [--offset N] [--f-skip] [--skip-indices ...]`: Prime Totient Stream Cipher ($\phi(p_k) = p_k - 1 \pmod{29}$) with offset and Fehu pause support (e.g. `/totient-stream dec 71 --f-skip`).
  - `/solve [page_id|all]`: Execute and verify all 9 canonical solved Liber Primus pages (e.g. `/solve welcome`, `/solve 71`, `/solve all`).

- **Advanced Cryptanalysis & Statistical Rigor**:
  - `/crack <target> [--deep] [--compound] [--randomize] [--rotations] [--f-skip] [--extended-dict] [--crib-limit N] [--top-k N] [--seed N] [--no-metal] [--no-ane]`: 10-stage $\text{GF}(29)$ cascade solver (statistical triage, consensus period detection, separable T-table optimization, dictionary & Metal GPU compound sweeps, deterministic streams, Berlekamp-Massey crib dragging, CoreML ANE reranking, `--deep` affine/autokey/cross-page sweeps, and Monte Carlo surrogate verification).
  - `/key-sweep` (alias `/keysweep`) `<target> [--wordlist FILE] [--mode sub|add|beaufort] [--period N] [--f-skip] [--rotations] [--variants] [--top-k N] [--force] [--no-metal]`: Batch-test large wordlists or the full **1,248,755-word** extended dictionary using Metal GPU acceleration and compressed `TestedKeySet` deduplication in `vectordb/ledger.sqlite3`.
  - `/triage <target>`: Statistical triage classifying cipher family (unigram IC, normalized $\kappa = 29 \cdot \text{IC}$, bigram IC, conditional entropy).
  - `/period <target> [max_period]`: Consensus key-length estimation combining Kasiski weighted GCD voting, difference periodogram comb filtering, and column IoC.
  - `/crib <target> <crib_word>`: Crib dragging with $\mathbb{F}_{29}$ Berlekamp-Massey linear complexity and $O(1)$ stream hash bank matching.
  - `/layout [target|calibrate]`: Layout side-channel mutual information analysis (word/line lengths, separators `᛫`, `᛬`, `᛭`, Fehu positions) with Miller-Madow bias correction and Besag-Clifford Monte Carlo null testing.
  - `/running-key <page> <text_file> [--mode sub|add|beaufort] [--f-skip] [--offset N]`: $\text{GF}(29)$ running-key decryption against reference literature.
  - `/running-key-scan <page> [--ref-dir DIR] [--step N] [--top-k N] [--force] [--f-skip]`: Sliding-window scan across all works in `corpus/reference_texts/` with $O(1)$ `batch_digest` deduplication.
  - `/lexicon [phrases|words|extended|all] [--limit N]`: Inspect curated philosophical phrases, master vocabulary, and the extended dictionary.

- **OpSec, Epistemic Ledger, Configuration & Telemetry**:
  - `/opsec <target>`: Authenticate Cicada 3301 PGP signature (`7A35090F`), inspect container headers, and compute alphabet-aware Shannon entropy $H(X)$.
  - `/ledger [page_id_or_word]`: Inspect persistent SQLite and ChromaDB attempt records, deduplication counts, and cosine nearest-neighbor hypothesis search.
  - `/hardware` (aliases `/gpu`, `/metal`, `/ane`): Query and benchmark Apple Silicon Metal GPU throughput (M keys/sec) and Apple Neural Engine status.
  - `/explain` (alias `/trace`): Inspect step-by-step mathematical calculation events and formulas from the last solver run.
  - `/boost [on|off|status|toggle]`: Toggle Deep Cryptanalytic Retrieval Boost (10 chunks, $2.0\times$ rune lexical rerank, 4,000-char context).
  - `/think [on|off|toggle]`: Toggle Chain-of-Thought (CoT) reasoning for supported models.
  - `/provider [name]`, `/model [key_or_name]`, `/host [url]`, `/profile [standard|low-spec]`, `/key [show|clear|<provider> <key>]`, `/cache clear`: Manage inference providers, models, remote Ollama URLs, memory profiles (8192 vs. 2048 context), `.env` API keys (`0600` permissions), and RAG cache.
  - `/status [--probe]`, `/bench [--profile] [--skip-vector] [--llm]`, `/clear`, `/help [command]`, `/exit` (`/quit`): System telemetry, microsecond benchmarking, manual, and session control.

---

## Guide 2: Standalone Solvers & Corpus Tools

### 1. Canonical Solved Pages Suite (`scripts/solve_canonical.py`)
Verifies and reproduces all 9 historically solved *Liber Primus* pages:
```bash
python3 scripts/solve_canonical.py          # Verify all 9 canonical solved pages
python3 scripts/solve_canonical.py welcome  # Solve/inspect Welcome
python3 scripts/solve_canonical.py 56       # Solve/inspect An End (56.jpg / LP 73)
python3 scripts/solve_canonical.py --json   # Machine-readable JSON output
```

### 2. Prime Totient Stream Cipher (`scripts/totient_stream.py`)
Implements the $\phi(p_k) = p_k - 1 \pmod{29}$ stream cipher with cleartext Fehu pause (`--f-skip`) support:
```bash
python3 scripts/totient_stream.py dec corpus/page_71_runes.md --f-skip
python3 scripts/totient_stream.py dec "ᚪᚾ᛫ᛖᚾᛞ..." --offset 0
python3 scripts/totient_stream.py enc "AN END WITHIN THE DEEP WEB" --f-skip
```

### 3. Page 56 Cascade Cryptanalysis (`scripts/cryptanalyze_page56.py`)
Evaluates the 273-rune transcript of Page 56 against three prioritized hypotheses (offset Euler totients, Pisano recurrence orbits in $\mathbb{F}_{29}$, and syntactic interrupter / clause-reset Vigenère) with Monte Carlo surrogate testing and SQLite ledger persistence:
```bash
python3 scripts/cryptanalyze_page56.py
python3 scripts/cryptanalyze_page56.py --top-k 10
python3 scripts/cryptanalyze_page56.py --json --no-log
```

### 4. Corpus Organizer (`scripts/porta.py`)
Reorganizes, classifies, and deduplicates `corpus/` files at **0% VRAM**:
- **Content Classification**: Detects Liber Primus page numbers and rune signatures.
- **Standardized Naming**: Normalizes irregular filenames into consistent `page_XX_*.md` names.
- **SHA-256 Deduplication**: Moves identical duplicates to `corpus/_duplicates/` while preserving `pages_index.json`.
```bash
python3 scripts/porta.py          # Classify, rename, and deduplicate
python3 scripts/porta.py --dedup  # Run duplicate cleanup only
```

---

## Recommended Offline Research Workflow

1. **Partition the Master Transcript** (if updated from raw transcription):
   ```bash
   python3 scripts/split_master_transcript.py
   ```
2. **Organize & Deduplicate the Corpus (Porta, 0 VRAM)**:
   ```bash
   python3 scripts/porta.py
   ```
3. **Chunk & Embed into ChromaDB (Bodleian)**:
   ```bash
   python3 scripts/bodleian.py
   ```
4. **Launch the Workstation**:
   ```bash
   python3 trithemius.py
   ```
   Or invoke commands directly: `python3 trithemius.py ask "What is the totient of page 56?"` or `python3 trithemius.py crack 56`.

---

## Canonical Solved Pages Reference

Trithemius verifies all 9 historically solved pages documented on the Uncovering Cicada wiki ([How the solved pages were solved](https://uncovering-cicada.fandom.com/wiki/How_the_solved_pages_of_the_Liber_Primus_were_solved)):

1. **Page 00** (`01.jpg`): Atbash in $\mathbb{F}_{29}$ ($C_i \to (28 - C_i) \pmod{29}$).
2. **Welcome** (`03.jpg - 04.jpg`): Modulo-29 Vigenère with key `DIVINITY` and cleartext Fehu pauses (F-skips).
3. **Some wisdom** (`05.jpg`): Direct Gematria Primus transliteration.
4. **Koan 1** (`06.jpg - 09.jpg`): Atbash followed by Caesar shift $+3$ in $\mathbb{F}_{29}$ (self-inverse involution).
5. **The loss of divinity** (`10.jpg - 13.jpg`): Direct Gematria Primus transliteration.
6. **Koan 2** (`14.jpg - 15.jpg`): Modulo-29 Vigenère with key `FIRFUMFERENFE` and cleartext F-skips.
7. **An instruction** (`16.jpg`): Direct Gematria Primus transliteration.
8. **An end** (`56.jpg` / LP `73.jpg`): Prime Totient Stream Cipher ($C_i \to (C_i - (p_i - 1)) \pmod{29}$) with F-skip at index 56.
9. **Parable** (`57.jpg`): Direct Gematria Primus transliteration.

```bash
python3 trithemius.py solve
python3 trithemius.py solve welcome
python3 trithemius.py atbash 00
python3 trithemius.py atbash 04 --shift 3
python3 trithemius.py vigenere dec 01 DIVINITY --f-skip
python3 trithemius.py totient-stream dec 71 --f-skip
```

---

## Verification & Regression Test Suite

Run the full unit and integration test suite (**454 tests across 44 test modules**, Python $\ge 3.10$):
```bash
python3 -m unittest discover -s tests
```
