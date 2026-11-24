"""
Formatters & Terminal Presentation — Pure-Python ConsoleRenderer.
Encapsulates all ANSI styling, tables, banners, and telemetry displays.
Zero external dependencies.
"""

import os
import sys
import textwrap
from typing import Optional, Dict, List, Tuple, Any

from ciphers.agrippa import decode_runes, is_prime
from ciphers.running_key import GATEKEEPER_THRESHOLD
from ciphers.opsec import CICADA_KEY_ID, CICADA_FINGERPRINT


class ConsoleRenderer:
    """Console UI formatter rendering deterministic cryptographic and telemetry presentations."""

    def __init__(self, stream: Optional[Any] = None):
        self.stream = stream
        if self.stream is not None:
            from contextlib import redirect_stdout
            for attr in dir(self):
                if attr.startswith("print_") and callable(getattr(self, attr)):
                    orig_method = getattr(self, attr)
                    def _make_wrapped(m):
                        def wrapped(*args, **kwargs):
                            with redirect_stdout(self.stream):
                                return m(*args, **kwargs)
                        return wrapped
                    setattr(self, attr, _make_wrapped(orig_method))

    COMMAND_DOCS = {
        "/ask": {
            "syntax": "/ask [--fresh] <query>",
            "summary": "Query RAG cryptanalytic engine with hybrid retrieval & deterministic routing",
            "description": (
                "Queries the workstation knowledge base. Evaluates deterministic routing\n"
                "rules (router.py) for exact Liber Primus page queries, rune transliterations,\n"
                "and Gematria lookups to provide instant, verified ground truth. For general\n"
                "questions, runs hybrid dense vector (ChromaDB) or zero-VRAM BM25 lexical\n"
                "retrieval with cryptographic relevance boosting, then streams LLM inference."
            ),
            "options": [
                "--fresh: Bypass RAG response cache and force fresh inference",
            ],
            "examples": [
                "/ask What is the sacred prime value of WELCOME?",
                "/ask --fresh What do the warning runes on page 57 signify?",
                "What is the significance of 3301? (Type query directly without /ask)",
            ],
        },
        "/web": {
            "syntax": "/web <query>",
            "summary": "Query Liber Primus RAG knowledge engine (offline corpus fallback)",
            "description": (
                "Queries the Liber Primus research corpus. Note: Live web reconnaissance has been\n"
                "retired in favor of the complete, authentic transcripts preserved offline in corpus/."
            ),
            "options": [],
            "examples": [
                "/web Liber Primus uncracked pages analysis",
                "/web Cicada 3301 sacred primes",
            ],
        },
        "/page": {
            "syntax": "/page <page_num>",
            "summary": "Inspect and transcribe specific Liber Primus page from corpus",
            "description": (
                "Locates and inspects canonical Liber Primus pages in corpus/ matching the\n"
                "given page number (e.g. 0, 56, 73). Displays document header, total lines,\n"
                "raw Futhorc runes, and English transcription preview."
            ),
            "options": [],
            "examples": [
                "/page 56",
                "/page 00",
                "/page 73",
            ],
        },
        "/gematria": {
            "syntax": "/gematria <runes_or_latin>",
            "summary": "Gematria Primus prime sum, totient, prime check & Atbash reflection",
            "description": (
                "Sacred number-theory calculator using Agrippan occult philosophy and the\n"
                "Cicada 3301 Gematria Primus 29-rune mapping. Converts Latin to Futhorc runes\n"
                "(and vice-versa), computes total prime sum, tests primality, computes Euler's\n"
                "totient phi(n), prime factorizes composite sums, calculates individual word\n"
                "prime sums, and applies Atbash reciprocal rune reflection."
            ),
            "options": [],
            "examples": [
                "/gematria ᚹᛖᛚᚳᚩᛗᛖ",
                "/gematria WELCOME PILGRIMS",
                "/gematria ᛗᚣᚱᚳ ᛞᛁᚠᛁᚾᛁᛏᚣ",
            ],
        },
        "/atbash": {
            "syntax": "/atbash <text_filepath_or_page> [--shift N]",
            "summary": "Modulo-29 Atbash and Caesar-shifted Atbash reflection cipher",
            "description": (
                "Applies Atbash reciprocal reflection over the 29-rune Futhorc alphabet:\n"
                "    decimal[i] = (28 - decimal[i]) mod 29\n"
                "If --shift is specified, adds an additive Caesar shift:\n"
                "    decimal[i] = ((28 - decimal[i]) + shift) mod 29\n"
                "Canonical methods:\n"
                "- Shift 0: Page 00 ('A warning', 01.jpg)\n"
                "- Shift 3: Koan 1 (06.jpg - 09.jpg, chunks 4-7; self-inverse involution)"
            ),
            "options": [
                "--shift N / -s N: Caesar shift added after Atbash (default: 0; Koan 1 uses 3)",
            ],
            "examples": [
                "/atbash 00",
                "/atbash 06 --shift 3",
                "/atbash \"ᚪ᛫ᚹᚪᚱᚾᚾᚷ...\"",
            ],
        },
        "/vigenere": {
            "syntax": "/vigenere <enc|dec> <text_filepath_or_page> <key> [--f-skip] [--skip-indices ...]",
            "summary": "Modulo-29 (Futhorc) or Modulo-26 (Latin) Vigenère cipher solver",
            "description": (
                "Cryptanalytic polyalphabetic solver. Accepts raw text, a file path (e.g. corpus/page_56_runes.md),\n"
                "or a page number (e.g. 56). For transcript files, automatically extracts clean runic text\n"
                "isolated from markdown headers and comments. If runes are detected in text or key,\n"
                "executes Modulo-29 rune shift algebra based on Gematria Primus rune indices.\n"
                "Otherwise executes Modulo-26 Classical Latin shift algebra. Supports cleartext Fehu (F)\n"
                "skips where key pointer pauses and Fehu passes through unencrypted (as on Welcome & Koan 2).\n"
                "Automatically passes decrypted text through the Al-Kindi statistical gatekeeper to compute\n"
                "Index of Coincidence (IoC), Chi-squared distance to English letter distribution,\n"
                "and English dictionary word ratio to determine plausibility."
            ),
            "options": [
                "enc / encode: Encrypt plaintext using key",
                "dec / decode: Decrypt ciphertext using key",
                "--f-skip: Enable cleartext Fehu keystream pause (default skip schedules for DIVINITY / FIRFUMFERENFE)",
                "--skip-indices: Explicit comma-separated skip indices (e.g. 48,74,84...)",
            ],
            "examples": [
                "/vigenere dec 01 DIVINITY --f-skip",
                "/vigenere dec 12 FIRFUMFERENFE --f-skip",
                "/vigenere dec corpus/page_56_runes.md DIVINITY",
                "/vigenere enc \"WELCOME PILGRIMS\" CICADA",
            ],
        },
        "/totient-stream": {
            "syntax": "/totient-stream <enc|dec> <text_filepath_or_page> [--offset N] [--f-skip] [--skip-indices ...]",
            "summary": "Liber Primus Prime Totient Stream Cipher (phi(p_i) = p_i - 1 mod 29)",
            "description": (
                "Executes the canonical Liber Primus stream cipher based on Euler totients of prime numbers:\n"
                "    decimal[i] = (decimal[i] - (primes[i + offset] - 1)) mod 29\n"
                "where primes[k] is the k-th prime (2, 3, 5, 7, 11, ...). Supports cleartext Fehu (F) skips\n"
                "(as on Page 56.jpg / 73.jpg 'An end', where index 56 has an unencrypted Fehu pausing the prime pointer)."
            ),
            "options": [
                "enc / encode: Encrypt plaintext using prime totient stream",
                "dec / decode: Decrypt ciphertext using prime totient stream",
                "--offset N: Starting offset into prime sequence (default: 0)",
                "--f-skip: Enable cleartext Fehu skip (defaults to skip index 56 for Page 56/73)",
                "--skip-indices: Comma-separated list of explicit rune positions to skip",
            ],
            "examples": [
                "/totient-stream dec 71 --f-skip",
                "/totient-stream dec 56 --f-skip",
                "/totient-stream enc \"AN END WITHIN THE DEEP WEB\" --f-skip",
            ],
        },
        "/totient": {
            "syntax": "/totient <enc|dec> <text_filepath_or_page> [--offset N] [--f-skip] [--skip-indices ...]",
            "summary": "Liber Primus Prime Totient Stream Cipher (phi(p_i) = p_i - 1 mod 29)",
            "description": (
                "Executes the canonical Liber Primus stream cipher based on Euler totients of prime numbers:\n"
                "    decimal[i] = (decimal[i] - (primes[i + offset] - 1)) mod 29\n"
                "where primes[k] is the k-th prime (2, 3, 5, 7, 11, ...). Supports cleartext Fehu (F) skips\n"
                "(as on Page 56.jpg / 73.jpg 'An end', where index 56 has an unencrypted Fehu pausing the prime pointer)."
            ),
            "options": [
                "enc / encode: Encrypt plaintext using prime totient stream",
                "dec / decode: Decrypt ciphertext using prime totient stream",
                "--offset N: Starting offset into prime sequence (default: 0)",
                "--f-skip: Enable cleartext Fehu skip (defaults to skip index 56 for Page 56/73)",
                "--skip-indices: Comma-separated list of explicit rune positions to skip",
            ],
            "examples": [
                "/totient dec 71 --f-skip",
                "/totient dec 56 --f-skip",
                "/totient enc \"AN END WITHIN THE DEEP WEB\" --f-skip",
            ],
        },
        "/solve": {
            "syntax": "/solve [page_id|all]",
            "summary": "Solve and verify canonical Liber Primus solved pages from official wiki",
            "description": (
                "Executes and validates the exact canonical cryptographic methods documented on the\n"
                "Uncovering Cicada wiki for all 9 solved Liber Primus pages:\n"
                "1. Page 00: Atbash in F_29\n"
                "2. Welcome (01-02): Vigenère DIVINITY with cleartext F-skips\n"
                "3. Some wisdom (03): Direct Gematria transliteration\n"
                "4. Koan 1 (04-07): Atbash + Caesar (+3) in F_29\n"
                "5. The loss of divinity (08-11): Direct Gematria transliteration\n"
                "6. Koan 2 (12-13): Vigenère FIRFUMFERENFE with cleartext F-skips\n"
                "7. An instruction (14): Direct Gematria transliteration\n"
                "8. An end (71 / 56.jpg): Prime Totient Stream Cipher with Fehu skip\n"
                "9. Parable (72 / 57.jpg): Direct Gematria transliteration"
            ),
            "options": [
                "target: Page number, name, or 'all' to verify entire suite (default: all)",
            ],
            "examples": [
                "/solve",
                "/solve all",
                "/solve 00",
                "/solve welcome",
                "/solve koan1",
                "/solve 71",
            ],
        },
        "/crack": {
            "syntax": "/crack <text_filepath_or_page> [--deep] [--compound] [--randomize] [--rotations] [--crib-limit N] [--top-k N] [--no-metal] [--no-ane]",
            "summary": "Automated Liber Primus GF(29) Cryptanalytic Cascade Solver with Apple Silicon Acceleration",
            "description": (
                "Executes the full end-to-end cryptanalytic taxonomy pipeline:\n"
                "1. Triage: Unigram IC, normalized kappa, bigram IC, and conditional entropy.\n"
                "2. Period Detection: Kasiski weighted GCD, difference periodogram comb, and column IoC.\n"
                "3. Periodic Solvers: Separable T-table coordinate optimization, MIC gauge scan, and coupled hill climbing.\n"
                "4. Dictionary Attack: O(m) candidate keyword evaluation using precomputed T-tables.\n"
                "5. Metal GPU Compound Sweeps: Evaluates all W^2 multi-word compound phrases on Metal shaders.\n"
                "6. Deterministic Streams: Totients phi(p), primes, Fibonacci, and natural counters with Fehu skip.\n"
                "7. Crib Dragging: Implied key linear complexity (Berlekamp-Massey) and stream hash bank matching.\n"
                "8. Apple Neural Engine Reranking: Cosine semantic naturalness scoring on CoreML ANE.\n"
                "9. Deep Mode (--deep): 812-space affine transforms, autokey, and cross-page running-key correlation.\n"
                "10. Verification & Ledger: Monte Carlo surrogate shuffle test and persistent SQLite logging."
            ),
            "options": [
                "--deep: Expand search to affine GF(29) transforms, autokey, and cross-page running keys",
                "--compound: Sweep exhaustive compound multi-word phrases (w1 + w2) on Metal GPU",
                "--randomize / --random: Randomize candidate vocabulary selection from full corpus lexicon",
                "--rotations: Evaluate all cyclic phase rotations for every dictionary keyword",
                "--crib-limit N: Maximum number of crib candidates to evaluate (positive int)",
                "--top-k N: Number of top candidate decryptions to display (default: 5)",
                "--no-metal: Disable Apple Silicon Metal GPU acceleration",
                "--no-ane: Disable Apple Neural Engine semantic reranking",
            ],
            "examples": [
                "/crack 56",
                "/crack corpus/page_56_runes.md",
                "/crack 56 --compound",
                "/crack 56 --deep",
                "/crack 56 --randomize --rotations",
                "/crack 56 --crib-limit 200 --top-k 3",
                "/crack \"ᛠᛁᚪ᛫ᛋᚣᛗᛞᚣᛋ᛫ᛒᛞᛄᛞ...\"",
            ],
        },
        "/hardware": {
            "syntax": "/hardware (aliases: /gpu, /metal, /ane)",
            "summary": "Query and benchmark Apple Silicon Metal GPU and Apple Neural Engine acceleration",
            "description": (
                "Displays detailed hardware telemetry for Apple Silicon hardware acceleration:\n"
                "- Metal GPU device name, unified memory buffer allocation, and compute pipeline state\n"
                "- GPU benchmark testing 1,000,000 combinatorial key evaluations (throughput in M keys/sec)\n"
                "- Apple Neural Engine (ANE) status, core count, TOPS compute capacity, and CoreML provider"
            ),
            "options": [],
            "examples": [
                "/hardware",
                "/gpu",
                "/metal",
                "/ane",
            ],
        },
        "/ledger": {
            "syntax": "/ledger [page_id_or_word]",
            "summary": "Inspect recorded cryptanalytic attempts in the ChromaDB vector database",
            "description": (
                "Displays telemetry from the persistent ChromaDB vector store and SQLite ledger:\n"
                "- Number of unique candidate words tested for a page or globally\n"
                "- Total attempt records and embeddings indexed in ChromaDB\n"
                "- Sample recently tested words to confirm deduplication\n"
                "- Cosine nearest-neighbor similarity search against previous hypotheses"
            ),
            "options": [
                "page_id: Target page to filter attempts (default: all pages)",
                "word: Hypothesis keyword to search for similar attempts in vector space",
            ],
            "examples": [
                "/ledger",
                "/ledger 56",
                "/ledger DIVINE",
            ],
        },
        "/triage": {
            "syntax": "/triage <text_filepath_or_page>",
            "summary": "Statistical triage & cipher family classification",
            "description": (
                "Computes unigram IC, normalized kappa (29*IC), bigram IC, conditional entropy,\n"
                "and word-length distribution to classify ciphertext into Monoalphabetic, Periodic\n"
                "Polyalphabetic, Transposition, or Stream/OTP cipher families."
            ),
            "options": [],
            "examples": [
                "/triage 56",
                "/triage corpus/page_00_runes.md",
            ],
        },
        "/period": {
            "syntax": "/period <text_filepath_or_page> [max_period]",
            "summary": "Key length & difference periodogram comb filter estimation",
            "description": (
                "Performs multi-metric consensus key length estimation ensembling Kasiski\n"
                "weighted GCD voting, difference periodogram chi-squared comb filtering, and\n"
                "column Index of Coincidence across periods m = 1..max_period."
            ),
            "options": [],
            "examples": [
                "/period 56",
                "/period corpus/page_56_runes.md 24",
            ],
        },
        "/crib": {
            "syntax": "/crib <text_filepath_or_page> <crib_word>",
            "summary": "Slide crib word to extract & analyze implied key fragments",
            "description": (
                "Slides candidate crib across all ciphertext positions and evaluates implied\n"
                "keystream fragments: Berlekamp-Massey linear complexity over GF(29), constant\n"
                "finite differences, and O(1) matching against precomputed deterministic stream hash bank."
            ),
            "options": [],
            "examples": [
                "/crib 56 DIVINITY",
                "/crib 56 WELCOME",
                "/crib corpus/page_56_runes.md SACRED",
            ],
        },
        "/opsec": {
            "syntax": "/opsec <text_or_filepath>",
            "summary": "Verify Cicada 3301 PGP 7A35090F signature & Shannon entropy",
            "description": (
                "Evaluates operational security and steganographic features of text or files.\n"
                "Checks for valid PGP message blocks and authenticates against the Cicada 3301\n"
                "PGP key (Key ID: 7A35090F, Fingerprint: 52C1 40A7 325F 33B4 7136 2950 20EE 2E87 7A35 090F).\n"
                "Performs header inspection for file format markers and computes Shannon entropy\n"
                "(0-8 bits/byte) to identify encrypted payloads vs plain English text."
            ),
            "options": [],
            "examples": [
                "/opsec corpus/page_73_an_end.md",
                "/opsec \"-----BEGIN PGP SIGNED MESSAGE-----\\n...\"",
            ],
        },
        "/layout": {
            "syntax": "/layout [target|calibrate]",
            "summary": "Layout side-channel mutual information analysis & calibration",
            "description": (
                "Models Liber Primus pages as multiplexed symbol and layout streams.\n"
                "Evaluates discrete mutual information I(layout ; keystream shift) for word lengths,\n"
                "line lengths, runic separators (᛫, ᛬, ᛭), and Fehu interrupt positions.\n"
                "Applies Miller-Madow bias correction and Besag-Clifford sequential Monte Carlo null testing.\n"
                "When run with 'calibrate' (or no arguments), evaluates all known-solved pages (0, 56, 57, 73)\n"
                "and persists results to the hypothesis ledger under family 'layout-carrier'."
            ),
            "options": [
                "target: Page ID, filepath, or raw runic text",
                "calibrate / all: Run calibration across all solved pages and persist to ledger",
            ],
            "examples": [
                "/layout calibrate",
                "/layout 56",
                "/layout corpus/page_00_runes.md",
            ],
        },
        "/organize": {
            "syntax": "/organize",
            "summary": "Deduplicate and classify corpus documents via Porta",
            "description": (
                "Corpus curation engine (Porta). Computes SHA-256 digests and normalized rune\n"
                "signatures across all corpus files. Moves duplicates into corpus/_duplicates/\n"
                "and generates structured classification metadata."
            ),
            "options": [],
            "examples": [
                "/organize",
            ],
        },
        "/ingest": {
            "syntax": "/ingest",
            "summary": "Chunk and index corpus documents into ChromaDB vector database",
            "description": (
                "Semantic ingestion pipeline (Bodleian). Chunks documents with cryptographic\n"
                "metadata (page numbers, rune flags, PGP status) and computes vector embeddings\n"
                "into vectordb/ for dense similarity retrieval."
            ),
            "options": [],
            "examples": [
                "/ingest",
            ],
        },
        "/status": {
            "syntax": "/status [--probe]",
            "summary": "Display system telemetry, provider health, model & corpus metrics",
            "description": (
                "Prints real-time workstation status, including active inference provider,\n"
                "active model name, hardware context profile, Chain-of-Thought status,\n"
                "Cryptanalytic Boost mode, configured API keys, corpus document count,\n"
                "indexed vector chunk count, and authentic Cicada PGP identity."
            ),
            "options": [
                "--probe: Validate connectivity and authentication for configured providers and model IDs",
            ],
            "examples": [
                "/status",
                "/status --probe",
            ],
        },
        "/think": {
            "syntax": "/think [on|off|toggle]",
            "summary": "Toggle Chain-of-Thought (CoT) reasoning for reasoning models",
            "description": (
                "Enables or disables Chain-of-Thought reasoning for models that support it\n"
                "(such as DeepSeek-R1, Qwen 2.5, Spark-X2.5). When enabled, displays internal\n"
                "reasoning trace before providing the final answer."
            ),
            "options": [
                "on / true / 1: Force enable reasoning",
                "off / false / 0: Force disable reasoning",
                "toggle / no argument: Toggle current state",
            ],
            "examples": [
                "/think on",
                "/think off",
                "/think toggle",
                "/think",
            ],
        },
        "/boost": {
            "syntax": "/boost [on|off|status|toggle]",
            "summary": "Toggle Deep Cryptanalytic Retrieval & Reranking Boost mode",
            "description": (
                "Amplifies cryptographic search relevance and candidate retrieval depth.\n"
                "When enabled: expands candidate retrieval budget to 10 chunks, multiplies\n"
                "Futhorc rune and Gematria keyword lexical match scores by 2.0x, and widens\n"
                "prompt context to 4,000 characters for deep multi-page cryptanalysis."
            ),
            "options": [
                "on / true / 1: Enable boost mode",
                "off / false / 0: Disable boost mode",
                "status / check: Display current boost status without modifying",
                "toggle (or no argument): Toggle current state",
            ],
            "examples": [
                "/boost on",
                "/boost off",
                "/boost status",
                "/boost",
            ],
        },
        "/provider": {
            "syntax": "/provider [name]",
            "summary": "Switch active LLM provider (ollama, groq, openai, gemini, anthropic, openrouter)",
            "description": (
                "Inspects or changes the active inference provider. Automatically resets\n"
                "the active model to the default model configured for that provider."
            ),
            "options": [
                "Supported: ollama, groq, openai, gemini, anthropic, openrouter",
            ],
            "examples": [
                "/provider",
                "/provider groq",
                "/provider ollama",
            ],
        },
        "/model": {
            "syntax": "/model [key_or_name]",
            "summary": "Switch active language model key or specify custom model",
            "description": (
                "Switches the active LLM. Can specify a registered preset model key\n"
                "(lfm, lfm-fast, spark, moe, moe-fast, tiny, light, fast, groq, openai, gemini, claude)\n"
                "or provide any custom model name supported by the active provider."
            ),
            "options": [],
            "examples": [
                "/model lfm",
                "/model lfm-fast",
                "/model spark",
                "/model llama-3.3-70b-versatile",
            ],
        },
        "/key": {
            "syntax": "/key  OR  /key <provider> <api_key>  OR  /key clear <provider>",
            "summary": "AI API key & cloud provider configuration section",
            "description": (
                "Opens the dedicated AI API key & cloud provider management section.\n"
                "Displays configured credentials, active provider status, and supported\n"
                "models. Securely persists keys into .env with restricted file permissions (0600)."
            ),
            "options": [
                "no argument / show: Display AI API key & cloud provider configuration panel",
                "<provider> <api_key>: Persist and activate personal API key",
                "clear <provider>: Remove saved API key for provider",
            ],
            "examples": [
                "/key",
                "/key show",
                "/key groq gsk_...",
                "/key openai sk-...",
                "/key clear groq",
            ],
        },
        "/keys": {
            "syntax": "/keys",
            "summary": "Alias for /key (AI API key & cloud provider configuration)",
            "description": "Opens the dedicated AI API key & cloud provider management section.",
            "options": [],
            "examples": [
                "/keys",
            ],
        },
        "/host": {
            "syntax": "/host [url]",
            "summary": "Set remote Ollama streaming endpoint host URL",
            "description": (
                "Configures the endpoint URL for Ollama streaming. Allows offloading\n"
                "inference to a remote GPU server, LAN workstation, or Ollama cloud tunnel."
            ),
            "options": [],
            "examples": [
                "/host http://192.168.1.50:11434",
                "/host http://localhost:11434",
            ],
        },
        "/profile": {
            "syntax": "/profile [standard|low-spec]",
            "summary": "Toggle hardware profile between standard and low-spec memory footprint",
            "description": (
                "Adjusts context window parameters for hardware optimization.\n"
                "'standard' enables 8,192 token context; 'low-spec' restricts context to\n"
                "2,048 tokens to minimize RAM and VRAM usage on resource-constrained devices."
            ),
            "options": [
                "standard / std / high: 8192 token context",
                "low / low-spec / lowspec: 2048 token context",
            ],
            "examples": [
                "/profile standard",
                "/profile low-spec",
            ],
        },
        "/cache": {
            "syntax": "/cache clear",
            "summary": "Clear exact RAG response cache in vectordb/cache.sqlite3",
            "description": (
                "Flushes all cached deterministic and RAG inference responses,\n"
                "forcing subsequent queries to perform fresh retrieval and generation."
            ),
            "options": [
                "clear: Purge cache database",
            ],
            "examples": [
                "/cache clear",
            ],
        },
        "/bench": {
            "syntax": "/bench [--profile] [--skip-vector] [--llm] [--compare BASELINE] [--save-baseline NAME]",
            "summary": "Run microsecond latency benchmark suite & hotspot profiling",
            "description": (
                "Executes the Trithemius performance benchmark suite. Measures cryptographic\n"
                "primitive latencies (Agrippa, Kasiski, Al-Kindi, Shannon entropy), BM25 zero-VRAM\n"
                "retrieval speed, and vector search. Can run Python cProfile hotspot profiling."
            ),
            "options": [
                "--profile: Run cProfile and print top 20 hotspot functions",
                "--skip-vector: Skip ChromaDB vector benchmarks",
                "--llm: Include local LLM time-to-first-token benchmark",
                "--compare NAME: Compare latencies against a saved baseline",
                "--save-baseline NAME: Save results as a tagged baseline",
            ],
            "examples": [
                "/bench",
                "/bench --profile",
                "/bench --skip-vector",
            ],
        },
        "/help": {
            "syntax": "/help [command]",
            "summary": "Display command manual or detailed help for a specific command",
            "description": (
                "Shows the complete command manual categorized by function, or detailed\n"
                "syntax, algorithms, and examples for a specific command."
            ),
            "options": [],
            "examples": [
                "/help",
                "/help gematria",
                "/help vigenere",
                "/help boost",
            ],
        },
        "/running-key": {
            "syntax": "/running-key <page> <text_file> [--mode sub|add|beaufort] [--f-skip] [--offset N]",
            "summary": "GF(29) running-key decryption against reference text",
            "description": (
                "Evaluates running-key cipher over GF(29) using a canonical reference text.\n"
                "Supports standard subtraction (sub), additive (add), and Beaufort modes,\n"
                "with dynamic Fehu-skip simulation where cleartext Fehu does not advance the keystream."
            ),
            "options": [
                "--mode: Decryption mode: sub, add, or beaufort (default: sub)",
                "--f-skip: Enable cleartext Fehu keystream pause",
                "--offset: Keystream start index offset (default: 0)",
            ],
            "examples": [
                "/running-key 56 corpus/reference_texts/blake_marriage_heaven_hell.txt --mode sub --f-skip",
                "/running-key 56 emerson_self_reliance.txt --offset 100",
            ],
        },
        "/running-key-scan": {
            "syntax": "/running-key-scan <page> [--ref-dir DIR] [--step N] [--top-k N]",
            "summary": "Sliding window running-key scan across canonical reference texts",
            "description": (
                "Scans all .txt reference texts in corpus/reference_texts/ across shift modes\n"
                "and Fehu-skip settings, scoring candidate alignments with calibrated runic models."
            ),
            "options": [
                "--ref-dir: Reference texts directory (default: corpus/reference_texts)",
                "--step: Sliding window step size (default: 1)",
                "--top-k / --limit: Number of top candidate alignments to retain (default: 5)",
            ],
            "examples": [
                "/running-key-scan 56",
                "/running-key-scan 56 --step 2 --top-k 10",
                "/running-key-scan 56 --limit 5",
            ],
        },
        "/lexicon": {
            "syntax": "/lexicon [phrases|words|all] [--limit N]",
            "summary": "Inspect master vocabulary, philosophical phrases, and reference words",
            "description": (
                "Displays curated multi-word philosophical aphorisms, reference text vocabulary,\n"
                "and master cryptanalytic keywords used for crib dragging and key generation."
            ),
            "options": [
                "phrases: Curated multi-word philosophical aphorisms (default)",
                "words: Master keyword dictionary",
                "all: Complete vocabulary overview",
            ],
            "examples": [
                "/lexicon phrases",
                "/lexicon words",
            ],
        },
        "/clear": {
            "syntax": "/clear",
            "summary": "Clear terminal screen buffer",
            "description": "Clears the active terminal window for a clean workspace.",
            "options": [],
            "examples": [
                "/clear",
            ],
        },
        "/exit": {
            "syntax": "/exit  OR  /quit",
            "summary": "Safely exit and disconnect from Trithemius Workstation",
            "description": "Terminates the interactive workstation session and returns to shell.",
            "options": [],
            "examples": [
                "/exit",
                "/quit",
            ],
        },
    }


    def print_gematria(self, data: dict):
        print("\n+--- [GEMATRIA PRIMUS ARITHMETIC] -----------------------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']} ({data.get('extraction_mode', '')})")
            if data.get("rune_count"):
                print(f"| Extracted Runes: {data['rune_count']}")
        print(f"| Input Text:      {data['input']}")
        print(f"| Futhorc Runes:   {data['runes']}")
        print(f"| Decoded Latin:   {data['decoded_latin']}")
        print(f"| Prime Sum:       {data['prime_sum']} (Euler Totient phi: {data['totient']}, Is Prime: {data['is_prime']})")
        print(f"| Prime Factors:   {data['prime_factors']}")
        print(f"| Atbash Runes:    {data['atbash_runes']}")
        print(f"| Atbash Latin:    {data['atbash_latin']}")
        if data['word_sums']:
            print("| Word Breakdown:")
            for word, w_sum in data['word_sums']:
                w_latin = decode_runes(word)
                w_prime = is_prime(w_sum)
                print(f"|   {word} ({w_latin}) -> Prime Sum: {w_sum} (Prime: {w_prime})")
        print("+--------------------------------------------------------------------------\n")


    def print_atbash(self, data: dict):
        m = data["metrics"]
        print("\n+--- [ATBASH REFLECTION (F_29)] -------------------------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']} ({data.get('extraction_mode', '')})")
            if data.get("rune_count"):
                print(f"| Extracted Runes: {data['rune_count']}")
        print(f"| Method:          {data['method']}")
        if "\n" in data["result_runes"]:
            print("| Result Runes:")
            for line in data["result_runes"].splitlines():
                print(f"|   {line}")
        else:
            print(f"| Result Runes:    {data['result_runes']}")
        if "\n" in data["decoded_latin"]:
            print("| Decoded Latin:")
            for line in data["decoded_latin"].splitlines():
                print(f"|   {line}")
        else:
            print(f"| Decoded Latin:   {data['decoded_latin']}")
        print(f"| Index of Coinc:  {data['ioc']}")
        print(f"| Chi-Squared:     {m.get('chi_squared', 'N/A')} (English < 180)")
        print(f"| Ngram Score:     {m.get('ngram_score', 'N/A')} (0.0 to 1.0)")
        print(f"| English Words:   {m.get('word_ratio', 'N/A')} ({m.get('word_ratio', 0)*100:.1f}%)")
        print(f"| Gatekeeper:      [{m.get('verdict', 'UNKNOWN')}]")
        print("+--------------------------------------------------------------------------\n")


    def print_vigenere(self, data: dict):
        m = data["metrics"]
        print("\n+--- [VIGENERE CRYPTANALYSIS] ---------------------------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']} ({data.get('extraction_mode', '')})")
            if data.get("rune_count"):
                print(f"| Extracted Runes: {data['rune_count']}")
        print(f"| Operation:       {data['mode']} via {data['alphabet']}")
        print(f"| Key:             {data['key']}")
        f_info = "ENABLED" if data.get("f_skip") or data.get("skip_indices") else "DISABLED"
        if data.get("skip_indices"):
            f_info += f" (Positions: {data['skip_indices']})"
        print(f"| Fehu (F) Skip:   {f_info}")
        if "\n" in data["result"]:
            print("| Result:")
            for line in data["result"].splitlines():
                print(f"|   {line}")
        else:
            print(f"| Result:          {data['result']}")
        if data["result"] != data["decoded_latin"]:
            if "\n" in data["decoded_latin"]:
                print("| Decoded Latin:")
                for line in data["decoded_latin"].splitlines():
                    print(f"|   {line}")
            else:
                print(f"| Decoded Latin:   {data['decoded_latin']}")
        print(f"| Index of Coinc:  {data['ioc']}")
        print(f"| Chi-Squared:     {m.get('chi_squared', 'N/A')} (English < 180)")
        print(f"| Ngram Score:     {m.get('ngram_score', 'N/A')} (0.0 to 1.0)")
        print(f"| English Words:   {m.get('word_ratio', 'N/A')} ({m.get('word_ratio', 0)*100:.1f}%)")
        print(f"| Gatekeeper:      [{m.get('verdict', 'UNKNOWN')}]")
        print("+--------------------------------------------------------------------------\n")


    def print_totient_stream(self, data: dict):
        m = data["metrics"]
        print("\n+--- [PRIME TOTIENT STREAM CIPHER] ---------------------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']} ({data.get('extraction_mode', '')})")
            if data.get("rune_count"):
                print(f"| Extracted Runes: {data['rune_count']}")
        print(f"| Operation:       {data['mode']} (Keystream: phi(p_i) = p_i - 1 mod 29)")
        print(f"| Prime Offset:    {data['offset']}")
        f_info = "ENABLED" if data.get("f_skip") or data.get("skip_indices") else "DISABLED"
        if data.get("skip_indices"):
            f_info += f" (Positions: {data['skip_indices']})"
        print(f"| Fehu (F) Skip:   {f_info}")
        if "\n" in data["result_runes"]:
            print("| Result Runes:")
            for line in data["result_runes"].splitlines():
                print(f"|   {line}")
        else:
            print(f"| Result Runes:    {data['result_runes']}")
        if "\n" in data["decoded_latin"]:
            print("| Decoded Latin:")
            for line in data["decoded_latin"].splitlines():
                print(f"|   {line}")
        else:
            print(f"| Decoded Latin:   {data['decoded_latin']}")
        print(f"| Index of Coinc:  {data['ioc']}")
        print(f"| Chi-Squared:     {m.get('chi_squared', 'N/A')} (English < 180)")
        print(f"| Ngram Score:     {m.get('ngram_score', 'N/A')} (0.0 to 1.0)")
        print(f"| English Words:   {m.get('word_ratio', 'N/A')} ({m.get('word_ratio', 0)*100:.1f}%)")
        print(f"| Gatekeeper:      [{m.get('verdict', 'UNKNOWN')}]")
        print("+--------------------------------------------------------------------------\n")


    def print_totient(self, data: dict):
        """Alias for print_totient_stream."""
        return self.print_totient_stream(data)


    def print_solve(self, data: dict):
        if "results" in data:
            # Batch verification report
            print("\n+--- [CANONICAL SOLVED PAGES VERIFICATION SUITE] -------------------------")
            print(f"| Total Pages Tested: {data['total']} | Verified: {data['verified']} | Failed: {data['failed']}")
            print("|\n| Status  Page ID            Image           Method")
            for pid, res in data["results"].items():
                status = "[PASS]" if res["verified"] else "[FAIL]"
                print(f"| {status:<6s}  {pid:<18s} {res['original_image']:<15s} {res['method']}")
            print("|\n+--------------------------------------------------------------------------")
            overall = "ALL 9 PAGES VERIFIED (100% REPRODUCED)" if data["all_passed"] else f"{data['verified']}/{data['total']} VERIFIED"
            print(f"| Verification Result: {overall}")
            print("+--------------------------------------------------------------------------\n")
        else:
            # Single page report
            status = "[PASS]" if data.get("verified") else "[FAIL]"
            print(f"\n+--- [CANONICAL SOLVED PAGE: {data['title'].upper()}] -------------------------")
            print(f"| ID:              {data['id']}")
            print(f"| Original Image:  {data['original_image']}")
            print(f"| Chunks:          {data['chunks']}")
            print(f"| Method:          {data['method']}")
            print(f"| Description:     {data['method_description']}")
            if data.get("key"):
                print(f"| Key:             {data['key']}")
            if data.get("skip_indices"):
                print(f"| Fehu Skip Ptr:   {data['skip_indices']}")
            print(f"| Rune Count:      {data['rune_count']}")
            print(f"| Verification:    {status}")
            if data.get("matched_fragments"):
                print(f"| Matched Phrases: {len(data['matched_fragments'])}/{len(data['matched_fragments']) + len(data.get('missing_fragments', []))}")
            latin_preview = data.get("plaintext_latin", "").strip()
            if latin_preview:
                print("|\n| Decrypted Latin Plaintext Preview:")
                lines = latin_preview.splitlines()
                for line in lines[:8]:
                    print(f"|   {line}")
                if len(lines) > 8:
                    print(f"|   ... ({len(lines) - 8} more lines)")
            print("+--------------------------------------------------------------------------\n")


    def print_crack(self, data: dict):
        triage = data.get("triage", {})
        print("\n+--- [LIBER PRIMUS CRYPTANALYTIC SOLVER] ----------------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']} ({data.get('extraction_mode', '')})")
            print(f"| Target Runes:    {data.get('rune_count', 0)}")
        else:
            print(f"| Target Input:    {data.get('target_input', '')[:45]}")
            print(f"| Target Runes:    {data.get('rune_count', 0)}")
        print(f"| Triage Status:   {triage.get('classification', 'N/A')} (Kappa: {triage.get('normalized_kappa', 0):.3f}, IC: {triage.get('ic', 0):.4f})")
        print(f"| Consensus Period: Top Period m = {data.get('top_period', 1)}")

        candidates = data.get("top_candidates", [])
        if candidates:
            print("|\n| TOP CANDIDATE DECRYPTIONS (Ranked by Calibrated GF(29) Fitness):")
            for idx, c in enumerate(candidates, 1):
                k_repr = str(c.get('key_latin') or c.get('stream', '') or "")
                score_str = f"Score: {c.get('score', 0):+.4f}"
                n_str = f" [ANE: {c.get('neural_score'):+.3f}]" if c.get("neural_score") is not None else ""
                acc_tag = f" [{c.get('accelerator')}]" if c.get("accelerator") else ""
                method_name = c.get("method", "UNKNOWN")

                single_line = f"| {idx}. [{score_str}]{n_str}{acc_tag} Method: {method_name} (Key: '{k_repr}')"
                if len(single_line) <= 75:
                    print(single_line)
                else:
                    print(f"| {idx}. [{score_str}]{n_str}{acc_tag} {method_name}")
                    if len(k_repr) > 56:
                        k_repr = k_repr[:53] + "..."
                    print(f"|    Key:     '{k_repr}'")

                preview = c.get("plaintext_latin", "").strip()
                if preview:
                    first_line = preview.splitlines()[0][:56]
                    print(f"|    Latin:   {first_line}...")
                sig = c.get("significance")
                if sig:
                    sig_str = "SIGNIFICANT" if sig.get("is_statistically_significant") else "BELOW_THRESHOLD"
                    print(f"|    Surrogate: Z-Score = {sig.get('z_score', 0):+.2f} (Null mean: {sig.get('null_mean', 0):.3f}, [{sig_str}])")

        cribs = data.get("crib_drag_hits", [])
        if cribs:
            print("|\n| CRIB DRAG MATCHES:")
            for h in cribs[:3]:
                match_desc = h.get("bank_match") or ("Lexicon Word" if h.get("is_lexicon_word") else f"Linear LC={h.get('linear_complexity')}")
                print(f"|    Pos {h.get('position'):3d}: Crib '{h.get('crib')}' -> Implied Key '{h.get('implied_key_runes')}' [{match_desc}]")

        rec_cnt = data.get("recorded_attempts_count", 0)
        tot_cnt = data.get("total_page_tested_words", 0)
        if rec_cnt or tot_cnt:
            page_id = data.get("page_id", "current target")
            print("|\n| VECTOR DATABASE TELEMETRY:")
            print(f"|    Attempts Recorded This Run: {rec_cnt}")
            print(f"|    Total Unique Words Tested on Page '{page_id}': {tot_cnt} (Deduplicated)")

        hw = data.get("hardware", {})
        if hw:
            metal_info = hw.get("metal_gpu", {})
            ane_info = hw.get("neural_engine", {})
            print("|\n| HARDWARE ACCELERATION TELEMETRY:")
            if metal_info.get("available"):
                print(f"|    Metal GPU:     {metal_info.get('device_name')} (UMA Zero-Copy, {metal_info.get('max_buffer_mb', 0):.0f} MB buffer)")
            else:
                print("|    Metal GPU:     Disabled / Multicore CPU Fallback")
            if ane_info.get("available"):
                print(f"|    Neural Engine: Active ({ane_info.get('cores', 16)}-Core ANE, {ane_info.get('tops_estimate', 0):.0f} TOPS via CoreML)")
            else:
                print("|    Neural Engine: Offline / CPU Heuristic")

        print("+--------------------------------------------------------------------------\n")


    def print_hardware(self, data: dict):
        if "error" in data:
            print(f"[!] Error inspecting hardware: {data['error']}\n")
            return
        print("\n+--- [APPLE SILICON HARDWARE ACCELERATION (M4 GPU & ANE)] -------------")
        mgpu = data.get("metal_gpu", {})
        ane = data.get("neural_engine", {})
        bm = data.get("benchmark", {})

        if mgpu.get("available"):
            print(f"| Metal Device:          {mgpu.get('device_name')}")
            print(f"| Unified Memory Buffer: {mgpu.get('max_buffer_mb', 0):.1f} MB")
            print("| Architecture:          Apple Silicon Unified Memory Architecture (UMA Zero-Copy)")
        else:
            print("| Metal Device:          Not Available (CPU Fallback)")

        if bm:
            print("|\n| GPU BENCHMARK (1,000,000 Key Combinations Sweep):")
            print(f"|    Evaluated Keys:     {bm.get('combinations_tested', 0):,}")
            print(f"|    Elapsed Time:       {bm.get('elapsed_seconds', 0):.4f} s")
            print(f"|    Throughput:         {bm.get('throughput_m_keys_per_sec', 0):.1f} Million keys/sec ({bm.get('combinations_per_second', 0):,.0f} ops/sec)")

        if ane.get("available"):
            print("|\n| APPLE NEURAL ENGINE (ANE):")
            print(f"|    Hardware Type:      {ane.get('hardware')}")
            print(f"|    Dedicated Cores:    {ane.get('cores')}")
            print(f"|    Compute Capacity:   {ane.get('tops_estimate', 0):.1f} TOPS")
            print(f"|    Execution Provider: {', '.join(ane.get('execution_providers', []))}")
            print("|    Neural Models:      Offline Local Cache Verified (Zero Network)")
        else:
            print("|\n| APPLE NEURAL ENGINE (ANE): Offline / CPU Fallback")
        print("+--------------------------------------------------------------------------\n")


    def print_ledger(self, data: dict):
        if "error" in data:
            print(f"[!] Error reading vector ledger: {data['error']}\n")
            return
        stats = data.get("stats", {})
        p = data.get("page") or "All Pages"
        print("\n+--- [CRYPTANALYTIC VECTOR DATABASE & LEDGER] -----------------------------")
        print(f"| Scope:               Page '{p}'")
        print(f"| Tested Words Count:  {stats.get('tested_words_count', 0)} unique words recorded")
        print(f"| Total Vector Store:  {stats.get('total_vector_records', 0)} embedding vectors stored")
        samples = stats.get("sample_words", [])
        if samples:
            print(f"| Sample Tested Words: {', '.join(samples[:8])}...")
        sim = data.get("similar_hypotheses", [])
        if sim:
            print("|\n| Similar Tested Hypotheses in Vector Space:")
            for h in sim:
                print(f"|    Word: '{h.get('word')}' | Method: {h.get('method')} | Cosine Sim: {h.get('similarity'):.3f} | Score: {h.get('score'):+.4f}")
        print("+--------------------------------------------------------------------------\n")


    def print_triage(self, data: dict):
        print("\n+--- [CRYPTANALYTIC STATISTICAL TRIAGE] -----------------------------------")
        if data.get("source_file"):
            print(f"| Source File:         {data['source_file']} ({data.get('extraction_mode', '')})")
        else:
            print(f"| Target:              {data.get('target_input', '')[:45]}")
        print(f"| Symbol Count:        {data.get('rune_count', 0)} runes")
        print(f"| Unigram IC:          {data.get('ic', 0):.5f} (Random Flat Noise = 0.03448)")
        print(f"| Normalized Kappa:    {data.get('normalized_kappa', 0):.4f} (Uniform = 1.0, English > 1.45)")
        print(f"| Bigram IC:           {data.get('bigram_ic', 0):.5f}")
        print(f"| Conditional Entropy: {data.get('conditional_entropy', 0):.4f} bits/rune")
        wl = data.get("word_lengths", {})
        if wl:
            top_lens = ", ".join(f"len {l}: {c}" for l, c in list(wl.items())[:6])
            print(f"| Word Lengths:        {top_lens}")
        print(f"| Cipher Diagnosis:    [{data.get('classification', 'UNKNOWN')}]")
        print(f"| Recommendation:      {data.get('recommendation', '')}")
        print("+--------------------------------------------------------------------------\n")


    def print_period(self, data: dict):
        print("\n+--- [KEY LENGTH & PERIODOGRAM ESTIMATION] --------------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']}")
        else:
            print(f"| Target:          {data.get('target_input', '')[:45]}")
        print(f"| Consensus Period: m = {data.get('top_period', 1)}")
        periods = data.get("periods", [])
        if periods:
            print("|\n| Period  Composite Score  Kasiski GCD  Comb Chi2  Column IoC")
            for m, score, meta in periods[:8]:
                print(f"| m = {m:<2d}    {score:<15.4f}  {meta.get('kasiski_score', 0):<11.3f}  {meta.get('diff_chi2', 0):<9.2f}  {meta.get('col_ioc', 0):.4f}")
        print("+--------------------------------------------------------------------------\n")


    def print_crib(self, data: dict):
        print("\n+--- [CRIB DRAGGING & ALGEBRAIC KEY ANALYSIS] ----------------------------")
        if data.get("source_file"):
            print(f"| Source File:     {data['source_file']}")
        print(f"| Crib Tested:     '{data.get('crib')}'")
        print(f"| Window Positions: {data.get('total_tested', 0)} offsets tested")
        hits = data.get("hits", [])
        if hits:
            print(f"| Significant Hits Found: {len(hits)}")
            print("|\n|  Pos  Implied Key  Lin Complex  Alg Order  Stream Bank Match")
            for h in hits[:10]:
                match_str = h.get("bank_match") or ("Lexicon Word" if h.get("is_lexicon_word") else "-")
                alg_str = f"Diff-deg {h.get('algebraic_order')}" if h.get('algebraic_order') is not None else "-"
                print(f"|  {h.get('position'):<4d} {h.get('implied_key_runes'):<12} LC={h.get('linear_complexity'):<8d} {alg_str:<10} {match_str}")
        else:
            print("| No significant linear recurrences or stream bank matches found for this crib.")
        print("+--------------------------------------------------------------------------\n")


    def print_running_key(self, data: dict):
        if "error" in data:
            print(f"\n[!] Error: {data['error']}\n")
            return

        print("\n+--- [GF(29) RUNNING-KEY CRYPTANALYSIS] -----------------------------------")
        if data.get("source_file"):
            print(f"| Target Cipher:   {data.get('page')} ({data.get('rune_count')} runes)")
            print(f"| Keystream File:  {data.get('source_file_basename', data.get('source_file'))} ({data.get('key_stream_len', 0)} key symbols)")
        print(f"| Decryption Mode: {data.get('mode', 'sub').upper()}")
        print(f"| Fehu (F) Skip:   {'ENABLED' if data.get('f_skip') else 'DISABLED'}")
        print(f"| Stream Offset:   {data.get('offset', 0)}")
        print(f"| Composite Score: {data.get('score', 0):+.4f} (Gatekeeper: >= {GATEKEEPER_THRESHOLD:.2f})")
        print(f"| Verdict:         [{'PLAUSIBLE' if data.get('passed') else 'REJECT'}]")
        runes_out = data.get("runes", "")
        latin_out = data.get("plain_latin", "")
        if runes_out:
            print(f"| Runes:           {runes_out[:80]}{'...' if len(runes_out) > 80 else ''}")
        if latin_out:
            print(f"| Decoded Latin:   {latin_out[:80]}{'...' if len(latin_out) > 80 else ''}")
        print("+--------------------------------------------------------------------------\n")


    def print_running_key_scan(self, data: dict):
        if "error" in data:
            print(f"\n[!] Error: {data['error']}\n")
            return

        print("\n+--- [GF(29) RUNNING-KEY REFERENCE SCAN] ----------------------------------")
        print(f"| Target Page:     {data.get('page')} ({data.get('rune_count')} runes)")
        print(f"| Reference Dir:   {data.get('ref_dir')}")
        print(f"| Scanning Step:   {data.get('step')}")
        candidates = data.get("candidates", [])
        if candidates:
            print(f"|\n| TOP {len(candidates)} CANDIDATE RUNNING KEYS (Ranked by GF(29) Fitness):")
            for idx, c in enumerate(candidates, 1):
                f_skip_str = "+f_skip" if c.get("f_skip") else "standard"
                verdict = "PLAUSIBLE" if c.get("passed") else "REJECT"
                print(f"| {idx}. [{c.get('score', 0):+.4f}] [{verdict}] File: {c.get('source_file')} | Mode: {c.get('mode')} ({f_skip_str}) | Offset: {c.get('offset')}")
                pt = c.get("plaintext", "")
                if pt:
                    print(f"|    Latin: {pt[:65]}...")
        else:
            print("| No viable candidate alignments found.")
        print("+--------------------------------------------------------------------------\n")


    def print_lexicon(self, data: dict):
        action = data.get("action", "phrases")
        print("\n+--- [MASTER LEXICON & PHILOSOPHICAL PHRASE HARVESTER] -------------------")
        if action == "phrases":
            total = data.get("total", 0)
            items = data.get("items", [])
            print(f"| Harvested Philosophical Phrases: {total} total (showing first {len(items)}):")
            print("|")
            for i in range(0, len(items), 2):
                c1 = f"{items[i]:<34}"
                c2 = f"{items[i+1]:<34}" if i + 1 < len(items) else ""
                print(f"|   {c1} {c2}")
        elif action == "words":
            total = data.get("total", 0)
            items = data.get("items", [])
            print(f"| Master Keyword Vocabulary: {total} words (showing first {len(items)}):")
            print("|")
            for i in range(0, len(items), 3):
                row = "  ".join(f"{items[j]:<22}" for j in range(i, min(i + 3, len(items))))
                print(f"|   {row}")
        else:
            print(f"| Total Phrases: {data.get('total_phrases', 0)} | Total Master Words: {data.get('total_words', 0)}")
        print("+--------------------------------------------------------------------------\n")


    def print_opsec(self, data: dict):
        if "error" in data:
            print(f"[!] OpSec Error: {data['error']}")
            return

        p = data["pgp"]
        f = data["features"]
        print("\n+--- [OPSEC & SIGNAL TELEMETRY] -------------------------------------------")
        if data["is_file"] and data["file_info"]:
            fi = data["file_info"]
            print(f"| File:            {data['target']} ({fi.get('size_bytes', 0)} bytes)")
            print(f"| Detected Type:   {fi.get('detected_type', 'Unknown')}")
            print(f"| Steg Target?     {fi.get('is_steg_candidate', False)}")

        print(f"| PGP Verdict:     [{p['verdict']}]")
        print(f"| Authentic 3301:  {p['is_official_key']} (Official Key: {CICADA_KEY_ID})")
        print(f"| Shannon Entropy: {f['entropy']} bits/char (High Entropy? {f.get('is_high_entropy', False)})")
        print(f"| Index of Coinc:  {f['ioc']}")
        print(f"| Signal Class:    [{f['classification'].upper()}]")
        print("+--------------------------------------------------------------------------\n")


    def print_layout_calibration(self, data: dict):
        print("\n+--- [LAYOUT SIDE-CHANNEL MUTUAL INFORMATION CALIBRATION] -----------------")
        print("| Family:          layout-carrier")
        print(f"| Total Tests:     {data.get('total_evaluations', 0)}")
        print("| Method:          Miller-Madow Bias Corrected MI + Sequential MC Permutation Null")
        print("|\n| Page  Title                N    Cipher          Key            Max I_MM (b)  Min p   Verdict")
        for p in data.get("pages", []):
            feats = p.get("features", {})
            max_mm = max((f["mi_mm"] for f in feats.values()), default=0.0)
            min_p = min((f["p_value"] for f in feats.values()), default=1.0)
            any_sig = any(f["is_significant"] for f in feats.values())
            verdict = "CARRIER" if any_sig else "EXCLUDED"
            key_display = p.get("key") or "-"
            title_trunc = (p.get("title") or "")[:20]
            cipher_trunc = (p.get("cipher") or "")[:14]
            print(f"| {p.get('page'):<4d}  {title_trunc:<20} {p.get('rune_count'):<4d} {cipher_trunc:<14}  {key_display:<14} {max_mm:<12.4f}  {min_p:<7.3f} {verdict}")

        print("|\n+--------------------------------------------------------------------------")
        print(f"| Overall Conclusion: [{data.get('overall_outcome', 'Outcome A')}]")
        print("+--------------------------------------------------------------------------\n")


    def print_layout_page(self, data: dict):
        stream = data["stream"]
        feats = data["features"]
        key_str = data.get("known_key")
        print(f"\n+--- [LAYOUT SIDE-CHANNEL TELEMETRY: {stream.page_id}] ----------------------")
        print(f"| Rune Count (N):    {len(stream)}")
        print(f"| Word Count:        {len(stream.words)}")
        print(f"| Line Count:        {len(stream.lines)}")
        print(f"| Fehu (ᚠ) Count:    {sum(stream.fehu_flags)}")
        sep_counts = {
            "᛫ (Word)": stream.separators.count("᛫"),
            "᛬ (Clause)": stream.separators.count("᛬"),
            "᛭ (Cross)": stream.separators.count("᛭"),
        }
        sep_str = " | ".join(f"{k}: {v}" for k, v in sep_counts.items())
        print(f"| Separators:        {sep_str}")
        if key_str:
            print(f"| Tested Keystream:  Key '{key_str}' (Canonical shifts)")
        else:
            print("| Tested Keystream:  Identity (shift 0)")
        print("|\n| Feature         I_raw (b)  Bias (b)   I_MM (b)   p-value  Trials  Verdict")
        for fname, r in feats.items():
            print(f"| {fname:<15} {r['mi_raw']:<10.4f} {r['bias']:<10.4f} {r['mi_mm']:<10.4f} {r['p_value']:<8.3f} {r['trials']:<7d} {r['outcome'][:15]}")
        print("+--------------------------------------------------------------------------\n")

    def print_explain(self, steps: Optional[List[dict]] = None):
        """Display mathematical calculation trace."""
        if not steps:
            print("\n[!] No calculation trace available. Run /crack first.\n")
            return
        print("\n+--- [MATHEMATICAL CALCULATION TRACE] -------------------------------------")
        for s in steps:
            print(f"| {s.get('stage')} ({s.get('module')}):")
            print(f"|   Formula: {s.get('formula')}")
            print(f"|   Result:  {s.get('result')} [{s.get('verdict')}]")
        print("+--------------------------------------------------------------------------\n")


    def print_command_list(self):
        """Display refined, categorized command reference divided by type."""
        print("-" * 78)
        print("COMMANDS REFERENCE: (Categorized by Type)")
        print("  [CRYPTANALYSIS]  /crack       /solve       /gematria      /atbash")
        print("                   /vigenere    /totient-stream             /triage")
        print("                   /period      /crib        /opsec         /layout")
        print("                   /lexicon     /running-key /running-key-scan")
        print("  [KNOWLEDGE]      /ask         /web         /page          /organize  /ingest")
        print("  [AI ENGINE]      /key (AI keys & config)   /provider      /model")
        print("                   /think       /boost       /host          /profile   /cache")
        print("  [SYSTEM]         /status      /bench       /hardware    /clear     /help")
        print("                   /exit        (Hardware aliases: /gpu, /metal, /ane)")
        print("  (Type any natural language query to ask the RAG assistant directly)")
        print("-" * 78)


    def print_help(self, command: Optional[str] = None):
        """Explain every command and its functions, with optional per-command deep dive."""
        import textwrap

        if command:
            cmd_norm = command.strip().lower()
            if not cmd_norm.startswith("/"):
                cmd_norm = "/" + cmd_norm
            if cmd_norm in ("/quit",):
                cmd_norm = "/exit"
            if cmd_norm in self.COMMAND_DOCS:
                doc = self.COMMAND_DOCS[cmd_norm]
                header = f"+--- [HELP: {cmd_norm}] "
                dashes = "-" * max(2, 78 - len(header))
                print(f"\n{header}{dashes}")
                print(f"| Summary:     {doc['summary']}")
                print(f"| Syntax:      {doc['syntax']}")
                print(f"| Description: {doc['description']}")
                if doc.get("options"):
                    print("|\n| Options / Flags:")
                    for opt in doc["options"]:
                        print(f"|   {opt}")
                if doc.get("examples"):
                    print("|\n| Examples:")
                    for ex in doc["examples"]:
                        print(f"|   {ex}")
                print("+" + "-" * 77 + "\n")
                return
            else:
                print(f"[!] Unknown command '{command}'. Type '/help' for full command manual.\n")
                return

        # Full manual display categorized by function
        print("\n" + "=" * 78)
        print("TRITHEMIUS WORKSTATION — COMPLETE COMMAND REFERENCE MANUAL")
        print("=" * 78)

        categories = [
            ("1. RAG & KNOWLEDGE RETRIEVAL", [
                ("/ask [--fresh] <query>", "Query RAG cryptanalytic engine with hybrid retrieval & routing"),
                ("/web <query>", "Query RAG engine (offline Liber Primus corpus fallback)"),
                ("/page <page_num>", "Inspect and transcribe specific Liber Primus page from corpus"),
            ]),
            ("2. CRYPTANALYSIS & SACRED NUMEROLOGY", [
                ("/gematria <runes|latin>", "Gematria Primus prime sum, totient, prime check & Atbash"),
                ("/atbash <t> [--shift N]", "Modulo-29 Atbash and Caesar-shifted Atbash reflection cipher"),
                ("/vigenere <enc|dec> <t> <k>", "Modulo-29 (Futhorc) or Modulo-26 (Latin) Vigenère cipher solver"),
                ("/totient-stream <m> <t>", "Liber Primus Prime Totient Stream Cipher (phi(p) = p - 1)"),
                ("/solve [target|all]", "Solve and verify canonical Liber Primus solved pages from wiki"),
                ("/crack <target> [options]", "Automated Liber Primus GF(29) Cryptanalytic Cascade Solver"),
                ("/triage <target>", "Statistical triage & cipher family classification (IC, kappa, entropy)"),
                ("/period <target> [max_p]", "Key length consensus & difference periodogram comb filter"),
                ("/crib <target> <crib>", "Slide known crib for Berlekamp-Massey LC & stream matching"),
                ("/opsec <target>", "Verify Cicada 3301 PGP 7A35090F signature & Shannon entropy"),
                ("/layout [target|calibrate]", "Layout side-channel mutual information & calibration"),
                ("/running-key <p> <t>", "GF(29) running-key decryption against reference text"),
                ("/running-key-scan <p>", "Sliding window running-key scan across reference texts"),
                ("/lexicon [phrases|words]", "Inspect master vocabulary and philosophical phrases"),
                ("/ledger [page]", "Inspect tested words and attempts in ChromaDB vector store"),
            ]),
            ("3. CORPUS MANAGEMENT & INGESTION", [
                ("/organize", "Deduplicate and classify corpus documents via Porta"),
                ("/ingest", "Chunk and index corpus documents into ChromaDB vector database"),
            ]),
            ("4. MODEL, ENGINE & HARDWARE CONFIGURATION", [
                ("/key [show|clear|<p> <k>]", "AI API keys & cloud provider configuration section"),
                ("/think [on|off|toggle]", "Toggle Chain-of-Thought (CoT) reasoning for reasoning models"),
                ("/boost [on|off|status]", "Toggle Deep Cryptanalytic Retrieval & Reranking Boost mode"),
                ("/provider [name]", "Switch active LLM provider (ollama, groq, openai, anthropic, etc.)"),
                ("/model [key_or_name]", "Switch active language model key or specify custom model"),
                ("/host [url]", "Set remote Ollama streaming endpoint host URL"),
                ("/profile [mode]", "Toggle hardware profile between standard and low-spec footprint"),
                ("/cache clear", "Clear exact RAG response cache in vectordb/cache.sqlite3"),
            ]),
            ("5. TELEMETRY, BENCHMARKING & SYSTEM", [
                ("/status", "Display system telemetry, provider health, model & corpus metrics"),
                ("/bench [options]", "Run microsecond latency benchmark suite & hotspot profiling"),
                ("/clear", "Clear terminal screen buffer"),
                ("/help [command]", "Display command manual or detailed help for a specific command"),
                ("/exit, /quit", "Safely exit and disconnect from Trithemius Workstation"),
            ]),
        ]

        syn_w = 30
        sum_w = 78 - syn_w - 4
        indent = " " * (syn_w + 4)

        for cat_title, cmd_tuples in categories:
            cat_header = f"--- {cat_title} "
            cat_dashes = "-" * max(2, 78 - len(cat_header))
            print(f"\n{cat_header}{cat_dashes}")
            for syn, summ in cmd_tuples:
                wrapped = textwrap.wrap(summ, width=sum_w)
                if not wrapped:
                    wrapped = [""]
                print(f"  {syn:<{syn_w}}  {wrapped[0]}")
                for extra in wrapped[1:]:
                    print(f"{indent}{extra}")

        print("\nTip: Type '/help <cmd>' (e.g. '/help gematria' or '/help boost') for details.")
        print("=" * 78 + "\n")


    def print_status(self, telemetry: dict, probe_results: Optional[list] = None):
        print("\n+--- [TRITHEMIUS SYSTEM TELEMETRY] ---------------------------------------")
        print(f"| Active Provider: {telemetry['provider_desc']}")
        print(f"| Active Model:    {telemetry['active_model']} ({telemetry['model_key']})")
        print(f"| Hardware Profile:{telemetry['profile_desc']}")
        print(f"| Chain-of-Thought:{'ENABLED' if telemetry.get('think') else 'DISABLED'}")
        print(f"| Retrieval Boost: {'ENABLED (Top-K=10, 2x Rerank Multiplier)' if telemetry.get('boost') else 'DISABLED'}")
        print(f"| Context Window:  {telemetry['context_window']} tokens")
        print(f"| Configured Keys: {telemetry['keys_summary']}")
        print(f"| Corpus Files:    {telemetry['corpus_files']} files in corpus/")
        print(f"| Vector Database: {telemetry['chunk_count']} chunks indexed in vectordb/ (BM25 zero-VRAM ready)")
        print(f"| Official PGP:    {telemetry['pgp_key_id']} ({telemetry['pgp_fingerprint']}...)")
        print("+--------------------------------------------------------------------------\n")

        if probe_results is not None:
            print("\n+--- [PROVIDER & MODEL HEALTH PROBE] -------------------------------------------------------------+")
            print(f"| {'Provider':<12} | {'Model':<30} | {'Status':<6} | {'Latency':<9} | {'Details':<26} |")
            print("+--------------+--------------------------------+--------+-----------+----------------------------+")
            for r in probe_results:
                status_str = "[OK]" if r["ok"] else "[FAIL]"
                lat_str = f"{r['latency_ms']:.1f} ms" if r["latency_ms"] > 0 else "-"
                detail_str = (r.get("details") or r.get("reason") or "")[:26]
                print(f"| {r['provider'].upper():<12} | {r['model']:<30} | {status_str:<6} | {lat_str:<9} | {detail_str:<26} |")
            print("+--------------+--------------------------------+--------+-----------+----------------------------+\n")
