# Cryptographic Engine & Cipher Modules

Pure-Python, zero-overhead, dependency-free cryptography modules for Liber Primus research and general cryptanalysis over Galois fields, number-theoretic streams, lattice reductions, and hardware compute accelerators.

All modules are designed according to strict standard-library principles:
- **Zero Mandatory External Dependencies**: 100% portable pure-Python standard library implementations across macOS, Linux, and Windows.
- **Cold-Start Latency**: `< 50ms` cold-start import time across all cryptographic modules.
- **Hardware Compute Layer with CPU Fallback**: Apple Silicon Metal GPU compute engine and Apple Neural Engine (ANE CoreML) acceleration with automatic, bit-exact pure-Python CPU fallbacks.

---

## 1. Primary Classical & Sacred Cryptography Modules

### agrippa.py — Gematria Primus & Sacred Math
Named for Heinrich Cornelius Agrippa (1486–1535). Implements the official 29-rune Anglo-Saxon Futhorc alphabet of the *Liber Primus*, mapping runes to indices ($0..28$) and sacred primes ($2..109$):
- Bidirectional Latin $\leftrightarrow$ Futhorc transliteration with English digraph handling (`TH`, `ING`, `EO`, `OE`, `AE`, `IA`, `EA`).
- Gematria prime sum calculations ($\sum \text{prime}(r)$) and per-word sums.
- Runic Atbash reflection ($r \mapsto 28 - r$).
- Sacred arithmetic: deterministic $6k \pm 1$ primality testing, Euler totient $\phi(n)$, and prime factorization.

### kasiski.py — Vigenère Solvers & Keystreams
Named for Friedrich Kasiski (1805–1881). Polyalphabetic substitution and stream generation:
- Modulo-29 runic Vigenère encoding and decoding in $\mathbb{F}_{29}$.
- Classical modulo-26 A–Z Vigenère with Friedman test and per-column $\chi^2$ key cracking.
- Dynamic keystream generators: prime sequences, Fibonacci sequences, Euler totient streams $\phi(p_k)$.
- Index of Coincidence (IoC) and Kasiski repeated-factor period estimation.

### al_kindi.py — Statistical Gatekeeper & Plausibility Filter
Named for Abu Yusuf Al-Kindi (801–873). Filters candidate decryptions against natural English:
- Length-invariant Kullback-Leibler divergence $D_{\text{KL}}(P_{\text{obs}} \parallel P_{\text{ref}})$ with Gibbs non-negativity lower bound clamp ($D_{\text{KL}} \ge 0.0$).
- Reduced chi-squared $\chi^2_\nu = \chi^2 / 25$ with analytical $p$-value via standard-library Wilson-Hilferty transformation (`math.erfc`).
- High-frequency English trigram and quadgram log-likelihood scoring.
- $O(1)$ master philosophical and cryptanalytic dictionary validation (`CORE_WORDS_FROZEN`).

### taxonomy.py — Comprehensive $\mathbb{F}_{29}$ Cryptanalytic Suite
Unified cascade solver and cryptanalytic taxonomy for recovering keys over the $\mathbb{F}_{29}$ linear channel:
- Calibrated hybrid bigram language model ($0.35 P_{\text{lp}} + 0.65 P_{\text{bg}}$) with Lidstone smoothing and persistent caching (`vectordb/z29_background_bigrams.json`).
- Statistical triage (unigram IC, normalized $\kappa = 29 \cdot \text{IC}$, bigram IC, conditional entropy, difference IoC).
- Multi-metric consensus key length estimation (Kasiski GCD, difference periodogram comb, column IoC).
- Separable $O(29 \cdot m)$ T-table solver, MIC gauge alignment, and coupled hill climbing.
- Matched-filter stream hash bank and fuzzy OEIS sequence matcher (Hamming distance $\le 2$ tolerance).
- Nonlinear S-box sweeps (affine inversion, power maps, Möbius maps) and `--include-ecc` keystream sweep.
- Seed-isolated Monte Carlo surrogate shuffle significance testing ($Z$-score, Bonferroni/Šidák $p_{\text{adj}}$) with automated SQLite ledger logging.

### entropy.py — Shannon Entropy & Signal Classification
Information density profiling and multi-alphabet signal detection:
- Alphabet-aware normalization across 4 distinct alphabets: Futhorc ($\mathbb{Z}_{29}$), Hexadecimal ($|\Sigma|=16$), Latin ($|\Sigma|=26$), and Raw Binary ($|\Sigma|=256$).
- Automatic rune delimiter filtering (`᛫`, `᛬`, `᛭`, whitespace) to prevent artificial entropy suppression.
- First-order Miller-Madow sample bias correction: $\hat{H}_{\text{MM}}(X) = H_{\text{obs}}(X) + \frac{m - 1}{2N \ln 2}$.
- 4D feature vector $\vec{F}$ (entropy, IoC, $\chi^2$, byte variance) classifying data as ciphertext/compressed, structured, or natural language.

### opsec.py — Cryptographic Verification & Authenticity
Forensic signal intelligence, signature verification, and security audit:
- PGP message and signature inspection against the official pinned Cicada 3301 primary key fingerprint `6D854CD7933322A601C3286D181F01E57A35090F` (Key ID `7A35090F`).
- Container magic byte detection and container grammar isolation.
- Binary Fast Walsh-Hadamard Transform (FWHT) and Difference Distribution Table (DDT) checks for S-box nonlinearity and differential uniformity.
- Comprehensive RSA public key audit pipeline (Miller-Rabin, Fermat close primes, Pollard's rho, Wiener continued fractions).

### solved_pages.py — Canonical Liber Primus Solved Pages
Faithful implementations and golden verification vectors for all 9 historically solved Liber Primus pages documented by the official community wiki.

### provenance.py — Forensic Manuscript Scan Validation
Header-level container provenance gate validating original 2014 Liber Primus JPEG scans against structural invariants: geometry ($2400 \times 3600$), JFIF density ($400 \text{ DPI}$), and APP2 Artifex Software ICC markers.

---

## 2. Specialized Cryptanalysis Modules (Previously Unlisted 14 Modules)

### affine.py — Semantic Normal Form & Group Reductions
Reduces arbitrary sequences of modular operations over $\mathbb{Z}_{29}$ into unique canonical irreducible form:
- Reduces Atbash, Caesar shifts, and affine mappings to $x \mapsto (ax + b) \bmod 29$ with $\gcd(a, 29) = 1$.
- Implements group operations for cyclic group $C_{29}$, dihedral group $D_{29}$ (order 58), and affine group $\text{Aff}(\mathbb{Z}_{29})$ (order 812).

### container.py — Polyglot Container Grammar & Overlay Analysis
Walks container structural grammar to true logical EOF without third-party dependencies:
- Format parsers: JPEG (JFIF/EXIF markers), PNG (chunk CRCs to `IEND`), GIF (`0x3B` trailer), ZIP (`EOCD`), and PDF (`%%EOF`).
- Isolates appended overlay payloads, computes overlay Shannon entropy, and flags polyglot/steganography targets.

### difference.py — Difference-Domain Constraint Solving & Sacred Sequences
Cryptanalysis in the forward difference domain $\Delta_i = (c_{i+1} - c_i) \bmod 29$:
- Zero-hole constraint checking ($\Delta c_i \neq 0$) reflecting empirical suppression of consecutive double runes in Liber Primus.
- Extended number-theoretic functions: Möbius $\mu(n)$, Liouville $\lambda(n)$, Carmichael $\lambda(n)$, and divisor functions $\sigma(n), d(n), \omega(n), \Omega(n)$.
- Difference Index of Coincidence `difference_ioc(runes, lag=1, modulus=29)` and word-level pattern IoC `pattern_ioc(words)`.

### fingerprint.py — Statistical Fingerprint & Forward Simulation
Likelihood-free inference (Analysis-by-Synthesis) for $\mathbb{Z}_{29}$ ciphertexts:
- Forward-simulates candidate cipher families on representative plaintext.
- Extracts summary vectors (doublet rate, $Z$-score, $N \cdot \text{IoC}$, consecutive difference zero suppression) and evaluates distance against the empirical Liber Primus manuscript profile.

### hash_hunt.py — Combinatorial 512-bit Hash Lattice
Combinatorial hash search engine targeting the unsolved 512-bit hash digest on Page 56 / 73:
- Normalization lattice evaluating combinations of hash algorithms (SHA-512, SHA3-512, BLAKE2b), text encodings (UTF-8, ASCII, UTF-16), and line delimiters (LF, CRLF, stripped).

### interrupter.py — Dynamic Keystream Interrupter Engine
Models dynamic keystream scheduling observed in solved pages (Pages 03–04, 14–15):
- 5 dynamic interrupt modes: cleartext Fehu pause (F-skip), ciphertext matching, key pausing vs advancing, and positional masks.
- Diagnostics for cleartext Fehu periodicity (`analyze_f_skip_periodicity`) and consecutive duplicate rune elevation (`detect_double_runes`).
- Constraint oracle callbacks for DPLL/CDCL SAT solver pruning via blocking clauses.

### keymap.py — Byte-to-$\mathbb{Z}_{29}$ Keystream Mapping
Translates arbitrary binary streams (hashes, PGP blocks, file headers) into valid $\mathbb{Z}_{29}$ keystreams:
- Mapping modes: naive modulo (`mod29`), rejection sampling for bytes $< 232$ (`reject232`) ensuring uniform distribution, and big-integer base-29 expansion (`base29`).

### lagcoinc.py — Exact 29-Channel FFT Coincidence Spectrum
Computes the full lag coincidence spectrum $\kappa(d) = \sum I(c_i = c_{i+d})$ across all lags $d \in [1, L-1]$:
- Indicator-channel decomposition into 29 binary sequences transformed via Fast Fourier Transforms in $O(29 \cdot N \log N)$ complexity.
- Automatic fallback between vectorized NumPy operations and pure-Python FFT.

### layout.py — Layout Side-Channel Mutual Information
Analyzes Liber Primus physical layouts as multiplexed side-channel carriers:
- Computes mutual information $I(\text{layout}; \text{keystream shift})$ between layout boundaries (separators `᛫`, `᛬`, `᛭`, line breaks, word lengths) and candidate key shifts.
- Validates significance via Miller-Madow bias correction and Besag-Clifford sequential Monte Carlo permutations.

### lexicon.py — Master Vocabulary & Candidate Transform Engine
Aggregates philosophical, occult, and mathematical vocabularies from Cicada 3301 lore:
- Generates multi-vector representations: forward, reversed, Atbash, prime mod 29, and variant Beaufort.
- Implements $O(1)$ prefix and set-membership lookups via `LexiconIndex`.

### running_key.py — Running-Key & Book Cipher Engine
Cryptanalysis of running-key ciphers over $\mathbb{F}_{29}$ Futhorc:
- Supports standard subtraction, addition, and variant Beaufort modes with dynamic cleartext Fehu-skip propagation.
- Sliding-window scanner across canonical reference literature in `corpus/reference_texts/`.

### sprt.py — Sequential Probability Ratio Test
Wald's SPRT for calibrated $\mathbb{Z}_{29}$ bigram language models:
- Early-stopping hypothesis testing discriminating between uniform noise $H_0$ and natural runic text $H_1$.
- Evaluates log-likelihood ratios with decision boundaries $A = \ln((1-\beta)/\alpha)$ and $B = \ln(\beta/(1-\alpha))$, enabling microsecond rejection of non-viable keys.

### unicity.py — Shannon Unicity Distance & Identifiability Budget
Computes information-theoretic bounds for cryptanalysis over $\mathbb{Z}_{29}$:
- Per-symbol language redundancy $D = \log_2(29) - H_L$.
- Shannon unicity distance $U = H(K) / D$.
- Maximum resolvable periodic key length $m_{\max} = N \cdot D / \log_2(29)$.

### zimmermann.py — Native RFC 4880 OpenPGP Verification
Zero-dependency, pure-Python RFC 4880 OpenPGP packet parser and signature verifier:
- RSA signature verification and PKCS#1 v1.5 padding checks with constant-time equality comparisons (`hmac.compare_digest`).
- Hash algorithms: SHA-256, SHA-384, SHA-512, SHA-224, and SHA-1.

---

## 3. Hardware Compute Acceleration & Fallback Layer

### metal_accel.py — Apple Silicon Metal GPU Compute Engine
Leverages Apple Silicon Metal compute shaders (`ciphers/metal_engine.m`, `ciphers/metal_engine.dylib`) and Unified Memory Architecture (UMA):
- High-throughput parallel key scoring ($> 10^7$ candidate keys/sec).
- 2-word and 3-word combinatorial compound phrase sweeps across precomputed T-tables.
- Massive parallel Monte Carlo surrogate shuffles.
- **Transparent CPU Fallback**: When running on Linux, Windows, or environments without Metal or NumPy, all operations transparently fall back to scalar pure-Python execution paths with identical semantics.

### ane_engine.py — Apple Neural Engine (ANE) CoreML Interface
Utilizes the Apple Silicon 16-core NPU via ONNX Runtime `CoreMLExecutionProvider`:
- Evaluates candidate plaintext naturalness and likelihood locally without network traffic.
- Transparent CPU fallback when the neural engine is unavailable.

---

## 4. Phase 2 Advanced Cryptanalytic Engines

### spectral_sbox.py — Differential & Nonlinear S-Box Analysis over $\mathbb{F}_{29}$
Comprehensive cryptographic S-box analysis suite operating over $\mathbb{F}_{29}$ and binary vector spaces:
- S-box generators: affine inversion $S(x) = (a \cdot x^{-1} + b) \bmod 29$ ($0^{-1} := 0$), Möbius maps on $\mathbb{P}^1(\mathbb{F}_{29})$, power maps $x^k \bmod 29$ for $\gcd(k, 28) = 1$, and double-affine compositions.
- Difference Distribution Table (DDT) and differential uniformity $\delta = \max_{\Delta x \neq 0, \Delta y} \text{DDT}(\Delta x, \Delta y)$ for both $\mathbb{Z}_{29}$ additive and bitwise XOR differences.
- Linear Approximation Table (LAT), Fast Walsh-Hadamard Transform (FWHT), nonlinearity (NL), Strict Avalanche Criterion (SAC), and algebraic degree (AD).
- Discrete Fourier Transform bias over $\mathbb{Z}_{29}$ and linear hull potential via correlation matrix powers $C^r$.

### algebraic.py — Algebraic Cryptanalysis via Macaulay Matrices / XL
Polynomial system solving and nonlinear feedback shift register (NLFSR) identification over $\mathbb{F}_{29}$:
- Multivariate polynomials in $\mathbb{F}_{29}[x_1, \dots, x_n]$ under degree reverse lexicographical (degrevlex) monomial ordering using sparse exponent mappings.
- Macaulay matrix generator $\mathcal{M}(D)$ building monomial shifts up to degree $D$.
- In-place Gaussian elimination over $\mathbb{F}_{29}$ to Reduced Row Echelon Form (RREF) using precomputed modular inverses.
- Nonlinear recurrence detector identifying quadratic and cubic NLFSR feedback polynomials from sequence fragments.
- SageMath Groebner basis / FGLM script exporter for large systems ($D > 3$ or columns $> 2000$).

### lattice.py — Lattice Reduction, Coppersmith Small Roots & Knapsack Solvers
Pure-Python lattice-based cryptanalysis:
- Gram-Schmidt orthogonalization and Lenstra–Lenstra–Lovász (LLL) basis reduction ($\delta = 0.99$, dimensions up to 40).
- Coppersmith's small roots algorithm for univariate modular polynomials via Howgrave-Graham lattice shifts.
- Low-density knapsack subset sum solver (Lagarias-Odlyzko / CJLOSS) targeting Gematria Primus prime weights.
- Integer relation detection (PSLQ analogue) over integer vectors.

### rsa_audit.py — Comprehensive RSA Security Audit Pipeline
Systematic audit suite evaluating RSA moduli and public keys:
- Deterministic Miller-Rabin primality certification using 12 certified bases for 64-bit integers and arbitrary-precision bounds.
- Fast factorization engines: Fermat's method for close primes, Pollard's rho with Brent's cycle detection and batched GCDs, and pairwise batch GCD across modulus collections.
- Small private exponent attacks: Wiener's continued fractions attack ($d < \frac{1}{3} N^{0.25}$), compact Boneh-Durfee lattice attacks, and shared prime MSB/LSB hybrid attacks.

### sat_oracle.py — Programmatic DPLL/CDCL SAT Solver with Watched Literals
Pure-Python Boolean satisfiability solver with custom cryptanalytic oracle hooks:
- Two-watched-literals scheme, decision heuristic (VSIDS-style), and conflict-driven clause learning (CDCL).
- Programmatic callback interface `oracle_fn(partial_assignment)` allowing cipher models to dynamically inspect candidate states.
- Non-chronological backjumping triggered by programmatic blocking clauses, accelerating search across Fehu skip positions and ambiguous runes.

### ecc_stream.py — Elliptic Curve Keystream Generator
Short Weierstrass elliptic curve arithmetic over prime fields $\mathbb{F}_p$ ($p \ge 5$):
- Curve verification: $y^2 = x^3 + ax + b \bmod p$ with discriminant $\Delta = -16(4a^3 + 27b^2) \bmod p$ and non-singularity enforcement ($4a^3 + 27b^2 \not\equiv 0 \pmod p$).
- Complete group law: point addition, point doubling, point negation, identity (point at infinity $\mathcal{O}$), and scalar multiplication via double-and-add.
- Hasse's theorem verification ($|\#E(\mathbb{F}_p) - (p+1)| \le 2\sqrt{p}$), Tonelli-Shanks modular square roots, and naive point counting on small fields.
- Deterministic keystream generation extracting $x(kP) \bmod 29$ and $y(kP) \bmod 29$ over $\mathbb{F}_{29}$ and canonical Cicada primes ($p = 3301, 1033, 761$).
- Stream encryption and decryption helpers in Futhorc rune space.
