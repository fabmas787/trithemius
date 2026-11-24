# Trithemius — Liber Primus Research Assistant

A local RAG-powered assistant + cryptography toolkit for investigating the Cicada 3301 mystery and the Liber Primus.
Runs locally using Ollama (**SparkLLM/Spark-X2.5-4B** or **DeepSeek-Coder-V2-Lite MoE**) + ChromaDB.

Each module is named after a historical cryptographer, philosopher, or scholar whose work matches its purpose:
- **Trithemius** (Johannes Trithemius, 1462–1516): Father of Western steganography & cryptography — Lead orchestrator & RAG assistant.
- **Agrippa** (Heinrich Cornelius Agrippa, 1486–1535): Occult philosopher & numerologist — 29-rune Gematria Primus & sacred math.
- **Kasiski** (Friedrich Kasiski, 1805–1881): Pioneer of polyalphabetic cryptanalysis — Vigenère mod-29 solver & keystreams.
- **Al-Kindi** (Abu Yusuf Al-Kindi, 801–873): Inventor of frequency analysis — Chi-squared & quadgram statistical gatekeeper.
- **Bodley** (Sir Thomas Bodley, 1545–1613): Founder of the Bodleian Library — Page-aware chunking & ChromaDB vector ingestion.
- **Porta** (Giambattista della Porta, 1535–1615): Renaissance author of *De Furtivis Literarum Notis* — Corpus classifier, standardized renaming & deduplication.
- **Walsingham** (Sir Francis Walsingham, 1532–1590) `[ARCHIVIATO]`: Spymaster di Elisabetta I — Web scout autonomo (archiviato e sostituito stabilmente dalla pipeline deterministica offline Bodleian + Porta + RAG).
- **Bacon** (Roger Bacon, 1220–1292) `[ARCHIVIATO]`: Empirista medievale — Iniezione di contesto da ricerche web live (archiviato; il comando `/web` opera ora come interrogazione RAG sul corpus offline).

---

## Architecture Overview

```
[Master Transcript & Corpus Curato] ──► [scripts/split_master_transcript.py]
                                                          │
                                                          ▼
                                                 [corpus/ Directory]
                                                          │
                         ┌────────────────────────────────┼────────────────────────────────┐
                         ▼                                ▼                                ▼
               [scripts/porta.py]               [scripts/bodleian.py]              [ciphers/opsec.py]
            (Classifica & Rinomina, 0 VRAM)   (Chunking Entropia & ChromaDB)       (Verifica PGP 7A35090F)
                                                          │
                                                          ▼
                                                [vectordb/ (ChromaDB)]
                                                          │
                                                          ▼
                                        [Trithemius Terminal Workstation]
                                                 (trithemius.py)
                                             SparkLLM / DeepSeek MoE
```

> [!NOTE]
> **Architettura 100% Offline e Deterministica**: Gli strumenti storici di web scraping (`scripts/walsingham.py`) e ricerca web live (`scripts/bacon.py`) sono stati archiviati e sostituiti stabilmente dalla pipeline deterministica offline **Bodleian + Porta + RAG**. Il comando `/web` della workstation è un alias diretto per l'interrogazione RAG del corpus locale indicizzato, garantendo confidenzialità crittografica (OpSec), assenza di latenze di rete e riproducibilità scientifica assoluta.

1. **trithemius.py** — Workstation crittanalitica terminal-first unificata (shell interattiva REPL + comandi diretti CLI).
2. **corpus/** — Testi grezzi: trascrizioni delle pagine, indice dei riferimenti (`pages_index.json`) e letteratura filosofica di confronto (`reference_texts/`).
3. **scripts/split_master_transcript.py** — Utility di partizionamento del transcript master runico del Liber Primus in pagine runiche standardizzate con preservazione dei delimitatori.
4. **scripts/porta.py** — Bibliotecario del corpus (identificazione numeri di pagina, standardizzazione dei nomi file, rimozione duplicati a 0% VRAM).
5. **scripts/bodleian.py** — Chunking a finestra scorrevole basato su entropia di Shannon, rilevamento rune e ingestione vettoriale in ChromaDB.
6. **scripts/ask.py** — Motore di interrogazione RAG ibrido con token streaming e filtro per pagina (`/page 56`).
7. **scripts/normalize_runes.py** — Normalizzazione dei caratteri runici Futhorc (`᛫`, `᛬`, `᛭`) e pulizia OCR.
8. **scripts/solve_canonical.py** — Risolutore e verificatore stand-alone per tutte le 9 pagine storicamente risolte del Liber Primus.
9. **scripts/totient_stream.py** — Utility stand-alone per il cifrario a flusso basato sui totienti di Eulero dei numeri primi sacri ($\phi(p) = p - 1 \pmod{29}$) con gestione pause Fehu (F-skip).
10. **scripts/cryptanalyze_page56.py** — Cascade solver e analisi esaustiva per la Pagina 56 / 73 (ipotesi totienti, orbite di Pisano in $\mathbb{F}_{29}$, interrupter Vigenère e logging su ledger SQLite).
11. **scripts/benchmark.py** — Benchmarking cProfile, baseline comparison e test di latenza per primitive crittografiche.
12. **ciphers/agrippa.py** — Mappatura ufficiale Gematria Primus a 29 rune, valori primi sacri (2..109), somme di parole, Atbash runico, totienti di Eulero.
13. **ciphers/kasiski.py** — Risolutore Vigenère modulo-29 in $\mathbb{F}_{29}$, keystream canonici Cicada (primi, Fibonacci, totienti), Indice di Coincidenza (IoC) e test di Friedman.
14. **ciphers/al_kindi.py** — Chi-quadro goodness-of-fit, verosimiglianza logaritmica quadgrammi/trigrammi inglesi, validazione del vocabolario dizionario.
15. **ciphers/taxonomy.py** — Suite tassonomica avanzata GF(29), modelli linguistici calibrati, periodogrammi, T-table solver, crib dragging, sweep S-Box nonlinear, sweep keystream ECC `--include-ecc`, e test surrogati Monte Carlo.
16. **14 Moduli Crittanalitici Specializzati (`ciphers/`)**:
    - `affine.py`: Forma canonica irriducibile $(ax + b) \bmod 29$ e riduzioni sui gruppi $C_{29}$, $D_{29}$, $\text{Aff}(\mathbb{Z}_{29})$.
    - `container.py`: Parser di grammatica container fino a EOF logico (JPEG, PNG, GIF, ZIP, PDF) ed estrazione overlay steganografici.
    - `difference.py`: Constraint solving nel dominio delle differenze $\Delta_i$, vincolo zero-hole, sequenze sacre ($\mu, \lambda, \lambda_{\text{carm}}, \sigma, d, \omega, \Omega$), difference IoC e pattern IoC.
    - `fingerprint.py`: Likelihood-free inference (Analysis-by-Synthesis) e confronto feature vector contro il profilo empirico del Liber Primus.
    - `hash_hunt.py`: Reticolo combinatorio per la ricerca dell'hash a 512 bit di Pagina 56 (SHA-512, SHA3-512, BLAKE2b).
    - `interrupter.py`: Motore interrupter dinamico a 5 configurazioni, pause Fehu (F-skip), diagnostica duplicati e callback per clausole SAT blocking.
    - `keymap.py`: Mappatura canonica di byte arbitrari in keystream in $\mathbb{Z}_{29}$ (`mod29`, `reject232`, `base29`).
    - `lagcoinc.py`: Spettro esatto di coincidenza via FFT su 29 canali indicatori con modalità NumPy e puro Python.
    - `layout.py`: Mutua informazione del layout $I(\text{layout}; \text{keystream shift})$, correzione Miller-Madow e test permutazionali Besag-Clifford.
    - `lexicon.py`: Vocabolario filosofico Cicada 3301 con trasformazioni multi-vettore e lookup $O(1)$ su prefissi.
    - `running_key.py`: Cifrario running-key e book cipher in $\mathbb{F}_{29}$ con propagazione F-skip e scansione sliding-window su testi letterari.
    - `sprt.py`: Sequential Probability Ratio Test (SPRT) di Wald sui bigrammi in $\mathbb{Z}_{29}$ con soglie di arresto rapido.
    - `unicity.py`: Distanza di unicità di Shannon $U = H(K)/D$, ridondanza del linguaggio e periodo massimo risolvibile.
    - `zimmermann.py`: Verifica OpenPGP RFC 4880 pura-Python con controlli RSA PKCS#1 v1.5 a tempo costante.
17. **ciphers/solved_pages.py** — Implementazioni canoniche verificate delle 9 pagine risolte secondo la documentazione storica del wiki Uncovering Cicada.
18. **ciphers/provenance.py** — Validatore forense per scansioni originali del manoscritto (geometria 2400x3600, JFIF 400 DPI, profilo ICC Artifex, tabelle di quantizzazione).
19. **Accelerazione Hardware con Fallback su CPU (`ciphers/metal_accel.py` & `ane_engine.py`)** — Compute engine GPU Metal Apple Silicon per scoring parallelo di chiavi e shuffles surrogati, e interfaccia Apple Neural Engine (ANE CoreML) per scoring semantico offline. In ambienti Linux, Windows o privi di GPU/NumPy, l'intero sistema esegue un fallback automatico e bit-exact su implementazioni in standard library pura.
20. **ciphers/entropy.py & opsec.py** — Entropia di Shannon normalizzata su 4 alfabeti, feature vector $\vec{F}$, autenticazione firma PGP Cicada `7A35090F`, diagnostica spettrale binaria FWHT/DDT e pipeline di audit RSA (Miller-Rabin, Fermat, Pollard's rho, Wiener).
21. **Nuovi Moduli Fase 2 (`ciphers/`)**:
    - `spectral_sbox.py`: Analisi spettrale, differenziale e non lineare di S-Box in $\mathbb{F}_{29}$ (DDT, uniformità differenziale, FWHT, LAT, non linearità, SAC, grado algebrico, linear hull potential).
    - `algebraic.py`: Crittanalisi algebrica mediante matrici di Macaulay ed eliminazione di Gauss a scala (RREF) in $\mathbb{F}_{29}$, rilevamento NLFSR ed esportatore SageMath.
    - `lattice.py`: Riduzione di reticoli con LLL ($\delta=0.99$), radici piccole di Coppersmith (Howgrave-Graham), subset sum Lagarias-Odlyzko/CJLOSS per pesi primi e relazioni intere (PSLQ).
    - `rsa_audit.py`: Pipeline di audit e fattorizzazione RSA (basi certificate Miller-Rabin, Fermat close primes, Pollard rho con ciclo di Brent, attacco di Wiener e Boneh-Durfee).
    - `sat_oracle.py`: Risolutore DPLL/CDCL con watched literals, callback per oracoli programmatici e iniezione dinamica di blocking clauses con backjumping.
    - `ecc_stream.py`: Aritmetica per curve ellittiche in forma di Weierstrass corta $y^2 = x^3 + ax + b \pmod p$, verifica bound di Hasse ed estrazione keystream $x(kP) \bmod 29, y(kP) \bmod 29$ su $\mathbb{F}_{29}$ e primi sacri Cicada (3301, 1033, 761).
22. **agents/** — Suite di orchestrazione multi-agente (`crew.py`, `duel.py`), Bayesian epistemic evidence ledger (`evidence.py`, `ledger.py` con manifest di riproducibilità a 10 punti e checklist a 8 punti) e regression runner (`regress.py`).

---

---

## Installazione per Sistema Operativo

Trithemius include **script di installazione e avvio automatizzati (1-click)** sia per **macOS** che per **Windows**, che verificano i prerequisiti, creano l'ambiente virtuale `venv` e installano tutte le dipendenze da `requirements.txt`.

### 🍎 Installazione su macOS (Apple Silicon M-Series o Intel)

#### 1. Prerequisiti
- **Python $\ge 3.10$**: È richiesta una versione di Python $\ge 3.10$ (consigliato Python 3.11 tramite Homebrew per compatibilità e performance ottimali):
  ```bash
  brew install python@3.11
  ```
- **NumPy $\ge 1.24.0$**: Necessario per abilitare l'accelerazione hardware Apple Silicon Metal GPU, l'Apple Neural Engine (ANE CoreML) e il calcolo FFT lag coincidence.
- **Ollama**: Scaricalo da [ollama.com](https://ollama.com/download) o via Homebrew:
  ```bash
  brew install ollama
  ollama serve &
  ```

#### 2. Installazione Automatizzata (1-Click)
Dalla cartella del progetto nel Terminale, esegui:
```bash
./install.sh
```
Lo script si occuperà di:
- Verificare la versione di Python idonea ($\ge 3.10$).
- Creare l'ambiente virtuale isolato `venv/`.
- Installare tutte le dipendenze da `requirements.txt`.
- Scaricare automaticamente i modelli Ollama (`nomic-embed-text` e `SparkLLM/Spark-X2.5-4B`).

#### 3. Avvio della Workstation su macOS
Per avviare la Workstation direttamente nel Terminale:
```bash
./start.sh
```

---

### 🪟 Installazione su Windows (10/11 - NVIDIA o CPU)

#### 1. Prerequisiti
- **Python $\ge 3.10$**: Scarica l'installer da [python.org/downloads](https://www.python.org/downloads/).
  > ⚠️ **FONDAMENTALE**: Durante l'installazione di Python, spunta la casella **"Add python.exe to PATH"**!
- **NumPy $\ge 1.24.0$**: Consigliato per le ottimizzazioni vettoriali e i calcoli crittanalitici ad alta velocità.
- **Ollama for Windows**: Scarica ed esegui l'installer ufficiale da [ollama.com/download/windows](https://ollama.com/download/windows).

#### 2. Installazione Automatizzata (1-Click)
Fai semplicemente **doppio clic** sul file:
```
install.bat
```
*(Oppure aprilo dal Prompt dei Comandi / PowerShell digitando `install.bat`)*

Lo script:
- Rileva Python su Windows ($\ge 3.10$).
- Crea l'ambiente virtuale `venv\`.
- Installa tutte le librerie necessarie (`requirements.txt`).
- Effettua il pull dei modelli in Ollama.

#### 3. Avvio della Workstation su Windows
Fai semplicemente **doppio clic** sul file:
```
start.bat
```
Si aprirà la Workstation interattiva direttamente nel Prompt dei Comandi / Terminale!

---

### ⚙️ Installazione Manuale Alternativa (Cross-Platform)

Se preferisci procedere manualmente da terminale:

```bash
# 1. Crea ed attiva il virtual environment (Python >= 3.10 richiesto)
# Su macOS/Linux:
python3 -m venv venv
source venv/bin/activate

# Su Windows (CMD o PowerShell):
python -m venv venv
venv\Scripts\activate

# 2. Installa le dipendenze base
pip install --upgrade pip
pip install -r requirements.txt

# 3. Installa NumPy per accelerazione hardware (Metal GPU, ANE, FFT lag coincidence)
pip install "numpy>=1.24.0"

# 4. Scarica i modelli in Ollama
ollama pull nomic-embed-text
ollama pull SparkLLM/Spark-X2.5-4B

# Modello MoE complementare opzionale:
ollama pull deepseek-coder-v2:16b

# 5. Avvia la Terminal Workstation
python trithemius.py
```

> [!IMPORTANT]
> **Compatibilità Python & Accelerazione Hardware**:
> - **Python $\ge 3.10$**: L'intero codice sorgente fa uso di type hint generici avanzati (es. `frozenset[str]`) e aritmetica modulare nativa moderna (es. inversione modulare `pow(base, -1, mod)`), richiedendo inderogabilmente Python versione 3.10 o superiore.
> - **NumPy $\ge 1.24.0$**: Il pacchetto `numpy>=1.24.0` è richiesto per sbloccare l'accelerazione compute shader Metal su GPU Apple Silicon, per il backend Apple Neural Engine (ANE CoreML) e per i calcoli FFT di autocorrelazione e lag coincidence. In assenza di NumPy, la workstation esegue automaticamente il fallback su implementazioni scalari in puro Python standard library.

---

## GUIDA 1: Utilizzo del Sistema Completo (Terminal Workstation)

Trithemius opera come una **Terminal Workstation interattiva ad alte prestazioni** e zero-overhead (sviluppata in Python puro con supporto Apple Silicon Metal / Neural Engine). La precedente interfaccia web sperimentale è stata archiviata a favore della workstation terminale unificata con supporto REPL e CLI.

### 1. Avviare la Shell Interattiva (REPL)
Nel tuo terminale (con il virtualenv attivo), esegui:
```bash
python3 trithemius.py
```
Verrà avviata la shell interattiva con prompt `trithemius>` e completamento automatico da tastiera (tasto Tab).

### 2. Le Funzionalità Principali della Workstation:
- **💬 RAG Assistant & Navigazione Corpus (Knowledge Engine)**:
  - `/ask [--fresh] <query>`: Interrogazione ibrida dense vector (ChromaDB) e BM25 zero-VRAM con routing deterministico per trascrizioni di pagine ed espansioni Gematria Primus.
  - `/web <query>`: Interrogazione del corpus offline curato via RAG (alias rapido, nessuna dipendenza da web scraping live).
  - `/page <numero>`: Ispezione della trascrizione originale, anteprima dei metadati e del testo runico di una pagina (es. `/page 56`, `/page 00`, `/page 73`).
- **ᚠ Gematria & Cifrari Canonici (Sacred Numerology & Classical Solvers)**:
  - `/gematria <testo>`: Traslitterazione bidirezionale latino/rune Futhorc, somma dei valori primi sacri (2..109), test di primalità, fattorizzazione, totiente di Eulero $\phi(n)$ e riflessione speculare Atbash.
  - `/atbash <target> [--shift N]`: Cifrario Atbash in $\mathbb{F}_{29}$ con Caesar shift facoltativo (es. `/atbash 00`, `/atbash 06 --shift 3` per Koan 1).
  - `/vigenere <enc|dec> <target> <chiave> [--f-skip]`: Cifrario Vigenère in $\mathbb{F}_{29}$ o mod-26 latino con pause del keystream sui caratteri Fehu (F-skip) e verifica statistica Al-Kindi.
  - `/totient-stream` (o `/totient`) `<enc|dec> <target> [--offset N] [--f-skip]`: Cifrario a flusso basato sui totienti di Eulero $\phi(p_k) = p_k - 1 \pmod{29}$, con gestione offset e pause Fehu (es. `/totient-stream dec 71 --f-skip`).
  - `/solve [target|all]`: Esecuzione e verifica immediata delle 9 pagine canoniche risolte del Liber Primus (es. `/solve welcome`, `/solve 71`, `/solve all`).
- **🔬 Crittanalisi Avanzata & Analisi Statistica**:
  - `/crack <target> [--deep] [--compound] [--rotations]`: Cascade solver esaustivo con triage unigram/bigram, stima periodo, T-table coordinate optimization, sweeps Metal GPU di frasi composte e reranking semantico CoreML ANE.
  - `/triage <target>`: Triage statistico per classificazione della famiglia di cifrario (unigram IC, normalized kappa $29 \cdot \text{IC}$, bigram IC, entropia condizionale).
  - `/period <target> [max_period]`: Stima consensuale della lunghezza chiave combinando Kasiski weighted GCD voting, periodogramma di differenze comb filter e column IoC.
  - `/crib <target> <crib_word>`: Crib dragging lungo il testo cifrato con calcolo della complessità lineare Berlekamp-Massey in $\mathbb{F}_{29}$ e matching su stream hash bank.
  - `/layout [target|calibrate]`: Analisi della mutua informazione del layout (lunghezze parole/righe, separatori `᛫`, `᛬`, `᛭`, posizioni Fehu) con correzione Miller-Madow e calibrazione su pagine risolte.
  - `/running-key <page> <file> [--mode sub|add|beaufort] [--f-skip]`: Decifrazione running-key in $\mathbb{F}_{29}$ contro testi letterari di riferimento (es. Blake, Emerson).
  - `/running-key-scan <page> [--step N] [--top-k N]`: Scansione sliding-window automatica su tutte le opere in `corpus/reference_texts/` con scoring runico calibrato.
  - `/lexicon [phrases|words|all]`: Esplorazione del vocabolario filosofico, aforismi e parole chiave master per attacchi dizionario e crib.
- **🛡️ OpSec, Ledger Epistemico & Telemetria Hardware**:
  - `/opsec <target>`: Autenticazione crittografica della firma PGP Cicada `7A35090F`, profilo entropico $H(X)$, Indice di Coincidenza (IoC) e rilevamento steganografico.
  - `/ledger [target]`: Ispezione del ledger persistente SQLite e ChromaDB con deduplicazione tentativi e ricerca per similarità coseno nearest-neighbor.
  - `/hardware` (alias `/gpu`, `/metal`, `/ane`): Telemetria e benchmark throughput per Apple Silicon Metal GPU (M chiavi/sec) e Apple Neural Engine (ANE).
  - `/boost [on|off|status|toggle]`: Modalità crittanalitica potenziata (espande il retrieval a 10 chunk, moltiplica lo score lessicale runico per $2.0\times$, estende il contesto a 4.000 caratteri).
  - `/bench [--profile] [--skip-vector] [--llm]`: Suite di benchmark per la misura delle latenze al microsecondo delle primitive crittografiche e profiling cProfile.
  - `/key [show|clear|<provider> <key>]`: Gestione sicura delle credenziali API salvate in `.env` con permessi restrittivi `0600`.
  - `/status [--probe]`: Telemetria real-time di sistema, provider LLM attivo, stato CoT, conteggio chunk vettoriali e identità PGP.
  - Output JSON: Per script automatici o integrazioni headless, aggiungi il flag `--json` (es. `python trithemius.py status --json`, `python trithemius.py crack 56 --json`).

---

## GUIDA 2: Pipeline di Cifratura e Risolutori Canonici (`solve_canonical.py`, `totient_stream.py`, `cryptanalyze_page56.py`)

> [!NOTE]
> **Nota Architetturale**: Lo web scraping autonomo (`scripts/walsingham.py`) e l'iniezione dinamica di ricerche web esterne (`scripts/bacon.py`) sono stati archiviati in favore del corpus offline curato e deterministico del Liber Primus (`corpus/` e master transcript). Questa guida illustra l'utilizzo pratico dei risolutori e strumenti crittanalitici autonomi operanti al 100% in locale.

La workstation include script stand-alone per la verifica formale, la decodifica di flussi totienti e la crittanalisi avanzata a cascata:

### 1. Suite Canonica di Risoluzione (`solve_canonical.py`)
Verifica e riproduce fedelmente tutte le 9 pagine storicamente risolte del Liber Primus documentate dalla community crittografica:
```bash
# Esegue la verifica formale di tutte le 9 pagine canoniche:
python3 scripts/solve_canonical.py

# Risolve ed ispeziona una pagina specifica (es. Welcome o Pagina 56 / An End):
python3 scripts/solve_canonical.py welcome
python3 scripts/solve_canonical.py 56

# Esporta i risultati in formato strutturato JSON per pipeline headless:
python3 scripts/solve_canonical.py --json
```

### 2. Risolutore Prime Totient Stream con F-Skips (`totient_stream.py`)
Implementa il cifrario a flusso basato sui totienti di Eulero $\phi(p_k) = p_k - 1$ in $\mathbb{F}_{29}$ ($C_i \to (C_i - (p_{i+\Delta} - 1)) \pmod{29}$), con supporto per la regola canonica di pausa del keystream sui caratteri Fehu (F-skip):
```bash
# Decodifica della Pagina 71 (56.jpg / An End) applicando l'F-skip a indice 56:
python3 scripts/totient_stream.py dec corpus/page_71_runes.md --f-skip

# Decodifica con offset arbitrario sui numeri primi:
python3 scripts/totient_stream.py dec "ᚪᚾ᛫ᛖᚾᛞ..." --offset 0

# Cifratura di testo in chiaro con generazione di keystream totiente:
python3 scripts/totient_stream.py enc "AN END WITHIN THE DEEP WEB" --f-skip
```

### 3. Crittanalisi a Cascata su Pagina 56 (`cryptanalyze_page56.py`)
Esegue l'analisi crittanalitica esaustiva della Pagina 56 (273 rune autentiche) contro tre ipotesi matematiche prioritarie:
- **Ipotesi 1 (Offset Euler Totient Keystream)**: $k_n = (p_{n + \Delta} - 1) \pmod{29}$ con shift sottrattivi, additivi e Beaufort, con e senza pause F-skip.
- **Ipotesi 2 (Pisano Orbit Recurrence in $\mathbb{F}_{29}$)**: ricorrenze modulari $S_{n+2} = (a S_{n+1} + b S_n) \pmod{29}$ (Fibonacci, Lucas, generatori su periodo di Pisano $\pi(29) = 14$).
- **Ipotesi 3 (Syntactic Interrupter & Clause-Reset Vigenère)**: clausole delimitate da `᛬` e parole da `᛫` con reset del keystream su parole chiave canoniche.

I candidati vengono filtrati tramite il modello linguistico runico composito, log-likelihood n-gram Al-Kindi, test chi-quadro $\chi^2$, test surrogati Monte Carlo (Sidak $p_{adj}$) e registrati nel ledger SQLite (`vectordb/ledger.sqlite3`):
```bash
# Esecuzione della crittanalisi completa su Pagina 56:
python3 scripts/cryptanalyze_page56.py

# Impostazione del numero di migliori candidati per ipotesi:
python3 scripts/cryptanalyze_page56.py --top-k 10

# Output in formato JSON con disattivazione del logging su ledger SQLite:
python3 scripts/cryptanalyze_page56.py --json --no-log
```

---

## GUIDA 3: Utilizzo del Solo Organizzatore del Corpus (`porta.py`)

Se hai scaricato molti file con nomi disordinati o vuoi pulire i duplicati nel corpus **a costo zero di memoria (0% VRAM)**:

### Cosa fa Porta:
- **Analisi del Contenuto**: legge il testo ed esamina i pattern runici per riconoscere automaticamente a quale pagina appartiene (es. riconosce la Pagina 00 Welcome, Pagina 56 Loss of Innocence, Pagina 57 Warning, Pagina 73 An End).
- **Rinominazione Standard**: trasforma nomi disordinati (es. `mirror_page_00.txt`) in nomi univoci e strutturati (es. `page_00_welcome.txt`).
- **Deduplicazione SHA-256**: se sono presenti copie identiche di un file, le individua e rimuove i duplicati, mantenendo il file primario.
- **Protezione File di Sistema**: preserva intatti file indice come `pages_index.json`.

### Comandi CLI:
```bash
# Riorganizza, classifica e rinomina i file del corpus in base al loro contenuto:
python3 scripts/porta.py

# Esegui solo la pulizia dei file duplicati:
python3 scripts/porta.py --dedup
```

---

## Pipeline di Lavoro Consigliata

Quando vuoi arricchire il sistema e fare una sessione di ricerca (pipeline locale e deterministica):

1. **Partiziona il Master Transcript (se aggiornato dal transcript grezzo)**:
   ```bash
   python3 scripts/split_master_transcript.py
   ```
2. **Organizza e Classifica il Corpus (Porta, 0 VRAM)**:
   ```bash
   python3 scripts/porta.py
   ```
3. **Ingestione Vettoriale con Entropia (Bodleian)**:
   ```bash
   python3 scripts/bodleian.py
   ```
4. **Avvia la Workstation ed Interroga Trithemius**:
   ```bash
   python3 trithemius.py
   ```
   (Oppure in modalità diretta CLI: `python3 trithemius.py ask "<domanda>"` o `python3 trithemius.py crack 56`)

---

## Canonical Solved Pages Suite & Ciphers (Liber Primus Wiki)

Trithemius include la suite canonica di verifica e decifrazione per tutte le 9 pagine storicamente risolte del Liber Primus documentate sul wiki ufficiale ([How the solved pages were solved](https://uncovering-cicada.fandom.com/wiki/How_the_solved_pages_of_the_Liber_Primus_were_solved)):

1. **Page 00** (`01.jpg`): Atbash in $\mathbb{F}_{29}$ ($C_i \to (28 - C_i) \pmod{29}$).
2. **Welcome** (`03.jpg - 04.jpg`): Vigenère Modulo-29 chiave `DIVINITY` con pause del keystream su Fehu in chiaro (F-skips).
3. **Some wisdom** (`05.jpg`): Traslitterazione diretta Gematria Primus.
4. **Koan 1** (`06.jpg - 09.jpg`): Atbash seguito da Caesar shift di +3 in $\mathbb{F}_{29}$ (involuzione auto-inversa).
5. **The loss of divinity** (`10.jpg - 13.jpg`): Traslitterazione diretta Gematria Primus.
6. **Koan 2** (`14.jpg - 15.jpg`): Vigenère Modulo-29 chiave `FIRFUMFERENFE` con pause F-skip.
7. **An instruction** (`16.jpg`): Traslitterazione diretta Gematria Primus.
8. **An end** (`56.jpg` / LP `73.jpg`): Prime Totient Stream Cipher ($C_i \to (C_i - (p_i - 1)) \pmod{29}$) con F-skip a indice 56.
9. **Parable** (`57.jpg`): Traslitterazione diretta Gematria Primus.

### Comandi CLI Dedicati:
```bash
# Verifica e risoluzione di tutte le 9 pagine canoniche:
python3 scripts/solve_canonical.py
python3 trithemius.py solve

# Risoluzione di una singola pagina (es. Welcome, Koan 1, An End):
python3 trithemius.py solve welcome
python3 trithemius.py solve koan1
python3 trithemius.py solve 71

# Cifrario Atbash e Atbash con Shift in F_29:
python3 trithemius.py atbash 00
python3 trithemius.py atbash 04 --shift 3

# Prime Totient Stream Cipher:
python3 scripts/totient_stream.py dec corpus/page_71_runes.md --f-skip
python3 trithemius.py totient-stream dec 71 --f-skip

# Vigenère con F-skips:
python3 trithemius.py vigenere dec 01 DIVINITY --f-skip
```

---

## Verifica & Suite di Regressione Crittografica

Per verificare in ogni momento la suite completa di test crittografici e di regressione (458 test unitari e di integrazione attraverso 46 test suite con Python $\ge 3.10$):
```bash
python3 -m unittest discover -s tests
```
Tutti i 458 test unitari e di integrazione passano al 100% senza alcuna regressione.
