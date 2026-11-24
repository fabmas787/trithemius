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
- **Walsingham** (Sir Francis Walsingham, 1532–1590) `[ARCHIVIATO / ROADMAP COMPONENT]`: Spymaster to Queen Elizabeth I — Autonomous web scout (archiviato, sostituito dalla pipeline offline Bodleian + Porta + RAG).
- **Bacon** (Roger Bacon, 1220–1292) `[ARCHIVIATO / ROADMAP COMPONENT]`: Medieval empiricist — Live DuckDuckGo search context injection.

---

## Architecture Overview

```
[Web / Archivio Storico] ──► [scripts/walsingham.py] [ARCHIVIATO / ROADMAP]
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

1. **trithemius.py** — Unified terminal-first cryptanalytic workstation (interactive REPL + CLI subcommands).
2. **corpus/** — Raw text: page transcripts, forum threads, reference index (`pages_index.json`).
3. **scripts/walsingham.py** `[ARCHIVIATO / ROADMAP COMPONENT]` — Autonomous web scout con anti-bot resilience (archiviato, sostituito stabilmente dalla pipeline locale deterministica Bodleian + Porta + RAG).
4. **scripts/porta.py** — Corpus librarian (identifies page numbers, standardizes filenames, removes duplicates).
5. **scripts/bodleian.py** — Shannon entropy sliding-window chunking, rune detection, and ChromaDB vector ingestion.
6. **scripts/ask.py** — Hybrid RAG query engine with streaming token output and page filtering (`/page 56`).
7. **scripts/normalize_runes.py** — Futhorc rune standardization (`᛫`, `᛬`, `᛭`) and OCR cleaner.
8. **ciphers/agrippa.py** — Official 29-rune Gematria Primus mapping, prime values (2..109), word sums, rune Atbash, Euler's totients.
9. **ciphers/kasiski.py** — Modulo-29 Rune Vigenère solver, Cicada keystreams (primes, Fibonacci, totients), English IoC + Friedman test.
10. **ciphers/al_kindi.py** — Chi-squared goodness-of-fit, English quadgram/trigram likelihood, dictionary vocabulary validation.
11. **ciphers/taxonomy.py** (+ 14 moduli ciphers) — Suite tassonomica avanzata GF(29), modelli linguistici calibrati, periodogrammi, T-table solver, crib dragging, surrogate tests, e i moduli `unicity`, `sprt`, `difference`, `lagcoinc`, `interrupter`, `running_key`, `affine`, `fingerprint`, `container`, `layout`, `lexicon`, `zimmermann`, `keymap`, `hash_hunt`.
12. **ciphers/metal_accel.py & ane_engine.py** — Accelerazione hardware opzionale Apple Silicon Metal GPU e Apple Neural Engine (ANE CoreML) con fallback trasparente su CPU.
13. **ciphers/entropy.py & opsec.py** — Shannon entropy $H(X)$, sliding-window boundary cuts, feature vector $\vec{F}$, verifica PGP Cicada `7A35090F`.
14. **archive/gui/** — Archived browser interface and legacy HTTP daemon.

---

---

## Installazione per Sistema Operativo

Trithemius include **script di installazione e avvio automatizzati (1-click)** sia per **macOS** che per **Windows**, che verificano i prerequisiti, creano l'ambiente virtuale `venv` e installano tutte le dipendenze da `requirements.txt`.

### 🍎 Installazione su macOS (Apple Silicon M-Series o Intel)

#### 1. Prerequisiti
- **Python 3.10+**: Consigliato tramite Homebrew:
  ```bash
  brew install python@3.11
  ```
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
- Verificare la versione di Python idonea.
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
- **Python 3.10+**: Scarica l'installer da [python.org/downloads](https://www.python.org/downloads/).
  > ⚠️ **FONDAMENTALE**: Durante l'installazione di Python, spunta la casella **"Add python.exe to PATH"**!
- **Ollama for Windows**: Scarica ed esegui l'installer ufficiale da [ollama.com/download/windows](https://ollama.com/download/windows).

#### 2. Installazione Automatizzata (1-Click)
Fai semplicemente **doppio clic** sul file:
```
install.bat
```
*(Oppure aprilo dal Prompt dei Comandi / PowerShell digitando `install.bat`)*

Lo script:
- Rileva Python su Windows.
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
# 1. Crea ed attiva il virtual environment
# Su macOS/Linux:
python3 -m venv venv
source venv/bin/activate

# Su Windows (CMD o PowerShell):
python -m venv venv
venv\Scripts\activate

# 2. Installa le dipendenze
pip install --upgrade pip
pip install -r requirements.txt

# 3. Scarica i modelli in Ollama
ollama pull nomic-embed-text
ollama pull SparkLLM/Spark-X2.5-4B

# Modello MoE complementare opzionale:
ollama pull deepseek-coder-v2:16b

# 4. Avvia la Terminal Workstation
python trithemius.py
```

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
- **💬 RAG Assistant (Chat Live & Query)**:
  - Interroga il corpus vettoriale con risposta in streaming token-by-token.
  - Scegli tra **SparkLLM** (default 4B con 1M di contesto) o **DeepSeek-Coder-V2** (MoE).
  - Comandi rapidi nella shell:
    - `/ask Come si decifra la pagina 56?` $\to$ ricerca ibrida BM25 e vettoriale.
    - `/page 56` $\to$ ispezione del testo sorgente e anteprima dei documenti.
    - `/web latest theories 2026` $\to$ interroga contemporaneamente il web tramite Bacon.
- **ᚠ Gematria & Ciphers Workbench**:
  - `/gematria <testo>`: traslitterazione bidirezionale latino/rune Futhorc, somma dei valori primi (2..109), totiente di Eulero $\phi(n)$ e primalità.
  - `/vigenere dec 56 DIVINITY`: decodifica e codifica Vigenère in $\mathbb{F}_{29}$ con plausibilità Al-Kindi.
  - `/atbash <target>`: cifrario Atbash speculare in $\mathbb{F}_{29}$ con shift facoltativo.
  - `/solve <pagina>`: esecuzione immediata dei risolutori canonici verificati.
  - `/crack <target>`: triage statistico automatico, cascata di risolutori e scoring su Apple Neural Engine / Metal.
- **🛡️ OpSec & PGP 7A35090F**:
  - `/opsec <file>`: verifica crittografica dell'autenticità PGP contro la chiave ufficiale `7A35090F`.
  - Calcola in tempo reale il profilo del segnale: entropia di Shannon $H(X)$, Indice di Coincidenza (IoC) e rune.
- **📁 Gestione Corpus & Telemetria**:
  - `/organize`: deduplica e indicizza i file in `corpus/` spostando i duplicati in `_duplicates/`.
  - `/ingest`: frammentazione ed embedding vettoriale con Bodleian.
  - `/status`: telemetria hardware, provider attivo, chunk indicizzati e stato PGP.
  - Output JSON: per script automatici o pipeline headless, usa `--json` (es. `python trithemius.py status --json`).

---

## GUIDA 2: Utilizzo del Solo Web Scraper Autonomo (`walsingham.py`) [ARCHIVIATO / ROADMAP COMPONENT]

> [!NOTE]
> **Nota Architetturale**: Lo script `scripts/walsingham.py` è archiviato (`[ARCHIVED / ROADMAP COMPONENT]`) ed è stato sostituito dalla pipeline deterministica e offline **Bodleian + Porta + RAG**. L'acquisizione, la deduplicazione e l'ingestione del corpus operano ora al 100% in locale senza dipendenze da scraping web esterno. Questa sezione è conservata a fini di riferimento storico e architetturale.

Se vuoi raccogliere trascrizioni runiche, indizi e discussioni dal web **senza sprecare risorse e senza avviare alcun modello LLM in VRAM (0% VRAM)**:

### Caratteristiche Anti-Bot di Walsingham:
1. **Rotazione User-Agent & Header completi**: alterna impronte digitali di browser reali (Chrome, Safari, Firefox, Edge).
2. **Backoff con Jitter**: su risposte `429 (Rate Limit)` o `503`, attende un intervallo casuale esponenziale e riprova.
3. **Circuit Breaker Anti-Crash**: se un sito è protetto da Cloudflare Turnstile/403 o va in timeout, **salta la risorsa senza mai interrompere lo script**.
4. **Accesso Raw Prioritario**: scarica direttamente dai repository GitHub raw dei solver (`raw.githubusercontent.com`), bypassando i firewall anti-scraping.
5. **Filtro di Qualità**: accetta solo contenuti contenenti rune Futhorc, blocchi PGP `7A35090F`, o parole chiave del Liber Primus, convertendo l'HTML in Markdown pulito.

### Comandi CLI:
```bash
# Esecuzione standard con query predefinita (scarica fino a 3 file rilevanti in corpus/):
python3 scripts/walsingham.py

# Ricerca specifica per una pagina del Liber Primus:
python3 scripts/walsingham.py --query "cicada 3301 page 56 rune transcription"

# Impostare un limite di file da scaricare:
python3 scripts/walsingham.py --query "liber primus solutions github raw" --limit 5
```
I file scaricati vengono salvati direttamente nella cartella `corpus/`, pronti per l'ingestion.

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

1. **Organizza e Classifica il Corpus (Porta, 0 VRAM)**:
   ```bash
   python3 scripts/porta.py
   ```
   *(Nota: lo scraper `walsingham.py` è archiviato; la pipeline opera sul corpus locale curato).*
2. **Ingestione Vettoriale con Entropia (Bodleian)**:
   ```bash
   python3 scripts/bodleian.py
   ```
3. **Avvia la Workstation ed Interroga Trithemius**:
   ```bash
   python3 trithemius.py
   ```
   (Oppure in modalità diretta CLI: `python3 trithemius.py ask "<domanda>"`)

---

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

Per verificare in ogni momento la suite completa di test:
```bash
./venv/bin/python -m unittest discover -s tests
```
Tutti i 367 test unitari e di integrazione passano al 100% senza regressioni.
