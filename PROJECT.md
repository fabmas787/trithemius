# Project: Trithemius Liber Primus Research Workstation

## Current Architecture
- **Interactive Terminal Workstation & CLI**: `trithemius.py` backward-compatible facade routing to `workstation/core/workstation.py`.
- **Domain Services Architecture**:
  - `CipherService` (`workstation/services/cipher_service.py`): Encapsulates classical and Liber Primus ciphers, triage, cascaded solvers, and OpSec inspection.
  - `CorpusService` (`workstation/services/corpus_service.py`): Unified document ingestion (Bodleian), deduplication (Porta), and page browsing.
  - `AssistantService` (`workstation/services/assistant_service.py`): Interactive RAG query pipeline, streaming LLM integration, exact answer cache, and web scouting context.
  - `SystemService` (`workstation/services/system_service.py`): Telemetry inspection, active hardware detection (Apple Silicon Metal / ANE), and provider probes.
- **Presentation & Dual Rendering**:
  - `ConsoleRenderer` (`workstation/ui/formatters.py`): High-density ANSI terminal layout.
  - `JsonRenderer` (`workstation/ui/json_renderer.py`): Machine-readable JSON output for automated pipelines (`--json`).
  - `TypedResult` hierarchy (`workstation/core/results.py`): Strongly typed domain outputs with dictionary/attribute dual access.
- **Command Routing & REPL**:
  - `CommandSpec` declarative registry (`workstation/commands.py`): 35 registered commands with CLI router and REPL shell.
  - Interactive REPL (`workstation/ui/repl.py`): Tab-completion, history, and tokenized arguments.
- **Historical Web GUI**: The experimental browser interface (`gui/`) has been formally archived; this repository checkout represents the dedicated high-performance Terminal Workstation.
- **Regression Test Baseline**: 352 passing unit and integration tests across 32 test suites, including byte-for-byte golden master validation.

## Milestone Status
| Milestone | Scope | Status | Notes |
|---|---|---|---|
| M1 | Monolith Refactoring & Service Extraction | COMPLETED | `trithemius.py` decomposed from 3,048 lines to 35-line facade; services in `workstation/services/`. |
| M2 | Dual Presentation & Typed Results | COMPLETED | `ConsoleRenderer`, `JsonRenderer` (`--json`), and `TypedResult` dataclasses implemented. |
| M3 | CLI/REPL Command Parity & Autocomplete | COMPLETED | 35 commands registered in `workstation/commands.py`; GNU readline shell in `workstation/ui/repl.py`. |
| M4 | Performance & Golden Master Hardening | COMPLETED | Unified corpus enumeration, GC-safe benchmarks, and diagnostic normalization in golden tests. |
| Legacy | Web Workstation GUI Overhaul | ARCHIVED | Archived in favor of zero-overhead, high-performance terminal workstation. |

## Code Layout
- `trithemius.py`: CLI entrypoint and backward-compatible facade.
- `workstation/`: Core workstation kernel, domain services, UI renderers, and CLI/REPL routers.
- `ciphers/`: GF(29) taxonomy, Gematria Primus, Vigenère mod-29, ANE/Metal acceleration, OpSec verification.
- `scripts/`: Corpus librarians (`porta.py`, `bodleian.py`), RAG retriever (`ask.py`), web scout (`walsingham.py`), benchmarking (`benchmark.py`).
- `corpus/`: Page transcripts, indexes, and reference literature (`corpus/reference_texts/`).
- `vectordb/`: Persistent ChromaDB embeddings and canonical hypothesis ledgers.
- `tests/`: 352 unit tests, AST architecture checks (`test_architecture.py`), and golden master suites (`tests/golden/`).
