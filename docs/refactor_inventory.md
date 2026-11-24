# Trithemius Refactor Inventory

*Generated during Phase 0 baseline verification.*

## 1. External Imports of `trithemius`
Search query: `grep -rn "from trithemius import\|import trithemius" .`
- `tests/test_solved_pages.py`: `from trithemius import TerminalWorkstation, main`
- `tests/test_terminal_workstation.py`: `from trithemius import TerminalWorkstation`, `from trithemius import main`
- `tests/test_cryptanalysis_taxonomy.py`: `import trithemius` (`trithemius.TerminalWorkstation()`)
- `tests/test_running_key.py`: `from trithemius import TerminalWorkstation`
- `tests/test_vector_attempts.py`: `from trithemius import TerminalWorkstation`
- `tests/test_canonical_solved_pages.py`: `import trithemius` (`trithemius.TerminalWorkstation()`, `trithemius.main(...)`)
- `tests/test_lexicon_rotation.py`: `from trithemius import TerminalWorkstation`

**Summary**: Only `TerminalWorkstation` and `main` are consumed externally.

## 2. Mock / Patch Targets
Search query: `grep -rn "patch" tests/`
- `tests/test_terminal_workstation.py`: `patch.object(TerminalWorkstation, "run_ask")`
- No string-based `patch("trithemius.*")` paths exist in the test suite. All other patches target `sys.stdout`, `builtins.input`, `os.system`, `config.get_api_key`, `requests.*`, `scripts.ask.*`, `scripts.providers.*`, or `os.environ`.

## 3. Legacy `config.py` Writers
Search query: `grep -rn "config\.[A-Z_]\+\s*=" .`
All occurrences are strictly internal to `trithemius.py`:
- `config.OLLAMA_HOST` (lines 151, 2732)
- `config.LOW_SPEC_MODE` (lines 158, 2744, 2749)
- `config.DEFAULT_NUM_CTX` (lines 159, 2745, 2750)

No test or external script writes to `config.py` module attributes.

## 4. REPL Tokenization & Input Framing
- `raw.startswith("/")`: Uses `parts = shlex.split(raw)`. `cmd = parts[0].lower()`, `args = parts[1:]`.
- Free text queries (does not start with `/`): Passes `raw` directly to `self.run_ask(raw, use_web=False)`.
- Handlers like `/ask` and `/web`: Take `args` from `shlex.split` and rejoin with `" ".join(args)`.

## 5. Tracked Credentials & Database Files
Search query: `git ls-files .env vectordb/`
- `.env`: Tracked in baseline commit (empty, 0 bytes; no credentials in git history).
- `vectordb/*.sqlite3`: `cache.sqlite3`, `chroma.sqlite3`, `ledger.sqlite3` are tracked in repo.
- `vectordb/ledger.sqlite3.bak_20261006_remediation`: Tracked backup file.

---

## 6. Refactoring Architecture Outcome (Completed)

1. **Monolith Decomposition**:
   - `trithemius.py` reduced from 3,048 lines to a 35-line backward-compatible facade.
   - Core kernel modularized into `workstation/core/workstation.py` (240 lines).
   - Domain services decomposed into:
     - `workstation/services/cipher_service.py` (`CipherService`)
     - `workstation/services/corpus_service.py` (`CorpusService`)
     - `workstation/services/assistant_service.py` (`AssistantService`)
     - `workstation/services/system_service.py` (`SystemService`)

2. **Presentation & Dual Rendering**:
   - Terminal presentation encapsulated in `workstation/ui/formatters.py` (`ConsoleRenderer`).
   - Machine-readable JSON output added in `workstation/ui/json_renderer.py` (`JsonRenderer`) accessible via `--json` CLI flag.
   - Dual-access typed domain result models (`TypedResult` subclasses) in `workstation/core/results.py`.

3. **Settings & CLI/REPL Parity**:
   - Dataclass single source of truth in `workstation/settings.py` with zero-regression module proxy in `config.py`.
   - Declarative `CommandSpec` table in `workstation/commands.py` (35 commands registered).
   - REPL shell in `workstation/ui/repl.py` with GNU readline tab-completion and safe input tokenization.
   - CLI router in `workstation/cli/parser.py`.

4. **Verification**:
   - Test suite expanded from 323 to 347 tests with 100% pass rate.
   - Golden master regression tests pass with byte-for-byte fidelity across CLI and REPL cases.
   - AST layer check (`tests/test_architecture.py`) enforces strict dependency boundaries.
