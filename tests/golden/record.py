import os
import re
import subprocess
import sys
import pathlib

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
REF_DIR = pathlib.Path(__file__).resolve().parent / "ref"
REF_DIR.mkdir(parents=True, exist_ok=True)

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
VOLATILE = [
    (re.compile(r"\d+(\.\d+)?\s?(ms|µs|us|s)\b"), "<T>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\S*"), "<TS>"),
    (re.compile(r"Surrogate: Z-Score = [^\n]+"), "Surrogate: <SURROGATE_STATS>"),
    (re.compile(r"Pos\s+\d+: Crib '[^']+' -> Implied Key '[^']+' \[[^\]]+\]"), "Pos <P>: Crib '<CRIB>' -> Implied Key '<KEY>' [<MATCH>]"),
    (re.compile(r"Total Unique Words Tested on Page '[^']+': \d+"), "Total Unique Words Tested on Page '<PAGE>': <WORD_COUNT>"),
    (re.compile(r"Attempts Recorded This Run: \d+"), "Attempts Recorded This Run: <COUNT>"),
]

CASES = {
    "gematria_welcome": ["gematria", "ᚹᛖᛚᚳᚩᛗᛖ"],
    "vigenere_dec_56":  ["vigenere", "dec", "56", "DIVINITY"],
    "triage_56":        ["triage", "56"],
    "period_56":        ["period", "56", "30"],
    "crib_56":          ["crib", "56", "DIVINITY"],
    "crack_0":          ["crack", "0"],
    "opsec_p73":        ["opsec", "corpus/page_73_an_end.md"],
    "status":           ["status"],
    "help":             ["--help"],
}

REPL_SCRIPT = """/gematria ᚹᛖᛚᚳᚩᛗᛖ
/page 56
/help
/help vigenere
/status
/exit
"""


DIAGNOSTIC_FILTERS = [
    re.compile(r"\[W:onnxruntime:[^\]]+\][^\n]*\n?"),
    re.compile(r".*CoreMLExecutionProvider.*failed to create compiler cache.*\n?", re.IGNORECASE),
    re.compile(r".*UserWarning:.*tokenizer.*\n?"),
]

ENV_OVERRIDES = {
    "NO_COLOR": "1",
    "PYTHONHASHSEED": "0",
    "ORT_LOG_LEVEL": "3",
    "TOKENIZERS_PARALLELISM": "false",
    "PYTHONWARNINGS": "ignore",
}


def normalize(text: str) -> str:
    text = ANSI.sub("", text)
    for rx, repl in VOLATILE:
        text = rx.sub(repl, text)
    for rx in DIAGNOSTIC_FILTERS:
        text = rx.sub("", text)
    return text


def run_cli(argv):
    env = {**os.environ, **ENV_OVERRIDES}
    p = subprocess.run(
        [sys.executable, str(BASE_DIR / "trithemius.py"), *argv],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(BASE_DIR),
    )
    return f"rc={p.returncode}\n--stdout--\n{normalize(p.stdout)}\n--stderr--\n{normalize(p.stderr)}"


def run_repl(script_input: str):
    env = {**os.environ, **ENV_OVERRIDES}
    p = subprocess.run(
        [sys.executable, str(BASE_DIR / "trithemius.py")],
        input=script_input,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(BASE_DIR),
    )
    return f"rc={p.returncode}\n--stdout--\n{normalize(p.stdout)}\n--stderr--\n{normalize(p.stderr)}"


def record_all():
    print("[*] Recording CLI golden master cases...")
    for name, argv in CASES.items():
        print(f"    - {name}: {' '.join(argv)}")
        out = run_cli(argv)
        (REF_DIR / f"{name}.txt").write_text(out, encoding="utf-8")

    print("[*] Recording REPL golden master session...")
    repl_out = run_repl(REPL_SCRIPT)
    (REF_DIR / "repl_session.txt").write_text(repl_out, encoding="utf-8")
    print(f"[+] All golden master references saved to {REF_DIR}")


if __name__ == "__main__":
    record_all()
