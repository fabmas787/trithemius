"""
Split Master Transcript — Liber Primus Runic Partitioning Utility

Parses corpus/liber-primus__transcription--master.txt into individual page
files adhering strictly to the delimiter rules defined in the file header:
- Word     : -  -> Standard Futhorc interpunct '᛫' (U+16EB)
- Three-dot: ,  -> Standard Futhorc triple dot '᛭' (U+16ED)
- Clause   : .  -> Standard Futhorc colon/clause divider '᛬' (U+16EC)
- Paragraph: &  -> Paragraph break ('\\n\\n')
- Segment  : $  -> Section separator ('---')
- Chapter  : §  -> Chapter delimiter ('§')
- Line     : /  -> Physical line break ('\\n')
- Page     : %  -> Page partition boundary

Generates standardized corpus/page_{XX}_runes.md files preserving both
the formatted runic text and the raw delimited transcription without
overwriting canonical solved pages.
"""

import os
import sys
from typing import Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import INDEX_BY_RUNE, decode_runes, gematria_prime_sum
except ImportError:
    from agrippa import INDEX_BY_RUNE, decode_runes, gematria_prime_sum

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus")
MASTER_FILE = os.path.join(CORPUS_DIR, "liber-primus__transcription--master.txt")
if not os.path.exists(MASTER_FILE):
    alt_file = os.path.join(CORPUS_DIR, "runes_liber-primus__transcription--master.txt")
    if os.path.exists(alt_file):
        MASTER_FILE = alt_file


def parse_delimiters(header_text: str) -> Dict[str, str]:
    """Parse delimiter mapping from the master transcript header."""
    delimiters = {
        "Word": "-",
        "Three-dot symbol": ",",
        "Clause": ".",
        "Paragraph": "&",
        "Segment": "$",
        "Chapter": "§",
        "Line": "/",
        "Page": "%",
    }
    for line in header_text.splitlines():
        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            if key in delimiters:
                delimiters[key] = val
    return delimiters


def format_chunk_runes(raw_chunk: str) -> str:
    """Apply delimiter transformations to create formatted runic representation."""
    lines = raw_chunk.strip().splitlines()
    formatted_lines: List[str] = []

    for line in lines:
        l = line.strip()
        if not l:
            continue
        if l == "&":
            formatted_lines.append("")
            continue
        if l == "$":
            formatted_lines.append("---")
            continue
        if l == "§":
            formatted_lines.append("§")
            continue

        # Strip line break delimiter if at line end
        if l.endswith("/"):
            l = l[:-1]

        # Check if line contains Futhorc runes
        has_runes = any(c in INDEX_BY_RUNE for c in l)
        if has_runes:
            converted = []
            for ch in l:
                if ch == "-":
                    converted.append("᛫")
                elif ch == ",":
                    converted.append("᛭")
                elif ch == ".":
                    converted.append("᛬")
                elif ch == "/":
                    converted.append("\n")
                elif ch == "&":
                    converted.append("\n\n")
                elif ch == "$":
                    converted.append("\n---\n")
                elif ch == "§":
                    converted.append("\n§\n")
                else:
                    converted.append(ch)
            formatted_lines.append("".join(converted))
        else:
            # Preserve hex/Latin/Mobius coordinates with line breaks resolved
            l_clean = l.replace("/", "\n")
            formatted_lines.append(l_clean)

    return "\n".join(formatted_lines)


def transliterate_chunk(formatted_runes: str) -> str:
    """Generate Latin transliteration for formatted runic text."""
    lines = formatted_runes.splitlines()
    trans_lines = []
    for line in lines:
        if not line.strip() or line.strip() in ("---", "§"):
            trans_lines.append(line)
            continue
        # Decode line
        decoded = decode_runes(line)
        trans_lines.append(decoded)
    return "\n".join(trans_lines)


def process_master_file(dry_run: bool = False) -> Dict[str, int]:
    """Partition master transcription into page files in corpus/."""
    if not os.path.exists(MASTER_FILE):
        raise FileNotFoundError(f"Master file not found: {MASTER_FILE}")

    with open(MASTER_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    header_lines = lines[:10]
    header_text = "\n".join(header_lines)
    delims = parse_delimiters(header_text)

    body_text = "\n".join(lines[10:])
    page_delim = delims.get("Page", "%")
    chunks = body_text.split(page_delim)

    total_chunks = len(chunks)
    created_files = 0
    total_runes = 0

    for idx, raw_chunk in enumerate(chunks):
        cleaned_raw = raw_chunk.strip()
        if not cleaned_raw:
            continue

        page_num = idx
        out_filename = f"page_{page_num:02d}_runes.md"
        out_filepath = os.path.join(CORPUS_DIR, out_filename)

        formatted_runes = format_chunk_runes(cleaned_raw)
        latin_trans = transliterate_chunk(formatted_runes)

        # Count runes and gematria prime sum
        page_runes = sum(1 for c in formatted_runes if c in INDEX_BY_RUNE)
        prime_sum = gematria_prime_sum(formatted_runes)
        total_runes += page_runes

        is_chapter_mark = (cleaned_raw == "§")
        title_suffix = "Chapter Delimiter Seal" if is_chapter_mark else f"Runic Transcript"

        doc_parts = [
            f"# Liber Primus — Page {page_num:02d}: {title_suffix}",
            f"<!-- cicada:page={page_num:02d} -->",
            f"<!-- cicada:rune_count={page_runes} -->",
            f"<!-- cicada:gematria_prime_sum={prime_sum} -->",
            f"<!-- cicada:source=liber-primus__transcription--master.txt -->",
            f"<!-- cicada:chunk_index={idx} -->",
            "",
            "## Rune Transcription",
            formatted_runes,
            "",
            "## Latin Transliteration",
            latin_trans,
            "",
            "## Master Delimited Representation",
            "```text",
            cleaned_raw,
            "```",
            "",
        ]
        doc_content = "\n".join(doc_parts)

        if not dry_run:
            with open(out_filepath, "w", encoding="utf-8") as out_f:
                out_f.write(doc_content)
            created_files += 1

    return {
        "total_chunks": total_chunks,
        "created_files": created_files,
        "total_runes": total_runes,
    }


def main():
    dry_run = "--dry-run" in sys.argv
    print("=== Partitioning Liber Primus Master Transcript ===")
    stats = process_master_file(dry_run=dry_run)
    action = "Scanned" if dry_run else "Created"
    print(f"[✓] {action} {stats['created_files']} page file(s) in corpus/")
    print(f"[*] Total runic characters indexed: {stats['total_runes']}")
    print(f"[*] Source chunks processed: {stats['total_chunks']}")


if __name__ == "__main__":
    main()
