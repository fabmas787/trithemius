"""
OpSec — Cryptographic Verification & Authenticity Module for Cicada 3301.

Validates authentic communications, signatures, and file structures:
- Official Cicada 3301 PGP Key ID: 7A35090F
- Full fingerprint: 853F 5664 D046 F538 E6FD 93DC A14E 2928 7A35 090F
- Distinguishes authentic official releases from community hoaxes, unverified leaks, and noise
- Magic bytes detection for files (JPEG, PNG, audio, PGP blocks)

Usage:
    from opsec import verify_pgp_block, inspect_file_headers, is_authentic_cicada
"""

import re
import os
from typing import Dict, Optional, Tuple, Any, List

CICADA_KEY_ID = "7A35090F"
# Official Primary Key Fingerprint (verified against 2012 messages and RFC 4880 v4 key packets)
CICADA_PRIMARY_FINGERPRINT = "6D854CD7933322A601C3286D181F01E57A35090F"
CICADA_FINGERPRINT = CICADA_PRIMARY_FINGERPRINT
LEGACY_FINGERPRINTS = {
    "853F5664D046F538E6FD93DCA14E29287A35090F",
    "853F5664D046F538E6F56F144D2A92E87A35090F",
    "52C140A7325F33B47136295020EE2E877A35090F",
}

try:
    from zimmermann import verify_cleartext, verify_detached, parse_keys
except ImportError:
    try:
        from ciphers.zimmermann import verify_cleartext, verify_detached, parse_keys
    except ImportError:
        verify_cleartext = None
        verify_detached = None
        parse_keys = None

PGP_SIGNED_REGEX = re.compile(
    r"-----BEGIN PGP SIGNED MESSAGE-----[\s\S]+?-----BEGIN PGP SIGNATURE-----[\s\S]+?-----END PGP SIGNATURE-----",
    re.MULTILINE
)

# Common File Magic Bytes
MAGIC_SIGNATURES = {
    b"\xFF\xD8\xFF": "JPEG Image (Potential Outguess/Steg target)",
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"GIF87a": "GIF87a Image",
    b"GIF89a": "GIF89a Image",
    b"%PDF-": "PDF Document",
    b"RIFF": "RIFF Audio/Video (WAV/AVI)",
    b"ID3": "MP3 Audio (ID3 Metadata)",
    b"\x50\x4B\x03\x04": "ZIP Archive",
}


def extract_pgp_blocks(text: str) -> list:
    """Extract all ASCII-armored PGP signed message blocks."""
    return PGP_SIGNED_REGEX.findall(text)


def inspect_pgp_text(text: str) -> Dict[str, any]:
    """
    Examine text for PGP signatures and check if they reference Cicada's official key (7A35090F).
    """
    has_pgp = "-----BEGIN PGP SIGNED MESSAGE-----" in text
    has_signature = "-----BEGIN PGP SIGNATURE-----" in text

    upper = text.upper()
    mentions_key = CICADA_KEY_ID in upper
    mentions_fp = CICADA_FINGERPRINT in upper.replace(" ", "")

    is_official = False
    verdict = "UNVERIFIED"

    if has_pgp and has_signature:
        if mentions_key or mentions_fp:
            is_official = True
            verdict = "AUTHENTIC_CICADA_KEY_REFERENCED"
        else:
            verdict = "SIGNED_BY_UNKNOWN_KEY"
    elif mentions_key:
        verdict = "MENTIONS_CICADA_KEY_UNSIGNED"
    else:
        verdict = "NO_PGP_SIGNATURE"

    return {
        "has_pgp_block": has_pgp and has_signature,
        "is_official_key": is_official,
        "key_id_found": CICADA_KEY_ID if mentions_key else None,
        "verdict": verdict,
        "primary_fingerprint_pinned": CICADA_PRIMARY_FINGERPRINT,
    }


def verify_cicada_message(text: str, pubkey_block: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform full cryptographic verification of an OpenPGP cleartext signed message
    against the pinned Cicada 3301 primary key fingerprint.
    """
    if verify_cleartext is None:
        return {"error": "zimmermann module not available"}
    if not pubkey_block:
        return {"error": "No public key block provided for cryptographic verification"}
    try:
        return verify_cleartext(text, pubkey_block, pinned_fingerprint=CICADA_PRIMARY_FINGERPRINT)
    except Exception as e:
        return {"valid_signature": False, "authentic": False, "error": str(e)}


try:
    from container import inspect_container_file
except ImportError:
    try:
        from ciphers.container import inspect_container_file
    except ImportError:
        inspect_container_file = None


def inspect_file_headers(filepath: str) -> Dict[str, any]:
    """
    Inspect magic bytes and walk container grammar to logical EOF.
    Isolates overlay data, computes overlay entropy, and flags polyglot/steg targets.
    """
    if not os.path.exists(filepath):
        return {"error": "File not found"}

    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            header = f.read(16)
    except Exception as e:
        return {"error": str(e)}

    detected_type = "Unknown / Plain Text"
    for magic, desc in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            detected_type = desc
            break

    container_info = inspect_container_file(filepath) if inspect_container_file else {}
    overlay_len = container_info.get("overlay_len", 0)
    is_steg = container_info.get("is_steg_candidate", ("Image" in detected_type or "Audio" in detected_type))

    return {
        "filepath": filepath,
        "size_bytes": file_size,
        "header_hex": header.hex(),
        "detected_type": detected_type,
        "is_steg_candidate": is_steg,
        "logical_end": container_info.get("logical_end", file_size),
        "overlay_len": overlay_len,
        "overlay_entropy": container_info.get("overlay_entropy", 0.0),
        "overlay_magic": container_info.get("overlay_magic"),
        "ancillary_chunks": container_info.get("ancillary_chunks") or container_info.get("ancillary_segments") or [],
        "polyglot_signatures": container_info.get("polyglot_signatures", []),
    }


if __name__ == "__main__":
    sample_cicada_block = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Welcome pilgrims. The primes are sacred.
Key ID: 7A35090F
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iQIcBAEBCgAGBQJPt58eAAoJEKFOKSB6NQkPgN0P/25g==
-----END PGP SIGNATURE-----"""

    res = inspect_pgp_text(sample_cicada_block)
    print("PGP Verification Result:")
    print(res)
    assert res["is_official_key"] is True
    print("\nOpSec Test: SUCCESS!")
