"""
Zimmermann — Native OpenPGP Signature Verification (RFC 4880 v4 + RSA).
Standard library only: hashlib, hmac, base64. Zero external dependencies.

Scope:
- RFC 4880 v4 RSA public keys and signatures.
- Cleartext signed messages (type 0x01) per RFC 4880 Section 7.
- Binary detached signatures (type 0x00).
- Constant-time full-block PKCS#1 v1.5 verification via hmac.compare_digest.
- SHA-256, SHA-384, SHA-512, SHA-224, and SHA-1 (flagged as weak_hash).
- Pinned fingerprint validation for primary keys and subkey binding identification.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple, Any

_HASHES: Dict[int, Tuple[str, str]] = {
    # OpenPGP hash id -> (hashlib name, DER DigestInfo prefix for PKCS#1 v1.5)
    2: ("sha1", "3021300906052b0e03021a05000414"),
    8: ("sha256", "3031300d060960864801650304020105000420"),
    9: ("sha384", "3041300d060960864801650304020205000430"),
    10: ("sha512", "3051300d060960864801650304020305000440"),
    11: ("sha224", "302d300d06096086480165030402040500041c"),
}
_WEAK_HASH_IDS = {2}  # SHA-1: accepted for historical 2012 messages but flagged


def crc24(data: bytes) -> int:
    """Compute RFC 4880 CRC-24 checksum."""
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(block: str) -> bytes:
    """Parse ASCII-armored PGP block and verify CRC-24 if present."""
    body: List[str] = []
    in_body = False
    crc_bytes: Optional[bytes] = None

    for ln in block.strip().splitlines():
        ln_stripped = ln.strip()
        if ln_stripped.startswith("-----BEGIN"):
            in_body = False
            continue
        if ln_stripped.startswith("-----END"):
            break
        if not in_body:
            if ln_stripped == "":
                in_body = True
            continue
        if ln_stripped.startswith("="):
            crc_bytes = base64.b64decode(ln_stripped[1:5])
        else:
            body.append(ln_stripped)

    raw = base64.b64decode("".join(body))
    if crc_bytes is not None:
        expected_crc = int.from_bytes(crc_bytes, "big")
        if expected_crc != crc24(raw):
            raise ValueError(f"invalid CRC24: expected {expected_crc:#x}, computed {crc24(raw):#x}")
    return raw


def _packets(data: bytes):
    """Yield (packet_tag, packet_body) for RFC 4880 data packets."""
    i = 0
    data_len = len(data)
    while i < data_len:
        tag = data[i]
        i += 1
        if tag & 0x40:  # New format packet
            t = tag & 0x3F
            if i >= data_len:
                break
            l = data[i]
            i += 1
            if 224 <= l < 255:
                raise ValueError("partial body length not supported")
            if 192 <= l < 224:
                if i >= data_len:
                    break
                l = ((l - 192) << 8) + data[i] + 192
                i += 1
            elif l == 255:
                if i + 4 > data_len:
                    break
                l = int.from_bytes(data[i:i + 4], "big")
                i += 4
        else:  # Old format packet
            t = (tag >> 2) & 0x0F
            length_type = tag & 3
            if length_type == 3:
                # Indeterminate length to EOF
                l = data_len - i
            else:
                n = {0: 1, 1: 2, 2: 4}[length_type]
                if i + n > data_len:
                    break
                l = int.from_bytes(data[i:i + n], "big")
                i += n
        if i + l > data_len:
            raise ValueError("packet length exceeds data length")
        yield t, data[i:i + l]
        i += l


def _mpi(buf: bytes, i: int) -> Tuple[int, int]:
    """Parse OpenPGP Multi-Precision Integer (MPI) at offset i."""
    bit_len = int.from_bytes(buf[i:i + 2], "big")
    n = (bit_len + 7) // 8
    val = int.from_bytes(buf[i + 2:i + 2 + n], "big")
    return val, i + 2 + n


def _subpackets(b: bytes):
    """Yield (subpacket_type, subpacket_body) from signature subpacket area."""
    i = 0
    b_len = len(b)
    while i < b_len:
        l = b[i]
        i += 1
        if 192 <= l < 255:
            if i >= b_len:
                break
            l = ((l - 192) << 8) + b[i] + 192
            i += 1
        elif l == 255:
            if i + 4 > b_len:
                break
            l = int.from_bytes(b[i:i + 4], "big")
            i += 4
        if i + l - 1 > b_len:
            break
        yield b[i] & 0x7F, b[i + 1:i + l]
        i += l


def parse_keys(block: str) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Parse an ASCII-armored public key block.
    Returns (keys_by_id16, primary_fingerprint) for every v4 RSA key packet.
    """
    keys: Dict[str, Dict[str, Any]] = {}
    primary: Optional[str] = None
    for t, body in _packets(dearmor(block)):
        if t in (6, 14) and len(body) > 6 and body[0] == 4 and body[5] == 1:
            n, i = _mpi(body, 6)
            e, _ = _mpi(body, i)
            fp = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
            if t == 6 and primary is None:
                primary = fp
            key_id16 = fp[-16:]
            keys[key_id16] = {"fp": fp, "n": n, "e": e, "primary": (t == 6)}
    return keys, primary


def parse_signature(block: str) -> Dict[str, Any]:
    """Extract and parse the first v4 signature packet from an ASCII-armored signature block."""
    for t, body in _packets(dearmor(block)):
        if t == 2:
            if body[0] != 4:
                raise ValueError("only v4 signatures are supported")
            sigtype = body[1]
            pub = body[2]
            hash_id = body[3]
            hl = int.from_bytes(body[4:6], "big")
            hashed = body[6:6 + hl]
            j = 6 + hl
            ul = int.from_bytes(body[j:j + 2], "big")
            unhashed = body[j + 2:j + 2 + ul]
            k = j + 2 + ul
            left16 = body[k:k + 2]
            s, _ = _mpi(body, k + 2)
            return {
                "sigtype": sigtype,
                "pub": pub,
                "hash": hash_id,
                "hashed": hashed,
                "unhashed": unhashed,
                "left16": left16,
                "sig": s,
            }
    raise ValueError("no signature packet found")


def parse_cleartext(message: str) -> Tuple[bytes, str, List[str]]:
    """
    Parse an RFC 4880 Section 7 cleartext signed message.
    Returns (canonical_text_bytes, signature_block, declared_hash_names).
    """
    lines = message.replace("\r\n", "\n").split("\n")
    start_idx = next(n for n, l in enumerate(lines) if l.strip() == "-----BEGIN PGP SIGNED MESSAGE-----") + 1
    declared: List[str] = []
    i = start_idx
    while i < len(lines) and lines[i].strip() != "":
        line_clean = lines[i].lower().strip()
        if line_clean.startswith("hash:"):
            declared += [h.strip().lower() for h in lines[i][5:].split(",")]
        i += 1
    # Skip empty header separator
    i += 1
    sig_idx = next(n for n in range(i, len(lines)) if lines[n].strip() == "-----BEGIN PGP SIGNATURE-----")
    # Section 7 dash-unescaping and trailing whitespace strip
    text = [(l[2:] if l.startswith("- ") else l).rstrip(" \t\r") for l in lines[i:sig_idx]]
    canonical_text = "\r\n".join(text).encode("utf-8")
    sig_block = "\n".join(lines[sig_idx:])
    return canonical_text, sig_block, declared


def _rsa_pkcs1_ok(sig: int, key: Dict[str, Any], hash_id: int, digest: bytes) -> bool:
    """Verify RSA signature using full PKCS#1 v1.5 block reconstruction and constant-time compare."""
    n, e = key["n"], key["e"]
    k = (n.bit_length() + 7) // 8
    if sig >= n:
        return False
    em = pow(sig, e, n).to_bytes(k, "big")
    prefix = bytes.fromhex(_HASHES[hash_id][1])
    expected = b"\x00\x01" + b"\xff" * (k - len(prefix) - len(digest) - 3) + b"\x00" + prefix + digest
    return hmac.compare_digest(em, expected)


def _verify(sig: Dict[str, Any], data: bytes, pubkey_block: str, pinned_fp: Optional[str]) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "valid_signature": False,
        "authentic": None,
        "weak_hash": False,
        "issuer_key_id": None,
        "signing_key_fingerprint": None,
        "primary_fingerprint": None,
        "created": None,
        "reasons": [],
    }

    if sig["pub"] != 1:
        raise ValueError(f"only RSA signatures are supported (got pub={sig['pub']})")
    if sig["hash"] not in _HASHES:
        raise ValueError(f"unsupported hash algorithm id {sig['hash']}")

    keys, primary = parse_keys(pubkey_block)
    res["primary_fingerprint"] = primary

    issuer: Optional[str] = None
    all_sub = list(_subpackets(sig["hashed"])) + list(_subpackets(sig["unhashed"]))
    for t, v in all_sub:
        if t == 33 and len(v) == 21:  # Issuer Fingerprint subpacket (v4)
            issuer = v[1:].hex().upper()[-16:]
        elif t == 16 and issuer is None and len(v) == 8:  # Issuer Key ID subpacket
            issuer = v.hex().upper()
        elif t == 2 and len(v) == 4:  # Signature Creation Time
            res["created"] = int.from_bytes(v, "big")

    res["issuer_key_id"] = issuer
    key = keys.get(issuer) if issuer else None
    if key is None:
        res["reasons"].append("issuer key not present in the supplied key block")
        return res

    res["signing_key_fingerprint"] = key["fp"]
    trailer = (
        bytes([4, sig["sigtype"], sig["pub"], sig["hash"]])
        + len(sig["hashed"]).to_bytes(2, "big")
        + sig["hashed"]
        + b"\x04\xff"
        + (6 + len(sig["hashed"])).to_bytes(4, "big")
    )
    digest = hashlib.new(_HASHES[sig["hash"]][0], data + trailer).digest()
    if digest[:2] != sig["left16"]:
        res["reasons"].append("digest prefix mismatch (message altered or wrong canonicalization)")
        return res

    res["valid_signature"] = _rsa_pkcs1_ok(sig["sig"], key, sig["hash"], digest)
    if not res["valid_signature"]:
        res["reasons"].append("RSA verification failed")

    res["weak_hash"] = sig["hash"] in _WEAK_HASH_IDS
    if res["weak_hash"]:
        res["reasons"].append("SHA-1 signature: collision-weak hash, acceptable only for historical messages")

    if not key["primary"]:
        res["reasons"].append("signed by a subkey: binding signature not verified")

    if pinned_fp is not None:
        clean_pinned = pinned_fp.replace(" ", "").upper()
        res["authentic"] = bool(res["valid_signature"] and primary == clean_pinned)
        if primary != clean_pinned:
            res["reasons"].append("key block primary fingerprint differs from the pinned fingerprint")

    return res


def verify_cleartext(message: str, pubkey_block: str, pinned_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Verify an RFC 4880 cleartext signed message."""
    data, sigblock, declared = parse_cleartext(message)
    sig = parse_signature(sigblock)
    if sig["sigtype"] != 0x01:
        raise ValueError(f"cleartext signatures must be type 0x01 (got {sig['sigtype']:#x})")
    res = _verify(sig, data, pubkey_block, pinned_fingerprint)
    hash_name = _HASHES[sig["hash"]][0]
    if declared and hash_name not in declared:
        res["reasons"].append(f"Hash header ({declared}) disagrees with signature packet ({hash_name})")
    return res


def verify_detached(data: bytes, sig_block: str, pubkey_block: str, pinned_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Verify an RFC 4880 binary detached signature (type 0x00)."""
    sig = parse_signature(sig_block)
    if sig["sigtype"] != 0x00:
        raise ValueError(f"only binary detached signatures (type 0x00) are supported (got {sig['sigtype']:#x})")
    return _verify(sig, data, pubkey_block, pinned_fingerprint)
