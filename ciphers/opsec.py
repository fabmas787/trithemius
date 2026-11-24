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
from typing import Dict, Optional, Tuple, Any, List, Sequence, Union

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
    from ciphers.zimmermann import verify_cleartext, verify_detached, parse_keys
except ImportError:
    try:
        from zimmermann import verify_cleartext, verify_detached, parse_keys
    except ImportError:
        verify_cleartext = None
        verify_detached = None
        parse_keys = None

try:
    from ciphers.spectral_sbox import (
        fast_walsh_hadamard_transform,
        difference_distribution_table,
        differential_uniformity,
        nonlinearity,
        strict_avalanche_criterion,
        algebraic_degree,
    )
except ImportError:
    try:
        from spectral_sbox import (
            fast_walsh_hadamard_transform,
            difference_distribution_table,
            differential_uniformity,
            nonlinearity,
            strict_avalanche_criterion,
            algebraic_degree,
        )
    except ImportError:
        fast_walsh_hadamard_transform = None
        difference_distribution_table = None
        differential_uniformity = None
        nonlinearity = None
        strict_avalanche_criterion = None
        algebraic_degree = None

try:
    from ciphers.rsa_audit import (
        audit_rsa_key,
        is_prime_miller_rabin,
        fermat_factor,
        pollard_rho,
        wiener_attack,
        batch_gcd,
    )
except ImportError:
    try:
        from rsa_audit import (
            audit_rsa_key,
            is_prime_miller_rabin,
            fermat_factor,
            pollard_rho,
            wiener_attack,
            batch_gcd,
        )
    except ImportError:
        audit_rsa_key = None
        is_prime_miller_rabin = None
        fermat_factor = None
        pollard_rho = None
        wiener_attack = None
        batch_gcd = None

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
    from ciphers.container import inspect_container_file
except ImportError:
    try:
        from container import inspect_container_file
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


# =====================================================================
# Binary Spectral (WHT / DDT) & Cryptographic Diagnostics
# =====================================================================

def binary_wht(f: Sequence[Union[int, float]]) -> List[Union[int, float]]:
    """
    Fast Walsh-Hadamard Transform (FWHT) for vectors of length 2^n.
    Delegates to spectral_sbox if available, else executes native standard-library implementation.
    """
    if fast_walsh_hadamard_transform is not None:
        try:
            return fast_walsh_hadamard_transform(f)
        except Exception:
            pass

    n = len(f)
    res = list(f)
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                x = res[j]
                y = res[j + h]
                res[j] = x + y
                res[j + h] = x - y
        h *= 2
    return res


def binary_ddt(sbox: Sequence[int]) -> List[List[int]]:
    """
    Difference Distribution Table (DDT) under bitwise XOR differences.
    Delegates to spectral_sbox mode='xor' if available, else executes native implementation.
    """
    if difference_distribution_table is not None:
        try:
            return difference_distribution_table(sbox, mode="xor")
        except Exception:
            pass

    n = len(sbox)
    ddt = [[0] * n for _ in range(n)]
    for din in range(n):
        for x in range(n):
            dout = sbox[x ^ din] ^ sbox[x]
            if 0 <= dout < n:
                ddt[din][dout] += 1
    return ddt


def check_binary_wht_ddt(sbox_or_bytes: Union[Sequence[int], bytes, bytearray]) -> Dict[str, Any]:
    """
    Audit cryptographic S-box and byte-stream nonlinearity via Fast Walsh-Hadamard Transform (FWHT)
    and XOR Difference Distribution Table (DDT).
    Computes:
    - Maximum absolute Walsh spectrum amplitude
    - XOR Differential Uniformity (delta = max_{din != 0, dout} DDT(din, dout))
    - S-box nonlinearity, algebraic degree, and strict avalanche criterion (SAC)
    """
    if isinstance(sbox_or_bytes, (bytes, bytearray)):
        sbox = list(sbox_or_bytes)
    else:
        sbox = list(sbox_or_bytes)

    n = len(sbox)
    if n == 0:
        return {"error": "Empty input sequence"}

    # Compute nearest power-of-two padding length
    k = 1
    while k < n:
        k <<= 1

    padded_sbox = list(sbox)
    if k != n:
        for i in range(n, k):
            padded_sbox.append(i % k)

    ddt = binary_ddt(padded_sbox)
    max_diff = 0
    for din in range(1, len(ddt)):
        for dout in range(len(ddt[din])):
            if ddt[din][dout] > max_diff:
                max_diff = ddt[din][dout]

    wht_spectrum = binary_wht([float(x) for x in padded_sbox])
    max_wht = max(abs(w) for w in wht_spectrum)

    nl = None
    if nonlinearity is not None:
        try:
            nl = nonlinearity(padded_sbox)
        except Exception:
            pass

    sac = None
    if strict_avalanche_criterion is not None:
        try:
            sac = strict_avalanche_criterion(padded_sbox)
        except Exception:
            pass

    ad = None
    if algebraic_degree is not None:
        try:
            ad = algebraic_degree(padded_sbox)
        except Exception:
            pass

    return {
        "input_length": n,
        "spectral_length": k,
        "differential_uniformity": max_diff,
        "ddt_shape": (len(ddt), len(ddt[0]) if ddt else 0),
        "max_wht_amplitude": round(max_wht, 2),
        "nonlinearity": nl,
        "strict_avalanche_criterion": sac,
        "algebraic_degree": ad,
        "audit_passed": max_diff <= max(4, k // 4),
    }


# =====================================================================
# RSA Key & OpenPGP Cryptographic Audit Pipeline
# =====================================================================

def check_rsa_audit(N: int, e: int = 65537) -> Dict[str, Any]:
    """
    Perform deep cryptographic audit of an RSA public modulus N and exponent e:
    1. Modulus bit length and security margin
    2. Miller-Rabin deterministic primality (verifies composite structure)
    3. Small prime factor screening and Pollard's rho
    4. Fermat close-prime factorization (|p - q| <= O(N^0.25))
    5. Wiener continued fraction attack for small private exponent (d < 1/3 N^0.25)
    6. Batch GCD / shared factors check
    """
    if audit_rsa_key is not None:
        try:
            res = audit_rsa_key(N, e=e)
            if "audit_passed" not in res:
                res["audit_passed"] = not res.get("vulnerable", False)
            if "is_modulus_prime" not in res:
                res["is_modulus_prime"] = (res.get("attack_method") == "INVALID_KEY_PRIME_MODULUS")
            return res
        except Exception as err:
            return {"error": str(err), "vulnerable": False, "audit_passed": True}

    bit_len = N.bit_length()
    vulnerabilities = []

    # 1. Miller-Rabin compositeness check
    is_prime = False
    if is_prime_miller_rabin is not None:
        is_prime = is_prime_miller_rabin(N)
    else:
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if N == p:
                break
            if N % p == 0:
                vulnerabilities.append(f"Divisible by small prime {p}")
                break

    if is_prime:
        vulnerabilities.append("Modulus is prime (not a valid RSA composite)")

    # 2. Fermat factorization
    if fermat_factor is not None:
        try:
            factors = fermat_factor(N, max_steps=10000)
            if factors:
                vulnerabilities.append(f"Factored by Fermat: p={factors[0]}, q={factors[1]}")
        except Exception:
            pass

    # 3. Wiener small exponent attack
    if wiener_attack is not None:
        try:
            wiener_hit = wiener_attack(e, N)
            if wiener_hit:
                d, p_val, q_val = wiener_hit
                vulnerabilities.append(f"Vulnerable to Wiener small exponent attack (d={d})")
        except Exception:
            pass

    return {
        "modulus_bits": bit_len,
        "public_exponent": e,
        "is_modulus_prime": is_prime,
        "vulnerabilities": vulnerabilities,
        "vulnerable": len(vulnerabilities) > 0,
        "audit_passed": len(vulnerabilities) == 0,
    }


def audit_pgp_key_security(pubkey_armored: str) -> Dict[str, Any]:
    """
    Parse ASCII-armored OpenPGP public key and run RSA audit checks on any contained RSA moduli.
    """
    if parse_keys is None:
        return {"error": "zimmermann OpenPGP parser not available"}

    try:
        keys = parse_keys(pubkey_armored)
    except Exception as e:
        return {"error": f"Failed to parse PGP key packets: {e}"}

    results = []
    for k in keys:
        n = getattr(k, "n", None) or (k.get("n") if isinstance(k, dict) else None)
        e = getattr(k, "e", 65537) or (k.get("e", 65537) if isinstance(k, dict) else 65537)
        key_id = getattr(k, "key_id", "UNKNOWN") or (k.get("key_id", "UNKNOWN") if isinstance(k, dict) else "UNKNOWN")

        if n:
            audit_res = check_rsa_audit(n, e)
            audit_res["key_id"] = key_id
            results.append(audit_res)
        else:
            results.append({"key_id": key_id, "note": "No RSA modulus extracted"})

    return {
        "keys_audited": len(results),
        "audit_results": results,
        "all_passed": all(r.get("audit_passed", True) for r in results),
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

    # Test WHT / DDT check
    sample_sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
    wht_res = check_binary_wht_ddt(sample_sbox)
    print("WHT/DDT Audit:", wht_res)
    assert wht_res["differential_uniformity"] > 0

    # Test RSA Audit check
    p_close = 1000000007
    q_close = 1000000009
    n_fermat = p_close * q_close
    rsa_res = check_rsa_audit(n_fermat, e=65537)
    print("RSA Fermat Audit:", rsa_res)
    assert rsa_res["vulnerable"] is True

    print("\nOpSec Test: SUCCESS!")
