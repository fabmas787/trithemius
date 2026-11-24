"""
Container — Container-layer grammar analysis, logical EOF detection,
overlay extraction, and polyglot signature scanning for Cicada 3301.

Supported Container Grammars:
1. JPEG (JFIF/EXIF): scans segments to EOI (0xFF, 0xD9), skips byte-stuffing and RST markers
2. PNG: walks 4-byte chunk lengths and CRCs to IEND (with ancillary chunk cataloging)
3. GIF: walks screen descriptor, extension blocks (0x21), and image blocks (0x2C) to trailer (0x3B)
4. ZIP: locates End of Central Directory (EOCD, PK\x05\x06) and parses variable comment field
5. PDF: locates last %%EOF marker, tracks incremental update revisions

Overlay & OpSec Analysis:
- Calculates Shannon entropy of isolated overlay bytes
- Detects nested/polyglot containers (full-offset regex signature scanning)
- Identifies PGP ASCII-armor blocks embedded in container overlays
- Filters known benign trailers (e.g. MPF / Multi-Picture Format, motion photos)
- Defensive design: malformed/fuzzed containers return error records and never crash
"""

import os
import re
import struct
import math
from collections import Counter
from typing import Dict, List, Tuple, Optional, Any, Set

MAGIC_SIGNATURES = {
    b"\xFF\xD8\xFF": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"\x50\x4B\x03\x04": "ZIP",
    b"\x50\x4B\x05\x06": "ZIP",
    b"\x50\x4B": "ZIP",
    b"%PDF-": "PDF",
    b"RIFF": "RIFF",
    b"-----BEGIN PGP": "PGP_ARMOR",
}

# Signatures for full-offset polyglot scan (compiled regex alternation)
POLYGLOT_PATTERNS = [
    (b"\x89PNG\r\n\x1a\n", "PNG_IMAGE"),
    (b"-----BEGIN PGP", "PGP_ARMORED_BLOCK"),
    (b"7z\xBC\xAF\x27\x1C", "7ZIP_ARCHIVE"),
    (b"Rar!\x1A\x07", "RAR_ARCHIVE"),
    (b"\x50\x4B\x03\x04", "ZIP_ARCHIVE"),
    (b"\x50\x4B\x05\x06", "ZIP_ARCHIVE"),
    (b"\xFF\xD8\xFF", "JPEG_IMAGE"),
    (b"%PDF-", "PDF_DOCUMENT"),
]

POLYGLOT_COMPILED_REGEX = re.compile(b"|".join(re.escape(sig) for sig, _ in POLYGLOT_PATTERNS))
SIG_TO_NAME = {sig: name for sig, name in POLYGLOT_PATTERNS}


def shannon_entropy_bytes(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0.0 to 8.0) directly from bytes."""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    ent = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 4)


# -----------------------------------------------------------------------------
# 1. Container Grammar Walkers
# -----------------------------------------------------------------------------

def walk_jpeg(data: bytes) -> Dict[str, Any]:
    """
    Walk JPEG marker segments to determine logical EOF (EOI: 0xFF, 0xD9).
    Correctly handles entropy-coded segments after SOS (0xFF, 0xDA),
    escaped 0xFF 0x00 bytes, and RST markers (0xFF, 0xD0..0xD7).
    """
    if len(data) < 4 or not data.startswith(b"\xFF\xD8"):
        return {"logical_end": -1, "error": "Not a valid JPEG (missing SOI marker)"}

    pos = 2
    n = len(data)
    ancillary_segments = []
    is_mpf = False

    while pos < n:
        # Find next 0xFF marker
        if data[pos] != 0xFF:
            pos += 1
            continue

        # Skip duplicate 0xFF padding bytes
        while pos < n and data[pos] == 0xFF:
            pos += 1

        if pos >= n:
            break

        marker = data[pos]
        pos += 1

        # Standalone markers with no length payload
        if marker in (0xD8, 0xD9):  # SOI, EOI
            if marker == 0xD9:
                return {
                    "logical_end": pos,
                    "ancillary_segments": ancillary_segments,
                    "is_mpf": is_mpf,
                    "format": "JPEG",
                }
            continue
        elif 0xD0 <= marker <= 0xD7 or marker in (0x01, 0x00):  # RST0..RST7, TEM, stuffed 0x00
            continue

        # Segment with 2-byte big-endian length (length includes the 2 length bytes)
        if pos + 2 > n:
            return {"logical_end": -1, "error": "Truncated JPEG marker length"}

        seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
        if seg_len < 2:
            return {"logical_end": -1, "error": f"Invalid JPEG segment length: {seg_len}"}

        seg_payload_start = pos + 2
        seg_payload_end = pos + seg_len

        # Record APPn segments and COM
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            seg_name = f"APP{marker - 0xE0}" if marker <= 0xEF else "COM"
            seg_data = data[seg_payload_start:min(seg_payload_end, seg_payload_start + 32)]
            ancillary_segments.append({"marker": seg_name, "length": seg_len, "preview": seg_data.hex()})
            if b"MPF\x00" in seg_data:
                is_mpf = True

        # SOS (Start of Scan) - After SOS header comes compressed entropy stream
        if marker == 0xDA:
            pos = seg_payload_end
            # Scan entropy stream until unescaped EOI (0xFF, 0xD9)
            while pos < n - 1:
                if data[pos] == 0xFF:
                    next_b = data[pos + 1]
                    if next_b == 0xD9:  # EOI found
                        return {
                            "logical_end": pos + 2,
                            "ancillary_segments": ancillary_segments,
                            "is_mpf": is_mpf,
                            "format": "JPEG",
                        }
                    elif next_b == 0x00 or (0xD0 <= next_b <= 0xD7):
                        pos += 2
                        continue
                    elif next_b == 0xFF:
                        pos += 1
                        continue
                    else:
                        # Another marker inside scan, skip it
                        pos += 2
                        continue
                pos += 1
            break
        else:
            pos = seg_payload_end

    return {"logical_end": -1, "error": "JPEG EOI (0xFF, 0xD9) marker not found"}


def walk_png(data: bytes) -> Dict[str, Any]:
    """
    Walk PNG chunks [Length 4B][Type 4B][Data NB][CRC 4B] to IEND.
    Extracts ancillary chunks (tEXt, iTXt, zTXt, eXIf, private chunks).
    """
    png_sig = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(png_sig):
        return {"logical_end": -1, "error": "Invalid PNG signature"}

    pos = len(png_sig)
    n = len(data)
    ancillary_chunks = []

    while pos + 8 <= n:
        chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        total_chunk_size = 4 + 4 + chunk_len + 4  # length + type + data + CRC

        if pos + total_chunk_size > n:
            return {"logical_end": -1, "error": f"Truncated PNG chunk {chunk_type.decode('latin1', errors='replace')}"}

        type_str = chunk_type.decode("latin1", errors="replace")
        # Ancillary or metadata chunks: tEXt, zTXt, iTXt, eXIf, or lowercase first letter (private)
        if type_str in ("tEXt", "zTXt", "iTXt", "eXIf") or type_str[0].islower():
            ancillary_chunks.append({
                "type": type_str,
                "length": chunk_len,
                "offset": pos,
            })

        pos += total_chunk_size
        if chunk_type == b"IEND":
            return {
                "logical_end": pos,
                "ancillary_chunks": ancillary_chunks,
                "format": "PNG",
            }

    return {"logical_end": -1, "error": "PNG IEND chunk not found"}


def walk_gif(data: bytes) -> Dict[str, Any]:
    """Walk GIF blocks to trailer byte (0x3B)."""
    if len(data) < 13 or not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return {"logical_end": -1, "error": "Invalid or truncated GIF"}

    pos = 13  # Header (6B) + Logical Screen Descriptor (7B)
    n = len(data)

    # Check Global Color Table
    packed = data[10]
    has_gct = bool(packed & 0x80)
    if has_gct:
        gct_size = 3 * (1 << ((packed & 0x07) + 1))
        pos += gct_size

    ancillary_blocks = []

    while pos < n:
        block_type = data[pos]
        if block_type == 0x3B:  # Trailer
            return {
                "logical_end": pos + 1,
                "ancillary_blocks": ancillary_blocks,
                "format": "GIF",
            }
        elif block_type == 0x21:  # Extension block
            if pos + 2 > n:
                break
            ext_label = data[pos + 1]
            pos += 2
            # Skip sub-blocks
            while pos < n:
                sub_len = data[pos]
                pos += 1
                if sub_len == 0:
                    break
                pos += sub_len
            ancillary_blocks.append(f"EXT_0x{ext_label:02X}")
        elif block_type == 0x2C:  # Image Descriptor
            if pos + 10 > n:
                break
            img_packed = data[pos + 9]
            has_lct = bool(img_packed & 0x80)
            pos += 10
            if has_lct:
                lct_size = 3 * (1 << ((img_packed & 0x07) + 1))
                pos += lct_size
            if pos < n:
                pos += 1  # LZW min code size
            # Skip sub-blocks
            while pos < n:
                sub_len = data[pos]
                pos += 1
                if sub_len == 0:
                    break
                pos += sub_len
        else:
            pos += 1

    return {"logical_end": -1, "error": "GIF trailer (0x3B) not found"}


def walk_zip(data: bytes) -> Dict[str, Any]:
    """Locate ZIP End of Central Directory (EOCD: PK\x05\x06) and calculate logical end."""
    eocd_sig = b"\x50\x4B\x05\x06"
    n = len(data)
    # EOCD is at least 22 bytes, search backwards up to 65535 + 22 bytes
    search_limit = max(0, n - 65557)
    idx = data.rfind(eocd_sig, search_limit)
    if idx == -1:
        return {"logical_end": -1, "error": "ZIP EOCD record (PK\x05\x06) not found"}

    if idx + 22 > n:
        return {"logical_end": -1, "error": "Truncated ZIP EOCD header"}

    comment_len = struct.unpack("<H", data[idx + 20:idx + 22])[0]
    logical_end = idx + 22 + comment_len
    if logical_end > n:
        logical_end = n

    return {
        "logical_end": logical_end,
        "eocd_offset": idx,
        "comment_len": comment_len,
        "format": "ZIP",
    }


def walk_pdf(data: bytes) -> Dict[str, Any]:
    """Locate last %%EOF in PDF, counting incremental update revisions."""
    eof_sig = b"%%EOF"
    n = len(data)
    idx = data.rfind(eof_sig)
    if idx == -1:
        return {"logical_end": -1, "error": "PDF %%EOF marker not found"}

    # Count incremental revisions
    rev_count = data.count(eof_sig)
    logical_end = idx + len(eof_sig)
    # Consume trailing newline or whitespace if present
    while logical_end < n and data[logical_end:logical_end + 1] in (b"\r", b"\n", b" ", b"\t"):
        logical_end += 1

    return {
        "logical_end": logical_end,
        "revision_count": rev_count,
        "format": "PDF",
    }


# -----------------------------------------------------------------------------
# 2. Universal Container Inspector & Polyglot Scanner
# -----------------------------------------------------------------------------

def scan_polyglot_signatures(data: bytes) -> List[Dict[str, Any]]:
    """Scan file bytes for embedded container signatures across all offsets using compiled regex alternation."""
    hits = []
    n = len(data)
    for m in POLYGLOT_COMPILED_REGEX.finditer(data):
        sig = m.group(0)
        sig_name = SIG_TO_NAME.get(sig, "UNKNOWN")
        hits.append({
            "type": sig_name,
            "offset": m.start(),
            "relative_to_eof": m.start() - n,
        })
    return hits


def inspect_container_bytes(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Perform deep container analysis on raw bytes:
    1. Identify container type by initial magic signature
    2. Walk container grammar to calculate exact logical EOF
    3. Isolate overlay bytes (beyond logical EOF)
    4. Compute overlay Shannon entropy, embedded magic, and PGP blocks
    5. Check allow-list for benign trailers (MPF, Motion Photo, PDF incremental)
    """
    n = len(data)
    if not n:
        return {"format": "EMPTY", "size_bytes": 0, "logical_end": 0, "overlay_len": 0}

    # Identify primary container
    result: Dict[str, Any] = {}
    if data.startswith(b"\xFF\xD8\xFF"):
        result = walk_jpeg(data)
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        result = walk_png(data)
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        result = walk_gif(data)
    elif data.startswith(b"\x50\x4B"):
        result = walk_zip(data)
    elif data.startswith(b"%PDF-"):
        result = walk_pdf(data)
    else:
        # Check if plain text / PGP armored block
        if b"-----BEGIN PGP" in data:
            return {
                "format": "PGP_ARMOR",
                "size_bytes": n,
                "logical_end": n,
                "overlay_len": 0,
                "is_steg_candidate": False,
            }
        return {
            "format": "UNKNOWN_OR_RAW",
            "size_bytes": n,
            "logical_end": n,
            "overlay_len": 0,
            "is_steg_candidate": False,
        }

    log_end = result.get("logical_end", -1)
    if log_end < 0 or log_end > n:
        result["size_bytes"] = n
        result["overlay_len"] = 0
        result["is_steg_candidate"] = False
        return result

    overlay_bytes = data[log_end:]
    overlay_len = len(overlay_bytes)
    overlay_entropy = shannon_entropy_bytes(overlay_bytes) if overlay_len > 0 else 0.0

    # Detect magic signatures in overlay
    overlay_magic = None
    if overlay_len >= 3:
        for magic, desc in MAGIC_SIGNATURES.items():
            if overlay_bytes.startswith(magic):
                overlay_magic = desc
                break

    has_pgp = b"-----BEGIN PGP" in overlay_bytes
    is_benign_trailer = False
    benign_reason = None

    # Check benign trailer allow-list
    if result.get("format") == "JPEG" and result.get("is_mpf"):
        is_benign_trailer = True
        benign_reason = "Multi-Picture Format (MPF) trailer"
    elif result.get("format") == "JPEG" and (b"GCamera" in overlay_bytes or b"MotionPhoto" in overlay_bytes):
        is_benign_trailer = True
        benign_reason = "Motion photo embedded stream"
    elif overlay_len <= 16 and overlay_bytes.strip() == b"":
        is_benign_trailer = True
        benign_reason = "Trailing padding/newlines"

    is_steg_target = (overlay_len > 0 and not is_benign_trailer) or (has_pgp) or (overlay_magic is not None)

    result.update({
        "size_bytes": n,
        "overlay_len": overlay_len,
        "overlay_entropy": overlay_entropy,
        "overlay_magic": overlay_magic,
        "has_pgp_in_overlay": has_pgp,
        "is_benign_trailer": is_benign_trailer,
        "benign_reason": benign_reason,
        "is_steg_candidate": is_steg_target,
    })
    return result


def inspect_container_file(filepath: str) -> Dict[str, Any]:
    """Inspect file on disk with full container grammar walking and polyglot scan."""
    if not os.path.exists(filepath):
        return {"error": "File not found"}
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        res = inspect_container_bytes(data, filename=os.path.basename(filepath))
        res["filepath"] = filepath
        res["polyglot_signatures"] = scan_polyglot_signatures(data)
        return res
    except Exception as e:
        return {"error": str(e), "filepath": filepath}


# -----------------------------------------------------------------------------
# 3. Optional P3: Lossless Embedding Detector (PoV Chi-Square & LSB Autocorr)
# -----------------------------------------------------------------------------

import zlib

def _chi2_sf(chi2: float, df: int) -> float:
    """Survival function (upper-tail p-value) for Chi-Squared distribution via Wilson-Hilferty approximation."""
    if df <= 0 or chi2 <= 0:
        return 1.0
    z = ((chi2 / df) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
    p = 0.5 * (1.0 - math.erf(z / math.sqrt(2.0)))
    return max(0.0, min(1.0, p))


def extract_lossless_pixels(data: bytes) -> Optional[Tuple[bytes, int, int]]:
    """
    Extract uncompressed 8-bit pixel raster (pixel_bytes, width, height) from lossless containers (PNG / BMP).
    Uses Pillow when available, with a pure-Python / stdlib fallback for PNG and BMP.
    """
    if not data:
        return None

    # 1. Pillow (preferred accelerator)
    try:
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(data))
        if im.format in ("PNG", "BMP", "TIFF"):
            gray = im.convert("L")
            return bytes(gray.tobytes()), gray.width, gray.height
    except Exception:
        pass

    # 2. Pure stdlib fallback for uncompressed BMP (BI_RGB)
    if data.startswith(b"BM") and len(data) >= 54:
        try:
            offset = struct.unpack("<I", data[10:14])[0]
            width, height = struct.unpack("<ii", data[18:26])
            bpp = struct.unpack("<H", data[28:30])[0]
            compression = struct.unpack("<I", data[30:34])[0]
            if compression == 0 and width > 0 and height != 0 and offset < len(data):
                abs_h = abs(height)
                row_size = ((bpp * width + 31) // 32) * 4
                pixels = bytearray()
                for y in range(abs_h):
                    row_start = offset + y * row_size
                    row_data = data[row_start:row_start + (width * bpp // 8)]
                    if bpp == 8:
                        pixels.extend(row_data)
                    elif bpp in (24, 32):
                        step = bpp // 8
                        for x in range(0, len(row_data) - step + 1, step):
                            b_val, g_val, r_val = row_data[x], row_data[x + 1], row_data[x + 2]
                            lum = (r_val * 299 + g_val * 587 + b_val * 114) // 1000
                            pixels.append(lum)
                if pixels:
                    return bytes(pixels), width, abs_h
        except Exception:
            pass

    # 3. Pure stdlib fallback for PNG (zlib + filter un-filtering)
    png_sig = b"\x89PNG\r\n\x1a\n"
    if data.startswith(png_sig) and len(data) >= 33:
        try:
            w, h, bit_depth, color_type = struct.unpack(">IIBB", data[16:26])
            if bit_depth == 8 and color_type in (0, 2):  # 8-bit grayscale or RGB
                bpp = 1 if color_type == 0 else 3
                pos = len(png_sig)
                idat_parts = []
                while pos + 8 <= len(data):
                    c_len = struct.unpack(">I", data[pos:pos + 4])[0]
                    c_type = data[pos + 4:pos + 8]
                    if c_type == b"IDAT":
                        idat_parts.append(data[pos + 8:pos + 8 + c_len])
                    elif c_type == b"IEND":
                        break
                    pos += 8 + c_len + 4

                if idat_parts:
                    raw_decomp = zlib.decompress(b"".join(idat_parts))
                    stride = 1 + w * bpp
                    reconstructed = bytearray()
                    prev_scanline = bytearray(w * bpp)

                    for y in range(h):
                        scanline_start = y * stride
                        if scanline_start + stride > len(raw_decomp):
                            break
                        filter_type = raw_decomp[scanline_start]
                        curr_filt = bytearray(raw_decomp[scanline_start + 1:scanline_start + stride])
                        recon = bytearray(w * bpp)

                        for x in range(w * bpp):
                            filt_x = curr_filt[x]
                            a = recon[x - bpp] if x >= bpp else 0
                            b = prev_scanline[x]
                            c = prev_scanline[x - bpp] if x >= bpp else 0

                            if filter_type == 0:
                                val = filt_x
                            elif filter_type == 1:
                                val = (filt_x + a) & 0xFF
                            elif filter_type == 2:
                                val = (filt_x + b) & 0xFF
                            elif filter_type == 3:
                                val = (filt_x + ((a + b) // 2)) & 0xFF
                            elif filter_type == 4:
                                p = a + b - c
                                pa = abs(p - a)
                                pb = abs(p - b)
                                pc = abs(p - c)
                                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                                val = (filt_x + pr) & 0xFF
                            else:
                                val = filt_x
                            recon[x] = val

                        prev_scanline = recon
                        if bpp == 1:
                            reconstructed.extend(recon)
                        else:
                            for px in range(0, len(recon), 3):
                                r_val, g_val, b_val = recon[px], recon[px + 1], recon[px + 2]
                                reconstructed.append((r_val * 299 + g_val * 587 + b_val * 114) // 1000)

                    if reconstructed:
                        return bytes(reconstructed), w, h
        except Exception:
            pass

    return None


def lsb_plane_autocorrelation(pixel_bytes: bytes, width: int = 0, height: int = 0) -> Dict[str, Any]:
    """
    LSB-Plane Autocorrelation Steganalysis for lossless carriers (PNG / BMP).
    Measures spatial correlation in the least significant bit (bit 0) plane.
    Natural uncompressed images display spatial correlation (r > 0.08).
    LSB embedding whitens the bit plane toward independent noise (|r| ~ 0).
    """
    if len(pixel_bytes) < 64:
        return {"r_lag1": 0.0, "r_horizontal": 0.0, "r_vertical": 0.0, "whitening_detected": False}

    bits = [b & 1 for b in pixel_bytes]
    n = len(bits)
    mean_b = sum(bits) / n
    var_b = sum((b - mean_b) ** 2 for b in bits) / n

    if var_b < 1e-9:
        return {"r_lag1": 0.0, "r_horizontal": 0.0, "r_vertical": 0.0, "whitening_detected": False}

    cov_1d = sum((bits[i] - mean_b) * (bits[i + 1] - mean_b) for i in range(n - 1)) / (n - 1)
    r_1d = cov_1d / var_b

    r_h = r_1d
    r_v = r_1d

    if width > 1 and height > 1 and width * height <= n:
        h_pairs = 0
        cov_h = 0.0
        for y in range(height):
            row_start = y * width
            for x in range(width - 1):
                cov_h += (bits[row_start + x] - mean_b) * (bits[row_start + x + 1] - mean_b)
                h_pairs += 1
        r_h = (cov_h / h_pairs) / var_b if h_pairs > 0 else r_1d

        v_pairs = 0
        cov_v = 0.0
        for y in range(height - 1):
            row_start = y * width
            next_row = (y + 1) * width
            for x in range(width):
                cov_v += (bits[row_start + x] - mean_b) * (bits[next_row + x] - mean_b)
                v_pairs += 1
        r_v = (cov_v / v_pairs) / var_b if v_pairs > 0 else r_1d

    r_metric = max(abs(r_h), abs(r_v))
    whitening_detected = (r_metric < 0.05) and (n >= 400)

    return {
        "r_lag1": round(r_1d, 4),
        "r_horizontal": round(r_h, 4),
        "r_vertical": round(r_v, 4),
        "whitening_detected": whitening_detected,
    }


def pov_chi_squared_test(pixel_bytes: bytes) -> Dict[str, Any]:
    """
    Westfeld-Pfitzmann Pairs of Values (PoV) Chi-Squared Steganalysis.
    Detects LSB embedding in lossless pixel/byte streams by measuring
    frequency equalization across adjacent pairs (2k, 2k+1).
    """
    if len(pixel_bytes) < 64:
        return {"chi2": 0.0, "df": 0, "chi2_per_df": 0.0, "p_value": 1.0, "steg_detected": False}

    counts = Counter(pixel_bytes)
    chi2 = 0.0
    df = 0

    for k in range(128):
        y0 = counts.get(2 * k, 0)
        y1 = counts.get(2 * k + 1, 0)
        pair_sum = y0 + y1
        if pair_sum > 0:
            expected = pair_sum / 2.0
            chi2 += ((y0 - expected) ** 2) / expected + ((y1 - expected) ** 2) / expected
            df += 1

    df = max(1, df - 1)
    normalized_stat = chi2 / df if df > 0 else 999.0
    p_val = _chi2_sf(chi2, df)
    # Low chi2 / df indicates suspicious LSB pairing equalization
    steg_detected = normalized_stat < 0.25 and len(pixel_bytes) >= 500

    return {
        "chi2": round(chi2, 3),
        "df": df,
        "chi2_per_df": round(normalized_stat, 3),
        "p_value": round(p_val, 4),
        "steg_detected": steg_detected,
    }
