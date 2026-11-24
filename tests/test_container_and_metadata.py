"""
Unit tests for Phase 4: Container-Layer Analysis & Provenance Prior (P1, P2, P3).
Tests:
1. Clean container fixtures (JPEG, PNG, GIF, ZIP, PDF) -> overlay_len == 0
2. Appended payloads recovered exactly at logical EOF boundary
3. PNG ancillary chunk detection (tEXt, private chunks)
4. Benign trailer allow-list (MPF, trailing newlines)
5. Robustness against malformed and fuzzed headers (no crashes)
6. Full-offset polyglot signature scanning
7. Retrieval provenance prior weighting (verified 1.5, unsigned 1.0, mismatch 0.4)
8. Westfeld-Pfitzmann PoV Chi-Square steganalysis
"""

import os
import sys
import struct
import zlib
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "ciphers"))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

import ciphers.container as container
import ciphers.opsec as opsec
import scripts.ask as ask


class TestContainerGrammarAndOverlay(unittest.TestCase):
    def _create_minimal_jpeg(self) -> bytes:
        # SOI (FF D8) + APP0 (FF E0, len=16) + SOS (FF DA, len=8) + data + EOI (FF D9)
        app0_payload = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        app0_len = len(app0_payload) + 2
        app0 = b"\xFF\xE0" + struct.pack(">H", app0_len) + app0_payload

        sos_payload = b"\x01\x01\x00\x00\x3F\x00"
        sos_len = len(sos_payload) + 2
        sos = b"\xFF\xDA" + struct.pack(">H", sos_len) + sos_payload
        entropy_data = b"\x12\x34\x56\x78\xFF\x00\x9A\xBC"  # Includes stuffed 0xFF 0x00
        eoi = b"\xFF\xD9"
        return b"\xFF\xD8" + app0 + sos + entropy_data + eoi

    def _create_minimal_png(self, ancillary_chunks: list = None) -> bytes:
        sig = b"\x89PNG\r\n\x1a\n"
        # IHDR: width=1, height=1, bit_depth=8, color_type=0, comp=0, filter=0, interlace=0 (13 bytes)
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
        ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

        # IDAT
        raw_scanline = b"\x00\x80"  # filter 0 + 1 gray pixel
        idat_data = zlib.compress(raw_scanline)
        idat_crc = zlib.crc32(b"IDAT" + idat_data)
        idat = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data + struct.pack(">I", idat_crc)

        extra = b""
        if ancillary_chunks:
            for c_type, c_data in ancillary_chunks:
                c_crc = zlib.crc32(c_type + c_data)
                extra += struct.pack(">I", len(c_data)) + c_type + c_data + struct.pack(">I", c_crc)

        # IEND
        iend_crc = zlib.crc32(b"IEND")
        iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
        return sig + ihdr + extra + idat + iend

    def _create_minimal_gif(self) -> bytes:
        # Header (GIF89a) + Screen Descriptor (7B: width 1, height 1, packed 0, bg 0, aspect 0) + Trailer (0x3B)
        return b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x3B"

    def _create_minimal_zip(self, comment: bytes = b"") -> bytes:
        # Minimal empty zip: only EOCD record (22B + comment)
        # PK\x05\x06, disk 0, disk with CD 0, CD entries disk 0, CD total 0, CD size 0, CD offset 0, comment len
        eocd_fixed = struct.pack("<4sHHHHIIH", b"\x50\x4B\x05\x06", 0, 0, 0, 0, 0, 0, len(comment))
        return eocd_fixed + comment

    def _create_minimal_pdf(self) -> bytes:
        return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\nstartxref\n9\n%%EOF\n"

    def test_clean_jpeg_and_overlay_recovery(self):
        clean_jpg = self._create_minimal_jpeg()
        res_clean = container.inspect_container_bytes(clean_jpg)
        self.assertEqual(res_clean["format"], "JPEG")
        self.assertEqual(res_clean["logical_end"], len(clean_jpg))
        self.assertEqual(res_clean["overlay_len"], 0)
        self.assertFalse(res_clean["is_steg_candidate"])

        # Append hidden ZIP payload
        hidden_zip = self._create_minimal_zip(comment=b"cicada_key")
        steg_jpg = clean_jpg + hidden_zip
        res_steg = container.inspect_container_bytes(steg_jpg)
        self.assertEqual(res_steg["format"], "JPEG")
        self.assertEqual(res_steg["logical_end"], len(clean_jpg))
        self.assertEqual(res_steg["overlay_len"], len(hidden_zip))
        self.assertEqual(res_steg["overlay_magic"], "ZIP")
        self.assertTrue(res_steg["is_steg_candidate"])

    def test_png_clean_overlay_and_ancillary_chunks(self):
        # PNG with ancillary tEXt chunk and private cUST chunk
        ancillary = [
            (b"tEXt", b"Comment\x00The primes are sacred"),
            (b"cUST", b"Secret payload metadata"),
        ]
        clean_png = self._create_minimal_png(ancillary_chunks=ancillary)
        res_clean = container.inspect_container_bytes(clean_png)
        self.assertEqual(res_clean["format"], "PNG")
        self.assertEqual(res_clean["logical_end"], len(clean_png))
        self.assertEqual(res_clean["overlay_len"], 0)
        types_found = [c["type"] for c in res_clean["ancillary_chunks"]]
        self.assertIn("tEXt", types_found)
        self.assertIn("cUST", types_found)

        # PNG with trailing bytes
        trailing = b"-----BEGIN PGP SIGNED MESSAGE-----\nKey ID: 7A35090F"
        steg_png = clean_png + trailing
        res_steg = container.inspect_container_bytes(steg_png)
        self.assertEqual(res_steg["logical_end"], len(clean_png))
        self.assertEqual(res_steg["overlay_len"], len(trailing))
        self.assertTrue(res_steg["has_pgp_in_overlay"])
        self.assertTrue(res_steg["is_steg_candidate"])

    def test_gif_and_zip_and_pdf(self):
        # GIF
        gif = self._create_minimal_gif()
        res_gif = container.inspect_container_bytes(gif + b"OVERLAY_BYTES")
        self.assertEqual(res_gif["format"], "GIF")
        self.assertEqual(res_gif["logical_end"], len(gif))
        self.assertEqual(res_gif["overlay_len"], len(b"OVERLAY_BYTES"))

        # ZIP
        zip_bytes = self._create_minimal_zip(comment=b"test_comment")
        res_zip = container.inspect_container_bytes(zip_bytes + b"EXTRA")
        self.assertEqual(res_zip["format"], "ZIP")
        self.assertEqual(res_zip["logical_end"], len(zip_bytes))
        self.assertEqual(res_zip["overlay_len"], len(b"EXTRA"))

        # PDF
        pdf_bytes = self._create_minimal_pdf()
        res_pdf = container.inspect_container_bytes(pdf_bytes + b"TRAILING")
        self.assertEqual(res_pdf["format"], "PDF")
        self.assertEqual(res_pdf["logical_end"], len(pdf_bytes))
        self.assertEqual(res_pdf["overlay_len"], len(b"TRAILING"))

    def test_benign_trailer_mpf_allow_list(self):
        # Construct JPEG with APP2 MPF marker segment
        mpf_data = b"MPF\x00\x00\x00\x00\x00"
        mpf_seg = b"\xFF\xE2" + struct.pack(">H", len(mpf_data) + 2) + mpf_data
        jpg = b"\xFF\xD8" + mpf_seg + b"\xFF\xD9" + b"TRAILING_MPF_STREAM"

        res = container.inspect_container_bytes(jpg)
        self.assertTrue(res["is_mpf"])
        self.assertTrue(res["is_benign_trailer"])
        self.assertFalse(res["is_steg_candidate"])

    def test_malformed_and_fuzzed_headers_never_crash(self):
        # Completely random bytes or truncated data
        fuzzed_inputs = [
            b"",
            b"\xFF\xD8\xFF",
            b"\x89PNG\r\n\x1a\n\x00\x00",
            b"GIF89a",
            b"\x50\x4B\x05\x06",
            b"%PDF-1.4 no eof marker anywhere",
            b"\x00" * 100,
        ]
        for data in fuzzed_inputs:
            res = container.inspect_container_bytes(data)
            self.assertIsInstance(res, dict)
            # Never raises exceptions, logical_end is either valid int or -1/0
            self.assertIn("logical_end", res)

    def test_polyglot_signature_scan(self):
        carrier = b"SOME_INITIAL_PADDING" + self._create_minimal_png() + b"MID_PADDING" + self._create_minimal_zip()
        hits = container.scan_polyglot_signatures(carrier)
        types = [h["type"] for h in hits]
        self.assertIn("PNG_IMAGE", types)
        self.assertIn("ZIP_ARCHIVE", types)


class TestProvenancePriorInRetrieval(unittest.TestCase):
    def test_relevance_boost_provenance_multipliers(self):
        doc = "Welcome pilgrims to the sacred primes and totients"
        query = "sacred primes"
        query_runes = []

        # 1. Verified official Cicada PGP
        meta_verified = {"sig_status": "verified_7A35090F", "is_pgp_signed": True}
        boost_verified = ask._calculate_relevance_boost(doc, meta_verified, query, query_runes)

        # 2. Unsigned chunk
        meta_unsigned = {"sig_status": "unsigned", "is_pgp_signed": False}
        boost_unsigned = ask._calculate_relevance_boost(doc, meta_unsigned, query, query_runes)

        # 3. Mismatch / unknown key
        meta_mismatch = {"sig_status": "mismatch", "is_pgp_signed": True}
        boost_mismatch = ask._calculate_relevance_boost(doc, meta_mismatch, query, query_runes)

        self.assertGreater(boost_verified, boost_unsigned)
        self.assertGreater(boost_unsigned, boost_mismatch)
        # Prior ratio should be 1.5 / 1.0 = 1.5 and 0.4 / 1.0 = 0.4
        self.assertAlmostEqual(boost_verified / boost_unsigned, 1.5, places=2)
        self.assertAlmostEqual(boost_mismatch / boost_unsigned, 0.4, places=2)


class TestLosslessSteganalysis(unittest.TestCase):
    def test_pov_chi_squared_detection(self):
        import random
        rng = random.Random(42)
        # Natural byte stream with independent bin fluctuations
        natural_bytes = bytes([rng.randint(0, 255) for _ in range(1500)])
        res_nat = container.pov_chi_squared_test(natural_bytes)
        self.assertFalse(res_nat["steg_detected"])
        self.assertGreater(res_nat["chi2_per_df"], 0.60)

        # Stego byte stream where adjacent pairs (2k, 2k+1) are strictly equalized by LSB embedding
        stego_bytes = bytearray()
        for k in range(128):
            stego_bytes.extend([2 * k] * 5 + [2 * k + 1] * 5)
        res_stego = container.pov_chi_squared_test(bytes(stego_bytes))
        self.assertTrue(res_stego["steg_detected"])
        self.assertLess(res_stego["chi2_per_df"], 0.25)

    def test_extract_lossless_pixels_png(self):
        # Create minimal 2x2 8-bit PNG
        ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 0, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
        ihdr_c = struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", ihdr_crc)

        scanlines = b"\x00\x10\x20\x00\x30\x40"  # 2 rows with filter 0
        idat_raw = zlib.compress(scanlines)
        idat_c = struct.pack(">I", len(idat_raw)) + b"IDAT" + idat_raw + struct.pack(">I", zlib.crc32(b"IDAT" + idat_raw))
        iend_c = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))

        png_data = b"\x89PNG\r\n\x1a\n" + ihdr_c + idat_c + iend_c
        extracted = container.extract_lossless_pixels(png_data)
        self.assertIsNotNone(extracted)
        px_bytes, w, h = extracted
        self.assertEqual((w, h), (2, 2))
        self.assertEqual(len(px_bytes), 4)

    def test_lsb_plane_autocorrelation_detection(self):
        import random
        rng = random.Random(42)
        # 1. Natural spatially correlated pixel plane (2D coherent autoregressive field)
        w, h = 30, 30
        natural_pixels = bytearray(w * h)
        for y in range(h):
            for x in range(w):
                if x == 0 and y == 0:
                    val = 120
                elif x == 0:
                    val = int(0.9 * natural_pixels[(y - 1) * w + x] + rng.randint(-3, 3))
                elif y == 0:
                    val = int(0.9 * natural_pixels[y * w + x - 1] + rng.randint(-3, 3))
                else:
                    val = int(0.48 * natural_pixels[(y - 1) * w + x] + 0.48 * natural_pixels[y * w + x - 1] + rng.randint(-2, 2))
                natural_pixels[y * w + x] = max(0, min(255, val))

        res_nat = container.lsb_plane_autocorrelation(bytes(natural_pixels), width=w, height=h)
        self.assertIn("r_horizontal", res_nat)
        self.assertIn("whitening_detected", res_nat)
        self.assertFalse(res_nat["whitening_detected"])
        self.assertGreater(res_nat["r_horizontal"], 0.05)

        # 2. Whitened stego plane: replaced with independent random bits
        stego_pixels = bytearray(natural_pixels)
        for i in range(len(stego_pixels)):
            stego_pixels[i] = (stego_pixels[i] & ~1) | rng.randint(0, 1)

        res_stego = container.lsb_plane_autocorrelation(bytes(stego_pixels), width=w, height=h)
        self.assertTrue(res_stego["whitening_detected"])
        self.assertLess(abs(res_stego["r_horizontal"]), 0.05)


if __name__ == "__main__":
    unittest.main()
