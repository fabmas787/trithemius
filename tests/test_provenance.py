"""
Unit tests for ciphers/provenance.py image provenance gate.
"""

import unittest
import os
import struct
import tempfile
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
CIPHERS_DIR = os.path.join(BASE_DIR, "ciphers")
if CIPHERS_DIR not in sys.path:
    sys.path.insert(0, CIPHERS_DIR)

from provenance import inspect_jpeg_structure, provenance_gate


def create_mock_jpeg(width=2400, height=3600, dpi=400, with_artifex=True) -> bytes:
    """Create a minimal mock JPEG byte stream with JFIF and SOF0 segments."""
    buf = bytearray()
    # SOI
    buf += b"\xFF\xD8"

    # APP0: JFIF (len=16)
    # len=16 includes length field (2 bytes) + identifier (5 bytes) + version (2 bytes) + units (1) + xdens (2) + ydens (2) + thumb (2)
    jfif_payload = b"JFIF\x00\x01\x01\x01" + struct.pack(">HH", dpi, dpi) + b"\x00\x00"
    app0_len = len(jfif_payload) + 2
    buf += b"\xFF\xE0" + struct.pack(">H", app0_len) + jfif_payload

    # APP2: ICC Profile
    if with_artifex:
        icc_payload = b"ICC_PROFILE\x00\x01\x01ICC data containing Artifex Software 2011 tag\x00"
        app2_len = len(icc_payload) + 2
        buf += b"\xFF\xE2" + struct.pack(">H", app2_len) + icc_payload

    # SOF0 (Baseline DCT)
    # payload: precision (1) + height (2) + width (2) + components (1) + component spec (3)
    sof_payload = b"\x08" + struct.pack(">HH", height, width) + b"\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sof_len = len(sof_payload) + 2
    buf += b"\xFF\xC0" + struct.pack(">H", sof_len) + sof_payload

    # EOI
    buf += b"\xFF\xD9"
    return bytes(buf)


class TestProvenanceGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pristine_carrier_validation(self):
        data = create_mock_jpeg(width=2400, height=3600, dpi=400, with_artifex=True)
        path = os.path.join(self.temp_dir.name, "pristine.jpg")
        with open(path, "wb") as f:
            f.write(data)

        passed, details = provenance_gate(path)
        self.assertTrue(passed)
        self.assertTrue(details["is_pristine_carrier"])
        self.assertTrue(details["is_canonical_dims"])
        self.assertTrue(details["is_canonical_dpi"])
        self.assertTrue(details["has_artifex_icc"])
        self.assertEqual(details["width"], 2400)
        self.assertEqual(details["height"], 3600)
        self.assertEqual(details["density_dpi"], (400, 400))
        self.assertEqual(len(details["flags"]), 0)

    def test_rescaled_image_rejection(self):
        # 1200x1800 (rescaled 50%)
        data = create_mock_jpeg(width=1200, height=1800, dpi=400, with_artifex=True)
        path = os.path.join(self.temp_dir.name, "rescaled.jpg")
        with open(path, "wb") as f:
            f.write(data)

        passed, details = provenance_gate(path)
        self.assertFalse(passed)
        self.assertFalse(details["is_canonical_dims"])
        self.assertTrue(any("Non-canonical dimensions" in fl for fl in details["flags"]))

    def test_missing_icc_rejection(self):
        data = create_mock_jpeg(width=2400, height=3600, dpi=400, with_artifex=False)
        path = os.path.join(self.temp_dir.name, "no_icc.jpg")
        with open(path, "wb") as f:
            f.write(data)

        passed, details = provenance_gate(path)
        self.assertFalse(passed)
        self.assertFalse(details["has_artifex_icc"])
        self.assertTrue(any("Missing Artifex" in fl for fl in details["flags"]))

    def test_non_jpeg_handling(self):
        path = os.path.join(self.temp_dir.name, "random.txt")
        with open(path, "wb") as f:
            f.write(b"NOT A JPEG AT ALL")

        passed, details = provenance_gate(path)
        self.assertFalse(passed)
        self.assertFalse(details["is_jpeg"])


if __name__ == "__main__":
    unittest.main()
