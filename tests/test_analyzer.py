"""Deterministic, harmless synthetic fixtures (no third-party binaries)."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from universal_decompiler.analyzer import analyze_file, report_text


def make_pe() -> bytes:
    data = bytearray(1024)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0)
    optional_start = 0x80 + 24
    struct.pack_into("<H", data, optional_start, 0x20B)
    struct.pack_into("<I", data, optional_start + 16, 0x1000)
    section = optional_start + 0xF0
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<I", data, section + 16, 16)
    struct.pack_into("<I", data, section + 20, 0x200)
    return bytes(data)


def make_elf() -> bytes:
    data = bytearray(128)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 24, 0x400080)
    return bytes(data)


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.p = Path(self.temp.name) / "sample.bin"

    def analyze(self, data: bytes):
        self.p.write_bytes(data)
        return analyze_file(self.p)

    def test_pe_machine_sections_hash_and_entrypoint(self):
        data = make_pe()
        r = self.analyze(data)
        self.assertEqual(r.file_format, "Windows Portable Executable (PE)")
        self.assertEqual(r.architecture, "x86-64")
        self.assertEqual(r.entry_point, "RVA 0x00001000")
        self.assertIn(".text", r.segments[1].label)
        self.assertEqual(r.sha256_hex, hashlib.sha256(data).hexdigest())
        self.assertIn(r.sha256_hex, report_text(r))

    def test_elf_architecture_and_entrypoint(self):
        r = self.analyze(make_elf())
        self.assertEqual(r.file_format, "ELF 64-bit executable/object")
        self.assertEqual(r.architecture, "ARM64")
        self.assertIn("400080", r.entry_point)

    def test_raw_unknown_does_not_guess_chip(self):
        r = self.analyze(b"just sample data" * 4)
        self.assertEqual(r.architecture, "Unknown")
        self.assertEqual(r.file_format, "Raw/unknown binary")
        self.assertTrue(r.warnings)

    def test_embedded_signature_is_only_candidate(self):
        r = self.analyze(b"random" + b"hsqs" + b"raw data")
        self.assertEqual(r.architecture, "Unknown")
        self.assertTrue(any("Signature candidate" in segment.details for segment in r.segments))

    def test_recognize_zip_and_gzip(self):
        self.assertEqual(self.analyze(b"PK\x03\x04x").file_format, "ZIP container")
        self.assertEqual(self.analyze(b"\x1f\x8bmore").file_format, "Gzip-compressed data")

    def test_malformed_pe_is_not_trusted(self):
        data = bytearray(80)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0xFFFF0000)
        r = self.analyze(bytes(data))
        self.assertEqual(r.file_format, "Raw/unknown binary")
        self.assertEqual(r.architecture, "Unknown")
        self.assertTrue(any("invalid" in item for item in r.warnings))

    def test_empty_file_rejected(self):
        self.p.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            analyze_file(self.p)

    def test_elf_truncated_rejected(self):
        r = self.analyze(b"\x7fELF")
        self.assertEqual(r.architecture, "Unknown")
        self.assertTrue(any("truncated" in item for item in r.warnings))


if __name__ == "__main__":
    unittest.main()
