"""Offline, read-only identification of PE, ELF and common firmware signatures.

This does not execute or decompile an input file. All size/offset data is validated.
Unknown raw binary is never assigned an architecture by guesswork.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
import struct
from typing import BinaryIO, Callable

SCAN_WINDOW = 4 * 1024 * 1024
HEX_PREVIEW_BYTES = 256
MAX_SECTIONS = 96

PE_MACHINES = {
    0x014C: "x86 (32-bit)", 0x8664: "x86-64", 0x01C0: "ARM",
    0x01C2: "ARM Thumb", 0x01C4: "ARM Thumb-2", 0xAA64: "ARM64",
    0x5032: "RISC-V 32", 0x5064: "RISC-V 64", 0x5128: "RISC-V 128",
}
ELF_MACHINES = {
    3: "x86 (32-bit)", 8: "MIPS", 20: "PowerPC", 21: "PowerPC 64",
    40: "ARM", 62: "x86-64", 183: "ARM64", 243: "RISC-V",
}
SIGNATURES = (
    (b"hsqs", "SquashFS filesystem (little-endian)"),
    (b"sqsh", "SquashFS filesystem (big-endian)"),
    (b"UBI#", "UBI erase-count header"),
    (b"\x7fELF", "Embedded ELF executable"),
    (b"\x27\x05\x19\x56", "U-Boot uImage header"),
)


@dataclass
class Segment:
    offset: int
    size: int | None
    label: str
    details: str = ""

    @property
    def offset_hex(self) -> str:
        return f"0x{self.offset:08X}"


@dataclass
class AnalysisReport:
    filename: str
    size_bytes: int
    sha256_hex: str
    file_format: str
    architecture: str
    endian: str
    confidence: str
    entry_point: str = "Unknown"
    segments: list[Segment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    hex_preview: str = ""
    scan_window_bytes: int = SCAN_WINDOW

    def as_dict(self) -> dict:
        return asdict(self)


def _unpack(data: bytes, offset: int, format_code: str):
    length = struct.calcsize(format_code)
    if offset < 0 or offset + length > len(data):
        raise ValueError("Truncated or out-of-range binary header")
    return struct.unpack_from(format_code, data, offset)[0]


def _hash_stream(stream: BinaryIO, progress: Callable[[str], None] | None = None) -> str:
    digest = sha256()
    stream.seek(0)
    chunks = 0
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
        chunks += 1
        if progress and chunks % 4 == 0:
            progress("hashing")
    return digest.hexdigest()


def _hex_preview(data: bytes) -> str:
    rows = []
    for off in range(0, min(len(data), HEX_PREVIEW_BYTES), 16):
        chunk = data[off:off + 16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{off:08X}  {hex_bytes:<47}  |{ascii_text}|")
    return "\n".join(rows)


def _identify_pe(stream: BinaryIO, sample: bytes, report: AnalysisReport) -> bool:
    if not sample.startswith(b"MZ") or len(sample) < 64:
        return False
    pe_offset = _unpack(sample, 0x3C, "<I")
    if pe_offset + 24 > report.size_bytes or pe_offset > 64 * 1024 * 1024:
        report.warnings.append("DOS signature found, but PE header offset is invalid/out of bounds.")
        return False
    stream.seek(pe_offset)
    header = stream.read(24)
    if len(header) != 24 or header[:4] != b"PE\0\0":
        report.warnings.append("DOS signature found without a valid PE header.")
        return False

    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", header, 4)
    report.file_format = "Windows Portable Executable (PE)"
    report.architecture = PE_MACHINES.get(machine, f"Unknown PE machine (0x{machine:04X})")
    report.endian = "Little-endian"
    report.confidence = "High (validated PE signature)"
    report.segments.append(Segment(0, pe_offset + 24, "PE headers"))

    optional_start = pe_offset + 24
    if optional_size >= 20 and optional_start + optional_size <= report.size_bytes:
        stream.seek(optional_start)
        optional = stream.read(optional_size)
        magic = _unpack(optional, 0, "<H")
        if magic in (0x10B, 0x20B):
            ep_rva = _unpack(optional, 16, "<I")
            report.entry_point = f"RVA 0x{ep_rva:08X}"
        else:
            report.warnings.append("Unrecognized PE optional header magic.")
    else:
        report.warnings.append("PE optional header missing or truncated.")

    table_start = optional_start + optional_size
    if section_count > MAX_SECTIONS:
        report.warnings.append(f"PE advertises {section_count} sections; showing at most {MAX_SECTIONS}.")
    for i in range(min(section_count, MAX_SECTIONS)):
        if table_start + (i + 1) * 40 > report.size_bytes:
            report.warnings.append("PE section table truncated.")
            break
        stream.seek(table_start + i * 40)
        record = stream.read(40)
        if len(record) != 40:
            report.warnings.append("PE section table truncated.")
            break
        name = record[:8].split(b"\0", 1)[0].decode("ascii", errors="replace") or f"section_{i}"
        raw_size = _unpack(record, 16, "<I")
        raw_offset = _unpack(record, 20, "<I")
        if raw_offset + raw_size > report.size_bytes:
            report.warnings.append(f"Section {name} extends beyond file; skipping invalid range.")
            continue
        report.segments.append(Segment(raw_offset, raw_size, f"PE section: {name}"))
    return True


def _identify_elf(sample: bytes, report: AnalysisReport) -> bool:
    if not sample.startswith(b"\x7fELF"):
        return False
    if len(sample) < 52 or sample[4] not in (1, 2) or sample[5] not in (1, 2):
        report.warnings.append("ELF magic detected, but identification/header is truncated or invalid.")
        return False
    endian = "<" if sample[5] == 1 else ">"
    bits = 32 if sample[4] == 1 else 64
    machine = _unpack(sample, 18, endian + "H")
    entry = _unpack(sample, 24, endian + ("I" if bits == 32 else "Q"))
    report.file_format = f"ELF {bits}-bit executable/object"
    report.architecture = ELF_MACHINES.get(machine, f"Unknown ELF machine ({machine})")
    report.endian = "Little-endian" if endian == "<" else "Big-endian"
    report.confidence = "High (validated ELF identification)"
    report.entry_point = f"0x{entry:0{bits // 4}X}"
    report.segments.append(Segment(0, 52 if bits == 32 else 64, "ELF header"))
    return True


def _identify_container(sample: bytes, report: AnalysisReport) -> None:
    if sample.startswith(b"PK\x03\x04"):
        report.file_format = "ZIP container"
        report.confidence = "High (container signature)"
        report.segments.append(Segment(0, None, "ZIP archive"))
    elif sample.startswith(b"\x1f\x8b"):
        report.file_format = "Gzip-compressed data"
        report.confidence = "High (compression signature)"
        report.segments.append(Segment(0, None, "Gzip stream"))
    elif sample.startswith(b"hsqs") or sample.startswith(b"sqsh"):
        report.file_format = "SquashFS filesystem"
        report.confidence = "High (filesystem signature)"
        report.segments.append(Segment(0, None, "SquashFS image"))
    elif sample.startswith(b"\x27\x05\x19\x56"):
        report.file_format = "U-Boot uImage"
        report.confidence = "High (image signature)"
        report.segments.append(Segment(0, None, "U-Boot header"))
    else:
        report.warnings.append("Raw/unknown binary: architecture cannot be determined reliably from this scan.")


def analyze_file(path: str | Path, *, progress: Callable[[str], None] | None = None) -> AnalysisReport:
    """Analyze untrusted bytes without executing, extracting, or modifying the input."""
    if progress:
        progress("validating_file")
    input_path = Path(path)
    if not input_path.is_file():
        raise ValueError("Select a readable file (not a directory).")
    size = input_path.stat().st_size
    if not size:
        raise ValueError("The selected file is empty.")

    with input_path.open("rb") as stream:
        sample = stream.read(min(size, SCAN_WINDOW))
        if progress:
            progress("inspecting_headers")
        report = AnalysisReport(
            filename=input_path.name,
            size_bytes=size,
            sha256_hex="",
            file_format="Raw/unknown binary",
            architecture="Unknown",
            endian="Unknown",
            confidence="Undetermined",
            hex_preview=_hex_preview(sample),
            scan_window_bytes=len(sample),
        )
        # PE sections live at a file offset, not necessarily within the initial sample.
        if not _identify_pe(stream, sample, report) and not _identify_elf(sample, report):
            _identify_container(sample, report)
        for magic, description in SIGNATURES:
            start = 0
            matches = 0
            while matches < 8:
                idx = sample.find(magic, start)
                if idx < 0:
                    break
                if idx != 0 or not any(s.offset == 0 and description.lower() in s.label.lower() for s in report.segments):
                    report.segments.append(Segment(idx, None, description, "Signature candidate; not proof of valid content"))
                start = idx + len(magic)
                matches += 1
        if progress:
            progress("hashing")
        if size > SCAN_WINDOW:
            report.warnings.append(f"Embedded-signature search limited to first {SCAN_WINDOW:,} bytes; this is not a whole-image partition map.")
        report.sha256_hex = _hash_stream(stream, progress)
    return report


def report_text(report: AnalysisReport) -> str:
    lines = [
        "UNIVERSAL DECOMPILER — STAGE 1 ANALYSIS (READ-ONLY)",
        "", f"File: {report.filename}", f"Size: {report.size_bytes:,} bytes",
        f"SHA-256: {report.sha256_hex}", f"Format: {report.file_format}",
        f"Architecture: {report.architecture}", f"Endianness: {report.endian}",
        f"Entry point: {report.entry_point}", f"Confidence: {report.confidence}",
        "", "FOUND SECTIONS / SIGNATURE CANDIDATES:",
    ]
    for item in report.segments:
        size = "unknown" if item.size is None else f"{item.size:,} B"
        lines.append(f"  {item.offset_hex} | {size:>12} | {item.label} | {item.details}")
    if not report.segments:
        lines.append("  (none identified)")
    lines.extend(["", "WARNINGS:"] + ([f"  - {w}" for w in report.warnings] or ["  (none)"]))
    lines.extend(["", "HEX PREVIEW (first 256 bytes):", report.hex_preview, ""])
    return "\n".join(lines)
