from __future__ import annotations

import io
import struct
import zipfile

from il2cpp_lens.detect import METADATA_MAGIC, scan_bytes


def _minimal_metadata() -> bytes:
    # Enough of a v29 header to pass content detection. The actual parser tests
    # use a richer fixture in test_metadata.py.
    blob = bytearray(512)
    struct.pack_into("<II", blob, 0, METADATA_MAGIC, 29)
    struct.pack_into("<II", blob, 8, 0x100, 0)
    struct.pack_into("<II", blob, 16, 0x100, 0)
    struct.pack_into("<II", blob, 24, 0x100, 16)
    blob[0x100 : 0x110] = b"\0Test\0Player\0"
    return bytes(blob)


def test_detection_does_not_depend_on_filename() -> None:
    payload = b"prefix" + _minimal_metadata()
    candidates = scan_bytes(payload, label="renamed.bin")
    metadata = [candidate for candidate in candidates if candidate.kind == "il2cpp-metadata"]
    assert len(metadata) == 1
    assert metadata[0].offset == 6
    assert metadata[0].details["version"] == 29


def test_detection_scans_zip_entries_without_extracting() -> None:
    entry = _minimal_metadata()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("arbitrary-name.bin", entry)
    candidates = scan_bytes(buffer.getvalue(), label="package.any")
    metadata = [candidate for candidate in candidates if candidate.kind == "il2cpp-metadata"]
    assert len(metadata) == 1
    assert metadata[0].container.endswith("!arbitrary-name.bin")
