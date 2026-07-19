from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Iterable

from .models import FileCandidate

METADATA_MAGIC = 0xFAB11BAF
METADATA_MAGIC_BYTES = struct.pack("<I", METADATA_MAGIC)

_MACHO_MAGICS: dict[bytes, str] = {
    b"\xfe\xed\xfa\xce": "mach-o-32-be",
    b"\xce\xfa\xed\xfe": "mach-o-32-le",
    b"\xfe\xed\xfa\xcf": "mach-o-64-be",
    b"\xcf\xfa\xed\xfe": "mach-o-64-le",
    b"\xca\xfe\xba\xbe": "fat-mach-o-32-be",
    b"\xbe\xba\xfe\xca": "fat-mach-o-32-le",
    b"\xca\xfe\xba\xbf": "fat-mach-o-64-be",
    b"\xbf\xba\xfe\xca": "fat-mach-o-64-le",
}
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_MAX_DEFAULT_BYTES = 512 * 1024 * 1024
_MAX_ZIP_ENTRY_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_DEPTH = 3


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _metadata_is_plausible(data: bytes, offset: int) -> bool:
    """Reject random occurrences of the four-byte magic value."""

    if offset < 0 or offset + 16 > len(data):
        return False
    if data[offset : offset + 4] != METADATA_MAGIC_BYTES:
        return False
    version = _u32(data, offset + 4)
    if version < 1 or version > 100:
        return False

    # The first two table pairs are string-literal and string-data ranges.
    # A real metadata file has ranges that fit inside the containing blob.
    for pair_offset in (8, 16):
        table_offset = _u32(data, offset + pair_offset)
        table_size = _u32(data, offset + pair_offset + 4)
        if table_offset > len(data) - offset:
            return False
        if table_size > len(data) - offset - table_offset:
            return False

    string_offset = _u32(data, offset + 24)
    string_size = _u32(data, offset + 28)
    if string_offset > len(data) - offset:
        return False
    if string_size > len(data) - offset - string_offset:
        return False
    return True


def _metadata_extent(data: bytes, offset: int) -> int:
    """Return a conservative extent from the header's known ranges."""

    extent = 8
    # Reading the first 40 pairs is safe for supported metadata headers; stop
    # as soon as the blob ends. Invalid ranges are simply ignored.
    cursor = offset + 8
    while cursor + 8 <= len(data) and cursor < offset + 512:
        rel_offset = _u32(data, cursor)
        size = _u32(data, cursor + 4)
        if rel_offset <= len(data) - offset and size <= len(data) - offset - rel_offset:
            extent = max(extent, rel_offset + size)
        cursor += 8
    return min(extent, len(data) - offset)


def _macho_details(data: bytes, offset: int) -> dict[str, str | int]:
    magic = data[offset : offset + 4]
    details: dict[str, str | int] = {"magic": magic.hex(), "format": _MACHO_MAGICS[magic]}
    if len(data) >= offset + 8 and not _MACHO_MAGICS[magic].startswith("fat-"):
        # cputype is endian-dependent. This is only a lightweight hint; the
        # full Mach-O parser belongs to the next milestone.
        endian = ">" if _MACHO_MAGICS[magic].endswith("-be") else "<"
        details["cpu_type"] = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
    return details


def scan_bytes(
    data: bytes,
    *,
    label: str = "<memory>",
    base_offset: int = 0,
    archive_depth: int = 0,
) -> list[FileCandidate]:
    """Scan arbitrary bytes using content signatures, never file names."""

    candidates: list[FileCandidate] = []
    seen: set[tuple[str, int]] = set()

    # A ZIP/IPA is a container, not the executable itself. Inspect its entries
    # first and avoid treating compressed/stored payload bytes in the central
    # directory as a second top-level binary candidate.
    if data[:4] in _ZIP_SIGNATURES and archive_depth < _MAX_ARCHIVE_DEPTH:
        try:
            import io

            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir() or info.file_size > _MAX_ZIP_ENTRY_BYTES:
                        continue
                    try:
                        entry = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    entry_label = f"{label}!{info.filename}"
                    candidates.extend(
                        scan_bytes(
                            entry,
                            label=entry_label,
                            base_offset=0,
                            archive_depth=archive_depth + 1,
                        )
                    )
            return candidates
        except (OSError, zipfile.BadZipFile):
            # A malformed archive may still contain a useful embedded blob;
            # fall through to the signature scan below.
            pass

    cursor = 0
    while True:
        found = data.find(METADATA_MAGIC_BYTES, cursor)
        if found < 0:
            break
        cursor = found + 1
        if not _metadata_is_plausible(data, found):
            continue
        key = ("metadata", found)
        if key in seen:
            continue
        seen.add(key)
        extent = _metadata_extent(data, found)
        candidates.append(
            FileCandidate(
                container=label,
                kind="il2cpp-metadata",
                offset=base_offset + found,
                size=extent,
                details={"version": _u32(data, found + 4)},
                # Keep the complete tail as the parser may need a table whose
                # header uses a count rather than a byte size. ``size`` above
                # is only the conservative reported extent.
                payload=data[found:],
            )
        )

    for magic, format_name in _MACHO_MAGICS.items():
        cursor = 0
        while True:
            found = data.find(magic, cursor)
            if found < 0:
                break
            cursor = found + 1
            key = ("mach-o", found)
            if key in seen:
                continue
            # Avoid classifying a random four-byte sequence as a Mach-O. A
            # complete header must at least contain cputype/cpusubtype.
            if found + 12 > len(data):
                continue
            seen.add(key)
            candidates.append(
                FileCandidate(
                    container=label,
                    kind="mach-o",
                    offset=base_offset + found,
                    size=len(data) - found,
                    details=_macho_details(data, found),
                    payload=data[found:],
                )
            )

    return candidates


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path


def scan_path(
    path: str | Path,
    *,
    max_bytes: int = _MAX_DEFAULT_BYTES,
) -> list[FileCandidate]:
    """Scan a file or directory recursively.

    The scanner intentionally does not filter on names such as
    ``global-metadata.dat`` or ``UnityFramework``.
    """

    root = Path(path)
    if root.is_dir():
        results: list[FileCandidate] = []
        for child in _iter_files(root):
            try:
                if child.stat().st_size > max_bytes:
                    continue
                results.extend(scan_bytes(child.read_bytes(), label=str(child)))
            except OSError:
                continue
        return results

    if not root.is_file():
        raise FileNotFoundError(str(root))
    if root.stat().st_size > max_bytes:
        raise ValueError(f"input is larger than the configured limit ({max_bytes} bytes)")
    return scan_bytes(root.read_bytes(), label=str(root))
