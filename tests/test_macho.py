from __future__ import annotations

import struct

from il2cpp_lens.macho import MachOImage, parse_macho


def _thin_arm64_fixture() -> bytes:
    # A minimal 64-bit little-endian image with one __TEXT segment and one
    # __text section. It is a parser fixture, not an executable program.
    header_size = 32
    segment_size = 72 + 80
    command_bytes = segment_size
    data = bytearray(header_size + command_bytes + 16)
    struct.pack_into(
        "<IIIIIIII",
        data,
        0,
        0xFEEDFACF,
        0x0100000C,  # CPU_TYPE_ARM64
        0,
        2,  # MH_EXECUTE
        1,
        command_bytes,
        0,
        0,
    )
    cursor = header_size
    struct.pack_into(
        "<II16sQQQQIIII",
        data,
        cursor,
        0x19,
        segment_size,
        b"__TEXT\0\0\0\0\0\0\0\0\0\0",
        0x100000000,
        0x1000,
        0,
        len(data),
        7,
        5,
        1,
        0,
    )
    cursor += 72
    struct.pack_into(
        "<16s16sQQIIIIIIII",
        data,
        cursor,
        b"__text\0\0\0\0\0\0\0\0\0\0",
        b"__TEXT\0\0\0\0\0\0\0\0\0\0",
        0x1000000B8,
        16,
        header_size + command_bytes,
        2,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    return bytes(data)


def test_thin_macho_segments_and_address_mapping() -> None:
    image = parse_macho(_thin_arm64_fixture())
    assert isinstance(image, MachOImage)
    assert image.image_base == 0x100000000
    assert image.segments[0].name == "__TEXT"
    section = image.segments[0].sections[0]
    assert section.name == "__text"
    assert image.vm_to_file_offset(0x1000000B8) == section.file_offset
    assert image.file_offset_to_vm(section.file_offset) == 0x1000000B8
    assert image.vm_to_rva(0x1000000B8) == 0xB8
