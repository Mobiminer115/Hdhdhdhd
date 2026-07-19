from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


class MachOParseError(ValueError):
    pass


_MAGIC_INFO: dict[bytes, tuple[str, bool, str]] = {
    b"\xfe\xed\xfa\xce": ("big", False, "mach-o-32-be"),
    b"\xce\xfa\xed\xfe": ("little", False, "mach-o-32-le"),
    b"\xfe\xed\xfa\xcf": ("big", True, "mach-o-64-be"),
    b"\xcf\xfa\xed\xfe": ("little", True, "mach-o-64-le"),
}
_FAT_MAGIC_INFO: dict[bytes, tuple[str, bool]] = {
    b"\xca\xfe\xba\xbe": ("big", False),
    b"\xbe\xba\xfe\xca": ("little", False),
    b"\xca\xfe\xba\xbf": ("big", True),
    b"\xbf\xba\xfe\xca": ("little", True),
}

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26


def _clean_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Section:
    segment_name: str
    name: str
    address: int
    size: int
    file_offset: int
    alignment: int
    flags: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment": self.segment_name,
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "file_offset": self.file_offset,
            "alignment": self.alignment,
            "flags": self.flags,
        }


@dataclass(frozen=True)
class Segment:
    name: str
    vm_address: int
    vm_size: int
    file_offset: int
    file_size: int
    max_protection: int
    initial_protection: int
    sections: tuple[Section, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "vm_address": self.vm_address,
            "vm_size": self.vm_size,
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "max_protection": self.max_protection,
            "initial_protection": self.initial_protection,
            "sections": [section.to_dict() for section in self.sections],
        }


@dataclass
class MachOImage:
    format: str
    endian: str
    is_64_bit: bool
    cpu_type: int
    cpu_subtype: int
    file_type: int
    command_count: int
    command_bytes: int
    flags: int
    segments: list[Segment] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)
    uuid: str | None = None
    code_signature: tuple[int, int] | None = None
    function_starts: tuple[int, int] | None = None
    symbol_table: tuple[int, int, int, int] | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def image_base(self) -> int:
        text_segments = [segment.vm_address for segment in self.segments if segment.name == "__TEXT"]
        return min(text_segments) if text_segments else 0

    def file_offset_to_vm(self, file_offset: int) -> int | None:
        for segment in self.segments:
            if segment.file_offset <= file_offset < segment.file_offset + segment.file_size:
                return segment.vm_address + (file_offset - segment.file_offset)
        return None

    def vm_to_file_offset(self, address: int) -> int | None:
        for segment in self.segments:
            if segment.vm_address <= address < segment.vm_address + segment.vm_size:
                delta = address - segment.vm_address
                if delta < segment.file_size:
                    return segment.file_offset + delta
        return None

    def vm_to_rva(self, address: int) -> int | None:
        if not self.image_base:
            return None
        return address - self.image_base

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "endian": self.endian,
            "is_64_bit": self.is_64_bit,
            "cpu_type": self.cpu_type,
            "cpu_subtype": self.cpu_subtype,
            "file_type": self.file_type,
            "command_count": self.command_count,
            "command_bytes": self.command_bytes,
            "flags": self.flags,
            "image_base": self.image_base,
            "segments": [segment.to_dict() for segment in self.segments],
            "dylibs": list(self.dylibs),
            "uuid": self.uuid,
            "code_signature": self.code_signature,
            "function_starts": self.function_starts,
            "symbol_table": self.symbol_table,
            "warnings": list(self.warnings),
        }


@dataclass
class FatMachO:
    endian: str
    is_64_bit_arch_table: bool
    slices: list[tuple[int, int, int, int, MachOImage | None]]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "fat-mach-o",
            "endian": self.endian,
            "is_64_bit_arch_table": self.is_64_bit_arch_table,
            "slices": [
                {
                    "cpu_type": cpu_type,
                    "cpu_subtype": cpu_subtype,
                    "offset": offset,
                    "size": size,
                    "image": image.to_dict() if image else None,
                }
                for cpu_type, cpu_subtype, offset, size, image in self.slices
            ],
            "warnings": list(self.warnings),
        }


def _unpack(data: bytes, endian: str, fmt: str, offset: int) -> tuple[Any, ...]:
    prefix = ">" if endian == "big" else "<"
    size = struct.calcsize(prefix + fmt)
    if offset < 0 or offset + size > len(data):
        raise MachOParseError("Mach-O load command is truncated")
    return struct.unpack_from(prefix + fmt, data, offset)


def _read_cstring(data: bytes, offset: int, limit: int | None = None) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end_limit = len(data) if limit is None else min(limit, len(data))
    end = data.find(b"\0", offset, end_limit)
    if end < 0:
        end = end_limit
    return data[offset:end].decode("utf-8", errors="replace")


def _parse_thin(data: bytes) -> MachOImage:
    if len(data) < 28:
        raise MachOParseError("Mach-O header is truncated")
    info = _MAGIC_INFO.get(data[:4])
    if info is None:
        raise MachOParseError("not a thin Mach-O image")
    endian, is_64, format_name = info
    header_fmt = "IIIIIII" + ("I" if is_64 else "")
    values = _unpack(data, endian, header_fmt, 0)
    _, cpu_type, cpu_subtype, file_type, command_count, command_bytes, flags = values[:7]
    image = MachOImage(
        format=format_name,
        endian=endian,
        is_64_bit=is_64,
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
        file_type=file_type,
        command_count=command_count,
        command_bytes=command_bytes,
        flags=flags,
    )
    command_offset = 32 if is_64 else 28
    command_end = command_offset + command_bytes
    if command_end > len(data):
        raise MachOParseError("Mach-O load command area is truncated")

    segment_command = LC_SEGMENT_64 if is_64 else LC_SEGMENT
    section_size = 80 if is_64 else 68
    for _ in range(command_count):
        if command_offset + 8 > command_end:
            raise MachOParseError("Mach-O command header is truncated")
        cmd, cmd_size = _unpack(data, endian, "II", command_offset)
        if cmd_size < 8 or command_offset + cmd_size > command_end:
            raise MachOParseError("invalid Mach-O load command size")

        if cmd == segment_command:
            expected_min = 72 if is_64 else 56
            if cmd_size < expected_min:
                raise MachOParseError("truncated segment command")
            if is_64:
                values = _unpack(data, endian, "II16sQQQQIIII", command_offset)
                _, _, raw_name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _ = values
                section_cursor = command_offset + 72
                sections: list[Section] = []
                for _section_index in range(nsects):
                    if section_cursor + section_size > command_offset + cmd_size:
                        raise MachOParseError("truncated 64-bit section")
                    section_values = _unpack(data, endian, "16s16sQQIIIIIIII", section_cursor)
                    (
                        section_name,
                        section_segment,
                        address,
                        size,
                        file_offset,
                        align,
                        _reloff,
                        _nreloc,
                        section_flags,
                        _reserved1,
                        _reserved2,
                        _reserved3,
                    ) = section_values
                    sections.append(
                        Section(
                            _clean_name(section_segment),
                            _clean_name(section_name),
                            address,
                            size,
                            file_offset,
                            align,
                            section_flags,
                        )
                    )
                    section_cursor += section_size
            else:
                values = _unpack(data, endian, "II16sIIIIIIII", command_offset)
                _, _, raw_name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _ = values
                section_cursor = command_offset + 56
                sections = []
                for _section_index in range(nsects):
                    if section_cursor + section_size > command_offset + cmd_size:
                        raise MachOParseError("truncated 32-bit section")
                    section_values = _unpack(data, endian, "16s16sIIIIIIIII", section_cursor)
                    (
                        section_name,
                        section_segment,
                        address,
                        size,
                        file_offset,
                        align,
                        _reloff,
                        _nreloc,
                        section_flags,
                        _reserved1,
                        _reserved2,
                    ) = section_values
                    sections.append(
                        Section(
                            _clean_name(section_segment),
                            _clean_name(section_name),
                            address,
                            size,
                            file_offset,
                            align,
                            section_flags,
                        )
                    )
                    section_cursor += section_size
            image.segments.append(
                Segment(
                    _clean_name(raw_name),
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    tuple(sections),
                )
            )
        elif cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB):
            name_offset = _unpack(data, endian, "I", command_offset + 8)[0]
            image.dylibs.append(_read_cstring(data, command_offset + name_offset, command_offset + cmd_size))
        elif cmd == LC_UUID and cmd_size >= 24:
            raw_uuid = data[command_offset + 8 : command_offset + 24]
            image.uuid = "-".join(
                (
                    raw_uuid[0:4].hex(),
                    raw_uuid[4:6].hex(),
                    raw_uuid[6:8].hex(),
                    raw_uuid[8:10].hex(),
                    raw_uuid[10:16].hex(),
                )
            )
        elif cmd == LC_CODE_SIGNATURE and cmd_size >= 16:
            data_offset, data_size = _unpack(data, endian, "II", command_offset + 8)
            image.code_signature = (data_offset, data_size)
        elif cmd == LC_FUNCTION_STARTS and cmd_size >= 16:
            data_offset, data_size = _unpack(data, endian, "II", command_offset + 8)
            image.function_starts = (data_offset, data_size)
        elif cmd == LC_SYMTAB and cmd_size >= 24:
            image.symbol_table = _unpack(data, endian, "IIII", command_offset + 8)

        command_offset += cmd_size

    if command_offset != command_end:
        image.warnings.append("load command cursor did not end at sizeofcmds")
    return image


def parse_macho(data: bytes) -> MachOImage | FatMachO:
    """Parse a thin or fat Mach-O image without executing it."""

    if data[:4] in _MAGIC_INFO:
        return _parse_thin(data)
    fat_info = _FAT_MAGIC_INFO.get(data[:4])
    if fat_info is None:
        raise MachOParseError("input is not Mach-O")
    endian, is_64_arch_table = fat_info
    if len(data) < 8:
        raise MachOParseError("fat Mach-O header is truncated")
    arch_count = _unpack(data, endian, "I", 4)[0]
    arch_size = 32 if is_64_arch_table else 20
    slices: list[tuple[int, int, int, int, MachOImage | None]] = []
    warnings: list[str] = []
    cursor = 8
    for _ in range(arch_count):
        if cursor + arch_size > len(data):
            raise MachOParseError("fat Mach-O architecture table is truncated")
        if is_64_arch_table:
            cpu_type, cpu_subtype, offset, size, _align, _reserved = _unpack(data, endian, "IIQQII", cursor)
        else:
            cpu_type, cpu_subtype, offset, size, _align = _unpack(data, endian, "IIIII", cursor)
        cursor += arch_size
        image: MachOImage | None = None
        if offset + size <= len(data):
            try:
                parsed = _parse_thin(data[offset : offset + size])
                if isinstance(parsed, MachOImage):
                    image = parsed
            except MachOParseError as exc:
                warnings.append(f"slice at 0x{offset:X}: {exc}")
        else:
            warnings.append(f"slice at 0x{offset:X} exceeds file size")
        slices.append((cpu_type, cpu_subtype, offset, size, image))
    return FatMachO(endian, is_64_arch_table, slices, warnings)
