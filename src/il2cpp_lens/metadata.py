from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from .models import (
    FieldRecord,
    ImageRecord,
    MetadataHeader,
    MethodRecord,
    TableRange,
    TypeRecord,
)

METADATA_MAGIC = 0xFAB11BAF


class MetadataParseError(ValueError):
    pass


@dataclass(frozen=True)
class _HeaderField:
    name: str
    minimum: float = 0
    maximum: float = 10_000
    unit: str = "bytes"

    def enabled(self, version: float) -> bool:
        return self.minimum <= version <= self.maximum


# This follows the public Il2CppGlobalMetadataHeader layout. All entries are
# four-byte values; the two values in each pair are an offset and a size/count.
_HEADER_FIELDS: tuple[_HeaderField, ...] = (
    _HeaderField("string_literals"),
    _HeaderField("string_literal_data"),
    _HeaderField("strings"),
    _HeaderField("events"),
    _HeaderField("properties"),
    _HeaderField("methods"),
    _HeaderField("parameter_default_values"),
    _HeaderField("field_default_values"),
    _HeaderField("field_and_parameter_default_value_data"),
    _HeaderField("field_marshaled_sizes"),
    _HeaderField("parameters"),
    _HeaderField("fields"),
    _HeaderField("generic_parameters"),
    _HeaderField("generic_parameter_constraints"),
    _HeaderField("generic_containers"),
    _HeaderField("nested_types"),
    _HeaderField("interfaces"),
    _HeaderField("vtable_methods"),
    _HeaderField("interface_offsets"),
    _HeaderField("type_definitions"),
    _HeaderField("rgctx_entries", maximum=24.1, unit="records"),
    _HeaderField("images"),
    _HeaderField("assemblies"),
    _HeaderField("metadata_usage_lists", minimum=19, maximum=24.5, unit="records"),
    _HeaderField("metadata_usage_pairs", minimum=19, maximum=24.5, unit="records"),
    _HeaderField("field_refs", minimum=19),
    _HeaderField("referenced_assemblies", minimum=20),
    _HeaderField("attributes_info", minimum=21, maximum=27.2, unit="records"),
    _HeaderField("attribute_types", minimum=21, maximum=27.2),
    _HeaderField("attribute_data", minimum=29),
    _HeaderField("attribute_data_ranges", minimum=29),
    _HeaderField("unresolved_virtual_call_parameter_types", minimum=22),
    _HeaderField("unresolved_virtual_call_parameter_ranges", minimum=22),
    _HeaderField("windows_runtime_type_names", minimum=23),
    _HeaderField("windows_runtime_strings", minimum=27),
    _HeaderField("exported_type_definitions", minimum=24),
)


def _profile_candidates(raw_version: int) -> tuple[float, ...]:
    if raw_version == 24:
        # Unity shipped several incompatible 24.x layouts while retaining the
        # raw header version 24. Try each known profile and select the one with
        # the most internally consistent ranges.
        return (24.0, 24.1, 24.2, 24.4, 24.5)
    return (float(raw_version),)


def _read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise MetadataParseError("metadata header is truncated")
    return struct.unpack_from("<I", data, offset)[0]


def _read_i32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise MetadataParseError("metadata header is truncated")
    return struct.unpack_from("<i", data, offset)[0]


def _parse_header_profile(data: bytes, version: float) -> MetadataHeader:
    if len(data) < 8:
        raise MetadataParseError("metadata is shorter than its magic and version")
    magic = _read_u32(data, 0)
    raw_version = _read_i32(data, 4)
    if magic != METADATA_MAGIC:
        raise MetadataParseError(f"bad metadata magic 0x{magic:08X}")
    if raw_version < 1 or raw_version > 100:
        raise MetadataParseError(f"implausible metadata version {raw_version}")

    cursor = 8
    tables: dict[str, TableRange] = {}
    for field in _HEADER_FIELDS:
        if not field.enabled(version):
            continue
        if cursor + 8 > len(data):
            raise MetadataParseError("metadata header ended before all table ranges")
        offset = _read_u32(data, cursor)
        size = _read_u32(data, cursor + 4)
        cursor += 8
        tables[field.name] = TableRange(field.name, offset, size, field.unit)

    # Score is calculated by the caller; keep parsing strict enough to reject
    # false positives but allow empty optional tables.
    for table in tables.values():
        if table.offset > len(data):
            raise MetadataParseError(
                f"table {table.name} lies outside the metadata blob "
                f"(offset={table.offset}, size={table.size}, file={len(data)})"
            )
        if table.unit == "bytes" and table.size > len(data) - table.offset:
            raise MetadataParseError(
                f"table {table.name} lies outside the metadata blob "
                f"(offset={table.offset}, size={table.size}, file={len(data)})"
            )

    return MetadataHeader(
        magic=magic,
        version=raw_version,
        effective_version=str(version).rstrip("0").rstrip("."),
        header_size=cursor,
        tables=tables,
    )


def _header_score(header: MetadataHeader, data_len: int) -> int:
    score = 0
    for name in ("strings", "type_definitions", "fields", "methods", "images"):
        table = header.tables.get(name)
        if table is None:
            continue
        if table.offset == 0 and table.size == 0:
            score += 1
        elif table.offset >= header.header_size and (
            table.unit != "bytes" or table.end <= data_len
        ):
            score += 4
        else:
            score -= 5
    if header.header_size <= data_len:
        score += 2
    return score


def parse_header(data: bytes) -> MetadataHeader:
    raw_version = _read_i32(data, 4) if len(data) >= 8 else -1
    candidates: list[tuple[int, MetadataHeader]] = []
    errors: list[str] = []
    for profile in _profile_candidates(raw_version):
        try:
            header = _parse_header_profile(data, profile)
        except MetadataParseError as exc:
            errors.append(str(exc))
            continue
        candidates.append((_header_score(header, len(data)), header))
    if not candidates:
        detail = errors[-1] if errors else "unknown header error"
        raise MetadataParseError(detail)
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return candidates[0][1]


def _layout(version: float, kind: str) -> tuple[tuple[str, str], ...]:
    """Return a version-aware record layout.

    Formats use little-endian struct codes without a leading ``<``. The
    metadata format stores these records packed, so native alignment is not
    used.
    """

    if kind == "type":
        fields: list[tuple[str, str]] = [
            ("name_index", "I"),
            ("namespace_index", "I"),
        ]
        if version <= 24:
            fields.append(("custom_attribute_index", "i"))
        fields.append(("byval_type_index", "i"))
        if version <= 24.5:
            fields.append(("byref_type_index", "i"))
        fields.extend(
            [
                ("declaring_type_index", "i"),
                ("parent_index", "i"),
                ("element_type_index", "i"),
            ]
        )
        if version <= 24.1:
            fields.extend([("rgctx_start_index", "i"), ("rgctx_count", "i")])
        fields.append(("generic_container_index", "i"))
        if version <= 22:
            fields.extend(
                [
                    ("delegate_wrapper_from_managed_to_native_index", "i"),
                    ("marshaling_functions_index", "i"),
                ]
            )
        if 21 <= version <= 22:
            fields.extend([("ccw_function_index", "i"), ("guid_index", "i")])
        fields.extend(
            [
                ("flags", "I"),
                ("field_start", "i"),
                ("method_start", "i"),
                ("event_start", "i"),
                ("property_start", "i"),
                ("nested_types_start", "i"),
                ("interfaces_start", "i"),
                ("vtable_start", "i"),
                ("interface_offsets_start", "i"),
                ("method_count", "H"),
                ("property_count", "H"),
                ("field_count", "H"),
                ("event_count", "H"),
                ("nested_type_count", "H"),
                ("vtable_count", "H"),
                ("interfaces_count", "H"),
                ("interface_offsets_count", "H"),
                ("bitfield", "I"),
            ]
        )
        if version >= 19:
            fields.append(("token", "I"))
        return tuple(fields)

    if kind == "field":
        fields = [("name_index", "I"), ("type_index", "i")]
        if version <= 24:
            fields.append(("custom_attribute_index", "i"))
        if version >= 19:
            fields.append(("token", "I"))
        return tuple(fields)

    if kind == "method":
        fields = [
            ("name_index", "I"),
            ("declaring_type", "i"),
            ("return_type", "i"),
        ]
        if version >= 31:
            fields.append(("return_parameter_token", "i"))
        fields.append(("parameter_start", "i"))
        if version <= 24:
            fields.append(("custom_attribute_index", "i"))
        fields.append(("generic_container_index", "i"))
        if version <= 24.1:
            fields.extend(
                [
                    ("method_index", "i"),
                    ("invoker_index", "i"),
                    ("delegate_wrapper_index", "i"),
                    ("rgctx_start_index", "i"),
                    ("rgctx_count", "i"),
                ]
            )
        fields.extend(
            [
                ("token", "I"),
                ("flags", "H"),
                ("iflags", "H"),
                ("slot", "H"),
                ("parameter_count", "H"),
            ]
        )
        return tuple(fields)

    if kind == "image":
        fields = [
            ("name_index", "I"),
            ("assembly_index", "i"),
            ("type_start", "i"),
            ("type_count", "I"),
        ]
        if version >= 24:
            fields.extend([("exported_type_start", "i"), ("exported_type_count", "I")])
        fields.append(("entry_point_index", "i"))
        if version >= 19:
            fields.append(("token", "I"))
        if version >= 24.1:
            fields.extend([("custom_attribute_start", "i"), ("custom_attribute_count", "I")])
        return tuple(fields)

    raise ValueError(f"unknown metadata record kind: {kind}")


def _layout_size(layout: Iterable[tuple[str, str]]) -> int:
    return struct.calcsize("<" + "".join(fmt for _, fmt in layout))


def _read_record(data: bytes, offset: int, layout: tuple[tuple[str, str], ...]) -> dict[str, int]:
    size = _layout_size(layout)
    if offset < 0 or offset + size > len(data):
        raise MetadataParseError("metadata record is truncated")
    values = struct.unpack_from("<" + "".join(fmt for _, fmt in layout), data, offset)
    return {name: int(value) for (name, _), value in zip(layout, values)}


class MetadataReader:
    """Read standard, unencrypted IL2CPP global metadata."""

    def __init__(self, data: bytes, *, source: str = "") -> None:
        self.data = data
        self.source = source
        self.header = parse_header(data)
        self.version_profile = float(self.header.effective_version or self.header.version)
        self.warnings: list[str] = []
        self._string_cache: dict[int, str] = {}
        self.types = self._read_types()
        self.fields = self._read_fields()
        self.methods = self._read_methods()
        self.images = self._read_images()
        self._attach_owners()

    def _table(self, name: str) -> TableRange | None:
        return self.header.tables.get(name)

    def _read_string_at(self, index: int) -> str:
        table = self._table("strings")
        if table is None or index < 0 or index >= table.size:
            return f"<string#{index}>"
        absolute = table.offset + index
        end = self.data.find(b"\0", absolute, table.end)
        if end < 0:
            end = table.end
        return self.data[absolute:end].decode("utf-8", errors="replace")

    def string(self, index: int) -> str:
        if index not in self._string_cache:
            self._string_cache[index] = self._read_string_at(index)
        return self._string_cache[index]

    def _read_table_records(self, table_name: str, kind: str) -> list[tuple[int, dict[str, int], int]]:
        table = self._table(table_name)
        if table is None or table.size == 0:
            return []
        layout = _layout(self.version_profile, kind)
        record_size = _layout_size(layout)
        if record_size <= 0:
            return []
        if table.size % record_size:
            self.warnings.append(
                f"{table_name} size {table.size} is not divisible by record size {record_size}"
            )
        count = table.size // record_size
        # Avoid pathological allocations from corrupted input.
        if count > 2_000_000:
            raise MetadataParseError(f"{table_name} contains an unreasonable record count: {count}")
        records: list[tuple[int, dict[str, int], int]] = []
        for index in range(count):
            offset = table.offset + index * record_size
            records.append((index, _read_record(self.data, offset, layout), record_size))
        return records

    def _read_types(self) -> list[TypeRecord]:
        result: list[TypeRecord] = []
        for index, raw, size in self._read_table_records("type_definitions", "type"):
            result.append(
                TypeRecord(
                    index=index,
                    name=self.string(raw.get("name_index", -1)),
                    namespace=self.string(raw.get("namespace_index", -1)),
                    name_index=raw.get("name_index", -1),
                    namespace_index=raw.get("namespace_index", -1),
                    metadata_offset=self._table("type_definitions").offset + index * size,  # type: ignore[union-attr]
                    metadata_size=size,
                    field_start=raw.get("field_start", -1),
                    field_count=raw.get("field_count", 0),
                    method_start=raw.get("method_start", -1),
                    method_count=raw.get("method_count", 0),
                    flags=raw.get("flags", 0),
                    token=raw.get("token", 0),
                )
            )
        return result

    def _read_fields(self) -> list[FieldRecord]:
        result: list[FieldRecord] = []
        table = self._table("fields")
        if table is None:
            return result
        for index, raw, size in self._read_table_records("fields", "field"):
            result.append(
                FieldRecord(
                    index=index,
                    name=self.string(raw.get("name_index", -1)),
                    name_index=raw.get("name_index", -1),
                    type_index=raw.get("type_index", -1),
                    token=raw.get("token", 0),
                    metadata_offset=table.offset + index * size,
                    metadata_size=size,
                )
            )
        return result

    def _read_methods(self) -> list[MethodRecord]:
        result: list[MethodRecord] = []
        table = self._table("methods")
        if table is None:
            return result
        for index, raw, size in self._read_table_records("methods", "method"):
            result.append(
                MethodRecord(
                    index=index,
                    name=self.string(raw.get("name_index", -1)),
                    name_index=raw.get("name_index", -1),
                    declaring_type=raw.get("declaring_type", -1),
                    return_type=raw.get("return_type", -1),
                    parameter_start=raw.get("parameter_start", -1),
                    parameter_count=raw.get("parameter_count", 0),
                    token=raw.get("token", 0),
                    metadata_offset=table.offset + index * size,
                    metadata_size=size,
                )
            )
        return result

    def _read_images(self) -> list[ImageRecord]:
        result: list[ImageRecord] = []
        table = self._table("images")
        if table is None:
            return result
        for index, raw, size in self._read_table_records("images", "image"):
            result.append(
                ImageRecord(
                    index=index,
                    name=self.string(raw.get("name_index", -1)),
                    name_index=raw.get("name_index", -1),
                    type_start=raw.get("type_start", -1),
                    type_count=raw.get("type_count", 0),
                    metadata_offset=table.offset + index * size,
                    metadata_size=size,
                )
            )
        return result

    def _attach_owners(self) -> None:
        for type_record in self.types:
            field_end = type_record.field_start + type_record.field_count
            if type_record.field_start < 0 or field_end < type_record.field_start or field_end > len(self.fields):
                self.warnings.append(
                    f"type {type_record.full_name} has an invalid field range "
                    f"{type_record.field_start}:{field_end}"
                )
            else:
                field_slice = self.fields[type_record.field_start : field_end]
            for field in field_slice if type_record.field_start >= 0 and field_end <= len(self.fields) else []:
                # Frozen records make accidental mutation impossible; replace
                # the list item with an owner-aware copy.
                self.fields[field.index] = FieldRecord(**{**field.__dict__, "owner": type_record.full_name})
            method_end = type_record.method_start + type_record.method_count
            if type_record.method_start < 0 or method_end < type_record.method_start or method_end > len(self.methods):
                self.warnings.append(
                    f"type {type_record.full_name} has an invalid method range "
                    f"{type_record.method_start}:{method_end}"
                )
            else:
                method_slice = self.methods[type_record.method_start : method_end]
            for method in method_slice if type_record.method_start >= 0 and method_end <= len(self.methods) else []:
                self.methods[method.index] = MethodRecord(**{**method.__dict__, "owner": type_record.full_name})

    def dump_text(self, *, max_types: int | None = None) -> str:
        lines = [
            f"IL2CPP metadata version {self.header.version}"
            f" (profile {self.header.effective_version or self.header.version})",
            f"Header size: 0x{self.header.header_size:X}",
            f"Types: {len(self.types)}  Fields: {len(self.fields)}  Methods: {len(self.methods)}",
        ]
        selected = self.types if max_types is None else self.types[:max_types]
        for type_record in selected:
            lines.append("")
            lines.append(f"class {type_record.full_name}")
            field_end = type_record.field_start + type_record.field_count
            field_slice = (
                self.fields[type_record.field_start : field_end]
                if 0 <= type_record.field_start <= field_end <= len(self.fields)
                else []
            )
            for field in field_slice:
                lines.append(
                    f"  {field.owner}.{field.name} : metadata+0x{field.metadata_offset:X}"
                )
            method_end = type_record.method_start + type_record.method_count
            method_slice = (
                self.methods[type_record.method_start : method_end]
                if 0 <= type_record.method_start <= method_end <= len(self.methods)
                else []
            )
            for method in method_slice:
                lines.append(
                    f"  {method.owner}.{method.name}() : metadata+0x{method.metadata_offset:X}"
                )
        if self.warnings:
            lines.append("")
            lines.append("Warnings:")
            lines.extend(f"- {warning}" for warning in self.warnings)
        return "\n".join(lines)

    def search(self, query: str) -> list[dict[str, object]]:
        """Find resolved symbols by name or qualified name."""

        needle = query.casefold()
        results: list[dict[str, object]] = []
        for record in self.types:
            if needle in record.full_name.casefold():
                results.append({"kind": "type", **record.to_dict()})
        for record in self.fields:
            qualified = record.to_dict()["qualified_name"]
            if needle in str(qualified).casefold() or needle in record.name.casefold():
                results.append({"kind": "field", **record.to_dict()})
        for record in self.methods:
            qualified = record.to_dict()["qualified_name"]
            if needle in str(qualified).casefold() or needle in record.name.casefold():
                results.append({"kind": "method", **record.to_dict()})
        return results

    def to_dict(self, *, max_types: int | None = None) -> dict[str, object]:
        types = self.types if max_types is None else self.types[:max_types]
        return {
            "source": self.source,
            "header": self.header.to_dict(),
            "counts": {
                "types": len(self.types),
                "fields": len(self.fields),
                "methods": len(self.methods),
                "images": len(self.images),
            },
            "types": [record.to_dict() for record in types],
            "fields": [record.to_dict() for record in self.fields],
            "methods": [record.to_dict() for record in self.methods],
            "images": [record.to_dict() for record in self.images],
            "warnings": list(self.warnings),
        }


def parse_metadata(data: bytes, *, source: str = "") -> MetadataReader:
    return MetadataReader(data, source=source)
