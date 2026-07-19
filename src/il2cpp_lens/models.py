from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TableRange:
    """A range described by an IL2CPP metadata header."""

    name: str
    offset: int
    size: int
    unit: str = "bytes"

    @property
    def end(self) -> int:
        return self.offset + self.size

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "unit": self.unit,
            "end": self.end,
        }


@dataclass
class MetadataHeader:
    magic: int
    version: int
    effective_version: str
    header_size: int
    tables: dict[str, TableRange] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": f"0x{self.magic:08X}",
            "version": self.version,
            "effective_version": self.effective_version,
            "header_size": self.header_size,
            "tables": {name: table.to_dict() for name, table in self.tables.items()},
        }


@dataclass(frozen=True)
class TypeRecord:
    index: int
    name: str
    namespace: str
    name_index: int
    namespace_index: int
    metadata_offset: int
    metadata_size: int
    field_start: int
    field_count: int
    method_start: int
    method_count: int
    flags: int
    token: int

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "namespace": self.namespace,
            "full_name": self.full_name,
            "name_index": self.name_index,
            "namespace_index": self.namespace_index,
            "metadata_offset": self.metadata_offset,
            "metadata_size": self.metadata_size,
            "field_start": self.field_start,
            "field_count": self.field_count,
            "method_start": self.method_start,
            "method_count": self.method_count,
            "flags": self.flags,
            "token": self.token,
        }


@dataclass(frozen=True)
class FieldRecord:
    index: int
    name: str
    name_index: int
    type_index: int
    token: int
    metadata_offset: int
    metadata_size: int
    owner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "name_index": self.name_index,
            "type_index": self.type_index,
            "token": self.token,
            "metadata_offset": self.metadata_offset,
            "metadata_size": self.metadata_size,
            "owner": self.owner,
            "qualified_name": f"{self.owner}.{self.name}" if self.owner else self.name,
        }


@dataclass(frozen=True)
class MethodRecord:
    index: int
    name: str
    name_index: int
    declaring_type: int
    return_type: int
    parameter_start: int
    parameter_count: int
    token: int
    metadata_offset: int
    metadata_size: int
    owner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "name_index": self.name_index,
            "declaring_type": self.declaring_type,
            "return_type": self.return_type,
            "parameter_start": self.parameter_start,
            "parameter_count": self.parameter_count,
            "token": self.token,
            "metadata_offset": self.metadata_offset,
            "metadata_size": self.metadata_size,
            "owner": self.owner,
            "qualified_name": f"{self.owner}.{self.name}" if self.owner else self.name,
        }


@dataclass(frozen=True)
class ImageRecord:
    index: int
    name: str
    name_index: int
    type_start: int
    type_count: int
    metadata_offset: int
    metadata_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "name_index": self.name_index,
            "type_start": self.type_start,
            "type_count": self.type_count,
            "metadata_offset": self.metadata_offset,
            "metadata_size": self.metadata_size,
        }


@dataclass
class FileCandidate:
    container: str
    kind: str
    offset: int
    size: int
    details: dict[str, Any] = field(default_factory=dict)
    payload: bytes = field(default=b"", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "container": self.container,
            "kind": self.kind,
            "offset": self.offset,
            "size": self.size,
            "details": self.details,
        }
