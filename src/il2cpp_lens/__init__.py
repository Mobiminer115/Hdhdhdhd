"""Portable IL2CPP metadata inspection core."""

from .metadata import MetadataReader, MetadataParseError, parse_metadata
from .detect import scan_path, scan_bytes
from .macho import MachOImage, FatMachO, MachOParseError, parse_macho

__all__ = [
    "MetadataReader",
    "MetadataParseError",
    "parse_metadata",
    "scan_path",
    "scan_bytes",
    "MachOImage",
    "FatMachO",
    "MachOParseError",
    "parse_macho",
]

__version__ = "0.1.0"
