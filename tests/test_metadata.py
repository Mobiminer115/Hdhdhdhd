from __future__ import annotations

import struct

from il2cpp_lens.metadata import MetadataReader, _HEADER_FIELDS, _layout_size, _layout


def _make_fixture() -> bytes:
    version = 29
    header_fields = [field for field in _HEADER_FIELDS if field.enabled(float(version))]
    header_size = 8 + len(header_fields) * 8
    data = bytearray(header_size)
    struct.pack_into("<II", data, 0, 0xFAB11BAF, version)

    strings = b"\0Game\0Player\0reach\0Update\0"
    string_indexes = {"Game": 1, "Player": 6, "reach": 13, "Update": 19}
    type_layout = _layout(float(version), "type")
    field_layout = _layout(float(version), "field")
    method_layout = _layout(float(version), "method")
    image_layout = _layout(float(version), "image")

    type_record = struct.pack(
        "<" + "".join(fmt for _, fmt in type_layout),
        string_indexes["Player"],
        string_indexes["Game"],
        0,  # byval type
        -1,  # declaring type
        -1,  # parent
        -1,  # element type
        -1,  # generic container
        0,  # flags
        0,  # field start
        0,  # method start
        0,  # event start
        0,  # property start
        0,  # nested types start
        0,  # interfaces start
        0,  # vtable start
        0,  # interface offsets start
        1, 0, 1, 0, 0, 0, 0, 0,  # counts
        0,  # bitfield
        1,  # token
    )
    field_record = struct.pack("<" + "".join(fmt for _, fmt in field_layout), string_indexes["reach"], 0, 2)
    method_record = struct.pack(
        "<" + "".join(fmt for _, fmt in method_layout),
        string_indexes["Update"],
        0,
        0,
        0,
        -1,
        3,
        0,
        0,
        0,
        0,
    )
    image_record = struct.pack(
        "<" + "".join(fmt for _, fmt in image_layout),
        string_indexes["Game"],
        0,
        0,
        1,
        0,
        0,
        -1,
        1,
        0,
        0,
    )

    cursor = (header_size + 0x0F) & ~0x0F
    ranges: dict[str, tuple[int, int]] = {}

    def append_table(name: str, payload: bytes) -> None:
        nonlocal cursor
        cursor = (cursor + 0x0F) & ~0x0F
        if len(data) < cursor:
            data.extend(b"\0" * (cursor - len(data)))
        data.extend(payload)
        ranges[name] = (cursor, len(payload))
        cursor += len(payload)

    append_table("strings", strings)
    append_table("type_definitions", type_record)
    append_table("fields", field_record)
    append_table("methods", method_record)
    append_table("images", image_record)

    field_positions = {field.name: index for index, field in enumerate(header_fields)}
    for name, (offset, size) in ranges.items():
        index = field_positions[name]
        struct.pack_into("<II", data, 8 + index * 8, offset, size)
    # All other table ranges remain zero.
    return bytes(data)


def test_names_and_ownership_are_resolved() -> None:
    reader = MetadataReader(_make_fixture(), source="renamed.input")
    assert reader.header.version == 29
    assert reader.types[0].full_name == "Game.Player"
    assert reader.fields[0].name == "reach"
    assert reader.fields[0].owner == "Game.Player"
    assert reader.methods[0].name == "Update"
    assert reader.methods[0].owner == "Game.Player"
    report = reader.to_dict()
    assert report["counts"] == {"types": 1, "fields": 1, "methods": 1, "images": 1}


def test_text_dump_contains_resolved_names() -> None:
    dump = MetadataReader(_make_fixture()).dump_text()
    assert "class Game.Player" in dump
    assert "Game.Player.reach : metadata+0x180" in dump
    assert "Game.Player.Update() : metadata+0x190" in dump


def test_search_finds_a_field_by_qualified_name() -> None:
    reader = MetadataReader(_make_fixture())
    matches = reader.search("Player.reach")
    assert len(matches) == 1
    assert matches[0]["kind"] == "field"
    assert matches[0]["qualified_name"] == "Game.Player.reach"
