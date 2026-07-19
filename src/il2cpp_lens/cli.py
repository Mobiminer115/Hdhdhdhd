from __future__ import annotations

import argparse
import json
import sys

from .detect import scan_path
from .metadata import MetadataParseError, MetadataReader
from .macho import MachOParseError, parse_macho


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="il2cpp-lens",
        description="Scan arbitrary files for IL2CPP metadata and inspect names.",
    )
    parser.add_argument("input", help="file or directory; the filename is not used for detection")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--candidate", type=int, default=None, help="inspect one candidate by index")
    parser.add_argument("--max-types", type=int, default=None, help="limit type output")
    parser.add_argument("--find", default=None, help="search resolved type/field/method names")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        candidates = scan_path(args.input)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.candidate is not None:
        if args.candidate < 0 or args.candidate >= len(candidates):
            print(f"error: candidate index must be between 0 and {len(candidates) - 1}", file=sys.stderr)
            return 2
        candidates = [candidates[args.candidate]]

    reports: list[dict[str, object]] = []
    for candidate in candidates:
        report: dict[str, object] = {"candidate": candidate.to_dict()}
        if candidate.kind == "il2cpp-metadata":
            try:
                reader = MetadataReader(candidate.payload, source=candidate.container)
                report["metadata"] = reader.to_dict(max_types=args.max_types)
                if args.find:
                    report["matches"] = reader.search(args.find)
            except MetadataParseError as exc:
                report["error"] = str(exc)
        elif candidate.kind == "mach-o":
            try:
                report["macho"] = parse_macho(candidate.payload).to_dict()
            except MachOParseError as exc:
                report["error"] = str(exc)
        reports.append(report)

    if args.json:
        print(json.dumps({"input": args.input, "candidates": reports}, indent=2, ensure_ascii=False))
        return 0

    if not reports:
        print("No IL2CPP metadata or Mach-O candidate found.")
        return 0
    for index, report in enumerate(reports):
        candidate = report["candidate"]
        assert isinstance(candidate, dict)
        print(f"[{index}] {candidate['kind']}  {candidate['container']}  +0x{candidate['offset']:X}")
        if "metadata" in report:
            metadata = report["metadata"]
            assert isinstance(metadata, dict)
            header = metadata["header"]
            counts = metadata["counts"]
            assert isinstance(header, dict) and isinstance(counts, dict)
            print(
                f"    version={header['version']} profile={header['effective_version']} "
                f"types={counts['types']} fields={counts['fields']} methods={counts['methods']}"
            )
            for type_record in metadata["types"]:
                assert isinstance(type_record, dict)
                print(f"    {type_record['full_name']}")
                for field in metadata["fields"]:
                    assert isinstance(field, dict)
                    if field.get("owner") == type_record["full_name"]:
                        print(
                            f"      field {field['name']} "
                            f"(metadata+0x{field['metadata_offset']:X}, type#{field['type_index']})"
                        )
                for method in metadata["methods"]:
                    assert isinstance(method, dict)
                    if method.get("owner") == type_record["full_name"]:
                        print(
                            f"      method {method['name']}() "
                            f"(metadata+0x{method['metadata_offset']:X})"
                        )
            if "matches" in report:
                print(f"    matches for {args.find!r}: {len(report['matches'])}")
                for match in report["matches"]:
                    assert isinstance(match, dict)
                    print(
                        f"      {match['kind']}: {match.get('qualified_name', match.get('full_name'))}"
                    )
        elif "macho" in report:
            macho = report["macho"]
            assert isinstance(macho, dict)
            print(
                f"    format={macho.get('format', macho.get('kind', 'Mach-O'))} "
                f"image_base=0x{macho.get('image_base', 0):X} "
                f"segments={len(macho.get('segments', macho.get('slices', [])))}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
