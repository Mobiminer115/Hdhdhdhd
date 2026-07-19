# IL2CPP Lens

IL2CPP Lens is the parser core for a mobile-friendly Unity/IL2CPP inspector.
It deliberately identifies inputs by their bytes rather than by their file
names. A file can be renamed, embedded in an IPA, or placed inside an archive
and the scanner will still look for the IL2CPP metadata magic and Mach-O
headers.

This first milestone is a portable reference implementation. It can:

- scan a file, directory, or ZIP/IPA recursively;
- find `global-metadata.dat` by its magic value, even when it has another name;
- parse the metadata header and table ranges;
- resolve type, field, method, and image names from the metadata string table;
- emit a JSON report or a readable text dump.

It does not yet claim to decompile native ARM64 into C-like pseudocode or to
recover offsets from an encrypted/obfuscated metadata blob. Those are separate
analysis stages which will consume this core.

## Run locally

```bash
cd il2cpp-lens
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m il2cpp_lens path/to/any/file --json
```

The command accepts any filename. For a ZIP/IPA it inspects entries without
extracting them to disk. A metadata candidate can be selected with
`--candidate` when an input contains more than one candidate.

## Safety and scope

Use the tool only with binaries and metadata that you own or are authorized to
analyze. The parser is read-only; it does not execute a target program, bypass
code signing, or modify an input file.
