r"""Print the data of an RF() entry in src/fuzz/main.c as C declarations.

Usage (from the repository root):

    uv run --no-project python -I \
        .claude/skills/triage-crash/scripts/rf_data.py src/fuzz/main.c <n> [--reflection]

Default: one `static const unsigned char data[N]` array.
--reflection: split the way test_reflection_type_context() does - an optional
packed FYPG blob (header + its three regions), then an entry type line, a meta
line and the YAML document - into blob[], entry[], meta[] and yaml[], all byte
arrays. entry[] and meta[] are C strings and end in an added 0x00 - pass them
as `(const char *)x`; yaml[] has no terminator - `(const char *)yaml, sizeof(yaml)`.
"""

import re
import sys
from pathlib import Path

FYPG_HDR_SIZE = 0x40
FYPG_REGION_OFFSETS = (0x18, 0x28, 0x30)
BYTES_PER_LINE = 12


def rf_bytes(src: str, n: str) -> bytes:
    """Return the input bytes of RF(n), checked against its size argument."""
    pattern = r"RF\(" + re.escape(n) + r',\n.*?\n("(?:\\x[0-9a-f]{2})*"),\n(\d+)\n\)'
    m = re.search(pattern, src, re.S)
    if not m:
        sys.exit(f"RF({n}) not found")
    data = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-f]{2})", m.group(1)))
    if len(data) != int(m.group(2)):
        sys.exit(f"RF({n}): size {m.group(2)} does not match {len(data)} bytes")
    return data


def packed_blob_size(data: bytes) -> int:
    """Mirror the harness: header plus regions, or everything on an overrun."""
    if len(data) < FYPG_HDR_SIZE or data[:4] != b"FYPG":
        return 0
    n = FYPG_HDR_SIZE
    for off in FYPG_REGION_OFFSETS:
        r = int.from_bytes(data[off : off + 8], "big")
        if r > len(data) - n:
            return len(data)
        n += r
    return n


def c_array(name: str, b: bytes) -> str:
    """Format bytes as a sized C array."""
    out = [f"static const unsigned char {name}[{len(b)}] = {{"]
    for i in range(0, len(b), BYTES_PER_LINE):
        out.append("\t" + " ".join(f"0x{c:02x}," for c in b[i : i + BYTES_PER_LINE]))
    out.append("};")
    return "\n".join(out)


def c_cstring(name: str, b: bytes) -> str:
    """Format a C string part as a byte array with its terminating NUL."""
    return c_array(name, b + b"\0")


def main() -> None:
    """Print the declarations for RF(argv[2]) of the file argv[1]."""
    if len(sys.argv) < 3:  # noqa: PLR2004
        sys.exit(__doc__)
    data = rf_bytes(Path(sys.argv[1]).read_text(), sys.argv[2])
    if "--reflection" not in sys.argv[3:]:
        print(c_array("data", data))
        return
    bs = packed_blob_size(data)
    rest = data[bs:]
    if rest.count(b"\n") < 2:  # noqa: PLR2004
        sys.exit("no entry and meta lines after the blob: no type context runs")
    entry, rest = rest.split(b"\n", 1)
    meta, yaml = rest.split(b"\n", 1)
    if bs:
        print(c_array("blob", data[:bs]))
        print()
    print(c_cstring("entry", entry))
    print(c_cstring("meta", meta))
    print(c_array("yaml", yaml))


if __name__ == "__main__":
    main()
