# Cartographer — User Manual

Cartographer is an extension to BPFVol3, a set of Volatility 3 plugins for eBPF
memory forensics. It recovers the contents of eBPF hash-family maps from a Linux
physical memory image, offline, and decodes them into readable, typed records
using the kernel's BPF Type Format (BTF). It also finds maps that have been
removed from the kernel's map registry, including maps hidden by an attacker and
maps that were freed before the image was taken.

This manual describes how to run the tool and read its output. For the exact
pinned versions, the symbol profile build, and the test environment, see
`ENVIRONMENT.md`.


## 1. What it does, in one paragraph

The baseline tool, BPFVol3, can list eBPF programs, maps and links from a memory
image but can only dump the contents of array maps. Cartographer adds recovery
of the hash-map family (plain hash, LRU, per-CPU, and LRU per-CPU), a per-map
status so a damaged image degrades gracefully instead of producing wrong data,
BTF decoding so recovered bytes are shown as named fields, discovery of a map
through the programs that use it as well as through the registry, and an
optional scanner that finds maps by searching raw memory when no registry or
program points at them.


## 2. Requirements

A working BPFVol3 install inside a pinned Volatility 3 tree, a Python virtual
environment with Volatility's dependencies, and a symbol profile that matches
the kernel of the image being analysed. The exact revisions and the profile
build are recorded in `ENVIRONMENT.md`. Support is validated against one
documented kernel build; a different kernel needs its own matching profile.

The five files this project adds or changes live in the Volatility tree as
follows:

    volatility3/utility/map.py                           map recovery + status
    volatility3/utility/btf.py                           BTF decoder
    volatility3/framework/plugins/linux/bpf_listmaps.py  the map plugin
    volatility3/framework/plugins/linux/unlink_map.py    test fixture (plugin)
    volatility3/framework/plugins/linux/bpf_scanmaps.py  orphaned-map scanner

The planters and the verification harness (`cart_btf_loader.c`, `hide_loader.c`,
`plant_maps.c`, `verify.py`, and so on) are run directly and do not go in the
Volatility tree.


## 3. Acquiring an image

Any Linux memory acquisition tool that produces a LiME-format image works. This
project uses LEMON. The map to be analysed must be alive in kernel memory at the
moment of capture, so whatever created it must still be running. A short
two-terminal pattern is used for the test maps: one terminal runs a loader that
creates the maps and stays open, and a second terminal runs the acquisition
while the loader is held. The loader is stopped only after the image is written.


## 4. Listing and dumping maps

The main plugin lists every eBPF map found in the image and, on request, writes
each map's contents to a file.

    vol.py -s <symbols> -f <image> -o <outdir> linux.bpf_listmaps.MapList [--dump] [--raw]

Options:

- `--dump` writes each map's contents to a file in the output directory. Without
  it, only the table is shown.
- `--raw` writes the stored bytes instead of BTF-decoded records. Use it for
  byte-for-byte checks against ground truth; omit it to get readable fields.

The output directory must already exist. Volatility never overwrites an output
file, so clear the directory between runs to avoid reading a stale result.

The table has the usual map fields (offset, id, type, name, key size, value
size, maximum entries) plus two columns this project adds, STATUS and SOURCE,
described in section 6.


## 5. Scanning for orphaned maps

The scanner finds maps by searching memory for the fixed pointer every map of a
given type carries to the kernel's shared operations table. It therefore finds a
map even when the registry no longer lists it and no program references it. It is
an optional, opt-in plugin and does not run as part of normal listing.

    vol.py -s <symbols> -f <image> -o <outdir> linux.bpf_scanmaps.ScanMaps [--dump]

`--dump` writes each recovered map's contents, decoded when the map's BTF can
still be read and as raw bytes otherwise. The scan reads the whole image, so it
takes longer than listing. Add `-vv` before the plugin name to see its internal
diagnostics.

The scanner adds a SCAN column that classifies each find; see section 6.


## 6. Reading the output

### The dump files

With `--dump`, each map's contents are written to a hidden file in the output
directory (the name begins with a dot). The map plugin names them
`.map_<offset>_<id>` and the scanner names them `.scan_<offset>_<id>`. List them
with `ls -a`. Each file holds one JSON object of the map's key/value pairs. A
decoded value looks like `{pid: 1337, comm: "cartographer", count: 42}`; the
same value in raw mode looks like `[39 05 00 00 63 61 72 74 ...]`.

### The STATUS column

- `traversed` — the whole structure was examined with no error. This is not a
  claim that the contents are authentic, only that recovery reached the end.
- `partial` — recovery hit unreadable memory, a bad pointer, a cycle, or a
  bound, and returned the entries recovered so far.
- `unsupported` — the map type or layout is out of scope (for example
  `HASH_OF_MAPS`, which stores pointers to other maps rather than values).
- `not dumped` — contents were never read, because `--dump` was not given.

### The SOURCE column (map plugin)

How the map was reached:

- `idr` — found in the kernel's map registry.
- `prog` — found only through a program that uses it; absent from the registry.
- `idr+prog` — found both ways.

A map shown as `prog` is one the registry no longer lists but a program still
uses: a map hidden from registry-based tools, recovered through the program
reference.

### The SCAN column (scanner)

How each find relates to the registry:

- `in idr` — the registry points at this exact structure; a normal live map.
- `dup of live` — same id and name as a registered map but at a different
  address; a second view or copy of a live map, not a separate map.
- `freed` — the id is zero. The kernel clears a map's id when it frees the map
  normally, so this is a map that died the ordinary way.
- `ORPHANED` — not registered, not a copy of a registered map, and not freed the
  normal way. A deliberately unlinked map lands here, and so can a copy of a map
  that no longer exists.
- `ORPHANED xN` — as above, but the same id and name turned up N times.
- `(live)` / `(dead)` — appended to an orphan when it carries BTF: `(live)` if
  its type information still reads, as a live map's does; `(dead)` if it had BTF
  but the BTF no longer reads. Read `(live)` as strong evidence of a hidden live
  map rather than proof, since a map freed just before capture can still pass.


## 7. Supported map types

Recovered and decoded: `ARRAY` (from the baseline), `HASH`, `LRU_HASH`,
`PERCPU_HASH`, and `LRU_PERCPU_HASH`. BTF decoding handles integers, typedefs and
type qualifiers, structures and unions, and arrays (character and byte arrays as
text or capped hex, other arrays as a capped list).

Not supported: `HASH_OF_MAPS` (stores pointers to other maps, not values) and
map types outside the hash family. Enum fields are shown as their numeric value.


## 8. Verifying recovery

The harness `verify.py` compares recovered bytes against ground truth recorded
by a planter while it ran.

    vol.py -s <symbols> -f <image> -o <outdir> linux.bpf_listmaps.MapList --dump --raw
    python3 verify.py <truth-file> <outdir>

`--raw` is required here, because the harness compares bytes, not decoded
records. It prints a per-map pass/fail table and exits non-zero if any planted
map was not fully recovered.


## 9. Test fixtures

These reproduce the conditions used to evaluate the tool. They operate on copies
of an image or on output files and are not part of the recovery tool.

- `unlink_map.UnlinkMap` — zeroes a map's slot in the registry in a copy of an
  image, modelling a map unlinked from the registry while still in memory.
- `find_next.FindNext` — corrupts a hash chain pointer in a copy of an image,
  modelling damaged memory, so the status layer can be shown reporting `partial`.
- `cart_btf`, `hide`, and `plant_maps` — loaders that create maps with known
  contents and record ground truth.


## 10. Limitations

Support is validated for one documented kernel build. A map that is both
unlinked and referenced by nothing can only be found by the scanner, which is
heuristic rather than exhaustive. Acquiring memory on the machine under analysis,
especially more than once, leaves copies of kernel objects in RAM that the
scanner will also report. A map's status of `traversed` means recovery reached
the end, not that the bytes are authentic; in particular, bytes read from a map
that has been freed and partly overwritten may read cleanly yet no longer belong
to that map.
