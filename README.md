# Cartographer

Cartographer is an extension to [BPFVol3](https://github.com/vobst/BPFVol3) for Volatility 3. It recovers the contents of eBPF maps from a Linux physical memory image, offline, and decodes them into named, typed fields using the kernel's BPF Type Format (BTF). It also finds maps that have been removed from the kernel's map registry, the step an eBPF rootkit would take to hide its data from live tools.

ICT3215 Digital Forensics, Singapore Institute of Technology. Damon Seah, Jovan Lee Songying, Louis Goh Yao Ming, Neo Zhan Ming Derrick, Edward Lim Hong Hwee.

## What it adds to BPFVol3

| Feature | Baseline BPFVol3 | Cartographer |
|---|---|---|
| Map contents recovered | array maps only | array, hash, LRU hash, per-CPU hash, LRU per-CPU hash |
| Damaged or tampered images | no status | per-map STATUS: `traversed`, `partial`, `unsupported`, `not dumped` |
| Decoding | integers and arrays stubbed | integers, typedefs, structs, unions, arrays and enums decoded by name |
| Finding maps | kernel registry (`map_idr`) only | registry, plus maps referenced by loaded programs (SOURCE column) |
| Hidden maps | not found | optional scanner finds maps by their kernel signature in raw memory (`bpf_scanmaps`) |

## Repository layout

```
bpfvol3/                  BPFVol3 with Cartographer's changes (MIT, Valentin Obst)
  src/plugins/            Volatility plugins; Cartographer's are bpf_listmaps.py and bpf_scanmaps.py
  src/utility/            shared code; Cartographer's are map.py (recovery) and btf.py (decoding)
tests/                    test scaffolding, not part of the tool
  plugins/                unlink_map.py, find_next.py, chain_stats.py (edit or inspect image copies)
  fixtures/               loaders that plant maps with known contents (*.c, *.bpf.c)
  verify.py               compares recovered bytes with what the loaders planted
  collect_evidence.sh     runs the main evaluation on one image
  collect_collide.sh      runs the hash-collision test
evidence/                 output of the runs reported in the paper
USER_MANUAL.md            how to run the tool and read its output
ENVIRONMENT.md            pinned versions, setup and reproduction steps
```

Only the files under `bpfvol3/src/` are the tool. Everything under `tests/` exists to create test conditions and check the results.

## Quick start

Cartographer needs a working Volatility 3 and BPFVol3 setup and a symbol profile for the exact kernel of the image; `ENVIRONMENT.md` gives the pinned versions and steps. With those in place:

```
vol.py -s <symbols> -f <image> -o <outdir> linux.bpf_listmaps.MapList --dump
vol.py -s <symbols> -f <image> -o <outdir> linux.bpf_scanmaps.ScanMaps --dump
```

`USER_MANUAL.md` explains every option and column.

## Evidence

Each folder holds the complete output of one experiment in the report.

| Folder | Image | Supports |
|---|---|---|
| `evidence/main/` | `final.lime`, SHA-256 `5731bdfe…6f151c7a` | Table I (except `cart_collide`), Table II, Figs. 2–6, run times, per-CPU check (Section V-A to V-F) |
| `evidence/evidence_collide/` | `collide.lime`, SHA-256 `af311aca…5f8fcadf` | hash-collision test, the `cart_collide` row of Table I (Section V-B) |
| `evidence/evidence_borrow/` | `final.lime`, scanner run with `--borrow-btf` | decoding dead maps with borrowed BTF, and why its output is unverified (Section V-F) |
| `evidence/truth/` | — | what each loader planted, used by `verify.py` |

Start with the `SUMMARY.txt` in each folder. The memory images are not in the repository because of their size and because memory images can contain sensitive data.

## Credits

Built on BPFVol3 by Valentin Obst (MIT licence; see `bpfvol3/LICENSE.md`), Volatility 3 by the Volatility Foundation, btf2json by Valentin Obst, and LEMON by Oliveri et al. for memory acquisition.
