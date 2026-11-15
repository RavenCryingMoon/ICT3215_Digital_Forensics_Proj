# Environment and reproduction

This file records the exact environment used to develop and test Cartographer, and the steps needed to reproduce the results in the report. Steps marked **TODO** still need the exact command that was used on the test machine.

Last verified: 2026-11-14 (final evaluation run; every planted entry recovered, see `evidence/main/SUMMARY.txt`).

## 1. Test system

| Item | Value |
|---|---|
| OS | Kali Linux (rolling), x86_64 |
| Kernel | `6.12.38+kali-amd64` |
| CPUs | 32 possible (`/sys/devices/system/cpu/possible` = `0-31`) |
| Python | 3.13.7 (system), virtual environment at `~/cart-venv` |

The memory images and the symbol profile all belong to this exact kernel build.

- `apt update` only refreshes the package lists and is safe.
- `apt upgrade` and `apt full-upgrade` can install a newer kernel. Neither should be run on the test machine until the evaluation is finished.
- Kali rolling no longer carries `linux-image-6.12.38+kali-amd64-dbg`, so a DWARF-based profile can no longer be built for this kernel (see section 4).

## 2. Pinned components

| Component | Version | Role |
|---|---|---|
| Volatility 3 | commit `18e5d7a7f2e2a85d0178307dd502e2729488e93a` (reports 2.5.2) | Memory analysis framework |
| BPFVol3 | commit `4123d3f74cbe407876eca5cb78500fd0046a435a` (MIT, Valentin Obst) | BPF plugins that this project extends |
| btf2json | commit `4a64f9c` | Builds the symbol profile from BTF and kallsyms |
| LEMON | v2.0, commit `e133938`, built with `make MODE=core` | Memory acquisition (LiME format) |
| libbpf, clang, gcc | Kali packages at the time of testing | Building the test loaders in `tests/fixtures/` |

## 3. Memory images

| File | Size | SHA-256 | Used for |
|---|---|---|---|
| `final.lime` | 8.0 GB | `5731bdfe58cd66b9cb1a1483e10197bf8701f7c7c3d6982e4a946a3d6f151c7a` | main evaluation and the BTF-borrowing test |
| `collide.lime` | 8.0 GB | `af311acaa63a68248f769a95dbd42260caff97470d750a19f17f29f75f8fcadf` | hash-collision test |

The images are not stored in this repository because of their size, and because a memory image can contain sensitive data. Obtain them from the team share and check them before use:

```
sha256sum final.lime collide.lime
```

### How the images were taken

The maps must be alive in memory at the moment of capture, so the loaders run in their own terminals and stay running until the image is written. All loaders are in `tests/fixtures/`.

Build the loaders once (in `~/DF_proj`, where the loaders and their `.bpf.o` files live):

```
gcc -static -O2 -o plant_maps plant_maps.c
gcc -static -O2 -o plant_lru_pcpu plant_lru_pcpu.c
gcc -static -O2 -o plant_collide plant_collide.c
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c cart_btf.bpf.c -o cart_btf.bpf.o
gcc -O2 -o cart_btf_loader cart_btf_loader.c -lbpf
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c hide.bpf.c -o hide.bpf.o
gcc -O2 -o hide_loader hide_loader.c -lbpf
```

`final.lime`: start these four, one per terminal, and leave them running. Each prints its ground truth and then `PLANTED-OK`.

```
sudo ./plant_maps       | tee ~/DF_proj/truth_plant.txt
sudo ./cart_btf_loader  | tee ~/DF_proj/truth_btf.txt
sudo ./hide_loader      | tee ~/DF_proj/truth_hide.txt
sudo ./plant_lru_pcpu   | tee ~/DF_proj/truth_lru_pcpu.txt
```

Then, in a fifth terminal, take the image, and only afterwards stop the loaders with Ctrl+C:

```
sudo ~/DF_proj/lemon/lemon.core.x86_64 -d ~/DF_proj/final.lime
sudo chown kali:kali ~/DF_proj/final.lime
```

`collide.lime`: the same, with only `sudo ./plant_collide | tee ~/DF_proj/truth_collide.txt` running, and `collide.lime` as the output file.

The truth files from these runs are kept in `evidence/truth/`.

## 4. Symbol profile

Volatility needs a symbol profile (ISF JSON) that matches the kernel exactly. The usual tool, dwarf2json, reads the kernel's `-dbg` package, which is no longer available for this kernel. The profile is therefore built with btf2json from two sources on the test machine:

- `/sys/kernel/btf/vmlinux`: the kernel's built-in BTF type information (struct layouts).
- `/proc/kallsyms`: kernel symbol addresses. Reading it requires root; without root, every address reads as zero.

Both should be captured on the machine that produced the image, in the same boot as the acquisition where possible.

> **TODO:** confirm that the two capture commands below match the ones used, and add how btf2json was built at commit `4a64f9c`.

```
cd ~/DF_proj
cp /sys/kernel/btf/vmlinux btf.raw
sudo cat /proc/kallsyms > kallsyms.map
mkdir -p symbols
~/.cargo/bin/btf2json --btf btf.raw --map kallsyms.map --banner "$(cat /proc/version)"$'\n' > symbols/kali-6.12.38.json
```

btf2json prints `ERROR btf2json::isf] 12 symbols reference missing types, 12 unique types are missing`. None of the types used by this project are affected. To check that they are present:

```
python3 -c "
import json; j=json.load(open('symbols/kali-6.12.38.json'))
print({t:t in j['user_types'] for t in ['bpf_map','bpf_htab','bucket','htab_elem','bpf_array']})
print({s:s in j['symbols'] for s in ['map_idr','prog_idr','linux_banner','init_task','htab_map_ops','array_map_ops']})"
```

Every value printed must be `True`.

## 5. Volatility 3, BPFVol3 and Cartographer

> **TODO:** add the exact commands used to clone Volatility at the pinned commit, create `~/cart-venv` and install its requirements, and install upstream BPFVol3 into it (file copies and BPFVol3's Volatility patch).

The schema of the pinned Volatility only accepts symbol profiles whose sources are of kind `dwarf`, `symtab` or `system-map`. btf2json records its sources with kinds this version does not list (`btf`, `symdb`), so the schema needs one change. The command does nothing if the change is already in place:

```
cd ~/DF_proj/vol3-pinned
grep -q 'btf|symdb' volatility3/schemas/schema-6.2.0.json || \
  sed -i 's/"\^(dwarf|symtab|system-map)\$"/"^(btf|symdb|dwarf|symtab|system-map)$"/' volatility3/schemas/schema-6.2.0.json
```

### Installing Cartographer's files

Cartographer's files are copied from this repository into the Volatility tree. Set `REPO` to wherever this repository is cloned on the test machine:

```
REPO=~/DF_proj/ICT3215_Digital_Forensics_Proj
V=~/DF_proj/vol3-pinned/volatility3

# the tool
cp $REPO/bpfvol3/src/utility/map.py $REPO/bpfvol3/src/utility/btf.py $V/utility/
cp $REPO/bpfvol3/src/plugins/bpf_listmaps.py $REPO/bpfvol3/src/plugins/bpf_scanmaps.py $V/framework/plugins/linux/

# test plugins, needed only to reproduce the evaluation
cp $REPO/tests/plugins/*.py $V/framework/plugins/linux/

find ~/DF_proj/vol3-pinned -name __pycache__ -type d -prune -exec rm -rf {} +
```

Copy again after any change in the repository. Clearing `__pycache__` matters: Python otherwise keeps running the old version of a changed file.

Copies are used instead of symbolic links. A link only works when the repository is cloned on the same machine at the exact path the link names; when it is not, Volatility silently fails to load the plugin (`invalid choice linux.bpf_listmaps.MapList`).

## 6. Running the plugins

```
cd ~/DF_proj/vol3-pinned
rm -rf ../out && mkdir -p ../out
~/cart-venv/bin/python vol.py -s ../symbols -f ../final.lime -o ../out linux.bpf_listmaps.MapList --dump
~/cart-venv/bin/python vol.py -s ../symbols -f ../final.lime -o ../out linux.bpf_scanmaps.ScanMaps --dump
ls -la ../out/
```

- `--raw` (MapList) writes stored bytes instead of decoded records; `verify.py` needs it.
- `--borrow-btf` (ScanMaps) decodes dead maps with a matching live map's BTF. Its output is unverified; see `USER_MANUAL.md`.
- The output directory must exist before the run.
- Each map's contents are written to a hidden file named `.map_<offset>_<id>` (scanner: `.scan_<offset>_<id>`), so the files only show up with `ls -a`.
- Volatility never overwrites an output file. If a file of the same name already exists, the new one is written as `-1.map_…`, `-2.map_…` and so on. Emptying the output directory before every run keeps the files from the latest run only.
- Global options such as `-v`, `-vv`, `-q` or `-r csv` must come before the plugin name. Placed after it, they are rejected and Volatility exits without running.

## 7. Reproducing the evaluation

With the images, truth files and plugins in place (sections 3 and 5), run from `~/DF_proj/vol3-pinned`:

| Experiment | Command | Output |
|---|---|---|
| Main evaluation | `bash $REPO/tests/collect_evidence.sh` | `~/DF_proj/evidence/` |
| Hash collisions | `bash $REPO/tests/collect_collide.sh` | `~/DF_proj/evidence_collide/` |
| Borrowed BTF | `~/cart-venv/bin/python vol.py -q -s ../symbols -f ../final.lime -o ../evidence_borrow/scan linux.bpf_scanmaps.ScanMaps --dump --borrow-btf` | `~/DF_proj/evidence_borrow/` |

The scripts expect the loaders' truth files in `~/DF_proj` and the images at `~/DF_proj/final.lime` and `~/DF_proj/collide.lime`; the paths are set at the top of each script. The main run takes about 4 minutes on the test machine (the scanner reads the whole image in about 97 s with a peak memory of 3.5 GB; each listing takes 11–14 s and about 500 MB). It makes one temporary copy of the image at a time, so it needs free disk space of about one image size.

## 8. Expected results

Map list from `final.lime` (`evidence/main/01_maplist.txt`, columns aligned):

```
OFFSET (V)      ID  TYPE             NAME             KEY SIZE  VALUE SIZE  MAX ENTRIES  STATUS       SOURCE
0x9faa8175ec00  11  HASH_OF_MAPS     cgroup_hash      8         4           2048         unsupported  idr+prog
0x9faa81521400  51  ARRAY            cart_arr         4         8           4            traversed    idr
0x9faa444eac00  52  HASH             cart_hash        4         8           16           traversed    idr
0x9faa444eb000  53  LRU_HASH         cart_lru         4         8           64           traversed    idr
0x9faa444ea000  54  PERCPU_HASH      cart_pcpu        4         8           16           traversed    idr
0x9faa81189000  55  HASH             cart_hash_np     6         12          8            traversed    idr
0x9faa8118b000  56  HASH             cart_empty       4         4           8            traversed    idr
0x9faa444ef400  57  HASH             cart_btf         4         40          16           traversed    idr
0x9faa442a0400  58  HASH             hide_rules       4         36          16           traversed    idr+prog
0x9faa51deec00  63  LRU_PERCPU_HASH  cart_lru_pcpu    4         8           16           traversed    idr
0xad0e515d9ef8  65  ARRAY            read_mem_array_  4         2097156     1            traversed    idr+prog
0xad0e411a5ef8  67  ARRAY            mem_ebp.kconfig  4         9           1            traversed    idr
```

The `cart_*` maps and `hide_rules` are the planted test maps. `read_mem_array_` and `mem_ebp.kconfig` belong to LEMON's own eBPF reader. `cgroup_hash` was already present on the system and is reported `unsupported`, because maps of maps store pointers to other maps rather than values. Offsets and ids change with every boot and every capture.

`verify.py` must report `PASS` for every planted map (`evidence/main/01_verify_*.txt`), and `cart_collide` must report 64 of 64 matched (`evidence/evidence_collide/verify.txt`).

## 9. Known harmless messages

| Message | Cause |
|---|---|
| `SyntaxWarning: invalid escape sequence …` | Python 3.12 and later warn about escape sequences in older Volatility source. No effect. |
| `The following plugins could not be loaded …` | The optional packages `yara-python`, `pycryptodome`, `capstone` and `networkx` are not installed. Only the plugins that need them are affected; Cartographer's plugins do not need them. |
| `WARNING … map 41/cart_btf is incomplete (partial recovery)` during a scan | The scanner found an old, freed copy of a map whose memory has been reused. Expected; see Table II and Section V-F of the report. |
| `BrokenPipeError` after piping into `head` | `head` closes the pipe early. No effect. |
| btf2json `… unique types are missing` | See section 4. |

## 10. Directory layout on the test machine

```
~/DF_proj/
├── final.lime          main memory image (not in the repository)
├── collide.lime        collision-test image (not in the repository)
├── truth_*.txt         ground truth printed by the loaders
├── btf.raw             BTF captured from /sys/kernel/btf/vmlinux
├── kallsyms.map        captured /proc/kallsyms
├── symbols/            generated profile kali-6.12.38.json
├── vol3-pinned/        Volatility 3 @ 18e5d7a with BPFVol3 and Cartographer installed
├── BPFVol3/            upstream BPFVol3 clone @ 4123d3f
├── lemon/              LEMON v2.0 build
├── evidence/           output of collect_evidence.sh
├── evidence_collide/   output of collect_collide.sh
├── evidence_borrow/    output of the borrowed-BTF run
└── ICT3215_Digital_Forensics_Proj/   this repository
~/cart-venv/            Python virtual environment
```
