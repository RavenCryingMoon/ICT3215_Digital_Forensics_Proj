# Environment and reproduction

This file records the exact environment used to develop and test Cartographer, and the steps needed to reproduce the results. Steps marked **TODO** still need the exact command that was used on the test machine.

Last verified: 2026-10-14 (the `cart_hash` recovery matches `tests/truth/cart_hash.truth.json`).

## 1. Test system

| Item | Value |
|---|---|
| OS | Kali Linux (rolling), x86_64 |
| Kernel | `6.12.38+kali-amd64` |
| Python | 3.13 (system), virtual environment at `~/cart-venv` |

The memory image and the symbol profile both belong to this exact kernel build.

- `apt update` only refreshes the package lists and is safe.
- `apt upgrade` and `apt full-upgrade` can install a newer kernel. Neither should be run on the test machine until the evaluation is finished.
- Kali rolling no longer carries `linux-image-6.12.38+kali-amd64-dbg`, so a DWARF-based profile can no longer be built for this kernel (see section 4).

## 2. Pinned components

| Component | Version | Role |
|---|---|---|
| Volatility 3 | commit `18e5d7a7f2e2a85d0178307dd502e2729488e93a` (reports 2.5.2) | Memory analysis framework |
| BPFVol3 | commit `4123d3f` (MIT, Valentin Obst) | BPF plugins that this project extends |
| btf2json | commit `4a64f9c` | Builds the symbol profile from BTF and kallsyms |
| LEMON | v2.0, commit `e133938`, built with `make MODE=core` | Memory acquisition (LiME format) |

## 3. Memory image

| Item | Value |
|---|---|
| File | `kali.lime` (LiME format) |
| Acquired with | LEMON v2.0 on the test system, after the test maps were planted |
| SHA-256 | `4937393f3e6a4846772273ce470516e9124ee89f724bccbf88707c284bf9725a` |

The image is not stored in this repository because of its size, and because a memory image can contain sensitive data. Obtain it from the team share and check it before use:

```
sha256sum kali.lime
```

> **TODO:** add the LEMON acquisition command and the procedure used to plant the test maps.

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
print({s:s in j['symbols'] for s in ['map_idr','linux_banner','init_task']})"
```

Every value printed must be `True`.

## 5. Volatility 3 and BPFVol3

> **TODO:** add the exact commands used to clone Volatility at the pinned commit, create `~/cart-venv` and install its requirements, and install BPFVol3 into it (file copies and BPFVol3's Volatility patch).

After installation, BPFVol3's files sit inside the Volatility tree:

| BPFVol3 source | Location in `vol3-pinned` |
|---|---|
| `src/plugins/*` | `volatility3/framework/plugins/linux/` (for example `bpf_listmaps.py`) |
| `src/utility/*` | `volatility3/utility/` (for example `map.py`) |

The schema of the pinned Volatility only accepts symbol profiles whose sources are of kind `dwarf`, `symtab` or `system-map`. btf2json records its sources with kinds this version does not list (`btf`, `symdb`), so the schema needs one change. The command does nothing if the change is already in place:

```
cd ~/DF_proj/vol3-pinned
grep -q 'btf|symdb' volatility3/schemas/schema-6.2.0.json || \
  sed -i 's/"\^(dwarf|symtab|system-map)\$"/"^(btf|symdb|dwarf|symtab|system-map)$"/' volatility3/schemas/schema-6.2.0.json
```

### Linking the repository copy

This project changes `volatility3/utility/map.py`. To make sure Volatility always loads the version in this repository, the installed file is replaced with a symbolic link to it:

```
ln -sf ~/DF_proj/cartographer/bpfvol3/src/utility/map.py \
       ~/DF_proj/vol3-pinned/volatility3/utility/map.py
find ~/DF_proj/vol3-pinned -name __pycache__ -type d -exec rm -rf {} +
```

Edits to the repository file then take effect on the next run without any copying. The link follows whichever branch is checked out in the repository. Any other file this project changes later should be linked the same way.

## 6. Running the plugin

```
cd ~/DF_proj/vol3-pinned
rm -rf ../out && mkdir -p ../out
~/cart-venv/bin/python vol.py -s ../symbols -f ../kali.lime -o ../out linux.bpf_listmaps.MapList --dump
ls -la ../out/
```

- The output directory must exist before the run.
- Each map's contents are written to a hidden file named `.map_<offset>_<id>`, so the files only show up with `ls -a`.
- Volatility never overwrites an output file. If a file of the same name already exists, the new one is written as `-1.map_…`, `-2.map_…` and so on. Emptying `out/` before every run keeps the files from the latest run only.
- Global options such as `-v` or `-vv` must come before the plugin name, for example `vol.py -vv -s ../symbols … linux.bpf_listmaps.MapList --dump`. Placed after the plugin name, they are rejected and Volatility exits without running.

## 7. Expected results

Map list (columns aligned for readability):

```
OFFSET (V)      ID  TYPE          NAME             KEY SIZE  VALUE SIZE  MAX ENTRIES
0x8e43c7833c00  22  HASH_OF_MAPS  cgroup_hash      8         4           2048
0x8e43ca8f1600  23  ARRAY         cart_arr         4         8           4
0x8e43c3e6a400  24  HASH          cart_hash        4         8           16
0x9a4592531ef8  26  ARRAY         read_mem_array_  4         2097156     1
0x9a458070def8  28  ARRAY         mem_ebp.kconfig  4         9           1
```

`cart_arr` and `cart_hash` are the planted test maps. `read_mem_array_` and `mem_ebp.kconfig` belong to LEMON's own eBPF reader. `cgroup_hash` was already present on the system.

`cart_hash` dump (`.map_0x8e43c3e6a400_24`, 38 bytes):

```
{"b'9\\x05\\x00\\x00'": "b'CARTOGR1'"}
```

| Field | Bytes | Meaning |
|---|---|---|
| Key | `39 05 00 00` | 1337 (32-bit, little-endian) |
| Value | `43 41 52 54 4f 47 52 31` | ASCII `CARTOGR1` |

This matches `tests/truth/cart_hash.truth.json`. The doubled backslashes are JSON escaping of Python's text form of the bytes. The map has no BTF information attached, so the bytes are shown undecoded.

`cart_arr` dump (`.map_0x8e43ca8f1600_23`): index 1 holds `11 22 33 44 55 66 77 88`; indexes 0, 2 and 3 are zero.

`cgroup_hash` dumps `{}` because `HASH_OF_MAPS` is not a supported map type.

## 8. Known harmless messages

| Message | Cause |
|---|---|
| `SyntaxWarning: invalid escape sequence …` | Python 3.12 and later warn about escape sequences in older Volatility source. No effect. |
| `The following plugins could not be loaded …` | The optional packages `yara-python`, `pycryptodome`, `capstone` and `networkx` are not installed. Only the plugins that need them are affected; `bpf_listmaps` does not need them. |
| `BrokenPipeError` after piping into `head` | `head` closes the pipe early. No effect. |
| btf2json `… unique types are missing` | See section 4. |

## 9. Directory layout on the test machine

```
~/DF_proj/
├── kali.lime        memory image (not in the repository)
├── btf.raw          BTF captured from /sys/kernel/btf/vmlinux
├── kallsyms.map     captured /proc/kallsyms
├── symbols/         generated profile kali-6.12.38.json
├── vol3-pinned/     Volatility 3 @ 18e5d7a with BPFVol3 installed
├── BPFVol3/         upstream BPFVol3 clone @ 4123d3f
├── out/             plugin output
└── cartographer/    this repository
~/cart-venv/         Python virtual environment
```
