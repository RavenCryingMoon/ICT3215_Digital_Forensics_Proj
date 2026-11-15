# bpf_scanmaps.py — optional, best-effort scanner for orphaned BPF maps.
#
# Finds bpf_map structures by scanning the kernel's virtual address space for
# their `ops` pointer. Every hash map's bpf_map.ops points at the kernel's
# shared htab_map_ops table (a fixed symbol address), so a map can be found by
# that fingerprint even when it has been unlinked from map_idr AND is used by
# no program — the case neither the registry walk nor the program walk reaches.
#
# Each hit is labelled in the SCAN column:
#   in idr       the registry points at this exact structure (a normal live map)
#   dup of live  same id and name as a registered map but at another address:
#                a second copy of a live map, not a separate map
#   freed        id is 0; the kernel clears a map's id when it frees it normally
#   ORPHANED     none of the above: not registered, not a copy of a registered
#                map, not freed the normal way. A deliberately unlinked map
#                lands here, but so can a copy of a map that no longer exists.
#   ORPHANED xN  as ORPHANED, but the same id and name turned up N times
#
# ORPHANED hits that carry BTF are probed and marked:
#   (live)  the map's type information still decodes, as a live map's does
#   (dead)  it had BTF but the BTF no longer reads: a dead map or a stale copy
# A recently freed map can still pass as (live), so read (live) as strong
# evidence rather than proof. Maps without BTF get no marker.
#
# Borrowed BTF: a dead map's own BTF is usually gone, but its header still
# records its name, sizes and type numbers. If a map whose BTF still reads has
# the same name, map type, key and value sizes and type numbers, it came from
# the same program, so its BTF is used to decode the dead map. The SCAN label
# then ends in ", BTF from id N" and the dump file name ends in _btf<N>, so a
# borrowed decoding is never mistaken for the map's own. Unnamed maps never
# borrow: a name is required to make the match.
#
# Borrowing is OFF unless --borrow-btf is given. In testing, a freed map's
# header outlived its data: the chain walk led into memory the kernel had
# reused, and borrowed field names made that garbage look like real records.
# Treat borrowed decodings as unverified.
#
# This is an isolated, opt-in plugin; it cannot affect the core plugins. It
# emits [scanmaps] diagnostics on stderr so the pipeline can be inspected.
#
# Place in: volatility3/framework/plugins/linux/bpf_scanmaps.py
# Run:      vol.py -s ../symbols -f ../image.lime -o ../out linux.bpf_scanmaps.ScanMaps --dump
#           add --borrow-btf to decode dead maps with a matching live map's BTF

import logging
import struct

from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.utility.datastructures import XArray
from volatility3.utility.map import BpfMap

vollog = logging.getLogger(__name__)


class ScanMaps(plugins.PluginInterface):
    """Scan memory for bpf_map structures by their ops pointer, recovering
    maps even when unlinked from map_idr and used by no program."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 0, 8)

    OPS_SYMBOLS = (
        "htab_map_ops",
        "htab_lru_map_ops",
        "htab_percpu_map_ops",
        "htab_lru_percpu_map_ops",
        "array_map_ops",
    )

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="If set, recovered map contents are written to a file.",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="borrow_btf",
                description="Decode dead maps with the BTF of a matching live map "
                "(same name, type, sizes and type ids). Results are unverified.",
                optional=True,
                default=False,
            ),
        ]

    def _sym_addr(self, vmlinux, name):
        """Absolute virtual address of a symbol, or None."""
        try:
            return vmlinux.get_absolute_symbol_address(name)
        except Exception:
            pass
        try:
            return int(vmlinux.object_from_symbol(symbol_name=name).vol.offset)
        except Exception:
            return None

    def _registry(self, vmlinux):
        """Maps reachable through map_idr: the set of their addresses, and a
        dict from (id, name) to address, used to recognise copies of live
        maps found elsewhere in memory."""
        addrs, keys = set(), {}
        try:
            map_idr = vmlinux.object_from_symbol(symbol_name="map_idr")
            for m in XArray(map_idr.idr_rt, "bpf_map", self.context).xa_for_each():
                addr = int(m.vol.offset)
                addrs.add(addr)
                try:
                    bm = BpfMap(m, self.context)
                    keys[(int(bm.map.id), bm.name)] = addr
                except Exception:
                    pass
        except exceptions.InvalidAddressException:
            pass
        return addrs, keys

    def _label(self, map_virt, bm, reg_addrs, reg_keys, sightings, alive):
        """How this hit relates to the registry (see the table at the top)."""
        key = (int(bm.map.id), bm.name)
        if map_virt in reg_addrs:
            return "in idr"
        if key in reg_keys:
            return "dup of live"
        if key[0] == 0:
            return "freed"
        label = "ORPHANED"
        if sightings[key] > 1:
            label += f" x{sightings[key]}"
        if alive is True:
            label += " (live)"
        elif alive is False:
            label += " (dead)"
        return label

    def _btf_alive(self, bm):
        """Whether the map's BTF can still be read.

        True: its type information decodes, as a live map's does.
        False: it had BTF, but the BTF no longer reads (dead map or stale copy).
        None: it never had BTF, so there is no signal either way.

        Decoding zero-filled buffers touches the same type entries, member
        entries and names that decoding real data does, without needing any
        of the map's own entries, so it also works on empty maps.
        """
        try:
            btf_ptr = int(bm.map.btf)
        except Exception:
            return None
        key_id, value_id = bm.btf_key_type_id, bm.btf_value_type_id
        if btf_ptr == 0 or not (key_id or value_id):
            return None
        if bm.btf is None:  # had a BTF pointer, but the object would not load
            return False
        try:
            if key_id:
                size = min(int(bm.map.key_size), 1 << 22)
                bm.btf.sprintf_bytes(b"\x00" * size, key_id)
            if value_id:
                size = min(int(bm.map.value_size), 1 << 22)
                bm.btf.sprintf_bytes(b"\x00" * size, value_id)
        except Exception:
            return False
        return True

    @staticmethod
    def _match_key(bm):
        """What two maps must share for one to lend its BTF to the other."""
        return (
            bm.name,
            str(bm.type),
            int(bm.map.key_size),
            int(bm.map.value_size),
            bm.btf_key_type_id,
            bm.btf_value_type_id,
        )

    def _borrow_btf(self, bm, donors):
        """Give a map whose own BTF is unreadable the BTF of a matching map.
        Returns the donor's id, or None when there is no safe match."""
        if not bm.name:
            return None
        donor = donors.get(self._match_key(bm))
        if donor is None:
            return None
        own = bm.btf
        bm.btf = donor.btf
        if self._btf_alive(bm) is True:      # the donor's types fit this map
            return int(donor.map.id)
        bm.btf = own
        return None

    def _dump(self, map_virt, bm, suffix=""):
        """Write the map's contents: decoded when its BTF is readable, raw
        bytes otherwise (a freed map's BTF is often already unmapped)."""
        try:
            text = bm.dump()
        except Exception:
            try:
                text = bm.dump(raw=True)
                vollog.debug(
                    f"[scanmaps] map {bm.label}: BTF unreadable, dumped raw bytes"
                )
            except Exception:
                return
        try:
            with self.open(f"scan_{hex(map_virt)}_{bm.map.id}{suffix}") as f:
                f.write(text.encode("UTF-8"))
        except Exception:
            pass

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        dump = bool(self.config.get("dump"))
        borrow = bool(self.config.get("borrow_btf"))
        layer = self.context.layers[vmlinux.layer_name]  # kernel virtual layer

        ops_off = vmlinux.get_type("bpf_map").vol.members["ops"][0]

        # Fingerprint: each ops table's address, little-endian.
        # Volatility reports symbol addresses in its 48-bit address space, but
        # the pointer actually stored in memory is the full canonical 64-bit
        # kernel address (top 16 bits set). Search for both forms.
        needles = {}
        for sym in self.OPS_SYMBOLS:
            addr = self._sym_addr(vmlinux, sym)
            if addr is None:
                continue
            forms = {addr}
            if addr & (1 << 47):
                forms.add(addr | 0xFFFF000000000000)
            for form in forms:
                needles[struct.pack("<Q", form)] = sym

        resolved = {needles[k]: hex(struct.unpack("<Q", k)[0]) for k in needles}
        vollog.debug(f"[scanmaps] ops_off={ops_off} needles={len(needles)} {resolved}")
        if not needles:
            vollog.warning("[scanmaps] no ops symbols resolved; nothing to scan")
            return

        # Pass 1: collect every hit that looks like a real map.
        seen, found, hits = set(), [], 0
        scanner = scanners.MultiStringScanner(list(needles.keys()))
        for offset, _pattern in layer.scan(context=self.context, scanner=scanner):
            hits += 1
            map_virt = offset - ops_off
            if map_virt in seen:
                continue
            seen.add(map_virt)
            try:
                bm = BpfMap(map_virt, self.context)
                ks = int(bm.map.key_size)
                vs = int(bm.map.value_size)
                me = int(bm.map.max_entries)
                # reject stray pointers: a real map has sane sizes
                if not (0 < ks <= 4096 and 0 < vs and 0 < me <= 10_000_000):
                    continue
                _ = bm.name  # force a name read; garbage hits throw here
            except Exception:
                continue
            found.append((map_virt, bm))
        vollog.debug(f"[scanmaps] raw hits={hits}, validated maps={len(found)}")

        # Pass 2: compare against the registry, count repeats, then label.
        reg_addrs, reg_keys = self._registry(vmlinux)
        sightings = {}
        for _, bm in found:
            key = (int(bm.map.id), bm.name)
            sightings[key] = sightings.get(key, 0) + 1

        # Whose BTF still reads, and which of those can lend it (registered first).
        alive = {map_virt: self._btf_alive(bm) for map_virt, bm in found}
        donors = {}
        for map_virt, bm in sorted(found, key=lambda f: f[0] not in reg_addrs):
            if alive[map_virt] is True and bm.name:
                donors.setdefault(self._match_key(bm), bm)

        for map_virt, bm in found:
            label = self._label(map_virt, bm, reg_addrs, reg_keys, sightings, alive[map_virt])
            suffix = ""
            if borrow and alive[map_virt] is False:
                donor_id = self._borrow_btf(bm, donors)
                if donor_id is not None:
                    label += f", BTF from id {donor_id} (unverified)"
                    suffix = f"_btf{donor_id}"
                    vollog.debug(f"[scanmaps] map {bm.label}: decoding with BTF of map {donor_id}")
            if dump:
                self._dump(map_virt, bm, suffix)
            yield (0, (*bm.row(), label))

    def run(self):
        columns = [
            ("OFFSET (V)", str),
            ("ID", int),
            ("TYPE", str),
            ("NAME", str),
            ("KEY SIZE", int),
            ("VALUE SIZE", int),
            ("MAX ENTRIES", int),
            ("STATUS", str),
            ("SCAN", str),
        ]
        return renderers.TreeGrid(columns, self._generator())
