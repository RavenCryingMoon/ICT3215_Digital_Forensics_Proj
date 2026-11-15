# chain_stats.py — test helper for Cartographer's evaluation.
#
# Counts how many entries sit in each bucket of one hash map, read straight
# from the memory image, so the report can show that hash collisions (buckets
# holding a chain of two or more entries) really occurred. It walks the
# buckets on its own, without using map.py, so it is an independent check on
# the recovery code.
#
# Place in: volatility3/framework/plugins/linux/chain_stats.py
# Run:      vol.py -s ../symbols -f ../collide.lime linux.chain_stats.ChainStats --map 0x<OFFSET>
#           (OFFSET = the map's OFFSET (V) column in the MapList output)

import struct

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins

ADDR_MASK = 0xFFFFFFFFFFFF   # Volatility shows kernel addresses in 48-bit form


class ChainStats(plugins.PluginInterface):
    """Chain length per bucket of one eBPF hash map (test helper)."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 0, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="map",
                description="bpf_map virtual offset, from the MapList OFFSET column",
                optional=False,
            ),
        ]

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[vmlinux.layer_name]
        addr = int(self.config["map"], 0)

        def read_ptr(a):
            return struct.unpack("<Q", layer.read(a & ADDR_MASK, 8))[0]

        # bpf_map is the first member of bpf_htab, so the map address is the htab address
        htab = vmlinux.object("bpf_htab", offset=addr, absolute=True)
        n_buckets = int(htab.n_buckets)
        max_entries = int(htab.map.max_entries)
        buckets = int(htab.buckets)
        try:
            bucket_size = vmlinux.get_type("bucket").size
        except Exception:
            bucket_size = 16          # struct bucket = hlist_nulls_head (8) + spinlock, padded

        lengths = []
        problems = 0
        for i in range(n_buckets):
            # struct bucket starts with hlist_nulls_head.first; an htab_elem starts
            # with its hlist_nulls_node, whose first field is next. A pointer with
            # the low bit set is the end-of-chain marker.
            p = read_ptr(buckets + i * bucket_size)
            seen, n = set(), 0
            while not (p & 1):
                if p in seen or n > max_entries:
                    problems += 1
                    break
                seen.add(p)
                n += 1
                p = read_ptr(p)
            lengths.append(n)

        total = sum(lengths)
        hist = {}
        for n in lengths:
            hist[n] = hist.get(n, 0) + 1
        hist_txt = ", ".join(f"{k} entr{'y' if k == 1 else 'ies'}: {v}" for k, v in sorted(hist.items()))

        return renderers.TreeGrid(
            [
                ("MAP", str),
                ("BUCKETS", int),
                ("ENTRIES", int),
                ("EMPTY BUCKETS", int),
                ("BUCKETS WITH 2+", int),
                ("LONGEST CHAIN", int),
                ("BUCKETS BY CHAIN LENGTH", str),
                ("WALK PROBLEMS", int),
            ],
            [(0, (
                hex(addr), n_buckets, total,
                sum(1 for n in lengths if n == 0),
                sum(1 for n in lengths if n >= 2),
                max(lengths) if lengths else 0,
                hist_txt, problems,
            ))],
        )
