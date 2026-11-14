# find_next.py — test helper for Cartographer's safety layer.
#
# Finds a BPF hash-map element, works out the FILE offset of its `next` pointer
# (the first 8 bytes of the element), and — if --outfile is given — overwrites
# that pointer with the element's own address, turning the chain into a
# self-loop. Running the map dumper on the corrupted copy then makes that map
# trip the cycle guard and report "partial".
#
# It prefers a bucket whose head element CHAINS to another element, so the
# self-loop orphans the rest of that chain and the recovered entry count drops
# (a visible before/after). If no chained bucket exists it falls back to any
# non-empty bucket (corruption is still detected, but no entries are hidden).
#
# This is a test fixture, not part of the recovery code.
#
# Place in: volatility3/framework/plugins/linux/find_next.py
# Run:      vol.py -s ../symbols -f ../kali2.lime linux.find_next.FindNext \
#                  --htab 0x8b7907a6ec00 --outfile ../kali2_cycle.lime

import struct

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins


class FindNext(plugins.PluginInterface):
    """Locate (and optionally corrupt) a hash-map element's next pointer."""

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
                name="htab",
                description="offset of the bpf_map, from the MapList OFFSET column "
                "(e.g. 0x8b7907a6ec00)",
                optional=False,
            ),
            requirements.StringRequirement(
                name="outfile",
                description="path to a COPY of the image to corrupt; omit to only print",
                optional=True,
                default=None,
            ),
        ]

    def _first(self, vmlinux, addr):
        """head element pointer of the bucket at addr, as an int."""
        b = vmlinux.object("bucket", offset=addr, absolute=True)
        return int(b.head.first)

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        off = int(self.config["htab"], 0)

        htab = vmlinux.object("bpf_htab", offset=off, absolute=True)
        base = int(htab.buckets)
        bsz = int(vmlinux.get_type("bucket").size)
        n = int(htab.n_buckets)

        ev = None
        bucket_i = None
        chained = False

        # pass 1: prefer a bucket whose head element chains to a second element
        for i in range(n):
            first = self._first(vmlinux, base + i * bsz)
            if first & 1:
                continue  # empty bucket (nulls marker)
            elem = vmlinux.object("htab_elem", offset=first, absolute=True)
            nxt = int(elem.hash_node.next)
            if not (nxt & 1):  # points to another element -> a real chain
                ev, bucket_i, chained = first, i, True
                break

        # pass 2: fall back to any non-empty bucket
        if ev is None:
            for i in range(n):
                first = self._first(vmlinux, base + i * bsz)
                if not (first & 1):
                    ev, bucket_i = first, i
                    break

        if ev is None:
            raise ValueError("no non-empty bucket found in this map")

        # virtual address -> physical -> offset inside the image file
        virt = self.context.layers[vmlinux.layer_name]
        paddr, phys_name = virt.translate(ev)
        foff, _ = self.context.layers[phys_name].translate(paddr)
        foff = int(foff)

        action = "printed only (no --outfile)"
        if self.config.get("outfile"):
            with open(self.config["outfile"], "r+b") as f:
                f.seek(foff)
                f.write(struct.pack("<Q", ev))
            action = f"wrote self-pointer into {self.config['outfile']}"

        return renderers.TreeGrid(
            [
                ("bucket", int),
                ("chained", str),
                ("elem_vaddr", str),
                ("next_file_offset", int),
                ("action", str),
            ],
            [(0, (bucket_i, "yes" if chained else "no", hex(ev), foff, action))],
        )
