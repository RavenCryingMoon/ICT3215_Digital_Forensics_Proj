# unlink_map.py — test fixture for Cartographer's multi-root discovery.
#
# Zeroes the map_idr slot that points at a given map, in a COPY of the image.
# This models a rootkit that has unlinked its map from the kernel's map
# registry (so a registry walk — and a live `bpftool` — go blind to it) while
# a loaded program keeps using it. Running the map plugin on the edited copy
# then recovers that map only through the program path (SOURCE = prog), proving
# multi-root discovery sees what the registry alone cannot.
#
# This is a test fixture, not part of the recovery code. It edits a frozen
# image file; it does not touch any live system.
#
# Place in: volatility3/framework/plugins/linux/unlink_map.py
# Run (reads the original to locate the slot, writes zeros into the copy):
#   cp kali_hide.lime kali_hide_unlinked.lime
#   vol.py -s ../symbols -f ../kali_hide.lime linux.unlink_map.UnlinkMap \
#          --map 0x8b7907a72400 --outfile ../kali_hide_unlinked.lime

import struct

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins

# An xa_node holds this many slots when CONFIG_BASE_SMALL=0 (the usual case).
XA_CHUNK_SIZE = 64
# Entries with these low bits set are internal (a pointer to another node),
# not a user pointer — same test the XArray helper uses.
XA_NODE_THRESHOLD = 0x1000


class UnlinkMap(plugins.PluginInterface):
    """Simulate a map unlinked from map_idr by zeroing its registry slot."""

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
                description="bpf_map virtual offset, from the MapList OFFSET "
                "column (e.g. 0x8b7907a72400)",
                optional=False,
            ),
            requirements.StringRequirement(
                name="outfile",
                description="path to a COPY of the image to edit; omit to only print",
                optional=True,
                default=None,
            ),
        ]

    def _is_node(self, entry):
        """True if an xarray entry points to another node (not a user pointer)."""
        return (entry & 0b11) == 0b10 and entry > XA_NODE_THRESHOLD

    def _to_node(self, vmlinux, entry):
        """Turn a node entry into the xa_node it points at."""
        return vmlinux.object("xa_node", offset=entry - 0b10, absolute=True)

    def _find_slot(self, vmlinux, node, target, depth=0):
        """Virtual address of the slot in this subtree holding `target`, or None."""
        if depth > 6:  # radix tree is shallow; guard against a bad pointer loop
            return None
        for i in range(XA_CHUNK_SIZE):
            slot = node.slots[i]
            entry = int(slot)
            if entry == 0:
                continue
            if self._is_node(entry):
                found = self._find_slot(
                    vmlinux, self._to_node(vmlinux, entry), target, depth + 1
                )
                if found is not None:
                    return found
            elif entry == target:         # a user pointer equal to our map's address
                return int(slot.vol.offset)
        return None

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        target = int(self.config["map"], 0)

        map_idr = vmlinux.object_from_symbol(symbol_name="map_idr")
        head = int(map_idr.idr_rt.xa_head)

        slot_vaddr = None
        if head == 0:
            pass
        elif self._is_node(head):
            slot_vaddr = self._find_slot(
                vmlinux, self._to_node(vmlinux, head), target
            )
        elif head == target:
            # single-entry xarray: the head field itself holds the pointer
            slot_vaddr = int(map_idr.idr_rt.xa_head.vol.offset)

        if slot_vaddr is None:
            raise ValueError(
                f"map {hex(target)} not found in map_idr "
                "(check the OFFSET value)"
            )

        # virtual -> physical -> offset inside the image file
        virt = self.context.layers[vmlinux.layer_name]
        paddr, phys_name = virt.translate(slot_vaddr)
        foff, _ = self.context.layers[phys_name].translate(paddr)
        foff = int(foff)

        action = "printed only (no --outfile)"
        if self.config.get("outfile"):
            with open(self.config["outfile"], "r+b") as f:
                f.seek(foff)
                f.write(struct.pack("<Q", 0))   # zero the 8-byte slot
            action = f"zeroed map_idr slot in {self.config['outfile']}"

        return renderers.TreeGrid(
            [
                ("map", str),
                ("slot_vaddr", str),
                ("slot_file_offset", int),
                ("action", str),
            ],
            [(0, (hex(target), hex(slot_vaddr), foff, action))],
        )
