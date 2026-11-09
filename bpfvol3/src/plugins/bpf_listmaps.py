# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
A Volatility3 plugin that tries to display information
typically accessed via bpftool map (list|dump) subcommands
"""
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, ClassVar, Optional

from volatility3.framework import exceptions
from volatility3.framework.objects.utility import array_of_pointers
from volatility3.utility.helpers import make_vol_type

from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.framework.renderers import TreeGrid
from volatility3.utility.datastructures import XArray
from volatility3.utility.map import BpfMap

if TYPE_CHECKING:
    from volatility3.framework.interfaces.objects import ObjectInterface


class MapList(PluginInterface):
    """Lists the BPF maps present in a particular Linux memory image."""

    _required_framework_version: ClassVar = (2, 0, 0)

    _version: ClassVar = (0, 0, 0)

    @classmethod
    def get_requirements(
        cls,
    ) -> list[RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="id",
                description="Filter on specific BPF map IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="If True, map contents are written to a file.",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="raw",
                description="If set, dump raw bytes instead of BTF-decoded "
                "values (for verification against ground truth).",
                optional=True,
                default=False,
            ),
        ]

    def _generator(
        self,
        filter_func: Callable[[BpfMap], bool] = lambda _: False,
        dump: bool = False,
        raw: bool = False,
    ) -> Iterable[tuple[int, tuple]]:
        """Generates the BPF map list
                Args:
                    filter_func: A function which takes a BPF map object and
                        returns True if the map should be ignored/filtered
                    dump: If True, full map contents are written to a file
                Yields:
                    Each row
                """
        for m in self.list_maps(
            self.context, self.config["kernel"], filter_func
        ):
            if dump:
                with self.open(
                    f"map_{hex(m.map.vol.get('offset'))}_{m.map.id}"
                ) as f:
                    f.write(m.dump(raw=raw).encode("UTF-8"))
            yield (0, (*m.row(), getattr(m, "source", "idr")))

    @classmethod
    def list_maps(
        cls,
        context: ContextInterface,
        vmlinux_module_name: str = "kernel",
        filter_func: Callable[[BpfMap], bool] = lambda _: False,
    ) -> Iterable[BpfMap]:
        """Lists BPF maps found through multiple roots: the map registry
        (map_idr) and the maps referenced by loaded programs (used_maps).
        Maps are de-duplicated by address, and each gets a `source` marker
        (idr, prog, or idr+prog) showing how it was reached."""
        vmlinux: ModuleInterface = context.modules[vmlinux_module_name]

        seen: dict[int, BpfMap] = {}   # map offset -> BpfMap (with .source set)

        # Source A: the map registry.
        map_idr: ObjectInterface = vmlinux.object_from_symbol(
            symbol_name="map_idr"
        )
        for m in XArray(map_idr.idr_rt, "bpf_map", context).xa_for_each():
            bm: BpfMap = BpfMap(m, context)
            seen[int(bm.map.vol.offset)] = bm
            bm.source = "idr"

        # Source B: maps referenced by loaded programs (prog_idr -> used_maps).
        prog_idr: ObjectInterface = vmlinux.object_from_symbol(
            symbol_name="prog_idr"
        )
        for prog in XArray(prog_idr.idr_rt, "bpf_prog", context).xa_for_each():
            try:
                aux = prog.aux
                n = int(aux.used_map_cnt)
                if n <= 0:
                    continue
                map_ptrs = array_of_pointers(
                    aux.used_maps.dereference(),
                    n,
                    make_vol_type("bpf_map", context),
                    context,
                )
                for mp in map_ptrs:
                    bm = BpfMap(mp, context)
                    off = int(bm.map.vol.offset)
                    if off in seen:
                        if seen[off].source == "idr":
                            seen[off].source = "idr+prog"
                    else:
                        bm.source = "prog"
                        seen[off] = bm
            except exceptions.InvalidAddressException:
                continue

        # Yield unique maps, applying the caller's filter.
        for bm in seen.values():
            if filter_func(bm):
                continue
            yield bm

    @classmethod
    def create_filter(
        cls,
        id_list: Optional[list[int]] = None,
    ) -> Callable[[BpfMap], bool]:
        """Constructs a filter function for BPF maps
        Args:
            id_list: List of BPF map IDs that are acceptable
                (or None if all are acceptable)
        Returns:
            Function which, when provided a BPF map object, returns True
            iff the map is to be filtered out of the list
        """
        id_list = id_list or []
        id_filter_list: list[int] = [x for x in id_list if x is not None]
        if id_filter_list:

            def filter_func(x: BpfMap) -> bool:
                return int(x.map.id) not in id_filter_list

            return filter_func

        return lambda _: False

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("OFFSET (V)", str),
            ("ID", int),
            ("TYPE", str),
            ("NAME", str),
            ("KEY SIZE", int),
            ("VALUE SIZE", int),
            ("MAX ENTRIES", int),
            ("STATUS", str),
            ("SOURCE", str),
        ]

        filter_func: Callable[[BpfMap], bool] = self.create_filter(
            self.config.get("id", None)
        )
        dump: bool = bool(self.config.get("dump"))
        raw: bool = bool(self.config.get("raw"))

        return TreeGrid(
            columns,
            self._generator(filter_func, dump, raw),
        )
