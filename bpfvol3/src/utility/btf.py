# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
This file contains classes for working with BPF type information.
"""
import logging
from collections.abc import Iterable
from typing import ClassVar, Optional

from volatility3.framework import constants, interfaces
from volatility3.framework.objects.utility import array_of_pointers
from volatility3.utility.enums import BtfKind
from volatility3.utility.helpers import (
    get_object,
    get_vol_template,
    make_vol_type,
)

vollog = logging.getLogger(__name__)


class BtfError(Exception):
    """Raised when obtaining BTF is not possible"""


class Btf:
    """Wraps a struct btf and implements, e.g., pretty printing of data
    by using type information."""

    # Map a kind to the type of the data that follows it
    kind_to_vtype: ClassVar = {BtfKind.BTF_KIND_DATASEC: "btf_var_secinfo"}

    def __init__(
        self,
        btf: interfaces.objects.ObjectInterface,
        context: interfaces.context.ContextInterface,
    ):
        self.btf = btf
        self.context = context
        if self.btf.has_valid_member("types"):
            self.types = array_of_pointers(
                self.btf.types.dereference(),
                self.btf.nr_types,
                make_vol_type("btf_type", self.context),
                self.context,
            )
        else:
            raise BtfError

    def get_string(self, type_id) -> str:
        btf_type = self._type_by_id(type_id)
        return self._get_string(btf_type.name_off)

    def sprintf_bytes(
        self,
        b: bytes,
        type_id: int,
        btf_type: Optional[interfaces.objects.ObjectInterface] = None,
    ) -> str:
        """Pretty print a bytes array using its BPF type information.
        inspired by "bpf_snprintf_btf" helper, "btf_type_show" in particular
        """
        s = ""
        if not btf_type:
            btf_type = self._type_by_id(type_id)
        kind_flag, kind, vlen = self._parse_info(int(btf_type.info))

        # check "btf_kind_operations" for implementation details
        if kind == BtfKind.BTF_KIND_DATASEC:
            # btf_datasec_show
            s += f"section ({self._get_string(btf_type.name_off)}) = " + "{\n"
            for vsi in self._list_vector(btf_type, kind, vlen):
                s += self.sprintf_bytes(
                    b[vsi.offset : vsi.offset + vsi.size], vsi.type
                )
        elif kind == BtfKind.BTF_KIND_VAR:
            # btf_var_show
            s += f" ({self._get_string(btf_type.name_off)})"
            type_id, btf_type = self._type_id_resolve(type_id)
            s += self.sprintf_bytes(b, type_id, btf_type=btf_type)
        elif kind == BtfKind.BTF_KIND_ARRAY:
            arr = get_object(
                "btf_array", btf_type.vol.offset + btf_type.vol.size, self.context)
            elem_type_id = int(arr.type)
            nelems = int(arr.nelems)
            elem_size = self._type_size(elem_type_id) or 1
            if elem_size == 1:
                # byte/char array: show as text if printable, else capped hex.
                text = bytes(b[:nelems]).split(b"\x00", 1)[0]
                if all(0x20 <= c < 0x7F for c in text[:256]):   # empty -> "" (all() is True)
                    s += '"' + text[:256].decode("ascii", "replace") + '"'
                else:
                    head = bytes(b[:64])
                    more = " ..." if nelems > 64 else ""
                    s += "[" + " ".join(format(c, "02x") for c in head) + more + "]"
            else:
                MAX = 64   # cap multi-byte arrays too, just in case
                shown = min(nelems, MAX)
                parts = [
                    self.sprintf_bytes(b[i * elem_size:(i + 1) * elem_size], elem_type_id)
                    for i in range(shown)
                ]
                more = ", ..." if nelems > shown else ""
                s += "[" + ", ".join(parts) + more + "]"
        elif kind in (BtfKind.BTF_KIND_STRUCT, BtfKind.BTF_KIND_UNION):
            # The header is followed by `vlen` btf_member entries.
            msize_tmpl = get_vol_template("btf_member", self.context).vol.size
            start = btf_type.vol.offset + btf_type.vol.size
            parts = []
            for i in range(vlen):
                m = get_object("btf_member", start + i * msize_tmpl, self.context)
                mname = self._get_string(m.name_off)
                byte_off = (int(m.offset) & 0xFFFFFF) // 8   # bit offset -> byte offset
                msz = self._type_size(int(m.type))
                mbytes = b[byte_off:byte_off + msz] if msz else b[byte_off:]
                parts.append(f"{mname}: " + self.sprintf_bytes(mbytes, int(m.type)))
            s += "{" + ", ".join(parts) + "}"
        # NEW: typedef / const / volatile / restrict / type_tag just wrap another
        # type and carry no bytes of their own — decode the underlying type with
        # the same bytes. (This is what makes __u32 resolve to its int.)
        elif kind in (
            BtfKind.BTF_KIND_TYPEDEF,
            BtfKind.BTF_KIND_CONST,
            BtfKind.BTF_KIND_VOLATILE,
            BtfKind.BTF_KIND_RESTRICT,
            BtfKind.BTF_KIND_TYPE_TAG,
        ):
            s += self.sprintf_bytes(b, int(btf_type.type))

        # CHANGED: real integer decoding (was a stub that printed raw bytes).
        elif kind == BtfKind.BTF_KIND_INT:
            if isinstance(b, int):
                s += str(b)
            # An INT is followed by one u32 of "int info", sitting right after
            # the btf_type header (same place _list_vector reads trailing data).
            else:
                info_word = int(get_object(
                    "unsigned int",
                    btf_type.vol.offset + btf_type.vol.size,
                    self.context,
                ))
                encoding = (info_word >> 24) & 0x0F   # bit flags: 1=SIGNED, 2=CHAR, 4=BOOL
                bits = info_word & 0xFF               # width in bits (e.g. 32 for u32)
                nbytes = (bits // 8) or len(b)        # width in bytes; fall back to all bytes
                signed = bool(encoding & 1)
                is_bool = bool(encoding & 4)
                val = int.from_bytes(b[:nbytes], "little", signed=signed)
                if is_bool:
                    s += "true" if val else "false"
                else:
                    s += str(val)
        else:
            vollog.log(
                constants.LOGLEVEL_V,
                f"BTF kind not (yet) supported: {kind}, defaulting to"
                " hex dump",
            )
            s += f"[{' '.join(format(n, '02x') for n in list(b))}]"
        return s

    def _type_id_resolve(
        self, type_id: int
    ) -> tuple[int, interfaces.objects.ObjectInterface]:
        # btf_type_id_resolve
        type_id = self._resolved_type_id(type_id)
        return type_id, self._type_by_id(type_id)

    def get_start_id(self, btf: interfaces.objects.ObjectInterface) -> int:
        if btf.has_member("start_id"):
            # >= 5.11-rc1, 951bb64
            return int(btf.start_id)
        return 0

    def _resolved_type_id(self, type_id: int) -> int:
        # btf_resolved_type_id
        btf = self.btf

        while type_id < self.get_start_id(btf):
            btf = btf.base_btf
        return btf.resolved_ids.dereference().cast(
            "array",
            count=0xFFFF,
            subtype=get_vol_template("unsigned int", self.context),
        )[type_id - self.get_start_id(btf)]

    def _type_by_id(self, type_id: int) -> interfaces.objects.ObjectInterface:
        # btf_type_by_id
        btf = self.btf
        while type_id < self.get_start_id(btf):
            btf = btf.base_btf
        return array_of_pointers(
            btf.types.dereference(),
            btf.nr_types,
            make_vol_type("btf_type", self.context),
            self.context,
        )[type_id - self.get_start_id(btf)].dereference()

    def _get_string(self, offset: int) -> str:
        """Fetch a string from the string table"""
        return get_object(
            "char",
            self.btf.strings.dereference().vol.offset + offset,
            self.context,
        ).cast("string", max_length=100, errors="replace")

    def _parse_info(self, info: int) -> tuple[bool, BtfKind, int]:
        """Parse the btf_type.info into (kind_flag, kind, vlen)"""
        kind_flag = bool(info & 2**31)
        kind = BtfKind((info >> 24) & 0b11111)
        vlen = info & (2**15 - 1)
        return kind_flag, kind, vlen

    def _list_vector(
        self,
        btf_type: interfaces.objects.ObjectInterface,
        kind: BtfKind,
        vlen: int,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """List the vector that succeeds some kinds of types"""
        start = btf_type.vol.offset + btf_type.vol.size
        elem_type = self.kind_to_vtype.get(kind, None)
        if not elem_type:
            vollog.log(
                constants.LOGLEVEL_V,
                "Listing of vector for BTF kind not (yet) supported: "
                f"{kind}",
            )
            return []
        elem_sz = get_vol_template(elem_type, self.context).vol.size
        for i in range(vlen):
            obj = get_object(elem_type, start + elem_sz * i, self.context)
            yield obj
            
    def _skip_modifiers(self, type_id):
        """Follow typedef/const/volatile/restrict/type_tag to the real type.
        Returns (resolved_type_id, its btf_type object)."""
        bt = self._type_by_id(type_id)
        while True:
            _, kind, _ = self._parse_info(int(bt.info))
            if kind in (
                BtfKind.BTF_KIND_TYPEDEF, BtfKind.BTF_KIND_CONST,
                BtfKind.BTF_KIND_VOLATILE, BtfKind.BTF_KIND_RESTRICT,
                BtfKind.BTF_KIND_TYPE_TAG,
            ):
                type_id = int(bt.type)
                bt = self._type_by_id(type_id)
            else:
                return type_id, bt

    def _type_size(self, type_id):
        """Size in bytes of a type (after resolving typedefs/modifiers)."""
        _, bt = self._skip_modifiers(type_id)
        _, kind, _ = self._parse_info(int(bt.info))
        if kind in (
            BtfKind.BTF_KIND_INT, BtfKind.BTF_KIND_STRUCT,
            BtfKind.BTF_KIND_UNION, BtfKind.BTF_KIND_ENUM,
            BtfKind.BTF_KIND_ENUM64, BtfKind.BTF_KIND_FLOAT,
        ):
            return int(bt.size)
        if kind == BtfKind.BTF_KIND_PTR:
            return 8
        if kind == BtfKind.BTF_KIND_ARRAY:
            arr = get_object("btf_array", bt.vol.offset + bt.vol.size, self.context)
            return int(arr.nelems) * self._type_size(int(arr.type))
        return 0

    def _is_char(self, type_id):
        """True if the type is a char (an 8-bit int flagged CHAR in BTF)."""
        _, bt = self._skip_modifiers(type_id)
        _, kind, _ = self._parse_info(int(bt.info))
        if kind != BtfKind.BTF_KIND_INT:
            return False
        info_word = int(get_object(
            "unsigned int", bt.vol.offset + bt.vol.size, self.context))
        encoding = (info_word >> 24) & 0x0F
        return bool(encoding & 2)   # BTF_INT_CHAR

    def _skip_modifiers(self, type_id):
        """Follow typedef/const/volatile/restrict/type_tag to the real type.
        Returns (resolved_type_id, its btf_type object)."""
        bt = self._type_by_id(type_id)
        for _ in range(32):  # real chains are a few hops; corrupted BTF can loop
            _, kind, _ = self._parse_info(int(bt.info))
            if kind not in (
                BtfKind.BTF_KIND_TYPEDEF, BtfKind.BTF_KIND_CONST,
                BtfKind.BTF_KIND_VOLATILE, BtfKind.BTF_KIND_RESTRICT,
                BtfKind.BTF_KIND_TYPE_TAG,
            ):
                return type_id, bt
            type_id = int(bt.type)
            bt = self._type_by_id(type_id)
        raise BtfError("modifier chain too long; BTF looks corrupted")
