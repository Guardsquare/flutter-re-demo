import struct

import idc
import ida_bytes, ida_name, ida_offset

MAX_OBJ_NAME_LEN = 30

def read_smi(smi_ptr):
    smi_data = idc.get_qword(smi_ptr)
    if smi_data & 1 == 0:
        return smi_data >> 1
    raise Exception(f"Invalid Smi at 0x{smi_ptr}: {smi_data}")


def get_info_from_tag(tag):
    cid = (tag >> 16) & 0xffff
    size_tag = (tag >> 8) & 0xff
    is_canonical = (tag >> 4) & 0x1
    gc_data = (tag) & 0x0f
    return cid, size_tag, is_canonical, gc_data


class DartObject(object):
    def __init__(self, dart_obj_ptr, create_object=False):
        self.dart_obj_ptr = dart_obj_ptr
        self.dart_obj_name = None
        self.tag, _ = struct.unpack("<II", ida_bytes.get_bytes(self.dart_obj_ptr, 8))
        if create_object:
            self.create_object()

    def get_ida_struc_name(self, cid):
        return f"DartUnkObj{cid}"

    def create_ida_struct(self, cid):
        sid = idc.get_struc_id(self.get_ida_struc_name(cid))
        if sid != idc.BADADDR:
            return
        x = idc.add_struc(idc.BADADDR, self.get_ida_struc_name(cid), is_union=False)
        idc.add_struc_member(x, "is_canonical_and_gc", -1, (idc.FF_BYTE | idc.FF_DATA) & 0xFFFFFFFF, -1, 1)
        idc.add_struc_member(x, "size_tag", -1, (idc.FF_BYTE | idc.FF_DATA) & 0xFFFFFFFF, -1, 1)
        idc.add_struc_member(x, "cid", -1, (idc.FF_WORD | idc.FF_DATA) & 0xFFFFFFFF, -1, 2)
        idc.add_struc_member(x, "padding", -1, (idc.FF_DWORD | idc.FF_DATA) & 0xFFFFFFFF, -1, 4)
        idc.add_struc_member(x, "unk_offs", -1, (idc.FF_QWORD | idc.FF_0OFF | idc.FF_DATA) & 0xFFFFFFFF, -1, 8, -1, 0, idc.REF_OFF64)

    def get_struct_len(self):
        return -1

    def get_prefix(self, cid):
        return f"do{cid}"

    def rename_dart_obj(self, cid):

        idc.set_name(self.dart_obj_ptr, f"{self.get_prefix(cid)}_{self.dart_obj_ptr:x}",
                     ida_name.SN_FORCE | ida_name.SN_NOCHECK)
        # Because ida_name.SN_FORCE and ida_name.SN_NOCHECK, the name of the function can be different
        # from full_func_name, thus we read it from DB after it has been set
        self.dart_obj_name = idc.get_name(self.dart_obj_ptr)

    def create_object(self):
        cid, size_tag, is_canonical, gc_data = get_info_from_tag(self.tag)
        self.create_ida_struct(cid)
        idc.create_struct(self.dart_obj_ptr, self.get_struct_len(), self.get_ida_struc_name(cid))
        print(f"  {self.get_ida_struc_name(cid)} found at 0x{self.dart_obj_ptr:x}")
        self.rename_dart_obj(cid)


class DartString1(DartObject):
    def get_ida_struc_name(self, cid):
        return "DartString1"

    def get_prefix(self, cid):
        return "ds1"

    def create_ida_struct(self, cid):
        sid = idc.get_struc_id(self.get_ida_struc_name(cid))
        if sid != idc.BADADDR:
            return
        x = idc.add_struc(idc.BADADDR, self.get_ida_struc_name(cid), is_union=False)
        idc.add_struc_member(x, "is_canonical_and_gc", -1, (idc.FF_BYTE | idc.FF_DATA) & 0xFFFFFFFF, -1, 1)
        idc.add_struc_member(x, "size_tag", -1, (idc.FF_BYTE | idc.FF_DATA) & 0xFFFFFFFF, -1, 1)
        idc.add_struc_member(x, "cid", -1, (idc.FF_WORD | idc.FF_DATA) & 0xFFFFFFFF, -1, 2)
        idc.add_struc_member(x, "padding", -1, (idc.FF_DWORD | idc.FF_DATA) & 0xFFFFFFFF, -1, 4)
        idc.add_struc_member(x, "s_len", -1, (idc.FF_QWORD | idc.FF_DATA) & 0xFFFFFFFF, -1, 8)
        idc.add_struc_member(x, "s", -1, (idc.FF_STRLIT | idc.FF_DATA) & 0xFFFFFFFF, idc.STRTYPE_C, 0)

    def get_struct_len(self):
        return 16 + read_smi(self.dart_obj_ptr + 8)

    def rename_dart_obj(self, cid):
        try:
            string_len = read_smi(self.dart_obj_ptr + 8)
            string_data = ida_bytes.get_bytes(self.dart_obj_ptr + 16, string_len).decode("ascii")
            idc.set_name(self.dart_obj_ptr, f"{self.get_prefix(cid)}_{string_data}"[:MAX_OBJ_NAME_LEN],
                         ida_name.SN_FORCE | ida_name.SN_NOCHECK)
            # Because ida_name.SN_FORCE and ida_name.SN_NOCHECK, the name of the function can be different
            # from full_func_name, thus we read it from DB after it has been set
            self.dart_obj_name = idc.get_name(self.dart_obj_ptr)
        except Exception as e:
            super().rename_dart_obj(cid)
            pass


class DartObjectsCreator(object):
    def __init__(self, object_pool_ptr, verbose=False):
        self.object_pool_ptr = object_pool_ptr
        self.verbose = verbose
        self.dart_object_by_cid = {
            0x55: DartString1
        }

        tag, _, self.nb_elt = struct.unpack("<IIQ", ida_bytes.get_bytes(self.object_pool_ptr, 16))
        print(f"ObjectPool at 0x{self.object_pool_ptr:x} has {self.nb_elt} objects")

    def create_all_objects(self):
        known_dart_obj = {}
        nb_address_obj = 0
        nb_primitive_obj = 0

        for i in range(self.nb_elt):
            dart_obj_ptr_ptr = self.object_pool_ptr + 16 + 8 * i
            dart_obj_ptr = idc.get_qword(dart_obj_ptr_ptr)
            if dart_obj_ptr & 1 == 1:
                dart_obj_ptr = dart_obj_ptr - 1
                if dart_obj_ptr not in known_dart_obj:
                    tag, _ = struct.unpack("<II", ida_bytes.get_bytes(dart_obj_ptr, 8))
                    cid, size_tag, is_canonical, gc_data = get_info_from_tag(tag)
                    if cid in self.dart_object_by_cid:
                        known_dart_obj[dart_obj_ptr] = self.dart_object_by_cid[cid](dart_obj_ptr, create_object=True)
                    else:
                        known_dart_obj[dart_obj_ptr] = DartObject(dart_obj_ptr, create_object=True)

                ida_offset.op_offset(dart_obj_ptr_ptr, 0, idc.REF_OFF64)
                if known_dart_obj[dart_obj_ptr].dart_obj_name is not None:
                    idc.set_name(dart_obj_ptr_ptr, f"p_{known_dart_obj[dart_obj_ptr].dart_obj_name}",
                                 ida_name.SN_FORCE | ida_name.SN_NOCHECK)
            elif ida_bytes.is_mapped(dart_obj_ptr):
                if self.verbose:
                    print(f"At 0x{dart_obj_ptr_ptr:x}: Address found with value 0x{dart_obj_ptr:x}")
                ida_offset.op_offset(dart_obj_ptr_ptr, 0, idc.REF_OFF64)
                address_name = idc.get_name(dart_obj_ptr)
                if address_name is not None:
                    idc.set_name(dart_obj_ptr_ptr, f"p_{address_name}", ida_name.SN_FORCE | ida_name.SN_NOCHECK)
                nb_address_obj += 1
            else:
                if self.verbose:
                    print(f"At 0x{dart_obj_ptr_ptr:x}: Primitive object found with value 0x{dart_obj_ptr:x}")
                nb_primitive_obj += 1

        print(f"Object Pool parsed: {len(known_dart_obj)} Dart Objects created, {nb_primitive_obj} Primitive Objects, "
              f"{nb_address_obj} addresses")
