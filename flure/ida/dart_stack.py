from keystone import *
from capstone import *

import idc
import ida_bytes


def replace_x15_by_sp(start_ea, end_ea, redo_analysis=True):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ea = start_ea
    while ea < end_ea:
        orig_ins = idc.generate_disasm_line(ea, 0)
        orig_ins_cs_info_list = [x for x in cs.disasm_lite(idc.get_bytes(ea, 4), ea, 1)]
        if len(orig_ins_cs_info_list) == 0:
            ea = idc.next_head(ea)
            continue
        orig_ins_cs_info = orig_ins_cs_info_list[0]
        orig_ins_cs = " ".join(orig_ins_cs_info[2:])
        if "X15" in orig_ins:
            try:
                new_ins = orig_ins_cs.replace("x15", "SP")
                new_ins_asm = ks.asm(new_ins, ea, as_bytes=True)[0]
                ida_bytes.patch_bytes(ea, new_ins_asm)
                print(f"At 0x{ea:x}: Patching {orig_ins} -> {new_ins}")
            except KsError as e:
                print(f"At 0x{ea:x}: Can't patch {orig_ins} -> {new_ins}: {e}")
            except TypeError as e:
                print(f"At 0x{ea:x}: Can't patch {orig_ins} -> {new_ins}: {e}")
        ea = idc.next_head(ea)
    if redo_analysis:
        idc.plan_and_wait(start_ea, end_ea)