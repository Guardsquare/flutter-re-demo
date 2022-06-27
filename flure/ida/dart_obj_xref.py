import re
import struct

import ida_struct
import idc
import ida_bytes, ida_name, ida_offset


LOAD_X27_PATTERN = "\[X27,#0x(\S*)\]"
RE_LOAD_X27_PATTERN = re.compile(LOAD_X27_PATTERN)


# ADD             <reg_tmp>, X27, #0x<index_high>,LSL#<index_high_shift>
ADD_X27_PATTERN = "ADD             (\S*), X27, #0x(\S*),LSL#(\S*)"
RE_ADD_X27_PATTERN = re.compile(ADD_X27_PATTERN)
# LDR             <reg_dst>, [<reg_tmp>,#0x<index_low>]
LDR_AFTER_ADD_PATTERN = "LDR             (\S*), \[(\S*),#0x(\S*)\]"
RE_LDR_AFTER_ADD_PATTERN = re.compile(LDR_AFTER_ADD_PATTERN)


def get_dart_object_index_pattern_1(addr):
    # LDR <reg_dst>, [X27,#0x<index>]
    if idc.print_insn_mnem(addr) != "LDR":
        return None
    match_info = RE_LOAD_X27_PATTERN.match(idc.print_operand(addr, 1))
    if not match_info:
        return None
    obj_index = int(match_info.group(1), 16)
    return obj_index


def get_dart_object_index_pattern_2(addr):
    # To speed up a bit
    # if (idc.print_insn_mnem(addr) != "ADD") or (idc.print_insn_mnem(idc.next_head(addr)) != "LDR"):
    #     return False
    # ADD             <reg_tmp>, X27, #0x<index_high>,LSL#<index_high_shift>
    disasm_line = idc.generate_disasm_line(addr, 0)
    add_match_info = RE_ADD_X27_PATTERN.match(disasm_line)
    if not add_match_info:
        return None
    disasm_line = idc.generate_disasm_line(idc.next_head(addr), 0)
    ldr_match_info = RE_LDR_AFTER_ADD_PATTERN.match(disasm_line)
    if not ldr_match_info:
        return None
    tmp_reg, index_high, index_shift = add_match_info.group(1), add_match_info.group(2), add_match_info.group(3)
    dst_reg, tmp_reg_2, index_low = ldr_match_info.group(1), ldr_match_info.group(2), ldr_match_info.group(3)
    if tmp_reg != tmp_reg_2:
        return None
    index_high = int(index_high, 16)
    index_low = int(index_low, 16)
    index_shift = int(index_shift, 10)
    obj_index = (index_high << index_shift) + index_low
    return obj_index


def add_dart_object_xref(addr, object_pool_ptr, dart_object_index):
    dart_obj_ptr_ptr = object_pool_ptr + dart_object_index
    dart_obj_ptr = idc.get_qword(dart_obj_ptr_ptr)
    idc.add_dref(addr, dart_obj_ptr_ptr, idc.dr_R)
    if dart_obj_ptr & 1 == 1:
        dart_obj_ptr = dart_obj_ptr - 1
        idc.add_dref(addr, dart_obj_ptr, idc.dr_R)


def check_and_add_dart_object_xref(addr, object_pool_ptr):
    dart_object_index = get_dart_object_index_pattern_1(addr)
    if dart_object_index is None:
        dart_object_index = get_dart_object_index_pattern_2(addr)
        addr = idc.next_head(addr)
    if dart_object_index is None:
        return False
    add_dart_object_xref(addr, object_pool_ptr, dart_object_index)
    return True


def parse_code_and_add_dart_object_xref(object_pool_ptr):
    start_ea = 0
    ea = start_ea
    nb_xref_added = 0
    while ea < idc.BADADDR:
        xref_added = check_and_add_dart_object_xref(ea, object_pool_ptr)
        if xref_added:
            nb_xref_added += 1
        ea = idc.next_head(ea)
    print(f"Number of xref added to Dart Object {nb_xref_added}")
