import re
import struct

import ida_struct
import idc
import ida_bytes, ida_name, ida_offset


LOAD_X27_PATTERN = r"\[X27,#0x(\S*)\]"
RE_LOAD_X27_PATTERN = re.compile(LOAD_X27_PATTERN)


# ADD             <reg_tmp>, X27, #0x<index_high>,LSL#<index_high_shift>
ADD_X27_PATTERN = r"ADD             (\S*), X27, #(\S*),LSL#(\d+)"
RE_ADD_X27_PATTERN = re.compile(ADD_X27_PATTERN)
# LDR             <reg_dst>, [<reg_tmp>,#0x<index_low>]
LDR_AFTER_ADD_PATTERN = r"LDR             (\S*), \[(\S*),#0x(\S*)\]"
RE_LDR_AFTER_ADD_PATTERN = re.compile(LDR_AFTER_ADD_PATTERN)

LDR_AFTER_ADD_PATTERN2 = r"LDR             (\S*), \[(\S*)\]"
RE_LDR_AFTER_ADD_PATTERN2 = re.compile(LDR_AFTER_ADD_PATTERN2)

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

    if ldr_match_info := RE_LDR_AFTER_ADD_PATTERN.match(disasm_line):
        dst_reg, tmp_reg_2, index_low = ldr_match_info.group(1), ldr_match_info.group(2), ldr_match_info.group(3)
    elif ldr_match_info := RE_LDR_AFTER_ADD_PATTERN2.match(disasm_line):
        dst_reg, tmp_reg_2, index_low = ldr_match_info.group(1), ldr_match_info.group(2), "0"
    else:
        return None

    tmp_reg, index_high, index_shift = add_match_info.group(1), add_match_info.group(2), add_match_info.group(3)
    if tmp_reg != tmp_reg_2:
        return None
    index_high = int(index_high, 16)
    index_low = int(index_low, 16)
    index_shift = int(index_shift, 10)
    obj_index = (index_high << index_shift) + index_low
    return obj_index


# ADD             <reg_tmp>, X27, #0x<index_high>
RE_ADD_X27_PATTERN2 = re.compile(r"ADD             (\S*), X27, #([x0-9a-fA-F]+)")

# ADD             <reg_tmp>, <reg_tmp>, #0x<index_low>
RE_ADD_TMP_PATTERN = re.compile(r"ADD             (\S*), (\S*), #(\S+)")

# LDP             reg_dst_1, reg_dst_2, [<reg_tmp>,#<index_low>]
RE_LDP_AFTER_ADD_PATTERN = re.compile(r"LDP             (\S*), (\S*), \[(\S*)\,#(\S*)\]")

# LDP             reg_dst_1, reg_dst_2, [<reg_tmp>]
RE_LDP_AFTER_ADD_PATTERN2 = re.compile(r"LDP             (\S*), (\S*), \[(\S*)\]")


def get_dart_object_index_pattern_3(addr):
    """
    70FD44BC9C
    ADD             X16, X27, #0x750
    LDP             X5, X30, [X16]

    and

    70FD44BB70
    ADD             X16, X27, #7,LSL#12
    ADD             X16, X16, #0x7D0
    LDP             X5, X30, [X16]

    and

    70FD450624
    ADD             X16, X27, #0xE,LSL#12
    LDP             X5, X30, [X16,#0x1E0]
    """
    instructions_count = 2          # count of instructions in matched pattern
    disasm_line = idc.generate_disasm_line(addr, 0)
    add_match_info = RE_ADD_X27_PATTERN.match(disasm_line)

    if not add_match_info:
        add_match_info = RE_ADD_X27_PATTERN2.match(disasm_line)
        if not add_match_info:
            return None
        else:
            tmp_reg, index_high, index_shift = add_match_info.group(1), add_match_info.group(2).replace(";", ""), "0"
    else:
        tmp_reg, index_high, index_shift = add_match_info.group(1), add_match_info.group(2).replace(";",""),\
            add_match_info.group(3).replace(";", "")

    # for the case when there is one more add
    addr = idc.next_head(addr)
    disasm_line = idc.generate_disasm_line(addr, 0)
    add_match_info_2 = RE_ADD_TMP_PATTERN.match(disasm_line)

    if add_match_info_2:
        instructions_count += 1
        addr = idc.next_head(addr)

    disasm_line = idc.generate_disasm_line(addr, 0)
    ldp_match_info = RE_LDP_AFTER_ADD_PATTERN.match(disasm_line) or RE_LDP_AFTER_ADD_PATTERN2.match(disasm_line)

    if not ldp_match_info:
        return None

    dst_reg, dst_reg1, tmp_reg_2 = ldp_match_info.group(1), ldp_match_info.group(2), ldp_match_info.group(3)

    if tmp_reg != tmp_reg_2:
        return None

    if len(ldp_match_info.groups()) > 3:
        index_low = ldp_match_info.group(4)
    else:
        index_low = "0"

    index_low_2 = 0
    if add_match_info_2:
        dst_reg_2, src_reg_2, delta_2 = add_match_info_2.group(1), add_match_info_2.group(2), add_match_info_2.group(3)
        index_low_2 = int(delta_2, 0)

    index_high = int(index_high, 0)
    index_low = int(index_low, 0)
    index_shift = int(index_shift, 0)
    obj_index = (index_high << index_shift) + index_low + index_low_2

    return instructions_count, obj_index, obj_index + 8


def add_dart_object_xref(addr, object_pool_ptr, dart_object_index):
    dart_obj_ptr_ptr = object_pool_ptr + dart_object_index
    dart_obj_ptr = idc.get_qword(dart_obj_ptr_ptr)
    idc.add_dref(addr, dart_obj_ptr_ptr, idc.dr_R)
    if dart_obj_ptr & 1 == 1:
        dart_obj_ptr = dart_obj_ptr - 1
        idc.add_dref(addr, dart_obj_ptr, idc.dr_R)


def check_and_add_dart_object_xref(addr, object_pool_ptr):
    if dart_object_index := get_dart_object_index_pattern_1(addr):
        add_dart_object_xref(addr, object_pool_ptr, dart_object_index)
    elif dart_object_index := get_dart_object_index_pattern_2(addr):
        addr = idc.next_head(addr)
        add_dart_object_xref(addr, object_pool_ptr, dart_object_index)
    elif dart_object_index := get_dart_object_index_pattern_3(addr):
        instructions_count = dart_object_index[0] - 1
        while instructions_count > 0:
            addr = idc.next_head(addr)
            instructions_count -= 1
        add_dart_object_xref(addr, object_pool_ptr, dart_object_index[1])
        add_dart_object_xref(addr, object_pool_ptr, dart_object_index[2])
    else:
        return False
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
