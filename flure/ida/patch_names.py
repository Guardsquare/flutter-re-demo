import idautils
import ida_dirtree
import idc
import ida_name, ida_funcs

from flure.code_info import CodeInfo
from flure.ida.utils import safe_rename

func_dir: ida_dirtree.dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

SMALL_FUNC_MAPPING = {
    "==": "__equals__",
    ">>": "__rshift__",
    "<<": "__lshift__",
    "~/": "__truncdiv__",
    "[]=": "__list_set__",
    "unary-": "__neg__",
    "<=": "__inf_eq__",
    ">=": "__sup_eq__",
    "!=": "__neq__",
    "|": "__or__",
    "&": "__and__",
    "^": "__xor__",
    "+": "__add__",
    "*": "__mul__",
    "-": "__sub__",
    "<": "__inf__",
    ">": "__sup__",
    "%": "__mod__",
    "/": "__fiv__",
    "~": "__bnot__",
}


def create_ida_folders(code_info: CodeInfo):
    exported_entries = {}
    for entry in idautils.Entries():
        exported_entries[entry[3]] = entry[2]
    for class_info in code_info.classes:
        dir_path = class_info.module_path.replace(":", "/")
        func_dir.mkdir(dir_path)
        class_name = class_info.name
        for func_info in class_info.functions:
            func_name = func_info.name
            if func_info.relative_base != 0:
                func_offset = func_info.offset + exported_entries[func_info.relative_base]
            else:
                func_offset = func_info.offset
            for k, v in SMALL_FUNC_MAPPING.items():
                if func_name == k:
                    func_name = v
            func_name = func_name.replace(":", "::")
            full_func_name = f"{class_name}::{func_name}" if class_info.name is not None else func_name

            ida_funcs.add_func(func_offset, idc.BADADDR)
            given_name = safe_rename(func_offset, full_func_name)
            func_dir.rename(given_name, f"{dir_path}/{given_name}")
