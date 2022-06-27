import sys, os
import idaapi, idautils, ida_kernwin
import idc

try:
    import flure
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

idaapi.require("flure.ida.dart_stack")
from flure.ida.dart_stack import replace_x15_by_sp


def get_text_segment_bound():
    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        if seg_name == ".text":
            return idc.get_segm_start(seg_ea), idc.get_segm_end(seg_ea)
    return 0, idc.BADADDR


if __name__ == "__main__":
    default_start_ea, default_end_ea = get_text_segment_bound()
    start_ea = ida_kernwin.ask_addr(default_start_ea, "Please enter start of code")
    if start_ea is not None:
        end_ea = ida_kernwin.ask_addr(default_end_ea, "Please enter end of code")
        if end_ea is not None:
            replace_x15_by_sp(start_ea, end_ea, redo_analysis=True)
