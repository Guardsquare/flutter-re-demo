import idaapi
import ida_segment
import ida_bytes


def add_dartvm_segment(start_ea, name, perm, input_file):
    with open(input_file, "rb") as fp:
        seg_data = fp.read()
    end_ea = start_ea + len(seg_data)
    s = ida_segment.segment_t()
    s.start_ea = start_ea
    s.end_ea = end_ea
    s.perm = perm
    s.bitness = 2
    s.align = ida_segment.saRelByte
    idaapi.add_segm_ex(s, name, None, ida_segment.ADDSEG_OR_DIE)
    with open(input_file, "rb") as fp:
        ida_bytes.patch_bytes(start_ea, seg_data)

