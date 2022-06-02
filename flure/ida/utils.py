import idc
import ida_name


def safe_rename(offset, wanted_name, option=ida_name.SN_FORCE | ida_name.SN_NOCHECK):
    idc.set_name(offset, wanted_name, option)
    # Because ida_name.SN_FORCE and ida_name.SN_NOCHECK, the actual name can be different
    # from wanted_name, thus we read it from DB after it has been set
    return idc.get_name(offset)
