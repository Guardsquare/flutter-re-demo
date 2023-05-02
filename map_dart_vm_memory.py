import sys, os
import idaapi, ida_kernwin, ida_segment
from get_options import get_options

try:
    import flure
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

idaapi.require("flure.ida.create_segment")
from flure.ida.create_segment import add_dartvm_segment

if __name__ == "__main__":
    options = get_options()
    ro_memory_file_name = options.get("dump_ro", None)
    if ro_memory_file_name is None:
        ro_memory_file_name = ida_kernwin.ask_file(False,
                                                   "/Users/boris/Desktop/demo_flutter/obfu/dump_mem/0x7200000000",
                                                   "Flutter RO memory filename")
    if ro_memory_file_name is not None:
        try:
            guessed_ro_memory_address = int(os.path.basename(ro_memory_file_name), 16)
        except ValueError:
            guessed_ro_memory_address = 0
        ro_memory_address = ida_kernwin.ask_addr(guessed_ro_memory_address, "Please enter Flutter RO memory address")
        if ro_memory_address is not None:
            print(f"Mapping {ro_memory_file_name} at 0x{ro_memory_address:x}")
            add_dartvm_segment(ro_memory_address, "flutter_ro", ida_segment.SEGPERM_READ,
                               ro_memory_file_name)

    rw_memory_file_name = options.get("dump_rw", None)
    if rw_memory_file_name is None:
        rw_memory_file_name = ida_kernwin.ask_file(False,
                                                   "/Users/boris/Desktop/demo_flutter/obfu/dump_mem/0x7200080000",
                                                   "Flutter RW memory filename")
    if rw_memory_file_name is not None:
        try:
            guessed_rw_memory_address = int(os.path.basename(rw_memory_file_name), 16)
        except ValueError:
            guessed_rw_memory_address = 0
        rw_memory_address = ida_kernwin.ask_addr(guessed_rw_memory_address, "Please enter Flutter RW memory address")
        if rw_memory_address is not None:
            print(f"Mapping {rw_memory_file_name} at 0x{rw_memory_address:x}")
            add_dartvm_segment(rw_memory_address, "flutter_rw", ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_READ,
                               rw_memory_file_name)

    if len(options.get("memory_dumps", [])) > 2:
        mapped_regions = [os.path.basename(ro_memory_file_name), os.path.basename(rw_memory_file_name)]
        for i, dump_file_name in enumerate(options["memory_dumps"]):
            f_name = os.path.basename(dump_file_name)
            if f_name in mapped_regions:
                continue
            try:
                memory_address = int(f_name, 16)
            except ValueError:
                memory_address = ida_kernwin.ask_addr(0,
                                                      f"Please enter Flutter additional {i} memory address"
                                                      f"with name {f_name}")
            if memory_address is not None:
                print(f"Mapping {dump_file_name} at 0x{memory_address:x}")
                add_dartvm_segment(memory_address, f"flutter_{i}", ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_READ,
                                   dump_file_name)
