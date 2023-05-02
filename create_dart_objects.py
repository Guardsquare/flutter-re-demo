import sys, os
import idaapi, ida_kernwin
from get_options import get_options

try:
    import flure
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

idaapi.require("flure.ida.dart_obj_create")
from flure.ida.dart_obj_create import DartObjectsCreator


if __name__ == "__main__":
    object_pool_address = get_options().get("object_pool", None)
    if object_pool_address is None:
        object_pool_address = ida_kernwin.ask_addr(0x7200600040, "Please enter Object Pool address")
    else:
        object_pool_address = int(object_pool_address, 0)

    if object_pool_address is not None:
        dart_object_creator = DartObjectsCreator(object_pool_address)
        dart_object_creator.create_all_objects()
