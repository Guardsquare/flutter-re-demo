import sys, os
import idaapi, ida_kernwin
from get_options import get_options

try:
    import flure
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

idaapi.require("flure.ida.object_pool_microcode")
from flure.ida.object_pool_microcode import X27ReplaceHook

if __name__ == "__main__":
    try:
        x27_replace_hook.unhook()
        del x27_replace_hook
    except NameError as e:
        pass
    finally:
        object_pool_address = get_options().get("object_pool", None)
        if object_pool_address is None:
            object_pool_address = ida_kernwin.ask_addr(0x7200600040, "Please enter Object Pool address")
        else:
            object_pool_address = int(object_pool_address, 0)
        if object_pool_address is not None:
            flure.ida.object_pool_microcode.OBJECT_POOL_PTR = object_pool_address
            x27_replace_hook = X27ReplaceHook()
            x27_replace_hook.hook()
            print("Microcode X27 hook registered")