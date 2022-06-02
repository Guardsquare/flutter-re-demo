import sys, os, json
import idaapi, ida_kernwin
try:
    import flure
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

idaapi.require("flure.code_info")
idaapi.require("flure.ida.patch_names")
from flure.code_info import CodeInfo
from flure.ida.patch_names import create_ida_folders

if __name__ == "__main__":
    function_info_file = ida_kernwin.ask_file(False, f"*.json", "Flutter snapshot function name filename")
    if function_info_file is not None:
        with open(function_info_file, 'r') as fp:
            code_info = CodeInfo.load(json.load(fp))
        create_ida_folders(code_info)
