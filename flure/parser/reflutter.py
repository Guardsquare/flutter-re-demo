from flure.code_info import CodeInfo, ClassInfo, FunctionInfo

LIBRARY_TOKEN = b"Library:'"
CLASS_TOKEN = b"Class: "
FUNCTION_TOKEN = b"  Function "
KNOWN_PREFIXES_IGNORED = [b"Random ", b"Map<Object, ", b"Class: ", b"dynamic ", b'', b'}']


class ReFlutterDumpParser(object):
    def __init__(self, filename):
        self.filename = filename
        self.code_info = CodeInfo()
        self.parse()

    def parse(self):
        with open(self.filename, "rb") as fp:
            lines = fp.readlines()
        cur_line_index = 0
        while cur_line_index < len(lines):
            if lines[cur_line_index].startswith(LIBRARY_TOKEN):
                class_info, next_line_index = self.parse_class(lines, cur_line_index)
                self.code_info.add_classes(class_info)
                cur_line_index = next_line_index
            else:
                raise Exception(f"Unknown line while parsing file: {lines[cur_line_index].strip()}")

    def parse_class(self, lines, start_index):
        class_info = self.parse_class_declaration_line(lines[start_index])
        cur_line_index = start_index + 1
        while cur_line_index < len(lines):
            if lines[cur_line_index].startswith(LIBRARY_TOKEN):
                return class_info, cur_line_index
            elif lines[cur_line_index].startswith(FUNCTION_TOKEN):
                func_info = self.parse_function_lines(lines[cur_line_index:cur_line_index + 5])
                class_info.add_function(func_info)
                cur_line_index += 5
            else:
                prefix_found = False
                for known_ignored_prefix in KNOWN_PREFIXES_IGNORED:
                    if lines[cur_line_index].strip().startswith(known_ignored_prefix):
                        cur_line_index += 1
                        prefix_found = True
                        break
                if not prefix_found:
                    raise Exception(f"Unknown line while parsing class: {lines[cur_line_index].strip()}")
        return class_info, cur_line_index

    @staticmethod
    def parse_class_declaration_line(line):
        if not line.startswith(LIBRARY_TOKEN):
            raise Exception(f"Invalid line while parsing class declaration line: '{line}'")
        module_path = line.split(b"'")[1].decode("ascii")
        class_full_declaration = line.split(b"'")[2].strip()
        if not class_full_declaration.startswith(CLASS_TOKEN):
            return ClassInfo(module_path, None, None)
        class_name = class_full_declaration[len(CLASS_TOKEN):].split(b" ")[0].decode("ascii")
        return ClassInfo(module_path, class_name, class_full_declaration[:-1].decode("ascii"))

    @staticmethod
    def parse_function_lines(func_lines):
        if (func_lines[1].strip() != b'') or (func_lines[3].strip() != b'') or (func_lines[4].strip() != b'}'):
            raise Exception(f"Invalid lines while parsing function declaration line: '{func_lines}'")
        # Function 'get:_instantiator_type_arguments@0150898': getter. (_Closure@0150898) => dynamic
        func_info = func_lines[0].strip()[:-1]
        func_name = func_info.split(b"'")[1].decode("ascii")
        func_signature = func_info.split(b"'")[2][1:].decode("ascii")
        # Code Offset: _kDartIsolateSnapshotInstructions + 0x00000000002ebfb0
        func_offset = func_lines[2].strip().split(b"+")[1].strip()
        func_relative_base = func_lines[2].strip().split(b"+")[0].split(b":")[1].strip().decode("ascii")
        return FunctionInfo(func_name, func_signature, int(func_offset, 16), func_relative_base)