from elftools.elf.elffile import ELFFile, SymbolTableSection

from flure.code_info import CodeInfo, ClassInfo, FunctionInfo


class DwarfParser(object):
    def __init__(self, filename):
        self.filename = filename
        self.code_info = CodeInfo()
        self.parse()

    @staticmethod
    def get_file_entries(dwarf_info, cu):
        line_program = dwarf_info.line_program_for_CU(cu)
        if line_program is None:
            print('Warning: DWARF info is missing a line program for this CU')
            return []
        return line_program.header["file_entry"]

    def parse(self):
        known_symbol_address = self.parse_dwarf()
        self.parse_symbols_table(known_symbol_address)

    def parse_dwarf(self):
        known_symbol_address = []
        with open(self.filename, 'rb') as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                raise Exception(f"File {self.filename} has no DWARF info")
            dwarf_info = elffile.get_dwarf_info()
            classes_by_name = {}
            for CU in dwarf_info.iter_CUs():
                file_entries = self.get_file_entries(dwarf_info, CU)
                for DIE in CU.iter_DIEs():
                    if DIE.tag == 'DW_TAG_subprogram':
                        if 'DW_AT_low_pc' not in DIE.attributes:
                            continue
                        low_pc = DIE.attributes['DW_AT_low_pc'].value
                        if 'DW_AT_abstract_origin' not in DIE.attributes:
                            raise Exception(f"Unknown DIE: {DIE}")
                        abstract_origin = DIE.get_DIE_from_attribute('DW_AT_abstract_origin')
                        full_func_name = abstract_origin.attributes['DW_AT_name'].value.decode("ascii")
                        decl_file = file_entries[abstract_origin.attributes['DW_AT_decl_file'].value - 1].name.decode("ascii")
                        if "." in full_func_name:
                            class_name = full_func_name.split(".")[0]
                            func_name = ".".join(full_func_name.split(".")[1:])
                        else:
                            class_name = ""
                            func_name = full_func_name
                        if " " in class_name:
                            if (class_name.split(" ")[0] != "new") or (len(class_name.split(" ")) != 2):
                                raise Exception(f"Not-handled space in '{full_func_name}'")
                            class_name = class_name.split(" ")[1]
                        if class_name == "":
                            class_name = "__null__"
                        full_class_name = ".".join([decl_file, class_name])
                        if full_class_name not in classes_by_name:
                            classes_by_name[full_class_name] = ClassInfo(decl_file, class_name, "")
                        classes_by_name[full_class_name].add_function(FunctionInfo(func_name, "", low_pc, 0))
                        known_symbol_address.append(low_pc)
                for full_class_name, class_info in classes_by_name.items():
                    self.code_info.add_classes(class_info)
                return known_symbol_address

    def parse_symbols_table(self, known_symbol_address):
        known_symbol_address = known_symbol_address if known_symbol_address is not None else []
        with open(self.filename, 'rb') as f:
            elffile = ELFFile(f)
            precompiled_code = ClassInfo("precompiled", None, None)
            for section in elffile.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        symbol_address = symbol.entry['st_value']
                        if symbol_address not in known_symbol_address:
                            precompiled_code.add_function(FunctionInfo(symbol.name, "", symbol.entry['st_value'], 0))
            self.code_info.add_classes(precompiled_code)
