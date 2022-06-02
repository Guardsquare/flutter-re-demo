
class FunctionInfo(object):
    def __init__(self, name, signature, offset, relative_base):
        self.name = name
        self.signature = signature
        self.offset = offset
        self.relative_base = relative_base

    @staticmethod
    def load(func_info_dict):
        return FunctionInfo(func_info_dict["name"], func_info_dict["signature"],
                            func_info_dict["offset"], func_info_dict["relative_base"])

    def dump(self):
        return {
            "name": self.name,
            "signature": self.signature,
            "offset": self.offset,
            "relative_base": self.relative_base,
        }


class ClassInfo(object):
    def __init__(self, module_path, name, full_declaration):
        self.module_path = module_path
        self.name = name
        self.full_declaration = full_declaration
        self.functions = []

    def add_function(self, func_info: FunctionInfo):
        self.functions.append(func_info)

    @staticmethod
    def load(class_info_dict):
        class_info = ClassInfo(class_info_dict["module"], class_info_dict["name"], class_info_dict["full_declaration"])
        for func_info_dict in class_info_dict["functions"]:
            class_info.add_function(FunctionInfo.load(func_info_dict))
        return class_info

    def dump(self):
        return {
            "module": self.module_path,
            "name": self.name,
            "full_declaration": self.full_declaration,
            "functions": [func_info.dump() for func_info in self.functions]
        }


class CodeInfo(object):
    def __init__(self):
        self.classes = []

    def add_classes(self, func_info: ClassInfo):
        self.classes.append(func_info)

    @staticmethod
    def load(code_info_dict):
        code_info = CodeInfo()
        for class_info_dict in code_info_dict["classes"]:
            code_info.add_classes(ClassInfo.load(class_info_dict))
        return code_info

    def dump(self):
        return {
            "classes": [class_info.dump() for class_info in self.classes]
        }
