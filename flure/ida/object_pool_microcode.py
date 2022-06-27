import ida_hexrays

OBJECT_POOL_PTR = 0

def format_mop_t(mop_in: ida_hexrays.mop_t) -> str:
    if mop_in is None:
        return "mop_t is None"
    if mop_in.t > 15:
        return "Unknown mop type {0}".format(mop_in.t)
    return mop_in.dstr()


class MyMopVisitor(ida_hexrays.mop_visitor_t):
    def visit_mop(self, op: ida_hexrays.mop_t, op_type, is_target: bool) -> "int":
        mop_info = format_mop_t(op)
        if is_target:
            return 0
        if op.t != ida_hexrays.mop_r:
            return 0
        if mop_info != "x27.8":
            return 0
        op.make_number(OBJECT_POOL_PTR, 8)
        return 0


class X27ReplaceHook(ida_hexrays.Hexrays_Hooks):
    def microcode(self, mba: ida_hexrays.mba_t) -> "int":
        x = MyMopVisitor()
        return mba.for_all_ops(x)

