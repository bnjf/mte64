
class OpNodePrinter:
    def __init__(self, val):
        self.val = val

    def to_string (self):
        op = self.val['op']
        value = self.val['value']
        left = self.val['left']
        right = self.val['right']

        op_to_str = [ "#", "x", "%ptr", "sub", "add", "xor", "mul", "rol", "ror", "shl", "shr", "or_", "and_", "imul", "jnz" ]

        if op < 3:
            if op == 1:
                return 'x'
            return hex(value)
        else:
            l = left.dereference()
            r = right.dereference()
            return f'{op_to_str[op]}({l}, {r})'

def lookup_type (val):
    if str(val.type) == 'op_node_t':
        return OpNodePrinter(val)
    return None

gdb.pretty_printers.append (lookup_type)

