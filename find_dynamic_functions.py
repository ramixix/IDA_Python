import idautils
import idc

for func in idautils.Functions():
    flag = idc.get_func_attr(func, FUNCATTR_FLAGS)
    if flag & FUNC_LIB or flag & FUNC_THUNK:
        continue

    disasm_addr = list(idautils.FuncItems(func))
    for line in disasm_addr:
        mnemonic = idc.print_insn_mnem(line)
        if(mnemonic == "call" or mnemonic == "jmp"):
            # idc.get_operand_type returns an integer that is internally called op_t.type
            operand = idc.get_operand_type(line, 0)
            # o_reg == 1
            if(operand == o_reg):
                print(f"{hex(line)}\t{idc.generate_disasm_line(line, 0)}\t\t(function:{idc.get_func_name(func)})")

# operand types
# 1 = register  example : push eax
# 5 = constant  example : push 5
# 4 = memory    example : push [ebp+arg_C]
# 7 = location? example : jz    short loc_1000282E