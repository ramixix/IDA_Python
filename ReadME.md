# Introduction
I use this repository as a reference to find examples of commonly used functions in IDA_Python. I will actively add new examples whenever I come across new one, but most of these examples are taken from Alexander Hanel's book "The Beginner's Guide to IDAPython". I will also include different scripts that I have used in different examples to decode or extract configurations.

## To get address of the curser (Return an integer value that contain the address at which the cursor is placed at)
- idc.get_screen_ea()
- idc.here()

example :
```py
    # both here() and get_screen_ea() return the same address which is the address of curser
    ea = idc.get_screen_ea()
    print("0x%x %s" % (ea, ea))
        > 0x401570 4199792
    ea = here()
    print(f"{hex(ea)}, {ea}")
        > 0x401570 419972
```

---

## Get the minimum/maximum address that is present in an IDB
- idc.get_inf_attr(INF_MIN_EA)
- idc.get_inf_attr(INF_MAX_EA)

example :
```py
    print(hex(idc.get_inf_attr(INF_MIN_EA)))
        > 0x401000L
    print(hex(idc.get_inf_attr(INF_MAX_EA)))
        > 0x51d0A0L
```

---

## To specify what section does a address is reside
- idc.get_segm_name([address])

example :
```py
    ea = 0x401570 # or ea = 4199792
    idc.get_segm_name(ea) 
        > .text 
```

---

## To get disassembly of an address and access each element of disassembly (mnemonic, oprand(s)...)
- idc.generate_disasm_line([address], 0)
- idc.print_insn_mnem([address])
- idc.print_operand([address],0) get first oprand
- idc.print_operand([address],1) get second oprand
- idc.print_operand([address],long n) get nth oprand

example :
```py
    ea = 0x1000296F
    print(idc.generate_disasm_line(ea, 0)) # get disassembly
        > mov     ecx, [ebp+Parameter]
    print(idc.print_insn_mnem(ea)) # get mnemonic
        > mov
    print(idc.print_operand(ea,0)) # get first operand
        > eax
    print(idc.print_operand(ea,1)) # get second operand
        > [ebp+Parameter]
```

---

## To verify an address exists
- idc.BADADDR
- idaapi.BADADDR
- BADADDR

example :
```py
    # All three return the same number
    # in 32-bit
    print(idc.BADADDR, hex(idc.BADADDR))
    print(idaapi.BADADDR, hex(idaapi.BADADDR))
    print(BADADDR, hex(BADADDR))
        > 4294967295 0xffffffff     # return the integer and hex value of all three functions above

    # to check if the current address is a valid address 
    if  BADADDR != here():
        print "valid address"


    # in 64-bit
    print(idc.BADADDR, hex(idc.BADADDR))
    print(idaapi.BADADDR, hex(idaapi.BADADDR))
    print(BADADDR, hex(BADADDR))
        > 18446744073709551615 0xffffffffffffffff
```