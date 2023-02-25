# Introduction
I use this repository as a reference to find examples of commonly used functions in IDA_Python. I will actively add new examples whenever I come across new one, but most of these examples are taken from Alexander Hanel's book "The Beginner's Guide to IDAPython". I will also include different scripts that I have used in different examples to decode or extract configurations.


## 1. BASICS
### **To get address of the curser (Return an integer value that contain the address at which the cursor is placed at)**
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

### **Get the minimum/maximum address that is present in an IDB**
- idc.get_inf_attr(INF_MIN_EA)
- idc.get_inf_attr(INF_MAX_EA)

example :
```py
    print(hex(idc.get_inf_attr(INF_MIN_EA)))
        > 0x401000L
    print(hex(idc.get_inf_attr(INF_MAX_EA)))
        > 0x51d0A0L
```

### **To specify what section does a address is reside**
- idc.get_segm_name([address])

example :
```py
    ea = 0x401570 # or ea = 4199792
    idc.get_segm_name(ea) 
        > .text 
```

### **To get disassembly of an address and access each element of disassembly (mnemonic, oprand(s)...)**
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

### **To verify an address exists**
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

---

## 2. SEGMENTS
### **Iterating through all segments**
```py
    # idautils.Segments() returns an iterator type object. We can loop through the object by using a for loop. Each item in the list is a segment's start address.
    for seg in idautils.Segments():
        print(idc.get_segm_name(seg))   # segment name
        print(idc.get_segm_start(seg))  # segment's starting address
        print(idc.get_segm_end(seg))    # segment's ending address
```

---

## 3. FUNCTIONS
### **Iterate through all functions**
```py
    # idautils.Functions() returns a list of known functions. The list contains the start address of each function. idautils.Functions() can be passed arguments to search within a range. If we wanted to do this we would pass the start and end address idautils.Functions(start_addr, end_addr). To get a functions name we use idc.get_func_name(ea). "ea" can be any address within the function boundaries.
    for func in idautils.Functions():
        print(hex(func), idc.get_func_name(func))
```

### **Get function boundaries**
example :
```py
    # "idaapi.get_func(address)" will return a class of "idaapi.func_t"
    func = idaapi.get_func(0x100027a7)
    print(f"strat: {hex(func.start_ea)} end: {hex(func.end_ea)}")
        > strat: 0x100027a7 end: 0x10002832
```

Another way to get function boudaries, is by using **"idc.get_func_attr(ea, FUNCATTR_START)"** and **"idc.get_func_attr(ea, FUNCATTR_END)"**:
```py
    ea = 0x100027a7
    start = idc.get_func_attr(ea, FUNCATTR_START)
    end = idc.get_func_attr(ea, FUNCATTR_END)
    print(f"strat: {hex(start)} end: {hex(end)}")
        > strat: 0x100027a7 end: 0x10002832
```

example : 
```py
    ea = idc.here()
    start = idc.get_func_attr(ea, FUNCATTR_START)
    end = idc.get_func_attr(ea, FUNCATTR_END)
    cur_addr = start
    while cur_addr <= end:
        print(hex(cur_addr), idc.generate_disasm_line(cur_addr, 0))
        cur_addr = idc.next_head(cur_addr, end) # get the start of the next instruction
        
    # A flaw to this approach is it relies on the instructions to be contained within the boundaries of the start and end of the function. If there was a jump to an address higher than the end of the function the loop would prematurely exit.

    > output:
    0x100027a7 push    ebp
    0x100027a8 mov     ebp, esp
    0x100027aa sub     esp, 2CCh
    0x100027b0 push    2C8h
    0x100027b5 lea     eax, [ebp+Context.Dr0]
    ...
```

### **Function Flags**
- For gathering information about functions use "idc.get_func_attr(ea, FUNCATTR_FLAGS)"
    - flags :
        - FUNC_NORET
        - FUNC_FAR
        - FUNC_LIB
        - FUNC_STATIC
        - FUNC_FRAME
        - FUNC_USERFAR
        - FUNC_HIDDEN
        - FUNC_THUNK
        - FUNC_BOTTOMBP

example : 
```py
    import idautils
    for func in idautils.Functions():
        # Get the flags and then check the value by using a logical AND operation on the returned value.
        flags = idc.get_func_attr(func,FUNCATTR_FLAGS)
        if flags & FUNC_NORET:
            # (integer 1) identify a function that does not execute a "return" instruction. (No "return" or "leave" at the end of function)
            print(hex(func), "FUNC_NORET")
        if flags & FUNC_FAR:
            # (int 2) if it1 uses segmented memory
            print(hex(func), "FUNC_FAR")
        if flags & FUNC_LIB:
            # (int 4) used to find library code.
            print(hex(func), "FUNC_LIB")
        if flags & FUNC_STATIC:
            # identify functions that were compiled as a static function
            print(hex(func), "FUNC_STATIC")
        if flags & FUNC_FRAME:
            # This flag indicates the function uses a frame pointer "ebp". Functions that use frame pointers typically start with the standard function prologue for setting up the stack frame.
            print(hex(func), "FUNC_FRAME")
        if flags & FUNC_USERFAR:
            # (int 32) if user has specified far-ness of the function
            print(hex(func), "FUNC_USERFAR")
        if flags & FUNC_HIDDEN:
            # Functions with the FUNC_HIDDEN flag means they are hidden and needs to be expanded to view.
            print(hex(func), "FUNC_HIDDEN")
        if flags & FUNC_THUNK:
            # This flag identifies functions that are thunk functions. (Thunk functions are simple functions that jump to another function.)
            print(hex(func), "FUNC_THUNK")
        if flags & FUNC_LIB:
            # Similar to FUNC_FRAM this flag is used to track the frame pointer. It identifies functions that base pointer points to the stack pointer.
            print(hex(func), "FUNC_BOTTOMBP")
        
        # It should be noted that a function can consist of multiple flags. Look at the output below the 0x10002afa is both HIDDEN and THUNK function.
    > output:
        ...
        0x10002a0c FUNC_FRAME
        0x10002a62 FUNC_FRAME
        0x10002afa FUNC_HIDDEN
        0x10002afa FUNC_THUNK
        0x10002b00 FUNC_HIDDEN
        0x10002b00 FUNC_THUNK
        ...
```

---

## 4. Instructions

### **Access instructions within a function**
As we saw we can get instruction inside a function by starting from begining of a function and loop util the end of the function and use idc.next_head(curr_add, end_add) to get the instruction at the current address. but we said that approach relies on the instructions to be contained within the boundaries of the start and end of the function and if there be a jump to an address higher than the end of the function the loop will prematurely exit. One another way is to use **idautils.FuncItems(ea)**, which returns a list that contians all instruction addresses belonging to that function. 

example : 
```py
    ea = 0x100027a7
    # idautils.FuncItems(ea) returns an iterator type but is cast to a list
    dism_addr = list(idautils.FuncItems(ea))
    print(dism_addr)
        > output : [268445607, 268445608, ... , 268445745]
    for line in dism_addr:
        print(hex(line), idc.generate_disasm_line(line,0))

    > output:
        0x100027a7 push    ebp
        0x100027a8 mov     ebp, esp
        0x100027aa sub     esp, 2CCh
        0x100027b0 push    2C8h
        ...
```

### **Get next/previous instruction/adddress
To get Previous/Next instruction : idc.next_head(addr) / idc.prev_head(addr)
To get Previous/Next address : idc.next_addr(addr) / idc.prev_addr(addr)

```py
    ea = 0x10004f24
    print(hex(ea), idc.generate_disasm_line(ea, 0))
        > 0x10004f24 call sub_10004F32

    # next_head function get the start of the next instruction but not the next address
    next_instr = idc.next_head(ea)
    print(hex(next_instr), idc.generate_disasm_line(next_instr, 0))
        > 0x10004f29 mov  [esi], eax
    prev_instr = idc.prev_head(ea)
    print(hex(prev_instr), idc.generate_disasm_line(prev_instr, 0))
        > 0x10004f1e mov [esi+98h], eax

    print hex(idc.next_addr(ea)) # addr + 1
        > 0x10004f25
    print hex(idc.prev_head(ea)) # addr - 1
        > 0x10004f23
```