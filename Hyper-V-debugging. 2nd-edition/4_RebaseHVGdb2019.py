#based on https://github.com/Cr4sh/IDA-VMware-GDB
Ptr = Qword

# type argument for SegCreate()
segment_type = 2

def get_interrupt_vector_64(number):

    idtr_str = Eval('SendGDBMonitor("r idtr")')
    print("idtr_str %s" % idtr_str)

    # extract and convert IDT base

    idt = int(idtr_str[10: 10 + 18], 16)

    # go to the specified IDT descriptor
    idt += number * 16

    # build interrupt vector address
    descriptor_0 = Qword(idt)
    descriptor_1 = Qword(idt + 8)
    descriptor = ((descriptor_0 >> 32) & 0xffff0000) + (descriptor_0 & 0xffff) + (descriptor_1 << 32)

    print("idt vector %s" % hex(descriptor))

    #
    # if you have error with idt vector (f.e. see value 0xffff..fff), see manual memory region in GDB debugger option.
    # IDT vector address must be inside this region
    #

    return descriptor

# def end

def get_module_base(addr):

    page_mask = 0xFFFFFFFFFFFFF000

    # align address by PAGE_SIZE
    addr &= page_mask

    # find module base by address inside it
    l = 0
    while l < 5 * 1024 * 1024:

        # check for the MZ signature
        w = Word(addr - l)
        if w == 0x5a4d:

            return addr - l

        l += 0x1000

    raise Exception("get_module_base(): Unable to locate DOS signature")

# def end

addr = get_interrupt_vector_64(1)
kernel_base = get_module_base(addr)


print("Kernel base is %s" % str(hex(kernel_base)))
for ea in Segments():
    if SegName(ea) == ".text":
        code_seg_base = ea
delta_seg = kernel_base - code_seg_base + 0x200000
#print delta_seg
rebase_program(delta_seg, MSF_FIXONCE)


