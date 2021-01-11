#
# developed by @gerhart_x
# GPL licence
# IDA PRO 7.5
#

# based on https://github.com/Cr4sh/IDA-VMware-GDB

def get_interrupt_vector_64(number):

    idtr_str = idc.eval_idc('SendGDBMonitor("r idtr")') ## info registers for qemu

    w_idt_str_start = idtr_str.find("base=")+5
    w_idt_str_end = idtr_str.find(" ",  w_idt_str_start)
    w_idt_str = idtr_str[w_idt_str_start: w_idt_str_end]

    print("idt_str %s" % w_idt_str)

    # extract and convert IDT base

    idt = int(w_idt_str, 16)

    # go to the specified IDT descriptor
    idt += number * 16

    # build interrupt vector address

    descriptor_0 = idc.get_qword(idt)
    descriptor_1 = idc.get_qword(idt + 8)
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
        w = idc.get_wide_word(addr - l)
        if w == 0x5a4d:

            return addr - l

        l += 0x1000

    raise Exception("get_module_base(): Unable to locate DOS signature")

# def end

addr = get_interrupt_vector_64(1)
kernel_base = get_module_base(addr)


print("Kernel base is %s" % str(hex(kernel_base)))
for ea in Segments():
    if idc.get_segm_name(ea) == ".text":
        code_seg_base = ea
delta_seg = kernel_base - code_seg_base + 0x200000
#print delta_seg
ida_segment.rebase_program(delta_seg, MSF_FIXONCE)


