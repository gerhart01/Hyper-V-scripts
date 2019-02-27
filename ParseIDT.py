import idaapi

idtr_str = Eval('SendDbgCommand("r idtr")')
idtr = long(idtr_str[5:-1],16)
print "idtr = 0x%x" % idtr
i = 256
for i in range(0,256):
    buf = idaapi.dbg_read_memory(idtr+16*i, 16)
    isr = 0
    isr = isr + (ord(buf[11]) << (8*7))
    isr = isr + (ord(buf[10]) << (8*6))
    isr = isr + (ord(buf[9]) << (8*5))
    isr = isr + (ord(buf[8]) << (8*4))
    isr = isr + (ord(buf[7]) << (8*3))
    isr = isr + (ord(buf[6]) << (8*2))
    isr = isr + (ord(buf[1]) << (8*1))
    isr = isr + (ord(buf[0]) << (8*0))
    #for j in range(6,12):
    #    isr = isr+(ord(buf[j]) << (8*(j-4)))
    #for j in range(0,2):
    #    isr = isr+(ord(buf[j]) << (8*(j)))
    print "isr %x address = 0x" % i,hex(isr)
    idc.MakeCode(isr)
    idc.MakeFunction(isr)
    MakeNameEx(isr,str('mISR_') + hex(i).upper(), SN_NOWARN)
