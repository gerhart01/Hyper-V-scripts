__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"

#
# developed by @gerhart_x
# IDA PRO 7.5
#

import idaapi

idtr_str = idc.eval_idc('send_dbg_command("r idtr")')
idtr = int(idtr_str[5:-1], 16)
print("idtr = 0x%x" % idtr)
i = 256

for i in range(0, 256):
    buf = idaapi.dbg_read_memory(idtr+16*i, 16)
    isr = 0
    isr = isr + (buf[11] << (8*7))
    isr = isr + (buf[10] << (8*6))
    isr = isr + (buf[9] << (8*5))
    isr = isr + (buf[8] << (8*4))
    isr = isr + (buf[7] << (8*3))
    isr = isr + (buf[6] << (8*2))
    isr = isr + (buf[1] << (8*1))
    isr = isr + (buf[0] << (8*0))
    print("ISR_%x address:" % i, hex(isr))
    idc.create_insn(isr)
    idc.add_func(isr)
    idc.set_name(isr, str('mISR_') + hex(i).upper(), SN_NOWARN)
