import idaapi

HvEntryPoint = idc.get_reg_value('rdx')
print("HvEntryPoint: ", hex(HvEntryPoint))

#
# patched instruction:
# mov     rax, cr4
#

patch_offset = 0x7A
ida_bytes.patch_byte(HvEntryPoint + patch_offset, 0xEB)
ida_bytes.patch_byte(HvEntryPoint + patch_offset + 1, 0xFE)

nop_count = 1

for i in range(0, nop_count):
    ida_bytes.patch_byte(patch_offset + 2 + i, 0x90)

print("patch is finished")
