import idaapi

HvEntryPoint = GetRegValue('rdx')
print("HvEntryPoint: ", hex(HvEntryPoint))

#
# patched instruction:
# mov     rax, cr4
#

patch_offset = 0x7A
PatchByte(HvEntryPoint + patch_offset, 0xEB)
PatchByte(HvEntryPoint + patch_offset + 1, 0xFE)

nop_count = 1

for i in range(0, nop_count):
    PatchByte(patch_offset + 2 + i, 0x90)

print("patch is finished")
