import idaapi
import idautils


def GetExportedFunctionByName(name):
    for funcAddr in idautils.Functions():
        funcName = idc.get_func_name(funcAddr)
        if funcName == name:
            print(name + ":" + hex(funcAddr))
            return funcAddr

HvEntryPoint = GetExportedFunctionByName('start')
print("hvix64 entry point: ", hex(HvEntryPoint))

#
# restored instruction:
# mov     rax, cr4
#

patch_offset = 0x7A
original_opcode = [0x0F, 0x20, 0xE0]
patch_address = HvEntryPoint + patch_offset

for code_byte in original_opcode:
    ida_bytes.patch_byte(patch_address, code_byte)
    patch_address = patch_address + 1

print("restore is finished")
