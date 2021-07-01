__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"

import idautils
import idaapi

hvl_load_start = (0x48, 0x89, 0x5c, 0x24, 0x10)
hvl_launch_start = (0x4C, 0x8B, 0xDC)
hvix64_launch_start = {}


def GetFuncByName(name):
    var_address = idc.get_name_ea_simple(name)

    if var_address == 0:
        print("variable " + name + " was not found")
        return 0

    f_address = idc.Qword(var_address)

    if f_address == 0:
        print("function address is 0")
        return 0

    print(name + ":" + hex(f_address))

    return f_address


def PatchHvix64():
    nop_count = 3

    # HvImageInfo - manual defined structure inside hvloader.dll. Pointer inside HvlLaunchHypervisor, near
    # hvix64 launching proc.

    # mov    rax, cr4
    # btr    rax, 7
    # mov    cr4, rax
    # mov    rcx, cs: HvImageInfo
    # mov    rdx, [rcx + 10h]; hvix64.exe entry  point
    # mov    rcx, [rcx + 18h]; hvix64.exe image  size call mJumpToHvCodeL0
    # good idea to find HvImageBase in hvloader image address space.
    # hvix64.exe VA is not accessible, until some cr3 modification.

    hv_image_info_struct = GetFuncByName("HvImageInfo")
    hvix_start = idc.Qword(hv_image_info_struct + 0x10)

    print("patched hvix_start address: " + hex(hvix_start))

    ida_bytes.patch_byte(hvix_start, 0xEB)
    ida_bytes.patch_byte(hvix_start + 1, 0xFE)

    for i in range(0, nop_count):
        ida_bytes.patch_byte(hvix_start + 2 + i, 0x90)


def GetExportedFunctionByName(name):
    for funcAddr in idautils.Functions():
        funcName = idc.get_func_name(funcAddr)
        if funcName == name:
            print(name + ":" + hex(funcAddr))
            return funcAddr


def RestoreProc(hv_function_address, ar_bytes):
    i = 0
    for x in ar_bytes:
        ida_bytes.patch_byte(hv_function_address + i, x)
        i = i + 1


def RestoreHvLoader(func_name, bytes_ar):
    print("script starting")
    func_address = GetExportedFunctionByName(func_name)

    if func_address != 0:
        RestoreProc(func_address, bytes_ar)
        print("restore finished")
    else:
        print("hvl_load_hv is 0")


# RestoreHvLoader("HvlLoadHypervisor", hvl_load_start)
RestoreHvLoader("HvlLaunchHypervisor", hvl_launch_start)
