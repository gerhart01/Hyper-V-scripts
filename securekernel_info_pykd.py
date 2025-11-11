
__author__ = "Arthur Khudyaev (www.x.com/gerhart_x)"
__license__ = "GPL3"
__version__ = "1.4.0"

#
# some variables was taken from
# https://pdfs.semanticscholar.org/e275/cc28c5c8e8e158c45e5e773d0fa3da01e118.pdf
#
# Example: "!py -g securekernel_parse_pykd.py skvars"
#

import argparse
import sys
from pykd import *


def find_securekernel_base():
    try:
        securnt = pykd.module("securekernel")
        print("securekernel base:", securnt)
        return securnt
    except:
        print("securekernel.exe module is not found")
        return 0


def parse_idt_table():

    skip_ski_fatal_exception = True
    ski_fatal_exception = 0

    if skip_ski_fatal_exception:
        try:
            securnt = pykd.module("securekernel")
            print("securekernel base:", securnt)
            ski_fatal_exception = securnt.SkiFatalException
            print("Skip securekernel!SkiFatalException routine:", hex(ski_fatal_exception))
        except:
            print("securekernel.exe module is not found")
    
    idtr = reg("idtr")

    print("idtr = ", hex(idtr))
    i = 256
    count = 0
    for i in range(0, 256):
        buf = loadBytes(idtr+16*i, 16)
        if buf[2] != 0: 
            #print "IDT selector %x" % buf[2]
            isr = 0
            isr = isr + (buf[11] << (8*7))
            isr = isr + (buf[10] << (8*6))
            isr = isr + (buf[9] << (8*5))
            isr = isr + (buf[8] << (8*4))
            isr = isr + (buf[7] << (8*3))
            isr = isr + (buf[6] << (8*2))
            isr = isr + (buf[1] << (8*1))
            isr = isr + (buf[0] << (8*0))
            if skip_ski_fatal_exception:
                if isr != ski_fatal_exception:
                    print(i, "ISR: ", findSymbol(isr))
                    count = count + 1
            else:
                print(i, "ISR: ", findSymbol(isr))
                count = count + 1

    print("Count:", count)
    

def list_loaded_modules():

    # 
	# some information was taken from 
	# https://github.com/Cr4sh/s6_pcie_microblaze/blob/master/python/payloads/DmaBackdoorHv/backdoor_client/backdoor_client/backdoor_client.cpp
	# 
    
    obj_securnt = find_securekernel_base()
    
    module_path_offset = 0x48
    module_name_offset = 0x58

    if obj_securnt == 0:
        return

    SkLoadedModuleList = obj_securnt.SkLoadedModuleList

    print("SkLoadedModuleList:", hex(SkLoadedModuleList))

    list_entry = pykd.ptrQWord(SkLoadedModuleList)
    list_next = ptrQWord(list_entry)

    module_name = pykd.loadUnicodeString(list_entry + module_name_offset)
    print("module_name: ", module_name)

    module_path = pykd.loadUnicodeString(list_entry + module_path_offset)
    print("module_path: ", module_path)
    print("")

    while (list_next != SkLoadedModuleList):
    
        module_name = pykd.loadUnicodeString(list_next + module_name_offset)
        print("module_name: ", module_name)

        module_path = pykd.loadUnicodeString(list_next + module_path_offset)
        print("module_path: ", module_path)
        print("")

        list_next = pykd.ptrQWord(list_next)
        # print("list_next:", hex(list_next))
    
    return 0


def list_syscall_entries():

    obj_securnt = find_securekernel_base()

    if obj_securnt == 0:
        return

    IumSyscallDispEntries = obj_securnt.IumSyscallDispEntries

    print("IumSyscallDispEntries: ", hex(IumSyscallDispEntries))

    break_cycle = False
    i = 0
    count = 0

    while (break_cycle == False):

        syscall_entry = pykd.ptrQWord(IumSyscallDispEntries + i*8)

        if (syscall_entry == 0):
             
            break_cycle = True
            break

        syscall_number = pykd.ptrQWord(IumSyscallDispEntries + i*8 + 8)

        syscal_number_str = hex(syscall_number)+":"

        print(syscal_number_str,findSymbol(syscall_entry))
        
        i = i + 2
        count = count + 1

    print("Count:", count)


def get_process_name_by_pid(pid):
    pslist = pykd.getLocalProcesses()

    for ps_obj in pslist:

        print(ps_obj[0])
        if ps_obj[0] == pid:
            return ps_obj[1]

    return "None"
    

def list_sk_process():

    obj_securnt = find_securekernel_base()

    if obj_securnt == 0:
        return

    SkpsProcessList = obj_securnt.SkpsProcessList

    print("SkpsProcessList:", hex(SkpsProcessList))

    proc_entry = pykd.ptrQWord(SkpsProcessList)

    # ps_name = get_process_name_by_pid(0x278)

    a = pykd.getNumberProcesses()
    print(a)

def print_ascii_string_variable(obj_securnt, varName):
    try:
        x = getattr(obj_securnt, varName)
    except:
        print("Variable " + varName + " is not presented in current version of securekernel")
        return
    
    #varAddress = hex(pykd.ptrQWord(x))
    varValue = pykd.loadCStr(x)

    print(varName+":", varValue)


def print_variable(obj_securnt, varName, size):
    
    try:
        x = getattr(obj_securnt, varName)
    except:
        print("Variable " + varName + " is not presented in current version of securekernel")
        return

    varValue = ""
    if size == 1:
        varValue = hex(pykd.ptrByte(x))
    if size == 2:
        varValue = hex(pykd.ptrWord(x))
    if size == 4:
        varValue = hex(pykd.ptrDWord(x))
    if size == 8:
        varValue = hex(pykd.ptrQWord(x))

    print(varName+":", varValue)
    return


def list_sk_variables():
    
    obj_securnt = find_securekernel_base()

    if obj_securnt == 0:
        return

    print_ascii_string_variable(obj_securnt, "SkBuildLab")
    print_variable(obj_securnt, "CmNtCSDVersion", 8)
    print_variable(obj_securnt, "SkpsSystemDirectoryTableBase", 8)
    print_variable(obj_securnt, "SkImageBase", 8)
    print_variable(obj_securnt, "SkeLoaderBlock", 8)
    print_variable(obj_securnt, "IumSyscallDescriptor", 4)
    print_variable(obj_securnt, "IumSyscallCustomApiFcnTable", 8)
    print_variable(obj_securnt, "ShvlpFlags", 4)
    print_variable(obj_securnt, "SkeProcessorBlock", 8)
    print_variable(obj_securnt, "SkpKernelVtl0BufferBase", 8)
    print_variable(obj_securnt, "SkpKernelVtl1BufferBase", 8)
    print_variable(obj_securnt, "SkpKernelVtl0BufferLock", 4)
    print_variable(obj_securnt, "SkpKernelVtl0BufferHint", 4)
    print_variable(obj_securnt, "SkpNtosUserSharedData", 8)
    print_variable(obj_securnt, "SkmiCodeIntegrityData", 8)
    print_variable(obj_securnt, "SkmiCodeIntegrityDataSize", 4)
    print_variable(obj_securnt, "SkmiImageTableSize", 4)
    print_variable(obj_securnt, "SkobpGlobalHandleTable", 8)
    print_variable(obj_securnt, "SkiNtosIdt", 8)
    print_variable(obj_securnt, "IumLkArrayHandle", 8)
    print_variable(obj_securnt, "IumIdkSigningHandle", 8)
    print_variable(obj_securnt, "IumTpmBindingItemsHandle", 8)
    print_variable(obj_securnt, "IumLkHandle", 8)
    print_variable(obj_securnt, "IumHbkHandle", 8)
    print_variable(obj_securnt, "IumIdkHandle", 8)
    print_variable(obj_securnt, "IumMkPerBootHandle", 8)
    print_variable(obj_securnt, "SkeProcessorArchitecture", 2)
    print_variable(obj_securnt, "SkmiHighestPhysicalPage", 8)
    print_variable(obj_securnt, "SkmiLowestPhysicalPage", 8)
    print_variable(obj_securnt, "SkmmNumberOfPhysicalPages", 8)
    print_variable(obj_securnt, "SkpspNativeDllInfo", 8)
    print_variable(obj_securnt, "VertdllExports", 8)
    print_variable(obj_securnt, "NtdllExports", 8)
    print_variable(obj_securnt, "SkeKernelStackSize", 4)
    print_variable(obj_securnt, "SkeNtKernelImports", 8)
    print_variable(obj_securnt, "SkiHyperlaunchEntrypoint", 8)
    print_variable(obj_securnt, "SkmmNtoskrnlBase", 8)
    print_variable(obj_securnt, "SkeNtKernelImports", 8)
    print_variable(obj_securnt, "PsIumSystemProcess", 8)
    print_variable(obj_securnt, "ShvlpPartitionInfoPage", 8)
    print_variable(obj_securnt, "ShvlpVpAssistPfn", 8)
    print_variable(obj_securnt, "ShvlEarlyBootParameterPage", 8)
    print_variable(obj_securnt, "ShvlpVtlCall", 8)
    print_variable(obj_securnt, "ShvlpHypercallCodePage", 8)
    print_variable(obj_securnt, "ShvlpCodePa", 8)
    print_variable(obj_securnt, "ShvlpEnteredMinimalDispatchLoop", 1)
    print_variable(obj_securnt, "ShvlpEnlightenmentInfo", 8)
    print_variable(obj_securnt, "ShvlpHandleExceptionIntercept", 8)
    print_variable(obj_securnt, "ShvlpReferenceTscPage", 8)
    print_variable(obj_securnt, "SkiProfileListHead", 8)
    print_variable(obj_securnt, "SkiLongIpiLog", 8)
    print_variable(obj_securnt, "SkmiScPrvSecurePool", 8)
    print_variable(obj_securnt, "RtlpHpHeapGlobals", 8)
    print_variable(obj_securnt, "SkiInitialPrcbStorage", 1)
    print_variable(obj_securnt, "NtGlobalFlag", 4)
    print_variable(obj_securnt, "IumpSingleThreadedServiceRequestEntered", 4)
    print_variable(obj_securnt, "RtlpInterceptorsCount", 4)
    print_variable(obj_securnt, "SkhalpEfiRuntimeServicesBlock", 8)
    print_variable(obj_securnt, "SkmiDriverProxyActiveSwapDelayeedFreeList", 8)
    print_variable(obj_securnt, "SkhalpDmaEnablerListHead", 8)
    print_variable(obj_securnt, "SkpnpSdevDeviceTypesAvailable", 4)
    print_variable(obj_securnt, "SkpnpSdevTable", 8)
    print_variable(obj_securnt, "SkpsProcessListLock", 4)
    print_variable(obj_securnt, "SkpsProcessList", 8)
    print_variable(obj_securnt, "SkpgHotpatchIpiRequest", 8)
    print_variable(obj_securnt, "SkpgExtentChecksActiveCount", 4)
    print_variable(obj_securnt, "SkpgHibernateActive", 4)
    print_variable(obj_securnt, "SkpgPatchGuardTbFlush", 4)
    print_variable(obj_securnt, "IumSkCrashDumpEncryptionHandle", 8)
    print_variable(obj_securnt, "IumHvCrashDumpEncryptionHandle", 8)
    print_variable(obj_securnt, "RtlpPropStoreLock", 4)
    print_variable(obj_securnt, "RtlpPtrTreeLock", 4)
    print_variable(obj_securnt, "g_SecureBootActivePlatformManifestSize", 4)
    print_variable(obj_securnt, "g_SecureBootActivePlatformManifest", 8)
    print_variable(obj_securnt, "SecurePoolGlobalState", 8)
    print_variable(obj_securnt, "SkpIcInterceptInstalled", 1)
    print_variable(obj_securnt, "SkpLiveDumpContext", 4)
    print_variable(obj_securnt, "SkpWorkItemQueued", 4)
    print_variable(obj_securnt, "SkpWorkItemList", 8)
    print_variable(obj_securnt, "SkNtosUserSharedData", 8)
    print_variable(obj_securnt, "SkPoolAllocationsFailed", 4)
    print_variable(obj_securnt, "KdpDebuggerDataListHead", 8)
    print_variable(obj_securnt, "KdDebuggerDataBlock", 8)
    print_variable(obj_securnt, "KdVersionBlock", 4)
    print_variable(obj_securnt, "SkmmSystemRangeStart", 8)
    print_variable(obj_securnt, "SkmmUserProbeAddress", 1)
    print_variable(obj_securnt, "SkmmPhysicalMemoryBlock", 1)
    print_variable(obj_securnt, "SkBuildNumber", 4)
    print_variable(obj_securnt, "SkmmNteBase", 8)
    print_variable(obj_securnt, "SkmmPfnDatabase", 8)
    print_variable(obj_securnt, "SkmmPteBase", 8)
    print_variable(obj_securnt, "SkmmUserProbeAddress", 8)
    print_variable(obj_securnt, "SkmmSystemRangeStart", 8)
    print_variable(obj_securnt, "SkmmHighestUserAddress", 8)        

def main():
    """Main dispatcher function"""
    parser = argparse.ArgumentParser(
        description="Kernel debugging and analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'command',
        choices=['idt', 'modules', 'syscalls', 'skprocess', 'skvars'],
        help='Command to execute'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Function mapping
    commands = {
        'idt': parse_idt_table,
        'modules': list_loaded_modules,
        'syscalls': list_syscall_entries,
        'skprocess': list_sk_process,
        'skvars': list_sk_variables
    }
    
    # Execute the selected function
    try:
        commands[args.command]()
    except KeyError:
        print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error executing {args.command}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
