#
# developed by @gerhart_x
#

#
# some variables was taken from
# https://pdfs.semanticscholar.org/e275/cc28c5c8e8e158c45e5e773d0fa3da01e118.pdf
#


from pykd import *
import sys

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
    # idtr = 0xfffff80224148970
    print("idtr = ", hex(idtr))
    i = 256
    count = 0
    for i in range(0, 256):
        buf = loadBytes(idtr+16*i, 16)
        if buf[2] != 0: #idtEntry.Selector
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
	# some info was taken from 
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

    print("IumSyscallDispEntries:", hex(IumSyscallDispEntries))

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

	# https://github.com/Cr4sh/s6_pcie_microblaze/blob/master/python/payloads/DmaBackdoorHv/backdoor_client/backdoor_client/backdoor_client.cpp

    obj_securnt = find_securekernel_base()

    if obj_securnt == 0:
        return

    SkpsProcessList = obj_securnt.SkpsProcessList

    print("SkpsProcessList:", hex(SkpsProcessList))

    proc_entry = pykd.ptrQWord(SkpsProcessList)

    # ps_name = get_process_name_by_pid(0x278)

    a = pykd.getNumberProcesses()
    print(a)

def list_sk_variables():
    
    obj_securnt = find_securekernel_base()

    if obj_securnt == 0:
        return

    SkpsSystemDirectoryTableBase = pykd.ptrQWord(obj_securnt.SkpsSystemDirectoryTableBase)
    print("SkpsSystemDirectoryTableBase:", hex(SkpsSystemDirectoryTableBase))

    SkImageBase = pykd.ptrQWord(obj_securnt.SkImageBase)
    print("SkImageBase:", hex(SkImageBase))

    SkeLoaderBlock = pykd.ptrQWord(obj_securnt.SkeLoaderBlock)
    print("SkeLoaderBlock:", hex(SkeLoaderBlock))

    IumSyscallDescriptor = obj_securnt.IumSyscallDescriptor
    print("IumSyscallDescriptor array:", hex(IumSyscallDescriptor))

    IumSyscallCustomApiFcnTable = pykd.ptrQWord(obj_securnt.IumSyscallCustomApiFcnTable)
    print("IumSyscallCustomApiFcnTable:", hex(IumSyscallCustomApiFcnTable))

    ShvlpFlags = pykd.ptrQWord(obj_securnt.ShvlpFlags)
    print("ShvlpFlags:",hex(ShvlpFlags))

    SkeProcessorBlock = pykd.ptrQWord(obj_securnt.SkeProcessorBlock)
    print("SkeProcessorBlock:",hex(SkeProcessorBlock))

    SkpKernelVtl0BufferBase = pykd.ptrQWord(obj_securnt.SkpKernelVtl0BufferBase)
    print("SkpKernelVtl0BufferBase:",hex(SkpKernelVtl0BufferBase))

    SkpKernelVtl1BufferBase = pykd.ptrQWord(obj_securnt.SkpKernelVtl1BufferBase)
    print("SkpKernelVtl1BufferBase:",hex(SkpKernelVtl1BufferBase))

    SkpNtosUserSharedData = obj_securnt.SkpNtosUserSharedData
    print("SkpNtosUserSharedData address:", hex(SkpNtosUserSharedData))

    SkmiImageTableSize = pykd.ptrDWord(obj_securnt.SkmiImageTableSize)
    print("SkmiImageTableSize:", hex(SkmiImageTableSize))

def sar_5(value):

    res_value = value >> 5
    res_value = res_value | 0xF800000000000000

    return res_value

    

def decypher_ski_secure_service_table():

    obj_securnt = find_securekernel_base()

    if obj_securnt == 0:
        return

    SkiSecureServiceTable = obj_securnt.SkiSecureServiceTable
    print("SkiSecureServiceTable:",hex(SkiSecureServiceTable))

    SkiSecureServiceLimit = pykd.ptrDWord(obj_securnt.SkiSecureServiceLimit)
    print("SkiSecureServiceLimit:",hex(SkiSecureServiceLimit))

    count = 0

    while (count < SkiSecureServiceLimit):

        compact_sk_syscall = pykd.ptrDWord(SkiSecureServiceTable + count * 4)

        # movsxd  r11, dword ptr [r10+rax*4]
        
        deciphered_value = (0xFFFFFFFF00000000+compact_sk_syscall) & 0xFFFFFFFFFFFFFFFF

        # sar     r11, 5

        deciphered_value = sar_5(deciphered_value)

        # add     r10, r11

        deciphered_value = (deciphered_value + SkiSecureServiceTable) & 0xFFFFFFFFFFFFFFFF

        result_string = hex(count)+". Compact syscall: "+hex(compact_sk_syscall)+". Deciphered syscall: "+findSymbol(deciphered_value)

        print(result_string)

        count+=1

        
    

# parse_idt_table()  
# list_loaded_modules()
# list_syscall_entries()
# list_sk_process()
# list_sk_variables()
decypher_ski_secure_service_table()



