__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"

#
# developed by @gerhart_x
# IDA PRO 7.5
#

# Script parsing and formating structures with hypercall handlers in hvix64.exe
# Microsoft doesn't provide symbols for hvix64.exe, therefore i called it VmcallHandlersTable
# Hypercalls were taken from Hyper-V TLFS, winhvr.sys, winhv.sys, ntoskrnl.exe, securekernel.exe
# Windows 10 and Windows Server 2019 have different hypercalls. There are not many, but don't forget about it.

# 04-01-2020 Add hvix64 OS detection by hypercalls count
# 04-01-2020 Hypercall names updates from hvgdk.h (https://github.com/ionescu007/hdk/blob/master/hvgdk.h)
# 04-01-2020 Add dynamically hypercall's count finding method
# 27-08-2020 Hypercalls updates from new version of hvgdk.h (https://github.com/ionescu007/hdk/blob/master/hvgdk.h)
# https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml

import idaapi

hvcalls_dict = {
    0x0000: 'HvCallReserved00',
    0x0001: 'HvCallSwitchVirtualAddressSpace',
    0x0002: 'HvCallFlushVirtualAddressSpace',
    0x0003: 'HvCallFlushVirtualAddressList',
    0x0004: 'HvCallGetLogicalProcessorRunTime',
    0x0005: 'HvCallUpdateHvProcessorFeatures',              #winhvr.sys (09.2019)
    0x0006: 'HvCallSwitchAliasMap',
    0x0007: 'HvCallUpdateMicrocodeDatabase',                #ntoskrnl.exe, HvDynamicUpdateMicrocode has same microcode
    0x0008: 'HvCallNotifyLongSpinWait',
    0x0009: 'HvCallParkedLogicalProcessors',
    0x000a: 'HvCallInvokeHypervisorDebugger',                  
	#2016
    0x000b: 'HvCallSendSyntheticClusterIpi',                #SkpgPatchGuardCallbackRoutine
    0x000c: 'HvCallModifyVtlProtectionMask',
    0x000d: 'HvCallEnablePartitionVtl',
    0x000e: 'HvCallDisablePartitionVtl',
    0x000f: 'HvCallEnableVpVtl',
    0x0010: 'HvCallDisableVpVtl',
    0x0011: 'HvCallVtlCall',
    0x0012: 'HvCallVtlReturn',
    0x0013: 'HvCallFlushVirtualAddressSpaceEx',
    0x0014: 'HvCallFlushVirtualAddressListEx',
    0x0015: 'HvCallSendSyntheticClusterIpiEx',              #securekernel.exe, SkpgPatchGuardCallbackRoutine
	#####
    0x0016: 'HvCallQueryImageInfo',
    0x0017: 'HvCallMapPatchPages',                          #securekernel.exe, ShvlLoadHypervisorPatch
    0x0018: 'HvCallCommitPatch',                            #securekernel.exe, ShvlLoadHypervisorPatch
    0x0019: 'HvCallSyncContext ',
    0x001a: 'HvCallSyncContextEx',
    0x001b: 'HvCallReadPerfRegister',
    0x001c: 'HvCallWritePerfRegister',                      #ntoskrnl.exe, Fast hypercall
    0x001d: 'HvCallReserved00',
    0x001e: 'HvCallReserved00',
    0x001f: 'HvCallReserved00',
    0x0020: 'HvCallReserved00',
    0x0021: 'HvCallReserved00',
    0x0022: 'HvCallReserved00',
    0x0023: 'HvCallReserved00',
    0x0024: 'HvCallReserved00',
    0x0025: 'HvCallReserved00',
    0x0026: 'HvCallReserved00',
    0x0027: 'HvCallReserved00',
    0x0028: 'HvCallReserved00',
    0x0029: 'HvCallReserved00',
    0x002a: 'HvCallReserved00',
    0x002b: 'HvCallReserved00',
    0x002c: 'HvCallReserved00',
    0x002d: 'HvCallReserved00',
    0x002e: 'HvCallReserved00',
    0x002f: 'HvCallReserved00',
    0x0030: 'HvCallReserved00',
    0x0031: 'HvCallReserved00',
    0x0032: 'HvCallReserved00',
    0x0033: 'HvCallReserved00',
    0x0034: 'HvCallReserved00',
    0x0035: 'HvCallReserved00',
    0x0036: 'HvCallReserved00',
    0x0037: 'HvCallReserved00',
    0x0038: 'HvCallReserved00',
    0x0039: 'HvCallReserved00',
    0x003a: 'HvCallReserved00',
    0x003b: 'HvCallReserved00',
    0x003c: 'HvCallReserved00',
    0x003d: 'HvCallReserved00',
    0x003e: 'HvCallReserved00',
    0x003f: 'HvCallReserved00',
    0x0040: 'HvCallCreatePartition',
    0x0041: 'HvCallInitializePartition',
    0x0042: 'HvCallFinalizePartition',
    0x0043: 'HvCallDeletePartition',
    0x0044: 'HvCallGetPartitionProperty',
    0x0045: 'HvCallSetPartitionProperty',
    0x0046: 'HvCallGetPartitionId',
    0x0047: 'HvCallGetNextChildPartition',
    0x0048: 'HvCallDepositMemory',
    0x0049: 'HvCallWithdrawMemory',
    0x004A: 'HvCallGetMemoryBalance',
    0x004B: 'HvCallMapGpaPages',
    0x004C: 'HvCallUnmapGpaPages',
    0x004D: 'HvCallInstallIntercept',
    0x004E: 'HvCallCreateVp',
    0x004F: 'HvCallDeleteVp',
    0x0050: 'HvCallGetVpRegisters',
    0x0051: 'HvCallSetVpRegisters',
    0x0052: 'HvCallTranslateVirtualAddress',                #used by securekernel.exe
    0x0053: 'HvCallReadGpa',
    0x0054: 'HvCallWriteGpa',
    0x0055: 'HvCallAssertVirtualInterruptDeprecated',                             #depricated
    0x0056: 'HvCallClearVirtualInterrupt',
    0x0057: 'HvCallCreatePortDeprecated',
    0x0058: 'HvCallDeletePort',
    0x0059: 'HvCallConnectPortDeprecated',
    0x005A: 'HvCallGetPortProperty',
    0x005B: 'HvCallDisconnectPort',
    0x005C: 'HvCallPostMessage',
    0x005D: 'HvCallSignalEvent',
    0x005E: 'HvCallSavePartitionState',                     #HvCancelSavePartitionState in latest winhvr.sys (09.2019), HvSavePartitionState has same Hypercall ID
    0x005F: 'HvCallRestorePartitionState',                  #HvCancelRestorePartitionState in latest winhvr.sys (09.2019)
    0x0060: 'HvCallInitializeEventLogBufferGroup',
    0x0061: 'HvCallFinalizeEventLogBufferGroup',
    0x0062: 'HvCallCreateEventLogBuffer',
    0x0063: 'HvCallDeleteEventLogBuffer',
    0x0064: 'HvCallMapEventLogBuffer',
    0x0065: 'HvCallUnmapEventLogBuffer',
    0x0066: 'HvCallSetEventLogGroupSources',
    0x0067: 'HvCallReleaseEventLogBuffer',
    0x0068: 'HvCallFlushEventLogBuffer',
    0x0069: 'HvCallPostDebugData',
    0x006A: 'HvCallRetrieveDebugData',
    0x006B: 'HvCallResetDebugSession',
    0x006C: 'HvCallMapStatsPage',
    0x006D: 'HvCallUnmapStatsPage',
    0x006E: 'HvCallMapSparseGpaPages',
    0x006F: 'HvCallSetSystemProperty',                      #HvConfigureProfiler, HvSetHvDebugProperty we can see in winhvr.sys (09.2019)
    0x0070: 'HvCallSetPortProperty',
    0x0071: 'HvCallOutputDebugCharacter',
    0x0072: 'HvCallEchoIncrement',
    0x0073: 'HvCallPerfNop',
    0x0074: 'HvCallPerfNopInput',
    0x0075: 'HvCallPerfNopOutput',
    0x0076: 'HvCallAddLogicalProcessor',
    0x0077: 'HvCallRemoveLogicalProcessor',
    0x0078: 'HvCallQueryNumaDistance',
    0x0079: 'HvCallSetLogicalProcessorProperty',
    0x007A: 'HvCallGetLogicalProcessorProperty',
    0x007B: 'HvCallGetSystemProperty',                      #HvGetSystemInformation in winhvr.sys (09.2019)
    0x007C: 'HvCallMapDeviceInterrupt',
    0x007D: 'HvCallUnmapDeviceInterrupt',
    0x007E: 'HvCallRetargetDeviceInterrupt',                #renamed
    0x007F: 'HvCallRetargetRootDeviceInterrupt',            #made reserved
    0x0080: 'HvCallMapDevicePages',                         #HvAssertDeviceInterrupt in winhvr.sys (09.2019). HvMapDevicePages is not present.
    0x0081: 'HvCallUnmapDevicePages',
    0x0082: 'HvCallAttachDevice',
    0x0083: 'HvCallDetachDevice',
    0x0084: 'HvCallEnterSleepState',
    0x0085: 'HvCallNotifyStandbyTransition',                        #HvNotifyStandbyTransition in winhvr.sys (09.2019)
    0x0086: 'HvCallPrepareForHibernate',
    0x0087: 'HvCallNotifyPartitionEvent',
    0x0088: 'HvCallGetLogicalProcessorRegisters',
    0x0089: 'HvCallSetLogicalProcessorRegisters',
    0x008A: 'HvCallQueryAssociatedLpsforMca',
    0x008B: 'HvCallNotifyRingEmpty',                        #HvGetNextQueuedPort in winhvr.sys (09.2019)
    0x008C: 'HvCallInjectSyntheticMachineCheck',
    0x008d: 'HvCallScrubPartition',
    0x008e: 'HvCallCollectLivedump',
    0x008f: 'HvCallDisableHypervisor',
    0x0090: 'HvCallModifySparseGpaPages',
    0x0091: 'HvCallRegisterInterceptResult',
    0x0092: 'HvCallUnregisterInterceptResult',
	#2016
    0x0093: 'HvCallGetCoverageData',
    0x0094: 'HvCallAssertVirtualInterrupt',
    0x0095: 'HvCallCreatePort',
    0x0096: 'HvCallConnectPort',
    0x0097: 'HvCallGetSpaPageList',
    0x0098: 'HvCallReserved00',
    0x0099: 'HvCallStartVirtualProcessor',
    0x009A: 'HvCallGetVpIndexFromApicId',
    0x009B: 'HvCallGetPowerProperty',
    0x009C: 'HvCallSetPowerProperty',
    0x009D: 'HvCallCreatePasidSpace',
    0x009E: 'HvCallDeletePasidSpace',
    0x009F: 'HvCallSetPasidAddressSpace',
    0x00A0: 'HvCallFlushPasidAddressSpace',
    0x00A1: 'HvCallFlushPasidAddressList',
    0x00A2: 'HvCallAttachPasidSpace',
    0x00A3: 'HvCallDetachPasidSpace',
    0x00A4: 'HvCallEnablePasid',
    0x00A5: 'HvCallDisablePasid',
    0x00A6: 'HvCallAcknowledgePageRequest',
    0x00A7: 'HvCallCreateDevicePrQueue',
    0x00A8: 'HvCallDeleteDevicePrQueue',
    0x00A9: 'HvCallSetDevicePrqProperty',
    0x00AA: 'HvCallGetPhysicalDeviceProperty',
    0x00AB: 'HvCallSetPhysicalDeviceProperty',
    0x00AC: 'HvCallTranslateVirtualAddressEx',               #winhvr.sys. Early it has hypercall id 0x52
    0x00AD: 'HvCallCheckForIoIntercept',	                 #winhvr.sys
    0x00AE: 'HvCallSetGpaPageAttributes',                    #securekernel.exe
    0x00AF: 'HvCallFlushGuestPhysicalAddressSpace',
    0x00B0: 'HvCallFlushGuestPhysicalAddressList',
        #2019
    0x00B1: 'HvCallCreateDeviceDomain',
    0x00B2: 'HvCallAttachDeviceDomain',                      #securekernel.exe
    0x00B3: 'HvCallMapDeviceGpaPages',                       #securekernel.exe
    0x00B4: 'HvCallUnmapDeviceGpaPages',                     #securekernel.exe
    0x00B5: 'HvCallCreateCpuGroup',                          #winhvr.sys
    0x00B6: 'HvCallDeleteCpuGroup',                          #winhvr.sys
    0x00B7: 'HvCallGetCpuGroupProperty',                     #winhvr.sys
    0x00B8: 'HvCallSetCpuGroupProperty',                     #winhvr.sys
    0x00B9: 'HvCallGetCpuGroupAffinity',                     #winhvr.sys
    0x00BA: 'HvCallGetNextCpuGroup',                         #winhvr.sys
    0x00BB: 'HvCallGetNextCpuGroupPartition',                #winhvr.sys
    0x00BC: 'HvCallAddPhysicalMemory',
    0x00BD: 'HvCallCompleteIntercept',                       #winhvr.sys
    0x00BE: 'HvCallPrecommitGpaPages',                       #winhvr.sys
    0x00BF: 'HvCallUncommitGpaPages',                        #winhvr.sys
    0x00C0: 'HvCallReserved00',
    0x00C1: 'HvCallReserved00', 
    0x00C2: 'HvCallDispatchVp',                              #winhvr.sys, fast hypercall
    0x00C3: 'HvCallProcessIommuPrq',
    0x00C4: 'HvCallDetachDeviceDomain',
    0x00C5: 'HvCallDeleteDeviceDomain',
    0x00C6: 'HvCallQueryDeviceDomain',
    0x00C7: 'HvCallMapSparseDeviceGpaPages',
    0x00C8: 'HvCallUnmapSparseDeviceGpaPages',
    0x00C9: 'HvCallGetGpaPagesAccessState',                  #winhvr.sys
    0x00CA: 'HvCallGetSparseGpaPagesAccessState',
    0x00CB: 'HvCallInvokeTestFramework', 
    0x00CC: 'HvCallQueryVtlProtectionMaskRange',             #winhvr.sys
    0x00CD: 'HvCallModifyVtlProtectionMaskRange',            #winhvr.sys
    0x00CE: 'HvCallConfigureDeviceDomain',
    0x00CF: 'HvCallQueryDeviceDomainProperties',
    0x00D0: 'HvCallFlushDeviceDomain',
    0x00D1: 'HvCallFlushDeviceDomainList', 
    0x00D2: 'HvCallAcquireSparseGpaPageHostAccess',          #winhvr.sys
    0x00D3: 'HvCallReleaseSparseGpaPageHostAccess',          #winhvr.sys
    0x00D4: 'HvCallCheckSparseGpaPageVtlAccess',             #winhvr.sys
    0x00D5: 'HvCallEnableDeviceInterrupt',
    0x00D6: 'HvCallFlushTlb',
    0x00D7: 'HvCallAcquireSparseSpaPageHostAccess',          #winhvr.sys
    0x00D8: 'HvCallUnacquireSparseSpaPageHostAccess',          #winhvr.sys
    0x00D9: 'HvCallAcceptGpaPages',                          #winhv.sys
    0x00DA: 'HvCallUnacceptGpaPages',
    0x00DB: 'HvCallModifySparseGpaPageHostVisibility',                          #winhvr.sys
    0x00DC: 'HvCallLockSparseGpaPageMapping',
    0x00DD: 'HvCallUnlockSparseGpaPageMapping',
    0x00DE: 'HvCallRequestProcessorHalt',
    0x00DF: 'HvCallGetInterceptData',
    0x00E0: 'HvCallQueryDeviceInterruptTarget',              #winhvr.sys
    0x00E1: 'HvCallMapVpStatePage',                          #winhvr.sys (HvMapVpStatePage in Windows 10)
    0x00E2: 'HvCallUnmapVpStatePage',
    0x00E3: 'HvCallGetXsaveData',                            #winhvr.sys
    0x00E4: 'HvCallSetXsaveData',                            #winhvr.sys
    0x00E5: 'HvCallGetLocalInterruptControllerState',        #winhvr.sys
    0x00E6: 'HvCallSetLocalInterruptControllerState',        #winhvr.sys
    0x00E7: 'HvCallCreateIptBuffers',                        #winhvr.sys (Windows 10)
    0x00E8: 'HvCallDeleteIptBuffers',                        #winhvr.sys (Windows 10)
    ## hvgdk.h
    0x00E9: 'HvCallControlHypervisorIptTrace',
    0x00EA: 'HvCallReserveDeviceInterrupt',
    0x00EB: 'HvCallPersistDevice',
    0x00EC: 'HvCallUnpersistDevice',
    0x00ED: 'HvCallPersistDeviceInterrupt',
    0x00EE: 'HvCallUpdatePerformanceStateCountersForLp',
}

os_hvcall = {
    0x8C: "Windows Server 2012",
    0x92: "Windows Server 2012 R2",
    0xAD: "Windows Server 2016 TP4",
    0xBC: "Windows Server 2016",
    0xDE: "Windows 10, build 1803",
    0xE6: "Windows Server 2019",
    0xE8: "Windows 10 19H1",
    0xEE: "Windows 10 20H1",
}

TableEntrySize = 0x18 #size of struct for every hypervisor handler
hv_stats = ida_enum.get_enum("HV_HYPERCALL_STATS_GROUP")  # hypercall's category using for statistic purpose

def check_hvix_os_version(hv_call_count):
    global os_hvcall
    if hv_call_count in os_hvcall:
        print(os_hvcall[hv_call_count])
    else:
        print("Uknown hvix64.exe OS. You can see build number in file properties")

def add_hypercall_stats_enum(hv_call_count):

    #
    # Microsoft suddenly changed hypercall's categories numbers in Windows 20H1
    #
    global hv_stats

    if hv_call_count >= 0xee:
        win_20h1_offset = 3
    else:
        win_20h1_offset = 0

    if hv_stats != 0xffffffffffffffff:
        print("enum HV_HYPERCALL_STATS_GROUP already exists")

    if hv_stats == 0xffffffffffffffff:
        hv_stats = idc.add_enum(-1, "HV_HYPERCALL_STATS_GROUP", 0)
        ida_typeinf.begin_type_updating(ida_typeinf.UTP_ENUM)
        idc.add_enum_member(hv_stats, "GPA_SPACE_HYPERCALL", 0x3D + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "LOGICAL_PROCESSOR_HYPERCALL", 0x3E + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "LONG_SPIN_WAIT_HYPERCALL", 0x3F + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "OTHER_HYPERCALL", 0x40 + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "INTER_PARTITION_COMMUNICATION_HYPERCALL", 0x41 + win_20h1_offset, -1)  # i don't see same counter in PerformanceMonitor, but there is category in Hyper-v TLFS.
        idc.add_enum_member(hv_stats, "VIRTUAL_INTERRUPT_HYPERCALL", 0x42 + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "VIRTUAL_MMU_HYPERCALL", 0x43 + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "VIRTUAL_PROCESSOR_HYPERCALL", 0x44 + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "VIRTUAL_PROCESSOR_HYPERCALL02", 0x45 + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "FLUSH_PHYSICAL_ADDRESS_SPACE", 0x8F + win_20h1_offset, -1)
        idc.add_enum_member(hv_stats, "FLUSH_PHYSICAL_ADDRESS_LIST", 0x90 + win_20h1_offset, -1)
        ida_typeinf.end_type_updating(ida_typeinf.UTP_ENUM)

def get_hypercall_count(table_address):
    count = 1
    while True:
        hv_call_number = idc.get_wide_dword(table_address+8+count*TableEntrySize)
        if hv_call_number == 0:
            print("max hypercall number:", hex(count-1))
            return count-1
        else:
            count += 1

StartAddress = idaapi.get_segm_by_name("CONST").start_ea #usually start of CONST segment, but it will can change in future
print("Address of HvCallTable is ", hex(StartAddress))

hvCallCount = get_hypercall_count(StartAddress)

if hvCallCount > len(hvcalls_dict):
    print("Warning! Hypercall's count is more then size of table with list of known hypercalls. Some hypercalls will be undefined")

add_hypercall_stats_enum(hvCallCount)
check_hvix_os_version(hvCallCount)

idc.set_name(StartAddress, str('HvCallTable'), SN_NOWARN)

# Working with first element manually

HvCallReserved00 = idc.get_qword(StartAddress)
ida_bytes.del_items(HvCallReserved00, 0, 1)
idc.create_insn(HvCallReserved00)
idc.add_func(HvCallReserved00)
idc.set_name(HvCallReserved00, str('HvCallReserved00'), SN_NOWARN)
for j in range(0,6):
    idc.create_data(StartAddress+8+j*2,  FF_WORD,  2,  ida_idaapi.BADADDR)
j=j+1
idc.create_data(StartAddress+8+j*2,  FF_DWORD,  4,  ida_idaapi.BADADDR)
idc.op_enum(StartAddress+8+j*2, 0, hv_stats, 0)

# Next elements
for i in range(1,hvCallCount+1):
    hvCallAddress = idc.get_qword(StartAddress+i*TableEntrySize)
    if (hvCallAddress !=HvCallReserved00):
        idc.create_insn(hvCallAddress)
        idc.add_func(hvCallAddress)
        idc.set_name(hvCallAddress,hvcalls_dict[i], SN_NOWARN)
    for j in range(0,6):
        dw_addr = idc.create_data(StartAddress+i*TableEntrySize+8+j*2,  FF_WORD,  2,  ida_idaapi.BADADDR)
    j=j+1
    idc.create_data(StartAddress+i*TableEntrySize+8+j*2,  FF_DWORD,  4,  ida_idaapi.BADADDR)
    idc.op_enum(StartAddress+i*TableEntrySize+8+j*2, 0, hv_stats, 0)
