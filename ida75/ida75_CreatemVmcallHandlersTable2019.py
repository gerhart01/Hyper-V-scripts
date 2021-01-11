#
# developed by @gerhart_x
# GPL licence
# IDA PRO 7.5
#

#Script parses and formats structure with hypercall hanlders in hvix64.exe 
#Microsoft doesn't provide symbols #for hvix64.exe, therefore i called it VmcallHandlersTable

import idaapi

hvcalls_dict = {
    0x0001: 'HvCallSwitchVirtualAddressSpace',
    0x0002: 'HvCallFlushVirtualAddressSpace',
    0x0003: 'HvCallFlushVirtualAddressList',
    0x0004: 'HvCallGetLogicalProcessorRunTime',
    0x0005: 'HvCallUpdateHvProcessorFeatures',
    0x0006: 'HvSwitchAliasMap',
    0x0007: 'HvUpdateMicrocodeDatabase',
    0x0008: 'HvCallNotifyLongSpinWait',
    0x0009: 'HvCallParkLogicalProcessors',
    0x000a: 'HvCallInvokeHypervisorDebugger',#excluded from TLFS 5.0
	#2016
    0x000b: 'HvCallSendSyntheticClusterIpi',
    0x000c: 'HvCallModifyVtlProtectionMask',
    0x000d: 'HvCallEnablePartitionVtl',
    0x000e: 'HvCallDisablePartitionVtl',
    0x000f: 'HvCallEnableVpVtl',
    0x0010: 'HvCallDisableVpVtl',
    0x0011: 'HvCallVtlCall',
    0x0012: 'HvCallVtlReturn',
    0x0013: 'HvCallFlushVirtualAddressSpaceEx',
    0x0014: 'HvCallFlushVirtualAddressListEx',
    0x0015: 'HvCallSendSyntheticClusterIpiEx',
	#####
    0x0016: 'HvCallReserved00',
    0x0017: 'HvCallReserved00',
    0x0018: 'HvCallReserved00',
    0x0019: 'HvCallReserved00',
    0x001a: 'HvCallReserved00',
    0x001b: 'HvCallReserved00',
    0x001c: 'HvCallReserved00',
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
    0x0040: 'HvCreatePartition',
    0x0041: 'HvInitializePartition',
    0x0042: 'HvFinalizePartition',
    0x0043: 'HvDeletePartition',
    0x0044: 'HvGetPartitionProperty',
    0x0045: 'HvSetPartitionProperty',
    0x0046: 'HvGetPartitionId',
    0x0047: 'HvGetNextChildPartition',
    0x0048: 'HvDepositMemory',
    0x0049: 'HvWithdrawMemory',
    0x004A: 'HvGetMemoryBalance',
    0x004B: 'HvMapGpaPages',
    0x004C: 'HvUnmapGpaPages',
    0x004D: 'HvInstallIntercept',
    0x004E: 'HvCreateVp',
    0x004F: 'HvDeleteVp',
    0x0050: 'HvGetVpRegisters',
    0x0051: 'HvSetVpRegisters',
    0x0052: 'HvTranslateVirtualAddress',
    0x0053: 'HvReadGpa',
    0x0054: 'HvWriteGpa',
    0x0055: 'HvDepricated',#depricated
    0x0056: 'HvClearVirtualInterrupt',
    0x0057: 'HvCreatePort',
    0x0058: 'HvDeletePort',
    0x0059: 'HvConnectPort',
    0x005A: 'HvGetPortProperty',
    0x005B: 'HvDisconnectPort',
    0x005C: 'HvPostMessage',
    0x005D: 'HvSignalEvent',
    0x005E: 'HvSavePartitionState',
    0x005F: 'HvRestorePartitionState',
    0x0060: 'HvInitializeEventLogBufferGroup',
    0x0061: 'HvFinalizeEventLogBufferGroup',
    0x0062: 'HvCreateEventLogBuffer',
    0x0063: 'HvDeleteEventLogBuffer',
    0x0064: 'HvMapEventLogBuffer',
    0x0065: 'HvUnmapEventLogBuffer',
    0x0066: 'HvSetEventLogGroupSources',
    0x0067: 'HvReleaseEventLogBuffer',
    0x0068: 'HvFlushEventLogBuffer',
    0x0069: 'HvPostDebugData',
    0x006A: 'HvRetrieveDebugData',
    0x006B: 'HvResetDebugSession',
    0x006C: 'HvMapStatsPage',
    0x006D: 'HvUnmapStatsPage',
    0x006E: 'HvCallMapSparseGpaPages',
    0x006F: 'HvCallSetSystemProperty',
    0x0070: 'HvCallSetPortProperty',
    0x0071: 'HvCallReserved00',
    0x0072: 'HvCallReserved00',
    0x0073: 'HvCallReserved00',
    0x0074: 'HvCallReserved00',
    0x0075: 'HvCallReserved00',
    0x0076: 'HvCallAddLogicalProcessor',
    0x0077: 'HvCallRemoveLogicalProcessor',
    0x0078: 'HvCallQueryNumaDistance',
    0x0079: 'HvCallSetLogicalProcessorProperty',
    0x007A: 'HvCallGetLogicalProcessorProperty',
    0x007B: 'HvCallGetSystemProperty',
    0x007C: 'HvCallMapDeviceInterrupt',
    0x007D: 'HvCallUnmapDeviceInterrupt',
    0x007E: 'HvCallRetargetDeviceInterrupt', #renamed
    0x007F: 'HvCallReserved00', #made reserved
    0x0080: 'HvCallMapDevicePages',
    0x0081: 'HvCallUnmapDevicePages',
    0x0082: 'HvCallAttachDevice',
    0x0083: 'HvCallDetachDevice',
    0x0084: 'HvCallEnterSleepState',
    0x0085: 'HvCallPrepareForSleep',
    0x0086: 'HvCallPrepareForHibernate',
    0x0087: 'HvCallNotifyPartitionEvent',
    0x0088: 'HvCallGetLogicalProcessorRegisters',
    0x0089: 'HvCallSetLogicalProcessorRegisters',
    0x008A: 'HvCallQueryAssociatedLpsforMca',
    0x008B: 'HvCallNotifyRingEmpty',
    0x008C: 'HvCallInjectSyntheticMachineCheck',
    0x008d: 'HvCallScrubPartition',
    0x008e: 'HvCallCollectLivedump',
    0x008f: 'HvCallDisableHypervisor',
    0x0090: 'HvCallModifySparseGpaPages',
    0x0091: 'HvCallRegisterInterceptResult',
    0x0092: 'HvCallUnregisterInterceptResult',
	#2016
    0x0093: 'HvForgottenDocumented01',
    0x0094: 'HvCallAssertVirtualInterrupt',
    0x0095: 'HvCallCreatePort',
    0x0096: 'HvCallConnectPort',
    0x0097: 'HvCallGetSpaPageList',
    0x0098: 'HvCallReserved00',
    0x0099: 'HvCallStartVirtualProcessor',
    0x009A: 'HvCallGetVpIndexFromApicId',
    0x009B: 'HvCallReserved00',
    0x009C: 'HvCallReserved00',
    0x009D: 'HvCallReserved00',
    0x009E: 'HvCallReserved00',
    0x009F: 'HvCallReserved00',
    0x00A0: 'HvCallReserved00',
    0x00A1: 'HvCallReserved00',
    0x00A2: 'HvCallReserved00',
    0x00A3: 'HvCallReserved00',
    0x00A4: 'HvCallReserved00',
    0x00A5: 'HvCallReserved00',
    0x00A6: 'HvCallReserved00',
    0x00A7: 'HvCallReserved00',
    0x00A8: 'HvCallReserved00',
    0x00A9: 'HvCallReserved00',
    0x00AA: 'HvCallReserved00',
    0x00AB: 'HvCallReserved00',
    0x00AC: 'HvCallReserved00',
    0x00AD: 'HvCallReserved00',	
    0x00AE: 'HvCallReserved00',
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
}

TableEntrySize = 0x18 #size of struct for every hypervisor handler
hv_stats = ida_enum.get_enum("HV_HYPERCALL_STATS_GROUP")  # hypercall's category using for statistic purpose

def add_hypercall_stats_enum(hv_call_count):

    global hv_stats

    if hv_stats != 0xffffffffffffffff:
        print("enum HV_HYPERCALL_STATS_GROUP already exists")

    if hv_stats == 0xffffffffffffffff:
        hv_stats = idc.add_enum(-1, "HV_HYPERCALL_STATS_GROUP", 0)
        ida_typeinf.begin_type_updating(ida_typeinf.UTP_ENUM)
        idc.add_enum_member(hv_stats, "GPA_SPACE_HYPERCALL", 0x3D, -1)
        idc.add_enum_member(hv_stats, "LOGICAL_PROCESSOR_HYPERCALL", 0x3E, -1)
        idc.add_enum_member(hv_stats, "LONG_SPIN_WAIT_HYPERCALL", 0x3F, -1)
        idc.add_enum_member(hv_stats, "OTHER_HYPERCALL", 0x40, -1)
        idc.add_enum_member(hv_stats, "INTER_PARTITION_COMMUNICATION_HYPERCALL", 0x41,
                            -1)  # i don't see same counter in PerformanceMonitor, but there is category in Hyper-v TLFS.
        idc.add_enum_member(hv_stats, "VIRTUAL_INTERRUPT_HYPERCALL", 0x42, -1)
        idc.add_enum_member(hv_stats, "VIRTUAL_MMU_HYPERCALL", 0x43, -1)
        idc.add_enum_member(hv_stats, "VIRTUAL_PROCESSOR_HYPERCALL", 0x44, -1)
        ida_typeinf.end_type_updating(ida_typeinf.UTP_ENUM)

def get_hypercall_count(table_address):
    count = 1
    while True:
        hv_call_number = idc.get_wide_dword(table_address+8+count*TableEntrySize)
        if hv_call_number == 0:
            print("max hypercall number:", hex(count-1))
            hv_count = count-1
            break
        else:
            count += 1

    if hv_count > len(hvcalls_dict):
        print("hvcall_dict_len:", hex(len(hvcalls_dict)))
        print("Warning! Hypercall's count is more then size of table with list of known hypercalls. Some hypercalls will be undefined")
        hv_count = len(hvcalls_dict)

    return hv_count


StartAddress = idaapi.get_segm_by_name("CONST").start_ea  #usually start of CONST segment, but it will can change in future
print("Address of HvCallTable is ", hex(StartAddress))

hvCallCount = get_hypercall_count(StartAddress)

add_hypercall_stats_enum(hvCallCount)

idc.set_name(StartAddress, str('HvCallTable'), SN_NOWARN)

#
# first table element
#

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
for i in range(1, hvCallCount+1):
    hvCallAddress = idc.get_qword(StartAddress+i*TableEntrySize)

    if (hvCallAddress != HvCallReserved00):
        idc.create_insn(hvCallAddress)
        idc.add_func(hvCallAddress)
        # print("hvcalls_dict[i]", hvcalls_dict[i])
        idc.set_name(hvCallAddress, hvcalls_dict[i], SN_NOWARN)

    for j in range(0, 6):
        dw_addr = idc.create_data(StartAddress+i*TableEntrySize+8+j*2,  FF_WORD,  2,  ida_idaapi.BADADDR)

    j=j+1
    idc.create_data(StartAddress+i*TableEntrySize+8+j*2,  FF_DWORD,  4,  ida_idaapi.BADADDR)
    idc.op_enum(StartAddress+i*TableEntrySize+8+j*2, 0, hv_stats, 0)

