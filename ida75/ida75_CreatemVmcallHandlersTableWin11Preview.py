__author__ = "Gerhart"
__license__ = "GPL"
__version__ = "1.3.0"

#
# developed by @gerhart_x
# GPL3 licence
# 
#

#
# Script parsing and formating structures with hypercall handlers in hvix64.exe
# Microsoft doesn't provide symbols for hvix64.exe, therefore i called it VmcallHandlersTable
# Hypercalls were taken from Hyper-V TLFS, winhvr.sys, winhv.sys, ntoskrnl.exe, securekernel.exe
# Windows 10 and Windows Server 2019 have different hypercalls. There are not many, but don't forget about it.
# tested in IDA PRO 7.5
#

# 04-01-2020 Add hvix64 OS detection by hypercalls count
# 04-01-2020 Hypercall names updates from hvgdk.h (https://github.com/ionescu007/hdk/blob/master/hvgdk.h)
# 04-01-2020 Add dynamically hypercall's count finding method
# 27-08-2020 Hypercalls updates from new version of hvgdk.h (https://github.com/ionescu007/hdk/blob/master/hvgdk.h)
# 07-07-2021 Add import hvcalls_results.json from hvcall_extract.py script ()auto extract hvcalls used procedures
#            from winhvr.sys, winhv.sys, ntoskrnl.exe, securekernel.exe
# 18-08-2021 Update hypercalls list from Intel debugger obj file
#
#       Windows 11 preview has some chaos on hypercall's statistic group
#       (f.e reserved hypercall and HvCallCreatePartition have same category).
#       It will be commented until release

import os
import idaapi
import json

g_hvcalls_dict = {
    0x0000: 'HvCallReserved0000',
    0x0001: 'HvCallSwitchVirtualAddressSpace',
    0x0002: 'HvCallFlushVirtualAddressSpace',
    0x0003: 'HvCallFlushVirtualAddressList',
    0x0004: 'HvCallGetLogicalProcessorRunTime',
    0x0005: 'HvCallUpdateHvProcessorFeatures',
    0x0006: 'HvCallSwitchAliasMap',
    0x0007: 'HvCallUpdateMicrocode',
    0x0008: 'HvCallNotifyLongSpinWait',
    0x0009: 'HvCallParkedVirtualProcessors',
    0x000A: 'HvCallInvokeHypervisorDebugger',
    0x000B: 'HvCallSendSyntheticClusterIpi',
    0x000C: 'HvCallModifyVtlProtectionMask',
    0x000D: 'HvCallEnablePartitionVtl',
    0x000E: 'HvCallDisablePartitionVtl',
    0x000F: 'HvCallEnableVpVtl',
    0x0010: 'HvCallDisableVpVtl',
    0x0011: 'HvCallVtlCall',
    0x0012: 'HvCallVtlReturn',
    0x0013: 'HvCallFlushVirtualAddressSpaceEx',
    0x0014: 'HvCallFlushVirtualAddressListEx',
    0x0015: 'HvCallSendSyntheticClusterIpiEx',
    0x0016: 'HvCallQueryImageInfo',
    0x0017: 'HvCallMapImagePages',
    0x0018: 'HvCallCommitPatch',
    0x0019: 'HvCallSyncContext',
    0x001A: 'HvCallSyncContextEx',
    0x001B: 'HvCallSetPerfRegister',
    0x001C: 'HvCallGetPerfRegister',
    0x001D: 'HvCallReserved001d',
    0x001E: 'vCallReserved001e',
    0x001F: 'HvCallReserved001f',
    0x0020: 'HvCallReserved0020',
    0x0021: 'HvCallReserved0021',
    0x0022: 'HvCallReserved0022',
    0x0023: 'HvCallReserved0023',
    0x0024: 'HvCallReserved0024',
    0x0025: 'HvCallReserved0025',
    0x0026: 'HvCallReserved0026',
    0x0027: 'HvCallReserved0027',
    0x0028: 'HvCallReserved0028',
    0x0029: 'HvCallReserved0029',
    0x002A: 'HvCallReserved002a',
    0x002B: 'HvCallReserved002b',
    0x002C: 'HvCallReserved002c',
    0x002D: 'HvCallReserved002d',
    0x002E: 'HvCallReserved002e',
    0x002F: 'HvCallReserved002f',
    0x0030: 'HvCallReserved0030',
    0x0031: 'HvCallReserved0031',
    0x0032: 'HvCallReserved0032',
    0x0033: 'HvCallReserved0033',
    0x0034: 'HvCallReserved0034',
    0x0035: 'HvCallReserved0035',
    0x0036: 'HvCallReserved0036',
    0x0037: 'HvCallReserved0037',
    0x0038: 'HvCallReserved0038',
    0x0039: 'HvCallReserved0039',
    0x003A: 'HvCallReserved003a',
    0x003B: 'HvCallReserved003b',
    0x003C: 'HvCallReserved003c',
    0x003D: 'HvCallReserved003d',
    0x003E: 'HvCallReserved003e',
    0x003F: 'HvCallReserved003f',
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
    0x0052: 'HvCallTranslateVirtualAddress',
    0x0053: 'HvCallReadGpa',
    0x0054: 'HvCallWriteGpa',
    0x0055: 'HvCallAssertVirtualInterruptDeprecated',
    0x0056: 'HvCallClearVirtualInterrupt',
    0x0057: 'HvCallCreatePortDeprecated',
    0x0058: 'HvCallDeletePort',
    0x0059: 'HvCallConnectPortDeprecated',
    0x005A: 'HvCallGetPortProperty',
    0x005B: 'HvCallDisconnectPort',
    0x005C: 'HvCallPostMessage',
    0x005D: 'HvCallSignalEvent',
    0x005E: 'HvCallSavePartitionState',
    0x005F: 'HvCallRestorePartitionState',
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
    0x006F: 'HvCallSetSystemProperty',
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
    0x007B: 'HvCallGetSystemProperty',
    0x007C: 'HvCallMapDeviceInterrupt',
    0x007D: 'HvCallUnmapDeviceInterrupt',
    0x007E: 'HvCallRetargetDeviceInterrupt',
    0x007F: 'HvCallRetargetRootDeviceInterrupt',
    0x0080: 'HvCallAssertDeviceInterrupt',
    0x0081: 'HvCallReserved0081',
    0x0082: 'HvCallAttachDevice',
    0x0083: 'HvCallDetachDevice',
    0x0084: 'HvCallEnterSleepState',
    0x0085: 'HvCallNotifyStandbyTransition',
    0x0086: 'HvCallPrepareForHibernate',
    0x0087: 'HvCallNotifyPartitionEvent',
    0x0088: 'HvCallGetLogicalProcessorRegisters',
    0x0089: 'HvCallSetLogicalProcessorRegisters',
    0x008A: 'HvCallQueryAssociatedLpsForMca',
    0x008B: 'HvCallNotifyPortRingEmpty',
    0x008C: 'HvCallInjectSyntheticMachineCheck',
    0x008D: 'HvCallScrubPartition',
    0x008E: 'HvCallCollectLivedump',
    0x008F: 'HvCallDisableHypervisor',
    0x0090: 'HvCallModifySparseGpaPages',
    0x0091: 'HvCallRegisterInterceptResult',
    0x0092: 'HvCallUnregisterInterceptResult',
    0x0093: 'HvCallGetCoverageData',
    0x0094: 'HvCallAssertVirtualInterrupt',
    0x0095: 'HvCallCreatePort',
    0x0096: 'HvCallConnectPort',
    0x0097: 'HvCallGetSpaPageList',
    0x0098: 'HvCallReserved0098',
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
    0x00A6: 'HvCallAcknowledgeDevicePageRequest',
    0x00A7: 'HvCallCreateDevicePrQueue',
    0x00A8: 'HvCallDeleteDevicePrQueue',
    0x00A9: 'HvCallSetDevicePrqProperty',
    0x00AA: 'HvCallGetPhysicalDeviceProperty',
    0x00AB: 'HvCallSetPhysicalDeviceProperty',
    0x00AC: 'HvCallTranslateVirtualAddressEx',
    0x00AD: 'HvCallCheckForIoIntercept',
    0x00AE: 'HvCallSetGpaPageAttributes',
    0x00AF: 'HvCallFlushGuestPhysicalAddressSpace',
    0x00B0: 'HvCallFlushGuestPhysicalAddressList',
    0x00B1: 'HvCallCreateDeviceDomain',
    0x00B2: 'HvCallAttachDeviceDomain',
    0x00B3: 'HvCallMapDeviceGpaPages',
    0x00B4: 'HvCallUnmapDeviceGpaPages',
    0x00B5: 'HvCallCreateCpuGroup',
    0x00B6: 'HvCallDeleteCpuGroup',
    0x00B7: 'HvCallGetCpuGroupProperty',
    0x00B8: 'HvCallSetCpuGroupProperty',
    0x00B9: 'HvCallGetCpuGroupAffinity',
    0x00BA: 'HvCallGetNextCpuGroup',
    0x00BB: 'HvCallGetNextCpuGroupPartition',
    0x00BC: 'HvCallAddPhysicalMemory',
    0x00BD: 'HvCallCompleteIntercept',
    0x00BE: 'HvCallPrecommitGpaPages',
    0x00BF: 'HvCallUncommitGpaPages',
    0x00C0: 'HvCallSignalEventDirect',
    0x00C1: 'HvCallPostMessageDirect',
    0x00C2: 'HvCallDispatchVp',
    0x00C3: 'HvCallProcessIommuPrq',
    0x00C4: 'HvCallDetachDeviceDomain',
    0x00C5: 'HvCallDeleteDeviceDomain',
    0x00C6: 'HvCallQueryDeviceDomain',
    0x00C7: 'HvCallMapSparseDeviceGpaPages',
    0x00C8: 'HvCallUnmapSparseDeviceGpaPages',
    0x00C9: 'HvCallGetGpaPagesAccessState',
    0x00CA: 'HvCallGetSparseGpaPagesAccessState',
    0x00CB: 'HvCallInvokeTestFramework',
    0x00CC: 'HvCallQueryVtlProtectionMaskRange',
    0x00CD: 'HvCallModifyVtlProtectionMaskRange',
    0x00CE: 'HvCallConfigureDeviceDomain',
    0x00CF: 'HvCallQueryDeviceDomainProperties',
    0x00D0: 'HvCallFlushDeviceDomain',
    0x00D1: 'HvCallFlushDeviceDomainList',
    0x00D2: 'HvCallAcquireSparseGpaPageHostAccess',
    0x00D3: 'HvCallReleaseSparseGpaPageHostAccess',
    0x00D4: 'HvCallCheckSparseGpaPageVtlAccess',
    0x00D5: 'HvCallEnableDeviceInterrupt',
    0x00D6: 'HvCallFlushTlb',
    0x00D7: 'HvCallAcquireSparseSpaPageHostAccess',
    0x00D8: 'HvCallReleaseSparseSpaPageHostAccess',
    0x00D9: 'HvCallAcceptGpaPages',
    0x00DA: 'HvCallUnacceptGpaPages',
    0x00DB: 'HvCallModifySparseGpaPageHostVisibility',
    0x00DC: 'HvCallLockSparseGpaPageMapping',
    0x00DD: 'HvCallUnlockSparseGpaPageMapping',
    0x00DE: 'HvCallRequestProcessorHalt',
    0x00DF: 'HvCallGetInterceptData',
    0x00E0: 'HvCallQueryDeviceInterruptTarget',
    0x00E1: 'HvCallMapVpStatePage',
    0x00E2: 'HvCallUnmapVpStatePage',
    0x00E3: 'HvCallGetVpState',
    0x00E4: 'HvCallSetVpState',
    0x00E5: 'HvCallGetVpSetFromMda',
    0x00E6: 'HvCallReserved00E6',
    0x00E7: 'HvCallCreateIptBuffers',
    0x00E8: 'HvCallDeleteIptBuffers',
    0x00E9: 'HvCallControlHypervisorIptTrace',
    0x00EA: 'HvCallReserveDeviceInterrupt',
    0x00EB: 'HvCallPersistDevice',
    0x00EC: 'HvCallUnpersistDevice',
    0x00ED: 'HvCallPersistDeviceInterrupt',
    0x00EE: 'HvCallRefreshPerformanceCounters',
    0x00EF: 'HvCallImportIsolatedPages',
    0x00F0: 'HvCallCompletePendingIsolatedPagesImport',
    0x00F1: 'HvCallCompleteIsolatedImport',
    0x00F2: 'HvCallIssueSnpPspGuestRequest',
    0x00F3: 'HvCallRootSignalEvent',
    0x00F4: 'HvCallGetVpCpuidValues',
    0x00F5: 'HvCallReadSystemMemory',
    0x00F6: 'HvCallSetHwWatchdogConfig',
    0x00F7: 'HvCallRemovePhysicalMemory',
    0x00F8: 'HvCallLogHypervisorSystemConfig',
    0x00F9: 'HvCallIssueNestedSnpPspRequests',
    0x00FA: 'HvCallCompleteSnpPspRequests',
    0x00FB: 'HvCallSubsumeInitializedMemory',
    0x00FC: 'HvCallSubsumeVp',
    0x00FD: 'HvCallDestroySubsumedContext'
}

#
# hypercalls count can be changed with every tuesday's patch in latest Windows version
#

g_os_hvcall = {
    0x8C: "Windows Server 2012",
    0x92: "Windows Server 2012 R2",
    0xBC: "Windows Server 2016",
    0xDE: "Windows 10, build 1803",
    0xE6: "Windows Server 2019",
    0xE8: "Windows 10 19H1",
    0xEE: "Windows 10 (20H1, 21H1)",
    0xFD: "Windows 11 preview",
}

g_TableEntrySize = 0x18  # size of struct for every hypervisor handlegr
g_hv_stats = ida_enum.get_enum("HV_HYPERCALL_STATS_GROUP")  # hypercall's category using for statistic purpose


def path_exist(path):
    if os.path.exists(path):
        return True
    else:
        return False


def load_dict_from_file(file_path):
    hv_dict = {}

    if not os.path.exists(file_path):
        print("file " + file_path + "doesn't exist")
        return hv_dict

    with open(file_path, "r") as read_content:
        hv_dict = json.load(read_content)

    hv_dict_int = {}

    for key in hv_dict:
        hv_dict_int[int(key, 16)] = hv_dict[key]

    return hv_dict_int


def replace_hvcall_names_with_autoloaded_values(filename):
    if not os.path.exists(filename):
        print("Path ", filename, " doesn't exist")
        return

    d_hvcall = load_dict_from_file(filename)

    if d_hvcall:
        hvcalls_list = list(d_hvcall.keys())
        for key in g_hvcalls_dict:
            if key in hvcalls_list:
                print("hvcall " + g_hvcalls_dict[key] + " replaced on " + d_hvcall[key])
                g_hvcalls_dict[key] = d_hvcall[key]


def check_hvix_os_version(hv_call_count):
    global g_os_hvcall
    if hv_call_count in g_os_hvcall:
        print(g_os_hvcall[hv_call_count])
    else:
        print("Unknown hvix64.exe OS. You can see build number in file properties")


def add_hypercall_stats_enum(hv_call_count):
    #
    # Microsoft suddenly changed hypercall's categories numbers in Windows 20H1
    #

    global g_hv_stats

    if 0xee <= hv_call_count <= 0xfc:
        win_20h1_offset = 3
    elif hv_call_count >= 0xfd:
        win_20h1_offset = 1
    else:
        win_20h1_offset = 0

    if g_hv_stats != 0xffffffffffffffff:
        print("enum HV_HYPERCALL_STATS_GROUP already exists")

    if g_hv_stats == 0xffffffffffffffff:
        g_hv_stats = idc.add_enum(-1, "HV_HYPERCALL_STATS_GROUP", 0)
        ida_typeinf.begin_type_updating(ida_typeinf.UTP_ENUM)
        idc.add_enum_member(g_hv_stats, "GPA_SPACE_HYPERCALL", 0x3D + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "LOGICAL_PROCESSOR_HYPERCALL", 0x3E + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "LONG_SPIN_WAIT_HYPERCALL", 0x3F + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "OTHER_HYPERCALL", 0x40 + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "INTER_PARTITION_COMMUNICATION_HYPERCALL", 0x41 + win_20h1_offset,
                            -1)  # i don't see same counter in PerformanceMonitor, but there is category in Hyper-v TLFS.
        idc.add_enum_member(g_hv_stats, "VIRTUAL_INTERRUPT_HYPERCALL", 0x42 + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "VIRTUAL_MMU_HYPERCALL", 0x43 + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "VIRTUAL_PROCESSOR_HYPERCALL", 0x44 + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "VIRTUAL_PROCESSOR_HYPERCALL02", 0x45 + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "FLUSH_PHYSICAL_ADDRESS_SPACE", 0x8F + win_20h1_offset, -1)
        idc.add_enum_member(g_hv_stats, "FLUSH_PHYSICAL_ADDRESS_LIST", 0x90 + win_20h1_offset, -1)
        ida_typeinf.end_type_updating(ida_typeinf.UTP_ENUM)


def get_hypercall_count(table_address):
    global g_TableEntrySize
    global g_hv_stats

    count = 1
    while True:
        hv_call_number = idc.get_wide_dword(table_address + 8 + count * g_TableEntrySize)
        if hv_call_number == 0:
            print("Hypercalls count in file:", hex(count - 1))
            return count - 1
        else:
            count += 1


def set_hypercalls_name():
    global g_TableEntrySize

    StartAddress = idaapi.get_segm_by_name(
        "CONST").start_ea  # usually start of CONST segment, but it will can change in future
    print("Address of HvCallTable is ", hex(StartAddress))

    hvCallCount = get_hypercall_count(StartAddress)

    hv_table_count = len(g_hvcalls_dict)

    if hvCallCount > len(g_hvcalls_dict):
        print(
            "Warning! Hypercall's count is more then size of table with list of known hypercalls. Some hypercalls will be undefined. ")

    add_hypercall_stats_enum(hvCallCount)
    check_hvix_os_version(hvCallCount)

    idc.set_name(StartAddress, str('HvCallTable'), SN_NOWARN)

    # Working with first element manually

    HvCallReserved00 = idc.get_qword(StartAddress)
    ida_bytes.del_items(HvCallReserved00, 0, 1)
    idc.create_insn(HvCallReserved00)
    idc.add_func(HvCallReserved00)
    idc.set_name(HvCallReserved00, str('HvCallReserved00'), SN_NOWARN)
    for j in range(0, 6):
        idc.create_data(StartAddress + 8 + j * 2, FF_WORD, 2, ida_idaapi.BADADDR)
    j = j + 1
    idc.create_data(StartAddress + 8 + j * 2, FF_DWORD, 4, ida_idaapi.BADADDR)
    # idc.op_enum(StartAddress + 8 + j * 2, 0, g_hv_stats, 0)

    # Next elements
    for i in range(1, hvCallCount + 1):
        hvCallAddress = idc.get_qword(StartAddress + i * g_TableEntrySize)

        if hvCallAddress != HvCallReserved00:
            idc.create_insn(hvCallAddress)
            idc.add_func(hvCallAddress)
            if i < hv_table_count:
                idc.set_name(hvCallAddress, g_hvcalls_dict[i], SN_NOWARN)
            else:
                hvcall_name = "HvCallUknown" + hex(i)
                idc.set_name(hvCallAddress, hvcall_name, SN_NOWARN)
        for j in range(0, 6):
            dw_addr = idc.create_data(StartAddress + i * g_TableEntrySize + 8 + j * 2, FF_WORD, 2, ida_idaapi.BADADDR)
        j = j + 1
        idc.create_data(StartAddress + i * g_TableEntrySize + 8 + j * 2, FF_DWORD, 4, ida_idaapi.BADADDR)
        # idc.op_enum(StartAddress + i * g_TableEntrySize + 8 + j * 2, 0, g_hv_stats, 0)


#
# replace hvcall names from hvgdk.h with autofound values (script extract_hvcalls.py)
#

fn = "F:\\path\\to\\autoextracted\\results.json"

if path_exist(fn):
    print("hypercalls will be merged with values from files: ", fn)
    replace_hvcall_names_with_autoloaded_values(fn)

set_hypercalls_name()
