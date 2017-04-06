__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.1"

#Script parses and formats structure with hypercall hanlders in hvix64.exe\hvax64.exe 
#Microsoft doesn't provide symbols #for hvix64.exe, therefore i called it VmcallHandlersTable
#
#Open hvix64.exe\hvax64.exe in IDA PRO and run script
#
#
# Table element description (on HvSwitchVirtualAddressSpace hypercall)
#dq offset HvSwitchVirtualAddressSpace ; address of specific hypercall handler
#CONST:FFFFF80006232020                 dw 1                    ; VMCALL ID
#CONST:FFFFF80006232022                 dw 0                    ; REP CALL or not REP CALL
#CONST:FFFFF80006232024                 dw 8                    ; size of hypercall input param (in bytes)  without rep prefix
#CONST:FFFFF80006232026                 dw 0                    ; size of hypercall input param with rep prefix
#CONST:FFFFF80006232028                 dw 0                    ; hypercall output 1 element param size without rep prefix
#CONST:FFFFF8000623202A                 dw 0                    ; hypercall output 1 element param size with rep prefix
#CONST:FFFFF8000623202C                 dd 43h                  ; group number of hypercall (f.e Virtual Interrupt Interfaces)
#CONST:FFFFF8000623202C                                         ; used like index in table of statistics of hypercall using
#
#
#
#
#

import idaapi

TableEntrySize = 0x18 #size of struct for every hypervisor handler

hvcalls_dict = {
    0x0001: 'HvSwitchVirtualAddressSpace',
    0x0002: 'HvFlushVirtualAddressSpace',
    0x0003: 'HvFlushVirtualAddressList',
    0x0004: 'HvGetLogicalProcessorRunTime',
    0x0005: 'Reserved for future use',
    0x0006: 'Reserved for future use',
    0x0007: 'Reserved for future use',
    0x0008: 'HvNotifyLongSpinWait',
    0x0009: 'HvParkedVirtualProcessors',
    0x000a: 'HvUndocumented00',#excluded from TLFS 5.0
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
	0x0093: 'HvUndocumented01',
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
	0x00B1: 'HvUndocumented02',
	0x00B2: 'HvUndocumented03',
	0x00B3: 'HvUndocumented04',
	0x00B4: 'HvUndocumented05',
	0x00B5: 'HvUndocumented06',
	0x00B6: 'HvUndocumented07',
	0x00B7: 'HvUndocumented08',
	0x00B8: 'HvUndocumented09',
	0x00B9: 'HvUndocumented10',
	0x00BA: 'HvUndocumented11',
	0x00BB: 'HvUndocumented12',
	0x00BC: 'HvUndocumented13'
}

hvStats = GetEnum("HV_HYPERCALL_STATS_GROUP") #hypercall's category using for statistic purpose
if hvStats != 0xffffffffffffffffL:
    print "enum HV_HYPERCALL_STATS_GROUP already exists"
if hvStats == 0xffffffffffffffffL:
    hvStats = AddEnum(-1, "HV_HYPERCALL_STATS_GROUP", 0)
    BeginTypeUpdating(UTP_ENUM)
    AddConst(hvStats,"GPA_SPACE_HYPERCALL",0x3D)
    AddConst(hvStats,"LOGICAL_PROCESSOR_HYPERCALL",0x3E)
    AddConst(hvStats,"LONG_SPIN_WAIT_HYPERCALL",0x3F)
    AddConst(hvStats,"OTHER_HYPERCALL",0x40)
    AddConst(hvStats,"INTER_PARTITION_COMMUNICATION_HYPERCALL",0x41)# i don't see same counter in PerformanceMonitor, but there is category in Hyper-v TLFS.
    AddConst(hvStats,"VIRTUAL_INTERRUPT_HYPERCALL",0x42)
    AddConst(hvStats,"VIRTUAL_MMU_HYPERCALL",0x43)
    AddConst(hvStats,"VIRTUAL_PROCESSOR_HYPERCALL",0x44)
    EndTypeUpdating(UTP_ENUM)

StartAddress = idaapi.get_segm_by_name("CONST").startEA #usually start of CONST segment, but it will can change in future
print "Address of HypercallHandlerTable is ",hex(StartAddress)
#hvCallCount = 0x92 #count of hypercalls in Windows Server 2012 R2
#hvCallCount = 0xAD count of hypercalls in Windows Server 2016 TP4
#hvCallCount = 0xBC #count of hypercalls in Windows Server 2016
hvCallCount = len(hvcalls_dict)

print "hvcalls_dict size is",hex(hvCallCount)

HvCallReserved00 = idc.Qword(StartAddress)
idc.MakeCode(HvCallReserved00)
idc.MakeFunction(HvCallReserved00)
MakeNameEx(HvCallReserved00,str('HvCallReserved00'), SN_NOWARN)
for j in range(0,6):
    idc.MakeWord(StartAddress+8+j*2)
j=j+1
idc.MakeDword(StartAddress+8+j*2)
for i in range(1,hvCallCount+1):
    hvCallAddress = idc.Qword(StartAddress+i*TableEntrySize)
    if (hvCallAddress !=HvCallReserved00):
        idc.MakeCode(hvCallAddress)
        idc.MakeFunction(hvCallAddress)
        MakeNameEx(hvCallAddress,hvcalls_dict[i], SN_NOWARN)
    for j in range(0,6):
        dw_addr = idc.MakeWord(StartAddress+i*TableEntrySize+8+j*2)
    j=j+1
    idc.MakeDword(StartAddress+i*TableEntrySize+8+j*2)
    OpEnumEx(StartAddress+i*TableEntrySize+8+j*2, 0, hvStats, 0)

