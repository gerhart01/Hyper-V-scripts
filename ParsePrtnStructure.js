/// <reference path="JSProvider.d.ts" />
// __author__ = "Gerhart"
// __license__ = "GPL3"
// __version__ = "1.0"

//
// .scriptrun "ParsePrtnStructure.js"
// 
//

"use strict";

var WINDOWS_SERVER_2016 = false;
var WINDOWS_SERVER_2019 = false;
var WINDOWS_SERVER_2022 = false;
var WINDOWS_11 = true;
var WINDOWS_11_PREVIEW = false;

var header = [];
var header_tabs = [];

var g_WinHvpPartitionArray = 0;
var g_PrintTableEntryCounter = 0;

function hex(num, padding)
{
    padding = 0;
    var result = '';
    if (num != null)
    {
        result = num.toString(16).padStart(padding, "0");
    }
    return result;
}

if (WINDOWS_SERVER_2022 == true){
    var PARTITION_NAME_OFFSET = 0x88;
    var MBLOCKS_ARRAY_PRTN_OFFSET = 0x2ac0;

    var GPAR_BLOCK_HANDLE_OFFSET = 0x2e50;
    var GPAR_ELEMENT_COUNT_OFFSET = 0x14;

    // GPAR element offsets

    var GPAR_ELEMENT_MBLOCK_ELEMENT = 0x170;
    var GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178;
    var GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180;

    // MBLOCK element offsets

    var MBLOCK_ELEMENT_MBHANDLE = 0x18;
    var MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xF0;
}

if (WINDOWS_SERVER_2019 == true){
    var PARTITION_NAME_OFFSET = 0x78;
    var MBLOCKS_ARRAY_PRTN_OFFSET = 0x1218;

    var GPAR_BLOCK_HANDLE_OFFSET = 0x1520;
    var GPAR_ELEMENT_COUNT_OFFSET = 0x14;

    // GPAR element offsets

    var GPAR_ELEMENT_MBLOCK_ELEMENT = 0x170;
    var GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178;
    var PAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180;

    // MBLOCK element offsets

    var MBLOCK_ELEMENT_MBHANDLE = 0x18;
    var MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xF0;
}


if (WINDOWS_SERVER_2016 == true){
    var PARTITION_NAME_OFFSET = 0x70;
    var MBLOCKS_ARRAY_PRTN_OFFSET = 0x1240;

    var GPAR_BLOCK_HANDLE_OFFSET = 0x13A0;
    var GPAR_ELEMENT_COUNT_OFFSET = 0x18;

    // GPAR element offsets

    var GPAR_ELEMENT_MBLOCK_ELEMENT = 0x128;
    var GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178;
    var GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180;

    // MBLOCK element offsets

    var MBLOCK_ELEMENT_MBHANDLE = 0x18;
    var MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xE0;
}

if (WINDOWS_11 == true)
{
    var PARTITION_NAME_OFFSET = 0x88;
    var MBLOCKS_ARRAY_PRTN_OFFSET = 0x2ac0;

    var GPAR_BLOCK_HANDLE_OFFSET = 0x2e90;
    var GPAR_ELEMENT_COUNT_OFFSET = 0x14;

    // GPAR element offsets

    var GPAR_ELEMENT_MBLOCK_ELEMENT = 0x178;
    var GPAR_ELEMENT_SOME_GPA_OFFSET = 0x180;
    var GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x188;

    // MBLOCK element offsets

    var MBLOCK_ELEMENT_MBHANDLE = 0x18;
    var MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xE0;
}

if (WINDOWS_11_PREVIEW == true)
{
    var PARTITION_NAME_OFFSET = 0x88;
    var MBLOCKS_ARRAY_PRTN_OFFSET = 0xac8;
    var GPAR_BLOCK_HANDLE_OFFSET = 0xea0;
    var GPAR_ELEMENT_COUNT_OFFSET = 0x14;

    // GPAR element offsets

    var GPAR_ELEMENT_MBLOCK_ELEMENT = 0x180;
    var GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178;
    var GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x190;

    // MBLOCK element offsets

    var MBLOCK_ELEMENT_MBHANDLE = 0x20;
    var MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xE0;
}

var PARTITION_ID_OFFSET = PARTITION_NAME_OFFSET + 0x200;
var MBLOCK_ELEMENT_BITMAP_SIZE_01 = 0x38;
var MBLOCK_ELEMENT_BITMAP_SIZE_02 = 0x40;
var GPAR_ELEMENT_SIGNATURE = 0;
var GPAR_ELEMENT_GPA_INDEX_START = 0x100;
var GPAR_ELEMENT_GPA_INDEX_END = 0x108;
var MBLOCK_ELEMENT_SIGNATURE = 0;
var GPAR_ELEMENT_UM_FLAGS = 0x120;
var GPAR_ARRAY_OFFSET = 0x8;
var MBLOCK_ARRAY_START_POSITION_OFFSET = 8;
var MBLOCK_ARRAY_ELEMENT_COUNT_OFFSET = 0;

function Read64bit(address)
{
    var result = 0;
    result = host.memory.readMemoryValues(address, 1, 8);
    return result[0];
}

function Read32bit(address)
{
    var result = 0;
    result = host.memory.readMemoryValues(address, 1, 4);
    return result[0];
}

//
// https://gist.githubusercontent.com/hkraw/5bc0a4cf4615da4e3bb3a846ecb4fe19/raw/e8320146935cb67f446cafb1d4a5353bbc40dfaf/windbg_pwndbg_wrap.js
//

function ReadString(Addr, MaxLength) {
    let Value = null;
    try {
        Value = host.memory.readString(Addr);
    } catch(e) {
        return null;
    }

    if(Value.length > MaxLength) {
        return Value.substr(0, MaxLength);
    }

    return Value;
}

function ReadWideString(Addr) {
    let Value = null;
    try {
        Value = host.memory.readWideString(Addr);
    } catch(e) {
    }

    return Value;
}

function PrintStrings()
{
    for (var i = 0; i < arguments.length; i++) {
        host.diagnostics.debugLog(arguments[i]);
    }
    host.diagnostics.debugLog('\n');
}

function PrintDml(str1)
{
    var g_ctl = host.namespace.Debugger.Utility.Control;
    var str2 = '<col fg=\"changed\"> hello syntax color \n</col>"';
    var cmd = '.printf /D ' + '"'+str2+'"';
    
    var output = g_ctl.ExecuteCommand(cmd);
}

function pr1str(var1)
{
    host.diagnostics.debugLog(var1, '\n');
}

function pr2str(var1, var2)
{
    host.diagnostics.debugLog(var1, var2, '\n');
}

function PrintObjType(obj)
{
    if (typeof txt === 'object')
    {
        PrintStrings(obj.constructor.name);
    }
    else
    {
        PrintStrings(typeof txt);
    }
}

function PrintGlobalHeader()
{
    var length = header.length;

    for (let i = 0; i < length; i++){
        var str = header[i];
        var tab = header_tabs[i] - str.length;
        if (tab > 0)
        {
            host.diagnostics.debugLog(str.padEnd(header_tabs[i], ' '));
        } 
    };

    host.diagnostics.debugLog('\n');
}

function PrintMBlockArray(pMBlockArray, dqMBlocksCount)
{
    var dash = '\n'+''.padEnd(110, '-');

    header  = ["Index", "Signature", "MBlock Address", "MBHandle", "BitmapSize01", "BitmapSize02", "GPA Array"];
    header_tabs = [6, 12, 22, 10, 16, 16, 22];  

    pr1str("");
    pr1str("MBlock array content:");
    pr1str(dash);

    PrintGlobalHeader();

    for (let i = 0; i < dqMBlocksCount; i++){

        g_PrintTableEntryCounter = 0;
        var objMBlock = Read64bit(pMBlockArray.add(MBLOCK_ARRAY_START_POSITION_OFFSET + i * 8));

        if (objMBlock.subtract(0xffff000000000000) < 0)
        {
            PrintStrings("objMBlock has unusual value. Probably, this is one of docker partitions, which is not contains some memory blocks links");
            continue;
        }

        var uSignature = ReadString(objMBlock);
        var qwMBHandle = Read64bit(objMBlock.add(MBLOCK_ELEMENT_MBHANDLE));
        var qwBitmapSize01 = Read64bit(objMBlock.add(MBLOCK_ELEMENT_BITMAP_SIZE_01));
        var qwBitmapSize02 = Read64bit(objMBlock.add(MBLOCK_ELEMENT_BITMAP_SIZE_02));

        if (qwBitmapSize01 == qwBitmapSize02){
            qwBitmapSize02 = "Same";
        }

        var qwGuestAddressArray = Read64bit(objMBlock.add(MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY));

        PrintTableEntry(i);
        PrintTableEntry(uSignature);

        if (qwBitmapSize02 == "Same")
        {
            PrintTableEntry(objMBlock);
        } 
        else
        {
            PrintTableEntry('No');
        }

        PrintTableEntry(qwMBHandle);
        PrintTableEntry(qwBitmapSize01);
        PrintTableEntry(qwBitmapSize02);
        PrintTableEntry(qwGuestAddressArray);
        host.diagnostics.debugLog('\n');
    }
}

function get_spaces_count(index, txt)
{
    var str = header[index];
    var tab = header_tabs[index] - str.length;
    var result = '';
    var txt_len = 0;

    if (typeof txt === 'string')
    {
        txt_len = txt.length;
    }
    if (typeof txt === 'number' | typeof txt === 'object')
    {
        txt_len = txt.toString().length;
    }

    if (tab >= 0)
    {
        result = ''.padEnd(header_tabs[index] - txt_len, ' ');
    }

    return result;
}

function PrintTableEntry(objValue)
{
    host.diagnostics.debugLog(objValue, get_spaces_count(g_PrintTableEntryCounter, objValue));
    g_PrintTableEntryCounter += 1;
}

function PrintGparArray(pGparArray, dwGparElementCounts)
{
    var dash = '\n'+''.padEnd(160, '-');

    if (WINDOWS_SERVER_2019 == true | WINDOWS_SERVER_2022 == true | WINDOWS_11 == true | WINDOWS_11_PREVIEW == true)
    {
        header = ["Index", "Signature", "StartPageNum", "EndPageNum", "BlockSize", "MemoryBlockGpaRangeFlag", "MBlock", "SomeGPA offset", "VmmemGPA offset"];
        header_tabs = [6, 12, 15, 15, 15, 26, 22, 22, 22];
    }

    if (WINDOWS_SERVER_2016 == true)
    {
        header  = ["Index", "Signature", "StartPageNum", "EndPageNum", "BlockSize", "MemoryBlockGpaRangeFlag", "MBlock"];
        header_tabs = [6, 12, 15, 15, 15, 26, 22];   
    }

    pr1str("");
    pr1str("GPAR Array content");
    pr1str(dash);

    PrintGlobalHeader();

    for (let i = 0; i < dwGparElementCounts; i++){

        g_PrintTableEntryCounter = 0;

        var objGpar = Read64bit(pGparArray.add(i * 8));
        var uSignature = ReadString(objGpar);
        var qwGpaIndexStart = Read64bit(objGpar.add(GPAR_ELEMENT_GPA_INDEX_START));
        var qwGpaIndexEnd = Read64bit(objGpar.add(GPAR_ELEMENT_GPA_INDEX_END));
        var qwBlockSize = qwGpaIndexEnd.subtract(qwGpaIndexStart);

        qwBlockSize = qwBlockSize.add(1);

        var dwUmFlag = Read32bit(objGpar.add(GPAR_ELEMENT_UM_FLAGS));
        var qwMblockAddress = Read64bit(objGpar.add(GPAR_ELEMENT_MBLOCK_ELEMENT));

        PrintTableEntry(i);
        PrintTableEntry(uSignature);
        PrintTableEntry(qwGpaIndexStart);
        PrintTableEntry(qwGpaIndexEnd);
        PrintTableEntry(qwBlockSize);
        PrintTableEntry(dwUmFlag);
        PrintTableEntry(qwMblockAddress);

        if (WINDOWS_SERVER_2016 == false)
        {
            var qwSomeGpa = Read64bit(objGpar.add(GPAR_ELEMENT_SOME_GPA_OFFSET));
            var qwVmmemGpa = Read64bit(objGpar.add(GPAR_ELEMENT_VMMEM_GPA_OFFSET));

            PrintTableEntry(qwSomeGpa);
            PrintTableEntry(qwVmmemGpa);
        } 
        host.diagnostics.debugLog('\n');
    }
}

function PrintPartitionHandleInfo(hPartitionHandle)
{
    PrintStrings("");

    var PartitionSignature = ReadString(hPartitionHandle, 0x100);
    PrintStrings('PartitionSignature: ', PartitionSignature);

    if (PartitionSignature == "Exo "){
        PrintStrings("EXO partition parsing is not implemented yet.");
        return 0;
    }

    var uPartitionNameAddress = hPartitionHandle.add(PARTITION_NAME_OFFSET);
    PrintStrings("Partition name address: ", uPartitionNameAddress, ". PARTITION_NAME_OFFSET: ", hex(PARTITION_NAME_OFFSET));
    var uPartitionName = ReadWideString(hPartitionHandle.add(PARTITION_NAME_OFFSET));
    var qwPartitionId = Read64bit(hPartitionHandle.add(PARTITION_ID_OFFSET));

    PrintStrings("Partition name: ", uPartitionName);
    PrintStrings("Partition id: ", qwPartitionId);

    //
    // MBlocks information
    //
    
    var pMBlockTable = Read64bit(hPartitionHandle.add(MBLOCKS_ARRAY_PRTN_OFFSET));
    var qwMBlocksCount = Read64bit(pMBlockTable.add(MBLOCK_ARRAY_ELEMENT_COUNT_OFFSET));
    qwMBlocksCount = qwMBlocksCount.subtract(1);

    //
    // GPAR blocks information
    //

    var pGparBlockHandle = Read64bit(hPartitionHandle.add(GPAR_BLOCK_HANDLE_OFFSET));
    var dwGparElementCounts = Read32bit(pGparBlockHandle.add(GPAR_ELEMENT_COUNT_OFFSET));
    var pGparArray = Read64bit(pGparBlockHandle.add(GPAR_ARRAY_OFFSET));

    PrintStrings("MBBlocks table address: ", hex(pMBlockTable));
    PrintStrings("MBBlocks table element count: ", qwMBlocksCount);

    PrintStrings("Gpar block handle address: ", hex(pGparBlockHandle));
    PrintStrings("Gpar Element Count: ", dwGparElementCounts);
    PrintStrings("pGparArray address: ", hex(pGparArray));

    PrintGparArray(pGparArray, dwGparElementCounts);
    PrintMBlockArray(pMBlockTable, qwMBlocksCount);
}

function invokeScript()
{
    var g_ctl = host.namespace.Debugger.Utility.Control;
    PrintStrings("Execute .reload command");   
    var output = g_ctl.ExecuteCommand(".reload");

    g_WinHvpPartitionArray = host.getModuleSymbolAddress('winhvr', 'WinHvpPartitionArray');
    PrintStrings('WinHvpPartitionArray address:', g_WinHvpPartitionArray);

    var ptrInternalPartitions = Read64bit(g_WinHvpPartitionArray);

    if (ptrInternalPartitions.convertToNumber() == 0)
    {
        PrintStrings('It looks like there are no active Hyper-V VMs');
        return;
    }

    var PartitionsCount = Read32bit(ptrInternalPartitions);
    PrintStrings('PartitionsCount:', PartitionsCount);

    if (PartitionsCount == 0)
    {
        PrintStrings('VM count is 0\n');
        return;
    }

    PrintStrings("ptrInternalPartitions:", ptrInternalPartitions);

    for (let prtn_num = 0; prtn_num < PartitionsCount; prtn_num++){
		
        var prtn_host_pointer = ptrInternalPartitions.add(0x10 + prtn_num * 0x10);
        var PartitionsVar = Read64bit(prtn_host_pointer);
        var VidPartitionId = Read64bit(PartitionsVar.add(8));
        var PartitionHandle = Read64bit(PartitionsVar.add(0x18));
		
        PrintStrings("VidPartitionId:", VidPartitionId);
        PrintStrings("PartitionHandle:", PartitionHandle);
        PrintPartitionHandleInfo(PartitionHandle);
    }
}

function initializeScript()
{
    //
    // Extends our notion of a process to place architecture information on it.
    //
}