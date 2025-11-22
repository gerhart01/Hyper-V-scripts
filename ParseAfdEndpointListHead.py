__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.4.0"

# Based on http://www.codemachine.com/article_findafdendpoints.html
# list afd.sys driver endpoints with some additional information. Hyper-V sockets endpoints are included.
# Use pykd WinDBG extension for script execution.

from pykd import *
import sys

EPROCESS_OBJ_OFFSET 	= 0
ACTIVE_PROCESS 			= 0
AFD_ENDPOINT_OFFSET 	= 0
FN_SYMBOL_NAME 			= 0
IMAGE_NAME 				= 0

def findEprocessOffset(AfdEndpoint):

	global AFD_ENDPOINT_OFFSET

	ptrProcessStart     = 0x20
	ptrProcessEnd       = 0x40

	for i in range(AfdEndpoint + ptrProcessStart - AFD_ENDPOINT_OFFSET, AfdEndpoint + ptrProcessEnd - AFD_ENDPOINT_OFFSET):

		eprocessPtr = ptrQWord(i)
		
		try:
			eprocessFlags = ptrQWord(eprocessPtr)
		except:
			continue

		if eprocessFlags == 3:

			global EPROCESS_OBJ_OFFSET
			EPROCESS_OBJ_OFFSET = i - (AfdEndpoint - AFD_ENDPOINT_OFFSET)

			print("EPROCESS_OBJ_OFFSET: " + hex(EPROCESS_OBJ_OFFSET) + ". Address: ", hex(i))

			return


def findAfdOffset(AfdEndpoint):

	afdOffsetEnd     = 0x100
	afdOffsetBegin   = 0x180

	for i in range(AfdEndpoint - afdOffsetBegin, AfdEndpoint - afdOffsetEnd):

		afd = pykd.ptrWord(i) & 0xafd0

		if (afd == 0xafd0): 

			global AFD_ENDPOINT_OFFSET
			AFD_ENDPOINT_OFFSET = AfdEndpoint - i

			print("Found afd offset (AFD_ENDPOINT_OFFSET): " + hex(AfdEndpoint - i) + ". Address: " + hex(i))

			return

def findProviderSymbolOffset(AfdEndpoint):

	provNameOffsetEnd    = 0x90
	provNameOffsetBegin  = 0x160

	for i in range(AfdEndpoint - provNameOffsetBegin, AfdEndpoint - provNameOffsetEnd):
		prvName = ""

		try:
			prvName = findSymbol(ptrQWord(i))
		except:
			continue

		if prvName.find("Provider") != -1:

			global FN_SYMBOL_NAME
			FN_SYMBOL_NAME = AfdEndpoint - i

			print("FN_SYMBOL_NAME: " + hex(FN_SYMBOL_NAME) + ". Address: ", hex(pykd.ptrQWord(i)))

def findFieldOffset(structName, fieldName):

	cmdName = "dt " + structName + " " + fieldName
	structStr = pykd.dbgCommand(cmdName)

	offset_start = structStr.find("+")
	offset_end = structStr.find(" ",offset_start)

	struct_offset = structStr[offset_start+1:offset_end]
	print(structName + " " + fieldName, " offset:", struct_offset)

	return int(struct_offset, 16)


def findEprocessFieldOffset():

	global ACTIVE_PROCESS
	global IMAGE_NAME

	ACTIVE_PROCESS = findFieldOffset("nt!_EPROCESS","ActiveProcessLinks")
	IMAGE_NAME = findFieldOffset("nt!_EPROCESS","ImageFileName")


def findOffsets(AfdEndpoint):

	findAfdOffset(AfdEndpoint)
	findProviderSymbolOffset(AfdEndpoint)
	findEprocessFieldOffset()
	findEprocessOffset(AfdEndpoint)


print("Script for AfdEndpointList parsing")
print("Executing .reload command ...")
pykd.dbgCommand(".reload")

afd = module("afd")
ListHead = afd.AfdEndpointListHead

if ListHead == "":
	print("Check, if afd!AfdEndpointListHead symbol name is presented. Try restart debugger (WinDBG (classic), kd, WinDBG)")
	exit()

ptrNext = ptrQWord(ListHead)
findOffsets(ptrNext)

print("afd!AfdEndpointListHead address: " + hex(ListHead))
print("----AfdEndpoint: "+hex(ptrNext) +". Afd prefix: ", hex(ptrWord(ptrNext - AFD_ENDPOINT_OFFSET)))
print("-------------------------------------------------------------------------------------------------------------------------")

count = 1

format_string = '{:<22s}{:<16s}{:<45s}{:<30s}{:<22s}'
print(format_string.format("AfdEndpoint", "Sign", "Provider function", "Process Name", "ActiveProcessLinks"))
print("")

while (ptrNext != ListHead) & (ptrNext != 0xffffffffffffffff):

	addPtrNext = hex(ptrNext)
	afdSign = hex(ptrWord(ptrNext - AFD_ENDPOINT_OFFSET))
	afdProviderFunction = findSymbol(ptrQWord(ptrNext - FN_SYMBOL_NAME))
	afdProcessName = loadCStr(ptrQWord(ptrNext - AFD_ENDPOINT_OFFSET + EPROCESS_OBJ_OFFSET) + IMAGE_NAME)
	afdActiveProcessLink = hex(ptrQWord(ptrNext - AFD_ENDPOINT_OFFSET + EPROCESS_OBJ_OFFSET) + ACTIVE_PROCESS)
	print(format_string.format(addPtrNext, afdSign, afdProviderFunction, afdProcessName, afdActiveProcessLink))
	ptrNext = ptrQWord(ptrNext)
	count = count + 1

print("Cycle end. Count", count)