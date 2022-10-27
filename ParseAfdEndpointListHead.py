__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.3.0"

# based on http://www.codemachine.com/article_findafdendpoints.html
# list afd endpoints with some additional info. Hyper-V sockets endpoints are included.
# Use pykd WinDBG extension for script execution

from pykd import *
import sys

win2019 = False
win11 = False
win2022 = False

EPROCESS_AFD_OFFSET = 0x28
ACTIVE_PROCESS = 0
AFD_ENDPOINT_OFFSET = 0
FN_SYMBOL_NAME = 0
IMAGE_NAME = 0

if win2019:
	AFD_ENDPOINT_OFFSET = 0x120
	FN_SYMBOL_NAME = 0x108
	IMAGE_NAME = 0x450

if win11:
	AFD_ENDPOINT_OFFSET = 0x130
	FN_SYMBOL_NAME = 0x118
	IMAGE_NAME = 0x5a8
if win2022:
	AFD_ENDPOINT_OFFSET = 0x120
	FN_SYMBOL_NAME = 0x108
	IMAGE_NAME = 0x5a8


def findAfdOffset(AfdEndpoint):
	afdOffsetEnd = 0x110
	afdOffsetBegin = 0x150
	for i in range(AfdEndpoint-afdOffsetBegin, AfdEndpoint-afdOffsetEnd):

		afd = pykd.ptrWord(i) & 0xafd0

		if (afd == 0xafd0): 
			print("found afd offset ", hex(AfdEndpoint - i))
			global AFD_ENDPOINT_OFFSET
			AFD_ENDPOINT_OFFSET = AfdEndpoint - i
			return

def findProviderSymbolOffset(AfdEndpoint):
	provNameOffsetEnd = 0x100
	provNameOffsetBegin = 0x140
	for i in range(AfdEndpoint-provNameOffsetBegin, AfdEndpoint-provNameOffsetEnd):
		prvName = ""

		try:
			prvName = findSymbol(ptrQWord(i))
		except:
			continue

		if prvName.find("Provider") != -1:
			global FN_SYMBOL_NAME
			FN_SYMBOL_NAME = AfdEndpoint - i
			print("FN_SYMBOL_NAME: ", hex(FN_SYMBOL_NAME))

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



print("Script for AfdEndpointList head parsing")
print("Executing .reload command ...")
pykd.dbgCommand(".reload")

afd = module("afd")
ListHead = afd.AfdEndpointListHead

if ListHead == "":
	print("Check in WinDBG, if x afd!AfdEndpointListHead symbol name is presented. Try restart WinDBG")
	exit()

ptrNext = ptrQWord(ListHead)
findOffsets(ptrNext)

print("afd!AfdEndpointListHead address is ", hex(ListHead))
print("----AfdEndpoint:", hex(ptrNext), "afd prefix: ", hex(ptrWord(ptrNext-AFD_ENDPOINT_OFFSET)))

count = 1

format_string = '{:<22s}{:<16s}{:<45s}{:<30s}{:<22s}'
print(format_string.format("AfdEndpoint", "Sign", "Provider function", "Process Name", "ActiveProcessLinks"))
print("")

while (ptrNext != ListHead) & (ptrNext != 0xffffffffffffffff):

	addPtrNext = hex(ptrNext);
	afdSign = hex(ptrWord(ptrNext-AFD_ENDPOINT_OFFSET))
	afdProviderFunction = findSymbol(ptrQWord(ptrNext-FN_SYMBOL_NAME))
	afdProcessName = loadCStr(ptrQWord(ptrNext-AFD_ENDPOINT_OFFSET+EPROCESS_AFD_OFFSET)+IMAGE_NAME)
	afdActiveProcessLink = hex(ptrQWord(ptrNext-AFD_ENDPOINT_OFFSET+EPROCESS_AFD_OFFSET)+ACTIVE_PROCESS)

	print(format_string.format(addPtrNext, afdSign, afdProviderFunction, afdProcessName, afdActiveProcessLink))
	ptrNext = ptrQWord(ptrNext)
	count = count+1

print("Cycle end. Count", count)