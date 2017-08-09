__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "0.0.1"

#bases on http://www.codemachine.com/article_findafdendpoints.html
#list afd endpoints with some additional info. Hyper-V sockets endpoints are included.

from pykd import *
import sys


afd = module("afd")
ListHead = afd.AfdEndpointListHead
print "afd!AfdEndpointListHead address is ",hex(ListHead)
ptrNext = ptrQWord(ListHead)
print "----AfdEndpoint",hex(ListHead),hex(ptrWord(ListHead-0x120))
count = 1
while (ptrNext <> ListHead) & (ptrNext != 0xffffffffffffffffL):
	print "----AfdEndpoint",hex(ptrNext),hex(ptrWord(ptrNext-0x120)),findSymbol(ptrQWord(ptrNext-0x108)),loadCStr(ptrQWord(ptrNext-0x120+0x28)+0x450),hex(ptrQWord(ptrQWord(ptrNext-0x120+0x28)+0x2e8))
	ptrNext = ptrQWord(ptrNext)
	count = count+1
print "Cycle end. Count", count
