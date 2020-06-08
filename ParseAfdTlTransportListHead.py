__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.2.0"

# parsing AfdTlTransportListHead structure

from pykd import *
import sys

AF_dict = {
 0:"AF_UNSPEC", 
 1:"AF_UNIX",       
 2:"AF_INET",       
 3:"AF_IMPLINK",    
 4:"AF_PUP",        
 5:"AF_CHAOS",      
 6:"AF_NS",         
 7:"AF_OSI",              
 8:"AF_ECMA",           
 9:"AF_DATAKIT", 
 10:"AF_CCITT",      
 11:"AF_SNA",        
 12:"AF_DECnet",     
 13:"AF_DLI",        
 14:"AF_LAT",        
 15:"AF_HYLINK",     
 16:"AF_APPLETALK",  
 17:"AF_NETBIOS",    
 18:"AF_VOICEVIEW",  
 19:"AF_FIREFOX",    
 20:"AF_UNKNOWN1",   
 21:"AF_BAN",        
 22:"AF_ATM",        
 23:"AF_INET6",      
 24:"AF_CLUSTER",    
 25:"AF_12844",      
 26:"AF_IRDA",       
 28:"AF_NETDES",   
 29:"AF_TCNPROCESS",
 30:"AF_TCNMESSAGE", 
 31:"AF_ICLFXBM",
 32:"AF_BTH",
 33:"AF_LINK",
 34:"AF_HYPERV",
 35:"AF_MAX"
}

afd = pykd.module("afd")
ListHead = afd.AfdTlTransportListHead
afd_rbx = ptrQWord(ListHead)
print("cs:AfdTlTransportListHead address is ", hex(afd_rbx))

while (afd_rbx != ListHead) & (afd_rbx != 0xffffffffffffffff):
    print("----Address family", hex(ptrByte(afd_rbx + 0x16)), "[", AF_dict[ptrByte(afd_rbx + 0x16)], "]")
    print("--Dispatch function", findSymbol(ptrQWord(afd_rbx + 0x28)))
    afd_rbx = ptrQWord(afd_rbx)
print("Cycle end. Afd_rbx", hex(afd_rbx))