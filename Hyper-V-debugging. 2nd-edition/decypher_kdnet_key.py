__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"

from pykd import *

## https://stackoverflow.com/questions/1181919/python-base-36-encoding


def base36encode(number, alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Converts an integer to a base36 string."""
    if not isinstance(number, int):
        raise TypeError('number must be an integer')

    base36 = ''
    sign = ''

    if number < 0:
        sign = '-'
        number = -number

    if 0 <= number < len(alphabet):
        return sign + alphabet[number]

    while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36

    return sign + base36

def base36decode(number):
    return int(number, 36)

def get_kdnet_base36_key(kdnet_key_address):
    kdnet_key_part1 = base36encode(ptrQWord(kdnet_key_address))
    kdnet_key_part2 = base36encode(ptrQWord(kdnet_key_address + 8))
    kdnet_key_part3 = base36encode(ptrQWord(kdnet_key_address + 0x10))
    kdnet_key_part4 = base36encode(ptrQWord(kdnet_key_address + 0x18))

    kdnet_base36_key = kdnet_key_part1 + "." + kdnet_key_part2 + "." + kdnet_key_part3 + "." + kdnet_key_part4
    return kdnet_base36_key

kdnet = pykd.module("kdcom") # Yes kdnet module is shown as kdcom module
kdnet_parameters = kdnet.KdNetParameters

diff_os_offset = 0 #0 for Windows Server 2019, 0x10 for Windows 10X

kd_port = ptrDWord(kdnet_parameters+0xfc)
if kd_port == 0:
    diff_os_offset = 0x20
    kd_port = ptrDWord(kdnet_parameters + 0xfc+0x10)

print("kd_port:", kd_port)
print("\n")

kdnet_key = kdnet_parameters+0x150+diff_os_offset
kdnet_base36_key = get_kdnet_base36_key(kdnet_key)
print("kdnet key:", kdnet_base36_key)

kdnet_key = kdnet_parameters+0x150+0x20+diff_os_offset
kdnet_base36_key_2 = get_kdnet_base36_key(kdnet_key)
print("kdnet 2nd key (if presented):", kdnet_base36_key_2)



connection_string = "net:port="+str(kd_port)+",key="+kdnet_base36_key
print("WinDBG connection string:", connection_string)
