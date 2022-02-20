__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"

import os
import sys
import json
import pathlib

# ntoskrnl, build 10.0.20298.1
g_hardcoded_hvcalls_10_0_20298_1 = {
    0x2: "HvlpSlowFlushListTb",  # v9 = 2i64; #  LODWORD(v19) = 3;
    0x3: "HvlpSlowFlushListTb",  # v9 = 2i64; #  LODWORD(v19) = 3;
    0x13: "HvlpSlowFlushAddressSpaceTbEx",  # HvcallInitiateHypercall(((v10 + 7) << 14) & 0x3FE0000 | 0x13u
    # difference in parameters HvlpFastFlushAddressSpaceTbEx (v4 + 7) << 14) & 0x3FE0000 | 0x10013u
    0x14: "HvlpSlowFlushListTbEx",  # LODWORD(v20) = ((v11 + 7) << 14) & 0x3FE0000 | 0x14;
    0x15: "HvlpSlowSendSyntheticClusterIpiEx",  # v8 = HvcallInitiateHypercall(((v5 + 7) << 14) & 0x3FE0000 | 0x15i64,
    0x48: "HvlMapGpaPages",  # LODWORD(a6) = 75;
    # HvlpDepositPages - different name for same hypercall
    0x4E: 'HvlpCreateRootVirtualProcessor',
    # HvcallInitInputControl(0x4E, &v15); v11 = HvcallInitiateHypercall(v15, v9, 0i64, v10);
    0x6E: "HvlMapSparseGpaPages",
    # LODWORD(a5) = 110; "v30": "HvlNotifyPageHeat",  v11 = 0x8003i64; HIDWORD(v30) =    # HIDWORD(v11) ^ ((unsigned __int16)v13 ^ WORD2(v11)) & 0xFFF;
    0x7C: "HvlMapDeviceInterrupt",  # HvcallInitiateHypercall(((v10 + 7) << 14) & 0x3FE0000 | 0x7Ci64
    0x7F: "HvlRetargetDeviceInterrupt",  # v18 = 127i64;
    0x82: "HvlRegisterDeviceId",  # HvcallInitiateHypercall((v6 << 14) & 0x3FE0000 | 0x82i64

    0x88: 'HvlLpReadMultipleMsr',  # LODWORD(v17) = 136;
    0x89: "HvlLpWriteMultipleMsr",  # LODWORD(v16) = 137;
    0xA1: "HvlpSlowFlushPasidAddressList",  # LODWORD(v14) = 161; HvcallInitiateHypercall(v14, v17, 0i64, v9);
    0xA6: 'HvlpSlowAcknowledgePageRequest',
    # LODWORD(v12) = 166; # HvlpAffinityToHvProcessorSet ((v10 + 7) << 14) & 0x3FE0000 | 0x14; HvcallFastExtended(v13 | 0x10000
    0xB3: "HvlDmaMapDeviceLogicalRange",  # v17 = 0xB3;
    # v15 = HvcallFastExtended(v19, (unsigned int)&v18, 0x10, 0, 0);
    0xBC: "HvlpAddRemovePhysicalMemory",  # v10 = 0x100BC;v19 = v10;
    0xC7: "HvlDmaMapDeviceSparsePages",  # v12 = 199;
    0xC8: "HvlDmaUnmapDeviceSparsePages",  # v12 = 200;
    0xCA: 'HvlGetSparseGpaPagesAccessState',  # LODWORD(v27) = 202;
    0xDB: "HvlChangeIsolatedMemoryVisibility",  # LODWORD(v20) = 219;
}

# ntoskrnl, build 10.0.20344.1
g_hardcoded_hvcalls_10_0_20344_1 = {
    0x7: "HvlpDynamicUpdateMicrocode",  # HvcallFastExtended(v12, (unsigned int)&v13, HvcallInitInputControl(7i64
    0x10013: "HvlpFastFlushAddressSpaceTbEx",  # HvcallFastExtended(((v4 + 7) << 14) & 0x3FE0000 | 0x10013u,
    0x10014: "HvlpFastFlushListTbEx",  # v13 = ((v10 + 7) << 14) & 0x3FE0000 | 0x14; HvcallFastExtended(v13 | 0x10000,
    0x8003: "HvlNotifyPageHeat",  # v11 = 0x8003i64;
}

g_hardcoded_hvcalls_10_0_19041_1052 = {
    0x7: "HvlpCondenseMicrocode",  # HvcallInitInputControl(7i64, &v2);
    0x48: "HvlpDepositPages",  # LODWORD(v26) = 0x48; HvcallInitiateHypercall(v26,
}

g_hardcoded_hvcalls = [
    g_hardcoded_hvcalls_10_0_19041_1052,
    g_hardcoded_hvcalls_10_0_20298_1,
    g_hardcoded_hvcalls_10_0_20344_1
]

g_script_args = len(idc.ARGV)
print("g_script_args", g_script_args)

if g_script_args > 0:
    ida_auto.auto_wait()

g_current_dir = str(pathlib.Path(__file__).parent.resolve())

#
#   directories for searching and saving
#

g_hvcall_dir_saving = g_current_dir + "\\hvcalls_json_files\\"
g_hvcall_unknown_dir_saving = g_hvcall_dir_saving + "\\unknown\\"

#
# import Idahunt module
#

sys.path.append(g_current_dir + "\\idahunt\\")
import ida_helper

g_idb_name = ida_helper.get_idb_name()

g_hvcall_dict = {}
g_hvcall_dict_unknown = {}
g_hvcall_dict_unknown_index = 0

# hvcall_file_path = g_current_dir + "\\hvcalls_dict.json"

if not os.path.exists(g_hvcall_dir_saving):
    os.makedirs(g_hvcall_dir_saving)

if not os.path.exists(g_hvcall_unknown_dir_saving):
    os.makedirs(g_hvcall_unknown_dir_saving)


def save_dict_to_file(file_path, t_dict):
    file = open(file_path, "w")
    print("Saving file to ", file_path)
    json.dump(t_dict, file, indent=4)  # sort_keys=True
    file.close()


def load_dict_from_file(file_path):
    file = open(file_path, "r")
    hv_dict = file.read()
    print(file)
    return hv_dict


#
#  script is used for modules winhvr.sys, winhv.sys, securekernel.exe, ntoskrnl.exe
#  P.S. many functions inside export of winhvr.sys doesn't use hypercalls
#

def get_function_name_by_address(fn_address):
    hvcall_name = idc.get_func_name(fn_address)

    if hvcall_name == '':
        print("Function name is empty. Address:", fn_address)
        return ''

    return hvcall_name


def get_function_with_params(hv_decompile, hvcall_aux_fn_name):
    #
    # first, find end of function params. It is ")" or ");"
    #

    hvcall_start = hv_decompile.find(hvcall_aux_fn_name) + len(hvcall_aux_fn_name) + 1
    hvcall_end = hv_decompile.find(");", hvcall_start) + 2  # -1 will be returned in error

    print("hvcall_start:", hvcall_start)
    print("hvcall_end:", hvcall_end)

    if hvcall_end == 1:  # -1 + 2 = 1
        print("hv_decompile", hv_decompile)
        hvcall_end = hv_decompile.find(")", hvcall_start) + 1
        print("hvcall_end without );", hvcall_end)

    param_string = hv_decompile[hvcall_start:hvcall_end]

    # print(param_string, "hvcall_name:", hvcall_name)

    param_string = param_string.replace("\n", "")
    param_string = param_string.replace("(", "")

    return param_string


def find_value_in_hvcalls_hardcoded(d_value):
    global g_hardcoded_hvcalls

    for d_dict in g_hardcoded_hvcalls:
        for key, value in d_dict.items():
            if value == d_value:
                print("record was found in g_hardcoded_hvcalls array. key:", int(key), "key type:", type(key), "value:",
                      value)
                return int(key)

    return "id_unknown"


def extract_hvcall_id_from_param(number_str, hvcall_name):
    global g_hvcall_dict_unknown_index
    b_hex = False

    # hvcall_name = hvcall_name.replace("WinHv", "HvCall")

    id_str = number_str.find("u,")

    if id_str != -1:
        b_hex = True
    else:
        id_str = number_str.find("i64")

    if id_str != -1:
        hvcall_id = number_str[:id_str]
    else:
        hvcall_id = number_str

    if (hvcall_id.find("0x") != -1) and (b_hex == False):
        b_hex = True

    #
    # some exceptions for ShvlInjectVtl0Nmi
    # ShvlpInitiateFastHypercall(v0 + 0x94, &v2, (v0 + 32), 0, v0, v0, v0);
    #

    if hvcall_id.find("+") != -1:
        digit_right_bound = hvcall_id.find("+") + 1
        hvcall_id = hvcall_id[digit_right_bound:]

    #
    # some exceptions for ShvlModifySparseSpaPageHostAccess
    # (ShvlpInitiateRepListHypercall)(0xD8 - (a1 != 0), 1i64, *a5, v6, 8, a4, 8, 0i64, 0, a5);
    #

    if hvcall_id.find("-") != -1:
        digit_left_bound = hvcall_id.find("-")
        hvcall_id = hvcall_id[:digit_left_bound]

    hvcall_id = hvcall_id.replace(" ", "")

    print("number_str", number_str)
    print("hvcall_id", hvcall_id)

    #
    # First, we try extract hvcall_id from cypher. If it is hard-extracted value (like v10 from Hex-Rays) we need extract it from default array or written to g_hvcall_dict_unknown
    #

    try:
        if b_hex:
            hvcall_id = hvcall_id.replace("u", "")
            hvcall_id = int(hvcall_id, 16)
        else:
            hvcall_id = int(hvcall_id)
    except:

        hvcall_id_hard = find_value_in_hvcalls_hardcoded(hvcall_name)  # can return number or string "id_unknown"
        print("hvcall_id_hard", hvcall_id_hard)

        if hvcall_id_hard == "id_unknown":
            hvcall_dict_unknown_entry = [hvcall_id, hvcall_name]
            g_hvcall_dict_unknown[g_hvcall_dict_unknown_index] = hvcall_dict_unknown_entry
            g_hvcall_dict_unknown_index = g_hvcall_dict_unknown_index + 1
            print(hvcall_name, "was added to unknown hvcalls array")
            hvcall_id = "id_unknown"
        else:
            g_hvcall_dict[hvcall_id_hard] = hvcall_name + "_hardcoded_value"
            hvcall_id = "item_replaced"

    if hvcall_id == 0:
        print("hvcall_id in str format", number_str)

    return hvcall_id  # if we return value after replacing we can get problem with next parsing of old dict


def get_hvcall_from_decompiler_result(hvcall_aux_fn_name, fn_address, arg_number, hvcall_name):

    hvcall_id = 0

    try:
        hv_decompile = str(idaapi.decompile(fn_address))
    except:
        print("bad function decompilation", hvcall_aux_fn_name)
        return ""

    if hv_decompile:

        param_string = get_function_with_params(hv_decompile, hvcall_aux_fn_name)

        print(hvcall_aux_fn_name + ". param_string:" + param_string + "hvcall_name:" + hvcall_name)

        #
        # parsing digital number of cypher. Function can get 5 or 6 parameters
        # part of param in hex format like
        #  "0x4Cu", 219, 80i64, 0xCi64
        #

        param0_right_bound = param_string.find(", ")
        param1_right_bound = param_string.find(", ", param0_right_bound + 2)

        #
        # if function has only 2 parameters
        #

        if param1_right_bound == -1:
            param1_right_bound = param_string.find(");")
            if param1_right_bound == -1:
                param1_right_bound = param_string.find(")")

        print("param0_right_bound", param0_right_bound)
        print("param1_right_bound", param1_right_bound)

        #
        # parsing different parameters
        # arg_number - number of arguemtn position in function parameters
        #

        if arg_number == 0:
            param0 = param_string[:param0_right_bound]
            hvcall_id = extract_hvcall_id_from_param(param0, hvcall_name)
            print("id0", hvcall_id)

        if arg_number == 1:
            param1 = param_string[(param0_right_bound + 2):param1_right_bound]
            hvcall_id = extract_hvcall_id_from_param(param1, hvcall_name)
            print("id1", hvcall_id)

        #
        # we have results such as 0xCi64 in WinHvModifyVtlProtectionMask
        # looks like decompiler error. We can convert number in 12I64
        #

    return hvcall_id


def find_hvcall_by_aux_function_name(fn_name, arg_number, method):
    #
    # arguments number from zero
    #

    count = 0

    print("Processing ", fn_name, "...")

    fn_address = idc.get_name_ea_simple(fn_name)

    if fn_address == 0xffffffffffffffff:
        print("Bad function name")
        return False

    for xref in XrefsTo(fn_address, ida_xref.XREF_ALL):

        # print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
        hvcall_name = get_function_name_by_address(xref.frm)

        if (hvcall_name == "") or (hvcall_name == "WinHvpAllocatingHypercall"):
            continue

        error_info = 0

        if method == "decompile":

            hvcall_id = get_hvcall_from_decompiler_result(fn_name, xref.frm, arg_number, hvcall_name)

            if (hvcall_id != 0) and (hvcall_id != "id_unknown") and (hvcall_id != "item_replaced"):

                if type(hvcall_id) == "str":
                    print("Warning. type of hvcall_id is string:", hvcall_id(), hvcall_name)

                g_hvcall_dict[hvcall_id] = hvcall_name   # .replace("WinHv", "HvCall")  # we need check hardcoded array

            count += 1

        if method == "disasm":
            var_args = ida_helper.get_call_arguments_x64_windows(xref.frm, debug=False)
            # print(str(var_args))
            if var_args:
                if len(var_args) > arg_number:
                    g_hvcall_dict[var_args[arg_number]] = hvcall_name # .replace("WinHv", "HvCall")
                    count += 1

            # print(hex(var_args[arg_number]))

    print("count of xRefs functions in ", fn_name, ": ", count)


def check_dict_on_str(dict1):
    l_list = list(dict1.keys())

    for key in l_list:
        print("Key type is: ", type(key), "Key is: ", key, "value: ", dict1[key])
        # if type(key) == 'str':
        #    print("Warning. Key type is string: ", key, "value: ", dict1[key])


def print_hvcall(hvcalls, is_str):
    if is_str:
        for item in hvcalls.items():
            str_print = str(item[0]) + ": " + str(item[1])
            print(str_print)
    else:
        check_dict_on_str(hvcalls)
        for item in sorted(hvcalls.items()):
            str_print = hex(int(item[0])) + ": " + item[1]
            print(str_print)


def str_key_to_int_with_sorting(dictionary):
    dict_tmp = {}

    for key in dictionary.keys():
        dict_tmp[int(key)] = dictionary[key]

    sorted_dict = {k: dict_tmp[k] for k in sorted(dict_tmp)}

    dict_tmp = {}

    for key in sorted_dict.keys():
        dict_tmp[hex(key)] = sorted_dict[key]

    return dict_tmp


def int_key_to_hex(dictionary):
    dict_result = {}

    for key in dictionary.keys():
        dict_result[hex(key)] = dictionary[key]

    return dict_result


def get_file_version():
    from pefile import PE

    pename = ida_nalt.get_input_file_path()

    pe = PE(pename)
    if not 'VS_FIXEDFILEINFO' in pe.__dict__:
        print("ERROR: Oops, %s has no version info. Can't continue." % (pename))
        return
    if not pe.VS_FIXEDFILEINFO:
        print("ERROR: VS_FIXEDFILEINFO field not set for %s. Can't continue." % (pename))
        return

    verinfo = pe.VS_FIXEDFILEINFO[0]

    prodver = str(verinfo.ProductVersionMS >> 16) + "." + str(verinfo.ProductVersionMS & 0xFFFF) + "." + str(
        verinfo.ProductVersionLS >> 16) + "." + str(verinfo.ProductVersionLS & 0xFFFF)

    return prodver


def extract_hvcalls():
    #
    # winhvr.sys, winhv.sys
    #

    if (g_idb_name == "winhvr.sys") or (g_idb_name == "winhv.sys"):
        find_hvcall_by_aux_function_name('WinHvpSimplePoolHypercall_CallViaMacro', 1, "decompile")
        find_hvcall_by_aux_function_name('WinHvpRangeRepHypercall', 0, "decompile")
        find_hvcall_by_aux_function_name('WinHvpSpecialListRepHypercall', 0, "decompile")

    #
    # securekernel.exe, securekernella57.exe
    #

    if (g_idb_name == "securekernel.exe") or (g_idb_name == "securekernella57.exe"):
        find_hvcall_by_aux_function_name('ShvlpInitiateFastHypercall', 0, "decompile")
        find_hvcall_by_aux_function_name('ShvlpInitiateRepListHypercall', 0, "decompile")

    #
    # ntoskrnl.exe, ntkrla57.exe
    #

    if (g_idb_name == "ntoskrnl.exe") or (g_idb_name == "ntkrla57.exe"):
        find_hvcall_by_aux_function_name('HvcallFastExtended', 0, "decompile")
        find_hvcall_by_aux_function_name('HvcallInitiateHypercall', 0, "decompile")

    print_hvcall(g_hvcall_dict, False)

    print("saving g_hvcall_dict to json ...")

    fv = get_file_version()

    #
    # if you copy idb from another place you can have error with pathM which are stored in idb file
    #

    filename = g_hvcall_dir_saving + ida_helper.get_idb_name() + "_" + fv + ".json"
    hvcall_dict = str_key_to_int_with_sorting(g_hvcall_dict)
    save_dict_to_file(filename, hvcall_dict)

    #
    # save file with uknown hypercalls
    #

    if len(g_hvcall_dict_unknown) > 0:
        unknown_filename = g_hvcall_unknown_dir_saving + "unknown_" + ida_helper.get_idb_name() + "_" + fv + ".json"
        save_dict_to_file(unknown_filename, g_hvcall_dict_unknown)
        print("hvcalls with unknown result of analysis  - need manual analysis")
        print_hvcall(g_hvcall_dict_unknown, True)

    print("g_hvcall_dict lenght:", len(g_hvcall_dict))
    print("g_hvcall_dict_unknown lenght:", len(g_hvcall_dict_unknown))
    print("db file:", ida_nalt.get_input_file_path())
    print("idb", g_idb_name)


extract_hvcalls()

if g_script_args > 0:
    idc.qexit(0)
