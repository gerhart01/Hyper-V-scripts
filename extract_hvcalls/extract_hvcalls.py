__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"


import os
import sys
import json
import pathlib

hard_hvcalls = {

}

script_args = len(idc.ARGV)
print("script_args", script_args)

if script_args > 0:
    ida_auto.auto_wait()

current_dir = str(pathlib.Path(__file__).parent.resolve())

sys.path.append(current_dir + "\\idahunt\\")
import ida_helper

hvcall_dict = {}
hvcall_dict_unknown = {}

# hvcall_file_path = current_dir + "\\hvcalls_dict.json"

hvcall_dir_saving = current_dir + "\\hvcalls_json_files\\"
hvcall_unknown_dir_saving = hvcall_dir_saving + "\\unknown\\"

if not os.path.exists(hvcall_dir_saving):
    os.makedirs(hvcall_dir_saving)

if not os.path.exists(hvcall_unknown_dir_saving):
    os.makedirs(hvcall_unknown_dir_saving)


def find_duplicates(dict1, dict2):
    intersect = []
    for item in dict1.keys():
        if item in dict2.keys():
            intersect.append(item)
    print("Intersects:", intersect)


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
        print("Function name is empty")
        return hvcall_name

    return hvcall_name


def get_function_with_params(hv_decompile, hvcall_aux_fn_name):
    #
    # first, find end of function params. It is ")"
    #

    hvcall_start = hv_decompile.find(hvcall_aux_fn_name) + len(hvcall_aux_fn_name) + 1
    hvcall_end = hv_decompile.find(");", hvcall_start) + 2  ## -1 will be returned in error

    print("hvcall_start:", hvcall_start)
    print("hvcall_end:", hvcall_end)

    if hvcall_end == 1:
        print("hv_decompile", hv_decompile)
        hvcall_end = hv_decompile.find(")", hvcall_start) + 1
        print("hvcall_end without );", hvcall_end)

    param_string = hv_decompile[hvcall_start:hvcall_end]

    # print(param_string, "hvcall_name:", hvcall_name)

    param_string = param_string.replace("\n", "")
    param_string = param_string.replace("(", "")

    return param_string


def extract_hvcall_id_from_param(number_str, hvcall_name):
    b_hex = False

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

    try:
        if b_hex:
            hvcall_id = hvcall_id.replace("u", "")
            hvcall_id = int(hvcall_id, 16)
        else:
            hvcall_id = int(hvcall_id)
    except:
        hvcall_dict_unknown[hvcall_id] = hvcall_name.replace("WinHv", "HvCall")
        hvcall_id = "id_unknown"

    if hvcall_id == 0:
        print("hvcall_id in str format", number_str)

    return hvcall_id


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
        # if function has 2 parameters
        #

        if param1_right_bound == -1:
            param1_right_bound = param_string.find(");")
            if param1_right_bound == -1:
                param1_right_bound = param_string.find(")")

        print("param0_right_bound", param0_right_bound)
        print("param1_right_bound", param1_right_bound)

        #
        # parsing different parameters
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

    # print(hex(WinHvpSimplePoolHypercall_CallViaMacro))
    for xref in XrefsTo(fn_address, ida_xref.XREF_ALL):

        # print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
        hvcall_name = get_function_name_by_address(xref.frm)

        if hvcall_name == "" or hvcall_name == "WinHvpAllocatingHypercall":
            continue

        error_info = 0

        if method == "decompile":

            hvcall_id = get_hvcall_from_decompiler_result(fn_name, xref.frm, arg_number, hvcall_name)

            if (hvcall_id != 0) and (hvcall_id != "id_unknown"):
                hvcall_dict[hvcall_id] = hvcall_name.replace("WinHv", "HvCall")
                count += 1

        if method == "disasm":
            var_args = ida_helper.get_call_arguments_x64_windows(xref.frm, debug=False)
            # print(str(var_args))
            if var_args:
                if len(var_args) > arg_number:
                    hvcall_dict[var_args[arg_number]] = hvcall_name.replace("WinHv", "HvCall")
                    count += 1

            # print(hex(var_args[arg_number]))

    print("count of xRefs functions in ", fn_name, ": ", count)


def print_hvcall(hvcalls, is_str):
    if is_str:
        for item in hvcalls.items():
            str_print = str(item[0]) + ": " + str(item[1])
            print(str_print)
    else:
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


#
# winhvr.sys, winhv.sys
#

find_hvcall_by_aux_function_name('WinHvpSimplePoolHypercall_CallViaMacro', 1, "decompile")
find_hvcall_by_aux_function_name('WinHvpRangeRepHypercall', 0, "decompile")
find_hvcall_by_aux_function_name('WinHvpSpecialListRepHypercall', 0, "decompile")

#
# securekernel.exe
#

find_hvcall_by_aux_function_name('ShvlpInitiateFastHypercall', 0, "decompile")
find_hvcall_by_aux_function_name('ShvlpInitiateRepListHypercall', 0, "decompile")

#
# ntoskrnl.exe
#

find_hvcall_by_aux_function_name('HvcallFastExtended', 0, "decompile")
find_hvcall_by_aux_function_name('HvcallInitiateHypercall', 0, "decompile")

print_hvcall(hvcall_dict, False)

print("saving hvcall_dict to json ...")

filename = hvcall_dir_saving + ida_helper.get_idb_name() + ".json"
hvcall_dict = str_key_to_int_with_sorting(hvcall_dict)
save_dict_to_file(filename, hvcall_dict)

if len(hvcall_dict_unknown) > 0:
    unknown_filename = hvcall_unknown_dir_saving + "unknown_" + ida_helper.get_idb_name() + ".json"
    save_dict_to_file(unknown_filename, hvcall_dict_unknown)
    print("hvcalls with unknown result of analysis  - need manual analysis")
    print_hvcall(hvcall_dict_unknown, True)

print("hvcall_dict lenght:", len(hvcall_dict))
print("hvcall_dict_unknown lenght:", len(hvcall_dict_unknown))
print("db file:", ida_nalt.get_input_file_path())
print("idb", ida_helper.get_idb_name())

if script_args > 0:
    idc.qexit(0)