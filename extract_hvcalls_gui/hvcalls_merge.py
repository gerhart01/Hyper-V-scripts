__author__ = "Gerhart"
__license__ = "GPL3"
__version__ = "1.0.0"

import os
import json
import pathlib

hvcall_dir_saving = str(pathlib.Path(__file__).parent.resolve()) + "\\hvcalls_json_files\\"
hvcall_dir_result = str(pathlib.Path(__file__).parent.resolve()) + "\\result\\"
hvcall_dir_saving_unknown = hvcall_dir_saving + "unknown\\"

if not os.path.exists(hvcall_dir_result):
    os.makedirs(hvcall_dir_result)


def load_dict_from_file(file_path):
    hv_dict = {}

    if not os.path.exists(file_path):
        print("file " + file_path + "doesn't exist")
        return hv_dict

    with open(file_path, "r") as read_content:
        hv_dict = json.load(read_content)

    return hv_dict


def save_dict_to_file(hvcall_file_path, t_dict):
    file = open(hvcall_file_path, "w")
    print("Saving file to ", hvcall_file_path)
    json.dump(t_dict, file, indent=4)
    file.close()


def correct_found_hypercalls(hvcall_dict):

    for key in hvcall_dict.keys():
        str_hvcall_name = hvcall_dict[key]
        str_hvcall_name = str_hvcall_name.replace("WinHv", "HvCall")
        str_hvcall_name = str_hvcall_name.replace("Shvl", "HvCall")
        str_hvcall_name = str_hvcall_name.replace("Skhal", "HvCall")
        str_hvcall_name = str_hvcall_name.replace("Hvlp", "HvCall")
        str_hvcall_name = str_hvcall_name.replace("Hvl", "HvCall")
        hvcall_dict[key] = str_hvcall_name

    return


def key_to_int(s_key):
    dd_key = 0
    try:
        dd_key = int(s_key)
    except:
        dd_key = int(s_key, 16)

    return dd_key


def str_key_to_int(dict1):
    dict2 = {}

    try:
        for key in dict1.keys():
            dict2[int(key)] = dict1[key]
    except:
        for key in dict1.keys():
            dict2[int(key, 16)] = dict1[key]

    sorted_dict2 = {k: dict2[k] for k in sorted(dict2)}

    return sorted_dict2


def str_key_to_int_with_sorting(dictionary):
    dict_tmp = {}

    for key in dictionary.keys():
        dict_tmp[int(key)] = dictionary[key]

    sorted_dict = {k: dict_tmp[k] for k in sorted(dict_tmp)}

    dict_tmp = {}

    for key in sorted_dict.keys():
        dict_tmp[hex(key)] = sorted_dict[key]

    return dict_tmp


def get_dict_key_by_val(dict1, searching_value):
    for key, value in dict1.items():
        if value in searching_value:
            return dict1[key]


def find_duplicates_in_dicts(dict1, dict2):
    dict1_list = list(dict1.keys())
    dict2_list = list(dict2.keys())

    if dict1 == {} or dict2 == {}:
        return

    for key in dict1_list:
        if key in dict2_list:
            print("   duplicate in key found. key:", key, "dict1:", dict1[key], "dict2", dict2[key])

    dict1_values = list(dict1.values())
    dict2_values = list(dict2.values())

    for value in dict1_values:
        if value in dict2_values:
            key = list(dict1.keys())[list(dict1.values()).index(value)]
            print("   duplicate in value found:" + str(value) + "(hvcall_id=" + key + ")")


def remove_param_values_from_hvcall(d_hvcalls):
    #
    # remove all params above 0x1000 for exporting
    #

    hvcall_fixed = {}

    dict1_list = list(d_hvcalls.keys())
    count = 0

    for key in dict1_list:
        short_key = key & 0xFFF

        if (short_key in dict1_list) and (key > 0x1000):
            print("hypercall " + hex(key) + ":" + d_hvcalls[key] + "already presented in dictionary")
            count = count + 1
        else:
            hvcall_fixed[short_key] = d_hvcalls[key]

    print("count of duplicated hypercalls (with parameters): ", count)

    return hvcall_fixed


def is_string_in_list_element(l_list, s_string):
    d_len = len(l_list)

    for ss in l_list:
        if s_string in ss:
            return True

    return False


def convert_dic_values_to_list(dict1):
    for key in dict1.keys():
        value = dict1[key]
        tmp = [value]
        dict1[key] = tmp


def merge_values_in_dict(main_dict, merge_dict, filename):
    #
    # add hypercall params above 0x1000 to dictionary
    # add duplicated key and values in dictionary
    # key (hvcall_id) and value (hvcall_name) must be presented always
    #

    #
    # we need compare new value with values in list corresponding with hvcall and decide: add or not to add to value
    # list
    #

    filename = "_" + filename

    main_dict_keys = list(main_dict.keys())
    main_dict_values = list(main_dict.values())
    count = 0

    for key, value in merge_dict.items():

        res_list = value[0] + filename  # [value[0], filename]
        b_action = False

        short_key = key & 0xFFF

        #
        # If hvcall_id is same ad main_dict we need add value, if it new or not add value if it same as old
        # We add values, if it new, or not add if it not new.
        #

        if (short_key in main_dict_keys) and (key > 0x1000):
            main_dict[key].append(["hvcall param is duplicated:" + hex(short_key) + " " + value[0] + filename])

        if key in main_dict_keys:
            if value in main_dict_values:
                # nothing to do
                b_action = True
            else:
                if len(value) > 1:
                    print("Warning. element len is more then 1")

                main_dict[key].append(res_list)
                b_action = True

        if b_action:
            continue

        main_dict[key] = [res_list]

    print("count of duplicated hypercalls (with parameters): ", count)

    return


def merge_dicts(*dict_args):
    result = {}
    for dictionary in dict_args:
        if dictionary == {}:
            continue
        else:
            result.update(dictionary)

    return result


def merge_hv_call_files(hvcalls_dir, save_duplicates):
    if not os.path.exists(hvcalls_dir):
        print("directory " + hvcalls_dir + " doesn't exist")
        return

    d_hvcalls = {}

    files = os.listdir(hvcalls_dir)

    count = 0

    for f in files:
        fn = hvcalls_dir + f
        if os.path.isdir(fn):
            continue

        file_dict = load_dict_from_file(fn)

        if file_dict == {}:
            print("empty dictionary in", fn)
            continue

        print("processing " + f + "... hvcall count:" + str(len(file_dict.keys())))

        if save_duplicates:
            convert_dic_values_to_list(file_dict)
            file_dict = str_key_to_int(file_dict)
            d_hvcalls = str_key_to_int(d_hvcalls)
            merge_values_in_dict(d_hvcalls, file_dict, f)
        else:
            result = merge_dicts(d_hvcalls, file_dict)
            d_hvcalls = result
            find_duplicates_in_dicts(d_hvcalls, file_dict)

        count = count + 1

    return d_hvcalls


def print_hvcall(d_hvcalls, is_str, caption):

    if (d_hvcalls == {}) or (d_hvcalls is None):
        print("hvcalls_" + caption + " is empty")
        return

    if is_str:
        for item in d_hvcalls.items():
            str_print = str(item[0]) + ": " + str(item[1])
            print(str_print)
    else:
        for item in sorted(d_hvcalls.items()):
            str_print = hex(int(item[0])) + ": " + item[1]
            print(str_print)

    print("hvcalls_" + caption + " table element's count:", len(d_hvcalls))


#
# parsing known hvcalls
#

def parsing_hv_json_files():

    #
    #   Parsing results with duplicates inn separate file
    #

    hvcall_dict_double = merge_hv_call_files(hvcall_dir_saving, True)
    save_dict_to_file(hvcall_dir_result + "hvcalls_results_with_duplicates.json", str_key_to_int_with_sorting(hvcall_dict_double))

    #
    # Parsing results to final files
    #

    hvcall_dict_good = merge_hv_call_files(hvcall_dir_saving, False)
    hvcall_int_good_tmp = str_key_to_int(hvcall_dict_good)
    hvcall_int_good = remove_param_values_from_hvcall(hvcall_int_good_tmp)
    correct_found_hypercalls(hvcall_int_good)

    print_hvcall(hvcall_int_good, False, "known")
    save_dict_to_file(hvcall_dir_result + "hvcalls_results.json", str_key_to_int_with_sorting(hvcall_int_good))

    #
    # parsing unknown hvcalls
    #

    hvcall_dict_unknown = merge_hv_call_files(hvcall_dir_saving_unknown, False)
    print_hvcall(hvcall_dict_unknown, True, "unknown")
    if hvcall_dict_unknown:
        save_dict_to_file(hvcall_dir_result + "hvcalls_unknown.json", hvcall_dict_unknown)


parsing_hv_json_files()