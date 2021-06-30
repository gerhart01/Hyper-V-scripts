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


def find_duplicates_in_dicts(dict1, dict2):
    rev_dict = {}

    dict1_list = list(dict1.keys())
    dict2_list = list(dict2.keys())

    for key in dict1_list:
        if key in dict2_list:
            print("duplicate in keys found:", key, dict1[key])

    dict1_values = list(dict1.values())
    dict2_values = list(dict2.values())

    for value in dict1_values:
        if value in dict2_values:
            key = list(dict1.keys())[list(dict1.values()).index(value)]
            print("duplicate in value found:" + value + "(hvcall_id=" + key + ")")


def remove_param_values_from_hvcall(hvcall_orig):
    #
    # remove all params above 0x1000 for exporting
    #

    hvcall_fixed = {}

    dict1_list = list(hvcall_orig.keys())

    for key in dict1_list:
        short_key = key & 0xFFF
        hvcall_fixed[short_key] = hvcall_orig[key]

    return hvcall_fixed


def merge_dicts(*dict_args):
    # https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression-taking-union-of-dictiona
    """
    Given any number of dictionaries, shallow copy and merge into a new dict,
    precedence goes to key-value pairs in latter dictionaries.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


def merge_hv_call_files(hvcalls_dir):
    if not os.path.exists(hvcalls_dir):
        print("directory " + hvcalls_dir + " doesn't exist")
        return

    hvcall_dict = {}

    files = os.listdir(hvcalls_dir)

    count = 0

    for f in files:

        if os.path.isdir(hvcalls_dir + f):
            continue

        file_dict = load_dict_from_file(hvcalls_dir + f)

        if file_dict == {}:
            print("empty dictionary in", hvcalls_dir + f)

        print("processing " + f + "... hvcall count:" + str(len(file_dict.keys())))
        # file_dict = str_key_to_int(file_dict_str)
        result = merge_dicts(hvcall_dict, file_dict)
        hvcall_dict = result

        if count > 1:
            find_duplicates_in_dicts(hvcall_dict, file_dict)

        count = count + 1

        # result = diff(file_dict, hvcall_dict)
        # print(list(result))

        # hvcall_dict = merge_dict2(file_dict, hvcall_dict)

    return hvcall_dict


def print_hvcall(hvcalls, is_str, caption):

    if (hvcalls == {}) or (hvcalls == None):
        print("hvcalls_"+caption+" is empty")
        return

    if is_str:
        for item in hvcalls.items():
            str_print = str(item[0]) + ": " + str(item[1])
            print(str_print)
    else:
        for item in sorted(hvcalls.items()):
            str_print = hex(int(item[0])) + ": " + item[1]
            print(str_print)

    print("hvcalls_" + caption + " table element's count:", len(hvcalls))


hvcall_dict_good = merge_hv_call_files(hvcall_dir_saving)
hvcall_dict_unknown = merge_hv_call_files(hvcall_dir_saving_unknown)

hvcall_int_good = str_key_to_int(hvcall_dict_good)
# hvcall_int_unknown = str_key_to_int(hvcall_dict_unknown)

print_hvcall(hvcall_int_good, False, "known")
print_hvcall(hvcall_dict_unknown, True, "unknown")

save_dict_to_file(hvcall_dir_result + "hvcalls_results.json", str_key_to_int_with_sorting(hvcall_int_good))
save_dict_to_file(hvcall_dir_result + "hvcalls_unknown.json",  hvcall_dict_unknown)