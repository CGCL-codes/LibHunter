# 执行分析的核心过程
import datetime
import logging
import multiprocessing
import os
import pickle
import random
import re
import sys
import time
import traceback
from collections import Counter
from functools import partial
from multiprocessing import Pool, Manager, Process

import Levenshtein
import networkx as nx
from tqdm import tqdm

from apk import Apk
from config import (class_similar, lib_similar, max_thread_num, method_similar, pickle_dir,
                    listener_process, worker_init, setup_logger)
from lib import ThirdLib
from util import split_list_n_list
abstract_method_weight =3


# Get each opcode and its corresponding number (from 1 to 232).
def get_opcode_coding(path):
    opcode_dict = {}
    with open(path, "r", encoding="utf-8") as file:
        for line in file.readlines():
            line = line.strip("\n")
            if line != "":
                opcode = line[:line.find(":")]
                num = line[line.find(":") + 1:]
                opcode_dict[opcode] = num

    return opcode_dict


# Implement the library mapping file to which the subprocess build method belongs
def sub_method_map_decompile(lib_folder,
                             libs,
                             global_lib_info_dict):
    logger = setup_logger()
    if not os.path.exists(pickle_dir):
        os.mkdir(pickle_dir)

    for lib in libs:
        lib_pickle_path = os.path.join(pickle_dir, lib).replace(".dex", ".pkl")
        try:
            if os.path.exists(lib_pickle_path):
                with open(lib_pickle_path, 'rb') as file:
                    lib_obj = pickle.load(file)
            else:
                lib_obj = ThirdLib(lib_folder + "/" + lib, logger)
                pickle.dump(lib_obj, open(lib_pickle_path, 'wb'))
        except Exception as e:
            traceback_str = traceback.format_exc()  # Get stack frame string
            logger.error("Error in sub_method_map_decompile: %s\n%s", e, traceback_str)
            continue

        # Record library decompilation information object
        global_lib_info_dict[lib] = lib_obj


# 实现子进程提前反编译所有单个库
def sub_decompile_lib(lib_folder,
                      libs,
                      global_lib_info_dict):
    logger = setup_logger()
    for lib in libs:
        if lib not in global_lib_info_dict:
            lib_obj = ThirdLib(lib_folder + "/" + lib, logger)
        else:
            lib_obj = global_lib_info_dict[lib]

        global_lib_info_dict[lib] = lib_obj


# Filter the current app class through the Bloom filter and return a collection of classes that satisfy the filter criteria
def deal_bloom_filter(lib_class_name, lib_classes_dict, app_filter):
    if len(lib_classes_dict[lib_class_name]) == 2:  # Indicates that it is currently an interface or abstract classc
        lib_class_bloom_info = lib_classes_dict[lib_class_name][1]
    else:
        lib_class_bloom_info = lib_classes_dict[lib_class_name][3]

    satisfy_classes = set()
    satisfy_count = 0

    for index in lib_class_bloom_info:

        if index not in app_filter:  # Indicates that no class with this feature exists in the current app
            return set()

        # Get the set of all classes in the app that satisfy this condition
        count = lib_class_bloom_info[index]
        if satisfy_count == 0:
            satisfy_classes = app_filter[index][count - 1]
            satisfy_count += 1
        else:
            satisfy_classes = satisfy_classes & app_filter[index][count - 1]

    return satisfy_classes


def _match_counter(count_a: Counter, count_b: Counter):
    # Check if for every element in count_a,
    # the count is less than or equal to its count in count_b
    for element in count_a:
        if count_a[element] > count_b.get(element, 0):
            return False
    return True


def is_match(pattern, string):
    return bool(pattern.match(string))


def match_with_regex_new(strings, patterns):
    n = len(patterns)
    m = len(strings)

    adj_matrix = [[is_match(pattern, string) for string in strings] for pattern in patterns]

    matching = [-1] * m

    def dfs(u, visited):
        for v in range(m):
            if adj_matrix[u][v] and not visited[v]:
                visited[v] = True
                if matching[v] == -1 or dfs(matching[v], visited):
                    matching[v] = u
                    return True
        return False

    for u in range(n):
        visited = [False] * m
        dfs(u, visited)

    return all(match != -1 for match in matching)


def match_with_regex(lst1, patterns):
    """
    Check if elements of lst1 match at least one regex from lst2.
    """
    # used = [False] * len(patterns)
    for item1 in lst1:
        found = False
        for i, pattern in enumerate(patterns):
            if pattern.match(item1):
                # used[i] = True
                found = True
                break
        if not found:
            return False
    return True


def match_fields(lst1: list, lst2: list):
    """
    Check if all fields in the first list match at least one regex from the second list.
    """
    # 计算两个列表中每个元素的出现次数
    counts1 = Counter(lst1)
    counts2 = Counter(lst2)

    # 遍历 lst1 中每个元素的计数
    for item, count_in_lst1 in counts1.items():
        # 检查 lst2 中该元素的计数是否小于 lst1 中该元素的计数
        if counts2[item] < count_in_lst1:
            return False  # 如果 lst2 中某个元素的数量不足，则不包含
    return True  # 如果所有元素在 lst2 中的数量都足够，则包含


def _match_fuzzy_signature_interface(lib_class_dict, apk_classes_dict):
    satisfy_classes = set()

    lib_method_patterns = lib_class_dict[0]
    lib_class_desc_pattern = lib_class_dict[1]
    for apk_class_name in apk_classes_dict:
        apk_class_dict = apk_classes_dict[apk_class_name]
        if len(apk_class_dict) != 2:
            continue
        # apk_field_counter: Counter = apk_class_dict[4]
        apk_method_sigs = apk_class_dict[0]
        apk_class_desc = apk_class_dict[1]
        if not lib_class_desc_pattern.match(apk_class_desc):
            continue
        # the methods in apk should contain all the methods in lib
        if match_with_regex(apk_method_sigs, lib_method_patterns):
            # and _match_counter(apk_field_counter, lib_field_counter)):
            satisfy_classes.add(apk_class_name)
        else:
            pass

    return satisfy_classes


def _match_fuzzy_signature(lib_class_dict, apk_classes_dict):
    satisfy_classes = set()

    # lib_field_counter: Counter = lib_class_dict[5]
    lib_method_patterns = lib_class_dict[5]
    lib_field_patterns = lib_class_dict[6]
    lib_class_desc_pattern = lib_class_dict[7]
    for apk_class_name in apk_classes_dict:
        apk_class_dict = apk_classes_dict[apk_class_name]
        if len(apk_class_dict) == 2:
            continue
        # apk_field_counter: Counter = apk_class_dict[4]
        apk_method_sigs = apk_class_dict[4]
        apk_field_sigs = apk_class_dict[5]
        apk_class_desc = apk_class_dict[6]
        if not lib_class_desc_pattern.match(apk_class_desc):
            continue
        # the methods in apk should contain all the methods in lib
        if match_with_regex(apk_method_sigs, lib_method_patterns) and \
                match_fields(apk_field_sigs, lib_field_patterns):
            # and _match_counter(apk_field_counter, lib_field_counter)):
            satisfy_classes.add(apk_class_name)
        else:
            pass

    return satisfy_classes


# Processing to get the filter result set of each class in all classes of the apk, record it in the filter_result dictionary, and statistically filter the effect of the information
def pre_match(apk_obj, lib_obj, LOGGER):
    lib_classes_dict = lib_obj.classes_dict
    apk_classes_dict = apk_obj.classes_dict
    app_filter = apk_obj.app_filter
    LOGGER.debug("app_filter: %s", app_filter)

    filter_result = {}
    for lib_class_name in lib_classes_dict:

        if len(lib_classes_dict[lib_class_name]) == 2:
            satisfy_classes = _match_fuzzy_signature_interface(lib_classes_dict[lib_class_name], apk_classes_dict)
        else:
            satisfy_classes = _match_fuzzy_signature(lib_classes_dict[lib_class_name], apk_classes_dict)

        if len(satisfy_classes) > 0:
            filter_result[lib_class_name] = satisfy_classes

    return filter_result


# The use of inclusion to determine matches is to resist control flow randomization, insertion of invalid code, randomization of partial code positions, etc.
def match(apk_method_opcode_list, lib_method_opcode_list, opcode_dict):
    method_bloom_filter = {}
    for opcode in apk_method_opcode_list:
        method_bloom_filter[opcode_dict[opcode]] = 1

    # Then take the apk class and match it in the filter
    for opcode in lib_method_opcode_list:
        if opcode != "" and opcode_dict[opcode] not in method_bloom_filter:
            return False

    return True


def edit_distance_similarity(list1, list2):
    return 1 - Levenshtein.distance(list1, list2) / max(len(list1), len(list2))


def list_intersection(list1, list2):
    intersection = []
    temp_list2 = list2.copy()
    for item in list1:
        if item in temp_list2:
            intersection.append(item)
            temp_list2.remove(item)
    return intersection


def list_union(list1, list2):
    union = list1.copy()
    temp_list2 = list2.copy()
    for item in list1:
        if item in temp_list2:
            temp_list2.remove(item)
    union.extend(temp_list2)
    return union


def jaccard_similarity(list1 :list, list2:list):
    set1 = set(list1)
    set2 = set(list2)
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    if len(union) == 0:
        return 1.0  # The empty set of identical sets returns a similarity of 1.
    similarity = len(intersection) / len(union)
    return similarity

def jaccard_similarity2(list1: list, list2: list):
    # Handle the special case where both lists are empty
    if not list1 and not list2:
        return 1.0

    # Count element occurrences in each list
    counter1 = Counter(list1)
    counter2 = Counter(list2)

    intersection_count = 0
    union_count = 0

    # Get all unique elements present in either list
    all_unique_elements = set(counter1.keys()) | set(counter2.keys())

    for element in all_unique_elements:
        count1 = counter1.get(element, 0)
        count2 = counter2.get(element, 0)

        # Intersection: sum of the minimum counts for each common element
        intersection_count += min(count1, count2)

        # Union: sum of the maximum counts for each element
        union_count += max(count1, count2)

    # If the union is empty (which should only happen if both lists were empty,
    # and we've already handled that, but as a safeguard)
    if union_count == 0:
        return 0.0
    else:
        return intersection_count / union_count


def calculate_intersection_ratio(list1: list, list2: list):
    # If list1 is empty, return 1.0 as per your requirement.
    if not list1:
        return 1.0

    # If list2 is empty, there are no elements to repeat, so the proportion is 0.
    if not list2:
        return 0.0

    # Count element occurrences in both lists
    counter1 = Counter(list1)
    counter2 = Counter(list2)

    repeated_count = 0

    # Iterate through elements in list1's counter to find overlaps with list2
    for element, count_in_list1 in counter1.items():
        count_in_list2 = counter2.get(element, 0)

        # The number of times this element from list2 can be "matched" by list1
        # is the minimum of its count in list2 and its count in list1.
        repeated_count += min(count_in_list2, count_in_list1)

    # The proportion is the total number of "repeated" elements divided by the total
    # number of elements in list2.
    return repeated_count / len(list1)


def calculate_intersection_ratio2(list1, list2):
    set1 = set(list1)
    set2 = set(list2)

    # Check if set1 is empty to avoid division by zero errors
    if len(set1) == 0:
        return 1

    intersection = set1.intersection(set2)

    ratio = len(intersection) / len(set1)

    return ratio


# Perform a coarse-grained match between an apk and a lib, get the coarse-grained similarity value, a list of all apk classes that have completed the match
def coarse_match(apk_obj, lib_obj, filter_result, LOGGER):
    # Record the matching relationships of specific methods in each coarse-grained matched class, to be used later at a fine-grained level to determine if these methods are true matches.
    # apk_class_methods_match_dict = {}
    lib_class_match_dict = {}
    lib_match_classes = set()
    abstract_lib_match_classes = set()
    abstract_apk_match_classes = set()

    lib_classes_dict = lib_obj.classes_dict
    apk_classes_dict = apk_obj.classes_dict

    for lib_class in lib_classes_dict:
        qualified_class_name_match = False

        if lib_class not in filter_result:
            continue

        class_match_dict = {}

        filter_set = filter_result[lib_class]

        if len(lib_classes_dict[lib_class]) == 2:
            for apk_class in filter_set:
                if apk_class in abstract_apk_match_classes:
                    continue
                if apk_class not in apk_classes_dict or len(apk_classes_dict[apk_class]) > 2:
                    continue
                apk_method_sigs = apk_classes_dict[apk_class][0]
                lib_method_patterns = lib_classes_dict[lib_class][0]
                apk_class_method_num = len(apk_method_sigs)
                lib_class_method_num = len(lib_method_patterns)

                if apk_class_method_num > 0 and apk_class_method_num == lib_class_method_num and \
                        match_with_regex(apk_method_sigs, lib_method_patterns):
                    LOGGER.debug("match interface %s  ->  %s", lib_class, apk_class)
                    abstract_apk_match_classes.add(apk_class)
                    abstract_lib_match_classes.add(lib_class)
                    break

            continue

        for apk_class in filter_set:
            if apk_class not in apk_classes_dict:
                continue

            if len(apk_classes_dict[apk_class]) == 1:
                continue

            if qualified_class_name_match:
                break

            # use class name to accelerate the match
            if apk_class == lib_class:
                class_match_dict.clear()
                qualified_class_name_match = True


            # Perform one-to-one matching of methods in the class, with the goal of getting all methods in the lib class that complete a one-to-one match (looking for maximum similarity matches each time)
            methods_match_dict = {}  # Used to record the relationship between the class methods in the apk and the corresponding lib class method matches, one-to-one
            methods_tomatch_dict = {}  # Used to record the relationship between class methods in the apk and their corresponding lib class method matches, one-to-many
            apk_class_methods_dict = apk_classes_dict[apk_class][3]
            lib_class_methods_dict = lib_classes_dict[lib_class][4]
            lib_match_methods = []  # Ensures that methods in the lib class are not duplicated and matched.

            # Because of the possibility of apk shrinking, the method will be less, so use the apk's method to match the lib's method.
            for apk_method in apk_class_methods_dict:
                max_method_sim = -1

                for lib_method in lib_class_methods_dict:

                    if lib_method in lib_match_methods:
                        continue

                    # Guaranteed fuzzy signature matching
                    lib_method_info = lib_class_methods_dict[lib_method]
                    apk_method_info = apk_class_methods_dict[apk_method]
                    lib_method_pattern = re.compile(lib_method_info[4])
                    apk_method_sig = apk_method_info[4]
                    if not lib_method_pattern.match(apk_method_sig):
                        second_pattern = lib_method_info[-1]
                        if type(second_pattern) is not re.Pattern:
                            continue
                        else:
                            if not second_pattern.match(apk_method_sig):
                                continue

                    # Try to match the overall MD5 value of the method
                    if apk_method_info[0] == lib_method_info[0]:
                        if apk_method in methods_match_dict:
                            lib_match_methods.remove(methods_match_dict[apk_method])
                        methods_match_dict[apk_method] = lib_method
                        lib_match_methods.append(lib_method)
                        break

                    apk_method_opcodes: list = apk_method_info[1]
                    lib_method_opcodes: list = lib_method_info[1]
                    # sim_op = edit_distance_similarity(apk_method_opcodes, lib_method_opcodes)
                    sim_op = jaccard_similarity2(apk_method_opcodes, lib_method_opcodes)

                    apk_method_strings: list = apk_method_info[2]
                    lib_method_strings: list = lib_method_info[2]
                    sim_str = jaccard_similarity2(apk_method_strings, lib_method_strings)
                    sim = (sim_op + sim_str) / 2

                    # if len(apk_method_opcodes) <= 4:
                    #     continue
                    if sim >= method_similar:
                        # print(f'{apk_method}:{len(apk_method_opcodes)} <--> {lib_method}:{len(lib_method_opcodes)}')
                        # print(f'sim:{sim} mul:{len(apk_method_opcodes)*sim}')
                        # print(f'----------------------------------')
                        if sim > max_method_sim:
                            if apk_method in methods_match_dict:
                                lib_match_methods.remove(methods_match_dict[apk_method])
                            methods_match_dict[apk_method] = lib_method
                            lib_match_methods.append(lib_method)
                            max_method_sim = sim
                        # if(apk_method[:apk_method.rfind(".")]==lib_method[:lib_method.rfind(".")]):
                        #     print(f'{apk_method}<->{lib_method} {sim}')
                    elif apk_method not in methods_match_dict:
                        # the apk should contain tpl methods opcodes
                        overlap_op_sim = calculate_intersection_ratio(lib_method_opcodes, apk_method_opcodes)
                        overlap_str_sim = calculate_intersection_ratio(lib_method_strings, apk_method_strings)
                        overlap_sim = (overlap_op_sim + overlap_str_sim) / 2

                        if overlap_sim >= method_similar:
                            if apk_method not in methods_tomatch_dict:
                                methods_tomatch_dict[apk_method] = []
                            methods_tomatch_dict[apk_method].append(lib_method)


                keys_to_remove = []

                # Iterate through the dictionary and add the keys to be deleted to the list
                for method_tomatch in methods_tomatch_dict:
                    if method_tomatch in methods_match_dict:
                        keys_to_remove.append(method_tomatch)

                # Delete these keys at the end of the traversal
                for key in keys_to_remove:
                    methods_tomatch_dict.pop(key)


            # Determine if the class matches based on the method in the apk class that completes the match
            match_methods_weight = 0
            for apk_method in methods_match_dict.keys():
                match_methods_weight += apk_class_methods_dict[apk_method][3]
            for apk_method in methods_tomatch_dict.keys():
                match_methods_weight += apk_class_methods_dict[apk_method][3]

            class_weight = apk_classes_dict[apk_class][2]
            class_sim = match_methods_weight / class_weight

            # Class coarse-grained matching if the sum of the weights of the matching methods in the apk class / total class weight > threshold
            if class_sim >= class_similar:
                lib_match_classes.add(lib_class)
                class_match_dict[apk_class] = [methods_match_dict, methods_tomatch_dict]

        # Record details of coarse-grained matches of apk classes to all lib classes
        if len(class_match_dict) != 0:
            lib_class_match_dict[lib_class] = class_match_dict

    return lib_match_classes, abstract_lib_match_classes, lib_class_match_dict


def check_method_invoke_times_and_length(method_name, lib_classes_dict):
    class_name = method_name[:method_name.rfind(".")]
    invoke_method_length_limits = [10000, 28, 16, 12, 10]
    # invoke_method_length_limits = [10000, 28, 16, 12, 10 ,10 ,10]
    if class_name not in lib_classes_dict.keys():
        return False
    # This class does not have a method that can be inlined.
    if len(lib_classes_dict[class_name]) < 5:
        return False

    # Handling the case where the method name is not in the dictionary
    if method_name not in lib_classes_dict[class_name][4].keys():
        return False
    # Indicates that the method has not been called
    if len(lib_classes_dict[class_name][4][method_name]) <= 5:
        return False
    invoke_time, invoke_method_length = lib_classes_dict[class_name][4][method_name][5]
    if invoke_time >= 5:
        return False
    else:
        # invoke_method_length = lib_classes_dict[class_name][4][method_name][3]
        return invoke_method_length <= invoke_method_length_limits[invoke_time - 1]


def check_method_access_flags(method_name, lib_classes_dict):
    class_name = method_name[:method_name.rfind(".")]
    if class_name not in lib_classes_dict.keys():
        return False
    if len(lib_classes_dict[class_name]) < 5:
        return False

    if method_name not in lib_classes_dict[class_name][4].keys():
        return False
    if len(lib_classes_dict[class_name][4][method_name]) < 5:
        return False
    # Locked on call, no inlining
    if "synchronized" in lib_classes_dict[class_name][4][method_name][4]:
        return False

    return True


def get_method_action(node, node_dict, method_action_dict, Lib_methods_string: dict, route_method_set, invoke_length,
                      lib_classes_dict, isInlined=False):
    method_name = node[:node.rfind("_")]
    node_num = int(node[node.rfind("_") + 1:])
    cur_action_seq: list = node_dict[node][0]
    callees = []
    # delete move-result in cur_action_seq
    if isInlined and node_num != 1 and len(cur_action_seq) > 0 and 10 <= cur_action_seq[0] <= 12:
        cur_action_seq = cur_action_seq[1:]

    if node.endswith("_1"):  # Indicates that the call entered a new method
        if method_name in method_action_dict:
            return method_action_dict[method_name]
        route_method_set.add(method_name)

    invoke_method_name = node_dict[node][1]
    cur_invoke_len = invoke_length

    doInline = False
    if invoke_method_name != [] and invoke_method_name not in route_method_set and invoke_method_name + "_1" in node_dict \
            and invoke_length <= 20 \
            and check_method_invoke_times_and_length(invoke_method_name, lib_classes_dict) \
            and check_method_access_flags(invoke_method_name, lib_classes_dict):
        callees.append(invoke_method_name)
        doInline = True
        invoke_length += 1
        seq,sub_callees = get_method_action(invoke_method_name + "_1", node_dict, method_action_dict, Lib_methods_string,
                                route_method_set,
                                invoke_length, lib_classes_dict)
        callees.extend(sub_callees)

        # Remove the "invoke-virtual" at the end of cur_action_seq
        cur_action_seq = cur_action_seq[:-1]
        # delete the return statement in callee
        if len(seq) > 0:
            seq_last_opcode: int = seq[-1]
            if 14 <= seq_last_opcode <= 17:
                seq = seq[:-1]

            cur_action_seq = cur_action_seq + seq

    next_node = method_name + "_" + str(node_num + 1)
    if next_node in node_dict:
        seq, sub_callees = get_method_action(next_node, node_dict, method_action_dict, Lib_methods_string, route_method_set,
                                cur_invoke_len,
                                lib_classes_dict, doInline)

        cur_action_seq = cur_action_seq + seq
        callees.extend(sub_callees)
    if doInline:
        Lib_methods_string[method_name] = Lib_methods_string[method_name] + Lib_methods_string[invoke_method_name]
    if node.endswith("_1"):
        # method_action_dict[method_name] = deal_opcode_deq(cur_action_seq)
        method_action_dict[method_name] = (cur_action_seq, callees)
        route_method_set.remove(method_name)

    return cur_action_seq, callees


def get_methods_action(method_list, lib_obj: ThirdLib, Lib_methods_string: dict):
    method_action_dict = {}
    lib_classes_dict = lib_obj.classes_dict
    for method in method_list:
        get_method_action(method + "_1", lib_obj.nodes_dict, method_action_dict, Lib_methods_string, set(), 0,
                          lib_classes_dict)

    return method_action_dict


# Fine-grained matching
def fine_match(apk_obj, lib_obj, lib_class_match_dict, LOGGER):
    apk_classes_dict = apk_obj.classes_dict
    lib_classes_dict = lib_obj.classes_dict
    lib_pre_methods = set()

    apk_methods_action = {}
    apk_methods_string = {}
    lib_mathods_string = {}
    for lib_class in lib_obj.classes_dict:
        if len(lib_classes_dict[lib_class]) == 2:
            continue
        for lib_method in lib_obj.classes_dict[lib_class][4]:
            lib_mathods_string[lib_method] = lib_classes_dict[lib_class][4][lib_method][2]

    for lib_class in lib_class_match_dict:
        for apk_class in lib_class_match_dict[lib_class]:
            # only to match the methods in the pass the overlap filter
            for apk_method in lib_class_match_dict[lib_class][apk_class][1].keys():
                apk_methods_action[apk_method] = apk_classes_dict[apk_class][3][apk_method][1]
                apk_methods_string[apk_method] = apk_classes_dict[apk_class][3][apk_method][2]
            for lib_methods in lib_class_match_dict[lib_class][apk_class][1].values():
                lib_pre_methods.update(set(list(lib_methods)))

    LOGGER.debug("Cross-Inlining...")
    lib_methods_action = get_methods_action(lib_pre_methods, lib_obj, lib_mathods_string)
    tp = fp = tn = fn = 0


    lib_class_match_result = {}
    finish_apk_classes = []
    lib_match_methods_map = {}

    for lib_class in lib_class_match_dict:
        lib_match_methods_map[lib_class] = {}
        max_match_class_opcodes = 0
        match_apk_class = ""
        # Filter one-to-many matches from apk class to lib class to one-to-one matches
        for apk_class in lib_class_match_dict[lib_class]:
            lib_match_methods_map[lib_class][apk_class] = set()

            if apk_class in finish_apk_classes:
                continue

            cur_match_class_opcodes = 0
            for apk_method, lib_method in lib_class_match_dict[lib_class][apk_class][0].items():
                cur_match_class_opcodes += lib_classes_dict[lib_class][4][lib_method][3]


            # For the apk method that tomatches in a coarse-grained match, find the single most matching lib method
            lib_match_methods = []
            for apk_method, lib_methods in lib_class_match_dict[lib_class][apk_class][1].items():
                apk_method_opcodes: list = apk_methods_action[apk_method]
                apk_mathod_strings: list = apk_methods_string[apk_method]
                LOGGER.debug("apk_method: %s", apk_method_opcodes)
                max_method_sim = -1
                max_method_name = None
                match_lib_method = " "
                match_lib_callees = []
                match_lib_method_opcodes = []
                TP = FP = TN = FN = 0
                for lib_method in lib_methods:
                    if lib_method in lib_match_methods:
                        continue
                    lib_method_opcodes, callees = lib_methods_action[lib_method]
                    lib_method_strings: list = lib_mathods_string[lib_method]
                    # lib_method_opcodes = lib_classes_dict[lib_class][4][lib_method][1]
                    # callees = []
                    # lib_method_strings: set = lib_classes_dict[lib_class][4][lib_method][2]
                    LOGGER.debug("lib_method: %s", lib_method_opcodes)
                    # if match(apk_method_opcodes, lib_method_opcodes, opcode_dict):
                    sim_opc = jaccard_similarity(apk_method_opcodes, lib_method_opcodes)
                    sim_str = jaccard_similarity(apk_mathod_strings, lib_method_strings)

                    # if (apk_method == lib_method):
                    #     print(f'{apk_method} {lib_method} {sim}')
                    sim = 0.5 * sim_opc + 0.5 * sim_str
                    if sim >= method_similar and sim > max_method_sim:
                        if match_lib_method == " ":
                            match_lib_method = lib_method
                            match_lib_callees = callees
                            match_lib_method_opcodes = lib_method_opcodes
                            lib_match_methods.append(match_lib_method)
                            max_method_sim = sim
                            max_method_name = lib_method
                        # Indicates that methods with previous matches have been stored in lib_match_methods
                        else:
                            lib_match_methods.remove(match_lib_method)
                            match_lib_method = lib_method
                            lib_match_methods.append(match_lib_method)
                            match_lib_callees = callees
                            max_method_sim = sim
                            max_method_name = lib_method

                if match_lib_method != " ":
                    # if(apk_method==match_lib_method):
                    #     print(f'{apk_method} <---> {match_lib_method} :{max_method_sim}')
                    #     print(f'{apk_method_opcodes}')
                    #     print(f'{match_lib_method_opcodes}')
                    lib_match_methods.append(match_lib_method)
                    lib_match_methods_map[lib_class][apk_class].add(
                        (apk_method, match_lib_method, tuple(match_lib_callees)))
                    cur_match_class_opcodes += lib_classes_dict[lib_class][4][match_lib_method][3]
                    for callee in match_lib_callees:
                        callee_class = callee[:callee.rfind(".")]
                        cur_match_class_opcodes += lib_classes_dict[callee_class][4][callee][3]

            if cur_match_class_opcodes > max_match_class_opcodes:
                max_match_class_opcodes = cur_match_class_opcodes
                match_apk_class = apk_class

        if match_apk_class == "":
            continue

        # if lib_class == match_apk_class:
        #     print(f"TP@ {lib_class} <---> {match_apk_class} :{max_match_class_opcodes}")
        # elif max_match_class_opcodes > 10:
        #     print(f"FP@ {lib_class} <---> {match_apk_class} :{max_match_class_opcodes}")

        match_info = [match_apk_class, max_match_class_opcodes]
        # print(f'{lib_class} <---> {match_apk_class} :{max_match_class_opcodes}')
        # print(lib_match_methods_map[lib_class][match_apk_class])
        lib_class_match_result[lib_class] = match_info
        finish_apk_classes.append(match_apk_class)
    LOGGER.info(f'{lib_obj.lib_name} fp:{fp} fn:{fn} tp:{tp} tn:{tn}')
    return lib_class_match_result


def detect(apk_obj, lib_obj, LOGGER):
    '''
    Detecting library information contained in an apk
    :param apk_obj: build apk object
    :param lib: library name
    :param lib_obj: The library object to build.
    :return: Dictionary to return detection results
    '''
    if len(lib_obj.classes_dict) == 0:
        return {}

    lib_opcode_num = lib_obj.lib_opcode_num
    lib_classes_dict = lib_obj.classes_dict

    result = {}
    avg_filter_rate = 0
    avg_time = 0

    filter_result = pre_match(apk_obj, lib_obj, LOGGER)
    pre_match_opcodes = 0
    for lib_class in filter_result:
        # if lib_class not in filter_result[lib_class] and lib_class in apk_obj.classes_dict:
        #     print("FP lib_class: ", lib_class)
        # elif lib_class in filter_result[lib_class]:
        #     print("TP lib_class: ", lib_class)

        if len(lib_classes_dict[lib_class]) == 2:  # Description is an interface or abstract class
            pre_match_opcodes += (len(lib_classes_dict[lib_class][0]) * abstract_method_weight)
        else:
            pre_match_opcodes += lib_classes_dict[lib_class][2]
        LOGGER.debug("Pre-match lib_class: %s", lib_class)
        for apk_class in filter_result[lib_class]:
            LOGGER.debug("apk_class: %s", apk_class)
        LOGGER.debug("-------------------------------")

    # Determine if the pre-match result does not contain
    pre_match_rate = pre_match_opcodes / lib_opcode_num
    if pre_match_rate < lib_similar:
        LOGGER.debug("Pre-match failed library: %s, pre-match rate is: %f", lib_obj.lib_name, pre_match_rate)
        return {}

    # avg_filter_rate += filter_rate
    # LOGGER.debug("filter_rate: %f", filter_rate)
    # LOGGER.debug("filter_effect: %f", filter_effect)

    # Perform coarse-grained matching
    lib_match_classes, abstract_lib_match_classes, lib_class_match_dict = coarse_match(apk_obj,
                                                                                                       lib_obj,
                                                                                                       filter_result,
                                                                                                       LOGGER)
    for lib_class in lib_class_match_dict:
        if len(lib_class_match_dict[lib_class]) > 1:

            LOGGER.debug("Coarse-grained matching lib_class: %s", lib_class)
            for apk_class in lib_class_match_dict[lib_class]:
                LOGGER.debug("apk_class: %s", apk_class)
                for lib_method in lib_class_match_dict[lib_class][apk_class][0]:
                    LOGGER.debug("apk class function %s → lib class function %s", lib_method,
                                 lib_class_match_dict[lib_class][apk_class][0][lib_method])
        LOGGER.debug("-------------------------------")

    # Calculate the match score of abstract classes or interfaces in the library
    abstract_match_opcodes = 0
    for abstract_class in abstract_lib_match_classes:
        abstract_match_opcodes += (len(lib_classes_dict[abstract_class][0]) * abstract_method_weight)

    # Calculate lib coarse-grained matching score
    lib_coarse_match_opcode_num = 0
    for lib_class in lib_match_classes:
        lib_coarse_match_opcode_num += lib_classes_dict[lib_class][2]
    lib_coarse_match_opcode_num += abstract_match_opcodes

    LOGGER.debug("The coarse-grained unmatched classes in the library are as follows:")
    for lib_class in lib_classes_dict:
        if lib_class not in lib_match_classes and lib_class not in abstract_lib_match_classes:
            # print("FN fine lib_class: ", lib_class)
            LOGGER.debug("lib_class: %s" % lib_class)

    lib_coarse_match_rate = lib_coarse_match_opcode_num / lib_opcode_num
    LOGGER.debug("Number of all opcodes in class matched by lib coarse-graining: %d", lib_coarse_match_opcode_num)
    LOGGER.debug("lib coarse-grained rate: %f", lib_coarse_match_rate)
    LOGGER.debug("Number of matched classes in library: %d", len(lib_match_classes) + len(abstract_lib_match_classes))
    LOGGER.debug("Number of all participating matched classes in the library: %d", len(lib_classes_dict))


    if lib_coarse_match_rate < lib_similar:
        LOGGER.debug("Coarse match failed library: %s, coarse match rate is: %f", lib_obj.lib_name, lib_coarse_match_rate)
        return {}

    # Perform fine-grained matching
    lib_class_match_result = fine_match(apk_obj,
                                        lib_obj,
                                        lib_class_match_dict,
                                        LOGGER)
    for lib_class in lib_class_match_result:
        LOGGER.debug("Fine-grained: library class %s → application class %s", lib_class, lib_class_match_result[lib_class][0])
    LOGGER.debug("The fine-grained unmatched classes in the library are as follows:")
    for lib_class in lib_classes_dict:
        if lib_class not in abstract_lib_match_classes and lib_class not in lib_class_match_result:
            # print("FN fine lib_class: ", lib_class)
            LOGGER.debug("lib_class: %s", lib_class)

    final_match_opcodes = 0
    for lib_class in lib_class_match_result:
        # print("lib_class: ", lib_class, lib_class_match_result[lib_class][0], lib_class_match_result[lib_class][1])
        final_match_opcodes += lib_class_match_result[lib_class][1]
    # print("sum / total num:",final_match_opcodes, lib_opcode_num)
    final_match_opcodes += abstract_match_opcodes

    # Adjust the library similarity threshold according to whether the library to be detected is a pure interface library or not
    min_lib_match = lib_similar
    if lib_obj.interface_lib:
        min_lib_match = 1.0

    temp_list = [final_match_opcodes, lib_opcode_num, final_match_opcodes / lib_opcode_num]
    if final_match_opcodes / lib_opcode_num >= min_lib_match:
        result[lib_obj.lib_name] = temp_list
    return result



# Implementing child process detection
def sub_detect_lib(lib,
                   apk,
                   global_apk_info_dict,
                   global_finished_jar_dict,
                   global_lib_info_dict):
    # Test all versions of the same library and return a dictionary of the results (key is the jar name, value is four values)
    logger = setup_logger()
    start_lib = datetime.datetime.now()
    if lib not in global_lib_info_dict:
        logger.info("Library: %s not parsed successfully in previous step, skipped", lib)
        return
    result = detect(global_apk_info_dict[apk], global_lib_info_dict[lib], logger)
    end_lib = datetime.datetime.now()
    logger.info("Detecting libraries: %s complete, time: %d", lib, (end_lib - start_lib).seconds)

    if len(result) != 0:
        global_finished_jar_dict.update(result)


# Implementing subthreads to determine cyclic dependency libraries based on dependencies
def sub_find_loop_dependence_libs(libs, dependence_relation, loop_dependence_libs, shared_lock_loop_libs):
    DG = nx.DiGraph(list(dependence_relation))
    for lib_name in libs:
        try:
            nx.find_cycle(DG, source=lib_name)
            shared_lock_loop_libs.acquire()
            if lib_name not in loop_dependence_libs:
                loop_dependence_libs.append(lib_name)
            shared_lock_loop_libs.release()
        except Exception:
            pass


def monitor_progress(global_running_jar_list, all_libs_num):
    time_sec = 0
    while True:
        finish_num = all_libs_num - len(global_running_jar_list)
        finish_rate = int(finish_num / all_libs_num * 100)
        print('\r' + "current analysis: " + '▇' * (finish_rate // 2) + f'{finish_rate}%', end='')
        if finish_num >= all_libs_num:
            break
        time.sleep(1)
        time_sec += 1


def init_worker():
    logger = logging.getLogger()
    # Remove all handlers associated with the root logger
    handlers = logger.handlers[:]
    for handler in handlers:
        logger.removeHandler(handler)


def search_libs_in_app(lib_dex_folder=None,
                       apk_folder=None,
                       output_folder='outputs',
                       processes=None):
    to_analysze_apks = os.listdir(apk_folder)
    print("num of apk to analyze: ", len(to_analysze_apks))
    LOGGER = setup_logger()

    thread_num = processes if processes != None else max_thread_num
    LOGGER.info("Analyzing maximum number of cpu used: %d", thread_num)

    LOGGER.debug("Starting to extract all library information...")
    time_start = datetime.datetime.now()
    libs = os.listdir(lib_dex_folder)
    random.shuffle(libs)
    with Manager() as manager:
        log_queue1 = manager.Queue()

        global_lib_info_dict = manager.dict()
        decompile_thread_num = min(thread_num, len(libs))
        sub_lists = split_list_n_list(libs, decompile_thread_num)

        listener1 = Process(target=listener_process, args=(log_queue1,))
        listener1.start()

        with Pool(processes=decompile_thread_num, initializer=worker_init, initargs=(log_queue1,)) as pool:
            tasks_method_maps = [
                pool.apply_async(sub_method_map_decompile,
                                 (lib_dex_folder, sub_libs, global_lib_info_dict))
                for sub_libs in sub_lists
            ]

            for task in tasks_method_maps:
                task.get()

        # Stop the listener
        log_queue1.put(None)
        listener1.join()

        log_queue2 = manager.Queue()
        listener2 = Process(target=listener_process, args=(log_queue2,))
        listener2.start()

        with Pool(processes=decompile_thread_num, initializer=worker_init, initargs=(log_queue2,)) as pool:
            # Part II: Library decompilation to extract information
            tasks_decompile = [
                pool.apply_async(sub_decompile_lib, (
                    lib_dex_folder, sub_libs, global_lib_info_dict))
                for sub_libs in sub_lists
            ]

            # Wait for all library decompilation tasks to complete
            for task in tasks_decompile:
                task.get()

        # Stop the listener
        log_queue2.put(None)
        listener2.join()
        print("All TPL information extracted ...")

        time_end = datetime.datetime.now()
        LOGGER.debug("All libraries extracted, time: %d", (time_end - time_start).seconds)

        # 载入所有dex文件并分配任务
        libs_list = os.listdir(lib_dex_folder)

        finish_apks = []
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        for apk in os.listdir(output_folder):
            finish_apks.append(apk.replace(".txt", ""))

        all_libs_num = len(libs_list)
        LOGGER.info("The number of libraries analyzed this time is: %d", all_libs_num)

        global_apk_info_dict = manager.dict()
        for apk in os.listdir(apk_folder):

            # if apk in finish_apks:
            #     continue

            print("start analyzing: ", apk)
            LOGGER.info("Starting analysis: %s", apk)
            apk_time_start = datetime.datetime.now()

            apk_pickle_path = os.path.join(pickle_dir, apk).replace(".apk", ".pkl")
            try:
                if os.path.exists(apk_pickle_path):
                    with open(apk_pickle_path, 'rb') as file:
                        apk_obj = pickle.load(file)
                else:
                    apk_obj = Apk(apk_folder + "/" + apk, LOGGER)
                    pickle.dump(apk_obj, open(apk_pickle_path, 'wb'))
            except Exception as e:
                LOGGER.error("Error in decompile apk: %s", e)
                continue

            global_apk_info_dict[apk] = apk_obj

            global_finished_jar_dict = manager.dict()

            process_lib_partial = partial(sub_detect_lib, apk=apk, global_apk_info_dict=global_apk_info_dict,
                                          global_finished_jar_dict=global_finished_jar_dict,
                                          global_lib_info_dict=global_lib_info_dict)
            log_queue3 = manager.Queue()
            listener3 = Process(target=listener_process, args=(log_queue3,))
            listener3.start()
            with Pool(processes=thread_num, initializer=worker_init, initargs=(log_queue3,)) as pool:
                list(tqdm(pool.imap(process_lib_partial, libs_list), total=len(libs_list), desc=apk, colour='blue'))
                pool.close()
                pool.join()

            # Stop the listener
            log_queue3.put(None)
            listener3.join()


            LOGGER.info("-------------------------------------------------------------------")
            LOGGER.info("Detailed detection information for all libraries included is as follows:")
            for lib, infos in global_finished_jar_dict.items():
                # print(lib, infos)
                LOGGER.info("%s  :  %f   %f   %f", lib, infos[0],
                            infos[1], infos[2])
            LOGGER.info("-------------------------------------------------------------------")
            # Output apk analysis duration
            apk_time_end = datetime.datetime.now()
            apk_time = (apk_time_end - apk_time_start).seconds
            with open(output_folder + "/" + apk + ".txt", "w", encoding="utf-8") as result:
                for lib in sorted(global_finished_jar_dict.keys()):
                    result.write("lib: " + lib + "\n")
                    result.write("similarity: " + str(global_finished_jar_dict[lib][2]) + "\n\n")
                result.write("time: " + str(apk_time) + "s")

            LOGGER.info("Current apk analysis time: %d (in seconds)", apk_time)
            del global_apk_info_dict[apk]


def sub_detect_apk(apk,
                   lib_obj,
                   apk_folder,
                   global_result_dict):
    apk_obj = Apk(apk_folder + "/" + apk)
    result = detect(apk_obj, lib_obj)

    if len(result) != 0:
        global_result_dict[apk] = str(result[lib_obj.lib_name][2])


def search_lib_in_app(lib_dex_folder=None,
                      apk_folder=None,
                      output_folder='outputs',
                      processes=None):
    LOGGER = setup_logger()
    # Setting the number of cpu's analyzed
    thread_num = processes if processes != None else max_thread_num
    LOGGER.info("Analyzing the number of cpu used: %d", thread_num)

    LOGGER.debug("Starting to extract library information...")
    time_start = datetime.datetime.now()

    lib_path = ""
    for lib in os.listdir(lib_dex_folder):
        lib_path = lib_dex_folder + "/" + lib
    lib_obj = ThirdLib(lib_path)

    time_end = datetime.datetime.now()
    LOGGER.debug("Library extraction complete, time: %d", (time_end - time_start).seconds)

    global_apk_list = multiprocessing.Manager().list()
    for apk in os.listdir(apk_folder):
        global_apk_list.append(apk)
    global_result_dict = multiprocessing.Manager().dict()
    share_lock_apk = multiprocessing.Manager().Lock()
    share_lock_result = multiprocessing.Manager().Lock()

    print("Start detection ...")
    processes_list_detect = []
    for i in range(1, thread_num + 1):
        process_name = str(i)
        thread = multiprocessing.Process(target=sub_detect_apk, args=(process_name,
                                                                      lib_obj,
                                                                      apk_folder,
                                                                      global_apk_list,
                                                                      global_result_dict,
                                                                      share_lock_apk,
                                                                      share_lock_result))
        processes_list_detect.append(thread)

    for thread in processes_list_detect:
        thread.start()

    # The master process periodically detects the number of libraries currently analyzed and displays them in a percentage progress bar
    time_sec = 0
    all_apks_num = len(os.listdir(apk_folder))
    LOGGER.info("The number of apks analyzed this time is: %d", all_apks_num)
    time.sleep(1)
    finish_num = all_apks_num - len(global_apk_list)
    while finish_num < all_apks_num:
        finish_rate = int(finish_num / all_apks_num * 100)
        print('\r' + "current analysis: " + '▇' * (int(finish_rate / 2)) + str(finish_rate) + '%', end='')
        time.sleep(1)
        time_sec += 1
        finish_num = all_apks_num - len(global_apk_list)
    print('\r' + "current analysis: " + '▇' * (int(finish_num / all_apks_num * 100 / 2)) + str(
        int(finish_num / all_apks_num * 100)) + '%', end='')
    print("")

    for thread in processes_list_detect:
        thread.join()

    with open(output_folder + "/results.txt", "w", encoding="utf-8") as result:
        result.write("apk name library name similarity score\n")
        for k in sorted(global_result_dict.keys()):
            result.write(k + "   " + lib_obj.lib_name + "   " + global_result_dict[k] + '\n')

    # Output apk analysis duration
    time_end = datetime.datetime.now()
    LOGGER.info("Detection duration: %d (in seconds)", (time_end - time_start).seconds)
