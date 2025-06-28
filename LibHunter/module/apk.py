# 构建apk对象
import datetime
import hashlib
import os

from androguard.core.analysis.analysis import Analysis, DVMBasicBlock, MethodAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat, EncodedMethod
from util import valid_method_name, toMillisecond

filter_record_limit = 10
abstract_method_weight = 3 

class Apk(object):

    def __init__(self, apk_path, logger):
        self.LOGGER = logger
        self.apk_name = None  

        self.classes_dict = dict()  # Record all the class information in the apk
        self.app_filter = dict()
        self.android_jars = self.read_android_jars()
        self.condition_jump_ins = [
            'if-eq',  # == Jump if equal to a specific value
            'if-ne',  # != Jump if not equal to a specific value
            'if-lt',  # < Jump if less than a specific value
            'if-ge',  # >= Jump if greater than or equal to a specific value
            'if-gt',  # > Jump if greater than a specific value
            'if-le',  # <= Jump if less than or equal to a specific value
            'if-eqz',  # ==0 Jump if equal to zero
            'if-nez',  # !=0 Jump if not equal to zero
            'if-ltz',  # <0 Jump if less than zero
            'if-gez',  # >=0 Jump if greater than or equal to zero
            'if-gtz',  # >0 Jump if greater than zero
            'if-lez'  # <=0 Jump if less than or equal to zero
        ]
        self.half_condition_jump_ins = [
            'if-eq',  # == Jump if equal to a specific value
            'if-lt',  # < Jump if less than a specific value
            'if-le',  # <= Jump if less than or equal to a specific value
            'if-eqz',  # ==0 Jump if equal to zero
            'if-ltz',  # <0 Jump if less than zero
            'if-lez'  # <=0 Jump if less than or equal to zero
        ]

        # Parses the dex file corresponding to the lib when initializing the ThirdLib object.
        self.LOGGER.debug("Starting to parse %s ..." , os.path.basename(apk_path))
        self._parse_apk(apk_path)
        self.LOGGER.debug("%s parsing complete", os.path.basename(apk_path))

    def read_android_jars(self):
        clz = []
        with open(r'libs/androidJar.txt') as f:
            for line in f.readlines():
                clz.append(line.strip())
        return clz

    def _parse_apk(self, apk_path):
        self.apk_name = os.path.basename(apk_path)
        time_start = datetime.datetime.now()
        try:
            apk_obj = APK(apk_path)
        except Exception as e:
            print(e)
            return
        time_end = datetime.datetime.now()
        self.LOGGER.debug("apk decompilation complete, time: %d ms", toMillisecond(time_start, time_end))

        time_start = datetime.datetime.now()
        for dex in apk_obj.get_all_dex():
            try:
                dex_obj = DalvikVMFormat(dex)
                analysis_obj = Analysis(dex_obj)
            except Exception:
                return

            for cls in dex_obj.get_classes():
                class_name = cls.get_name().replace("/", ".")[1:-1]
                class_name_short = class_name[class_name.rfind(".") + 1:]
                if class_name_short.startswith("R$"):  
                    continue

                class_info_list = []
                method_num = 0  
                class_opcode_num = 0  
                class_filter = {}  
                class_method_md5_list = []
                class_method_info_dict = {}
                class_method_sigs = []
                class_field_sigs = []
                class_desc = ''

                super_class_name = cls.get_superclassname()
                if super_class_name.startswith("Ljava/"):
                    class_desc += super_class_name
                elif super_class_name in self.android_jars:
                    class_desc += super_class_name
                elif super_class_name != "":
                    class_desc += "Other"

                interface_class_names = cls.get_interfaces()
                for interface_class_name in interface_class_names:
                    if interface_class_name.startswith("Ljava/"):
                        class_desc += interface_class_name
                    elif interface_class_name in self.android_jars:
                        class_desc += interface_class_name
                    else:
                        class_desc += "Other"

                class_access_flags = cls.get_access_flags_string()

                # print(class_access_flags)
                # if class_access_flags == "0x0" or class_access_flags.find("public") != -1:
                #     class_desc += "public "
                # if class_access_flags.find("static") != -1:
                #     class_desc += "static "
                # if class_access_flags.find("final") != -1:
                #     class_desc += "final "
                # if class_access_flags.find("private") != -1:
                #     class_desc += "private "

                JAVA_BASIC_TYPR_DICT = {"B": 4, "S": 5, "I": 6, "J": 7, "F": 8, "D": 9, "Z": 10, "C": 11}
                JAVA_BASIC_TYPR_ARR_DICT = {"[B": 13, "[S": 14, "[I": 15, "[J": 16, "[F": 17, "[D": 18, "[Z": 19,
                                            "[C": 20}
                RETURN_JAVA_BASIC_TYPR_DICT = {"B": 4, "S": 5, "I": 6, "J": 7, "F": 8, "D": 9, "Z": 10, "C": 11,
                                               "V": 12}
                if len(cls.get_fields()) == 0:  
                    class_filter[7] = 1
                else:
                    for EncodedField_obj in cls.get_fields():

                        field_access_flag = EncodedField_obj.get_access_flags_string()
                        if 'synthetic' in field_access_flag:
                            continue
                        field_des = EncodedField_obj.get_descriptor()
                        my_field_des = ''

                        if field_access_flag.find("static") != -1:
                            my_field_des += "static "

                        if field_des.startswith("Ljava/"):
                            my_field_des += field_des[0:field_des.rfind("/")]
                        elif field_des in self.android_jars:
                            my_field_des += field_des[0:field_des.rfind("/")]
                        elif field_des in JAVA_BASIC_TYPR_DICT:
                            my_field_des += field_des
                        elif field_des.startswith("[Ljava/"):
                            my_field_des += "[Ljava/"
                        elif field_des in JAVA_BASIC_TYPR_ARR_DICT:
                            my_field_des += field_des
                        elif field_des.startswith("["):
                            my_field_des += "Array"
                        else:
                            my_field_des += "Other"

                        class_field_sigs.append(my_field_des)

                for method in cls.get_methods():

                    if method.full_name.find("<init>") != -1 or method.full_name.find("<clinit>") != -1:
                        continue
                    
                    # 忽略编译器隐式生成的函数
                    method_name_only = method.get_name()
                    if (method_name_only.startswith("access$") or  # 内部类访问方法
                        method_name_only.startswith("$") or        # Lambda表达式生成的方法
                        method_name_only.find("$") != -1 and method_name_only.find("lambda$") != -1 or  # Lambda方法
                        method_name_only.startswith("valueOf") and "enum" in cls.get_access_flags_string() or  # 枚举valueOf方法
                        method_name_only == "values" and "enum" in cls.get_access_flags_string() or  # 枚举values方法
                        method_name_only.find("$switch$") != -1 or  # switch语句优化生成的方法
                        method_name_only.startswith("bridge$") or   # 桥接方法
                        method_name_only.find("$serialVersionUID") != -1):  # 序列化相关
                        continue

                    method_descriptor = ""

                    # Each method sets two integer values m, n, which are used to calculate the subscripts of the current combination of method parameters and return value features in the Bloom filter
                    method_info = method.get_descriptor()
                    method_return_value = method_info[method_info.rfind(")") + 1:]

                    if method_return_value.startswith("Ljava/lang/Object"):
                        method_descriptor += "Ljava/lang/Object/"
                    elif method_return_value.startswith("Ljava/lang/String"):
                        method_descriptor += "Ljava/lang/String/"
                    elif method_return_value.startswith("Ljava/"):
                        # method_descriptor += method_return_value[0:method_return_value.rfind("/")]
                        method_descriptor += "Ljava/"
                    elif method_return_value in self.android_jars:
                        method_descriptor += method_return_value[0:method_return_value.rfind("/")]
                    elif method_return_value in RETURN_JAVA_BASIC_TYPR_DICT:
                        method_descriptor += method_return_value
                    elif method_return_value.startswith("[Ljava/"):
                        method_descriptor += "[Ljava/"
                    elif method_return_value in JAVA_BASIC_TYPR_ARR_DICT:
                        m = JAVA_BASIC_TYPR_ARR_DICT[method_return_value] + 1
                        method_descriptor += method_return_value
                    elif method_return_value.startswith("["):
                        method_descriptor += "Array"
                    else:
                        method_descriptor += "X"
                    method_descriptor = "{" + method_descriptor + "}"
                    method_access_flags = method.get_access_flags_string()

                    if method_access_flags.find("synchronized") != -1:
                        method_descriptor = "{synchronized}" + method_descriptor

                    if method.full_name.find("<init>") != -1:
                        method_descriptor = "{<init>}" + method_descriptor

                    # Record method parameter types
                    method_param_info = method_info[method_info.find("(") + 1:method_info.find(")")]
                    param_split = method_param_info.split(" ")
                    # Information on each parameter of the statistical method
                    if method_param_info != "":
                        method_param_des = []
                        for parm in param_split:
                            if parm.startswith("Ljava/"):
                                method_param_des.append("{Ljava/}")
                            elif parm in self.android_jars:
                                method_param_des.append("{" + parm + "}")
                            elif parm in ["B", "S", "I", "J", "F", "D", "Z", "C"]:
                                method_param_des.append('{' + parm + "}")
                            elif parm.startswith("["):
                                method_param_des.append("{Array}")
                            else:
                                method_param_des.append("{X}")
                        # Writes the method parameter information into the method's descriptor, sorted by dictionary
                        for parm in method_param_des:
                            method_descriptor = method_descriptor + parm


                    class_method_sigs.append(method_descriptor)

                    method_name = valid_method_name(method.full_name)

                    method_info_list = []

                    if method.full_name.startswith("Ljava"):
                        continue

                    method_opcodes, method_strings = self.my_get_method_opcodes(analysis_obj, method, method_name)

                    if len(method_opcodes) == 0 or len(method_opcodes) > 3000:
                        continue

                    method_num += 1
                    method_opcode_num = len(method_opcodes)
                    class_opcode_num += method_opcode_num

                    methodmd5 = hashlib.md5()
                    methodmd5.update(' '.join(map(str, method_opcodes)).encode("utf-8"))
                    method_md5_value = methodmd5.hexdigest()

                    class_method_md5_list.append(method_md5_value)

                    method_info_list.append(method_md5_value)
                    method_info_list.append(method_opcodes)
                    method_info_list.append(method_strings)
                    method_info_list.append(method_opcode_num)
                    method_info_list.append(method_descriptor)

                    # Avoid the effects of method overloading in a class, so for overloaded methods, you must ensure that the method names are different
                    class_method_info_dict[method_name] = method_info_list

                if (class_access_flags.find("interface") != -1 or class_access_flags.find("abstract") != -1):
                    class_info_list.append(class_method_sigs)
                    class_info_list.append(class_desc)
                    self.classes_dict[cls.get_name().replace("/", ".")[1:-1]] = class_info_list
                    continue

                if len(class_method_info_dict) == 0:
                    continue

                class_method_md5_list.sort()
                class_md5 = ""
                for method_md5 in class_method_md5_list:
                    class_md5 += method_md5

                classmd5 = hashlib.md5()
                classmd5.update(class_md5.encode("utf-8"))
                class_md5_value = classmd5.hexdigest()

                class_info_list.append(class_md5_value)
                class_info_list.append(method_num)

                class_info_list.append(class_opcode_num)
                class_info_list.append(class_method_info_dict)
                # class_info_list.append(Counter(class_field_sigs))
                class_info_list.append(class_method_sigs)
                class_info_list.append(class_field_sigs)
                class_info_list.append(class_desc)

                self.classes_dict[cls.get_name().replace("/", ".")[1:-1]] = class_info_list

                # if 'retrofit2' in class_name:
                #     retrofit += class_opcode_num
                #     print(class_name, class_opcode_num, retrofit)
            # print(f"retrofit2 {self.apk_name}", retrofit)

        time_end = datetime.datetime.now()
        self.LOGGER.debug("Parsing apk completed, time: %d ms", toMillisecond(time_start, time_end))

    def my_get_method_opcodes(self, analysis_obj: Analysis, method: EncodedMethod, method_name: str):
        strings = []
        instructions = []
        # cur_instructions = []
        num = 1

        queue = []

        visited = set()
        try:
            mx: MethodAnalysis = analysis_obj.get_method(method)
            if len(mx.basic_blocks.bb) > 0:
                first_block: DVMBasicBlock = mx.basic_blocks.get_basic_block_pos(0)
                queue.append(first_block)  
                if len(mx.exceptions.gets()) > 0:
                    for exception in mx.exceptions.gets():
                        for exc in exception.exceptions:
                            queue.append(exc[2])
            else:
                return instructions, strings
        except Exception as e:
            print("method: ", method)
            print(e)
            return instructions, strings

        while queue:
            block = queue.pop(0) 
            if block in visited:
                continue
            visited.add(block)

            for ins in block.get_instructions():
                name = ins.get_name()
                instructions.append(ins.get_op_value())
                # cur_instructions.append(ins.get_op_value())
                # if name.startswith("invoke"):
                    # line = ins.get_output()
                    # invoke_info = line[line.find("L"):]
                    # method_info = invoke_info.replace("->", " ").replace("(", " (")
                    #
                    # if method_info.startswith("Ljava"):
                    #     continue

                    # node_info = [cur_instructions[:-1]]
                    # invoke_method_valid_name = valid_method_name(method_info)  
                    # node_info.append(invoke_method_valid_name)
                    # self.nodes_dict[method_name + "_" + str(num)] = node_info
                    # num += 1
                    # cur_instructions = []
                if name == "const-string":
                    raw_string = ins.get_raw_string()
                    if raw_string != "":
                        strings.append(raw_string)

            # Determine the block to traverse based on the conditional branch
            last_ins = list(block.get_instructions())[-1]
            if last_ins.get_name() in self.condition_jump_ins: 
                blocks = block.get_next()
                false_target = block.get_end()
                true_branch = None
                false_branch = None
                if false_target == blocks[0][2].get_start():
                    true_branch = blocks[1][2]
                    false_branch = blocks[0][2]
                elif false_target == blocks[1][2].get_start():
                    true_branch = blocks[0][2]
                    false_branch = blocks[1][2]
                else:
                    Exception("Invalid jump target offset")

                if last_ins.get_name() in self.half_condition_jump_ins:
                    queue.append(true_branch)
                    queue.append(false_branch)
                else:
                    queue.append(false_branch)
                    queue.append(true_branch)

            else:
                for child in block.get_next():
                    queue.append(child[2])

        # node_info = [cur_instructions[:-1], []]
        # self.nodes_dict[method_name + "_" + str(num)] = node_info
        return instructions, strings

    # Add the specified element to the class filter
    def _add_class_filter(self, class_filter, index):
        index_num = class_filter.get(index, 0)
        count = int(index_num) + 1
        if count > filter_record_limit:
            count = filter_record_limit
        class_filter[index] = count

    # Add the class name from the app to the collection in the appropriate place in the Bloom filter.
    def _add_filter(self, class_name, index, num):
        contain_list = self.app_filter.get(index, [set() for i in range(filter_record_limit)])
        set_index = int(num) - 1
        if set_index > filter_record_limit:
            set_index = filter_record_limit
        class_set = contain_list.pop(set_index)
        class_set.add(class_name)
        contain_list.insert(set_index, class_set)
        self.app_filter[index] = contain_list
