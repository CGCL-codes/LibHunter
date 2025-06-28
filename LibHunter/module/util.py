import re


def valid_method_name(method_full_name):
    method_full_name = method_full_name.replace(" ", "")
    class_name = method_full_name[1:method_full_name.find(";")].replace("/",
                                                                        ".")  # com.google.android.gms.internal.bn.onPause()V
    other = method_full_name[method_full_name.find(";") + 1:]  #
    return class_name + "." + other


def read_file_to_list(path, mode='r', encoding='utf-8'):
    lines_list = []
    with open(path, mode, encoding=encoding) as file:
        for line in file.readlines():
            lines_list.append(line.strip("\n"))
    return lines_list


def generate_regex(input_string):
    escaped_input = re.escape(input_string)

    regex_pattern = re.sub(r'\\\{.*?\\\}\\#', r'(\\{.*?\\})?', escaped_input)

    regex_pattern = regex_pattern.replace('\\#', '')

    return re.compile(regex_pattern)


def convert_to_optional_regex(input_string):
    matches = re.findall(r'\{.*?\}#?', input_string)

    regex_parts = []
    for match in matches:
        if match.endswith('#'):
            part = re.escape(match[:-1]) + '?'
        else:
            part = re.escape(match)

        regex_parts.append(part)

    final_regex = '^' + ''.join(regex_parts) + '$'
    return re.compile(final_regex)


def split_list_n_list(origin_list, n):
    if len(origin_list) % n == 0:
        cnt = len(origin_list) // n
    else:
        cnt = len(origin_list) // n + 1

    for i in range(0, n):
        yield origin_list[i * cnt:(i + 1) * cnt]


def deal_opcode_deq(opcode_seq):
    new_seq = ""
    for seq in set(opcode_seq.split(" ")):
        new_seq = new_seq + seq + " "
    return new_seq[:-1]


def toMillisecond(start_time, end_time):
    return (end_time - start_time).seconds * 1000 + (end_time - start_time).microseconds / 1000


DexConst4_SIZE = 1
DexMove_SIZE = 1
DexMoveException_SIZE = 1
DexBase1Format_SIZE = 1
DexMonitorExit_SIZE = 1
DexConst16_SIZE = 2
DexConstWide16_SIZE = 2
DexConstString_SIZE = 2
DexConstClass_SIZE = 2
DexMonitorEnter_SIZE = 1
DexCheckCast_SIZE = 2
DexInstanceOf_SIZE = 2
DexArrayLength_SIZE = 1
DexNewInstance_SIZE = 2
DexNewArray_SIZE = 2
DexFilledNewArray_SIZE = 3
DexThrow_SIZE = 1
DexGoto_SIZE = 2
DexBase2Format_SIZE = 2
DexAget_SIZE = 2
DexAput_SIZE = 2
DexNotInt_SIZE = 1
DexNotLong_SIZE = 1
DexBase3Format_SIZE = 3
DexSget_SIZE = 2
DexSput_SIZE = 2
DexInvokeVirtual_SIZE = 3
DexNegInt_SIZE = 1
DexNegLong_SIZE = 1
DexIntToLong_SIZE = 1
DexIntToFloat_SIZE = 1
DexIntToDouble_SIZE = 1
DexLongToInt_SIZE = 1
DexLongToFloat_SIZE = 1

DexLongToDouble_SIZE = 1
DexFloatToInt_SIZE = 1
DexFloatToLong_SIZE = 1
DexFloatToDouble_SIZE = 1
DexDoubleToInt_SIZE = 1
DexDoubleToLong_SIZE = 1
DexDoubleToFloat_SIZE = 1
DexIntToByte_SIZE = 1
DexIntToChar_SIZE = 1
DexIntToShort_SIZE = 1
DexAddInt_SIZE = 1
DexAddLong_SIZE = 1
DexAddFloat_SIZE = 1
DexAddDouble_SIZE = 1
DexAddInt2Addr_SIZE = 1
DexAddLong2Addr_SIZE = 1
DexAddFloat2Addr_SIZE = 1
DexAddDouble2Addr_SIZE = 1
DexExecuteInline_SIZE = 3
DexInvokeDirectEmpty_SIZE = 3
DexIgetQuick_SIZE = 2
DexIgetWideQuick_SIZE = 2
DexIgetObjectQuick_SIZE = 2
DexIputQuick_SIZE = 2
DexIputWideQuick_SIZE = 2
DexIputObjectQuick_SIZE = 2
DexInvokeVirtualQuick_SIZE = 3
DexInvokeVirtualQuick_RANGE_SIZE = 3
DexInvokeSuperQuick_SIZE = 3
DexInvokeSuperQuick_RANGE_SIZE = 3
DexNegDouble_SIZE = 1
DexNegFloat_SIZE = 1


instruction_size_map = {
    'nop': 1,
    'move': DexMove_SIZE,
    'move/from16': DexMove_SIZE,
    'move/16': DexMove_SIZE,
    'move-wide': DexMove_SIZE,
    'move-wide/from16': DexMove_SIZE,
    'move-wide/16': DexMove_SIZE,
    'move-object': DexMove_SIZE,
    'move-object/from16': DexMove_SIZE,
    'move-object/16': DexMove_SIZE,
    'move-result': DexMove_SIZE,
    'move-result-wide': DexMove_SIZE,
    'move-result-object': DexMove_SIZE,
    'move-exception': DexMoveException_SIZE,
    'return-void': DexBase1Format_SIZE,
    'return': DexBase1Format_SIZE,
    'return-wide': DexBase1Format_SIZE,
    'return-object': DexBase1Format_SIZE,
    'const/4': DexConst4_SIZE,
    'const/16': DexConst16_SIZE,
    'const': DexConst16_SIZE,
    'const/high16': DexConst16_SIZE,
    'const-wide/16': DexConstWide16_SIZE,
    'const-wide/32': DexConstWide16_SIZE,
    'const-wide': DexConstWide16_SIZE,
    'const-wide/high16': DexConstWide16_SIZE,
    'const-string': DexConstString_SIZE,
    'const-string/jumbo': DexConstString_SIZE,
    'const-class': DexConstClass_SIZE,
    'monitor-enter': DexMonitorEnter_SIZE,
    'monitor-exit': DexMonitorExit_SIZE,
    'check-cast': DexCheckCast_SIZE,
    'instance-of': DexInstanceOf_SIZE,
    'array-length': DexArrayLength_SIZE,
    'new-instance': DexNewInstance_SIZE,
    'new-array': DexNewArray_SIZE,
    'filled-new-array': DexFilledNewArray_SIZE,
    'filled-new-array/range': DexFilledNewArray_SIZE,
    'throw': DexThrow_SIZE,
    'goto': DexGoto_SIZE,
    'goto/16': DexGoto_SIZE,
    'goto/32': DexGoto_SIZE,
    'packed-switch': DexBase1Format_SIZE,
    'sparse-switch': DexBase1Format_SIZE,
    'cmpl-float': DexBase2Format_SIZE,
    'cmpg-float': DexBase2Format_SIZE,
    'cmpl-double': DexBase2Format_SIZE,
    'cmpg-double': DexBase2Format_SIZE,
    'cmp-long': DexBase2Format_SIZE,
    'if-eq': DexBase2Format_SIZE,
    'if-ne': DexBase2Format_SIZE,
    'if-lt': DexBase2Format_SIZE,
    'if-ge': DexBase2Format_SIZE,
    'if-gt': DexBase2Format_SIZE,
    'if-le': DexBase2Format_SIZE,
    'if-eqz': DexBase1Format_SIZE,
    'if-nez': DexBase1Format_SIZE,
    'if-ltz': DexBase1Format_SIZE,
    'if-gez': DexBase1Format_SIZE,
    'if-gtz': DexBase1Format_SIZE,
    'if-lez': DexBase1Format_SIZE,
    'aget': DexAget_SIZE,
    'aget-wide': DexAget_SIZE,
    'aget-object': DexAget_SIZE,
    'aget-boolean': DexAget_SIZE,
    'aget-byte': DexAget_SIZE,
    'aget-char': DexAget_SIZE,
    'aget-short': DexAget_SIZE,
    'aput': DexAput_SIZE,
    'aput-wide': DexAput_SIZE,
    'aput-object': DexAput_SIZE,
    'aput-boolean': DexAput_SIZE,
    'aput-byte': DexAput_SIZE,
    'aput-char': DexAput_SIZE,
    'aput-short': DexAput_SIZE,
    'iget': DexBase2Format_SIZE,
    'iget-wide': DexBase2Format_SIZE,
    'iget-object': DexBase2Format_SIZE,
    'iget-boolean': DexBase2Format_SIZE,
    'iget-byte': DexBase2Format_SIZE,
    'iget-char': DexBase2Format_SIZE,
    'iget-short': DexBase2Format_SIZE,
    'iput': DexBase2Format_SIZE,
    'iput-wide': DexBase2Format_SIZE,
    'iput-object': DexBase2Format_SIZE,
    'iput-boolean': DexBase2Format_SIZE,
    'iput-byte': DexBase2Format_SIZE,
    'iput-char': DexBase2Format_SIZE,
    'iput-short': DexBase2Format_SIZE,
    'sget': DexSget_SIZE,
    'sget-wide': DexSget_SIZE,
    'sget-object': DexSget_SIZE,
    'sget-boolean': DexSget_SIZE,
    'sget-byte': DexSget_SIZE,
    'sget-char': DexSget_SIZE,
    'sget-short': DexSget_SIZE,
    'sput': DexSput_SIZE,
    'sput-wide': DexSput_SIZE,
    'sput-object': DexSput_SIZE,
    'sput-boolean': DexSput_SIZE,
    'sput-byte': DexSput_SIZE,
    'sput-char': DexSput_SIZE,
    'sput-short': DexSput_SIZE,
    'invoke-virtual': DexInvokeVirtual_SIZE,
    'invoke-super': DexInvokeVirtual_SIZE,
    'invoke-direct': DexInvokeVirtual_SIZE,
    'invoke-static': DexInvokeVirtual_SIZE,
    'invoke-interface': DexInvokeVirtual_SIZE,
    'invoke-virtual/range': DexInvokeVirtual_SIZE,
    'invoke-super/range': DexInvokeVirtual_SIZE,
    'invoke-direct/range': DexInvokeVirtual_SIZE,
    'invoke-static/range': DexInvokeVirtual_SIZE,
    'invoke-interface/range': DexInvokeVirtual_SIZE,
    'neg-int': DexNegInt_SIZE,
    'not-int': DexNegInt_SIZE,
    'neg-long': DexNegLong_SIZE,
    'not-long': DexNegLong_SIZE,
    'neg-float': DexNegFloat_SIZE,
    'neg-double': DexNegDouble_SIZE,
    'int-to-long': DexIntToLong_SIZE,
    'int-to-float': DexIntToFloat_SIZE,
    'int-to-double': DexIntToDouble_SIZE,
    'long-to-int': DexLongToInt_SIZE,
    'long-to-float': DexLongToFloat_SIZE,
    'long-to-double': DexLongToDouble_SIZE,
    'float-to-int': DexFloatToInt_SIZE,
    'float-to-long': DexFloatToLong_SIZE,
    'float-to-double': DexFloatToDouble_SIZE,
    'double-to-int': DexDoubleToInt_SIZE,
    'double-to-long': DexDoubleToLong_SIZE,
    'double-to-float': DexDoubleToFloat_SIZE,
    'int-to-byte': DexIntToByte_SIZE,
    'int-to-char': DexIntToChar_SIZE,
    'int-to-short': DexIntToShort_SIZE,
    'add-int': DexAddInt_SIZE,
    'sub-int': DexAddInt_SIZE,
    'mul-int': DexAddInt_SIZE,
    'div-int': DexAddInt_SIZE,
    'rem-int': DexAddInt_SIZE,
    'and-int': DexAddInt_SIZE,
    'or-int': DexAddInt_SIZE,
    'xor-int': DexAddInt_SIZE,
    'shl-int': DexAddInt_SIZE,
    'shr-int': DexAddInt_SIZE,
    'ushr-int': DexAddInt_SIZE,
    'add-long': DexAddLong_SIZE,
    'sub-long': DexAddLong_SIZE,
    'mul-long': DexAddLong_SIZE,
    'div-long': DexAddLong_SIZE,
    'rem-long': DexAddLong_SIZE,
    'and-long': DexAddLong_SIZE,
    'or-long': DexAddLong_SIZE,
    'xor-long': DexAddLong_SIZE,
    'shl-long': DexAddLong_SIZE,
    'shr-long': DexAddLong_SIZE,
    'ushr-long': DexAddLong_SIZE,
    'add-float': DexAddFloat_SIZE,
    'sub-float': DexAddFloat_SIZE,
    'mul-float': DexAddFloat_SIZE,
    'div-float': DexAddFloat_SIZE,
    'rem-float': DexAddFloat_SIZE,
    'add-double': DexAddDouble_SIZE,
    'sub-double': DexAddDouble_SIZE,
    'mul-double': DexAddDouble_SIZE,
    'div-double': DexAddDouble_SIZE,
    'rem-double': DexAddDouble_SIZE,
    'add-int/2addr': DexAddInt2Addr_SIZE,
    'sub-int/2addr': DexAddInt2Addr_SIZE,
    'mul-int/2addr': DexAddInt2Addr_SIZE,
    'div-int/2addr': DexAddInt2Addr_SIZE,
    'rem-int/2addr': DexAddInt2Addr_SIZE,
    'and-int/2addr': DexAddInt2Addr_SIZE,
    'or-int/2addr': DexAddInt2Addr_SIZE,
    'xor-int/2addr': DexAddInt2Addr_SIZE,
    'shl-int/2addr': DexAddInt2Addr_SIZE,
    'shr-int/2addr': DexAddInt2Addr_SIZE,
    'ushr-int/2addr': DexAddInt2Addr_SIZE,
    'add-long/2addr': DexAddLong2Addr_SIZE,
    'sub-long/2addr': DexAddLong2Addr_SIZE,
    'mul-long/2addr': DexAddLong2Addr_SIZE,
    'div-long/2addr': DexAddLong2Addr_SIZE,
    'rem-long/2addr': DexAddLong2Addr_SIZE,
    'and-long/2addr': DexAddLong2Addr_SIZE,
    'or-long/2addr': DexAddLong2Addr_SIZE,
    'xor-long/2addr': DexAddLong2Addr_SIZE,
    'shl-long/2addr': DexAddLong2Addr_SIZE,
    'shr-long/2addr': DexAddLong2Addr_SIZE,
    'ushr-long/2addr': DexAddLong2Addr_SIZE,
    'add-float/2addr': DexAddFloat2Addr_SIZE,
    'sub-float/2addr': DexAddFloat2Addr_SIZE,
    'mul-float/2addr': DexAddFloat2Addr_SIZE,
    'div-float/2addr': DexAddFloat2Addr_SIZE,
    'rem-float/2addr': DexAddFloat2Addr_SIZE,
    'add-double/2addr': DexAddDouble2Addr_SIZE,
    'sub-double/2addr': DexAddDouble2Addr_SIZE,
    'mul-double/2addr': DexAddDouble2Addr_SIZE,
    'div-double/2addr': DexAddDouble2Addr_SIZE,
    'rem-double/2addr': DexAddDouble2Addr_SIZE,
    'execute-inline': DexExecuteInline_SIZE,
    'invoke-direct-empty': DexInvokeDirectEmpty_SIZE,
    'iget-quick': DexIgetQuick_SIZE,
    'iget-wide-quick': DexIgetWideQuick_SIZE,
    'iget-object-quick': DexIgetObjectQuick_SIZE,
    'iput-quick': DexIputQuick_SIZE,
    'iput-wide-quick': DexIputWideQuick_SIZE,
    'iput-object-quick': DexIputObjectQuick_SIZE,
    'invoke-virtual-quick': DexInvokeVirtualQuick_SIZE,
    'invoke-virtual-quick/range': DexInvokeVirtualQuick_RANGE_SIZE,
    'invoke-super-quick': DexInvokeSuperQuick_SIZE,
    'invoke-super-quick/range': DexInvokeSuperQuick_RANGE_SIZE,
}

opcode_id_map = dict()
with open('module/opcodes_encoding.txt', 'r', encoding='utf-8') as file:
    for line in file.readlines():
        # iget-short:83
        opcode, opcode_id = line.strip().split(':')
        opcode_id_map[opcode] = int(opcode_id)
