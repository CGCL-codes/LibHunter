from androguard.core.analysis.analysis import Analysis, MethodAnalysis
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.decompiler.dad.decompile import DvMethod
from androguard.decompiler.dad.graph import construct
from androguard.decompiler.dad.instruction import AssignExpression, InvokeRangeInstruction, Param
from androguard.util import read
from module.androguard.decompiler.dad.dataflow import build_def_use

skip_classes = ['String']


def analysis_callee_arguments_wapper(dex_obj, analysis_obj):
    callsites_arguments = {}
    for cls in dex_obj.get_classes():
        for method in cls.get_methods():
            if method.code_off == 0:
                continue
            mx: MethodAnalysis = analysis_obj.get_method(method)
            dv_method: DvMethod = DvMethod(mx)
            graph = construct(dv_method.start_block, dv_method.var_to_name, dv_method.exceptions)
            use_defs, _ = build_def_use(graph, dv_method.lparams)
            analysis_callee_arguments(graph, use_defs, callsites_arguments)
    return callsites_arguments


def analysis_callee_arguments(graph, use_defs, callsites_arguments):
    """
    Analyze the arguments of the callee method in the graph
    """

    for index, stmt in graph.loc_to_ins.items():
        if isinstance(stmt, AssignExpression):
            if stmt.is_call():
                rhs = stmt.get_rhs()
                if isinstance(rhs, InvokeRangeInstruction):
                    continue

                # if rhs.cls.startswith('java'):
                #     continue
                if '.' not in rhs.cls:
                    continue

                for var in rhs.args:
                    defs = use_defs[(var, index)]
                    if len(defs) != 1:
                        continue
                    def_index = defs.pop()
                    if def_index < 0:
                        continue
                    def_stmt = graph.loc_to_ins[def_index]
                    def_stmt_rhs = def_stmt.get_rhs()
                    if type(def_stmt_rhs) is list:
                        continue
                    if not isinstance(def_stmt_rhs, Param) and def_stmt_rhs.is_const():
                        var_index = rhs.args.index(var)
                        # print("VAR_{}={} in callee {}".format(var,def_stmt_rhs.__str__(), rhs))
                        callee = '{}.{}({}){}'.format(rhs.cls, rhs.name, ''.join(rhs.ptype), rhs.rtype)
                        value = def_stmt_rhs.__str__()
                        if callee not in callsites_arguments:
                            args = ['ud'] * len(rhs.args)
                            args[var_index] = value
                            callsites_arguments[callee] = args

                        else:
                            old_values = callsites_arguments[callee]
                            if old_values[var_index] != value:
                                old_values[var_index] = 'NAC'
                                callsites_arguments[callee] = old_values


if __name__ == '__main__':
    dex_obj = DalvikVMFormat(read('libs_dex/okhttp-3.12.0.dex'))
    analysis_obj: Analysis = Analysis(dex_obj)
    analysis_obj.create_xref()
    name = 'Lokhttp3/Cookie; parse (J Lokhttp3/HttpUrl; Ljava/lang/String;)Lokhttp3/Cookie;'
    callsites_arguments = analysis_callee_arguments_wapper(dex_obj, analysis_obj)
    print(callsites_arguments)
