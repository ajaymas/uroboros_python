from cg import cg
from cfg import cfg
from utils.ail_utils import read_file
from utils.pp_print import pp_print_list, pp_print_file

class Analysis(object):

    @staticmethod
    def global_bss():
        lines = read_file('globalbss.info')
        def mapper(l):
            items = l.strip().split()
            return (items[0][1:].upper(), items[1])
        return map(mapper, lines)

    @staticmethod
    def analyze_one(il, fl, re):
        _cfg = cfg()
        _cg = cg()
        _cg.set_funcs(fl)
        _cfg.set_funcs(fl)
        u_fl = filter(lambda f: not f.is_lib, fl)
        print '     user defined func number', len(u_fl)
        _il = _cg.visit(il)
        _il = re.visit_type_infer_analysis([], _il)
        _il = re.share_lib_processing(_il)
        _il = re.adjust_loclabel(_il)

        re.reassemble_dump(u_fl)

        _il = re.adjust_jmpref(_il)
        _il = _cfg.visit(_il)

        bbl = _cfg.get_bbl()
        return (_cfg.get_fbl(), bbl, _cfg.get_cfg_table(_il),
                _cg.get_cg_table(), re.add_bblock_label(bbl, _il), re)

    @staticmethod
    def post_analyze(il, re):
        il = re.unify_loc(il)
        ils = pp_print_list(il)
        ils = re.adjust_globallabel(Analysis.global_bss(), ils)
        pp_print_file(ils)