import subprocess
def make_pesudo(func_name,file_path):
    try:
        fp=open(file_path + ".c.json",'r')
        fp.close()
        fp=open(file_path + ".c.backend.bc",'r')
        fp.close()
    except:
        sef = subprocess.call(['/home/bob/projects/retdec-install/bin/retdec-bin2llvmir', "-provider-init", "-decoder", "-verify", 
                               "-x87-fpu", "-main-detection", "-idioms-libgcc", "-inst-opt", "-cond-branch-opt", "-syscalls", "-stack", 
                               "-constants", "-param-return", "-local-vars", "-inst-opt", "-simple-types", "-generate-dsm", "-remove-asm-instrs", 
                               "-class-hierarchy", "-select-fncs", "-inst-opt", "-x86-addr-spaces", "-value-protect", "-instcombine", "-tbaa", 
                               "-targetlibinfo", "-basicaa", "-domtree", "-simplifycfg", "-domtree", "-early-cse", "-lower-expect", 
                               "-targetlibinfo", "-tbaa", "-basicaa", "-globalopt", "-mem2reg", "-instcombine", "-simplifycfg", "-basiccg", 
                               "-domtree", "-early-cse", "-lazy-value-info", "-jump-threading", "-correlated-propagation", "-simplifycfg", 
                               "-instcombine", "-simplifycfg", "-reassociate", "-domtree", "-loops", "-loop-simplify", "-lcssa", "-loop-rotate", 
                               "-licm", "-lcssa", "-instcombine", "-scalar-evolution", "-loop-simplifycfg", "-loop-simplify", "-aa", 
                               "-loop-accesses", "-loop-load-elim", "-lcssa", "-indvars", "-loop-idiom", "-loop-deletion", "-memdep", "-gvn", 
                               "-memdep", "-sccp", "-instcombine", "-lazy-value-info", "-jump-threading", "-correlated-propagation", "-domtree", 
                               "-memdep", "-dse", "-dce", "-bdce", "-adce", "-die", "-simplifycfg", "-instcombine", "-strip-dead-prototypes", 
                               "-globaldce", "-constmerge", "-constprop", "-instnamer", "-domtree", "-instcombine", "-instcombine", "-tbaa", 
                               "-targetlibinfo", "-basicaa", "-domtree", "-simplifycfg", "-domtree", "-early-cse", "-lower-expect", "-targetlibinfo", 
                               "-tbaa", "-basicaa", "-globalopt", "-mem2reg", "-instcombine", "-simplifycfg", "-basiccg", "-domtree", "-early-cse", 
                               "-lazy-value-info", "-jump-threading", "-correlated-propagation", "-simplifycfg", "-instcombine", "-simplifycfg", 
                               "-reassociate", "-domtree", "-loops", "-loop-simplify", "-lcssa", "-loop-rotate", "-licm", "-lcssa", "-instcombine", 
                               "-scalar-evolution", "-loop-simplifycfg", "-loop-simplify", "-aa", "-loop-accesses", "-loop-load-elim", "-lcssa", 
                               "-indvars", "-loop-idiom", "-loop-deletion", "-memdep", "-gvn", "-memdep", "-sccp", "-instcombine", "-lazy-value-info", 
                               "-jump-threading", "-correlated-propagation", "-domtree", "-memdep", "-dse", "-dce", "-bdce", "-adce", "-die", 
                               "-simplifycfg", "-instcombine", "-strip-dead-prototypes", "-globaldce", "-constmerge", "-constprop", "-instnamer", 
                               "-domtree", "-instcombine", "-simple-types", "-stack-ptr-op-remove", "-inst-opt", "-idioms", "-global-to-local", 
                               "-dead-global-assign", "-instcombine", "-phi2seq", "-value-protect", "-disable-inlining", "-disable-simplify-libcalls", 
                               "-config-path", file_path + ".c.json", "-max-memory-half-ram", "-o", file_path + ".c.backend.bc"], universal_newlines=True)
        if sef != 0:
            result = "None"
        return result
    sef = subprocess.call(["/home/bob/projects/retdec-install/bin/retdec-llvmir2hll", "-target-hll=c", "-var-renamer=readable", 
                           "-var-name-gen=fruit", "-var-name-gen-prefix=", "-call-info-obtainer=optim", "-arithm-expr-evaluator=c", 
                           "-validate-module", "-llvmir2bir-converter=orig", "-o", file_path + ".c", file_path + ".c.backend.bc", 
                           "-enable-debug", "-emit-debug-comments", "-config-path=" + file_path + ".c.json", "-max-memory-half-ram"], universal_newlines=True)
    
    if sef != 0:
        result = "None"
        return result
    fp = open(file_path+".c", "r")
    result = fp.read()
    fp.close()
    return result