
indexs =  ['sldt', 'mov', 'push', 'pop', 'xchg', 'in', 'out', 'xlat', 'lea', 'lds', 'les', 'lahf', 'sahf', 'pushf',
   'pusha', 'pushfd', 'pushad', 'popf', 'movsx', 'movzx', 'add', 'sbb', 'dec', 'neg', 'cmp', 'adc', 'inc', 'aaa', 'daa',
    'sub', 'aas', 'das', 'mul', 'imul', 'aam', 'div', 'idiv', 'aad', 'cbw', 'cwd', 'cwde', 'not', 'shl', 'shld', 'sal', 
    'shr', 'shrd', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'and', 'test', 'or', 'xor']


registers = ['rax', 'eax', 'ax', 'al', 'rbx', 'ebx', 'bx', 'bl', 'rcx', 'ecx', 'cx', 'cl', 'rdx', 'edx', 'dx', 'dl',
 'rsi', 'esi', 'si', 'sil', 'rdi','ah', 'ch', 'dh','bh', 'edi', 'di', 'dil', 'rbp', 'ebp', 'bp', 'bpl', 'rsp', 'esp', 'sp', 'spl', 'r8', 'r8d',
  'r8w', 'r8b', 'r9', 'r9d', 'r9w', 'r9b', 'r10', 'r10d', 'r10w', 'r10b', 'r11', 'r11d', 'r11w', 'r11b', 'r12', 'r12d',
   'r12w', 'r12b', 'r13', 'r13d', 'r13w', 'r13b', 'r14', 'r14d', 'r14w', 'r14b', 'r15', 'r15d', 'r15w', 'r15b', ]

pointer = ['esp', 'esi', 'ebp']

logic = ['0xffffffff', '0xffff0000', '0xfffffff0', '0xfffffffe']
#logic 부분 더 추가해야함.