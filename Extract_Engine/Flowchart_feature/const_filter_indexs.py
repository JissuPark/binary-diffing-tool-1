
indexs =  ['sldt', 'mov', 'push', 'pop', 'xchg', 'in', 'out', 'xlat', 'lea', 'lds', 'les', 'lahf', 'sahf', 'pushf',
   'pusha', 'pushfd', 'pushad', 'popf', 'movsx', 'movzx', 'add', 'sbb', 'dec', 'neg', 'cmp', 'adc', 'inc', 'aaa', 'daa',
    'sub', 'aas', 'das', 'mul', 'imul', 'aam', 'div', 'idiv', 'aad', 'cbw', 'cwd', 'cwde', 'not', 'shl', 'shld', 'sal', 
    'shr', 'shrd', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'and', 'test', 'or', 'xor']


registers = ['rax', 'eax', 'ax', 'al', 'rbx', 'ebx', 'bx', 'bl', 'rcx', 'ecx', 'cx', 'cl', 'rdx', 'edx', 'dx', 'dl',
 'rsi', 'esi', 'si', 'sil', 'rdi','ah', 'ch', 'dh','bh', 'edi', 'di', 'dil', 'rbp', 'ebp', 'bp', 'bpl', 'rsp', 'esp', 'sp', 'spl', 'r8', 'r8d',
  'r8w', 'r8b', 'r9', 'r9d', 'r9w', 'r9b', 'r10', 'r10d', 'r10w', 'r10b', 'r11', 'r11d', 'r11w', 'r11b', 'r12', 'r12d',
   'r12w', 'r12b', 'r13', 'r13d', 'r13w', 'r13b', 'r14', 'r14d', 'r14w', 'r14b', 'r15', 'r15d', 'r15w', 'r15b', ]

pointer = ['esp', 'esi', 'ebp']



'''

--------- operand 2개일 때 --------- 
	operand1		operand2
	조건 1 operand1 에 (esp, esi, ebp) 등이 없어야 입장한다.
		조건 2 operand2 에 "ptr"이 없어야 입장한다.
			조건 3 operand2는 const_opcode_indexs.registers 에 존재하지 않아야 입장한다.
				조건 4 operand2 != 0 and [정규식 0x123456자리] 가 아니여야 입장한다.



--------- operand 1개일 때 --------- 
	조건 1 operand[0]에 "ptr"이 없어야 입장한다 (and) const_opcode_index.registers에 존재하지 않아야한다. (and) operand[0] != '0' (and) len(operand[0]) !=8


'''