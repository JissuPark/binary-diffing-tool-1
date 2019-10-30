indexs = ['sldt', 'mov', 'push', 'pop', 'xchg', 'in', 'out', 'xlat', 'lea', 'lds', 'les', 'lahf', 'sahf', 'pushf',
          'pusha', 'pushfd', 'pushad', 'popf', 'movsx', 'movzx', 'add', 'sbb', 'dec', 'neg', 'cmp', 'adc', 'inc', 'aaa',
          'daa',
          'sub', 'aas', 'das', 'mul', 'imul', 'aam', 'div', 'idiv', 'aad', 'cbw', 'cwd', 'cwde', 'not', 'shl', 'shld',
          'sal',
          'shr', 'shrd', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'and', 'test', 'or', 'xor']

registers = ['rax', 'eax', 'ax', 'al', 'rbx', 'ebx', 'bx', 'bl', 'rcx', 'ecx', 'cx', 'cl', 'rdx', 'edx', 'dx', 'dl',
             'rsi', 'esi', 'si', 'sil', 'rdi', 'ah', 'ch', 'dh', 'bh', 'edi', 'di', 'dil', 'rbp', 'ebp', 'bp', 'bpl',
             'rsp', 'esp', 'sp', 'spl', 'r8', 'r8d',
             'r8w', 'r8b', 'r9', 'r9d', 'r9w', 'r9b', 'r10', 'r10d', 'r10w', 'r10b', 'r11', 'r11d', 'r11w', 'r11b',
             'r12', 'r12d',
             'r12w', 'r12b', 'r13', 'r13d', 'r13w', 'r13b', 'r14', 'r14d', 'r14w', 'r14b', 'r15', 'r15d', 'r15w',
             'r15b', 'ss', 'cs', 'ds', 'es', 'fs', 'gs']

pointer = ['esp', 'esi', 'ebp']

logic = ['0xffffffff', '0xffff0000', '0xfffffff0', '0xfffffffe']
# logic 부분 더 추가해야함.

opcodes = [
    'arpl', 'fstp8', 'pavgw', 'pabsw', 'fincstp', 'clflush', 'lidt', 'fld1', 'lfs', 'rsm', 'cvtps2pi', 'cmpxchg8b',
    'scas', 'fimul', 'callf', 'fsubrp', 'setnp', 'fnsetpm nop', 'jp', 'fnstsw', 'orps', 'pshufw', 'fucom', 'cmovo',
    'popad', 'packssdw', 'fyl2x', 'pmuludq', 'fnsave', 'fisub', 'x', 'cmpps', 'cmovbe', 'sar', 'prefetcht2', 'psrld',
    'movups', 'cmovb', 'cvttps2pi', 'fucompp', 'fidivr', 'fucomi', 'stos', 'setz', 'fcmovnbe', 'rsqrtps', 'phsubd',
    'pminsw', 'pushfd', 'hint_nop', 'ficomp', 'fcompp', 'fucomip', 'psrlw', 'xsetbv', 'psraw', 'fabs', 'fdecstp',
    'vmptrst', 'rcr', 'pcmpgtd', 'phaddd', 'fldpi', 'vmresume', 'popa', 'int', 'fpatan', 'sldt', 'bound', 'movnti',
    'shufps', 'add', 'jl', 'fprem1', 'fidiv', 'comiss', 'maskmovq', 'mwait', 'enter', 'punpckldq', 'pmulhuw', 'movs',
    'bt', 'vmwrite', 'jmpf', 'stc', 'frstor', 'cwde', 'ltr', 'sfence', 'fmul', 'pslld', 'lar', 'undefined', 'btr',
    'pmaddubsw', 'psignw', 'fldenv', 'fyl2xp1', 'mulps', 'pminub', 'bsr', 'psubw', 'punpckhwd', 'xlat', 'pxor',
    'psubusb', 'phsubw', 'pabsd', 'fnclex', 'retn', 'psadbw', 'movhlps', 'fchs', 'setns', 'lgs', 'movq', 'setbe',
    'fneni nop', 'shld', 'js', 'fstp', 'cmp', 'r8', 'pmaddwd', 'iretd', 'pextrw', 'cmovnl', 'movntps', 'movzx',
    'ffreep', 'invlpg', 'paddb', 'psubsw', 'jbe', 'cbw', 'fcmovu', 'mov', 'jb', 'lldt', 'movsx', 'fnstcw', 'pcmpgtw',
    'ficom', 'rdmsr', 'fisubr', 'btc', 'punpckhbw', 'phaddw', 'out', 'xrstor', 'paddw', 'fldz', 'paddsw', 'pavgb',
    'phsubsw', 'cmovnle', 'paddq', 'sal', 'aaa', 'setle', 'paddusw', 'setb', 'psllw', 'cvtps2pd', 'wrmsr', 'das',
    'idiv', 'prefetchnta', 'jo', 'pmullw', 'str', 'fldln2', 'not', 'fiadd', 'test', 'smsw', 'ins', 'fnop', 'punpcklwd',
    'fldl2e', 'pmovmskb', 'faddp', 'fxsave', 'fscale', 'fcom2', 'fist', 'bts', 'setnb', 'phaddsw', 'packsswb', 'setl',
    'movlhps', 'fsubr', 'loopnz', 'jnl', 'cmovns', 'lds', 'setp', 'fptan', 'andps', 'minps', 'movhps', 'ror', 'monitor',
    'leave', 'amx', 'r16/32', 'fxch4', 'fldl2t', 'jns', 'cmovp', 'subps', 'addps', 'fprem', 'fstp9', 'aas', 'jnle',
    'xsave', 'lahf', 'fcmovnb', 'por', 'lmsw', 'cmovz', 'fcmove', 'cli', 'fsincos', 'cmovle', 'ud', 'psubb', 'xadd',
    'fwait', 'fistp', 'jnbe', 'rol', 'fxtract', 'rcpps', 'vmptrld', 'fsub', 'pusha', 'sbb', 'fcmovbe', 'divps', 'loopz',
    'movntq', 'vmlaunch', 'and', 'aad', 'loop', 'movmskps', 'movaps', 'pcmpeqd', 'div', 'fcomi', 'packuswb', 'psignb',
    'cmovnz', 'cpuid', 'fldcw', 'vmcall', 'pmulhw', 'fdivrp', 'fsqrt', 'fcmovb', 'cmovnp', 'cmovnb', 'pcmpgtb',
    'getsec', 'movlps', 'pmaxub', 'psignd', 'fcomp', 'fild', 'pcmpeqb', 'fmulp', 'daa', 'pcmpeqw', 'popf', 'cmovno',
    'fxch7', 'fdivr', 'pand', 'ud2', 'fninit', 'fcmovne', 'cwd', 'verw', 'cvtpi2ps', 'sti', 'psrlq', 'cdq', 'xorps',
    'cmovnbe', 'frndint', 'pop', 'shl', 'psubsb', 'fcmovnu', 'lss', 'unpcklps', 'xor', 'paddusb', 'setnle', 'inc',
    'invd', 'pushad', 'mfence', 'aam', 'cld', 'fucomp', 'pinsrw', 'fadd', 'cvtdq2ps', 'fld', 'maxps', 'paddsb', 'mul',
    'rdtsc', 'punpckhdq', 'call', 'cmpxchg', 'psubusw', 'pabsb', 'andnps', 'seto', 'f2xm1', 'sub', 'xchg', 'fstp1',
    'int1', 'punpcklbw', 'fst', 'nop', 'ffree', 'jnz', 'sgdt', 'emms', 'push', 'std', 'les', 'jno', 'fxch', 'ucomiss',
    'bsf', 'rcl', 'fcomp3', 'fnstenv', 'salc', 'psubd', 'popfd', 'adx', 'lgdt', 'jz', 'lods', 'wbinvd', 'psllq', 'retf',
    'lfence', 'verr', 'movbe', 'palignr', 'fbstp', 'in', 'prefetcht0', 'jnb', 'fisttp', 'vmread', 'setnl', 'fsin',
    'fndisi nop', 'jle', 'sysexit', 'ldmxcsr', 'pushf', 'pmaxsw', 'fcom', 'outs', 'jnp', 'lsl', 'sidt', 'fcomip',
    'psrad', 'ftst', 'or', 'sysenter', 'into', 'movd', 'fdivp', 'rdpmc', 'prefetcht1', 'pandn', 'shr', 'fdiv', 'sahf',
    'hlt', 'rdtscp', 'fxam', 'setnbe', 'paddd', 'cmovl', 'adc', 'pshufb', 'lea', 'imul', 'setno', 'cmovs', 'vmxoff',
    'iret', 'fbld', 'jcxz', 'psubq', 'rl', 'jmp', 'neg', 'sqrtps', 'dec', 'shrd', 'clc', 'setnz', 'xgetbv', 'stmxcsr',
    'fsubp', 'cmc', 'unpckhps', 'fldlg2', 'pmulhrsw', 'sets', 'fxrstor', 'clts', 'cmps', 'fcos', 'fcomp5'

]

primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
          109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
          233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
          367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
          499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
          643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
          797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
          947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063,
          1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201,
          1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319,
          1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471,
          1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597,
          1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723,
          1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
          1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011,
          2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141,
          2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293,
          2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417,
          2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591,
          2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711,
          2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843,
          2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001,
          3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169,
          3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319,
          3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463,
          3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593,
          3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733,
          3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889,
          3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027,
          4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201,
          4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339,
          4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507,
          4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651,
          4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801,
          4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969,
          4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107,
          5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281,
          5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441,
          5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581,
          5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741,
          5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869,
          5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067,
          6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217,
          6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353,
          6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547,
          6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691,
          6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841,
          6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991,
          6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177,
          7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333,
          7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523,
          7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649,
          7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823,
          7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993,
          8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167,
          8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311,
          8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513,
          8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669,
          8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807,
          8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969,
          8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137,
          9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293,
          9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437,
          9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619,
          9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769,
          9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923,
          9929, 9931, 9941, 9949, 9967, 9973]

prime_set = {'arpl': 2, 'fstp8': 3, 'pavgw': 5, 'pabsw': 7, 'fincstp': 11, 'clflush': 13, 'lidt': 17, 'fld1': 19,
             'lfs': 23, 'rsm': 29, 'cvtps2pi': 31, 'cmpxchg8b': 37, 'scas': 41, 'fimul': 43, 'callf': 47, 'fsubrp': 53,
             'setnp': 59, 'fnsetpm nop': 61, 'jp': 67, 'fnstsw': 71, 'orps': 73, 'pshufw': 79, 'fucom': 83, 'cmovo': 89,
             'popad': 97, 'packssdw': 101, 'fyl2x': 103, 'pmuludq': 107, 'fnsave': 109, 'fisub': 113, 'x': 127,
             'cmpps': 131, 'cmovbe': 137, 'sar': 139, 'prefetcht2': 149, 'psrld': 151, 'movups': 157, 'cmovb': 163,
             'cvttps2pi': 167, 'fucompp': 173, 'fidivr': 179, 'fucomi': 181, 'stos': 191, 'setz': 193, 'fcmovnbe': 197,
             'rsqrtps': 199, 'phsubd': 211, 'pminsw': 223, 'pushfd': 227, 'hint_nop': 229, 'ficomp': 233, 'fcompp': 239,
             'fucomip': 241, 'psrlw': 251, 'xsetbv': 257, 'psraw': 263, 'fabs': 269, 'fdecstp': 271, 'vmptrst': 277,
             'rcr': 281, 'pcmpgtd': 283, 'phaddd': 293, 'fldpi': 307, 'vmresume': 311, 'popa': 313, 'int': 317,
             'fpatan': 331, 'sldt': 337, 'bound': 347, 'movnti': 349, 'shufps': 353, 'add': 359, 'jl': 367,
             'fprem1': 373, 'fidiv': 379, 'comiss': 383, 'maskmovq': 389, 'mwait': 397, 'enter': 401, 'punpckldq': 409,
             'pmulhuw': 419, 'movs': 421, 'bt': 431, 'vmwrite': 433, 'jmpf': 439, 'stc': 443, 'frstor': 449,
             'cwde': 457, 'ltr': 461, 'sfence': 463, 'fmul': 467, 'pslld': 479, 'lar': 487, 'undefined': 491,
             'btr': 499, 'pmaddubsw': 503, 'psignw': 509, 'fldenv': 521, 'fyl2xp1': 523, 'mulps': 541, 'pminub': 547,
             'bsr': 557, 'psubw': 563, 'punpckhwd': 569, 'xlat': 571, 'pxor': 577, 'psubusb': 587, 'phsubw': 593,
             'pabsd': 599, 'fnclex': 601, 'retn': 607, 'psadbw': 613, 'movhlps': 617, 'fchs': 619, 'setns': 631,
             'lgs': 641, 'movq': 643, 'setbe': 647, 'fneni nop': 653, 'shld': 659, 'js': 661, 'fstp': 673, 'cmp': 677,
             'r8': 683, 'pmaddwd': 691, 'iretd': 701, 'pextrw': 709, 'cmovnl': 719, 'movntps': 727, 'movzx': 733,
             'ffreep': 739, 'invlpg': 743, 'paddb': 751, 'psubsw': 757, 'jbe': 761, 'cbw': 769, 'fcmovu': 773,
             'mov': 787, 'jb': 797, 'lldt': 809, 'movsx': 811, 'fnstcw': 821, 'pcmpgtw': 823, 'ficom': 827,
             'rdmsr': 829, 'fisubr': 839, 'btc': 853, 'punpckhbw': 857, 'phaddw': 859, 'out': 863, 'xrstor': 877,
             'paddw': 881, 'fldz': 883, 'paddsw': 887, 'pavgb': 907, 'phsubsw': 911, 'cmovnle': 919, 'paddq': 929,
             'sal': 937, 'aaa': 941, 'setle': 947, 'paddusw': 953, 'setb': 967, 'psllw': 971, 'cvtps2pd': 977,
             'wrmsr': 983, 'das': 991, 'idiv': 997, 'prefetchnta': 1009, 'jo': 1013, 'pmullw': 1019, 'str': 1021,
             'fldln2': 1031, 'not': 1033, 'fiadd': 1039, 'test': 1049, 'smsw': 1051, 'ins': 1061, 'fnop': 1063,
             'punpcklwd': 1069, 'fldl2e': 1087, 'pmovmskb': 1091, 'faddp': 1093, 'fxsave': 1097, 'fscale': 1103,
             'fcom2': 1109, 'fist': 1117, 'bts': 1123, 'setnb': 1129, 'phaddsw': 1151, 'packsswb': 1153, 'setl': 1163,
             'movlhps': 1171, 'fsubr': 1181, 'loopnz': 1187, 'jnl': 1193, 'cmovns': 1201, 'lds': 1213, 'setp': 1217,
             'fptan': 1223, 'andps': 1229, 'minps': 1231, 'movhps': 1237, 'ror': 1249, 'monitor': 1259, 'leave': 1277,
             'amx': 1279, 'r16/32': 1283, 'fxch4': 1289, 'fldl2t': 1291, 'jns': 1297, 'cmovp': 1301, 'subps': 1303,
             'addps': 1307, 'fprem': 1319, 'fstp9': 1321, 'aas': 1327, 'jnle': 1361, 'xsave': 1367, 'lahf': 1373,
             'fcmovnb': 1381, 'por': 1399, 'lmsw': 1409, 'cmovz': 1423, 'fcmove': 1427, 'cli': 1429, 'fsincos': 1433,
             'cmovle': 1439, 'ud': 1447, 'psubb': 1451, 'xadd': 1453, 'fwait': 1459, 'fistp': 1471, 'jnbe': 1481,
             'rol': 1483, 'fxtract': 1487, 'rcpps': 1489, 'vmptrld': 1493, 'fsub': 1499, 'pusha': 1511, 'sbb': 1523,
             'fcmovbe': 1531, 'divps': 1543, 'loopz': 1549, 'movntq': 1553, 'vmlaunch': 1559, 'and': 1567, 'aad': 1571,
             'loop': 1579, 'movmskps': 1583, 'movaps': 1597, 'pcmpeqd': 1601, 'div': 1607, 'fcomi': 1609,
             'packuswb': 1613, 'psignb': 1619, 'cmovnz': 1621, 'cpuid': 1627, 'fldcw': 1637, 'vmcall': 1657,
             'pmulhw': 1663, 'fdivrp': 1667, 'fsqrt': 1669, 'fcmovb': 1693, 'cmovnp': 1697, 'cmovnb': 1699,
             'pcmpgtb': 1709, 'getsec': 1721, 'movlps': 1723, 'pmaxub': 1733, 'psignd': 1741, 'fcomp': 1747,
             'fild': 1753, 'pcmpeqb': 1759, 'fmulp': 1777, 'daa': 1783, 'pcmpeqw': 1787, 'popf': 1789, 'cmovno': 1801,
             'fxch7': 1811, 'fdivr': 1823, 'pand': 1831, 'ud2': 1847, 'fninit': 1861, 'fcmovne': 1867, 'cwd': 1871,
             'verw': 1873, 'cvtpi2ps': 1877, 'sti': 1879, 'psrlq': 1889, 'cdq': 1901, 'xorps': 1907, 'cmovnbe': 1913,
             'frndint': 1931, 'pop': 1933, 'shl': 1949, 'psubsb': 1951, 'fcmovnu': 1973, 'lss': 1979, 'unpcklps': 1987,
             'xor': 1993, 'paddusb': 1997, 'setnle': 1999, 'inc': 2003, 'invd': 2011, 'pushad': 2017, 'mfence': 2027,
             'aam': 2029, 'cld': 2039, 'fucomp': 2053, 'pinsrw': 2063, 'fadd': 2069, 'cvtdq2ps': 2081, 'fld': 2083,
             'maxps': 2087, 'paddsb': 2089, 'mul': 2099, 'rdtsc': 2111, 'punpckhdq': 2113, 'call': 2129,
             'cmpxchg': 2131, 'psubusw': 2137, 'pabsb': 2141, 'andnps': 2143, 'seto': 2153, 'f2xm1': 2161, 'sub': 2179,
             'xchg': 2203, 'fstp1': 2207, 'int1': 2213, 'punpcklbw': 2221, 'fst': 2237, 'nop': 2239, 'ffree': 2243,
             'jnz': 2251, 'sgdt': 2267, 'emms': 2269, 'push': 2273, 'std': 2281, 'les': 2287, 'jno': 2293, 'fxch': 2297,
             'ucomiss': 2309, 'bsf': 2311, 'rcl': 2333, 'fcomp3': 2339, 'fnstenv': 2341, 'salc': 2347, 'psubd': 2351,
             'popfd': 2357, 'adx': 2371, 'lgdt': 2377, 'jz': 2381, 'lods': 2383, 'wbinvd': 2389, 'psllq': 2393,
             'retf': 2399, 'lfence': 2411, 'verr': 2417, 'movbe': 2423, 'palignr': 2437, 'fbstp': 2441, 'in': 2447,
             'prefetcht0': 2459, 'jnb': 2467, 'fisttp': 2473, 'vmread': 2477, 'setnl': 2503, 'fsin': 2521,
             'fndisi nop': 2531, 'jle': 2539, 'sysexit': 2543, 'ldmxcsr': 2549, 'pushf': 2551, 'pmaxsw': 2557,
             'fcom': 2579, 'outs': 2591, 'jnp': 2593, 'lsl': 2609, 'sidt': 2617, 'fcomip': 2621, 'psrad': 2633,
             'ftst': 2647, 'or': 2657, 'sysenter': 2659, 'into': 2663, 'movd': 2671, 'fdivp': 2677, 'rdpmc': 2683,
             'prefetcht1': 2687, 'pandn': 2689, 'shr': 2693, 'fdiv': 2699, 'sahf': 2707, 'hlt': 2711, 'rdtscp': 2713,
             'fxam': 2719, 'setnbe': 2729, 'paddd': 2731, 'cmovl': 2741, 'adc': 2749, 'pshufb': 2753, 'lea': 2767,
             'imul': 2777, 'setno': 2789, 'cmovs': 2791, 'vmxoff': 2797, 'iret': 2801, 'fbld': 2803, 'jcxz': 2819,
             'psubq': 2833, 'rl': 2837, 'jmp': 2843, 'neg': 2851, 'sqrtps': 2857, 'dec': 2861, 'shrd': 2879,
             'clc': 2887, 'setnz': 2897, 'xgetbv': 2903, 'stmxcsr': 2909, 'fsubp': 2917, 'cmc': 2927, 'unpckhps': 2939,
             'fldlg2': 2953, 'pmulhrsw': 2957, 'sets': 2963, 'fxrstor': 2969, 'clts': 2971, 'cmps': 2999, 'fcos': 3001,
             'fcomp5': 3011, 'ret':3019, 'jae': 3023, 'setg': 3037, 'pshuflw': 3041, 'cmovne':3049 , 'rep movsd':3061,
             'movdqu':3067, 'stosd':3079, 'je':3083, 'movsb':3089, 'jne':3109, 'jge':3119, 'lock xadd':3121, 'jg':3137,
             'movsd':3163, 'sete':3167, 'movsw':3169, 'repne scasb':3181, 'cmova':3187, 'ja':3191, 'pushal':3203,
             'movlpd':3209, 'movdqa':3217, 'cmove':3221, 'setne':3229, 'rep movsb': 3251,}


def make_prime_set():
    '''
    에라토스테네스의 체를 이용한 소수 구하기
    '''
    n = 10000  # 어느 범위까지 구할건지
    a = [False, False] + [True] * (n - 1)
    primes = []

    for i in range(2, n + 1):
        if a[i]:
            primes.append(i)
            for j in range(2 * i, n + 1, i):
                a[j] = False
    print(primes)
    print(len(primes))


def make_opcode_set():
    '''
    인터넷에서 opcodes 싹 긁어온 파일을 저장해서 set으로 저장해주는 함수
    :return:
    '''
    opset = set()
    with open(r"C:\malware\opcodes.txt", 'rt', encoding='UTF-8') as opcode_file:
        for line in opcode_file.readlines():
            try:
                # print(line.split('\t')[8])
                opset.add(line.split('\t')[8].lower())
            except:
                pass
    with open(r"C:\malware\opcodes2.txt", 'rt', encoding='UTF-8') as opcode_file:
        for line in opcode_file.readlines():
            try:
                # print(line.split('\t')[9])
                opset.add(line.split('\t')[9].lower())
            except:
                pass

    print(opset) # opcode 전체 출력
    print(len(opset)) # opcode 몇 개 있는지 확인
    print('add' in opset) # opcode가 있는지 확인


def make_prime_dict():
    '''
    opcode와 소수를 묶어주는 함수
    :return:
    '''
    prime_dict = dict(zip(opcodes, primes))
    print(prime_dict)


if __name__ == "__main__":
    make_opcode_set()
    make_prime_set()
    make_prime_dict()
