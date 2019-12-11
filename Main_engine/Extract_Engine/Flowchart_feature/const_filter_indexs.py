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

logic = ['0xffffffff', '0xffff0000', '0x0000ffff', '0xffffff80', '0xfffffffe']

imageBase = ['0x40000000', '0x10000000', '0x50000000', '0x70000000']


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

prime_set = {
    'mov': 2, 'push': 3, 'xor': 5, 'je': 7, 'jz': 11, 'sub': 13, 'cmp': 17, 'shrd': 19, 'phsubw': 23,
     'syscall': 29, 'fxch': 31, 'r64/16': 37, 'fneni nop': 41, 'maskmovq': 43, 'lgdt': 47, 'fcmovu': 53, 'ftst': 59,
     'vmxon': 61, 'fdivp': 67, 'jl': 71, 'pextrw': 73, 'cmovnc': 79, 'setno': 83, 'cmpxchg': 89, 'x': 97,
     'pcmpeqd': 101, 'cmc': 103, 'fisttp': 107, 'mulpd': 109, 'icebp': 113, 'lmsw': 127, 'fild': 131, 'divps': 137,
     'setnl': 139, 'cmovns': 149, 'packuswb': 151, 'cvtsd2ss': 157, 'bts': 163, 'fucomi': 167, 'aad': 173, 'psrld': 179,
     'ud2': 181, 'lodsw': 191, 'fcom': 193, 'stmxcsr': 197, 'ffreep': 199, 'andnps': 211, 'pmulhw': 223, 'pminsb': 227,
     'bound': 229, 'movmskpd': 233, 'setz': 239, 'movsq': 241, 'outs': 251, 'roundps': 257, 'adx': 263, 'str': 269,
     'movddup': 271, 'cmovpo': 277, 'outsd': 281, 'pushfd': 283, 'pcmpeqw': 293, 'pand': 307, 'pmaxub': 311,
     'pandn': 313, 'hsubpd': 317, 'cvtpi2pd': 331, 'fadd': 337, 'fs': 347, 'jnc': 349, 'jpo': 353, 'lodsq': 359,
     'pmovzxdq': 367, 'pmovsxbw': 373, 'pminsd': 379, 'maxsd': 383, 'btr': 389, 'pshuflw': 397, 'fcomp3': 401,
     'amx': 409, 'psignd': 419, 'fcomp5': 421, 'fdecstp': 431, 'pblendw': 433, 'wait': 439, 'arpl': 443, 'hlt': 449,
     'pmulld': 457, 'dppd': 461, 'movs': 463, 'smsw': 467, 'jna': 479, 'cmovo': 487, 'movsb': 491, 'neg': 499,
     'pcmpgtq': 503, 'verr': 509, 'jle': 521, 'lgs': 523, 'fstp8': 541, 'rcr': 547, 'addsubps': 557, 'phaddw': 563,
     'fsub': 569, 'sidt': 571, 'das': 577, 'clc': 587, 'stosw': 593, 'cmovnbe': 599, 'r8': 601, 'jnp': 607,
     'movntdq': 613, 'mulsd': 617, 'invalid': 619, 'mwait': 631, 'fxam': 641, 'fldenv': 643, 'fldln2': 647, 'invd': 653,
     'popcnt': 659, 'maskmovdqu': 661, 'movdqa': 673, 'pcmpgtw': 677, 'lldt': 683, 'ficomp': 691, 'fucom': 701,
     'rep': 709, 'verw': 719, 'addpd': 727, 'punpckldq': 733, 'movntps': 739, 'fimul': 743, 'fstsw': 751, 'maxpd': 757,
     'popfq': 761, 'wbinvd': 769, 'aaa': 773, 'pinsrd': 787, 'addss': 797, 'paddusw': 809, 'movsw': 811, 'retn': 821,
     'pmovsxwd': 823, 'pminuw': 827, 'lodsb': 829, 'minps': 839, 'punpckhwd': 853, 'fldl2e': 857, 'psignb': 859,
     'setpe': 863, 'movbe': 877, 'addsubpd': 881, 'pmullw': 883, 'cvtpd2dq': 887, 'movsxd': 907, 'pushad': 911,
     'movups': 919, 'pmaxsd': 929, 'pmaxsb': 937, 'sahf': 941, 'scasw': 947, 'unpcklps': 953, 'paddb': 967,
     'setnb': 971, 'lss': 977, 'orpd': 983, 'rcpss': 991, 'fnop': 997, 'pmovmskb': 1009, 'cvtss2sd': 1013,
     'punpckhbw': 1019, 'es': 1021, 'fcmovnu': 1031, 'std': 1033, 'cmpsb': 1039, 'psignw': 1049, 'fyl2x': 1051,
     'pusha': 1061, 'swapgs': 1063, 'lea': 1069, 'cmovge': 1087, 'movhpd': 1091, 'divpd': 1093, 'fscale': 1097,
     'fwait': 1103, 'fxsave': 1109, 'fnstsw': 1117, 'cvttsd2si': 1123, 'movsd': 1129, 'insb': 1151, 'pshufhw': 1153,
     'salc': 1163, 'andpd': 1171, 'setns': 1181, 'lsl': 1187, 'pmovsxdq': 1193, 'js': 1201, 'cmove': 1213,
     'cvtsi2sd': 1217, 'ss': 1223, 'f2xm1': 1229, 'pmovzxbd': 1231, 'fldl2t': 1237, 'maxps': 1249, 'sti': 1259,
     'subss': 1277, 'unpcklpd': 1279, 'hsubps': 1283, 'pshufb': 1289, 'fsave': 1291, 'jnbe': 1297, 'fstenv': 1301,
     'movq2dq': 1303, 'fptan': 1307, 'fcmovbe': 1319, 'cvtdq2ps': 1321, 'minsd': 1327, 'setp': 1361, 'jnz': 1367,
     'idiv': 1373, 'setne': 1381, 'jc': 1399, 'repz': 1409, 'hint_nop': 1423, 'fidivr': 1427, 'psubsb': 1429,
     'jno': 1433, 'cvtpd2pi': 1439, 'leave': 1447, 'adc': 1451, 'jo': 1453, 'punpckhqdq': 1459, 'xsave': 1471,
     'ud': 1481, 'movss': 1483, 'pmulhrsw': 1487, 'phaddsw': 1489, 'subpd': 1493, 'movsldup': 1499, 'div': 1511,
     'nop': 1523, 'fxch4': 1531, 'pcmpgtd': 1543, 'setnc': 1549, 'pcmpeqb': 1553, 'lfence': 1559, 'jae': 1567,
     'fstp': 1571, 'fcom2': 1579, 'fxrstor': 1583, 'paddsw': 1597, 'shl': 1601, 'paddd': 1607, 'cdqe': 1609,
     'pslldq': 1613, 'sysret': 1619, 'pavgw': 1621, 'movntq': 1627, 'scas': 1637, 'fcmovb': 1657, 'packssdw': 1663,
     'fsin': 1667, 'ucomiss': 1669, 'insd': 1693, 'ucomisd': 1697, 'lock': 1699, 'stc': 1709, 'cmpxchg16b': 1721,
     'movapd': 1723, 'undefined': 1733, 'stosb': 1741, 'pmovsxbd': 1747, 'cmovnz': 1753, 'wrmsr': 1759, 'setng': 1777,
     'in': 1783, 'xorps': 1787, 'emms': 1789, 'pmaxud': 1801, 'cvtps2dq': 1811, 'orps': 1823, 'paddusb': 1831,
     'fdivr': 1847, 'jge': 1861, 'ds': 1867, 'fxch7': 1871, 'fabs': 1873, 'cmovnp': 1877, 'vmread': 1879, 'enter': 1889,
     'r16/32': 1901, 'prefetcht2': 1907, 'psubw': 1913, 'add': 1931, 'popa': 1933, 'invvpid': 1949, 'lodsd': 1951,
     'xlat': 1973, 'jnge': 1979, 'cmovno': 1987, 'psubusw': 1993, 'sbb': 1997, 'not': 1999, 'retf': 2003,
     'pmovzxbw': 2011, 'pshufd': 2017, 'ror': 2027, 'rol': 2029, 'fidiv': 2039, 'jbe': 2053, 'fist': 2063,
     'outsb': 2069, 'pmovsxwq': 2081, 'xgetbv': 2083, 'fcmovnb': 2087, 'setnge': 2089, 'cvttps2pi': 2099,
     'vmptrst': 2111, 'inc': 2113, 'cmovpe': 2129, 'fnstenv': 2131, 'daa': 2137, 'sysexit': 2141, 'ptest': 2143,
     'pinsrw': 2153, 'bsf': 2161, 'psubsw': 2179, 'mul': 2203, 'cli': 2207, 'rsqrtps': 2213, 'jnb': 2221, 'xchg': 2237,
     'cmovnb': 2239, 'fcompp': 2243, 'pabsd': 2251, 'cqo': 2267, 'stosq': 2269, 'loop': 2273, 'prefetchnta': 2281,
     'divss': 2287, 'psubd': 2293, 'blendps': 2297, 'lds': 2309, 'fprem1': 2311, 'pextrd': 2333, 'psraw': 2339,
     'fnsave': 2341, 'cvttss2si': 2347, 'cmppd': 2351, 'loopne': 2357, 'fbld': 2371, 'psubusb': 2377, 'cvttpd2pi': 2381,
     'psubq': 2383, 'movmskps': 2389, 'fsubr': 2393, 'call': 2399, 'pavgb': 2411, 'jng': 2417, 'movupd': 2423,
     'fmul': 2437, 'fcmovne': 2441, 'setnbe': 2447, 'setbe': 2459, 'jnae': 2467, 'fdivrp': 2473, 'test': 2477,
     'pcmpistri': 2503, 'pause': 2521, 'fnsetpm nop': 2531, 'movlpd': 2539, 'sqrtpd': 2543, 'jecxz': 2549,
     'vmxoff': 2551, 'sysenter': 2557, 'cmovl': 2579, 'xadd': 2591, 'vmcall': 2593, 'paddw': 2609, 'into': 2617,
     'lar': 2621, 'pmovsxbq': 2633, 'pminsw': 2647, 'subps': 2657, 'addsd': 2659, 'fisubr': 2663, 'mpsadbw': 2671,
     'aam': 2677, 'fiadd': 2683, 'fchs': 2687, 'phsubsw': 2689, 'haddps': 2693, 'pmuldq': 2699, 'paddsb': 2707,
     'fcmovnbe': 2711, 'fninit': 2713, 'jrcxz': 2719, 'vmlaunch': 2729, 'setna': 2731, 'addps': 2741, 'btc': 2749,
     'movdqu': 2753, 'fnclex': 2767, 'fcmove': 2777, 'popad': 2789, 'cmpsq': 2791, 'fldlg2': 2797, 'psrlw': 2801,
     'packusdw': 2803, 'seto': 2819, 'rdmsr': 2833, 'pabsw': 2837, 'phminposuw': 2843, 'or': 2851, 'fpatan': 2857,
     'cbw': 2861, 'psrldq': 2879, 'insw': 2887, 'fcomp': 2897, 'shld': 2903, 'fstp9': 2909, 'psrlq': 2917, 'setc': 2927,
     'movaps': 2939, 'rdtsc': 2953, 'setg': 2957, 'int': 2963, 'paddq': 2969, 'rdtscp': 2971, 'iretq': 2999,
     'fst': 3001, 'xrstor': 3011, 'fstcw': 3019, 'cmpss': 3023, 'dpps': 3037, 'vmclear': 3041, 'cwde': 3049,
     'pabsb': 3061, 'cvtsi2ss': 3067, 'cmovle': 3079, 'jnl': 3083, 'jmp': 3089, 'cvtps2pd': 3109, 'movlhps': 3119,
     'pmovzxwd': 3121, 'cmps': 3137, 'les': 3163, 'fucomp': 3167, 'pushfq': 3169, 'stosd': 3181, 'pslld': 3187,
     'cvtsd2si': 3191, 'cmpps': 3203, 'clflush': 3209, 'mulss': 3217, 'xorpd': 3221, 'comiss': 3229, 'jcxz': 3251,
     'callf': 3253, 'finit': 3257, 'psubb': 3259, 'clts': 3271, 'sqrtss': 3299, 'cwd': 3301, 'cmpxchg8b': 3307,
     'pmaxsw': 3313, 'psadbw': 3319, 'shufps': 3323, 'movdq2q': 3329, 'pmaxuw': 3331, 'rl': 3343, 'phaddd': 3347,
     'invept': 3359, 'fsincos': 3361, 'jne': 3371, 'roundsd': 3373, 'pinsrb': 3389, 'setl': 3391, 'imul': 3407,
     'cpuid': 3413, 'repne': 3433, 'setnle': 3449, 'stos': 3457, 'subsd': 3461, 'jnle': 3463, 'setb': 3467,
     'fld': 3469, 'unpckhpd': 3491, 'punpcklwd': 3499, 'movzx': 3511, 'outsw': 3517, 'fldcw': 3527, 'fldz': 3529,
     'setle': 3533, 'lddqu': 3539, 'jb': 3541, 'jmpf': 3547, 'fndisi nop': 3557, 'repnz': 3559, 'packsswb': 3571,
     'pblendvb': 3581, 'fnstcw': 3583, 'fsubp': 3593, 'seta': 3607, 'rsm': 3613, 'fbstp': 3617, 'cmovbe': 3623,
     'vmresume': 3631, 'fclex': 3637, 'comisd': 3643, 'aas': 3659, 'setpo': 3671, 'dec': 3673, 'pcmpgtb': 3677,
     'setae': 3691, 'ffree': 3697, 'pmuludq': 3701, 'rcpps': 3709, 'cmovna': 3719, 'fsqrt': 3727, 'fsubrp': 3733,
     'sqrtps': 3739, 'cdq': 3761, 'movhps': 3767, 'punpcklbw': 3769, 'ficom': 3779, 'movd': 3793, 'movntdqa': 3797,
     'sldt': 3803, 'int1': 3821, 'cld': 3823, 'invlpg': 3833, 'vmwrite': 3847, 'andnpd': 3851, 'divsd': 3853,
     'pmovzxwq': 3863, 'shr': 3877, 'cmpsw': 3881, 'cvtps2pi': 3889, 'phsubd': 3907, 'fstp1': 3911, 'pmovzxbq': 3917,
     'setnz': 3919, 'pextrq': 3923, 'movshdup': 3929, 'faddp': 3931, 'out': 3943, 'movlps': 3947, 'pop': 3967,
     'roundss': 3989, 'prefetcht1': 4001, 'lfs': 4003, 'lods': 4007, 'frstor': 4013, 'xsetbv': 4019, 'popfd': 4021,
     'sqrtsd': 4027, 'shufpd': 4049, 'ja': 4051, 'pextrb': 4057, 'pcmpestri': 4073, 'rcl': 4079, 'cmovc': 4091,
     'punpcklqdq': 4093, 'pshufw': 4099, 'ldmxcsr': 4111, 'por': 4127, 'cmovz': 4129, 'fmulp': 4133, 'monitor': 4139,
     'minpd': 4153, 'lidt': 4157, 'cmovnle': 4159, 'cvtdq2pd': 4177, 'xlatb': 4201, 'cvttps2dq': 4211, 'fprem': 4217,
     'rsqrtss': 4219, 'pcmpestrm': 4229, 'blendvpd': 4231, 'roundpd': 4241, 'fdiv': 4243, 'cmovp': 4253, 'and': 4259,
     'pxor': 4261, 'cvtpi2ps': 4271, 'cmovae': 4273, 'fxtract': 4283, 'pmaddubsw': 4289, 'movq': 4297, 'cmovng': 4327,
     'ins': 4337, 'cmovb': 4339, 'iretd': 4349, 'pushf': 4357, 'cvtss2si': 4363, 'fcomi': 4373, 'blendvps': 4391,
     'gs': 4397, 'rdpmc': 4409, 'jp': 4421, 'pcmpistrm': 4423, 'vmptrld': 4441, 'frndint': 4447, 'setge': 4451,
     'sar': 4457, 'fldpi': 4463, 'scasd': 4481, 'movntpd': 4483, 'cmova': 4493, 'crc32': 4507, 'iret': 4513,
     'loopz': 4517, 'bsr': 4519, 'fcomip': 4523, 'jns': 4547, 'insertps': 4549, 'psrad': 4561, 'fucomip': 4567,
     'unpckhps': 4583, 'pminub': 4591, 'setnae': 4597, 'jg': 4603, 'fucompp': 4621, 'extractps': 4637, 'maxss': 4639,
     'jpe': 4643, 'cmovnae': 4649, 'pmaddwd': 4651, 'fcos': 4657, 'pmulhuw': 4663, 'haddpd': 4673, 'fisub': 4679,
     'sets': 4691, 'cmovnge': 4703, 'cmovne': 4721, 'andps': 4723, 'sfence': 4729, 'cvttpd2dq': 4733, 'pcmpeqq': 4751,
     'bt': 4759, 'fincstp': 4783, 'mulps': 4787, 'scasq': 4789, 'fistp': 4793, 'minss': 4799, 'mfence': 4801,
     'sete': 4813, 'prefetcht0': 4817, 'cmovg': 4831, 'sgdt': 4861, 'punpckhdq': 4871, 'getsec': 4877, 'pinsrq': 4889,
     'cmpsd': 4903, 'repe': 4909, 'cs': 4919, 'cmovnl': 4931, 'setalc': 4933, 'movnti': 4937, 'r16/32/64': 4943,
     'fld1': 4951, 'psllq': 4957, 'popf': 4967, 'setnp': 4969, 'pminud': 4973, 'loope': 4987, 'cmovs': 4993,
     'psllw': 4999, 'cvtpd2ps': 5003, 'movhlps': 5009, 'sal': 5011, 'lahf': 5021, 'blendpd': 5023, 'scasb': 5039,
     'fyl2xp1': 5051, 'movsx': 5059, 'ltr': 5077, 'palignr': 5081, 'loopnz': 5087, '': 5099}



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
    return primes


def make_opcode_set():
    '''
    인터넷에서 opcodes 싹 긁어온 파일을 저장해서 set으로 저장해주는 함수
    :return:
    '''
    opset = set()
    with open(r"C:\malware\coder32(1).txt", 'rt', encoding='UTF-8') as opcode_file:
        for line in opcode_file.readlines():
            try:
                # print(line.split('\t')[8])
                opset.add(line.split('\t')[8].lower())
            except:
                pass
    with open(r"C:\malware\coder32(2).txt", 'rt', encoding='UTF-8') as opcode_file:
        for line in opcode_file.readlines():
            try:
                # print(line.split('\t')[9])
                opset.add(line.split('\t')[9].lower())
            except:
                pass
    with open(r"C:\malware\coder64(1).txt", 'rt', encoding='UTF-8') as opcode_file:
        for line in opcode_file.readlines():
            try:
                # print(line.split('\t')[8])
                opset.add(line.split('\t')[8].lower())
            except:
                pass
    with open(r"C:\malware\coder64(2).txt", 'rt', encoding='UTF-8') as opcode_file:
        for line in opcode_file.readlines():
            try:
                # print(line.split('\t')[9])
                opset.add(line.split('\t')[9].lower())
            except:
                pass
    print(opset)  # opcode 전체 출력
    print(len(opset))  # opcode 몇 개 있는지 확인
    print('JE' in opset)  # opcode가 있는지 확인
    return opset


def make_prime_dict():
    '''
    opcode와 소수를 묶어주는 함수
    :return:
    '''
    opcodes = make_opcode_set()
    primes = make_prime_set()
    prime_dict = dict(zip(opcodes, primes))
    print(prime_dict)


if __name__ == "__main__":
    # make_opcode_set()
    # make_prime_set()
    make_prime_dict()
