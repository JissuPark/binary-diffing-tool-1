import sys
from capstone import *
from decompiler import *
from host import dis
from output import c

# Create a Capstone object, which will be used as disassembler
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Define a bunch of bytes to disassemble
code = sys.argv[1]

# Create the capstone-specific backend; it will yield expressions that the decompiler is able to use.
disasm = dis.available_disassemblers['capstone'].create(md, code, 0x1000)
#print(disasm)
# Create the decompiler
dec = decompiler_t(disasm, 0x1000)

# Transform the function until it is decompiled
dec.step_until(step_decompiled)

# Tokenize and output the function as string
#print(dec.function)
print(''.join([str(o) for o in c.tokenizer(dec.function).tokens]))

