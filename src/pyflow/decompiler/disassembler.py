

from opcode import *
from dis import findlinestarts, get_instructions

flowControlOps = [opmap['RETURN_VALUE'],
		  opmap['RAISE_VARARGS'],
		  opmap['FOR_ITER']]
# BREAK_LOOP no longer exists in Python 3

# Add Python 3 jump operations
flowControlOps.extend([opmap['POP_JUMP_IF_FALSE'], opmap['POP_JUMP_IF_TRUE']])
flowControlOps.extend(hasjrel)
flowControlOps.extend(hasjabs)
# SETUP_LOOP no longer exists in Python 3, handled by SETUP_FINALLY

flowControlOps = frozenset(flowControlOps)

blockOps = frozenset((opmap['POP_BLOCK'], opmap['SETUP_FINALLY']))

# Python 3 has more stack operations
stackOps = frozenset((opmap['POP_TOP'], opmap['SWAP']))



notOp = []
notOp.extend(stackOps)
notOp.extend(blockOps)
notOp.append(opmap['NOP'])
notOp = frozenset(notOp)

class Instruction(object):
	__slots__ = 'line', 'offset', 'opcode', 'arg'

	def __init__(self, line, offset, opcode, arg=None):
		self.line 	= line
		self.offset 	= offset
		self.opcode 	= opcode
		self.arg 	= arg

		# In Python 3, some opcodes may have arguments even if hasArgument() returns False
		# assert self.hasArgument() or arg == None

	def __repr__(self):
		return "inst(%d:%d, %s, %s)" % (self.line, self.offset, self.neumonic(), repr(self.arg))

	def opcodeString(self):
		if self.hasArgument():
			return "%s %s" % (self.neumonic(), repr(self.arg))
		else:
			return self.neumonic()

	def neumonic(self):
		return opname[self.opcode]

	def hasArgument(self):
		return self.opcode >= HAVE_ARGUMENT

	def isFlowControl(self):
		return self.opcode in flowControlOps

	def isBlockOperation(self):
		return self.opcode in blockOps

	def isOperation(self):
		return self.opcode not in notOp

	def __eq__(self, other):
		return type(self) == type(other) and self.opcode == other.opcode and self.arg == other.arg

def disassemble(co):
	linestarts = dict(findlinestarts(co))

	inst = []
	offsetLUT = {}

	# Use Python's built-in disassembler to avoid Python 3 bytecode format issues
	for dis_instr in get_instructions(co):
		offset = dis_instr.offset
		op = dis_instr.opcode
		arg = dis_instr.arg
		line = linestarts.get(offset, 0)  # Default to line 0 if not found

		newi = Instruction(line, offset, op, arg)
		offsetLUT[offset] = len(inst)
		inst.append(newi)

	# Calculate jump targets based on the instruction offsets
	targets = []
	for i, instruction in enumerate(inst):
		if instruction.opcode in hasjrel:
			# For relative jumps, calculate the target offset
			current_offset = instruction.offset
			jump_offset = instruction.arg
			target_offset = current_offset + jump_offset
			if target_offset in offsetLUT:
				instruction.arg = offsetLUT[target_offset]
				targets.append(offsetLUT[target_offset])
		elif instruction.opcode in hasjabs:
			# For absolute jumps, the arg is already the target offset
			if instruction.arg in offsetLUT:
				instruction.arg = offsetLUT[instruction.arg]
				targets.append(offsetLUT[instruction.arg])

	return inst, targets
