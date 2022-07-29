from zapper.assembly.functions import AssemblyFunction


class RegisterAllocation:

	def __init__(self):
		self.free_registers = set()
		self.n_registers = 0

	def _next_free_register(self):
		try:
			return self.free_registers.pop()
		except KeyError:
			ret = self.n_registers
			self.n_registers += 1
			return ret

	def run(self, function: AssemblyFunction):
		all_instructions = function.get_all_instructions()
		last_used = {}
		for instruction in all_instructions:
			for register in instruction.get_registers():
				last_used[register] = instruction

		# allocate "me" as the first argument
		function.me_register.location = self._next_free_register()

		# allocate the arguments subsequently
		for arg in function.argument_registers:
			arg.location = self._next_free_register()

		for instruction in all_instructions:
			for register in instruction.get_registers():
				if register.location == -1:
					register.location = self._next_free_register()

			for register in instruction.get_registers():
				if last_used[register] is instruction:
					self.free_registers.add(register.location)


def register_allocation(function: AssemblyFunction):
	a = RegisterAllocation()
	a.run(function)
