from typing import Type, Dict, List
from unittest import TestCase

from tests.examples.contract_coin import Coin
from tests.examples.contract_dex import DexOffer
from tests.examples.contract_example_1 import ContractExample1
from tests.examples.contract_example_2 import ContractExample2
from tests.examples.contract_example_3 import ContractExample3
from tests.examples.contract_example_4 import ContractExample4, InnerExample
from zapper.assembly.assembly_class import AssemblyClass
from zapper.assembly.assembly_storage import AssemblyStorage
from zapper.assembly.fields import AssemblyField
from zapper.assembly.functions import AssemblyFunction
from zapper.assembly.instructions.call_instruction import CallInstruction
from zapper.assembly.values import ClassReference, FieldReference, Register
from zapper.compiler.compiler import compile_contract
from zapper.lang.contract import Contract


class TestCompileToInline(TestCase):

	def __init__(self, *args, **kwargs):
		self.assembly_classes: Dict[Type[Contract], AssemblyClass] = {}
		self.original_strings: Dict[Type[Contract], str] = {}
		super().__init__(*args, **kwargs)

	def test_compile_to_inline_examples(self):
		self.compile_to_inline([ContractExample1, ContractExample2, ContractExample3, ContractExample4, InnerExample])

	def test_compile_to_inline_coin_dex(self):
		self.compile_to_inline([Coin, DexOffer])

	def compile_to_inline(self, classes: List[Contract]):
		with self.subTest("all"):  # hack to ensure exceptions are printed
			assembly_storage = AssemblyStorage()

			for c in classes:
				# compile
				assembly_class = compile_contract(c)
				self.assembly_classes[c] = assembly_class

				# add
				assembly_storage.add_class(assembly_class)
				self.original_strings[c] = str(assembly_class)

			# link
			assembly_storage.link_new_classes()
			for c in classes:
				self.check_string_preserved(c)

			# check no unlinked references
			for c in assembly_storage.assembly_classes.values():
				for f in c.functions.values():
					self.check_no_unlinked(f)

			# run check
			assembly_storage.check_new_classes()
			for c in classes:
				self.check_string_preserved(c)

			# inline
			assembly_storage.inline_new_classes()

			# check all calls inlined and labels unique
			for c in assembly_storage.assembly_classes.values():
				for f in c.functions.values():
					self.check_all_calls_inlined(f)
					self.check_register_labels_unique(f)

			# insert runtime checks
			assembly_storage.insert_runtime_checks_for_new_classes()

			# allocate
			assembly_storage.allocation_for_new_classes()

			# check expected locations of registers
			for c in assembly_storage.assembly_classes.values():
				for f in c.functions.values():
					self.check_register_locations(f)

	def check_string_preserved(self, c: Type[Contract]):
		expected_string = self.original_strings[c]
		current_assembly_class = self.assembly_classes[c]
		current_string = str(current_assembly_class)
		self.assertEqual(expected_string, current_string)

	def check_register_locations(self, f):
		self.assertEqual(f.me_register.location, 0)
		i = 1
		for arg in f.argument_registers:
			self.assertEqual(arg.location, i)
			i += 1

	def check_value_linked(self, value):
		if value is not None:
			if isinstance(value, ClassReference):
				self.assertIsInstance(value.assembly_class, AssemblyClass)
			elif isinstance(value, FieldReference):
				self.assertIsInstance(value.field, AssemblyField)

	def check_no_unlinked(self, f):
		for i in f.instructions:
			if isinstance(i, CallInstruction):
				self.assertIsInstance(i.function, AssemblyFunction)
			self.check_value_linked(i.value_1)
			self.check_value_linked(i.value_2)

	def check_all_calls_inlined(self, f):
		for i in f.instructions:
			self.assertNotIsInstance(i, CallInstruction, "found non-inlined call instruction")

	def check_register_labels_unique(self, f):
		register_for_name = {}
		for i in f.instructions:
			if i.value_1 is not None and isinstance(i.value_1, Register):
				if i.value_1.label in register_for_name:
					self.assertEqual(register_for_name[i.value_1.label], i.value_1, f"register {i.value_1.label} with identical label not identical")
				else:
					register_for_name[i.value_1.label] = i.value_1
			if i.value_2 is not None and isinstance(i.value_2, Register):
				if i.value_2.label in register_for_name:
					self.assertEqual(register_for_name[i.value_2.label], i.value_2, f"register {i.value_2.label} with identical label not identical")
				else:
					register_for_name[i.value_2.label] = i.value_2