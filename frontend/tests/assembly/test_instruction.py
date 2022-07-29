from unittest import TestCase

from zapper.assembly.instructions import MoveInstruction, ConditionalMoveInstruction
from zapper.assembly.values import Register, Constant
from zapper.lang.types import Uint
from zapper.runtime.serialized_assembly import serialize_instruction


class TestInstruction(TestCase):

    def test_inlined_equivalent(self):
        source = Register('source')
        destination = Register('destination')
        i = MoveInstruction(destination, source)

        new_source = Register('new_source')

        inlined = i.get_inlined_equivalent({source: new_source}, 'postfix')
        self.assertEqual(str(inlined), 'MOV destination#postfix new_source _')

    def test_serialization(self):
        destination = Register('destination')
        destination.location = 7
        condition = Register('condition')
        condition.location = 4
        source = Register('source')
        source.location = 2

        i = ConditionalMoveInstruction(destination, condition, source)
        s = serialize_instruction(i)
        self.assertEqual(s.opcode, i.opcode)
        self.assertEqual(s.dst, 7)
        self.assertEqual(s.src_1, "04")
        self.assertEqual(s.src_1_is_const, False)
        self.assertEqual(s.src_2, "02")
        self.assertEqual(s.src_2_is_const, False)

        i = ConditionalMoveInstruction(destination, Constant(33, Uint), source)
        s = serialize_instruction(i)
        self.assertEqual(s.src_1, "21")
        self.assertEqual(s.src_1_is_const, True)
        self.assertEqual(s.src_2, "02") # NOTE: hex format
        self.assertEqual(s.src_2_is_const, False)

        i = ConditionalMoveInstruction(destination, condition, Constant(77, Uint))
        s = serialize_instruction(i)
        self.assertEqual(s.src_1, "04")
        self.assertEqual(s.src_1_is_const, False)
        self.assertEqual(s.src_2, "4d")
        self.assertEqual(s.src_2_is_const, True)
