from unittest import TestCase

from zapper.assembly.instructions.call_instruction import CallInstruction
from zapper.lang.types import Address, Uint

from zapper.assembly.references import QualifiedReference
from zapper.assembly.instructions import LoadInstruction, MoveInstruction, StoreInstruction
from zapper.assembly.fields import AssemblyField
from zapper.assembly.assembly_class import AssemblyClass
from zapper.assembly.assembly_storage import AssemblyStorage
from zapper.assembly.functions import AssemblyFunction
from zapper.assembly.values import Register, FieldReference


me = Register('me')
me.assembly_type = Address


class TestLinking(TestCase):

    def test_linking(self):
        s = AssemblyStorage()
        c1 = AssemblyClass('qualified.class_1_name', False)
        c2 = AssemblyClass('qualified.class_2_name', False)

        arg = Register('arg')
        arg.assembly_type = c1.qualified_name
        internal = Register('internal')
        ret = Register('ret')
        ret.assembly_type = c1.qualified_name

        owner1 = AssemblyField('owner', Address)
        owner2 = AssemblyField('owner', Address)
        field1 = AssemblyField('field_name', Uint)
        field2 = AssemblyField('other_field_name', Uint)
        function = AssemblyFunction('some_fn', [], Register('me'), [], arg)
        c1.add_field(field1)
        c1.add_field(owner1)
        c2.add_field(field2)
        c2.add_field(owner2)
        c2.add_function(function)

        field1_reference = FieldReference(QualifiedReference(c1.qualified_name, field1.field_name, field1.field_type))
        field2_reference = FieldReference(QualifiedReference(c2.qualified_name, field2.field_name, field2.field_type))
        function_reference = QualifiedReference(c2.qualified_name, function.function_name, function.return_register.assembly_type)
        load = LoadInstruction(internal, arg, field1_reference)
        load2 = LoadInstruction(internal, arg, field2_reference)
        store = StoreInstruction(internal, arg, field1_reference)
        call = CallInstruction(internal, function_reference, [], False)
        move = MoveInstruction(ret, internal)
        function = AssemblyFunction('function_name', [load, load2, store, call, move], me, [arg], ret)
        c1.add_function(function)

        s.add_class(c1)
        s.add_class(c2)
        s.link_new_classes()

        self.assertTrue(isinstance(load.field.field, AssemblyField))
        self.assertEqual(load.field.field.location, field1.location)
        self.assertTrue(isinstance(load2.field.field, AssemblyField))
        self.assertEqual(load2.field.field.location, field2.location)
        self.assertTrue(isinstance(store.field.field, AssemblyField))
        self.assertEqual(store.field.field.location, field1.location)
        self.assertTrue(isinstance(call.function, AssemblyFunction))
        self.assertEqual(call.function.function_name, 'some_fn')
