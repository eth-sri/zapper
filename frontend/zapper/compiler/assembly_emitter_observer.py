from typing import Any, Callable, Type

from zapper.assembly.instructions.fresh_instruction import FreshInstruction
from zapper.assembly.instructions.now_instruction import NowInstruction
from zapper.assembly.instructions.public_key_instruction import PublicKeyInstruction
from zapper.utils.inspection import get_class_that_defined_method

from zapper.assembly.binary_operations import BinaryOperator
from zapper.assembly.instructions.kill_instruction import KillInstruction
from zapper.assembly.references import QualifiedReference
from zapper.assembly.instructions.call_instruction import CallInstruction
from zapper.assembly.types import zapper_type_to_assembly_type
from zapper.assembly.values import Register, FieldReference, Value, Constant
from zapper.compiler.instruction_builder import InstructionBuilder
from zapper.lang.types import ZapperType, is_reference, Address, Uint, Long, is_uint_literal, AddressConst, LongConst
from zapper.assembly.instructions import LoadInstruction, StoreInstruction, BinaryOperationInstruction, \
    RequireInstruction, MoveInstruction, ConditionalMoveInstruction
from zapper.lang.event_observer import EventObserver
from zapper.lang.field import Field
from zapper.lang.function import Function, extract_function


class AssemblyEmitterObserver(EventObserver):

    def __init__(self, value: Value, expression_type: ZapperType, builder: InstructionBuilder):
        if is_reference(expression_type):
            super().__init__(expression_type)
        else:
            super().__init__(None)
        self.expression_type = expression_type
        self.value = value
        self.builder = builder
        self.owner_register = None

    def require(self, e):
        e = self._wrap(e)
        instruction = RequireInstruction(e.value)
        self.builder.append(instruction)

    def require_equals(self, e1, e2):
        e1 = self._wrap(e1)
        e2 = self._wrap(e2)
        self.require(e1 == e2)

    def if_then_else(self, condition, e_true, e_false):
        condition = self._wrap(condition)
        e_true = self._wrap(e_true)
        e_false = self._wrap(e_false)

        res_register = self.builder.next_register('res')
        self.builder.append(MoveInstruction(res_register, e_false.value))
        self.builder.append(ConditionalMoveInstruction(res_register, condition.value, e_true.value))

        ret = self._return_observer(res_register, e_true.value.assembly_type)
        return ret

    @property
    def me(self):
        ret = AssemblyEmitterObserver(self.builder.me_register, Address, self.builder)
        return ret

    @property
    def owner(self):
        if self.owner_register is None:
            self.owner_register = self.builder.next_register('owner')

        field = self._get_owner_field()
        instruction = LoadInstruction(self.owner_register, self.value, field)
        self.builder.append(instruction)

        ret = self._return_observer(self.owner_register, Address)
        return ret

    @property
    def address(self):
        address_register = self.builder.next_register('address')
        instruction = PublicKeyInstruction(address_register, self.value)
        self.builder.append(instruction)

        ret = self._return_observer(address_register, Address)
        return ret

    @owner.setter
    def owner(self, value):
        field = self._get_owner_field()
        instruction = StoreInstruction(value, self.register, field)
        self.builder.append(instruction)

    def create_new_object(self, constructor_function: Callable, *args):
        function = extract_function(get_class_that_defined_method(constructor_function), constructor_function.__name__)
        assert function.is_constructor
        return self.function_call(function, *args)

    def kill(self):
        instruction = KillInstruction(self.value)
        self.builder.append(instruction)

    def fresh(self):
        fresh_register = self.builder.next_register('fresh')
        instruction = FreshInstruction(fresh_register)
        self.builder.append(instruction)

        ret = self._return_observer(fresh_register, Long)
        return ret

    def now(self):
        now_register = self.builder.next_register('now')
        instruction = NowInstruction(now_register)
        self.builder.append(instruction)

        ret = self._return_observer(now_register, Uint)
        return ret

    def function_call(self, function: Function, *args, sender_is_self=False):
        return_register = self.builder.next_register('return')
        reference = self._get_qualified_reference(function.name, function.return_type, function.contract_type)
        args = [self._wrap(a).value for a in args]
        call = CallInstruction(return_register, reference, args, sender_is_self)
        self.builder.append(call)

        ret = self._return_observer(return_register, function.return_type)
        return ret

    def read_field(self, field: Field) -> Any:
        read_register = self.builder.next_register('read')
        reference = self._get_field(field.name, field.zapper_type)
        load = LoadInstruction(read_register, self.value, reference)
        self.builder.append(load)

        ret = self._return_observer(read_register, field.zapper_type)
        return ret

    def write_field(self, field: Field, e):
        reference = self._get_field(field.name, field.zapper_type)

        e = self._wrap(e)
        if isinstance(e.value, Constant):
            reg = self.builder.next_register('constant')
            move = MoveInstruction(reg, e.value)
            self.builder.append(move)
            rhs = reg
        else:
            assert isinstance(e.value, Register)
            rhs = e.value
        store = StoreInstruction(rhs, self.value, reference)
        self.builder.append(store)

    ###########
    # HELPERS #
    ###########

    def _get_field(self, field_name: str, field_type: ZapperType):
        field = self._get_qualified_reference(field_name, field_type)
        field = FieldReference(field)
        return field

    def _get_owner_field(self):
        return self._get_field("owner", Address)

    def _get_qualified_reference(self, label: str, t: ZapperType, contract_containing_label: Type['Contract'] = None):
        if contract_containing_label is None:
            contract_containing_label = self.expression_type

        t = zapper_type_to_assembly_type(t)
        contract_containing_label = zapper_type_to_assembly_type(contract_containing_label)

        r = QualifiedReference(contract_containing_label, label, t)
        return r

    def _return_observer(self, register: Register, zapper_type: ZapperType):
        return AssemblyEmitterObserver(register, zapper_type, self.builder)

    def _binary_operator(self, other, op: BinaryOperator):
        other = self._wrap(other)
        ret = self.builder.next_register(op.name)
        instruction = BinaryOperationInstruction(op, ret, self.value, other.value)
        self.builder.append(instruction)

        ret = self._return_observer(ret, Uint)
        return ret

    def _wrap(self, value):
        return ensure_expression_observer(value, self.builder)

    ###############
    # EXPRESSIONS #
    ###############

    def __add__(self, other):
        # self + other
        return self._binary_operator(other, BinaryOperator.PLUS)

    def __radd__(self, other):
        # other + self
        return self + other

    def __sub__(self, other):
        # self - other
        return self._binary_operator(other, BinaryOperator.MINUS)

    def __rsub__(self, other):
        # other - self
        return self._wrap(other) - self

    def __mul__(self, other):
        # self * other
        return self._binary_operator(other, BinaryOperator.MULTIPLY)

    def __rmul__(self, other):
        # other * self
        return self * other

    def __eq__(self, other):
        # self == other
        return self._binary_operator(other, BinaryOperator.EQUALS)

    def __lt__(self, other):
        # self < other
        return self._binary_operator(other, BinaryOperator.LESS)

    def __gt__(self, other):
        # self > other
        return self._wrap(other) < self

    # definitions in terms of others

    def __invert__(self):
        return 1 - self

    def __and__(self, other):
        return self * other

    def __or__(self, other):
        return (self + other) - (self * other)

    def __ne__(self, other):
        eq = self == other
        return ~eq

    def __le__(self, other):
        # self <= other
        return (self < other) | (self == other)

    def __ge__(self, other):
        return (self > other) | (self == other)


def ensure_expression_observer(value, builder: InstructionBuilder = None):
    if isinstance(value, AssemblyEmitterObserver):
        return value
    elif isinstance(value, AddressConst):
        value = Constant(value.val, Address)
        e = AssemblyEmitterObserver(value, Address, builder)
        return e
    elif isinstance(value, LongConst):
        value = Constant(value.val, Long)
        e = AssemblyEmitterObserver(value, Long, builder)
        return e
    else:
        assert isinstance(value, int)
        # int literals are always treated as Uint (not Long or Address)
        assert is_uint_literal(value)
        value = Constant(value, Uint)
        e = AssemblyEmitterObserver(value, Uint, builder)
        return e
