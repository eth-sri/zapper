import itertools
import textwrap
from dataclasses import dataclass, field as dataclass_field
from typing import Dict, TYPE_CHECKING, List

from zapper.assembly.security import AssemblySecurityException
from zapper.compiler.register_allocation import register_allocation
from zapper.utils.general import order_dictionary_by_keys

if TYPE_CHECKING:
    from zapper.assembly.fields import AssemblyField
    from zapper.assembly.functions import AssemblyFunction
    from zapper.assembly.assembly_storage import AssemblyStorage
    from zapper.assembly.values import Register


@dataclass
class AssemblyClass:

    qualified_name: str
    has_address: bool
    fields: Dict[str, 'AssemblyField'] = dataclass_field(default_factory=dict)
    functions: Dict[str, 'AssemblyFunction'] = dataclass_field(default_factory=dict)
    class_id: int = None

    ######################
    # FIELDS & FUNCTIONS #
    ######################

    def add_field(self, field: 'AssemblyField'):
        if field.assembly_class is not None and field.assembly_class != self:
            msg = f'Tried adding field {field.field_name} with incorrect class {field.assembly_class.qualified_name} to {self.qualified_name}'
            raise AssemblySecurityException(msg)
        if field.field_name in self.fields:
            raise AssemblySecurityException(f'Tried adding field {field.field_name} to {self.qualified_name} twice')

        field.assembly_class = self
        self.fields[field.field_name] = field

        self.set_field_locations()

    def get_field(self, field_name: str):
        return self.fields[field_name]

    def add_function(self, function: 'AssemblyFunction'):
        if function.assembly_class is not None and function.assembly_class != self:
            msg = f'Tried adding function {function.function_name} with incorrect class {function.assembly_class.qualified_name} to {self.qualified_name}'
            raise AssemblySecurityException(msg)
        if function.function_name in self.functions:
            raise AssemblySecurityException(f'Tried adding function {function.function_name} to {self.qualified_name} twice')

        function.assembly_class = self
        self.functions[function.function_name] = function

    def get_function(self, function_name: str):
        return self.functions[function_name]

    ###########
    # LINKING #
    ###########

    def link(self, assembly_storage: 'AssemblyStorage'):
        for f in self.functions.values():
            f.link(assembly_storage)

    ##########
    # CHECKS #
    ##########

    def infer_and_check_types(self, allow_type_change=False):
        for f in self.functions.values():
            f.infer_and_check_types(allow_type_change=allow_type_change)

    def check_access_policy(self, assembly_storage: 'AssemblyStorage'):
        for f in self.functions.values():
            f.check_access_policy(assembly_storage)

    def check_register_labels(self):
        for f in self.functions.values():
            f.check_register_labels()

    def check_constructors(self):
        for f in self.functions.values():
            f.check_constructor()

    def insert_runtime_checks(self, class_to_id: Dict[str, int]):
        for f in self.functions.values():
            f.insert_runtime_checks(class_to_id)

    ###############
    # COMPILATION #
    ###############

    def inline_function(self, assembly_storage: 'AssemblyStorage', function_name: str):
        prev_function = self.functions[function_name]
        self.functions[function_name] = prev_function.inline(assembly_storage)

    def set_field_locations(self):
        ordered_fields = order_dictionary_by_keys(self.fields)
        if 'owner' in ordered_fields:
            # ensure owner is first field
            ordered_fields.move_to_end('owner', last=False)
        for location, (name, assembly_field) in enumerate(ordered_fields.items()):
            assembly_field.location = location

    def register_allocation(self):
        for f in self.functions.values():
            register_allocation(f)

    ###########
    # HELPERS #
    ###########

    def get_registers(self) -> List['Register']:
        all_registers = list(itertools.chain(*[f.get_registers() for f in self.functions.values()]))
        return all_registers

    def __str__(self):
        ret = 'class ' + self.qualified_name + ':\n'
        ret += '\n'.join(['    ' + str(f) for f in self.fields.values()])
        ret += '\n\n'
        ret += '\n\n'.join([textwrap.indent(str(f), prefix='    ') for f in self.functions.values()])
        return ret
