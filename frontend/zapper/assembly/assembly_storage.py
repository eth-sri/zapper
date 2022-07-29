import itertools
from typing import Dict, List, TYPE_CHECKING

from zapper.lang.types import Address, is_address
from zapper.utils.general import get_duplicates
from zapper.assembly.security import AssemblySecurityException

if TYPE_CHECKING:
    from zapper.assembly.assembly_class import AssemblyClass


class AssemblyStorage:

    def __init__(self):
        self.assembly_classes: Dict[str, 'AssemblyClass'] = {}
        self.classes_to_check: List['AssemblyClass'] = []
        self.class_to_id: Dict[str, int] = {}
        self._next_class_id = 0

    def add_class(self, c: 'AssemblyClass'):
        if c.qualified_name in self.assembly_classes:
            msg = f'Tried adding class {c.qualified_name} twice'
            raise AssemblySecurityException(msg)

        if 'owner' not in c.fields:
            msg = f'Class {c.qualified_name} does not define an "owner" field'
            raise AssemblySecurityException(msg)
        if not is_address(c.fields['owner'].field_type):
            msg = f'Field "owner" of class {c.qualified_name} does not have address type'
            raise AssemblySecurityException(msg)
        if not c.fields['owner'].location == 0:
            msg = f'Field "owner" of class {c.qualified_name} is not at location 0'
            raise AssemblySecurityException(msg)

        c.class_id = self._next_class_id
        self.class_to_id[c.qualified_name] = c.class_id
        self._next_class_id += 1

        self.assembly_classes[c.qualified_name] = c
        self.classes_to_check.append(c)

    def __getitem__(self, qualified_name: str):
        return self.assembly_classes[qualified_name]

    def link_new_classes(self):
        for c in self.classes_to_check:
            c.link(self)

    def check_new_classes(self):
        for c in self.classes_to_check:
            c.infer_and_check_types(allow_type_change=False)
            c.check_access_policy(self)
            c.check_register_labels()
            c.check_constructors()
            self._check_reused_registers()

    def inline_new_classes(self):
        # find call graph (to select order of inlining and detect recursive calls)
        remaining_callgraph = {}
        classes_to_check_names = [c.qualified_name for c in self.classes_to_check]
        for c in self.classes_to_check:
            for f in c.functions.values():
                remaining_callgraph[(c.qualified_name, f.function_name)] \
                    = [(c, f) for (c, f) in f.get_called_function_names() if c in classes_to_check_names]

        # inline in reverse topological sort order
        while len(remaining_callgraph) > 0:
            found = False
            for (class_name, function_name) in remaining_callgraph:
                if len(remaining_callgraph[(class_name, function_name)]) == 0:
                    # it is safe to inline all child calls of this function
                    self.assembly_classes[class_name].inline_function(self, function_name)

                    # update remaining call graph
                    for other in remaining_callgraph:
                        if (class_name, function_name) in remaining_callgraph[other]:
                            remaining_callgraph[other].remove((class_name, function_name))
                    del remaining_callgraph[(class_name, function_name)]

                    found = True
                    break   # breaks for-loop
            if not found:
                # no call without children found, call graph contains a cycle
                raise AssertionError("detected cycle in call graph, cannot inline")

    def allocation_for_new_classes(self):
        for c in self.classes_to_check:
            c.set_field_locations()
            c.register_allocation()

    def insert_runtime_checks_for_new_classes(self):
        for c in self.classes_to_check:
            c.insert_runtime_checks(self.class_to_id)

    def reset_new_classes(self):
        self.classes_to_check = []

    def _check_reused_registers(self):
        all_registers = list(itertools.chain(*[c.get_registers() for c in self.assembly_classes.values()]))
        duplicates = get_duplicates(all_registers)
        if len(duplicates) > 0:
            raise AssemblySecurityException('Registers are reused across functions: ' + ' '.join(duplicates))
