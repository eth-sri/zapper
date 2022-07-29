from dataclasses import dataclass

from zapper.assembly.types import AssemblyType, check_assembly_type


@dataclass
class QualifiedReference:
    qualified_class_name: str
    name: str
    field_type: AssemblyType

    def __post_init__(self):
        assert isinstance(self.qualified_class_name, str)
        assert isinstance(self.name, str)
        check_assembly_type(self.field_type)
