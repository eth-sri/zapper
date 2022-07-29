from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from zapper.assembly.types import AssemblyType, is_assembly_type, assembly_type_to_str

if TYPE_CHECKING:
    from zapper.assembly.assembly_class import AssemblyClass


@dataclass
class AssemblyField:

    field_name: str
    field_type: AssemblyType
    assembly_class: 'AssemblyClass' = None
    location: int = None

    def __post_init__(self):
        assert isinstance(self.field_name, str)
        assert is_assembly_type(self.field_type)
        from zapper.assembly.assembly_class import AssemblyClass
        assert isinstance(self.assembly_class, Optional[AssemblyClass])
        assert isinstance(self.location, Optional[int])

    def __str__(self):
        return assembly_type_to_str(self.field_type) + ' ' + self.field_name
