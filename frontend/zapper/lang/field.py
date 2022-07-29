from dataclasses import dataclass
from typing import Type, TYPE_CHECKING, get_type_hints

from zapper.utils.inspection import get_and_resolve_type_hints

if TYPE_CHECKING:
    from zapper.lang.contract import Contract
    from zapper.lang.types import ZapperType


@dataclass
class Field:
    """
    Attributes:
        contract_type: the type of the contract holding the field
        name: the name of the field
        zapper_type: the type of the field
    """
    contract_type: Type['Contract']
    name: str
    zapper_type: 'ZapperType'

    def __post_init__(self):
        from zapper.lang.contract import Contract
        from zapper.lang.types import is_zapper_type

        assert issubclass(self.contract_type, Contract)
        assert isinstance(self.name, str)
        assert is_zapper_type(self.zapper_type)


def extract_field(cls: Type, name: str):
    t = get_and_resolve_type_hints(cls, cls)[name]
    f = Field(cls, name, t)
    return f
