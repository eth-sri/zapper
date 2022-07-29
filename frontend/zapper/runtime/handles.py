from typing import TYPE_CHECKING, Dict, Optional

from zapper.lang.contract import Contract
from zapper.lang.types import ZapperType, is_reference
from zapper.utils.inspection import get_qualified_name

if TYPE_CHECKING:
    from zapper.runtime.runtime import Runtime


class FunctionHandle:
    def __init__(self,
                 runtime: 'Runtime',
                 class_name: str,
                 function_name: str,
                 argument_types: Dict[str, ZapperType],
                 return_obj_class: Optional[Contract],
                 receiver_object_id: Optional[int]):
        self._hdl_runtime = runtime
        self._hdl_argument_types = argument_types
        self._hdl_return_obj_class = return_obj_class
        self._hdl_class_name = class_name
        self._hdl_function_name = function_name
        self._hdl_receiver_object_id = receiver_object_id

    def __call__(self, *args, **kwargs):
        if "sender" not in kwargs:
            raise AssertionError("Expected named argument 'sender'")
        if len(args) != len(self._hdl_argument_types):
            raise AssertionError(f"Expected {len(self._hdl_argument_types)} positional arguments, but got {len(args)}")
        sender_account = kwargs["sender"]
        arguments = list(args) if self._hdl_receiver_object_id is None else [self._hdl_receiver_object_id] + list(args)
        for i in range(0, len(arguments)):
            # unwrap object ids
            if isinstance(arguments[i], ObjectHandle):
                arguments[i] = arguments[i]._hdl_object_id
        ret = self._hdl_runtime.call_function(self._hdl_class_name, self._hdl_function_name, sender_account, arguments)
        if self._hdl_return_obj_class is None:
            return ret
        else:
            return ObjectHandle(self._hdl_runtime, self._hdl_return_obj_class, ret)


class ObjectHandle:
    def __init__(self, runtime: 'Runtime', clazz: Contract, object_id: int):
        self._hdl_runtime = runtime
        self._hdl_class = clazz
        self._hdl_class_name = get_qualified_name(clazz)
        self._hdl_object_id = object_id

    def __getattr__(self, item):
        if item.startswith("_hdl_"):
            # normal read
            return super().__getattribute__(item)
        elif item in self._hdl_class.zapper_functions:
            f = self._hdl_class.zapper_functions[item]
            if f.is_constructor:
                raise AttributeError(f"Cannot call constructor function '{item}' on object handle (use class handle instead)")
            if f.is_private:
                raise AttributeError(f"Member {item} of {self._hdl_class_name} is private")
            if is_reference(f.return_type):
                return_obj_class = f.return_type
            else:
                return_obj_class = None
            # remove self from argument types
            argument_types = f.argument_types.copy()
            del argument_types["self"]
            return FunctionHandle(self._hdl_runtime, self._hdl_class_name, item, argument_types, return_obj_class, self._hdl_object_id)
        elif item == "address":
            return int(self._hdl_runtime.get_raw_state(self._hdl_object_id).addr_object, 16)
        elif item in self._hdl_class.zapper_fields:
            fields = self._hdl_runtime.get_field_values(self._hdl_object_id)
            field_type = self._hdl_class.zapper_fields[item].zapper_type
            if is_reference(field_type):
                return ObjectHandle(self._hdl_runtime, field_type, fields[item])
            return fields[item]
        else:
            raise AttributeError(f"Class {self._hdl_class_name} does not have member {item}")


class ClassHandle:
    def __init__(self, runtime: 'Runtime', clazz: Contract):
        assert(issubclass(clazz, Contract))
        self._hdl_runtime = runtime
        self._hdl_class = clazz
        self._hdl_class_name = get_qualified_name(clazz)

    def __getattr__(self, item):
        if item.startswith("_hdl_"):
            # normal read
            return super().__getattribute__(item)
        elif item in self._hdl_class.zapper_functions:
            f = self._hdl_class.zapper_functions[item]
            if not f.is_constructor:
                raise AttributeError(f"Member {item} is not a constructor function of {self._hdl_class_name}")
            if f.is_private:
                raise AttributeError(f"Member {item} of {self._hdl_class_name} is private")
            # remove self from argument types
            argument_types = f.argument_types.copy()
            del argument_types["self"]
            return FunctionHandle(self._hdl_runtime, self._hdl_class_name, item, argument_types, self._hdl_class, None)
        else:
            raise AttributeError(f"Class {self._hdl_class_name} does not have member {item}")
