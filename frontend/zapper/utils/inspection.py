import functools
import inspect
from typing import Type, get_type_hints, List, Dict


def get_and_resolve_type_hints(cls: Type, item) -> Dict[str, Type]:
    annotations = getattr(item, '__annotations__', None)
    types = {}
    for t in annotations:
        if isinstance(annotations[t], str):
            # try to resolve references of the class to itself
            if cls.__name__ == annotations[t]:
                types[t] = cls
                continue
            # TODO: add support for circular type hints beyond self
        types[t] = annotations[t]
    return types


def get_member_names_no_superclass(cls: Type, include_fields: bool, include_functions: bool) -> List['str']:
    """
    Returns: All non-internal functions and field names on this class, excluding items defined in its superclass.
    """
    members = []
    dct = cls.__dict__
    if include_functions:
        members = members + [c for c in dct if not c.startswith('__') and not c.endswith('__')]
    if include_fields:
        members = members + [c for c in dct["__annotations__"] if not c.startswith('__') and not c.endswith('__')]
    return members


def extract_argument_from_stack(stack_position: int, argument_position: int, expected_type=object):
    stack = inspect.stack()

    # extract stack frame with respect to caller
    stack_position += 1
    if len(stack) < stack_position:
        return None
    stack_entry = stack[stack_position]

    # extract first argument from stack
    argument_information = inspect.getargvalues(stack_entry.frame)
    argument_names = argument_information.args
    if len(argument_names) <= argument_position:
        return None
    argument = argument_information.locals[argument_names[argument_position]]

    # check type
    if not isinstance(argument, expected_type):
        return None

    return argument


def get_class_that_defined_method(meth):
    # https://stackoverflow.com/questions/3589311/get-defining-class-of-unbound-method-object-in-python-3/25959545#25959545
    if isinstance(meth, functools.partial):
        return get_class_that_defined_method(meth.func)
    if inspect.ismethod(meth) or (inspect.isbuiltin(meth) and getattr(meth, '__self__', None) is not None and getattr(meth.__self__, '__class__', None)):
        for cls in inspect.getmro(meth.__self__.__class__):
            if meth.__name__ in cls.__dict__:
                return cls
        meth = getattr(meth, '__func__', meth)  # fallback to __qualname__ parsing
    if inspect.isfunction(meth):
        cls = getattr(inspect.getmodule(meth),
                      meth.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)[0],
                      None)
        if isinstance(cls, type):
            return cls
    return getattr(meth, '__objclass__', None)  # handle special descriptor objects


def get_qualified_name(klass: Type):
    # https://stackoverflow.com/questions/2020014/get-fully-qualified-class-name-of-an-object-in-python
    module = klass.__module__
    if module == 'builtins':
        return klass.__qualname__  # avoid outputs like 'builtins.str'
    return module + '.' + klass.__qualname__
