import json
import base64
from enum import Enum
from functools import singledispatch
from typing import Any, Union

from .errors import UnimplementedError, ValidationError
from .utils import snake_to_camel_case


JSONValue = Union[dict, list, bool, int, float, str]


@singledispatch
def jsonify(data: Any, convert_case: bool = True) -> JSONValue:
  if not isinstance(data, Enum) and hasattr(data, '__dict__'):
    data = data.__dict__

  if isinstance(data, Enum):
    return jsonify(data.value, convert_case)
  elif type(data) is dict:
    for k in data:
      if type(k) is not str:
        raise ValidationError('The type of dict keys must be a string in JSON')

    return {
      (snake_to_camel_case(k) if convert_case else k): jsonify(
        v, convert_case) for k, v in (
          data.items()) if v is not None
    }
  elif type(data) is bytes:
    return list(data)
  elif type(data) in (str, int, float, bool):
    return data
  elif type(data) in (list, tuple):
    return [jsonify(x, convert_case) for x in data]
  else:
    raise UnimplementedError(
      'JSON conversion for given data is not supported')