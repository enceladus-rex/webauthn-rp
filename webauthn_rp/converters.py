import json
import base64
from enum import Enum
from functools import singledispatch
from typing import Any, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
  EllipticCurvePublicNumbers,
  SECP256R1,
  SECP384R1,
  SECP521R1,
)

from .types import (
  CredentialPublicKey,
  PublicKey,
  PublicKeyCredential,
  EC2CredentialPublicKey,
)

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


@singledispatch
def cryptography_public_key(
    credential_public_key: CredentialPublicKey) -> PublicKey:
  raise UnimplementedError('Must implement public key conversion')


@cryptography_public_key.register(EC2CredentialPublicKey)
def cryptography_ec2_public_key(
    credential_public_key: EC2CredentialPublicKey) -> PublicKey:
  x = int.from_bytes(credential_public_key.x, 'big')
  y = int.from_bytes(credential_public_key.y, 'big')
  
  curve = None
  if credential_public_key.crv.name == 'P_256': curve = SECP256R1()
  elif credential_public_key.crv.name == 'P_384': curve = SECP384R1()
  elif credential_public_key.crv.name == 'P_521': curve = SECP521R1()
  else:
    raise UnimplementedError('Unsupported cryptography EC2 curve {}'.format(
      credential_public_key.crv.name
    ))
  
  print('EC2 public key', x, y, curve)
  ecpn = EllipticCurvePublicNumbers(x, y, curve)
  return ecpn.public_key(default_backend())