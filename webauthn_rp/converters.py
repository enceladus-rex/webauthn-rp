import base64
import json
from enum import Enum
from functools import singledispatch
from typing import Any, Union

import cbor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import \
    SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import \
    SECP384R1
from cryptography.hazmat.primitives.asymmetric.ec import \
    SECP521R1
from cryptography.hazmat.primitives.asymmetric.ec import \
    EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.ed448 import \
    Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
    Ed25519PublicKey

from .errors import UnimplementedError, ValidationError
from .types import (CredentialPublicKey, EC2CredentialPublicKey,
                    OKPCredentialPublicKey, PublicKey, PublicKeyCredential)
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

    return {(snake_to_camel_case(k) if convert_case else k):
            jsonify(v, convert_case)
            for k, v in (data.items()) if v is not None}
  elif type(data) is bytes:
    return base64.b64encode(data).decode('utf-8')
  elif type(data) in (str, int, float, bool):
    return data
  elif type(data) in (list, tuple):
    return [jsonify(x, convert_case) for x in data]
  else:
    raise UnimplementedError('JSON conversion for given data is not supported')


@singledispatch
def cryptography_public_key(credential_public_key: CredentialPublicKey
                            ) -> PublicKey:
  raise UnimplementedError('Must implement public key conversion')


@cryptography_public_key.register(EC2CredentialPublicKey)
def cryptography_ec2_public_key(credential_public_key: EC2CredentialPublicKey
                                ) -> PublicKey:
  x = int.from_bytes(credential_public_key.x, 'big')
  y = int.from_bytes(credential_public_key.y, 'big')

  curve = None
  if credential_public_key.crv.name == 'P_256': curve = SECP256R1()
  elif credential_public_key.crv.name == 'P_384': curve = SECP384R1()
  elif credential_public_key.crv.name == 'P_521': curve = SECP521R1()
  else:
    raise UnimplementedError('Unsupported cryptography EC2 curve {}'.format(
        credential_public_key.crv.name))

  ecpn = EllipticCurvePublicNumbers(x, y, curve)
  return ecpn.public_key(default_backend())


@cryptography_public_key.register(OKPCredentialPublicKey)
def cryptography_okp_public_key(credential_public_key: OKPCredentialPublicKey
                                ) -> PublicKey:
  if credential_public_key.crv.name == 'ED25519':
    return Ed25519PublicKey.from_public_bytes(credential_public_key.x)
  elif credential_public_key.crv.name == 'ED448':
    return Ed448PublicKey.from_public_bytes(credential_public_key.x)
  else:
    raise UnimplementedError('Unsupported cryptography OKP curve {}'.format(
        credential_public_key.crv.name))


def build_base_cose_dictionary(credential_public_key: CredentialPublicKey
                               ) -> dict:
  d = {}
  d[1] = credential_public_key.kty.value
  if credential_public_key.kid is not None:
    d[2] = credential_public_key.kid
  assert credential_public_key.alg is not None
  d[3] = credential_public_key.alg.value
  if credential_public_key.key_ops is not None:
    d[4] = [x.value for x in credential_public_key.key_ops]
  if credential_public_key.key_ops is not None:
    d[5] = credential_public_key.base_IV
  return d


@singledispatch
def cose_key(credential_public_key: CredentialPublicKey) -> bytes:
  raise UnimplementedError('Must implement cose key conversion')


@cose_key.register(EC2CredentialPublicKey)
def cose_key_from_ec2(credential_public_key: EC2CredentialPublicKey) -> bytes:
  d = build_base_cose_dictionary(credential_public_key)
  d[-1] = credential_public_key.crv.value
  d[-2] = credential_public_key.x
  d[-3] = credential_public_key.y
  return cbor.dumps(d)


@cose_key.register(OKPCredentialPublicKey)
def cose_key_from_okp(credential_public_key: OKPCredentialPublicKey) -> bytes:
  d = build_base_cose_dictionary(credential_public_key)
  d[-1] = credential_public_key.crv.value
  d[-2] = credential_public_key.x
  return cbor.dumps(d)
