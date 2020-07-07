import base64
from enum import Enum
from functools import singledispatch
from typing import Any, Dict, Optional, Union

import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, SECP384R1, SECP521R1, EllipticCurvePublicNumbers)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from webauthn_rp.errors import (JSONConversionError, PublicKeyConversionError,
                                UnimplementedError)
from webauthn_rp.types import (CredentialPublicKey, EC2CredentialPublicKey,
                               EC2PublicKey, JSONValue, OKPCredentialPublicKey,
                               OKPPublicKey, PublicKey)
from webauthn_rp.utils import snake_to_camel_case

__all__ = [
    'jsonify',
    'cryptography_public_key',
    'cryptography_ec2_public_key',
    'cryptography_okp_public_key',
    'cose_key',
    'cose_ec2_public_key',
    'cose_okp_public_key',
]


@singledispatch
def jsonify(data: Any, convert_case: bool = True) -> JSONValue:
    """Convert a Python object into a JSON value.

    Args:
      data (Any): The object to convert.
      convert_case (bool): Whether to convert the attribute names of the object
        into camel case from snake case.
      
    Returns:
      A JSONValue.

    Raises:
      JSONConversionError: If the provided data cannot be converted into
        valid JSON.
      UnimplementedError: If the conversion logic for the given data type has
        not been implemented.
    """
    if not isinstance(data, Enum) and hasattr(data, '__dict__'):
        data = data.__dict__

    if isinstance(data, Enum):
        return jsonify(data.value, convert_case)
    elif type(data) is dict:
        for k in data:
            if type(k) is not str:
                raise JSONConversionError(
                    'The type of dict keys must be a string in JSON')

        return {(snake_to_camel_case(k) if convert_case else k):
                jsonify(v, convert_case)
                for k, v in (data.items()) if v is not None}
    elif type(data) is bytes:
        return base64.b64encode(data).decode('ascii')
    elif type(data) in (str, int, float, bool):
        return data
    elif type(data) in (list, tuple):
        return [jsonify(x, convert_case) for x in data]
    elif data is None:
        return None
    else:
        raise UnimplementedError(
            'JSON conversion for given data is not supported')


@singledispatch
def cryptography_public_key(
        credential_public_key: CredentialPublicKey) -> PublicKey:
    """Convert a `CredentialPublicKey` into a cryptography `PublicKey`.

    Args:
      credential_public_key (CredentialPublicKey): The key to convert.

    Returns:
      A cryptography `PublicKey`.

    Raises:
      UnimplementedError: If the conversion logic for the given type of
        `CredentialPublicKey` has not been implemented.
    """
    raise UnimplementedError('Must implement public key conversion')


@cryptography_public_key.register(EC2CredentialPublicKey)
def cryptography_ec2_public_key(
        credential_public_key: EC2CredentialPublicKey) -> EC2PublicKey:
    """Convert an `EC2CredentialPublicKey` into a cryptography `EC2PublicKey`.

    Args:
      credential_public_key (EC2CredentialPublicKey): The key to convert.

    Returns:
      A cryptography `EC2PublicKey`.

    Raises:
      UnimplementedError: If the conversion logic for the given type of
        CredentialPublicKey has not been implemented.
      PublicKeyConversionError: If the provided key could not be converted
        into a valid cryptography `EC2PublicKey`.
    """
    x = int.from_bytes(credential_public_key.x, 'big')
    y = int.from_bytes(credential_public_key.y, 'big')

    curve: Optional[Union[SECP256R1, SECP384R1, SECP521R1]] = None
    if credential_public_key.crv.name == 'P_256': curve = SECP256R1()
    elif credential_public_key.crv.name == 'P_384': curve = SECP384R1()
    elif credential_public_key.crv.name == 'P_521': curve = SECP521R1()
    else:
        raise UnimplementedError(
            'Unsupported cryptography EC2 curve {}'.format(
                credential_public_key.crv.name))

    assert curve is not None

    ecpn = EllipticCurvePublicNumbers(x, y, curve)

    try:
        return ecpn.public_key(default_backend())
    except ValueError:
        raise PublicKeyConversionError('Invalid EC2 public key')


@cryptography_public_key.register(OKPCredentialPublicKey)
def cryptography_okp_public_key(
        credential_public_key: OKPCredentialPublicKey) -> OKPPublicKey:
    """Convert an `OKPCredentialPublicKey` into a cryptography `OKPPublicKey`.

    Args:
      credential_public_key (EC2CredentialPublicKey): The key to convert.

    Returns:
      A cryptography `EC2PublicKey`.

    Raises:
      UnimplementedError: If the conversion logic for the given type of
        CredentialPublicKey has not been implemented.
      PublicKeyConversionError: If the provided key could not be converted
        into a valid cryptography `EC2PublicKey`.
    """
    try:
        if credential_public_key.crv.name == 'ED25519':
            return Ed25519PublicKey.from_public_bytes(credential_public_key.x)
        elif credential_public_key.crv.name == 'ED448':
            return Ed448PublicKey.from_public_bytes(credential_public_key.x)
        else:
            raise UnimplementedError(
                'Unsupported cryptography OKP curve {}'.format(
                    credential_public_key.crv.name))
    except ValueError:
        raise PublicKeyConversionError('Invalid OKP public key')


def _build_base_cose_dictionary(
        credential_public_key: CredentialPublicKey) -> Dict:
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
    """Convert a `CredentialPublicKey` into a COSE key.

    Args:
      credential_public_key (CredentialPublicKey): The key to convert.

    Returns:
      The COSE-encoded key bytes.
    """
    raise UnimplementedError('Must implement cose key conversion')


@cose_key.register(EC2CredentialPublicKey)
def cose_ec2_public_key(
        credential_public_key: EC2CredentialPublicKey) -> bytes:
    """Convert an `EC2CredentialPublicKey` into a COSE key.

    Args:
      credential_public_key (EC2CredentialPublicKey): The key to convert.

    Returns:
      The COSE-encoded key bytes.
    """
    d = _build_base_cose_dictionary(credential_public_key)
    d[-1] = credential_public_key.crv.value
    d[-2] = credential_public_key.x
    d[-3] = credential_public_key.y
    return cbor2.dumps(d)


@cose_key.register(OKPCredentialPublicKey)
def cose_okp_public_key(
        credential_public_key: OKPCredentialPublicKey) -> bytes:
    """Convert an `OKPCredentialPublicKey` into a COSE key.

    Args:
      credential_public_key (OKPCredentialPublicKey): The key to convert.

    Returns:
      The COSE-encoded key bytes.
    """
    d = _build_base_cose_dictionary(credential_public_key)
    d[-1] = credential_public_key.crv.value
    d[-2] = credential_public_key.x
    return cbor2.dumps(d)
