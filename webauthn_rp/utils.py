import base64
import re
from typing import TYPE_CHECKING, Union

from cryptography.hazmat.primitives.hashes import (SHA256, SHA384, SHA512,
                                                   HashAlgorithm)

from webauthn_rp.constants import (ED448_COORDINATE_BYTE_LENGTH,
                                   ED25519_COORDINATE_BYTE_LENGTH,
                                   P_256_COORDINATE_BYTE_LENGTH,
                                   P_384_COORDINATE_BYTE_LENGTH,
                                   P_521_COORDINATE_BYTE_LENGTH)

if TYPE_CHECKING:
    from webauthn_rp import types

__all__ = [
    'snake_to_camel_case',
    'camel_to_snake_case',
    'url_base64_encode',
    'url_base64_decode',
    'curve_coordinate_byte_length',
    'ec2_hash_algorithm',
]

_CURVE_COORDINATE_BYTE_LENGTHS = {
    'P_256': P_256_COORDINATE_BYTE_LENGTH,
    'P_384': P_384_COORDINATE_BYTE_LENGTH,
    'P_521': P_521_COORDINATE_BYTE_LENGTH,
    'ED25519': ED25519_COORDINATE_BYTE_LENGTH,
    'ED448': ED448_COORDINATE_BYTE_LENGTH,
}

_EC2_HASH_ALGORITHMS = {
    'ES256': SHA256,
    'ES384': SHA384,
    'ES512': SHA512,
}


def snake_to_camel_case(s: str) -> str:
    """Convert a snake cased string into camel case.

    Args:
      s (str): A snake cased string.

    Returns:
      The camel case converted string.
    """
    chunks = [x for x in re.split(r'_+', s) if x]
    capped = [x[0].upper() + x[1:] for x in chunks[1:]]
    if chunks:
        return chunks[0] + ''.join(capped)
    return ''


def camel_to_snake_case(s: str) -> str:
    """Convert a camel cased string into snake case.

    Args:
      s (str): A camel cased string.

    Returns:
      The snake case converted string.
    """
    words = []
    s_index = 0
    for i in range(len(s)):
        if s[i].isupper():
            words.append(s[s_index:i].lower())
            s_index = i
    if s_index < len(s): words.append(s[s_index:].lower())
    return '_'.join(words)


def url_base64_encode(b: bytes) -> bytes:
    """Base64 encode raw bytes using URL semantics.

    Args:
      b (bytes): The raw bytes to encode.

    Returns:
      The base64-encoded bytes.

    References:
      * https://tools.ietf.org/html/rfc4648#section-5
    """
    return base64.b64encode(b, b'-_')


def url_base64_decode(s: str) -> bytes:
    """Base64 decode a string using URL semantics.

    Args:
      s (str): The string to decode.

    Returns:
      The base64-decoded bytes.

    References:
      * https://tools.ietf.org/html/rfc4648#section-5
    """
    return base64.b64decode(s + '===', b'-_')


def curve_coordinate_byte_length(
    crv: Union['types.EC2Curve.Name', 'types.EC2Curve.Value',
               'types.OKPCurve.Name', 'types.OKPCurve.Value']
) -> int:
    """Get the fixed number of bytes that an elliptic curve coordinate takes.

    Args:
      crv (Union['types.EC2Curve.Name', 'types.EC2Curve.Value',
        'types.OKPCurve.Name', 'types.OKPCurve.Value']): The elliptic curve.

    Returns:
      The byte length.
    """
    assert crv.name in _CURVE_COORDINATE_BYTE_LENGTHS, 'Unexpected curve'
    return _CURVE_COORDINATE_BYTE_LENGTHS[crv.name]


def ec2_hash_algorithm(
    alg: Union['types.COSEAlgorithmIdentifier.Name',
               'types.COSEAlgorithmIdentifier.Value']
) -> HashAlgorithm:
    """Get a `HashAlgorithm` instance from an algorithm identifier.

    Args:
      alg (Union['types.COSEAlgorithmIdentifier.Name',
        'types.COSEAlgorithmIdentifier.Value']): A cryptography `HashAlgorithm`
        instance for the given algorithm.

    Returns:
      A `HashAlgorithm` instance.
    """
    assert alg.name in _EC2_HASH_ALGORITHMS, 'Invalid COSE algorithm'
    return _EC2_HASH_ALGORITHMS[alg.name]()
