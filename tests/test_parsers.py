import base64
from itertools import chain, combinations

import cbor2
import pytest

from webauthn_rp.constants import *
from webauthn_rp.errors import DecodingError, ParserError, TokenBindingError
from webauthn_rp.parsers import *
from webauthn_rp.types import *

from .common import (assert_objects_equal, attested_credential_data,
                     authenticator_data, json_bytes)


@pytest.mark.parametrize(
    'field_key, valid_types, dictionary, required, expected', [
        ('key', [int], dict(key=1, a=1), True, 1),
        ('key', [str], dict(key='val'), True, 'val'),
        ('key', [int, str], dict(key=1), True, 1),
        ('key', [int, str], dict(key='val'), True, 'val'),
        ('key', [int], dict(key=1, a=1), False, 1),
        ('key', [str], dict(key='val'), False, 'val'),
        ('key', [int, str], dict(key=1), False, 1),
        ('key', [int, str], dict(key='val'), False, 'val'),
        ('key', [int], dict(), False, None),
        ('key', [], dict(), False, None),
        ('key', [], dict(a=1), False, None),
    ])
def test_parse_dictionary_field_success(field_key, valid_types, dictionary,
                                        required, expected):
  parse_dictionary_field(field_key, valid_types, dictionary,
                         required) == expected


@pytest.mark.parametrize('field_key, valid_types, dictionary, required', [
    ('key', [int], dict(a=1), True),
    ('key', [str], dict(a='val'), True),
    ('key', [int, str], dict(a=1), True),
    ('key', [int, str], dict(a='val'), True),
    ('key', [str], dict(key=1, a=1), True),
    ('key', [int], dict(key='val'), True),
    ('key', [bytes, str], dict(key=1), True),
    ('key', [int, bytes], dict(key='val'), True),
    ('key', [str], dict(key=1, a=1), False),
    ('key', [int], dict(key='val'), False),
    ('key', [bytes, str], dict(key=1), False),
    ('key', [int, bytes], dict(key='val'), False),
])
def test_parse_dictionary_field_error(field_key, valid_types, dictionary,
                                      required):
  with pytest.raises(ParserError):
    parse_dictionary_field(field_key, valid_types, dictionary, required)


@pytest.mark.parametrize('supported, data, valid', [
    ({'a', 'b'}, dict(a=1), True),
    ({'a', 'b'}, dict(b=1), True),
    ({'a', 'b'}, dict(a=1, b=2), True),
    ({'a', 'b'}, dict(), True),
    ({'a', 'b'}, dict(c=1), False),
    ({'a', 'b'}, dict(a=1, c=1), False),
    ({'a', 'b'}, dict(a=1, b=1, c=1), False),
])
def test_check_unsupported_keys(supported, data, valid):
  if valid:
    check_unsupported_keys(supported, data)
  else:
    with pytest.raises(ParserError):
      check_unsupported_keys(supported, data)


@pytest.mark.parametrize('data, expected', [
    ('abcdef==', b'i\xb7\x1dy'),
    (base64.b64encode(b'!@#$%^&*()-+').decode('utf-8'), b'!@#$%^&*()-+'),
])
def test_bytes_from_base64_success(data, expected):
  assert bytes_from_base64(data) == expected


@pytest.mark.parametrize('data', [
    'abcdef=',
    b'!@#$%^&*()-+',
])
def test_bytes_from_base64_error(data):
  with pytest.raises(ParserError):
    bytes_from_base64(data)


def _b64s(x: bytes) -> str:
  return base64.b64encode(x).decode('utf-8')


@pytest.mark.parametrize('data, expected', [
    (dict(id='a',
          rawId=_b64s(b'b'),
          type='c',
          response=dict(clientDataJSON=_b64s(b'e'),
                        attestationObject=_b64s(b'f'))),
     PublicKeyCredential(id='a',
                         raw_id=b'b',
                         type='c',
                         response=AuthenticatorAttestationResponse(
                             client_data_JSON=b'e', attestation_object=b'f'))),
    (dict(id='a',
          rawId=_b64s(b'b'),
          type='c',
          response=dict(clientDataJSON=_b64s(b'e'),
                        authenticatorData=_b64s(b'f'),
                        signature=_b64s(b'g'),
                        userHandle=_b64s(b'h'))),
     PublicKeyCredential(id='a',
                         raw_id=b'b',
                         type='c',
                         response=AuthenticatorAssertionResponse(
                             client_data_JSON=b'e',
                             authenticator_data=b'f',
                             signature=b'g',
                             user_handle=b'h'))),
])
def test_parse_public_key_credential_success(data, expected):
  pkc = parse_public_key_credential(data)
  assert_objects_equal(pkc, expected)


@pytest.mark.parametrize('data', [
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         x=1,
         response=dict(clientDataJSON=_b64s(b'e'),
                       attestationObject=_b64s(b'f'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(
             x=1, clientDataJSON=_b64s(b'e'), attestationObject=_b64s(b'f'))),
    dict(id=1,
         rawId=_b64s(b'b'),
         type='c',
         x=1,
         response=dict(clientDataJSON=_b64s(b'e'),
                       attestationObject=_b64s(b'f'))),
    dict(id='a',
         rawId=b'a',
         type='c',
         response=dict(clientDataJSON=_b64s(b'e'),
                       attestationObject=_b64s(b'f'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type=b'c',
         response=dict(clientDataJSON=_b64s(b'e'),
                       attestationObject=_b64s(b'f'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(clientDataJSON=1., attestationObject=_b64s(b'f'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(clientDataJSON=_b64s(b'e'), attestationObject=[])),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         y='a',
         response=dict(clientDataJSON=_b64s(b'e'),
                       authenticatorData=_b64s(b'f'),
                       signature=_b64s(b'g'),
                       userHandle=_b64s(b'h'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(y='a',
                       clientDataJSON=_b64s(b'e'),
                       authenticatorData=_b64s(b'f'),
                       signature=_b64s(b'g'),
                       userHandle=_b64s(b'h'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(clientDataJSON=1.,
                       authenticatorData=_b64s(b'f'),
                       signature=_b64s(b'g'),
                       userHandle=_b64s(b'h'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(clientDataJSON=_b64s(b'e'),
                       authenticatorData=2,
                       signature=_b64s(b'g'),
                       userHandle=_b64s(b'h'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(clientDataJSON=_b64s(b'e'),
                       authenticatorData=_b64s(b'f'),
                       signature=b'3',
                       userHandle=_b64s(b'h'))),
    dict(id='a',
         rawId=_b64s(b'b'),
         type='c',
         response=dict(clientDataJSON=_b64s(b'e'),
                       authenticatorData=_b64s(b'f'),
                       signature=_b64s(b'g'),
                       userHandle=4)),
])
def test_parse_public_key_credential_error(data):
  with pytest.raises(ParserError):
    parse_public_key_credential(data)


@pytest.mark.parametrize('data, expected', [({
    1: x.value
}, x) for x in list(COSEKeyType.Name) + list(COSEKeyType.Value)])
def test_parse_credential_public_key_kty_success(data, expected):
  assert parse_credential_public_key_kty(data) == expected


@pytest.mark.parametrize('data', [{
    1: x
} for x in (-1, -2, '_invalid', '1')] + [
    {},
    {
        2: 1
    },
    {
        2: ''
    },
])
def test_parse_credential_public_key_kty_error(data):
  with pytest.raises(ParserError):
    parse_credential_public_key_kty(data)


@pytest.mark.parametrize('data, expected', [
    ({3: x.value}, x) for x in \
    list(COSEAlgorithmIdentifier.Name) + list(COSEAlgorithmIdentifier.Value)
])
def test_parse_credential_public_key_alg_success(data, expected):
  assert parse_credential_public_key_alg(data) == expected


@pytest.mark.parametrize('data', [{
    3: x
} for x in (-1, -2, '_invalid', '1')] + [
    {},
    {
        2: 1
    },
    {
        2: ''
    },
])
def test_parse_credential_public_key_alg_error(data):
  with pytest.raises(ParserError):
    parse_credential_public_key_alg(data)


@pytest.mark.parametrize('data, expected', [({
    4: x
}, z) for x, z in [
    ([y.value
      for y in COSEKeyOperation.Name], [y for y in COSEKeyOperation.Name]),
    ([y.value
      for y in COSEKeyOperation.Value], [y for y in COSEKeyOperation.Value]),
    ([y.value for y in chain(COSEKeyOperation.Name, COSEKeyOperation.Value)],
     [y for y in chain(COSEKeyOperation.Name, COSEKeyOperation.Value)]),
]] + [({}, None)])
def test_parse_credential_public_key_key_ops_success(data, expected):
  assert parse_credential_public_key_key_ops(data) == expected


@pytest.mark.parametrize('data', [{
    4: x
} for x in (
    -1,
    -2,
    '_invalid',
    '1',
    ['x'],
    [-1],
    [COSEKeyOperation.Name.DECRYPT.value, 'y'],
)] + [{
    4: []
}])
def test_parse_credential_public_key_key_ops_error(data):
  with pytest.raises(ParserError):
    parse_credential_public_key_key_ops(data)


@pytest.mark.parametrize('data, expected', [
    ({
        1: COSEKeyType.Name.EC2.value,
        2: b'key-id',
        3: COSEAlgorithmIdentifier.Name.ES256.value,
        4:
        [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
        5: b'base-IV'
    },
     dict(kty=COSEKeyType.Name.EC2,
          kid=b'key-id',
          alg=COSEAlgorithmIdentifier.Name.ES256,
          key_ops=[COSEKeyOperation.Name.VERIFY, COSEKeyOperation.Name.SIGN],
          base_IV=b'base-IV')),
    ({
        1:
        COSEKeyType.Value.EC2.value,
        2:
        b'key-id',
        3:
        COSEAlgorithmIdentifier.Value.ES256.value,
        4: [
            COSEKeyOperation.Value.VERIFY.value,
            COSEKeyOperation.Value.SIGN.value
        ],
        5:
        b'base-IV'
    },
     dict(kty=COSEKeyType.Value.EC2,
          kid=b'key-id',
          alg=COSEAlgorithmIdentifier.Value.ES256,
          key_ops=[COSEKeyOperation.Value.VERIFY, COSEKeyOperation.Value.SIGN],
          base_IV=b'base-IV')),
])
def test_parse_credential_public_key_kwargs_success(data, expected):
  assert parse_credential_public_key_kwargs(data) == expected


@pytest.mark.parametrize('data', [
    {
        1: 1.0,
        2: b'key-id',
        3: COSEAlgorithmIdentifier.Name.ES256.value,
        4:
        [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
        5: b'base-IV'
    },
    {
        1: COSEKeyType.Name.EC2.value,
        2: 'string',
        3: COSEAlgorithmIdentifier.Name.ES256.value,
        4:
        [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
        5: b'base-IV'
    },
    {
        1: COSEKeyType.Name.EC2.value,
        2: b'key-id',
        3: -1,
        4:
        [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
        5: b'base-IV'
    },
    {
        1:
        COSEKeyType.Name.EC2.value,
        2:
        b'key-id',
        3:
        COSEAlgorithmIdentifier.Name.ES256.value,
        4: [
            b'x', COSEKeyOperation.Name.VERIFY.value,
            COSEKeyOperation.Name.SIGN.value
        ],
        5:
        b'base-IV'
    },
    {
        1: COSEKeyType.Name.EC2.value,
        2: b'key-id',
        3: COSEAlgorithmIdentifier.Name.ES256.value,
        4:
        [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
        5: 'string'
    },
])
def test_parse_credential_public_key_kwargs_error(data):
  with pytest.raises(ParserError):
    parse_credential_public_key_kwargs(data)


@pytest.mark.parametrize('data, expected', [({
    -1: x.value
}, x) for x in chain(EC2Curve.Name, EC2Curve.Value)])
def test_parse_ec2_public_key_crv_success(data, expected):
  assert parse_ec2_public_key_crv(data) == expected


@pytest.mark.parametrize('data', [
    {
        -1: b''
    },
    {
        -1: 1.
    },
    {
        -1: 'x'
    },
    {
        -1: -1
    },
    {},
    {
        2: 1
    },
])
def test_parse_ec2_public_key_crv_error(data):
  with pytest.raises(ParserError):
    parse_ec2_public_key_crv(data)


@pytest.mark.parametrize('data, expected', [({
    -1: x.value
}, x) for x in chain(OKPCurve.Name, OKPCurve.Value)])
def test_parse_okp_public_key_crv_success(data, expected):
  assert parse_okp_public_key_crv(data) == expected


@pytest.mark.parametrize('data', [
    {
        -1: b''
    },
    {
        -1: 1.
    },
    {
        -1: 'x'
    },
    {
        -1: -1
    },
    {},
    {
        2: 1
    },
])
def test_parse_okp_public_key_crv_error(data):
  with pytest.raises(ParserError):
    parse_okp_public_key_crv(data)


@pytest.mark.parametrize('data, expected', [
    ({
        -2:
        b'x' * ED25519_COORDINATE_BYTE_LENGTH,
        -1:
        OKPCurve.Value.ED25519.value,
        1:
        COSEKeyType.Value.OKP.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     OKPCredentialPublicKey(
         kty=COSEKeyType.Value.OKP,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.EDDSA,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * ED25519_COORDINATE_BYTE_LENGTH,
         crv=OKPCurve.Value.ED25519,
     )),
    ({
        -2:
        b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1:
        OKPCurve.Value.ED448.value,
        1:
        COSEKeyType.Value.OKP.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     OKPCredentialPublicKey(
         kty=COSEKeyType.Value.OKP,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.EDDSA,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * ED448_COORDINATE_BYTE_LENGTH,
         crv=OKPCurve.Value.ED448,
     )),
    ({
        -2:
        b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1:
        OKPCurve.Value.ED448.value,
        1:
        COSEKeyType.Value.OKP.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     OKPCredentialPublicKey(
         kty=COSEKeyType.Value.OKP,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.EDDSA,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * ED448_COORDINATE_BYTE_LENGTH,
         crv=OKPCurve.Value.ED448,
     )),
])
def test_parse_okp_public_key_success(data, expected):
  assert_objects_equal(parse_okp_public_key(data), expected)


@pytest.mark.parametrize('data', [
    {
        -2: 'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: 'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: 'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: 'invalid',
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: -1,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: 'invalid',
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [-3],
        5: b'base-IV',
    }, {
        -3: b'y' * P_256_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_256_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_256.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES256.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_384_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_384_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_384.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES384.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_521.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }
])
def test_parse_okp_public_key_error(data):
  with pytest.raises(ParserError):
    parse_okp_public_key(data)


@pytest.mark.parametrize('data, expected', [
    ({
        -3:
        b'y' * P_256_COORDINATE_BYTE_LENGTH,
        -2:
        b'x' * P_256_COORDINATE_BYTE_LENGTH,
        -1:
        EC2Curve.Value.P_256.value,
        1:
        COSEKeyType.Value.EC2.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.ES256.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     EC2CredentialPublicKey(
         kty=COSEKeyType.Value.EC2,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.ES256,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * P_256_COORDINATE_BYTE_LENGTH,
         y=b'y' * P_256_COORDINATE_BYTE_LENGTH,
         crv=EC2Curve.Value.P_256,
     )),
    ({
        -3:
        b'y' * P_384_COORDINATE_BYTE_LENGTH,
        -2:
        b'x' * P_384_COORDINATE_BYTE_LENGTH,
        -1:
        EC2Curve.Value.P_384.value,
        1:
        COSEKeyType.Value.EC2.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.ES384.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     EC2CredentialPublicKey(
         kty=COSEKeyType.Value.EC2,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.ES384,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * P_384_COORDINATE_BYTE_LENGTH,
         y=b'y' * P_384_COORDINATE_BYTE_LENGTH,
         crv=EC2Curve.Value.P_384,
     )),
    ({
        -3:
        b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2:
        b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1:
        EC2Curve.Value.P_521.value,
        1:
        COSEKeyType.Value.EC2.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     EC2CredentialPublicKey(
         kty=COSEKeyType.Value.EC2,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.ES512,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * P_521_COORDINATE_BYTE_LENGTH,
         y=b'y' * P_521_COORDINATE_BYTE_LENGTH,
         crv=EC2Curve.Value.P_521,
     )),
])
def test_parse_ec2_public_key_success(data, expected):
  assert_objects_equal(parse_ec2_public_key(data), expected)


@pytest.mark.parametrize('data', [
    {
        -2: 'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: 'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: 'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: 'invalid',
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: -1,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: 'invalid',
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [-3],
        5: b'base-IV',
    }, {
        -3: 'y' * P_256_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_256_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_256.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES256.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_384_COORDINATE_BYTE_LENGTH,
        -2: 'x' * P_384_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_384.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES384.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1: 'invalid',
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_521.value,
        1: -3,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_521.value,
        1: COSEKeyType.Value.EC2.value,
        2: 'kid',
        3: COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_521.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: 'invalid',
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    }, {
        -3:
        b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2:
        b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1:
        EC2Curve.Value.P_521.value,
        1:
        COSEKeyType.Value.EC2.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            b'x', COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    }, {
        -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
        -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
        -1: EC2Curve.Value.P_521.value,
        1: COSEKeyType.Value.EC2.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.ES512.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: 'base-IV',
    }
])
def test_parse_ec2_public_key_error(data):
  with pytest.raises(ParserError):
    parse_ec2_public_key(data)


@pytest.mark.parametrize(
    'data, expected',
    [
        (dict(), AuthenticationExtensionsClientOutputs()),
    ] + [
        (  # type: ignore
            {
                x[0]: x[-2]  # type: ignore
                for x in c
            },
            AuthenticationExtensionsClientOutputs(**{  # type: ignore
                x[1]: x[-1]  # type: ignore
                for x in c
            })) for c in combinations((
                ('appid', 'appid', True, True),
                ('txAuthSimple', 'tx_auth_simple', 'auth', 'auth'),
                ('txAuthGeneric', 'tx_auth_generic', b'auth', b'auth'),
                ('authnSel', 'authn_sel', True, True),
                ('exts', 'exts', ['appid', 'uvi'], ['appid', 'uvi']),
                ('uvi', 'uvi', b'uvi', b'uvi'),
                ('loc', 'loc', {
                    'latitude': 1,
                    'longitude': 2,
                    'altitude': 3,
                    'accuracy': 4.,
                    'altitudeAccuracy': 5.,
                    'heading': 6.,
                    'speed': 7.,
                },
                 Coordinates(latitude=1,
                             longitude=2,
                             altitude=3,
                             accuracy=4.,
                             altitude_accuracy=5.,
                             heading=6.,
                             speed=7.)),
                ('uvm', 'uvm', [[1, 2, 3], [4, 5, 6]], [[1, 2, 3], [4, 5, 6]]),
                ('biometricPerfBounds', 'biometric_perf_bounds', True, True),
            ), 3)
    ])
def test_parse_extensions_success(data, expected):
  assert_objects_equal(parse_extensions(data), expected)


@pytest.mark.parametrize(
    'data',
    [
        dict(invalid=1),
    ] + [
        {
            x[0]: x[1]  # type: ignore
        } for x in (
            ('appid', 'invalid'),
            ('appid', b'invalid'),
            ('txAuthSimple', b'auth'),
            ('txAuthSimple', 1),
            ('txAuthGeneric', 'auth'),
            ('txAuthGeneric', 1.),
            ('authnSel', 'invalid'),
            ('authnSel', 1),
            ('exts', ['appid', b'uvi']),
            ('exts', [1, 'uvi']),
            ('exts', 'invalid'),
            ('uvi', 'uvi'),
            ('uvi', 1),
            ('loc', {
                'latitude': 'invalid',
                'longitude': 2,
                'altitude': 3,
                'accuracy': 4.,
                'altitudeAccuracy': 5.,
                'heading': 6.,
                'speed': 7.,
            }),
            ('loc', {
                'latitude': 1,
                'longitude': 2,
                'altitude': 3,
                'accuracy': b'invalid',
                'altitudeAccuracy': 5.,
                'heading': 6.,
                'speed': 7.,
            }),
            ('uvm', [['invalid', 2, 3], [4, 5, 6]]),
            ('uvm', [[1, 2., 3], [4, 5, 6]]),
            ('uvm', 'invalid'),
            ('biometricPerfBounds', 'invalid'),
            ('biometricPerfBounds', 1),
        )
    ])
def test_parse_extensions_error(data):
  with pytest.raises(ParserError):
    parse_extensions(data)


@pytest.mark.parametrize('data, expected', [
    ({
        'alg': x.value
    }, x)
    for x in chain(COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value)
])
def test_parse_attestation_statement_alg_success(data, expected):
  assert_objects_equal(parse_attestation_statement_alg(data), expected)


@pytest.mark.parametrize('data', [
    {
        'alg': 'invalid'
    },
    {
        'alg': -1
    },
    {},
])
def test_parse_attestation_statement_alg_error(data):
  with pytest.raises(ParserError):
    parse_attestation_statement_alg(data)


@pytest.mark.parametrize('data, expected', [
    ({
        'x5c': [b'x', b'y'],
    }, [b'x', b'y']),
    ({
        'x5c': (b'x', b'y'),
    }, (b'x', b'y')),
])
def test_parse_attestation_statement_x5c_success(data, expected):
  assert_objects_equal(parse_attestation_statement_x5c(data), expected)


@pytest.mark.parametrize('data', [
    {
        'x5c': 'invalid'
    },
    {
        'x5c': -1
    },
    {
        'x5c': [1]
    },
    {
        'x5c': ['x']
    },
    {
        'x5c': (1, )
    },
    {
        'x5c': ('x', )
    },
    {},
])
def test_parse_attestation_statement_x5c_error(data):
  with pytest.raises(ParserError):
    parse_attestation_statement_x5c(data)


@pytest.mark.parametrize('data, expected', [
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
    },
     PackedAttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                sig=b'signature')),
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'x5c': [b'x', b'y']
    },
     PackedX509AttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                    sig=b'signature',
                                    x5c=[b'x', b'y'])),
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'ecdaaKeyId': b'key-id'
    },
     PackedECDAAAttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                     sig=b'signature',
                                     ecdaa_key_id=b'key-id')),
])
def test_parse_packed_attestation_statement_success(data, expected):
  assert_objects_equal(parse_packed_attestation_statement(data), expected)


@pytest.mark.parametrize('data', [{}, {
    'alg': -1,
    'sig': b'signature',
}, {
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': 'signature',
}, {
    'invalid': 'data',
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': b'signature',
}])
def test_parse_packed_attestation_statement_error(data):
  with pytest.raises(ParserError):
    parse_packed_attestation_statement(data)


@pytest.mark.parametrize('data, expected', [
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'ver': '1',
        'certInfo': b'cert-info',
        'pubArea': b'pub-area',
    },
     TPMAttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                             sig=b'signature',
                             ver='1',
                             cert_info=b'cert-info',
                             pub_area=b'pub-area')),
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'ver': '1',
        'certInfo': b'cert-info',
        'pubArea': b'pub-area',
        'x5c': [b'x', b'y']
    },
     TPMX509AttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                 sig=b'signature',
                                 ver='1',
                                 cert_info=b'cert-info',
                                 pub_area=b'pub-area',
                                 x5c=[b'x', b'y'])),
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'ver': '1',
        'certInfo': b'cert-info',
        'pubArea': b'pub-area',
        'ecdaaKeyId': b'key-id'
    },
     TPMECDAAAttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                  sig=b'signature',
                                  ver='1',
                                  cert_info=b'cert-info',
                                  pub_area=b'pub-area',
                                  ecdaa_key_id=b'key-id')),
])
def test_parse_tpm_attestation_statement_success(data, expected):
  assert_objects_equal(parse_tpm_attestation_statement(data), expected)


@pytest.mark.parametrize('data', [{}, {
    'alg': -1,
    'sig': b'signature',
    'ver': '1',
    'certInfo': b'cert-info',
    'pubArea': b'pub-area',
}, {
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': 'signature',
    'ver': '1',
    'certInfo': b'cert-info',
    'pubArea': b'pub-area',
}, {
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': 'signature',
    'ver': b'1',
    'certInfo': b'cert-info',
    'pubArea': b'pub-area',
}, {
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': 'signature',
    'ver': '1',
    'certInfo': 'cert-info',
    'pubArea': b'pub-area',
}, {
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': 'signature',
    'ver': '1',
    'certInfo': b'cert-info',
    'pubArea': 'pub-area',
}, {
    'invalid': 'data',
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': b'signature',
    'ver': '1',
    'certInfo': b'cert-info',
    'pubArea': b'pub-area',
}, {
    'invalid': 'data',
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': b'signature',
    'ver': '1',
    'certInfo': b'cert-info',
    'pubArea': b'pub-area',
    'x5c': [b'x', b'y']
}, {
    'invalid': 'data',
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': b'signature',
    'ver': '1',
    'certInfo': b'cert-info',
    'pubArea': b'pub-area',
    'ecdaaKeyId': b'key-id'
}])
def test_parse_tpm_attestation_statement_error(data):
  with pytest.raises(ParserError):
    parse_tpm_attestation_statement(data)


@pytest.mark.parametrize('data, expected', [
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'x5c': [b'x', b'y']
    },
     AndroidKeyAttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                    sig=b'signature',
                                    x5c=[b'x', b'y'])),
    ({
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'x5c': [b'x', b'y']
    },
     AndroidKeyAttestationStatement(alg=COSEAlgorithmIdentifier.Value.ES256,
                                    sig=b'signature',
                                    x5c=[b'x', b'y'])),
])
def test_parse_android_key_attestation_statement_success(data, expected):
  assert_objects_equal(parse_android_key_attestation_statement(data), expected)


@pytest.mark.parametrize('data', [
    {},
    {
        'alg': -1,
        'sig': b'signature',
        'x5c': [b'x', b'y']
    },
    {
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': 'signature',
        'x5c': [b'x', b'y']
    },
    {
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'x5c': b'x'
    },
    {
        'invalid': 'x',
        'alg': COSEAlgorithmIdentifier.Value.ES256.value,
        'sig': b'signature',
        'x5c': [b'x', b'y']
    },
])
def test_parse_android_key_attestation_statement_error(data):
  with pytest.raises(ParserError):
    parse_android_key_attestation_statement(data)


@pytest.mark.parametrize('data, expected', [({
    'ver': '1',
    'response': b'response'
}, AndroidSafetyNetAttestationStatement(ver='1', response=b'response'))])
def test_parse_android_safetynet_attestation_statement_success(data, expected):
  assert_objects_equal(parse_android_safetynet_attestation_statement(data),
                       expected)


@pytest.mark.parametrize('data', [
    {},
    {
        'ver': b'1',
        'response': b'response'
    },
    {
        'ver': '1',
        'response': 'response'
    },
    {
        'invalid': '1',
        'ver': '1',
        'response': b'response'
    },
])
def test_parse_android_safetynet_attestation_statement_error(data):
  with pytest.raises(ParserError):
    parse_android_safetynet_attestation_statement(data)


@pytest.mark.parametrize(
    'data, expected',
    [({
        'sig': b'signature',
        'x5c': [b'x']
    }, FIDOU2FAttestationStatement(sig=b'signature', x5c=[b'x'])),
     ({
         'sig': b'signature',
         'x5c': [b'x', b'y']
     }, FIDOU2FAttestationStatement(sig=b'signature', x5c=[b'x', b'y']))])
def test_parse_fido_u2f_attestation_statement_success(data, expected):
  assert_objects_equal(parse_fido_u2f_attestation_statement(data), expected)


@pytest.mark.parametrize('data', [
    {},
    {
        'sig': 'signature',
        'x5c': [b'x', b'y']
    },
    {
        'sig': b'signature',
        'x5c': ['x', b'y']
    },
    {
        'sig': b'signature',
        'x5c': b'x'
    },
])
def test_parse_fido_u2f_attestation_statement_error(data):
  with pytest.raises(ParserError):
    parse_fido_u2f_attestation_statement(data)


@pytest.mark.parametrize('data, expected', [
    ({}, NoneAttestationStatement()),
])
def test_parse_none_attestation_statement_success(data, expected):
  assert_objects_equal(parse_none_attestation_statement(data), expected)


@pytest.mark.parametrize('data', [{
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': b'signature',
}, {
    'alg': COSEAlgorithmIdentifier.Value.ES256.value,
    'sig': b'signature',
    'x5c': [b'x']
}, {
    'sig': b'signature',
    'x5c': [b'x']
}, {
    'invalid': '1',
}])
def test_parse_none_attestation_statement_error(data):
  with pytest.raises(ParserError):
    parse_none_attestation_statement(data)


@pytest.mark.parametrize('data, expected', [
    (json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
    }),
     CollectedClientData(
         type='type', challenge='challenge', origin='http://example.com')),
    (json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': {
            'status': TokenBindingStatus.SUPPORTED.value
        }
    }),
     CollectedClientData(
         type='type',
         challenge='challenge',
         origin='http://example.com',
         token_binding=TokenBinding(status=TokenBindingStatus.SUPPORTED))),
    (json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': {
            'status': TokenBindingStatus.PRESENT.value,
            'id': 'binding-id'
        }
    }),
     CollectedClientData(type='type',
                         challenge='challenge',
                         origin='http://example.com',
                         token_binding=TokenBinding(
                             status=TokenBindingStatus.PRESENT,
                             id='binding-id'))),
])
def test_parse_client_data_success(data, expected):
  assert_objects_equal(parse_client_data(data), expected)


@pytest.mark.parametrize('data', [
    json_bytes({
        'type': -1,
        'challenge': 'challenge',
        'origin': 'http://example.com'
    }),
    json_bytes({
        'type': 'type',
        'challenge': -1,
        'origin': 'http://example.com'
    }),
    json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': -1,
    }),
    json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': 'x'
    }),
    json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': {}
    }),
    json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': {
            'status': -1
        }
    }),
    json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': {
            'status': '----'
        }
    }),
    json_bytes({
        'type': 'type',
        'challenge': 'challenge',
        'origin': 'http://example.com',
        'tokenBinding': {
            'status': TokenBindingStatus.PRESENT.value,
        }
    }),
])
def test_parse_client_data_error(data):
  with pytest.raises((ParserError, TokenBindingError)):
    parse_client_data(data)


@pytest.mark.parametrize('data, expected', [
    ({
        -2:
        b'x' * ED25519_COORDINATE_BYTE_LENGTH,
        -1:
        OKPCurve.Value.ED25519.value,
        1:
        COSEKeyType.Value.OKP.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     OKPCredentialPublicKey(
         kty=COSEKeyType.Value.OKP,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.EDDSA,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * ED25519_COORDINATE_BYTE_LENGTH,
         crv=OKPCurve.Value.ED25519,
     )),
    ({
        -3:
        b'y' * P_256_COORDINATE_BYTE_LENGTH,
        -2:
        b'x' * P_256_COORDINATE_BYTE_LENGTH,
        -1:
        EC2Curve.Value.P_256.value,
        1:
        COSEKeyType.Value.EC2.value,
        2:
        b'kid',
        3:
        COSEAlgorithmIdentifier.Value.ES256.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5:
        b'base-IV',
    },
     EC2CredentialPublicKey(
         kty=COSEKeyType.Value.EC2,
         kid=b'kid',
         alg=COSEAlgorithmIdentifier.Value.ES256,
         key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
         base_IV=b'base-IV',
         x=b'x' * P_256_COORDINATE_BYTE_LENGTH,
         y=b'y' * P_256_COORDINATE_BYTE_LENGTH,
         crv=EC2Curve.Value.P_256,
     )),
])
def test_parse_cose_key_success(data, expected):
  assert_objects_equal(parse_cose_key(data), expected)


@pytest.mark.parametrize('data', [
    {
        -2: 'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: b'invalid',
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    },
    {
        -2: 'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: 'invalid',
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    },
    {
        -2: 'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    },
    {
        -2: 'x' * ED448_COORDINATE_BYTE_LENGTH,
        -1: OKPCurve.Value.ED448.value,
        1: COSEKeyType.Value.OKP.value,
        2: b'kid',
        3: COSEAlgorithmIdentifier.Value.EDDSA.value,
        4: [
            COSEKeyOperation.Value.SIGN.value,
            COSEKeyOperation.Value.VERIFY.value
        ],
        5: b'base-IV',
    },
])
def test_parse_cose_key_error(data):
  with pytest.raises(ParserError):
    parse_cose_key(data)


@pytest.mark.parametrize('data, expected', [
    (authenticator_data(
        b'x' * 32,
        AuthenticatorDataFlag.UP.value,
        b'y' * 4,
    ),
     AuthenticatorData(
         rp_id_hash=b'x' * 32,
         flags=AuthenticatorDataFlag.UP.value,
         sign_count=int.from_bytes(b'y' * 4, 'big'),
     )),
    (authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
         | AuthenticatorDataFlag.ED.value), b'y' * 4,
        attested_credential_data(
            b'z' * 16,
            10,
            b'a' * 10,
            cbor2.dumps({
                -3:
                b'y' * P_256_COORDINATE_BYTE_LENGTH,
                -2:
                b'x' * P_256_COORDINATE_BYTE_LENGTH,
                -1:
                EC2Curve.Value.P_256.value,
                1:
                COSEKeyType.Value.EC2.value,
                2:
                b'kid',
                3:
                COSEAlgorithmIdentifier.Value.ES256.value,
                4: [
                    COSEKeyOperation.Value.SIGN.value,
                    COSEKeyOperation.Value.VERIFY.value
                ],
                5:
                b'base-IV',
            }),
        ), cbor2.dumps({
            'appid': True,
        })),
     AuthenticatorData(
         rp_id_hash=b'x' * 32,
         flags=(AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
                | AuthenticatorDataFlag.ED.value),
         sign_count=int.from_bytes(b'y' * 4, 'big'),
         attested_credential_data=AttestedCredentialData(
             aaguid=b'z' * 16,
             credential_id_length=10,
             credential_id=b'a' * 10,
             credential_public_key=EC2CredentialPublicKey(
                 kty=COSEKeyType.Value.EC2,
                 kid=b'kid',
                 alg=COSEAlgorithmIdentifier.Value.ES256,
                 key_ops=[
                     COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY
                 ],
                 base_IV=b'base-IV',
                 x=b'x' * P_256_COORDINATE_BYTE_LENGTH,
                 y=b'y' * P_256_COORDINATE_BYTE_LENGTH,
                 crv=EC2Curve.Value.P_256,
             )),
         extensions=AuthenticationExtensionsClientOutputs(appid=True))),
    (authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value),
        b'y' * 4,
        attested_credential_data(
            b'z' * 16,
            10,
            b'a' * 10,
            cbor2.dumps({
                -3:
                b'y' * P_256_COORDINATE_BYTE_LENGTH,
                -2:
                b'x' * P_256_COORDINATE_BYTE_LENGTH,
                -1:
                EC2Curve.Value.P_256.value,
                1:
                COSEKeyType.Value.EC2.value,
                2:
                b'kid',
                3:
                COSEAlgorithmIdentifier.Value.ES256.value,
                4: [
                    COSEKeyOperation.Value.SIGN.value,
                    COSEKeyOperation.Value.VERIFY.value
                ],
                5:
                b'base-IV',
            }),
        ),
    ),
     AuthenticatorData(
         rp_id_hash=b'x' * 32,
         flags=(AuthenticatorDataFlag.UP.value
                | AuthenticatorDataFlag.AT.value),
         sign_count=int.from_bytes(b'y' * 4, 'big'),
         attested_credential_data=AttestedCredentialData(
             aaguid=b'z' * 16,
             credential_id_length=10,
             credential_id=b'a' * 10,
             credential_public_key=EC2CredentialPublicKey(
                 kty=COSEKeyType.Value.EC2,
                 kid=b'kid',
                 alg=COSEAlgorithmIdentifier.Value.ES256,
                 key_ops=[
                     COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY
                 ],
                 base_IV=b'base-IV',
                 x=b'x' * P_256_COORDINATE_BYTE_LENGTH,
                 y=b'y' * P_256_COORDINATE_BYTE_LENGTH,
                 crv=EC2Curve.Value.P_256,
             )),
     )),
    (authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.ED.value),
        b'y' * 4,
        extensions=cbor2.dumps({
            'appid': True,
        })),
     AuthenticatorData(
         rp_id_hash=b'x' * 32,
         flags=(AuthenticatorDataFlag.UP.value
                | AuthenticatorDataFlag.ED.value),
         sign_count=int.from_bytes(b'y' * 4, 'big'),
         extensions=AuthenticationExtensionsClientOutputs(appid=True))),
])
def test_parse_authenticator_data_success(data, expected):
  assert_objects_equal(parse_authenticator_data(data), expected)


@pytest.mark.parametrize('data', [
    b''
    b'x' * 32,
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.ED.value),
        b'y' * 4,
    ),
    authenticator_data(b'x' * 32, (AuthenticatorDataFlag.UP.value),
                       b'y' * 4,
                       extensions=cbor2.dumps({
                           'appid': True,
                       })),
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value),
        b'y' * 4,
        attested_credential_data(
            b'z' * 16,
            10,
            b'a' * 10,
            cbor2.dumps({
                -3:
                b'y' * P_256_COORDINATE_BYTE_LENGTH,
                -2:
                b'x' * P_256_COORDINATE_BYTE_LENGTH,
                -1:
                EC2Curve.Value.P_256.value,
                1:
                COSEKeyType.Value.EC2.value,
                2:
                b'kid',
                3:
                COSEAlgorithmIdentifier.Value.ES256.value,
                4: [
                    COSEKeyOperation.Value.SIGN.value,
                    COSEKeyOperation.Value.VERIFY.value
                ],
                5:
                b'base-IV',
            }),
        ),
    ),
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value),
        b'y' * 4,
    ),
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value),
        b'y' * 4,
        attested_credential_data(
            b'z' * 16,
            10,
            b'a' * 10,
            b'invalid',
        ),
    ),
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value),
        b'y' * 4,
        attested_credential_data(
            b'z' * 16,
            10,
            b'a' * 10,
            cbor2.dumps([1, 2, 3]),
        ),
    ),
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.ED.value),
        b'y' * 4,
        extensions=b'invalid'),
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.ED.value),
        b'y' * 4,
        extensions=cbor2.dumps([1, 2, 3])),
])
def test_parse_authenticator_data_error(data):
  with pytest.raises((ParserError, DecodingError)):
    parse_authenticator_data(data)


@pytest.mark.parametrize('data, expected', [(cbor2.dumps({
    'authData':
    authenticator_data(
        b'x' * 32,
        (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
         | AuthenticatorDataFlag.ED.value), b'y' * 4,
        attested_credential_data(
            b'z' * 16,
            10,
            b'a' * 10,
            cbor2.dumps({
                -3:
                b'y' * P_256_COORDINATE_BYTE_LENGTH,
                -2:
                b'x' * P_256_COORDINATE_BYTE_LENGTH,
                -1:
                EC2Curve.Value.P_256.value,
                1:
                COSEKeyType.Value.EC2.value,
                2:
                b'kid',
                3:
                COSEAlgorithmIdentifier.Value.ES256.value,
                4: [
                    COSEKeyOperation.Value.SIGN.value,
                    COSEKeyOperation.Value.VERIFY.value
                ],
                5:
                b'base-IV',
            }),
        ), cbor2.dumps({
            'appid': True,
        })),
    'fmt':
    AttestationStatementFormatIdentifier.FIDO_U2F.value,
    'attStmt': {
        'sig': b'signature',
        'x5c': [b'x']
    }
}), (AttestationObject(auth_data=AuthenticatorData(
    rp_id_hash=b'x' * 32,
    flags=(AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
           | AuthenticatorDataFlag.ED.value),
    sign_count=int.from_bytes(b'y' * 4, 'big'),
    attested_credential_data=AttestedCredentialData(
        aaguid=b'z' * 16,
        credential_id_length=10,
        credential_id=b'a' * 10,
        credential_public_key=EC2CredentialPublicKey(
            kty=COSEKeyType.Value.EC2,
            kid=b'kid',
            alg=COSEAlgorithmIdentifier.Value.ES256,
            key_ops=[
                COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY
            ],
            base_IV=b'base-IV',
            x=b'x' * P_256_COORDINATE_BYTE_LENGTH,
            y=b'y' * P_256_COORDINATE_BYTE_LENGTH,
            crv=EC2Curve.Value.P_256,
        )),
    extensions=AuthenticationExtensionsClientOutputs(appid=True)),
                       fmt=AttestationStatementFormatIdentifier.FIDO_U2F,
                       att_stmt=FIDOU2FAttestationStatement(sig=b'signature',
                                                            x5c=[b'x'])),
     {
         'authData':
         authenticator_data(
             b'x' * 32,
             (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
              | AuthenticatorDataFlag.ED.value), b'y' * 4,
             attested_credential_data(
                 b'z' * 16,
                 10,
                 b'a' * 10,
                 cbor2.dumps({
                     -3:
                     b'y' * P_256_COORDINATE_BYTE_LENGTH,
                     -2:
                     b'x' * P_256_COORDINATE_BYTE_LENGTH,
                     -1:
                     EC2Curve.Value.P_256.value,
                     1:
                     COSEKeyType.Value.EC2.value,
                     2:
                     b'kid',
                     3:
                     COSEAlgorithmIdentifier.Value.ES256.value,
                     4: [
                         COSEKeyOperation.Value.SIGN.value,
                         COSEKeyOperation.Value.VERIFY.value
                     ],
                     5:
                     b'base-IV',
                 }),
             ), cbor2.dumps({
                 'appid': True,
             })),
         'fmt':
         AttestationStatementFormatIdentifier.FIDO_U2F.value,
         'attStmt': {
             'sig': b'signature',
             'x5c': [b'x']
         }
     }))])
def test_parse_attestation_success(data, expected):
  assert_objects_equal(parse_attestation(data), expected)


@pytest.mark.parametrize('data', [
    b'invalid',
    cbor2.dumps([1, 2, 3]),
    cbor2.dumps({}),
    cbor2.dumps({
        'authData': 'auth-data',
        'fmt': AttestationStatementFormatIdentifier.FIDO_U2F.value,
        'attStmt': {
            'sig': b'signature',
            'x5c': [b'x']
        }
    }),
    cbor2.dumps({
        'authData':
        authenticator_data(
            b'x' * 32,
            (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
             | AuthenticatorDataFlag.ED.value), b'y' * 4,
            attested_credential_data(
                b'z' * 16,
                10,
                b'a' * 10,
                cbor2.dumps({
                    -3:
                    b'y' * P_256_COORDINATE_BYTE_LENGTH,
                    -2:
                    b'x' * P_256_COORDINATE_BYTE_LENGTH,
                    -1:
                    EC2Curve.Value.P_256.value,
                    1:
                    COSEKeyType.Value.EC2.value,
                    2:
                    b'kid',
                    3:
                    COSEAlgorithmIdentifier.Value.ES256.value,
                    4: [
                        COSEKeyOperation.Value.SIGN.value,
                        COSEKeyOperation.Value.VERIFY.value
                    ],
                    5:
                    b'base-IV',
                }),
            ), cbor2.dumps({
                'appid': True,
            })),
        'fmt':
        b'packed',
        'attStmt': {
            'sig': b'signature',
            'x5c': [b'x']
        }
    }),
    cbor2.dumps({
        'authData':
        authenticator_data(
            b'x' * 32,
            (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
             | AuthenticatorDataFlag.ED.value), b'y' * 4,
            attested_credential_data(
                b'z' * 16,
                10,
                b'a' * 10,
                cbor2.dumps({
                    -3:
                    b'y' * P_256_COORDINATE_BYTE_LENGTH,
                    -2:
                    b'x' * P_256_COORDINATE_BYTE_LENGTH,
                    -1:
                    EC2Curve.Value.P_256.value,
                    1:
                    COSEKeyType.Value.EC2.value,
                    2:
                    b'kid',
                    3:
                    COSEAlgorithmIdentifier.Value.ES256.value,
                    4: [
                        COSEKeyOperation.Value.SIGN.value,
                        COSEKeyOperation.Value.VERIFY.value
                    ],
                    5:
                    b'base-IV',
                }),
            ), cbor2.dumps({
                'appid': True,
            })),
        'fmt':
        AttestationStatementFormatIdentifier.FIDO_U2F.value,
        'attStmt':
        b'att-stmt'
    }),
    cbor2.dumps({
        'authData':
        authenticator_data(
            b'x' * 32,
            (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
             | AuthenticatorDataFlag.ED.value), b'y' * 4,
            attested_credential_data(
                b'z' * 16,
                10,
                b'a' * 10,
                cbor2.dumps({
                    -3:
                    b'y' * P_256_COORDINATE_BYTE_LENGTH,
                    -2:
                    b'x' * P_256_COORDINATE_BYTE_LENGTH,
                    -1:
                    EC2Curve.Value.P_256.value,
                    1:
                    COSEKeyType.Value.EC2.value,
                    2:
                    b'kid',
                    3:
                    COSEAlgorithmIdentifier.Value.ES256.value,
                    4: [
                        COSEKeyOperation.Value.SIGN.value,
                        COSEKeyOperation.Value.VERIFY.value
                    ],
                    5:
                    b'base-IV',
                }),
            ), cbor2.dumps({
                'appid': True,
            })),
        'fmt':
        -1,
        'attStmt': {
            'sig': b'signature',
            'x5c': [b'x']
        }
    }),
])
def test_parse_attestation_error(data):
  with pytest.raises((ParserError, DecodingError)):
    parse_attestation(data)
