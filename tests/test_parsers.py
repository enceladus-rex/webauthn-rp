import base64

import pytest

from itertools import chain

from webauthn_rp.constants import *
from webauthn_rp.errors import ValidationError
from webauthn_rp.parsers import (
    bytes_from_base64, check_unsupported_keys, parse_dictionary_field,
    parse_public_key_credential, parse_credential_public_key_kty,
    parse_credential_public_key_alg, parse_credential_public_key_key_ops,
    parse_credential_public_key_kwargs, parse_ec2_public_key_crv,
    parse_okp_public_key_crv, parse_okp_public_key,
    parse_ec2_public_key)
from webauthn_rp.types import (AuthenticatorAssertionResponse,
                               AuthenticatorAttestationResponse,
                               PublicKeyCredential, COSEKeyType,
                               COSEAlgorithmIdentifier, COSEKeyOperation,
                               EC2Curve, OKPCurve, CredentialPublicKey,
                               OKPCredentialPublicKey, EC2CredentialPublicKey)

from .common import assert_objects_equal


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
  with pytest.raises(ValidationError):
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
    with pytest.raises(ValidationError):
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
  with pytest.raises(ValidationError):
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
  with pytest.raises(ValidationError):
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
  with pytest.raises(ValidationError):
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
  with pytest.raises(ValidationError):
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
} for x in (-1, -2, '_invalid', '1', ['x'], [-1], [COSEKeyOperation.Name.DECRYPT.value, 'y'], )] + [
  {4: []}
])
def test_parse_credential_public_key_key_ops_error(data):
  with pytest.raises(ValidationError):
    parse_credential_public_key_key_ops(data)


@pytest.mark.parametrize('data, expected', [
  ({
    1: COSEKeyType.Name.EC2.value,
    2: b'key-id',
    3: COSEAlgorithmIdentifier.Name.ES256.value,
    4: [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
    5: b'base-IV'
  }, dict(
    kty=COSEKeyType.Name.EC2,
    kid=b'key-id',
    alg=COSEAlgorithmIdentifier.Name.ES256,
    key_ops=[COSEKeyOperation.Name.VERIFY, COSEKeyOperation.Name.SIGN],
    base_IV=b'base-IV'
  )),
  ({
    1: COSEKeyType.Value.EC2.value,
    2: b'key-id',
    3: COSEAlgorithmIdentifier.Value.ES256.value,
    4: [COSEKeyOperation.Value.VERIFY.value, COSEKeyOperation.Value.SIGN.value],
    5: b'base-IV'
  }, dict(
    kty=COSEKeyType.Value.EC2,
    kid=b'key-id',
    alg=COSEAlgorithmIdentifier.Value.ES256,
    key_ops=[COSEKeyOperation.Value.VERIFY, COSEKeyOperation.Value.SIGN],
    base_IV=b'base-IV'
  )),
])
def test_parse_credential_public_key_kwargs_success(data, expected):
  assert parse_credential_public_key_kwargs(data) == expected


@pytest.mark.parametrize('data', [
  {
    1: 1.0,
    2: b'key-id',
    3: COSEAlgorithmIdentifier.Name.ES256.value,
    4: [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
    5: b'base-IV'
  },
  {
    1: COSEKeyType.Name.EC2.value,
    2: 'string',
    3: COSEAlgorithmIdentifier.Name.ES256.value,
    4: [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
    5: b'base-IV'
  },
  {
    1: COSEKeyType.Name.EC2.value,
    2: b'key-id',
    3: -1,
    4: [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
    5: b'base-IV'
  },
  {
    1: COSEKeyType.Name.EC2.value,
    2: b'key-id',
    3: COSEAlgorithmIdentifier.Name.ES256.value,
    4: [b'x', COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
    5: b'base-IV'
  },
  {
    1: COSEKeyType.Name.EC2.value,
    2: b'key-id',
    3: COSEAlgorithmIdentifier.Name.ES256.value,
    4: [COSEKeyOperation.Name.VERIFY.value, COSEKeyOperation.Name.SIGN.value],
    5: 'string'
  },
])
def test_parse_credential_public_key_key_ops_error(data):
  with pytest.raises(ValidationError):
    parse_credential_public_key_kwargs(data)


@pytest.mark.parametrize('data, expected', [
  ({-1: x.value}, x) for x in chain(EC2Curve.Name, EC2Curve.Value)
])
def test_parse_ec2_public_key_crv_success(data, expected):
  assert parse_ec2_public_key_crv(data) == expected


@pytest.mark.parametrize('data', [
  {-1: b''},
  {-1: 1.},
  {-1: 'x'},
  {-1: -1},
  {},
  {2: 1},
])
def test_parse_ec2_public_key_crv_error(data):
  with pytest.raises(ValidationError):
    parse_ec2_public_key_crv(data)


@pytest.mark.parametrize('data, expected', [
  ({-1: x.value}, x) for x in chain(OKPCurve.Name, OKPCurve.Value)
])
def test_parse_okp_public_key_crv_success(data, expected):
  assert parse_okp_public_key_crv(data) == expected


@pytest.mark.parametrize('data', [
  {-1: b''},
  {-1: 1.},
  {-1: 'x'},
  {-1: -1},
  {},
  {2: 1},
])
def test_parse_okp_public_key_crv_error(data):
  with pytest.raises(ValidationError):
    parse_okp_public_key_crv(data)


@pytest.mark.parametrize('data, expected', [
  (
    {
      -2: b'x' * ED25519_COORDINATE_BYTE_LENGTH,
      -1: OKPCurve.Value.ED25519.value,
      1: COSEKeyType.Value.OKP.value,
      2: b'kid',
      3: COSEAlgorithmIdentifier.Value.EDDSA.value,
      4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
      5: b'base-IV',
    },
    OKPCredentialPublicKey(
      kty=COSEKeyType.Value.OKP,
      kid=b'kid',
      alg=COSEAlgorithmIdentifier.Value.EDDSA,
      key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
      base_IV=b'base-IV',
      x=b'x' * ED25519_COORDINATE_BYTE_LENGTH,
      crv=OKPCurve.Value.ED25519,
    )
  ),
  (
    {
      -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
      -1: OKPCurve.Value.ED448.value,
      1: COSEKeyType.Value.OKP.value,
      2: b'kid',
      3: COSEAlgorithmIdentifier.Value.EDDSA.value,
      4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
      5: b'base-IV',
    },
    OKPCredentialPublicKey(
      kty=COSEKeyType.Value.OKP,
      kid=b'kid',
      alg=COSEAlgorithmIdentifier.Value.EDDSA,
      key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
      base_IV=b'base-IV',
      x=b'x' * ED448_COORDINATE_BYTE_LENGTH,
      crv=OKPCurve.Value.ED448,
    )
  ),
  (
    {
      -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
      -1: OKPCurve.Value.ED448.value,
      1: COSEKeyType.Value.OKP.value,
      2: b'kid',
      3: COSEAlgorithmIdentifier.Value.EDDSA.value,
      4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
      5: b'base-IV',
    },
    OKPCredentialPublicKey(
      kty=COSEKeyType.Value.OKP,
      kid=b'kid',
      alg=COSEAlgorithmIdentifier.Value.EDDSA,
      key_ops=[COSEKeyOperation.Value.SIGN, COSEKeyOperation.Value.VERIFY],
      base_IV=b'base-IV',
      x=b'x' * ED448_COORDINATE_BYTE_LENGTH,
      crv=OKPCurve.Value.ED448,
    )
  ),
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
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: 'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: 'base-IV',
  },{
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: 'invalid',
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: -1,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: 'invalid',
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [-3],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_256_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_256_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_256.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES256.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_384_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_384_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_384.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES384.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_521.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES512.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  }
])
def test_parse_okp_public_key_error(data):
  with pytest.raises(ValidationError):
    parse_okp_public_key(data)


@pytest.mark.parametrize('data, expected', [
  (
    {
      -3: b'y' * P_256_COORDINATE_BYTE_LENGTH,
      -2: b'x' * P_256_COORDINATE_BYTE_LENGTH,
      -1: EC2Curve.Value.P_256.value,
      1: COSEKeyType.Value.EC2.value,
      2: b'kid',
      3: COSEAlgorithmIdentifier.Value.ES256.value,
      4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
      5: b'base-IV',
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
    )
  ),
  (
    {
      -3: b'y' * P_384_COORDINATE_BYTE_LENGTH,
      -2: b'x' * P_384_COORDINATE_BYTE_LENGTH,
      -1: EC2Curve.Value.P_384.value,
      1: COSEKeyType.Value.EC2.value,
      2: b'kid',
      3: COSEAlgorithmIdentifier.Value.ES384.value,
      4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
      5: b'base-IV',
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
    )
  ),
  (
    {
      -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
      -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
      -1: EC2Curve.Value.P_521.value,
      1: COSEKeyType.Value.EC2.value,
      2: b'kid',
      3: COSEAlgorithmIdentifier.Value.ES512.value,
      4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
      5: b'base-IV',
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
    )
  ),
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
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: 'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: 'base-IV',
  },{
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: 'invalid',
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: -1,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: 'invalid',
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -2: b'x' * ED448_COORDINATE_BYTE_LENGTH,
    -1: OKPCurve.Value.ED448.value,
    1: COSEKeyType.Value.OKP.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.EDDSA.value,
    4: [-3],
    5: b'base-IV',
  },
  {
    -3: 'y' * P_256_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_256_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_256.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES256.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_384_COORDINATE_BYTE_LENGTH,
    -2: 'x' * P_384_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_384.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES384.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: 'invalid',
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES512.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_521.value,
    1: -3,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES512.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_521.value,
    1: COSEKeyType.Value.EC2.value,
    2: 'kid',
    3: COSEAlgorithmIdentifier.Value.ES512.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_521.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: 'invalid',
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_521.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES512.value,
    4: [b'x', COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: b'base-IV',
  },
  {
    -3: b'y' * P_521_COORDINATE_BYTE_LENGTH,
    -2: b'x' * P_521_COORDINATE_BYTE_LENGTH,
    -1: EC2Curve.Value.P_521.value,
    1: COSEKeyType.Value.EC2.value,
    2: b'kid',
    3: COSEAlgorithmIdentifier.Value.ES512.value,
    4: [COSEKeyOperation.Value.SIGN.value, COSEKeyOperation.Value.VERIFY.value],
    5: 'base-IV',
  }
])
def test_parse_ec2_public_key_error(data):
  with pytest.raises(ValidationError):
    parse_ec2_public_key(data)