import base64

import pytest

from webauthn_rp.errors import ValidationError
from webauthn_rp.parsers import (bytes_from_base64, check_unsupported_keys,
                                 parse_dictionary_field,
                                 parse_public_key_credential)
from webauthn_rp.types import (AuthenticatorAssertionResponse,
                               AuthenticatorAttestationResponse,
                               PublicKeyCredential)

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
