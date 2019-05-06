from collections import namedtuple
from enum import Enum

from typing import Sequence, Union

from ..errors import UnimplementedError, ValidationError
from ..types import CredentialPublicKey, COSEKeyType


def unimplemented(credential_public_key: CredentialPublicKey):
  raise UnimplementedError((
    'Validation for credential public key type {}, '
    'alg type {} is unimplemented').format(
      credential_public_key.kty, credential_public_key.alg))


def validate_kty(
    validator_ktys: Union[str, Sequence[str]],
    credential_public_key: CredentialPublicKey):
  if type(validator_ktys) is str:
    validator_ktys = [validator_ktys]

  for kty in validator_ktys:
    if credential_public_key.kty.name == kty: return

  raise ValidationError(
    'Invalid public key alg type {}, expecting one of {}'.format(
      credential_public_key.kty.name, validator_ktys
    ))


def validate_key_ops(
    validator_key_ops: Union[str, Sequence[str]],
    credential_public_key: CredentialPublicKey):
  if type(validator_key_ops) is str:
    validator_key_ops = [validator_key_ops]

  if len(validator_key_ops) == 0: return
  if credential_public_key.key_ops is None:
    raise ValidationError('Found no key ops')
  
  ops = set(validator_key_ops)
  for kop in credential_public_key.key_ops:
    if kop.name in ops: ops.remove(kop.name)

  if ops:
    raise ValidationError(
      'Missing key ops {}'.format(list(ops)))


def ecdsa_validator(
    credential_public_key: CredentialPublicKey,
    create: bool = False, verify: bool = False):
  validate_kty('EC2', credential_public_key)
  
  ops = []
  if create: ops.append('SIGN')
  if verify: ops.append('VERIFY')
  validate_key_ops(ops, credential_public_key)


def eddsa_validator(
    credential_public_key: CredentialPublicKey,
    create: bool = False, verify: bool = False):
  validate_kty('OKP', credential_public_key)
  
  ops = []
  if create: ops.append('SIGN')
  if verify: ops.append('VERIFY')
  validate_key_ops(ops, credential_public_key)


def mac_validator(
    credential_public_key: CredentialPublicKey,
    create: bool = False, verify: bool = False):
  validate_kty('SYMMETRIC', credential_public_key)
  
  ops = []
  if create: ops.append('MAC_CREATE')
  if verify: ops.append('MAC_VERIFY')
  validate_key_ops(ops, credential_public_key)


def cm_validator(
    credential_public_key: CredentialPublicKey,
    encrypt: bool = False, decrypt: bool = False):
  validate_kty('SYMMETRIC', credential_public_key)
  
  ops = []
  if encrypt: ops.append('WRAP_KEY')
  if decrypt: ops.append('UNWRAP_KEY')
  validate_key_ops(ops, credential_public_key)


def direct_validator(
    credential_public_key: CredentialPublicKey):
  validate_kty('SYMMETRIC', credential_public_key)


def directkdf_validator(
    credential_public_key: CredentialPublicKey):
  validate_kty('SYMMETRIC', credential_public_key)


def kw_validator(
    credential_public_key: CredentialPublicKey,
    encrypt: bool = False, decrypt: bool = False):
  validate_kty('SYMMETRIC', credential_public_key)
  
  ops = []
  if encrypt: ops.extend(['ENCRYPT', 'WRAP_KEY'])
  if decrypt: ops.extend(['DECRYPT', 'UNWRAP_KEY'])
  validate_key_ops(ops, credential_public_key)


def ecdh_validator(
    credential_public_key: CredentialPublicKey):
  validate_kty(['EC2', 'OKP'], credential_public_key)
  if credential_public_key.key_ops is not None:
    if len(credential_public_key.key_ops) != 0:
      raise ValidationError('Key Ops must be empty')


def chachapoly_validator(
    credential_public_key: CredentialPublicKey,
    encrypt: bool = False, decrypt: bool = False):
  validate_kty('SYMMETRIC', credential_public_key)
  ops = []
  if encrypt: ops.extend(['ENCRYPT', 'WRAP_KEY'])
  if decrypt: ops.extend(['DECRYPT', 'UNWRAP_KEY'])
  validate_key_ops(ops, credential_public_key)


class CredentialPublicKeyValidator(Enum):
  ES256 = ecdsa_validator
  ES384 = ecdsa_validator
  ES512 = ecdsa_validator

  EDDSA = eddsa_validator

  ECDH_ES_HKDF_256 = ecdh_validator
  ECDH_ES_HKDF_512 = ecdh_validator
  ECDH_SS_HKDF_256 = ecdh_validator
  ECDH_SS_HKDF_512 = ecdh_validator

  HMAC_256_64 = mac_validator
  HMAC_256_256 = mac_validator
  HMAC_384_384 = mac_validator
  HMAC_512_512 = mac_validator

  AES_MAC_128_64 = mac_validator
  AES_MAC_256_64 = mac_validator
  AES_MAC_128_128 = mac_validator
  AES_MAC_256_128 = mac_validator

  A256KW = kw_validator
  A192KW = kw_validator
  A128KW = kw_validator

  A128GCM = cm_validator
  A192GCM = cm_validator
  A256GCM = cm_validator

  DIRECT = direct_validator

  DIRECT_HKDF_SHA_256 = directkdf_validator
  DIRECT_HKDF_SHA_512 = directkdf_validator
  DIRECT_HKDF_AES_128 = directkdf_validator
  DIRECT_HKDF_AES_256 = directkdf_validator

  AES_CCM_16_64_128 = cm_validator
  AES_CCM_16_64_256 = cm_validator
  AES_CCM_64_64_128 = cm_validator
  AES_CCM_64_64_256 = cm_validator
  AES_CCM_16_128_128 = cm_validator
  AES_CCM_16_128_256 = cm_validator
  AES_CCM_64_128_128 = cm_validator
  AES_CCM_64_128_256 = cm_validator
  
  CHACHA20_POLY1305 = chachapoly_validator


def validate(
    credential_public_key: CredentialPublicKey):
  if credential_public_key.alg is None: return
  try:
    validator = getattr(CredentialPublicKeyValidator, credential_public_key.alg.name)
  except AttributeError:
    raise UnimplementedError(
      'Unsupported credential public key alg enum name {}'.format(
        credential_public_key.alg.name))
  
  validator(credential_public_key)