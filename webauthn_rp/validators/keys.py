from collections import namedtuple
from enum import Enum

from typing import Sequence, Union

from ..errors import UnimplementedError, ValidationError
from ..types import CredentialPublicKey, COSEKeyType


def unimplemented(credential_public_key: CredentialPublicKey):
  raise UnimplementedError(
    'Validation for credential public key type {} is unimplemented'.format(
      credential_public_key.kty))


def validate_kty(
    validator_ktys: Union[str, Sequence[str]],
    credential_public_key: CredentialPublicKey):
  if type(validator_ktys) is str:
    validator_ktys = [validator_ktys]

  for kty in validator_ktys:
    if credential_public_key.key.name == kty: return

  raise ValidationError(
    'Invalid public key type {}'.format(kty_enum_name))


def validate_key_ops(
    validator_key_ops: Union[str, Sequence[str]],
    credential_public_key: CredentialPublicKey):
  if type(validator_key_ops) is str:
    validator_key_ops = [validator_key_ops]
  
  ops = set(validator_key_ops)
  for kop in credential_public_key.key_ops:
    if kop.name in ops: ops.remove(kop.name)

  if ops:
    raise ValidationError(
      'Missing key ops {}'.format(list(ops)))


def ecdsa_validator(
    credential_public_key: CredentialPublicKey,
    sign: bool = False, verify: bool = False):
  validate_kty('EC2', credential_public_key)
  
  ops = []
  if sign: ops.append('SIGN')
  if verify: ops.append('VERIFY')
  validate_key_ops(ops, credential_public_key)


class CredentialPublicKeyValidator(Enum):
  ES256 = ecdsa_validator
  ES384 = ecdsa_validator
  ES512 = ecdsa_validator

  EDDSA = unimplemented # ('EC2', unimplemented)  

  ECDH_ES_HKDF_256 = unimplemented # (('EC2', 'OKP'), unimplemented)  
  ECDH_ES_HKDF_512 = unimplemented # (('EC2', 'OKP'), unimplemented)  
  ECDH_SS_HKDF_256 = unimplemented # (('EC2', 'OKP'), unimplemented)  
  ECDH_SS_HKDF_512 = unimplemented # (('EC2', 'OKP'), unimplemented)  

  HMAC_256_64 = unimplemented # ('SYMMETRIC', unimplemented)  
  HMAC_256_256 = unimplemented # ('SYMMETRIC', unimplemented)  
  HMAC_384_384 = unimplemented # ('SYMMETRIC', unimplemented)  
  HMAC_512_512 = unimplemented # ('SYMMETRIC', unimplemented)  

  AES_MAC_128_64 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_MAC_256_64 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_MAC_128_128 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_MAC_256_128 = unimplemented # ('SYMMETRIC', unimplemented)  

  A256KW = unimplemented # ('SYMMETRIC', unimplemented)  
  A192KW = unimplemented # ('SYMMETRIC', unimplemented)  
  A128KW = unimplemented # ('SYMMETRIC', unimplemented)  

  A128GCM = unimplemented # ('SYMMETRIC', unimplemented)  
  A192GCM = unimplemented # ('SYMMETRIC', unimplemented)  
  A256GCM = unimplemented # ('SYMMETRIC', unimplemented)  

  DIRECT = unimplemented # ('SYMMETRIC', unimplemented)  

  DIRECT_HKDF_SHA_256 = unimplemented # ('SYMMETRIC', unimplemented)  
  DIRECT_HKDF_SHA_512 = unimplemented # ('SYMMETRIC', unimplemented)  
  DIRECT_HKDF_AES_128 = unimplemented # ('SYMMETRIC', unimplemented)  
  DIRECT_HKDF_AES_256 = unimplemented # ('SYMMETRIC', unimplemented)  

  AES_CCM_16_64_128 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_16_64_256 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_64_64_128 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_64_64_256 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_16_128_128 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_16_128_256 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_64_128_128 = unimplemented # ('SYMMETRIC', unimplemented)  
  AES_CCM_64_128_256 = unimplemented # ('SYMMETRIC', unimplemented)  
  
  CHACHA20_POLY1305 = unimplemented # ('SYMMETRIC', unimplemented)

  def __init__(self, kty, func):
    self.kty = kty
    self.func = func  


def validate(
    credential_public_key: CredentialPublicKey):
  if credential_public_key.alg is None: return
  try:
    validator = CredentialPublicKeyValidator[credential_public_key.alg.name]
  except KeyError:
    raise UnimplementedError(
      'Unsupported credential public key type enum name {}'.format(
        credential_public_key.kty.name))
  
  validator.value(credential_public_key)