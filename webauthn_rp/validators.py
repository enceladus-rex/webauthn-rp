from collections import namedtuple
from enum import Enum
from typing import Sequence, Union

from webauthn_rp.errors import UnimplementedError, ValidationError
from webauthn_rp.types import (COSEAlgorithmIdentifier, COSEKeyType,
                               CredentialPublicKey, EC2CredentialPublicKey,
                               EC2Curve, OKPCredentialPublicKey, OKPCurve)


def validate_kty(validator_ktys: Union[str, Sequence[str]],
                 credential_public_key: CredentialPublicKey):
  validator_ktys: Sequence[str] = [validator_ktys] if (  # type: ignore
      type(validator_ktys) is str) else validator_ktys

  for kty in validator_ktys:
    if credential_public_key.kty.name == kty: return

  raise ValidationError(
      'Invalid public key alg type {}, expecting one of {}'.format(
          credential_public_key.kty.name, validator_ktys))


def validate_key_ops(validator_key_ops: Union[str, Sequence[str]],
                     credential_public_key: CredentialPublicKey):
  validator_key_ops: Sequence[str] = [validator_key_ops] if (  # type: ignore
      type(validator_key_ops) is str) else validator_key_ops
  if len(validator_key_ops) == 0: return
  if credential_public_key.key_ops is None:
    raise ValidationError('Found no key ops')

  ops = set(validator_key_ops)
  for kop in credential_public_key.key_ops:
    if kop.name in ops: ops.remove(kop.name)

  if ops:
    raise ValidationError('Missing key ops {}'.format(list(ops)))


def ecdsa_validator(credential_public_key: EC2CredentialPublicKey,
                    sign: bool = False,
                    verify: bool = False):
  validate_kty('EC2', credential_public_key)
  ops = []
  if sign: ops.append('SIGN')
  if verify: ops.append('VERIFY')
  validate_key_ops(ops, credential_public_key)
  assert credential_public_key.crv is not None
  if credential_public_key.crv.name not in {'P_256', 'P_384', 'P_521'}:
    raise ValidationError('Invalid EC2 curve for key type')


def eddsa_validator(credential_public_key: OKPCredentialPublicKey,
                    sign: bool = False,
                    verify: bool = False):
  validate_kty('OKP', credential_public_key)
  ops = []
  if sign: ops.append('SIGN')
  if verify: ops.append('VERIFY')
  validate_key_ops(ops, credential_public_key)
  assert credential_public_key.crv is not None
  if credential_public_key.crv.name not in {'ED25519', 'ED448'}:
    raise ValidationError('Invalid OKP curve for key type')


class CredentialPublicKeyValidator(Enum):
  ES256 = ecdsa_validator
  ES384 = ecdsa_validator
  ES512 = ecdsa_validator

  EDDSA = eddsa_validator


def validate(credential_public_key: CredentialPublicKey,
             sign: bool = False,
             verify: bool = False) -> None:
  if credential_public_key.alg is None: return
  try:
    validator = getattr(CredentialPublicKeyValidator,
                        credential_public_key.alg.name)
  except AttributeError:
    raise UnimplementedError(
        'Unsupported credential public key alg enum name {}'.format(
            credential_public_key.alg.name))

  validator(credential_public_key, sign=sign, verify=verify)
