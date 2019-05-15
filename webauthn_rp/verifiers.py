from functools import singledispatch

import cryptography
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from .converters import cryptography_public_key
from .errors import ValidationError, UnimplementedError, VerificationError
from .types import (
  CredentialPublicKey,
  EC2CredentialPublicKey,
  OKPCredentialPublicKey,
)


@singledispatch
def verify(
    credential_public_key: CredentialPublicKey,
    signature: bytes, data: bytes):
  raise UnimplementedError('Must implement verification for {}'.format(
    str(type(credential_public_key))
  ))


@verify.register(EC2CredentialPublicKey)
def verify_ec2_credential_public_key(
    credential_public_key: EC2CredentialPublicKey,
    signature: bytes, data: bytes):
  public_key = cryptography_public_key(credential_public_key)

  hash_algorithm = None
  if credential_public_key.crv.name == 'P_256': hash_algorithm = SHA256
  elif credential_public_key.crv.name == 'P_384': hash_algorithm = SHA384
  elif credential_public_key.crv.name == 'P_512': hash_algorithm = SHA512
  else:
    raise ValidationError('Unsupported EC2 curve {}'.format(
      credential_public_key.crv.name
    ))
    
  try:
    public_key.verify(signature, data, hash_algorithm)
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('EC2 verification failure')


@verify.register(OKPCredentialPublicKey)
def verify_okp_credential_public_key(
    credential_public_key: OKPCredentialPublicKey,
    signature: bytes, data: bytes):
  public_key = cryptography_public_key(credential_public_key)

  try:
    public_key.verify(signature, data)
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('OKP verification failure')