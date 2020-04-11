from functools import singledispatch
from typing import cast

import cryptography
import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

from webauthn_rp.converters import cryptography_public_key
from webauthn_rp.errors import (UnimplementedError, ValidationError,
                                VerificationError)
from webauthn_rp.types import (COSEAlgorithmIdentifier, CredentialPublicKey,
                               EC2CredentialPublicKey, EC2KeyType,
                               EC2PublicKey, OKPCredentialPublicKey,
                               OKPKeyType, OKPPublicKey)


@singledispatch
def verify(credential_public_key: CredentialPublicKey, signature: bytes,
           data: bytes):
  raise UnimplementedError('Must implement verification for {}'.format(
      str(type(credential_public_key))))


@verify.register(EC2CredentialPublicKey)
def verify_ec2_credential_public_key(
    credential_public_key: EC2CredentialPublicKey, signature: bytes,
    data: bytes):
  public_key = cast(EC2PublicKey,
                    cryptography_public_key(credential_public_key))
  if credential_public_key.alg is None:
    raise ValidationError('alg must not be None')

  alg_name = credential_public_key.alg.name
  alg_to_hash = {
      'ES256': SHA256,
      'ES384': SHA384,
      'ES512': SHA512,
  }

  hash_algorithm = None
  if alg_name in alg_to_hash:
    hash_algorithm = ECDSA(alg_to_hash[alg_name]())
  else:
    raise ValidationError('Unsupported EC2 alg {}'.format(alg_name))

  try:
    public_key.verify(signature, data, hash_algorithm)
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('EC2 verification failure')


@verify.register(OKPCredentialPublicKey)
def verify_okp_credential_public_key(
    credential_public_key: OKPCredentialPublicKey, signature: bytes,
    data: bytes):
  public_key = cast(OKPPublicKey,
                    cryptography_public_key(credential_public_key))

  try:
    public_key.verify(signature, data)
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('OKP verification failure')
