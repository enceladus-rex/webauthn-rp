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
                               EC2CredentialPublicKey, EC2Curve, EC2PublicKey,
                               OKPCredentialPublicKey, OKPCurve, OKPPublicKey)
from webauthn_rp.utils import ec2_hash_algorithm


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

  signature_algorithm = ECDSA(ec2_hash_algorithm(credential_public_key.alg))

  try:
    public_key.verify(signature, data, signature_algorithm)
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
