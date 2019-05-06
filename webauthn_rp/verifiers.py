from functools import singledispatch

import cryptography
import cryptography.x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate

from typing import Tuple, Sequence, Optional

from .errors import UnimplementedError, ValidationError, VerificationError
from .types import (
  FIDOU2FAttestationStatement,
  NoneAttestationStatement,
  AttestationStatement,
  CredentialPublicKey,
  AttestationObject,
  AttestationType,
  TrustedPath,
)


@singledispatch
def verify(
    att_stmt: AttestationStatement,
    att_obj: AttestationObject,
    auth_data: bytes,
    client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  raise UnimplementedError(
    '{} verification unimplemented'.format(type(att_stmt)))


@verify.register(FIDOU2FAttestationStatement)
def verify_fido_u2f(
    att_stmt: FIDOU2FAttestationStatement,
    att_obj: AttestationObject,
    auth_data: bytes,
    client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  if len(att_stmt.x5c) != 1:
    raise ValidationError(
      'FIDO U2F verification failed: must have a single X.509 certificate')
  
  att_cert = att_stmt.x5c[0]
  att_cert_x509 = cryptography.x509.load_pem_x509_certificate(
    att_cert, default_backend())
  att_cert_x509_pk = att_cert_x509.public_key()
  if not isinstance(att_cert_x509_pk, EllipticCurvePublicKey):
    raise ValidationError(
      'FIDO U2F verification failed: must use an Elliptic Curve Public Key')

  if not isinstance(att_cert_x509_pk.curve, SECP256R1):
    raise ValidationError(
      'FIDO U2F verification failed: must use an Elliptic Curve Public Key')

  credential_public_key = (
    att_obj.auth_data.attested_credential_data.credential_public_key)
  public_key_u2f = bytes.fromhex('04') + (
    credential_public_key.x + credential_public_key.y)

  rp_id_hash = att_obj.auth_data.rp_id_hash
  credential_id = att_obj.auth_data.attested_credential_data
  verification_data = (
    bytes.fromhex('00') + rp_id_hash + (
      client_data_hash + credential_id + public_key_u2f))

  try:
    att_cert_x509_pk.verify(att_stmt.sig, verification_data, SHA256())
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('FIDO U2F verification failed: invalid signature')
  
  return AttestationType.UNCERTAIN, [att_cert_x509]


@verify.register(NoneAttestationStatement)
def verify_none(
    att_stmt: NoneAttestationStatement,
    att_obj: AttestationObject,
    auth_data: bytes,
    client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  return AttestationType.NONE, None