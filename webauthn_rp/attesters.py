from functools import singledispatch
from typing import Optional, Sequence, Tuple, cast

import cryptography
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, ECDSA, SECP256R1)
from cryptography.hazmat.primitives.hashes import (SHA256, SHA384, SHA512)
from cryptography.x509 import Certificate

from .converters import cryptography_public_key
from .errors import (AttestationError, UnimplementedError, ValidationError,
                     VerificationError)
from .types import (AndroidKeyAttestationStatement, AttestationObject,
                    AttestationStatement, AttestationType, CredentialPublicKey,
                    EC2CredentialPublicKey, FIDOU2FAttestationStatement,
                    NoneAttestationStatement, TrustedPath)


@singledispatch
def attest(att_stmt: AttestationStatement, att_obj: AttestationObject,
           auth_data: bytes,
           client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  raise UnimplementedError('{} verification unimplemented'.format(
      type(att_stmt)))


@attest.register(FIDOU2FAttestationStatement)
def attest_fido_u2f(att_stmt: FIDOU2FAttestationStatement,
                    att_obj: AttestationObject, auth_data: bytes,
                    client_data_hash: bytes
                    ) -> Tuple[AttestationType, TrustedPath]:
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

  assert att_obj.auth_data is not None
  assert att_obj.auth_data.attested_credential_data is not None

  credential_public_key = cast(
      EC2CredentialPublicKey,
      att_obj.auth_data.attested_credential_data.credential_public_key)

  assert credential_public_key is not None
  public_key_u2f = bytes.fromhex('04') + (credential_public_key.x +
                                          credential_public_key.y)

  rp_id_hash = att_obj.auth_data.rp_id_hash
  credential_id = att_obj.auth_data.attested_credential_data.credential_id
  verification_data = (bytes.fromhex('00') + rp_id_hash +
                       (client_data_hash + credential_id + public_key_u2f))

  try:
    att_cert_x509_pk.verify(att_stmt.sig, verification_data, SHA256())
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('FIDO U2F verification failed: invalid signature')

  return AttestationType.UNCERTAIN, [att_cert_x509]


@attest.register(AndroidKeyAttestationStatement)
def attest_android_key(att_stmt: AndroidKeyAttestationStatement,
                       att_obj: AttestationObject, auth_data: bytes,
                       client_data_hash: bytes
                       ) -> Tuple[AttestationType, TrustedPath]:
  if len(att_stmt.x5c) == 0:
    raise ValidationError('Must have at least 1 X509 certificate')

  credential_certificate = cryptography.x509.load_pem_x509_certificate(
      att_stmt.x5c[0], default_backend())
  cred_cert_pk = credential_certificate.public_key()

  assert att_stmt.alg is not None
  alg_name = att_stmt.alg.name

  alg_to_hash = {
      'ES256': SHA256,
      'ES384': SHA384,
      'ES512': SHA512,
  }

  hash_algorithm = None
  if alg_name in alg_to_hash: hash_algorithm = ECDSA(alg_to_hash[alg_name]())
  elif alg_name != 'EDDSA':
    raise ValidationError('Unsupported hashing algorithm {}'.format(alg_name))

  verification_data = auth_data + client_data_hash
  try:
    if hash_algorithm is not None:
      cred_cert_pk.verify(att_stmt.sig, verification_data, hash_algorithm)
    else:
      cred_cert_pk.verify(att_stmt.sig, verification_data)
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError(
        'Android Key verification failed: invalid signature')

  assert att_obj.auth_data is not None
  assert att_obj.auth_data.attested_credential_data is not None

  cpk = cryptography_public_key(
      att_obj.auth_data.attested_credential_data.credential_public_key)

  if cpk != cred_cert_pk:
    raise ValidationError(
        ('Certificate public key in attestation statement must match the '
         'provided credential public key'))

  return AttestationType.UNCERTAIN, [credential_certificate]


@attest.register(NoneAttestationStatement)
def attest_none(att_stmt: NoneAttestationStatement, att_obj: AttestationObject,
                auth_data: bytes, client_data_hash: bytes
                ) -> Tuple[AttestationType, TrustedPath]:
  return AttestationType.NONE, None
