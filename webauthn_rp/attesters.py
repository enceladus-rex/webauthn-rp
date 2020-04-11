from functools import singledispatch
from typing import Optional, Sequence, Tuple, cast

import cryptography
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import Certificate
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error

from webauthn_rp.asn1 import KeyDescription
from webauthn_rp.constants import KM_ORIGIN_GENERATED, KM_PURPOSE_SIGN
from webauthn_rp.converters import cryptography_public_key
from webauthn_rp.errors import (AttestationError, UnimplementedError,
                                ValidationError, VerificationError)
from webauthn_rp.types import (AndroidKeyAttestationStatement,
                               AttestationObject, AttestationStatement,
                               AttestationType, CredentialPublicKey,
                               EC2CredentialPublicKey,
                               FIDOU2FAttestationStatement,
                               NoneAttestationStatement, TrustedPath)


@singledispatch
def attest(att_stmt: AttestationStatement, att_obj: AttestationObject,
           auth_data: bytes,
           client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  raise UnimplementedError('{} verification unimplemented'.format(
      type(att_stmt)))


@attest.register(FIDOU2FAttestationStatement)
def attest_fido_u2f(
    att_stmt: FIDOU2FAttestationStatement, att_obj: AttestationObject,
    auth_data: bytes,
    client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  """Attest a FIDO U2F key.

  Args:
    att_stmt (FIDOU2FAttestationStatement): The attestation statment.
    att_obj (AttestationObject): The attestation object.
    auth_data (bytes): The raw authenticator data.
    client_data_hash (bytes): The client data hash.

  Returns:
    The attestation type and trusted path.
  
  References:
    * https://www.w3.org/TR/webauthn/#fido-u2f-attestation
  """
  if len(att_stmt.x5c) != 1:
    raise ValidationError(
        'FIDO U2F verification failed: must have a single X.509 certificate')

  att_cert = att_stmt.x5c[0]
  att_cert_x509 = cryptography.x509.load_der_x509_certificate(
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
  public_key_u2f = b'\x04' + (credential_public_key.x +
                              credential_public_key.y)

  rp_id_hash = att_obj.auth_data.rp_id_hash
  credential_id = att_obj.auth_data.attested_credential_data.credential_id
  verification_data = (b'\x00' + rp_id_hash +
                       (client_data_hash + credential_id + public_key_u2f))

  assert att_stmt.sig is not None

  try:
    att_cert_x509_pk.verify(att_stmt.sig, verification_data, ECDSA(SHA256()))
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError('FIDO U2F verification failed: invalid signature')

  return AttestationType.BASIC, [att_cert_x509]


@attest.register(AndroidKeyAttestationStatement)
def attest_android_key(
    att_stmt: AndroidKeyAttestationStatement, att_obj: AttestationObject,
    auth_data: bytes,
    client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  """Attest an android key.

  Args:
    att_stmt (AndroidKeyAttestationStatement): The attestation statment.
    att_obj (AttestationObject): The attestation object.
    auth_data (bytes): The raw authenticator data.
    client_data_hash (bytes): The client data hash.

  Returns:
    The attestation type and trusted path.
  
  References:
    * https://www.w3.org/TR/webauthn/#android-key-attestation
    * https://source.android.com/security/keystore/attestation
    * https://developer.android.com/training/articles/security-key-attestation
  """
  if len(att_stmt.x5c) == 0:
    raise ValidationError('Must have at least 1 X509 certificate')

  credential_certificate = cryptography.x509.load_der_x509_certificate(
      att_stmt.x5c[0], default_backend())
  cred_cert_pk = credential_certificate.public_key()
  if not isinstance(
      cred_cert_pk,
      (EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey)):
    raise ValidationError(
        'Android key verification failed: must use an Elliptic Curve Public Key'
    )

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

  assert att_obj.auth_data is not None
  assert att_obj.auth_data.attested_credential_data is not None

  cpk = cryptography_public_key(
      att_obj.auth_data.attested_credential_data.credential_public_key)

  verification_data = auth_data + client_data_hash
  assert att_stmt.sig is not None

  try:
    if hash_algorithm is not None:
      assert isinstance(cred_cert_pk, EllipticCurvePublicKey)
      cred_cert_pk.verify(att_stmt.sig, verification_data, hash_algorithm)
    else:
      assert isinstance(cred_cert_pk, (Ed25519PublicKey, Ed448PublicKey))
      cred_cert_pk.verify(att_stmt.sig, verification_data)
  except cryptography.exceptions.InvalidSignature:
    raise VerificationError(
        'Android Key verification failed: invalid signature')

  cpk_public_bytes = cpk.public_bytes(Encoding.DER,
                                      PublicFormat.SubjectPublicKeyInfo)
  cred_cert_public_bytes = cred_cert_pk.public_bytes(
      Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
  if cpk_public_bytes != cred_cert_public_bytes:
    raise ValidationError(
        ('Certificate public key in attestation statement must match the '
         'provided credential public key'))

  try:
    extension = credential_certificate.extensions.get_extension_for_oid(
        ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17'))
    assert isinstance(extension.value, UnrecognizedExtension)
  except cryptography.x509.ExtensionNotFound:
    raise ValidationError(
        'Could not find android key attestation certificate extension data')

  try:
    key_description, _ = decode(extension.value.value, KeyDescription())
  except PyAsn1Error:
    raise ValidationError(
        'Unable to decode DER-encoded Android Key Description')

  attestation_challenge = key_description['attestationChallenge'].asOctets()
  if attestation_challenge != client_data_hash:
    raise ValidationError(
        'Client data hash does not match value of attestation extension data')

  all_apps_se = key_description['softwareEnforced']['allApplications']
  all_apps_tee = key_description['teeEnforced']['allApplications']
  if all_apps_se.hasValue() or all_apps_tee.hasValue():
    raise ValidationError('The allApplications field must not be present '
                          'in the android key description')

  # TODO: Consider selecting the appropriate AuthorizationList.
  tee_origin = key_description['teeEnforced']['origin']
  tee_purpose = key_description['teeEnforced']['purpose']
  if not tee_origin.hasValue() or int(tee_origin) != KM_ORIGIN_GENERATED:
    raise ValidationError('The teeEnforced origin field must equal '
                          'KM_ORIGIN_GENERATED={}'.format(KM_ORIGIN_GENERATED))

  # TODO: Determine if other purposes are also allowed in this set.
  if not tee_purpose.hasValue() or tee_purpose.count(KM_PURPOSE_SIGN) == 0:
    raise ValidationError('The teeEnforced purpose field must contain '
                          'KM_PURPOSE_SIGN={}'.format(KM_PURPOSE_SIGN))

  return AttestationType.BASIC, [credential_certificate]


@attest.register(NoneAttestationStatement)
def attest_none(
    att_stmt: NoneAttestationStatement, att_obj: AttestationObject,
    auth_data: bytes,
    client_data_hash: bytes) -> Tuple[AttestationType, TrustedPath]:
  return AttestationType.NONE, None
