import datetime
import hashlib
from typing import List, Optional

import cryptography
import cryptography.x509
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, EllipticCurve, EllipticCurvePublicNumbers,
    generate_private_key)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.extensions import Extension, UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

import webauthn_rp.types
from webauthn_rp.asn1 import AuthorizationList, KeyDescription
from webauthn_rp.attesters import attest
from webauthn_rp.constants import (EC2_P_256_NUMBER_LENGTH,
                                   KM_ORIGIN_GENERATED, KM_PURPOSE_SIGN)
from webauthn_rp.errors import ValidationError, VerificationError
from webauthn_rp.types import (AndroidKeyAttestationStatement,
                               AttestationObject,
                               AttestationStatementFormatIdentifier,
                               AttestationType, AttestedCredentialData,
                               AuthenticatorData, COSEAlgorithmIdentifier,
                               COSEKeyType, EC2CredentialPublicKey, EC2KeyType,
                               FIDOU2FAttestationStatement,
                               NoneAttestationStatement, PrivateKey, PublicKey)

TEST_RP_ID = b'example.org'
TEST_RP_ID_HASH = hashlib.sha256(TEST_RP_ID).digest()
TEST_CREDENTIAL_ID = b'credential-id'
TEST_CREDENTIAL_ID_LENGTH = len(TEST_CREDENTIAL_ID)
TEST_AAGUID = b'x' * 16


def generate_x509_certificate(public_key: PublicKey,
                              private_key: PrivateKey,
                              algorithm: hashes.HashAlgorithm,
                              extensions: Optional[List[Extension]] = None):
  if extensions is None:
    extensions = []
  builder = cryptography.x509.CertificateBuilder(
      issuer_name=x509.Name(
          [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'issuer')]),
      subject_name=x509.Name(
          [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'subject')]),
      serial_number=1,
      not_valid_before=datetime.datetime(2000,
                                         1,
                                         1,
                                         0,
                                         0,
                                         0,
                                         tzinfo=datetime.timezone.utc),
      not_valid_after=datetime.datetime(3000,
                                        1,
                                        1,
                                        0,
                                        0,
                                        0,
                                        tzinfo=datetime.timezone.utc),
      public_key=public_key,
      extensions=extensions)

  return builder.sign(private_key=private_key,
                      algorithm=algorithm,
                      backend=default_backend())


def generate_elliptic_curve_x509_certificate(curve: EllipticCurve):
  private_key = generate_private_key(curve, default_backend())
  public_key = private_key.public_key()
  return generate_x509_certificate(public_key, private_key,
                                   hashes.SHA256()), private_key, public_key


def generate_elliptic_curve_x509_certificate_android(
    curve: EllipticCurve, attestation_challenge: bytes):
  android_key_oid = ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17')
  android_key_description = KeyDescription()
  android_key_description['attestationVersion'] = 0
  android_key_description['attestationSecurityLevel'] = 0
  android_key_description['keymasterVersion'] = 0
  android_key_description['keymasterSecurityLevel'] = 0
  android_key_description['attestationChallenge'] = attestation_challenge
  android_key_description['uniqueId'] = b'unique'

  software_enforced = AuthorizationList()
  software_enforced['origin'] = KM_ORIGIN_GENERATED
  software_enforced['purpose'].append(KM_PURPOSE_SIGN)
  android_key_description['softwareEnforced'] = software_enforced

  tee_enforced = AuthorizationList()
  tee_enforced['origin'] = KM_ORIGIN_GENERATED
  tee_enforced['purpose'].append(KM_PURPOSE_SIGN)
  android_key_description['teeEnforced'] = tee_enforced

  der_key = encode(android_key_description)

  extensions = [
      Extension(android_key_oid, False,
                UnrecognizedExtension(android_key_oid, der_key))
  ]

  private_key = generate_private_key(curve, default_backend())
  public_key = private_key.public_key()
  return generate_x509_certificate(
      public_key, private_key, hashes.SHA256(),
      extensions=extensions), private_key, public_key


def generate_signature(private_key: PrivateKey, data: bytes) -> bytes:
  return private_key.sign(data, ECDSA(hashes.SHA256()))


def test_attest_fido_u2f():
  client_data_hash = b'client-data-hash'

  certificate, private_key, public_key = generate_elliptic_curve_x509_certificate(
      SECP256R1())
  public_numbers = private_key.private_numbers().public_numbers

  x = public_numbers.x.to_bytes(EC2_P_256_NUMBER_LENGTH, 'big')
  y = public_numbers.y.to_bytes(EC2_P_256_NUMBER_LENGTH, 'big')
  public_key_u2f = b'\x04' + x + y
  verification_data = b''.join([
      b'\x00',
      TEST_RP_ID_HASH,
      client_data_hash,
      TEST_CREDENTIAL_ID,
      public_key_u2f,
  ])

  credential_public_key = EC2CredentialPublicKey(
      x=x,
      y=y,
      kty=COSEKeyType.Name.EC2,
      crv=EC2KeyType.Name.P_256,
  )

  attested_credential_data = AttestedCredentialData(
      aaguid=TEST_AAGUID,
      credential_id_length=TEST_CREDENTIAL_ID_LENGTH,
      credential_id=TEST_CREDENTIAL_ID,
      credential_public_key=credential_public_key,
  )

  signature = generate_signature(private_key, verification_data)

  auth_data = b'auth-data'
  invalid_att_stmt = FIDOU2FAttestationStatement(sig=b'', x5c=[b'', b''])

  att_obj = AttestationObject(
      auth_data=AuthenticatorData(
          rp_id_hash=TEST_RP_ID_HASH,
          flags=0,
          sign_count=0,
          attested_credential_data=attested_credential_data,
          extensions=None),
      fmt=AttestationStatementFormatIdentifier.FIDO_U2F,
      att_stmt=invalid_att_stmt)

  with pytest.raises(ValidationError):
    attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

  der_certificate = certificate.public_bytes(Encoding.DER)
  valid_att_stmt = FIDOU2FAttestationStatement(sig=signature,
                                               x5c=[der_certificate])

  att_obj.att_stmt = valid_att_stmt
  assert attest(valid_att_stmt, att_obj, auth_data,
                client_data_hash) == (AttestationType.BASIC, [certificate])

  unverified_att_stmt = FIDOU2FAttestationStatement(sig=b'bad-signature',
                                                    x5c=[der_certificate])
  att_obj.att_stmt = unverified_att_stmt
  with pytest.raises(VerificationError):
    attest(unverified_att_stmt, att_obj, auth_data, client_data_hash)


def test_attest_android_key():
  client_data_hash = b'client-data-hash'
  auth_data = b'auth-data'

  certificate, private_key, public_key = generate_elliptic_curve_x509_certificate_android(
      SECP256R1(), client_data_hash)
  public_numbers = private_key.private_numbers().public_numbers

  x = public_numbers.x.to_bytes(EC2_P_256_NUMBER_LENGTH, 'big')
  y = public_numbers.y.to_bytes(EC2_P_256_NUMBER_LENGTH, 'big')
  public_key_android = b'\x04' + x + y
  verification_data = auth_data + client_data_hash

  credential_public_key = EC2CredentialPublicKey(
      x=x,
      y=y,
      kty=COSEKeyType.Name.EC2,
      crv=EC2KeyType.Name.P_256,
  )

  attested_credential_data = AttestedCredentialData(
      aaguid=TEST_AAGUID,
      credential_id_length=TEST_CREDENTIAL_ID_LENGTH,
      credential_id=TEST_CREDENTIAL_ID,
      credential_public_key=credential_public_key,
  )

  signature = generate_signature(private_key, verification_data)

  invalid_att_stmt = AndroidKeyAttestationStatement(
      alg=COSEAlgorithmIdentifier.Name.ES256, sig=b'', x5c=[])

  att_obj = AttestationObject(
      auth_data=AuthenticatorData(
          rp_id_hash=TEST_RP_ID_HASH,
          flags=0,
          sign_count=0,
          attested_credential_data=attested_credential_data,
          extensions=None),
      fmt=AttestationStatementFormatIdentifier.FIDO_U2F,
      att_stmt=invalid_att_stmt)

  with pytest.raises(ValidationError):
    attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

  der_certificate = certificate.public_bytes(Encoding.DER)
  valid_att_stmt = AndroidKeyAttestationStatement(
      alg=COSEAlgorithmIdentifier.Name.ES256,
      sig=signature,
      x5c=[der_certificate])

  att_obj.att_stmt = valid_att_stmt
  assert attest(valid_att_stmt, att_obj, auth_data,
                client_data_hash) == (AttestationType.BASIC, [certificate])

  unverified_att_stmt = AndroidKeyAttestationStatement(
      alg=COSEAlgorithmIdentifier.Name.ES256,
      sig=b'bad-signature',
      x5c=[der_certificate])
  att_obj.att_stmt = unverified_att_stmt
  with pytest.raises(VerificationError):
    attest(unverified_att_stmt, att_obj, auth_data, client_data_hash)


def test_attest_none(mocker):
  mocker.patch('webauthn_rp.types.AttestationObject')
  assert attest(NoneAttestationStatement(),
                webauthn_rp.types.AttestationObject(), b'',
                b'') == (AttestationType.NONE, None)
