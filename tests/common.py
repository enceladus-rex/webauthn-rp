import datetime
import hashlib
import random
from base64 import b64encode
from enum import Enum
from pprint import pprint
from typing import Any, Dict, List, Optional, Tuple, Type

import cryptography
import cryptography.x509
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, SECP384R1, SECP521R1, EllipticCurve,
    EllipticCurvePrivateKey, EllipticCurvePublicNumbers, generate_private_key)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.extensions import Extension, UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from webauthn_rp.asn1 import AuthorizationList, KeyDescription
from webauthn_rp.constants import *
from webauthn_rp.errors import ValidationError, VerificationError
from webauthn_rp.parsers import parse_cose_key
from webauthn_rp.types import *
from webauthn_rp.utils import curve_coordinate_byte_length

TEST_RP_ID = b'example.org'
TEST_RP_ID_HASH = hashlib.sha256(TEST_RP_ID).digest()
TEST_CREDENTIAL_ID = b'credential-id'
TEST_CREDENTIAL_ID_LENGTH = len(TEST_CREDENTIAL_ID)
TEST_AAGUID = b'x' * 16


def base64s(b: bytes) -> str:
  return b64encode(b).decode('utf8')


def generate_pseudorandom_bytes(num_bytes: int, seed: Any = None) -> bytes:
  rs = random.Random()
  if seed is not None:
    rs.seed(seed)

  b = []
  for _ in range(num_bytes):
    b.append(rs.randint(0, 255))
  return bytes(b)


def single_byte_errors(data: bytes) -> List[bytes]:
  errors = []
  for i in range(len(data)):
    e = bytes([(data[i] + 1) % 256])
    errors.append(data[:i - 1] + e + data[i + 1:])
  return errors


def generate_x509_certificate(
    public_key: PublicKey,
    private_key: PrivateKey,
    algorithm: hashes.HashAlgorithm,
    extensions: Optional[List[Extension]] = None) -> x509.Certificate:
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


def generate_elliptic_curve_x509_certificate(
    curve: EllipticCurve
) -> Tuple[x509.Certificate, EC2PrivateKey, EC2PublicKey]:
  private_key = generate_private_key(curve, default_backend())
  public_key = private_key.public_key()
  return generate_x509_certificate(public_key, private_key,
                                   hashes.SHA256()), private_key, public_key


def generate_elliptic_curve_x509_certificate_android(
    curve: EllipticCurve, attestation_challenge: bytes
) -> Tuple[x509.Certificate, EC2PrivateKey, EC2PublicKey]:
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


def generate_signature(private_key: EC2PrivateKey, data: bytes) -> bytes:
  return private_key.sign(data, ECDSA(hashes.SHA256()))


def generate_ec2_private_key(crv: EC2Curve.Value) -> EllipticCurvePrivateKey:
  key_to_curve = {
      EC2Curve.Value.P_256: SECP256R1,
      EC2Curve.Value.P_384: SECP384R1,
      EC2Curve.Value.P_521: SECP521R1,
  }

  curve = key_to_curve[crv]
  return generate_private_key(curve(), default_backend())  # type: ignore


def generate_ec2_public_key(crv: EC2Curve.Value) -> EllipticCurvePublicKey:
  return generate_ec2_private_key(crv).public_key()


def generate_ec2_credential_public_key(
    crv: EC2Curve.Value,
    alg: Optional[COSEAlgorithmIdentifier.Value] = None
) -> EC2CredentialPublicKey:
  clen = curve_coordinate_byte_length(crv)
  random_public_numbers = generate_ec2_public_key(crv).public_numbers()
  return EC2CredentialPublicKey(
      kty=COSEKeyType.Value.EC2,
      crv=crv,
      alg=alg or COSEAlgorithmIdentifier.Value.ES256,
      x=random_public_numbers.x.to_bytes(clen, 'big'),
      y=random_public_numbers.y.to_bytes(clen, 'big'),
  )


def generate_okp_private_key(
    crv: OKPCurve.Value) -> Union[Ed25519PrivateKey, Ed448PrivateKey]:
  crv_to_pk = {
      OKPCurve.Value.ED25519: Ed25519PrivateKey,
      OKPCurve.Value.ED448: Ed448PrivateKey,
  }

  return crv_to_pk[crv].generate()  # type: ignore


def generate_okp_credential_public_key(
    crv: OKPCurve.Value, alg: Optional[COSEAlgorithmIdentifier.Value] = None):
  private_key_generator = {
      OKPCurve.Value.ED25519: Ed25519PrivateKey,
      OKPCurve.Value.ED448: Ed448PrivateKey,
  }

  private_key = private_key_generator[crv].generate()  # type: ignore
  public_number = private_key.public_key().public_bytes(
      Encoding.Raw, PublicFormat.Raw)

  return OKPCredentialPublicKey(
      kty=COSEKeyType.Value.OKP,
      crv=crv,
      alg=alg or COSEAlgorithmIdentifier.Value.ES256,
      x=public_number,
  )


def assert_objects_equal(a, b):
  assert type(a) is type(b)

  if isinstance(a, (int, str, float, bytes, Enum)):
    assert a == b
  elif isinstance(a, (list, tuple)):
    assert len(a) == len(b)
    for x, y in zip(a, b):
      assert_objects_equal(x, y)
  elif isinstance(a, set):
    assert a == b
  elif a is None:
    assert a == b
  else:
    assert set(a.__dict__.keys()) == set(b.__dict__.keys())

    for k in a.__dict__:
      assert_objects_equal(a.__dict__[k], b.__dict__[k])
