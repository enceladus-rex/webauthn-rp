import hashlib
from typing import Any, Optional
from unittest.mock import MagicMock

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from webauthn_rp.backends import CredentialsBackend
from webauthn_rp.constants import P_256_COORDINATE_BYTE_LENGTH
from webauthn_rp.converters import cryptography_public_key
from webauthn_rp.errors import RegistrationError, WebAuthnRPError
from webauthn_rp.registrars import CredentialData, CredentialsRegistrar
from webauthn_rp.types import *
from webauthn_rp.utils import ec2_hash_algorithm

from .common import (attested_credential_data, authenticator_data, base64s,
                     generate_ec2_credential_public_key,
                     generate_ec2_private_key, json_bytes)

TEST_USER = PublicKeyCredentialUserEntity(name='user',
                                          id=b'user-id',
                                          display_name='username')

TEST_RP_ORIGIN = 'https://example.com'
TEST_RP_ID = 'example.com'
TEST_RP_ID_HASH = hashlib.sha256(TEST_RP_ID.encode('utf-8')).digest()
TEST_RP = PublicKeyCredentialRpEntity(name='example.com', id=TEST_RP_ID)

TEST_EC2_CRV = EC2Curve.Value.P_256
TEST_COSE_ALG = COSEAlgorithmIdentifier.Value.ES256
TEST_CRYPTOGRAPHY_PRIVATE_KEY = generate_ec2_private_key(TEST_EC2_CRV)
TEST_CRYPTOGRAPHY_PUBLIC_KEY = TEST_CRYPTOGRAPHY_PRIVATE_KEY.public_key()
TEST_CRYPTOGRAPHY_PUBLIC_NUMBERS = TEST_CRYPTOGRAPHY_PUBLIC_KEY.public_numbers(
)
TEST_CREDENTIAL_PUBLIC_KEY = EC2CredentialPublicKey(
    kty=COSEKeyType.Value.EC2,
    crv=TEST_EC2_CRV,
    alg=TEST_COSE_ALG,
    x=TEST_CRYPTOGRAPHY_PUBLIC_NUMBERS.x.to_bytes(P_256_COORDINATE_BYTE_LENGTH,
                                                  'big'),
    y=TEST_CRYPTOGRAPHY_PUBLIC_NUMBERS.y.to_bytes(P_256_COORDINATE_BYTE_LENGTH,
                                                  'big'),
)


class ErrorCredentialsRegistrar(CredentialsRegistrar):
  def register_creation_options(self,
                                options: CredentialCreationOptions) -> Any:
    raise Exception()

  def register_request_options(self, options: CredentialRequestOptions) -> Any:
    raise Exception()

  def register_credential_creation(
      self,
      credential: PublicKeyCredential,
      att: AttestationObject,
      att_type: AttestationType,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      trusted_path: Optional[TrustedPath] = None) -> Any:
    raise Exception()

  def register_credential_request(self, credential: PublicKeyCredential,
                                  authenticator_data: AuthenticatorData,
                                  user: PublicKeyCredentialUserEntity,
                                  rp: PublicKeyCredentialRpEntity) -> Any:
    raise Exception()

  def get_credential_data(self,
                          credential_id: bytes) -> Optional[CredentialData]:
    raise Exception()

  def check_user_owns_credential(self, user_handle: bytes,
                                 credential_id: bytes) -> Optional[bool]:
    raise Exception()


class SuccessCredentialsRegistrar(CredentialsRegistrar):
  def register_creation_options(self,
                                options: CredentialCreationOptions) -> Any:
    pass

  def register_request_options(self, options: CredentialRequestOptions) -> Any:
    pass

  def register_credential_creation(
      self,
      credential: PublicKeyCredential,
      att: AttestationObject,
      att_type: AttestationType,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      trusted_path: Optional[TrustedPath] = None) -> Any:
    pass

  def register_credential_request(self, credential: PublicKeyCredential,
                                  authenticator_data: AuthenticatorData,
                                  user: PublicKeyCredentialUserEntity,
                                  rp: PublicKeyCredentialRpEntity) -> Any:
    pass

  def get_credential_data(self,
                          credential_id: bytes) -> Optional[CredentialData]:
    return CredentialData(TEST_CREDENTIAL_PUBLIC_KEY, 0)

  def check_user_owns_credential(self, user_handle: bytes,
                                 credential_id: bytes) -> Optional[bool]:
    return True


def test_credentials_backend_options_registration():
  backend = CredentialsBackend(ErrorCredentialsRegistrar())
  with pytest.raises(RegistrationError):
    backend.handle_creation_options(options=MagicMock())

  with pytest.raises(RegistrationError):
    backend.handle_request_options(options=MagicMock())

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  backend.handle_creation_options(options=MagicMock())
  backend.handle_request_options(options=MagicMock())


def test_credentials_backend_creation_success():
  backend = CredentialsBackend(SuccessCredentialsRegistrar())

  challenge = b'challenge'
  credential_id = b'credential-id'

  client_data_JSON = json_bytes({
      'type': 'webauthn.create',
      'challenge': base64s(challenge),
      'origin': TEST_RP_ORIGIN,
  })

  public_key_credential = PublicKeyCredential(
      id=base64s(credential_id),
      type='credential-type',
      raw_id=credential_id,
      response=AuthenticatorAttestationResponse(
          client_data_JSON=client_data_JSON,
          attestation_object=cbor2.dumps({
              'authData':
              authenticator_data(
                  TEST_RP_ID_HASH, (AuthenticatorDataFlag.UP.value
                                    | AuthenticatorDataFlag.AT.value
                                    | AuthenticatorDataFlag.ED.value),
                  b'\x00' * 4,
                  attested_credential_data(
                      b'z' * 16,
                      len(credential_id),
                      credential_id,
                      cbor2.dumps({
                          -3: TEST_CREDENTIAL_PUBLIC_KEY.y,
                          -2: TEST_CREDENTIAL_PUBLIC_KEY.x,
                          -1: TEST_CREDENTIAL_PUBLIC_KEY.crv.value,
                          1: TEST_CREDENTIAL_PUBLIC_KEY.kty.value,
                          3: TEST_CREDENTIAL_PUBLIC_KEY.alg.value,
                      }),
                  ), cbor2.dumps({
                      'appid': True,
                  })),
              'fmt':
              AttestationStatementFormatIdentifier.NONE.value,
              'attStmt': {}
          })))

  expected_challenge = challenge

  backend.handle_credential_creation(
      credential=public_key_credential,
      user=TEST_USER,
      rp=TEST_RP,
      expected_challenge=expected_challenge,
      expected_origin=TEST_RP_ORIGIN,
  )


def test_credentials_backend_request_success():
  backend = CredentialsBackend(SuccessCredentialsRegistrar())

  challenge = b'challenge'
  credential_id = b'credential-id'
  auth_data = authenticator_data(
      TEST_RP_ID_HASH,
      (AuthenticatorDataFlag.UP.value | AuthenticatorDataFlag.AT.value
       | AuthenticatorDataFlag.ED.value), b'\x00' * 4,
      attested_credential_data(
          b'z' * 16,
          len(credential_id),
          credential_id,
          cbor2.dumps({
              -3: TEST_CREDENTIAL_PUBLIC_KEY.y,
              -2: TEST_CREDENTIAL_PUBLIC_KEY.x,
              -1: TEST_CREDENTIAL_PUBLIC_KEY.crv.value,
              1: TEST_CREDENTIAL_PUBLIC_KEY.kty.value,
              3: TEST_CREDENTIAL_PUBLIC_KEY.alg.value,
          }),
      ), cbor2.dumps({
          'appid': True,
      }))
  client_data_JSON = json_bytes({
      'type': 'webauthn.get',
      'challenge': base64s(challenge),
      'origin': TEST_RP_ORIGIN,
  })

  signature_algorithm = ECDSA(ec2_hash_algorithm(TEST_COSE_ALG))
  signature = TEST_CRYPTOGRAPHY_PRIVATE_KEY.sign(
      auth_data + hashlib.sha256(client_data_JSON).digest(),
      signature_algorithm,
  )

  public_key_credential = PublicKeyCredential(
      id=base64s(credential_id),
      type='credential-type',
      raw_id=credential_id,
      response=AuthenticatorAssertionResponse(
          client_data_JSON=client_data_JSON,
          authenticator_data=auth_data,
          signature=signature,
      ))

  expected_challenge = challenge

  backend.handle_credential_request(
      credential=public_key_credential,
      user=TEST_USER,
      rp=TEST_RP,
      expected_challenge=expected_challenge,
      expected_origin=TEST_RP_ORIGIN,
  )
