import hashlib
from typing import Any, Optional
from unittest.mock import MagicMock

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from webauthn_rp.backends import CredentialsBackend
from webauthn_rp.constants import P_256_COORDINATE_BYTE_LENGTH
from webauthn_rp.converters import cryptography_public_key
from webauthn_rp.errors import *
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


class ExceptionCredentialsRegistrar(CredentialsRegistrar):
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
    return CredentialData(TEST_CREDENTIAL_PUBLIC_KEY, 0, TEST_USER)


class ErrorCredentialsRegistrar(CredentialsRegistrar):
  def register_creation_options(self,
                                options: CredentialCreationOptions) -> Any:
    return 'Error'

  def register_request_options(self, options: CredentialRequestOptions) -> Any:
    return 'Error'

  def register_credential_creation(
      self,
      credential: PublicKeyCredential,
      att: AttestationObject,
      att_type: AttestationType,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      trusted_path: Optional[TrustedPath] = None) -> Any:
    return 'Error'

  def register_credential_request(self, credential: PublicKeyCredential,
                                  authenticator_data: AuthenticatorData,
                                  user: PublicKeyCredentialUserEntity,
                                  rp: PublicKeyCredentialRpEntity) -> Any:
    return 'Error'

  def get_credential_data(self,
                          credential_id: bytes) -> Optional[CredentialData]:
    return CredentialData(TEST_CREDENTIAL_PUBLIC_KEY, 0, TEST_USER)


def test_credentials_backend_options_registration():
  backend = CredentialsBackend(ExceptionCredentialsRegistrar())
  with pytest.raises(RegistrationError):
    backend.handle_creation_options(options=MagicMock())

  with pytest.raises(RegistrationError):
    backend.handle_request_options(options=MagicMock())

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


def test_credentials_backend_creation_error():
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

  client_data_JSON_error = json_bytes({
      'type': 'webauthn.get',
      'challenge': base64s(challenge),
      'origin': TEST_RP_ORIGIN,
  })

  public_key_credential.response.client_data_JSON = client_data_JSON_error
  with pytest.raises(ValidationError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  public_key_credential.response.client_data_JSON = client_data_JSON
  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge + b'-altered',
        expected_origin=TEST_RP_ORIGIN,
    )

  client_data_JSON_error = json_bytes({
      'type': 'webauthn.create',
      'challenge': '\x90\x91\x92',
      'origin': TEST_RP_ORIGIN,
  })

  public_key_credential.response.client_data_JSON = client_data_JSON_error
  with pytest.raises(DecodingError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  public_key_credential.response.client_data_JSON = client_data_JSON
  with pytest.raises(OriginError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin='https://example.org/path',
    )

  with pytest.raises(OriginError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin='https://',
    )

  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin='https://alternative.org',
    )

  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(credential=public_key_credential,
                                       user=TEST_USER,
                                       rp=TEST_RP,
                                       expected_challenge=expected_challenge,
                                       expected_origin=TEST_RP_ORIGIN,
                                       token_binding=TokenBinding(
                                           status=TokenBindingStatus.PRESENT,
                                           id='token-binding-id'))

  client_data_JSON_token_binding = json_bytes({
      'type': 'webauthn.create',
      'challenge': base64s(challenge),
      'origin': TEST_RP_ORIGIN,
      'tokenBinding': {
          'status': 'supported'
      }
  })

  public_key_credential.response.client_data_JSON = (
      client_data_JSON_token_binding)
  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(credential=public_key_credential,
                                       user=TEST_USER,
                                       rp=TEST_RP,
                                       expected_challenge=expected_challenge,
                                       expected_origin=TEST_RP_ORIGIN,
                                       token_binding=TokenBinding(
                                           status=TokenBindingStatus.PRESENT,
                                           id='token-binding-id'))

  public_key_credential.response.client_data_JSON = json_bytes({
      'type':
      'webauthn.create',
      'challenge':
      base64s(challenge),
      'origin':
      TEST_RP_ORIGIN,
      'tokenBinding': {
          'status': 'present',
          'id': 'token-binding-id'
      }
  })

  backend.handle_credential_creation(credential=public_key_credential,
                                     user=TEST_USER,
                                     rp=TEST_RP,
                                     expected_challenge=expected_challenge,
                                     expected_origin=TEST_RP_ORIGIN,
                                     token_binding=TokenBinding(
                                         status=TokenBindingStatus.PRESENT,
                                         id='token-binding-id'))

  public_key_credential.response.client_data_JSON = json_bytes({
      'type':
      'webauthn.create',
      'challenge':
      base64s(challenge),
      'origin':
      TEST_RP_ORIGIN,
      'tokenBinding': {
          'status': 'present',
          'id': 'token-binding-id-invalid'
      }
  })

  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(credential=public_key_credential,
                                       user=TEST_USER,
                                       rp=TEST_RP,
                                       expected_challenge=expected_challenge,
                                       expected_origin=TEST_RP_ORIGIN,
                                       token_binding=TokenBinding(
                                           status=TokenBindingStatus.PRESENT,
                                           id='token-binding-id'))

  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  public_key_credential.response.client_data_JSON = client_data_JSON

  public_key_credential_error = PublicKeyCredential(
      id=base64s(credential_id),
      type='credential-type',
      raw_id=credential_id,
      response=AuthenticatorAttestationResponse(
          client_data_JSON=client_data_JSON,
          attestation_object=cbor2.dumps({
              'authData':
              authenticator_data(
                  hashlib.sha256(b'invalid').digest(),
                  (AuthenticatorDataFlag.UP.value
                   | AuthenticatorDataFlag.AT.value
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
                  })),
              'fmt':
              AttestationStatementFormatIdentifier.NONE.value,
              'attStmt': {}
          })))

  with pytest.raises(IntegrityError):
    backend.handle_credential_creation(
        credential=public_key_credential_error,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  public_key_credential_error = PublicKeyCredential(
      id=base64s(credential_id),
      type='credential-type',
      raw_id=credential_id,
      response=AuthenticatorAttestationResponse(
          client_data_JSON=client_data_JSON,
          attestation_object=cbor2.dumps({
              'authData':
              authenticator_data(
                  TEST_RP_ID_HASH, (AuthenticatorDataFlag.AT.value
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

  with pytest.raises(ValidationError):
    backend.handle_credential_creation(
        credential=public_key_credential_error,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  public_key_credential_error = PublicKeyCredential(
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

  with pytest.raises(ValidationError):
    backend.handle_credential_creation(
        credential=public_key_credential_error,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        require_user_verification=True,
    )

  with pytest.raises(ValidationError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        expected_extensions={ExtensionIdentifier.TX_AUTH_SIMPLE})

  backend = CredentialsBackend(ExceptionCredentialsRegistrar())
  with pytest.raises(RegistrationError):
    backend.handle_credential_creation(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  backend = CredentialsBackend(ErrorCredentialsRegistrar())
  with pytest.raises(RegistrationError):
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


def test_credentials_backend_request_error():
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

  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=b'cred-id',
            )
        ])

  backend = CredentialsBackend(ExceptionCredentialsRegistrar())
  with pytest.raises(RegistrationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
      return None

  backend = CredentialsBackend(TestCredentialsRegistrar())
  with pytest.raises(NotFoundError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
      return CredentialData(TEST_CREDENTIAL_PUBLIC_KEY,
                            0,
                            user_entity=PublicKeyCredentialUserEntity(
                                name='user',
                                id=b'user-id-mismatch',
                                display_name='username'))

  backend = CredentialsBackend(TestCredentialsRegistrar())
  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(NotFoundError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
      return CredentialData(TEST_CREDENTIAL_PUBLIC_KEY,
                            0,
                            TEST_USER,
                            rp_entity=PublicKeyCredentialRpEntity(
                                name='example.com', id='mismatch'))

  backend = CredentialsBackend(TestCredentialsRegistrar())
  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
      return CredentialData(TEST_CREDENTIAL_PUBLIC_KEY, 0, TEST_USER, TEST_RP)

  backend = CredentialsBackend(TestCredentialsRegistrar())
  backend.handle_credential_request(
      credential=public_key_credential,
      user=TEST_USER,
      expected_challenge=expected_challenge,
      expected_origin=TEST_RP_ORIGIN,
  )

  public_key_credential_error = PublicKeyCredential(
      id=base64s(credential_id),
      type='credential-type',
      raw_id=credential_id,
      response=AuthenticatorAssertionResponse(
          client_data_JSON=client_data_JSON,
          authenticator_data=auth_data,
          signature=signature,
          user_handle=b'mismatch',
      ))

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential_error,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  client_data_JSON = json_bytes({
      'type': 'webauthn.create',
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

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  client_data_JSON = json_bytes({
      'type': 'webauthn.get',
      'challenge': '\x90\x91\x92',
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

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(DecodingError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  client_data_JSON = json_bytes({
      'type': 'webauthn.get',
      'challenge': 'mismatch',
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

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(IntegrityError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

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

  backend = CredentialsBackend(SuccessCredentialsRegistrar())
  with pytest.raises(IntegrityError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin='https://mismatch',
    )

  with pytest.raises(IntegrityError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        token_binding=TokenBinding(status=TokenBindingStatus.SUPPORTED))

  client_data_JSON = json_bytes({
      'type': 'webauthn.get',
      'challenge': base64s(challenge),
      'origin': TEST_RP_ORIGIN,
      'tokenBinding': {
          'status': 'supported'
      }
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

  with pytest.raises(IntegrityError):
    backend.handle_credential_request(credential=public_key_credential,
                                      user=TEST_USER,
                                      rp=TEST_RP,
                                      expected_challenge=expected_challenge,
                                      expected_origin=TEST_RP_ORIGIN,
                                      token_binding=TokenBinding(
                                          status=TokenBindingStatus.PRESENT,
                                          id='token-binding-id',
                                      ))

  client_data_JSON = json_bytes({
      'type': 'webauthn.get',
      'challenge': base64s(challenge),
      'origin': TEST_RP_ORIGIN,
      'tokenBinding': {
          'status': 'present',
          'id': 'token-binding-id-mismatch',
      }
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

  with pytest.raises(IntegrityError):
    backend.handle_credential_request(credential=public_key_credential,
                                      user=TEST_USER,
                                      rp=TEST_RP,
                                      expected_challenge=expected_challenge,
                                      expected_origin=TEST_RP_ORIGIN,
                                      token_binding=TokenBinding(
                                          status=TokenBindingStatus.PRESENT,
                                          id='token-binding-id',
                                      ))

  with pytest.raises(IntegrityError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  with pytest.raises(IntegrityError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=PublicKeyCredentialRpEntity(name='example.com',
                                       id='mismatch.example.com'),
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
    )

  auth_data = authenticator_data(
      TEST_RP_ID_HASH, (AuthenticatorDataFlag.AT.value
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
      'tokenBinding': {
          'status': 'present',
          'id': 'token-binding-id',
      }
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

  with pytest.raises(ValidationError):
    backend.handle_credential_request(credential=public_key_credential,
                                      user=TEST_USER,
                                      rp=TEST_RP,
                                      expected_challenge=expected_challenge,
                                      expected_origin=TEST_RP_ORIGIN,
                                      token_binding=TokenBinding(
                                          status=TokenBindingStatus.PRESENT,
                                          id='token-binding-id',
                                      ))

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

  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        token_binding=TokenBinding(
            status=TokenBindingStatus.PRESENT,
            id='token-binding-id',
        ),
        require_user_verification=True,
    )

  with pytest.raises(ValidationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        token_binding=TokenBinding(
            status=TokenBindingStatus.PRESENT,
            id='token-binding-id',
        ),
        expected_extensions={ExtensionIdentifier.TX_AUTH_SIMPLE},
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
      return CredentialData(
          TEST_CREDENTIAL_PUBLIC_KEY,
          10,
          TEST_USER,
      )

  backend = CredentialsBackend(TestCredentialsRegistrar())
  with pytest.raises(SignatureCountError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        token_binding=TokenBinding(
            status=TokenBindingStatus.PRESENT,
            id='token-binding-id',
        ),
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def register_credential_request(self, credential: PublicKeyCredential,
                                    authenticator_data: AuthenticatorData,
                                    user: PublicKeyCredentialUserEntity,
                                    rp: PublicKeyCredentialRpEntity) -> Any:
      raise Exception()

  backend = CredentialsBackend(TestCredentialsRegistrar())
  with pytest.raises(RegistrationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        token_binding=TokenBinding(
            status=TokenBindingStatus.PRESENT,
            id='token-binding-id',
        ),
    )

  class TestCredentialsRegistrar(SuccessCredentialsRegistrar):
    def register_credential_request(self, credential: PublicKeyCredential,
                                    authenticator_data: AuthenticatorData,
                                    user: PublicKeyCredentialUserEntity,
                                    rp: PublicKeyCredentialRpEntity) -> Any:
      return 'Error'

  backend = CredentialsBackend(TestCredentialsRegistrar())
  with pytest.raises(RegistrationError):
    backend.handle_credential_request(
        credential=public_key_credential,
        user=TEST_USER,
        rp=TEST_RP,
        expected_challenge=expected_challenge,
        expected_origin=TEST_RP_ORIGIN,
        token_binding=TokenBinding(
            status=TokenBindingStatus.PRESENT,
            id='token-binding-id',
        ),
    )
