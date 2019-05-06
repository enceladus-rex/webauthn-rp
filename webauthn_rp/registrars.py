from cryptography.x509 import Certificate

from typing import Optional, Sequence, Union, NamedTuple

from .errors import UnimplementedError
from .types import (
  CredentialCreationOptions,
  CredentialRequestOptions,
  AuthenticatorAttestationResponse,
  AuthenticatorAssertionResponse,
  PublicKeyCredentialUserEntity,
  PublicKeyCredentialRpEntity,
  AttestationObject,
  AttestationStatementFormatIdentifier,
  AttestationType,
  AuthenticatorData,
  PublicKeyCredential,
  PublicKey,
  TrustedPath,
)


class CredentialData(NamedTuple):
  public_key: PublicKey
  signature_count: int
  user_entity: Optional[PublicKeyCredentialUserEntity] = None
  rp_entity: Optional[PublicKeyCredentialRpEntity] = None


class CredentialsRegistrar:

  def register_creation_options(
      self, options: CredentialCreationOptions, **kwargs) -> bool:
    raise UnimplementedError('Must implement register_creation_options')

  def register_request_options(
      self, options: CredentialRequestOptions, **kwargs) -> bool:
    raise UnimplementedError('Must implement register_request_options')

  def register_credential_creation(
      self, credential: PublicKeyCredential,
      att: AttestationObject, 
      att_type: AttestationType,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      cryptography_public_key: PublicKey,
      trusted_path: Optional[TrustedPath] = None,
      **kwargs) -> bool:
    raise UnimplementedError(
      'Must implement register_credential_creation')

  def register_credential_request(
      self, credential: PublicKeyCredential,
      authenticator_data: AuthenticatorData,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      **kwargs) -> bool:
    raise UnimplementedError(
      'Must implement register_credential_request')

  def get_creation_options_challenge(
      self, user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      **kwargs) -> Optional[bytes]:
    raise UnimplementedError(
      'Must implement get_creation_options_challenge')

  def get_request_options_challenge(
      self, user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      **kwargs) -> Optional[bytes]:
    raise UnimplementedError(
      'Must implement get_request_options_challenge')

  def get_credential_data(
      self, credential_id: bytes,
      **kwargs) -> Optional[CredentialData]:
    raise UnimplementedError(
      'Must implement get_credential_data')
  
  def check_user_owns_credential(
      self, user_handle: bytes, credential_id: bytes,
      **kwargs) -> Optional[bool]:
    raise UnimplementedError(
      'Must implement check_user_owns_credential')