from typing import Sequence

from .types import (
    AttestationConveyancePreference, AuthenticationExtensionsClientInputs,
    AuthenticatorSelectionCriteria, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity)


class CredentialCreationOptionsBuilder:
  def __init__(
      self,
      rp: PublicKeyCredentialRpEntity,
      pub_key_cred_params: Sequence[PublicKeyCredentialParameters],
      timeout: int,
      authenticator_selection: AuthenticatorSelectionCriteria,
      extensions: AuthenticationExtensionsClientInputs,
      attestation:
      AttestationConveyancePreference = AttestationConveyancePreference.NONE,
      exclude_credentials: Sequence[PublicKeyCredentialDescriptor] = None):
    self.rp = rp
    self.pub_key_cred_params = pub_key_cred_params
    self.timeout = timeout
    self.authenticator_selection = authenticator_selection
    self.extensions = extensions
    self.attestation = attestation
    self.exclude_credentials = exclude_credentials

  def build(self, user: PublicKeyCredentialUserEntity,
            challenge: bytes) -> CredentialCreationOptions:
    return CredentialCreationOptions(
        public_key=PublicKeyCredentialCreationOptions(
            rp=self.rp,
            user=user,
            challenge=challenge,
            pub_key_cred_params=self.pub_key_cred_params,
            timeout=self.timeout,
            authenticator_selection=self.authenticator_selection,
            extensions=self.extensions,
            attestation=self.attestation,
            exclude_credentials=self.exclude_credentials))
