from copy import deepcopy
from typing import Optional, Sequence

from webauthn_rp.errors import BuilderError
from webauthn_rp.types import (
    AttestationConveyancePreference, AuthenticationExtensionsClientInputs,
    AuthenticatorSelectionCriteria, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity)


class CredentialCreationOptionsBuilder:
  def __init__(
      self,
      *,
      rp: Optional[PublicKeyCredentialRpEntity] = None,
      pub_key_cred_params: Optional[
          Sequence[PublicKeyCredentialParameters]] = None,
      timeout: Optional[int] = None,
      authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None,
      extensions: Optional[AuthenticationExtensionsClientInputs] = None,
      attestation: Optional[
          AttestationConveyancePreference] = AttestationConveyancePreference.
      NONE,
      exclude_credentials: Optional[
          Sequence[PublicKeyCredentialDescriptor]] = None):
    self._rp = rp
    self._pub_key_cred_params = pub_key_cred_params
    self._timeout = timeout
    self._authenticator_selection = authenticator_selection
    self._extensions = extensions
    self._attestation = attestation
    self._exclude_credentials = exclude_credentials

  def _copy(self) -> 'CredentialCreationOptionsBuilder':
    return deepcopy(self)

  def rp(
      self,
      rp: PublicKeyCredentialRpEntity) -> 'CredentialCreationOptionsBuilder':
    assert rp is not None
    c = self._copy()
    c._rp = rp
    return c

  def pub_key_cred_params(
      self, pub_key_cred_params: Sequence[PublicKeyCredentialParameters]
  ) -> 'CredentialCreationOptionsBuilder':
    assert pub_key_cred_params is not None
    c = self._copy()
    c._pub_key_cred_params = pub_key_cred_params
    return c

  def timeout(self, timeout: int) -> 'CredentialCreationOptionsBuilder':
    assert timeout is not None
    c = self._copy()
    c._timeout = timeout
    return c

  def authenticator_selection(
      self, authenticator_selection: AuthenticatorSelectionCriteria
  ) -> 'CredentialCreationOptionsBuilder':
    assert authenticator_selection is not None
    c = self._copy()
    c._authenticator_selection = authenticator_selection
    return c

  def extensions(
      self, extensions: AuthenticationExtensionsClientInputs
  ) -> 'CredentialCreationOptionsBuilder':
    assert extensions is not None
    c = self._copy()
    c._extensions = extensions
    return c

  def attestation(
      self, attestation: AttestationConveyancePreference
  ) -> 'CredentialCreationOptionsBuilder':
    assert attestation is not None
    c = self._copy()
    c._attestation = attestation
    return c

  def exclude_credentials(
      self,
      exclude_credentials: Optional[Sequence[PublicKeyCredentialDescriptor]]
  ) -> 'CredentialCreationOptionsBuilder':
    c = self._copy()
    c._exclude_credentials = exclude_credentials
    return c

  def build(self, *, user: PublicKeyCredentialUserEntity,
            challenge: bytes) -> CredentialCreationOptions:
    for x, y in (
        (self._rp, 'relying party'),
        (self._pub_key_cred_params, 'public key credential params'),
        (self._timeout, 'timeout'),
        (self._authenticator_selection, 'authenticator selection'),
        (self._extensions, 'extensions'),
        (self._attestation, 'attestation conveyance preference'),
    ):
      if x is None:
        raise BuilderError(
            'Must fully specify builder before build, missing {}'.format(y))

    assert self._rp is not None
    assert self._pub_key_cred_params is not None
    assert self._timeout is not None
    assert self._authenticator_selection is not None
    assert self._extensions is not None
    assert self._attestation is not None

    return CredentialCreationOptions(
        public_key=PublicKeyCredentialCreationOptions(
            rp=self._rp,
            user=user,
            challenge=challenge,
            pub_key_cred_params=self._pub_key_cred_params,
            timeout=self._timeout,
            authenticator_selection=self._authenticator_selection,
            extensions=self._extensions,
            attestation=self._attestation,
            exclude_credentials=self._exclude_credentials))
