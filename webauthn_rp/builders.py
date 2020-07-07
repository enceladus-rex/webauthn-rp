from copy import deepcopy
from typing import Optional, Sequence

from webauthn_rp.errors import BuilderError
from webauthn_rp.types import (
    AttestationConveyancePreference, AuthenticationExtensionsClientInputs,
    AuthenticatorSelectionCriteria, CredentialCreationOptions,
    CredentialMediationRequirement, CredentialRequestOptions,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    UserVerificationRequirement)

__all__ = [
    'CredentialCreationOptionsBuilder',
    'CredentialRequestOptionsBuilder',
]


class CredentialCreationOptionsBuilder:
    """A CredentialCreationOptions builder.

    Using a builder can allow for saving shared build parameters and simplify
    the construction of option data types which can have a number of nested
    attributes.

    After initializing the builder, each time an attribute is updated using one
    of the provided setter functions, a new copy of the builder is returned and
    the original is left unmodified.

    In the following example, `builder`, and `builder_n` would be different:

    >>> builder = CredentialCreationOptionsBuilder()
    >>> builder_n = builder.rp(...).attestation(...)
    """
    def __init__(
        self,
        *,
        rp: Optional[PublicKeyCredentialRpEntity] = None,
        pub_key_cred_params: Optional[
            Sequence[PublicKeyCredentialParameters]] = None,
        timeout: Optional[int] = None,
        authenticator_selection: Optional[
            AuthenticatorSelectionCriteria] = None,
        extensions: Optional[AuthenticationExtensionsClientInputs] = None,
        attestation: Optional[
            AttestationConveyancePreference] = AttestationConveyancePreference.
        NONE,
        exclude_credentials: Optional[
            Sequence[PublicKeyCredentialDescriptor]] = None
    ) -> None:
        """Initialize the builder's attributes.

        Args:
          rp (Optional[PublicKeyCredentialRpEntity]): The Relying Party being
            used.
          pub_key_cred_params (Optional[Sequence[
            PublicKeyCredentialParameters]]): The public key credential
            parameters used to create the credential.
          timeout (Optional[int]): The timeout to create the credential.
          authenticator_selection (Optional[AuthenticatorSelectionCriteria]):
            The specific criteria to enforce on the created authenticator.
          extensions (Optional[AuthenticationExtensionsClientInputs]): Any
            extension inputs to provide to the authenticator.
          attestation (Optional[AttestationConveyancePreference]): The
            preference to enforce on allowed authenticator attestations.
          exclude_credentials (Optional[Sequence[
            PublicKeyCredentialDescriptor]]): An optional list of credentials
            to exclude from use.
        """
        self._rp = rp
        self._pub_key_cred_params = pub_key_cred_params
        self._timeout = timeout
        self._authenticator_selection = authenticator_selection
        self._extensions = extensions
        self._attestation = attestation
        self._exclude_credentials = exclude_credentials

    def _copy(self) -> 'CredentialCreationOptionsBuilder':
        return deepcopy(self)

    def rp(self, rp: PublicKeyCredentialRpEntity
           ) -> 'CredentialCreationOptionsBuilder':
        """Set the Relying Party (RP).

        Args:
          rp (PublicKeyCredentialRpEntity): The Relying Party being used.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        assert rp is not None
        c = self._copy()
        c._rp = rp
        return c

    def pub_key_cred_params(
        self, pub_key_cred_params: Sequence[PublicKeyCredentialParameters]
    ) -> 'CredentialCreationOptionsBuilder':
        """Set the public key credential parameters.

        Args:
          pub_key_cred_params (Sequence[PublicKeyCredentialParameters]]): The
            public key credential parameters used to create the credential.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        assert pub_key_cred_params is not None
        c = self._copy()
        c._pub_key_cred_params = pub_key_cred_params
        return c

    def timeout(self,
                timeout: Optional[int]) -> 'CredentialCreationOptionsBuilder':
        """Set the timeout.

        Args:
          timeout (Optional[int]): The timeout to create the credential.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        c = self._copy()
        c._timeout = timeout
        return c

    def authenticator_selection(
        self, authenticator_selection: Optional[AuthenticatorSelectionCriteria]
    ) -> 'CredentialCreationOptionsBuilder':
        """Set the authenticator selection.

        authenticator_selection (Optional[AuthenticatorSelectionCriteria]):
            The specific criteria to enforce on the created authenticator.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        c = self._copy()
        c._authenticator_selection = authenticator_selection
        return c

    def extensions(
        self, extensions: Optional[AuthenticationExtensionsClientInputs]
    ) -> 'CredentialCreationOptionsBuilder':
        """Set the authenticator extensions' client inputs.

        Args:
          extensions (Optional[AuthenticationExtensionsClientInputs]): Any
            extension inputs to provide to the authenticator.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        c = self._copy()
        c._extensions = extensions
        return c

    def attestation(
        self, attestation: AttestationConveyancePreference
    ) -> 'CredentialCreationOptionsBuilder':
        """Set the attestation conveyance preference.

        Args:
          attestation (Optional[AttestationConveyancePreference]): The
            preference to enforce on allowed authenticator attestations.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        assert attestation is not None
        c = self._copy()
        c._attestation = attestation
        return c

    def exclude_credentials(
        self,
        exclude_credentials: Optional[Sequence[PublicKeyCredentialDescriptor]]
    ) -> 'CredentialCreationOptionsBuilder':
        """Set the public key credentials to exclude from use.

        Args:
          exclude_credentials (Optional[Sequence[
            PublicKeyCredentialDescriptor]]): An optional list of credentials
            to exclude from use.

        Returns:
          A new `CredentialCreationOptionsBuilder` copy.
        """
        c = self._copy()
        c._exclude_credentials = exclude_credentials
        return c

    def build(self, *, user: PublicKeyCredentialUserEntity,
              challenge: bytes) -> CredentialCreationOptions:
        """Build a CredentialCreationOptions instance.

        Args:
          user (PublicKeyCredentialUserEntity): The user whose credential
            is being requested.
          challenge (bytes): The challenge to provide to the user's credential.

        Returns:
          An instance of `CredentialCreationOptions`.

        Raises:
          BuilderError: If a required attribute has not been set yet.
        """
        assert user is not None
        assert challenge is not None

        for x, y in (
            (self._rp, 'relying party'),
            (self._pub_key_cred_params, 'public key credential params'),
            (self._attestation, 'attestation conveyance preference'),
        ):
            if x is None:
                raise BuilderError(
                    'Must fully specify builder before build, missing {}'.
                    format(y))

        assert self._rp is not None
        assert self._pub_key_cred_params is not None
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


class CredentialRequestOptionsBuilder:
    """A CredentialRequestOptions builder.

    Using a builder can allow for saving shared build parameters and simplify
    the construction of option data types which can have a number of nested
    attributes.

    After initializing the builder, each time an attribute is updated using one
    of the provided setter functions, a new copy of the builder is returned and
    the original is left unmodified.

    In the following example, `builder`, and `builder_n` would be different:

    >>> builder = CredentialRequestOptionsBuilder()
    >>> builder_n = builder.mediation(...).rp_id(...)
    """
    def __init__(
        self,
        *,
        mediation: CredentialMediationRequirement = (
            CredentialMediationRequirement.OPTIONAL),
        timeout: Optional[int] = None,
        rp_id: Optional[str] = None,
        extensions: Optional[AuthenticationExtensionsClientInputs] = None,
        user_verification: Optional[UserVerificationRequirement] = (
            UserVerificationRequirement.PREFERRED)
    ) -> None:
        """Initialize the builder's attributes.

        Args:
          mediation (CredentialMediationRequirement): The kind of mediation
            that should be enforced between the user agent and the user's
            authenticator.
          timeout (Optional[int]): The timeout to request the credential.
          rp_id (Optional[str]): The Relying Party ID to use.
          extensions (Optional[AuthenticationExtensionsClientInputs]): Any
            extension inputs to provide to the authenticator.
          user_verification (Optional[UserVerificationRequirement]): An
            optional specification of whether or not a user's verification is
            required.
        """
        self._mediation = mediation
        self._timeout = timeout
        self._rp_id = rp_id
        self._extensions = extensions
        self._user_verification = user_verification

    def _copy(self) -> 'CredentialRequestOptionsBuilder':
        return deepcopy(self)

    def mediation(
        self, mediation: CredentialMediationRequirement
    ) -> 'CredentialRequestOptionsBuilder':
        """Set credential mediation requirement.

        Args:
          mediation (CredentialMediationRequirement): The kind of mediation
            that should be enforced between the user agent and the user's
            authenticator.

        Returns:
          A new `CredentialRequestOptionsBuilder` copy.
        """
        assert mediation is not None
        c = self._copy()
        c._mediation = mediation
        return c

    def timeout(self,
                timeout: Optional[int]) -> 'CredentialRequestOptionsBuilder':
        """Set the timeout.

        Args:
          mediation (PublicKeyCredentialRpEntity): The Relying Party being used.

        Returns:
          A new `CredentialRequestOptionsBuilder` copy.
        """
        c = self._copy()
        c._timeout = timeout
        return c

    def rp_id(self, rp_id: Optional[str]) -> 'CredentialRequestOptionsBuilder':
        """Set the Relying Party ID.

        Args:
          rp_id (Optional[str]): The Relying Party ID to use.

        Returns:
          A new `CredentialRequestOptionsBuilder` copy.
        """
        c = self._copy()
        c._rp_id = rp_id
        return c

    def extensions(
        self, extensions: Optional[AuthenticationExtensionsClientInputs]
    ) -> 'CredentialRequestOptionsBuilder':
        """Set the authenticator extensions' client inputs.

        Args:
          extensions (Optional[AuthenticationExtensionsClientInputs]): Any
            extension inputs to provide to the authenticator.

        Returns:
          A new `CredentialRequestOptionsBuilder` copy.
        """
        c = self._copy()
        c._extensions = extensions
        return c

    def user_verification(
        self, user_verification: Optional[UserVerificationRequirement]
    ) -> 'CredentialRequestOptionsBuilder':
        """Set the user verification requirement.

        Args:
          user_verification (Optional[UserVerificationRequirement]): An
            optional specification of whether or not a user's verification is
            required.

        Returns:
          A new `CredentialRequestOptionsBuilder` copy.
        """
        c = self._copy()
        c._user_verification = user_verification
        return c

    def build(
        self,
        *,
        challenge: bytes,
        allow_credentials: Optional[
            Sequence[PublicKeyCredentialDescriptor]] = None
    ) -> CredentialRequestOptions:
        """Build a CredentialRequestOptions instance.

        Args:
          challenge (bytes): The challenge to provide to the user's credential.
          allow_credentials (Optional[
            Sequence[PublicKeyCredentialDescriptor]]): A optional list of
            allowed credentials ordered from most preferred to least preferred.

        Returns:
          An instance of `CredentialRequestOptions`.

        Raises:
          BuilderError: If a required attribute has not been set yet.
        """
        assert challenge is not None

        if self._mediation is None:
            raise BuilderError(
                'Must fully specify builder before build, missing mediation')

        return CredentialRequestOptions(
            mediation=self._mediation,
            public_key=PublicKeyCredentialRequestOptions(
                challenge=challenge,
                timeout=self._timeout,
                rp_id=self._rp_id,
                extensions=self._extensions,
                allow_credentials=allow_credentials,
                user_verification=self._user_verification))
