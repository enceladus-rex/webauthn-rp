from typing import Any, NamedTuple, Optional

from webauthn_rp.errors import UnimplementedError
from webauthn_rp.types import (AttestationObject, AttestationType,
                               AuthenticatorData, CredentialCreationOptions,
                               CredentialPublicKey, CredentialRequestOptions,
                               PublicKeyCredential,
                               PublicKeyCredentialRpEntity,
                               PublicKeyCredentialUserEntity, TrustedPath)

__all__ = [
    'CredentialData',
    'CredentialsRegistrar',
]


class CredentialData(NamedTuple):
    """Information stored about a specific user credential.

    Attributes:
      credential_public_key (CredentialPublicKey): The public key associated
        with a particular credential.
      signature_count (Optional[int]): The current signature count of a
        credential if one has been registered. It should be None if it has not
        been initialized yet (right after the creation of a credential).
      user_entity (PublicKeyCredentialUserEntity): The user that owns the
        credential.
      rp_entity (Optional[PublicKeyCredentialRpEntity]): The optional Relying
        Party that is associated with this credential.
    """
    credential_public_key: CredentialPublicKey
    signature_count: Optional[int]
    user_entity: PublicKeyCredentialUserEntity
    rp_entity: Optional[PublicKeyCredentialRpEntity] = None


class CredentialsRegistrar:
    """A registrar for public key credentials.

    This class specifies the interface between the `CredentialsBackend` and the
    Relying Party's credentials storage and processing layer.

    The provided methods will be invoked by the `CredentialsBackend` at
    specific points during the user registration and user authentication
    phases.
    """
    def register_credential_attestation(
            self,
            credential: PublicKeyCredential,
            att: AttestationObject,
            att_type: AttestationType,
            user: PublicKeyCredentialUserEntity,
            rp: PublicKeyCredentialRpEntity,
            trusted_path: Optional[TrustedPath] = None) -> Any:
        """Registers the attempted attestation of a credential by a user.

        This is the last step in the user registration ceremony which was
        initiated by the user agent. Successful completion indicates that the
        user's credential has been stored and is ready for authentication.

        Args:
          credential (PublicKeyCredential): The public key credential to
            associate with a user and Relying Party.
          att (AttestationObject): The attestation object associated with the
            given public key credential.
          att_type (AttestationType): The type of attestation that was
            confirmed by the `CredentialsBackend`.
          user (PublicKeyCredentialUserEntity): The user to associate with
            the public key credential.
          rp (PublicKeyCredentialRpEntity): The Relying Party to associate with
            the public key credential.
          trusted_path (Optional[TrustedPath]): The optional trusted path
            for the credential and attestation object provided by the
            `CredentialsBackend`.

        Returns:
          None for success and anything else to indicate an error.
        """
        raise UnimplementedError('Must implement register_credential_creation')

    def register_credential_assertion(self, credential: PublicKeyCredential,
                                      authenticator_data: AuthenticatorData,
                                      user: PublicKeyCredentialUserEntity,
                                      rp: PublicKeyCredentialRpEntity) -> Any:
        """Registers the attempted assertion of a credential by a user.

        This is the last step in the user authentication ceremony which was
        initiated by the user agent. Successful completion indicates that the
        any necessary state related to the user's credential was updated and
        the authentication process can finish.

        Args:
          credential (PublicKeyCredential): The public key credential
            associated with the given user and Relying Party.
          authenticator_data (AuthenticatorData): The parsed authenticator
            data.
          user (PublicKeyCredentialUserEntity): The user associated with
            the public key credential.
          rp (PublicKeyCredentialRpEntity): The Relying Party associated with
            the public key credential.

        Returns:
          None for success and anything else to indicate an error.
        """
        raise UnimplementedError('Must implement register_credential_request')

    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
        """Gets the `CredentialData` associated with a specific credential.

        Args:
          credential_id (bytes): The probabilistically-unique credential ID.

        Returns:
          The `CredentialData` associated with the given ID or None if it
          does not exist.

        References:
          * https://w3.org/TR/webauthn/#credential-id
        """
        raise UnimplementedError('Must implement get_credential_data')
