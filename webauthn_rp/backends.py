import hashlib
import json
from typing import Any, Collection, Optional, Sequence, Set, Union, cast
from urllib.parse import urlparse

import cryptography
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256

from webauthn_rp.attesters import attest
from webauthn_rp.converters import cryptography_public_key, jsonify
from webauthn_rp.errors import (
    ChallengeError, ClientDataTypeError, CredentialDataError,
    CredentialNotAllowedError, DecodingError, ExtensionError, InternalError,
    OriginError, RegistrationError, RPIDError, RPIDHashError, RPNotFoundError,
    SignatureCountError, TokenBindingError, UserHandleError, UserIDError,
    UserPresenceError, UserVerificationError, WebAuthnRPError)
from webauthn_rp.parsers import (parse_attestation_object,
                                 parse_authenticator_data, parse_client_data,
                                 parse_origin)
from webauthn_rp.registrars import CredentialsRegistrar
from webauthn_rp.types import (
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse,
    AuthenticatorDataFlag, CredentialCreationOptions, CredentialRequestOptions,
    ExtensionIdentifier, Origin, PublicKeyCredential,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity, TokenBinding)
from webauthn_rp.utils import url_base64_decode
from webauthn_rp.verifiers import verify

__all__ = [
    'CredentialsBackend',
]


class CredentialsBackend:
  """A backend to manage the registration and authentication of credentials.

  The process of registering a credential involves:
    1. Creating a CredentialCreationOptions object (possibly using a builder).
    2. Calling CredentialsBackend.handle_creation_options with the options.
    3. Converting the options to JSON using the jsonify converter.
    4. Sending the JSON options to the user's client.
    5. Getting a JSON PublicKeyCredential from the user's client.
    6. Parsing the JSON PublicKeyCredential using parse_public_key_credential.
    7. Finally calling CredentialsBackend.handle_credential_creation.

  Attributes:
    registrar (CredentialsRegistrar): The RP credentials registrar.
  """
  def __init__(self, registrar: CredentialsRegistrar) -> None:
    """Initialize the credentials backend with a registrar.

    Args:
      registrar (CredentialsRegistrar): The RP credentials registrar.
    """
    self.registrar = registrar

  def _extract_allowed_origins(
      self, expected_origin: Union[str, Collection[str]]) -> Set[Origin]:
    allowed_origins: Set[Origin] = set()
    if isinstance(expected_origin, str):
      allowed_origins.add(parse_origin(expected_origin))
    else:
      if len(expected_origin) == 0:
        raise OriginError('Must provide at least one expected origin')

      for opaque_origin in expected_origin:
        allowed_origins.add(parse_origin(opaque_origin))

    return allowed_origins

  def handle_creation_options(self, *,
                              options: CredentialCreationOptions) -> None:
    """Handle options that will be used to register the user's credential.

    Args:
      options (CredentialCreationOptions): The credential registration options.

    Raises:
      RegistrationError: Could not register the options with the credentials
        registrar.
    """
    try:
      response = self.registrar.register_creation_options(options)
    except Exception as e:
      raise RegistrationError(
          'Failed to register creation options ({!r})'.format(e))

    if response is not None:
      raise RegistrationError(
          'Failed to register creation options ({})'.format(response))

  def handle_credential_creation(
      self,
      *,
      credential: PublicKeyCredential,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      expected_challenge: bytes,
      expected_origin: Union[str, Collection[str]],
      token_binding: Optional[TokenBinding] = None,
      require_user_verification: bool = False,
      expected_extensions: Optional[Set[ExtensionIdentifier]] = None) -> None:
    """Handle the registration of a user's credential.

    Args:
      credential (PublicKeyCredential): The public key credential generated by
        the user's client containing an authenticator attestation response.
      user (PublicKeyCredentialUserEntity): The user to be registered.
      rp (PublicKeyCredentialRpEntity): The RP to use to register the user.
      expected_challenge (bytes): The initial challenge sent to the user's
        client.
      expected_origin (Union[str, Collection[str]]): The exact origin to use 
        for the RP or a collection of allowed origins.
      token_binding (Optional[TokenBinding]): The optional token binding to
        check for.
      require_user_verification (bool): Whether to require user verification.
      expected_extensions (Optional[Set[ExtensionIdentifier]]): The set of
        extensions that are required to be present.
      
    Raises:
      ClientDataTypeError: The type of the client data is invalid.
      ChallengeError: The user's challenge and the expected challenge don't
        match.
      DecodingError: There is an error in decoding some data.
      ParserError: There is an error in parsing some data.
      OriginError: There is an issue with a provided web origin.
      TokenBindingError: There is a mismatch in the provided and the user's
        token binding.
      RPIDError: The provided and the user's RP IDs don't match.
      UserPresenceError: The user was not present during authentication.
      UserVerificationError: The user did not perform verification but the
        require_user_verification parameter is True.
      ExtensionError: An expected extension is missing.
      RegistrationError: There is an issue registering the user with the
        credentials registrar.
      InternalError: An unexpected internal error occurred.
    """
    try:
      allowed_origins = self._extract_allowed_origins(expected_origin)

      response = cast(AuthenticatorAttestationResponse, credential.response)
      collected_client_data = parse_client_data(response.client_data_JSON)

      if collected_client_data.type != 'webauthn.create':
        raise ClientDataTypeError('Invalid client data type {}'.format(
            collected_client_data.type))

      try:
        challenge = url_base64_decode(collected_client_data.challenge)
        if challenge != expected_challenge:
          raise ChallengeError(
              'Given and expected challenge byte strings don\'t match')
      except ValueError:
        raise DecodingError('Failed to decode the base64 encoded challenge')

      client_origin = parse_origin(collected_client_data.origin)
      if client_origin not in allowed_origins:
        raise OriginError(
            'Given ({0}) and expected ({1}) RP origin don\'t match'.format(
                collected_client_data.origin, expected_origin))

      if token_binding is not None:
        if collected_client_data.token_binding is None:
          raise TokenBindingError('Expecting Token Binding in client data')

        if token_binding.status != collected_client_data.token_binding.status:
          raise TokenBindingError(
              ('Given ({0}) and expected ({1}) Token Binding '
               'statuses dont\'t match').format(
                   collected_client_data.token_binding.status,
                   token_binding.status))

        if token_binding.id != collected_client_data.token_binding.id:
          raise TokenBindingError(
              ('Given ({0}) and expected ({1}) Token Binding '
               'IDs dont\'t match').format(
                   collected_client_data.token_binding.id, token_binding.id))
      elif collected_client_data.token_binding is not None:
        raise TokenBindingError('Unexpected Token Binding in client data')

      client_data_JSON_hash = hashlib.sha256(
          response.client_data_JSON).digest()
      rp_id_hash = hashlib.sha256(rp.id.encode('utf-8')).digest()

      attestation, raw_att_obj = parse_attestation_object(
          response.attestation_object)
      if attestation.auth_data.rp_id_hash != rp_id_hash:
        raise RPIDHashError('RP ID hash does not match')

      if not (AuthenticatorDataFlag.UP.value & attestation.auth_data.flags):
        raise UserPresenceError('User present flag must be set')

      if require_user_verification:
        if not (AuthenticatorDataFlag.UV.value & attestation.auth_data.flags):
          raise UserVerificationError('User verification flag must be set')

      if expected_extensions is not None:
        for e in expected_extensions:
          if not hasattr(attestation.auth_data.extensions, e.key) or getattr(
              attestation.auth_data.extensions, e.key) is None:
            raise ExtensionError('Missing extension {}'.format(e.value))

      assert attestation.auth_data is not None
      assert attestation.auth_data.attested_credential_data is not None

      att_type, trusted_path = attest(
          attestation.att_stmt,
          attestation.auth_data.attested_credential_data.credential_public_key,
          raw_att_obj['authData'], client_data_JSON_hash)

      try:
        response = self.registrar.register_credential_creation(
            credential=credential,
            att=attestation,
            att_type=att_type,
            user=user,
            rp=rp,
            trusted_path=trusted_path,
        )
      except Exception as e:
        raise RegistrationError(
            'Failed to register credential creation ({!r})'.format(e))

      if response is not None:
        raise RegistrationError(
            'Failed to register credential creation ({})'.format(response))
    except WebAuthnRPError:
      raise
    except Exception as e:
      raise InternalError('Unexepected error encountered: {!r}'.format(e))

  def handle_request_options(self, *,
                             options: CredentialRequestOptions) -> None:
    """Handle options that'll be used to authenticate the user's credential.

    Args:
      options (CredentialRequestOptions): The credential authentication
        options.

    Raises:
      RegistrationError: Could not register the options with the credentials
        registrar.
    """
    try:
      response = self.registrar.register_request_options(options)
    except Exception as e:
      raise RegistrationError(
          'Failed to register request options ({!r})'.format(e))

    if response is not None:
      raise RegistrationError(
          'Failed to register request options ({})'.format(response))

  def handle_credential_request(
      self,
      *,
      credential: PublicKeyCredential,
      expected_challenge: bytes,
      expected_origin: Union[str, Collection[str]],
      rp: Optional[PublicKeyCredentialRpEntity] = None,
      user: Optional[PublicKeyCredentialUserEntity] = None,
      allow_credentials: Optional[
          Sequence[PublicKeyCredentialDescriptor]] = None,
      token_binding: Optional[TokenBinding] = None,
      require_user_verification: bool = False,
      expected_extensions: Optional[Set[ExtensionIdentifier]] = None,
      ignore_clone_error: bool = False) -> None:
    """Handle authentication using a user's credential.

    Args:
      credential (PublicKeyCredential): The public key credential generated by
        the user's client containing an authenticator assertion response.
      expected_challenge (bytes): The initial challenge sent to the user's
        client.
      expected_origin (Union[str, Collection[str]]): The exact origin to use 
        for the RP or a collection of allowed origins.
      rp (PublicKeyCredentialRpEntity): The optional RP to enforce when
        authenticating the user (if not supplied an RP must be part of the
        credential data returned for the user by the credentials registrar).
      user (PublicKeyCredentialUserEntity): The optional user to be 
        authenticated (if not supplied a user handle must exist in the
        authenticator assertion response).
      allow_credentials (Optional[Sequence[PublicKeyCredentialDescriptor]]):
        An optional specification of the credentials that the user
        authenticating is allowed to use.
      token_binding (Optional[TokenBinding]): The optional token binding to
        check for.
      require_user_verification (bool): Whether to require user verification.
      expected_extensions (Optional[Set[ExtensionIdentifier]]): The set of
        extensions that are required to be present.
      ignore_clone_error (bool): Whether or not to ignore a signature count
        error that indicates a possible authenticator clone.
      
    Raises:
      ClientDataTypeError: The type of the client data is invalid.
      ChallengeError: The user's challenge and the expected challenge don't
        match.
      DecodingError: There is an error in decoding some data.
      ParserError: There is an error in parsing some data.
      OriginError: There is an issue with a provided web origin.
      TokenBindingError: There is a mismatch in the provided and the user's
        token binding.
      RPIDError: The provided and the user's RP IDs don't match.
      UserPresenceError: The user was not present during authentication.
      UserVerificationError: The user did not perform verification but the
        require_user_verification parameter is True.
      ExtensionError: An expected extension is missing.
      RegistrationError: There is an issue registering the user with the
        credentials registrar.
      CredentialNotAllowedError: A set of allowed credentials is provided and
        the user's credential is not in that set.
      UserIDError: There is a mismatch in the provided user's ID and the user
        ID belonging to the user that the credentials registrar has associated 
        with the credential.
      UserHandleError: There is a mismatch in the user handle present in the
        authenticator assertion response and the user ID belonging to the user 
        that the credentials registrar has associated with the credential.
      RPNotFoundError: An RP was not provided and could not be retrieved from
        the credentials registrar.
      SignatureCountError: The signature count of the credential indicates
        that the authenticator could potentially have been cloned.
      InternalError: An unexpected internal error occurred.
    """
    try:
      allowed_origins = self._extract_allowed_origins(expected_origin)

      response = cast(AuthenticatorAssertionResponse, credential.response)
      if allow_credentials is not None:
        allowed = False
        for cred in allow_credentials:
          if cred.id == credential.raw_id:
            allowed = True
            break

        if not allowed:
          raise CredentialNotAllowedError('Provided credential is not allowed')

      try:
        credential_data = self.registrar.get_credential_data(credential.raw_id)
      except Exception as e:
        raise RegistrationError(
            'Error enountered while getting credential data ({!r})'.format(e))

      if credential_data is None:
        raise CredentialDataError('Could not get credential data')

      registered_user = credential_data.user_entity
      if user is not None:
        if registered_user.id != user.id:
          raise UserIDError(
              'Registered user and provided user IDs do not match')
      else:
        if response.user_handle is None:
          raise UserHandleError('User handle is required in response')

        user = registered_user

      if response.user_handle is not None:
        if response.user_handle != user.id:
          raise UserHandleError('User handle doesn\'t match user ID')

      registered_rp = credential_data.rp_entity
      if registered_rp is None:
        if rp is None:
          raise RPNotFoundError(
              ('Could not find a registered RP with the credential '
               'and one was not provided for verification'))
      elif rp is not None:
        if registered_rp.id != rp.id:
          raise RPIDError('Registered RP and provided RP IDs do not match')
      else:
        rp = registered_rp

      collected_client_data = parse_client_data(response.client_data_JSON)
      if collected_client_data.type != 'webauthn.get':
        raise ClientDataTypeError('Invalid client data type {}'.format(
            collected_client_data.type))

      try:
        challenge = url_base64_decode(collected_client_data.challenge)
        if challenge != expected_challenge:
          raise ChallengeError(
              'Given and expected challenge byte strings don\'t match')
      except ValueError:
        raise DecodingError('Failed to decode the base64 encoded challenge')

      client_origin = parse_origin(collected_client_data.origin)
      if client_origin not in allowed_origins:
        raise OriginError(
            'Given ({0}) and expected ({1}) RP origin don\'t match'.format(
                collected_client_data.origin, expected_origin))

      if token_binding is not None:
        if collected_client_data.token_binding is None:
          raise TokenBindingError('Expecting Token Binding in client data')

        if token_binding.status != collected_client_data.token_binding.status:
          raise TokenBindingError(
              ('Given ({0}) and expected ({1}) Token Binding '
               'statuses dont\'t match').format(
                   collected_client_data.token_binding.status,
                   token_binding.status))

        if token_binding.id != collected_client_data.token_binding.id:
          raise TokenBindingError(
              ('Given ({0}) and expected ({1}) Token Binding '
               'IDs dont\'t match').format(
                   collected_client_data.token_binding.id, token_binding.id))
      elif collected_client_data.token_binding is not None:
        raise TokenBindingError('Unexpected Token Binding in client data')

      client_data_JSON_hash = hashlib.sha256(
          response.client_data_JSON).digest()
      rp_id_hash = hashlib.sha256(rp.id.encode('utf-8')).digest()

      auth_data = parse_authenticator_data(response.authenticator_data)
      if auth_data.rp_id_hash != rp_id_hash:
        raise RPIDHashError('RP ID hash does not match')

      if not (AuthenticatorDataFlag.UP.value & auth_data.flags):
        raise UserPresenceError('User present flag must be set')

      if require_user_verification:
        if not (AuthenticatorDataFlag.UV.value & auth_data.flags):
          raise UserVerificationError('User verification flag must be set')

      if expected_extensions is not None:
        for ee in expected_extensions:
          if not hasattr(auth_data.extensions, ee.key) or getattr(
              auth_data.extensions, ee.key) is None:
            raise ExtensionError('Missing extension {}'.format(ee.value))

      verification_data = response.authenticator_data + client_data_JSON_hash
      verify(credential_data.credential_public_key, response.signature,
             verification_data)

      registered_sign_count = credential_data.signature_count

      if auth_data.sign_count != 0 or registered_sign_count != 0:
        if auth_data.sign_count <= registered_sign_count:
          if not ignore_clone_error:
            raise SignatureCountError(
                'Detected a possible authenticator clone')

      try:
        response = self.registrar.register_credential_request(
            credential=credential,
            authenticator_data=auth_data,
            user=user,
            rp=rp,
        )
      except Exception as e:
        raise RegistrationError(
            'Failed to register credential request ({!r})'.format(e))

      if response is not None:
        raise RegistrationError(
            'Failed to register credential request ({})'.format(response))
    except WebAuthnRPError:
      raise
    except Exception as e:
      raise InternalError('Unexepected error encountered: {!r}'.format(e))
