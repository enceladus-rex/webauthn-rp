import cbor
import hashlib
import json

from typing import Optional, Set, Sequence, cast

from cryptography.hazmat.primitives.hashes import SHA256

from .converters import cryptography_public_key, jsonify
from .errors import (
  AuthenticationError,
  DecodingError,
  IntegrityError,
  ValidationError,
  VerificationError,
  NotFoundError,
  RegistrationError,
  ParseError)
from .parsers import parse_client_data, parse_attestation
from .registrars import CredentialsRegistrar
from .types import (
  CredentialCreationOptions,
  CredentialRequestOptions,
  AuthenticatorAttestationResponse,
  AuthenticatorAssertionResponse,
  PublicKeyCredentialUserEntity,
  PublicKeyCredentialRpEntity,
  AuthenticatorDataFlag,
  ExtensionIdentifier,
  PublicKeyCredentialDescriptor,
  PublicKeyCredential,
  TokenBinding)
from .verifiers import verify
from .utils import url_base64_decode, extract_origin


class CredentialsBackend:

  def __init__(self, registrar: CredentialsRegistrar):
    self.registrar = registrar

  def handle_creation_options(
      self, options: CredentialCreationOptions):
    if not self.registrar.register_creation_options(options):
      raise RegistrationError('Failed to register creation options')

  def handle_request_options(
      self, options: CredentialRequestOptions):
    if not self.registrar.register_request_options(options):
      raise RegistrationError('Failed to register request options')

  def handle_credential_creation(
      self, credential: PublicKeyCredential,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      token_binding: Optional[TokenBinding] = None,
      require_user_verification: bool = False,
      expected_extensions: Optional[Set[ExtensionIdentifier]] = None,
      **registrar_kwargs):
    response = cast(AuthenticatorAttestationResponse, credential.response)
    collected_client_data = parse_client_data(response.client_data_JSON)
    if collected_client_data is None:
      raise ParseError('Could not parse the client data dictionary')
    
    print('collected_client_data', jsonify(collected_client_data))
    if collected_client_data.type != 'webauthn.create':
      raise ValidationError('Invalid client data type {}'.format(
        collected_client_data.type))

    try:
      challenge = url_base64_decode(collected_client_data.challenge)
      create_options_challenge = self.registrar.get_creation_options_challenge(
        user, rp, **registrar_kwargs
      )

      if challenge != create_options_challenge:
        raise IntegrityError(
          'Given and expected challenge byte strings don\'t match')
    except ValueError:
      raise DecodingError('Failed to decode the base64 encoded challenge')

    rp_origin = rp_origin = extract_origin(collected_client_data.origin)
    if rp_origin != rp.id:
      raise IntegrityError(
        'Given ({0}) and expected ({1}) RP origin don\'t match'.format(
          rp_origin, rp.id))
    
    if token_binding is not None:
      if collected_client_data.token_binding is None:
        raise IntegrityError(
          'Expecting Token Binding in client data')
      
      if token_binding.status != collected_client_data.token_binding.status:
        raise IntegrityError((
          'Given ({0}) and expected ({1}) Token Binding '
          'statuses dont\'t match').format(
            collected_client_data.token_binding.status, token_binding.status))

      if token_binding.id != collected_client_data.token_binding.id:
        raise IntegrityError((
          'Given ({0}) and expected ({1}) Token Binding '
          'ids dont\'t match').format(
            collected_client_data.token_binding.id, token_binding.id))
    elif collected_client_data.token_binding is not None:
      raise IntegrityError('Unexpected Token Binding in client data')
    
    client_data_JSON_hash = hashlib.sha256(response.client_data_JSON)
    rp_id_hash = hashlib.sha256(rp.id.encode('utf-8')).digest()

    attestation, raw_att_obj = parse_attestation(response.attestation_object)
    print('rp_id_hash', attestation.auth_data.rp_id_hash, rp_id_hash)
    if attestation.auth_data.rp_id_hash != rp_id_hash:
      raise IntegrityError('RP ID hash does not match')

    if not (AuthenticatorDataFlag.UP.value & attestation.auth_data.flags):
      raise ValidationError('User present flag must be set')

    if require_user_verification:
      if not (AuthenticatorDataFlag.UV.value & attestation.auth_data.flags):
        raise ValidationError('User verification flag must be set')
    
    if expected_extensions is not None:
      for e in expected_extensions:
        if not hasattr(
            attestation.auth_data.attested_credential_data.extensions,
            e.key) or getattr(
            attestation.auth_data.attested_credential_data.extensions,
            e.key) is None:
          raise ValidationError('Missing extension {}'.format(e.value))

    print(type(attestation.att_stmt))
    att_type, trusted_path = verify(
      attestation.att_stmt,
      attestation.auth_data.attested_credential_data.credential_public_key,
      raw_att_obj['authData'],
      client_data_JSON_hash)

    crypto_pk = cryptography_public_key(
      attestation.auth_data.attested_credential_data.credential_public_key)

    if not self.registrar.register_credential_creation(
          credential=credential, att=attestation,
          att_type=att_type, user=user, rp=rp,
          cryptography_public_key=crypto_pk,
          trusted_path=trusted_path,
          **registrar_kwargs
        ):
      raise RegistrationError('Failed to create credential')
  
  def handle_credential_request(
      self, credential: PublicKeyCredential,
      rp: Optional[PublicKeyCredentialRpEntity] = None,
      user: Optional[PublicKeyCredentialUserEntity] = None,
      allow_credentials:
        Optional[Sequence[PublicKeyCredentialDescriptor]] = None,
      token_binding: Optional[TokenBinding] = None,
      require_user_verification: bool = False,
      expected_extensions: Optional[Set[ExtensionIdentifier]] = None,
      ignore_clone_error: bool = False,
      **registrar_kwargs) -> bool:
    response = cast(AuthenticatorAssertionResponse, credential.response)
    if allow_credentials is not None:
      allowed = False
      for cred in allow_credentials:
        if cred.id == credential.raw_id:
          allowed = True
          break

      if not allowed:
        raise ValidationError('Provided credential is not allowed')

    credential_data = self.registrar.get_credential_data(
      credential.raw_id, **registrar_kwargs)

    if credential_data is None:
      raise NotFoundError('Could not get credential data')

    registered_user = credential_data.user_entity
    
    if registered_user is None:
      raise NotFoundError('Could not find a user with the credential')

    registered_rp = credential_data.rp_entity

    if registered_rp is None:
      if rp is None:
        raise NotFoundError((
          'Could not find a registered rp with the credential '
          'and one was not provided for verification'))
    elif rp is not None:
      if registered_rp.id != rp.id:
        raise ValidationError('Registered rp and provided rp ids do not match')
    else:
      rp = registered_rp  

    if user is not None:
      if response.user_handle is not None:
        if response.user_handle != user.id:
          raise ValidationError('User handle doesn\'t match user id')
    else:
      if response.user_handle is None:
        raise ValidationError((
          'User cannot be verified, must provide one or '
          'there must be a user handle'))
      
      valid_credential = self.registrar.check_user_owns_credential(
        response.user_handle, credential.raw_id, **registrar_kwargs)
      
      if not valid_credential:
        raise ValidationError('User does not own credential')

    cpk = credential_data.public_key

    collected_client_data = parse_client_data(response.client_data_JSON)
    if collected_client_data is None:
      raise ParseError('Could not parse the client data dictionary')
    
    if collected_client_data.type != 'webauthn.get':
      raise ValidationError('Invalid client data type {}'.format(
        collected_client_data.type))

    try:
      challenge = url_base64_decode(collected_client_data.challenge)
      request_options_challenge = self.registrar.get_request_options_challenge(
        user, rp, **registrar_kwargs)

      if challenge != request_options_challenge:
        raise IntegrityError(
          'Given and expected challenge byte strings don\'t match')
    except ValueError:
      raise DecodingError('Failed to decode the base64 encoded challenge')

    rp_origin = extract_origin(collected_client_data.origin)
    if rp_origin != rp.id:
      raise IntegrityError(
        'Given ({0}) and expected ({1}) RP origin don\'t match'.format(
          rp_origin, rp.id))
    
    if token_binding is not None:
      if collected_client_data.token_binding is None:
        raise IntegrityError(
          'Expecting Token Binding in client data')
      
      if token_binding.status != collected_client_data.token_binding.status:
        raise IntegrityError((
          'Given ({0}) and expected ({1}) Token Binding '
          'statuses dont\'t match').format(
            collected_client_data.token_binding.status, token_binding.status))

      if token_binding.id != collected_client_data.token_binding.id:
        raise IntegrityError((
          'Given ({0}) and expected ({1}) Token Binding '
          'ids dont\'t match').format(
            collected_client_data.token_binding.id, token_binding.id))
    elif collected_client_data.token_binding is not None:
      raise IntegrityError('Unexpected Token Binding in client data')
    
    client_data_JSON_hash = hashlib.sha256(response.client_data_JSON)
    rp_id_hash = hashlib.sha256(rp.id.encode('utf-8'))
    
    auth_data = parse_authenticator_data(
      response.authenticator_data)

    if auth_data.rp_id_hash != rp_id_hash:
      raise IntegrityError('RP ID hash does not match')

    if not (AuthenticatorDataFlag.UP.value & auth_data.flags):
      raise ValidationError('User present flag must be set')

    if require_user_verification:
      if not (AuthenticatorDataFlag.UV.value & auth_data.flags):
        raise ValidationError('User verification flag must be set')
    
    if expected_extensions is not None:
      for e in expected_extensions:
        if not hasattr(
            auth_data.attested_credential_data.extensions,
            e.key) or getattr(
            auth_data.attested_credential_data.extensions,
            e.key) is None:
          raise ValidationError('Missing extension {}'.format(e.value))

    try:
      verification_data = response.authenticator_data + client_data_JSON_hash
      cpk.verify(response.signature, verification_data, SHA256())
    except cryptography.exceptions.InvalidSignature:
      raise VerificationError(
        'Assertion verification failed: invalid signature')
    
    registered_sign_count = credential_data.signature_count

    if auth_data.sign_count != 0 or registered_sign_count != 0:
      if auth_data.sign_count <= registered_sign_count:
        if not ignore_clone_error:
          raise SignatureCountError(
            'Detected a possible authenticator clone')

    if not self.registrar.register_credential_request(
          credential=credential,
          authenticator_data=authenticator_data,
          user=user, rp=rp,
          **registrar_kwargs
        ):
      raise RegistrationError('Failed to request credential')