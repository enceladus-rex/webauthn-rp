import cbor
import json
import struct

from enum import Enum
from typing import Optional, Union, Sequence, Any, Tuple, Set

from .errors import (
  DecodingError,
  TokenBindingError,
  ValidationError,
)
from .types import (
  CollectedClientData,
  TokenBinding,
  TokenBindingStatus,
  AttestationObject,
  AttestationStatementFormatIdentifier,
  AuthenticatorData,
  COSEKeyType,
  COSEAlgorithmIdentifier,
  COSEKeyOperation,

  CredentialPublicKey,
  FIDOU2FCredentialPublicKey,

  AuthenticationExtensionsClientOutputs,
  Coordinates,
  AttestedCredentialData,
  AttestationStatement,
  
  PackedAttestationStatement,
  PackedX509AttestationStatement,
  PackedECDAAAttestationStatement,

  TPMAttestationStatement,
  TPMX509AttestationStatement,
  TPMECDAAAttestationStatement,
  
  AndroidKeyAttestationStatement,
  AndroidSafetyNetAttestationStatement,
  FIDOU2FAttestationStatement,
  NoneAttestationStatement
)
from . import validators


def parse_dictionary_field(
    field_key: Any,
    valid_types: Union[type, Sequence[type]],
    dictionary: dict,
    required: bool = True) -> Any:
  if type(valid_types) is type:
    valid_types = [valid_types]
  
  field = dictionary.get(field_key)
  if field is None:
    if not required: return
    raise ValidationError(
      '{} is required in dictionary keys'.format(
        field_name))

  if type(field) not in valid_types:
    raise ValidationError(
      '{} type must be one of {}'.format(field_name, str(valid_types)))

  return field


def parse_credential_public_key_kty(
    credential_public_key: dict) -> Union[COSEKeyType.Name, COSEKeyType.Value]:
  kty_raw = parse_dictionary_field(
    1, (int, str), credential_public_key)

  try:
    kty = COSEKeyType(kty_raw)
  except KeyError:
    raise ValidationError(
      'Invalid credential public key type {}'.format(kty_raw))
  return kty


def parse_credential_public_key_alg(
    credential_public_key: dict) -> Union[
      COSEAlgorithmIdentifier.Name,
      COSEAlgorithmIdentifier.Value]:
  alg_raw = parse_dictionary_field(
    1, (int, str), credential_public_key)

  try:
    alg = COSEAlgorithmIdentifier(alg_raw)
  except KeyError:
    raise ValidationError(
      'Invalid credential public key alg type {}'.format(alg_raw))
  return alg


def parse_credential_public_key_key_ops(
    credential_public_key: dict) -> Sequence[
      Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]:
  key_ops_raw = parse_dictionary_field(
    4, (list, tuple), credential_public_key, False)
  
  if key_ops_raw is None: return

  if len(key_ops_raw) < 1:
    raise ValidationError(
      'Credential public key key_ops(4) must have at least 1 element')

  key_ops = []
  for i, ko in enumerate(key_ops_raw):
    if type(ko) not in (str, int):
      raise ValidationError((
        'Credential public key key_ops(3) index {} should either be a'
        ' text string or an integer').format(i))
    
    try:
      key_ops.append(COSEAlgorithmIdentifier(ko))
    except KeyError:
      raise ValidationError(
        'Invalid credential public key key op {}'.format(
          credential_public_key[4]))
  return key_ops


def parse_credential_public_key_kwargs(
    credential_public_key: dict) -> dict:
  kty = parse_credential_public_key_kty(credential_public_key)
  kid = parse_dictionary_field(
      2, bytes, credential_public_key, False)
  alg = parse_credential_public_key_alg(credential_public_key)
  key_ops = parse_credential_public_key_key_ops(
      credential_public_key)
  base_IV = parse_dictionary_field(
    5, bytes, credential_public_key, False)
  return {
    'kty': kty,
    'kid': kid,
    'alg': alg,
    'key_ops': key_ops,
    'base_IV': base_IV
  }


def parse_fido_u2f_credential_public_key(
    credential_public_key: dict) -> FIDOU2FCredentialPublicKey:
  x = parse_dictionary_field(-2, bytes, credential_public_key)
  y = parse_dictionary_field(-3, bytes, credential_public_key)

  if len(x) != 32 or len(y) != 32:
    raise ValidationError(
      'Packed credential public key x and y must be 32 bytes')

  return FIDOU2FCredentialPublicKey(
    x=x, y=y,
    **parse_credential_public_key_kwargs(credential_public_key),
  )


def parse_packed_credential_public_key(
    credential_public_key: dict) -> CredentialPublicKey:
  raise UnimplementedError('Packed credential public key unimplemented')


def parse_tpm_credential_public_key(
    credential_public_key: dict) -> CredentialPublicKey:
  raise UnimplementedError('TPM credential public key unimplemented')


def parse_android_key_credential_public_key(
    credential_public_key: dict) -> CredentialPublicKey:
  raise UnimplementedError('Android Key credential public key unimplemented')


def parse_android_safetynet_credential_public_key(
    credential_public_key: dict) -> CredentialPublicKey:
  raise UnimplementedError('Android SafetyNet credential public key unimplemented')


def parse_none_credential_public_key(
    credential_public_key: dict) -> CredentialPublicKey:
  raise UnimplementedError('None credential public key unimplemented')


class CredentialPublicKeyParser(Enum):
  PACKED = parse_packed_credential_public_key
  TPM = parse_tpm_credential_public_key
  ANDROID_KEY = parse_android_key_credential_public_key
  ANDROID_SAFETYNET = parse_android_safetynet_credential_public_key
  FIDO_U2F = parse_fido_u2f_credential_public_key
  NONE = parse_none_credential_public_key


def parse_extensions(
    extensions: dict) -> AuthenticationExtensionsClientOutputs:
  supported_extensions = {
    'appid', 'txAuthSimple', 'txAuthGeneric', 'authnSel',
    'exts', 'uvi', 'loc', 'uvm', 'biometricPerfBounds'
  }

  unsupported_extensions = set(extensions.keys()).difference(
    supported_extensions)
  
  if unsupported_extensions:
    raise ValidationError('Found unsupported extensions {}'.format(
      str(unsupported_extensions)))
  
  appid = extensions.get('appid')
  tx_auth_simple = extensions.get('txAuthSimple')
  tx_auth_generic = extensions.get('txAuthGeneric')
  authn_sel = extensions.get('authnSel')
  exts = extensions.get('exts')
  uvi = extensions.get('uvi')
  loc = extensions.get('loc')
  uvm = extensions.get('uvm')
  biometric_perf_bounds = extensions.get('biometricPerfBounds')

  if appid is not None:
    if type(appid) is not bool:
      raise ValidationError('appid extension client output should be a bool')
  
  if tx_auth_simple is not None:
    if type(tx_auth_simple) is not bool:
      raise ValidationError(
        'tx_auth_simple extension client output should be a str')

  if tx_auth_generic is not None:
    if type(tx_auth_generic) is not bytes:
      raise ValidationError(
        'tx_auth_generic extension client output should be bytes')
  
  if authn_sel is not None:
    if type(authn_sel) is not bool:
      raise ValidationError(
        'authn_sel extension client output should be bool')

  if exts is not None:
    if type(exts) not in (list, tuple):
      raise ValidationError(
        'exts extension client output should be list')
    
    for i, e in enumerate(exts):
      if type(e) is not str:
        raise ValidationError(
          'exts[{0}] extension client output should be str'.format(i))

  if uvi is not None:
    if type(uvi) is not bytes:
      raise ValidationError(
        'uvi extension client output should be bytes')

  if loc is not None:
    if type(loc) is not dict:
      raise ValidationError(
        'loc extension client output should be dict')

    if any(type(x) is not float for x in loc.values()):
      raise ValidationError('Coordinate value in loc extension must be float')

    supported_cvalues = {
      'latitude', 'longitude', 'altitude', 'accuracy',
      'altitudeAccuracy', 'heading', 'speed'}

    unsupported_cvalues = set(loc.keys()).difference(supported_cvalues)
    if unsupported_cvalues:
      raise ValidationError('Found unsupported loc key values {}'.format(
        str(unsupported_cvalues)))

    loc = Coordinates(
      latitude=loc.get('latitude'),
      longitude=loc.get('longitude'),
      altitude=loc.get('altitude'),
      accuracy=loc.get('accuracy'),
      altitude_accuracy=loc.get('altitudeAccuracy'),
      heading=loc.get('heading'),
      speed=loc.get('speed'))
  
  if uvm is not None:
    if type(uvm) is not list:
      raise ValidationError(
        'uvm extension client output should be list')

    for i, uvm_entry in enumerate(uvm):
      if type(uvm_entry) is not list:
        raise ValidationError(
          'uvm[{0}] extension client output should be list'.format(i))
      
      for j, v in enumerate(uvm_entry):
        if type(v) is not str:
          raise ValidationError(
            'uvm[{0}][{1}] extension client output should be str'.format(i, j))
  
  if biometric_perf_bounds is not None:
    if type(biometric_perf_bounds) is not bool:
      raise ValidationError(
        'biometric_perf_bounds extension client output should be bool')

  return AuthenticationExtensionsClientOutputs(
    appid=appid,
    tx_auth_simple=tx_auth_simple,
    tx_auth_generic=tx_auth_generic,
    authn_sel=authn_sel,
    exts=exts,
    uvi=uvi,
    loc=loc,
    uvm=uvm,
    biometric_perf_bounds=biometric_perf_bounds,
  )


def check_unsupported_keys(supported: Set[str], data: dict):
  unsupported_keys = set(data.keys()).difference(supported)
  if unsupported_keys:
    raise ValidationError((
      'Found unsupported keys in attestation statement {}').format(
        str(unsupported_keys)))


def parse_attestation_statement_alg(
    att_stmt: dict) -> Union[
      COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]:
  alg = parse_dictionary_field('alg', (int, str), att_stmt)

  try:
    alg = COSEAlgorithmIdentifier(alg)
  except KeyError:
    raise ValidationError('Invalid algorithm identifier {}'.format(alg))
  return alg


def parse_attestation_statement_x5c(
    att_stmt: dict) -> bytes:
  x5c = parse_dictionary_field('x5c', (list, tuple), att_stmt)
  
  for i, e in enumerate(x5c):
    if type(e) is not bytes:
      raise ValidationError(
        'x5c[{}] must be a byte string'.format(i))
  return x5c


def parse_packed_attestation_statement(
    att_stmt: dict) -> PackedAttestationStatement:
  supported_keys = {'alg', 'sig'}
  alg = parse_attestation_statement_alg(att_stmt)
  sig = parse_dictionary_field('sig', bytes, att_stmt)
  
  if 'x5c' in att_stmt:
    supported_keys.add('x5c')
    check_unsupported_keys(supported_keys, att_stmt)
    x5c = parse_attestation_statement_x5c(att_stmt)
    return PackedX509AttestationStatement(
      alg=alg, sig=sig, x5c=x5c)
  
  if 'ecdaaKeyId' in att_stmt:
    supported_keys.add('ecdaaKeyId')
    check_unsupported_keys(supported_keys, att_stmt)
    ecdaa_key_id = parse_dictionary_field('ecdaaKeyId', bytes, att_stmt)
    return PackedECDAAAttestationStatement(
      alg=alg, sig=sig, ecdaa_key_id=ecdaa_key_id)

  check_unsupported_keys(supported_keys, att_stmt)
  return PackedAttestationStatement(alg=alg, sig=sig)


def parse_tpm_attestation_statement(
    att_stmt: dict) -> TPMAttestationStatement:
  supported_keys = {'alg', 'sig', 'ver', 'certInfo', 'pubArea'}
  alg = parse_attestation_statement_alg(att_stmt)
  sig = parse_dictionary_field('sig', bytes, att_stmt)
  ver = parse_dictionary_field('ver', str, att_stmt)
  cert_info = parse_dictionary_field('certInfo', bytes, att_stmt)
  pub_area = parse_dictionary_field('pubArea', bytes, att_stmt)

  if 'x5c' in att_stmt:
    supported_keys.add('x5c')  
    check_unsupported_keys(supported_keys, att_stmt)
    x5c = parse_attestation_statement_x5c(att_stmt)
    return TPMX509AttestationStatement(
      alg=alg, sig=sig, ver=ver, cert_info=cert_info, 
      pub_area=pub_area, x5c=x5c)
  
  if 'ecdaaKeyId' in att_stmt:
    supported_keys.add('ecdaaKeyId')
    check_unsupported_keys(supported_keys, att_stmt)
    ecdaa_key_id = parse_attestation_statement_ecdaa_key_id(att_stmt)
    return TPMECDAAAttestationStatement(
      alg=alg, sig=sig, ver=ver, cert_info=cert_info, 
      pub_area=pub_area, ecdaa_key_id=ecdaa_key_id)

  check_unsupported_keys(supported_keys, att_stmt)
  return TPMAttestationStatement(
    alg=alg, sig=sig, ver=ver, cert_info=cert_info, pub_area=pub_area
  )


def parse_android_key_attestation_statement(
    att_stmt: dict) -> AndroidKeyAttestationStatement:
  supported_keys = {'alg', 'sig', 'x5c'}
  alg = parse_attestation_statement_alg(att_stmt)
  sig = parse_dictionary_field('sig', bytes, att_stmt)  
  x5c = parse_attestation_statement_x5c(att_stmt)
  check_unsupported_keys(supported_keys, att_stmt)
  return AndroidKeyAttestationStatement(
    alg=alg, sig=sig, x5c=x5c)


def parse_android_safetynet_attestation_statement(
    att_stmt: dict) -> AndroidSafetyNetAttestationStatement:
  supported_keys = {'alg', 'sig', 'ver', 'response'}
  alg = parse_attestation_statement_alg(att_stmt)
  sig = parse_dictionary_field('sig', bytes, att_stmt)  
  ver = parse_dictionary_field('ver', str, att_stmt)
  response = parse_dictionary_field('response', bytes, att_stmt)
  check_unsupported_keys(supported_keys, att_stmt)
  return AndroidSafetyNetAttestationStatement(
    alg=alg, sig=sig, ver=ver, response=response)


def parse_fido_u2f_attestation_statement(
    att_stmt: dict) -> FIDOU2FAttestationStatement:
  supported_keys = {'alg', 'sig', 'x5c'}
  alg = parse_attestation_statement_alg(att_stmt)
  sig = parse_dictionary_field('sig', bytes, att_stmt)  
  x5c = parse_attestation_statement_x5c(att_stmt)
  check_unsupported_keys(supported_keys, att_stmt)
  return FIDOU2FAttestationStatement(
    alg=alg, sig=sig, x5c=x5c)


def parse_none_attestation_statement(
    att_stmt: dict) -> NoneAttestationStatement:
  check_unsupported_keys({}, att_stmt)
  return NoneAttestationStatement()


class AttestationStatementParser(Enum):
  PACKED = parse_packed_attestation_statement
  TPM = parse_tpm_attestation_statement
  ANDROID_KEY = parse_android_key_attestation_statement
  ANDROID_SAFETYNET = parse_android_safetynet_attestation_statement
  FIDO_U2F = parse_fido_u2f_attestation_statement
  NONE = parse_none_attestation_statement


def parse_client_data(client_data_json: str) -> Optional[CollectedClientData]:
  try:
    client_data_text = response.client_data_json.decode('utf-8')
    client_data = json.loads(client_data_text)
  except (UnicodeDecodeError, json.JSONDecodeError):
    raise DecodingError('Could not decode the client data JSON')

  type_ = client_data.get('type')
  challenge = client_data.get('challenge')
  origin = client_data.get('origin')

  if all((type_, challenge, origin), lambda x: isinstance(x, str)):
    token_binding_data = client_data.get('tokenBinding')
    if token_binding_data is not None:
      token_binding_status = token_binding_data.get('status')
      token_binding_id = token_binding_data.get('id')

      if token_binding_status == TokenBindingStatus.PRESENT and (
          token_binding_id is None):
        raise TokenBindingError(
          'Token Binding must contain an id if status is {}'.format(
            TokenBindingStatus.PRESENT
          ))
      
      token_binding = TokenBinding(
        status=token_binding_status, id=token_binding_id)

    return CollectedClientData(
      type=type_,
      challenge=challenge,
      origin=origin,
      token_binding=token_binding
    )


def parse_authenticator_data(
    auth_data: bytes,
    fmt: Optional[
      AttestationStatementFormatIdentifier] = None) -> AuthenticatorData:
  if len(auth_data) < 35:
    raise ValidationError('Attestation auth data must be at least 35 bytes')

  rp_id_hash = auth_data[:32]
  flags = auth_data[32]
  signature_counter_bytes = auth_data[33:37]
  signature_counter_uint32 = struct.unpack('>I', counter_bytes)

  attested_credential_data = None
  if len(auth_data) >= 53:
    aaguid = auth_data[35:51]
    credential_id_length_bytes = auth_data[51:53]
    credential_id_length_uint16 = struct.unpack('>H')
    credential_id = auth_data[53:(53 + credential_id_length_uint16)]
    credential_public_key_bytes = auth_data[
      (53 + credential_id_length_uint16):]

    try:
      credential_public_key, bytes_read = cbor._loads(
        credential_public_key_bytes)
    except ValueError:
      raise DecodingError('Could not decode the credential public key CBOR')

    if type(credential_public_key) is not dict:
      raise ValidationError('Credential public key must be a dictionary')

    cpk = None
    if fmt is not None:
      try:
        cpk_parser = CredentialPublicKeyParser[fmt.name]
      except KeyError:
        ValidationError('Parser not supported for key type {}'.format(
          fmt.name))

      cpk = cpk_parser(credential_public_key)
      validators.keys.validate(cpk)

    extension_bytes = credential_public_key_bytes[bytes_read:]

    aeci = None
    if extension_bytes:
      try:
        extensions = cbor.loads(extension_bytes)
      except ValueError:
        raise DecodingError('Could not decode the extensions CBOR')
      aeci = parse_extensions(extensions)
    
    attested_credential_data = AttestedCredentialData(
      aaguid=aaguid,
      credential_id_length=credential_id_length_uint16,
      credential_id=credential_id,
      credential_public_key=cpk,
      extensions=aeci,
    )

  return AuthenticatorData(
    rp_id_hash=rp_id_hash,
    flags=flags,
    sign_count=signature_counter_uint32,
    attested_credential_data=attested_credential_data
  )


def parse_attestation(attestation_object: bytes) -> Tuple[
    AttestationObject, dict]:
  try:
    attestation_object_data = cbor.loads(attestation_object)
  except ValueError:
    raise DecodingError('Could not decode the attestation object CBOR')

  try:
    auth_data = attestation_object_data['authData']
    fmt = attestation_object_data['fmt']
    att_stmt = attestation_object_data['attStmt']
    
    if type(fmt) is not str:
      raise ValidationError('fmt must be a text string')

    try:
      asfi = AttestationStatementFormatIdentifier[fmt]
    except KeyError:
      raise ValidationError('Invalid attestation statement format identifier')

    if type(auth_data) is not bytes:
      raise ValidationError('Attestation auth data should be bytes')
    
    authenticator_data = parse_authenticator_data(
      auth_data, asfi)
  except KeyError as e:
    raise ValidationError('Missing {} in attestation'.format(str(e)))

  if type(att_stmt) is not dict:
    raise ValidationError('attStmt must be a dictionary')

  try:
    as_parser = AttestationStatementParser[asfi.name]
    attestation_statement = as_parser(att_stmt)
  except KeyError:
    raise ValidationError('Unsupported attestation statement {}'.format(
      asfi.name))

  return AttestationObject(
    auth_data=authenticator_data,
    fmt=asfi,
    att_stmt=attestation_statement,
  ), attestation_object_data