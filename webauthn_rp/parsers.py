import base64
import binascii
import io
import json
import struct
from enum import Enum
from functools import singledispatch
from typing import Any, List, Optional, Sequence, Set, Tuple, Union, cast

import cbor2

from webauthn_rp.constants import (ED448_COORDINATE_BYTE_LENGTH,
                                   ED25519_COORDINATE_BYTE_LENGTH,
                                   P_256_COORDINATE_BYTE_LENGTH,
                                   P_384_COORDINATE_BYTE_LENGTH,
                                   P_521_COORDINATE_BYTE_LENGTH)
from webauthn_rp.errors import (DecodingError, TokenBindingError,
                                ValidationError)
from webauthn_rp.types import (
    AndroidKeyAttestationStatement, AndroidSafetyNetAttestationStatement,
    AttestationObject, AttestationStatement,
    AttestationStatementFormatIdentifier, AttestedCredentialData,
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse, AuthenticatorData, AuthenticatorDataFlag,
    CollectedClientData, Coordinates, COSEAlgorithmIdentifier,
    COSEKeyOperation, COSEKeyType, CredentialPublicKey, EC2CredentialPublicKey,
    EC2Curve, FIDOU2FAttestationStatement, NoneAttestationStatement,
    OKPCredentialPublicKey, OKPCurve, PackedAttestationStatement,
    PackedECDAAAttestationStatement, PackedX509AttestationStatement,
    PublicKeyCredential, TokenBinding, TokenBindingStatus,
    TPMAttestationStatement, TPMECDAAAttestationStatement,
    TPMX509AttestationStatement)
from webauthn_rp.utils import curve_coordinate_byte_length
from webauthn_rp.validators import validate


def parse_dictionary_field(field_key: Any,
                           valid_types: Union[type, Sequence[type]],
                           dictionary: dict,
                           required: bool = True) -> Any:
  valid_types_seq: Sequence[type] = [valid_types] if (  # type: ignore
      type(valid_types) is type) else valid_types
  field = dictionary.get(field_key)
  if field is None:
    if not required: return
    raise ValidationError(
        '{} is required in dictionary keys'.format(field_key))

  if type(field) not in valid_types_seq:
    raise ValidationError('{} type must be one of {} not {}'.format(
        field_key, str(valid_types_seq), str(type(field))))

  return field


def check_unsupported_keys(supported: Set[str], data: dict):
  unsupported_keys = set(data.keys()).difference(supported)
  if unsupported_keys:
    raise ValidationError(
        ('Found unsupported keys in data {}').format(str(unsupported_keys)))


def bytes_from_base64(s: str) -> bytes:
  try:
    return base64.b64decode(s)
  except Exception:
    raise ValidationError('Invalid base64 string')


def parse_public_key_credential(data: dict) -> PublicKeyCredential:
  check_unsupported_keys({'id', 'rawId', 'response', 'type'}, data)
  id_ = parse_dictionary_field('id', str, data)
  type_ = parse_dictionary_field('type', str, data)
  raw_id = bytes_from_base64(parse_dictionary_field('rawId', str, data))

  response = parse_dictionary_field('response', dict, data)
  client_data_JSON = bytes_from_base64(
      parse_dictionary_field('clientDataJSON', str, response))

  if 'attestationObject' in response:
    # Parse AuthenticatorAttestationResponse
    check_unsupported_keys({'clientDataJSON', 'attestationObject'}, response)

    attestation_object = bytes_from_base64(
        parse_dictionary_field('attestationObject', str, response))

    return PublicKeyCredential(id=id_,
                               type=type_,
                               raw_id=raw_id,
                               response=AuthenticatorAttestationResponse(
                                   client_data_JSON=client_data_JSON,
                                   attestation_object=attestation_object))
  else:
    # Parse AuthenticatorAssertionResponse
    check_unsupported_keys(
        {'clientDataJSON', 'authenticatorData', 'signature', 'userHandle'},
        response)

    authenticator_data = bytes_from_base64(
        parse_dictionary_field('authenticatorData', str, response))
    signature = bytes_from_base64(
        parse_dictionary_field('signature', str, response))
    user_handle_b64s = parse_dictionary_field('userHandle', str, response,
                                              False)
    user_handle = None
    if user_handle_b64s is not None:
      user_handle = bytes_from_base64(user_handle_b64s)

    return PublicKeyCredential(id=id_,
                               type=type_,
                               raw_id=raw_id,
                               response=AuthenticatorAssertionResponse(
                                   client_data_JSON=client_data_JSON,
                                   authenticator_data=authenticator_data,
                                   signature=signature,
                                   user_handle=user_handle))


def parse_credential_public_key_kty(
    credential_public_key: dict) -> Union[COSEKeyType.Name, COSEKeyType.Value]:
  kty_raw = parse_dictionary_field(1, (int, str), credential_public_key)

  try:
    kty = cast(Union[COSEKeyType.Name, COSEKeyType.Value],
               COSEKeyType(kty_raw))  # type: ignore
  except (KeyError, ValueError):
    raise ValidationError(
        'Invalid credential public key type {}'.format(kty_raw))
  return kty


def parse_credential_public_key_alg(
    credential_public_key: dict
) -> Union[COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]:
  alg_raw = parse_dictionary_field(3, (int, str), credential_public_key)

  try:
    alg = cast(Union[COSEAlgorithmIdentifier.Name,
                     COSEAlgorithmIdentifier.Value],
               COSEAlgorithmIdentifier(alg_raw))  # type: ignore
  except (KeyError, ValueError):
    raise ValidationError(
        'Invalid credential public key alg type {}'.format(alg_raw))
  return alg


def parse_credential_public_key_key_ops(
    credential_public_key: dict
) -> Optional[Sequence[Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]]:
  key_ops_raw = parse_dictionary_field(4, (list, tuple), credential_public_key,
                                       False)

  if key_ops_raw is None: return None

  if len(key_ops_raw) < 1:
    raise ValidationError(
        'Credential public key key_ops(4) must have at least 1 element')

  key_ops: List[Union[COSEKeyOperation.Name, COSEKeyOperation.Value]] = []
  for i, ko in enumerate(key_ops_raw):
    if type(ko) not in (str, int):
      raise ValidationError(
          ('Credential public key key_ops(3) index {} should either be a'
           ' text string or an integer').format(i))

    try:
      key_ops.append(COSEKeyOperation(ko))  # type: ignore
    except (KeyError, ValueError):
      raise ValidationError('Invalid credential public key key op {}'.format(
          credential_public_key[4]))

  return key_ops


def parse_credential_public_key_kwargs(credential_public_key: dict) -> dict:
  kty = parse_credential_public_key_kty(credential_public_key)
  kid = parse_dictionary_field(2, bytes, credential_public_key, False)
  alg = parse_credential_public_key_alg(credential_public_key)
  key_ops = parse_credential_public_key_key_ops(credential_public_key)
  base_IV = parse_dictionary_field(5, bytes, credential_public_key, False)
  return {
      'kty': kty,
      'kid': kid,
      'alg': alg,
      'key_ops': key_ops,
      'base_IV': base_IV
  }


def parse_ec2_public_key_crv(
    credential_public_key: dict) -> Union[EC2Curve.Name, EC2Curve.Value]:
  crv_raw = parse_dictionary_field(-1, (int, str), credential_public_key)
  try:
    return EC2Curve(crv_raw)  # type: ignore
  except (KeyError, ValueError):
    raise ValidationError('Invalid EC2 curve {}'.format(crv_raw))


def parse_okp_public_key_crv(
    credential_public_key: dict) -> Union[OKPCurve.Name, OKPCurve.Value]:
  crv_raw = parse_dictionary_field(-1, (int, str), credential_public_key)
  try:
    return OKPCurve(crv_raw)  # type: ignore
  except (KeyError, ValueError):
    raise ValidationError('Invalid OKP curve {}'.format(crv_raw))


def parse_okp_public_key(credential_public_key: dict) -> CredentialPublicKey:
  x = parse_dictionary_field(-2, bytes, credential_public_key)
  crv = parse_okp_public_key_crv(credential_public_key)
  crv_len = curve_coordinate_byte_length(crv)
  if len(x) != crv_len:
    raise ValidationError(
        'Packed credential public key x and y must be {} bytes'.format(
            crv_len))

  return OKPCredentialPublicKey(
      crv=crv,
      x=x,
      **parse_credential_public_key_kwargs(credential_public_key),
  )


def parse_ec2_public_key(
    credential_public_key: dict) -> EC2CredentialPublicKey:
  x = parse_dictionary_field(-2, bytes, credential_public_key)
  y = parse_dictionary_field(-3, bytes, credential_public_key)
  crv = parse_ec2_public_key_crv(credential_public_key)
  crv_len = curve_coordinate_byte_length(crv)
  if len(x) != crv_len or len(y) != crv_len:
    raise ValidationError(
        'Packed credential public key x and y must be {} bytes'.format(
            crv_len))

  return EC2CredentialPublicKey(
      x=x,
      y=y,
      crv=crv,
      **parse_credential_public_key_kwargs(credential_public_key),
  )


class CredentialPublicKeyParser(Enum):
  OKP = parse_okp_public_key
  EC2 = parse_ec2_public_key


def parse_extensions(
    extensions: dict) -> AuthenticationExtensionsClientOutputs:
  supported_extensions = {
      'appid', 'txAuthSimple', 'txAuthGeneric', 'authnSel', 'exts', 'uvi',
      'loc', 'uvm', 'biometricPerfBounds'
  }

  unsupported_extensions = set(
      extensions.keys()).difference(supported_extensions)

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
    if type(tx_auth_simple) is not str:
      raise ValidationError(
          'tx_auth_simple extension client output should be a str')

  if tx_auth_generic is not None:
    if type(tx_auth_generic) is not bytes:
      raise ValidationError(
          'tx_auth_generic extension client output should be bytes')

  if authn_sel is not None:
    if type(authn_sel) is not bool:
      raise ValidationError('authn_sel extension client output should be bool')

  if exts is not None:
    if type(exts) not in (list, tuple):
      raise ValidationError('exts extension client output should be list')

    for i, e in enumerate(exts):
      if type(e) is not str:
        raise ValidationError(
            'exts[{0}] extension client output should be str'.format(i))

  if uvi is not None:
    if type(uvi) is not bytes:
      raise ValidationError('uvi extension client output should be bytes')

  if loc is not None:
    if type(loc) is not dict:
      raise ValidationError('loc extension client output should be dict')

    if any(type(x) not in (int, float) for x in loc.values()):
      raise ValidationError('Coordinate value in loc extension must be float')

    supported_cvalues = {
        'latitude', 'longitude', 'altitude', 'accuracy', 'altitudeAccuracy',
        'heading', 'speed'
    }

    unsupported_cvalues = set(loc.keys()).difference(supported_cvalues)
    if unsupported_cvalues:
      raise ValidationError('Found unsupported loc key values {}'.format(
          str(unsupported_cvalues)))

    loc = Coordinates(latitude=loc.get('latitude'),
                      longitude=loc.get('longitude'),
                      altitude=loc.get('altitude'),
                      accuracy=loc.get('accuracy'),
                      altitude_accuracy=loc.get('altitudeAccuracy'),
                      heading=loc.get('heading'),
                      speed=loc.get('speed'))

  if uvm is not None:
    if type(uvm) is not list:
      raise ValidationError('uvm extension client output should be list')

    for i, uvm_entry in enumerate(uvm):
      if type(uvm_entry) is not list:
        raise ValidationError(
            'uvm[{0}] extension client output should be list'.format(i))

      for j, v in enumerate(uvm_entry):
        if type(v) is not int:
          raise ValidationError(
              'uvm[{0}][{1}] extension client output should be str'.format(
                  i, j))

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


def parse_attestation_statement_alg(
    att_stmt: dict
) -> Union[COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]:
  alg = parse_dictionary_field('alg', (int, str), att_stmt)

  try:
    alg = COSEAlgorithmIdentifier(alg)  # type: ignore
  except (KeyError, ValueError):
    raise ValidationError('Invalid algorithm identifier {}'.format(alg))
  return alg


def parse_attestation_statement_x5c(att_stmt: dict) -> Sequence[bytes]:
  x5c = parse_dictionary_field('x5c', (list, tuple), att_stmt)

  for i, e in enumerate(x5c):
    if type(e) is not bytes:
      raise ValidationError('x5c[{}] must be a byte string'.format(i))
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
    return PackedX509AttestationStatement(alg=alg, sig=sig, x5c=x5c)

  if 'ecdaaKeyId' in att_stmt:
    supported_keys.add('ecdaaKeyId')
    check_unsupported_keys(supported_keys, att_stmt)
    ecdaa_key_id = parse_dictionary_field('ecdaaKeyId', bytes, att_stmt)
    return PackedECDAAAttestationStatement(alg=alg,
                                           sig=sig,
                                           ecdaa_key_id=ecdaa_key_id)

  check_unsupported_keys(supported_keys, att_stmt)
  return PackedAttestationStatement(alg=alg, sig=sig)


def parse_tpm_attestation_statement(att_stmt: dict) -> TPMAttestationStatement:
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
    return TPMX509AttestationStatement(alg=alg,
                                       sig=sig,
                                       ver=ver,
                                       cert_info=cert_info,
                                       pub_area=pub_area,
                                       x5c=x5c)

  if 'ecdaaKeyId' in att_stmt:
    supported_keys.add('ecdaaKeyId')
    check_unsupported_keys(supported_keys, att_stmt)
    ecdaa_key_id = parse_dictionary_field('ecdaaKeyId', bytes, att_stmt)
    return TPMECDAAAttestationStatement(alg=alg,
                                        sig=sig,
                                        ver=ver,
                                        cert_info=cert_info,
                                        pub_area=pub_area,
                                        ecdaa_key_id=ecdaa_key_id)

  check_unsupported_keys(supported_keys, att_stmt)
  return TPMAttestationStatement(alg=alg,
                                 sig=sig,
                                 ver=ver,
                                 cert_info=cert_info,
                                 pub_area=pub_area)


def parse_android_key_attestation_statement(
    att_stmt: dict) -> AndroidKeyAttestationStatement:
  supported_keys = {'alg', 'sig', 'x5c'}
  alg = parse_attestation_statement_alg(att_stmt)
  sig = parse_dictionary_field('sig', bytes, att_stmt)
  x5c = parse_attestation_statement_x5c(att_stmt)
  check_unsupported_keys(supported_keys, att_stmt)
  return AndroidKeyAttestationStatement(alg=alg, sig=sig, x5c=x5c)


def parse_android_safetynet_attestation_statement(
    att_stmt: dict) -> AndroidSafetyNetAttestationStatement:
  supported_keys = {'ver', 'response'}
  ver = parse_dictionary_field('ver', str, att_stmt)
  response = parse_dictionary_field('response', bytes, att_stmt)
  check_unsupported_keys(supported_keys, att_stmt)
  return AndroidSafetyNetAttestationStatement(ver=ver, response=response)


def parse_fido_u2f_attestation_statement(
    att_stmt: dict) -> FIDOU2FAttestationStatement:
  supported_keys = {'sig', 'x5c'}
  sig = parse_dictionary_field('sig', bytes, att_stmt)
  x5c = parse_attestation_statement_x5c(att_stmt)
  check_unsupported_keys(supported_keys, att_stmt)
  return FIDOU2FAttestationStatement(sig=sig, x5c=x5c)


def parse_none_attestation_statement(
    att_stmt: dict) -> NoneAttestationStatement:
  check_unsupported_keys(set(), att_stmt)
  return NoneAttestationStatement()


class AttestationStatementParser(Enum):
  PACKED = parse_packed_attestation_statement
  TPM = parse_tpm_attestation_statement
  ANDROID_KEY = parse_android_key_attestation_statement
  ANDROID_SAFETYNET = parse_android_safetynet_attestation_statement
  FIDO_U2F = parse_fido_u2f_attestation_statement
  NONE = parse_none_attestation_statement


def parse_client_data(
    client_data_JSON: bytes) -> Optional[CollectedClientData]:
  try:
    client_data_text = client_data_JSON.decode('utf-8')
    client_data = json.loads(client_data_text)
  except (UnicodeDecodeError, json.JSONDecodeError):
    raise DecodingError('Could not decode the client data JSON')

  if type(client_data) is not dict:
    raise ValidationError('Client data JSON must be a dictionary')

  type_ = client_data.get('type')
  challenge = client_data.get('challenge')
  origin = client_data.get('origin')

  if not all(isinstance(x, str) for x in (type_, challenge, origin)):
    raise ValidationError('Invalid client data parsed')

  token_binding_data = client_data.get('tokenBinding')
  token_binding = None
  if token_binding_data is not None:
    if type(token_binding_data) is not dict:
      raise ValidationError('Token Binding data must be a dictionary')

    token_binding_status = token_binding_data.get('status')
    token_binding_id = token_binding_data.get('id')

    if token_binding_status is None:
      raise ValidationError('Token Binding status must be present')

    try:
      token_binding_status_enum = TokenBindingStatus(token_binding_status)
    except ValueError:
      raise ValidationError(
          'Invalid Token Binding status {}'.format(token_binding_status))

    if token_binding_status_enum == TokenBindingStatus.PRESENT and (
        token_binding_id is None):
      raise TokenBindingError(
          'Token Binding must contain an id if status is {}'.format(
              TokenBindingStatus.PRESENT))

    token_binding = TokenBinding(status=token_binding_status_enum,
                                 id=token_binding_id)

  return CollectedClientData(type=type_,
                             challenge=challenge,
                             origin=origin,
                             token_binding=token_binding)


def parse_cose_key(
    credential_public_key: Union[dict, bytes]) -> CredentialPublicKey:
  if type(credential_public_key) is bytes:
    try:
      credential_public_key = cbor2.loads(credential_public_key)
    except cbor2.CBORDecodeError:
      raise ValidationError('Could not decode credential public key CBOR')

    if type(credential_public_key) is not dict:
      raise ValidationError('Credential public key CBOR must be a dictionary')
  try:
    cose_key_type = COSEKeyType(credential_public_key[1])  # type: ignore
  except (KeyError, ValueError):
    raise ValidationError('Invalid or missing COSE key type encountered')

  try:
    cpk_parser = getattr(CredentialPublicKeyParser,
                         cose_key_type.name)  # type: ignore
  except AttributeError:
    raise ValidationError('Parser not supported for key type {}'.format(
        cose_key_type.name))  # type: ignore

  return cpk_parser(credential_public_key)


def _read_bytes(bio: io.BytesIO, n: int) -> bytes:
  x = bio.read1(n)
  if len(x) != n:
    raise EOFError('Unexpected number of bytes read')
  return x


def parse_authenticator_data(
    auth_data: bytes,
    fmt: Optional[AttestationStatementFormatIdentifier] = None
) -> AuthenticatorData:
  if len(auth_data) < 37:
    raise ValidationError('Attestation auth data must be at least 35 bytes')

  rp_id_hash = auth_data[:32]
  flags = auth_data[32]
  signature_counter_bytes = auth_data[33:37]
  signature_counter_uint32, = struct.unpack('>I', signature_counter_bytes)

  attested_credential_data_included = bool(flags
                                           & AuthenticatorDataFlag.AT.value)
  extension_data_included = bool(flags & AuthenticatorDataFlag.ED.value)

  remaining_bytes_io = io.BytesIO(auth_data[37:])

  attested_credential_data = None
  aeci = None

  if attested_credential_data_included:
    try:
      aaguid = _read_bytes(remaining_bytes_io, 16)
      credential_id_length_bytes = _read_bytes(remaining_bytes_io, 2)
      credential_id_length_uint16, = struct.unpack('>H',
                                                   credential_id_length_bytes)
      credential_id = _read_bytes(remaining_bytes_io,
                                  credential_id_length_uint16)

      try:
        credential_public_key = cbor2.load(remaining_bytes_io)
      except cbor2.CBORDecodeError:
        raise DecodingError('Could not decode the credential public key CBOR')

      if type(credential_public_key) is not dict:
        raise ValidationError('Credential public key must be a dictionary')

      cpk = parse_cose_key(credential_public_key)
      validate(cpk)

      attested_credential_data = AttestedCredentialData(
          aaguid=aaguid,
          credential_id_length=credential_id_length_uint16,
          credential_id=credential_id,
          credential_public_key=cpk,
      )
    except EOFError:
      raise ValidationError(
          'Could not read the included attested credential data')

  if extension_data_included:
    try:
      try:
        extensions = cbor2.load(remaining_bytes_io)
      except cbor2.CBORDecodeError:
        raise DecodingError('Could not decode the extensions CBOR')

      if type(extensions) is not dict:
        raise ValidationError('Extension data CBOR must be a dictionary')

      aeci = parse_extensions(extensions)
    except EOFError:
      raise ValidationError('Could not read the included extension data')

  if remaining_bytes_io.read1(1) != b'':
    raise ValidationError(
        'The authenticator data has unexpected leftover bytes')

  return AuthenticatorData(
      rp_id_hash=rp_id_hash,
      flags=flags,
      sign_count=signature_counter_uint32,
      attested_credential_data=attested_credential_data,
      extensions=aeci,
  )


def parse_attestation(
    attestation_object: bytes) -> Tuple[AttestationObject, dict]:
  try:
    attestation_object_data = cbor2.loads(attestation_object)
  except cbor2.CBORDecodeError:
    raise DecodingError('Could not decode the attestation object CBOR')

  if type(attestation_object_data) is not dict:
    raise ValidationError('Attestation object CBOR must be a dictionary')

  try:
    auth_data = attestation_object_data['authData']
    fmt = attestation_object_data['fmt']
    att_stmt = attestation_object_data['attStmt']

    if type(fmt) is not str:
      raise ValidationError('fmt must be a text string')

    try:
      asfi = AttestationStatementFormatIdentifier(fmt)
    except ValueError:
      raise ValidationError('Invalid attestation statement format identifier')

    if type(auth_data) is not bytes:
      raise ValidationError('Attestation auth data should be bytes')

    authenticator_data = parse_authenticator_data(auth_data, asfi)
  except KeyError as e:
    raise ValidationError('Missing key in attestation ({})'.format(str(e)))

  if type(att_stmt) is not dict:
    raise ValidationError('attStmt must be a dictionary')

  try:
    as_parser = getattr(AttestationStatementParser, asfi.name)
    attestation_statement = as_parser(att_stmt)
  except AttributeError:
    raise ValidationError('Unsupported attestation statement {}'.format(
        asfi.name))

  return AttestationObject(
      auth_data=authenticator_data,
      fmt=asfi,
      att_stmt=attestation_statement,
  ), attestation_object_data
