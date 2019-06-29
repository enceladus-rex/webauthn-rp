from typing import Optional

from webauthn_rp.types import *
from webauthn_rp.constants import *
from webauthn_rp.converters import (
  jsonify,
  cryptography_ec2_public_key,
  cryptography_okp_public_key,
  cose_key_from_ec2,
  cose_key_from_okp,
)

from webauthn_rp.parsers import (
  parse_cose_key,
)

from base64 import b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import (
  generate_private_key,
  EllipticCurvePrivateKey,
  EllipticCurvePrivateKey,
  SECP256R1,
  SECP384R1,
  SECP521R1,
)

from pprint import pprint

from .common import assert_objects_equal


def base64s(b: bytes) -> str:
  return b64encode(b).decode('utf8')


def generate_ec2_private_key(crv: EC2KeyType.Value) -> EllipticCurvePrivateKey:
  key_to_curve = {
    EC2KeyType.Value.P_256: SECP256R1,
    EC2KeyType.Value.P_384: SECP384R1,
    EC2KeyType.Value.P_521: SECP521R1,
  }

  curve = key_to_curve[crv]

  return generate_private_key(
    curve(),
    default_backend()
  )


def generate_ec2_public_key(crv: EC2KeyType.Value) -> EllipticCurvePublicKey:
  return generate_ec2_private_key(crv).public_key()


def generate_ec2_credential_public_key(
    crv: EC2KeyType.Value, 
    alg: Optional[COSEAlgorithmIdentifier.Value] = None) -> EC2CredentialPublicKey:
  key_to_klen = {
    EC2KeyType.Value.P_256: EC2_P_256_NUMBER_LENGTH,
    EC2KeyType.Value.P_384: EC2_P_384_NUMBER_LENGTH,
    EC2KeyType.Value.P_521: EC2_P_521_NUMBER_LENGTH,
  }

  klen = key_to_klen[crv]

  random_public_numbers = generate_ec2_public_key(crv).public_numbers()
  return EC2CredentialPublicKey(
    kty=COSEKeyType.Value.EC2,
    crv=crv,
    alg=alg or COSEAlgorithmIdentifier.Value.ES256,
    x=random_public_numbers.x.to_bytes(klen, 'big'),
    y=random_public_numbers.y.to_bytes(klen, 'big'),
  )


def generate_okp_credential_public_key(
  crv: OKPKeyType.Value,
  alg: Optional[COSEAlgorithmIdentifier.Value] = None):
  private_key_generator = {
    OKPKeyType.Value.ED25519: Ed25519PrivateKey,
    OKPKeyType.Value.ED448: Ed448PrivateKey,
  }

  private_key = private_key_generator[crv].generate()
  public_number = private_key.public_key().public_bytes(
    Encoding.Raw, PublicFormat.Raw
  )

  return OKPCredentialPublicKey(
    kty=COSEKeyType.Value.OKP,
    crv=crv,
    alg=alg or COSEAlgorithmIdentifier.Value.ES256,
    x=public_number,
  )


def test_jsonify_credential_creation_options():
  rp_name = 'Example Test'
  rp_id = 'example.test'
  user_name = 'example'
  user_id = b'random'
  user_display_name = 'dp'
  challenge = b'secure-random'
  pub_key_cred_params = [
    PublicKeyCredentialParameters(
      type=PublicKeyCredentialType.PUBLIC_KEY,
      alg=COSEAlgorithmIdentifier.Value.ES256
    ),
    PublicKeyCredentialParameters(
      type=PublicKeyCredentialType.PUBLIC_KEY,
      alg=COSEAlgorithmIdentifier.Value.ES384,
    )
  ]
  timeout = 30500
  authenticator_selection = AuthenticatorSelectionCriteria(
    authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
    require_resident_key=False,
    user_verification=UserVerificationRequirement.REQUIRED,
  )
  extensions= AuthenticationExtensionsClientInputs(
    appid='appid',
    tx_auth_simple='tx_auth_simple',
    tx_auth_generic=TxAuthGenericArg(
      content_type='text/plain',
      content=b'sample text'),
    authn_sel=[
      b'auth1',
      b'auth2',
      b'auth3',
    ],
    exts=True,
    uvi=False,
    loc=True,
    uvm=False,
    biometric_perf_bounds=AuthenticatorBiometricPerfBounds(
      FAR=0.4,
      FRR=0.5,
    )
  )
  attestation_conveyance = AttestationConveyancePreference.DIRECT
  exclude_credentials = [
    PublicKeyCredentialDescriptor(
      type=PublicKeyCredentialType.PUBLIC_KEY,
      id=b'excluded-credential',
      transports=[AuthenticatorTransport.BLE, AuthenticatorTransport.NFC],
    )
  ]

  cco = CredentialCreationOptions(
    public_key=PublicKeyCredentialCreationOptions(
      rp=PublicKeyCredentialRpEntity(
        name=rp_name,
        id=rp_id),
      user=PublicKeyCredentialUserEntity(
        name=user_name,
        id=user_id,
        display_name=user_display_name),
      challenge=challenge,
      pub_key_cred_params=pub_key_cred_params,
      timeout=timeout,
      authenticator_selection=authenticator_selection,
      extensions=extensions,
      attestation=attestation_conveyance,
      exclude_credentials=exclude_credentials,
    )
  )

  cco_json = jsonify(cco)

  expected_cco_json = {
    'publicKey': {
      'rp': {
        'name': rp_name,
        'id': rp_id,
      },
      'user': {
        'name': user_name,
        'id': base64s(user_id),
        'displayName': user_display_name,
      },
      'challenge': base64s(challenge),
      'pubKeyCredParams': [{
        'type': x.type.value,
        'alg': x.alg.value,
      } for x in pub_key_cred_params],
      'timeout': timeout,
      'authenticatorSelection': {
        'authenticatorAttachment': (
          authenticator_selection.authenticator_attachment.value),
        'requireResidentKey': (
          authenticator_selection.require_resident_key),
        'userVerification': (
          authenticator_selection.user_verification.value),
      },
      'extensions': {
        'appid': extensions.appid,
        'txAuthSimple': extensions.tx_auth_simple,
        'txAuthGeneric': {
          'contentType': extensions.tx_auth_generic.content_type,
          'content': base64s(extensions.tx_auth_generic.content),
        },
        'authnSel': [base64s(x) for x in extensions.authn_sel],
        'exts': extensions.exts,
        'uvi': extensions.uvi,
        'loc': extensions.loc,
        'uvm': extensions.uvm,
        'biometricPerfBounds': {
          'FAR': extensions.biometric_perf_bounds.FAR,
          'FRR': extensions.biometric_perf_bounds.FRR,
        },
      },
      'attestation': attestation_conveyance.value,
      'excludeCredentials': [{
        'type': x.type.value,
        'id': base64s(x.id),
        'transports': [y.value for y in x.transports]
      } for x in exclude_credentials]
    }
  }

  assert cco_json == expected_cco_json


def test_jsonify_credential_request_options():
  rp_id = 'example.py'
  challenge = b'request-challenge'
  timeout = 3600
  user_verification = UserVerificationRequirement.PREFERRED
  extensions= AuthenticationExtensionsClientInputs(
    appid='appid',
    tx_auth_simple='tx_auth_simple',
    tx_auth_generic=TxAuthGenericArg(
      content_type='text/plain',
      content=b'sample text'),
    authn_sel=[
      b'auth1',
      b'auth2',
      b'auth3',
    ],
    exts=True,
    uvi=False,
    loc=True,
    uvm=False,
    biometric_perf_bounds=AuthenticatorBiometricPerfBounds(
      FAR=0.4,
      FRR=0.5,
    )
  )
  allow_credentials = [
    PublicKeyCredentialDescriptor(
      type=PublicKeyCredentialType.PUBLIC_KEY,
      id=b'excluded-credential',
      transports=[AuthenticatorTransport.BLE, AuthenticatorTransport.NFC],
    )
  ]
  mediation = CredentialMediationRequirement.REQUIRED

  cro = CredentialRequestOptions(
    mediation=mediation,
    public_key=PublicKeyCredentialRequestOptions(
      rp_id=rp_id,
      challenge=challenge,
      timeout=timeout,
      extensions=extensions,
      user_verification=user_verification,
      allow_credentials=allow_credentials
    )
  )

  cro_json = jsonify(cro)

  expected_cro_json = {
    'mediation': mediation.value,
    'publicKey': {
      'rpId': rp_id,
      'challenge': base64s(challenge),
      'timeout': timeout,
      'extensions': {
        'appid': extensions.appid,
        'txAuthSimple': extensions.tx_auth_simple,
        'txAuthGeneric': {
          'contentType': extensions.tx_auth_generic.content_type,
          'content': base64s(extensions.tx_auth_generic.content),
        },
        'authnSel': [base64s(x) for x in extensions.authn_sel],
        'exts': extensions.exts,
        'uvi': extensions.uvi,
        'loc': extensions.loc,
        'uvm': extensions.uvm,
        'biometricPerfBounds': {
          'FAR': extensions.biometric_perf_bounds.FAR,
          'FRR': extensions.biometric_perf_bounds.FRR,
        },
      },
      'userVerification': user_verification.value,
      'allowCredentials': [{
        'type': x.type.value,
        'id': base64s(x.id),
        'transports': [y.value for y in x.transports]
      } for x in allow_credentials]
    }
  }

  assert cro_json == expected_cro_json


def test_cryptography_ec2_public_key():
  key_data = (
    (EC2KeyType.Value.P_256, 32),
    (EC2KeyType.Value.P_384, 48),
    (EC2KeyType.Value.P_521, 66),
  )

  for crv, klen in key_data:
    random_public_key = generate_ec2_public_key(crv)
    random_public_numbers = random_public_key.public_numbers()
    ec2_key = EC2CredentialPublicKey(
      kty=COSEKeyType.Value.EC2,
      crv=crv,
      x=random_public_numbers.x.to_bytes(klen, 'big'),
      y=random_public_numbers.y.to_bytes(klen, 'big'),
    )

    converted_public_key = cryptography_ec2_public_key(ec2_key)
    converted_public_numbers = converted_public_key.public_numbers()
    
    assert converted_public_numbers.x == random_public_numbers.x
    assert converted_public_numbers.y == random_public_numbers.y


def test_cryptography_okp_public_key_ed25519():
  ed25519_private_key = Ed25519PrivateKey.generate()
  ed25519_public_number = ed25519_private_key.public_key().public_bytes(
    Encoding.Raw, PublicFormat.Raw
  )

  okp_key = OKPCredentialPublicKey(
    kty=COSEKeyType.Value.OKP,
    crv=OKPKeyType.Value.ED25519,
    x=ed25519_public_number,
  )

  converted_public_key = cryptography_okp_public_key(okp_key)
  converted_public_number = converted_public_key.public_bytes(
    Encoding.Raw, PublicFormat.Raw
  )

  assert ed25519_public_number == converted_public_number


def test_cryptography_okp_public_key_ed448():
  ed448_private_key = Ed448PrivateKey.generate()
  ed448_public_number = ed448_private_key.public_key().public_bytes(
    Encoding.Raw, PublicFormat.Raw
  )

  okp_key = OKPCredentialPublicKey(
    kty=COSEKeyType.Value.OKP,
    crv=OKPKeyType.Value.ED448,
    x=ed448_public_number,
  )

  converted_public_key = cryptography_okp_public_key(okp_key)
  converted_public_number = converted_public_key.public_bytes(
    Encoding.Raw, PublicFormat.Raw
  )

  assert ed448_public_number == converted_public_number


def test_cose_key_from_ec2():
  crvs = (
    EC2KeyType.Value.P_256,
    EC2KeyType.Value.P_384,
    EC2KeyType.Value.P_521,
  )

  for crv in crvs:
    ec2_key = generate_ec2_credential_public_key(crv)
    cose_key = cose_key_from_ec2(ec2_key)
    parsed_ec2_key = parse_cose_key(cose_key)
    assert_objects_equal(ec2_key, parsed_ec2_key)


def test_cose_key_from_okp():
  crvs = (
    OKPKeyType.Value.ED25519,
    OKPKeyType.Value.ED448,
  )

  for crv in crvs:
    okp_key = generate_okp_credential_public_key(crv)
    cose_key = cose_key_from_okp(okp_key)
    parsed_okp_key = parse_cose_key(cose_key)
    assert_objects_equal(okp_key, parsed_okp_key)