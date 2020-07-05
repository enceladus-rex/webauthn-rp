from base64 import b64encode
from pprint import pprint
from typing import Optional

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, SECP384R1, SECP521R1, EllipticCurvePrivateKey,
    generate_private_key)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from webauthn_rp.constants import *
from webauthn_rp.converters import (_build_base_cose_dictionary,
                                    cose_ec2_public_key, cose_okp_public_key,
                                    cryptography_ec2_public_key,
                                    cryptography_okp_public_key, jsonify)
from webauthn_rp.errors import JSONConversionError, PublicKeyConversionError
from webauthn_rp.parsers import parse_cose_key
from webauthn_rp.types import *

from .common import (assert_objects_equal, base64s,
                     generate_ec2_credential_public_key,
                     generate_ec2_private_key, generate_ec2_public_key,
                     generate_okp_credential_public_key, generate_private_key)


@pytest.mark.parametrize('data, expected', [
    (None, None),
])
def test_jsonify_success(data, expected):
    jsonify(data) == expected


@pytest.mark.parametrize('data', [
    {
        1: 'data',
    },
])
def test_jsonify_errors(data):
    with pytest.raises(JSONConversionError):
        jsonify(data)


def test_jsonify_credential_creation_options():
    rp_name = 'Example Test'
    rp_id = 'example.test'
    user_name = 'example'
    user_id = b'random'
    user_display_name = 'dp'
    challenge = b'secure-random'
    pub_key_cred_params = [
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,
                                      alg=COSEAlgorithmIdentifier.Value.ES256),
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
    extensions = AuthenticationExtensionsClientInputs(
        appid='appid',
        tx_auth_simple='tx_auth_simple',
        tx_auth_generic=TxAuthGenericArg(content_type='text/plain',
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
        ))
    attestation_conveyance = AttestationConveyancePreference.DIRECT
    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=b'excluded-credential',
            transports=[
                AuthenticatorTransport.BLE, AuthenticatorTransport.NFC
            ],
        )
    ]

    cco = CredentialCreationOptions(
        public_key=PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(name=rp_name, id=rp_id),
            user=PublicKeyCredentialUserEntity(
                name=user_name, id=user_id, display_name=user_display_name),
            challenge=challenge,
            pub_key_cred_params=pub_key_cred_params,
            timeout=timeout,
            authenticator_selection=authenticator_selection,
            extensions=extensions,
            attestation=attestation_conveyance,
            exclude_credentials=exclude_credentials,
        ))

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
            'challenge':
            base64s(challenge),
            'pubKeyCredParams': [{
                'type': x.type.value,
                'alg': x.alg.value,
            } for x in pub_key_cred_params],
            'timeout':
            timeout,
            'authenticatorSelection': {
                'authenticatorAttachment':
                (authenticator_selection.authenticator_attachment.value),
                'requireResidentKey':
                (authenticator_selection.require_resident_key),
                'userVerification':
                (authenticator_selection.user_verification.value),
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
            'attestation':
            attestation_conveyance.value,
            'excludeCredentials': [{
                'type':
                x.type.value,
                'id':
                base64s(x.id),
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
    extensions = AuthenticationExtensionsClientInputs(
        appid='appid',
        tx_auth_simple='tx_auth_simple',
        tx_auth_generic=TxAuthGenericArg(content_type='text/plain',
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
        ))
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=b'excluded-credential',
            transports=[
                AuthenticatorTransport.BLE, AuthenticatorTransport.NFC
            ],
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
            allow_credentials=allow_credentials))

    cro_json = jsonify(cro)

    expected_cro_json = {
        'mediation': mediation.value,
        'publicKey': {
            'rpId':
            rp_id,
            'challenge':
            base64s(challenge),
            'timeout':
            timeout,
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
            'userVerification':
            user_verification.value,
            'allowCredentials': [{
                'type': x.type.value,
                'id': base64s(x.id),
                'transports': [y.value for y in x.transports]
            } for x in allow_credentials]
        }
    }

    assert cro_json == expected_cro_json


@pytest.mark.parametrize('data, expected',
                         [(CredentialPublicKey(
                             kty=COSEKeyType.Value.EC2,
                             kid=b'kid',
                             alg=COSEAlgorithmIdentifier.Value.ES256,
                             key_ops=[COSEKeyOperation.Value.VERIFY],
                             base_IV=b'base-IV',
                         ), {
                             1: COSEKeyType.Value.EC2.value,
                             2: b'kid',
                             3: COSEAlgorithmIdentifier.Value.ES256.value,
                             4: [COSEKeyOperation.Value.VERIFY.value],
                             5: b'base-IV'
                         })])
def test__build_base_cose_dictionary_success(data, expected):
    _build_base_cose_dictionary(data) == expected


def test_cryptography_ec2_public_key():
    key_data = (
        (EC2Curve.Value.P_256, P_256_COORDINATE_BYTE_LENGTH),
        (EC2Curve.Value.P_384, P_384_COORDINATE_BYTE_LENGTH),
        (EC2Curve.Value.P_521, P_521_COORDINATE_BYTE_LENGTH),
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
        Encoding.Raw, PublicFormat.Raw)

    okp_key = OKPCredentialPublicKey(
        kty=COSEKeyType.Value.OKP,
        crv=OKPCurve.Value.ED25519,
        x=ed25519_public_number,
    )

    converted_public_key = cryptography_okp_public_key(okp_key)
    converted_public_number = converted_public_key.public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    assert ed25519_public_number == converted_public_number


def test_cryptography_okp_public_key_ed448():
    ed448_private_key = Ed448PrivateKey.generate()
    ed448_public_number = ed448_private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    okp_key = OKPCredentialPublicKey(
        kty=COSEKeyType.Value.OKP,
        crv=OKPCurve.Value.ED448,
        x=ed448_public_number,
    )

    converted_public_key = cryptography_okp_public_key(okp_key)
    converted_public_number = converted_public_key.public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    assert ed448_public_number == converted_public_number


def test_cose_ec2_public_key():
    for crv in EC2Curve.Value:
        ec2_key = generate_ec2_credential_public_key(crv)
        cose_key = cose_ec2_public_key(ec2_key)
        parsed_ec2_key = parse_cose_key(cose_key)
        assert_objects_equal(ec2_key, parsed_ec2_key)


def test_cose_okp_public_key():
    for crv in OKPCurve.Value:
        okp_key = generate_okp_credential_public_key(crv)
        cose_key = cose_okp_public_key(okp_key)
        parsed_okp_key = parse_cose_key(cose_key)
        assert_objects_equal(okp_key, parsed_okp_key)
