import datetime
import hashlib
from typing import List, Optional, Tuple
from unittest.mock import MagicMock

import cryptography
import cryptography.x509
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, SECP384R1, EllipticCurve, EllipticCurvePublicNumbers,
    generate_private_key)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.extensions import Extension, UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

import webauthn_rp.types
from webauthn_rp.asn1 import AuthorizationList, KeyDescription
from webauthn_rp.attesters import attest
from webauthn_rp.constants import (ED25519_COORDINATE_BYTE_LENGTH,
                                   KM_ORIGIN_GENERATED, KM_PURPOSE_SIGN,
                                   P_256_COORDINATE_BYTE_LENGTH)
from webauthn_rp.errors import AttestationError, VerificationError
from webauthn_rp.types import (
    AndroidKeyAttestationStatement, AttestationObject,
    AttestationStatementFormatIdentifier, AttestationType,
    AttestedCredentialData, AuthenticatorData, COSEAlgorithmIdentifier,
    COSEKeyType, EC2CredentialPublicKey, EC2Curve, EC2PrivateKey, EC2PublicKey,
    FIDOU2FAttestationStatement, NoneAttestationStatement,
    OKPCredentialPublicKey, OKPCurve, PrivateKey, PublicKey)

from .common import (TEST_AAGUID, TEST_CREDENTIAL_ID,
                     TEST_CREDENTIAL_ID_LENGTH, TEST_RP_ID, TEST_RP_ID_HASH,
                     generate_android_extensions,
                     generate_elliptic_curve_x509_certificate,
                     generate_elliptic_curve_x509_certificate_android,
                     generate_elliptic_curve_x509_certificate_android_raw,
                     generate_signature, generate_x509_certificate,
                     single_byte_errors)


def test_attest_fido_u2f():
    client_data_hash = b'client-data-hash'

    certificate, private_key, public_key = generate_elliptic_curve_x509_certificate(
        SECP256R1())
    public_numbers = private_key.private_numbers().public_numbers

    x = public_numbers.x.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')
    y = public_numbers.y.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')
    public_key_u2f = b'\x04' + x + y
    verification_data = b''.join([
        b'\x00',
        TEST_RP_ID_HASH,
        client_data_hash,
        TEST_CREDENTIAL_ID,
        public_key_u2f,
    ])

    credential_public_key = EC2CredentialPublicKey(
        x=x,
        y=y,
        kty=COSEKeyType.Name.EC2,
        crv=EC2Curve.Name.P_256,
    )

    attested_credential_data = AttestedCredentialData(
        aaguid=TEST_AAGUID,
        credential_id_length=TEST_CREDENTIAL_ID_LENGTH,
        credential_id=TEST_CREDENTIAL_ID,
        credential_public_key=credential_public_key,
    )

    signature = generate_signature(private_key, verification_data)

    auth_data = b'auth-data'
    invalid_att_stmt = FIDOU2FAttestationStatement(sig=b'', x5c=[b'', b''])

    att_obj = AttestationObject(
        auth_data=AuthenticatorData(
            rp_id_hash=TEST_RP_ID_HASH,
            flags=0,
            sign_count=0,
            attested_credential_data=attested_credential_data,
            extensions=None),
        fmt=AttestationStatementFormatIdentifier.FIDO_U2F,
        att_stmt=invalid_att_stmt)

    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

    der_certificate = certificate.public_bytes(Encoding.DER)
    valid_att_stmt = FIDOU2FAttestationStatement(sig=signature,
                                                 x5c=[der_certificate])

    att_obj.att_stmt = valid_att_stmt
    assert attest(valid_att_stmt, att_obj, auth_data,
                  client_data_hash) == (AttestationType.BASIC, [certificate])

    unverified_att_stmt = FIDOU2FAttestationStatement(sig=b'bad-signature',
                                                      x5c=[der_certificate])
    att_obj.att_stmt = unverified_att_stmt
    with pytest.raises(AttestationError):
        attest(unverified_att_stmt, att_obj, auth_data, client_data_hash)

    invalid_pk = rsa.generate_private_key(931, 4096, default_backend())
    invalid_pubk = invalid_pk.public_key()
    invalid_certificate = generate_x509_certificate(invalid_pubk, invalid_pk,
                                                    hashes.SHA256())

    invalid_signature = invalid_pk.sign(verification_data, PKCS1v15(),
                                        hashes.SHA256())
    invalid_der_certificate = invalid_certificate.public_bytes(Encoding.DER)
    invalid_att_stmt = FIDOU2FAttestationStatement(
        sig=invalid_signature, x5c=[invalid_der_certificate])

    att_obj.att_stmt = invalid_att_stmt
    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

    invalid_certificate, invalid_pk, invalid_pubk = generate_elliptic_curve_x509_certificate(
        SECP384R1())
    invalid_signature = generate_signature(invalid_pk, verification_data)
    invalid_der_certificate = invalid_certificate.public_bytes(Encoding.DER)
    invalid_att_stmt = FIDOU2FAttestationStatement(
        sig=invalid_signature, x5c=[invalid_der_certificate])

    att_obj.att_stmt = invalid_att_stmt
    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)


def test_attest_android_key():
    client_data_hash = b'client-data-hash'
    auth_data = b'auth-data'

    certificate, private_key, public_key = generate_elliptic_curve_x509_certificate_android(
        SECP256R1(), client_data_hash)
    public_numbers = private_key.private_numbers().public_numbers

    x = public_numbers.x.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')
    y = public_numbers.y.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')
    public_key_android = b'\x04' + x + y
    verification_data = auth_data + client_data_hash

    credential_public_key = EC2CredentialPublicKey(
        x=x,
        y=y,
        kty=COSEKeyType.Name.EC2,
        crv=EC2Curve.Name.P_256,
    )

    attested_credential_data = AttestedCredentialData(
        aaguid=TEST_AAGUID,
        credential_id_length=TEST_CREDENTIAL_ID_LENGTH,
        credential_id=TEST_CREDENTIAL_ID,
        credential_public_key=credential_public_key,
    )

    signature = generate_signature(private_key, verification_data)

    invalid_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256, sig=b'', x5c=[])

    att_obj = AttestationObject(
        auth_data=AuthenticatorData(
            rp_id_hash=TEST_RP_ID_HASH,
            flags=0,
            sign_count=0,
            attested_credential_data=attested_credential_data,
            extensions=None),
        fmt=AttestationStatementFormatIdentifier.FIDO_U2F,
        att_stmt=invalid_att_stmt)

    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

    der_certificate = certificate.public_bytes(Encoding.DER)
    valid_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=signature,
        x5c=[der_certificate])

    att_obj.att_stmt = valid_att_stmt
    assert attest(valid_att_stmt, att_obj, auth_data,
                  client_data_hash) == (AttestationType.BASIC, [certificate])

    unverified_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=b'bad-signature',
        x5c=[der_certificate])
    att_obj.att_stmt = unverified_att_stmt
    with pytest.raises(AttestationError):
        attest(unverified_att_stmt, att_obj, auth_data, client_data_hash)

    invalid_pk = rsa.generate_private_key(931, 4096, default_backend())
    invalid_pubk = invalid_pk.public_key()
    invalid_certificate = generate_x509_certificate(invalid_pubk, invalid_pk,
                                                    hashes.SHA256())

    invalid_signature = invalid_pk.sign(verification_data, PKCS1v15(),
                                        hashes.SHA256())
    invalid_der_certificate = invalid_certificate.public_bytes(Encoding.DER)

    invalid_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=invalid_signature,
        x5c=[invalid_der_certificate])
    att_obj.att_stmt = invalid_att_stmt
    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

    att_obj.att_stmt = valid_att_stmt

    while True:
        random_pk = generate_private_key(SECP256R1(), default_backend())
        random_public_numbers = random_pk.private_numbers().public_numbers
        rx = random_public_numbers.x.to_bytes(P_256_COORDINATE_BYTE_LENGTH,
                                              'big')
        ry = random_public_numbers.y.to_bytes(P_256_COORDINATE_BYTE_LENGTH,
                                              'big')

        if rx != x or ry != y:
            break

    att_obj.auth_data.attested_credential_data.credential_public_key = (
        EC2CredentialPublicKey(
            x=rx,
            y=ry,
            kty=COSEKeyType.Name.EC2,
            crv=EC2Curve.Name.P_256,
        ))

    with pytest.raises(AttestationError):
        attest(valid_att_stmt, att_obj, auth_data, client_data_hash)

    invalid_certificate, invalid_pk, invalid_pubk = generate_elliptic_curve_x509_certificate(
        SECP256R1())
    invalid_public_numbers = invalid_pk.private_numbers().public_numbers

    x = invalid_public_numbers.x.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')
    y = invalid_public_numbers.y.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')

    att_obj.auth_data.attested_credential_data.credential_public_key = (
        EC2CredentialPublicKey(
            x=x,
            y=y,
            kty=COSEKeyType.Name.EC2,
            crv=EC2Curve.Name.P_256,
        ))

    invalid_signature = generate_signature(invalid_pk, verification_data)
    invalid_der_certificate = invalid_certificate.public_bytes(Encoding.DER)
    invalid_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=invalid_signature,
        x5c=[invalid_der_certificate])

    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

    invalid_certificate, invalid_pk, invalid_pubk = generate_elliptic_curve_x509_certificate_android_raw(
        SECP256R1(), b'invalid')
    invalid_public_numbers = invalid_pk.private_numbers().public_numbers

    x = invalid_public_numbers.x.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')
    y = invalid_public_numbers.y.to_bytes(P_256_COORDINATE_BYTE_LENGTH, 'big')

    att_obj.auth_data.attested_credential_data.credential_public_key = (
        EC2CredentialPublicKey(
            x=x,
            y=y,
            kty=COSEKeyType.Name.EC2,
            crv=EC2Curve.Name.P_256,
        ))

    invalid_signature = generate_signature(invalid_pk, verification_data)
    invalid_der_certificate = invalid_certificate.public_bytes(Encoding.DER)
    invalid_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=invalid_signature,
        x5c=[invalid_der_certificate])

    with pytest.raises(AttestationError):
        attest(invalid_att_stmt, att_obj, auth_data, client_data_hash)

    okp_pk = Ed25519PrivateKey.generate()
    okp_pubk = okp_pk.public_key()

    okp_certificate = generate_x509_certificate(
        okp_pubk, okp_pk, None, generate_android_extensions(client_data_hash))

    x = okp_pubk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    att_obj.auth_data.attested_credential_data.credential_public_key = (
        OKPCredentialPublicKey(
            x=x,
            kty=COSEKeyType.Name.OKP,
            crv=OKPCurve.Name.ED25519,
        ))

    okp_signature = okp_pk.sign(verification_data)
    okp_der_certificate = okp_certificate.public_bytes(Encoding.DER)
    okp_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=okp_signature,
        x5c=[okp_der_certificate])

    assert attest(okp_att_stmt, att_obj, auth_data,
                  client_data_hash) == (AttestationType.BASIC,
                                        [okp_certificate])

    okp_pk = Ed448PrivateKey.generate()
    okp_pubk = okp_pk.public_key()

    okp_certificate = generate_x509_certificate(
        okp_pubk, okp_pk, None, generate_android_extensions(client_data_hash))

    x = okp_pubk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    att_obj.auth_data.attested_credential_data.credential_public_key = (
        OKPCredentialPublicKey(
            x=x,
            kty=COSEKeyType.Name.OKP,
            crv=OKPCurve.Name.ED448,
        ))

    okp_signature = okp_pk.sign(verification_data)
    okp_der_certificate = okp_certificate.public_bytes(Encoding.DER)
    okp_att_stmt = AndroidKeyAttestationStatement(
        alg=COSEAlgorithmIdentifier.Name.ES256,
        sig=okp_signature,
        x5c=[okp_der_certificate])

    assert attest(okp_att_stmt, att_obj, auth_data,
                  client_data_hash) == (AttestationType.BASIC,
                                        [okp_certificate])


def test_attest_none(monkeypatch):
    assert attest(NoneAttestationStatement(), MagicMock(), b'',
                  b'') == (AttestationType.NONE, None)
