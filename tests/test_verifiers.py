import pytest
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from webauthn_rp.errors import VerificationError
from webauthn_rp.types import (COSEAlgorithmIdentifier, COSEKeyType,
                               EC2CredentialPublicKey, EC2Curve,
                               OKPCredentialPublicKey, OKPCurve)
from webauthn_rp.utils import curve_coordinate_byte_length, ec2_hash_algorithm
from webauthn_rp.verifiers import verify

from .common import (generate_ec2_private_key, generate_okp_private_key,
                     generate_pseudorandom_bytes, single_byte_errors)


@pytest.mark.parametrize('crv, alg', [
    (EC2Curve.Value.P_256, COSEAlgorithmIdentifier.Value.ES256),
    (EC2Curve.Value.P_384, COSEAlgorithmIdentifier.Value.ES384),
    (EC2Curve.Value.P_521, COSEAlgorithmIdentifier.Value.ES512),
])
@pytest.mark.parametrize('data', [
    generate_pseudorandom_bytes(100, 1),
    generate_pseudorandom_bytes(100, 2),
    generate_pseudorandom_bytes(100, 3),
    generate_pseudorandom_bytes(100, 4),
    generate_pseudorandom_bytes(100, 5),
])
def test_verify_ec2(crv: EC2Curve.Value, alg: COSEAlgorithmIdentifier.Value,
                    data: bytes):
    private_key = generate_ec2_private_key(crv)

    clen = curve_coordinate_byte_length(crv)
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    ec2_public_key = EC2CredentialPublicKey(
        kty=COSEKeyType.Value.EC2,
        crv=crv,
        alg=alg,
        x=public_numbers.x.to_bytes(clen, 'big'),
        y=public_numbers.y.to_bytes(clen, 'big'),
    )

    signature_algorithm = ECDSA(ec2_hash_algorithm(alg))
    signature = private_key.sign(data, signature_algorithm)

    verify(ec2_public_key, signature, data)

    errors = single_byte_errors(signature)
    for error in errors:
        with pytest.raises(VerificationError):
            verify(ec2_public_key, error, data)


@pytest.mark.parametrize('crv, alg', [
    (OKPCurve.Value.ED25519, COSEAlgorithmIdentifier.Value.EDDSA),
    (OKPCurve.Value.ED448, COSEAlgorithmIdentifier.Value.EDDSA),
])
@pytest.mark.parametrize('data', [
    generate_pseudorandom_bytes(100, 1),
    generate_pseudorandom_bytes(100, 2),
    generate_pseudorandom_bytes(100, 3),
    generate_pseudorandom_bytes(100, 4),
    generate_pseudorandom_bytes(100, 5),
])
def test_verify_okp(crv: OKPCurve.Value, alg: COSEAlgorithmIdentifier.Value,
                    data: bytes):
    private_key = generate_okp_private_key(crv)

    clen = curve_coordinate_byte_length(crv)
    public_key = private_key.public_key()

    ec2_public_key = OKPCredentialPublicKey(
        kty=COSEKeyType.Value.OKP,
        crv=crv,
        alg=alg,
        x=public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )

    signature = private_key.sign(data)

    verify(ec2_public_key, signature, data)

    errors = single_byte_errors(signature)
    for error in errors:
        with pytest.raises(VerificationError):
            verify(ec2_public_key, error, data)
