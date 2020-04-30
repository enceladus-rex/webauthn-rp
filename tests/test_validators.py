import itertools
from typing import Optional, Union

import pytest

from webauthn_rp.errors import ValidationError
from webauthn_rp.types import (COSEAlgorithmIdentifier, COSEKeyOperation,
                               COSEKeyType, CredentialPublicKey,
                               EC2CredentialPublicKey, EC2Curve,
                               OKPCredentialPublicKey, OKPCurve)
from webauthn_rp.validators import validate

from .common import (generate_ec2_credential_public_key,
                     generate_okp_credential_public_key)


@pytest.mark.parametrize('credential_public_key', [
    generate_ec2_credential_public_key(x, y) for x, y in itertools.product(
        (EC2Curve.Value.P_256, EC2Curve.Value.P_384,
         EC2Curve.Value.P_521), (COSEAlgorithmIdentifier.Value.ES256,
                                 COSEAlgorithmIdentifier.Value.ES384,
                                 COSEAlgorithmIdentifier.Value.ES512))
] + [
    generate_okp_credential_public_key(x, y)
    for x, y in itertools.product((OKPCurve.Value.ED25519, OKPCurve.Value.ED448
                                   ), (COSEAlgorithmIdentifier.Value.EDDSA, ))
])
def test_validate_success(credential_public_key):
  validate(credential_public_key)


def replace_curve(
    credential_public_key: Union[EC2CredentialPublicKey,
                                 OKPCredentialPublicKey],
    crv: Union[EC2Curve.Value, OKPCurve.Value]
) -> Union[EC2CredentialPublicKey, OKPCredentialPublicKey]:
  credential_public_key.crv = crv
  return credential_public_key


@pytest.mark.parametrize('credential_public_key', [
    replace_curve(generate_ec2_credential_public_key(x, y), z)
    for x, y, z in itertools.product(
        (EC2Curve.Value.P_256, EC2Curve.Value.P_384, EC2Curve.Value.P_521),
        (COSEAlgorithmIdentifier.Value.ES256,
         COSEAlgorithmIdentifier.Value.ES384,
         COSEAlgorithmIdentifier.Value.ES512,
         COSEAlgorithmIdentifier.Value.EDDSA), (OKPCurve.Value.ED25519,
                                                OKPCurve.Value.ED448))
] + [
    replace_curve(generate_okp_credential_public_key(x, y), z)
    for x, y, z in itertools.product(
        (OKPCurve.Value.ED25519,
         OKPCurve.Value.ED448), (COSEAlgorithmIdentifier.Value.ES256,
                                 COSEAlgorithmIdentifier.Value.ES384,
                                 COSEAlgorithmIdentifier.Value.ES512,
                                 COSEAlgorithmIdentifier.Value.EDDSA),
        (EC2Curve.Value.P_256, EC2Curve.Value.P_384, EC2Curve.Value.P_521))
] + [
    generate_ec2_credential_public_key(x, y) for x, y in itertools.product(
        (EC2Curve.Value.P_256, EC2Curve.Value.P_384,
         EC2Curve.Value.P_521), (COSEAlgorithmIdentifier.Value.EDDSA, ))
] + [
    generate_okp_credential_public_key(x, y)
    for x, y in itertools.product((OKPCurve.Value.ED25519, OKPCurve.Value.ED448
                                   ), (COSEAlgorithmIdentifier.Value.ES256,
                                       COSEAlgorithmIdentifier.Value.ES384,
                                       COSEAlgorithmIdentifier.Value.ES512))
])
def test_validate_error(credential_public_key):
  with pytest.raises(ValidationError):
    validate(credential_public_key)
