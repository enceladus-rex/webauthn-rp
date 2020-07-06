from functools import singledispatch

from webauthn_rp.errors import UnimplementedError, ValidationError
from webauthn_rp.types import (CredentialPublicKey, EC2CredentialPublicKey,
                               OKPCredentialPublicKey)

__all__ = [
    'validate',
    'validate_ec2_public_key',
    'validate_okp_public_key',
]


@singledispatch
def validate(credential_public_key: CredentialPublicKey) -> None:
    """Validate the format of a `CredentialPublicKey`.

    Args:
      credential_public_key (CredentialPublicKey): The credential public key to
        validate.

    Raises:
      ValidationError: If the given credential public key is invalid.
      UnimplementedError: If the logic to validate the given type of key is not
        implemented.
    """
    raise UnimplementedError('Must implement credential public key validator')


@validate.register(EC2CredentialPublicKey)
def validate_ec2_public_key(
        credential_public_key: EC2CredentialPublicKey) -> None:
    """Validate the format of an `EC2CredentialPublicKey`.

    Args:
      credential_public_key (EC2CredentialPublicKey): The credential public key to
        validate.

    Raises:
      ValidationError: If the given credential public key is invalid.
      UnimplementedError: If the logic to validate the given type of key is not
        implemented.
    """
    assert credential_public_key.kty.name == 'EC2'
    assert credential_public_key.crv is not None
    assert credential_public_key.alg is not None

    if credential_public_key.crv.name not in {'P_256', 'P_384', 'P_521'}:
        raise ValidationError('Invalid curve for key type')

    if credential_public_key.alg.name not in {'ES256', 'ES384', 'ES512'}:
        raise ValidationError('Invalid alg for key type')


@validate.register(OKPCredentialPublicKey)
def validate_okp_public_key(
        credential_public_key: OKPCredentialPublicKey) -> None:
    """Validate the format of an `OKPCredentialPublicKey`.

    Args:
      credential_public_key (OKPCredentialPublicKey): The credential public key to
        validate.

    Raises:
      ValidationError: If the given credential public key is invalid.
      UnimplementedError: If the logic to validate the given type of key is not
        implemented.
    """
    assert credential_public_key.kty.name == 'OKP'
    assert credential_public_key.crv is not None
    assert credential_public_key.alg is not None

    if credential_public_key.crv.name not in {'ED25519', 'ED448'}:
        raise ValidationError('Invalid curve for key type')

    if credential_public_key.alg.name not in {'EDDSA'}:
        raise ValidationError('Invalid alg for key type')
