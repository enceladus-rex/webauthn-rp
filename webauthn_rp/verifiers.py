from functools import singledispatch
from typing import cast

import cryptography
import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from webauthn_rp.converters import cryptography_public_key
from webauthn_rp.errors import UnimplementedError, VerificationError
from webauthn_rp.types import (CredentialPublicKey, EC2CredentialPublicKey,
                               EC2PublicKey, OKPCredentialPublicKey,
                               OKPPublicKey)
from webauthn_rp.utils import ec2_hash_algorithm

__all__ = [
    'verify',
    'verify_ec2_public_key',
    'verify_okp_public_key',
]


@singledispatch
def verify(credential_public_key: CredentialPublicKey, signature: bytes,
           data: bytes) -> None:
    """Verify a signature over data using a `CredentialPublicKey`.

    Args:
      credential_public_key (CredentialPublicKey): The credential public key to
        use for verification.
      signature (bytes): The signature to verify.
      data (bytes): The data over which to compute the signature.

    Raises:
      VerificationError: If the provided signature is not correct.
      UnimplementedError: If the logic to verify using the given type of key is
        not implemented.
    """
    raise UnimplementedError('Must implement verification for {}'.format(
        str(type(credential_public_key))))


@verify.register(EC2CredentialPublicKey)
def verify_ec2_public_key(credential_public_key: EC2CredentialPublicKey,
                          signature: bytes, data: bytes) -> None:
    """Verify the a signature over data using an `EC2CredentialPublicKey`.

    Args:
      credential_public_key (EC2CredentialPublicKey): The credential public key
        to use for verification.
      signature (bytes): The signature to verify.
      data (bytes): The data over which to compute the signature.

    Raises:
      VerificationError: If the provided signature is not correct.
      UnimplementedError: If the logic to verify using the given type of key is
        not implemented.
    """
    public_key = cast(EC2PublicKey,
                      cryptography_public_key(credential_public_key))
    if credential_public_key.alg is None:
        raise VerificationError('alg must not be None')

    signature_algorithm = ECDSA(ec2_hash_algorithm(credential_public_key.alg))

    try:
        public_key.verify(signature, data, signature_algorithm)
    except cryptography.exceptions.InvalidSignature:
        raise VerificationError('EC2 verification failure')


@verify.register(OKPCredentialPublicKey)
def verify_okp_public_key(credential_public_key: OKPCredentialPublicKey,
                          signature: bytes, data: bytes) -> None:
    """Verify the a signature over data using an `OKPCredentialPublicKey`.

    Args:
      credential_public_key (OKPCredentialPublicKey): The credential public key
        to use for verification.
      signature (bytes): The signature to verify.
      data (bytes): The data over which to compute the signature.

    Raises:
      VerificationError: If the provided signature is not correct.
      UnimplementedError: If the logic to verify using the given type of key is
        not implemented.
    """
    public_key = cast(OKPPublicKey,
                      cryptography_public_key(credential_public_key))

    try:
        public_key.verify(signature, data)
    except cryptography.exceptions.InvalidSignature:
        raise VerificationError('OKP verification failure')
