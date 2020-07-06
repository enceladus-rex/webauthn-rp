import pytest

from webauthn_rp.errors import UnimplementedError
from webauthn_rp.registrars import CredentialsRegistrar


def test_credentials_registrar():
    registrar = CredentialsRegistrar()

    with pytest.raises(UnimplementedError):
        registrar.register_credential_attestation(
            None,
            None,
            None,
            None,
            None,
        )

    with pytest.raises(UnimplementedError):
        registrar.register_credential_assertion(
            None,
            None,
            None,
            None,
        )

    with pytest.raises(UnimplementedError):
        registrar.get_credential_data(b'')
