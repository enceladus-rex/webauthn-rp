import pytest

from webauthn_rp.errors import UnimplementedError
from webauthn_rp.registrars import CredentialsRegistrar


def test_credentials_registrar():
  registrar = CredentialsRegistrar()

  registrar.register_creation_options(None)
  registrar.register_request_options(None)

  with pytest.raises(UnimplementedError):
    registrar.register_credential_creation(
        None,
        None,
        None,
        None,
        None,
    )

  with pytest.raises(UnimplementedError):
    registrar.register_credential_request(
        None,
        None,
        None,
        None,
    )

  with pytest.raises(UnimplementedError):
    registrar.get_credential_data(b'', )
