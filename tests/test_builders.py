from unittest.mock import MagicMock

import pytest

from webauthn_rp.builders import CredentialCreationOptionsBuilder
from webauthn_rp.errors import BuilderError
from webauthn_rp.types import CredentialCreationOptions


def test_credential_creation_options_builder_success():
  builder = CredentialCreationOptionsBuilder(
      rp=MagicMock(),
      pub_key_cred_params=MagicMock(),
      timeout=MagicMock(),
      authenticator_selection=MagicMock(),
      extensions=MagicMock(),
      attestation=MagicMock(),
      exclude_credentials=MagicMock(),
  )

  assert isinstance(builder.build(user=MagicMock(), challenge=MagicMock()),
                    CredentialCreationOptions)

  funcs = ('rp', 'pub_key_cred_params', 'timeout', 'authenticator_selection',
           'extensions', 'attestation', 'exclude_credentials')
  for fn in funcs:
    b = getattr(builder, fn)(MagicMock())
    isinstance(b.build(user=MagicMock(), challenge=MagicMock()),
               CredentialCreationOptions)


def test_credential_creation_options_builder_error():
  builder = CredentialCreationOptionsBuilder()
  with pytest.raises(BuilderError):
    builder.build(user=MagicMock(), challenge=MagicMock())

  funcs = ('rp', 'pub_key_cred_params', 'timeout', 'authenticator_selection',
           'extensions')
  for fn in funcs:
    with pytest.raises(AssertionError):
      getattr(builder, fn)(None)

  with pytest.raises(BuilderError):
    builder.build(user=MagicMock(), challenge=MagicMock())
