from unittest.mock import MagicMock

import pytest

from webauthn_rp.builders import (CredentialCreationOptionsBuilder,
                                  CredentialRequestOptionsBuilder)
from webauthn_rp.errors import BuilderError
from webauthn_rp.types import (CredentialCreationOptions,
                               CredentialRequestOptions)


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

    funcs = ('rp', 'pub_key_cred_params')
    for fn in funcs:
        with pytest.raises(AssertionError):
            getattr(builder, fn)(None)

    with pytest.raises(BuilderError):
        builder.build(user=MagicMock(), challenge=MagicMock())


def test_credential_request_options_builder_success():
    builder = CredentialRequestOptionsBuilder(
        mediation=MagicMock(),
        timeout=MagicMock(),
        rp_id=MagicMock(),
        extensions=MagicMock(),
        allow_credentials=MagicMock(),
        user_verification=MagicMock(),
    )

    assert isinstance(builder.build(challenge=MagicMock()),
                      CredentialRequestOptions)

    builder = CredentialRequestOptionsBuilder()
    assert isinstance(builder.build(challenge=MagicMock()),
                      CredentialRequestOptions)

    funcs = ('mediation', 'timeout', 'rp_id', 'extensions',
             'allow_credentials', 'user_verification')
    for fn in funcs:
        b = getattr(builder, fn)(MagicMock())
        isinstance(b.build(challenge=MagicMock()), CredentialRequestOptions)


def test_credential_request_options_builder_error():
    builder = CredentialRequestOptionsBuilder()

    funcs = ('mediation', )
    for fn in funcs:
        with pytest.raises(AssertionError):
            getattr(builder, fn)(None)
