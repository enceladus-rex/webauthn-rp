class WebAuthnRPError(Exception):
    """The base error for all exceptions raised by the library."""
    pass


class BackendError(WebAuthnRPError):
    """Raised for an error in a backend."""
    pass


class ClientDataTypeError(BackendError):
    """Raised for an invalid client data type."""
    pass


class ChallengeError(BackendError):
    """Raised for an invalid challenge."""
    pass


class TokenBindingError(BackendError):
    """Raised for an error in token binding."""
    pass


class RPIDHashError(BackendError):
    """Raised for a mismatching Relying Party ID hash."""
    pass


class UserPresenceError(BackendError):
    """Raised for a missing user presence bit when it is required."""
    pass


class UserVerificationError(BackendError):
    """Raised for a missing user verification bit when it is required."""
    pass


class ExtensionError(BackendError):
    """Raised for a missing extension."""
    pass


class CredentialNotAllowedError(BackendError):
    """Raised for the use of disallowed credential."""
    pass


class UserIDError(BackendError):
    """Raised for an invalid user ID."""
    pass


class UserHandleError(BackendError):
    """Raised for an invalid user handle."""
    pass


class RPNotFoundError(BackendError):
    """Raised for a missing Relying Party configuration."""
    pass


class RPIDError(BackendError):
    """Raised for an invalid Relying Party ID."""
    pass


class RegistrationError(BackendError):
    """Raised for an error during registration."""
    pass


class CredentialDataError(BackendError):
    """Raised for an unretrievable `CredentialData`."""
    pass


class SignatureCountError(BackendError):
    """Raised for an invalid signature count."""
    pass


class ConverterError(WebAuthnRPError):
    """Raised for an error during data type conversion."""
    pass


class JSONConversionError(ConverterError):
    """Raised for an error converting data into JSON."""
    pass


class PublicKeyConversionError(ConverterError):
    """Raised for an error converting a `CredentialPublicKey`."""
    pass


class ParserError(WebAuthnRPError):
    """Raised for an error parsing raw data."""
    pass


class DecodingError(ParserError):
    """Raised for an error decoding raw data."""
    pass


class OriginError(WebAuthnRPError):
    """Raised for an invalid web origin."""
    pass


class VerificationError(WebAuthnRPError):
    """Raised for an error verifying a signature using a `CredentialPublicKey`.
    """
    pass


class UnimplementedError(WebAuthnRPError):
    """Raised for an attempt to use an unimplemented feature."""
    pass


class ValidationError(WebAuthnRPError):
    """Raised for an error validating the format of a `CredentialPublicKey`."""
    pass


class BuilderError(WebAuthnRPError):
    """Raised for a builder error."""
    pass


class AttestationError(WebAuthnRPError):
    """Raised for an invalid attestation statement."""
    pass


class InternalError(WebAuthnRPError):
    """Raised for an unexpected internal error."""
    pass
