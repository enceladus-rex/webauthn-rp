class WebAuthnRPError(Exception):
    pass


class BackendError(WebAuthnRPError):
    pass


class ClientDataTypeError(BackendError):
    pass


class ChallengeError(BackendError):
    pass


class TokenBindingError(BackendError):
    pass


class RPIDHashError(BackendError):
    pass


class UserPresenceError(BackendError):
    pass


class UserVerificationError(BackendError):
    pass


class ExtensionError(BackendError):
    pass


class CredentialNotAllowedError(BackendError):
    pass


class UserIDError(BackendError):
    pass


class UserHandleError(BackendError):
    pass


class RPNotFoundError(BackendError):
    pass


class RPIDError(BackendError):
    pass


class RegistrationError(BackendError):
    pass


class CredentialDataError(BackendError):
    pass


class SignatureCountError(BackendError):
    pass


class ConverterError(WebAuthnRPError):
    pass


class JSONConversionError(ConverterError):
    pass


class PublicKeyConversionError(ConverterError):
    pass


class ParserError(WebAuthnRPError):
    pass


class DecodingError(ParserError):
    pass


class OriginError(WebAuthnRPError):
    pass


class VerificationError(WebAuthnRPError):
    pass


class AuthenticationError(WebAuthnRPError):
    pass


class UnimplementedError(WebAuthnRPError):
    pass


class ValidationError(WebAuthnRPError):
    pass


class BuilderError(WebAuthnRPError):
    pass


class AttestationError(WebAuthnRPError):
    pass


class InternalError(WebAuthnRPError):
    pass
