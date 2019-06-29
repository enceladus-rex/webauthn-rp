class WebAuthnRPError(Exception):
  pass


class DecodingError(WebAuthnRPError):
  pass


class ParseError(WebAuthnRPError):
  pass


class IntegrityError(WebAuthnRPError):
  pass


class VerificationError(WebAuthnRPError):
  pass


class AuthenticationError(WebAuthnRPError):
  pass


class TokenBindingError(WebAuthnRPError):
  pass


class UnimplementedError(WebAuthnRPError):
  pass


class ValidationError(WebAuthnRPError):
  pass


class NotFoundError(WebAuthnRPError):
  pass


class SignatureCountError(WebAuthnRPError):
  pass


class RegistrationError(WebAuthnRPError):
  pass


class AttestationError(WebAuthnRPError):
  pass
