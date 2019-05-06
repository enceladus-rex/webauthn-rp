from typing import Optional, Sequence, Union
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

from .utils import camel_to_snake_case


PublicKey = Union[DSAPublicKey, EllipticCurvePublicKey, RSAPublicKey]
TrustedPath = Optional[Sequence[Certificate]]


class NameValueEnumsContainer(type):

  def __call__(cls, value):
    if type(value) is int:
      return cls.Value(value)
    elif type(value) is str:
      return cls.Name(value)
    else:
      raise KeyError('Invalid key {}'.format(value))

  def __getitem__(cls, value):
    if type(value) is int:
      return cls.Value[value]
    elif type(value) is str:
      return cls.Name[value]
    else:
      raise KeyError('Invalid key {}'.format(value))


class PublicKeyCredentialEntity:
  """
  The PublicKeyCredentialEntity describes a user account, or a WebAuthn Relying
  Party, which a public key credential is associated with or scoped to,
  respectively.
  
  Attributes:
    name (str): A human-palatable name for the entity.
      Its function depends on what the PublicKeyCredentialEntity represents:

      * When inherited by PublicKeyCredentialRpEntity it is a human-palatable
        identifier for the Relying Party, intended only for display.
      * When inherited by PublicKeyCredentialUserEntity, it is a
        human-palatable identifier for a user account. It is intended only
        for display, i.e., aiding the user in determining the difference
        between user accounts with similar displayNames.
    icon (str):
      A serialized URL which resolves to an image associated with the entity.
      For example, this could be a user’s avatar or a Relying Party's logo.
      This URL MUST be an a priori authenticated URL. Authenticators MUST
      accept and store a 128-byte minimum length for an icon member’s value.
      Authenticators MAY ignore an icon member’s value if its length is
      greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches
      of the URL, at the cost of needing more storage.

  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialentity
  """

  def __init__(self, *, name: str, icon: Optional[str] = None):
    self.name = name
    self.icon = icon


class PublicKeyCredentialRpEntity(PublicKeyCredentialEntity):
  """
  The PublicKeyCredentialRpEntity is used to supply additional
  Relying Party attributes when creating a new credential.

  Attributes:
    name (str): A human-palatable name for the entity.
      Its function depends on what the PublicKeyCredentialEntity represents:

      * When inherited by PublicKeyCredentialRpEntity it is a human-palatable
        identifier for the Relying Party, intended only for display.
      * When inherited by PublicKeyCredentialUserEntity, it is a
        human-palatable identifier for a user account. It is intended only
        for display, i.e., aiding the user in determining the difference
        between user accounts with similar displayNames.
    icon (str):
      A serialized URL which resolves to an image associated with the entity.
      For example, this could be a user’s avatar or a Relying Party's logo.
      This URL MUST be an a priori authenticated URL. Authenticators MUST
      accept and store a 128-byte minimum length for an icon member’s value.
      Authenticators MAY ignore an icon member’s value if its length is
      greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches
      of the URL, at the cost of needing more storage.
    id (str): A unique identifier for the Relying Party entity.

  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialentity
  """

  def __init__(self, *, name: str, icon: Optional[str] = None, id: str):
    super().__init__(name=name, icon=icon)
    self.id = id


class PublicKeyCredentialUserEntity(PublicKeyCredentialEntity):
  """
  The PublicKeyCredentialUserEntity is used to supply additional user account
  attributes when creating a new credential.

  Attributes:
    name (str): A human-palatable name for the entity.
      Its function depends on what the PublicKeyCredentialEntity represents:

      * When inherited by PublicKeyCredentialRpEntity it is a human-palatable
        identifier for the Relying Party, intended only for display.
      * When inherited by PublicKeyCredentialUserEntity, it is a
        human-palatable identifier for a user account. It is intended only
        for display, i.e., aiding the user in determining the difference
        between user accounts with similar displayNames.
    icon (str):
      A serialized URL which resolves to an image associated with the entity.
      For example, this could be a user’s avatar or a Relying Party's logo.
      This URL MUST be an a priori authenticated URL. Authenticators MUST
      accept and store a 128-byte minimum length for an icon member’s value.
      Authenticators MAY ignore an icon member’s value if its length is
      greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches
      of the URL, at the cost of needing more storage.
    id (bytes): The user handle of the user account entity. 
      To ensure secure operation, authentication and authorization decisions
      MUST be made on the basis of this id member, not the displayName nor
      name members.

      Since the user handle (id) is not considered personally identifying
      information, the Relying Party SHOULD NOT include personally identifying
      information, e.g., e-mail addresses or usernames, in the user handle.
      This includes hash values of personally identifying information, unless
      the hash function is salted with salt values private to the Relying
      Party, since hashing does not prevent probing for guessable input values.
      It is RECOMMENDED to let the user handle be 64 random bytes, and store
      this value in the user’s account.
    display_name (str): A human-palatable name for the user account, intended
      only for display. The Relying Party SHOULD let the user choose this,
      and SHOULD NOT restrict the choice more than necessary.
  
  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialentity
    * https://w3.org/TR/webauthn/#user-handle
    * https://w3.org/TR/webauthn/#sctn-user-handle-privacy
  """

  def __init__(
      self, *, name: str, icon: Optional[str] = None, id: bytes,
      display_name: str):
    super().__init__(name=name, icon=icon)
    self.id = id
    self.display_name = display_name


class PublicKeyCredentialType(Enum):
  """
  This enumeration defines the valid credential types. It is an extension
  point; values can be added to it in the future, as more credential types are
  defined. The values of this enumeration are used for versioning the
  Authentication Assertion and attestation structures according to the type of
  the authenticator.

  Attributes:
    PUBLIC_KEY (str): The only credential type.

  References:
    * https://w3.org/TR/webauthn/#enumdef-publickeycredentialtype
  """

  PUBLIC_KEY = 'public-key'


class AuthenticatorTransport(Enum):
  """
  Authenticators may implement various transports for communicating with
  clients. This enumeration defines hints as to how clients might communicate
  with a particular authenticator in order to obtain an assertion for a
  specific credential. Note that these hints represent the WebAuthn Relying
  Party's best belief as to how an authenticator may be reached. A Relying
  Party may obtain a list of transports hints from some attestation statement
  formats or via some out-of-band mechanism; it is outside the scope of this
  specification to define that mechanism.

  Attributes:
    USB (str): Indicates the respective authenticator can be contacted over
      removable USB.
    NFC (str): Indicates the respective authenticator can be contacted over
      Near Field Communication (NFC).
    BLE (str): Indicates the respective authenticator can be contacted over
      Bluetooth Smart (Bluetooth Low Energy / BLE).
    INTERNAL (str): Indicates the respective authenticator is contacted using
      a client device-specific transport. These authenticators are not
      removable from the client device.

  References:
    * https://w3.org/TR/webauthn/#enumdef-authenticatortransport
  """

  USB = 'usb'
  NFC = 'nfc'
  BLE = 'ble'
  INTERNAL = 'internal'


class COSEAlgorithmIdentifier(metaclass=NameValueEnumsContainer):
  """
  A COSEAlgorithmIdentifier's value is a number identifying a cryptographic
  algorithm. The algorithm identifiers SHOULD be values registered in the
  IANA COSE Algorithms registry.

  This Enum only contains algorithms that are internally supported. It can be
  extended upon further support.

  References:
    * https://w3.org/TR/webauthn/#typedefdef-cosealgorithmidentifier
    * https://iana.org/assignments/cose/cose.xhtml#algorithms
  """
  
  class Name(Enum):
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'

    EDDSA = 'EdDSA'

    ECDH_ES_HKDF_256 = 'ECDH-ES + HKDF-256'
    ECDH_ES_HKDF_512 = 'ECDH-ES + HKDF-512'
    ECDH_SS_HKDF_256 = 'ECDH-SS + HKDF-256'
    ECDH_SS_HKDF_512 = 'ECDH-SS + HKDF-512'

    HMAC_256_64 = 'HMAC 256/64'
    HMAC_256_256 = 'HMAC 256/256'
    HMAC_384_384 = 'HMAC 384/384'
    HMAC_512_512 = 'HMAC 512/512'

    AES_MAC_128_64 = 'AES-MAC 128/64'
    AES_MAC_256_64 = 'AES-MAC 256/64'
    AES_MAC_128_128 = 'AES-MAC 128/128'
    AES_MAC_256_128 = 'AES-MAC 256/128'

    A256KW = 'A256KW'
    A192KW = 'A192KW'
    A128KW = 'A128KW'

    A128GCM = 'A128GCM'
    A192GCM = 'A192GCM'
    A256GCM = 'A256GCM'

    DIRECT = 'direct'

    DIRECT_HKDF_SHA_256 = 'direct+HKDF-SHA-256'
    DIRECT_HKDF_SHA_512 = 'direct+HKDF-SHA-512'
    DIRECT_HKDF_AES_128 = 'direct+HKDF-AES-128'
    DIRECT_HKDF_AES_256 = 'direct+HKDF-AES-256'

    AES_CCM_16_64_128 = 'AES-CCM-16-64-128'
    AES_CCM_16_64_256 = 'AES-CCM-16-64-256'
    AES_CCM_64_64_128 = 'AES-CCM-64-64-128'
    AES_CCM_64_64_256 = 'AES-CCM-64-64-256'
    AES_CCM_16_128_128 = 'AES-CCM-16-128-128'
    AES_CCM_16_128_256 = 'AES-CCM-16-128-256'
    AES_CCM_64_128_128 = 'AES-CCM-64-128-128'
    AES_CCM_64_128_256 = 'AES-CCM-64-128-256'
    
    CHACHA20_POLY1305 = 'ChaCha20/Poly1305'

  class Value(Enum):
    ES256 = -7
    ES384 = -35
    ES512 = -36

    EDDSA = -8

    ECDH_ES_HKDF_256 = -25
    ECDH_ES_HKDF_512 = -26
    ECDH_SS_HKDF_256 = -27
    ECDH_SS_HKDF_512 = -28

    HMAC_256_64 = 4
    HMAC_256_256 = 5
    HMAC_384_384 = 6
    HMAC_512_512 = 7

    AES_MAC_128_64 = 14
    AES_MAC_256_64 = 15
    AES_MAC_128_128 = 25
    AES_MAC_256_128 = 26

    A256KW = -5
    A192KW = -4
    A128KW = -3

    A128GCM = 1
    A192GCM = 2
    A256GCM = 3

    DIRECT = -6

    DIRECT_HKDF_SHA_256 = -10
    DIRECT_HKDF_SHA_512 = -11
    DIRECT_HKDF_AES_128 = -12
    DIRECT_HKDF_AES_256 = -13

    AES_CCM_16_64_128 = 10
    AES_CCM_16_64_256 = 11
    AES_CCM_64_64_128 = 12
    AES_CCM_64_64_256 = 13
    AES_CCM_16_128_128 = 30
    AES_CCM_16_128_256 = 31
    AES_CCM_64_128_128 = 32
    AES_CCM_64_128_256 = 33

    CHACHA20_POLY1305 = 24


class PublicKeyCredentialParameters:
  """
  PublicKeyCredentialParameters is used to supply additional parameters when
  creating a new credential.

  Attributes:
    type (PublicKeyCredentialType):
      This member specifies the type of credential to be created.
    alg (COSEAlgorithmIdentifier):
      This member specifies the cryptographic signature algorithm with which
      the newly generated credential will be used, and thus also the type of
      asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
  
  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialparameters
  """

  def __init__(
      self, *, type: PublicKeyCredentialType,
      alg: COSEAlgorithmIdentifier):
    self.type = type
    self.alg = alg


class PublicKeyCredentialDescriptor:
  """
  The PublicKeyCredentialDescriptor contains the attributes that are specified
  by a caller when referring to a public key credential as an input parameter
  to the navigator.credentials.create() or navigator.credentials.get() methods
  (on the client side). It mirrors the fields of the PublicKeyCredential object
  returned by the latter methods.

  Attributes:
    type (PublicKeyCredentialType):
      This member contains the type of the public key credential the caller
      is referring to.
    id (bytes):
      This member contains the credential ID of the public key credential
      the caller is referring to.
    transports (Sequence[AuthenticatorTransport]):
      This OPTIONAL member contains a hint as to how the client might
      communicate with the managing authenticator of the public key
      credential the caller is referring to.
  
  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
  """

  def __init__(
      self, *, type: PublicKeyCredentialType, id: bytes,
      transports: Optional[Sequence[AuthenticatorTransport]] = None):
    self.type = type
    self.id = id
    self.transports = transports


class AuthenticatorAttachment(Enum):
  """
  This enumeration’s values describe authenticators' attachment modalities.
  Relying Parties use this for two purposes:
  
    * to express a preferred authenticator attachment modality when calling
      navigator.credentials.create() to create a credential, and
    * to inform the client of the Relying Party's best belief about how to
      locate the managing authenticators of the credentials listed in
      allowCredentials when calling navigator.credentials.get() (on the
      client side).

  Attributes:
    PLATFORM (str):
      This value indicates platform attachment.
    CROSS_PLATFORM (str):
      This value indicates cross-platform attachment.

  References:
    * https://w3.org/TR/webauthn/#enumdef-authenticatorattachment
  """

  PLATFORM = 'platform'
  CROSS_PLATFORM = 'cross-platform'


class AttestationConveyancePreference(Enum):
  """
  WebAuthn Relying Parties may use AttestationConveyancePreference to specify
  their preference regarding attestation conveyance during credential
  generation.

  Attributes:
    NONE (str):
      This value indicates that the Relying Party is not interested
      in authenticator attestation. For example, in order to potentially avoid
      having to obtain user consent to relay identifying information to the
      Relying Party, or to save a roundtrip to an Attestation CA.
    INDIRECT (str):
      This value indicates that the Relying Party prefers an
      attestation conveyance yielding verifiable attestation statements, but
      allows the client to decide how to obtain such attestation statements.
      The client MAY replace the authenticator-generated attestation statements
      with attestation statements generated by an Anonymization CA, in order to
      protect the user’s privacy, or to assist Relying Parties with attestation
      verification in a heterogeneous ecosystem.
    DIRECT (str):
      This value indicates that the Relying Party wants to receive
      the attestation statement as generated by the authenticator.

  References:
    * https://w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
  """

  NONE = 'none'
  INDIRECT = 'indirect'
  DIRECT = 'direct'


class UserVerificationRequirement(Enum):
  """
  A WebAuthn Relying Party may require user verification for some of its
  operations but not for others, and may use this type to express its needs.

  Attributes:
    REQUIRED (str):
      This value indicates that the Relying Party requires user verification
      for the operation and will fail the operation if the response does not
      have the UV flag set.
    PREFERRED (str):
      This value indicates that the Relying Party prefers user verification
      for the operation if possible, but will not fail the operation if the
      response does not have the UV flag set.
    DISCOURAGED (str):
      This value indicates that the Relying Party does not want user
      verification employed during the operation (e.g., in the interest of
      minimizing disruption to the user interaction flow).

  References:
    * https://w3.org/TR/webauthn/#enumdef-userverificationrequirement
  """

  REQUIRED = 'required'
  PREFERRED = 'preferred'
  DISCOURAGED = 'discouraged'


class TxAuthGenericArg:

  def __init__(self, *, content_type: str, content: bytes):
    self.content_type = content_type
    self.content = content


class Coordinates:

  def __init__(
      self, *, latitude: float, longitude : float,
      altitude: Optional[float] = None, accuracy: float,
      altitude_accuracy: Optional[float] = None,
      heading: Optional[float] = None,
      speed: Optional[float] = None):
    self.latitude = latitude
    self.longitude = longitude
    self.altitude = altitude
    self.accuracy = accuracy
    self.altitude_accuracy = altitude_accuracy
    self.heading = heading
    self.speed = speed


AAGUID = bytes
AuthenticatorSelectionList = Sequence[AAGUID]
AuthenticationExtensionsSupported = Sequence[str]
UvmEntry = Sequence[int]
UvmEntries = Sequence[UvmEntry]


class AuthenticatorBiometricPerfBounds:

  def __init__(self, *, FAR: float, FRR: float):
    self.FAR = FAR
    self.FRR = FRR

class ExtensionIdentifier(Enum):
  APPID = 'appid'
  TX_AUTH_SIMPLE = 'txAuthSimple'
  TX_AUTH_GENERIC = 'txAuthGeneric'
  AUTHN_SEL = 'authnSel'
  EXTS = 'exts'
  UVI = 'uvi'
  LOC = 'loc'
  UVM = 'uvm'
  BIOMETRIC_PERF_BOUNDS = 'biometricPerfBounds'

  @property
  def key(self):
    return camel_to_snake_case(self.value)
  

class AuthenticationExtensionsClientInputs:
  """
  This is an object containing the client extension input values for zero or
  more WebAuthn extensions.

  References:
    * https://w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs
  """
  
  def __init__(
      self, *, appid: Optional[str] = None,
      tx_auth_simple: Optional[str] = None,
      tx_auth_generic: Optional[TxAuthGenericArg] = None,
      authn_sel: Optional[AuthenticatorSelectionList] = None,
      exts: Optional[bool] = None,
      uvi: Optional[bool] = None,
      loc: Optional[bool] = None,
      uvm: Optional[bool] = None,
      biometric_perf_bounds:
        Optional[AuthenticatorBiometricPerfBounds] = None):
    self.appid = appid
    self.tx_auth_simple = tx_auth_simple
    self.tx_auth_generic = tx_auth_generic
    self.authn_sel = authn_sel
    self.exts = exts
    self.uvi = uvi
    self.loc = loc
    self.uvm = uvm
    self.biometric_perf_bounds = biometric_perf_bounds


class AuthenticationExtensionsClientOutputs:
  """
  This is an object containing the client extension output values for zero or
  more WebAuthn extensions.

  References:
    * https://w3.org/TR/webauthn/#dictdef-authenticationextensionsclientoutputs
  """
  
  def __init__(
      self, *, appid: Optional[bool] = None,
      tx_auth_simple: Optional[str] = None,
      tx_auth_generic: Optional[bytes] = None,
      authn_sel: Optional[bool] = None,
      exts: Optional[AuthenticationExtensionsSupported] = None,
      uvi: Optional[bytes] = None,
      loc: Optional[Coordinates] = None,
      uvm: Optional[UvmEntries] = None,
      biometric_perf_bounds: Optional[bool] = None):
    self.appid = appid
    self.tx_auth_simple = tx_auth_simple
    self.tx_auth_generic = tx_auth_generic
    self.authn_sel = authn_sel
    self.exts = exts
    self.uvi = uvi
    self.loc = loc
    self.uvm = uvm
    self.biometric_perf_bounds = biometric_perf_bounds


class AuthenticatorSelectionCriteria:
  """
  WebAuthn Relying Parties may use the AuthenticatorSelectionCriteria to
  specify their requirements regarding authenticator attributes.

  Attributes:
    authenticator_attachment (AuthenticatorAttachment):
      If this member is present, eligible authenticators are filtered to only
      authenticators attached with the specified Authenticator Attachment
      Enumeration (enum AuthenticatorAttachment).
    require_resident_key (bool):
      This member describes the Relying Party's requirements regarding
      resident credentials. If the parameter is set to true, the
      authenticator MUST create a client-side-resident public key credential
      source when creating a public key credential.
    user_verification (UserVerificationRequirement):
      This member describes the Relying Party's requirements regarding user
      verification for the navigator.credentials.create() operation
      (on the client side). Eligible authenticators are filtered to only those
      capable of satisfying this requirement.

  References:
    * https://w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria
  """

  def __init__(
      self, *,
      authenticator_attachment: Optional[AuthenticatorAttachment] = None,
      require_resident_key: bool = False,
      user_verification:
        UserVerificationRequirement = UserVerificationRequirement.PREFERRED):
    self.authenticator_attachment = authenticator_attachment
    self.require_resident_key = require_resident_key
    self.user_verification = user_verification


class PublicKeyCredentialCreationOptions:
  """Options for Credential Creation

  Attributes:
    rp (PublicKeyCredentialRpEntity): This member contains data about the
      Relying Party responsible for the request.
    user (PublicKeyCredentialUserEntity): This member contains data about the
      user account for which the Relying Party is requesting attestation.
    challenge (bytes): This member contains a challenge intended to be used
      for generating the newly created credential’s attestation object.
    pub_key_cred_params (Sequence[PublicKeyCredentialParameters]):
      This member contains information about the desired properties of the
      credential to be created. The sequence is ordered from most preferred
      to least preferred. The client makes a best-effort to create the most
      preferred credential that it can.
    timeout (int): This member specifies a time, in milliseconds, that the
      caller is willing to wait for the call to complete. This is treated as
      a hint, and MAY be overridden by the client.
    authenticator_selection (AuthenticatorSelectionCriteria):
      This member is intended for use by Relying Parties that wish to select
      the appropriate authenticators to participate in the
      navigator.credentials.create() operation (on the client side).
    extensions (AuthenticationExtensionsClientInputs):
      This member contains additional parameters requesting additional
      processing by the client and authenticator. For example, the caller may
      request that only authenticators with certain capabilities be used to
      create the credential, or that particular information be returned in
      the attestation object.
    attestation (AttestationConveyancePreference):
      This member is intended for use by Relying Parties that wish to express
      their preference for attestation conveyance.
    exclude_credentials (Sequence[PublicKeyCredentialDescriptor]):
      This member is intended for use by Relying Parties that wish to limit
      the creation of multiple credentials for the same account on a single
      authenticator. The client is requested to return an error if the new
      credential would be created on an authenticator that also contains one
      of the credentials enumerated in this parameter.

  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
  """

  def __init__(
      self, *, rp: PublicKeyCredentialRpEntity, 
      user: PublicKeyCredentialUserEntity,
      challenge: bytes, 
      pub_key_cred_params: Sequence[PublicKeyCredentialParameters],
      timeout: Optional[int] = None, 
      authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None,
      extensions: Optional[AuthenticationExtensionsClientInputs] = None,
      attestation: 
        AttestationConveyancePreference = AttestationConveyancePreference.NONE,
      exclude_credentials:
        Optional[Sequence[PublicKeyCredentialDescriptor]] = None):
    self.rp = rp
    self.user = user
    self.challenge = challenge
    self.pub_key_cred_params = pub_key_cred_params
    self.timeout = timeout
    self.exclude_credentials = exclude_credentials
    self.authenticator_selection = authenticator_selection
    self.attestation = attestation
    self.extensions = extensions


class PublicKeyCredentialRequestOptions:
  """
  The PublicKeyCredentialRequestOptions object supplies
  navigator.credentials.get() with the data it needs to generate an assertion
  (on the client side). Its challenge member MUST be present, while its other
  members are OPTIONAL.

  Attributes:
    challenge (bytes): This member represents a challenge that the selected
      authenticator signs, along with other data, when producing an
      authentication assertion.
    timeout (int): This OPTIONAL member specifies a time, in milliseconds,
      that the caller is willing to wait for the call to complete. The value
      is treated as a hint, and MAY be overridden by the client.
    rp_id (str): This OPTIONAL member specifies the relying party identifier
      claimed by the caller. If omitted, its value will be the
      CredentialsContainer object’s relevant settings object's origin's
      effective domain.
    extensions (AuthenticationExtensionsClientInputs): 
    allow_credentials (Sequence[PublicKeyCredentialDescriptor]):
      This OPTIONAL member contains a list of PublicKeyCredentialDescriptor
      objects representing public key credentials acceptable to the caller,
      in descending order of the caller’s preference (the first item in the
      list is the most preferred credential, and so on down the list).
    user_verification (UserVerificationRequirement):
      This OPTIONAL member describes the Relying Party's requirements
      regarding user verification for the navigator.credentials.get() operation
      (on the client side). Eligible authenticators are filtered to only those
      capable of satisfying this requirement.

  References:
    * https://w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
  """

  def __init__(
      self, *, challenge: bytes, timeout: Optional[int] = None,
      rp_id: Optional[str] = None,
      extensions: Optional[AuthenticationExtensionsClientInputs] = None,
      allow_credentials:
        Optional[Sequence[PublicKeyCredentialDescriptor]] = None,
      user_verification:
        Optional[UserVerificationRequirement] = (
          UserVerificationRequirement.PREFERRED)):
    self.challenge = challenge
    self.timeout = timeout
    self.rp_id = rp_id
    self.allow_credentials = allow_credentials or list()
    self.user_verification = user_verification
    self.extensions = extensions


class CredentialCreationOptions:
  """
  The object used for registration of credentials using the
  navigator.credentials.create() function on the client side.

  Attributes:
    public_key (PublicKeyCredentialCreationOptions):
      The creation options for the public key credential.

  References:
    * https://w3.org/TR/webauthn/#credentialcreationoptions-extension
  """

  def __init__(
      self, *, public_key: PublicKeyCredentialCreationOptions):
    self.public_key = public_key


class CredentialRequestOptions:
  """
  The object used to obtain assertions using the
  navigator.credentials.get() function on the client side.

  Attributes:
    public_key (PublicKeyCredentialRequestOptions):
      The request options for the public key credential.

  References:
    * https://w3.org/TR/webauthn/#credentialrequestoptions-extension
  """

  def __init__(
      self, *, public_key: PublicKeyCredentialRequestOptions):
    self.public_key = public_key


class AuthenticatorResponse:
  """
  Authenticators respond to Relying Party requests by returning an object
  derived from an AuthenticatorResponse.

  Attributes:
    client_data_JSON (bytes): This attribute contains a JSON serialization of
      the client data passed to the authenticator by the client in its call
      to either navigator.credentials.create() or navigator.credentials.get().

  References:
    * https://w3.org/TR/webauthn/#authenticatorresponse
  """

  def __init__(self, *, client_data_JSON: bytes):
    self.client_data_JSON = client_data_JSON


class AuthenticatorAttestationResponse(AuthenticatorResponse):
  """
  The AuthenticatorAttestationResponse represents the authenticator's response
  to a client’s request for the creation of a new public key credential. It
  contains information about the new credential that can be used to identify
  it for later use, and metadata that can be used by the WebAuthn Relying Party
  to assess the characteristics of the credential during registration.

  Attributes:
    client_data_JSON (bytes): This attribute contains a JSON serialization of
      the client data passed to the authenticator by the client in its call
      to either navigator.credentials.create() or navigator.credentials.get().
    attestation_object (bytes): This attribute contains an attestation object,
      which is opaque to, and cryptographically protected against tampering by,
      the client. The attestation object contains both authenticator data and
      an attestation statement. The former contains the AAGUID, a unique
      credential ID, and the credential public key. The contents of the
      attestation statement are determined by the attestation statement
      format used by the authenticator. It also contains any additional
      information that the Relying Party's server requires to validate the
      attestation statement, as well as to decode and validate the
      authenticator data along with the JSON-serialized client data.

  References:
    * https://w3.org/TR/webauthn/#authenticatorattestationresponse
    * https://w3.org/TR/webauthn/#authenticatorresponse
  """
  
  def __init__(self, *, client_data_JSON: bytes, attestation_object: bytes):
    super().__init__(client_data_JSON=client_data_JSON)
    self.attestation_object = attestation_object


class AuthenticatorAssertionResponse(AuthenticatorResponse):
  """
  The AuthenticatorAssertionResponse interface represents an authenticator's
  response to a client’s request for generation of a new authentication
  assertion given the WebAuthn Relying Party's challenge and OPTIONAL list
  of credentials it is aware of. This response contains a cryptographic
  signature proving possession of the credential private key, and optionally
  evidence of user consent to a specific transaction.

  Attributes:
    client_data_JSON (bytes): This attribute contains a JSON serialization of
      the client data passed to the authenticator by the client in its call
      to either navigator.credentials.create() or navigator.credentials.get().
    authenticator_data (bytes): This attribute contains the authenticator data
      returned by the authenticator.
    signature (bytes): This attribute contains the raw signature returned from
      the authenticator.
    user_handle (bytes): This attribute contains the user handle returned from
      the authenticator, or null if the authenticator did not return a user handle.

  References:
    * https://w3.org/TR/webauthn/#authenticatorassertionresponse
    * https://w3.org/TR/webauthn/#authenticatorresponse
  """
  
  def __init__(
      self, *, client_data_JSON: bytes, authenticator_data: bytes,
      signature: bytes, user_handle: Optional[bytes] = None):
    super().__init__(client_data_JSON=client_data_JSON)
    self.authenticator_data = authenticator_data
    self.signature = signature
    self.user_handle = user_handle


class Credential:
  """
  A credential is an object which allows a developer to make an authentication
  decision for a particular action.
  
  Attributes:
    id (str): The credential’s identifier.
      The requirements for the identifier are distinct for each type of
      credential. It might represent a username for username/password tuples,
      for example.
    type (str): Specifies the credential type represented by this object.

  References:
    * https://w3.org/TR/credential-management-1/#credential
  """

  def __init__(self, *, id: str, type: str):
    self.id = id
    self.type = type


class PublicKeyCredential(Credential):
  """
  PublicKeyCredential inherits from Credential, and contains the attributes
  that are returned to the caller when a new credential is created, or a new
  assertion is requested.

  Attributes:
    id (str): The credential’s identifier.
      The requirements for the identifier are distinct for each type of
      credential. It might represent a username for username/password tuples,
      for example.
    type (str): Specifies the credential type represented by this object.
    raw_id (bytes): This attribute is the raw credential id.
    response (AuthenticatorResponse): This attribute contains the
      authenticator's response to the client’s request to either create a
      public key credential, or generate an authentication assertion. If the
      PublicKeyCredential is created in response to
      navigator.credentials.create(), this attribute’s value will be an
      AuthenticatorAttestationResponse, otherwise, the PublicKeyCredential was
      created in response to navigator.credentials.get(), and this attribute’s
      value will be an AuthenticatorAssertionResponse.

  References:
    * https://w3.org/TR/webauthn/#iface-pkcredential
    * https://w3.org/TR/credential-management-1/#credential
  """

  def __init__(
      self, *, id: str, type: str, raw_id: bytes,
      response: AuthenticatorResponse):
    super().__init__(id=id, type=type)
    self.raw_id = raw_id
    self.response = response


class TokenBindingStatus(Enum):
  """
  The status of a Token Binding.

  Attributes:
    SUPPORTED (str):
      Indicates the client supports token binding, but it was not negotiated
      when communicating with the Relying Party.
    PRESENT (str):
      Indicates token binding was used when communicating with the Relying
      Party. In this case, the id member MUST be present.

  References:
    * https://w3.org/TR/webauthn/#enumdef-tokenbindingstatus
  """

  SUPPORTED = 'supported'
  PRESENT = 'present'


class TokenBinding:
  """
  TokenBinding contains information about the state of the Token Binding
  protocol used when the client was communicating with the Relying Party.

  Attributes:
    status (TokenBindingStatus): The status of the Token Binding.
    id (str): This member MUST be present if status is present, and MUST be a
      base64url encoding of the Token Binding ID that was used when
      the client was communicating with the Relying Party.

  References:
    * https://w3.org/TR/webauthn/#dictdef-tokenbinding
  """

  def __init__(self, *, status: TokenBindingStatus, id: Optional[str] = None):
    self.status = status
    self.id = id


class CollectedClientData:
  """
  The client data represents the contextual bindings of both the WebAuthn
  Relying Party and the client.

  Attributes:
    type (str): This member contains the string "webauthn.create" when creating
      new credentials, and "webauthn.get" when getting an assertion from an
      existing credential. The purpose of this member is to prevent certain
      types of signature confusion attacks (where an attacker substitutes one
      legitimate signature for another).
    challenge (str): This member contains the base64url encoding of the
      challenge provided by the Relying Party.
    origin (str): This member contains the fully qualified origin of the
      requester, as provided to the authenticator by the client, in the syntax
      defined by RFC6454.
    token_binding (TokenBinding): This OPTIONAL member contains information
      about the state of the Token Binding protocol used when the client was
      communicating with the Relying Party. Its absence indicates that the
      client doesn’t support token binding.

  References:
    * https://w3.org/TR/webauthn/#dictdef-collectedclientdata
  """

  def __init__(
      self, *, type: str, challenge: str, origin: str,
      token_binding: Optional[TokenBinding] = None):
    self.type = type
    self.challenge = challenge
    self.origin = origin
    self.token_binding = token_binding


class AuthenticatorDataFlag(Enum):
  UP = 1 << 0
  RFU1 = 1 << 1
  UV = 1 << 2
  RFU2 = (1 << 3) | (1 << 4) | (1 << 5)
  AT = 1 << 6
  ED = 1 << 7


class COSEKeyType(metaclass=NameValueEnumsContainer):

  class Name(Enum):
    OKP = 'OKP'
    EC2 = 'EC2'
    SYMMETRIC = 'Symmetric'

  class Value(Enum):
    OKP = 1
    EC2 = 2
    SYMMETRIC = 4


class COSEKeyOperation(metaclass=NameValueEnumsContainer):

  class Name(Enum):
    SIGN = 'sign'
    VERIFY = 'verify'
    ENCRYPT = 'encrypt'
    DECRYPT = 'decrypt'
    WRAP_KEY = 'wrap key'
    UNWRAP_KEY = 'unwrap key'
    DERIVE_KEY = 'derive key'
    DERIVE_BITS = 'derive bits'
    MAC_CREATE = 'MAC create'
    MAC_VERIFY = 'MAC verify'

  class Value(Enum):
    SIGN = 1
    VERIFY = 2
    ENCRYPT = 3
    DECRYPT = 4
    WRAP_KEY = 5
    UNWRAP_KEY = 6
    DERIVE_KEY = 7
    DERIVE_BITS = 8
    MAC_CREATE = 9
    MAC_VERIFY = 10


class EC2KeyType(metaclass=NameValueEnumsContainer):

  class Name(Enum):
    P_256 = 'P-256'
    P_384 = 'P-384'
    P_521 = 'P-521'

  class Value(Enum):
    P_256 = 1
    P_384 = 2
    P_521 = 3


class OKPKeyType(metaclass=NameValueEnumsContainer):

  class Name(Enum):
    X25519 = 'X25519'
    X448 = 'X448'
    ED25519 = 'Ed25519'
    ED448 = 'Ed448'

  class Value(Enum):
    X25519 = 4
    X448 = 5
    ED25519 = 6
    ED448 = 7


class CredentialPublicKey:

  def __init__(
      self, *, kty: Union[COSEKeyType.Name, COSEKeyType.Value],
      kid: Optional[bytes] = None,
      alg:
        Optional[
          Union[
            COSEAlgorithmIdentifier.Name,
            COSEAlgorithmIdentifier.Value]] = None,
      key_ops:
        Optional[
          Sequence[
            Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]] = None,
      base_IV: Optional[bytes] = None):
    self.kty = kty
    self.kid = kid
    self.alg = alg
    self.key_ops = key_ops
    self.base_IV = base_IV


class EC2CredentialPublicKey(CredentialPublicKey):

  def __init__(
      self, *, kty: Union[COSEKeyType.Name, COSEKeyType.Value],
      kid: Optional[bytes] = None,
      alg:
        Optional[
          Union[
            COSEAlgorithmIdentifier.Name,
            COSEAlgorithmIdentifier.Value]] = None,
      key_ops:
        Optional[
          Sequence[
            Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]] = None,
      base_IV: Optional[bytes] = None,
      x: bytes,
      y: bytes,
      crv: Union[EC2KeyType.Name, EC2KeyType.Value]):
    super().__init__(
      kty=kty, kid=kid, alg=alg, key_ops=key_ops, base_IV=base_IV)
    self.x = x
    self.y = y
    self.crv = crv


class OKPCredentialPublicKey(CredentialPublicKey):

  def __init__(
      self, *, kty: Union[COSEKeyType.Name, COSEKeyType.Value],
      kid: Optional[bytes] = None,
      alg:
        Optional[
          Union[
            COSEAlgorithmIdentifier.Name,
            COSEAlgorithmIdentifier.Value]] = None,
      key_ops:
        Optional[
          Sequence[
            Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]] = None,
      base_IV: Optional[bytes] = None,
      crv: Union[OKPKeyType.Name, OKPKeyType.Value],
      x: bytes,
      d: bytes):
    super().__init__(
      kty=kty, kid=kid, alg=alg, key_ops=key_ops, base_IV=base_IV)
    self.crv = crv
    self.x = x
    self.d = d


class AttestedCredentialData:

  def __init__(
      self, aaguid: bytes, credential_id_length: int, credential_id: bytes,
      credential_public_key: Optional[CredentialPublicKey] = None,
      extensions: Optional[AuthenticationExtensionsClientOutputs] = None):
    self.aaguid = aaguid
    self.credential_id_length = credential_id_length
    self.credential_id = credential_id
    self.credential_public_key = credential_public_key
    self.extensions = extensions


class AuthenticatorData:

  def __init__(
      self, *, rp_id_hash: bytes, flags: int, sign_count: int,
      attested_credential_data: Optional[AttestedCredentialData] = None):
    self.rp_id_hash = rp_id_hash
    self.flags = flags
    self.sign_count = sign_count
    self.attested_credential_data = attested_credential_data


class AttestationStatementFormatIdentifier(Enum):
  PACKED = 'packed'
  TPM = 'tpm'
  ANDROID_KEY = 'android-key'
  ANDROID_SAFETYNET = 'android-safetynet'
  FIDO_U2F = 'fido-u2f'
  NONE = 'none'


class AttestationType(Enum):
  BASIC = 'Basic'
  ATTCA = 'AttCA'
  ECDAA = 'ECDAA'
  SELF = 'Self'
  NONE = 'None'
  UNCERTAIN = 'Uncertain'


class AttestationStatement:
  def __init__(
      self, *, alg: Optional[COSEAlgorithmIdentifier] = None,
      sig: Optional[bytes] = None):
    self.alg = alg
    self.sig = sig


class PackedAttestationStatement(AttestationStatement):

  def __init__(self, *, alg: COSEAlgorithmIdentifier, sig: bytes):
    super().__init__(alg=alg, sig=sig)


class PackedX509AttestationStatement(PackedAttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes, x5c: Sequence[bytes]):
    super().__init__(alg=alg, sig=sig)
    self.x5c = x5c


class PackedECDAAAttestationStatement(PackedAttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes, ecdaa_key_id: bytes):
    super().__init__(alg=alg, sig=sig)
    self.ecdaa_key_id = ecdaa_key_id


class TPMAttestationStatement(AttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes, ver: str,
      cert_info: bytes, pub_area: bytes):
    super().__init__(alg=alg, sig=sig)
    self.ver = ver
    self.cert_info = cert_info
    self.pub_area = pub_area


class TPMX509AttestationStatement(TPMAttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes, ver: str,
      cert_info: bytes, pub_area: bytes, x5c: Sequence[bytes]):
    super().__init__(
      self, alg=alg, sig=sig, ver=ver, cert_info=cert_info, pub_area=pub_area)
    self.x5c = x5c


class TPMECDAAAttestationStatement(TPMAttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes, ver: str,
      cert_info: bytes, pub_area: bytes, ecdaa_key_id: bytes):
    super().__init__(
      self, alg=alg, sig=sig, ver=ver, cert_info=cert_info, pub_area=pub_area)
    self.ecdaa_key_id = ecdaa_key_id


class AndroidKeyAttestationStatement(AttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes,
      x5c: Sequence[bytes]):
    super().__init__(alg=alg, sig=sig)
    self.x5c = x5c


class AndroidSafetyNetAttestationStatement(AttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes, ver: str,
      response: bytes):
    super().__init__(alg=alg, sig=sig)
    self.ver = ver
    self.response = response


class FIDOU2FAttestationStatement(AttestationStatement):

  def __init__(
      self, *, alg: COSEAlgorithmIdentifier, sig: bytes,
      x5c: Sequence[bytes]):
    super().__init__(alg=alg, sig=sig)
    self.x5c = x5c


class NoneAttestationStatement(AttestationStatement):
  pass


class AttestationObject:
  """
  Authenticators MUST also provide some form of attestation. The basic
  requirement is that the authenticator can produce, for each credential public
  key, an attestation statement verifiable by the WebAuthn Relying Party.
  Typically, this attestation statement contains a signature by an attestation
  private key over the attested credential public key and a challenge, as well
  as a certificate or similar data providing provenance information for the
  attestation public key, enabling the Relying Party to make a trust decision.
  However, if an attestation key pair is not available, then the authenticator
  MUST perform self attestation of the credential public key with the
  corresponding credential private key. All this information is returned by
  authenticators any time a new public key credential is generated, in the
  overall form of an attestation object.

  """

  def __init__(
      self, *, auth_data: AuthenticatorData,
      fmt: AttestationStatementFormatIdentifier,
      att_stmt: AttestationStatement):
    self.auth_data = auth_data
    self.fmt = fmt
    self.att_stmt = att_stmt