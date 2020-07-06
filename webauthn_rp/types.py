from enum import Enum
from typing import NamedTuple, Optional, Sequence, Union

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.asymmetric.ed448 import (Ed448PrivateKey,
                                                             Ed448PublicKey)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.x509 import Certificate

from webauthn_rp.utils import camel_to_snake_case

__all__ = [
    'EC2PublicKey',
    'OKPPublicKey',
    'EC2PrivateKey',
    'OKPPrivateKey',
    'PublicKey',
    'PrivateKey',
    'TrustedPath',
    'JSONValue',
    'Origin',
    'PublicKeyCredentialEntity',
    'PublicKeyCredentialRpEntity',
    'PublicKeyCredentialUserEntity',
    'PublicKeyCredentialType',
    'AuthenticatorTransport',
    'COSEAlgorithmIdentifier',
    'PublicKeyCredentialParameters',
    'PublicKeyCredentialDescriptor',
    'AuthenticatorAttachment',
    'AttestationConveyancePreference',
    'UserVerificationRequirement',
    'TxAuthGenericArg',
    'Coordinates',
    'AAGUID',
    'AuthenticatorSelectionList',
    'AuthenticationExtensionsSupported',
    'UvmEntry',
    'UvmEntries',
    'AuthenticatorBiometricPerfBounds',
    'ExtensionIdentifier',
    'AuthenticationExtensionsClientInputs',
    'AuthenticationExtensionsClientOutputs',
    'AuthenticatorSelectionCriteria',
    'PublicKeyCredentialCreationOptions',
    'PublicKeyCredentialRequestOptions',
    'CredentialCreationOptions',
    'CredentialMediationRequirement',
    'CredentialRequestOptions',
    'AuthenticatorResponse',
    'AuthenticatorAttestationResponse',
    'AuthenticatorAssertionResponse',
    'Credential',
    'PublicKeyCredential',
    'TokenBindingStatus',
    'TokenBinding',
    'CollectedClientData',
    'AuthenticatorDataFlag',
    'COSEKeyType',
    'COSEKeyOperation',
    'EC2Curve',
    'OKPCurve',
    'CredentialPublicKey',
    'EC2CredentialPublicKey',
    'OKPCredentialPublicKey',
    'AttestedCredentialData',
    'AuthenticatorData',
    'AttestationStatementFormatIdentifier',
    'AttestationType',
    'AttestationStatement',
    'PackedAttestationStatement',
    'PackedX509AttestationStatement',
    'PackedECDAAAttestationStatement',
    'TPMAttestationStatement',
    'TPMX509AttestationStatement',
    'TPMECDAAAttestationStatement',
    'AndroidKeyAttestationStatement',
    'AndroidSafetyNetAttestationStatement',
    'FIDOU2FAttestationStatement',
    'NoneAttestationStatement',
    'AttestationObject',
]

EC2PublicKey = Union[EllipticCurvePublicKey]
OKPPublicKey = Union[Ed25519PublicKey, Ed448PublicKey]

EC2PrivateKey = Union[EllipticCurvePrivateKey]
OKPPrivateKey = Union[Ed25519PrivateKey, Ed448PrivateKey]

PublicKey = Union[EC2PublicKey, OKPPublicKey]
PrivateKey = Union[EC2PrivateKey, OKPPrivateKey]
TrustedPath = Optional[Sequence[Certificate]]

JSONValue = Union[dict, list, bool, int, float, str, None]


class Origin(NamedTuple):
    """An origin as defined by the standard.

  References:
    * https://www.w3.org/TR/html53/browsers.html#concept-cross-origin
  """
    scheme: str
    hostname: str
    port: int


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
    def __init__(self, *, name: str, icon: Optional[str] = None) -> None:
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
      id (str): A unique identifier for the Relying Party entity. By default, the
        RP ID for a WebAuthn operation is set to the caller’s origin's effective
        domain. This default MAY be overridden by the caller, as long as the 
        caller-specified RP ID value is a registrable domain suffix of or is 
        equal to the caller’s origin's effective domain.

    References:
      * https://w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity
      * https://w3.org/TR/webauthn/#dictdef-publickeycredentialentity
      * https://www.w3.org/TR/webauthn/#rp-id
    """
    def __init__(self,
                 *,
                 name: str,
                 icon: Optional[str] = None,
                 id: str) -> None:
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
    def __init__(self,
                 *,
                 name: str,
                 icon: Optional[str] = None,
                 id: bytes,
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


class _NameValueEnumsContainer(type):
    """
    A metaclass used to enable Enums that can take on a string and integer type
    for a name and value respectively.
    """
    Name: Enum
    Value: Enum

    def __call__(  # type: ignore
            cls: '_NameValueEnumsContainer',  # type: ignore
            value: Union[int, str]) -> Enum:
        if type(value) is int:
            return cls.Value(value)  # type: ignore
        elif type(value) is str:
            return cls.Name(value)  # type: ignore
        else:
            raise KeyError('Invalid key {}'.format(value))


class COSEAlgorithmIdentifier(metaclass=_NameValueEnumsContainer):
    """
    A COSEAlgorithmIdentifier's value is a number identifying a cryptographic
    algorithm. The algorithm identifiers SHOULD be values registered in the
    IANA COSE Algorithms registry.

    This Enum only contains algorithms that are internally supported. It can be
    extended upon further support. As Web Authentication mainly performs signing
    and verification, only algorithms that pertain to those operations are
    considered.

    References:
      * https://w3.org/TR/webauthn/#typedefdef-cosealgorithmidentifier
      * https://iana.org/assignments/cose/cose.xhtml#algorithms
    """
    class Name(Enum):
        ES256 = 'ES256'
        ES384 = 'ES384'
        ES512 = 'ES512'

        EDDSA = 'EdDSA'

    class Value(Enum):
        ES256 = -7
        ES384 = -35
        ES512 = -36

        EDDSA = -8


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
        alg: Union[COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]
    ) -> None:
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
      transports (Optional[Sequence[AuthenticatorTransport]]):
        This OPTIONAL member contains a hint as to how the client might
        communicate with the managing authenticator of the public key
        credential the caller is referring to.
    
    References:
      * https://w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
    """
    def __init__(
            self,
            *,
            type: PublicKeyCredentialType,
            id: bytes,
            transports: Optional[Sequence[AuthenticatorTransport]] = None
    ) -> None:
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
    """
    The input type of the txAuthGeneric extension.

    Attributes:
      content_type (str): MIME-Type of the content, e.g., "image/png"
      content (bytes): The byte string data.

    References
      * https://w3.org/TR/webauthn/#sctn-generic-txauth-extension
    """
    def __init__(self, *, content_type: str, content: bytes) -> None:
        self.content_type = content_type
        self.content = content


class Coordinates:
    """
    The geographic coordinate reference system used by the attributes in this
    interface is the World Geodetic System (2d) [WGS84]. No other reference
    system is supported.

    Attributes:
      latitude (float): Geographic latitude specified in decimal degrees.
      longitude (float): Geographic longitude specified in decimal degrees.
      altitude (Optional[float]): Denotes the height of the position, specified
        in meters above the ellipsoid established by
        http://earth-info.nga.mil/GandG/publications/tr8350.2/wgs84fin.pdf.
        If the implementation cannot provide altitude information, the value of
        this attribute must be null.
      accuracy (float):
        Denotes the accuracy level of the latitude and longitude coordinates.
        It is specified in meters and must be supported by all implementations.
        The value of the accuracy attribute must be a non-negative real number.
      altitude_accuracy (Optional[float]):
        Specified in meters. If the implementation cannot provide altitude
        information, the value of this attribute must be null. Otherwise, the
        value must be a non-negative real number.
      heading (Optional[float]):
        Denotes the direction of travel of the hosting device and is specified in
        degrees, where 0° ≤ heading < 360°, counting clockwise relative to the
        true north. If the implementation cannot provide heading information, the
        value of this attribute must be null. If the hosting device is stationary
        (i.e. the value of the speed attribute is 0), then the value of the
        heading attribute must be NaN.
      speed (Optional[float]):
        Denotes the magnitude of the horizontal component of the hosting device's
        current velocity and is specified in meters per second. If the
        implementation cannot provide speed information, the value of this
        attribute must be null. Otherwise, the value of the speed attribute must
        be a non-negative real number.
      
      Notes:
        * The accuracy and altitude_accuracy values returned by an implementation
          should correspond to a 95% confidence level.

      References:
        * https://w3.org/TR/webauthn/#sctn-location-extension
        * https://w3.org/TR/geolocation-API/#coordinates_interface
    """
    def __init__(self,
                 *,
                 latitude: float,
                 longitude: float,
                 altitude: Optional[float] = None,
                 accuracy: float,
                 altitude_accuracy: Optional[float] = None,
                 heading: Optional[float] = None,
                 speed: Optional[float] = None) -> None:
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
    """
    Biometric performance bounds.

    Attributes:
      FAR (float): The maximum false acceptance rate for a biometric
        authenticator allowed by the Relying Party.
      FRR (float): The maximum false rejection rate for a biometric authenticator
        allowed by the Relying Party.
    
    References:
      * w3.org/TR/webauthn/#sctn-authenticator-biometric-criteria-extension
    """
    def __init__(self, *, FAR: float, FRR: float) -> None:
        self.FAR = FAR
        self.FRR = FRR


class ExtensionIdentifier(Enum):
    """
    The string identifier of supported extensions.

    Attributes:
      APPID (str):
        This extension allows WebAuthn Relying Parties that have previously
        registered a credential using the legacy FIDO JavaScript APIs to request
        an assertion. The FIDO APIs use an alternative identifier for Relying
        Parties called an AppID [FIDO-APPID], and any credentials created using
        those APIs will be scoped to that identifier. Without this extension,
        they would need to be re-registered in order to be scoped to an RP ID.

        This extension does not allow FIDO-compatible credentials to be created.
        Thus, credentials created with WebAuthn are not backwards compatible with
        the FIDO JavaScript APIs.
      TX_AUTH_SIMPLE (str):
        This extension allows for a simple form of transaction authorization.
        A Relying Party can specify a prompt string, intended for display on a
        trusted device on the authenticator.
      TX_AUTH_GENERIC (str):
        This extension allows images to be used as transaction authorization
        prompts as well. This allows authenticators without a font rendering
        engine to be used and also supports a richer visual appearance.
      AUTHN_SEL (str):
        This extension allows a WebAuthn Relying Party to guide the selection of
        the authenticator that will be leveraged when creating the credential.
        It is intended primarily for Relying Parties that wish to tightly control
        the experience around credential creation.
      EXTS (str):
        This extension enables the WebAuthn Relying Party to determine which
        extensions the authenticator supports.
      UVI (str):
        This extension enables use of a user verification index.
      LOC (str):
        This extension provides the authenticator's current location to the
        WebAuthn Relying Party.
      UVM (str);
        This extension enables use of a user verification method.
      BIOMETRIC_PERF_BOUNDS (str):
        This extension allows WebAuthn Relying Parties to specify the desired
        performance bounds for selecting biometric authenticators as candidates
        to be employed in a registration ceremony.

    References:
      * https://w3.org/TR/webauthn/#sctn-defined-extensions
    """

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
    def key(self) -> str:
        return camel_to_snake_case(self.value)


class AuthenticationExtensionsClientInputs:
    """
    This is an object containing the client extension input values for zero or
    more WebAuthn extensions.

    Attributes:
      appid (Optional[str]): A single string specifying a FIDO AppID.
      tx_auth_simple (Optional[str]): A single string prompt.
      tx_auth_generic (Optional[TxAuthGenericArg]):
        An object containing generic inputs.
      authn_sel (Optional[AuthenticatorSelectionList]):
        A sequence of AAGUIDs. Each AAGUID corresponds to an authenticator model
        that is acceptable to the Relying Party for this credential creation. The
        list is ordered by decreasing preference.

        An AAGUID is defined as an array containing the globally unique
        identifier of the authenticator model being sought.
      exts (Optional[bool]):
        The Boolean value true to indicate that this extension is requested by
        the Relying Party.
      uvi (Optional[bool]):
        The Boolean value true to indicate that this extension is requested by
        the Relying Party.
      loc (Optional[bool]):
        The Boolean value true to indicate that this extension is requested by
        the Relying Party.
      uvm (Optional[bool]):
        The Boolean value true to indicate that this extension is requested by
        the Relying Party.
      biometric_perf_bounds (Optional[AuthenticatorBiometricPerfBounds]):
        The biometric performance bounds.

    References:
      * https://w3.org/TR/webauthn/#extensions
      * https://w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs
      * https://w3.org/TR/webauthn/#dictdef-authenticationextensionsclientoutputs
    """
    def __init__(
        self,
        *,
        appid: Optional[str] = None,
        tx_auth_simple: Optional[str] = None,
        tx_auth_generic: Optional[TxAuthGenericArg] = None,
        authn_sel: Optional[AuthenticatorSelectionList] = None,
        exts: Optional[bool] = None,
        uvi: Optional[bool] = None,
        loc: Optional[bool] = None,
        uvm: Optional[bool] = None,
        biometric_perf_bounds: Optional[
            AuthenticatorBiometricPerfBounds] = None
    ) -> None:
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

    Attributes:
      appid (Optional[bool]): If true, the AppID was used and thus, when
        verifying an assertion, the Relying Party MUST expect the rpIdHash to be
        the hash of the AppID, not the RP ID.
      tx_auth_simple (Optional[str]):
        The authenticator extension output string UTF-8 decoded into a string.
      tx_auth_generic (Optional[bytes]): A generic byte string.
      authn_sel (Optional[AuthenticatorSelectionList]):
        Returns the value true to indicate to the Relying Party that the
        extension was acted upon.
      exts (Optional[AuthenticationExtensionsSupported]):
        Returns the list of supported extensions as an array of extension
        identifier strings.
      uvi (Optional[bytes]):
        Returns the authenticator extension output as a byte string.
      loc (Optional[Coordinates]):
        Returns an object that encodes the location information in the
        authenticator extension output as a Coordinates value.
      uvm (Optional[UvmEntries]):
        Returns a sequence of UvmEntry objects which are 3-element arrays of
        numbers that encode the factors in the authenticator extension output.
      biometric_perf_bounds (Optional[bool]):
        Returns the value true to indicate to the Relying Party that the
        extension was acted upon.

    References:
      * https://w3.org/TR/webauthn/#dictdef-authenticationextensionsclientoutputs
    """
    def __init__(self,
                 *,
                 appid: Optional[bool] = None,
                 tx_auth_simple: Optional[str] = None,
                 tx_auth_generic: Optional[bytes] = None,
                 authn_sel: Optional[bool] = None,
                 exts: Optional[AuthenticationExtensionsSupported] = None,
                 uvi: Optional[bytes] = None,
                 loc: Optional[Coordinates] = None,
                 uvm: Optional[UvmEntries] = None,
                 biometric_perf_bounds: Optional[bool] = None) -> None:
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
        self,
        *,
        authenticator_attachment: Optional[AuthenticatorAttachment] = None,
        require_resident_key: bool = False,
        user_verification:
        UserVerificationRequirement = UserVerificationRequirement.PREFERRED
    ) -> None:
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
        self,
        *,
        rp: PublicKeyCredentialRpEntity,
        user: PublicKeyCredentialUserEntity,
        challenge: bytes,
        pub_key_cred_params: Sequence[PublicKeyCredentialParameters],
        timeout: Optional[int] = None,
        authenticator_selection: Optional[
            AuthenticatorSelectionCriteria] = None,
        extensions: Optional[AuthenticationExtensionsClientInputs] = None,
        attestation:
        AttestationConveyancePreference = AttestationConveyancePreference.NONE,
        exclude_credentials: Optional[
            Sequence[PublicKeyCredentialDescriptor]] = None
    ) -> None:
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
      timeout (Optional[int]): This OPTIONAL member specifies a time, in milliseconds,
        that the caller is willing to wait for the call to complete. The value
        is treated as a hint, and MAY be overridden by the client.
      rp_id (Optional[str]): This OPTIONAL member specifies the relying party identifier
        claimed by the caller. If omitted, its value will be the
        CredentialsContainer object’s relevant settings object's origin's
        effective domain.
      extensions (AuthenticationExtensionsClientInputs): 
      allow_credentials (Optional[Sequence[PublicKeyCredentialDescriptor]]):
        This OPTIONAL member contains a list of PublicKeyCredentialDescriptor
        objects representing public key credentials acceptable to the caller,
        in descending order of the caller’s preference (the first item in the
        list is the most preferred credential, and so on down the list).
      user_verification (Optional[UserVerificationRequirement]):
        This OPTIONAL member describes the Relying Party's requirements
        regarding user verification for the navigator.credentials.get() operation
        (on the client side). Eligible authenticators are filtered to only those
        capable of satisfying this requirement.

    References:
      * https://w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
    """
    def __init__(
        self,
        *,
        challenge: bytes,
        timeout: Optional[int] = None,
        rp_id: Optional[str] = None,
        extensions: Optional[AuthenticationExtensionsClientInputs] = None,
        allow_credentials: Optional[
            Sequence[PublicKeyCredentialDescriptor]] = None,
        user_verification: Optional[UserVerificationRequirement] = (
            UserVerificationRequirement.PREFERRED)
    ) -> None:
        self.challenge = challenge
        self.timeout = timeout
        self.rp_id = rp_id
        self.allow_credentials = allow_credentials
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
    def __init__(self, *,
                 public_key: PublicKeyCredentialCreationOptions) -> None:
        self.public_key = public_key


class CredentialMediationRequirement(Enum):
    """
    When making a request via get(options), developers can set a case-by-case
    requirement for user mediation by choosing the appropriate
    CredentialMediationRequirement enum value.

    Attributes:
      SILENT (str):
        User mediation is suppressed for the given operation. If the operation
        can be performed without user involvement, wonderful. If user involvement
        is necessary, then the operation will return null rather than involving
        the user.
      OPTIONAL (str):
        If credentials can be handed over for a given operation without user
        mediation, they will be. If user mediation is required, then the user
        agent will involve the user in the decision.
      REQUIRED (str):
        The user agent will not hand over credentials without user mediation,
        even if the prevent silent access flag is unset for an origin.
    
    References:
      * https://w3.org/TR/credential-management-1/#mediation-requirements
    """

    SILENT = 'silent'
    OPTIONAL = 'optional'
    REQUIRED = 'required'


class CredentialRequestOptions:
    """
    The object used to obtain assertions using the
    navigator.credentials.get() function on the client side.

    Attributes:
      mediation (CredentialMediationRequirement):
        Specifies the mediation requirements for a given credential request.
      public_key (PublicKeyCredentialRequestOptions):
        The request options for the public key credential.

    References:
      * https://w3.org/TR/webauthn/#credentialrequestoptions-extension
      * https://w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions
    """
    def __init__(self,
                 *,
                 mediation: CredentialMediationRequirement = (
                     CredentialMediationRequirement.OPTIONAL),
                 public_key: PublicKeyCredentialRequestOptions) -> None:
        self.mediation = mediation
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
    def __init__(self, *, client_data_JSON: bytes) -> None:
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
    def __init__(self, *, client_data_JSON: bytes,
                 attestation_object: bytes) -> None:
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
      user_handle (Optional[bytes]): This attribute contains the user handle returned from
        the authenticator, or null if the authenticator did not return a user handle.

    References:
      * https://w3.org/TR/webauthn/#authenticatorassertionresponse
      * https://w3.org/TR/webauthn/#authenticatorresponse
    """
    def __init__(self,
                 *,
                 client_data_JSON: bytes,
                 authenticator_data: bytes,
                 signature: bytes,
                 user_handle: Optional[bytes] = None) -> None:
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
    def __init__(self, *, id: str, type: str) -> None:
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
    def __init__(self, *, id: str, type: str, raw_id: bytes,
                 response: AuthenticatorResponse) -> None:
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
    def __init__(self,
                 *,
                 status: TokenBindingStatus,
                 id: Optional[str] = None) -> None:
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
      token_binding (Optional[TokenBinding]): This OPTIONAL member contains
        information about the state of the Token Binding protocol used when the
        client was communicating with the Relying Party. Its absence 
        that the client doesn’t support token binding.

    References:
      * https://w3.org/TR/webauthn/#dictdef-collectedclientdata
    """
    def __init__(self,
                 *,
                 type: str,
                 challenge: str,
                 origin: str,
                 token_binding: Optional[TokenBinding] = None) -> None:
        self.type = type
        self.challenge = challenge
        self.origin = origin
        self.token_binding = token_binding


class AuthenticatorDataFlag(Enum):
    """
    The authenticator data bit flags.

    Attributes:
      UP (int): User is present.
      RFU1 (int): Reserved for future use.
      UV (int): User is verified.
      RFU2 (int): Reserved for future use.
      AT (int): Attested credential data included.
      ED (int): Extension data is included in the authenticator data.
      
    References:
      * https://w3.org/TR/webauthn/#sec-authenticator-data
    """

    UP = 1 << 0
    RFU1 = 1 << 1
    UV = 1 << 2
    RFU2 = (1 << 3) | (1 << 4) | (1 << 5)
    AT = 1 << 6
    ED = 1 << 7


class COSEKeyType(metaclass=_NameValueEnumsContainer):
    """
    A metaclass for the COSEKeyOperation Name and Value Enums.
    
    Both the Name and Value Enums share the following documentation.

    The COSEKeyType object defines a way to hold a single key object. It is still
    required that the members of individual key types be defined.

    Attributes:
      OKP: Octet Key Pair
      EC2: Elliptic Curve Keys with X, Y Coordinate pair
      SYMMETRIC: Symmetric Keys
    
    References:
      * https://cose-wg.github.io/cose-spec/#rfc.section.13
    """
    class Name(Enum):
        OKP = 'OKP'
        EC2 = 'EC2'
        SYMMETRIC = 'Symmetric'

    class Value(Enum):
        OKP = 1
        EC2 = 2
        SYMMETRIC = 4


class COSEKeyOperation(metaclass=_NameValueEnumsContainer):
    """
    A metaclass for the COSEKeyOperation Name and Value Enums.

    Both the Name and Value Enums share the following documentation.

    The COSEKeyOperation object specifies the type of operations that are
    permitted for the COSE Key.

    Attributes:
      SIGN: The key is used to create signatures. Requires private key fields.
      VERIFY: The key is used for verification of signatures.
      ENCRYPT: The key is used for key transport encryption.
      DECRYPT: The key is used for key transport decryption. Requires private key
        fields.
      WRAP_KEY: The key is used for key wrapping.
      UNWRAP_KEY: The key is used for key unwrapping. Requires private key
        fields.
      DERIVE_KEY: The key is used for deriving keys. Requires private key fields.
      DERIVE_BITS: The key is used for deriving bits not to be used as a key.
        Requires private key fields.
      MAC_CREATE: The key is used for creating MACs.
      MAC_VERIFY: The key is used for validating MACs.

    References:
      * https://cose-wg.github.io/cose-spec/#rfc.section.7.1
    """
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


class EC2Curve(metaclass=_NameValueEnumsContainer):
    """
    A metaclass for the EC2Curve Name and Value Enums.

    Both the Name and Value Enums share the following documentation.

    Attributes:
      P_256: NIST P-256 also known as secp256r1.
      P_384: NIST P-384 also known as secp384r1.
      P_521: NIST P-521 also known as secp521r1.

    References:
      * https://cose-wg.github.io/cose-spec/#rfc.section.13.1
    """
    class Name(Enum):
        P_256 = 'P-256'
        P_384 = 'P-384'
        P_521 = 'P-521'

    class Value(Enum):
        P_256 = 1
        P_384 = 2
        P_521 = 3


class OKPCurve(metaclass=_NameValueEnumsContainer):
    """
    A metaclass for the OKPCurve Name and Value Enums.

    Both the Name and Value Enums share the following documentation.

    Attributes:
      ED25519: Ed25519 for use with EdDSA only.
      ED448: Ed448 for use with EdDSA only.

    References:
      * https://cose-wg.github.io/cose-spec/#rfc.section.13.1
    """
    class Name(Enum):
        ED25519 = 'Ed25519'
        ED448 = 'Ed448'

    class Value(Enum):
        ED25519 = 6
        ED448 = 7


class CredentialPublicKey:
    """
    The credential public key encoded in COSE_Key format.

    Attributes:
      kty (Union[COSEKeyType.Name, COSEKeyType.Value]):
        This parameter is used to identify the family of keys for this structure,
        and thus the set of key type specific parameters to be found. This 
        parameter MUST be present in a key object. Implementations MUST verify
        that the key type is appropriate for the algorithm being processed. The
        key type MUST be included as part of the trust decision process.
      kid (Optional[bytes]):
        This parameter is used to give an identifier for a key. The identifier is
        not structured and can be anything from a user provided string to a value
        computed on the public portion of the key. This field is intended for
        matching against a 'kid' parameter in a message in order to filter down
        the set of keys that need to be checked.
      alg (Optional[
        Union[COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]]):
        This parameter is used to restrict the algorithm that is used with the
        key. If this parameter is present in the key structure, the application
        MUST verify that this algorithm matches the algorithm for which the key
        is being used. If the algorithms do not match, then this key object MUST
        NOT be used to perform the cryptographic operation. Note that the same
        key can be in a different key structure with a different or no algorithm
        specified, however this is considered to be a poor security practice.
      key_ops (Optional[
        Sequence[Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]]):
        This parameter is defined to restrict the set of operations that a key is
        to be used for. Algorithms define the values of key ops that are
        permitted to appear and are required for specific operations.
      base_IV (Optional[bytes]): 
        This parameter is defined to carry the base portion of an IV. This field
        provides the ability to associate a partial IV with a key that is then
        modified on a per message basis with the partial IV. Extreme care needs
        to be taken when using a Base IV in an application. Many encryption
        algorithms lose security if the same IV is used twice.

    References:
      * https://w3.org/TR/webauthn/#sec-attested-credential-data
      * https://cose-wg.github.io/cose-spec/#rfc.section.7
      * https://cose-wg.github.io/cose-spec/#rfc.section.7.1
    """
    def __init__(self,
                 *,
                 kty: Union[COSEKeyType.Name, COSEKeyType.Value],
                 kid: Optional[bytes] = None,
                 alg: Optional[Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value]] = None,
                 key_ops: Optional[Sequence[Union[
                     COSEKeyOperation.Name, COSEKeyOperation.Value]]] = None,
                 base_IV: Optional[bytes] = None) -> None:
        self.kty = kty
        self.kid = kid
        self.alg = alg
        self.key_ops = key_ops
        self.base_IV = base_IV


class EC2CredentialPublicKey(CredentialPublicKey):
    """
    The Elliptic Curve Cryptography (EC2) credential public key encoded in
    COSE_Key format.

    Attributes:
      kty (Union[COSEKeyType.Name, COSEKeyType.Value]):
        This parameter is used to identify the family of keys for this structure,
        and thus the set of key type specific parameters to be found. This 
        parameter MUST be present in a key object. Implementations MUST verify
        that the key type is appropriate for the algorithm being processed. The
        key type MUST be included as part of the trust decision process.
      kid (Optional[bytes]):
        This parameter is used to give an identifier for a key. The identifier is
        not structured and can be anything from a user provided string to a value
        computed on the public portion of the key. This field is intended for
        matching against a 'kid' parameter in a message in order to filter down
        the set of keys that need to be checked.
      alg (Optional[
        Union[COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]]):
        This parameter is used to restrict the algorithm that is used with the
        key. If this parameter is present in the key structure, the application
        MUST verify that this algorithm matches the algorithm for which the key
        is being used. If the algorithms do not match, then this key object MUST
        NOT be used to perform the cryptographic operation. Note that the same
        key can be in a different key structure with a different or no algorithm
        specified, however this is considered to be a poor security practice.
      key_ops (Optional[
        Sequence[Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]]):
        This parameter is defined to restrict the set of operations that a key is
        to be used for. Algorithms define the values of key ops that are
        permitted to appear and are required for specific operations.
      base_IV (Optional[bytes]): 
        his parameter is defined to carry the base portion of an IV. This field
        provides the ability to associate a partial IV with a key that is then
        modified on a per message basis with the partial IV. Extreme care needs
        to be taken when using a Base IV in an application. Many encryption
        algorithms lose security if the same IV is used twice.
      x (bytes): The Elliptic Curve X Coordinate.
      y (bytes): The Elliptic Curve Y Coordinate.
      crv (Union[EC2Curve.Name, EC2Curve.Value]):
        The Elliptic Curve Identifier.

    References:
      * https://w3.org/TR/webauthn/#sec-attested-credential-data
      * https://cose-wg.github.io/cose-spec/#rfc.section.7
      * https://cose-wg.github.io/cose-spec/#rfc.section.7.1
      * https://cose-wg.github.io/cose-spec/#rfc.section.13.1
      * https://cose-wg.github.io/cose-spec/#rfc.section.13.1.1
    """
    def __init__(self,
                 *,
                 kty: Union[COSEKeyType.Name, COSEKeyType.Value],
                 kid: Optional[bytes] = None,
                 alg: Optional[Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value]] = None,
                 key_ops: Optional[Sequence[Union[
                     COSEKeyOperation.Name, COSEKeyOperation.Value]]] = None,
                 base_IV: Optional[bytes] = None,
                 x: bytes,
                 y: bytes,
                 crv: Union[EC2Curve.Name, EC2Curve.Value]) -> None:
        super().__init__(kty=kty,
                         kid=kid,
                         alg=alg,
                         key_ops=key_ops,
                         base_IV=base_IV)
        self.x = x
        self.y = y
        self.crv = crv


class OKPCredentialPublicKey(CredentialPublicKey):
    """
    The Octet Key Pair (OKP) credential public key encoded in COSE_Key format.

    Attributes:
      kty (Union[COSEKeyType.Name, COSEKeyType.Value]):
        This parameter is used to identify the family of keys for this structure,
        and thus the set of key type specific parameters to be found. This 
        parameter MUST be present in a key object. Implementations MUST verify
        that the key type is appropriate for the algorithm being processed. The
        key type MUST be included as part of the trust decision process.
      kid (Optional[bytes]):
        This parameter is used to give an identifier for a key. The identifier is
        not structured and can be anything from a user provided string to a value
        computed on the public portion of the key. This field is intended for
        matching against a 'kid' parameter in a message in order to filter down
        the set of keys that need to be checked.
      alg (Optional[
        Union[COSEAlgorithmIdentifier.Name, COSEAlgorithmIdentifier.Value]]):
        This parameter is used to restrict the algorithm that is used with the
        key. If this parameter is present in the key structure, the application
        MUST verify that this algorithm matches the algorithm for which the key
        is being used. If the algorithms do not match, then this key object MUST
        NOT be used to perform the cryptographic operation. Note that the same
        key can be in a different key structure with a different or no algorithm
        specified, however this is considered to be a poor security practice.
      key_ops (Optional[
        Sequence[Union[COSEKeyOperation.Name, COSEKeyOperation.Value]]]):
        This parameter is defined to restrict the set of operations that a key is
        to be used for. Algorithms define the values of key ops that are
        permitted to appear and are required for specific operations.
      base_IV (Optional[bytes]): 
        his parameter is defined to carry the base portion of an IV. This field
        provides the ability to associate a partial IV with a key that is then
        modified on a per message basis with the partial IV. Extreme care needs
        to be taken when using a Base IV in an application. Many encryption
        algorithms lose security if the same IV is used twice.
      x (bytes): The Elliptic Curve X Coordinate.
      y (bytes): The Elliptic Curve Y Coordinate.
      crv (Union[OKPCurve.Name, OKPCurve.Value]):
        The Elliptic Curve Identifier.

    References:
      * https://w3.org/TR/webauthn/#sec-attested-credential-data
      * https://cose-wg.github.io/cose-spec/#rfc.section.7
      * https://cose-wg.github.io/cose-spec/#rfc.section.7.1
      * https://cose-wg.github.io/cose-spec/#rfc.section.13.1
      * https://cose-wg.github.io/cose-spec/#rfc.section.13.2
    """
    def __init__(self,
                 *,
                 kty: Union[COSEKeyType.Name, COSEKeyType.Value],
                 kid: Optional[bytes] = None,
                 alg: Optional[Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value]] = None,
                 key_ops: Optional[Sequence[Union[
                     COSEKeyOperation.Name, COSEKeyOperation.Value]]] = None,
                 base_IV: Optional[bytes] = None,
                 crv: Union[OKPCurve.Name, OKPCurve.Value],
                 x: bytes) -> None:
        super().__init__(kty=kty,
                         kid=kid,
                         alg=alg,
                         key_ops=key_ops,
                         base_IV=base_IV)
        self.crv = crv
        self.x = x


class AttestedCredentialData:
    """
    Attested credential data is a variable-length byte array added to the
    authenticator data when generating an attestation object for a given
    credential.

    Attributes:
      aaguid (bytes): The AAGUID of the authenticator.
        Each authenticator has an AAGUID, which is a 128-bit identifier
        indicating the type (e.g. make and model) of the authenticator. The
        AAGUID MUST be chosen by the manufacturer to be identical across all
        substantially identical authenticators made by that manufacturer, and
        different (with high probability) from the AAGUIDs of all other types of
        authenticators. The AAGUID for a given type of authenticator SHOULD be
        randomly generated to ensure this. The Relying Party MAY use the AAGUID
        to infer certain properties of the authenticator, such as certification
        level and strength of key protection, using information from other
        sources.
      credential_id_length (int): Byte length of Credential ID, parsed from a
        16-bit unsigned big-endian integer.
      credential_id (bytes):
        A probabilistically-unique byte sequence identifying a public key
        credential source and its authentication assertions.
      credential_public_key (Optional[CredentialPublicKey]):
        The credential public key encoded in COSE_Key format. The
        COSE_Key-encoded credential public key MUST contain the "alg" parameter
        and MUST NOT contain any other OPTIONAL parameters. The "alg" parameter
        MUST contain a COSEAlgorithmIdentifier value. The encoded credential
        public key MUST also contain any additional REQUIRED parameters
        stipulated by the relevant key type specification, i.e., REQUIRED for the
        key type "kty" and algorithm "alg".

    References:
      * https://w3.org/TR/webauthn/#sec-attested-credential-data
      * https://w3.org/TR/webauthn/#aaguid
      * https://w3.org/TR/webauthn/#credential-id
      * https://www.w3.org/TR/webauthn/#credential-public-key
    """
    def __init__(
            self,
            aaguid: bytes,
            credential_id_length: int,
            credential_id: bytes,
            credential_public_key: Optional[CredentialPublicKey] = None
    ) -> None:
        self.aaguid = aaguid
        self.credential_id_length = credential_id_length
        self.credential_id = credential_id
        self.credential_public_key = credential_public_key


class AuthenticatorData:
    """
    The authenticator data structure encodes contextual bindings made by the
    authenticator. These bindings are controlled by the authenticator itself, and
    derive their trust from the WebAuthn Relying Party's assessment of the
    security properties of the authenticator. In one extreme case, the
    authenticator may be embedded in the client, and its bindings may be no more
    trustworthy than the client data. At the other extreme, the authenticator may
    be a discrete entity with high-security hardware and software, connected to
    the client over a secure channel. In both cases, the Relying Party receives
    the authenticator data in the same format, and uses its knowledge of the
    authenticator to make trust decisions.

    Attributes:
      rp_id_hash (bytes): SHA-256 hash of the RP ID the credential is scoped to.
      flags (int): 8 flag bits for the authenticator data.
      sign_count (int):
        Signature counter parsed from a 32-bit unsigned big-endian integer.
      attested_credential_data (Optional[AttestedCredentialData]):
        The attested credential data.
      extensions (Optional[AuthenticationExtensionsClientOutputs]):
        Extension-defined authenticator data.

    References:
      * https://w3.org/TR/webauthn/#authenticator-data
    """
    def __init__(
        self,
        *,
        rp_id_hash: bytes,
        flags: int,
        sign_count: int,
        attested_credential_data: Optional[AttestedCredentialData] = None,
        extensions: Optional[AuthenticationExtensionsClientOutputs] = None
    ) -> None:
        self.rp_id_hash = rp_id_hash
        self.flags = flags
        self.sign_count = sign_count
        self.attested_credential_data = attested_credential_data
        self.extensions = extensions


class AttestationStatementFormatIdentifier(Enum):
    """
    Attestation statement formats are identified by a string, called an
    attestation statement format identifier, chosen by the author of the
    attestation statement format.

    Attributes:
      PACKED (str):
        This is a WebAuthn optimized attestation statement format. It uses a very
        compact but still extensible encoding method. It is implementable by
        authenticators with limited resources (e.g., secure elements).
      TPM (str):
        This attestation statement format is generally used by authenticators
        that use a Trusted Platform Module as their cryptographic engine.
      ANDROID_KEY (str):
        When the authenticator in question is a platform-provided Authenticator
        on the Android "N" or later platform, the attestation statement is based
        on the Android key attestation. In these cases, the attestation statement
        is produced by a component running in a secure operating environment, but
        the authenticator data for the attestation is produced outside this
        environment. The WebAuthn Relying Party is expected to check that the
        authenticator data claimed to have been used for the attestation is
        consistent with the fields of the attestation certificate’s extension
        data.
      ANDROID_SAFETYNET (str):
        When the authenticator in question is a platform-provided Authenticator
        on certain Android platforms, the attestation statement is based on the
        SafetyNet API. In this case the authenticator data is completely
        controlled by the caller of the SafetyNet API (typically an application
        running on the Android platform) and the attestation statement only
        provides some statements about the health of the platform and the
        identity of the calling application. This attestation does not provide
        information regarding provenance of the authenticator and its associated
        data. Therefore platform-provided authenticators SHOULD make use of the
        Android Key Attestation when available, even if the SafetyNet API is also
        present.
      FIDO_U2F (str):
        This attestation statement format is used with FIDO U2F authenticators.
      NONE (str):
        The none attestation statement format is used to replace any
        authenticator-provided attestation statement when a WebAuthn Relying
        Party indicates it does not wish to receive attestation information.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement-format-identifier
    """

    PACKED = 'packed'
    TPM = 'tpm'
    ANDROID_KEY = 'android-key'
    ANDROID_SAFETYNET = 'android-safetynet'
    FIDO_U2F = 'fido-u2f'
    NONE = 'none'


class AttestationType(Enum):
    """
    WebAuthn supports several attestation types, defining the semantics of
    attestation statements and their underlying trust models.

    Attributes:
      BASIC (str):
        In the case of basic attestation, the authenticator’s attestation key pair
        is specific to an authenticator model. Thus, authenticators of the same
        model often share the same attestation key pair.
      SELF (str):
        In the case of self attestation, also known as surrogate basic attestation,
        the Authenticator does not have any specific attestation key. Instead it
        uses the credential private key to create the attestation signature.
        Authenticators without meaningful protection measures for an attestation
        private key typically use this attestation type.
      ATTCA (str):
        In this case, an authenticator is based on a Trusted Platform Module (TPM)
        and holds an authenticator-specific "endorsement key" (EK). This key is
        used to securely communicate with a trusted third party, the Attestation CA
        (formerly known as a "Privacy CA"). The authenticator can generate multiple
        attestation identity key pairs (AIK) and requests an Attestation CA to
        issue an AIK certificate for each. Using this approach, such an
        authenticator can limit the exposure of the EK (which is a global
        correlation handle) to Attestation CA(s). AIKs can be requested for each
        authenticator-generated public key credential individually, and conveyed
        to Relying Parties as attestation certificates.
      ECDAA (str):
        In this case, the Authenticator receives direct anonymous attestation (DAA)
        credentials from a single DAA-Issuer. These DAA credentials are used along
        with blinding to sign the attested credential data. The concept of blinding
        avoids the DAA credentials being misused as global correlation handle.
        WebAuthn supports DAA using elliptic curve cryptography and bilinear
        pairings, called ECDAA in this specification. Consequently we denote the
        DAA-Issuer as ECDAA-Issuer.
      NONE (str): In this case, no attestation information is available.
      UNCERTAIN (str): In this case, the attestation type is uncertain.

    References:
      * https://w3.org/TR/webauthn/#sctn-attestation-types
    """

    BASIC = 'Basic'
    ATTCA = 'AttCA'
    ECDAA = 'ECDAA'
    SELF = 'Self'
    NONE = 'None'
    UNCERTAIN = 'Uncertain'


class AttestationStatement:
    """
    An important component of the attestation object is the attestation
    statement. This is a specific type of signed data object, containing
    statements about a public key credential itself and the authenticator that
    created it. It contains an attestation signature created using the key of the
    attesting authority (except for the case of self attestation, when it is
    created using the credential private key). In order to correctly interpret an
    attestation statement, a Relying Party needs to understand these two aspects
    of attestation:

      1. The attestation statement format is the manner in which the signature is
      represented and the various contextual bindings are incorporated into the
      attestation statement by the authenticator. In other words, this defines
      the syntax of the statement. Various existing components and OS platforms
      (such as TPMs and the Android OS) have previously defined attestation
      statement formats.
      2. The attestation type defines the semantics of attestation statements and
      their underlying trust models. Specifically, it defines how a Relying Party
      establishes trust in a particular attestation statement, after verifying
      that it is cryptographically valid.

    Attributes:
      alg (Optional[COSEAlgorithmIdentifier]):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (Optional[bytes]): A byte string containing the attestation signature.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
    """
    def __init__(self,
                 *,
                 alg: Optional[Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value]] = None,
                 sig: Optional[bytes] = None) -> None:
        self.alg = alg
        self.sig = sig


class PackedAttestationStatement(AttestationStatement):
    """
    The Packed Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#packed-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes) -> None:
        super().__init__(alg=alg, sig=sig)


class PackedX509AttestationStatement(PackedAttestationStatement):
    """
    The Packed X.509 Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.
      x5c (Sequence[bytes]):
        The elements of this array contain the attestation certificate and its 
        certificate chain, each encoded in X.509 format. The attestation
        certificate MUST be the first element in the array.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#packed-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes, x5c: Sequence[bytes]) -> None:
        super().__init__(alg=alg, sig=sig)
        self.x5c = x5c


class PackedECDAAAttestationStatement(PackedAttestationStatement):
    """
    The Packed ECDAA Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.
      ecdaa_key_id (bytes):
        The identifier of the ECDAA-Issuer public key. This is the BigNumberToB
        encoding of the component "c" of the ECDAA-Issuer public key.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#packed-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes, ecdaa_key_id: bytes) -> None:
        super().__init__(alg=alg, sig=sig)
        self.ecdaa_key_id = ecdaa_key_id


class TPMAttestationStatement(AttestationStatement):
    """
    The TPM Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.
      ver (str):
        The version of the TPM specification to which the signature conforms.
      cert_info (bytes):
        The TPMS_ATTEST structure over which the above signature was computed.
      pub_area (bytes):
        The TPMT_PUBLIC structure used by the TPM to represent the credential
        public key.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#tpm-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes, ver: str, cert_info: bytes,
                 pub_area: bytes) -> None:
        super().__init__(alg=alg, sig=sig)
        self.ver = ver
        self.cert_info = cert_info
        self.pub_area = pub_area


class TPMX509AttestationStatement(TPMAttestationStatement):
    """
    The TPM X.509 Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.
      ver (str):
        The version of the TPM specification to which the signature conforms.
      cert_info (bytes):
        The TPMS_ATTEST structure over which the above signature was computed.
      pub_area (bytes):
        The TPMT_PUBLIC structure used by the TPM to represent the credential
        public key.
      x5c (Sequence[bytes]):
        The elements of this array contain the attestation certificate and its 
        certificate chain, each encoded in X.509 format. The attestation
        certificate MUST be the first element in the array.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#tpm-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes, ver: str, cert_info: bytes, pub_area: bytes,
                 x5c: Sequence[bytes]) -> None:
        super().__init__(alg=alg,
                         sig=sig,
                         ver=ver,
                         cert_info=cert_info,
                         pub_area=pub_area)
        self.x5c = x5c


class TPMECDAAAttestationStatement(TPMAttestationStatement):
    """
    The TPM ECDAA Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.
      ver (str):
        The version of the TPM specification to which the signature conforms.
      cert_info (bytes):
        The TPMS_ATTEST structure over which the above signature was computed.
      pub_area (bytes):
        The TPMT_PUBLIC structure used by the TPM to represent the credential
        public key.
      ecdaa_key_id (bytes):
        The identifier of the ECDAA-Issuer public key. This is the BigNumberToB
        encoding of the component "c" of the ECDAA-Issuer public key.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#tpm-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes, ver: str, cert_info: bytes, pub_area: bytes,
                 ecdaa_key_id: bytes) -> None:
        super().__init__(alg=alg,
                         sig=sig,
                         ver=ver,
                         cert_info=cert_info,
                         pub_area=pub_area)
        self.ecdaa_key_id = ecdaa_key_id


class AndroidKeyAttestationStatement(AttestationStatement):
    """
    The Android Key Attestation Statement.

    Attributes:
      alg (COSEAlgorithmIdentifier):
        A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        to generate the attestation signature.
      sig (bytes): A byte string containing the attestation signature.
      x5c (Sequence[bytes]):
        The elements of this array contain the attestation certificate and its 
        certificate chain, each encoded in X.509 format. The attestation
        certificate MUST be the first element in the array.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#android-key-attestation
    """
    def __init__(self, *, alg: Union[COSEAlgorithmIdentifier.Name,
                                     COSEAlgorithmIdentifier.Value],
                 sig: bytes, x5c: Sequence[bytes]) -> None:
        super().__init__(alg=alg, sig=sig)
        self.x5c = x5c


class AndroidSafetyNetAttestationStatement(AttestationStatement):
    """
    The Android SafetyNet Attestation Statement.

    Attributes:
      ver (str):
        The version number of Google Play Services responsible for providing the
        SafetyNet API.
      response (bytes):
        The UTF-8 encoded result of the getJwsResult() call of the SafetyNet API.
        This value is a JWS object (see SafetyNet online documentation) in
        Compact Serialization.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://w3.org/TR/webauthn/#android-safetynet-attestation
    """
    def __init__(self, *, ver: str, response: bytes) -> None:
        super().__init__(alg=None, sig=None)
        self.ver = ver
        self.response = response


class FIDOU2FAttestationStatement(AttestationStatement):
    """
    The FIDO U2F Attestation Statement.

    Attributes:
      sig (bytes):
        The attestation signature. The signature was calculated over the (raw)
        U2F registration response message received by the client from the
        authenticator.
      x5c (Sequence[bytes]):
        A single element array containing the attestation certificate in X.509
        format.

    References:
      * https://w3.org/TR/webauthn/#attestation-statement
      * https://www.w3.org/TR/webauthn/#fido-u2f-attestation
    """
    def __init__(self, *, sig: bytes, x5c: Sequence[bytes]) -> None:
        super().__init__(alg=None, sig=sig)
        self.x5c = x5c


class NoneAttestationStatement(AttestationStatement):
    """
    The None Attestation Statement. Consists of an empty object.

    References:
      * https://w3.org/TR/webauthn/#none-attestation
    """
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

    Attributes:
      auth_data (AuthenticatorData): The authenticator data.
      fmt (AttestationStatementFormatIdentifier):
        The format of the attestation statement.
      att_stmt (AttestationStatment): The attestation statement.

    References:
      * https://w3.org/TR/webauthn/#attestation-object
    """
    def __init__(self, *, auth_data: AuthenticatorData,
                 fmt: AttestationStatementFormatIdentifier,
                 att_stmt: AttestationStatement) -> None:
        self.auth_data = auth_data
        self.fmt = fmt
        self.att_stmt = att_stmt
