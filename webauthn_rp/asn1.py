from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.type.univ import (Boolean, Enumerated, Integer, Null, OctetString,
                              Sequence, SetOf)

__all__ = [
    'SecurityLevel',
    'VerifiedBootState',
    'RootOfTrust',
    'AuthorizationList',
    'KeyDescription',
]


class SecurityLevel(Enumerated):
    """The extent to which the key pair is protected.

    References:
      * https://developer.android.com/training/articles/security-key-attestation#certificate_schema_securitylevel
    """
    componentType = NamedValues(Software=0, TrustedEnvironment=1, StrongBox=2)


class VerifiedBootState(Enumerated):
    """The level of protection provided to the user and to apps after booting.

    References:
      * https://developer.android.com/training/articles/security-key-attestation#certificate_schema_verifiedbootstate
    """
    componentType = NamedValues(Verified=0,
                                SelfSigned=1,
                                Unverified=2,
                                Failed=3)


class RootOfTrust(Sequence):
    """Information about the device's status.

    References:
      * https://developer.android.com/training/articles/security-key-attestation#certificate_schema_rootoftrust
    """
    componentType = NamedTypes(
        NamedType('verifiedBootKey', OctetString()),
        NamedType('deviceLocked', Boolean()),
        NamedType('verifiedBootState', VerifiedBootState()),
        NamedType('verifiedBootHash', OctetString()),
    )


class AuthorizationList(Sequence):
    """Properties of the key pair as in the Keymaster hardware abstraction layer.

    References:
      * https://developer.android.com/training/articles/security-key-attestation#certificate_schema_authorizationlist
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'purpose',
            SetOf(Integer()).subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
        OptionalNamedType(
            'algorithm',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 2))),
        OptionalNamedType(
            'keySize',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 3))),
        OptionalNamedType(
            'digest',
            SetOf(Integer()).subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 5))),
        OptionalNamedType(
            'padding',
            SetOf(Integer()).subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 6))),
        OptionalNamedType(
            'ecCurve',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 10))),
        OptionalNamedType(
            'rsaPublicExponent',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 200))),
        OptionalNamedType(
            'rollbackResistance',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 303))),
        OptionalNamedType(
            'activeDateTime',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 400))),
        OptionalNamedType(
            'originationExpireDateTime',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 401))),
        OptionalNamedType(
            'usageExpireDateTime',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 402))),
        OptionalNamedType(
            'noAuthRequired',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 503))),
        OptionalNamedType(
            'userAuthType',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 504))),
        OptionalNamedType(
            'authTimeout',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 505))),
        OptionalNamedType(
            'allowWhileOnBody',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 506))),
        OptionalNamedType(
            'trustedUserPresenceRequired',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 507))),
        OptionalNamedType(
            'trustedConfirmationRequired',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 508))),
        OptionalNamedType(
            'unlockedDeviceRequired',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 509))),
        OptionalNamedType(
            'allApplications',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 600))),
        OptionalNamedType(
            'applicationId',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 601))),
        OptionalNamedType(
            'creationDateTime',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 701))),
        OptionalNamedType(
            'origin',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 702))),
        OptionalNamedType(
            'rollbackResistant',
            Null().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 703))),
        OptionalNamedType(
            'rootOfTrust',
            RootOfTrust().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 704))),
        OptionalNamedType(
            'osVersion',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 705))),
        OptionalNamedType(
            'osPatchLevel',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 706))),
        OptionalNamedType(
            'attestationApplicationId',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 709))),
        OptionalNamedType(
            'attestationIdBrand',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 710))),
        OptionalNamedType(
            'attestationIdDevice',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 711))),
        OptionalNamedType(
            'attestationIdProduct',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 712))),
        OptionalNamedType(
            'attestationIdSerial',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 713))),
        OptionalNamedType(
            'attestationIdImei',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 714))),
        OptionalNamedType(
            'attestationIdMeid',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 715))),
        OptionalNamedType(
            'attestationIdManufacturer',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 716))),
        OptionalNamedType(
            'attestationIdModel',
            OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 717))),
        OptionalNamedType(
            'vendorPatchLevel',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 718))),
        OptionalNamedType(
            'bootPatchLevel',
            Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 719))),
    )


class KeyDescription(Sequence):
    """Information about the key pair being verified through key attestation.

    References:
      * https://developer.android.com/training/articles/security-key-attestation#certificate_schema_keydescription
    """
    componentType = NamedTypes(
        NamedType('attestationVersion', Integer()),
        NamedType('attestationSecurityLevel', SecurityLevel()),
        NamedType('keymasterVersion', Integer()),
        NamedType('keymasterSecurityLevel', SecurityLevel()),
        NamedType('attestationChallenge', OctetString()),
        NamedType('uniqueId', OctetString()),
        NamedType('softwareEnforced', AuthorizationList()),
        NamedType('teeEnforced', AuthorizationList()),
    )
