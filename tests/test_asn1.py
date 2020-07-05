import pytest
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from webauthn_rp.asn1 import AuthorizationList, KeyDescription


def test_encode_decode():
    kd = KeyDescription()
    kd['attestationVersion'] = 0
    kd['attestationSecurityLevel'] = 0
    kd['keymasterVersion'] = 0
    kd['keymasterSecurityLevel'] = 0
    kd['attestationChallenge'] = b'attestation-challenge'
    kd['uniqueId'] = b'unique-id'

    software_enforced = AuthorizationList()
    software_enforced['origin'] = 0
    software_enforced['purpose'].append(1)
    software_enforced['allApplications'] = None

    tee_enforced = AuthorizationList()

    kd['softwareEnforced'] = software_enforced
    kd['teeEnforced'] = tee_enforced

    encoded = encode(kd)
    decoded, remainder = decode(encoded, KeyDescription())

    assert remainder == b''
