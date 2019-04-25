from webauthn_rp.types import *
from webauthn_rp.converters import jsonify

from pprint import pprint


def test_jsonify_credential_creation_options():
  cco = CredentialCreationOptions(
    public_key=PublicKeyCredentialCreationOptions(
      rp=PublicKeyCredentialRpEntity(
        name='Example Test',
        id='example.test'),
        user=PublicKeyCredentialUserEntity(
          name='example0',
          id='example0'.encode('utf-8'),
          display_name='example0'),
        challenge=b'j2g30g9jdg092jg30',
        pub_key_cred_params=[PublicKeyCredentialParameters(
          type=PublicKeyCredentialType.PUBLIC_KEY,
          alg=COSEAlgorithmIdentifier.Value.ES256)]
    )
  )

  pprint(jsonify(cco))