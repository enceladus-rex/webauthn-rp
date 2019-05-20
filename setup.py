from distutils.core import setup


setup(
  name='webauthn-rp',
  version='0.0',
  description='Web Authentication Relying Party Library',
  author='enceladus-rex',
  packages=['webauthn_rp'],
  install_requires=[
    'cbor',
    'cryptography',
    'pyopenssl',
  ],
)
