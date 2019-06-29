import setuptools
from distutils.core import setup
from os.path import dirname, join


setup(
  name='webauthn-rp',
  version='0.0.2',
  description='Web Authentication Relying Party Library',
  author='enceladus-rex',
  packages=['webauthn_rp'],
  url='https://github.com/enceladus-rex/webauthn-rp',
  long_description=open(join(dirname(__file__), 'README.md')).read(),
  long_description_content_type='text/markdown',
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
  ],
  install_requires=[
    'cbor==1.0.0',
    'cryptography==2.6.1',
  ],
)
