import setuptools
from distutils.core import setup
from os.path import dirname, join


setup(
  name='webauthn-rp',
  version='0.0.3',
  description='Web Authentication Relying Party Library',
  author='enceladus-rex',
  packages=['webauthn_rp'],
  url='https://github.com/enceladus-rex/webauthn-rp',
  long_description=open('README.md').read(),
  long_description_content_type='text/markdown',
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
  ],
  test_suite='tests',
  install_requires=[
    'cbor~=1.0',
    'cryptography~=2.6',
  ],
  setup_requirements=[
    'setuptools>=38.6',
    'twine>=1.11',
    'wheel>=0.31',
  ],
  test_requirements=[
    'pytest~=4.4',
    'coverage~=4.5',
    'yapf~=0.27',
    'mypy~=0.701',
    'isort~=4.3',
  ]
)
