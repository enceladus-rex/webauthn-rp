from distutils.core import setup
from os.path import dirname, join

import setuptools


def get_version():
  with open(join(dirname(__file__), 'webauthn_rp/__init__.py'), 'r') as f:
    for line in f.read().splitlines():
      if line.startswith('__version__'):
        delim = '"' if '"' in line else "'"
        return line.split(delim)[1]
    else:
      raise RuntimeError("Unable to find version string.")


with open('requirements.txt') as rt:
  requirements_txt = rt.read()

with open('README.md') as rt:
  readme_txt = rt.read()

install_requires = [
    line.strip() for line in requirements_txt.split()
    if (not line.startswith('#'))
]

setup_requirements = [
    'setuptools>=38.6',
    'twine>=1.11',
    'wheel>=0.31',
]

test_requirements = [
    'pytest~=4.4',
    'pytest-cov~=2.7',
    'codecov~=2.0',
    'coverage~=4.5',
    'yapf~=0.27',
    'mypy~=0.701',
    'isort~=4.3',
]

setup(name='webauthn-rp',
      version=get_version(),
      description='Web Authentication Relying Party Library',
      author='enceladus-rex',
      packages=['webauthn_rp'],
      url='https://github.com/enceladus-rex/webauthn-rp',
      long_description=readme_txt,
      long_description_content_type='text/markdown',
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
      ],
      test_suite='tests',
      install_requires=install_requires,
      setup_requirements=setup_requirements,
      test_requirements=test_requirements,
      extras_require={
          'test': test_requirements,
      })
