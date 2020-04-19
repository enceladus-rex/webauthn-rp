import pytest

from webauthn_rp.types import COSEAlgorithmIdentifier, EC2Curve, OKPCurve
from webauthn_rp.utils import (camel_to_snake_case,
                               curve_coordinate_byte_length,
                               ec2_hash_algorithm, snake_to_camel_case,
                               url_base64_decode, url_base64_encode)


def test_snake_to_camel_case():
  assert snake_to_camel_case('') == ''
  assert snake_to_camel_case('___') == ''
  assert snake_to_camel_case('a') == 'a'
  assert snake_to_camel_case('a_b_c') == 'aBC'
  assert snake_to_camel_case('a__b_c') == 'aBC'
  assert snake_to_camel_case('a__b__c') == 'aBC'
  assert snake_to_camel_case('_a__b__c') == 'aBC'
  assert snake_to_camel_case('_a__b__c_') == 'aBC'
  assert snake_to_camel_case('a_Bc_d') == 'aBcD'
  assert snake_to_camel_case('a_BC_d') == 'aBCD'


def test_camel_to_snake_case():
  assert camel_to_snake_case('') == ''
  assert camel_to_snake_case('a') == 'a'
  assert camel_to_snake_case('aBCD') == 'a_b_c_d'
  assert camel_to_snake_case('abCdEf') == 'ab_cd_ef'
  assert camel_to_snake_case('abCDEf') == 'ab_c_d_ef'
  assert camel_to_snake_case('ab_cd_Ef') == 'ab_cd__ef'


def test_url_base64_encode():
  assert url_base64_encode(b'') == b''
  assert url_base64_encode(b'\xF8') == b'-A=='
  assert url_base64_encode(b'\xFC') == b'_A=='


def test_url_base64_decode():
  assert url_base64_decode('') == b''
  assert url_base64_decode('-A==') == b'\xF8'
  assert url_base64_decode('_A==') == b'\xFC'
  assert url_base64_decode('-A=') == b'\xF8'
  assert url_base64_decode('_A=') == b'\xFC'
  assert url_base64_decode('-A') == b'\xF8'
  assert url_base64_decode('_A') == b'\xFC'


@pytest.mark.parametrize('crv',
                         list(EC2Curve.Name) + list(EC2Curve.Value) +
                         list(OKPCurve.Name) + list(OKPCurve.Value))
def test_curve_coordinate_byte_length(crv):
  l = curve_coordinate_byte_length(crv)
  assert type(l) is int
  assert l > 0


@pytest.mark.parametrize('alg', [
    COSEAlgorithmIdentifier.Name.ES256,
    COSEAlgorithmIdentifier.Name.ES256,
    COSEAlgorithmIdentifier.Name.ES256,
    COSEAlgorithmIdentifier.Value.ES256,
    COSEAlgorithmIdentifier.Value.ES256,
    COSEAlgorithmIdentifier.Value.ES256,
])
def test_ec2_hash_algorithm_success(alg):
  ec2_hash_algorithm(alg)


@pytest.mark.parametrize('alg', [
    COSEAlgorithmIdentifier.Name.EDDSA,
    COSEAlgorithmIdentifier.Value.EDDSA,
])
def test_ec2_hash_algorithm_error(alg):
  with pytest.raises(AssertionError):
    ec2_hash_algorithm(alg)
