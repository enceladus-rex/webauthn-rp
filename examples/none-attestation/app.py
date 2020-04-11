import json
import secrets
import time
from datetime import datetime
from typing import Any, NamedTuple, Optional, Sequence, Union

from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy

from webauthn_rp.backends import CredentialsBackend
from webauthn_rp.converters import cose_key, jsonify
from webauthn_rp.errors import WebAuthnRPError
from webauthn_rp.parsers import parse_cose_key, parse_public_key_credential
from webauthn_rp.registrars import *
from webauthn_rp.types import (
    COSEAlgorithmIdentifier, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialType)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/webauthn.db'

db = SQLAlchemy(app)

example_rp = PublicKeyCredentialRpEntity(name='localhost', id='localhost')
example_timeout = 60000
example_credential_parameters = [
    PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,
                                  alg=COSEAlgorithmIdentifier.Value.ES256)
]


def timestamp():
  return int(time.mktime(datetime.now().timetuple()))


class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(32), unique=True)
  user_handle = db.Column(db.String(64), unique=True)
  credentials = db.relationship('Credential',
                                backref=db.backref('user', lazy=True))
  challenges = db.relationship('Challenge',
                               backref=db.backref('user', lazy=True))

  @staticmethod
  def by_user_handle(user_handle: bytes) -> 'User':
    return User.query.filter_by(user_handle=user_handle).first()


class Credential(db.Model):
  id = db.Column(db.String(), primary_key=True)
  signature_count = db.Column(db.Integer, default=0)
  credential_public_key = db.Column(db.String)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Challenge(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  request = db.Column(db.String, unique=True)
  timestamp = db.Column(db.Integer)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class RegistrarImpl(CredentialsRegistrar):
  def register_credential_creation(
      self,
      credential: PublicKeyCredential,
      att: AttestationObject,
      att_type: AttestationType,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      trusted_path: Optional[TrustedPath] = None) -> bool:
    assert att.auth_data is not None
    assert att.auth_data.attested_credential_data is not None
    cpk = att.auth_data.attested_credential_data.credential_public_key

    user_model = User.by_user_handle(user.id)
    if user_model is None: return False

    credential_model = Credential()
    credential_model.id = credential.raw_id
    credential_model.signature_count = 0
    credential_model.credential_public_key = cose_key(cpk)
    credential_model.user = user_model

    db.session.add(credential_model)
    db.session.commit()
    return True

  def register_credential_request(self, credential: PublicKeyCredential,
                                  authenticator_data: AuthenticatorData,
                                  user: PublicKeyCredentialUserEntity,
                                  rp: PublicKeyCredentialRpEntity) -> bool:
    credential_model = Credential.query.filter_by(id=credential.raw_id).first()
    credential_model.signature_count = authenticator_data.sign_count
    db.session.commit()
    return True

  def get_credential_data(self,
                          credential_id: bytes) -> Optional[CredentialData]:
    credential_model = Credential.query.filter_by(id=credential_id).first()
    return CredentialData(
        parse_cose_key(credential_model.credential_public_key),
        credential_model.signature_count,
    )

  def check_user_owns_credential(self, user_handle: bytes,
                                 credential_id: bytes) -> Optional[bool]:
    credential_model = Credential.query.filter_by(id=credential_id).first()
    return credential_model.user.user_handle == user_handle


credentials_backend = CredentialsBackend(RegistrarImpl())


@app.route('/registration/request/', methods=['POST'])
def registration_request():
  username = request.form['username']

  user_model = User.query.filter_by(username=username).first()
  if user_model is not None:
    credential_model = Credential.query.filter_by(
        user_id=user_model.id).first()

    if credential_model is not None:
      return ('User already registered', 400, {})

    user_handle = user_model.user_handle
  else:
    user_handle = secrets.token_bytes(32)

    user_model = User()
    user_model.username = username
    user_model.user_handle = user_handle
    db.session.add(user_model)
    db.session.commit()

  challenge_bytes = secrets.token_bytes(64)
  challenge = Challenge()
  challenge.request = challenge_bytes
  challenge.timestamp = timestamp()
  challenge.user_id = user_model.id

  db.session.add(challenge)
  db.session.commit()

  options = CredentialCreationOptions(
      public_key=PublicKeyCredentialCreationOptions(
          rp=example_rp,
          user=PublicKeyCredentialUserEntity(
              name=username, id=user_handle, display_name=username),
          challenge=challenge_bytes,
          timeout=example_timeout,
          pub_key_cred_params=example_credential_parameters,
      ))

  credentials_backend.handle_creation_options(options=options)

  options_json = jsonify(options)
  response_json = {
      'challengeID': challenge.id,
      'creationOptions': options_json,
  }

  response_json_string = json.dumps(response_json)

  return (response_json_string, 200, {'Content-Type': 'application/json'})


@app.route('/registration/response/', methods=['POST'])
def registration_response():
  challengeID = request.form['challengeID']
  credential = parse_public_key_credential(
      json.loads(request.form['credential']))
  username = request.form['username']

  if type(credential.response) is not AuthenticatorAttestationResponse:
    return ('Invalid response type', 400)

  challenge_model = Challenge.query.filter_by(id=challengeID).first()
  if not challenge_model:
    return ('Could not find challenge matching given id', 400)

  user_model = User.query.filter_by(username=username).first()
  if not user_model:
    return ('Invalid username', 400)

  current_timestamp = timestamp()
  if current_timestamp - challenge_model.timestamp > example_timeout:
    return ('Timeout', 408)

  user_entity = PublicKeyCredentialUserEntity(name=username,
                                              id=user_model.user_handle,
                                              display_name=username)

  try:
    credentials_backend.handle_credential_creation(
        credential=credential,
        user=user_entity,
        rp=example_rp,
        expected_challenge=challenge_model.request)
  except WebAuthnRPError as e:
    return ('Could not handle credential creation', 400)

  return ('Success', 200)


@app.route('/authentication/request/', methods=['POST'])
def authentication_request():
  username = request.form['username']

  user_model = User.query.filter_by(username=username).first()
  if user_model is None:
    # User is not registered.
    return ('User not registered', 400)

  credential_model = Credential.query.filter_by(user_id=user_model.id).first()
  if credential_model is None:
    return ('User without credential', 400)

  challenge_bytes = secrets.token_bytes(64)
  challenge = Challenge()
  challenge.request = challenge_bytes
  challenge.timestamp = timestamp()
  challenge.user_id = user_model.id

  db.session.add(challenge)
  db.session.commit()

  options = CredentialRequestOptions(
      public_key=PublicKeyCredentialRequestOptions(
          rp_id=example_rp.id,
          challenge=challenge_bytes,
          timeout=example_timeout,
          allow_credentials=[
              PublicKeyCredentialDescriptor(
                  id=credential_model.id,
                  type=PublicKeyCredentialType.PUBLIC_KEY,
              )
          ],
      ))

  options_json = jsonify(options)
  response_json = {
      'challengeID': challenge.id,
      'getOptions': options_json,
  }
  response_json_str = json.dumps(response_json)

  try:
    credentials_backend.handle_request_options(options=options)
  except WebAuthnRPError:
    return ('Could not handle request options', 400)

  return (response_json_str, 200, {'Content-Type': 'application/json'})


@app.route('/authentication/response/', methods=['POST'])
def authentication_response():
  challengeID = request.form['challengeID']
  credential = parse_public_key_credential(
      json.loads(request.form['credential']))
  username = request.form['username']

  if type(credential.response) is not AuthenticatorAssertionResponse:
    return HttpResponse('Invalid response type', status=400)

  challenge_model = Challenge.query.filter_by(id=challengeID).first()
  if not challenge_model:
    return ('Could not find challenge matching given id', 400)

  user_model = User.query.filter_by(username=username).first()
  if not user_model:
    return ('Invalid username', 400)

  current_timestamp = timestamp()
  if current_timestamp - challenge_model.timestamp > example_timeout:
    return ('Timeout', 408)

  user_entity = PublicKeyCredentialUserEntity(name=username,
                                              id=user_model.user_handle,
                                              display_name=username)

  try:
    credentials_backend.handle_credential_request(
        credential=credential,
        user=user_entity,
        rp=example_rp,
        expected_challenge=challenge_model.request)
  except WebAuthnRPError as e:
    return ('Could not handle credential creation', 400)

  return ('Success', 200)


@app.route('/')
def index():
  return render_template('app.html')


if __name__ == '__main__':
  db.create_all()
  app.run(debug=True)
