from flask import Flask
from flask import request
from flask_sqlalchemy import SQLAlchemy

import json

from typing import Optional, Sequence, Union, NamedTuple

from webauthn_rp.converters import cose_key, jsonify
from webauthn_rp.parsers import parse_cose_key
from webauthn_rp.registrars import *


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'

db = SQLAlchemy(app)


class User(db.Model):
  username = db.Column(db.String(32), primary_key=True)
  user_handle = db.Column(db.String(64), unique=True)
  
  @staticmethod
  def by_user_handle(user_handle: bytes) -> 'User':
    return User.query.filter_by(User.user_handle == user_handle).first()


class Credential(db.Model):
  id = db.Column(db.String(), primary_key=True)
  signature_count = db.Column(db.Integer, default=0)
  credential_public_key = db.Column(db.String)
  user = db.relationship('User', backref=db.backref('credentials', lazy=True))


class Challenge(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  request = db.Column(db.String, unique=True)
  user = db.relationship('User', backref=db.backref('challenges', lazy=True))


class RegistrarImpl(CredentialsRegistrar):

  def _register_options(
      self, options: Union[
        CredentialCreationOptions, CredentialRequestOptions]):
    user_model = User.by_user_handle(options.public_key.user.id)
    if user_model is None: return False
    
    challenge = Challenge()
    challenge.request = challenge
    challenge.user = user_model

    db.session.add(challenge)
    db.session.commit()
    return True

  def register_creation_options(
      self, options: CredentialCreationOptions) -> bool:
    return self._register_options(options)

  def register_request_options(
      self, options: CredentialRequestOptions) -> bool:
    return self._register_options(options)

  def register_credential_creation(
      self, credential: PublicKeyCredential,
      att: AttestationObject, 
      att_type: AttestationType,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity,
      trusted_path: Optional[TrustedPath] = None) -> bool:
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

  def register_credential_request(
      self, credential: PublicKeyCredential,
      authenticator_data: AuthenticatorData,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity) -> bool:
    credential_model = Credential.query.get(id=credential.raw_id)
    credential_model.signature_count = authenticator_data.sign_count
    db.session.commit()
    return True

  def get_credential_data(
      self, credential_id: bytes) -> Optional[CredentialData]:
    credential_model = Credential.query.get(id=credential_id)
    return CredentialData(
      parse_cose_key(
        credential_model.credential_public_key),
      credential_model.signature_count,
    )
  
  def check_user_owns_credential(
      self, user_handle: bytes, credential_id: bytes) -> Optional[bool]:
    credential_model = Credential.query.get(id=credential_id)
    return credential_model.user.user_handle == user_handle


@app.route('/registration/request/', methods=['POST'])
def registration_request():
  username = request.form['username']
  credentials = json.loads(request.form['credentials'])

  user_model = User.query.filter_by(username=username).first()
  if user_model is not None:
    return 

  options = CredentialCreationOptions(
    public_key=PublicKeyCredentialCreationOptions(
      rp=PublicKeyCredentialRpEntity(
        name='webauthn-rp',
        id='localhost'),
      user=PublicKeyCredentialUserEntity(
        name=cco.employee.username,
        id=cco.user_entity.user_handle,
        display_name=cco.user_entity.display_name),
      challenge=cco.credential_challenge.challenge,
      timeout=WEBAUTHN_CHALLENGE_TIMEOUT,
      pub_key_cred_params=supported_public_key_credential_parameters(),
    )
  )

  options_json = jsonify(options)


@app.route('/registration/response/')
def registration_response():
  return 'Hello, World!'


@app.route('/authentication/request/')
def authentication_request():
  return 'Hello, World!'


@app.route('/authentication/request/')
def authentication_response():
  return 'Hello, World!'