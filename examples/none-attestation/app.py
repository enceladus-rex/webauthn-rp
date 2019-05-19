from flask import Flask

from typing import Optional, Sequence, Union, NamedTuple

from webauthn_rp.converters import cose_key
from webauthn_rp.registrars import *


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'

db = SQLAlchemy(app)


class User(db.Model):
  username = db.Column(db.String(32), primary_key=True)
  user_handle = db.Column(db.String(64), unique=True)
  
  @staticmethod
  def by_user_handle(user_handle: bytes) -> User:
    return User.query.filter_by(User.user_handle == user_handle).first()


class Credential(db.Model):
  id = db.Column(db.String(), primary_key=True)
  signature_count = db.Column(db.Integer, default=0)
  credential_public_key = db.Column(db.String)
  user = db.relationship('User', backref=db.backref('credentials', lazy=True))


class Challenge(db.Model):
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

  def register_credential_request(
      self, credential: PublicKeyCredential,
      authenticator_data: AuthenticatorData,
      user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity) -> bool:
    raise UnimplementedError(
      'Must implement register_credential_request')

  def get_creation_options_challenge(
      self, user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity) -> Optional[bytes]:
    raise UnimplementedError(
      'Must implement get_creation_options_challenge')

  def get_request_options_challenge(
      self, user: PublicKeyCredentialUserEntity,
      rp: PublicKeyCredentialRpEntity) -> Optional[bytes]:
    raise UnimplementedError(
      'Must implement get_request_options_challenge')

  def get_credential_data(
      self, credential_id: bytes) -> Optional[CredentialData]:
    raise UnimplementedError(
      'Must implement get_credential_data')
  
  def check_user_owns_credential(
      self, user_handle: bytes, credential_id: bytes) -> Optional[bool]:
    raise UnimplementedError(
      'Must implement check_user_owns_credential')


@app.route('/registration/request/')
def registration_request():
    return 'Hello, World!'


@app.route('/registration/response/')
def registration_request():
    return 'Hello, World!'


@app.route('/authentication/request/')
def registration_request():
    return 'Hello, World!'


@app.route('/authentication/request/')
def registration_request():
    return 'Hello, World!'