import json
import secrets
import time
from datetime import datetime
from typing import Any, Optional

from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy

from webauthn_rp.backends import CredentialsBackend
from webauthn_rp.builders import *
from webauthn_rp.converters import cose_key, jsonify
from webauthn_rp.errors import WebAuthnRPError
from webauthn_rp.parsers import parse_cose_key, parse_public_key_credential
from webauthn_rp.registrars import *
from webauthn_rp.types import (
    AttestationObject, AttestationType, AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse, AuthenticatorData,
    COSEAlgorithmIdentifier, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, TrustedPath)

##### Flask & SQLAlchemy configuration

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/webauthn_rp.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True)
    user_handle = db.Column(db.String(64), unique=True)
    credentials = db.relationship('Credential',
                                  backref=db.backref('user', lazy=True))
    challenges = db.relationship('Challenge',
                                 backref=db.backref('user', lazy=True))

    @staticmethod
    def by_user_handle(user_handle: bytes) -> Optional['User']:
        return User.query.filter_by(user_handle=user_handle).first()


class Credential(db.Model):
    id = db.Column(db.String(), primary_key=True)
    signature_count = db.Column(db.Integer, nullable=True)
    credential_public_key = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request = db.Column(db.String, unique=True)
    timestamp_ms = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


##### Utilities


def timestamp_ms():
    return int(time.time() * 1000)


##### Webauthn-RP Registrar


class RegistrarImpl(CredentialsRegistrar):
    def register_credential_attestation(
            self,
            credential: PublicKeyCredential,
            att: AttestationObject,
            att_type: AttestationType,
            user: PublicKeyCredentialUserEntity,
            rp: PublicKeyCredentialRpEntity,
            trusted_path: Optional[TrustedPath] = None) -> Any:
        assert att.auth_data is not None
        assert att.auth_data.attested_credential_data is not None
        cpk = att.auth_data.attested_credential_data.credential_public_key

        user_model = User.by_user_handle(user.id)
        if user_model is None: return 'No user found'

        credential_model = Credential()
        credential_model.id = credential.raw_id
        credential_model.signature_count = None
        credential_model.credential_public_key = cose_key(cpk)
        credential_model.user = user_model

        db.session.add(credential_model)
        db.session.commit()

    def register_credential_assertion(self, credential: PublicKeyCredential,
                                      authenticator_data: AuthenticatorData,
                                      user: PublicKeyCredentialUserEntity,
                                      rp: PublicKeyCredentialRpEntity) -> Any:
        credential_model = Credential.query.filter_by(
            id=credential.raw_id).first()
        credential_model.signature_count = authenticator_data.sign_count
        db.session.commit()

    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
        credential_model = Credential.query.filter_by(id=credential_id).first()
        if credential_model is None:
            return None

        return CredentialData(
            parse_cose_key(credential_model.credential_public_key),
            credential_model.signature_count,
            PublicKeyCredentialUserEntity(
                name=credential_model.user.username,
                id=credential_model.user.user_handle,
                display_name=credential_model.user.username))


##### Webauthn-RP configuration

APP_ORIGIN = 'http://localhost:5000'
APP_TIMEOUT = 60000
APP_RELYING_PARTY = PublicKeyCredentialRpEntity(name='localhost',
                                                id='localhost')

APP_CCO_BUILDER = CredentialCreationOptionsBuilder(
    rp=APP_RELYING_PARTY,
    pub_key_cred_params=[
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,
                                      alg=COSEAlgorithmIdentifier.Value.ES256)
    ],
    timeout=APP_TIMEOUT,
)

APP_CRO_BUILDER = CredentialRequestOptionsBuilder(
    rp_id=APP_RELYING_PARTY.id,
    timeout=APP_TIMEOUT,
)

APP_CREDENTIALS_BACKEND = CredentialsBackend(RegistrarImpl())

###### URL handlers


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
        user_handle = secrets.token_bytes(64)

        user_model = User()
        user_model.username = username
        user_model.user_handle = user_handle
        db.session.add(user_model)
        db.session.commit()

    challenge_bytes = secrets.token_bytes(64)
    challenge = Challenge()
    challenge.request = challenge_bytes
    challenge.timestamp_ms = timestamp_ms()
    challenge.user_id = user_model.id

    db.session.add(challenge)
    db.session.commit()

    options = APP_CCO_BUILDER.build(
        user=PublicKeyCredentialUserEntity(name=username,
                                           id=user_handle,
                                           display_name=username),
        challenge=challenge_bytes,
    )

    options_json = jsonify(options)
    response_json = {
        'challengeID': challenge.id,
        'creationOptions': options_json,
    }

    response_json_string = json.dumps(response_json)

    return (response_json_string, 200, {'Content-Type': 'application/json'})


@app.route('/registration/response/', methods=['POST'])
def registration_response():
    try:
        challengeID = request.form['challengeID']
        credential = parse_public_key_credential(
            json.loads(request.form['credential']))
        username = request.form['username']
    except Exception:
        return ('Could not parse input data', 400)

    if type(credential.response) is not AuthenticatorAttestationResponse:
        return ('Invalid response type', 400)

    challenge_model = Challenge.query.filter_by(id=challengeID).first()
    if not challenge_model:
        return ('Could not find challenge matching given id', 400)

    user_model = User.query.filter_by(username=username).first()
    if not user_model:
        return ('Invalid username', 400)

    current_timestamp = timestamp_ms()
    if current_timestamp - challenge_model.timestamp_ms > APP_TIMEOUT:
        return ('Timeout', 408)

    user_entity = PublicKeyCredentialUserEntity(name=username,
                                                id=user_model.user_handle,
                                                display_name=username)

    try:
        APP_CREDENTIALS_BACKEND.handle_credential_attestation(
            credential=credential,
            user=user_entity,
            rp=APP_RELYING_PARTY,
            expected_challenge=challenge_model.request,
            expected_origin=APP_ORIGIN)
    except WebAuthnRPError:
        return ('Could not handle credential attestation', 400)

    return ('Success', 200)


@app.route('/authentication/request/', methods=['POST'])
def authentication_request():
    username = request.form['username']

    user_model = User.query.filter_by(username=username).first()
    if user_model is None:
        return ('User not registered', 400)

    credential_model = Credential.query.filter_by(
        user_id=user_model.id).first()
    if credential_model is None:
        return ('User without credential', 400)

    challenge_bytes = secrets.token_bytes(64)
    challenge = Challenge()
    challenge.request = challenge_bytes
    challenge.timestamp_ms = timestamp_ms()
    challenge.user_id = user_model.id

    db.session.add(challenge)
    db.session.commit()

    options = APP_CRO_BUILDER.build(
        challenge=challenge_bytes,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=credential_model.id,
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )
        ])

    options_json = jsonify(options)
    response_json = {
        'challengeID': challenge.id,
        'requestOptions': options_json,
    }

    response_json_string = json.dumps(response_json)

    return (response_json_string, 200, {'Content-Type': 'application/json'})


@app.route('/authentication/response/', methods=['POST'])
def authentication_response():
    try:
        challengeID = request.form['challengeID']
        credential = parse_public_key_credential(
            json.loads(request.form['credential']))
        username = request.form['username']
    except Exception:
        return ('Could not parse input data', 400)

    if type(credential.response) is not AuthenticatorAssertionResponse:
        return ('Invalid response type', 400)

    challenge_model = Challenge.query.filter_by(id=challengeID).first()
    if not challenge_model:
        return ('Could not find challenge matching given id', 400)

    user_model = User.query.filter_by(username=username).first()
    if not user_model:
        return ('Invalid username', 400)

    current_timestamp = timestamp_ms()
    if current_timestamp - challenge_model.timestamp_ms > APP_TIMEOUT:
        return ('Timeout', 408)

    user_entity = PublicKeyCredentialUserEntity(name=username,
                                                id=user_model.user_handle,
                                                display_name=username)

    try:
        APP_CREDENTIALS_BACKEND.handle_credential_assertion(
            credential=credential,
            user=user_entity,
            rp=APP_RELYING_PARTY,
            expected_challenge=challenge_model.request,
            expected_origin=APP_ORIGIN)
    except WebAuthnRPError:
        return ('Could not handle credential assertion', 400)

    return ('Success', 200)


@app.route('/')
def index():
    return render_template('app.html')


##### Main

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
