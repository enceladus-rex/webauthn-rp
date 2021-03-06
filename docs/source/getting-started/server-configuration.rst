====================
Server Configuration
====================

Configuring a server to use this library requires doing a few things:

* Implementing the `CredentialsRegistrar` interface from `webauthn-rp`.
* Setting up a database to store the registered credential public keys and metadata.
* Configuring and handling routes for the user client to:

  a. Begin registration for an authenticator.
  b. Send back the attested registration response.
  c. Begin authentication with an authenticator.
  d. Send back the asserted authentication response.

You can use the same route to handle all the client requests and responses, though
in this example we'll split them up for clarity.

Also, we'll use the `Flask` lightweight Python web framework along with an extension
for the `SQLAlchemy` object relational mapping framework. You can install them both 
using pip:

.. code-block:: bash

  pip install Flask Flask-SQLAlchemy

Registrar Overview
------------------

Before creating the database models it is useful to take a look at the
CredentialsRegistrar interface to understand what kinds of data it needs to
store and retrieve.

.. literalinclude:: ../../../webauthn_rp/registrars.py
   :pyobject: CredentialsRegistrar

Focusing on the `get_credential_data` function, notice that you'll need to be able to
retrieve a number of fields related to a particular credential. 

.. note::
  
  Each credential can be identified using a byte string that is at least 16 bytes
  long and is probabilistically unique. The specific data you'll want to retrieve is
  enumerated in the `CredentialData` NamedTuple shown below. The first three
  fields, `credential_public_key`, `signature_count`, and `user_entity` are required.

.. literalinclude:: ../../../webauthn_rp/registrars.py
   :pyobject: CredentialData

How you store the `credential_public_key` in the database is your choice, however,
considering that it is represented in the specification 
using the COSE_Key CBOR (Concise Binary Object Representation) format, that is the
compact format that is recommended, especially if you just want to store a binary
blob. This library also contains some utility functions to convert to and from this
particular encoding (used below).

.. note::
  
  A user handle is a byte string that the Relying Party uses to identify the user
  but should contain no personally identifiable information, i.e. not a username or
  email address.

The data to be stored is provided in the two `register` functions. In particular you
can find the `credential_public_key` using the `att` parameter under
`att.auth_data.attested_credential_data.credential_public_key` and the
`signature_count` under `att.auth_data.sign_count`. Additionally, the `credential_id`
is under `att.auth_data.attested_credential_data.credential_id`.

Lastly, although not explicitly retrieved using a `get` function, you'll need to store
the challenge that is used for each registration and authentication ceremony in order
to have the `CredentialsBackend` check it for verification. The challenge is provided
in the `options` object under `options.public_key.challenge`.

Flask Setup
-----------

To configure Flask create a file `app.py` in a work directory with the following:

.. code-block::

  from flask import Flask

  app = Flask(__name__)
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/example.db'

  db = SQLAlchemy(app)

The setups up the app and database engine. 

Database Models
---------------

From the previous sections, the data required for retrieval has been established and
so now we can move on to building the database models.

The user model is quite simple and just contains:

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: User

Similarly the credential model is:

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: Credential

You'll also need to store the challenge information that was used during
registration and authentication so that you are able to verify it.

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: Challenge

That's the bare minimum you'll need in order to get started. Next, we'll revisit
the registrar in order to implement the required functions.

Implementing the Registrar
----------------------

Although the register functions are passed a lot of data, we'll only focus on the
key pieces of information that need to be stored for later retrieval as previously
mentioned.

Putting it all together yields:

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: RegistrarImpl

Next, we'll go about creating and handling the registration and authentication routes.

Registration Request
--------------------

When a user client wants to register an authenticator with a Relying Party, it'll first need
to request some options from the Relying Party that specify a number of things, namely what
kinds of authenticators are acceptable and which challenge should be used. In this particular
example, the user will be registering for the first time and so also provides a desired username.

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: registration_request

To reidentify the challenge, note that we're also sending a unique ID with the JSON response.

Registration Response
---------------------

If the client successfully is able to use the creation options from the registration request
to generate an attestation on the user's behalf, then this endpoint will verify the attestation
and finish the user's registration if valid.

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: registration_response

Along with using the credentials backend to verify the challenge and the rest of the attestation,
object we're also checking to make sure that the response was sent before the specified timeout.

Authentication Request
----------------------

The authentication flow is very much like the registration flow, just that credential
request options are returned instead of credential creation options.

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: authentication_request

Authentication Response
-----------------------

Finally, the authentication flow also mirrors the registration flow, just that an assertion
is expected rather than an attestation object. 

.. literalinclude:: ../../../examples/flask/app.py
   :pyobject: authentication_response