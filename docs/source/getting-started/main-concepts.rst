=============
Main Concepts
=============

In case you haven't already, now is a good time to install the library. It is
entirely in Python 3.x so you can use `pip` to install it:

.. code-block:: bash

  pip install webauthn-rp

If you aren't familiar with some of the key concepts involved with web authentication
you may want read this page to gain some insight before you start using the library.

Why WebAuthn?
-------------

Web Authentication enables multi-factor authentication using public key
cryptography and trusted hardware platforms (authenticators) that can generate
private and pubilc key pairs to perform signing and verification on a user's behalf.
Compared to other multi-factor authentication techniques, some of the benefits that
the Web Authentication specification aims to bring are:

1. It is easy to use and widely compatible.
2. The authenticator hardware does not need to be managed by the Relying Party.
3. Registration and authentication are resistant to man-in-the-middle attacks,
   especially when attestation is used and can be trusted.

The third point is important because many phishing-related attacks are done
using man-in-the-middle techniques.


Reference Terminology
---------------------

* `Relying Party` - The entity whose web application utilizes the Web Authentication
  API to register and authentication users.
* `Authenticator` - A cryptographic entity used by a WebAuthn Client to (i) generate
  a public key credential and register it with a Relying Party, and (ii) authenticate
  by potentially verifying the user, and then cryptographically signing and
  returning, in the form of an Authentication Assertion, a challenge and other data
  presented by a WebAuthn Relying Party (in concert with the WebAuthn Client).
* `Attestation` - Generally, attestation is a statement serving to bear witness,
  confirm, or authenticate. In the WebAuthn context, attestation is employed to
  attest to the provenance of an authenticator (history and origin) and the data
  it emits; including, for example: credential IDs, credential key pairs, signature
  counters, etc. An attestation statement is conveyed in an attestation object
  during registration.
* `Registration` - The ceremony where a user, a Relying Party, and the user’s
  client (containing at least one authenticator) work in concert to create a public
  key credential and associate it with the user’s Relying Party account. Note that
  this includes employing a test of user presence or user verification.
* `Authentication` - The ceremony where a user, and the user’s client (containing at
  least one authenticator) work in concert to cryptographically prove to a Relying
  Party that the user controls the credential private key associated with a
  previously-registered public key credential (see Registration). Note that this
  includes a test of user presence or user verification.
* `Public Key Credential` - Generically, a credential is data one entity presents to
  another in order to authenticate the former to the latter. The term public key
  credential refers to one of: a public key credential source, the possibly-attested
  credential public key corresponding to a public key credential source, or an
  authentication assertion. Which one is generally determined by context.

Challenge and Response
----------------------

As opposed to sending a password that does not change with each use, the model
adopted by WebAuthn is that the Relying Party sends a secure random string to the
client for registration and authentication. This string is incorporated into the data
that is signed by the authenticator using its private key. Therefore each response
should be probabilistically unique (extremely low chance of using the same challenge).
The signed data is then verified using the public key that the Relying Party has
registered for the user. In order to register a public key, the Relying Party can
specify whether or not the user must provided an attestation, which can be for example
a certificate chain for the authenticator's public key. Attestations enables one to
ensure that at the time of use, a particular hardware certificate is trusted by
validating its chain of trust (checking that there haven't been any revocations).
Furthermore, due to the nature of asymmetric encryption, gaining access to the public
key (which is shared with the Relying Party) does not allow one to authenticate as
the user. The private key is actually never shared and is usually kept in its own
separate memory.

Links
^^^^^

* https://www.w3.org/TR/webauthn/#sctn-rp-benefits
* https://www.w3.org/TR/webauthn/#terminology