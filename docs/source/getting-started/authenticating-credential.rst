========
Authenticating Credential
========

To authenticate the same user, `test`, that was registered previously we can do the following.

1. Type in the username, `test`, and hit authenticate to get the request options and use them to prompt the user to insert and then touch their key.

.. figure:: ../_static/authenticate-request.png
  :alt: Credential Request
  :align: center

2. After using a security key that has a none-attestation, send back the assertion object
and finish authenticating.

.. figure:: ../_static/authenticate-success.png
  :alt: Authentication Success
  :align: center