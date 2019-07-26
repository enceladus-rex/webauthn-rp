========
Client Configuration
========

The example used in this tutorial will have a simple client that allows users to register
a username with a credential and verify them. It'll be assumed that the flask server
backend will be running on localhost:5000. To perform a post request at an endpoint,
we can then use:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 25-31

Essentially, the client will need to call the previous endpoints to get options to use
with the browser's credentials API and subsequently return the attestation or
assertion object depending on the type of request.

The HTML is basic and includes just a textbox for the username, buttons for registration
and authentication as well as a colored status indicator. Some JavaScript utilities
are also included for base64 handling and setting the status.

The JavaScript utilities:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 13-24,96-99

The HTML body:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: html
   :lines: 182-191

Registration
------------

Getting the credential creation options:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 33-45,118-134

Sending the attestation:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 66-77,101-116

Combined:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 170-173

Authentication
--------------

Getting the credential request options:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 46-65,153-168

Sending the assertion:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 78-95,136-151

Combined:

.. literalinclude:: ../../../examples/none-attestation/templates/app.html
   :language: javascript
   :lines: 175-178